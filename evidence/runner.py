"""Isolated Evidence Engine campaign runner, control checks, and offline replay."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import tempfile
from typing import Any, Callable, Mapping, Sequence
import uuid

from bin.replay_benchmark import run_deterministic_benchmark, run_deterministic_replay
from evidence.ledger import (
    DEFAULT_EVENT_LEDGER_FILENAME,
    collect_environment_metadata,
    derive_outcomes_from_ledger,
    ingest_context_receipts,
    run_cursor_cli_conformance,
)
from evidence.metrics import compute_arm_summary, compute_paired_comparison, plan_evaluation_matrix
from policies.api import EVIDENCE_SCHEMA_VERSION, EvidenceContractV1, VALID_EVAL_TIERS
from spool.receipts import check_unsafe_link, receipts_path_for
from spool.store import slice_spool, spool_tool_output

_TASK_SPECS_RAW: tuple[tuple[str, str, str], ...] = (
    ("task_01", "Fix off-by-one boundary in parser", "bugfix"),
    ("task_02", "Deduplicate config normalization helper", "refactor"),
    ("task_03", "Triage flaky fixture isolation test", "test_triage"),
    ("task_04", "Summarize structured error log stream", "log_analysis"),
    ("task_05", "Enforce strict schema validation on API input", "api_contract"),
    ("task_06", "Reject path traversal in file loader", "security_audit"),
    ("task_07", "Add JSON flag to CLI subcommand", "cli_feature"),
    ("task_08", "Eliminate quadratic loop in index lookup", "performance"),
    ("task_09", "Guard shared state updates with file lock", "concurrency"),
    ("task_10", "Verify cross-platform path joining in bundler", "packaging"),
    ("task_11", "Validate backward-compatible ledger migration", "schema_validation"),
    ("task_12", "Return explicit exit code on malformed input", "error_handling"),
    ("task_13", "Parse nested CLI flags with quoted arguments", "parsing"),
    ("task_14", "Invalidate stale cache on config change", "caching"),
    ("task_15", "Report missing runtime dependency in diagnostics", "diagnostics"),
)
_DEFAULT_BUDGET: dict[str, Any] = {"max_turns": 20, "timeout_s": 300.0, "max_cost_usd": 2.0}

DEFAULT_BENCHMARK_TASKS: tuple[dict[str, Any], ...] = tuple(
    {
        "task_id": tid, "title": title, "category": cat, "pass_criterion_id": f"criterion_{idx:02d}",
        "max_turns": int(_DEFAULT_BUDGET["max_turns"]), "timeout_s": float(_DEFAULT_BUDGET["timeout_s"]),
        "max_cost_usd": float(_DEFAULT_BUDGET["max_cost_usd"]),
    }
    for idx, (tid, title, cat) in enumerate(_TASK_SPECS_RAW, 1)
)

_OFFLINE_CLAIM = (
    "offline_contract_replay_only: verifies deterministic transforms, integrity, "
    "latency, and durability; does NOT prove live model trajectories."
)
_PILOT_CLAIM = "small_live_pilot_regression_gate: isolated regression gate; not powered for causal release proof."
_RELEASE_CLAIM = (
    "controlled_isolated_ab_evaluation: compares Cost per Passed Run under pinned "
    "versions, budgets, and pass criteria."
)
_UNVERIFIED_RELEASE_CLAIM = "unverified_release_evaluation: control or completeness violations prevent causal claim."
_UNPINNED_SENTINELS = frozenset({"unpinned", "latest", "auto", "unknown"})
_ISO_ENV_KEYS = (
    "CONTEXT_GUARD_HOME", "CONTEXT_GUARD_STATE_DIR", "CONTEXT_GUARD_SPOOL_DIR",
    "CONTEXT_GUARD_CONFIG_PATH", "CONTEXT_GUARD_WORKSPACE_ROOT",
)

__all__ = [
    "DEFAULT_BENCHMARK_TASKS", "evaluate_campaign_runs", "execute_isolated_campaign",
    "plan_isolated_campaign", "run_offline_evidence_replay", "verify_campaign_controls",
]


def _utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_text(val: Any) -> str:
    return val.strip() if isinstance(val, str) else ""


def _canon_path_str(raw: Any) -> str:
    txt = str(raw).strip() if isinstance(raw, (str, Path)) else ""
    return os.path.normcase(os.path.realpath(txt)) if txt else ""


def _parse_budget_tuple(raw: Mapping[str, Any]) -> tuple[tuple[int, float, float] | None, str | None]:
    src: Mapping[str, Any] = raw["budget"] if isinstance(raw.get("budget"), Mapping) else raw
    turns, tout, cost = src.get("max_turns"), src.get("timeout_s"), src.get("max_cost_usd")
    if turns is None or tout is None or cost is None:
        return None, "missing_budget_fields"
    if isinstance(turns, bool) or not isinstance(turns, int) or turns <= 0:
        return None, "invalid_budget_max_turns"
    if isinstance(tout, bool) or not isinstance(tout, (int, float)) or float(tout) <= 0.0:
        return None, "invalid_budget_timeout_s"
    if isinstance(cost, bool) or not isinstance(cost, (int, float)) or float(cost) < 0.0:
        return None, "invalid_budget_max_cost_usd"
    return (int(turns), round(float(tout), 6), round(float(cost), 6)), None


def verify_campaign_controls(
    runs: Sequence[Mapping[str, Any]], *, expected_arms: Sequence[str] | None = None
) -> dict[str, Any]:
    """Verify isolated workspaces, pinned versions, identical budgets, and per-task pass criteria."""
    if not runs:
        return {
            "ok": False, "run_count": 0, "arms_observed": [], "isolated_workspaces_ok": False,
            "pinned_versions_ok": False, "identical_budgets_ok": False,
            "identical_pass_criteria_ok": False, "violations": ["no_runs_provided"],
        }
    violations: list[str] = []
    iso_ok = pinned_ok = budgets_ok = criteria_ok = True
    seen_paths: dict[str, str] = {}
    existing_paths: list[tuple[Path, str]] = []
    seen_ws_ids: dict[str, str] = {}
    seen_versions: set[tuple[str, str, str, str]] = set()
    seen_budgets: set[tuple[int, float, float]] = set()
    task_criteria: dict[str, set[str]] = {}
    seen_arms: set[str] = set()

    for idx, raw in enumerate(runs):
        if not isinstance(raw, Mapping):
            violations.append(f"invalid_run_mapping:idx_{idx}")
            iso_ok = pinned_ok = budgets_ok = criteria_ok = False
            continue
        label = _clean_text(raw.get("run_id")) or f"idx_{idx}"
        if (arm := _clean_text(raw.get("arm"))):
            seen_arms.add(arm)
        if raw.get("shared_workspace") is True:
            violations.append(f"shared_workspace_flag:{label}")
            iso_ok = False

        raw_ws = raw.get("isolated_workspace") or raw.get("workspace_path") or raw.get("workspace_dir")
        canon_ws, ws_id = _canon_path_str(raw_ws), _clean_text(raw.get("workspace_id"))
        if not canon_ws and not ws_id:
            violations.append(f"missing_isolated_workspace:{label}")
            iso_ok = False
        if canon_ws:
            if canon_ws in seen_paths:
                violations.append(f"shared_workspace_path:{label}:{seen_paths[canon_ws]}")
                iso_ok = False
            else:
                seen_paths[canon_ws] = label
            if (cand_p := Path(str(raw_ws))).exists():
                for prev_p, prev_lbl in existing_paths:
                    try:
                        if os.path.samefile(str(cand_p), str(prev_p)):
                            violations.append(f"samefile_workspace:{label}:{prev_lbl}")
                            iso_ok = False
                            break
                    except OSError:
                        pass
                existing_paths.append((cand_p, label))
        if ws_id:
            if ws_id in seen_ws_ids:
                violations.append(f"shared_workspace_id:{label}:{seen_ws_ids[ws_id]}")
                iso_ok = False
            else:
                seen_ws_ids[ws_id] = label

        h_id = _clean_text(raw.get("harness_id") or raw.get("harness")).lower()
        hb_id = _clean_text(raw.get("harness_build_id"))
        m_id = _clean_text(raw.get("model_id") or raw.get("model"))
        cg_ver = _clean_text(raw.get("context_guard_version"))
        if not (h_id and hb_id and m_id and cg_ver):
            violations.append(f"missing_pinned_version:{label}")
            pinned_ok = False
        elif any(x.lower() in _UNPINNED_SENTINELS for x in (h_id, hb_id, m_id, cg_ver)):
            violations.append(f"unpinned_version_sentinel:{label}")
            pinned_ok = False
        else:
            seen_versions.add((h_id, hb_id, m_id, cg_ver))

        bt, b_err = _parse_budget_tuple(raw)
        if b_err is not None or bt is None:
            violations.append(f"{b_err or 'invalid_budget'}:{label}")
            budgets_ok = False
        else:
            seen_budgets.add(bt)

        tid, cid = _clean_text(raw.get("task_id")), _clean_text(raw.get("pass_criterion_id"))
        if not tid:
            violations.append(f"missing_task_id:{label}")
            criteria_ok = False
        elif not cid:
            violations.append(f"missing_pass_criterion_id:{label}")
            criteria_ok = False
        else:
            task_criteria.setdefault(tid, set()).add(cid)

    if len(seen_versions) > 1:
        violations.append("version_drift_across_runs")
        pinned_ok = False
    if len(seen_budgets) > 1:
        violations.append("budget_drift_across_runs")
        budgets_ok = False
    for tid in sorted(task_criteria):
        if len(task_criteria[tid]) > 1:
            violations.append(f"pass_criterion_drift:{tid}")
            criteria_ok = False
    if expected_arms is not None:
        if (missing := [a for a in expected_arms if a not in seen_arms]):
            violations.append(f"missing_expected_arms:{','.join(missing)}")

    ok = iso_ok and pinned_ok and budgets_ok and criteria_ok and not violations
    return {
        "ok": ok, "run_count": len(runs), "arms_observed": sorted(seen_arms),
        "isolated_workspaces_ok": iso_ok, "pinned_versions_ok": pinned_ok,
        "identical_budgets_ok": budgets_ok, "identical_pass_criteria_ok": criteria_ok,
        "violations": violations,
    }


def _select_tasks(task_count: int) -> list[dict[str, Any]]:
    tasks = [dict(t) for t in DEFAULT_BENCHMARK_TASKS[:task_count]]
    for idx in range(len(tasks) + 1, task_count + 1):
        tasks.append({
            "task_id": f"task_{idx:02d}", "title": f"Deterministic benchmark task {idx:02d}",
            "category": "general", "pass_criterion_id": f"criterion_{idx:02d}",
            "max_turns": int(_DEFAULT_BUDGET["max_turns"]), "timeout_s": float(_DEFAULT_BUDGET["timeout_s"]),
            "max_cost_usd": float(_DEFAULT_BUDGET["max_cost_usd"]),
        })
    return tasks


def plan_isolated_campaign(
    tier: str, *, harness_id: str = "claude", model_id: str = "claude-sonnet-4-6",
    harness_build_id: str = "unavailable", task_count: int | None = None, repeats: int | None = None,
    max_budget_usd: float | None = None, est_run_cost_usd: float | None = None,
    observed_cost_sd_usd: float | None = None, target_ci_half_width_usd: float | None = None,
    workspace_parent: Path | None = None,
) -> dict[str, Any]:
    """Build a deterministic isolated evaluation plan without spawning live models or network I/O."""
    matrix = plan_evaluation_matrix(
        tier, task_count=task_count, repeats=repeats, max_budget_usd=max_budget_usd,
        est_run_cost_usd=est_run_cost_usd, observed_cost_sd_usd=observed_cost_sd_usd,
        target_ci_half_width_usd=target_ci_half_width_usd,
    )
    clean_harness = _clean_text(harness_id).lower() or "claude"
    clean_model = _clean_text(model_id) or "claude-sonnet-4-6"
    clean_build = _clean_text(harness_build_id) or "unavailable"
    env_meta = collect_environment_metadata(clean_harness, model_id=clean_model, harness_build_id=clean_build, runtime_cfg={})
    cg_ver, total_runs = env_meta["context_guard_version"], int(matrix["total_runs"])
    per_run_cap = round(float(max_budget_usd) / max(1, total_runs), 6) if max_budget_usd is not None else float(_DEFAULT_BUDGET["max_cost_usd"])
    budget = {"max_turns": int(_DEFAULT_BUDGET["max_turns"]), "timeout_s": float(_DEFAULT_BUDGET["timeout_s"]), "max_cost_usd": per_run_cap}
    campaign_id = f"{tier}_{clean_harness}_{int(matrix['tasks'])}x{len(matrix['arms'])}x{int(matrix['repeats'])}"
    tasks = _select_tasks(int(matrix["tasks"]))
    ws_base = Path(workspace_parent).resolve() if workspace_parent is not None else None
    run_specs: list[dict[str, Any]] = []
    for task in tasks:
        tid = str(task["task_id"])
        for arm in matrix["arms"]:
            for rep in range(int(matrix["repeats"])):
                run_id = f"{clean_harness}_{arm}_{tid}_r{rep}"
                ws_rel = f"{arm}/{tid}/r{rep}"
                ws_id = "ws_" + hashlib.sha256(f"{campaign_id}:{run_id}".encode("utf-8")).hexdigest()[:16]
                run_specs.append({
                    "run_id": run_id, "task_id": tid, "task_title": task["title"], "category": task["category"],
                    "pass_criterion_id": task["pass_criterion_id"], "arm": arm, "repeat_idx": rep,
                    "harness_id": clean_harness, "harness": clean_harness, "harness_build_id": clean_build,
                    "model_id": clean_model, "context_guard_version": cg_ver, "workspace_id": ws_id,
                    "workspace_rel": ws_rel, "isolated_workspace": str(ws_base / ws_rel) if ws_base is not None else ws_rel,
                    "budget": dict(budget), **budget,
                })
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION, "campaign_id": campaign_id, "tier": tier,
        "gate_role": matrix["gate_role"], "statistical_proof": bool(matrix["statistical_proof"]),
        "network_executed": False, "subprocesses_spawned": 0, "environment": env_meta, "matrix": matrix,
        "budget_contract": {**budget, "max_campaign_budget_usd": max_budget_usd, "total_runs": total_runs},
        "arms": list(matrix["arms"]), "tasks": tasks, "run_specs": run_specs, "total_runs": len(run_specs),
    }


def _trajectory_claim_for(tier: str, stat_proof: bool) -> str:
    if tier == "offline_replay":
        return _OFFLINE_CLAIM
    if tier == "small_live_pilot":
        return _PILOT_CLAIM
    return _RELEASE_CLAIM if stat_proof else _UNVERIFIED_RELEASE_CLAIM


def _derive_budget_contract(runs: Sequence[Mapping[str, Any]], explicit: Mapping[str, Any] | None) -> dict[str, Any]:
    if explicit is not None:
        return dict(explicit)
    if runs and isinstance(runs[0], Mapping):
        parsed, _ = _parse_budget_tuple(runs[0])
        if parsed is not None:
            return {"max_turns": parsed[0], "timeout_s": parsed[1], "max_cost_usd": parsed[2], "total_runs": len(runs)}
    return {"total_runs": len(runs)}


def evaluate_campaign_runs(
    runs: Sequence[Mapping[str, Any]], *, campaign_id: str, tier: str, harness_id: str,
    harness_build_id: str = "unavailable", model_id: str = "unknown",
    runtime_cfg: Mapping[str, Any] | None = None, runtime_verifications: Mapping[str, str] | None = None,
    budget_contract: Mapping[str, Any] | None = None, seed: int = 42, bootstrap_iters: int = 1000,
    run_cursor_gate: bool = False,
) -> EvidenceContractV1:
    """Verify controls and compute EvidenceContractV1 metrics for a set of campaign runs."""
    if tier not in VALID_EVAL_TIERS:
        raise ValueError(f"Unsupported evaluation tier: {tier!r}")
    clean_harness = _clean_text(harness_id).lower() or "unknown"
    clean_build = _clean_text(harness_build_id) or "unavailable"
    clean_model = _clean_text(model_id) or "unknown"
    env_meta = collect_environment_metadata(
        clean_harness, model_id=clean_model, harness_build_id=clean_build,
        runtime_cfg=runtime_cfg, runtime_verifications=runtime_verifications,
    )
    by_arm: dict[str, list[Mapping[str, Any]]] = {}
    for raw in runs:
        if isinstance(raw, Mapping):
            by_arm.setdefault(_clean_text(raw.get("arm")) or "unknown", []).append(raw)
    arms = list(by_arm.keys()) or (["baseline", "context_guard"] if tier != "release_evaluation" else ["baseline", "context_guard", "context_guard_rtk"])
    controls = verify_campaign_controls(runs, expected_arms=arms if len(by_arm) >= 2 else None)
    arm_summaries = {a: compute_arm_summary(a, by_arm.get(a, ()), seed=seed, bootstrap_iters=bootstrap_iters) for a in arms}
    cursor_gate = run_cursor_cli_conformance() if (clean_harness == "cursor" and run_cursor_gate) else None
    cursor_ok = True if cursor_gate is None else bool(cursor_gate.get("admitted"))

    paired_comparisons: list[dict[str, Any]] = []
    if len(by_arm) >= 2:
        base_arm = "baseline" if "baseline" in by_arm else arms[0]
        for treat_arm in arms:
            if treat_arm == base_arm:
                continue
            cmp_res = compute_paired_comparison(base_arm, treat_arm, by_arm[base_arm], by_arm[treat_arm], seed=seed, bootstrap_iters=bootstrap_iters)
            if not cursor_ok:
                cmp_res["comparisons_blocked"] = True
            paired_comparisons.append(cmp_res)

    disclosed = [item for a in arms for item in (arm_summaries[a].get("disclosed_failures") or ())]
    viol_count = sum(len(arm_summaries[a].get("contract_violations") or ()) for a in arms)
    all_defined = bool(runs) and all(arm_summaries[a].get("cost_per_passed_run_status") == "defined" for a in arms)
    stat_proof = (tier == "release_evaluation" and bool(controls["ok"]) and len(by_arm) >= 2 and all_defined and viol_count == 0 and cursor_ok)
    uncertainty = {
        "statistical_proof": stat_proof, "method": "wilson_95_and_task_cluster_bootstrap",
        "per_arm": {a: {k: arm_summaries[a][k] for k in ("pass_rate_ci_95", "pass_rate_cluster_ci_95", "cost_per_passed_run_ci_95")} for a in arms},
        "paired_deltas": [{"baseline_arm": p["baseline_arm"], "treatment_arm": p["treatment_arm"], "cost_per_passed_run_delta_ci_95": p["unconditional"]["cost_per_passed_run_delta_ci_95"]} for p in paired_comparisons],
    }
    verdict_ok = bool(controls["ok"]) and bool(runs) and cursor_ok and all_defined and viol_count == 0
    verdict: dict[str, Any] = {
        "ok": verdict_ok, "tier": tier, "statistical_proof": stat_proof, "controls": controls,
        "all_arms_defined": all_defined, "contract_violation_count": viol_count,
    }
    if cursor_gate is not None:
        verdict["cursor_conformance"] = cursor_gate
    return EvidenceContractV1(
        schema_version=EVIDENCE_SCHEMA_VERSION, campaign_id=str(campaign_id), tier=tier, generated_at=_utc_now_iso_z(),
        statistical_proof=stat_proof, trajectory_claim=_trajectory_claim_for(tier, stat_proof), environment=env_meta,
        arms=arms, budget_contract=_derive_budget_contract(runs, budget_contract), arm_summaries=arm_summaries,
        paired_comparisons=paired_comparisons, disclosed_failures=disclosed, uncertainty_bounds=uncertainty, gate_verdict=verdict,
    )


def run_offline_evidence_replay(
    *, harness_id: str = "claude", model_id: str = "claude-sonnet-4-6",
    harness_build_id: str = "offline-replay", seed: int = 42,
) -> EvidenceContractV1:
    """Execute isolated offline replay, spool/ledger roundtrip, and Cursor conformance into EvidenceContractV1."""
    clean_harness = _clean_text(harness_id).lower() or "claude"
    clean_model = _clean_text(model_id) or "claude-sonnet-4-6"
    clean_build = _clean_text(harness_build_id) or "offline-replay"
    eff_seed = int(seed)

    with tempfile.TemporaryDirectory(prefix="cg_offline_ev_") as td:
        root = Path(td).resolve()
        ws_dir, spool_dir, cursor_dir = root / "workspace", root / "spool", root / "cursor_conf"
        ledger_path = root / "evidence" / DEFAULT_EVENT_LEDGER_FILENAME
        ws_dir.mkdir(parents=True, exist_ok=True)
        replay_res = run_deterministic_replay()
        bench_res = run_deterministic_benchmark(iterations=2)
        big_output = "\n".join(f"offline_line_{idx:04d}: " + ("a" * 72) for idx in range(240)) + "\n"
        receipts_path = receipts_path_for(spool_dir)
        spooled = spool_tool_output(
            big_output, session_id="offline_replay_01", call_id="call_replay_01", harness=clean_harness,
            tool_name="Bash", workspace_root=ws_dir, isolation="workspace", spool_dir=spool_dir,
            receipts_path=receipts_path, max_spool_entry_bytes=1_048_576, turn_correlation="harness_native",
        )
        if spooled is not None:
            slice_res = slice_spool(
                spooled[0].spool_id, start_line=1, limit=40, workspace_root=ws_dir,
                session_id="offline_replay_01", isolation="workspace", harness=clean_harness,
                receipts_path=receipts_path, spool_dir=spool_dir, call_id="call_replay_slice_01",
            )
        else:
            slice_res = {"ok": False, "error": "spool_skipped"}
        ingest_res = ingest_context_receipts(ledger_path, receipts_path)
        derived_res = derive_outcomes_from_ledger(ledger_path)
        cursor_conf = run_cursor_cli_conformance(work_dir=cursor_dir)

    env_meta = collect_environment_metadata(clean_harness, model_id=clean_model, harness_build_id=clean_build, runtime_cfg={})
    cg_ver = env_meta["context_guard_version"]
    replay_ok, bench_ok = bool(replay_res.get("ok")), bool(bench_res.get("ok"))
    spool_ok = spooled is not None and bool(slice_res.get("ok"))
    totals = derived_res.get("totals") or {}
    ledger_ok = (
        bool(ingest_res.get("ok")) and bool(derived_res.get("ok"))
        and derived_res.get("completeness") == "complete"
        and int(totals.get("created", 0) or 0) >= 1 and int(totals.get("recoveries", 0) or 0) >= 1
        and int(derived_res.get("reliability_failures", 0) or 0) == 0
    )
    cursor_ok = (
        bool(cursor_conf.get("ok")) and bool(cursor_conf.get("admitted"))
        and cursor_conf.get("cache_attribution_status") == "excluded_missing_telemetry"
    )
    all_ok = replay_ok and bench_ok and spool_ok and ledger_ok and cursor_ok

    is_cursor = clean_harness == "cursor"
    slice_bytes = len(str(slice_res.get("content") or "").encode("utf-8")) if spool_ok else 0
    tasks = _select_tasks(6)
    synth_runs: list[dict[str, Any]] = []
    for t_idx, task in enumerate(tasks):
        tid = str(task["task_id"])
        for arm in ("baseline", "context_guard"):
            is_cg = arm == "context_guard"
            run_id = f"offline_{arm}_{tid}_r0"
            ws_id = "ws_" + hashlib.sha256(f"{run_id}:{eff_seed}".encode("utf-8")).hexdigest()[:16]
            rec: dict[str, Any] = {
                "run_id": run_id, "task_id": tid, "pass_criterion_id": task["pass_criterion_id"],
                "arm": arm, "repeat_idx": 0, "harness_id": clean_harness, "harness": clean_harness,
                "harness_build_id": clean_build, "model_id": clean_model, "context_guard_version": cg_ver,
                "workspace_id": ws_id, "isolated_workspace": f"offline_isolated/{arm}/{tid}",
                "budget": dict(_DEFAULT_BUDGET), "outcome_class": "passed" if all_ok else "failed_attempt",
                "passed": all_ok, "turns": (2 if is_cg else 4) + (t_idx % 2),
                "latency_ms": float((620 if is_cg else 940) + (t_idx * 45)),
                "cost_usd": round((0.021 if is_cg else 0.039) + (t_idx * 0.002), 6),
                "fresh_input_tokens": (900 if is_cg else 1850) + (t_idx * 60),
                "output_tokens": (220 if is_cg else 340) + (t_idx * 15),
                "cache_read_tokens": None if is_cursor else ((4200 if is_cg else 3100) + (t_idx * 80)),
                "cache_write_tokens": None if is_cursor else ((400 if is_cg else 650) + (t_idx * 20)),
                "ttl_cache_misses": 0, "reliability_failures": 0 if ledger_ok else 1,
                "recovery_calls": 1 if (is_cg and t_idx == 0 and spool_ok) else 0,
                "recovery_model_turns": 1 if (is_cg and t_idx == 0 and spool_ok) else 0,
                "unique_recovered_bytes": slice_bytes if (is_cg and t_idx == 0 and spool_ok) else 0,
                "total_recovered_bytes": slice_bytes if (is_cg and t_idx == 0 and spool_ok) else 0,
            }
            if is_cursor:
                rec["cache_attribution_status"] = "excluded_missing_telemetry"
            synth_runs.append(rec)

    report = evaluate_campaign_runs(
        synth_runs, campaign_id=f"offline_replay_{clean_harness}_s{eff_seed}", tier="offline_replay",
        harness_id=clean_harness, harness_build_id=clean_build, model_id=clean_model, runtime_cfg={},
        budget_contract={**_DEFAULT_BUDGET, "task_count": len(tasks), "repeats": 1, "total_runs": len(synth_runs)},
        seed=eff_seed, bootstrap_iters=200, run_cursor_gate=False,
    )
    report["environment"] = env_meta
    report["statistical_proof"] = False
    report["trajectory_claim"] = _OFFLINE_CLAIM
    report["gate_verdict"]["ok"] = bool(report["gate_verdict"]["ok"] and all_ok)
    report["gate_verdict"]["checks"] = {
        "deterministic_replay_ok": replay_ok, "deterministic_benchmark_ok": bench_ok,
        "spool_and_slice_ok": spool_ok, "durable_ledger_ok": ledger_ok, "cursor_conformance_ok": cursor_ok,
    }
    report["gate_verdict"]["ledger_outcomes"] = derived_res
    report["gate_verdict"]["cursor_conformance"] = cursor_conf
    report["gate_verdict"]["benchmark"] = {
        k: bench_res.get(k) for k in ("ok", "isolated", "measurement_scope", "iterations", "corpus_calls", "raw_bytes", "delivered_bytes", "saved_bytes", "saved_tokens", "savings_pct")
    }
    report["gate_verdict"]["replay"] = {
        "ok": replay_ok, "read_ledger_schema": replay_res.get("read_ledger_schema"),
        "outcomes_schema": replay_res.get("outcomes_schema"),
    }
    return report


def _run_in_workspace_base(
    plan: Mapping[str, Any], executor_fn: Callable[[Mapping[str, Any], Path], Mapping[str, Any]], ws_base: Path,
    *, runtime_cfg: Mapping[str, Any] | None, runtime_verifications: Mapping[str, str] | None,
    seed: int, bootstrap_iters: int,
) -> EvidenceContractV1:
    if check_unsafe_link(ws_base):
        raise OSError("unsafe_path: workspace_parent")
    campaign_id = _clean_text(plan.get("campaign_id")) or f"{plan['tier']}_campaign"
    camp_root = (ws_base / f"{campaign_id}_{uuid.uuid4().hex[:8]}").resolve()
    camp_root.mkdir(parents=True, exist_ok=False)
    allocated: list[Path] = []
    collected: list[dict[str, Any]] = []
    for idx, raw_spec in enumerate(plan["run_specs"]):
        if not isinstance(raw_spec, Mapping):
            raise ValueError(f"run_specs[{idx}] must be a mapping")
        run_id = _clean_text(raw_spec.get("run_id")) or f"run_{idx:04d}"
        run_ws = (camp_root / f"{idx:04d}_{run_id}").resolve()
        run_ws.mkdir(parents=True, exist_ok=False)
        for prev in allocated:
            if os.path.samefile(str(run_ws), str(prev)):
                raise RuntimeError(f"duplicate isolated workspace allocated for {run_id}")
        allocated.append(run_ws)

        env_root = camp_root / ".cg_env" / f"{idx:04d}"
        state_d, spool_d = env_root / "state", env_root / "spool"
        state_d.mkdir(parents=True, exist_ok=True)
        spool_d.mkdir(parents=True, exist_ok=True)
        cfg_p = env_root / "config.json"
        if not cfg_p.exists():
            cfg_p.write_text("{}", encoding="utf-8")
        iso_env = {
            "CONTEXT_GUARD_HOME": str(env_root), "CONTEXT_GUARD_STATE_DIR": str(state_d),
            "CONTEXT_GUARD_SPOOL_DIR": str(spool_d), "CONTEXT_GUARD_CONFIG_PATH": str(cfg_p),
            "CONTEXT_GUARD_WORKSPACE_ROOT": str(run_ws),
        }
        spec_copy: dict[str, Any] = {
            **dict(raw_spec), "isolated_workspace": str(run_ws),
            "workspace_id": "ws_" + hashlib.sha256(str(run_ws).encode("utf-8")).hexdigest()[:16],
            "isolated_env": iso_env,
        }
        saved_env = {k: os.environ.get(k) for k in _ISO_ENV_KEYS}
        try:
            os.environ.update(iso_env)
            raw_res = executor_fn(spec_copy, run_ws)
        finally:
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        if not isinstance(raw_res, Mapping):
            raise ValueError(f"executor_fn returned non-mapping for {run_id}")
        merged = {**spec_copy, **dict(raw_res)}
        merged.pop("isolated_env", None)
        collected.append(merged)

    first = collected[0]
    raw_env_in = plan.get("environment")
    env_in: Mapping[str, Any] = raw_env_in if isinstance(raw_env_in, Mapping) else {}
    eff_harness = _clean_text(env_in.get("harness_id") or first.get("harness_id")) or "claude"
    eff_build = _clean_text(env_in.get("harness_build_id") or first.get("harness_build_id")) or "unavailable"
    eff_model = _clean_text(env_in.get("model_id") or first.get("model_id")) or "unknown"
    raw_budget = plan.get("budget_contract")
    eff_budget: Mapping[str, Any] | None = raw_budget if isinstance(raw_budget, Mapping) else None
    return evaluate_campaign_runs(
        collected, campaign_id=campaign_id, tier=str(plan["tier"]), harness_id=eff_harness,
        harness_build_id=eff_build, model_id=eff_model, runtime_cfg=runtime_cfg,
        runtime_verifications=runtime_verifications, budget_contract=eff_budget,
        seed=seed, bootstrap_iters=bootstrap_iters, run_cursor_gate=(eff_harness == "cursor"),
    )


def execute_isolated_campaign(
    plan: Mapping[str, Any], executor_fn: Callable[[Mapping[str, Any], Path], Mapping[str, Any]],
    *, workspace_parent: Path | None = None, runtime_cfg: Mapping[str, Any] | None = None,
    runtime_verifications: Mapping[str, str] | None = None, seed: int = 42, bootstrap_iters: int = 1000,
) -> EvidenceContractV1:
    """Execute a planned campaign with a fresh isolated workspace directory per run."""
    if not isinstance(plan, Mapping) or plan.get("tier") not in VALID_EVAL_TIERS:
        raise ValueError("Invalid campaign plan or tier")
    run_specs = plan.get("run_specs")
    if not isinstance(run_specs, Sequence) or isinstance(run_specs, (str, bytes)) or not run_specs:
        raise ValueError("Campaign plan must contain non-empty run_specs")
    if workspace_parent is not None:
        ws_base = Path(workspace_parent)
        ws_base.mkdir(parents=True, exist_ok=True)
        return _run_in_workspace_base(
            plan, executor_fn, ws_base, runtime_cfg=runtime_cfg,
            runtime_verifications=runtime_verifications, seed=seed, bootstrap_iters=bootstrap_iters,
        )
    with tempfile.TemporaryDirectory(prefix="cg_campaign_") as td:
        return _run_in_workspace_base(
            plan, executor_fn, Path(td), runtime_cfg=runtime_cfg,
            runtime_verifications=runtime_verifications, seed=seed, bootstrap_iters=bootstrap_iters,
        )
