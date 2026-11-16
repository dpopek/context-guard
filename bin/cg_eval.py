#!/usr/bin/env python3
"""Unified CLI and Markdown/JSON renderer for the Context-Guard Evidence Engine."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import sys
from typing import Any, Mapping

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from evidence.ledger import (  # noqa: E402
    DEFAULT_EVENT_LEDGER_FILENAME,
    derive_outcomes_from_ledger,
    ingest_context_receipts,
    run_cursor_cli_conformance,
)
from evidence.runner import (  # noqa: E402
    evaluate_campaign_runs,
    plan_isolated_campaign,
    run_offline_evidence_replay,
)
from hooks.state_store import resolve_plugin_root  # noqa: E402
from policies.governor import replay_governor_decisions  # noqa: E402
from spool.receipts import atomic_write_bytes, check_unsafe_link, receipts_path_for  # noqa: E402


def _as_map(val: Any) -> Mapping[str, Any]:
    return val if isinstance(val, Mapping) else {}


def _fmt_usd(val: Any) -> str:
    return f"${float(val):.4f}" if isinstance(val, (int, float)) and not isinstance(val, bool) else "n/a"


def _fmt_pct(val: Any) -> str:
    return f"{float(val) * 100.0:.1f}%" if isinstance(val, (int, float)) and not isinstance(val, bool) else "n/a"


def _render_plan_markdown(plan: Mapping[str, Any]) -> str:
    matrix, env, budget = _as_map(plan.get("matrix")), _as_map(plan.get("environment")), _as_map(plan.get("budget_contract"))
    arms = ", ".join(f"`{a}`" for a in (plan.get("arms") or ())) or "_none_"
    lines = [
        f"# Context-Guard Evaluation Plan (`{plan.get('tier', '')}`)",
        "",
        f"- Campaign ID: `{plan.get('campaign_id', '')}` | Gate role: `{plan.get('gate_role', '')}` | Statistical proof: `{bool(plan.get('statistical_proof'))}`",
        f"- Harness: `{env.get('harness_id', '')}` (`{env.get('harness_build_id', 'unavailable')}`) | Model: `{env.get('model_id', '')}` | CG: `v{env.get('context_guard_version', 'unavailable')}`",
        f"- Matrix: `{matrix.get('tasks', 0)}` tasks x `{matrix.get('arm_count', 0)}` arms ({arms}) x `{matrix.get('repeats', 0)}` repeats = `{plan.get('total_runs', 0)}` isolated runs",
        f"- Budget per run: `max_turns={budget.get('max_turns')}`, `timeout_s={budget.get('timeout_s')}`, `max_cost_usd={budget.get('max_cost_usd')}`",
        f"- Network executed: `{bool(plan.get('network_executed', False))}` | Subprocesses spawned: `{int(plan.get('subprocesses_spawned', 0) or 0)}`",
    ]
    return "\n".join(lines) + "\n"


def _render_cursor_markdown(res: Mapping[str, Any]) -> str:
    checks = _as_map(res.get("checks"))
    lines = [
        "# Context-Guard Cursor CLI Conformance Gate",
        "",
        f"- Status: `{'PASS' if res.get('ok') else 'FAIL'}` | Admitted: `{bool(res.get('admitted'))}` | Comparisons blocked: `{bool(res.get('comparisons_blocked'))}`",
        f"- Cache attribution: `{res.get('cache_attribution_status', 'excluded_missing_telemetry')}` | Hook fingerprint: `{res.get('hook_config_fingerprint', '')}`",
        "",
        "| Check | Passed |",
        "|---|---|",
    ]
    for name, passed in checks.items():
        lines.append(f"| `{name}` | `{bool(passed)}` |")
    return "\n".join(lines) + "\n"


def _render_ledger_markdown(res: Mapping[str, Any]) -> str:
    totals = _as_map(res.get("totals"))
    lines = [
        "# Context-Guard Durable Evidence Ledger Verification",
        "",
        f"- OK: `{bool(res.get('ok'))}` | Completeness: `{res.get('completeness', 'unavailable')}` | Events: `{int(res.get('event_count', 0) or 0)}` | Corrupt lines: `{int(res.get('corrupt_source_lines', 0) or 0)}`",
        f"- Totals: `created={totals.get('created', 'unavailable')}`, `delivery_verified={totals.get('delivery_verified', 'unavailable')}`, `recoveries={totals.get('recoveries', 'unavailable')}`, `reliability_failures={res.get('reliability_failures', 0)}`",
    ]
    by_group = res.get("by_group")
    if isinstance(by_group, Mapping) and by_group:
        lines.extend(["", "| Group | Created | Verified | Recoveries | Reliability Failures |", "|---|---:|---:|---:|---:|"])
        for gkey, row in by_group.items():
            if isinstance(row, Mapping):
                lines.append(
                    f"| `{gkey}` | {int(row.get('created', 0) or 0)} | {int(row.get('delivery_verified', 0) or 0)} | "
                    f"{int(row.get('recoveries', 0) or 0)} | {int(row.get('reliability_failures', 0) or 0)} |"
                )
    return "\n".join(lines) + "\n"


def _render_governor_markdown(res: Mapping[str, Any]) -> str:
    gates = _as_map(res.get("gates"))
    lines = [
        "# Context-Guard Adaptive Governor Replay Check",
        "",
        f"- Status: `{'PASS' if res.get('ok') else 'FAIL'}` | Gates passed: `{int(res.get('checks_passed', 0) or 0)}/{int(res.get('checks_total', len(gates)) or 0)}`",
        "",
        "| Gate | Passed |",
        "|---|---|",
    ]
    for name, passed in gates.items():
        lines.append(f"| `{name}` | `{bool(passed)}` |")
    return "\n".join(lines) + "\n"


def render_evidence_markdown(report: Mapping[str, Any]) -> str:
    """Format an Evidence Engine contract, plan, conformance, governor, or ledger report as Markdown."""
    if "run_specs" in report and "matrix" in report:
        return _render_plan_markdown(report)
    if "admitted" in report and "checks" in report and report.get("harness_id") == "cursor":
        return _render_cursor_markdown(report)
    if "completeness" in report and "arm_summaries" not in report:
        return _render_ledger_markdown(report)
    if "gates" in report and "checks_passed" in report:
        return _render_governor_markdown(report)

    env = _as_map(report.get("environment"))
    verdict = _as_map(report.get("gate_verdict"))
    controls = _as_map(verdict.get("controls"))
    lines = [
        f"# Context-Guard Evidence Report (`{report.get('tier', 'unknown')}`)",
        "",
        f"- Campaign ID: `{report.get('campaign_id', '')}` | Generated: `{report.get('generated_at', '')}` | Statistical proof: `{bool(report.get('statistical_proof'))}`",
        f"- Trajectory claim: {report.get('trajectory_claim', '')}",
        (
            f"- Environment: `{env.get('harness_id', 'unknown')}` (`{env.get('harness_build_id', 'unavailable')}`) | "
            f"Model: `{env.get('model_id', 'unknown')}` | CG: `v{env.get('context_guard_version', 'unavailable')}` | "
            f"Attestation implies runtime verified: `{bool(env.get('attestation_key_implies_runtime_verified', False))}`"
        ),
        f"- Hook config fingerprint: `{env.get('hook_config_fingerprint', '')}`",
        "",
        "## Arm Summaries",
        "",
        "| Arm | Headline / Raw | Pass Rate (95% Wilson) | Cost / Passed Run (95% CI) | Total Cost | Cache Status | TTL Misses | Reliability Failures |",
        "|---|---:|---|---|---:|---|---:|---:|",
    ]
    arm_summaries = _as_map(report.get("arm_summaries"))
    for arm_name, s in arm_summaries.items():
        if not isinstance(s, Mapping):
            continue
        pr_ci, cp_ci = _as_map(s.get("pass_rate_ci_95")), _as_map(s.get("cost_per_passed_run_ci_95"))
        cppr_status = str(s.get("cost_per_passed_run_status") or "unavailable")
        cppr_str = _fmt_usd(s.get("cost_per_passed_run")) if cppr_status == "defined" else cppr_status
        ci_hi = "unbounded" if cp_ci.get("unbounded_high") else _fmt_usd(cp_ci.get("ci_95_high"))
        ci_str = f"[{_fmt_usd(cp_ci.get('ci_95_low'))}, {ci_hi}]"
        pr_str = f"{_fmt_pct(s.get('pass_rate'))} [{_fmt_pct(pr_ci.get('low'))}, {_fmt_pct(pr_ci.get('high'))}]"
        lines.append(
            f"| `{arm_name}` | {int(s.get('headline_runs', 0) or 0)}/{int(s.get('raw_runs', 0) or 0)} | {pr_str} | "
            f"{cppr_str} {ci_str} | {_fmt_usd(s.get('total_headline_cost_usd'))} | "
            f"`{s.get('cache_attribution_status', 'unavailable')}` | {int(s.get('ttl_cache_misses', 0) or 0)} | "
            f"{int(s.get('reliability_failures', 0) or 0)} |"
        )

    paired = report.get("paired_comparisons") or ()
    if paired:
        lines.extend(["", "## Paired Comparisons", ""])
        for cmp_item in paired:
            if not isinstance(cmp_item, Mapping):
                continue
            uncond = _as_map(cmp_item.get("unconditional"))
            cond = _as_map(cmp_item.get("paired_cost_on_shared_passes"))
            lines.append(
                f"- **`{cmp_item.get('baseline_arm')}` -> `{cmp_item.get('treatment_arm')}`** "
                f"(cache: `{cmp_item.get('cache_comparison_status')}`): "
                f"unconditional Cost/Pass delta `{_fmt_usd(uncond.get('cost_per_passed_run_delta_usd'))}`, "
                f"Pass Rate delta `{_fmt_pct(uncond.get('pass_rate_delta'))}`."
            )
            lines.append(
                f"  - Conditional shared-pass cost (`shared_pass_count={int(cond.get('shared_pass_count', 0) or 0)}`): "
                f"delta `{_fmt_usd(cond.get('mean_cost_delta_usd'))}` — _{cond.get('selection_bias_warning', '')}_"
            )

    lines.extend(["", "## Gate Verdict", ""])
    lines.append(
        f"- Gate OK: `{bool(verdict.get('ok'))}` | Controls OK: `{bool(controls.get('ok'))}` | "
        f"Disclosed failures: `{len(report.get('disclosed_failures') or ())}`"
    )
    raw_viols = controls.get("violations")
    if isinstance(raw_viols, (list, tuple)) and raw_viols:
        lines.append(f"- Control violations: `{', '.join(str(v) for v in raw_viols)}`")
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cg-eval", description="Context-Guard Evidence Engine CLI.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--offline-replay", action="store_true", help="Run isolated offline deterministic replay (default).")
    mode.add_argument("--pilot", action="store_true", help="Small live pilot tier (6x2x3=36) with --plan or --runs-file.")
    mode.add_argument("--release", action="store_true", help="Release evaluation tier (12-15x3x2=72-90) with --plan or --runs-file.")
    mode.add_argument("--cursor-conformance", action="store_true", help="Run isolated Cursor CLI hook conformance gate.")
    mode.add_argument("--ledger-verify", action="store_true", help="Verify/ingest durable event ledger and derive Outcomes v4.")
    mode.add_argument("--governor-check", action="store_true", help="Replay Adaptive Governor capability, breaker, and security invariants.")
    parser.add_argument("--plan", action="store_true", help="Emit isolated campaign plan without running external LLMs.")
    parser.add_argument("--runs-file", type=Path, default=None, help="JSON file of isolated campaign runs to evaluate.")
    parser.add_argument("--outcomes-baseline", type=Path, default=None, help="Optional Outcomes v4 JSON baseline for --ledger-verify.")
    parser.add_argument("--ledger-path", type=Path, default=None, help="Override evidence_events.json path for --ledger-verify.")
    parser.add_argument("--receipts-path", type=Path, default=None, help="Override receipts.jsonl path for --ledger-verify.")
    parser.add_argument("--harness", choices=("claude", "cursor", "antigravity", "codex"), default="claude", help="Target harness ID.")
    parser.add_argument("--model", default="claude-sonnet-4-6", help="Pinned model identifier.")
    parser.add_argument("--harness-build", default="unavailable", help="Pinned harness CLI build/version identifier.")
    parser.add_argument("--tasks", type=int, default=None, help="Task count override for --plan.")
    parser.add_argument("--repeats", type=int, default=None, help="Repeat count override for --plan.")
    parser.add_argument("--max-budget-usd", type=float, default=None, help="Max campaign USD budget cap for --plan.")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic RNG seed.")
    parser.add_argument("--output", type=Path, default=None, help="Atomically write report to file.")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    fmt.add_argument("--markdown", action="store_true", help="Emit Markdown output (default).")
    return parser


def _emit_error(code: str, detail: str, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"ok": False, "error": code, "detail": detail}))
    else:
        print(f"error: {detail}", file=sys.stderr)
    return 2


def _load_runs_file(path: Path) -> tuple[list[Mapping[str, Any]], dict[str, Any], str | None]:
    if check_unsafe_link(path.parent) or check_unsafe_link(path) or not path.is_file():
        return [], {}, "runs file does not exist or is an unsafe link"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [], {}, f"failed to parse runs file JSON: {exc}"
    if isinstance(parsed, list):
        if any(not isinstance(item, Mapping) for item in parsed):
            return [], {}, "runs file list entries must be JSON objects"
        return parsed, {}, None
    if isinstance(parsed, Mapping) and isinstance(parsed.get("runs"), list):
        raw_runs = parsed["runs"]
        if any(not isinstance(item, Mapping) for item in raw_runs):
            return [], {}, "runs file 'runs' entries must be JSON objects"
        return raw_runs, dict(parsed), None
    return [], {}, "runs file must be a JSON array or an object with a 'runs' list"


def _resolve_ledger_paths(ns: argparse.Namespace) -> tuple[Path, Path]:
    receipts_p = Path(ns.receipts_path) if ns.receipts_path is not None else receipts_path_for()
    if ns.ledger_path is not None:
        return Path(ns.ledger_path), receipts_p
    if ns.receipts_path is not None:
        return receipts_p.parent / DEFAULT_EVENT_LEDGER_FILENAME, receipts_p
    if (env_state := str(os.environ.get("CONTEXT_GUARD_STATE_DIR") or "").strip()):
        return Path(env_state) / DEFAULT_EVENT_LEDGER_FILENAME, receipts_p
    if str(os.environ.get("CONTEXT_GUARD_SPOOL_DIR") or "").strip():
        return receipts_p.parent / DEFAULT_EVENT_LEDGER_FILENAME, receipts_p
    return resolve_plugin_root() / "telemetry" / DEFAULT_EVENT_LEDGER_FILENAME, receipts_p


def _emit_report(report: Mapping[str, Any], ns: argparse.Namespace) -> int | None:
    rendered = (json.dumps(report, indent=2) + "\n") if ns.json else render_evidence_markdown(report)
    if ns.output is not None:
        out_p = Path(ns.output)
        if check_unsafe_link(out_p.parent) or check_unsafe_link(out_p) or (out_p.exists() and out_p.is_dir()):
            return _emit_error("unsafe_output_path", f"Refusing unsafe output path: {out_p}", bool(ns.json))
        out_p.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(out_p, rendered.encode("utf-8"))
    print(rendered, end="")
    return None


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `cg-eval` / `cg eval`."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv and raw_argv[0] == "eval":
        raw_argv = raw_argv[1:]
    wants_json = "--json" in raw_argv
    parser = _build_parser()
    try:
        ns = parser.parse_args(raw_argv)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        if wants_json:
            print(json.dumps({"ok": False, "error": "invalid_arguments"}))
        return 2

    as_json = bool(ns.json)
    if ns.tasks is not None and ns.tasks <= 0:
        return _emit_error("invalid_arguments", "--tasks must be >= 1", as_json)
    if ns.repeats is not None and ns.repeats <= 0:
        return _emit_error("invalid_arguments", "--repeats must be >= 1", as_json)
    if ns.max_budget_usd is not None and (not math.isfinite(float(ns.max_budget_usd)) or float(ns.max_budget_usd) < 0.0):
        return _emit_error("invalid_arguments", "--max-budget-usd must be finite and >= 0", as_json)

    if ns.cursor_conformance:
        if ns.runs_file is not None or ns.plan:
            return _emit_error("invalid_arguments", "--cursor-conformance cannot be combined with --plan or --runs-file", as_json)
        res = run_cursor_cli_conformance()
        if (err_rc := _emit_report(res, ns)) is not None:
            return err_rc
        return 0 if res.get("ok") else 1

    if ns.ledger_verify:
        if ns.runs_file is not None or ns.plan:
            return _emit_error("invalid_arguments", "--ledger-verify cannot be combined with --plan or --runs-file", as_json)
        if ns.outcomes_baseline is not None:
            ob_p = Path(ns.outcomes_baseline)
            if check_unsafe_link(ob_p.parent) or check_unsafe_link(ob_p) or not ob_p.is_file():
                return _emit_error("invalid_outcomes_baseline", f"Missing or unsafe outcomes baseline: {ob_p}", as_json)
        ledger_p, receipts_p = _resolve_ledger_paths(ns)
        ingest_res: dict[str, Any] | None = None
        if receipts_p.exists() or ns.outcomes_baseline is not None:
            ingest_res = ingest_context_receipts(ledger_p, receipts_p, outcomes_path=ns.outcomes_baseline)
        derived = derive_outcomes_from_ledger(ledger_p)
        if ingest_res is not None:
            derived["ingest"] = ingest_res
        if (err_rc := _emit_report(derived, ns)) is not None:
            return err_rc
        return 0 if derived.get("ok") else 1

    if ns.governor_check:
        if ns.runs_file is not None or ns.plan:
            return _emit_error("invalid_arguments", "--governor-check cannot be combined with --plan or --runs-file", as_json)
        res = replay_governor_decisions()
        if (err_rc := _emit_report(res, ns)) is not None:
            return err_rc
        return 0 if res.get("ok") else 1

    tier = "small_live_pilot" if ns.pilot else ("release_evaluation" if ns.release else "offline_replay")
    if ns.plan and ns.runs_file is not None:
        return _emit_error("invalid_arguments", "--plan and --runs-file are mutually exclusive", as_json)

    if ns.plan:
        try:
            plan = plan_isolated_campaign(
                tier, harness_id=ns.harness, model_id=ns.model, harness_build_id=ns.harness_build,
                task_count=ns.tasks, repeats=ns.repeats, max_budget_usd=ns.max_budget_usd,
            )
        except ValueError as exc:
            return _emit_error("invalid_arguments", str(exc), as_json)
        if (err_rc := _emit_report(plan, ns)) is not None:
            return err_rc
        return 0

    if ns.runs_file is not None:
        runs, meta, load_err = _load_runs_file(Path(ns.runs_file))
        if load_err is not None:
            return _emit_error("invalid_runs_file", load_err, as_json)
        eff_harness = str(meta.get("harness_id") or ns.harness)
        eff_model = str(meta.get("model_id") or ns.model)
        eff_build = str(meta.get("harness_build_id") or ns.harness_build)
        eff_cid = str(meta.get("campaign_id") or f"{tier}_{Path(ns.runs_file).stem}")
        bc = meta.get("budget_contract") if isinstance(meta.get("budget_contract"), Mapping) else None
        rt_cfg = meta.get("runtime_cfg") if isinstance(meta.get("runtime_cfg"), Mapping) else None
        rt_ver = meta.get("runtime_verifications") if isinstance(meta.get("runtime_verifications"), Mapping) else None
        report = evaluate_campaign_runs(
            runs, campaign_id=eff_cid, tier=tier, harness_id=eff_harness, harness_build_id=eff_build,
            model_id=eff_model, runtime_cfg=rt_cfg, runtime_verifications=rt_ver,
            budget_contract=bc, seed=int(ns.seed), run_cursor_gate=(eff_harness.lower() == "cursor"),
        )
        if (err_rc := _emit_report(report, ns)) is not None:
            return err_rc
        return 0 if report["gate_verdict"].get("ok") else 1

    if tier in ("small_live_pilot", "release_evaluation"):
        return _emit_error(
            "missing_plan_or_runs_file",
            f"--{'pilot' if ns.pilot else 'release'} requires --plan or --runs-file <path>; live LLM processes are not spawned automatically.",
            as_json,
        )

    offline_report = run_offline_evidence_replay(
        harness_id=ns.harness, model_id=ns.model, harness_build_id=ns.harness_build, seed=int(ns.seed),
    )
    if (err_rc := _emit_report(offline_report, ns)) is not None:
        return err_rc
    return 0 if offline_report["gate_verdict"].get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
