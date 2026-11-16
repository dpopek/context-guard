"""Unit, control, isolation, and CLI tests for the Evidence Engine runner and `cg eval`."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import subprocess
from typing import Any, Mapping

import pytest

from bin import cg, cg_eval
from evidence.ledger import DEFAULT_EVENT_LEDGER_FILENAME
from evidence.runner import (
    DEFAULT_BENCHMARK_TASKS,
    evaluate_campaign_runs,
    execute_isolated_campaign,
    plan_isolated_campaign,
    run_offline_evidence_replay,
    verify_campaign_controls,
)
from hooks import config as hooks_config, outcomes, post_tool_use
from policies.api import EVIDENCE_SCHEMA_VERSION, EvidenceContractV1
from policies.governor import is_optimizer_tripped, reset_circuit_breaker
from spool import receipts as spool_receipts
from spool.store import slice_spool

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def _manifest_version() -> str:
    return str(json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8"))["version"])


def _clean_run_record(
    *,
    run_id: str,
    task_id: str,
    arm: str,
    workspace_path: Path,
    pass_criterion_id: str = "criterion_01",
    repeat_idx: int = 0,
    harness_id: str = "claude",
    harness_build_id: str = "2.1.300",
    model_id: str = "claude-sonnet-4-6",
    context_guard_version: str | None = None,
    max_turns: int = 20,
    timeout_s: float = 300.0,
    max_cost_usd: float = 2.0,
    passed: bool = True,
    cost_usd: float = 0.05,
    turns: int = 3,
    cache_missing: bool = False,
) -> dict[str, Any]:
    cg_ver = context_guard_version if context_guard_version is not None else _manifest_version()
    rec: dict[str, Any] = {
        "run_id": run_id,
        "task_id": task_id,
        "pass_criterion_id": pass_criterion_id,
        "arm": arm,
        "repeat_idx": repeat_idx,
        "harness_id": harness_id,
        "harness": harness_id,
        "harness_build_id": harness_build_id,
        "model_id": model_id,
        "context_guard_version": cg_ver,
        "workspace_id": f"ws_{run_id}",
        "isolated_workspace": str(workspace_path),
        "budget": {"max_turns": max_turns, "timeout_s": timeout_s, "max_cost_usd": max_cost_usd},
        "outcome_class": "passed" if passed else "failed_attempt",
        "passed": passed,
        "turns": turns,
        "latency_ms": 850.0,
        "cost_usd": cost_usd,
        "fresh_input_tokens": 1200,
        "output_tokens": 250,
        "cache_read_tokens": None if cache_missing else 4000,
        "cache_write_tokens": None if cache_missing else 500,
        "ttl_cache_misses": 0,
        "reliability_failures": 0,
    }
    if cache_missing:
        rec["cache_attribution_status"] = "excluded_missing_telemetry"
    return rec


def test_default_benchmark_tasks_and_plan_isolated_campaign_matrices(tmp_path: Path) -> None:
    assert len(DEFAULT_BENCHMARK_TASKS) == 15
    assert [t["task_id"] for t in DEFAULT_BENCHMARK_TASKS] == [f"task_{i:02d}" for i in range(1, 16)]
    for task in DEFAULT_BENCHMARK_TASKS:
        assert {"task_id", "title", "category", "pass_criterion_id", "max_turns", "timeout_s", "max_cost_usd"} <= set(task)
        assert int(task["max_turns"]) > 0 and float(task["timeout_s"]) > 0.0 and float(task["max_cost_usd"]) >= 0.0

    pilot = plan_isolated_campaign("small_live_pilot", workspace_parent=tmp_path / "pilot_ws")
    assert pilot["tier"] == "small_live_pilot"
    assert pilot["statistical_proof"] is False
    assert pilot["network_executed"] is False
    assert pilot["subprocesses_spawned"] == 0
    assert pilot["total_runs"] == 36
    assert len(pilot["run_specs"]) == 36
    assert len({spec["isolated_workspace"] for spec in pilot["run_specs"]}) == 36
    assert len({spec["workspace_id"] for spec in pilot["run_specs"]}) == 36
    assert not (tmp_path / "pilot_ws").exists()

    release = plan_isolated_campaign("release_evaluation", task_count=15, max_budget_usd=90.0)
    assert release["tier"] == "release_evaluation"
    assert release["statistical_proof"] is True
    assert release["total_runs"] == 90
    assert release["budget_contract"]["max_cost_usd"] == pytest.approx(1.0)


def test_offline_evidence_replay_is_isolated_deterministic_and_non_causal(tmp_path: Path) -> None:
    rep_a = run_offline_evidence_replay(seed=77)
    rep_b = run_offline_evidence_replay(seed=77)
    assert rep_a["schema_version"] == EVIDENCE_SCHEMA_VERSION
    assert rep_a["tier"] == "offline_replay"
    assert rep_a["statistical_proof"] is False
    assert "does NOT prove live model trajectories" in rep_a["trajectory_claim"]
    assert rep_a["arms"] == ["baseline", "context_guard"]
    assert rep_a["environment"]["context_guard_version"] == _manifest_version()
    assert rep_a["environment"]["attestation_key_implies_runtime_verified"] is False
    assert rep_a["gate_verdict"]["ok"] is True
    assert rep_a["gate_verdict"]["controls"]["ok"] is True
    checks = rep_a["gate_verdict"]["checks"]
    assert checks == {
        "deterministic_replay_ok": True,
        "deterministic_benchmark_ok": True,
        "spool_and_slice_ok": True,
        "durable_ledger_ok": True,
        "cursor_conformance_ok": True,
        "governor_replay_ok": True,
    }
    assert rep_a["gate_verdict"]["governor_replay"]["ok"] is True
    assert rep_a["gate_verdict"]["governor_replay"]["checks_passed"] == 8
    assert rep_a["gate_verdict"]["ledger_outcomes"]["completeness"] == "complete"
    assert rep_a["gate_verdict"]["ledger_outcomes"]["totals"]["created"] >= 1
    assert rep_a["gate_verdict"]["ledger_outcomes"]["totals"]["recoveries"] >= 1
    assert rep_a["gate_verdict"]["cursor_conformance"]["admitted"] is True
    assert rep_a["gate_verdict"]["cursor_conformance"]["cache_attribution_status"] == "excluded_missing_telemetry"

    cmp_a = {k: v for k, v in rep_a.items() if k != "generated_at"}
    cmp_b = {k: v for k, v in rep_b.items() if k != "generated_at"}
    assert cmp_a == cmp_b
    assert not list(tmp_path.iterdir())


def test_verify_campaign_controls_rejects_shared_workspace_unpinned_versions_and_budget_drift(tmp_path: Path) -> None:
    ws_b = tmp_path / "ws_base"
    ws_t = tmp_path / "ws_treat"
    ws_b.mkdir()
    ws_t.mkdir()

    clean_runs = [
        _clean_run_record(run_id="r1", task_id="task_01", arm="baseline", workspace_path=ws_b),
        _clean_run_record(run_id="r2", task_id="task_01", arm="context_guard", workspace_path=ws_t),
    ]
    ok_verdict = verify_campaign_controls(clean_runs, expected_arms=("baseline", "context_guard"))
    assert ok_verdict["ok"] is True
    assert ok_verdict["isolated_workspaces_ok"] is True
    assert ok_verdict["pinned_versions_ok"] is True
    assert ok_verdict["identical_budgets_ok"] is True
    assert ok_verdict["identical_pass_criteria_ok"] is True
    assert ok_verdict["violations"] == []

    shared_ws_runs = [
        _clean_run_record(run_id="r1", task_id="task_01", arm="baseline", workspace_path=ws_b),
        _clean_run_record(run_id="r2", task_id="task_01", arm="context_guard", workspace_path=ws_b),
    ]
    shared_ws_runs[1]["workspace_id"] = "ws_r2_diff_id"
    v_ws = verify_campaign_controls(shared_ws_runs)
    assert v_ws["ok"] is False
    assert v_ws["isolated_workspaces_ok"] is False
    assert any("shared_workspace_path" in v for v in v_ws["violations"])

    if os.name != "nt":
        sym_ws = tmp_path / "ws_sym"
        sym_ws.symlink_to(ws_b)
        sym_runs = [
            _clean_run_record(run_id="r1", task_id="task_01", arm="baseline", workspace_path=ws_b),
            _clean_run_record(run_id="r2", task_id="task_01", arm="context_guard", workspace_path=sym_ws),
        ]
        v_sym = verify_campaign_controls(sym_runs)
        assert v_sym["ok"] is False and v_sym["isolated_workspaces_ok"] is False

    unpinned_runs = [
        _clean_run_record(run_id="r1", task_id="task_01", arm="baseline", workspace_path=ws_b, model_id="claude-sonnet-4-6"),
        _clean_run_record(run_id="r2", task_id="task_01", arm="context_guard", workspace_path=ws_t, model_id="claude-opus-4-6"),
    ]
    v_ver = verify_campaign_controls(unpinned_runs)
    assert v_ver["ok"] is False and v_ver["pinned_versions_ok"] is False
    assert "version_drift_across_runs" in v_ver["violations"]

    sentinel_runs = [
        _clean_run_record(run_id="r1", task_id="task_01", arm="baseline", workspace_path=ws_b, harness_build_id="latest"),
        _clean_run_record(run_id="r2", task_id="task_01", arm="context_guard", workspace_path=ws_t, harness_build_id="latest"),
    ]
    v_sent = verify_campaign_controls(sentinel_runs)
    assert v_sent["ok"] is False and v_sent["pinned_versions_ok"] is False

    budget_drift_runs = [
        _clean_run_record(run_id="r1", task_id="task_01", arm="baseline", workspace_path=ws_b, max_turns=20),
        _clean_run_record(run_id="r2", task_id="task_01", arm="context_guard", workspace_path=ws_t, max_turns=30),
    ]
    v_bud = verify_campaign_controls(budget_drift_runs)
    assert v_bud["ok"] is False and v_bud["identical_budgets_ok"] is False
    assert "budget_drift_across_runs" in v_bud["violations"]

    crit_drift_runs = [
        _clean_run_record(run_id="r1", task_id="task_01", arm="baseline", workspace_path=ws_b, pass_criterion_id="criterion_01"),
        _clean_run_record(run_id="r2", task_id="task_01", arm="context_guard", workspace_path=ws_t, pass_criterion_id="criterion_other"),
    ]
    v_crit = verify_campaign_controls(crit_drift_runs)
    assert v_crit["ok"] is False and v_crit["identical_pass_criteria_ok"] is False
    assert "pass_criterion_drift:task_01" in v_crit["violations"]

    empty_verdict = verify_campaign_controls([])
    assert empty_verdict["ok"] is False and "no_runs_provided" in empty_verdict["violations"]


def test_execute_isolated_campaign_allocates_distinct_workspaces_per_run(tmp_path: Path) -> None:
    plan = plan_isolated_campaign(
        "small_live_pilot",
        harness_id="claude",
        model_id="claude-sonnet-4-6",
        harness_build_id="2.1.300",
        task_count=2,
        repeats=2,
    )
    assert plan["total_runs"] == 8

    seen_dirs: list[Path] = []
    seen_state_dirs: list[str] = []

    def _fake_executor(run_spec: Mapping[str, Any], run_ws: Path) -> Mapping[str, Any]:
        assert run_ws.is_dir()
        assert Path(run_spec["isolated_workspace"]) == run_ws
        assert os.environ.get("CONTEXT_GUARD_WORKSPACE_ROOT") == str(run_ws)
        iso_state = os.environ.get("CONTEXT_GUARD_STATE_DIR", "")
        assert iso_state and Path(iso_state).is_dir()
        seen_state_dirs.append(iso_state)
        marker = run_ws / "run_marker.txt"
        assert not marker.exists()
        marker.write_text(str(run_spec["run_id"]), encoding="utf-8")
        seen_dirs.append(run_ws)
        is_cg = run_spec["arm"] == "context_guard"
        return {
            "outcome_class": "passed",
            "passed": True,
            "turns": 2 if is_cg else 4,
            "cost_usd": 0.04 if is_cg else 0.08,
            "latency_ms": 600.0 if is_cg else 900.0,
            "fresh_input_tokens": 900 if is_cg else 1800,
            "output_tokens": 200 if is_cg else 350,
            "cache_read_tokens": 4500 if is_cg else 3000,
            "cache_write_tokens": 300 if is_cg else 600,
        }

    report: EvidenceContractV1 = execute_isolated_campaign(
        plan, _fake_executor, workspace_parent=tmp_path / "campaigns", seed=19, bootstrap_iters=200
    )
    assert len(seen_dirs) == 8
    assert len({os.path.realpath(str(p)) for p in seen_dirs}) == 8
    assert len(set(seen_state_dirs)) == 8
    for i, p1 in enumerate(seen_dirs):
        for p2 in seen_dirs[i + 1 :]:
            assert not os.path.samefile(str(p1), str(p2))
    assert report["tier"] == "small_live_pilot"
    assert report["statistical_proof"] is False
    assert report["gate_verdict"]["ok"] is True
    assert report["gate_verdict"]["controls"]["ok"] is True
    assert report["arm_summaries"]["baseline"]["cost_per_passed_run"] == pytest.approx(0.08)
    assert report["arm_summaries"]["context_guard"]["cost_per_passed_run"] == pytest.approx(0.04)
    assert report["paired_comparisons"][0]["unconditional"]["cost_per_passed_run_delta_usd"] == pytest.approx(-0.04)


def test_evaluate_campaign_runs_cursor_gate_and_release_statistical_proof(tmp_path: Path) -> None:
    runs: list[dict[str, Any]] = []
    for idx in range(1, 5):
        tid = f"task_{idx:02d}"
        for arm in ("baseline", "context_guard"):
            ws_dir = tmp_path / "cu_ws" / arm / tid
            ws_dir.mkdir(parents=True)
            runs.append(
                _clean_run_record(
                    run_id=f"cu_{arm}_{tid}",
                    task_id=tid,
                    arm=arm,
                    workspace_path=ws_dir,
                    pass_criterion_id=f"criterion_{idx:02d}",
                    harness_id="cursor",
                    harness_build_id="1.2.3",
                    cost_usd=0.05 if arm == "context_guard" else 0.09,
                    cache_missing=True,
                )
            )
    rel_cursor = evaluate_campaign_runs(
        runs,
        campaign_id="cursor_rel_01",
        tier="release_evaluation",
        harness_id="cursor",
        harness_build_id="1.2.3",
        model_id="claude-sonnet-4-6",
        bootstrap_iters=200,
        run_cursor_gate=True,
    )
    assert rel_cursor["statistical_proof"] is True
    assert rel_cursor["gate_verdict"]["ok"] is True
    assert rel_cursor["gate_verdict"]["cursor_conformance"]["admitted"] is True
    assert rel_cursor["paired_comparisons"][0]["comparisons_blocked"] is False
    assert rel_cursor["paired_comparisons"][0]["cache_comparison_status"] == "excluded_missing_telemetry"


def test_cg_eval_cli_offline_pilot_plan_and_runs_file_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cg_eval.main(["--offline-replay", "--json"]) == 0
    offline_data = json.loads(capsys.readouterr().out)
    assert offline_data["tier"] == "offline_replay"
    assert offline_data["statistical_proof"] is False
    assert offline_data["gate_verdict"]["ok"] is True

    assert cg_eval.main(["--pilot", "--plan", "--json"]) == 0
    pilot_plan = json.loads(capsys.readouterr().out)
    assert pilot_plan["tier"] == "small_live_pilot" and pilot_plan["total_runs"] == 36

    assert cg_eval.main(["--release", "--plan", "--tasks", "12", "--json"]) == 0
    rel_plan = json.loads(capsys.readouterr().out)
    assert rel_plan["tier"] == "release_evaluation" and rel_plan["total_runs"] == 72

    assert cg_eval.main(["--pilot", "--json"]) == 2
    err_pilot = json.loads(capsys.readouterr().out)
    assert err_pilot["ok"] is False and err_pilot["error"] == "missing_plan_or_runs_file"

    assert cg_eval.main(["--release"]) == 2
    assert "requires --plan or --runs-file" in capsys.readouterr().err

    assert cg_eval.main(["--pilot", "--runs-file", str(tmp_path / "missing.json"), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_runs_file"

    bad_json = tmp_path / "corrupt.json"
    bad_json.write_text("{not valid json", encoding="utf-8")
    assert cg_eval.main(["--pilot", "--runs-file", str(bad_json)]) == 2
    assert "failed to parse runs file" in capsys.readouterr().err

    ws1, ws2 = tmp_path / "r_ws_1", tmp_path / "r_ws_2"
    ws1.mkdir()
    ws2.mkdir()
    good_runs_path = tmp_path / "valid_runs.json"
    good_runs_path.write_text(
        json.dumps({
            "campaign_id": "cli_pilot_01",
            "harness_id": "claude",
            "harness_build_id": "2.1.300",
            "model_id": "claude-sonnet-4-6",
            "runs": [
                _clean_run_record(run_id="r1", task_id="task_01", arm="baseline", workspace_path=ws1, cost_usd=0.08),
                _clean_run_record(run_id="r2", task_id="task_01", arm="context_guard", workspace_path=ws2, cost_usd=0.04),
            ],
        }),
        encoding="utf-8",
    )
    assert cg.main(["eval", "--pilot", "--runs-file", str(good_runs_path), "--json"]) == 0
    evaluated = json.loads(capsys.readouterr().out)
    assert evaluated["gate_verdict"]["ok"] is True
    assert evaluated["arm_summaries"]["context_guard"]["cost_per_passed_run"] == pytest.approx(0.04)

    drift_runs_path = tmp_path / "drift_runs.json"
    drift_runs_path.write_text(
        json.dumps([
            _clean_run_record(run_id="r1", task_id="task_01", arm="baseline", workspace_path=ws1),
            _clean_run_record(run_id="r2", task_id="task_01", arm="context_guard", workspace_path=ws1),
        ]),
        encoding="utf-8",
    )
    assert cg_eval.main(["--pilot", "--runs-file", str(drift_runs_path), "--json"]) == 1
    drift_out = json.loads(capsys.readouterr().out)
    assert drift_out["gate_verdict"]["ok"] is False
    assert drift_out["gate_verdict"]["controls"]["isolated_workspaces_ok"] is False


def test_cg_eval_cli_enforces_zero_network_and_subprocess_free_offline_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(tmp_path / "empty_spool"))
    monkeypatch.delenv("CONTEXT_GUARD_STATE_DIR", raising=False)
    def _deny_network(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("network socket access is forbidden in cg-eval offline modes")

    monkeypatch.setattr(socket, "create_connection", _deny_network)
    monkeypatch.setattr(socket.socket, "connect", _deny_network)

    spawned_cmds: list[list[str]] = []
    real_run = subprocess.run

    def _spy_subprocess_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
        cmd_list = [str(part) for part in cmd] if isinstance(cmd, (list, tuple)) else [str(cmd)]
        spawned_cmds.append(cmd_list)
        if not (len(cmd_list) >= 2 and Path(cmd_list[1]).name == "pre_tool_use.py"):
            raise AssertionError(f"forbidden external subprocess spawned: {cmd_list}")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", _spy_subprocess_run)

    for args in (
        ["--pilot", "--plan", "--json"],
        ["--release", "--plan", "--json"],
        ["--cursor-conformance", "--json"],
        ["--ledger-verify", "--json"],
    ):
        assert cg_eval.main(args) == 0
        capsys.readouterr()
    assert spawned_cmds == []

    assert cg_eval.main(["--offline-replay", "--json"]) == 0
    replay_json = json.loads(capsys.readouterr().out)
    assert replay_json["gate_verdict"]["ok"] is True
    assert len(spawned_cmds) >= 1
    for cmd in spawned_cmds:
        assert Path(cmd[1]).name == "pre_tool_use.py"
        joined = " ".join(cmd)
        assert not any(ext in joined for ext in ("curl", "wget", "rtk", "codex"))
        assert not Path(cmd[0]).name.startswith(("claude", "cursor"))


def test_cg_eval_cli_cursor_conformance_ledger_verify_and_atomic_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    spool_dir = tmp_path / "spool"
    spool_dir.mkdir()
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))
    monkeypatch.delenv("CONTEXT_GUARD_STATE_DIR", raising=False)

    assert cg_eval.main(["--ledger-verify", "--json"]) == 0
    unavail = json.loads(capsys.readouterr().out)
    assert unavail["completeness"] == "unavailable" and unavail["totals"] is None

    rcpt = spool_receipts.build_receipt(
        event_type="spool_created", harness="claude", session_id="s_cli", workspace_id="ws_0123456789abcdef",
        turn_key="s_cli:step:1", call_id="c_01", spool_id="sp_000000000010", line_span=(0, 120),
        byte_span=(0, 8192), delivery_evidence="replacement_emitted", spool_id_referenced=False,
        timestamp="2026-11-16T12:00:00Z",
    )
    spool_receipts.append_receipt(rcpt, receipts_path=spool_dir / "receipts.jsonl")
    out_base = tmp_path / "outcomes.json"
    outcomes.record_direct_outcome("claude", "claude-sonnet-4-6", "outline", "applied", out_base)

    out_report = tmp_path / "out" / "ledger.json"
    assert cg_eval.main([
        "--ledger-verify", "--outcomes-baseline", str(out_base), "--output", str(out_report), "--json"
    ]) == 0
    capsys.readouterr()
    assert out_report.is_file()
    persisted = json.loads(out_report.read_text(encoding="utf-8"))
    assert persisted["completeness"] == "migrated_with_baseline"
    assert persisted["totals"]["created"] == 1
    assert (spool_dir / DEFAULT_EVENT_LEDGER_FILENAME).is_file()

    assert cg_eval.main(["--ledger-verify", "--outcomes-baseline", str(tmp_path / "missing_base.json")]) == 2
    capsys.readouterr()

    out_md = tmp_path / "out" / "cursor.md"
    assert cg_eval.main(["--cursor-conformance", "--markdown", "--output", str(out_md)]) == 0
    stdout_md = capsys.readouterr().out
    assert "# Context-Guard Cursor CLI Conformance Gate" in stdout_md
    assert out_md.read_text(encoding="utf-8") == stdout_md

    if os.name != "nt":
        sym_out = tmp_path / "sym_out.json"
        sym_out.symlink_to(tmp_path / "target.json")
        assert cg_eval.main(["--pilot", "--plan", "--output", str(sym_out), "--json"]) == 2
        assert json.loads(capsys.readouterr().out)["error"] == "unsafe_output_path"

    assert cg_eval.main(["--tasks", "0", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_arguments"


def test_cg_eval_markdown_renderer_covers_reports_plans_and_gates() -> None:
    report = run_offline_evidence_replay(seed=11)
    md = cg_eval.render_evidence_markdown(report)
    assert "# Context-Guard Evidence Report (`offline_replay`)" in md
    assert "does NOT prove live model trajectories" in md
    assert "Attestation implies runtime verified: `False`" in md
    assert "Conditional shared-pass cost" in md
    assert "Gate OK: `True`" in md

    plan = plan_isolated_campaign("small_live_pilot")
    plan_md = cg_eval.render_evidence_markdown(plan)
    assert "# Context-Guard Evaluation Plan (`small_live_pilot`)" in plan_md
    assert "36` isolated runs" in plan_md


def test_cg_eval_governor_check_cli_json_and_markdown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cg.main(["eval", "--governor-check", "--json"]) == 0
    gov_json = json.loads(capsys.readouterr().out)
    assert gov_json["ok"] is True and gov_json["checks_passed"] == 8 and gov_json["checks_total"] == 8
    assert all(gov_json["gates"].values())

    assert cg_eval.main(["--governor-check", "--markdown"]) == 0
    gov_md = capsys.readouterr().out
    assert "# Context-Guard Adaptive Governor Replay Check" in gov_md
    assert "PASS" in gov_md and "8/8" in gov_md and "security_never_lowered" in gov_md

    assert cg_eval.main(["--governor-check", "--plan", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_arguments"
    assert cg_eval.main(["--governor-check", "--runs-file", str(tmp_path / "r.json"), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_arguments"


def test_spool_integrity_failure_trips_governor_breaker_and_recovers_with_hysteresis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg_path = Path(os.environ["CONTEXT_GUARD_CONFIG_PATH"])
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "active"}}), encoding="utf-8")
    hooks_config.clear_config_cache()

    ws = tmp_path / "ws"
    state_dir = tmp_path / "state"
    spool_dir = state_dir / "spool"
    ws.mkdir(parents=True)
    state_dir.mkdir(parents=True)
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))

    def _bash_payload(call_id: str, fill: str) -> dict[str, Any]:
        body = "\n".join(f"row_{i:04d}: " + (fill * 72) for i in range(240)) + "\n"
        return {
            "tool_name": "Bash", "tool_input": {"command": f"pytest -{call_id}"},
            "tool_response": {"stdout": body, "stderr": ""}, "session_id": "sess_gov",
            "tool_use_id": call_id, "cwd": str(ws),
        }

    res1 = post_tool_use.handle_post_tool_use("claude", _bash_payload("call_1", "a"), state_dir=str(state_dir))
    out1 = str((res1.get("hookSpecificOutput") or {}).get("updatedToolOutput") or "")
    m = re.search(r"sp_[0-9a-f]{12}", out1)
    assert m is not None
    sid = m.group(0)

    (spool_dir / f"{sid}.txt").write_text("tampered\n", encoding="utf-8")
    sl = slice_spool(sid, workspace_root=ws, session_id="sess_gov", harness="claude", spool_dir=spool_dir)
    assert sl["ok"] is False and sl["error"] == "integrity_mismatch"
    assert is_optimizer_tripped("output_spool", state_dir=state_dir) is True

    assert post_tool_use.handle_post_tool_use("claude", _bash_payload("call_2", "b"), state_dir=str(state_dir)) == {}

    bad_reset = reset_circuit_breaker("output_spool", state_dir=spool_dir)
    assert bad_reset["ok"] is False and bad_reset["error"] == "hysteresis_requires_verification_or_operator_reset"
    assert post_tool_use.handle_post_tool_use("claude", _bash_payload("call_3", "c"), state_dir=str(state_dir)) == {}

    good_reset = reset_circuit_breaker(
        "output_spool", state_dir=spool_dir, verification_passed=True, verification_evidence="client_spool_probe_ok",
    )
    assert good_reset["ok"] is True and is_optimizer_tripped("output_spool", state_dir=state_dir) is False
    res4 = post_tool_use.handle_post_tool_use("claude", _bash_payload("call_4", "d"), state_dir=str(state_dir))
    assert "hookSpecificOutput" in res4
