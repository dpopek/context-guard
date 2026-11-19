"""Integrity tests for Schema v4 outcomes attribution, step-0 eviction, open_windows, and write failures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hooks import outcomes


def test_outcomes_step_zero_eviction_does_not_blackhole_future_step_zero_events(tmp_path: Path) -> None:
    ledger = tmp_path / "outcomes.json"
    assert outcomes.record_direct_outcome(
        "antigravity",
        "gemini-2.5-pro",
        "cli_rewrite",
        "applied",
        ledger,
        session_id="s-ag",
        step_idx=0,
        call_id="c-0",
    )

    for step in range(1, outcomes.STEP_LEDGER_MAX_ENTRIES + 4):
        assert outcomes.record_direct_outcome(
            "claude",
            "claude-sonnet-4-6",
            "range_trim",
            "applied",
            ledger,
            session_id="s-other",
            step_idx=step,
            call_id=f"other-{step}",
        )

    mid = outcomes.load_outcomes(ledger)
    assert "s-ag" not in mid["archived_max_step_by_session"]
    assert "s-ag:0" not in mid["archived_step_keys"]
    assert mid["archived_max_step_by_session"]["s-other"] >= 3

    assert outcomes.record_direct_outcome(
        "antigravity",
        "gemini-2.5-pro",
        "cli_rewrite",
        "applied",
        ledger,
        session_id="s-ag",
        step_idx=0,
        call_id="c-0-next",
    )
    after = outcomes.load_outcomes(ledger)
    assert after["late_unattributed"]["total"] == 0
    row = after["by_key"]["antigravity|gemini-2.5-pro|cli_rewrite"]
    assert row["total"] == 2
    assert row["applied"] == 2
    assert row["weighted_turns"] == pytest.approx(2.0)

    # Positive step already archived still routes to late_unattributed.
    assert outcomes.record_direct_outcome(
        "claude",
        "claude-sonnet-4-6",
        "range_trim",
        "applied",
        ledger,
        session_id="s-other",
        step_idx=1,
        call_id="late-1",
    )
    assert outcomes.load_outcomes(ledger)["late_unattributed"]["total"] == 1


def test_outcomes_pipe_in_session_id_and_multiple_windows_same_file(tmp_path: Path) -> None:
    ledger = tmp_path / "outcomes.json"
    file_a = tmp_path / "a.py"
    file_a.write_text("x = 1\n", encoding="utf-8")
    canon_a = os.path.realpath(str(file_a))

    sess_pipe = "org|team|1"
    outcomes.open_outcome_window(
        "claude",
        "claude-sonnet-4-6",
        "range_trim",
        sess_pipe,
        canon_a,
        step_idx=1,
        regret_window_steps=10,
        ledger_path=ledger,
        meta={"trimmed_start": 1, "trimmed_end": 20},
    )
    outcomes.open_outcome_window(
        "claude",
        "claude-sonnet-4-6",
        "range_trim",
        sess_pipe,
        canon_a,
        step_idx=2,
        regret_window_steps=10,
        ledger_path=ledger,
        meta={"trimmed_start": 50, "trimmed_end": 80},
    )
    # Colliding composite string with different session/target split must not overwrite.
    outcomes.open_outcome_window(
        "claude",
        "claude-sonnet-4-6",
        "range_trim",
        "org",
        f"team|1|{canon_a}",
        step_idx=2,
        regret_window_steps=10,
        ledger_path=ledger,
        meta={"trimmed_start": 1, "trimmed_end": 10},
    )

    loaded = outcomes.load_outcomes(ledger)
    assert len(loaded["open_windows"]) == 3
    for win in loaded["open_windows"].values():
        assert win["kind"] == "range_trim"
        assert isinstance(win["target_path"], str) and win["target_path"]

    # Overlapping only first trim span [1, 20] resolves Window 1 and leaves Window 2 open.
    assert outcomes.record_range_trim_regret(sess_pipe, canon_a, 5, 15, step_idx=3, ledger_path=ledger)
    mid = outcomes.load_outcomes(ledger)
    assert len(mid["open_windows"]) == 2
    assert mid["by_key"]["claude|claude-sonnet-4-6|range_trim"]["recovery"]["targeted"] == 1

    # Overlapping second trim span [50, 80] resolves Window 2 while "org" stays untouched.
    assert outcomes.record_range_trim_regret(sess_pipe, canon_a, 60, 70, step_idx=4, ledger_path=ledger)
    final = outcomes.load_outcomes(ledger)
    assert len(final["open_windows"]) == 1
    assert next(iter(final["open_windows"].values()))["session_id"] == "org"
    assert final["by_key"]["claude|claude-sonnet-4-6|range_trim"]["recovery"]["targeted"] == 2

    # Consuming windows on pipe-containing session_id works cleanly via stored target_path/kind.
    outcomes.open_outcome_window(
        "claude",
        "claude-sonnet-4-6",
        "outline",
        sess_pipe,
        canon_a,
        step_idx=5,
        regret_window_steps=10,
        ledger_path=ledger,
    )
    outcomes.consume_outcome_windows(sess_pipe, canon_a, kind="outline", ledger_path=ledger)
    after_consume = outcomes.load_outcomes(ledger)
    assert len(after_consume["open_windows"]) == 1
    assert next(iter(after_consume["open_windows"].values()))["session_id"] == "org"


def test_outcomes_reconcile_returns_false_when_atomic_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ledger = tmp_path / "outcomes.json"
    target = tmp_path / "mod.py"
    target.write_text("a = 1\n", encoding="utf-8")
    canon = os.path.realpath(str(target))

    assert outcomes.record_direct_outcome(
        "claude", "claude-sonnet-4-6", "range_trim", "applied", ledger, session_id="s-fail", step_idx=1, call_id="c1"
    )
    assert not outcomes.record_direct_outcome(
        "claude", "claude-sonnet-4-6", "range_trim", "applied", ledger, session_id="s-fail", step_idx=1, call_id="c1"
    )
    outcomes.open_outcome_window(
        "claude",
        "claude-sonnet-4-6",
        "range_trim",
        "s-fail",
        canon,
        step_idx=1,
        regret_window_steps=8,
        ledger_path=ledger,
        meta={"trimmed_start": 1, "trimmed_end": 20},
    )
    outcomes.open_outcome_window(
        "claude",
        "claude-sonnet-4-6",
        "cli_rewrite",
        "s-fail",
        "cli:pytest:tests",
        step_idx=1,
        regret_window_steps=8,
        ledger_path=ledger,
    )
    outcomes.open_outcome_window(
        "claude",
        "claude-sonnet-4-6",
        "output_spool",
        "s-fail",
        "spool:sp_abc",
        step_idx=1,
        regret_window_steps=8,
        ledger_path=ledger,
        meta={"cmd_sig": "bash:pytest"},
    )

    def _fail_write(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(outcomes, "write_json_atomic", _fail_write)
    assert outcomes.record_range_trim_regret("s-fail", canon, 5, 10, step_idx=2, ledger_path=ledger) is False
    assert outcomes.record_cli_verbose_regret("s-fail", "pytest:tests", step_idx=2, ledger_path=ledger) is False
    assert outcomes.record_spool_followup("s-fail", "sp_abc", "targeted", "none", step_idx=2, ledger_path=ledger) is False
    assert outcomes.record_spool_followup_request(
        "s-fail", "sp_abc", {"call_id": "c-req", "recovery": "targeted", "regret": "none", "step_idx": 2}, ledger_path=ledger
    ) is False
    assert outcomes.record_spool_command_repeat("s-fail", "bash:pytest", step_idx=2, ledger_path=ledger) is False
    err = capsys.readouterr().err
    assert "direct outcome telemetry skipped: OSError: disk full" in err
    assert len(outcomes.load_outcomes(ledger)["open_windows"]) == 3


def test_spool_followup_request_and_result_write_failure_leaves_window_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = tmp_path / "outcomes.json"
    assert outcomes.record_spool_followup_request(
        "s-miss", "sp_abc", {"call_id": "c1", "recovery": "targeted", "regret": "none", "step_idx": 1}, ledger_path=ledger
    ) is False
    assert outcomes.resolve_spool_followup_result("s-miss", "c1", True, ledger_path=ledger) is False

    outcomes.open_outcome_window(
        "claude", "claude-sonnet-4-6", "output_spool", "s-ok", "spool:sp_abc", step_idx=1,
        regret_window_steps=6, ledger_path=ledger, meta={"cmd_sig": "sig1", "total_lines": 250, "call_id": "em1"},
    )
    assert outcomes.record_spool_followup_request(
        "s-ok", "sp_abc", {"call_id": "c-rec", "recovery": "targeted", "regret": "none", "step_idx": 2}, ledger_path=ledger
    ) is True

    def _fail_write(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(outcomes, "write_json_atomic", _fail_write)
    assert outcomes.resolve_spool_followup_result("s-ok", "c-rec", True, ledger_path=ledger) is False
    monkeypatch.undo()
    loaded = outcomes.load_outcomes(ledger)
    assert "s-ok|spool:sp_abc|output_spool" in loaded["open_windows"]
    assert loaded["open_windows"]["s-ok|spool:sp_abc|output_spool"]["meta"]["p_cid"] == "c-rec"


def test_outcomes_dual_ended_trim_spans_trigger_regret_on_tail_reread(tmp_path: Path) -> None:
    ledger = tmp_path / "outcomes.json"
    target = tmp_path / "dual.py"
    target.write_text("x = 1\n", encoding="utf-8")
    canon = os.path.realpath(str(target))

    outcomes.open_outcome_window(
        "claude",
        "claude-sonnet-4-6",
        "range_trim",
        "s-dual",
        canon,
        step_idx=1,
        regret_window_steps=8,
        ledger_path=ledger,
        meta={"trimmed_spans": [[1, 20], [81, 100]]},
    )
    persisted_meta = next(iter(outcomes.load_outcomes(ledger)["open_windows"].values()))["meta"]
    assert persisted_meta["trimmed_spans"] == [[1, 20], [81, 100]]

    # Disjoint middle slice [30, 50] must NOT trigger regret.
    assert outcomes.record_range_trim_regret("s-dual", canon, 30, 50, step_idx=2, ledger_path=ledger) is False
    assert len(outcomes.load_outcomes(ledger)["open_windows"]) == 1

    # Tail re-read [85, 95] overlaps second span [81, 100] and resolves regret.
    assert outcomes.record_range_trim_regret("s-dual", canon, 85, 95, step_idx=3, ledger_path=ledger) is True
    assert outcomes.load_outcomes(ledger)["open_windows"] == {}
    row = outcomes.load_outcomes(ledger)["by_key"]["claude|claude-sonnet-4-6|range_trim"]
    assert row["recovery"]["targeted"] == 1
    assert row["regret"]["suspected"] == 1


def test_post_tool_use_default_state_dir_writes_range_trim_to_default_outcomes_ledger(
    tmp_path: Path, isolated_user_env: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json
    from hooks import config, post_tool_use, pre_tool_use

    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"read_confirm_policy": "bounded", "optimizers": {"range_trim": "active"}}), encoding="utf-8")
    config.clear_config_cache()
    default_outcomes = tmp_path / "default_outcomes.json"
    monkeypatch.setattr(outcomes, "DEFAULT_OUTCOMES_PATH", default_outcomes)
    target = tmp_path / "mod.py"
    target.write_text("\n".join(f"x_{i} = {i}" for i in range(1, 140)) + "\n", encoding="utf-8")

    try:
        assert pre_tool_use.evaluate_hook(
            {"conversationId": "s-def-out", "stepIdx": 1, "toolCall": {"id": "c1", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 50}}},
            state_dir=None,
        ) == {"decision": "allow"}
        post_tool_use.handle_post_tool_use(
            "antigravity",
            {"conversationId": "s-def-out", "stepIdx": 1, "toolCall": {"id": "c1", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 50}}},
            state_dir=None,
        )
        res_trim = pre_tool_use.evaluate_hook(
            {"conversationId": "s-def-out", "stepIdx": 2, "toolCall": {"id": "c2", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 100}}},
            state_dir=None,
        )
        assert res_trim == {"decision": "allow", "overwrite": {"StartLine": 51, "EndLine": 100}}
        post_tool_use.handle_post_tool_use(
            "antigravity",
            {"conversationId": "s-def-out", "stepIdx": 2, "toolCall": {"id": "c2", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 100}}},
            state_dir=None,
        )
        doc = outcomes.load_outcomes(default_outcomes)
        assert any(k.endswith("|range_trim") and row.get("applied") == 1 for k, row in doc["by_key"].items())
    finally:
        config.clear_config_cache()
