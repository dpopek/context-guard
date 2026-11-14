"""Intervention outcome telemetry: ledger normalization, direct outcomes, and follow-up tracking."""

from __future__ import annotations

import json
import os
from pathlib import Path

from hooks import outcomes, pre_tool_use as ptu
from tests.helpers import read_outcomes_ledger, read_session_state


def test_constants_and_ledger_path_helper(tmp_path: Path) -> None:
    assert outcomes.SCHEMA_VERSION == 3
    assert outcomes.OUTCOMES == ("applied", "targeted_followup", "full_bypass", "shell_bypass")
    assert outcomes.ROW_KEYS == ("total", *outcomes.OUTCOMES)
    assert not hasattr(outcomes, "WINDOW_STEPS")
    assert not hasattr(outcomes, "COVERAGE_THRESHOLD")
    assert outcomes.OUTCOMES_KINDS == outcomes.INTERVENTION_KINDS
    assert set(outcomes.OUTCOMES_KINDS) == {"outline", "range_trim", "cli_rewrite", "outline_pull"}
    assert outcomes.ledger_path_for(None) is None
    assert outcomes.ledger_path_for("") is None
    assert outcomes.ledger_path_for(str(tmp_path)) == tmp_path / "outcomes.json"


def test_load_outcomes_normalises_rows_and_drops_garbage(tmp_path: Path) -> None:
    ledger = tmp_path / "outcomes.json"
    ledger.write_text(
        json.dumps(
            {
                "by_key": {"claude|m|outline": {"total": "7", "targeted": None, "bogus": 1}, "bad": 3},
                "updated_at": "2026-11-13T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    data = outcomes.load_outcomes(ledger)
    expected_row = {key: 0 for key in outcomes.ROW_KEYS}
    expected_row["total"] = 7
    assert set(data.keys()) == {"schema_version", "updated_at", "by_key"}
    assert data["schema_version"] == outcomes.SCHEMA_VERSION
    assert data["by_key"] == {"claude|m|outline": expected_row}
    assert outcomes.load_outcomes(tmp_path / "missing.json")["by_key"] == {}

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not valid json", encoding="utf-8")
    assert outcomes.load_outcomes(corrupt)["by_key"] == {}


def test_estimate_delivered_end_line_respects_harness_caps_and_skewed_bytes() -> None:
    # Unknown total_lines (0) or negative slice_bytes must return None.
    assert outcomes.estimate_delivered_end_line("claude", 1, -1, 0, 1000) is None
    assert outcomes.estimate_delivered_end_line("claude", 1, -1, 100, -1) is None

    # 300 lines, 60 KB total in Antigravity (46,080 B cap) -> truncated at unknown line -> None.
    assert outcomes.estimate_delivered_end_line("antigravity", 1, 300, 300, 60_000) is None
    # Within byte cap, line cap still clamps 3000 -> 800 in Antigravity and 2000 in Claude.
    assert outcomes.estimate_delivered_end_line("antigravity", 1, -1, 3000, 30_000) == 800
    assert outcomes.estimate_delivered_end_line("claude", 1, -1, 3000, 30_000) == 2000
    # Claude rejects reads above 60 KB coverage ceiling, whereas Cursor allows 1500 lines at 70 KB.
    assert outcomes.estimate_delivered_end_line("claude", 1, -1, 1500, 70_000) is None
    assert outcomes.estimate_delivered_end_line("cursor", 1, -1, 1500, 70_000) == 1500
    # Inverted range returns None.
    assert outcomes.estimate_delivered_end_line("claude", 50, 20, 100, 500) is None


def test_record_direct_outcome_aggregates_and_quarantines_corrupt_ledger(
    tmp_path: Path, capsys
) -> None:
    ledger = tmp_path / "outcomes.json"
    outcomes.record_direct_outcome("claude", "claude-opus-4-6", "range_trim", "applied", ledger)
    outcomes.record_direct_outcome("claude", "claude-opus-4-6", "range_trim", "applied", ledger)
    outcomes.record_direct_outcome("antigravity", "gemini-2.5-pro", "cli_rewrite", "applied", ledger)
    outcomes.record_direct_outcome("claude", "claude-opus-4-6", "outline", "applied", ledger)
    outcomes.record_direct_outcome(
        "claude", "claude-opus-4-6", "outline", "targeted_followup", ledger, increment_total=False
    )

    data = outcomes.load_outcomes(ledger)
    row = data["by_key"]["claude|claude-opus-4-6|range_trim"]
    assert row["total"] == 2
    assert row["applied"] == 2
    assert data["by_key"]["antigravity|gemini-2.5-pro|cli_rewrite"]["applied"] == 1
    out_row = data["by_key"]["claude|claude-opus-4-6|outline"]
    assert out_row["total"] == 1
    assert out_row["applied"] == 1
    assert out_row["targeted_followup"] == 1

    # Corrupt ledger is quarantined instead of crashing.
    bad_ledger = tmp_path / "bad_outcomes.json"
    bad_ledger.write_text("[]", encoding="utf-8")
    outcomes.record_direct_outcome("claude", "m", "outline", "applied", bad_ledger)
    assert outcomes.load_outcomes(bad_ledger)["by_key"]["claude|m|outline"]["applied"] == 1
    corrupt_files = [p for p in tmp_path.iterdir() if p.name.startswith("bad_outcomes.json.corrupt-")]
    assert len(corrupt_files) == 1
    assert "was not a JSON object" in capsys.readouterr().err


def test_record_direct_outcome_fails_open_when_lock_unwritable(tmp_path: Path, capsys) -> None:
    (tmp_path / "outcomes.lock").mkdir()
    ledger = tmp_path / "outcomes.json"
    outcomes.record_direct_outcome("claude", "m", "outline", "applied", ledger)
    assert not ledger.exists()
    assert "direct outcome telemetry skipped" in capsys.readouterr().err


def test_load_and_record_outcomes_reset_legacy_v1_and_v2_schemas(tmp_path: Path) -> None:
    for legacy_ver in (1, 2):
        ledger = tmp_path / f"outcomes_v{legacy_ver}.json"
        ledger.write_text(
            json.dumps(
                {
                    "schema_version": legacy_ver,
                    "window_steps": 4,
                    "coverage_threshold": 0.85,
                    "updated_at": "2026-11-12T00:00:00+00:00",
                    "by_key": {
                        "codex|m|reread_block": {"total": 5},
                        "claude|m|outline": {"total": 20, "targeted": 20},
                    },
                }
            ),
            encoding="utf-8",
        )
        loaded = outcomes.load_outcomes(ledger)
        assert loaded["schema_version"] == 3
        assert loaded["by_key"] == {}

        outcomes.record_direct_outcome("antigravity", "m", "outline_pull", "applied", ledger)
        persisted = json.loads(ledger.read_text(encoding="utf-8"))
        assert persisted["schema_version"] == 3
        assert set(persisted["by_key"]) == {"antigravity|m|outline_pull"}
        assert persisted["by_key"]["antigravity|m|outline_pull"]["applied"] == 1


def test_e2e_transcript_auto_outline_targeted_followup_is_one_shot(tmp_path: Path) -> None:
    tr = tmp_path / ".system_generated" / "logs" / "transcript.jsonl"
    tr.parent.mkdir(parents=True)
    tr.write_text(
        "\n".join(json.dumps({"step_index": i, "type": "PLANNER_RESPONSE", "text": "x" * 1200}) for i in range(18))
        + "\n",
        encoding="utf-8",
    )
    state_dir = tmp_path / "state"

    r1 = ptu.evaluate_hook(
        {"conversationId": "c-tr", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(tr)}}},
        state_dir=str(state_dir),
    )
    assert r1["decision"] == "deny" and "AUTO-OUTLINE" in r1["reason"]
    row = read_outcomes_ledger(state_dir)["by_key"]["antigravity|unknown|outline"]
    assert row["total"] == 1 and row["applied"] == 1 and row["targeted_followup"] == 0

    r2 = ptu.evaluate_hook(
        {
            "conversationId": "c-tr",
            "stepIdx": 2,
            "toolCall": {"name": "read_file", "args": {"Path": str(tr), "StartLine": 1, "EndLine": 5}},
        },
        state_dir=str(state_dir),
    )
    assert r2["decision"] == "allow"
    row = read_outcomes_ledger(state_dir)["by_key"]["antigravity|unknown|outline"]
    assert row["total"] == 1 and row["applied"] == 1 and row["targeted_followup"] == 1

    r3 = ptu.evaluate_hook(
        {
            "conversationId": "c-tr",
            "stepIdx": 3,
            "toolCall": {"name": "read_file", "args": {"Path": str(tr), "StartLine": 6, "EndLine": 10}},
        },
        state_dir=str(state_dir),
    )
    assert r3["decision"] == "allow"
    row = read_outcomes_ledger(state_dir)["by_key"]["antigravity|unknown|outline"]
    assert row["total"] == 1 and row["applied"] == 1 and row["targeted_followup"] == 1


def test_e2e_unwrapped_sibling_read_clears_pending_on_both_files(tmp_path: Path) -> None:
    step_dir = tmp_path / ".system_generated" / "steps" / "5"
    step_dir.mkdir(parents=True)
    mcp_out = step_dir / "output.txt"
    mcp_out.write_text(
        json.dumps([{"idx": i, "val": "x" * 200} for i in range(90)]),
        encoding="utf-8",
    )
    assert mcp_out.stat().st_size >= 16_384
    state_dir = tmp_path / "state"

    r1 = ptu.evaluate_hook(
        {"conversationId": "c-unw", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(mcp_out)}}},
        state_dir=str(state_dir),
    )
    assert r1["decision"] == "deny"
    unwrapped = step_dir / "output_formatted.json"
    assert unwrapped.is_file()

    r2 = ptu.evaluate_hook(
        {
            "conversationId": "c-unw",
            "stepIdx": 2,
            "toolCall": {"name": "read_file", "args": {"Path": str(unwrapped), "StartLine": 1, "EndLine": 50}},
        },
        state_dir=str(state_dir),
    )
    assert r2["decision"] == "allow"
    row = read_outcomes_ledger(state_dir)["by_key"]["antigravity|unknown|outline"]
    assert row["total"] == 1 and row["applied"] == 1 and row["targeted_followup"] == 1

    files_state = read_session_state(state_dir)["files"]
    for entry in files_state.values():
        assert "pending_followup_kind" not in entry


def test_e2e_small_twg_inline_read_does_not_set_pending_followup(tmp_path: Path) -> None:
    twg_file = tmp_path / "twg" / "run1" / "stdout.json"
    twg_file.parent.mkdir(parents=True)
    twg_file.write_text(
        json.dumps({"command": "twg jira workitem get PROJ-1", "data": {"key": "PROJ-1", "summary": "Short"}}),
        encoding="utf-8",
    )
    state_dir = tmp_path / "state"

    r1 = ptu.evaluate_hook(
        {"conversationId": "c-twg", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(twg_file)}}},
        state_dir=str(state_dir),
    )
    assert r1["decision"] == "deny" and "— full payload inline)" in r1["reason"]
    files_state = read_session_state(state_dir)["files"]
    assert all("pending_followup_kind" not in e for e in files_state.values())

    ptu.evaluate_hook(
        {
            "conversationId": "c-twg",
            "stepIdx": 2,
            "toolCall": {"name": "read_file", "args": {"Path": str(twg_file), "StartLine": 1, "EndLine": 5}},
        },
        state_dir=str(state_dir),
    )
    row = read_outcomes_ledger(state_dir)["by_key"]["antigravity|unknown|outline"]
    assert row["total"] == 1 and row["applied"] == 1 and row["targeted_followup"] == 0


def test_e2e_outline_pull_followed_by_unbounded_read_records_full_bypass(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("\n".join(f"x_{i} = {i}" for i in range(40)) + "\n", encoding="utf-8")
    state_dir = tmp_path / "state"

    ptu.evaluate_hook(
        {"session_id": "s-pull", "tool_name": "Bash", "tool_input": {"command": f"cg-outline {target}"}},
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    ptu.evaluate_hook(
        {"session_id": "s-pull", "tool_name": "Read", "tool_input": {"file_path": str(target)}},
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    row = read_outcomes_ledger(state_dir)["by_key"]["claude|unknown|outline_pull"]
    assert row["total"] == 1 and row["applied"] == 1 and row["full_bypass"] == 1 and row["targeted_followup"] == 0


def test_e2e_outline_pull_shell_bypass_claude_vs_codex(tmp_path: Path) -> None:
    target = tmp_path / "mod.py"
    target.write_text("\n".join(f"line_{i} = {i}" for i in range(60)) + "\n", encoding="utf-8")

    cl_state = tmp_path / "cl_state"
    ptu.evaluate_hook(
        {"session_id": "cl-1", "tool_name": "Bash", "tool_input": {"command": f"cg-outline {target}"}},
        state_dir=str(cl_state),
        cli_harness="claude",
    )
    ptu.evaluate_hook(
        {"session_id": "cl-1", "tool_name": "Bash", "tool_input": {"command": f"cat {target}"}},
        state_dir=str(cl_state),
        cli_harness="claude",
    )
    cl_row = read_outcomes_ledger(cl_state)["by_key"]["claude|unknown|outline_pull"]
    assert cl_row["total"] == 1 and cl_row["applied"] == 1 and cl_row["shell_bypass"] == 1

    cx_state = tmp_path / "cx_state"
    ptu.evaluate_hook(
        {"session_id": "cx-1", "tool_name": "exec_command", "tool_input": {"cmd": f"cg-outline {target}"}},
        state_dir=str(cx_state),
        cli_harness="codex",
    )
    ptu.evaluate_hook(
        {"session_id": "cx-1", "tool_name": "exec_command", "tool_input": {"cmd": f"sed -n '1,40p' {target}"}},
        state_dir=str(cx_state),
        cli_harness="codex",
    )
    cx_row = read_outcomes_ledger(cx_state)["by_key"]["codex|unknown|outline_pull"]
    assert cx_row["total"] == 1 and cx_row["applied"] == 1 and cx_row["targeted_followup"] == 1 and cx_row["shell_bypass"] == 0

    ptu.evaluate_hook(
        {"session_id": "cx-1", "tool_name": "exec_command", "tool_input": {"cmd": f"cat {target}"}},
        state_dir=str(cx_state),
        cli_harness="codex",
    )
    cx_row = read_outcomes_ledger(cx_state)["by_key"]["codex|unknown|outline_pull"]
    assert cx_row["total"] == 1 and cx_row["applied"] == 1 and cx_row["targeted_followup"] == 1 and cx_row["shell_bypass"] == 0

    cx_cat_state = tmp_path / "cx_cat_state"
    ptu.evaluate_hook(
        {"session_id": "cx-cat", "tool_name": "exec_command", "tool_input": {"cmd": f"cg-outline {target}"}},
        state_dir=str(cx_cat_state),
        cli_harness="codex",
    )
    ptu.evaluate_hook(
        {"session_id": "cx-cat", "tool_name": "exec_command", "tool_input": {"cmd": f"cat {target}"}},
        state_dir=str(cx_cat_state),
        cli_harness="codex",
    )
    cx_cat_row = read_outcomes_ledger(cx_cat_state)["by_key"]["codex|unknown|outline_pull"]
    assert cx_cat_row["total"] == 1 and cx_cat_row["applied"] == 1 and cx_cat_row["shell_bypass"] == 1 and cx_cat_row["targeted_followup"] == 0


def test_e2e_followup_max_lines_250_boundary_bounded_and_unbounded_tail(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    body = "\n".join(f"v_{i} = {i}" for i in range(300)) + "\n"
    cases = [
        ("f1.py", 51, -1, 1, 0),   # 300 - 51 + 1 = 250 -> targeted_followup
        ("f2.py", 50, -1, 1, 1),   # 300 - 50 + 1 = 251 -> full_bypass
        ("f3.py", 1, 250, 2, 1),   # 250 - 1 + 1 = 250 -> targeted_followup
        ("f4.py", 1, 251, 2, 2),   # 251 - 1 + 1 = 251 -> full_bypass
    ]
    for step, (name, start_l, end_l, exp_targ, exp_full) in enumerate(cases, start=1):
        fpath = tmp_path / name
        fpath.write_text(body, encoding="utf-8")
        ptu.evaluate_hook(
            {"conversationId": "c-bnd", "stepIdx": step * 2 - 1, "toolCall": {"name": "run_command", "args": {"CommandLine": f"cg-outline {fpath}"}}},
            state_dir=str(state_dir),
        )
        ptu.evaluate_hook(
            {"conversationId": "c-bnd", "stepIdx": step * 2, "toolCall": {"name": "read_file", "args": {"Path": str(fpath), "StartLine": start_l, "EndLine": end_l}}},
            state_dir=str(state_dir),
        )
        row = read_outcomes_ledger(state_dir)["by_key"]["antigravity|unknown|outline_pull"]
        assert (row["targeted_followup"], row["full_bypass"]) == (exp_targ, exp_full)


def test_e2e_cold_shell_read_does_not_create_state_dir(tmp_path: Path) -> None:
    target = tmp_path / "mod.py"
    target.write_text("x = 1\n", encoding="utf-8")
    state_dir = tmp_path / "cold_state"

    ptu.evaluate_hook(
        {"session_id": "s-cold", "tool_name": "Bash", "tool_input": {"command": f"cat {target}"}},
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert not state_dir.exists()


def test_e2e_stale_sha256_shell_cat_clears_pending_without_bypass(tmp_path: Path) -> None:
    target = tmp_path / "mod.py"
    target.write_text("x = 1\n", encoding="utf-8")
    state_dir = tmp_path / "state"

    ptu.evaluate_hook(
        {"session_id": "s-sha", "tool_name": "Bash", "tool_input": {"command": f"cg-outline {target}"}},
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    target.write_text("x = 2\ny = 3\n", encoding="utf-8")
    ptu.evaluate_hook(
        {"session_id": "s-sha", "tool_name": "Bash", "tool_input": {"command": f"cat {target}"}},
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    row = read_outcomes_ledger(state_dir)["by_key"]["claude|unknown|outline_pull"]
    assert row["total"] == 1 and row["applied"] == 1 and row["shell_bypass"] == 0
    assert "pending_followup_kind" not in read_session_state(state_dir)["files"][os.path.realpath(target)]


def test_e2e_antigravity_run_command_uses_cwd_for_outline_pull_and_shell_bypass(tmp_path: Path) -> None:
    target = tmp_path / "mod.py"
    target.write_text("\n".join(f"k_{i} = {i}" for i in range(40)) + "\n", encoding="utf-8")
    state_dir = tmp_path / "state"

    ptu.evaluate_hook(
        {"conversationId": "c-ag", "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": "cg-outline mod.py", "Cwd": str(tmp_path)}}},
        state_dir=str(state_dir),
    )
    assert "pending_followup_kind" in read_session_state(state_dir)["files"][os.path.realpath(target)]

    ptu.evaluate_hook(
        {"conversationId": "c-ag", "stepIdx": 2, "toolCall": {"name": "run_command", "args": {"CommandLine": "cat mod.py", "Cwd": str(tmp_path)}}},
        state_dir=str(state_dir),
    )
    row = read_outcomes_ledger(state_dir)["by_key"]["antigravity|unknown|outline_pull"]
    assert row["total"] == 1 and row["applied"] == 1 and row["shell_bypass"] == 1


def test_e2e_small_twg_inline_read_clears_prior_outline_pull_pending_flag(tmp_path: Path) -> None:
    twg_file = tmp_path / "twg" / "run2" / "stdout.json"
    twg_file.parent.mkdir(parents=True)
    twg_file.write_text(
        json.dumps({"command": "twg jira workitem get PROJ-2", "data": {"key": "PROJ-2", "summary": "Short"}}),
        encoding="utf-8",
    )
    state_dir = tmp_path / "state"

    ptu.evaluate_hook(
        {"conversationId": "c-twg2", "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": f"cg-outline {twg_file}"}}},
        state_dir=str(state_dir),
    )
    r2 = ptu.evaluate_hook(
        {"conversationId": "c-twg2", "stepIdx": 2, "toolCall": {"name": "read_file", "args": {"Path": str(twg_file)}}},
        state_dir=str(state_dir),
    )
    assert r2["decision"] == "deny" and "— full payload inline)" in r2["reason"]
    assert all("pending_followup_kind" not in e for e in read_session_state(state_dir)["files"].values())

    ptu.evaluate_hook(
        {"conversationId": "c-twg2", "stepIdx": 3, "toolCall": {"name": "read_file", "args": {"Path": str(twg_file), "StartLine": 1, "EndLine": 5}}},
        state_dir=str(state_dir),
    )
    row = read_outcomes_ledger(state_dir)["by_key"]["antigravity|unknown|outline_pull"]
    assert row["total"] == 1 and row["applied"] == 1 and row["targeted_followup"] == 0 and row["full_bypass"] == 0
