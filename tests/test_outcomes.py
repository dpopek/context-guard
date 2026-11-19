"""Intervention outcome telemetry: ledger normalization, direct outcomes, and follow-up tracking."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hooks import outcomes, pre_tool_use as ptu
from tests.helpers import read_outcomes_ledger, read_session_state


def test_constants_and_ledger_path_helper(tmp_path: Path) -> None:
    assert outcomes.SCHEMA_VERSION == 4
    assert outcomes.RECOVERY_KEYS == ("none", "targeted", "full", "pending_or_unknown")
    assert outcomes.REGRET_KEYS == ("none", "suspected", "confirmed", "unknown")
    assert outcomes.EVIDENCE_KEYS == ("observed", "heuristic", "replay", "causal_ab")
    assert not hasattr(outcomes, "WINDOW_STEPS")
    assert not hasattr(outcomes, "COVERAGE_THRESHOLD")
    assert outcomes.OUTCOMES_KINDS == outcomes.INTERVENTION_KINDS
    assert set(outcomes.OUTCOMES_KINDS) == {"outline", "range_trim", "cli_rewrite", "outline_pull", "output_spool"}
    assert outcomes.ledger_path_for(None) is None
    assert outcomes.ledger_path_for("") is None
    assert outcomes.ledger_path_for(str(tmp_path)) == tmp_path / "outcomes.json"


def test_load_outcomes_normalises_rows_and_drops_garbage(tmp_path: Path) -> None:
    ledger = tmp_path / "outcomes.json"
    ledger.write_text(
        json.dumps(
            {
                "schema_version": 4,
                "by_key": {"claude|m|outline": {"total": "7", "recovery": {"targeted": "2"}, "bogus": 1}, "bad": 3},
                "updated_at": "2026-11-13T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    data = outcomes.load_outcomes(ledger)
    assert set(data.keys()) == {
        "schema_version", "updated_at", "by_key", "step_ledger",
        "archived_max_step_by_session", "archived_step_keys", "open_windows",
        "unattributed_anon", "late_unattributed",
    }
    assert data["schema_version"] == 4
    assert data["by_key"] == {
        "claude|m|outline": {
            "total": 7,
            "applied": 0,
            "recovery": {"none": 0, "targeted": 2, "full": 0, "pending_or_unknown": 0},
            "regret": {"none": 0, "suspected": 0, "confirmed": 0, "unknown": 0},
            "evidence": {"observed": 0, "heuristic": 0, "replay": 0, "causal_ab": 0},
            "weighted_turns": 0.0,
            "archived_weighted_turns": 0.0,
        }
    }
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
    assert out_row["recovery"]["targeted"] == 1
    assert out_row["regret"]["unknown"] == 1
    assert out_row["evidence"]["heuristic"] == 1

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
        assert loaded["schema_version"] == 4
        assert loaded["by_key"] == {}

        outcomes.record_direct_outcome("antigravity", "m", "outline_pull", "applied", ledger)
        persisted = json.loads(ledger.read_text(encoding="utf-8"))
        assert persisted["schema_version"] == 4
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
    assert row["total"] == 1 and row["applied"] == 1 and row["recovery"]["targeted"] == 0

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
    assert row["total"] == 1 and row["applied"] == 1 and row["recovery"]["targeted"] == 1 and row["regret"]["unknown"] == 1

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
    assert row["total"] == 1 and row["applied"] == 1 and row["recovery"]["targeted"] == 1


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
    assert row["total"] == 1 and row["applied"] == 1 and row["recovery"]["targeted"] == 1

    files_state = read_session_state(state_dir)["files"]
    for entry in files_state.values():
        assert "pending_followup_kind" not in entry


def test_e2e_small_twg_inline_read_does_not_set_pending_followup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hooks.config import clear_config_cache

    cfg_path = tmp_path / "cg_config.json"
    cfg_path.write_text(json.dumps({"integrations": {"atlassian_twg": "active"}}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    clear_config_cache()
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
    assert row["total"] == 1 and row["applied"] == 1 and row["recovery"]["targeted"] == 0


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
    assert row["total"] == 1 and row["applied"] == 1 and row["recovery"]["full"] == 1 and row["regret"]["suspected"] == 1 and row["recovery"]["targeted"] == 0


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
    assert cl_row["total"] == 1 and cl_row["applied"] == 1 and cl_row["recovery"]["full"] == 1 and cl_row["regret"]["suspected"] == 1

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
    assert cx_row["total"] == 1 and cx_row["applied"] == 1 and cx_row["recovery"]["targeted"] == 1 and cx_row["recovery"]["full"] == 0

    ptu.evaluate_hook(
        {"session_id": "cx-1", "tool_name": "exec_command", "tool_input": {"cmd": f"cat {target}"}},
        state_dir=str(cx_state),
        cli_harness="codex",
    )
    cx_row = read_outcomes_ledger(cx_state)["by_key"]["codex|unknown|outline_pull"]
    assert cx_row["total"] == 1 and cx_row["applied"] == 1 and cx_row["recovery"]["targeted"] == 1 and cx_row["recovery"]["full"] == 0

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
    assert cx_cat_row["total"] == 1 and cx_cat_row["applied"] == 1 and cx_cat_row["recovery"]["full"] == 1 and cx_cat_row["recovery"]["targeted"] == 0


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
        assert (row["recovery"]["targeted"], row["recovery"]["full"]) == (exp_targ, exp_full)


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
    assert row["total"] == 1 and row["applied"] == 1 and row["recovery"]["full"] == 0
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
    assert row["total"] == 1 and row["applied"] == 1 and row["recovery"]["full"] == 1 and row["regret"]["suspected"] == 1


def test_e2e_small_twg_inline_read_clears_prior_outline_pull_pending_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hooks.config import clear_config_cache

    cfg_path = tmp_path / "cg_config.json"
    cfg_path.write_text(json.dumps({"integrations": {"atlassian_twg": "active"}}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    clear_config_cache()
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
    assert row["total"] == 1 and row["applied"] == 1 and row["recovery"]["targeted"] == 0 and row["recovery"]["full"] == 0


def test_shadow_mode_invalidates_on_file_edit_compaction_and_rewind_and_hashes_paths_0600(
    tmp_path: Path,
) -> None:
    from hooks import telemetry

    state_dir = tmp_path / "state"
    shadow_path = telemetry.shadow_path_for(str(state_dir))
    assert shadow_path == state_dir / "shadow.json"
    secret_file = tmp_path / "secret_customer_file.py"
    secret_file.write_text("x = 1\n", encoding="utf-8")
    canon = os.path.realpath(secret_file)
    hashed = telemetry.pseudonymize_shadow_path(canon)
    assert len(hashed) == 32 and hashed == telemetry.pseudonymize_shadow_path(canon)
    assert "secret_customer_file" not in hashed

    assert not telemetry.record_shadow_read("sess-1", canon, 1, 50, 2, 1, "sha-a", min_tier=2, shadow_path=shadow_path, now_ts=1_000.0)
    assert hashed not in telemetry.load_shadow_ledger(shadow_path, now_ts=1_000.0)["sessions"].get("sess-1", {}).get("paths", {})
    assert telemetry.record_shadow_read("sess-1", canon, 1, 50, 3, 2, "sha-a", min_tier=2, shadow_path=shadow_path, now_ts=1_001.0)
    assert telemetry.record_shadow_read("sess-1", canon, 51, 90, 6, 3, "sha-a", min_tier=2, shadow_path=shadow_path, now_ts=1_002.0)

    if os.name == "posix":
        assert (shadow_path.stat().st_mode & 0o777) == 0o600
    raw_shadow_text = shadow_path.read_text(encoding="utf-8")
    assert "secret_customer_file" not in raw_shadow_text
    assert not (state_dir / "stats.json").exists()
    assert not (state_dir / ".context_guard_state.json").exists()

    # Compaction drops reads at or before checkpoint_step=3, preserves step 6.
    assert telemetry.invalidate_shadow_ledger(
        session_id="sess-1", checkpoint_step=3, shadow_path=shadow_path, now_ts=1_003.0
    )
    reads_after_compact = telemetry.load_shadow_ledger(shadow_path, now_ts=1_003.0)["sessions"]["sess-1"]["paths"][hashed]["reads"]
    assert reads_after_compact == [[51, 90, 6, 3]]

    # Rewind drops reads at or above max_step=6 when inclusive_rewind=True.
    assert telemetry.record_shadow_read("sess-1", canon, 1, 20, 4, 2, "sha-a", min_tier=2, shadow_path=shadow_path, now_ts=1_004.0)
    assert telemetry.invalidate_shadow_ledger(
        session_id="sess-1", max_step=6, inclusive_rewind=True, shadow_path=shadow_path, now_ts=1_005.0
    )
    reads_after_rewind = telemetry.load_shadow_ledger(shadow_path, now_ts=1_005.0)["sessions"]["sess-1"]["paths"][hashed]["reads"]
    assert reads_after_rewind == [[1, 20, 4, 2]]

    # File edit mismatch invalidates entry; changed content_sha256 in record_shadow_read resets reads.
    assert telemetry.invalidate_shadow_ledger(
        session_id="sess-1", raw_path=str(secret_file), content_sha256="sha-b", shadow_path=shadow_path, now_ts=1_006.0
    )
    assert hashed not in telemetry.load_shadow_ledger(shadow_path, now_ts=1_006.0)["sessions"].get("sess-1", {}).get("paths", {})
    assert telemetry.record_shadow_read("sess-1", canon, 1, 20, 7, 2, "sha-b", min_tier=2, shadow_path=shadow_path, now_ts=1_007.0)
    assert telemetry.record_shadow_read("sess-1", canon, 21, 40, 8, 2, "sha-c", min_tier=2, shadow_path=shadow_path, now_ts=1_008.0)
    assert telemetry.load_shadow_ledger(shadow_path, now_ts=1_008.0)["sessions"]["sess-1"]["paths"][hashed]["reads"] == [[21, 40, 8, 2]]

    # Retention bounds: <= 16 sessions, <= 200 hashes/session, 7-day TTL.
    for idx in range(20):
        assert telemetry.record_shadow_read(
            f"bulk-{idx}", str(tmp_path / f"f{idx}.py"), 1, 10, 1, 2, "sha", shadow_path=shadow_path, now_ts=2_000.0 + idx
        )
    loaded = telemetry.load_shadow_ledger(shadow_path, now_ts=2_030.0)
    assert len(loaded["sessions"]) <= 16
    for i in range(205):
        assert telemetry.record_shadow_read(
            "bulk-19", str(tmp_path / f"many_{i}.py"), 1, 10, 1, 2, "sha", shadow_path=shadow_path, now_ts=2_100.0 + i
        )
    assert len(telemetry.load_shadow_ledger(shadow_path, now_ts=2_400.0)["sessions"]["bulk-19"]["paths"]) <= 200
    assert telemetry.load_shadow_ledger(shadow_path, now_ts=2_400.0 + 7 * 86400 + 1)["sessions"] == {}


def test_v3_migration_maps_full_bypass_to_suspected_and_targeted_to_unknown_never_confirmed(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "outcomes.json"
    ledger.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "updated_at": "2026-11-10T00:00:00+00:00",
                "by_key": {
                    "claude|claude-sonnet-4-6|outline": {
                        "total": 10,
                        "applied": 9,
                        "targeted_followup": 3,
                        "full_bypass": 2,
                        "shell_bypass": 1,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    migrated = outcomes.load_outcomes(ledger)
    assert migrated["schema_version"] == 4
    row = migrated["by_key"]["claude|claude-sonnet-4-6|outline"]
    assert row["legacy_v3"] is True
    assert row["total"] == 10
    assert row["applied"] == 9
    assert row["recovery"] == {"none": 0, "targeted": 3, "full": 3, "pending_or_unknown": 0}
    assert row["regret"] == {"none": 0, "suspected": 3, "confirmed": 0, "unknown": 3}
    assert row["evidence"] == {"observed": 0, "heuristic": 6, "replay": 0, "causal_ab": 0}
    assert row["weighted_turns"] == 0.0
    assert row["archived_weighted_turns"] == 0.0
    rates = outcomes.compute_regret_rates(row)
    assert rates["confirmed_regret_rate"] == 0.0
    assert rates["suspected_regret_rate"] == pytest.approx(1.0)

    v2_ledger = tmp_path / "v2.json"
    v2_ledger.write_text(json.dumps({"schema_version": 2, "by_key": {"a|b|outline": {"total": 5}}}), encoding="utf-8")
    assert outcomes.load_outcomes(v2_ledger)["by_key"] == {}


def test_single_ledger_step_weights_survive_mid_write_failure_and_idempotent_event_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "outcomes.json"
    outcomes.record_direct_outcome(
        "claude", "claude-sonnet-4-6", "outline", "applied", ledger, session_id="s1", step_idx=1, call_id="c1"
    )
    outcomes.record_direct_outcome(
        "claude", "claude-sonnet-4-6", "range_trim", "applied", ledger, session_id="s1", step_idx=1, call_id="c2"
    )
    # Idempotent replay of c1:outline must not add duplicate weight or increment total/applied.
    outcomes.record_direct_outcome(
        "claude", "claude-sonnet-4-6", "outline", "applied", ledger, session_id="s1", step_idx=1, call_id="c1"
    )
    state = outcomes.load_outcomes(ledger)
    assert state["by_key"]["claude|claude-sonnet-4-6|outline"]["total"] == 1
    assert state["by_key"]["claude|claude-sonnet-4-6|outline"]["weighted_turns"] == pytest.approx(0.5)
    assert state["by_key"]["claude|claude-sonnet-4-6|range_trim"]["weighted_turns"] == pytest.approx(0.5)

    real_replace = os.replace

    def fail_once(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        raise OSError("simulated mid-write crash")

    monkeypatch.setattr(os, "replace", fail_once)
    outcomes.record_direct_outcome(
        "claude", "claude-sonnet-4-6", "outline", "applied", ledger, session_id="s1", step_idx=2, call_id="c3"
    )
    monkeypatch.setattr(os, "replace", real_replace)
    after_crash = outcomes.load_outcomes(ledger)
    assert after_crash["by_key"]["claude|claude-sonnet-4-6|outline"]["weighted_turns"] == pytest.approx(0.5)

    outcomes.record_direct_outcome(
        "claude", "claude-sonnet-4-6", "outline", "applied", ledger, session_id="s1", step_idx=2, call_id="c3"
    )
    after_retry = outcomes.load_outcomes(ledger)
    assert after_retry["by_key"]["claude|claude-sonnet-4-6|outline"]["weighted_turns"] == pytest.approx(1.5)


def test_outcomes_unattributed_anon_archived_terminal_steps_and_open_windows(tmp_path: Path) -> None:
    ledger = tmp_path / "outcomes.json"
    outcomes.record_direct_outcome("claude", "claude-sonnet-4-6", "outline", "applied", ledger)
    anon_state = outcomes.load_outcomes(ledger)
    assert anon_state["step_ledger"] == {}
    assert anon_state["unattributed_anon"]["total"] == 1
    assert anon_state["by_key"]["claude|claude-sonnet-4-6|outline"]["weighted_turns"] == 0.0

    for step in range(132):
        outcomes.record_direct_outcome(
            "claude",
            "claude-sonnet-4-6",
            "range_trim",
            "applied",
            ledger,
            session_id="s-arch",
            step_idx=step,
            call_id=f"c-{step}",
        )
    archived_state = outcomes.load_outcomes(ledger)
    assert len(archived_state["step_ledger"]) == 128
    assert archived_state["archived_max_step_by_session"]["s-arch"] >= 3
    assert archived_state["by_key"]["claude|claude-sonnet-4-6|range_trim"]["weighted_turns"] == pytest.approx(132.0)

    # Late event for already archived step must record to late_unattributed only.
    outcomes.record_direct_outcome(
        "claude",
        "claude-sonnet-4-6",
        "range_trim",
        "applied",
        ledger,
        session_id="s-arch",
        step_idx=1,
        call_id="c-late",
    )
    after_late = outcomes.load_outcomes(ledger)
    assert "s-arch:1" not in after_late["step_ledger"]
    assert after_late["late_unattributed"]["total"] == 1
    assert after_late["by_key"]["claude|claude-sonnet-4-6|range_trim"]["weighted_turns"] == pytest.approx(132.0)

    # Open window closes cleanly into recovery.none / regret.none / evidence.observed.
    outcomes.open_outcome_window(
        "claude", "claude-sonnet-4-6", "outline", "s-win", "/tmp/a.py", step_idx=5, regret_window_steps=3, ledger_path=ledger
    )
    outcomes.close_outcome_windows("s-win", current_step=9, ledger_path=ledger)
    win_row = outcomes.load_outcomes(ledger)["by_key"]["claude|claude-sonnet-4-6|outline"]
    assert win_row["recovery"]["none"] == 1
    assert win_row["regret"]["none"] == 1
    assert win_row["evidence"]["observed"] == 1


def test_pre_tool_use_attribution_and_window_consumption_no_double_count(tmp_path: Path) -> None:
    sd = tmp_path / "state"
    sd.mkdir()
    canon_a = os.path.realpath(str(tmp_path / "a.py"))
    (tmp_path / "a.py").write_text("".join(f"x_{i} = {i}\n" for i in range(400)), encoding="utf-8")

    # Synthetic callId -> unattributed_anon; explicit callId -> step_ledger
    ptu.evaluate_hook(
        {"conversationId": "s-attr", "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}}},
        state_dir=str(sd),
    )
    doc1 = read_outcomes_ledger(sd)
    assert doc1["unattributed_anon"]["total"] == 1 and doc1["step_ledger"] == {}

    ptu.evaluate_hook(
        {"conversationId": "s-attr", "stepIdx": 2, "toolCall": {"name": "run_command", "callId": "ag-real-2", "args": {"CommandLine": "git status"}}},
        state_dir=str(sd),
    )
    doc2 = read_outcomes_ledger(sd)
    assert "s-attr:2" in doc2["step_ledger"] and doc2["unattributed_anon"]["total"] == 1

    # Consumed open window does not double-count recovery.none when steps advance past regret_window_steps
    mcp_dir = tmp_path / ".system_generated" / "steps" / "1"
    mcp_dir.mkdir(parents=True)
    mcp = mcp_dir / "output.txt"
    mcp.write_text(json.dumps({"file_name": "big.py", "content": "\n".join(f"v_{i}={i}" for i in range(1500))}), encoding="utf-8")
    sd_w = tmp_path / "sd_win"
    sd_w.mkdir()
    ptu.evaluate_hook(
        {"conversationId": "s-w", "stepIdx": 1, "toolCall": {"name": "read_file", "callId": "o1", "args": {"Path": str(mcp), "StartLine": 1, "EndLine": -1}}},
        state_dir=str(sd_w),
    )
    # Bounded followup on target resolves outline recovery.targeted and consumes the open window
    ptu.evaluate_hook(
        {"conversationId": "s-w", "stepIdx": 2, "toolCall": {"name": "read_file", "callId": "r2", "args": {"Path": str(mcp), "StartLine": 1, "EndLine": 40}}},
        state_dir=str(sd_w),
    )
    # Advance stepIdx well beyond default regret_window_steps=2; window was consumed -> recovery.none stays 0!
    ptu.evaluate_hook(
        {"conversationId": "s-w", "stepIdx": 15, "toolCall": {"name": "run_command", "callId": "c15", "args": {"CommandLine": "echo done"}}},
        state_dir=str(sd_w),
    )
    row = read_outcomes_ledger(sd_w)["by_key"]["antigravity|unknown|outline"]
    assert row["recovery"]["targeted"] == 1 and row["recovery"]["none"] == 0

    # Unfollowed outline_pull open window closes cleanly to recovery.none once step advances
    ptu.evaluate_hook(
        {"conversationId": "s-u", "stepIdx": 1, "toolCall": {"name": "run_command", "callId": "p1", "args": {"CommandLine": f"cg-outline {canon_a}"}}},
        state_dir=str(sd_w),
    )
    ptu.evaluate_hook(
        {"conversationId": "s-u", "stepIdx": 10, "toolCall": {"name": "run_command", "callId": "p10", "args": {"CommandLine": "echo next"}}},
        state_dir=str(sd_w),
    )
    row_pull = read_outcomes_ledger(sd_w)["by_key"]["antigravity|unknown|outline_pull"]
    assert row_pull["recovery"]["none"] == 1 and row_pull["regret"]["none"] == 1


def test_open_outcome_window_preserves_scalar_meta_across_normalisation(tmp_path: Path) -> None:
    ledger = tmp_path / "outcomes.json"
    long_text = "x" * 200
    outcomes.open_outcome_window(
        "claude",
        "claude-sonnet-4-6",
        "output_spool",
        "s-meta",
        "spool:sp_001",
        step_idx=3,
        regret_window_steps=4,
        ledger_path=ledger,
        meta={
            "spool_id": "sp_001",
            "cmd_sig": "shell:pytest",
            "total_lines": 250,
            "ratio": 0.5,
            "flag": True,
            "long_str": long_text,
            "k7": 7,
            "k8": 8,
            "k9_dropped": 9,
            "nested": {"bad": 1},
            "list_val": [1, 2],
            "": "empty_key_dropped",
        },
    )
    # Trigger another unrelated write so _normalise_outcomes runs against the persisted open window
    outcomes.record_direct_outcome(
        "claude",
        "claude-sonnet-4-6",
        "outline",
        "applied",
        ledger,
        session_id="s-other",
        step_idx=1,
        call_id="c-other",
    )
    loaded = outcomes.load_outcomes(ledger)
    windows = loaded["open_windows"]
    assert len(windows) == 1
    meta = next(iter(windows.values()))["meta"]
    assert meta["spool_id"] == "sp_001"
    assert meta["cmd_sig"] == "shell:pytest"
    assert meta["total_lines"] == 250
    assert meta["ratio"] == 0.5
    assert meta["flag"] is True
    assert meta["long_str"] == "x" * 160
    assert len(meta) == 8
    assert "k9_dropped" not in meta
    assert "nested" not in meta
    assert "list_val" not in meta
    assert "" not in meta


