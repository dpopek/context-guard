from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from hooks.pre_invocation import (
    BYTES_THRESHOLD,
    STEP_THRESHOLD,
    WARN_COOLDOWN_STEPS,
    handle_pre_invocation,
    inspect_transcript_checkpoint,
)


@pytest.fixture
def pre_inv_env(tmp_path: Path) -> tuple[Path, Path]:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    transcript_file = tmp_path / "transcript.jsonl"
    return state_dir, transcript_file


def test_below_thresholds_returns_empty_dict(pre_inv_env: tuple[Path, Path]) -> None:
    state_dir, transcript_file = pre_inv_env
    transcript_file.write_text(
        json.dumps({"step_index": 10, "type": "USER_INPUT", "content": "hi"}) + "\n",
        encoding="utf-8",
    )
    res = handle_pre_invocation(
        {
            "conversationId": "conv-1",
            "initialNumSteps": 25,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert res == {}


def test_step_threshold_injects_ephemeral_message_and_records_cooldown(
    pre_inv_env: tuple[Path, Path],
) -> None:
    state_dir, transcript_file = pre_inv_env
    res_80 = handle_pre_invocation(
        {
            "conversationId": "conv-1",
            "initialNumSteps": STEP_THRESHOLD,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert "injectSteps" in res_80
    msg = res_80["injectSteps"][0]["ephemeralMessage"]
    assert "CONTEXT-GUARD AUTO-COMPACT SENSOR" in msg
    assert "/compact" in msg

    res_85 = handle_pre_invocation(
        {
            "conversationId": "conv-1",
            "initialNumSteps": STEP_THRESHOLD + 5,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert res_85 == {}

    res_100 = handle_pre_invocation(
        {
            "conversationId": "conv-1",
            "initialNumSteps": STEP_THRESHOLD + WARN_COOLDOWN_STEPS,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert "injectSteps" in res_100


def test_bytes_threshold_injects_ephemeral_message_below_step_limit(
    pre_inv_env: tuple[Path, Path],
) -> None:
    state_dir, transcript_file = pre_inv_env
    big_line = json.dumps(
        {"step_index": 12, "type": "GENERIC", "content": "x" * (BYTES_THRESHOLD + 1024)}
    )
    transcript_file.write_text(big_line + "\n", encoding="utf-8")
    res = handle_pre_invocation(
        {
            "conversationId": "conv-1",
            "initialNumSteps": 15,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert "injectSteps" in res
    assert "KB" in res["injectSteps"][0]["ephemeralMessage"]


def test_checkpoint_resets_step_and_byte_counters_and_prunes_old_reads(
    pre_inv_env: tuple[Path, Path],
) -> None:
    state_dir, transcript_file = pre_inv_env
    state_file = state_dir / ".context_guard_state.json"
    state_file.write_text(
        json.dumps(
            {
                "read_ledger_schema": 2,
                "files": {
                    "/tmp/old.py": {
                        "sha256": "aaa",
                        "reads": [[1, 100, 120, 2], [101, 200, 250, 2]],
                    },
                    "/tmp/mixed.py": {
                        "sha256": "bbb",
                        "reads": [[1, 50, 200, 2], [51, 100, 262, 2]],
                    },
                },
                "last_compact_warn_step": 240,
            }
        ),
        encoding="utf-8",
    )
    lines = [
        json.dumps(
            {
                "step_index": 100,
                "type": "GENERIC",
                "content": "y" * (BYTES_THRESHOLD + 5000),
            }
        ),
        json.dumps(
            {
                "step_index": 258,
                "source": "SYSTEM",
                "type": "CHECKPOINT",
                "content": "# Resuming",
            }
        ),
        json.dumps({"step_index": 262, "type": "USER_INPUT", "content": "next task"}),
    ]
    transcript_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = handle_pre_invocation(
        {
            "conversationId": "conv-1",
            "initialNumSteps": 263,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert res == {}

    updated_state = json.loads(state_file.read_text(encoding="utf-8"))
    assert updated_state["last_checkpoint_step"] == 258
    assert "/tmp/old.py" not in updated_state["files"]
    assert updated_state["files"]["/tmp/mixed.py"]["reads"] == [[51, 100, 262, 2]]


def test_multiple_checkpoints_use_latest_checkpoint_and_handle_malformed_jsonl(
    pre_inv_env: tuple[Path, Path],
) -> None:
    _state_dir, transcript_file = pre_inv_env
    lines = [
        json.dumps({"step_index": 80, "type": "CHECKPOINT", "content": "first"}),
        "{corrupted json line CHECKPOINT",
        json.dumps({"step_index": 190, "type": "CHECKPOINT", "content": "second"}),
        json.dumps({"step_index": 195, "type": "USER_INPUT", "content": "ok"}),
    ]
    transcript_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    last_cp, bytes_after, _cursor = inspect_transcript_checkpoint(str(transcript_file))
    assert last_cp == 190
    assert 10 < bytes_after < 200


def test_cli_subprocess_handles_valid_and_malformed_stdin(
    pre_inv_env: tuple[Path, Path],
) -> None:
    state_dir, transcript_file = pre_inv_env
    script = Path(__file__).resolve().parent.parent / "hooks" / "pre_invocation.py"
    bad_proc = subprocess.run(
        [sys.executable, str(script)],
        input="{bad json",
        text=True,
        capture_output=True,
        check=False,
    )
    assert bad_proc.returncode == 0
    assert json.loads(bad_proc.stdout) == {}

    valid_payload = json.dumps(
        {
            "conversationId": "conv-cli",
            "artifactDirectoryPath": str(state_dir),
            "initialNumSteps": STEP_THRESHOLD + 2,
            "transcriptPath": str(transcript_file),
        }
    )
    good_proc = subprocess.run(
        [sys.executable, str(script)],
        input=valid_payload,
        text=True,
        capture_output=True,
        check=False,
    )
    assert good_proc.returncode == 0
    out = json.loads(good_proc.stdout)
    assert "injectSteps" in out


def test_inspect_transcript_checkpoint_returns_the_cursor_without_mutating_input(
    pre_inv_env: tuple[Path, Path],
) -> None:
    _state_dir, transcript_file = pre_inv_env
    line1 = json.dumps({"step_index": 50, "type": "CHECKPOINT", "content": "cp1"}) + "\n"
    line2 = json.dumps({"step_index": 55, "type": "USER_INPUT", "content": "hello"}) + "\n"
    transcript_file.write_bytes((line1 + line2).encode("utf-8"))
    previous = {"path": "/elsewhere/transcript.jsonl", "inode": 1, "offset": 0}
    snapshot = dict(previous)

    scan = inspect_transcript_checkpoint(str(transcript_file), previous)

    assert previous == snapshot
    assert scan.last_cp_step == 50
    assert scan.bytes_since_cp == len(line2.encode("utf-8"))
    assert scan.cursor is not None
    assert scan.cursor["offset"] == len((line1 + line2).encode("utf-8"))


def test_incremental_transcript_cursor_seeks_from_previous_offset(
    pre_inv_env: tuple[Path, Path],
) -> None:
    _state_dir, transcript_file = pre_inv_env
    line1 = json.dumps({"step_index": 50, "type": "CHECKPOINT", "content": "cp1"}) + "\n"
    line2 = json.dumps({"step_index": 55, "type": "USER_INPUT", "content": "hello"}) + "\n"
    transcript_file.write_bytes((line1 + line2).encode("utf-8"))

    scan_1 = inspect_transcript_checkpoint(str(transcript_file))
    assert scan_1.last_cp_step == 50
    assert scan_1.bytes_since_cp == len(line2.encode("utf-8"))
    assert scan_1.cursor is not None
    assert scan_1.cursor["offset"] == len((line1 + line2).encode("utf-8"))

    line3 = json.dumps({"step_index": 60, "type": "PLANNER_RESPONSE", "content": "world"}) + "\n"
    with open(transcript_file, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line3)

    full_transcript = transcript_file.parent / "transcript_full.jsonl"
    full_transcript.write_text("x" * (BYTES_THRESHOLD + 2048), encoding="utf-8")

    scan_2 = inspect_transcript_checkpoint(str(transcript_file), scan_1.cursor)
    assert scan_2.last_cp_step == 50
    assert scan_2.bytes_since_cp >= BYTES_THRESHOLD + 2048
    assert scan_2.cursor is not None
    assert scan_2.cursor["offset"] == len((line1 + line2 + line3).encode("utf-8"))


def test_rewind_to_earlier_step_lowers_invocation_high_water_mark(
    pre_inv_env: tuple[Path, Path],
) -> None:
    state_dir, transcript_file = pre_inv_env
    state_file = state_dir / ".context_guard_state.json"
    state_file.write_text(
        json.dumps(
            {
                "read_ledger_schema": 2,
                "files": {
                    "/tmp/early.md": {"sha256": "abc", "reads": [[1, -1, 2, 2]]},
                    "/tmp/late.md": {"sha256": "def", "reads": [[1, -1, 7, 2]]},
                },
                "max_step_idx": 25,
                "max_inv_steps": 25,
            }
        ),
        encoding="utf-8",
    )
    transcript_file.write_text(
        json.dumps({"step_index": 5, "type": "USER_INPUT", "content": "rewound"}) + "\n",
        encoding="utf-8",
    )
    handle_pre_invocation(
        {
            "conversationId": "conv-rewind-5",
            "initialNumSteps": 5,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    updated = json.loads(state_file.read_text(encoding="utf-8"))
    assert updated["max_inv_steps"] == 5
    assert updated["max_step_idx"] == 5
    assert list(updated["files"]) == ["/tmp/early.md"]
    assert updated["files"]["/tmp/early.md"]["reads"] == [[1, -1, 2, 2]]


def test_rewind_to_zero_in_pre_invocation_clears_cached_reads_and_cursor(
    pre_inv_env: tuple[Path, Path],
) -> None:
    state_dir, transcript_file = pre_inv_env
    state_file = state_dir / ".context_guard_state.json"
    state_file.write_text(
        json.dumps(
            {
                "read_ledger_schema": 2,
                "files": {
                    "/tmp/skill.md": {
                        "sha256": "abc",
                        "reads": [[1, -1, 2, 2]],
                        "outlined": True,
                        "outlined_step": 2,
                    }
                },
                "max_step_idx": 25,
                "max_inv_steps": 25,
                "last_checkpoint_step": 10,
                "last_compact_warn_step": 20,
                "transcript_cursor": {"path": str(transcript_file), "inode": 1, "offset": 999},
            }
        ),
        encoding="utf-8",
    )
    transcript_file.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "rewound start"}) + "\n",
        encoding="utf-8",
    )
    res = handle_pre_invocation(
        {
            "conversationId": "conv-rewind",
            "initialNumSteps": 0,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert res == {}
    updated = json.loads(state_file.read_text(encoding="utf-8"))
    assert updated["files"] == {}
    assert updated["max_step_idx"] == 0
    assert updated["max_inv_steps"] == 0
    assert updated["last_checkpoint_step"] == 0
    assert updated["last_compact_warn_step"] == 0


def test_hard_compact_threshold_injects_hard_stop_directive(
    pre_inv_env: tuple[Path, Path],
) -> None:
    state_dir, transcript_file = pre_inv_env
    res_hard = handle_pre_invocation(
        {
            "conversationId": "conv-hard",
            "initialNumSteps": 210,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert "injectSteps" in res_hard
    msg = res_hard["injectSteps"][0]["ephemeralMessage"]
    assert "CONTEXT-GUARD AUTO-COMPACT HARD STOP" in msg
    assert "MANDATORY HARD STOP" in msg
    assert "DO NOT start the next plan task" in msg
    assert "Do NOT start any new multi-step" in msg


def test_subagent_transcript_skips_soft_compact_and_injects_ceiling_at_hard_threshold(
    pre_inv_env: tuple[Path, Path],
) -> None:
    state_dir, transcript_file = pre_inv_env
    sub_lines = [
        json.dumps(
            {
                "step_index": 0,
                "type": "USER_INPUT",
                "content": "The following is a <SYSTEM_MESSAGE> not actually sent by the user.\n<SYSTEM_MESSAGE>\nAudit CORE backlog",
            }
        ),
        json.dumps(
            {"step_index": 1, "type": "PLANNER_RESPONSE", "content": "Starting subagent work"}
        ),
    ]
    transcript_file.write_text("\n".join(sub_lines) + "\n", encoding="utf-8")

    res_soft = handle_pre_invocation(
        {
            "conversationId": "sub-conv",
            "initialNumSteps": 90,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert res_soft == {}

    with open(transcript_file, "a", encoding="utf-8") as fh:
        fh.write(
            json.dumps({"step_index": 2, "type": "PLANNER_RESPONSE", "content": "More work"})
            + "\n"
        )

    res_hard = handle_pre_invocation(
        {
            "conversationId": "sub-conv",
            "initialNumSteps": 205,
            "transcriptPath": str(transcript_file),
        },
        state_dir=str(state_dir),
    )
    assert "injectSteps" in res_hard
    msg = res_hard["injectSteps"][0]["ephemeralMessage"]
    assert "CONTEXT-GUARD SUBAGENT CONTEXT CEILING" in msg
    assert "send_message" in msg


def test_real_subagent_system_message_step0_and_parent_system_message_later(
    tmp_path: Path,
) -> None:
    sub_dir = tmp_path / "subagent"
    sub_dir.mkdir()
    sub_transcript = sub_dir / "transcript.jsonl"
    sub_lines = [
        json.dumps(
            {
                "step_index": 0,
                "source": "SYSTEM",
                "type": "SYSTEM_MESSAGE",
                "content": (
                    "The following is a <SYSTEM_MESSAGE> not actually sent by the user.\n"
                    "<SYSTEM_MESSAGE>\nSubagent task quoting <USER_REQUEST> in step 0\n</SYSTEM_MESSAGE>"
                ),
            }
        ),
        json.dumps(
            {
                "step_index": 1,
                "source": "SYSTEM",
                "type": "SYSTEM_MESSAGE",
                "content": "<SYSTEM_MESSAGE>\nNote: quoting <USER_REQUEST> inside system message\n</SYSTEM_MESSAGE>",
            }
        ),
    ]
    for idx in range(2, 95):
        sub_lines.append(
            json.dumps(
                {
                    "step_index": idx,
                    "source": "MODEL",
                    "type": "PLANNER_RESPONSE",
                    "content": "x" * 200,
                }
            )
        )
    sub_transcript.write_text("\n".join(sub_lines) + "\n", encoding="utf-8")

    res_95 = handle_pre_invocation(
        {
            "conversationId": "sub-real",
            "initialNumSteps": 95,
            "transcriptPath": str(sub_transcript),
        },
        state_dir=str(sub_dir),
    )
    assert res_95 == {}
    sub_state = json.loads((sub_dir / ".context_guard_state.json").read_text(encoding="utf-8"))
    assert sub_state["transcript_cursor"]["is_subagent"] is True

    parent_dir = tmp_path / "parent"
    parent_dir.mkdir()
    parent_transcript = parent_dir / "transcript.jsonl"
    parent_lines = [
        json.dumps(
            {
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "content": "<USER_REQUEST>\nFix EOD scanner\n</USER_REQUEST>",
            }
        ),
        json.dumps(
            {
                "source": "SYSTEM",
                "type": "SYSTEM_MESSAGE",
                "content": "<SYSTEM_MESSAGE>\n[Message] sender=subagent\n</SYSTEM_MESSAGE>",
            }
        ),
    ]
    for idx in range(2, 85):
        parent_lines.append(
            json.dumps(
                {
                    "step_index": idx,
                    "source": "MODEL",
                    "type": "PLANNER_RESPONSE",
                    "content": "y" * 200,
                }
            )
        )
    parent_transcript.write_text("\n".join(parent_lines) + "\n", encoding="utf-8")

    res_parent = handle_pre_invocation(
        {
            "conversationId": "parent-real",
            "initialNumSteps": 85,
            "transcriptPath": str(parent_transcript),
        },
        state_dir=str(parent_dir),
    )
    assert "injectSteps" in res_parent
    parent_msg = res_parent["injectSteps"][0]["ephemeralMessage"]
    assert "CONTEXT-GUARD AUTO-COMPACT SENSOR" in parent_msg
    parent_state = json.loads(
        (parent_dir / ".context_guard_state.json").read_text(encoding="utf-8")
    )
    assert parent_state["transcript_cursor"]["is_subagent"] is False


def test_full_transcript_inode_change_resets_full_offset(
    tmp_path: Path,
) -> None:
    import os

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True)
    compact = logs_dir / "transcript.jsonl"
    full_file = logs_dir / "transcript_full.jsonl"
    compact.write_text(json.dumps({"step_index": 1, "type": "USER_INPUT"}) + "\n", encoding="utf-8")
    full_file.write_text(
        json.dumps({"step_index": 2, "type": "CHECKPOINT"}) + "\n" + "x" * 200 + "\n",
        encoding="utf-8",
    )

    scan_1 = inspect_transcript_checkpoint(str(compact), None)
    assert scan_1.cursor is not None
    assert scan_1.last_cp_step == 2
    assert scan_1.cursor["full_inode"] == full_file.stat().st_ino

    # Replace transcript_full.jsonl with a larger file (or simulate inode rotation via stale full_inode)
    # containing a checkpoint at byte 0 (< previous full_offset) so only an inode-triggered reset to 0 sees it.
    replacement = logs_dir / "transcript_full.jsonl.new"
    replacement.write_text(
        json.dumps({"step_index": 9, "type": "CHECKPOINT"}) + "\n" + "y" * 400 + "\n",
        encoding="utf-8",
    )
    os.replace(replacement, full_file)

    stale_cursor = dict(scan_1.cursor)
    if full_file.stat().st_ino == stale_cursor["full_inode"]:
        stale_cursor["full_inode"] = int(stale_cursor["full_inode"]) + 99999

    scan_2 = inspect_transcript_checkpoint(str(compact), stale_cursor)
    assert scan_2.cursor is not None
    assert scan_2.last_cp_step == 9
    assert scan_2.cursor["full_inode"] == full_file.stat().st_ino


def test_pre_invocation_pre_compact_and_session_end_invalidate_shadow_and_close_windows(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hooks.config as cfg_mod
    from hooks import outcomes, pre_compact, session_end, telemetry

    sd = tmp_path / "st"
    sd.mkdir()
    sp, op = telemetry.shadow_path_for(sd), outcomes.ledger_path_for(str(sd))
    assert sp is not None and op is not None
    telemetry.record_shadow_read("s1", "/tmp/a.py", 1, 50, 2, 2, "sha1", shadow_path=sp)
    telemetry.record_shadow_read("s1", "/tmp/b.py", 1, 60, 6, 2, "sha2", shadow_path=sp)
    outcomes.open_outcome_window("claude", "m", "outline", "s1", "/tmp/a.py", step_idx=2, regret_window_steps=20, ledger_path=op)
    outcomes.open_outcome_window("claude", "m", "outline", "s1", "/tmp/b.py", step_idx=6, regret_window_steps=20, ledger_path=op)

    # Advance invocation high-water mark to step 6, then rewind to step 4 removing step 6 shadow entry
    assert handle_pre_invocation({"conversationId": "s1", "initialNumSteps": 6}, state_dir=str(sd)) == {}
    assert handle_pre_invocation({"conversationId": "s1", "initialNumSteps": 4}, state_dir=str(sd)) == {}
    paths_s1 = telemetry.load_shadow_ledger(sp)["sessions"].get("s1", {}).get("paths", {})
    assert any(r[2] == 2 for v in paths_s1.values() for r in v.get("reads", []))
    assert all(int(r[2]) < 4 for v in paths_s1.values() for r in v.get("reads", []))

    # Pre-compact clears all shadow records and closes open outcome windows
    assert pre_compact.handle_pre_compact({"session_id": "s1"}, state_dir=str(sd)) == {}
    paths_after = telemetry.load_shadow_ledger(sp)["sessions"].get("s1", {}).get("paths", {})
    assert paths_after == {}
    outcomes.open_outcome_window("claude", "m", "outline", "s1", "/tmp/c.py", step_idx=9, regret_window_steps=20, ledger_path=op)
    assert session_end.handle_session_end({"session_id": "s1"}, state_dir=str(sd)) == {}
    assert outcomes.load_outcomes(op)["open_windows"] == {}

    # Non-spammy NATIVE_FAIL_CLOSED_DRIFT warning in handle_pre_invocation when security active & drift present
    cursor_hooks = isolated_user_env / ".cursor" / "hooks.json"
    cursor_hooks.parent.mkdir(parents=True)
    cursor_hooks.write_text(json.dumps({"hooks": {"preToolUse": [{"command": "python3 pre_tool_use.py --harness cursor"}]}}), encoding="utf-8")
    cfg_file = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_file.parent.mkdir(parents=True, exist_ok=True)
    cfg_file.write_text(json.dumps({"restricted_bq_datasets": ["raw_sales"]}), encoding="utf-8")
    cfg_mod.clear_config_cache()

    sd2 = tmp_path / "st2"
    sd2.mkdir()
    r1 = handle_pre_invocation({"conversationId": "s-drift", "initialNumSteps": 1}, state_dir=str(sd2))
    assert "injectSteps" in r1 and "NATIVE_FAIL_CLOSED_DRIFT" in r1["injectSteps"][0]["ephemeralMessage"]
    r2 = handle_pre_invocation({"conversationId": "s-drift", "initialNumSteps": 2}, state_dir=str(sd2))
    assert r2 == {}


def test_pre_invocation_runs_drift_probe_outside_locked_state(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.platform_io import LOCK_EX, LOCK_NB, LOCK_UN, flock
    from hooks import config as cfg_mod, drift_probe, policy_engine, pre_compact, pre_invocation, session_end, state_store

    cfg_file = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_file.parent.mkdir(parents=True, exist_ok=True)
    cfg_file.write_text(json.dumps({"restricted_bq_datasets": ["raw_sales"]}), encoding="utf-8")
    cfg_mod.clear_config_cache()

    sd = tmp_path / "lock-check"
    sd.mkdir()
    lock_file = sd / ".context_guard_state.lock"

    # Confirm LOCK_EX | LOCK_NB fails with BlockingIOError when locked_state IS held.
    with state_store.locked_state(sd):
        with open(lock_file, "a+", encoding="utf-8") as fh:
            with pytest.raises(BlockingIOError):
                flock(fh.fileno(), LOCK_EX | LOCK_NB)

    probe_states: list[bool] = []

    def _probe_checking_lock() -> tuple[int, int, int]:
        with open(lock_file, "a+", encoding="utf-8") as fh:
            try:
                flock(fh.fileno(), LOCK_EX | LOCK_NB)
            except BlockingIOError:
                probe_states.append(True)
                return (2, 1, 295)
            flock(fh.fileno(), LOCK_UN)
            probe_states.append(False)
        return (2, 1, 295)

    monkeypatch.setattr(drift_probe, "probe_claude_cli_version", _probe_checking_lock)
    res1 = handle_pre_invocation({"conversationId": "s-lock", "initialNumSteps": 5}, state_dir=str(sd))
    assert res1 == {}
    assert probe_states == [False]
    state_obj = json.loads((sd / ".context_guard_state.json").read_text(encoding="utf-8"))
    assert state_obj.get("drift_warned") is True

    # Second call does not re-probe once drift_warned is persisted.
    res2 = handle_pre_invocation({"conversationId": "s-lock", "initialNumSteps": 6}, state_dir=str(sd))
    assert res2 == {}
    assert probe_states == [False]

    # Transition notifications in pre_invocation, pre_compact, and session_end also run unlocked.
    transition_events: list[tuple[str, bool]] = []

    def _record_transition(event: str, state: dict[str, object], _cfg: object) -> None:
        with open(lock_file, "a+", encoding="utf-8") as fh:
            try:
                flock(fh.fileno(), LOCK_EX | LOCK_NB)
            except BlockingIOError:
                transition_events.append((event, True))
                return
            flock(fh.fileno(), LOCK_UN)
            transition_events.append((event, False))

    monkeypatch.setattr(pre_invocation, "notify_session_transition", _record_transition)
    monkeypatch.setattr(pre_compact, "notify_session_transition", _record_transition)
    monkeypatch.setattr(policy_engine, "notify_session_transition", _record_transition)

    handle_pre_invocation({"conversationId": "s-lock", "initialNumSteps": 2}, state_dir=str(sd))
    pre_compact.handle_pre_compact({"session_id": "s-lock"}, state_dir=str(sd))
    session_end.handle_session_end({"session_id": "s-lock"}, state_dir=str(sd))
    assert transition_events == [("rewind", False), ("compact", False), ("session_end", False)]


def test_pre_compact_handles_value_and_type_errors_fail_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from hooks import pre_compact

    sd = tmp_path / "pc-err"
    sd.mkdir()
    (sd / ".context_guard_state.json").write_text(json.dumps({"files": {}, "read_ledger_schema": 2}), encoding="utf-8")

    def _bad_compaction(_state: dict[str, object], checkpoint_step: int | None = None) -> None:
        _ = checkpoint_step
        raise ValueError("corrupt step value")

    monkeypatch.setattr(pre_compact, "apply_compaction_boundary", _bad_compaction)
    assert pre_compact.handle_pre_compact({"session_id": "s-err"}, state_dir=str(sd)) == {}
    assert "pre_compact skipped: ValueError" in capsys.readouterr().err
