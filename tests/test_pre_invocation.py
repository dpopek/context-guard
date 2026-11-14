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
                "files": {
                    "/tmp/old.py": {
                        "sha256": "aaa",
                        "reads": [[1, 100, 120], [101, 200, 250]],
                    },
                    "/tmp/mixed.py": {
                        "sha256": "bbb",
                        "reads": [[1, 50, 200], [51, 100, 262]],
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
    assert updated_state["files"]["/tmp/mixed.py"]["reads"] == [[51, 100, 262]]


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
                "files": {
                    "/tmp/early.md": {"sha256": "abc", "reads": [[1, -1, 2]]},
                    "/tmp/late.md": {"sha256": "def", "reads": [[1, -1, 7]]},
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
    assert updated["files"]["/tmp/early.md"]["reads"] == [[1, -1, 2]]


def test_rewind_to_zero_in_pre_invocation_clears_cached_reads_and_cursor(
    pre_inv_env: tuple[Path, Path],
) -> None:
    state_dir, transcript_file = pre_inv_env
    state_file = state_dir / ".context_guard_state.json"
    state_file.write_text(
        json.dumps(
            {
                "files": {
                    "/tmp/skill.md": {
                        "sha256": "abc",
                        "reads": [[1, -1, 2]],
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
