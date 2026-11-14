"""Antigravity PreInvocation hook for checkpoint-aware auto-compact sensing and cache pruning."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, NamedTuple

_PLUGIN_ROOT = str(Path(__file__).resolve().parent.parent)
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from hooks.json_outliners import ANTIGRAVITY_FULL_TRANSCRIPT_NAME
from hooks.session_lifecycle import apply_compaction_boundary, prune_state_on_rewind
from hooks.state_store import (
    emit_json_and_sanitize_stdio,
    locked_state,
    resolve_state_dir,
    warn,
)

STEP_THRESHOLD = 80
HARD_STEP_THRESHOLD = 200
BYTES_THRESHOLD = 512 * 1024  # 512 KB post-checkpoint transcript size
HARD_BYTES_THRESHOLD = 1024 * 1024  # 1024 KB hard compact threshold
WARN_COOLDOWN_STEPS = 20


class TranscriptScan(NamedTuple):
    """Checkpoint position and the cursor to store; `cursor` is None when nothing was read."""

    last_cp_step: int
    bytes_since_cp: int
    cursor: dict[str, Any] | None


def scan_jsonl_incremental(
    file_path: str,
    start_offset: int,
    last_cp_step: int,
    cp_end_offset: int,
    is_subagent: bool = False,
) -> tuple[int, int, int, bool]:
    """Scan JSONL file from start_offset and return (new_offset, last_cp_step, cp_end_offset, is_subagent)."""
    current_offset = start_offset
    with open(file_path, "rb") as fh:
        if start_offset > 0:
            fh.seek(start_offset)
        for raw_line in fh:
            line_offset = current_offset
            current_offset += len(raw_line)
            if (
                b"CHECKPOINT" not in raw_line
                and b"<SYSTEM_MESSAGE>" not in raw_line
                and b"<USER_REQUEST>" not in raw_line
            ):
                continue
            try:
                entry = json.loads(raw_line.decode("utf-8", errors="replace"))
            except (ValueError, TypeError):
                continue
            if not isinstance(entry, dict):
                continue
            entry_type = entry.get("type")
            if entry_type == "CHECKPOINT":
                try:
                    last_cp_step = int(entry.get("step_index") or 0)
                except (ValueError, TypeError):
                    pass
                cp_end_offset = current_offset
            elif entry_type == "USER_INPUT":
                content_str = str(entry.get("content") or "")
                if "<USER_REQUEST>" in content_str:
                    is_subagent = False
                else:
                    raw_step = entry.get("step_index")
                    is_step_zero = (raw_step == 0) or (raw_step is None and line_offset == 0)
                    if is_step_zero and "<SYSTEM_MESSAGE>" in content_str:
                        is_subagent = True
            elif entry_type == "SYSTEM_MESSAGE":
                raw_step = entry.get("step_index")
                is_step_zero = (raw_step == 0) or (raw_step is None and line_offset == 0)
                if is_step_zero:
                    content_str = str(entry.get("content") or "")
                    if "<SYSTEM_MESSAGE>" in content_str:
                        is_subagent = True
    return (current_offset, last_cp_step, cp_end_offset, is_subagent)


_scan_jsonl_incremental = scan_jsonl_incremental


def inspect_transcript_checkpoint(
    transcript_path: str | None,
    cursor: dict[str, Any] | None = None,
) -> TranscriptScan:
    """Scan the transcript from `cursor` (O(delta)) and return the checkpoint and the next cursor."""
    if not transcript_path:
        return TranscriptScan(0, 0, None)
    try:
        canon = os.path.realpath(transcript_path)
        if not os.path.isfile(canon):
            return TranscriptScan(0, 0, None)
        st = os.stat(canon)
        valid_cursor = (
            isinstance(cursor, dict)
            and cursor.get("path") == canon
            and int(cursor.get("inode") or 0) == st.st_ino
            and st.st_size >= int(cursor.get("offset") or 0)
        )
        c = cursor if valid_cursor and isinstance(cursor, dict) else {}
        start_offset = int(c.get("offset") or 0)
        last_cp_step = int(c.get("last_cp_step") or 0)
        cp_end_offset = int(c.get("cp_end_offset") or 0)
        full_offset = int(c.get("full_offset") or 0)
        full_cp_offset = int(c.get("full_cp_offset") or 0)
        full_inode = int(c.get("full_inode") or 0)
        is_subagent = bool(c.get("is_subagent", False))

        new_offset, last_cp_step, cp_end_offset, is_subagent = scan_jsonl_incremental(
            canon, start_offset, last_cp_step, cp_end_offset, is_subagent=is_subagent
        )
        compact_bytes = max(0, new_offset - cp_end_offset)

        full_bytes = 0
        next_full_inode = 0
        full_candidate = Path(canon).with_name(ANTIGRAVITY_FULL_TRANSCRIPT_NAME)
        if full_candidate.is_file():
            full_canon = os.path.realpath(str(full_candidate))
            if full_canon != canon:
                full_st = os.stat(full_canon)
                next_full_inode = full_st.st_ino
                if full_st.st_size < full_offset or next_full_inode != full_inode:
                    full_offset = 0
                    full_cp_offset = 0
                full_offset, full_cp_step, full_cp_offset, full_is_subagent = scan_jsonl_incremental(
                    full_canon, full_offset, last_cp_step, full_cp_offset, is_subagent=is_subagent
                )
                last_cp_step = max(last_cp_step, full_cp_step)
                is_subagent = is_subagent or full_is_subagent
                full_bytes = max(0, full_offset - full_cp_offset)
            else:
                full_offset = 0
                full_cp_offset = 0
        else:
            full_offset = 0
            full_cp_offset = 0

        next_cursor = {
            "path": canon,
            "inode": st.st_ino,
            "offset": new_offset,
            "last_cp_step": last_cp_step,
            "cp_end_offset": cp_end_offset,
            "full_offset": full_offset,
            "full_cp_offset": full_cp_offset,
            "full_inode": next_full_inode,
            "is_subagent": is_subagent,
        }
        return TranscriptScan(last_cp_step, max(compact_bytes, full_bytes), next_cursor)
    except OSError:
        return TranscriptScan(0, 0, None)


def handle_pre_invocation(
    payload: dict[str, Any],
    state_dir: str | None = None,
) -> dict[str, Any]:
    """Evaluate PreInvocation payload, prune pre-checkpoint cache, and inject compact reminder."""
    if not isinstance(payload, dict):
        return {}
    try:
        initial_steps = int(payload.get("initialNumSteps") or 0)
    except (ValueError, TypeError):
        initial_steps = 0

    transcript_path = payload.get("transcriptPath")
    state_dir_path = resolve_state_dir(payload, state_dir)

    should_warn = False
    is_hard_stop = False
    is_subagent = False
    steps_since_cp = 0
    bytes_since_cp = 0
    try:
        with locked_state(state_dir_path) as txn:
            state = txn.state
            mutated = False
            max_seen_inv = int(state.get("max_inv_steps") or state.get("max_step_idx") or 0)
            is_rewind = initial_steps < max_seen_inv or (
                initial_steps == 0 and bool(state.get("files"))
            )
            if is_rewind and prune_state_on_rewind(state, initial_steps, inclusive=True):
                mutated = True
            # The prune leaves the invocation high-water mark alone: it counts invocations,
            # not tool steps, and only this hook moves it (down on a rewind, up otherwise).
            prev_inv = int(state.get("max_inv_steps") or 0)
            if (is_rewind or initial_steps > prev_inv) and prev_inv != initial_steps:
                state["max_inv_steps"] = initial_steps
                mutated = True

            stored_cursor = state.get("transcript_cursor")
            scan = inspect_transcript_checkpoint(
                transcript_path if isinstance(transcript_path, str) else None,
                stored_cursor if isinstance(stored_cursor, dict) else None,
            )
            last_cp_step, bytes_since_cp = scan.last_cp_step, scan.bytes_since_cp
            if scan.cursor is not None and scan.cursor != stored_cursor:
                state["transcript_cursor"] = scan.cursor
                mutated = True
            cursor = state.get("transcript_cursor")
            is_subagent = isinstance(cursor, dict) and bool(cursor.get("is_subagent", False))
            steps_since_cp = max(0, initial_steps - last_cp_step)
            prev_cp_step = int(state.get("last_checkpoint_step") or 0)
            if last_cp_step > prev_cp_step:
                apply_compaction_boundary(state, checkpoint_step=last_cp_step)
                mutated = True

            is_hard_stop = (
                steps_since_cp >= HARD_STEP_THRESHOLD or bytes_since_cp >= HARD_BYTES_THRESHOLD
            )
            threshold_crossed = (
                is_hard_stop
                if is_subagent
                else (
                    is_hard_stop
                    or steps_since_cp >= STEP_THRESHOLD
                    or bytes_since_cp >= BYTES_THRESHOLD
                )
            )
            if threshold_crossed:
                last_warn_step = int(state.get("last_compact_warn_step") or 0)
                if (
                    last_warn_step <= last_cp_step
                    or last_warn_step == 0
                    or (initial_steps - last_warn_step) >= WARN_COOLDOWN_STEPS
                ):
                    should_warn = True
                    state["last_compact_warn_step"] = max(1, initial_steps)
                    mutated = True

            if mutated:
                txn.dirty = True
    except (OSError, ValueError, TypeError) as exc:
        warn(f"pre_invocation sensor skipped: {type(exc).__name__}: {exc}")

    if not should_warn:
        return {}

    kb_since_cp = max(1, bytes_since_cp // 1024)
    if is_subagent:
        return {
            "injectSteps": [
                {
                    "ephemeralMessage": (
                        f"CONTEXT-GUARD SUBAGENT CONTEXT CEILING: Subagent trajectory has reached "
                        f"{steps_since_cp} steps ({kb_since_cp} KB). Subagents cannot run `/compact`. "
                        "Finish your current atomic step, synthesize your findings into a concise summary "
                        "(<40 lines), and immediately return your response to the parent agent via `send_message`."
                    )
                }
            ]
        }

    if is_hard_stop:
        return {
            "injectSteps": [
                {
                    "ephemeralMessage": (
                        f"CONTEXT-GUARD AUTO-COMPACT HARD STOP: Active context since last checkpoint "
                        f"has reached {steps_since_cp} steps ({kb_since_cp} KB), exceeding the hard ceiling "
                        f"({HARD_STEP_THRESHOLD} steps / {HARD_BYTES_THRESHOLD // 1024} KB). "
                        "MANDATORY HARD STOP: Finish ONLY your current atomic step (if running `/executing-plans`, "
                        "update the progress ledger and DO NOT start the next plan task). "
                        "Do NOT start any new multi-step exploration or implementation phase — immediately yield the turn "
                        "and ask the user to run `/compact` before continuing."
                    )
                }
            ]
        }

    return {
        "injectSteps": [
            {
                "ephemeralMessage": (
                    f"CONTEXT-GUARD AUTO-COMPACT SENSOR: Active context since last checkpoint "
                    f"has reached {steps_since_cp} steps ({kb_since_cp} KB). "
                    "At the end of your current response, display a prominent reminder "
                    "recommending that the user run `/compact` before starting the next phase."
                )
            }
        ]
    }


def main() -> int:
    out_obj: dict[str, Any] = {}
    try:
        raw_input = sys.stdin.read()
        if raw_input.strip():
            payload = json.loads(raw_input)
            out_obj = handle_pre_invocation(payload)
    except Exception as exc:  # noqa: BLE001 - hook CLI must fail open
        warn(f"pre_invocation main failed: {type(exc).__name__}: {exc}")
        out_obj = {}
    return emit_json_and_sanitize_stdio(out_obj)


if __name__ == "__main__":
    raise SystemExit(main())
