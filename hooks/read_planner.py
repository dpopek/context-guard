"""Silent range-trim and machine-artifact auto-outline planner for Context-Guard PreToolUse."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, NamedTuple

from hooks.config import load_runtime_config
from hooks.file_io import SHA256_MAX_HASH_BYTES, compute_file_sha256, count_file_lines_streaming
from hooks.json_outliners import (
    PreparedOutline, build_transcript_jsonl_outline, classify_special_read_target,
    finalize_outline_text, materialize_unwrap_write, prepare_mcp_step_outline,
)
from hooks.outcomes import estimate_delivered_end_line
from hooks.session_lifecycle import prune_state_on_rewind
from hooks.state_store import locked_state, merge_intervals, warn
from hooks.telemetry import BINARY_MEDIA_EXTENSIONS, HARNESS_READ_CAPS, cap_end_line_for_harness, measure_slice_bytes
from integrations.atlassian_twg import prepare_twg_stdout_outline

TRANSCRIPT_OUTLINE_LINE_THRESHOLD = 8
FOLLOWUP_TARGETED_MAX_LINES = 250


class FileReadOutcome(NamedTuple):
    """Result of evaluating one file read against the session ledger."""

    decision: dict[str, Any]
    intervention: str | None = None
    effective_step_idx: int = 0
    followup_resolution: tuple[str, str] | None = None


def normalize_effective_bounds(req_start: int, req_end: int, target_lines: int) -> tuple[int, int] | None:
    """Normalize 1-based `[req_start, req_end]` against `target_lines`; `None` on invalid/past-EOF bounds."""
    if req_start <= 0 or req_end < -1 or (req_end != -1 and req_end < req_start):
        return None
    if target_lines <= 0:
        return (req_start, req_end)
    if req_start > target_lines:
        return None
    return (req_start, target_lines if req_end == -1 else req_end)


def normalize_recorded_ranges(recorded_ranges: list[list[int]], target_lines: int) -> list[list[int]]:
    """Normalize legacy `-1` endpoints to `target_lines` (`> 0`) and drop invalid intervals."""
    out: list[list[int]] = []
    for entry in recorded_ranges:
        if not isinstance(entry, list) or len(entry) < 3:
            continue
        r_start, r_end, r_step = int(entry[0]), int(entry[1]), int(entry[2])
        if r_start <= 0 or r_end < -1 or (r_end != -1 and r_end < r_start):
            continue
        if target_lines > 0:
            if r_start > target_lines:
                continue
            r_end = target_lines if r_end == -1 else r_end
        out.append([r_start, r_end, r_step])
    return out


def covering_read_step(
    recorded_ranges: list[list[int]], req_start: int, req_end: int, target_lines: int = 0
) -> int | None:
    """Step of the recorded read that covers `[req_start, req_end]`, or `None` when none does."""
    bounds = normalize_effective_bounds(req_start, req_end, target_lines)
    if bounds is None:
        return None
    eff_start, eff_end = bounds
    for entry in merge_intervals(normalize_recorded_ranges(recorded_ranges, target_lines)):
        r_start, r_end, r_step = int(entry[0]), int(entry[1]), int(entry[2])
        if r_start <= eff_start and (r_end == -1 or (eff_end != -1 and r_end >= eff_end)):
            return r_step
    return None


def trim_partially_covered_range(
    reads: list[list[int]], req_start: int, req_end: int, target_lines: int = 0
) -> tuple[int, int] | None:
    """Trim leading or trailing overlap against already-read intervals."""
    bounds = normalize_effective_bounds(req_start, req_end, target_lines)
    if bounds is None or bounds[1] == -1:
        return None
    eff_start, eff_end = bounds
    new_start, new_end = eff_start, eff_end
    for entry in merge_intervals(normalize_recorded_ranges(reads, target_lines)):
        r_start, r_end = int(entry[0]), int(entry[1])
        if r_end == -1:
            if r_start <= new_end:
                new_end = r_start - 1
            continue
        if r_start <= new_start <= r_end < new_end:
            new_start = r_end + 1
        elif new_start < r_start <= new_end <= r_end:
            new_end = r_start - 1
    return (new_start, new_end) if (new_start, new_end) != (eff_start, eff_end) and new_start <= new_end else None


def _is_atlassian_twg_active() -> bool:
    runtime_cfg = load_runtime_config()
    integrations_cfg = runtime_cfg.get("integrations")
    return isinstance(integrations_cfg, dict) and integrations_cfg.get("atlassian_twg") == "active"


def _prepare_special_outline(
    canon: str,
    st_size: int,
    start_line: int,
    end_line: int,
    state_dir_path: Path,
    *,
    twg_active: bool | None = None,
) -> PreparedOutline | None:
    special = classify_special_read_target(canon)
    file_path = Path(canon)
    if special.is_mcp_step_output:
        return prepare_mcp_step_outline(file_path, st_size)
    if special.is_twg_stdout:
        is_active = _is_atlassian_twg_active() if twg_active is None else twg_active
        if not is_active:
            return None
        return prepare_twg_stdout_outline(file_path, st_size, cache_dir=(state_dir_path / "twg_cache"))
    if special.is_transcript_log:
        tr = build_transcript_jsonl_outline(file_path, st_size, SHA256_MAX_HASH_BYTES, start_line=start_line, end_line=end_line)
        if tr is not None and tr[0] > TRANSCRIPT_OUTLINE_LINE_THRESHOLD:
            return PreparedOutline(total_lines=tr[0], outline_text=tr[1])
    return None


def _build_outline_hint(harness: str, read_tool: str, file_arg: str) -> str:
    if harness == "codex":
        return f"Use `sed -n 'START,ENDp' {file_arg}` to read specific line ranges."
    if harness in ("claude", "cursor"):
        return f"Call `Read` with targeted `offset` and `limit` for `{file_arg}`."
    return f"Call `{read_tool}` with targeted `StartLine` and `EndLine` for `{file_arg}`."


def _mirror_unwrapped_entry(
    files_map: dict[str, Any], actual_unwrapped: str, eff_step: int,
    mark_outlined: bool = False, total_lines: int = 0, read_interval: list[int] | None = None,
    pending_followup_kind: str | None = None, mirror_source: str | None = None,
) -> None:
    if not actual_unwrapped or not os.path.isfile(actual_unwrapped):
        return
    u_sha = compute_file_sha256(actual_unwrapped) or ""
    existing = files_map.get(actual_unwrapped)
    if not isinstance(existing, dict) or existing.get("sha256") != u_sha:
        existing = {"sha256": u_sha, "reads": []}
    if mark_outlined:
        existing["outlined"] = True
        existing["outlined_step"] = eff_step
        if total_lines > 0:
            existing["outlined_total_lines"] = total_lines
    if pending_followup_kind is not None:
        existing["pending_followup_kind"] = pending_followup_kind
    if mirror_source is not None:
        existing["mirror_source"] = mirror_source
    if read_interval is not None:
        reads = existing.setdefault("reads", [])
        if isinstance(reads, list):
            reads.append(read_interval)
    files_map[actual_unwrapped] = existing


def handle_file_read_verdict(
    state_dir_path: Path,
    raw_path: str,
    start_line: int,
    end_line: int,
    byte_offset: int,
    step_idx: int,
    allow_auto_outline: bool = True,
    path_arg_key: str = "Path",
    auto_increment_step: bool = False,
    harness: str = "antigravity",
    read_tool: str = "read_file",
    can_trim: bool = True,
    can_redirect_path: bool = True,
    locked_state_fn: Callable[[Path], Any] = locked_state,
    unwrap_writer: Callable[[Any], str | None] = materialize_unwrap_write,
) -> FileReadOutcome:
    """Evaluate a file read, applying silent range trims and machine-artifact auto-outlines."""
    canon = os.path.realpath(raw_path)
    if not os.path.isfile(canon) or Path(canon).suffix.lower() in BINARY_MEDIA_EXTENSIONS:
        return FileReadOutcome({"decision": "allow"})
    sha256 = compute_file_sha256(canon)
    if sha256 is None:
        return FileReadOutcome({"decision": "allow"})
    st_size = os.path.getsize(canon)
    special = classify_special_read_target(canon)
    twg_active = special.is_twg_stdout and _is_atlassian_twg_active()
    is_special = special.is_mcp_step_output or twg_active or special.is_transcript_log
    prepared = (
        _prepare_special_outline(canon, st_size, start_line, end_line, state_dir_path, twg_active=twg_active)
        if is_special and byte_offset == 0
        else None
    )

    with locked_state_fn(state_dir_path) as txn:
        state = txn.state
        prev_max_step = int(state.get("max_tool_step_idx") or 0)
        if not auto_increment_step and step_idx > 0 and prev_max_step > 0 and step_idx < prev_max_step:
            prune_state_on_rewind(state, step_idx, inclusive=True)
        if auto_increment_step and step_idx <= 0:
            eff_step = int(state.get("auto_step_seq") or 0) + 1
            state["auto_step_seq"] = eff_step
        else:
            eff_step = step_idx
        if eff_step > int(state.get("max_tool_step_idx") or 0):
            state["max_tool_step_idx"] = eff_step

        files_map = state.setdefault("files", {})
        raw_entry = files_map.get(canon)
        entry = (
            dict(raw_entry)
            if isinstance(raw_entry, dict) and raw_entry.get("sha256") == sha256
            else {"sha256": sha256, "reads": []}
        )
        reads = list(entry.get("reads") or [])
        has_prior_step_reads = any(int(r[2]) != eff_step for r in reads if isinstance(r, list) and len(r) >= 3)
        wants_special_outline = (
            is_special
            and prepared is not None
            and byte_offset == 0
            and (allow_auto_outline or twg_active)
            and not entry.get("outlined")
            and (not has_prior_step_reads or special.is_transcript_log)
            and (
                (end_line == -1 or (end_line - start_line + 1) > TRANSCRIPT_OUTLINE_LINE_THRESHOLD)
                if special.is_transcript_log
                else True
            )
        )
        if wants_special_outline and prepared is not None:
            actual_unwrapped: str | None = None
            out_lines = int(prepared.total_lines)
            if can_redirect_path and prepared.pending_write is not None:
                actual_unwrapped = unwrap_writer(prepared.pending_write)
                if actual_unwrapped:
                    entry["unwrapped_path"] = actual_unwrapped
                    out_lines = count_file_lines_streaming(actual_unwrapped) or out_lines
            entry["outlined"] = True
            entry["outlined_step"] = eff_step
            entry["outlined_total_lines"] = out_lines
            outline_text = finalize_outline_text(prepared, actual_unwrapped)
            is_inline_twg = bool(twg_active and "— full payload inline)" in outline_text)
            if not is_inline_twg:
                entry["pending_followup_kind"] = "outline"
            else:
                entry.pop("pending_followup_kind", None)
            files_map[canon] = entry
            if actual_unwrapped:
                _mirror_unwrapped_entry(
                    files_map, actual_unwrapped, eff_step, mark_outlined=True, total_lines=out_lines,
                    pending_followup_kind=None if is_inline_twg else "outline",
                    mirror_source=None if is_inline_twg else canon,
                )
            if not txn.save():
                warn(f"allowing unguarded read of {canon}: outline marker not persisted")
                return FileReadOutcome({"decision": "allow"}, effective_step_idx=eff_step)
            basename = os.path.basename(canon) or canon
            if is_inline_twg:
                reason = (
                    f"CONTEXT-GUARD TWG INLINE READ: {basename} ({prepared.total_lines} lines) "
                    f"delivered inline to avoid out-of-workspace permission prompts:\n\n{outline_text}\n\n"
                    "No further `read_file` call is needed for this file."
                )
            else:
                hint = _build_outline_hint(harness, read_tool, raw_path or basename)
                reason = (
                    f"CONTEXT-GUARD AUTO-OUTLINE: {basename} has {prepared.total_lines} lines. "
                    f"Full-file read intercepted to save tokens. Structural outline:\n\n{outline_text}\n\n{hint}"
                )
            return FileReadOutcome({"decision": "deny", "reason": reason}, intervention="outline", effective_step_idx=eff_step)

        redirect_path: str | None = None
        wants_redirect_shape = start_line > 1 or end_line != -1 or not allow_auto_outline or twg_active
        if can_redirect_path and (special.is_mcp_step_output or twg_active) and wants_redirect_shape:
            prev_unwrapped = entry.get("unwrapped_path")
            if isinstance(prev_unwrapped, str) and os.path.isfile(prev_unwrapped):
                redirect_path = prev_unwrapped
            elif prepared is not None and prepared.pending_write is not None:
                actual = unwrap_writer(prepared.pending_write)
                if actual:
                    entry["unwrapped_path"] = actual
                    redirect_path = actual
                    reads = []
                    _mirror_unwrapped_entry(
                        files_map, actual, eff_step, mark_outlined=True,
                        total_lines=count_file_lines_streaming(actual) or 0,
                    )

        read_target = redirect_path or canon
        target_lines = count_file_lines_streaming(read_target) or 0
        probe_end = (
            min(target_lines, HARNESS_READ_CAPS.get(harness, (target_lines, 0))[0])
            if (start_line == 1 and end_line == -1 and target_lines > 0)
            else end_line
        )
        trimmed = (
            trim_partially_covered_range(reads, start_line, probe_end, target_lines=target_lines)
            if can_trim and byte_offset == 0
            else None
        )
        if trimmed is not None and target_lines > 0 and trimmed[0] > target_lines:
            trimmed = None
        exec_start, exec_end = trimmed if trimmed is not None else (start_line, end_line)
        capped_end = cap_end_line_for_harness(harness, exec_start, exec_end)
        slice_bytes = measure_slice_bytes(read_target, exec_start, capped_end)
        delivered_end = estimate_delivered_end_line(harness, exec_start, exec_end, target_lines, slice_bytes)
        interval: list[int] | None = None
        if delivered_end is not None and delivered_end > 0 and byte_offset == 0:
            interval = [exec_start, delivered_end, eff_step]
            reads.append(interval)
        entry["reads"] = reads
        files_map[canon] = entry
        if redirect_path and interval is not None:
            _mirror_unwrapped_entry(files_map, redirect_path, eff_step, read_interval=interval)
        followup_resolution: tuple[str, str] | None = None
        if byte_offset == 0:
            pending_kind = entry.pop("pending_followup_kind", None)
            entry.pop("outline_pull_step", None)
            for other in (entry.get("unwrapped_path"), entry.get("mirror_source"), redirect_path):
                if isinstance(other, str) and isinstance(files_map.get(other), dict):
                    other_pending = files_map[other].pop("pending_followup_kind", None)
                    files_map[other].pop("outline_pull_step", None)
                    if pending_kind is None and other_pending is not None:
                        pending_kind = other_pending
            if pending_kind in ("outline", "outline_pull"):
                if start_line == 1 and end_line == -1:
                    res_outcome = "full_bypass"
                elif end_line != -1:
                    res_outcome = "targeted_followup" if (end_line - start_line + 1) <= FOLLOWUP_TARGETED_MAX_LINES else "full_bypass"
                elif target_lines > 0 and (target_lines - start_line + 1) <= FOLLOWUP_TARGETED_MAX_LINES:
                    res_outcome = "targeted_followup"
                else:
                    res_outcome = "full_bypass"
                followup_resolution = (pending_kind, res_outcome)
        txn.dirty = True

        if trimmed is not None:
            ov: dict[str, Any] = {"StartLine": trimmed[0], "EndLine": trimmed[1]}
            if redirect_path:
                ov[path_arg_key] = redirect_path
            return FileReadOutcome(
                {"decision": "allow", "overwrite": ov}, intervention="range_trim",
                effective_step_idx=eff_step, followup_resolution=followup_resolution,
            )
        if redirect_path:
            return FileReadOutcome(
                {"decision": "allow", "overwrite": {path_arg_key: redirect_path}},
                effective_step_idx=eff_step, followup_resolution=followup_resolution,
            )
        return FileReadOutcome({"decision": "allow"}, effective_step_idx=eff_step, followup_resolution=followup_resolution)
