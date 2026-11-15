"""Unified session lifecycle transitions for conversation rewind and context compaction."""
from __future__ import annotations

import os
from typing import Any, Iterable

from hooks.state_store import filter_reads

PENDING_READ_TTL_SECONDS = 3600.0
MAX_PENDING_READS_PER_FILE = 32
COMPLETED_READ_IDS_MAX = 128

def _trim_fifo(mapping: dict[str, Any], limit: int) -> dict[str, Any]:
    while len(mapping) > limit:
        mapping.pop(next(iter(mapping)))
    return mapping

def gc_pending_reads(raw_pending: Any, now_ts: float) -> dict[str, Any]:
    """Return bounded non-stale `pending_reads` mapping (TTL <= 1h, FIFO <= 32)."""
    if not isinstance(raw_pending, dict):
        return {}
    kept = {
        cid: rec for cid, rec in raw_pending.items()
        if isinstance(cid, str) and isinstance(rec, dict) and not (
            isinstance((ts := rec.get("ts")), (int, float))
            and not isinstance(ts, bool) and (now_ts - float(ts)) > PENDING_READ_TTL_SECONDS
        )
    }
    return _trim_fifo(kept, MAX_PENDING_READS_PER_FILE)

def store_pending_read(entry: dict[str, Any], call_id: str, record: dict[str, Any], now_ts: float) -> None:
    """GC stale pending reads on `entry` and append `call_id -> record` bounded FIFO."""
    pending_map = gc_pending_reads(entry.get("pending_reads"), now_ts)
    pending_map[call_id] = record
    entry["pending_reads"] = _trim_fifo(pending_map, MAX_PENDING_READS_PER_FILE)

def record_completed_read_id(entry: dict[str, Any], call_id: str, tier: int, credited: bool) -> None:
    """Record terminal `call_id` outcome in bounded (`<= 128` FIFO) `completed_read_ids` map."""
    if not call_id:
        return
    raw = entry.get("completed_read_ids")
    completed: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}
    completed[call_id] = {"tier": tier, "credited": credited}
    entry["completed_read_ids"] = _trim_fifo(completed, COMPLETED_READ_IDS_MAX)

def invalidate_mutated_paths(state: dict[str, Any], targets: Iterable[str]) -> bool:
    """Clear cached read intervals, pending reads, completed read IDs, and outline metadata on paths."""
    if not isinstance((files_map := state.get("files")), dict):
        return False
    mutated = False
    for raw_path in targets:
        if not raw_path:
            continue
        for key in (os.path.realpath(raw_path), raw_path):
            if key not in files_map:
                continue
            if isinstance((entry := files_map.pop(key)), dict):
                entry["reads"] = []
                entry.pop("pending_reads", None)
                entry.pop("completed_read_ids", None)
            mutated = True
    return mutated

def _int_or_zero(value: Any) -> int:
    try:
        return 0 if isinstance(value, bool) else int(value or 0)
    except (TypeError, ValueError):
        return 0

def _pop_keys(mapping: dict[str, Any], keys: tuple[str, ...]) -> bool:
    mutated = False
    for key in keys:
        if mapping.pop(key, None) is not None:
            mutated = True
    return mutated

def prune_state_on_rewind(state: dict[str, Any], current_step: int, inclusive: bool = True) -> bool:
    """Prune cached file reads, outlines, and cursors rolled back by a rewind."""
    def keep_read(step: int) -> bool:
        return step < current_step if inclusive else step <= current_step

    def keep_outline(step: int) -> bool:
        return current_step != 0 and keep_read(step)

    mutated = filter_reads(state, keep_read, keep_outline)
    last_cp = _int_or_zero(state.get("last_checkpoint_step"))
    if (last_cp >= current_step and last_cp != 0) or (current_step == 0 and "transcript_cursor" in state):
        if last_cp >= current_step and last_cp != 0:
            state["last_checkpoint_step"] = 0
        state.pop("transcript_cursor", None)
        mutated = True
    if (lw := _int_or_zero(state.get("last_compact_warn_step"))) >= current_step and lw != 0:
        state["last_compact_warn_step"] = 0
        mutated = True
    for step_key in ("max_step_idx", "max_tool_step_idx"):
        if step_key in state and _int_or_zero(state.get(step_key)) > current_step:
            state[step_key] = current_step
            mutated = True
    if current_step == 0:
        if _pop_keys(state, ("gitlab_fallback_allowed", "bq_raw_fallback_allowed")):
            mutated = True
        if isinstance((files_map := state.get("files")), dict):
            for entry in files_map.values():
                if isinstance(entry, dict) and entry.pop("completed_read_ids", None) is not None:
                    mutated = True
    return _pop_keys(state, ("policy_state",)) or mutated

def apply_compaction_boundary(state: dict[str, Any], checkpoint_step: int | None = None) -> None:
    """Reset or prune session ledger state across full PreCompact (`None`) or incremental checkpoint."""
    _pop_keys(state, ("gitlab_fallback_allowed", "bq_raw_fallback_allowed", "policy_state"))
    if checkpoint_step is None:
        state["files"] = {}
        state["last_compact_warn_step"] = 0
        return
    state["last_checkpoint_step"] = checkpoint_step
    filter_reads(state, lambda step: step > checkpoint_step)
    if _int_or_zero(state.get("last_compact_warn_step")) <= checkpoint_step:
        state["last_compact_warn_step"] = 0
