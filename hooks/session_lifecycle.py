"""Unified session lifecycle transitions for conversation rewind and context compaction."""

from __future__ import annotations

from typing import Any

from hooks.state_store import filter_reads


def _int_or_zero(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def prune_state_on_rewind(
    state: dict[str, Any],
    current_step: int,
    inclusive: bool = True,
) -> bool:
    """Prune cached file reads, outlines, and cursors rolled back by a rewind."""

    def keep_read(step: int) -> bool:
        return step < current_step if inclusive else step <= current_step

    def keep_outline(step: int) -> bool:
        # A rewind to step 0 restarts the conversation: no outline survives it.
        return current_step != 0 and keep_read(step)

    mutated = filter_reads(state, keep_read, keep_outline)

    last_cp = _int_or_zero(state.get("last_checkpoint_step"))
    if last_cp >= current_step and last_cp != 0:
        state["last_checkpoint_step"] = 0
        state.pop("transcript_cursor", None)
        mutated = True
    elif current_step == 0 and "transcript_cursor" in state:
        state.pop("transcript_cursor", None)
        mutated = True

    last_warn = _int_or_zero(state.get("last_compact_warn_step"))
    if last_warn >= current_step and last_warn != 0:
        state["last_compact_warn_step"] = 0
        mutated = True

    # `max_inv_steps` counts invocations (`initialNumSteps`), not tool steps, and is owned by
    # pre_invocation. Tool step watermarks clamp downwards only when above `current_step`.
    for step_key in ("max_step_idx", "max_tool_step_idx"):
        if step_key in state and _int_or_zero(state.get(step_key)) > current_step:
            state[step_key] = current_step
            mutated = True

    if current_step == 0:
        for list_key in ("gitlab_fallback_allowed", "bq_raw_fallback_allowed"):
            if state.pop(list_key, None) is not None:
                mutated = True

    return mutated


def apply_compaction_boundary(
    state: dict[str, Any],
    checkpoint_step: int | None = None,
) -> None:
    """Reset or prune session ledger state across full PreCompact (`None`) or incremental checkpoint."""
    if checkpoint_step is None:
        state["files"] = {}
        state.pop("gitlab_fallback_allowed", None)
        state.pop("bq_raw_fallback_allowed", None)
        state["last_compact_warn_step"] = 0
        return

    state["last_checkpoint_step"] = checkpoint_step

    def keep_after_checkpoint(step: int) -> bool:
        return step > checkpoint_step

    filter_reads(state, keep_after_checkpoint)
    state.pop("gitlab_fallback_allowed", None)
    state.pop("bq_raw_fallback_allowed", None)
    if _int_or_zero(state.get("last_compact_warn_step")) <= checkpoint_step:
        state["last_compact_warn_step"] = 0
