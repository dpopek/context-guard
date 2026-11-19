#!/usr/bin/env python3
"""PreCompact hook for Claude Code, Cursor, and OpenAI Codex to reset Context-Guard read cache."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

_PLUGIN_ROOT = str(Path(__file__).resolve().parent.parent)
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from core.platform_io import warn  # noqa: E402
from hooks.config import load_runtime_config  # noqa: E402
from hooks.outcomes import close_outcome_windows, ledger_path_for  # noqa: E402
from hooks.policy_engine import notify_session_transition  # noqa: E402
from hooks.session_lifecycle import apply_compaction_boundary  # noqa: E402
from hooks.state_store import (  # noqa: E402
    emit_json_and_sanitize_stdio,
    locked_state,
    resolve_state_dir,
    state_file_in,
)
from hooks.telemetry import DEFAULT_SHADOW_PATH, invalidate_shadow_ledger, shadow_path_for  # noqa: E402


def handle_pre_compact(
    payload: dict[str, Any],
    state_dir: str | None = None,
) -> dict[str, Any]:
    """Clear cached file reads and outlines in the session ledger when native auto-compaction triggers."""
    if not isinstance(payload, dict):
        return {}
    sess_id = str(payload.get("session_id") or payload.get("conversation_id") or payload.get("conversationId") or "default")
    try:
        sp = shadow_path_for(state_dir)
        if (sp or DEFAULT_SHADOW_PATH).is_file():
            invalidate_shadow_ledger(session_id=sess_id, full_compact=True, shadow_path=sp)
    except (OSError, ValueError, TypeError) as exc:
        warn(f"pre_compact shadow reset skipped: {type(exc).__name__}: {exc}")
    try:
        close_outcome_windows(sess_id, force_all=True, ledger_path=ledger_path_for(state_dir))
    except (OSError, ValueError, TypeError) as exc:
        warn(f"pre_compact outcomes close skipped: {type(exc).__name__}: {exc}")

    state_snapshot: dict[str, Any] | None = None
    try:
        state_dir_path = resolve_state_dir(payload, state_dir)
        if not state_file_in(state_dir_path).exists():
            return {}
        with locked_state(state_dir_path) as txn:
            apply_compaction_boundary(txn.state, checkpoint_step=None)
            txn.dirty = True
            state_snapshot = copy.deepcopy(txn.state)
    except (OSError, ValueError, TypeError) as exc:
        warn(f"pre_compact skipped: {type(exc).__name__}: {exc}")
        return {}

    if state_snapshot is not None:
        try:
            notify_session_transition("compact", state_snapshot, load_runtime_config())
        except (OSError, ValueError, TypeError) as exc:
            warn(f"pre_compact transition skipped: {type(exc).__name__}: {exc}")
    return {}


def main() -> int:
    """CLI entrypoint reading PreCompact JSON from stdin and printing `{}` to stdout."""
    out_obj: dict[str, Any] = {}
    try:
        raw_input = sys.stdin.read()
        payload = json.loads(raw_input) if raw_input and raw_input.strip() else {}
        if not isinstance(payload, dict):
            payload = {}
        out_obj = handle_pre_compact(payload)
    except Exception as exc:  # noqa: BLE001 - hook CLI must fail open
        warn(f"pre_compact main failed: {type(exc).__name__}: {exc}")
        out_obj = {}
    return emit_json_and_sanitize_stdio(out_obj)


if __name__ == "__main__":
    raise SystemExit(main())
