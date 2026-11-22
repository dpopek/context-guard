"""Session-scoped escalation of repeated policy-pack denies (fail-open, message-only)."""
from __future__ import annotations

import hashlib, json, re, time
from pathlib import Path

from core.platform_io import warn, write_json_atomic

__all__ = ["REPEAT_DENY_NOTE", "REPEAT_DENY_WINDOW_S", "escalate_repeat_deny"]

_STATE_FILE = "policy_deny_last.json"
REPEAT_DENY_WINDOW_S = 600.0
REPEAT_DENY_NOTE = (" REPEATED BLOCK: this rule already blocked your previous attempt. Stop retrying or working around it;"
                    " this path is outside the agent's scope. Report to the operator and continue with other work.")


def escalate_repeat_deny(reason: str, pack_id: str, call_id: str, state_dir_path: Path | None, *, now_ts: float | None = None) -> str:
    """Append REPEAT_DENY_NOTE when the same pack rule blocks a new call within the window; never changes the decision."""
    if state_dir_path is None:
        return reason
    now = time.time() if now_ts is None else float(now_ts)
    sig = hashlib.sha256(f"{pack_id}\0{re.sub(r'`[^`]*`', '', reason)}".encode("utf-8", "replace")).hexdigest()[:16]
    target = Path(state_dir_path) / _STATE_FILE
    try:
        raw = json.loads(target.read_text(encoding="utf-8")) if target.is_file() else {}
    except (OSError, ValueError):
        raw = {}
    prev = raw if isinstance(raw, dict) else {}
    same_rule = prev.get("sig") == sig
    if same_rule and call_id and prev.get("call_id") == call_id:  # same call re-evaluated (Pass-2)
        return reason + REPEAT_DENY_NOTE if prev.get("escalated") is True else reason
    prev_ts = prev.get("ts")
    repeat = same_rule and isinstance(prev_ts, (int, float)) and 0 <= now - float(prev_ts) <= REPEAT_DENY_WINDOW_S
    try:
        write_json_atomic(target, {"sig": sig, "call_id": call_id, "ts": now, "escalated": repeat})
    except OSError as exc:
        warn(f"repeat-deny state not saved: {type(exc).__name__}")
    return reason + REPEAT_DENY_NOTE if repeat else reason
