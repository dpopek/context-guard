#!/usr/bin/env python3
"""SessionEnd hook: notify active policy packs and clean transient pending_reads state."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path[:0] = [r] if (r := str(Path(__file__).resolve().parent.parent)) not in sys.path else []
from hooks import config, policy_engine, state_store  # noqa: E402
from hooks.outcomes import close_outcome_windows, ledger_path_for  # noqa: E402
from hooks.telemetry import warn  # noqa: E402

def handle_session_end(payload: dict[str, Any], state_dir: str | None = None) -> dict[str, Any]:
    """Clear transient `pending_reads` markers and emit `session_end` transition event."""
    try:
        sess_id = str(payload.get("session_id") or payload.get("conversation_id") or payload.get("conversationId") or "default")
        close_outcome_windows(sess_id, force_all=True, ledger_path=ledger_path_for(state_dir))
        sdir = state_store.resolve_state_dir(payload, state_dir)
        if state_store.state_file_in(sdir).exists():
            cfg = config.load_runtime_config()
            with state_store.locked_state(sdir) as txn:
                files = txn.state.get("files")
                for entry in (files if isinstance(files, dict) else {}).values():
                    if isinstance(entry, dict) and entry.pop("pending_reads", None) is not None:
                        txn.dirty = True
                policy_engine.notify_session_transition("session_end", txn.state, cfg)
                txn.dirty = True
    except OSError as exc:
        warn(f"session_end skipped: {type(exc).__name__}: {exc}")
    return {}

def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint reading SessionEnd JSON from stdin, emitting `{}` and returning 0."""
    try:
        parser = argparse.ArgumentParser(add_help=False)
        for opt in ("--harness", "--state-dir"):
            parser.add_argument(opt, default=None)
        args, _ = parser.parse_known_args(argv)
        payload = json.loads(raw) if (raw := sys.stdin.read().strip()) else {}
        handle_session_end(payload if isinstance(payload, dict) else {}, state_dir=args.state_dir)
    except (Exception, SystemExit) as exc:  # noqa: BLE001
        warn(f"session_end main failed: {type(exc).__name__}: {exc}")
    return state_store.emit_json_and_sanitize_stdio({})

if __name__ == "__main__":
    raise SystemExit(main())
