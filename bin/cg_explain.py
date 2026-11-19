#!/usr/bin/env python3
"""Diagnostic CLI entrypoint for `cg explain <event-id>`."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from services.explain_service import explain_intervention, render_explain_markdown  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cg-explain",
        description="Explain a Context-Guard intervention, spool lifecycle, and delivery evidence tier.",
    )
    parser.add_argument("event_id", help="Target event_id, receipt_id, or spool_id to explain.")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit structured ExplainContractV1 JSON output.")
    fmt.add_argument("--markdown", action="store_true", help="Emit Markdown report (default).")
    parser.add_argument("--receipts-path", type=Path, default=None, help="Override receipts.jsonl path.")
    parser.add_argument("--spool-dir", type=Path, default=None, help="Override spool directory path.")
    parser.add_argument("--ledger-path", type=Path, default=None, help="Override evidence_events.json path.")
    parser.add_argument("--state-dir", type=Path, default=None, help="Override governor state directory path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `cg explain` / `cg_explain.py`."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if len(raw_argv) >= 2 and raw_argv[0] == "explain" and not raw_argv[1].startswith("-"):
        raw_argv = raw_argv[1:]
    wants_json = "--json" in raw_argv
    try:
        ns = _build_parser().parse_args(raw_argv)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        if wants_json:
            print(json.dumps({"ok": False, "error": "invalid_arguments"}))
        return 2
    report = explain_intervention(
        str(ns.event_id),
        receipts_path=Path(ns.receipts_path).expanduser() if ns.receipts_path is not None else None,
        spool_dir=Path(ns.spool_dir).expanduser() if ns.spool_dir is not None else None,
        ledger_path=Path(ns.ledger_path).expanduser() if ns.ledger_path is not None else None,
        state_dir=Path(ns.state_dir).expanduser() if ns.state_dir is not None else None,
    )
    print(json.dumps(report, indent=2) if ns.json else render_explain_markdown(report), end=("\n" if ns.json else ""))
    return 0 if report["ok"] else (2 if report["error"] == "invalid_event_id" else 1)


if __name__ == "__main__":
    raise SystemExit(main())
