#!/usr/bin/env python3
"""Command-line and MCP stdio entrypoint for Context-Guard reversible output spools."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_PLUGIN_ROOT = str(Path(__file__).resolve().parent.parent)
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from spool.mcp_server import serve_stdio  # noqa: E402
from spool.store import gc_spools, grep_spool, list_spools, slice_spool  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cg-spool", description="Inspect and manage Context-Guard output spools.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_slice = sub.add_parser("slice", help="Read a bounded line slice from a spool.")
    p_slice.add_argument("spool_id")
    p_slice.add_argument("--start", type=int, default=1)
    p_slice.add_argument("--limit", type=int, default=120)
    p_slice.add_argument("--end", type=int, default=None)
    p_slice.add_argument("--spool-dir", default=None)
    p_slice.add_argument("--json", action="store_true")

    p_grep = sub.add_parser("grep", help="Search a spool with a regex pattern.")
    p_grep.add_argument("spool_id")
    p_grep.add_argument("pattern_pos", nargs="?", default=None)
    p_grep.add_argument("--pattern", dest="pattern_flag", default=None)
    p_grep.add_argument("-i", "--ignore-case", action="store_true")
    p_grep.add_argument("--max-matches", type=int, default=50)
    p_grep.add_argument("--context", type=int, default=0)
    p_grep.add_argument("--spool-dir", default=None)
    p_grep.add_argument("--json", action="store_true")

    p_list = sub.add_parser("list", help="List spooled outputs newest-first.")
    p_list.add_argument("--session", default=None)
    p_list.add_argument("--spool-dir", default=None)
    p_list.add_argument("--json", action="store_true")

    p_gc = sub.add_parser("gc", help="Garbage-collect expired or LRU spools.")
    p_gc.add_argument("--max-age", type=float, default=None)
    p_gc.add_argument("--max-entries", type=int, default=None)
    p_gc.add_argument("--max-bytes", type=int, default=None)
    p_gc.add_argument("--spool-dir", default=None)
    p_gc.add_argument("--json", action="store_true")

    p_mcp = sub.add_parser("mcp", help="Run the stdio JSON-RPC 2.0 MCP spool server.")
    p_mcp.add_argument("--spool-dir", default=None)
    return parser


def _emit_result(cmd: str, res: dict[str, Any], as_json: bool) -> int:
    ok = bool(res.get("ok"))
    if as_json:
        print(json.dumps(res))
        return 0 if ok else 1
    if not ok:
        print(f"error: {res.get('error', 'unknown_error')}", file=sys.stderr)
        return 1
    if cmd == "slice":
        if res.get("content"):
            print(res["content"])
    elif cmd == "grep":
        for m in res.get("matches") or ():
            for b in m.get("before") or ():
                print(f"  {b}")
            print(f"{m['line']}:{m['text']}")
            for a in m.get("after") or ():
                print(f"  {a}")
    elif cmd == "list":
        entries = res.get("entries") or ()
        if not entries:
            print("No spooled outputs.")
        for ent in entries:
            print(
                f"{ent.get('spool_id')} | {ent.get('total_lines')} lines | "
                f"{ent.get('total_bytes')} B | {ent.get('tool_name')}"
            )
    elif cmd == "gc":
        print(
            f"removed={res.get('removed_count', 0)} ({res.get('removed_bytes', 0)} B) "
            f"remaining={res.get('remaining_count', 0)} ({res.get('remaining_bytes', 0)} B)"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `cg-spool` subcommands (`slice`, `grep`, `list`, `gc`, `mcp`)."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    wants_json = "--json" in raw_argv
    parser = _build_parser()
    try:
        ns = parser.parse_args(raw_argv)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        if wants_json:
            print(json.dumps({"ok": False, "error": "invalid_arguments"}))
        return 1

    eff_dir = Path(ns.spool_dir).expanduser() if getattr(ns, "spool_dir", None) else None
    cmd = str(ns.command)
    if cmd == "mcp":
        return serve_stdio(spool_dir=eff_dir)
    if cmd == "slice":
        res = slice_spool(ns.spool_id, start_line=ns.start, limit=ns.limit, end_line=ns.end, spool_dir=eff_dir)
        return _emit_result(cmd, res, bool(ns.json))
    if cmd == "grep":
        pattern = ns.pattern_flag if ns.pattern_flag is not None else ns.pattern_pos
        if pattern is None:
            err_res: dict[str, Any] = {"ok": False, "error": "missing_pattern"}
            return _emit_result(cmd, err_res, bool(ns.json))
        res = grep_spool(
            ns.spool_id, pattern, ignore_case=bool(ns.ignore_case),
            max_matches=ns.max_matches, context_lines=ns.context, spool_dir=eff_dir,
        )
        return _emit_result(cmd, res, bool(ns.json))
    if cmd == "list":
        res = list_spools(session_id=ns.session, spool_dir=eff_dir)
        return _emit_result(cmd, res, bool(ns.json))
    if cmd == "gc":
        gc_kwargs: dict[str, Any] = {"spool_dir": eff_dir}
        if ns.max_age is not None:
            gc_kwargs["max_age_seconds"] = ns.max_age
        if ns.max_entries is not None:
            gc_kwargs["max_entries"] = ns.max_entries
        if ns.max_bytes is not None:
            gc_kwargs["max_total_bytes"] = ns.max_bytes
        res = gc_spools(**gc_kwargs)
        return _emit_result(cmd, res, bool(ns.json))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
