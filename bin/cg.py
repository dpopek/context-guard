#!/usr/bin/env python3
"""Unified `cg` CLI dispatcher for Context-Guard."""
from __future__ import annotations

import json
import sys
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from hooks.state_store import resolve_plugin_root  # noqa: E402

_HELP_TEXT = """\
Usage: cg <command> [args...]

Commands:
  budget     Audit preamble, MCP server, and recommendation budgets
  doctor     Run cross-OS environment and harness self-diagnostics
  eval       Run Evidence Engine offline replay, plans, and campaign gates
  explain    Explain a specific intervention, spool lifecycle, and evidence tier
  export     Export scrubbed telemetry events off the hot path (--otel)
  status     Show token savings, outcomes, and usage reports
  spool      Inspect, search, GC, or serve reversible output spools
  outline    Generate a structural outline for source files

Options:
  -h, --help       Show this help message and exit
  -V, --version    Show the Context-Guard version and exit
"""


def _read_plugin_version() -> str:
    root = resolve_plugin_root()
    manifest = root / "plugin.json"
    if not manifest.is_file():
        manifest = _PACKAGE_ROOT / "plugin.json"
    return str(json.loads(manifest.read_text(encoding="utf-8"))["version"])


def main(argv: list[str] | None = None) -> int:
    """Dispatch `cg` subcommands (`budget`, `doctor`, `eval`, `explain`, `export`, `status`, `spool`, `outline`)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(_HELP_TEXT, end="")
        return 0
    if args[0] in ("-V", "--version"):
        print(f"context-guard {_read_plugin_version()}")
        return 0

    cmd, rest = args[0], args[1:]
    if cmd == "budget":
        from bin.cg_budget import main as budget_main

        return int(budget_main(rest))
    if cmd == "doctor":
        from bin.cg_status import main as status_main

        return int(status_main(["--doctor", *rest]))
    if cmd == "eval":
        from bin.cg_eval import main as eval_main

        return int(eval_main(rest))
    if cmd == "explain":
        from bin.cg_explain import main as explain_main

        return int(explain_main(rest))
    if cmd == "export":
        from bin.cg_export import main as export_main

        return int(export_main(rest))
    if cmd == "status":
        from bin.cg_status import main as status_main

        return int(status_main(rest))
    if cmd == "spool":
        from bin.cg_spool import main as spool_main

        return int(spool_main(rest))
    if cmd == "outline":
        from bin.outline import main as outline_main

        return int(outline_main(rest))

    print(
        f"cg: unknown subcommand '{cmd}'. Run 'cg --help' for available commands.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
