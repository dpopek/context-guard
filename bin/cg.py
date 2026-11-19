#!/usr/bin/env python3
"""Unified `cg` CLI dispatcher for Context-Guard."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from core.platform_io import read_plugin_version  # noqa: E402

_SUBCOMMANDS: tuple[str, ...] = (
    "budget",
    "doctor",
    "eval",
    "explain",
    "export",
    "status",
    "spool",
    "outline",
)

_HELP_TEXT = """\
Usage: cg <command> [args...]

Commands:
  budget     Audit preamble, MCP server, and recommendation budgets
  doctor     Run cross-OS environment, harness, security, and contract self-diagnostics
  eval       Run Evidence Engine replay, conformance, platform-matrix, and campaign gates
  explain    Explain a specific intervention, spool lifecycle, and evidence tier
  export     Export scrubbed telemetry events off the hot path (--otel)
  status     Show token savings, outcomes, and usage reports
  spool      Inspect, search, GC, or serve reversible output spools
  outline    Generate a structural outline for source files
  help       Show general help or help for a specific subcommand

Options:
  -h, --help       Show this help message and exit
  -V, --version    Show the Context-Guard version and exit
"""

_OUTLINE_HELP_TEXT = """\
usage: cg outline [-h] <file1> [<file2> ...]

Generate a structural symbol and line-range outline for source files.

options:
  -h, --help  show this help message and exit
"""


def _render_doctor_contracts_section(doc: Mapping[str, Any]) -> str:
    raw_dep = doc.get("deprecation_policy")
    raw_mat = doc.get("capability_matrix")
    raw_schemas = doc.get("core_schema_versions")
    dep: Mapping[str, Any] = raw_dep if isinstance(raw_dep, Mapping) else {}
    mat: Mapping[str, Any] = raw_mat if isinstance(raw_mat, Mapping) else {}
    schemas: Mapping[str, Any] = raw_schemas if isinstance(raw_schemas, Mapping) else {}
    raw_harnesses = mat.get("harnesses")
    harnesses: Mapping[str, Any] = raw_harnesses if isinstance(raw_harnesses, Mapping) else {}
    harness_names = ", ".join(sorted([str(k) for k in harnesses], key=lambda x: str(x)))
    lines = [
        "",
        "## Platform Contracts (`--contracts`)",
        "",
        (
            f"- Policy API Version: `{doc.get('policy_api_version')}` "
            f"(`v2_mandated={bool(dep.get('policy_api_v2_mandated'))}`, "
            f"`external_sdk={bool(dep.get('external_sdk_shipped'))}`)"
        ),
        (
            f"- Core Schemas Registered: `{len(schemas)}` | "
            f"Min Deprecation Window: `>= {int(dep.get('min_deprecation_minor_releases', 2) or 2)}` minor releases"
        ),
        f"- Harnesses Verified: `{harness_names}`",
    ]
    return "\n".join(lines) + "\n"


def run_doctor_cli(argv: list[str] | None = None) -> int:
    """Run cohesive `cg doctor` CLI supporting `--json`, `--markdown`, and `--contracts`."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv and raw_argv[0] == "doctor":
        raw_argv = raw_argv[1:]
    wants_json = "--json" in raw_argv
    parser = argparse.ArgumentParser(
        prog="cg doctor",
        description="Run cross-OS environment, harness, security, and contract self-diagnostics.",
    )
    parser.add_argument(
        "--contracts",
        action="store_true",
        help="Include frozen Policy API v1, core schema registry, deprecation policy, and capability matrix.",
    )
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit structured JSON diagnostic report.")
    fmt.add_argument("--markdown", action="store_true", help="Emit Markdown diagnostic report (default).")
    try:
        ns = parser.parse_args(raw_argv)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        if wants_json:
            print(json.dumps({"ok": False, "error": "invalid_arguments"}))
        return 2

    from evidence.conformance import build_capability_limitation_matrix, build_deprecation_policy
    from policies.api import CORE_SCHEMA_VERSIONS, DOCTOR_SCHEMA_VERSION, POLICY_API_VERSION
    from services import status_service

    doc: dict[str, Any] = dict(status_service.run_doctor())
    doc["schema_version"] = DOCTOR_SCHEMA_VERSION
    doc["policy_api_version"] = POLICY_API_VERSION
    doc["core_schema_versions"] = dict(CORE_SCHEMA_VERSIONS)
    if ns.contracts:
        doc["deprecation_policy"] = build_deprecation_policy()
        doc["capability_matrix"] = build_capability_limitation_matrix(include_live_effectiveness=False)

    if ns.json:
        print(json.dumps(doc, indent=2))
    else:
        rendered = status_service.render_doctor_report(doc)
        if ns.contracts:
            rendered += _render_doctor_contracts_section(doc)
        print(rendered, end="")
    return 0 if doc.get("ok") else 1


def _dispatch_subcommand(cmd: str, rest: list[str]) -> int:
    if cmd == "budget":
        from bin.cg_budget import main as budget_main

        return int(budget_main(rest))
    if cmd == "doctor":
        return run_doctor_cli(rest)
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

        try:
            return int(status_main(rest))
        except SystemExit as exc:
            return 0 if exc.code in (None, 0) else (int(exc.code) if isinstance(exc.code, int) else 2)
    if cmd == "spool":
        from bin.cg_spool import main as spool_main

        return int(spool_main(rest))
    if cmd == "outline":
        if rest and rest[0] in ("-h", "--help"):
            print(_OUTLINE_HELP_TEXT, end="")
            return 0
        from bin.outline import main as outline_main

        return int(outline_main(rest))
    print(
        f"cg: unknown subcommand '{cmd}'. Run 'cg --help' for available commands.",
        file=sys.stderr,
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    """Dispatch `cg` subcommands (`budget`, `doctor`, `eval`, `explain`, `export`, `status`, `spool`, `outline`, `help`)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(_HELP_TEXT, end="")
        return 0
    if args[0] in ("-V", "--version"):
        print(f"context-guard {read_plugin_version()}")
        return 0

    cmd, rest = args[0], args[1:]
    if cmd == "help":
        if not rest or rest[0] in ("-h", "--help"):
            print(_HELP_TEXT, end="")
            return 0
        target = rest[0]
        if target in _SUBCOMMANDS:
            return _dispatch_subcommand(target, ["--help"])
        print(
            f"cg: unknown subcommand '{target}'. Run 'cg --help' for available commands.",
            file=sys.stderr,
        )
        return 1

    return _dispatch_subcommand(cmd, rest)


if __name__ == "__main__":
    raise SystemExit(main())
