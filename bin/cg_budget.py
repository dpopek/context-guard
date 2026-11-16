#!/usr/bin/env python3
"""CLI and Markdown/JSON renderer for Context-Guard Preamble & MCP Budget Advisor."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, Mapping

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from bin import budget_advisor, mcp_inventory  # noqa: E402


def _fmt_num(value: Any, *, prefix: str = "", suffix: str = "") -> str:
    if not isinstance(value, int) or isinstance(value, bool):
        return "unavailable"
    return f"{prefix}{value:,}{suffix}"


def _fmt_evidence_num(value: Any, evidence: Any, *, prefix: str = "") -> str:
    if not isinstance(value, int) or isinstance(value, bool):
        return "unavailable"
    ev = str(evidence or "unavailable")
    return f"{prefix}{value:,} [{ev}]"


def _render_preamble_section(preamble: Mapping[str, Any]) -> list[str]:
    lines: list[str] = ["", "## Session Preamble & Static Overhead", "", "### Session Preamble Summary", ""]
    summaries = preamble.get("session_summaries") or {}
    if isinstance(summaries, Mapping) and summaries:
        lines.extend(
            [
                "| Harness | Sessions | Median | Recent (10) | p90 | Last | Cache Read Share | Evidence |",
                "|---|---:|---:|---:|---:|---:|---:|---|",
            ]
        )
        for row in summaries.values():
            if not isinstance(row, Mapping):
                continue
            harness = str(row.get("harness") or "")
            sessions = int(row.get("sessions") or 0)
            ev = str(row.get("evidence") or "unavailable")
            cache_pct = row.get("cache_read_share_pct")
            cache_ev = str(row.get("cache_evidence") or "unavailable")
            cache_str = f"{float(cache_pct):.1f}% [{cache_ev}]" if isinstance(cache_pct, (int, float)) else "unavailable"
            lines.append(
                f"| `{harness}` | {sessions:,} | {_fmt_num(row.get('median'))} | "
                f"{_fmt_num(row.get('recent_median'))} | {_fmt_num(row.get('p90'))} | "
                f"{_fmt_num(row.get('last'))} | {cache_str} | [{ev}] |"
            )
    else:
        lines.append("_No session preamble data available._")

    lines.extend(["", "### Static Instruction & Skill Files", ""])
    static_files = preamble.get("static_files") or []
    if static_files:
        lines.extend(
            [
                "| Harness | Component | Path | Bytes [measured] | Est. Tokens [estimated] | Lines |",
                "|---|---|---|---:|---:|---:|",
            ]
        )
        for rec in static_files:
            if not isinstance(rec, Mapping):
                continue
            line_str = f"{rec['lines']:,}" if isinstance(rec.get("lines"), int) else "n/a"
            lines.append(
                f"| `{rec.get('harness', '')}` | `{rec.get('component', '')}` | `{rec.get('path', '')}` | "
                f"{_fmt_num(rec.get('bytes'))} | {_fmt_num(rec.get('estimated_tokens'), prefix='~')} | {line_str} |"
            )
    else:
        lines.append("_No static instruction, rules, or skill files found._")

    by_harness = preamble.get("by_harness") or {}
    if isinstance(by_harness, Mapping) and by_harness:
        lines.extend(["", "**Per-harness static totals:**"])
        for h, info in by_harness.items():
            if not isinstance(info, Mapping):
                continue
            mem = f", memory_lines={info['memory_lines']}" if info.get("memory_lines") is not None else ""
            lines.append(
                f"- `{h}`: {int(info.get('static_bytes') or 0):,} B [measured], "
                f"~{int(info.get('static_estimated_tokens') or 0):,} tokens [estimated]{mem}"
            )

    lines.extend(["", "### Hygiene & Duplicate Skills", ""])
    warnings = preamble.get("warnings") or []
    if warnings:
        lines.extend(f"- [warning] {w}" for w in warnings)
    else:
        lines.append("_No preamble hygiene warnings._")
    return lines


def _render_mcp_section(mcp: Mapping[str, Any]) -> list[str]:
    summary = mcp.get("summary") or {}
    lines: list[str] = [
        "",
        "## MCP Server Inventory",
        "",
        (
            f"- Configured: `{int(summary.get('configured_servers') or 0)}` | "
            f"Enabled: `{int(summary.get('enabled_servers') or 0)}` | "
            f"Measured schemas: `{int(summary.get('measured_schema_servers') or 0)}` | "
            f"Unavailable schemas: `{int(summary.get('unavailable_schema_servers') or 0)}` | "
            f"Completeness: `{summary.get('completeness', 'unavailable')}`"
        ),
        (
            f"- Known tools total: `{_fmt_evidence_num(summary.get('known_tools_total'), summary.get('known_tools_evidence'))}` | "
            f"Est. schema tokens total: `{_fmt_evidence_num(summary.get('estimated_schema_tokens_total'), summary.get('estimated_schema_tokens_evidence'), prefix='~')}`"
        ),
        "",
    ]

    servers = mcp.get("servers") or []
    if servers:
        lines.extend(
            [
                "| Harness | Server | Scope | Transport | Enabled | Schema | Tools | Est. Schema Tokens | Transcript Preamble | Calls (30d) | Probe |",
                "|---|---|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for srv in servers:
            if not isinstance(srv, Mapping):
                continue
            tools_str = _fmt_evidence_num(srv.get("tool_count"), srv.get("tool_count_evidence"))
            toks_str = _fmt_evidence_num(srv.get("estimated_tokens"), srv.get("token_evidence"), prefix="~")
            tp_str = _fmt_evidence_num(srv.get("transcript_preamble_tokens"), srv.get("transcript_tokens_evidence"))
            calls_str = _fmt_evidence_num(srv.get("calls_30d"), srv.get("calls_evidence"))
            lines.append(
                f"| `{srv.get('harness', '')}` | `{srv.get('name', '')}` | `{srv.get('scope', '')}` | "
                f"`{srv.get('transport', '')}` | `{bool(srv.get('enabled'))}` | `{srv.get('schema_status', 'unavailable')}` | "
                f"{tools_str} | {toks_str} | {tp_str} | {calls_str} | `{srv.get('probe_status', 'not_probed')}` |"
            )
    else:
        lines.append("_No MCP servers discovered._")

    overlaps = mcp.get("overlaps") or []
    if overlaps:
        lines.extend(["", "### MCP Overlaps & Duplicates", ""])
        for ov in overlaps:
            if isinstance(ov, Mapping):
                lines.append(f"- **{ov.get('kind', '')}** (`{ov.get('harness', '')}`): {ov.get('detail', '')}")

    issues = mcp.get("config_issues") or []
    if issues:
        lines.extend(["", "### MCP Config Issues", ""])
        for iss in issues:
            if isinstance(iss, Mapping):
                lines.append(f"- **{iss.get('harness', '')}** (`{iss.get('path', '')}`): {iss.get('error', '')}")
    return lines


def _render_recommendations_section(recs: Mapping[str, Any]) -> list[str]:
    lines: list[str] = [
        "",
        "## Budget Recommendations (Advisory Only)",
        "",
        (
            f"_No config auto-mutation (`auto_applied={bool(recs.get('auto_applied'))}`). "
            f"No guaranteed billing savings (`guaranteed_savings={bool(recs.get('guaranteed_savings'))}`); "
            "prompt-cache `cache_read` effects and prefix invalidation apply._"
        ),
        "",
    ]
    items = recs.get("items") or []
    if items:
        for it in items:
            if not isinstance(it, Mapping):
                continue
            delta_str = _fmt_evidence_num(it.get("estimated_tokens_delta"), it.get("evidence"), prefix="~")
            lines.append(
                f"- **[{str(it.get('severity', '')).upper()}]** `{it.get('kind', '')}` "
                f"(`{it.get('harness', '')}` / `{it.get('target', '')}`, delta: {delta_str}): "
                f"{it.get('action', '')} _Cache caveat: {it.get('cache_caveat', '')}_"
            )
    else:
        lines.append("_No optimization recommendations at this time._")

    profiles = recs.get("session_profiles") or []
    if profiles:
        lines.extend(["", "### Cautious Session Profiles", ""])
        for prof in profiles:
            if not isinstance(prof, Mapping):
                continue
            delta_str = _fmt_evidence_num(prof.get("estimated_tokens_delta"), prof.get("evidence"), prefix="~")
            keep = ", ".join(f"`{s}`" for s in (prof.get("keep_servers") or ())) or "_none_"
            disable = ", ".join(f"`{s}`" for s in (prof.get("disable_candidates") or ())) or "_none_"
            lines.append(
                f"- **`{prof.get('name', '')}`** (delta: {delta_str}, auto_applied=`{bool(prof.get('auto_applied'))}`, "
                f"guaranteed_savings=`{bool(prof.get('guaranteed_savings'))}`): {prof.get('description', '')} "
                f"Keep: {keep}. Review disabling: {disable}."
            )
    return lines


def render_budget_markdown(report: Mapping[str, Any]) -> str:
    """Format a `run_budget_audit` report as Markdown with explicit evidence tags and caveats."""
    version = str(report.get("plugin_version") or "0.0.0")
    mode = str(report.get("mode") or "passive")
    harnesses = ", ".join(f"`{h}`" for h in (report.get("harnesses_scanned") or ())) or "_none_"
    lines: list[str] = [
        f"# Context-Guard Preamble & MCP Budget Advisor (v{version})",
        "",
        (
            f"- Mode: `{mode}` | Read-only: `{bool(report.get('read_only', True))}` | "
            f"No config auto-mutation (`auto_mutated_configs={bool(report.get('auto_mutated_configs', False))}`) | "
            "No guaranteed billing savings"
        ),
        f"- Harnesses scanned: {harnesses}",
    ]
    probe_warning = report.get("probe_warning")
    if mode == "probe" or probe_warning:
        lines.extend(["", "> [!WARNING]", f"> {probe_warning or mcp_inventory.PROBE_SIDE_EFFECT_WARNING}"])

    if isinstance(report.get("preamble"), Mapping):
        lines.extend(_render_preamble_section(report["preamble"]))
    if isinstance(report.get("mcp"), Mapping):
        lines.extend(_render_mcp_section(report["mcp"]))
    if isinstance(report.get("recommendations"), Mapping):
        lines.extend(_render_recommendations_section(report["recommendations"]))
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cg-budget",
        description="Read-only cross-harness preamble and MCP budget advisor.",
    )
    parser.add_argument("--preamble", action="store_true", help="Include preamble static & session overhead.")
    parser.add_argument("--mcp", action="store_true", help="Include passive MCP server inventory & overlaps.")
    parser.add_argument("--recommendations", action="store_true", help="Include conservative budget recommendations.")
    parser.add_argument("--probe", action="store_true", help="Opt-in active stdio probing (`initialize` + `tools/list`).")
    parser.add_argument("--probe-server", action="append", default=None, help="Restrict `--probe` to named MCP server(s).")
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=mcp_inventory.DEFAULT_PROBE_TIMEOUT_S,
        help=f"Per-server stdio probe timeout in seconds ([{mcp_inventory.MIN_PROBE_TIMEOUT_S}, {mcp_inventory.MAX_PROBE_TIMEOUT_S}]).",
    )
    parser.add_argument(
        "--harness",
        action="append",
        choices=mcp_inventory.SUPPORTED_HARNESSES,
        default=None,
        help="Restrict audit to specific harness(es).",
    )
    parser.add_argument("--workspace", "--workspace-root", dest="workspace", type=Path, default=None, help="Workspace directory (defaults to cwd).")
    parser.add_argument("--home", type=Path, default=None, help="Override home directory for isolated audits.")
    parser.add_argument("--usage-path", type=Path, default=None, help="Override token_usage.json ledger path.")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit structured JSON report.")
    fmt.add_argument("--markdown", action="store_true", help="Emit Markdown report (default).")
    return parser


def _emit_invalid(message: str, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"ok": False, "error": "invalid_arguments", "detail": message}))
    else:
        print(f"error: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `cg-budget` / `cg budget`."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv and raw_argv[0] == "budget":
        raw_argv = raw_argv[1:]
    wants_json = "--json" in raw_argv
    parser = _build_parser()
    try:
        ns = parser.parse_args(raw_argv)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        if wants_json:
            print(json.dumps({"ok": False, "error": "invalid_arguments"}))
        return 2

    any_section = bool(ns.preamble or ns.mcp or ns.recommendations)
    inc_preamble = bool(ns.preamble) if any_section else True
    inc_mcp = bool(ns.mcp) if any_section else True
    inc_recs = bool(ns.recommendations) if any_section else True

    if ns.probe and not (inc_mcp or inc_recs):
        return _emit_invalid("--probe cannot be used with --preamble alone; include --mcp or --recommendations.", bool(ns.json))

    timeout_s = float(ns.probe_timeout)
    if not math.isfinite(timeout_s) or not (mcp_inventory.MIN_PROBE_TIMEOUT_S <= timeout_s <= mcp_inventory.MAX_PROBE_TIMEOUT_S):
        return _emit_invalid(
            f"--probe-timeout must be between {mcp_inventory.MIN_PROBE_TIMEOUT_S} and {mcp_inventory.MAX_PROBE_TIMEOUT_S} seconds.",
            bool(ns.json),
        )

    eff_ws = ns.workspace if ns.workspace is not None else Path.cwd()
    report = budget_advisor.run_budget_audit(
        home=ns.home,
        workspace_root=eff_ws,
        usage_path=ns.usage_path,
        harnesses=ns.harness,
        include_preamble=inc_preamble,
        include_mcp=inc_mcp,
        include_recommendations=inc_recs,
        probe=bool(ns.probe),
        probe_servers=ns.probe_server,
        probe_timeout_s=timeout_s,
    )
    if ns.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_budget_markdown(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
