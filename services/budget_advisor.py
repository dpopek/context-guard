"""Cross-harness preamble measurement, session summary, and conservative budget recommendations."""

from __future__ import annotations

from datetime import date, timedelta
import math
from pathlib import Path
from typing import Any, Mapping, Sequence

from core.platform_io import read_plugin_version
from services import mcp_inventory, preamble_attribution, token_usage, usage_report
from services.transcript_parsers import nonneg_int

LARGE_INSTRUCTION_FILE_BYTES = 16_384

_SEVERITY_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2}
_PREFIX_CACHE_CAVEAT = (
    "Editing preambles or toggling servers mid-session invalidates the prompt-cache prefix and forces an uncached "
    "re-read; apply changes only between sessions. Note cached turns previously paid ~10% cache_read pricing."
)
_UNOBSERVED_SCHEMA_CAVEAT = (
    "Schema overhead is unknown in passive mode and may be deferred or served via prompt cache (`cache_read`); "
    "do not disable servers mid-session without checking actual usage or running opt-in `--probe`."
)
_MEMORY_CAVEAT = (
    "Lines past line 200 are never loaded; trimming only past line 200 leaves the prompt cache untouched, while "
    "editing lines 1-200 invalidates the prompt-cache prefix (`cache_read`) so edit only between sessions."
)


def _normalize_harnesses(harnesses: Sequence[str] | None) -> list[str]:
    return (
        list(mcp_inventory.SUPPORTED_HARNESSES)
        if harnesses is None
        else [h for h in mcp_inventory.SUPPORTED_HARNESSES if h in harnesses]
    )


def _read_bytes_and_text(path: Path) -> tuple[int, str] | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return len(raw), raw.decode("utf-8", errors="replace")


def _resolved_key(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def _add_static_file(
    out: list[dict[str, Any]], seen: set[Path], path: Path, harness: str, component: str,
    home: Path, workspace_root: Path | None, *, token_line_limit: int | None = None,
) -> int | None:
    """Append one measured file record if readable and not yet seen; returns full line count."""
    if not path.is_file():
        return None
    resolved = _resolved_key(path)
    if resolved in seen or (loaded := _read_bytes_and_text(resolved)) is None:
        return None
    seen.add(resolved)
    nbytes, text = loaded
    all_lines = text.splitlines()
    est_tokens = len("\n".join(all_lines[:token_line_limit]).encode("utf-8")) // 4 if token_line_limit is not None else nbytes // 4
    out.append({
        "harness": harness, "component": component, "path": mcp_inventory.format_display_path(path, home, workspace_root),
        "bytes": nbytes, "bytes_evidence": "measured", "estimated_tokens": est_tokens, "token_evidence": "estimated", "lines": len(all_lines),
    })
    return len(all_lines)


def _add_skills_listing(out: list[dict[str, Any]], skill_paths: Sequence[Path], harness: str, display_label: str) -> None:
    listings = [
        fm for path in skill_paths
        if (loaded := _read_bytes_and_text(path)) is not None and (fm := preamble_attribution.extract_skill_frontmatter_summary(loaded[1]))
    ]
    if not listings:
        return
    listing_bytes = len("\n".join(listings).encode("utf-8"))
    out.append({
        "harness": harness, "component": "skills_listing", "path": f"{display_label} ({len(skill_paths)} skills)",
        "bytes": listing_bytes, "bytes_evidence": "measured", "estimated_tokens": listing_bytes // 4, "token_evidence": "estimated", "lines": None,
    })


def _collect_claude_files(home: Path, workspace_root: Path | None, out: list[dict[str, Any]]) -> int | None:
    seen: set[Path] = set()
    for path in usage_report.collect_instruction_files([home / ".claude" / "CLAUDE.md"], home):
        _add_static_file(out, seen, path, "claude", "user_instructions", home, workspace_root)
    memory_lines: int | None = None
    if workspace_root is not None:
        proj_roots = [directory / name for directory in (workspace_root, *workspace_root.parents) for name in ("CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md")]
        for path in usage_report.collect_instruction_files(proj_roots, home):
            _add_static_file(out, seen, path, "claude", "workspace_instructions", home, workspace_root)
        lines_read = _add_static_file(
            out, seen, usage_report.memory_index_path(home, workspace_root),
            "claude", "memory_index", home, workspace_root, token_line_limit=usage_report.MEMORY_LOAD_LINES,
        )
        memory_lines = lines_read if lines_read is not None else 0
    _add_skills_listing(out, usage_report.skill_listing_files(home), "claude", "~/.claude/skills + plugins")
    return memory_lines


def _collect_antigravity_files(home: Path, workspace_root: Path | None, out: list[dict[str, Any]]) -> None:
    seen: set[Path] = set()
    for path in (home / ".gemini" / "GEMINI.md", home / ".gemini" / "AGENTS.md", home / ".gemini" / "config" / "AGENTS.md"):
        _add_static_file(out, seen, path, "antigravity", "user_instructions", home, workspace_root)
    for path in sorted((home / ".gemini" / "config" / "plugins").glob("*/rules/*.md")):
        _add_static_file(out, seen, path, "antigravity", "rules", home, workspace_root)
    if workspace_root is not None:
        for path in (workspace_root / "AGENTS.md", workspace_root / ".agents" / "AGENTS.md"):
            _add_static_file(out, seen, path, "antigravity", "workspace_instructions", home, workspace_root)
    skill_paths = (
        sorted((home / ".gemini" / "config" / "skills").glob("*/SKILL.md"))
        + sorted((home / ".gemini" / "config" / "plugins").glob("*/skills/*/SKILL.md"))
        + sorted((home / ".gemini" / "antigravity" / "builtin" / "skills").glob("*/SKILL.md"))
        + (sorted((workspace_root / ".agents" / "skills").glob("*/SKILL.md")) if workspace_root is not None else [])
    )
    label = "~/.gemini/**/skills + <workspace>/.agents/skills" if workspace_root is not None else "~/.gemini/**/skills"
    _add_skills_listing(out, skill_paths, "antigravity", label)


def _collect_codex_files(home: Path, workspace_root: Path | None, out: list[dict[str, Any]]) -> None:
    seen: set[Path] = set()
    _add_static_file(out, seen, home / ".codex" / "AGENTS.md", "codex", "user_instructions", home, workspace_root)
    if workspace_root is not None:
        _add_static_file(out, seen, workspace_root / "AGENTS.md", "codex", "workspace_instructions", home, workspace_root)


def _collect_cursor_files(home: Path, workspace_root: Path | None, out: list[dict[str, Any]]) -> None:
    if workspace_root is None:
        return
    seen: set[Path] = set()
    _add_static_file(out, seen, workspace_root / ".cursorrules", "cursor", "workspace_instructions", home, workspace_root)
    for pattern in ("*.mdc", "*.md"):
        for path in sorted((workspace_root / ".cursor" / "rules").glob(pattern)):
            _add_static_file(out, seen, path, "cursor", "rules", home, workspace_root)
    _add_static_file(out, seen, workspace_root / "AGENTS.md", "cursor", "workspace_instructions", home, workspace_root)


def _harness_cache_share(totals: Mapping[str, Any], base_harness: str) -> tuple[float | None, str]:
    inp = cread = cwrite = 0
    for tkey, row in totals.items():
        if not isinstance(row, Mapping) or str(tkey).partition("|")[0] != base_harness:
            continue
        events, total_only, row_read = nonneg_int(row.get("events")), nonneg_int(row.get("total_only")), nonneg_int(row.get("cache_read"))
        if events > 0 and total_only >= events and row_read == 0:
            continue
        inp += nonneg_int(row.get("input"))
        cread += row_read
        cwrite += nonneg_int(row.get("cache_write"))
    denom = inp + cread + cwrite
    return (round(cread / denom * 100.0, 1), "measured") if denom > 0 else (None, "unavailable")


def _cursor_session_values(usage_state: Mapping[str, Any] | None) -> list[int]:
    if not isinstance(usage_state, Mapping):
        return []
    preamble = usage_state.get("preamble")
    if isinstance(preamble, Mapping) and isinstance(preamble.get("cursor"), list):
        direct = [v for v in preamble["cursor"] if isinstance(v, int) and not isinstance(v, bool) and v > 0]
        if direct:
            return direct
    estimates = usage_state.get("cursor_estimates")
    if not isinstance(estimates, Mapping):
        return []
    return [
        entry["tokens"] for entry in estimates.values()
        if isinstance(entry, Mapping) and isinstance(entry.get("tokens"), int)
        and not isinstance(entry.get("tokens"), bool) and entry["tokens"] > 0
    ]


def _list_field(mapping: Mapping[str, Any], key: str) -> list[Any]:
    val = mapping.get(key)
    return list(val) if isinstance(val, list) else []


def _build_session_summaries(
    usage_state: Mapping[str, Any] | None, eff_harnesses: Sequence[str]
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, int]]]:
    state: Mapping[str, Any] = usage_state if isinstance(usage_state, Mapping) else {}
    raw_pre, raw_tot = state.get("preamble"), state.get("totals")
    preamble: Mapping[str, Any] = raw_pre if isinstance(raw_pre, Mapping) else {}
    totals: Mapping[str, Any] = raw_tot if isinstance(raw_tot, Mapping) else {}
    raw_int: dict[str, dict[str, int]] = {}
    ordered_rows: list[tuple[str, str]] = []

    if "antigravity" in eff_harnesses:
        raw_int["antigravity"] = usage_report.summarize_preamble(_list_field(preamble, "antigravity"))
        ordered_rows.append(("antigravity", "measured"))

    if "claude" in eff_harnesses:
        cl_cohorts = preamble_attribution.split_claude_parts(state.get("preamble_parts"))
        if cl_cohorts[preamble_attribution.CLAUDE_CLI_HARNESS] or cl_cohorts[preamble_attribution.CLAUDE_DESKTOP_HARNESS]:
            for cname in (preamble_attribution.CLAUDE_CLI_HARNESS, preamble_attribution.CLAUDE_DESKTOP_HARNESS):
                raw_int[cname] = usage_report.summarize_preamble([entry["measured"] for entry in cl_cohorts[cname]])
                ordered_rows.append((cname, "measured"))
        else:
            raw_int["claude"] = usage_report.summarize_preamble(_list_field(preamble, "claude"))
            ordered_rows.append(("claude", "measured"))

    if "codex" in eff_harnesses:
        cx_cohorts = preamble_attribution.split_codex_parts(state.get("codex_preamble_parts"))
        if cx_cohorts[preamble_attribution.CODEX_CLI_HARNESS] or cx_cohorts[preamble_attribution.CODEX_DESKTOP_HARNESS]:
            for cname in (preamble_attribution.CODEX_CLI_HARNESS, preamble_attribution.CODEX_DESKTOP_HARNESS):
                raw_int[cname] = usage_report.summarize_preamble([entry["measured"] for entry in cx_cohorts[cname]])
                ordered_rows.append((cname, "measured"))
        else:
            raw_int["codex"] = usage_report.summarize_preamble(_list_field(preamble, "codex"))
            ordered_rows.append(("codex", "measured"))

    if "cursor" in eff_harnesses:
        raw_int["cursor"] = usage_report.summarize_preamble(_cursor_session_values(state))
        ordered_rows.append(("cursor", "estimated"))

    summaries: dict[str, dict[str, Any]] = {}
    for row_name, active_ev in ordered_rows:
        stats = raw_int[row_name]
        if stats["sessions"] > 0:
            cache_pct, cache_ev = (None, "unavailable") if row_name == "cursor" else _harness_cache_share(totals, row_name.split(" ", 1)[0])
            summaries[row_name] = {
                "harness": row_name, "sessions": stats["sessions"], "median": stats["median"],
                "recent_median": stats["recent_median"], "p90": stats["p90"], "last": stats["last"],
                "evidence": active_ev, "cache_read_share_pct": cache_pct, "cache_evidence": cache_ev,
            }
        else:
            summaries[row_name] = {
                "harness": row_name, "sessions": 0, "median": None, "recent_median": None,
                "p90": None, "last": None, "evidence": "unavailable",
                "cache_read_share_pct": None, "cache_evidence": "unavailable",
            }
    return summaries, raw_int


def collect_preamble_budget(
    home: Path, workspace_root: Path | None = None, usage_state: Mapping[str, Any] | None = None, *, harnesses: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Measure static instruction/rules/memory/skill files and summarize observed session preambles."""
    eff_home, eff_ws, eff_harnesses = Path(home), (Path(workspace_root) if workspace_root is not None else None), _normalize_harnesses(harnesses)
    static_files: list[dict[str, Any]] = []
    memory_lines: int | None = _collect_claude_files(eff_home, eff_ws, static_files) if "claude" in eff_harnesses else None
    if "antigravity" in eff_harnesses:
        _collect_antigravity_files(eff_home, eff_ws, static_files)
    if "codex" in eff_harnesses:
        _collect_codex_files(eff_home, eff_ws, static_files)
    if "cursor" in eff_harnesses:
        _collect_cursor_files(eff_home, eff_ws, static_files)

    by_harness: dict[str, dict[str, Any]] = {}
    for h in eff_harnesses:
        rows = [f for f in static_files if f["harness"] == h]
        by_harness[h] = {
            "static_bytes": sum(int(r["bytes"]) for r in rows), "bytes_evidence": "measured",
            "static_estimated_tokens": sum(int(r["estimated_tokens"]) for r in rows), "token_evidence": "estimated",
            "memory_lines": memory_lines if h == "claude" else None,
        }

    session_summaries, raw_int_summaries = _build_session_summaries(usage_state, eff_harnesses)
    dup_skills: list[dict[str, Any]] = []
    for name, paths in usage_report.find_duplicate_skills(eff_home):
        disp_paths = [mcp_inventory.format_display_path(p, eff_home, eff_ws) for p in paths]
        if ("antigravity" not in eff_harnesses and all(dp.startswith("~/.gemini") for dp in disp_paths)) or (
            "claude" not in eff_harnesses and all(dp.startswith("~/.claude") for dp in disp_paths)
        ):
            continue
        dup_skills.append({"name": name, "count": len(disp_paths), "paths": disp_paths})

    warnings = usage_report.hygiene_warnings(memory_lines or 0, raw_int_summaries)
    for dup in dup_skills:
        warnings.append(f"Duplicate skill `{dup['name']}` found {dup['count']} times ({', '.join(dup['paths'])}).")
    for rec in static_files:
        if rec["component"] in ("user_instructions", "workspace_instructions", "rules") and rec["bytes"] > LARGE_INSTRUCTION_FILE_BYTES:
            warnings.append(f"Large instruction file `{rec['path']}` ({rec['bytes']:,} B / ~{rec['estimated_tokens']:,} tokens) exceeds {LARGE_INSTRUCTION_FILE_BYTES:,} B.")

    result: dict[str, Any] = {
        "harnesses_scanned": eff_harnesses, "static_files": static_files, "by_harness": by_harness,
        "session_summaries": session_summaries, "duplicate_skills": dup_skills, "warnings": warnings,
    }
    if "antigravity" in eff_harnesses:
        ag_parts = preamble_attribution.measure_antigravity_preamble(eff_home, eff_ws)
        result["antigravity_components"] = [{"component": label, "tokens": toks} for label, toks in ag_parts]
    return result


def _parse_iso_day(value: Any) -> date | None:
    if not isinstance(value, str) or len(value) < 10:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _has_component_use(usage_state: Mapping[str, Any] | None) -> bool:
    if not isinstance(usage_state, Mapping) or not isinstance((comp_use := usage_state.get("component_use")), Mapping):
        return False
    return any(isinstance(row, Mapping) and any(nonneg_int(cnt) > 0 for cnt in row.values()) for row in comp_use.values())


def _has_session_history(usage_state: Mapping[str, Any] | None) -> bool:
    if not isinstance(usage_state, Mapping):
        return False
    return any(bool(usage_state.get(k)) for k in ("totals", "preamble", "preamble_parts", "codex_preamble_parts", "cursor_estimates"))


def _make_item(
    item_id: str, kind: str, severity: str, harness: str, target: str,
    action: str, delta: int | None, evidence: str, caveat: str,
) -> dict[str, Any]:
    return {
        "id": item_id, "kind": kind, "severity": severity, "harness": harness,
        "target": target, "action": action, "estimated_tokens_delta": delta,
        "evidence": evidence, "auto_applied": False, "guaranteed_savings": False, "cache_caveat": caveat,
    }


def _collect_unused_recommendations(
    mcp: Mapping[str, Any], usage_state: Mapping[str, Any] | None, eff_today: date, items: list[dict[str, Any]]
) -> set[tuple[str, str]]:
    """Emit `unused_mcp_or_plugin_30d` only when 30-day component_use telemetry is actually present."""
    unused_pairs: set[tuple[str, str]] = set()
    if not isinstance(usage_state, Mapping) or not (_has_session_history(usage_state) and _has_component_use(usage_state)):
        return unused_pairs
    since = str(usage_state.get("component_use_since") or "")
    window_start = (eff_today - timedelta(days=preamble_attribution.CANDIDATE_WINDOW_DAYS - 1)).isoformat()
    if not since or _parse_iso_day(since) is None or since > window_start:
        return unused_pairs

    seen_keys: set[str] = set()
    for cand in preamble_attribution.find_candidates(usage_state.get("preamble_parts") or [], usage_state.get("component_use") or {}, eff_today):
        key, toks = str(cand["key"]), int(cand["tokens"])
        seen_keys.add(key)
        sev = "high" if toks >= 2_000 else "medium"
        items.append(_make_item(
            f"unused_mcp_or_plugin_30d:claude:{key}", "unused_mcp_or_plugin_30d", sev, "claude", key,
            f"Review disabling unused Claude plugin/MCP `{key}` (~{toks:,} tokens/session, 0 calls in last 30 days).",
            toks, "estimated", _PREFIX_CACHE_CAVEAT,
        ))
        if key.startswith("mcp:"):
            unused_pairs.add(("claude", key))

    for srv in mcp.get("servers") or ():
        if not isinstance(srv, Mapping) or srv.get("harness") != "claude" or srv.get("enabled") is not True:
            continue
        if srv.get("calls_evidence") != "measured" or srv.get("calls_30d") != 0:
            continue
        nkey = str(srv.get("normalized_key") or "")
        if not nkey or nkey in seen_keys:
            continue
        raw_toks = srv.get("estimated_tokens") if srv.get("estimated_tokens") is not None else srv.get("transcript_preamble_tokens")
        if not isinstance(raw_toks, int) or isinstance(raw_toks, bool) or raw_toks <= 0:
            continue
        seen_keys.add(nkey)
        unused_pairs.add(("claude", nkey))
        sev = "high" if raw_toks >= 2_000 else ("medium" if raw_toks >= preamble_attribution.CANDIDATE_MIN_TOKENS else "low")
        items.append(_make_item(
            f"unused_mcp_or_plugin_30d:claude:{nkey}", "unused_mcp_or_plugin_30d", sev, "claude", str(srv.get("name") or nkey),
            f"Review disabling unused Claude MCP server `{srv.get('name')}` (~{raw_toks:,} schema tokens, 0 calls in last 30 days).",
            raw_toks, "estimated", _PREFIX_CACHE_CAVEAT,
        ))
    return unused_pairs


def _collect_overlap_recommendations(mcp: Mapping[str, Any], items: list[dict[str, Any]]) -> None:
    servers = [s for s in (mcp.get("servers") or ()) if isinstance(s, Mapping) and s.get("enabled") is True]
    native_by_srv: dict[tuple[str, str], tuple[set[str], set[str]]] = {}
    dup_tools: dict[tuple[str, tuple[str, ...]], set[str]] = {}

    for ov in mcp.get("overlaps") or ():
        if not isinstance(ov, Mapping):
            continue
        kind, harness = str(ov.get("kind") or ""), str(ov.get("harness") or "")
        if kind == "duplicate_server_definition":
            nkey, sources = str(ov.get("normalized_key") or ""), [str(s) for s in (ov.get("sources") or ())]
            known = [
                int(t) for s in servers if s.get("harness") == harness and s.get("normalized_key") == nkey
                and isinstance((t := s.get("estimated_tokens") if s.get("estimated_tokens") is not None else s.get("transcript_preamble_tokens")), int)
                and not isinstance(t, bool)
            ]
            delta: int | None = (sum(known) - max(known)) if len(known) >= 2 else (known[0] if len(known) == 1 else None)
            ev, sev = ("estimated" if delta is not None else "unavailable"), ("high" if (delta is not None and delta >= 2_000) else "medium")
            items.append(_make_item(
                f"duplicate_mcp_server:{harness}:{nkey}", "duplicate_mcp_server", sev, harness, nkey,
                f"Consolidate duplicate `{nkey}` definitions in {harness} ({', '.join(sources)}) into a single scope.",
                delta, ev, _PREFIX_CACHE_CAVEAT,
            ))
        elif kind == "native_tool_overlap":
            cats, tools = native_by_srv.setdefault((harness, str(ov.get("server") or "")), (set(), set()))
            if ov.get("category"):
                cats.add(str(ov["category"]))
            tools.update(str(t) for t in (ov.get("matched_tools") or ()))
        elif kind == "duplicate_tool_name":
            srvs = tuple(sorted(str(s) for s in (ov.get("servers") or ())))
            if srvs and ov.get("tool_name"):
                dup_tools.setdefault((harness, srvs), set()).add(str(ov["tool_name"]))

    for (harness, sname), (cats, tools) in sorted(native_by_srv.items()):
        items.append(_make_item(
            f"mcp_tool_overlap:native:{harness}:{sname}", "mcp_tool_overlap", "medium" if len(cats) >= 2 else "low", harness, sname,
            f"Server `{sname}` overlaps native {harness} tools ({', '.join(sorted(cats))}: {', '.join(sorted(tools))}); consider disabling redundant tools or the server.",
            None, "unavailable", _PREFIX_CACHE_CAVEAT,
        ))
    for (harness, srvs), tools in sorted(dup_tools.items()):
        items.append(_make_item(
            f"mcp_tool_overlap:dup:{harness}:{'+'.join(srvs)}", "mcp_tool_overlap", "medium", harness, ", ".join(srvs),
            f"Active {harness} servers ({', '.join(srvs)}) expose duplicate tool names ({', '.join(sorted(tools))}); keep only one provider.",
            None, "unavailable", _PREFIX_CACHE_CAVEAT,
        ))


def _collect_preamble_recommendations(preamble: Mapping[str, Any], items: list[dict[str, Any]]) -> None:
    for dup in preamble.get("duplicate_skills") or ():
        if not isinstance(dup, Mapping):
            continue
        name, paths = str(dup.get("name") or ""), [str(p) for p in (dup.get("paths") or ())]
        harness = "antigravity" if paths and all(p.startswith("~/.gemini") for p in paths) else ("claude" if paths and all(p.startswith("~/.claude") for p in paths) else "multi")
        items.append(_make_item(
            f"duplicate_skills:{harness}:{name}", "duplicate_skills", "medium", harness, name,
            f"Deduplicate skill `{name}` ({dup.get('count', len(paths))} copies: {', '.join(paths)}); keep one canonical SKILL.md.",
            None, "unavailable", _PREFIX_CACHE_CAVEAT,
        ))

    mem_path = "MEMORY.md"
    for rec in preamble.get("static_files") or ():
        if not isinstance(rec, Mapping):
            continue
        if rec.get("component") == "memory_index" and rec.get("path"):
            mem_path = str(rec["path"])
        elif rec.get("component") in ("user_instructions", "workspace_instructions", "rules"):
            nbytes = rec.get("bytes")
            if isinstance(nbytes, int) and not isinstance(nbytes, bool) and nbytes > LARGE_INSTRUCTION_FILE_BYTES:
                est_tok = int(rec.get("estimated_tokens") or (nbytes // 4))
                excess = max(1, est_tok - (LARGE_INSTRUCTION_FILE_BYTES // 4))
                sev = "high" if nbytes >= 2 * LARGE_INSTRUCTION_FILE_BYTES else "medium"
                h, p = str(rec.get("harness") or ""), str(rec.get("path") or "")
                items.append(_make_item(
                    f"large_instruction_file:{h}:{p}", "large_instruction_file", sev, h, p,
                    f"Trim or split `{p}` ({nbytes:,} B / ~{est_tok:,} tokens); moving rare guidance to on-demand skills saves ~{excess:,} tokens above the 16 KiB budget.",
                    excess, "estimated", _PREFIX_CACHE_CAVEAT,
                ))

    claude_info = (preamble.get("by_harness") or {}).get("claude")
    mem_lines = claude_info.get("memory_lines") if isinstance(claude_info, Mapping) else None
    if isinstance(mem_lines, int) and not isinstance(mem_lines, bool) and mem_lines > usage_report.MEMORY_WARN_LINES:
        sev = "high" if mem_lines > usage_report.MEMORY_LOAD_LINES else "medium"
        items.append(_make_item(
            f"memory_index_truncation:claude:{mem_path}", "memory_index_truncation", sev, "claude", mem_path,
            f"Compact `{mem_path}` ({mem_lines} lines; Claude Code loads only the first {usage_report.MEMORY_LOAD_LINES} lines) by moving details into linked topic files.",
            None, "unavailable", _MEMORY_CAVEAT,
        ))


def _collect_unobserved_mcp_recommendations(mcp: Mapping[str, Any], items: list[dict[str, Any]]) -> None:
    by_harness: dict[str, list[str]] = {}
    has_stdio: dict[str, bool] = {}
    for srv in mcp.get("servers") or ():
        if not isinstance(srv, Mapping) or srv.get("enabled") is not True or srv.get("schema_status") != "unavailable":
            continue
        h = str(srv.get("harness") or "")
        by_harness.setdefault(h, []).append(str(srv.get("name") or ""))
        if srv.get("transport") == "stdio":
            has_stdio[h] = True
    for h, names in sorted(by_harness.items()):
        hint = " Run opt-in `cg budget --mcp --probe` for local stdio schemas." if has_stdio.get(h) else ""
        items.append(_make_item(
            f"unobserved_mcp_schemas:{h}", "unobserved_mcp_schemas", "low", h, ", ".join(names),
            f"Schema sizes unavailable in passive mode for {h} MCP server(s): {', '.join(names)}.{hint}",
            None, "unavailable", _UNOBSERVED_SCHEMA_CAVEAT,
        ))


def _build_session_profiles(mcp: Mapping[str, Any], unused_pairs: set[tuple[str, str]]) -> list[dict[str, Any]]:
    enabled = [s for s in (mcp.get("servers") or ()) if isinstance(s, Mapping) and s.get("enabled") is True]
    keep_min, disable_min, known_deltas = [], [], []
    for srv in enabled:
        label = f"{srv.get('harness')}:{srv.get('name')}"
        pair = (str(srv.get("harness") or ""), str(srv.get("normalized_key") or ""))
        is_bundled = srv.get("schema_status") == "bundled" or pair[1] == "mcp:context-guard-spool"
        calls = srv.get("calls_30d")
        is_used = srv.get("calls_evidence") == "measured" and isinstance(calls, int) and calls > 0
        if (is_bundled or is_used) and pair not in unused_pairs:
            keep_min.append(label)
        else:
            disable_min.append(label)
            raw_toks = srv.get("estimated_tokens") if srv.get("estimated_tokens") is not None else srv.get("transcript_preamble_tokens")
            if isinstance(raw_toks, int) and not isinstance(raw_toks, bool):
                known_deltas.append(raw_toks)
    min_delta: int | None = 0 if not disable_min else (sum(known_deltas) if known_deltas else None)
    min_ev = "estimated" if min_delta is not None else "unavailable"
    return [
        {
            "name": "minimal-core",
            "description": "Keep bundled Context-Guard spool and actively used MCP servers; review disabling unused or unverified servers between sessions.",
            "keep_servers": keep_min, "disable_candidates": disable_min, "estimated_tokens_delta": min_delta,
            "evidence": min_ev, "auto_applied": False, "guaranteed_savings": False, "cache_caveat": _PREFIX_CACHE_CAVEAT,
        },
        {
            "name": "full-integrations",
            "description": "Keep all currently enabled MCP servers active to preserve full tool availability and steady prompt-cache prefixes.",
            "keep_servers": [f"{s.get('harness')}:{s.get('name')}" for s in enabled], "disable_candidates": [],
            "estimated_tokens_delta": 0, "evidence": "estimated",
            "auto_applied": False, "guaranteed_savings": False, "cache_caveat": _PREFIX_CACHE_CAVEAT,
        },
    ]


def build_budget_recommendations(
    preamble: Mapping[str, Any], mcp: Mapping[str, Any], usage_state: Mapping[str, Any] | None = None, *, today: date | None = None,
) -> dict[str, Any]:
    """Generate conservative, non-mutating recommendations and cautious session profiles."""
    eff_today = today if today is not None else (_parse_iso_day((usage_state or {}).get("updated_at")) or date.today())
    items: list[dict[str, Any]] = []
    unused_pairs = _collect_unused_recommendations(mcp, usage_state, eff_today, items)
    _collect_overlap_recommendations(mcp, items)
    _collect_preamble_recommendations(preamble, items)
    _collect_unobserved_mcp_recommendations(mcp, items)

    items.sort(key=lambda it: (
        _SEVERITY_ORDER.get(str(it["severity"]), 9),
        -(int(it["estimated_tokens_delta"]) if isinstance(it.get("estimated_tokens_delta"), int) else -1),
        str(it["kind"]), str(it["harness"]), str(it["target"]), str(it["id"]),
    ))
    return {"auto_applied": False, "guaranteed_savings": False, "items": items, "session_profiles": _build_session_profiles(mcp, unused_pairs)}


def run_budget_audit(
    *, home: Path | None = None, workspace_root: Path | None = None, usage_path: Path | None = None,
    harnesses: Sequence[str] | None = None, include_preamble: bool = True, include_mcp: bool = True,
    include_recommendations: bool = True, probe: bool = False, probe_servers: Sequence[str] | None = None,
    probe_timeout_s: float = mcp_inventory.DEFAULT_PROBE_TIMEOUT_S,
) -> dict[str, Any]:
    """Run a read-only cross-harness preamble, MCP inventory, and advisory budget audit."""
    if probe and (not math.isfinite(probe_timeout_s) or not (mcp_inventory.MIN_PROBE_TIMEOUT_S <= probe_timeout_s <= mcp_inventory.MAX_PROBE_TIMEOUT_S)):
        raise ValueError(f"probe_timeout_s must be in [{mcp_inventory.MIN_PROBE_TIMEOUT_S}, {mcp_inventory.MAX_PROBE_TIMEOUT_S}]")
    eff_home, eff_ws = Path(home) if home is not None else Path.home(), Path(workspace_root) if workspace_root is not None else None
    eff_harnesses, roots = _normalize_harnesses(harnesses), token_usage.transcript_roots_for_home(eff_home)

    if usage_path is not None:
        u_state = token_usage.read_usage_snapshot(usage_path, roots=roots)
    elif home is not None:
        u_state = token_usage.read_usage_snapshot(None, roots=roots)
    else:
        u_state = token_usage.read_usage_snapshot(token_usage.DEFAULT_USAGE_PATH, roots=roots)

    eff_probe = bool(probe and (include_mcp or include_recommendations))
    preamble_data = collect_preamble_budget(eff_home, eff_ws, u_state, harnesses=eff_harnesses) if (include_preamble or include_recommendations) else None
    mcp_data = (
        mcp_inventory.collect_mcp_inventory(eff_home, eff_ws, u_state, harnesses=eff_harnesses, probe=eff_probe, probe_servers=probe_servers, probe_timeout_s=probe_timeout_s)
        if (include_mcp or include_recommendations)
        else None
    )

    requested_sections = [sec for sec, enabled in (("preamble", include_preamble), ("mcp", include_mcp), ("recommendations", include_recommendations)) if enabled]
    report: dict[str, Any] = {
        "schema_version": 1, "plugin_version": read_plugin_version(default="0.0.0"),
        "mode": "probe" if eff_probe else "passive", "read_only": True, "auto_mutated_configs": False,
        "probe_warning": mcp_inventory.PROBE_SIDE_EFFECT_WARNING if eff_probe else None,
        "harnesses_scanned": eff_harnesses, "requested_sections": requested_sections,
    }
    if include_preamble and preamble_data is not None:
        report["preamble"] = preamble_data
    if include_mcp and mcp_data is not None:
        report["mcp"] = mcp_data
    if include_recommendations and preamble_data is not None and mcp_data is not None:
        report["recommendations"] = build_budget_recommendations(preamble_data, mcp_data, u_state)
    return report
