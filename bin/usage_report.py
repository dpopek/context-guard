#!/usr/bin/env python3
"""Session preamble breakdown, hygiene warnings and the Markdown/JSON views of the token usage ledger."""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
import sys
from typing import Any

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from bin.preamble_attribution import (  # noqa: E402
    CANDIDATE_MIN_TOKENS,
    CANDIDATE_WINDOW_DAYS,
    CLAUDE_CLI_HARNESS,
    CLAUDE_DESKTOP_HARNESS,
    CODEX_CLI_HARNESS,
    CODEX_DESKTOP_HARNESS,
    COMPONENTS,
    extract_skill_frontmatter_summary,
    find_candidates,
    measure_antigravity_preamble,
    median,
    split_claude_parts,
    split_codex_parts,
    summarize_parts,
)
from hooks.outcomes import SCHEMA_VERSION as OUTCOMES_SCHEMA_VERSION  # noqa: E402

PREAMBLE_HOME = Path.home()
MEMORY_LOAD_LINES = 200
MEMORY_WARN_LINES = 150
PREAMBLE_WARN_TOKENS = 30_000
RECENT_PREAMBLE_WINDOW = 10
IMPORT_DEPTH = 5
_HARNESSES = ("antigravity", "claude", "codex", "cursor")
_IMPORT_RE = re.compile(r"(?<![\w`])@(~?[\w./-]+)")


@dataclass(frozen=True)
class PreambleBreakdown:
    """Estimated (bytes / 4) Claude Code and Antigravity preamble components and MEMORY.md line count."""

    components: tuple[tuple[str, int], ...]
    memory_lines: int
    antigravity_components: tuple[tuple[str, int], ...] = ()


def _tokens(text: str) -> int:
    return len(text.encode("utf-8")) // 4


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def memory_index_path(home: Path, project_dir: Path) -> Path:
    """The auto-memory index Claude Code loads for `project_dir` (every non-alphanumeric character becomes `-`)."""
    slug = re.sub(r"[^A-Za-z0-9]", "-", str(project_dir))
    return home / ".claude" / "projects" / slug / "memory" / "MEMORY.md"


def _import_targets(text: str, base: Path, home: Path) -> list[Path]:
    targets = []
    for raw in _IMPORT_RE.findall(text):
        candidate = home / raw[2:] if raw.startswith("~/") else base / raw
        if candidate.is_file():
            targets.append(candidate)
    return targets


def collect_instruction_files(roots: list[Path], home: Path) -> list[Path]:
    """Existing `roots` plus the files their `@path` imports reach, up to IMPORT_DEPTH hops, each listed once."""
    ordered: list[Path] = []
    frontier = [(path, 0) for path in roots if path.is_file()]
    while frontier:
        path, depth = frontier.pop(0)
        resolved = path.resolve()
        if resolved in ordered:
            continue
        ordered.append(resolved)
        if depth < IMPORT_DEPTH:
            frontier.extend((target, depth + 1) for target in _import_targets(_read_text(path), path.parent, home))
    return ordered


def active_claude_plugin_skill_files(home: Path) -> list[Path]:
    """Return active Claude plugin `SKILL.md` files from `installed_plugins.json` or newest cached versions."""
    files: list[Path] = []
    covered_plugin_dirs: set[Path] = set()
    installed_json = home / ".claude" / "plugins" / "installed_plugins.json"
    if installed_json.is_file():
        try:
            raw = json.loads(installed_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = None
        if isinstance(raw, dict):
            raw_plugins = raw.get("plugins")
            plugins_map: dict[str, Any] = raw_plugins if isinstance(raw_plugins, dict) else raw
            for entries in plugins_map.values():
                items = entries if isinstance(entries, list) else ([entries] if isinstance(entries, dict) else [])
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    inst_path = item.get("installPath")
                    if not isinstance(inst_path, str) or not inst_path.strip():
                        continue
                    inst_dir = Path(inst_path)
                    if inst_dir.is_dir():
                        try:
                            covered_plugin_dirs.add(inst_dir.parent.resolve())
                        except OSError:
                            pass
                        files.extend(sorted(inst_dir.glob("skills/*/SKILL.md")))
    for plugin_dir in sorted((home / ".claude" / "plugins" / "cache").glob("*/*")):
        try:
            resolved_parent = plugin_dir.resolve()
        except OSError:
            continue
        if resolved_parent in covered_plugin_dirs:
            continue
        versions = [entry for entry in plugin_dir.iterdir() if entry.is_dir()] if plugin_dir.is_dir() else []
        if versions:
            newest = max(versions, key=lambda entry: entry.stat().st_mtime)
            files.extend(sorted(newest.glob("skills/*/SKILL.md")))
    return files


def skill_listing_files(home: Path) -> list[Path]:
    """User skills plus the active version of every installed plugin."""
    files = sorted((home / ".claude" / "skills").glob("*/SKILL.md"))
    files.extend(active_claude_plugin_skill_files(home))
    return files


def _skill_name(path: Path) -> str:
    text = _read_text(path)
    if text.startswith("---"):
        end = text.find("\n---", 3)
        block = text[3:end] if end > 0 else ""
        for line in block.strip("\n").splitlines():
            if line.startswith("name:"):
                val = line.split(":", 1)[1].strip().strip("'\"")
                if val:
                    return val
    return path.parent.name


def find_duplicate_skills(home: Path | None = None) -> list[tuple[str, list[Path]]]:
    """Detect duplicate skill names separately within `.gemini` and `.claude` ecosystems (symlink-deduped)."""
    h = home if home is not None else PREAMBLE_HOME
    ecosystems = (
        sorted((h / ".gemini" / "config" / "skills").glob("*/SKILL.md"))
        + sorted((h / ".gemini" / "config" / "plugins").glob("*/skills/*/SKILL.md")),
        sorted((h / ".claude" / "skills").glob("*/SKILL.md"))
        + active_claude_plugin_skill_files(h),
    )
    duplicates: dict[str, list[Path]] = {}
    for eco_paths in ecosystems:
        by_name: dict[str, list[Path]] = {}
        seen_real: dict[str, set[str]] = {}
        for p in eco_paths:
            if not p.is_file():
                continue
            try:
                real = os.path.realpath(p)
            except OSError:
                continue
            name = _skill_name(p)
            reals = seen_real.setdefault(name, set())
            if real in reals:
                continue
            reals.add(real)
            by_name.setdefault(name, []).append(p)
        for name, paths in by_name.items():
            if len(paths) >= 2:
                duplicates.setdefault(name, []).extend(paths)
    return sorted(duplicates.items(), key=lambda item: item[0])


def _frontmatter_listing(text: str) -> str:
    """The `name:` and `description:` lines of a SKILL.md frontmatter, which is what the skills listing shows."""
    return extract_skill_frontmatter_summary(text)


def measure_preamble_components(home: Path, project_dir: Path) -> PreambleBreakdown:
    """Estimate what Claude Code loads before the first turn in `project_dir`, from the files on disk."""
    user_files = collect_instruction_files([home / ".claude" / "CLAUDE.md"], home)
    project_roots = [
        directory / name
        for directory in (project_dir, *project_dir.parents)
        for name in ("CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md")
    ]
    project_files = [path for path in collect_instruction_files(project_roots, home) if path not in user_files]
    memory_lines = _read_text(memory_index_path(home, project_dir)).splitlines()
    skills = "\n".join(
        listing for listing in (_frontmatter_listing(_read_text(path)) for path in skill_listing_files(home)) if listing
    )
    return PreambleBreakdown(
        components=(
            ("user CLAUDE.md + imports", sum(_tokens(_read_text(path)) for path in user_files)),
            ("project CLAUDE.md + imports", sum(_tokens(_read_text(path)) for path in project_files)),
            ("MEMORY.md index (first 200 lines)", _tokens("\n".join(memory_lines[:MEMORY_LOAD_LINES]))),
            ("skills listing", _tokens(skills)),
        ),
        memory_lines=len(memory_lines),
        antigravity_components=measure_antigravity_preamble(home, project_dir),
    )


def summarize_preamble(values: list[Any]) -> dict[str, int]:
    """Session count, median, recent-window median, p90 (nearest rank) and last value of a preamble history."""
    clean = [value for value in values if isinstance(value, int) and not isinstance(value, bool)]
    if not clean:
        return {"sessions": 0, "median": 0, "recent_median": 0, "p90": 0, "last": 0}
    ordered = sorted(clean)
    p90 = ordered[max(0, math.ceil(0.9 * len(ordered)) - 1)]
    return {
        "sessions": len(ordered),
        "median": median(ordered),
        "recent_median": median(clean[-RECENT_PREAMBLE_WINDOW:]),
        "p90": p90,
        "last": clean[-1],
    }


def hygiene_warnings(memory_lines: int, summaries: dict[str, dict[str, int]]) -> list[str]:
    """Report-only warnings: a MEMORY.md index near the load limit and a large recent/median preamble per harness."""
    warnings = []
    if memory_lines > MEMORY_WARN_LINES:
        warnings.append(
            f"MEMORY.md index has {memory_lines} lines; Claude Code loads only the first {MEMORY_LOAD_LINES}, "
            "so lines past that are never seen."
        )
    has_claude_split = any(
        summaries.get(cohort, {}).get("sessions", 0) > 0
        for cohort in (CLAUDE_CLI_HARNESS, CLAUDE_DESKTOP_HARNESS)
    )
    has_codex_split = any(
        summaries.get(cohort, {}).get("sessions", 0) > 0
        for cohort in (CODEX_CLI_HARNESS, CODEX_DESKTOP_HARNESS)
    )
    for harness in sorted(summaries):
        if (harness == "claude" and has_claude_split) or (harness == "codex" and has_codex_split):
            continue
        summary = summaries[harness]
        has_recent = "recent_median" in summary
        effective = summary.get("recent_median", summary.get("median", 0))
        if effective > PREAMBLE_WARN_TOKENS:
            if has_recent and summary.get("sessions", 0) > RECENT_PREAMBLE_WINDOW:
                warnings.append(
                    f"Recent {harness} session preamble median (last {RECENT_PREAMBLE_WINDOW}) is "
                    f"{effective:,} tokens (above {PREAMBLE_WARN_TOKENS:,})."
                )
            else:
                warnings.append(
                    f"Median {harness} session preamble is {effective:,} tokens (above {PREAMBLE_WARN_TOKENS:,})."
                )
    return warnings


def _row_int(row: Any, key: str) -> int:
    value = row.get(key) if isinstance(row, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def savings_share(
    state: dict[str, Any],
    saved_tokens_now: int,
    stats_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Context-Guard saved tokens against the real input tokens of the same UTC days."""
    raw_usage_days = state.get("by_day")
    usage_by_day = (
        {str(k): v for k, v in raw_usage_days.items() if isinstance(k, str) and len(k) == 10 and isinstance(v, dict)}
        if isinstance(raw_usage_days, dict)
        else {}
    )
    raw_stats_days = stats_state.get("by_day") if isinstance(stats_state, dict) else None
    stats_by_day = (
        {str(k): v for k, v in raw_stats_days.items() if isinstance(k, str) and len(k) == 10 and isinstance(v, dict)}
        if isinstance(raw_stats_days, dict)
        else {}
    )
    total_events = sum(
        _row_int(row, "events") for harnesses in usage_by_day.values() for row in harnesses.values()
    )
    if stats_by_day and usage_by_day:
        common_start_day = max(min(stats_by_day.keys()), min(usage_by_day.keys()))
        common_end_day = min(max(stats_by_day.keys()), max(usage_by_day.keys()))
        if common_start_day > common_end_day:
            return {
                "since": common_start_day,
                "until": common_end_day,
                "saved": 0,
                "real_input": 0,
                "share_pct": 0.0,
                "window_events": 0,
                "total_events": total_events,
            }
        saved_bytes_sum = sum(
            int(stats_by_day[d].get("saved_bytes", 0) or 0)
            for d in stats_by_day
            if common_start_day <= d <= common_end_day
        )
        saved = max(0, saved_bytes_sum) // 4
        real_input = 0
        window_events = 0
        for day, harnesses in usage_by_day.items():
            if common_start_day <= day <= common_end_day:
                for row in harnesses.values():
                    real_input += (
                        _row_int(row, "input") + _row_int(row, "cache_read") + _row_int(row, "cache_write")
                    )
                    window_events += _row_int(row, "events")
        denominator = real_input + saved
        share = round(saved / denominator * 100.0, 2) if denominator else 0.0
        return {
            "since": common_start_day,
            "until": common_end_day,
            "saved": saved,
            "real_input": real_input,
            "share_pct": share,
            "window_events": window_events,
            "total_events": total_events,
        }

    since = str(state.get("started_at") or "")
    since_day = _ledger_day(since[:10])
    since_prefix = since_day.isoformat() if since_day else ""
    saved = max(0, saved_tokens_now - _row_int(state, "saved_tokens_at_start"))
    real_input = 0
    window_events = 0
    for day, harnesses in (state.get("by_day") or {}).items():
        if day >= since[:10] and isinstance(harnesses, dict):
            for row in harnesses.values():
                real_input += _row_int(row, "input") + _row_int(row, "cache_read") + _row_int(row, "cache_write")
                window_events += _row_int(row, "events")
    until = max((d for d in usage_by_day if d >= since_prefix), default="") if since_day else ""
    denominator = real_input + saved
    share = round(saved / denominator * 100.0, 2) if denominator else 0.0
    return {
        "since": since,
        "until": until,
        "saved": saved,
        "real_input": real_input,
        "share_pct": share,
        "window_events": window_events,
        "total_events": total_events,
    }


def _cache_hit(row: dict[str, Any]) -> str:
    events = _row_int(row, "events")
    if events and _row_int(row, "total_only") == events:
        return "n/a (total only)"
    read = _row_int(row, "cache_read")
    denominator = _row_int(row, "input") + read + _row_int(row, "cache_write")
    return f"{read / denominator * 100.0:.1f}%" if denominator else "n/a"


def _preamble_summaries(state: dict[str, Any]) -> dict[str, dict[str, int]]:
    preamble = state.get("preamble") or {}
    summaries = {harness: summarize_preamble(values) for harness, values in preamble.items() if isinstance(values, list)}
    cohorts = split_claude_parts(state.get("preamble_parts"))
    if cohorts[CLAUDE_CLI_HARNESS] or cohorts[CLAUDE_DESKTOP_HARNESS]:
        for cohort_name in (CLAUDE_CLI_HARNESS, CLAUDE_DESKTOP_HARNESS):
            summaries[cohort_name] = summarize_preamble([entry["measured"] for entry in cohorts[cohort_name]])
    codex_cohorts = split_codex_parts(state.get("codex_preamble_parts"))
    if codex_cohorts[CODEX_CLI_HARNESS] or codex_cohorts[CODEX_DESKTOP_HARNESS]:
        for cohort_name in (CODEX_CLI_HARNESS, CODEX_DESKTOP_HARNESS):
            summaries[cohort_name] = summarize_preamble([entry["measured"] for entry in codex_cohorts[cohort_name]])
    return summaries


def _cursor_estimate(state: dict[str, Any]) -> dict[str, int]:
    entries = [entry for entry in (state.get("cursor_estimates") or {}).values() if isinstance(entry, dict)]
    return {"files": len(entries), "tokens": sum(_row_int(entry, "tokens") for entry in entries)}


def _backlog(state: dict[str, Any]) -> dict[str, int]:
    backlog = state.get("backlog")
    return {str(harness): _row_int(backlog, harness) for harness in backlog} if isinstance(backlog, dict) else {}


def _megabytes(size: int) -> str:
    return "<0.1 MB" if size < 0.1 * 1024 * 1024 else f"{size / (1024 * 1024):,.1f} MB"


def _ledger_day(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _attribution(state: dict[str, Any]) -> dict[str, Any]:
    """Measured Claude Code preamble breakdown and candidates; an exception yields only its class name."""
    try:
        entries = state.get("preamble_parts") or []
        summary = summarize_parts(entries)
        cohorts_raw = split_claude_parts(entries)
        cohorts = {name: summarize_parts(items) for name, items in cohorts_raw.items() if items}
        today = _ledger_day(state.get("updated_at"))
        since = str(state.get("component_use_since") or "")
        window_start = (today - timedelta(days=CANDIDATE_WINDOW_DAYS - 1)).isoformat() if today else ""
        ready = bool(today and since and since <= window_start and summary["sessions"])
        candidates = find_candidates(entries, state.get("component_use") or {}, today) if ready and today else []
        return {
            "source": "measured" if summary["sessions"] else "estimate",
            **summary,
            "cohorts": cohorts,
            "tracked_since": since or None,
            "window_end": today.isoformat() if today else None,
            "candidates_ready": ready,
            "candidates": candidates,
        }
    except Exception as exc:
        return {"error": type(exc).__name__}


def _measured_table(heading: str, sub: dict[str, Any]) -> list[str]:
    lines = ["", heading, "", "| Component | Plugin or server | Tokens |", "|---|---|---:|"]
    for component in COMPONENTS:
        keys = sub["components"].get(component, {})
        lines.extend(
            f"| {component} | `{key}` | {keys[key]:,} |"
            for key in sorted(keys, key=lambda name: (-keys[name], name))
        )
    lines.append(f"| tool schemas (unattributed) | | {sub['unattributed']:,} |")
    lines.append(f"| **measured median** | | **{sub['measured']:,}** |")
    if sub["clamped"]:
        lines.extend(
            ["", "_The attributed components exceed the measured preamble in the median session; the remainder is shown as 0._"]
        )
    return lines


def _breakdown_lines(attribution: dict[str, Any], claude_median: int, breakdown: PreambleBreakdown) -> list[str]:
    if "error" in attribution:
        return ["", "### Claude Code preamble breakdown", "", f"_Unavailable: {attribution['error']}_"]
    if attribution["source"] == "estimate":
        lines = ["", "### Claude Code preamble breakdown (estimate, bytes / 4)", "", "| Component | Tokens |", "|---|---:|"]
        lines.extend(f"| {label} | {tokens:,} |" for label, tokens in breakdown.components)
        known = sum(tokens for _, tokens in breakdown.components)
        lines.append(f"| system prompt + tools + MCP (unattributed) | {max(0, claude_median - known):,} |")
        lines.append(f"| **measured median** | **{claude_median:,}** |")
        return lines
    cohorts = attribution.get("cohorts") or {}
    if CLAUDE_DESKTOP_HARNESS in cohorts:
        lines = []
        for cohort_name in (CLAUDE_CLI_HARNESS, CLAUDE_DESKTOP_HARNESS):
            sub = cohorts.get(cohort_name)
            if sub and sub.get("sessions"):
                lines.extend(
                    _measured_table(
                        f"### Claude Code preamble breakdown — {cohort_name} (measured, median of {sub['sessions']:,} sessions)",
                        sub,
                    )
                )
        return lines
    return _measured_table(
        f"### Claude Code preamble breakdown (measured, median of {attribution['sessions']:,} sessions)",
        attribution,
    )


def _candidate_lines(attribution: dict[str, Any]) -> list[str]:
    lines = ["", "### Preamble candidates", ""]
    if "error" in attribution:
        return lines + [f"_Unavailable: {attribution['error']}_"]
    if not attribution["sessions"]:
        return lines + ["_No measured Claude Code sessions yet._"]
    if not attribution["candidates_ready"]:
        since = attribution["tracked_since"] or "n/a"
        return lines + [f"_Tool calls tracked since {since}; candidates need {CANDIDATE_WINDOW_DAYS} days._"]
    if not attribution["candidates"]:
        return lines + [f"_No candidates: every plugin or server above {CANDIDATE_MIN_TOKENS} tokens was called in the last {CANDIDATE_WINDOW_DAYS} days._"]
    lines.extend(["| Plugin or server | Median tokens per session | Calls (30 days) |", "|---|---:|---:|"])
    lines.extend(f"| `{row['key']}` | {row['tokens']:,} | {row['calls']} |" for row in attribution["candidates"])
    lines.extend(
        [
            "",
            f"_Median above {CANDIDATE_MIN_TOKENS} tokens per session and no call in the {CANDIDATE_WINDOW_DAYS} days "
            f"to {attribution['window_end']}. Report only; nothing was changed._",
        ]
    )
    return lines


_ADVISORY_LABELS = (
    ("advised_outline", "outline", "outline"),
    ("advised_reread", "reread", "reread"),
    ("advised_shell", "shell", "shell"),
    ("advised_inline_python", "inline_python", "inline python"),
)


def _active_outcomes_by_key(outcomes_state: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(outcomes_state, dict):
        return {}
    if "schema_version" in outcomes_state and outcomes_state.get("schema_version") != OUTCOMES_SCHEMA_VERSION:
        return {}
    by_key = outcomes_state.get("by_key")
    return by_key if isinstance(by_key, dict) else {}


def advisory_counts(outcomes_state: dict[str, Any] | None) -> dict[str, int]:
    """Advisory interventions per kind from the outcomes ledger; empty when there is none. Never feeds a saved total."""
    by_key = _active_outcomes_by_key(outcomes_state)
    if not by_key:
        return {}
    counts = {name: 0 for _, name, _ in _ADVISORY_LABELS}
    for key, row in by_key.items():
        kind = str(key).rpartition("|")[2]
        for advised, name, _ in _ADVISORY_LABELS:
            if kind == advised and isinstance(row, dict):
                counts[name] += _row_int(row, "total") + _row_int(row, "repeats")
    return counts if any(counts.values()) else {}


_DENIAL_KINDS = ("outline", "reread_block", "shell_block", "wide_followup")
_CACHE_READ_PRICE_RATIO = 0.1


def denial_overhead(state: dict[str, Any], outcomes_state: dict[str, Any] | None) -> dict[str, int]:
    """Input-equivalent tokens spent on the extra turn each denial forces; empty without denials.

    A denied call makes the model take one more turn, which re-reads the whole context from cache:
    the harness's mean cache read per call, priced at the cache-read ratio.
    """
    by_key = _active_outcomes_by_key(outcomes_state)
    if not by_key:
        return {}
    calls: dict[str, int] = {}
    cache_read: dict[str, int] = {}
    for key, row in (state.get("totals") or {}).items():
        harness = str(key).partition("|")[0]
        calls[harness] = calls.get(harness, 0) + _row_int(row, "events")
        cache_read[harness] = cache_read.get(harness, 0) + _row_int(row, "cache_read")
    denials = 0
    tokens = 0.0
    for key, row in by_key.items():
        harness = str(key).partition("|")[0]
        if str(key).rpartition("|")[2] not in _DENIAL_KINDS or not isinstance(row, dict):
            continue
        count = _row_int(row, "total") + _row_int(row, "repeats")
        denials += count
        if calls.get(harness):
            tokens += count * cache_read[harness] / calls[harness] * _CACHE_READ_PRICE_RATIO
    return {"denials": denials, "tokens": int(tokens)} if denials else {}


def sunset_verdict(share: dict[str, Any], overhead: dict[str, int]) -> dict[str, Any]:
    """Evaluate net savings after denial overhead and classify whether the 30-day sunset threshold is cleared."""
    saved = max(0, int(share.get("saved") or 0))
    denial_tok = max(0, int(overhead.get("tokens") or 0)) if overhead else 0
    window_events = max(0, int(share.get("window_events") or 0))
    total_events = max(0, int(share.get("total_events") or 0))
    if 0 < window_events < total_events:
        denial_tok = int(denial_tok * window_events / total_events)
    net_saved = saved - denial_tok
    real_input = max(0, int(share.get("real_input") or 0))
    denom = real_input + max(0, net_saved)
    net_share = round(net_saved / denom * 100.0, 2) if denom else 0.0
    since_d = _ledger_day(share.get("since"))
    until_d = _ledger_day(share.get("until"))
    window_days = max(0, (until_d - since_d).days + 1) if (since_d and until_d and until_d >= since_d) else 0
    if window_days < 30:
        status = "collecting_30d_window"
    elif net_share < 0.5:
        status = "sunset_candidate"
    else:
        status = "net_positive"
    return {
        "window_days": window_days,
        "target_days": 30,
        "net_saved": net_saved,
        "net_share_pct": net_share,
        "status": status,
    }


def _codex_breakdown_lines(state: dict[str, Any]) -> list[str]:
    cohorts_raw = split_codex_parts(state.get("codex_preamble_parts"))
    lines: list[str] = []
    for cohort_name in (CODEX_CLI_HARNESS, CODEX_DESKTOP_HARNESS):
        items = cohorts_raw.get(cohort_name) or []
        if items:
            sub = summarize_parts(items)
            lines.extend(
                _measured_table(
                    f"### Codex preamble breakdown — {cohort_name} (measured, median of {sub['sessions']:,} sessions)",
                    sub,
                )
            )
    return lines


def _antigravity_breakdown_lines(ag_median: int, breakdown: PreambleBreakdown) -> list[str]:
    if not breakdown.antigravity_components or (ag_median <= 0 and not any(t for _, t in breakdown.antigravity_components)):
        return []
    lines = ["", "### Antigravity preamble breakdown (estimate, bytes / 4)", "", "| Component | Tokens |", "|---|---:|"]
    lines.extend(f"| {label} | {tokens:,} |" for label, tokens in breakdown.antigravity_components)
    known = sum(tokens for _, tokens in breakdown.antigravity_components)
    if ag_median > 0:
        lines.append(f"| system prompt + built-in tools (unattributed) | {max(0, ag_median - known):,} |")
        lines.append(f"| **measured median** | **{ag_median:,}** |")
    return lines


def render_usage_sections(
    state: dict[str, Any],
    saved_tokens_now: int,
    breakdown: PreambleBreakdown,
    stats_state: dict[str, Any] | None = None,
    outcomes_state: dict[str, Any] | None = None,
) -> list[str]:
    """Markdown lines for Token Usage, Real Savings Share, Session Preamble and Preamble candidates; the first line is blank."""
    totals = state.get("totals") or {}
    cursor = _cursor_estimate(state)
    lines = ["", "## Token Usage (real, from transcripts)", ""]
    if totals or cursor["files"]:
        lines.append("| Harness | Model | Calls | Input | Cache read | Cache write | Output | Cache hit |")
        lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
        for key in sorted(totals):
            row = totals[key]
            harness, _, model = key.partition("|")
            lines.append(
                f"| `{harness}` | {model} | {_row_int(row, 'events'):,} | {_row_int(row, 'input'):,} "
                f"| {_row_int(row, 'cache_read'):,} | {_row_int(row, 'cache_write'):,} | {_row_int(row, 'output'):,} "
                f"| {_cache_hit(row)} |"
            )
        if cursor["files"]:
            lines.append(f"| `cursor` | estimate | {cursor['files']} files | ~{cursor['tokens']:,} | n/a | n/a | n/a | n/a |")
    else:
        lines.append("_No transcripts with usage found yet._")
    coverage = state.get("antigravity_coverage") or {}
    if _row_int(coverage, "planner"):
        lines.append("")
        lines.append(
            f"_Antigravity: usage on {_row_int(coverage, 'with_usage')} of {_row_int(coverage, 'planner')} planner steps._"
        )
    if _row_int(state, "skipped_lines"):
        lines.append(f"_Unparseable transcript lines skipped: {_row_int(state, 'skipped_lines'):,}._")
    unread = {harness: size for harness, size in sorted(_backlog(state).items()) if size}
    if unread:
        names = ", ".join(f"`{harness}` {_megabytes(size)}" for harness, size in unread.items())
        lines.append(f"_Backlog: {names} unread; totals are partial, run again to continue._")

    share = savings_share(state, saved_tokens_now, stats_state=stats_state)
    lines.extend(
        [
            "",
            "## Real Savings Share",
            "",
            f"- Context-Guard tokens saved since `{share['since'] or 'n/a'}` (estimated): `{share['saved']:,}`",
            f"- Real input tokens on the same days (input + cache read + cache write): `{share['real_input']:,}`",
            f"- Share of input avoided: **{share['share_pct']:.2f}%** (lower bound: an avoided read would also have "
            "been re-sent from cache on later turns; output tokens are unaffected)",
        ]
    )
    if unread:
        lines.append("- Computed on partial input: the transcript backlog above is not read yet.")
    advisories = advisory_counts(outcomes_state)
    if advisories:
        parts = ", ".join(f"{label} {advisories[name]:,}" for _, name, label in _ADVISORY_LABELS)
        lines.append(f"- Advisories (counted, never credited as saved): {parts}")
    overhead = denial_overhead(state, outcomes_state)
    if overhead:
        lines.append(
            f"- Forced-turn overhead (estimated, ledger lifetime): `{overhead['denials']:,}` denials, about "
            f"`{overhead['tokens']:,}` input-equivalent tokens re-read from cache; not deducted above"
        )
    verdict = sunset_verdict(share, overhead)
    lines.append(
        f"- Net 30-day impact (after denials): `{verdict['net_saved']:,}` (`{verdict['net_share_pct']:.2f}%` over "
        f"{verdict['window_days']}/{verdict['target_days']}d -> `{verdict['status']}`)"
    )

    summaries = _preamble_summaries(state)
    lines.extend(
        [
            "",
            "## Session Preamble",
            "",
            f"| Harness | Sessions | Median | Recent ({RECENT_PREAMBLE_WINDOW}) | p90 | Last |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    preamble_rows: list[str] = ["antigravity"]
    if CLAUDE_CLI_HARNESS in summaries or CLAUDE_DESKTOP_HARNESS in summaries:
        preamble_rows.extend([CLAUDE_CLI_HARNESS, CLAUDE_DESKTOP_HARNESS])
    else:
        preamble_rows.append("claude")
    if CODEX_CLI_HARNESS in summaries or CODEX_DESKTOP_HARNESS in summaries:
        preamble_rows.extend([CODEX_CLI_HARNESS, CODEX_DESKTOP_HARNESS])
    else:
        preamble_rows.append("codex")
    preamble_rows.append("cursor")
    for harness in preamble_rows:
        summary = summaries.get(harness)
        if summary and summary["sessions"]:
            lines.append(
                f"| `{harness}` | {summary['sessions']:,} | {summary['median']:,} | "
                f"{summary['recent_median']:,} | {summary['p90']:,} | {summary['last']:,} |"
            )
        else:
            lines.append(f"| `{harness}` | no data | | | | |")
    claude_median = summaries.get("claude", {}).get("median", 0)
    attribution = _attribution(state)
    lines.extend(_breakdown_lines(attribution, claude_median, breakdown))
    lines.extend(_codex_breakdown_lines(state))
    lines.extend(_antigravity_breakdown_lines(summaries.get("antigravity", {}).get("median", 0), breakdown))
    lines.extend(_candidate_lines(attribution))
    warnings = hygiene_warnings(breakdown.memory_lines, summaries)
    lines.extend(["", "### Hygiene", ""])
    lines.extend([f"- ⚠️ {warning}" for warning in warnings] or ["_No hygiene warnings._"])
    return lines


def usage_summary(
    state: dict[str, Any],
    saved_tokens_now: int,
    breakdown: PreambleBreakdown,
    stats_state: dict[str, Any] | None = None,
    outcomes_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The same data as the Markdown sections, for `cg_status --json`; no paths or message ids."""
    summaries = _preamble_summaries(state)
    share = savings_share(state, saved_tokens_now, stats_state=stats_state)
    overhead = denial_overhead(state, outcomes_state)
    return {
        "totals": state.get("totals") or {},
        "by_day": state.get("by_day") or {},
        "preamble": summaries,
        "antigravity_coverage": state.get("antigravity_coverage") or {},
        "cursor_estimate": _cursor_estimate(state),
        "skipped_lines": _row_int(state, "skipped_lines"),
        "backlog": _backlog(state),
        "partial": any(_backlog(state).values()),
        "started_at": state.get("started_at"),
        "updated_at": state.get("updated_at"),
        "savings_share": share,
        "advisories": advisory_counts(outcomes_state),
        "denial_overhead": overhead,
        "sunset_verdict": sunset_verdict(share, overhead),
        "breakdown": [{"component": label, "tokens": tokens} for label, tokens in breakdown.components],
        "antigravity_breakdown": [{"component": label, "tokens": tokens} for label, tokens in breakdown.antigravity_components],
        "attribution": _attribution(state),
        "warnings": hygiene_warnings(breakdown.memory_lines, summaries),
    }
