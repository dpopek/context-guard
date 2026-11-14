"""Session preamble breakdown, hygiene warnings and the token usage views."""
from __future__ import annotations

import os
from pathlib import Path

from bin.preamble_attribution import CODEX_CLI_HARNESS, CODEX_DESKTOP_HARNESS
from bin.token_usage import empty_usage_state
from bin.usage_report import (
    PreambleBreakdown,
    collect_instruction_files,
    hygiene_warnings,
    measure_preamble_components,
    memory_index_path,
    render_usage_sections,
    savings_share,
    skill_listing_files,
    sunset_verdict,
    summarize_preamble,
    usage_summary,
)


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_memory_index_path_uses_claude_project_slug(tmp_path: Path) -> None:
    home = tmp_path / "home"
    path = memory_index_path(home, Path("/Users/x/workspace/My.App/.claude"))
    assert path == home / ".claude" / "projects" / "-Users-x-workspace-My-App--claude" / "memory" / "MEMORY.md"


def test_imports_are_followed_once_relative_and_from_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    root = write(tmp_path / "proj" / "CLAUDE.md", "See @AGENTS.md and @~/shared.md, mail me@example.com, @missing.md\n")
    agents = write(tmp_path / "proj" / "AGENTS.md", "loop back @CLAUDE.md\n")
    shared = write(home / "shared.md", "shared\n")
    assert collect_instruction_files([root, tmp_path / "proj" / "absent.md"], home) == [
        root.resolve(),
        agents.resolve(),
        shared.resolve(),
    ]


def test_import_depth_is_limited(tmp_path: Path) -> None:
    files = [write(tmp_path / f"f{i}.md", f"@f{i + 1}.md\n") for i in range(8)]
    found = collect_instruction_files([files[0]], tmp_path)
    assert len(found) == 6  # the root plus IMPORT_DEPTH (5) hops


def test_skill_listing_takes_user_skills_and_newest_plugin_version(tmp_path: Path) -> None:
    home = tmp_path / "home"
    user = write(home / ".claude" / "skills" / "a" / "SKILL.md", "---\nname: a\n---\n")
    old = write(home / ".claude" / "plugins" / "cache" / "m" / "p" / "1.0" / "skills" / "s" / "SKILL.md", "x")
    new = write(home / ".claude" / "plugins" / "cache" / "m" / "p" / "2.0" / "skills" / "s" / "SKILL.md", "y")
    os.utime(old.parents[2], (1000, 1000))
    os.utime(new.parents[2], (2000, 2000))
    assert skill_listing_files(home) == [user, new]


def test_preamble_components_are_bytes_over_four(tmp_path: Path) -> None:
    home = tmp_path / "home"
    project = tmp_path / "work" / "proj"
    write(home / ".claude" / "CLAUDE.md", "u" * 400)
    write(project / "CLAUDE.md", "p" * 800)
    write(memory_index_path(home, project), "\n".join(f"- line {i}" for i in range(250)))
    write(home / ".claude" / "skills" / "a" / "SKILL.md", "---\nname: abcd\ndescription: " + "d" * 100 + "\nother: zzz\n---\nbody " * 50)
    breakdown = measure_preamble_components(home, project)
    components = dict(breakdown.components)
    assert components["user CLAUDE.md + imports"] == 100
    assert components["project CLAUDE.md + imports"] == 200
    assert components["MEMORY.md index (first 200 lines)"] == len("\n".join(f"- line {i}" for i in range(200)).encode()) // 4
    assert components["skills listing"] == len(("name: abcd\ndescription: " + "d" * 100).encode()) // 4
    assert breakdown.memory_lines == 250


def test_user_claude_md_is_not_counted_again_as_project_file(tmp_path: Path) -> None:
    home = tmp_path / "home"
    write(home / ".claude" / "CLAUDE.md", "u" * 400)
    components = dict(measure_preamble_components(home, home / "proj").components)
    assert components["user CLAUDE.md + imports"] == 100
    assert components["project CLAUDE.md + imports"] == 0


def test_summarize_preamble_median_p90_last() -> None:
    assert summarize_preamble([]) == {"sessions": 0, "median": 0, "p90": 0, "last": 0}
    assert summarize_preamble([50, 10, 30, 20]) == {"sessions": 4, "median": 25, "p90": 50, "last": 20}
    assert summarize_preamble(list(range(1, 11)) + [True, "x"]) == {"sessions": 10, "median": 5, "p90": 9, "last": 10}


def test_hygiene_warnings_thresholds() -> None:
    assert hygiene_warnings(150, {"claude": {"median": 30_000}}) == []
    warnings = hygiene_warnings(151, {"claude": {"median": 30_001}, "codex": {"median": 5}})
    assert len(warnings) == 2
    assert "151 lines" in warnings[0] and "first 200" in warnings[0]
    assert "claude" in warnings[1] and "30,001" in warnings[1]


def ledger() -> dict:
    state = empty_usage_state()
    state["started_at"] = "2026-11-01T08:00:00+00:00"
    state["saved_tokens_at_start"] = 1000
    state["totals"] = {
        "claude|claude-opus-5-5": {"input": 100, "output": 50, "cache_read": 800, "cache_write": 100, "events": 4, "total_only": 0},
        "codex|gpt-6.1-sol": {"input": 500, "output": 0, "cache_read": 0, "cache_write": 0, "events": 2, "total_only": 2},
    }
    state["by_day"] = {
        "2026-10-31": {"claude": {"input": 999999, "output": 0, "cache_read": 0, "cache_write": 0, "events": 1, "total_only": 0}},
        "2026-11-01": {"claude": {"input": 100, "output": 50, "cache_read": 800, "cache_write": 100, "events": 3, "total_only": 0}},
    }
    state["preamble"] = {"claude": [20000, 40000, 35000]}
    state["antigravity_coverage"] = {"planner": 18, "with_usage": 3}
    state["cursor_estimates"] = {"/x/c.json": {"inode": 1, "size": 9, "tokens": 250, "day": "2025-12-12"}}
    return state


BREAKDOWN = PreambleBreakdown(components=(("user CLAUDE.md + imports", 1000), ("skills listing", 4000)), memory_lines=160)


def test_savings_share_counts_only_days_since_start() -> None:
    assert savings_share(ledger(), 2000) == {
        "since": "2026-11-01T08:00:00+00:00",
        "saved": 1000,
        "real_input": 1000,
        "share_pct": 50.0,
    }


def test_rendered_sections() -> None:
    text = "\n".join(render_usage_sections(ledger(), 2000, BREAKDOWN))
    assert "| `claude` | claude-opus-5-5 | 4 | 100 | 800 | 100 | 50 | 80.0% |" in text
    assert "| `codex` | gpt-6.1-sol | 2 | 500 | 0 | 0 | 0 | n/a (total only) |" in text
    assert "| `cursor` | estimate | 1 files | ~250 | n/a | n/a | n/a | n/a |" in text
    assert "usage on 3 of 18 planner steps" in text
    assert "**50.00%**" in text
    assert "| `claude` | 3 | 35,000 | 40,000 | 35,000 |" in text
    assert "| `codex` | no data | | | |" in text
    assert "| system prompt + tools + MCP (unattributed) | 30,000 |" in text
    assert "160 lines" in text and "claude" in text


def test_rendered_sections_without_data() -> None:
    text = "\n".join(render_usage_sections(empty_usage_state(), 0, PreambleBreakdown(components=(), memory_lines=0)))
    assert "_No transcripts with usage found yet._" in text
    assert "_No hygiene warnings._" in text


def test_usage_summary_for_json() -> None:
    summary = usage_summary(ledger(), 2000, BREAKDOWN)
    assert summary["preamble"]["claude"]["median"] == 35000
    assert summary["cursor_estimate"] == {"files": 1, "tokens": 250}
    assert summary["savings_share"]["share_pct"] == 50.0
    assert summary["breakdown"][0] == {"component": "user CLAUDE.md + imports", "tokens": 1000}
    assert len(summary["warnings"]) == 2
    assert "cursors" not in summary and "seen_ids" not in summary


def test_backlog_marks_totals_and_share_as_partial() -> None:
    state = ledger()
    state["backlog"] = {"claude": 3 * 1024 * 1024, "codex": 0}
    text = "\n".join(render_usage_sections(state, 2000, BREAKDOWN))
    assert "_Backlog: `claude` 3.0 MB unread; totals are partial, run again to continue._" in text
    assert "partial input" in text
    summary = usage_summary(state, 2000, BREAKDOWN)
    assert summary["backlog"] == {"claude": 3 * 1024 * 1024, "codex": 0}
    assert summary["partial"] is True


def test_no_backlog_means_complete() -> None:
    text = "\n".join(render_usage_sections(ledger(), 2000, BREAKDOWN))
    assert "partial" not in text
    summary = usage_summary(ledger(), 2000, BREAKDOWN)
    assert summary["backlog"] == {} and summary["partial"] is False


def parts_ledger(since: str = "2026-09-01") -> dict:
    state = ledger()
    components = {
        "system_prompt": {"core": 5000},
        "skills": {"superpowers": 6000, "standalone": 1000},
        "deferred_tools": {"mcp:claude-in-chrome": 800, "builtin": 2000},
        "agents": {"searchfit-seo": 700},
    }
    state["preamble_parts"] = [{"measured": value, "components": components} for value in (80_000, 82_000, 84_000)]
    state["component_use"] = {"2026-10-30": {"superpowers": 3}, "2026-10-02": {"mcp:claude-in-chrome": 1}}
    state["component_use_since"] = since
    state["updated_at"] = "2026-11-01T09:00:00+00:00"
    return state


def test_measured_breakdown_replaces_the_estimate() -> None:
    text = "\n".join(render_usage_sections(parts_ledger(), 2000, BREAKDOWN))
    assert "### Claude Code preamble breakdown (measured, median of 3 sessions)" in text
    assert "| skills | `superpowers` | 6,000 |" in text
    assert "| deferred_tools | `builtin` | 2,000 |" in text
    assert "| tool schemas (unattributed) | | 66,500 |" in text
    assert "| **measured median** | | **82,000** |" in text
    assert "(unattributed) | 30,000 |" not in text


def test_estimate_is_labelled_when_no_session_was_measured() -> None:
    text = "\n".join(render_usage_sections(ledger(), 2000, BREAKDOWN))
    assert "### Claude Code preamble breakdown (estimate, bytes / 4)" in text
    assert "_No measured Claude Code sessions yet._" in text


def test_candidates_list_unused_plugins_and_servers_only() -> None:
    text = "\n".join(render_usage_sections(parts_ledger(), 2000, BREAKDOWN))
    section = text.split("### Preamble candidates", 1)[1].split("### Hygiene", 1)[0]
    assert "| `mcp:claude-in-chrome` | 800 | 0 |" in section
    assert "| `searchfit-seo` | 700 | 0 |" in section
    assert section.index("mcp:claude-in-chrome") < section.index("searchfit-seo")
    assert "superpowers" not in section and "standalone" not in section and "builtin" not in section
    assert "2026-11-01" in section and "nothing was changed" in section


def test_candidates_wait_for_30_days_of_tracked_calls() -> None:
    text = "\n".join(render_usage_sections(parts_ledger(since="2026-10-04"), 2000, BREAKDOWN))
    assert "_Tool calls tracked since 2026-10-04; candidates need 30 days._" in text
    ready = usage_summary(parts_ledger(since="2026-10-03"), 2000, BREAKDOWN)["attribution"]
    assert ready["candidates_ready"] is True and len(ready["candidates"]) == 2


def test_clamped_remainder_is_noted() -> None:
    state = parts_ledger()
    state["preamble_parts"] = [{"measured": 1000, "components": {"skills": {"superpowers": 3000}}}]
    text = "\n".join(render_usage_sections(state, 2000, BREAKDOWN))
    assert "| tool schemas (unattributed) | | 0 |" in text
    assert "remainder is shown as 0" in text


def test_attribution_json() -> None:
    attribution = usage_summary(parts_ledger(), 2000, BREAKDOWN)["attribution"]
    assert attribution["source"] == "measured"
    assert attribution["sessions"] == 3 and attribution["unattributed"] == 66_500
    assert attribution["window_end"] == "2026-11-01"
    assert attribution["candidates"][0] == {"key": "mcp:claude-in-chrome", "tokens": 800, "calls": 0}
    assert usage_summary(ledger(), 2000, BREAKDOWN)["attribution"]["source"] == "estimate"


def test_attribution_failure_shows_the_class_name(monkeypatch) -> None:
    import bin.usage_report as usage_report

    def broken(entries):
        raise RuntimeError("boom")

    monkeypatch.setattr(usage_report, "summarize_parts", broken)
    text = "\n".join(render_usage_sections(parts_ledger(), 2000, BREAKDOWN))
    assert text.count("_Unavailable: RuntimeError_") == 2
    assert "## Session Preamble" in text and "### Hygiene" in text
    assert usage_summary(parts_ledger(), 2000, BREAKDOWN)["attribution"] == {"error": "RuntimeError"}


def _outcomes(**totals: int) -> dict:
    return {"by_key": {f"claude|m|{kind}": {"total": n} for kind, n in totals.items()}}


def test_usage_report_lists_advisories_separately() -> None:
    base = "\n".join(render_usage_sections(ledger(), 2000, BREAKDOWN))
    out = _outcomes(advised_outline=3, advised_reread=1, advised_shell=2, advised_inline_python=0, outline_block=5)
    text = "\n".join(render_usage_sections(ledger(), 2000, BREAKDOWN, outcomes_state=out))
    assert "- Advisories (counted, never credited as saved): outline 3, reread 1, shell 2, inline python 0" in text
    assert "outline_block" not in text
    # Advisories never change any saved figure.
    assert [ln for ln in text.splitlines() if "saved" in ln and "Advisories" not in ln] == [
        ln for ln in base.splitlines() if "saved" in ln
    ]
    assert "Advisories" not in base
    summary = usage_summary(ledger(), 2000, BREAKDOWN, outcomes_state=out)
    assert summary["advisories"] == {"outline": 3, "reread": 1, "shell": 2, "inline_python": 0}
    assert summary["savings_share"] == usage_summary(ledger(), 2000, BREAKDOWN)["savings_share"]


def test_usage_report_advisories_include_repeats() -> None:
    out = {"by_key": {"claude|m|advised_outline": {"total": 2, "repeats": 3}}}
    text = "\n".join(render_usage_sections(ledger(), 2000, BREAKDOWN, outcomes_state=out))
    assert "outline 5, reread 0, shell 0, inline python 0" in text


def test_usage_report_estimates_forced_turn_overhead() -> None:
    state = dict(ledger())
    state["totals"] = {"claude|m": {"events": 10, "cache_read": 1_000_000}}
    out = {"by_key": {
        "claude|unknown|outline": {"total": 3, "repeats": 1},
        "claude|unknown|range_trim": {"total": 9},
        "claude|unknown|advised_outline": {"total": 7},
        "codex|unknown|shell_block": {"total": 2},
    }}
    # 4 Claude denials x (1,000,000 / 10 calls) x 0.1 = 40,000; Codex has no usage, so it adds denials only.
    summary = usage_summary(state, 50_000, BREAKDOWN, outcomes_state=out)
    assert summary["denial_overhead"] == {"denials": 6, "tokens": 40_000}
    text = "\n".join(render_usage_sections(state, 50_000, BREAKDOWN, outcomes_state=out))
    assert "- Forced-turn overhead (estimated, ledger lifetime): `6` denials, about `40,000` input-equivalent tokens" in text
    assert usage_summary(state, 50_000, BREAKDOWN)["denial_overhead"] == {}
    assert "Forced-turn overhead" not in "\n".join(render_usage_sections(state, 50_000, BREAKDOWN))


def test_mixed_claude_cli_and_desktop_preambles_are_reported_separately() -> None:
    state = ledger()
    cli_parts = {"system_prompt": {"core": 4000}, "skills": {"superpowers": 5000}, "deferred_tools": {"builtin": 2000}}
    desktop_parts = {
        "system_prompt": {"core": 9500},
        "skills": {"superpowers": 7500},
        "deferred_tools": {"builtin": 2000, "mcp:ccd_session": 300, "mcp:ccd_window": 200},
    }
    state["preamble"] = {"claude": [29_000, 30_000, 31_000, 88_000]}
    state["preamble_parts"] = [
        {"measured": 29_000, "components": cli_parts},
        {"measured": 30_000, "components": cli_parts},
        {"measured": 31_000, "components": cli_parts},
        {"measured": 88_000, "components": desktop_parts},
    ]
    text = "\n".join(render_usage_sections(state, 2000, PreambleBreakdown(components=(), memory_lines=10)))
    preamble_table = text.split("## Session Preamble", 1)[1].split("### ", 1)[0]
    assert "| `claude (cli)` | 3 | 30,000 | 31,000 | 31,000 |" in preamble_table
    assert "| `claude (desktop)` | 1 | 88,000 | 88,000 | 88,000 |" in preamble_table
    assert "| `claude` |" not in preamble_table
    assert "### Claude Code preamble breakdown — claude (cli) (measured, median of 3 sessions)" in text
    assert "### Claude Code preamble breakdown — claude (desktop) (measured, median of 1 sessions)" in text
    assert "| tool schemas (unattributed) | | 68,500 |" in text
    assert "Median claude (desktop) session preamble is 88,000 tokens" in text
    assert "Median claude session preamble" not in text
    assert "Median claude (cli) session preamble" not in text

    summary = usage_summary(state, 2000, PreambleBreakdown(components=(), memory_lines=10))
    assert summary["preamble"]["claude (cli)"] == {"sessions": 3, "median": 30_000, "p90": 31_000, "last": 31_000}
    assert summary["preamble"]["claude (desktop)"] == {"sessions": 1, "median": 88_000, "p90": 88_000, "last": 88_000}
    assert summary["preamble"]["claude"]["sessions"] == 4
    assert set(summary["attribution"]["cohorts"]) == {"claude (cli)", "claude (desktop)"}
    assert summary["attribution"]["cohorts"]["claude (desktop)"]["unattributed"] == 68_500
    assert len(summary["warnings"]) == 1


def test_desktop_only_claude_sessions_label_desktop_breakdown_and_no_cli_data() -> None:
    state = empty_usage_state()
    desktop_parts = {"deferred_tools": {"mcp:ccd_session": 250}}
    state["preamble"] = {"claude": [85_000]}
    state["preamble_parts"] = [{"measured": 85_000, "components": desktop_parts}]
    text = "\n".join(render_usage_sections(state, 0, PreambleBreakdown(components=(), memory_lines=0)))
    assert "| `claude (cli)` | no data | | | |" in text
    assert "| `claude (desktop)` | 1 | 85,000 | 85,000 | 85,000 |" in text
    assert "### Claude Code preamble breakdown — claude (desktop) (measured, median of 1 sessions)" in text


def test_codex_cohorts_and_antigravity_estimate_appear_in_usage_report() -> None:
    state = empty_usage_state()
    state["preamble"] = {"antigravity": [31_000], "codex": [16_000, 32_000]}
    state["codex_preamble_parts"] = [
        {"measured": 16_000, "cohort": CODEX_CLI_HARNESS, "components": {"system_prompt": {"core": 8000}}},
        {"measured": 32_000, "cohort": CODEX_DESKTOP_HARNESS, "components": {"other": {"app_context": 4000}}},
    ]
    bd = PreambleBreakdown(
        components=(),
        memory_lines=0,
        antigravity_components=(("user GEMINI.md / AGENTS.md", 1200), ("MCP tool schemas", 8000)),
    )
    text = "\n".join(render_usage_sections(state, 0, bd))
    assert "| `codex (cli)` | 1 | 16,000 | 16,000 | 16,000 |" in text
    assert "| `codex (desktop)` | 1 | 32,000 | 32,000 | 32,000 |" in text
    assert "### Codex preamble breakdown — codex (desktop) (measured, median of 1 sessions)" in text
    assert "### Antigravity preamble breakdown (estimate, bytes / 4)" in text
    summary = usage_summary(state, 0, bd)
    assert summary["preamble"][CODEX_DESKTOP_HARNESS]["median"] == 32_000
    assert summary["antigravity_breakdown"][0]["component"] == "user GEMINI.md / AGENTS.md"


def test_sunset_verdict_computes_net_gain_and_30_day_status() -> None:
    short_win = sunset_verdict(
        {"since": "2026-11-10", "until": "2026-11-13", "saved": 50_000, "real_input": 10_000_000},
        {"denials": 2, "tokens": 20_000},
    )
    assert short_win["window_days"] == 4
    assert short_win["net_saved"] == 30_000
    assert short_win["status"] == "collecting_30d_window"

    low_roi = sunset_verdict(
        {"since": "2026-10-01", "until": "2026-11-01", "saved": 100_000, "real_input": 1_000_000_000},
        {"denials": 5, "tokens": 120_000},
    )
    assert low_roi["window_days"] == 32
    assert low_roi["net_saved"] == -20_000
    assert low_roi["status"] == "sunset_candidate"

    good_roi = sunset_verdict(
        {"since": "2026-10-01", "until": "2026-11-01", "saved": 20_000_000, "real_input": 1_000_000_000},
        {"denials": 1, "tokens": 10_000},
    )
    assert good_roi["status"] == "net_positive"
    assert good_roi["net_share_pct"] > 0.5


def test_denial_overhead_and_sunset_verdict_ignore_legacy_v1_outcomes_schema() -> None:
    state = dict(ledger())
    state["totals"] = {"claude|m": {"events": 10, "cache_read": 1_000_000}}
    for legacy_ver in (1, 2):
        legacy_out = {
            "schema_version": legacy_ver,
            "by_key": {
                "antigravity|unknown|outline": {"total": 50},
                "codex|m|reread_block": {"total": 5},
                "claude|m|advised_shell": {"total": 20},
            },
        }
        summary = usage_summary(state, 50_000, BREAKDOWN, outcomes_state=legacy_out)
        assert summary["advisories"] == {}
        assert summary["denial_overhead"] == {}
        assert summary["sunset_verdict"]["net_saved"] > 0

    v3_out = {
        "schema_version": 3,
        "by_key": {"claude|m|outline": {"total": 1, "applied": 1, "targeted_followup": 1}},
    }
    summary_v3 = usage_summary(state, 50_000, BREAKDOWN, outcomes_state=v3_out)
    assert summary_v3["denial_overhead"] == {"denials": 1, "tokens": 10_000}

