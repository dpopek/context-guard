"""Unit and integration tests for Context-Guard Token Savings Telemetry & IDE Status Bar."""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from hooks.pre_tool_use import evaluate_hook
from hooks.telemetry import load_telemetry_stats


def test_telemetry_accumulates_mcp_outline_and_range_trim_savings(tmp_path: Path) -> None:
    mcp_dir = tmp_path / ".system_generated" / "steps" / "10"
    mcp_dir.mkdir(parents=True)
    mcp_out = mcp_dir / "output.txt"
    mcp_out.write_text(
        json.dumps(
            {
                "file_name": "mod.py",
                "file_path": "pkg/mod.py",
                "content": "\n".join(f"def fn_{i}() -> int:\n    return {i}\n" for i in range(90)),
            }
        )
        + (" " * 16_000),
        encoding="utf-8",
    )
    big_py = tmp_path / "module.py"
    body = "".join(f"    step_{j} = x + {j}\n" for j in range(9))
    lines = [f"def func_{i}(x: int) -> int:\n{body}    return x + {i}\n" for i in range(20)]
    big_py.write_text("".join(lines), encoding="utf-8")
    state_dir = tmp_path / "state"
    stats_file = state_dir / "telemetry_stats.json"

    # 1. Large MCP output.txt -> intercepted by AUTO-OUTLINE
    r1 = evaluate_hook(
        {"session_id": "t1", "tool_name": "Read", "tool_input": {"file_path": str(mcp_out)}},
        state_dir=str(state_dir),
        cli_harness="cursor",
    )
    assert r1["hookSpecificOutput"]["permissionDecision"] == "deny"
    s1 = load_telemetry_stats(stats_file)
    assert s1["events"]["outlines"] == 1
    assert s1["saved_tokens"] > 0
    assert s1["reduction_pct"] > 50.0
    installed_ts = s1["installed_at"]

    # 2. Targeted source read lines 1..30 -> allowed_reads (increases baseline, saved unchanged)
    r2 = evaluate_hook(
        {
            "session_id": "t1",
            "tool_name": "Read",
            "tool_input": {"file_path": str(big_py), "offset": 1, "limit": 30},
        },
        state_dir=str(state_dir),
        cli_harness="cursor",
    )
    assert r2 == {}
    s2 = load_telemetry_stats(stats_file)
    assert s2["events"]["allowed_reads"] == 1
    assert s2["baseline_bytes"] > s1["baseline_bytes"]
    assert s2["installed_at"] == installed_ts

    # 3. Partially overlapping read lines 20..50 -> ranges_trimmed (lines 20..30 saved)
    r3 = evaluate_hook(
        {
            "session_id": "t1",
            "tool_name": "Read",
            "tool_input": {"file_path": str(big_py), "offset": 20, "limit": 31},
        },
        state_dir=str(state_dir),
        cli_harness="cursor",
    )
    assert r3["hookSpecificOutput"]["permissionDecision"] == "allow"
    s3 = load_telemetry_stats(stats_file)
    assert s3["events"]["ranges_trimmed"] == 1
    assert s3["saved_bytes"] > s2["saved_bytes"]
    assert s3["by_harness"]["cursor"]["hits"] == 2


import json
from bin.cg_status import (
    format_compact_tokens,
    render_claude_hud,
    render_markdown_report,
    render_short_status,
)
from bin.install_harnesses import install_all, uninstall_all

VERSION = json.loads((Path(__file__).resolve().parent.parent / "plugin.json").read_text(encoding="utf-8"))["version"]


def test_cg_status_formats_short_claude_hud_and_markdown() -> None:
    assert format_compact_tokens(950) == "950"
    assert format_compact_tokens(14250) == "14.2k"
    assert format_compact_tokens(1500000) == "1.5M"

    stats = {
        "installed_at": "2026-10-29T06:00:00+00:00",
        "baseline_tokens": 100000,
        "saved_tokens": 68400,
        "reduction_pct": 68.4,
        "events": {
            "allowed_reads": 10,
            "outlines": 5,
            "rereads_blocked": 4,
            "ranges_trimmed": 2,
            "cli_rewrites": 3,
            "mcp_guards": 1,
        },
        "by_harness": {
            "antigravity": {"baseline_tokens": 50000, "saved_tokens": 35000, "hits": 8},
            "claude": {"baseline_tokens": 50000, "saved_tokens": 33400, "hits": 7},
        },
    }
    assert render_short_status(stats) == "CG: -68.4k tok (-68.4%)"

    hud = render_claude_hud(
        {"model": {"display_name": "Claude Opus"}, "context_window": {"used_percentage": 22}},
        stats,
    )
    assert "Claude Opus" in hud
    assert "22%" in hud
    assert "CG: -68.4k tok (-68.4%)" in hud

    # Empty Claude stdin fallback
    hud_empty = render_claude_hud({}, stats)
    assert "CG: -68.4k tok (-68.4%)" in hud_empty

    md = render_markdown_report(stats)
    assert f"Context-Guard v{VERSION} " in md
    assert "-68.4%" in md
    assert "antigravity" in md


def test_installer_wires_claude_statusline_and_ide_extensions(tmp_path: Path) -> None:
    claude_cfg = tmp_path / "settings.json"
    cursor_cfg = tmp_path / "cursor_hooks.json"
    codex_cfg = tmp_path / "codex_hooks.json"
    codex_toml = tmp_path / "config.toml"
    cursor_ext_dir = tmp_path / "cursor_extensions"
    agy_ext_dir = tmp_path / "agy_extensions"
    agy_ide_ext_dir = tmp_path / "agy_ide_extensions"
    cursor_ext_dir.mkdir()
    agy_ext_dir.mkdir()
    agy_ide_ext_dir.mkdir()

    (cursor_ext_dir / "extensions.json").write_text(
        '[{"identifier":{"id":"ms-python.python"},"version":"1.0.0"}]', encoding="utf-8"
    )
    (agy_ext_dir / "extensions.json").write_text("[]", encoding="utf-8")
    (agy_ide_ext_dir / "extensions.json").write_text("[]", encoding="utf-8")
    claude_cfg.write_text(
        '{"model": "opus", "statusLine": {"type": "command", "command": "old_hud.sh"}, "hooks": {}}',
        encoding="utf-8",
    )
    cursor_cfg.write_text('{"version": 1, "hooks": {}}', encoding="utf-8")
    codex_cfg.write_text('{"hooks": {}}', encoding="utf-8")
    codex_toml.write_text('model = "gpt-5"\n', encoding="utf-8")

    plugin_root = Path(__file__).resolve().parent.parent
    import time

    before_ms = int(time.time() * 1000)
    install_all(
        plugin_root,
        claude_cfg,
        cursor_cfg,
        codex_cfg,
        codex_toml,
        cursor_extensions_dir=cursor_ext_dir,
        antigravity_extensions_dir=agy_ext_dir,
        antigravity_ide_extensions_dir=agy_ide_ext_dir,
    )
    after_ms = int(time.time() * 1000)

    claude_data = json.loads(claude_cfg.read_text(encoding="utf-8"))
    assert "cg_status.py" in claude_data["statusLine"]["command"]
    assert "--claude-hud" in claude_data["statusLine"]["command"]

    for ext_dir in (cursor_ext_dir, agy_ext_dir, agy_ide_ext_dir):
        ext_list = json.loads((ext_dir / "extensions.json").read_text(encoding="utf-8"))
        cg_exts = [
            e
            for e in ext_list
            if e.get("identifier", {}).get("id") == "advox.context-guard-statusbar"
        ]
        assert len(cg_exts) == 1
        assert before_ms <= cg_exts[0]["metadata"]["installedTimestamp"] <= after_ms
        ext_pkg_dir = ext_dir / f"advox.context-guard-statusbar-{VERSION}"
        assert (ext_pkg_dir / "extension.js").is_file()
        assert (ext_pkg_dir / "icon.svg").is_file()
        assert (ext_pkg_dir / "README.md").is_file()
        assert "Context-Guard" in (ext_pkg_dir / "README.md").read_text(encoding="utf-8")
        assert (ext_pkg_dir / "CHANGELOG.md").is_file()
        pkg_manifest = json.loads((ext_pkg_dir / "package.json").read_text(encoding="utf-8"))
        assert before_ms <= pkg_manifest["__metadata"]["installedTimestamp"] <= after_ms
        views = pkg_manifest.get("contributes", {}).get("views", {})
        assert "contextGuard" in views
        assert "explorer" in views
        ext_js = (ext_pkg_dir / "extension.js").read_text(encoding="utf-8")
        assert "registerWebviewViewProvider" in ext_js
        assert "contextGuard.sidebarView" in ext_js
        assert "contextGuard.explorerView" in ext_js

    # Second run is idempotent (still 1 entry)
    install_all(
        plugin_root,
        claude_cfg,
        cursor_cfg,
        codex_cfg,
        codex_toml,
        cursor_extensions_dir=cursor_ext_dir,
        antigravity_extensions_dir=agy_ext_dir,
        antigravity_ide_extensions_dir=agy_ide_ext_dir,
    )
    ext_list_2 = json.loads((cursor_ext_dir / "extensions.json").read_text(encoding="utf-8"))
    assert (
        len(
            [
                e
                for e in ext_list_2
                if e.get("identifier", {}).get("id") == "advox.context-guard-statusbar"
            ]
        )
        == 1
    )

    # Uninstall restores previous statusLine and removes extension entry while keeping ms-python.python
    uninstall_all(
        claude_cfg,
        cursor_cfg,
        codex_cfg,
        codex_toml,
        cursor_extensions_dir=cursor_ext_dir,
        antigravity_extensions_dir=agy_ext_dir,
        antigravity_ide_extensions_dir=agy_ide_ext_dir,
    )
    claude_after = json.loads(claude_cfg.read_text(encoding="utf-8"))
    assert claude_after.get("statusLine") == {"type": "command", "command": "old_hud.sh"}
    assert "_context_guard_backup_statusLine" not in claude_after
    ext_after = json.loads((cursor_ext_dir / "extensions.json").read_text(encoding="utf-8"))
    assert len(ext_after) == 1
    assert ext_after[0]["identifier"]["id"] == "ms-python.python"
    agy_ide_after = json.loads((agy_ide_ext_dir / "extensions.json").read_text(encoding="utf-8"))
    assert agy_ide_after == []


def test_telemetry_classifies_twg_inline_as_outlines_and_credits_path_redirect(tmp_path: Path) -> None:
    from hooks.telemetry import record_file_read_outcome

    raw_file = tmp_path / "stdout.compact.json"
    raw_file.write_text("x" * 20000, encoding="utf-8")
    unwrapped = tmp_path / "stdout_formatted.json"
    unwrapped.write_text("y" * 8000, encoding="utf-8")
    stats_file = tmp_path / "stats.json"

    record_file_read_outcome(
        harness="antigravity",
        raw_path=str(raw_file),
        start_line=1,
        end_line=-1,
        decision={
            "decision": "deny",
            "reason": "CONTEXT-GUARD TWG INLINE READ: stdout.compact.json is a 1-line JSON dump...",
        },
        intervention="outline",
        stats_path=stats_file,
    )
    st1 = load_telemetry_stats(stats_file)
    assert st1["events"]["outlines"] == 1
    assert st1["events"]["rereads_blocked"] == 0

    record_file_read_outcome(
        harness="antigravity",
        raw_path=str(raw_file),
        start_line=1,
        end_line=-1,
        decision={"decision": "allow", "overwrite": {"Path": str(unwrapped)}},
        intervention=None,
        stats_path=stats_file,
    )
    st2 = load_telemetry_stats(stats_file)
    assert st2["events"]["ranges_trimmed"] == 1
    assert st2["saved_bytes"] > st1["saved_bytes"]


def test_block_gauge_and_svg_donut_sidebar_rendering() -> None:
    from bin.cg_status import format_block_gauge, render_claude_hud

    assert format_block_gauge(0.0) == "▱▱▱▱▱"
    assert format_block_gauge(21.6) == "▰▱▱▱▱"
    assert format_block_gauge(42.0) == "▰▰▱▱▱"
    assert format_block_gauge(68.4) == "▰▰▰▱▱"
    assert format_block_gauge(95.0) == "▰▰▰▰▰"

    stats = {
        "installed_at": "2026-10-29T06:00:00+00:00",
        "baseline_tokens": 100000,
        "saved_tokens": 68400,
        "reduction_pct": 68.4,
        "events": {"outlines": 5, "rereads_blocked": 4},
    }
    hud = render_claude_hud({"model": {"display_name": "Sonnet 4.6"}}, stats)
    assert "▰▰▰▱▱" in hud

    ext_js = (
        Path(__file__).resolve().parent.parent / "vscode-extension" / "extension.js"
    ).read_text(encoding="utf-8")
    assert "function formatBlockGauge(" in ext_js
    assert "function estimateCostUsd(" in ext_js
    assert "function escapeHtml(" in ext_js
    assert "stroke-dasharray" in ext_js
    assert "stroke-dashoffset" in ext_js
    assert "command:contextGuard.showReport" in ext_js
    assert "function formatStatusBarIdleText(" in ext_js
    assert "function formatStatusBarPulseText(" in ext_js
    assert "function formatContextWindows(" in ext_js


def test_last_event_tracking_and_compact_toolbar_formatting(tmp_path: Path) -> None:
    import subprocess
    from hooks.telemetry import record_telemetry_event

    stats_file = tmp_path / "stats.json"
    record_telemetry_event(
        harness="antigravity",
        event_kind="outlines",
        baseline_bytes=20000,
        saved_bytes=16800,
        stats_path=stats_file,
    )
    st = load_telemetry_stats(stats_file)
    assert "last_event" in st
    assert st["last_event"]["kind"] == "outlines"
    assert st["last_event"]["saved_tokens"] == 4200
    assert st["last_event"]["harness"] == "antigravity"

    hud = render_claude_hud(
        {"model": {"display_name": "Claude Opus"}, "context_window": {"used_percentage": 34}},
        st,
    )
    assert " · " in hud
    assert "[Claude Opus] · Ctx 34% · 🛡️ CG: -4.2k tok (-84.0%) ▰▰▰▰▱" == hud

    md = render_markdown_report(st)
    assert "Context Windows Saved (200k)" in md

    ext_path = Path(__file__).resolve().parent.parent / "vscode-extension" / "extension.js"
    node_script = (
        "const Module = require('module');"
        "const orig = Module._load;"
        "Module._load = (req, parent, isMain) => req === 'vscode' ? {} : orig(req, parent, isMain);"
        f"const ext = require({json.dumps(str(ext_path))});"
        "console.log(JSON.stringify({"
        "  zero: ext.formatStatusBarIdleText(null),"
        "  idle: ext.formatStatusBarIdleText({saved_tokens: 142500, reduction_pct: 68.4}),"
        "  pulse: ext.formatStatusBarPulseText({saved_tokens: 146700, reduction_pct: 68.4}, 4200, 'outlines'),"
        "  windows: ext.formatContextWindows(620000)"
        "}));"
    )
    proc = subprocess.run(
        ["node", "-e", node_script], capture_output=True, text=True, encoding="utf-8", check=True
    )
    js_out = json.loads(proc.stdout.strip())
    assert js_out["zero"] == "$(shield) 0 tok · 0%"
    assert js_out["idle"] == "$(shield) -142.5k · 68%"
    assert js_out["pulse"] == "$(zap) -4.2k (Outline) · 68%"
    assert js_out["windows"] == "3.1"






def _write_large_mcp_output(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "file_name": "mod.py",
                "file_path": "pkg/mod.py",
                "content": "\n".join(f"def fn_{i}() -> int:\n    return {i}\n" for i in range(90)),
            }
        )
        + (" " * 16_000),
        encoding="utf-8",
    )


def test_corrupt_ledger_fields_never_flip_a_deny_into_allow(tmp_path: Path) -> None:
    """Non-numeric ledger fields used to raise ValueError inside telemetry, which evaluate_hook turned into `{}` (allow)."""
    mcp_out = tmp_path / ".system_generated" / "steps" / "1" / "output.txt"
    _write_large_mcp_output(mcp_out)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    stats_file = state_dir / "telemetry_stats.json"
    stats_file.write_text(
        '{"baseline_bytes": "abc", "saved_bytes": null, "reduction_pct": "n/a", '
        '"events": {"outlines": "x"}, "by_harness": {"claude": {"hits": null}}}',
        encoding="utf-8",
    )

    res = evaluate_hook(
        {"session_id": "t-corrupt", "tool_name": "Read", "tool_input": {"file_path": str(mcp_out)}},
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert res["hookSpecificOutput"]["permissionDecision"] == "deny"
    st = load_telemetry_stats(stats_file)
    assert st["events"]["outlines"] == 1
    assert st["saved_tokens"] > 0
    assert st["by_harness"]["claude"]["hits"] == 1


def test_unexpected_telemetry_failure_is_logged_and_leaves_the_decision_intact(tmp_path: Path, monkeypatch, capsys) -> None:
    """Telemetry is best-effort: an exception inside it goes to stderr and never reaches the guard decision."""
    import hooks.telemetry as telemetry_mod

    mcp_out = tmp_path / ".system_generated" / "steps" / "2" / "output.txt"
    _write_large_mcp_output(mcp_out)
    state_dir = tmp_path / "state"

    def _broken_clock() -> str:
        raise RuntimeError("clock unavailable")

    monkeypatch.setattr(telemetry_mod, "now_iso", _broken_clock)
    res = evaluate_hook(
        {"session_id": "t-boom", "tool_name": "Read", "tool_input": {"file_path": str(mcp_out)}},
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert res["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "clock unavailable" in capsys.readouterr().err


def test_unparseable_ledger_is_quarantined_not_overwritten(tmp_path: Path) -> None:
    """A ledger that is not JSON is moved aside with its content intact; a fresh ledger takes the event."""
    from hooks.telemetry import record_telemetry_event

    stats_file = tmp_path / "stats.json"
    stats_file.write_text("{not json", encoding="utf-8")

    record_telemetry_event("claude", "outlines", 4000, 3600, stats_path=stats_file)

    quarantined = sorted(tmp_path.glob("stats.json.corrupt-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_text(encoding="utf-8") == "{not json"
    assert load_telemetry_stats(stats_file)["events"]["outlines"] == 1


def test_telemetry_credits_transcript_jsonl_auto_outline(
    tmp_path: Path,
) -> None:
    tr_dir = tmp_path / ".system_generated" / "logs"
    tr_dir.mkdir(parents=True)
    tr = tr_dir / "transcript_full.jsonl"
    tr.write_text(
        "".join(
            json.dumps({"step_index": i, "type": "PLANNER_RESPONSE", "content": f"step {i} " * 80}) + "\n"
            for i in range(40)
        ),
        encoding="utf-8",
    )
    state_dir = tmp_path / "state_tr_tel"
    stats_file = state_dir / "telemetry_stats.json"

    res = evaluate_hook(
        {
            "session_id": "claude-tel-1",
            "tool_name": "Read",
            "tool_input": {"file_path": str(tr)},
        },
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert res["hookSpecificOutput"]["permissionDecision"] == "deny"
    st = load_telemetry_stats(stats_file)
    assert st["events"]["outlines"] == 1
    assert st["by_harness"]["claude"]["hits"] == 1
    assert st["saved_bytes"] > 0
    assert st["saved_tokens"] > 0


def test_read_json_object_or_quarantine_moves_non_object_aside(tmp_path: Path, capsys) -> None:
    from hooks.telemetry import read_json_object_or_quarantine

    target = tmp_path / "ledger.json"
    assert read_json_object_or_quarantine(target) is None
    target.write_text("[1, 2]", encoding="utf-8")
    assert read_json_object_or_quarantine(target) is None
    assert not target.exists()
    quarantined = [p for p in tmp_path.iterdir() if p.name.startswith("ledger.json.corrupt-")]
    assert len(quarantined) == 1
    assert "was not a JSON object" in capsys.readouterr().err
    target.write_text('{"a": 1}', encoding="utf-8")
    assert read_json_object_or_quarantine(target) == {"a": 1}


def test_write_json_atomic_writes_indented_json_and_leaves_no_temp_files(tmp_path: Path) -> None:
    from hooks.telemetry import write_json_atomic

    target = tmp_path / "out.json"
    write_json_atomic(target, {"b": 2, "a": [1]}, prefix=".out.")
    assert target.read_text(encoding="utf-8") == '{\n  "b": 2,\n  "a": [\n    1\n  ]\n}\n'
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.json"]


def _outcomes_ledger(rows: dict[str, dict[str, int]], updated_at: str | None = "2026-10-30T12:00:00Z") -> dict:
    import hooks.outcomes as outcomes

    ledger = outcomes.default_outcomes_dict()
    ledger["updated_at"] = updated_at
    for key, counts in rows.items():
        row = {k: 0 for k in outcomes.ROW_KEYS}
        row.update(counts)
        ledger["by_key"][key] = row
    return ledger


def test_render_outcomes_report_rows_percentages_and_footer() -> None:
    from bin.cg_status import render_outcomes_report

    ledger = _outcomes_ledger(
        {
            "claude|claude-fable-5-1|outline": {
                "total": 10, "applied": 10, "targeted_followup": 6, "full_bypass": 2, "shell_bypass": 1,
            },
            "antigravity|unknown|range_trim": {"total": 4, "applied": 4},
            "antigravity|unknown|cli_rewrite": {"total": 2, "applied": 2},
            "claude|claude-fable-5-1|outline_pull": {"total": 0},
        }
    )
    report = render_outcomes_report(ledger)
    lines = report.splitlines()
    assert lines[0] == "# 🛡️ Context-Guard Intervention Outcomes"
    assert (
        "| Harness | Model | Kind | Interventions | Targeted follow-up | Full bypass | Shell bypass |"
    ) in lines
    assert "|---|---|---|---:|---:|---:|---:|" in lines
    assert "| antigravity | unknown | cli_rewrite | 2 | — | — | — |" in lines
    assert "| antigravity | unknown | range_trim | 4 | — | — | — |" in lines
    assert "| claude | claude-fable-5-1 | outline | 10 | 6 (60%) | 2 (20%) | 1 (10%) |" in lines
    assert "| claude | claude-fable-5-1 | outline_pull | 0 | 0 (n/a) | 0 (n/a) | 0 (n/a) |" in lines
    assert lines.index("| antigravity | unknown | cli_rewrite | 2 | — | — | — |") < lines.index(
        "| claude | claude-fable-5-1 | outline | 10 | 6 (60%) | 2 (20%) | 1 (10%) |"
    )
    assert lines[-1] == "_Schema: v3 · updated: 2026-10-30T12:00:00Z_"
    assert report.endswith("\n")


def test_render_outcomes_report_empty_ledger() -> None:
    from bin.cg_status import render_outcomes_report

    report = render_outcomes_report(_outcomes_ledger({}, updated_at=None))
    assert "No interventions recorded yet." in report
    assert "_Schema: v3 · updated: never_" in report


def test_cg_status_outcomes_flag_reads_ledger_path(tmp_path, capsys) -> None:
    from bin.cg_status import main as cg_status_main

    ledger = tmp_path / "outcomes.json"
    ledger.write_text(
        json.dumps(_outcomes_ledger({"claude|m|outline": {"total": 1, "applied": 1, "targeted_followup": 1}})),
        encoding="utf-8",
    )
    assert cg_status_main(["--outcomes", "--outcomes-path", str(ledger)]) == 0
    out = capsys.readouterr().out
    assert "| claude | m | outline | 1 | 1 (100%) | 0 (0%) | 0 (0%) |" in out


def test_cli_rewrite_is_counted_without_claiming_bytes(tmp_path: Path) -> None:
    # Output size of the rewritten command is unknown at PreToolUse: count it on Antigravity, credit no bytes.
    state_dir = tmp_path / "state"
    assert (
        evaluate_hook(
            {"session_id": "cli-1", "tool_name": "Bash", "tool_input": {"command": "pytest tests/"}},
            state_dir=str(state_dir),
            cli_harness="claude",
        )
        == {}
    )
    res = evaluate_hook(
        {
            "conversationId": "cli-ag-1",
            "stepIdx": 1,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest tests/"}},
        },
        state_dir=str(state_dir),
    )

    assert "--tb=short" in res["overwrite"]["CommandLine"]
    stats = load_telemetry_stats(state_dir / "telemetry_stats.json")
    assert stats["events"]["cli_rewrites"] == 1
    assert stats["baseline_bytes"] == 0
    assert stats["saved_bytes"] == 0
    assert stats["by_harness"]["antigravity"]["hits"] == 0
    assert "last_event" not in stats


def test_read_telemetry_classifies_by_intervention_kind_not_reason_wording(tmp_path: Path) -> None:
    from hooks.telemetry import record_file_read_outcome

    target = tmp_path / "big.py"
    target.write_text("x = 1\n" * 400, encoding="utf-8")
    stats_file = tmp_path / "stats.json"

    record_file_read_outcome(
        harness="claude",
        raw_path=str(target),
        start_line=1,
        end_line=-1,
        decision={"decision": "deny", "reason": "reworded outline message"},
        intervention="outline",
        stats_path=stats_file,
    )
    record_file_read_outcome(
        harness="claude",
        raw_path=str(target),
        start_line=1,
        end_line=40,
        decision={"decision": "allow", "overwrite": {"StartLine": 21, "EndLine": 40}},
        intervention="range_trim",
        stats_path=stats_file,
    )
    record_file_read_outcome(
        harness="claude",
        raw_path=str(target),
        start_line=1,
        end_line=40,
        decision={"decision": "allow"},
        intervention=None,
        stats_path=stats_file,
    )

    stats = load_telemetry_stats(stats_file)
    assert stats["events"]["outlines"] == 1
    assert stats["events"]["ranges_trimmed"] == 1
    assert stats["events"]["allowed_reads"] == 1


def test_markdown_report_tolerates_legacy_credit_reversals() -> None:
    from hooks.telemetry import load_telemetry_stats

    stats = load_telemetry_stats(Path("/nonexistent/stats.json"))
    stats["events"]["credit_reversals"] = 3
    assert "| Credits Taken Back After Bypass (`credit_reversals`) | 3 |" in render_markdown_report(stats)


def test_status_line_failure_says_unavailable_and_reports_why(monkeypatch, capsys) -> None:
    import bin.cg_status as cg_status

    def _broken(_path):
        raise ValueError("stats unreadable")

    monkeypatch.setattr(cg_status, "load_telemetry_stats", _broken)
    assert cg_status.main(["--short"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "CG: n/a\n"
    assert captured.err.startswith("context-guard: status line failed: ValueError: stats unreadable")


def test_cost_estimate_uses_current_input_rate_and_is_labelled_approximate() -> None:
    import subprocess

    ext_path = Path(__file__).resolve().parent.parent / "vscode-extension" / "extension.js"
    node_script = (
        "const Module = require('module');"
        "const orig = Module._load;"
        "Module._load = (req, parent, isMain) => req === 'vscode' ? {} : orig(req, parent, isMain);"
        f"const ext = require({json.dumps(str(ext_path))});"
        "console.log(JSON.stringify({"
        "  million: ext.estimateCostUsd(1000000),"
        "  note: ext.COST_BASIS_NOTE,"
        "  sidebar: ext.renderSidebarHtml({saved_tokens: 2500000, baseline_tokens: 4000000, reduction_pct: 62.5})"
        "}));"
    )
    proc = subprocess.run(
        ["node", "-e", node_script], capture_output=True, text=True, encoding="utf-8", check=True
    )
    out = json.loads(proc.stdout.strip())

    assert out["million"] == "4.00"
    assert "approx" in out["note"].lower()
    assert "$4/M" in out["note"]
    assert "≈$10.00" in out["sidebar"]
    assert "approx" in out["sidebar"].lower()
    assert f"v{VERSION}" in out["sidebar"]

    ext_js = ext_path.read_text(encoding="utf-8")
    assert "~$${costUsd}" not in ext_js
    assert "Est. API" not in ext_js
    assert ext_js.count("COST_BASIS_NOTE") >= 4


