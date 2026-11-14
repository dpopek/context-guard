"""Tests for signed daily ledger, common-horizon savings_share, UTC day parser, model precedence, and skill hygiene."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from bin.cg_status import render_doctor_report, run_doctor
from bin.install_harnesses import install_ide_extension
from bin.token_usage import (
    empty_usage_state,
    fold_jsonl_file,
    parse_antigravity_record,
    parse_utc_day,
)
from bin.usage_report import (
    active_claude_plugin_skill_files,
    find_duplicate_skills,
    savings_share,
)
from hooks.telemetry import (
    load_telemetry_stats,
    record_telemetry_event,
)


def test_cross_day_daily_sum_invariant_and_common_window(
    tmp_path: Path,
) -> None:
    stats_path = tmp_path / "stats.json"
    record_telemetry_event(
        "claude", "outlines", 5000, 4000, stats_path=stats_path, target_day="2026-11-08"
    )
    record_telemetry_event(
        "claude", "credit_reversals", -5000, -4000, stats_path=stats_path, target_day="2026-11-08"
    )
    stats = load_telemetry_stats(stats_path)
    assert sum(v["saved_bytes"] for v in stats["by_day"].values()) == stats["saved_bytes"] == 0
    assert stats["daily_ledger_started_at"] == "2026-11-08"

    record_telemetry_event(
        "claude", "outlines", 60000, 48000, stats_path=stats_path, target_day="2026-11-09"
    )
    record_telemetry_event(
        "claude", "outlines", 25000, 20000, stats_path=stats_path, target_day="2026-11-10"
    )
    stats2 = load_telemetry_stats(stats_path)
    assert sum(v["saved_bytes"] for v in stats2["by_day"].values()) == stats2["saved_bytes"] == 68000

    usage_state = {
        "started_at": "2026-11-09T18:11:00Z",
        "saved_tokens_at_start": 12000,
        "by_day": {
            "2026-11-09": {"claude": {"input": 40000, "cache_read": 8000, "cache_write": 0}}
        },
    }
    share = savings_share(usage_state, saved_tokens_now=17000, stats_state=stats2)
    assert share == {
        "since": "2026-11-09",
        "until": "2026-11-09",
        "saved": 12000,
        "real_input": 48000,
        "share_pct": 20.0,
    }


def test_day_parser_and_antigravity_model_pin_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert parse_utc_day("2026-11-09T00:30:00+0200") == "2026-11-08"
    assert parse_utc_day("2026-11-09T00:30:00+02:00") == "2026-11-08"
    assert parse_utc_day("2026-11-08T23:30:00-0500") == "2026-11-09"
    assert parse_utc_day("2026-11-09T12:00:00.123456789Z") == "2026-11-09"
    assert parse_utc_day("2026-11-09") == "2026-11-09"
    assert parse_utc_day("bad") == ""

    rec = {
        "type": "PLANNER_RESPONSE",
        "model": "auto",
        "modelName": "gemini-2.5-pro",
        "created_at": "bad",
        "createdAt": "2026-11-09T01:00:00+02:00",
        "input_tokens": 100,
        "output_tokens": 20,
    }
    ev = parse_antigravity_record(rec, "unknown")
    assert ev is not None
    assert ev.model == "gemini-2.5-pro"
    assert ev.day == "2026-11-08"

    transcript = tmp_path / "transcript_full.jsonl"
    transcript.write_text(
        json.dumps(rec)
        + "\n"
        + json.dumps(
            {
                "type": "PLANNER_RESPONSE",
                "model": "unknown",
                "created_at": "2026-11-09T12:00:00Z",
                "input_tokens": 50,
                "output_tokens": 10,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    # Without pin: record 1 sets cursor["model"] = "gemini-2.5-pro", inherited by record 2
    monkeypatch.setattr("bin.token_usage.pinned_model", lambda _h: None)
    state_unpinned = empty_usage_state()
    fold_jsonl_file(state_unpinned, "antigravity", transcript, budget=10000)
    assert state_unpinned["totals"]["antigravity|gemini-2.5-pro"]["events"] == 2

    # With pin: pinned_model("antigravity") overrides record_model and cursor["model"]
    monkeypatch.setattr("bin.token_usage.pinned_model", lambda _h: "claude-opus-4-6")
    state_pinned = empty_usage_state()
    fold_jsonl_file(state_pinned, "antigravity", transcript, budget=10000)
    assert state_pinned["totals"]["antigravity|claude-opus-4-6"]["events"] == 2


def test_find_duplicate_skills_uses_active_plugin_version_and_ignores_old_cache(
    tmp_path: Path,
) -> None:
    user_sk = tmp_path / ".claude" / "skills" / "demo" / "SKILL.md"
    old_sk = (
        tmp_path
        / ".claude"
        / "plugins"
        / "cache"
        / "mkt"
        / "plug"
        / "1.0.0"
        / "skills"
        / "demo"
        / "SKILL.md"
    )
    active_dir = tmp_path / ".claude" / "plugins" / "cache" / "mkt" / "plug" / "1.2.3"
    active_sk = active_dir / "skills" / "demo" / "SKILL.md"
    for p in (user_sk, old_sk, active_sk):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("---\nname: demo\ndescription: test\n---\n", encoding="utf-8")
    installed_json = tmp_path / ".claude" / "plugins" / "installed_plugins.json"
    installed_json.write_text(
        json.dumps({"plugins": {"plug@mkt": [{"installPath": str(active_dir)}]}}),
        encoding="utf-8",
    )
    active_files = active_claude_plugin_skill_files(tmp_path)
    assert active_files == [active_sk]

    dups = find_duplicate_skills(tmp_path)
    assert len(dups) == 1 and dups[0][0] == "demo"
    dup_paths = [str(p) for p in dups[0][1]]
    assert str(active_sk) in dup_paths and str(old_sk) not in dup_paths

    doc = run_doctor(plugin_root=tmp_path)
    assert "skill_hygiene" in doc
    assert doc["skill_hygiene"]["ok"] is True
    rendered = render_doctor_report(doc)
    assert "Skill hygiene" in rendered


def _rel_luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0, int(h[4:6], 16) / 255.0)
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in (r, g, b)]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _contrast_ratio(fg_hex: str, bg_hex: str) -> float:
    l1, l2 = _rel_luminance(fg_hex), _rel_luminance(bg_hex)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def test_logo_wcag_contrast_icon_png_and_context_audit_skill(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    logo_svg = (root / "assets" / "logo.svg").read_text(encoding="utf-8")
    assert "#0D9488" in logo_svg and "#0284C7" in logo_svg and "#0F172A" in logo_svg
    # Verify WCAG 2.1 SC 1.4.11 >= 3.0:1 non-text contrast on #FFFFFF and #0D1117
    assert _contrast_ratio("#0D9488", "#FFFFFF") >= 3.0
    assert _contrast_ratio("#0284C7", "#FFFFFF") >= 3.0
    assert _contrast_ratio("#0D9488", "#0D1117") >= 3.0
    assert _contrast_ratio("#0284C7", "#0D1117") >= 3.0
    # Verify interior strokes (#34D399, #38BDF8) against shield interior (#0F172A)
    assert _contrast_ratio("#34D399", "#0F172A") >= 7.0
    assert _contrast_ratio("#38BDF8", "#0F172A") >= 7.0

    icon_png = (root / "vscode-extension" / "icon.png").read_bytes()
    assert icon_png[:8] == b"\x89PNG\r\n\x1a\n"
    w, h = struct.unpack(">II", icon_png[16:24])
    assert (w, h) == (128, 128)

    exts_dir = tmp_path / "exts"
    exts_dir.mkdir(parents=True, exist_ok=True)
    status = install_ide_extension(root, extensions_dir=exts_dir)
    assert status == "updated"
    installed_dirs = list(exts_dir.glob("advox.context-guard-statusbar-*"))
    assert len(installed_dirs) == 1
    assert (installed_dirs[0] / "icon.png").is_file()
    assert (installed_dirs[0] / "icon.svg").is_file()

    skill_md = root / "skills" / "context-audit" / "SKILL.md"
    assert skill_md.is_file()
    assert "name: context-audit" in skill_md.read_text(encoding="utf-8")

