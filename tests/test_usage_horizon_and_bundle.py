"""Tests for signed daily ledger, common-horizon savings_share, UTC day parser, model precedence, and skill hygiene."""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

import pytest

from services.installer_service import install_ide_extension
from services.status_service import render_doctor_report, run_doctor
from services.token_usage import (
    USAGE_SCHEMA_VERSION,
    empty_usage_state,
    fold_jsonl_file,
    ingest_transcripts,
    parse_antigravity_record,
    parse_utc_day,
    restore_usage_state,
)
from services.usage_report import (
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
        "window_events": 0,
        "total_events": 0,
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
    monkeypatch.setattr("services.token_usage.pinned_model", lambda _h: None)
    state_unpinned = empty_usage_state()
    fold_jsonl_file(state_unpinned, "antigravity", transcript, budget=10000)
    assert state_unpinned["totals"]["antigravity|gemini-2.5-pro"]["events"] == 2

    # With pin: pinned_model("antigravity") overrides record_model and cursor["model"]
    monkeypatch.setattr("services.token_usage.pinned_model", lambda _h: "claude-opus-4-6")
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


def test_restore_usage_state_sanitizes_corrupt_inner_rows_from_path(tmp_path: Path) -> None:
    ledger = tmp_path / "token_usage.json"
    ledger.write_text(
        json.dumps(
            {
                "schema_version": USAGE_SCHEMA_VERSION,
                "totals": {
                    "claude|opus": 999,
                    "codex|o3": {"input": 10, "events": 1, "output": "bad", "cache_read": True, "cache_write": -4},
                },
                "preamble": {"claude": "bad", "codex": [100, True, -5, 200]},
                "preamble_parts": ["bad", {"measured": 100, "components": {}}],
                "codex_preamble_parts": [123, {"measured": 50, "cohort": "codex (cli)", "components": {}}],
            }
        ),
        encoding="utf-8",
    )
    restored = restore_usage_state(ledger)
    assert "claude|opus" not in restored["totals"]
    assert restored["totals"]["codex|o3"] == {"input": 10, "events": 1, "output": 0, "cache_read": 0, "cache_write": 0}
    assert restored["preamble"] == {"codex": [100, 0, 200]}
    assert restored["preamble_parts"] == [{"measured": 100, "components": {}}]
    assert restored["codex_preamble_parts"] == [{"measured": 50, "cohort": "codex (cli)", "components": {}}]

    bad_path = tmp_path / "corrupt.json"
    bad_path.write_text("{corrupt json", encoding="utf-8")
    quarantined = restore_usage_state(bad_path)
    assert quarantined["totals"] == {}
    assert len(list(tmp_path.glob("corrupt.json.corrupt-*"))) == 1


def test_antigravity_rewind_and_step_index_none_sidechain_reconciliation(tmp_path: Path) -> None:
    ag_tx = tmp_path / "ag" / "b1" / ".system_generated" / "logs" / "transcript.jsonl"
    ag_tx.parent.mkdir(parents=True)
    r1 = json.dumps({"type": "USER_INPUT", "step_index": 0, "content": "<USER_REQUEST>hi</USER_REQUEST>"})
    p1 = json.dumps({
        "type": "PLANNER_RESPONSE",
        "step_index": 1,
        "created_at": "2026-11-14T10:00:00Z",
        "model": "gemini-2.5-pro",
        "input_tokens": 1000,
        "output_tokens": 100,
    })
    p2 = json.dumps({
        "type": "PLANNER_RESPONSE",
        "step_index": 2,
        "created_at": "2026-11-14T10:01:00Z",
        "model": "gemini-2.5-pro",
        "input_tokens": 1500,
        "output_tokens": 200,
    })
    ag_tx.write_text(f"{r1}\n{p1}\n", encoding="utf-8")
    st = empty_usage_state()
    fold_jsonl_file(st, "antigravity", ag_tx, 1_000_000)
    with ag_tx.open("a", encoding="utf-8") as fh:
        fh.write(f"{p2}\n")
    fold_jsonl_file(st, "antigravity", ag_tx, 1_000_000)
    assert st["totals"]["antigravity|gemini-2.5-pro"]["input"] == 2500
    assert st["totals"]["antigravity|gemini-2.5-pro"]["events"] == 2

    # Truncate step 2 (rewind on same inode):
    ag_tx.write_text(f"{r1}\n{p1}\n", encoding="utf-8")
    fold_jsonl_file(st, "antigravity", ag_tx, 1_000_000)
    assert st["totals"]["antigravity|gemini-2.5-pro"]["input"] == 1000
    assert st["totals"]["antigravity|gemini-2.5-pro"]["events"] == 1
    assert st["by_day"]["2026-11-14"]["antigravity"]["input"] == 1000
    assert st["preamble"]["antigravity"] == [1000]

    # Truncate to incomplete line (no newline): must still drop prior row cleanly once!
    ag_tx.write_text("{incomplete", encoding="utf-8")
    fold_jsonl_file(st, "antigravity", ag_tx, 1_000_000)
    assert st["totals"] == {}
    assert st["by_day"] == {}
    assert st["preamble"] == {}

    # Omitted step_index (None) with <SYSTEM_MESSAGE> before <USER_REQUEST> marks sidechain;
    # after <USER_REQUEST>, <SYSTEM_MESSAGE> stays on main thread.
    sub_tx = tmp_path / "ag" / "sub" / ".system_generated" / "logs" / "transcript.jsonl"
    sub_tx.parent.mkdir(parents=True)
    sub_tx.write_text(
        "\n".join([
            json.dumps({"type": "USER_INPUT", "content": "<SYSTEM_MESSAGE>subagent</SYSTEM_MESSAGE>"}),
            json.dumps({"type": "PLANNER_RESPONSE", "created_at": "2026-11-14T10:02:00Z", "model": "flash", "input_tokens": 900, "output_tokens": 10}),
        ]) + "\n",
        encoding="utf-8",
    )
    main_tx = tmp_path / "ag" / "main2" / ".system_generated" / "logs" / "transcript.jsonl"
    main_tx.parent.mkdir(parents=True)
    main_tx.write_text(
        "\n".join([
            json.dumps({"type": "USER_INPUT", "content": "<USER_REQUEST>solve</USER_REQUEST>"}),
            json.dumps({"type": "SYSTEM_MESSAGE", "content": "<SYSTEM_MESSAGE>notify</SYSTEM_MESSAGE>"}),
            json.dumps({"type": "PLANNER_RESPONSE", "created_at": "2026-11-14T10:03:00Z", "model": "gemini-2.5-pro", "input_tokens": 500, "output_tokens": 20}),
        ]) + "\n",
        encoding="utf-8",
    )
    st2 = empty_usage_state()
    fold_jsonl_file(st2, "antigravity", sub_tx, 1_000_000)
    fold_jsonl_file(st2, "antigravity", main_tx, 1_000_000)
    assert st2["preamble"] == {"antigravity": [500]}


def test_forked_claude_and_codex_rewind_reconciles_all_per_file_contributions(tmp_path: Path) -> None:
    def _claude_rec(mid: str, inp: int, tool: tuple[str, dict[str, str]] | None = None) -> dict:
        msg: dict = {
            "id": mid,
            "model": "claude-opus-5-5",
            "usage": {"input_tokens": inp, "output_tokens": 5, "cache_read_input_tokens": 0, "cache_write": 0},
        }
        if tool:
            msg["content"] = [{"type": "tool_use", "id": f"t_{mid}", "name": tool[0], "input": tool[1]}]
        return {"type": "assistant", "isSidechain": False, "timestamp": "2026-11-14T10:00:00Z", "message": msg}

    roots = {name: tmp_path / name for name in ("antigravity", "claude", "codex", "cursor")}
    parent = roots["claude"] / "p" / "parent.jsonl"
    fork = roots["claude"] / "p" / "fork.jsonl"
    solo = roots["claude"] / "p" / "solo.jsonl"
    parent.parent.mkdir(parents=True)
    hook_att = {"type": "attachment", "attachment": {"type": "hook_additional_context", "content": ["h" * 400]}}

    parent.write_text(
        json.dumps(hook_att) + "\n" + json.dumps(_claude_rec("m1", 100, ("Skill", {"skill": "superpowers:tdd"}))) + "\n",
        encoding="utf-8",
    )
    fork.write_text(
        json.dumps(_claude_rec("m1", 100, ("Skill", {"skill": "superpowers:tdd"})))
        + "\n"
        + json.dumps(_claude_rec("m2", 200, ("mcp__alpha__ping", {})))
        + "\n",
        encoding="utf-8",
    )
    solo.write_text(
        json.dumps(hook_att) + "\n" + json.dumps(_claude_rec("m3", 600, ("mcp__beta__run", {}))) + "\n",
        encoding="utf-8",
    )
    os.utime(parent, (1000, 1000))
    os.utime(fork, (2000, 2000))
    os.utime(solo, (3000, 3000))

    st = empty_usage_state()
    ingest_transcripts(st, roots)
    assert st["totals"]["claude|claude-opus-5-5"]["events"] == 3
    assert st["totals"]["claude|claude-opus-5-5"]["input"] == 900
    assert st["component_use"] == {"2026-11-14": {"superpowers": 1, "mcp:alpha": 1, "mcp:beta": 1}}
    assert st["preamble"]["claude"] == [100, 600]
    assert len(st["preamble_parts"]) == 2

    # Atomic inode replacement of fork.jsonl: m1 stays owned by parent, m2 & mcp:alpha subtracted!
    repl = fork.with_suffix(".tmp")
    repl.write_text(
        json.dumps(_claude_rec("m1", 100, ("Skill", {"skill": "superpowers:tdd"})))
        + "\n"
        + json.dumps(_claude_rec("m4", 50))
        + "\n",
        encoding="utf-8",
    )
    os.replace(repl, fork)
    # Rewind solo.jsonl with smaller preamble and no beta call:
    solo.write_text(json.dumps(_claude_rec("m5", 250)) + "\n", encoding="utf-8")
    os.utime(parent, (1000, 1000))
    os.utime(fork, (2000, 2000))
    os.utime(solo, (3000, 3000))

    ingest_transcripts(st, roots)
    assert st["seen_ids"][str(parent)] == ["m1"]
    assert st["seen_ids"][str(fork)] == ["m4"]
    assert st["totals"]["claude|claude-opus-5-5"]["events"] == 3
    assert st["totals"]["claude|claude-opus-5-5"]["input"] == 400  # 100 + 50 + 250
    assert st["component_use"] == {"2026-11-14": {"superpowers": 1}}
    assert st["preamble"]["claude"] == [100, 250]
    assert len(st["preamble_parts"]) == 1

    # Codex rewind reconciles codex_preamble_parts + total_only row:
    codex_file = roots["codex"] / "2026" / "11" / "14" / "rollout-1.jsonl"
    codex_file.parent.mkdir(parents=True)
    codex_file.write_text(
        "\n".join([
            json.dumps({"timestamp": "2026-11-14T10:00:00Z", "type": "session_meta", "payload": {"originator": "codex_cli_rs", "source": "cli"}}),
            json.dumps({"type": "turn_context", "payload": {"model": "gpt-5.4"}}),
            json.dumps({"type": "response_item", "payload": {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "You are Codex.\n" + "x" * 200}]}}),
            json.dumps({"timestamp": "2026-11-14T10:00:01Z", "type": "event_msg", "payload": {"type": "token_count", "info": {"last_token_usage": {"total_tokens": 5000}}}}),
        ]) + "\n",
        encoding="utf-8",
    )
    ingest_transcripts(st, roots)
    assert st["totals"]["codex|gpt-5.4"]["total_only"] == 1
    assert len(st["codex_preamble_parts"]) == 1
    codex_file.write_text(
        "\n".join([
            json.dumps({"timestamp": "2026-11-14T10:00:00Z", "type": "session_meta", "payload": {"originator": "codex_cli_rs", "source": "cli"}}),
            json.dumps({"type": "turn_context", "payload": {"model": "gpt-5.4"}}),
            json.dumps({"type": "response_item", "payload": {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "You are Codex.\n" + "y" * 20}]}}),
            json.dumps({"timestamp": "2026-11-14T10:00:01Z", "type": "event_msg", "payload": {"type": "token_count", "info": {"last_token_usage": {"input_tokens": 1200, "cached_input_tokens": 0, "output_tokens": 10}}}}),
        ]) + "\n",
        encoding="utf-8",
    )
    ingest_transcripts(st, roots)
    assert st["totals"]["codex|gpt-5.4"]["total_only"] == 0
    assert st["totals"]["codex|gpt-5.4"]["events"] == 1
    assert st["preamble"]["codex"] == [1200]
    assert [e["measured"] for e in st["codex_preamble_parts"]] == [1200]

    # Antigravity rewind via os.replace rolls back planner/with_usage coverage counts:
    ag_file = roots["antigravity"] / "conv-1" / ".system_generated" / "logs" / "transcript_full.jsonl"
    ag_file.parent.mkdir(parents=True)
    ag_tmp = ag_file.with_suffix(".tmp")
    ag_tmp.write_text(
        "\n".join([
            json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "<USER_REQUEST>hi</USER_REQUEST>"}),
            json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "input_tokens": 100, "output_tokens": 20, "cache_read_tokens": 0}),
            json.dumps({"step_index": 2, "type": "PLANNER_RESPONSE"}),
        ]) + "\n",
        encoding="utf-8",
    )
    os.replace(ag_tmp, ag_file)
    ingest_transcripts(st, roots)
    assert st["antigravity_coverage"] == {"planner": 2, "with_usage": 1}

    ag_tmp.write_text(
        "\n".join([
            json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "<USER_REQUEST>hi</USER_REQUEST>"}),
            json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "input_tokens": 50, "output_tokens": 5, "cache_read_tokens": 0}),
        ]) + "\n",
        encoding="utf-8",
    )
    os.replace(ag_tmp, ag_file)
    ingest_transcripts(st, roots)
    assert st["antigravity_coverage"] == {"planner": 1, "with_usage": 1}

