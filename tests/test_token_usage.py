"""Real token usage read from harness transcripts."""
from __future__ import annotations

import json
import os
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from bin import token_usage, transcript_parsers
from bin.token_usage import (
    ingest_transcripts,
    prune_component_use,
    prune_vanished,
    refresh_usage,
)


def claude_line(
    mid: str = "msg_1",
    inp: int = 10,
    out: int = 5,
    read: int = 100,
    write: int = 20,
    sidechain: bool = False,
    ts: str = "2026-11-01T10:00:00.000Z",
    model: str = "claude-opus-5-5",
) -> dict[str, Any]:
    return {
        "type": "assistant",
        "isSidechain": sidechain,
        "timestamp": ts,
        "message": {
            "id": mid,
            "model": model,
            "usage": {
                "input_tokens": inp,
                "output_tokens": out,
                "cache_read_input_tokens": read,
                "cache_creation_input_tokens": write,
            },
        },
    }


def codex_line(**last: int) -> dict[str, Any]:
    return {
        "timestamp": "2026-10-31T10:41:36.212Z",
        "type": "event_msg",
        "payload": {
            "type": "token_count",
            "info": {"total_token_usage": {"total_tokens": 999999}, "last_token_usage": last},
        },
    }


def write_jsonl(path: Path, records: list[Any], newline_at_end: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(json.dumps(r) if not isinstance(r, str) else r for r in records)
    path.write_text(text + ("\n" if newline_at_end else ""), encoding="utf-8")


def append_jsonl(path: Path, records: list[Any]) -> None:
    with path.open("a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")


def roots_in(tmp_path: Path) -> dict[str, Path]:
    return {name: tmp_path / "t" / name for name in ("antigravity", "claude", "codex", "cursor")}


def fresh_state() -> dict[str, Any]:
    return token_usage.empty_usage_state()


def test_streaming_duplicates_are_counted_once(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    write_jsonl(roots["claude"] / "proj" / "s1.jsonl", [claude_line("a"), claude_line("a"), claude_line("b", inp=1)])
    state = fresh_state()
    ingest_transcripts(state, roots)
    row = state["totals"]["claude|claude-opus-5-5"]
    assert (row["events"], row["input"], row["cache_read"]) == (2, 11, 200)
    assert state["by_day"]["2026-11-01"]["claude"]["events"] == 2


def test_second_run_reads_only_appended_lines(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["claude"] / "proj" / "s1.jsonl"
    write_jsonl(path, [claude_line("a")])
    state = fresh_state()
    ingest_transcripts(state, roots)
    append_jsonl(path, [claude_line("a"), claude_line("b")])
    ingest_transcripts(state, roots)
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 2


def test_partial_last_line_waits_for_its_newline(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["claude"] / "proj" / "s1.jsonl"
    write_jsonl(path, [claude_line("a"), json.dumps(claude_line("b"))[:20]], newline_at_end=False)
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 1
    assert state["skipped_lines"] == 0


def test_shrunk_or_replaced_file_restarts_from_zero(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["claude"] / "proj" / "s1.jsonl"
    write_jsonl(path, [claude_line("a"), claude_line("b")])
    state = fresh_state()
    ingest_transcripts(state, roots)
    replacement = path.with_suffix(".new")
    write_jsonl(replacement, [claude_line("a")])
    os.replace(replacement, path)
    ingest_transcripts(state, roots)
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 3
    assert state["seen_ids"][str(path)] == ["a"]


def test_byte_limit_stops_and_next_run_resumes(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    first = roots["claude"] / "p" / "a.jsonl"
    second = roots["claude"] / "p" / "b.jsonl"
    write_jsonl(first, [claude_line("a")])
    write_jsonl(second, [claude_line("b")])
    state = fresh_state()
    used = ingest_transcripts(state, roots, max_bytes=first.stat().st_size)
    assert used == first.stat().st_size
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 1
    ingest_transcripts(state, roots)
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 2


def test_unparseable_lines_are_counted_not_fatal(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    write_jsonl(roots["claude"] / "p" / "s.jsonl", ["{broken", "[1, 2]", claude_line("a")])
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["skipped_lines"] == 2
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 1


def test_preamble_is_first_main_thread_call_and_skips_subagents(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    write_jsonl(roots["claude"] / "p" / "s.jsonl", [claude_line("a", inp=3, read=1000, write=500), claude_line("b", inp=9)])
    write_jsonl(roots["claude"] / "p" / "s" / "subagents" / "agent-1.jsonl", [claude_line("c", inp=7, sidechain=True)])
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["preamble"]["claude"] == [1503]
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 3


def test_preamble_is_recorded_once_per_file_across_runs(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["claude"] / "p" / "s.jsonl"
    write_jsonl(path, [{"type": "user", "message": {"content": "hi"}}])
    state = fresh_state()
    ingest_transcripts(state, roots)
    append_jsonl(path, [claude_line("a", inp=1, read=0, write=0), claude_line("b", inp=50)])
    ingest_transcripts(state, roots)
    assert state["preamble"]["claude"] == [1]


def test_preamble_history_keeps_last_200(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    for index in range(205):
        path = roots["claude"] / "p" / f"s{index:03d}.jsonl"
        write_jsonl(path, [claude_line(f"m{index}", inp=index, read=0, write=0)])
        # equal mtimes: oldest-first reading falls back to path order, so s204 is appended last
        os.utime(path, (1761955200, 1761955200))
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert len(state["preamble"]["claude"]) == 200
    assert state["preamble"]["claude"][-1] == 204


def test_codex_model_from_turn_context_and_total_only(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    write_jsonl(
        roots["codex"] / "2026" / "10" / "31" / "rollout-x.jsonl",
        [{"type": "turn_context", "payload": {"model": "gpt-6.1-sol"}}, codex_line(total_tokens=17590)],
    )
    state = fresh_state()
    ingest_transcripts(state, roots)
    row = state["totals"]["codex|gpt-6.1-sol"]
    assert (row["input"], row["events"], row["total_only"]) == (17590, 1, 1)
    assert state["preamble"]["codex"] == [17590]


def test_operator_pin_overrides_detected_model(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(token_usage, "pinned_model", lambda harness: "pinned-x" if harness == "claude" else None)
    roots = roots_in(tmp_path)
    write_jsonl(roots["claude"] / "p" / "s.jsonl", [claude_line("a")])
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert list(state["totals"]) == ["claude|pinned-x"]


def test_antigravity_coverage_and_mtime_day(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["antigravity"] / "conv" / ".system_generated" / "logs" / "transcript_full.jsonl"
    write_jsonl(
        path,
        [
            {"type": "USER_INPUT"},
            {"type": "PLANNER_RESPONSE", "input_tokens": 34421, "output_tokens": 377, "cache_read_tokens": 0},
            {"type": "PLANNER_RESPONSE"},
        ],
    )
    os.utime(path, (1761955200, 1761955200))  # 2025-11-01T00:00:00Z
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["antigravity_coverage"] == {"planner": 2, "with_usage": 1}
    assert state["totals"]["antigravity|unknown"]["input"] == 34421
    assert state["by_day"]["2025-11-01"]["antigravity"]["events"] == 1
    assert state["preamble"]["antigravity"] == [34421]


def test_cursor_estimate_is_replaced_not_summed_and_never_in_totals(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["cursor"] / "proj" / "agent-transcripts" / "c.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps([{"role": "user", "text": "a" * 400}]), encoding="utf-8")
    state = fresh_state()
    ingest_transcripts(state, roots)
    ingest_transcripts(state, roots)
    assert state["cursor_estimates"][str(path)]["tokens"] == 100
    path.write_text(json.dumps([{"role": "user", "text": "a" * 800}]), encoding="utf-8")
    ingest_transcripts(state, roots)
    assert [entry["tokens"] for entry in state["cursor_estimates"].values()] == [200]
    assert state["totals"] == {}


def test_prune_vanished_drops_cursors_but_keeps_totals(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["claude"] / "p" / "s.jsonl"
    write_jsonl(path, [claude_line("a")])
    state = fresh_state()
    ingest_transcripts(state, roots)
    path.unlink()
    prune_vanished(state)
    assert state["cursors"] == {} and state["seen_ids"] == {}
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 1


def test_refresh_persists_and_sets_start_once(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    write_jsonl(roots["claude"] / "p" / "s.jsonl", [claude_line("a")])
    ledger = tmp_path / "telemetry" / "token_usage.json"
    first = refresh_usage(ledger, roots, saved_tokens_now=500)
    second = refresh_usage(ledger, roots, saved_tokens_now=900)
    assert first["started_at"] == second["started_at"]
    assert second["saved_tokens_at_start"] == 500
    assert json.loads(ledger.read_text(encoding="utf-8"))["totals"]["claude|claude-opus-5-5"]["events"] == 1


def test_corrupt_ledger_is_quarantined_and_rebuilt(tmp_path: Path) -> None:
    ledger = tmp_path / "token_usage.json"
    ledger.write_text("[not an object]", encoding="utf-8")
    state = refresh_usage(ledger, roots_in(tmp_path))
    assert state["totals"] == {}
    assert len(list(tmp_path.glob("token_usage.json.corrupt-*"))) == 1


def test_mistyped_ledger_sections_are_reset(tmp_path: Path) -> None:
    ledger = tmp_path / "token_usage.json"
    ledger.write_text(
        json.dumps(
            {
                "totals": [],
                "skipped_lines": True,
                "started_at": 5,
                "preamble": {"claude": [1]},
                "antigravity_coverage": {"planner": "x"},
            }
        ),
        encoding="utf-8",
    )
    state = token_usage.restore_usage_state(ledger)
    assert state["totals"] == {} and state["skipped_lines"] == 0 and state["started_at"] is None
    assert state["preamble"] == {"claude": [1]}
    assert state["antigravity_coverage"] == {"planner": 0, "with_usage": 0}


def test_default_paths_are_isolated_by_conftest(tmp_path: Path) -> None:
    state = refresh_usage()
    assert state["totals"] == {}
    assert token_usage.DEFAULT_USAGE_PATH.is_file()
    assert str(tmp_path) in str(token_usage.DEFAULT_USAGE_PATH)


def codex_event(total: int, **last: int) -> dict[str, Any]:
    line = codex_line(**last)
    line["payload"]["info"]["total_token_usage"] = {"input_tokens": total, "output_tokens": 1, "total_tokens": total + 1}
    return line


def consumed(state: dict[str, Any], path: Path) -> int:
    return state["cursors"].get(str(path), {}).get("offset", 0)


def test_budget_is_shared_so_every_harness_advances(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    claude = roots["claude"] / "p" / "s.jsonl"
    write_jsonl(claude, [claude_line(f"m{index}") for index in range(40)])
    codex = roots["codex"] / "2026" / "10" / "31" / "rollout-x.jsonl"
    write_jsonl(
        codex,
        [{"type": "turn_context", "payload": {"model": "gpt-6.1-sol"}}]
        + [codex_event(100 * (index + 1), input_tokens=100) for index in range(5)],
    )
    size = codex.stat().st_size
    state = fresh_state()
    used = ingest_transcripts(state, roots, max_bytes=3 * size)
    assert consumed(state, codex) == size
    assert state["totals"]["codex|gpt-6.1-sol"]["events"] == 5
    # the idle harnesses' shares and codex's unused half pass to claude: more than an equal half
    assert consumed(state, claude) > 1.5 * size
    assert used <= 3 * size


def test_files_are_read_oldest_first(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    old = roots["claude"] / "p" / "a.jsonl"
    new = roots["claude"] / "p" / "b.jsonl"
    write_jsonl(old, [claude_line("a", inp=1)])
    write_jsonl(new, [claude_line("b", inp=2)])
    os.utime(old, (1761955200, 1761955200))
    os.utime(new, (1761958800, 1761958800))
    state = fresh_state()
    ingest_transcripts(state, roots, max_bytes=old.stat().st_size)
    assert state["totals"]["claude|claude-opus-5-5"]["input"] == 1


def test_backlog_is_stored_per_harness_and_clears(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    first = roots["claude"] / "p" / "a.jsonl"
    second = roots["claude"] / "p" / "b.jsonl"
    write_jsonl(first, [claude_line("a")])
    write_jsonl(second, [claude_line("b")])
    os.utime(first, (1761955200, 1761955200))
    os.utime(second, (1761958800, 1761958800))
    state = fresh_state()
    ingest_transcripts(state, roots, max_bytes=first.stat().st_size)
    assert state["backlog"]["claude"] == second.stat().st_size
    assert state["backlog"]["codex"] == 0
    ingest_transcripts(state, roots)
    assert set(state["backlog"].values()) == {0}


def test_backlog_is_normalised_on_restore(tmp_path: Path) -> None:
    ledger = tmp_path / "token_usage.json"
    ledger.write_text(json.dumps({"backlog": {"claude": "x", "codex": 5, "cursor": True}}), encoding="utf-8")
    assert token_usage.restore_usage_state(ledger)["backlog"] == {"claude": 0, "codex": 5, "cursor": 0}
    ledger.write_text(json.dumps({"backlog": [1, 2]}), encoding="utf-8")
    assert token_usage.restore_usage_state(ledger)["backlog"] == {}
    ledger.write_text(json.dumps({}), encoding="utf-8")
    assert token_usage.restore_usage_state(ledger)["backlog"] == {}


def test_corrupt_day_rows_are_dropped_on_restore(tmp_path: Path) -> None:
    ledger = tmp_path / "token_usage.json"
    ledger.write_text(json.dumps({
        "component_use": {"2026-11-01": 3, "2026-11-02": {"mcp:x": 1}},
        "by_day": {"2026-11-01": [1], "2026-11-02": {"claude": 7, "codex": {"input": 1}}},
    }), encoding="utf-8")
    state = token_usage.restore_usage_state(ledger)
    assert state["component_use"] == {"2026-11-02": {"mcp:x": 1}}
    assert state["by_day"] == {"2026-11-02": {"codex": {"input": 1}}}


def test_cursor_file_counts_against_the_budget(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["cursor"] / "proj" / "agent-transcripts" / "c.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps([{"role": "user", "text": "a" * 400}]), encoding="utf-8")
    size = path.stat().st_size
    state = fresh_state()
    assert ingest_transcripts(state, roots, max_bytes=size - 1) == 0
    assert state["cursor_estimates"] == {}
    assert state["backlog"]["cursor"] == size
    assert ingest_transcripts(state, roots, max_bytes=size) == size
    assert state["cursor_estimates"][str(path)]["tokens"] == 100
    assert ingest_transcripts(state, roots, max_bytes=size) == 0
    assert state["backlog"]["cursor"] == 0


def test_message_copied_into_another_file_is_counted_once(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    original = roots["claude"] / "p" / "a.jsonl"
    resumed = roots["claude"] / "p" / "b.jsonl"
    write_jsonl(original, [claude_line("a", inp=3, read=1000, write=500), claude_line("b", inp=9)])
    write_jsonl(resumed, [claude_line("b", inp=9), claude_line("c", inp=7)])
    os.utime(original, (1761955200, 1761955200))
    os.utime(resumed, (1761958800, 1761958800))
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 3
    assert state["totals"]["claude|claude-opus-5-5"]["input"] == 19
    assert state["preamble"]["claude"] == [1503]
    assert state["seen_ids"][str(resumed)] == ["c"]
    later = roots["claude"] / "p" / "c.jsonl"
    write_jsonl(later, [claude_line("c", inp=7), claude_line("d", inp=1)])
    ingest_transcripts(state, roots)
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 4
    assert state["preamble"]["claude"] == [1503]


def test_codex_repeated_total_is_counted_once(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["codex"] / "2026" / "10" / "31" / "rollout-x.jsonl"
    write_jsonl(
        path,
        [
            {"type": "turn_context", "payload": {"model": "gpt-6.1-sol"}},
            codex_event(100, input_tokens=100),
            codex_event(100, input_tokens=100),
            codex_event(150, input_tokens=50),
        ],
    )
    state = fresh_state()
    ingest_transcripts(state, roots)
    row = state["totals"]["codex|gpt-6.1-sol"]
    assert (row["events"], row["input"]) == (2, 150)
    append_jsonl(path, [codex_event(150, input_tokens=50), codex_event(170, input_tokens=20)])
    ingest_transcripts(state, roots)
    row = state["totals"]["codex|gpt-6.1-sol"]
    assert (row["events"], row["input"]) == (3, 170)


def attachment_line(kind: str, **fields: Any) -> dict[str, Any]:
    return {"type": "attachment", "attachment": {"type": kind, **fields}}


def tool_line(mid: str, *calls: tuple[str, dict[str, Any]], sidechain: bool = False, ts: str = "2026-11-01T10:00:00.000Z") -> dict[str, Any]:
    record = claude_line(mid, sidechain=sidechain, ts=ts)
    record["message"]["content"] = [{"type": "tool_use", "id": f"t_{mid}", "name": name, "input": args} for name, args in calls]
    return record


HOOKS = attachment_line("hook_additional_context", content=["h" * 400])
USER_MD = attachment_line("instructions", files=[{"type": "User", "content": "u" * 40}], rendered="x" * 999)


def test_first_main_call_stores_the_preamble_breakdown(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    write_jsonl(roots["claude"] / "p" / "s.jsonl", [HOOKS, attachment_line("hook_success", stdout="z" * 400), USER_MD, claude_line("a")])
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["preamble"]["claude"] == [130]
    assert state["preamble_parts"] == [{"measured": 130, "components": {"hooks": {"all": 100}, "instructions": {"User": 10}}}]
    assert "pending_parts" not in state["cursors"][str(roots["claude"] / "p" / "s.jsonl")]


def test_attachments_read_in_an_earlier_run_are_kept_in_the_cursor(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    path = roots["claude"] / "p" / "s.jsonl"
    write_jsonl(path, [HOOKS])
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["cursors"][str(path)]["pending_parts"] == {"hooks": {"all": 100}}
    assert state["preamble_parts"] == []
    append_jsonl(path, [USER_MD, claude_line("a")])
    ingest_transcripts(state, roots)
    assert state["preamble_parts"] == [{"measured": 130, "components": {"hooks": {"all": 100}, "instructions": {"User": 10}}}]


def test_resumed_file_stores_no_breakdown(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    first = roots["claude"] / "p" / "a.jsonl"
    second = roots["claude"] / "p" / "b.jsonl"
    write_jsonl(first, [HOOKS, claude_line("m1")])
    write_jsonl(second, [HOOKS, claude_line("m1"), claude_line("m2")])
    os.utime(first, (1000, 1000))
    os.utime(second, (2000, 2000))
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert len(state["preamble_parts"]) == 1
    assert "pending_parts" not in state["cursors"][str(second)]


def test_subagent_file_stores_no_breakdown(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    write_jsonl(roots["claude"] / "p" / "s" / "subagents" / "a.jsonl", [HOOKS, claude_line("a")])
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["preamble_parts"] == []


def test_malformed_attachment_is_skipped_and_the_preamble_kept(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    write_jsonl(roots["claude"] / "p" / "s.jsonl", [attachment_line("instructions", files="x"), claude_line("a")])
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["skipped_lines"] == 1
    assert state["preamble"]["claude"] == [130]
    assert state["preamble_parts"] == []


def test_tool_calls_are_counted_per_day_and_key(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    lines = [
        tool_line("m1", ("Skill", {"skill": "superpowers:brainstorming"})),
        tool_line("m1", ("mcp__claude-in-chrome__navigate", {})),
        tool_line("m2", ("Agent", {"subagent_type": "searchfit-seo:seo-auditor:AGENT"}), sidechain=True),
        tool_line("m3", ("Read", {"file_path": "/x"}), ts="2026-10-31T23:00:00.000Z"),
    ]
    write_jsonl(roots["claude"] / "p" / "s.jsonl", lines)
    write_jsonl(roots["claude"] / "p" / "s" / "subagents" / "a.jsonl", [tool_line("m4", ("Skill", {"skill": "superpowers:tdd"}))])
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["component_use"] == {"2026-11-01": {"superpowers": 2, "mcp:claude-in-chrome": 1, "searchfit-seo": 1}}
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 4


def test_tool_calls_of_a_resumed_copy_are_not_counted_again(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    first = roots["claude"] / "p" / "a.jsonl"
    second = roots["claude"] / "p" / "b.jsonl"
    call = ("Skill", {"skill": "superpowers:brainstorming"})
    write_jsonl(first, [tool_line("m1", call)])
    write_jsonl(second, [tool_line("m1", call), tool_line("m2", call)])
    os.utime(first, (1000, 1000))
    os.utime(second, (2000, 2000))
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["component_use"] == {"2026-11-01": {"superpowers": 2}}


def test_component_use_keeps_90_days(tmp_path: Path) -> None:
    today = date(2026, 11, 1)
    cutoff = today - timedelta(days=90)
    state = fresh_state()
    state["component_use"] = {
        (cutoff - timedelta(days=1)).isoformat(): {"a": 1},
        cutoff.isoformat(): {"b": 1},
        "bad": {"c": 1},
    }
    prune_component_use(state, today)
    assert state["component_use"] == {cutoff.isoformat(): {"b": 1}}


def test_refresh_sets_tracking_start_once_and_prunes(tmp_path: Path) -> None:
    ledger = tmp_path / "token_usage.json"
    first = refresh_usage(ledger, roots_in(tmp_path))
    assert first["component_use_since"] == first["updated_at"][:10]
    stored = json.loads(ledger.read_text(encoding="utf-8"))
    stored["component_use_since"] = "2026-01-01"
    stored["component_use"] = {"2000-01-01": {"old": 1}}
    ledger.write_text(json.dumps(stored), encoding="utf-8")
    second = refresh_usage(ledger, roots_in(tmp_path))
    assert second["component_use_since"] == "2026-01-01"
    assert second["component_use"] == {}


def test_token_usage_refresh_acquires_exclusive_lock_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    telemetry_dir = tmp_path / "telemetry"
    telemetry_dir.mkdir(parents=True)
    state_path = telemetry_dir / "token_usage.json"
    lock_path = telemetry_dir / "token_usage.lock"
    lock_path.write_text("usage-lock-sentinel\n", encoding="utf-8")

    def _make_roots(label: str, msg_id: str, input_tokens: int) -> dict[str, Path]:
        base = tmp_path / f"roots-{label}"
        claude_proj = base / "claude" / f"proj-{label}"
        claude_proj.mkdir(parents=True)
        transcript = claude_proj / f"{label}.jsonl"
        record = {
            "type": "assistant",
            "timestamp": "2026-11-07T10:00:00Z",
            "isSidechain": False,
            "message": {
                "id": msg_id,
                "role": "assistant",
                "model": "claude-sonnet-4-5",
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": 10,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                },
            },
        }
        transcript.write_text(json.dumps(record) + "\n", encoding="utf-8")
        return {
            "antigravity": base / "antigravity",
            "claude": base / "claude",
            "codex": base / "codex",
            "cursor": base / "cursor",
        }

    roots_a = _make_roots("a", "msg-concurrent-a", 110)
    roots_b = _make_roots("b", "msg-concurrent-b", 230)

    start_barrier = threading.Barrier(2, timeout=2.0)
    state_lock = threading.Lock()
    active_in_ingest = 0
    max_active_in_ingest = 0
    real_ingest = token_usage.ingest_transcripts

    def _tracked_ingest(state: dict[str, Any], roots: dict[str, Path], max_bytes: int) -> int:
        nonlocal active_in_ingest, max_active_in_ingest
        with state_lock:
            active_in_ingest += 1
            if active_in_ingest > max_active_in_ingest:
                max_active_in_ingest = active_in_ingest
        try:
            return real_ingest(state, roots, max_bytes)
        finally:
            with state_lock:
                active_in_ingest -= 1

    monkeypatch.setattr(token_usage, "ingest_transcripts", _tracked_ingest)

    errors: list[BaseException] = []

    def _worker(worker_roots: dict[str, Path]) -> None:
        try:
            start_barrier.wait()
            token_usage.refresh_usage(state_path=state_path, roots=worker_roots)
        except BaseException as exc:
            errors.append(exc)

    t1 = threading.Thread(target=_worker, args=(roots_a,))
    t2 = threading.Thread(target=_worker, args=(roots_b,))
    t1.start()
    t2.start()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)

    assert not errors
    assert max_active_in_ingest == 1
    assert lock_path.exists()
    assert lock_path.read_text(encoding="utf-8") == "usage-lock-sentinel\n"

    final_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert len(final_state["cursors"]) == 2
    row = final_state["totals"]["claude|claude-sonnet-4-5"]
    assert row["input"] == 340
    assert row["output"] == 20
    assert row["events"] == 2


def test_token_usage_lock_failure_is_read_only_and_cg_status_json_error_is_valid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from bin import cg_status

    usage_path = tmp_path / "telemetry" / "token_usage.json"
    usage_path.parent.mkdir(parents=True)
    initial_state = token_usage.empty_usage_state()
    initial_state["updated_at"] = "2026-11-01T00:00:00+00:00"
    before_bytes = json.dumps(initial_state, indent=2) + "\n"
    usage_path.write_text(before_bytes, encoding="utf-8")

    def _boom_flock(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("simulated flock failure")

    monkeypatch.setattr(token_usage.fcntl, "flock", _boom_flock)
    loaded = token_usage.refresh_usage(state_path=usage_path, roots={}, saved_tokens_now=500)
    assert usage_path.read_text(encoding="utf-8") == before_bytes
    assert isinstance(loaded, dict)

    def _boom_stats(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("simulated status failure")

    monkeypatch.setattr(cg_status, "load_telemetry_stats", _boom_stats)
    capsys.readouterr()
    rc = cg_status.main(["--json"])
    assert rc == 0
    out_json = json.loads(capsys.readouterr().out.strip())
    assert out_json.get("error") == "RuntimeError"


def test_token_usage_reexports_all_transcript_parser_symbols() -> None:
    expected = (
        "UsageEvent",
        "antigravity_model_from_record",
        "codex_model_from_record",
        "codex_total_counts",
        "estimate_cursor_tokens",
        "nonneg_int",
        "parse_antigravity_record",
        "parse_claude_record",
        "parse_codex_record",
        "parse_utc_day",
    )
    assert sorted(transcript_parsers.__all__) == sorted(expected)
    for name in expected:
        assert getattr(token_usage, name) is getattr(transcript_parsers, name)


def test_antigravity_cross_session_carryover_ignores_sidechain(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    p_a = roots["antigravity"] / "conv-a" / ".system_generated" / "logs" / "transcript_full.jsonl"
    p_sub_ui = roots["antigravity"] / "conv-sub-ui" / ".system_generated" / "logs" / "transcript_full.jsonl"
    p_sub_sys = roots["antigravity"] / "conv-sub-sys" / ".system_generated" / "logs" / "transcript_full.jsonl"
    p_b = roots["antigravity"] / "conv-b" / ".system_generated" / "logs" / "transcript_full.jsonl"
    write_jsonl(p_a, [
        {"step_index": 0, "type": "USER_INPUT", "content": "<USER_REQUEST>\nhi\n</USER_REQUEST>\n<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Argon High.\n</USER_SETTINGS_CHANGE>"},
        {"step_index": 1, "type": "PLANNER_RESPONSE", "created_at": "2026-11-12T10:00:00Z", "input_tokens": 100, "output_tokens": 20, "cache_read_tokens": 0},
    ])
    write_jsonl(p_sub_ui, [
        {"step_index": 0, "type": "USER_INPUT", "content": "<SYSTEM_MESSAGE>\nsubagent\n</SYSTEM_MESSAGE>"},
        {"step_index": 1, "type": "PLANNER_RESPONSE", "model": "flash", "created_at": "2026-11-12T10:05:00Z", "input_tokens": 50, "output_tokens": 5, "cache_read_tokens": 0},
    ])
    write_jsonl(p_sub_sys, [
        {"step_index": 0, "type": "SYSTEM_MESSAGE", "content": "The following is a <SYSTEM_MESSAGE> subagent"},
        {"step_index": 1, "type": "PLANNER_RESPONSE", "model": "flash", "created_at": "2026-11-12T10:06:00Z", "input_tokens": 60, "output_tokens": 6, "cache_read_tokens": 0},
    ])
    write_jsonl(p_b, [
        {"step_index": 0, "type": "USER_INPUT", "content": "<USER_REQUEST>\nnext\n</USER_REQUEST>"},
        {"step_index": 1, "type": "PLANNER_RESPONSE", "created_at": "2026-11-12T10:10:00Z", "input_tokens": 200, "output_tokens": 30, "cache_read_tokens": 0},
    ])
    os.utime(p_a, (1000, 1000)); os.utime(p_sub_ui, (1500, 1500)); os.utime(p_sub_sys, (1700, 1700)); os.utime(p_b, (2000, 2000))
    state = fresh_state()
    ingest_transcripts(state, roots)
    assert state["antigravity_last_model"] == "gemini4argonhigh"
    assert state["totals"]["antigravity|gemini4argonhigh"]["input"] == 300
    assert state["totals"]["antigravity|gemini4argonhigh"]["events"] == 2
    assert state["totals"]["antigravity|flash"]["events"] == 2
    assert "antigravity|unknown" not in state["totals"]
    assert state["preamble"]["antigravity"] == [100, 200]


def test_migrate_usage_state_v2_to_v3_resets_only_antigravity(tmp_path: Path) -> None:
    roots = roots_in(tmp_path)
    claude_k = str(roots["claude"] / "p" / "s.jsonl")
    codex_k = str(roots["codex"] / "2026" / "11" / "12" / "rollout-1.jsonl")
    ag_k = str(roots["antigravity"] / "c1" / ".system_generated" / "logs" / "transcript_full.jsonl")
    cursor_k = str(roots["cursor"] / "p" / "agent-transcripts" / "c.json")
    state: dict[str, Any] = {
        "schema_version": 2,
        "cursors": {claude_k: {"offset": 10}, codex_k: {"offset": 20}, ag_k: {"offset": 30}},
        "seen_ids": {claude_k: ["m1"], ag_k: ["a1"]},
        "cursor_estimates": {cursor_k: {"inode": 1, "size": 50, "tokens": 12, "day": "2026-11-12"}},
        "totals": {"claude|opus": {"events": 1}, "codex|gpt-5-codex": {"events": 2}, "antigravity|unknown": {"events": 3}},
        "by_day": {"2026-11-12": {"claude": {"events": 1}, "codex": {"events": 2}, "antigravity": {"events": 3}}},
        "preamble": {"claude": [100], "codex": [200], "antigravity": [300]},
        "preamble_parts": [], "codex_preamble_parts": [{"measured": 200, "cohort": "codex (cli)", "components": {}}],
        "component_use": {}, "component_use_since": None, "backlog": {"claude": 0, "codex": 5, "antigravity": 9},
        "antigravity_coverage": {"planner": 5, "with_usage": 2}, "antigravity_last_model": "stale",
    }
    assert token_usage.migrate_usage_state(state, roots) is True
    assert state["schema_version"] == 3 and state["antigravity_last_model"] == "unknown"
    assert state["antigravity_coverage"] == {"planner": 0, "with_usage": 0}
    assert set(state["totals"]) == {"claude|opus", "codex|gpt-5-codex"}
    assert set(state["by_day"]["2026-11-12"]) == {"claude", "codex"}
    assert state["preamble"] == {"claude": [100], "codex": [200]} and state["backlog"] == {"claude": 0, "codex": 5}
    assert len(state["codex_preamble_parts"]) == 1 and set(state["cursors"]) == {claude_k, codex_k}
    assert set(state["seen_ids"]) == {claude_k} and cursor_k in state["cursor_estimates"]
    assert token_usage.migrate_usage_state(state, roots) is False
    ledger = tmp_path / "restore.json"
    for bad in ("   ", "Auto", "UNKNOWN", "<synthetic>"):
        ledger.write_text(json.dumps({"schema_version": 3, "antigravity_last_model": bad}), encoding="utf-8")
        assert token_usage.restore_usage_state(ledger)["antigravity_last_model"] == "unknown"
