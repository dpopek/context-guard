"""Unit tests for stateless harness transcript record parsers."""
from __future__ import annotations

from typing import Any

from bin.transcript_parsers import (
    UsageEvent,
    antigravity_model_from_record,
    codex_model_from_record,
    codex_total_counts,
    estimate_cursor_tokens,
    nonneg_int,
    parse_antigravity_record,
    parse_claude_record,
    parse_codex_record,
    parse_utc_day,
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


def test_nonneg_int_coerces_invalid_and_negative_values() -> None:
    assert nonneg_int(0) == 0
    assert nonneg_int(42) == 42
    assert nonneg_int(-7) == 0
    assert nonneg_int(True) == 0
    assert nonneg_int(False) == 0
    assert nonneg_int("12") == 0
    assert nonneg_int(3.9) == 0
    assert nonneg_int(None) == 0


def test_parse_utc_day_handles_offsets_dates_and_invalid_inputs() -> None:
    assert parse_utc_day("2026-11-09T00:30:00+02:00") == "2026-11-08"
    assert parse_utc_day("2026-11-09T00:30:00+0200") == "2026-11-08"
    assert parse_utc_day("2026-11-08 23:30:00-0500") == "2026-11-09"
    assert parse_utc_day("2026-11-09T23:59:59-00:01") == "2026-11-10"
    assert parse_utc_day("2026-11-09T12:00:00.123456Z") == "2026-11-09"
    assert parse_utc_day("  2026-11-09  ") == "2026-11-09"
    assert parse_utc_day("2024-02-29") == "2024-02-29"
    assert parse_utc_day("2026-02-29") == ""
    assert parse_utc_day("2026-02-30T10:00:00Z") == ""
    assert parse_utc_day("2026-11-09T00:00:00+24:00") == ""
    assert parse_utc_day("2026-11-09T25:00:00Z") == ""
    assert parse_utc_day("") == ""
    assert parse_utc_day("   ") == ""
    assert parse_utc_day("not-a-date") == ""
    assert parse_utc_day(None) == ""
    assert parse_utc_day(20261109) == ""


def test_claude_line_maps_usage_fields() -> None:
    assert parse_claude_record(claude_line()) == UsageEvent(
        harness="claude",
        model="claude-opus-5-5",
        message_id="msg_1",
        is_sidechain=False,
        input=10,
        output=5,
        cache_read=100,
        cache_write=20,
        day="2026-11-01",
    )


def test_claude_line_with_zero_top_level_sums_iterations() -> None:
    line = claude_line(inp=0, out=0, read=0, write=0)
    line["message"]["usage"]["iterations"] = [
        {"input_tokens": 2, "output_tokens": 379, "cache_read_input_tokens": 210783, "cache_creation_input_tokens": 216},
        {"input_tokens": 1, "output_tokens": 1, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
    ]
    event = parse_claude_record(line)
    assert event is not None
    assert (event.input, event.output, event.cache_read, event.cache_write) == (3, 380, 210783, 216)


def test_claude_line_without_any_usage_is_skipped() -> None:
    assert parse_claude_record(claude_line(inp=0, out=0, read=0, write=0)) is None
    assert parse_claude_record({"type": "user", "message": {"content": "hi"}}) is None
    assert parse_claude_record({"type": "assistant", "message": "not a dict"}) is None


def test_claude_synthetic_model_reports_unknown_and_sidechain_is_kept() -> None:
    event = parse_claude_record(claude_line(model="<synthetic>", sidechain=True))
    assert event is not None
    assert event.model == "unknown"
    assert event.is_sidechain is True


def test_claude_counts_ignore_booleans_strings_and_negatives() -> None:
    line = claude_line(inp=7)
    line["message"]["usage"].update({"output_tokens": True, "cache_read_input_tokens": "9", "cache_creation_input_tokens": -4})
    event = parse_claude_record(line)
    assert event is not None
    assert (event.input, event.output, event.cache_read, event.cache_write) == (7, 0, 0, 0)


def test_codex_uses_last_usage_and_splits_cached_input() -> None:
    event = parse_codex_record(
        codex_line(input_tokens=1000, cached_input_tokens=800, cache_write_input_tokens=50, output_tokens=40, total_tokens=1040),
        "gpt-6.1-sol",
    )
    assert event == UsageEvent(
        harness="codex",
        model="gpt-6.1-sol",
        message_id="",
        is_sidechain=False,
        input=200,
        output=40,
        cache_read=800,
        cache_write=50,
        day="2026-10-31",
    )


def test_codex_total_only_is_kept_as_input() -> None:
    event = parse_codex_record(codex_line(input_tokens=0, cached_input_tokens=0, output_tokens=0, total_tokens=17590), "m")
    assert event is not None
    assert (event.input, event.output, event.cache_read, event.total_only) == (17590, 0, 0, True)


def test_codex_skips_other_records_and_null_info() -> None:
    assert parse_codex_record({"type": "event_msg", "payload": {"type": "token_count", "info": None}}, "m") is None
    assert parse_codex_record({"type": "turn_context", "payload": {"model": "x"}}, "m") is None
    assert parse_codex_record(codex_line(total_tokens=0), "m") is None


def test_codex_cached_input_exceeding_input_clamps_uncached_to_zero() -> None:
    event = parse_codex_record(codex_line(input_tokens=100, cached_input_tokens=250, output_tokens=10), "m")
    assert event is not None
    assert event.input == 0
    assert event.cache_read == 250


def test_codex_model_comes_from_turn_context() -> None:
    assert codex_model_from_record({"type": "turn_context", "payload": {"model": "GPT-6.1-Sol"}}) == "gpt-6.1-sol"
    assert codex_model_from_record({"type": "event_msg", "payload": {"model": "x"}}) is None


def test_codex_total_counts_extracts_tuple_and_handles_invalid_records() -> None:
    valid = {
        "type": "event_msg",
        "payload": {
            "type": "token_count",
            "info": {
                "total_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 40,
                    "output_tokens": 25,
                    "reasoning_output_tokens": True,
                    "total_tokens": -5,
                }
            },
        },
    }
    assert codex_total_counts(valid) == [100, 40, 25, 0, 0]
    assert codex_total_counts({"type": "turn_context", "payload": {}}) is None
    assert codex_total_counts({"type": "event_msg", "payload": {"type": "other"}}) is None
    assert codex_total_counts({"type": "event_msg", "payload": {"type": "token_count", "info": None}}) is None
    assert codex_total_counts({"type": "event_msg", "payload": {"type": "token_count", "info": {"total_token_usage": []}}}) is None


def test_antigravity_model_from_record_parses_settings_change() -> None:
    assert (
        antigravity_model_from_record(
            {
                "type": "USER_INPUT",
                "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Carbon (Medium). Do not comment.\n</USER_SETTINGS_CHANGE>",
            }
        )
        == "gemini4carbonmedium"
    )
    assert (
        antigravity_model_from_record(
            {
                "type": "USER_INPUT",
                "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from Gemini to Auto.\n</USER_SETTINGS_CHANGE>",
            }
        )
        is None
    )
    assert antigravity_model_from_record({"type": "USER_INPUT", "content": "plain message"}) is None
    assert antigravity_model_from_record({"type": "USER_INPUT", "content": "<USER_SETTINGS_CHANGE>other</USER_SETTINGS_CHANGE>"}) is None
    assert antigravity_model_from_record({"type": "PLANNER_RESPONSE", "content": "<USER_SETTINGS_CHANGE>"}) is None


def test_antigravity_planner_response_with_usage() -> None:
    record = {"type": "PLANNER_RESPONSE", "step_index": 4, "input_tokens": 5052, "output_tokens": 397, "cache_read_tokens": 34422}
    assert parse_antigravity_record(record, "unknown") == UsageEvent(
        harness="antigravity",
        model="unknown",
        message_id="",
        is_sidechain=False,
        input=5052,
        output=397,
        cache_read=34422,
        cache_write=0,
        day="",
    )


def test_antigravity_record_prefers_explicit_non_auto_model_and_parses_created_at() -> None:
    record = {
        "type": "PLANNER_RESPONSE",
        "model": "auto",
        "modelName": "Claude Sonnet 4.6",
        "created_at": "bad",
        "createdAt": "2026-11-09T01:00:00+02:00",
        "input_tokens": 10,
        "output_tokens": 5,
    }
    event = parse_antigravity_record(record, "fallback-model")
    assert event is not None
    assert event.model == "claudesonnet4.6"
    assert event.day == "2026-11-08"


def test_antigravity_without_usage_or_other_type_is_skipped() -> None:
    assert parse_antigravity_record({"type": "PLANNER_RESPONSE", "step_index": 2}, "m") is None
    assert parse_antigravity_record({"type": "GENERIC", "input_tokens": 5}, "m") is None


def test_cursor_estimate_is_text_bytes_over_four() -> None:
    transcript = [{"role": "user", "text": "a" * 40}, {"role": "assistant", "text": "ż" * 10}, {"role": "x"}, "junk"]
    assert estimate_cursor_tokens(transcript) == (40 + 20) // 4
    assert estimate_cursor_tokens([{"text": "🚀"}, {"text": None}, {"text": 42}]) == 1
    assert estimate_cursor_tokens([]) == 0
    assert estimate_cursor_tokens({"not": "a list"}) == 0


def test_parsers_handle_malformed_nested_types_and_model_fallbacks() -> None:
    claude_with_junk_iters = {
        "type": "assistant",
        "isSidechain": "true",
        "message": {
            "id": None,
            "model": 123,
            "usage": {"input_tokens": 0, "iterations": ["junk", None, {"input_tokens": 4, "output_tokens": 2}]},
        },
    }
    assert parse_claude_record(claude_with_junk_iters) == UsageEvent(
        harness="claude",
        model="unknown",
        message_id="",
        is_sidechain=False,
        input=4,
        output=2,
        cache_read=0,
        cache_write=0,
        day="",
    )
    assert parse_claude_record({"type": "assistant", "message": {"usage": {"input_tokens": 0, "iterations": "bad"}}}) is None
    assert parse_claude_record({"type": "assistant", "message": {"usage": None}}) is None

    assert parse_codex_record({"type": "event_msg", "payload": []}, "m") is None
    assert parse_codex_record({"type": "event_msg", "payload": {"type": "token_count", "info": {"last_token_usage": []}}}, "m") is None
    assert parse_codex_record({"type": "event_msg", "payload": {"type": "token_count", "info": {"last_token_usage": {"total_tokens": True}}}}, "m") is None
    assert parse_codex_record(codex_line(cache_write_input_tokens=15), "m") == UsageEvent(
        harness="codex",
        model="m",
        message_id="",
        is_sidechain=False,
        input=0,
        output=0,
        cache_read=0,
        cache_write=15,
        day="2026-10-31",
    )

    assert antigravity_model_from_record({"type": "USER_INPUT", "content": None}) is None
    ag_fallback = parse_antigravity_record(
        {
            "type": "PLANNER_RESPONSE",
            "created_at": 123,
            "createdAt": "2026-11-09T01:00:00+02:00",
            "model": "   ",
            "modelName": "???",
            "model_name": "Gemini 4 Argon",
            "cache_read_tokens": 50,
        },
        "fallback",
    )
    assert ag_fallback == UsageEvent(
        harness="antigravity",
        model="gemini4argon",
        message_id="",
        is_sidechain=False,
        input=0,
        output=0,
        cache_read=50,
        cache_write=0,
        day="2026-11-08",
    )
    ag_synth = parse_antigravity_record({"type": "PLANNER_RESPONSE", "model": " <synthetic>", "input_tokens": 5}, "fallback")
    assert ag_synth is not None and ag_synth.model == "fallback"
