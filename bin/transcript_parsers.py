"""Stateless harness transcript record parsers and UTC day normalizer for Claude, Codex, Antigravity, and Cursor."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from hooks.model_identity import (  # noqa: E402
    UNKNOWN_MODEL,
    extract_antigravity_model_change,
    normalize_model_label,
)

__all__ = [
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
]

_CODEX_TOTAL_COUNTS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "total_tokens",
)
_ISO_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:(Z)|([+-])(\d{2}):?(\d{2}))?)?$"
)


@dataclass(frozen=True)
class UsageEvent:
    """Token counts of one model call; `input` is uncached input, `total_only` marks a call reported only as a total."""

    harness: str
    model: str
    message_id: str
    is_sidechain: bool
    input: int
    output: int
    cache_read: int
    cache_write: int
    day: str
    total_only: bool = False


def nonneg_int(value: Any) -> int:
    """A non-negative token count; booleans, strings and negatives count as 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def parse_utc_day(timestamp: Any) -> str:
    """`YYYY-MM-DD` in UTC from an ISO-8601 timestamp (supporting Z, ±HH:MM, ±HHMM, fractional seconds), or ''."""
    if not isinstance(timestamp, str):
        return ""
    s = timestamp.strip()
    m = _ISO_TS_RE.match(s)
    if not m:
        return ""
    date_part, hh, mm, ss, z_flag, sign, off_h, off_m = m.groups()
    try:
        d_obj = date.fromisoformat(date_part)
        if hh is None:
            return d_obj.isoformat()
        if z_flag or not sign:
            tz = timezone.utc
        else:
            delta = timedelta(hours=int(off_h), minutes=int(off_m))
            tz = timezone(delta if sign == "+" else -delta)
        dt = datetime(d_obj.year, d_obj.month, d_obj.day, int(hh), int(mm), int(ss), tzinfo=tz)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")
    except ValueError:
        return ""


def _claude_tuple(source: dict[str, Any]) -> tuple[int, int, int, int]:
    return (
        nonneg_int(source.get("input_tokens")),
        nonneg_int(source.get("output_tokens")),
        nonneg_int(source.get("cache_read_input_tokens")),
        nonneg_int(source.get("cache_creation_input_tokens")),
    )


def _claude_counts(usage: dict[str, Any]) -> tuple[int, int, int, int]:
    """Top-level usage, or the sum of `iterations[]` when every top-level count is 0."""
    top = _claude_tuple(usage)
    if any(top):
        return top
    iterations = usage.get("iterations")
    parts = [_claude_tuple(item) for item in (iterations if isinstance(iterations, list) else []) if isinstance(item, dict)]
    return (
        sum(part[0] for part in parts),
        sum(part[1] for part in parts),
        sum(part[2] for part in parts),
        sum(part[3] for part in parts),
    )


def parse_claude_record(record: dict[str, Any]) -> UsageEvent | None:
    """An `assistant` line with non-zero `message.usage`; placeholder models such as `<synthetic>` report as unknown."""
    if record.get("type") != "assistant":
        return None
    message = record.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("usage"), dict):
        return None
    inp, out, read, write = _claude_counts(message["usage"])
    if not (inp or out or read or write):
        return None
    raw_model = message.get("model")
    model = normalize_model_label(raw_model) if isinstance(raw_model, str) and not raw_model.startswith("<") else UNKNOWN_MODEL
    return UsageEvent(
        harness="claude",
        model=model,
        message_id=str(message.get("id") or ""),
        is_sidechain=record.get("isSidechain") is True,
        input=inp,
        output=out,
        cache_read=read,
        cache_write=write,
        day=parse_utc_day(record.get("timestamp")),
    )


def codex_model_from_record(record: dict[str, Any]) -> str | None:
    """`payload.model` of a `turn_context` record, normalised; None for any other record."""
    payload = record.get("payload")
    if record.get("type") == "turn_context" and isinstance(payload, dict) and isinstance(payload.get("model"), str):
        return normalize_model_label(payload["model"])
    return None


def codex_total_counts(record: dict[str, Any]) -> list[int] | None:
    """The counts of a `token_count` event's cumulative `total_token_usage`, used only to spot a repeated event."""
    payload = record.get("payload")
    if record.get("type") != "event_msg" or not isinstance(payload, dict) or payload.get("type") != "token_count":
        return None
    info = payload.get("info")
    total = info.get("total_token_usage") if isinstance(info, dict) else None
    if not isinstance(total, dict):
        return None
    return [nonneg_int(total.get(name)) for name in _CODEX_TOTAL_COUNTS]


def parse_codex_record(record: dict[str, Any], model: str) -> UsageEvent | None:
    """A `token_count` event, counted from `last_token_usage` (the cumulative total would double count).

    OpenAI reports cached tokens inside `input_tokens`, so uncached input is the difference. Some
    Codex builds fill only `total_tokens`; such a call is kept as input with `total_only=True`.
    """
    payload = record.get("payload")
    if record.get("type") != "event_msg" or not isinstance(payload, dict) or payload.get("type") != "token_count":
        return None
    info = payload.get("info")
    last = info.get("last_token_usage") if isinstance(info, dict) else None
    if not isinstance(last, dict):
        return None
    inp = nonneg_int(last.get("input_tokens"))
    cached = nonneg_int(last.get("cached_input_tokens"))
    write = nonneg_int(last.get("cache_write_input_tokens"))
    out = nonneg_int(last.get("output_tokens"))
    day = parse_utc_day(record.get("timestamp"))
    if inp or cached or write or out:
        return UsageEvent(
            harness="codex",
            model=model,
            message_id="",
            is_sidechain=False,
            input=max(0, inp - cached),
            output=out,
            cache_read=cached,
            cache_write=write,
            day=day,
        )
    total = nonneg_int(last.get("total_tokens"))
    if not total:
        return None
    return UsageEvent(
        harness="codex",
        model=model,
        message_id="",
        is_sidechain=False,
        input=total,
        output=0,
        cache_read=0,
        cache_write=0,
        day=day,
        total_only=True,
    )


def antigravity_model_from_record(record: dict[str, Any]) -> str | None:
    """Extract normalized model slug from Antigravity `USER_INPUT` `<USER_SETTINGS_CHANGE>` text."""
    if record.get("type") != "USER_INPUT":
        return None
    return extract_antigravity_model_change(str(record.get("content") or ""))


def parse_antigravity_record(record: dict[str, Any], model: str) -> UsageEvent | None:
    """A `PLANNER_RESPONSE` step that carries usage; extracts UTC day and per-record model when present."""
    if record.get("type") != "PLANNER_RESPONSE":
        return None
    inp = nonneg_int(record.get("input_tokens"))
    out = nonneg_int(record.get("output_tokens"))
    read = nonneg_int(record.get("cache_read_tokens"))
    if not (inp or out or read):
        return None
    day = parse_utc_day(record.get("created_at")) or parse_utc_day(record.get("createdAt"))
    rec_model = model
    for key in ("model", "modelName", "model_name"):
        raw_m = record.get(key)
        if isinstance(raw_m, str) and raw_m.strip() and not raw_m.strip().startswith("<"):
            norm_m = normalize_model_label(raw_m)
            if norm_m not in (UNKNOWN_MODEL, "auto"):
                rec_model = norm_m
                break
    return UsageEvent(
        harness="antigravity",
        model=rec_model,
        message_id="",
        is_sidechain=False,
        input=inp,
        output=out,
        cache_read=read,
        cache_write=0,
        day=day,
    )


def estimate_cursor_tokens(transcript: Any) -> int:
    """Bytes / 4 of every message `text` in a Cursor agent transcript (a JSON array); Cursor records no usage."""
    if not isinstance(transcript, list):
        return 0
    total = sum(
        len(item["text"].encode("utf-8"))
        for item in transcript
        if isinstance(item, dict) and isinstance(item.get("text"), str)
    )
    return total // 4
