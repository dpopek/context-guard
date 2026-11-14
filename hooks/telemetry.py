"""Atomic token savings telemetry ledger for Context-Guard."""

from __future__ import annotations

import itertools
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, NamedTuple

fcntl: Any
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    from hooks import file_io as fcntl

from hooks.shell_output import BUCKETS, Measurement
from hooks.state_store import resolve_plugin_root, warn

MAX_SINGLE_READ_BYTES = 46080
ANTIGRAVITY_READ_MAX_LINES = 800
ANTIGRAVITY_READ_MAX_BYTES = 46_080
CLAUDE_CURSOR_READ_MAX_LINES = 2_000
CLAUDE_CURSOR_MAX_SLICE_BYTES = 80_000
# Claude rejects a Read above 25k tokens; dense code reaches that near 60 KB, so a larger
# slice is never recorded as delivered (byte accounting keeps the 80 KB cap).
CLAUDE_COVERAGE_MAX_SLICE_BYTES = 60_000
CODEX_SHELL_READ_MAX_LINES = 2_000
CODEX_SHELL_MAX_SLICE_BYTES = 100_000

HARNESS_READ_CAPS: dict[str, tuple[int, int]] = {
    "antigravity": (ANTIGRAVITY_READ_MAX_LINES, ANTIGRAVITY_READ_MAX_BYTES),
    "claude": (CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES),
    "cursor": (CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES),
    "codex": (CODEX_SHELL_READ_MAX_LINES, CODEX_SHELL_MAX_SLICE_BYTES),
}


def cap_end_line_for_harness(harness: str, start_line: int, end_line: int) -> int:
    """Clamp `end_line` to the maximum single-call line span delivered by `harness`."""
    max_lines, _ = HARNESS_READ_CAPS.get(harness, (CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES))
    line_cap_end = max(1, start_line) + max_lines - 1
    return line_cap_end if (end_line == -1 or end_line > line_cap_end) else end_line


DEFAULT_TELEMETRY_PATH = resolve_plugin_root() / "telemetry" / "stats.json"

_EVENT_KEYS = (
    "allowed_reads", "outlines", "wide_followup_blocks", "wide_followup_retries", "multi_file_blocks",
    "multi_file_retries", "rereads_blocked", "ranges_trimmed", "cli_rewrites", "mcp_guards",
    "credit_reversals", "outline_pulls",
)
_HARNESS_KEYS = ("antigravity", "claude", "cursor", "codex")


class Credit(NamedTuple):
    """Bytes one telemetry event added to the ledger, so a later reversal can take them back."""

    baseline_bytes: int
    saved_bytes: int


NO_CREDIT = Credit(0, 0)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _as_int(value: Any) -> int:
    """Coerce a ledger field that may have been hand-edited or corrupted; anything non-numeric counts as 0."""
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError, OverflowError):
            return 0


def _as_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _default_stats_dict(installed_at: str | None = None) -> dict[str, Any]:
    now_str = installed_at or now_iso()
    return {
        "installed_at": now_str,
        "updated_at": now_str,
        "baseline_bytes": 0,
        "saved_bytes": 0,
        "baseline_tokens": 0,
        "saved_tokens": 0,
        "reduction_pct": 0.0,
        "events": {k: 0 for k in _EVENT_KEYS},
        "by_harness": {
            h: {"baseline_tokens": 0, "saved_tokens": 0, "hits": 0}
            for h in _HARNESS_KEYS
        },
        "by_day": {},
        "daily_ledger_started_at": None,
    }


def estimate_slice_bytes(
    file_path: str,
    start_line: int,
    end_line: int,
    byte_cap: int = MAX_SINGLE_READ_BYTES,
) -> int:
    """Stream-estimate byte size of requested [start_line, end_line] slice capped at `byte_cap`."""
    measured = measure_slice_bytes(file_path, start_line, end_line, byte_cap=byte_cap)
    return measured if measured is not None else 0


def measure_slice_bytes(
    file_path: str,
    start_line: int,
    end_line: int,
    byte_cap: int = 100_001,
) -> int | None:
    """Stream-measure byte size of [start_line, end_line] capped at `byte_cap`; None if missing/unreadable."""
    try:
        canon = os.path.realpath(file_path)
        if not os.path.isfile(canon):
            return None
        if start_line <= 1 and end_line == -1:
            return min(byte_cap, max(0, os.path.getsize(canon)))

        s_idx = max(0, start_line - 1)
        stop_idx = None if end_line == -1 else max(s_idx, end_line)
        total = 0
        with open(canon, "rb") as fh:
            for line in itertools.islice(fh, s_idx, stop_idx):
                total += len(line)
                if total >= byte_cap:
                    return byte_cap
        return total
    except OSError:
        return None


BINARY_MEDIA_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff", ".tif", ".avif",
        ".pdf",
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
        ".mp3", ".wav", ".ogg", ".flac", ".m4a", ".mp4", ".mov", ".avi", ".mkv", ".webm",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".wasm", ".class", ".jar", ".bin",
    }
)


SHELL_COUNTER_KEYS = (
    "count", "ok", "fail", "unknown", "tokens", "max_tokens", "spilled", "spilled_tokens", "sim_hits", "sim_saved_tokens",
)
SHELL_OUTCOMES = ("ok", "fail", "unknown")


def _normalise_shell_family(raw: Any) -> dict[str, Any]:
    src = raw if isinstance(raw, dict) else {}
    entry: dict[str, Any] = {key: _as_int(src.get(key)) for key in SHELL_COUNTER_KEYS}
    raw_buckets = src.get("buckets")
    buckets = raw_buckets if isinstance(raw_buckets, dict) else {}
    entry["buckets"] = {b: _as_int(buckets.get(b)) for b in BUCKETS}
    return entry


def _normalise_shell_output(raw: Any) -> dict[str, Any] | None:
    """Coerce the shell-output section of the ledger; None when the ledger has none."""
    if not isinstance(raw, dict):
        return None
    harnesses = raw.get("harnesses")
    return {
        "since": raw["since"] if isinstance(raw.get("since"), str) else "",
        "unparsed": _as_int(raw.get("unparsed")),
        "harnesses": (
            {
                str(h): {str(f): _normalise_shell_family(v) for f, v in families.items()}
                for h, families in harnesses.items()
                if isinstance(families, dict)
            }
            if isinstance(harnesses, dict)
            else {}
        ),
    }


def apply_shell_output(
    state: dict[str, Any], harness: str, family: str, measurement: Measurement | None, outcome: str
) -> None:
    """Count one shell call; `measurement` None means its output was not found in the payload."""
    section = state.setdefault("shell_output", {"since": "", "unparsed": 0, "harnesses": {}})
    if not section.get("since"):
        section["since"] = state["updated_at"]
    families = section.setdefault("harnesses", {}).setdefault(harness, {})
    entry = families.get(family) or _normalise_shell_family(None)
    families[family] = entry
    entry["count"] += 1
    entry[outcome if outcome in SHELL_OUTCOMES else "unknown"] += 1
    if measurement is None:
        section["unparsed"] = int(section.get("unparsed") or 0) + 1
        return
    # `tokens` and `max_tokens` are what reached the agent's context; a spilled output counts as its preview.
    entry["tokens"] += measurement.context_tokens
    entry["max_tokens"] = max(entry["max_tokens"], measurement.context_tokens)
    entry["buckets"][measurement.bucket] += 1
    if measurement.spilled:
        entry["spilled"] += 1
        entry["spilled_tokens"] += measurement.tokens
    if measurement.sim_hit:
        entry["sim_hits"] += 1
        entry["sim_saved_tokens"] += measurement.sim_saved_tokens


def _normalise_stats(raw: Any) -> dict[str, Any]:
    """Build a fully typed stats dict from whatever the ledger file held; every field is coerced, never trusted."""
    base = _default_stats_dict()
    if not isinstance(raw, dict):
        return base
    for key in ("installed_at", "updated_at"):
        if isinstance(raw.get(key), str) and raw[key]:
            base[key] = raw[key]
    for key in ("baseline_bytes", "saved_bytes", "baseline_tokens", "saved_tokens"):
        if key in raw:
            base[key] = _as_int(raw[key])
    if "reduction_pct" in raw:
        base["reduction_pct"] = _as_float(raw["reduction_pct"])
    events = raw.get("events")
    if isinstance(events, dict):
        for k in _EVENT_KEYS:
            base["events"][k] = _as_int(events.get(k))
    by_harness = raw.get("by_harness")
    if isinstance(by_harness, dict):
        for h, h_val in by_harness.items():
            if isinstance(h_val, dict):
                base["by_harness"][h] = {
                    "baseline_tokens": _as_int(h_val.get("baseline_tokens")),
                    "saved_tokens": _as_int(h_val.get("saved_tokens")),
                    "hits": _as_int(h_val.get("hits")),
                }
    by_harness_bytes = raw.get("by_harness_bytes")
    if isinstance(by_harness_bytes, dict):
        norm_hb: dict[str, dict[str, int]] = {}
        for h, hb_val in by_harness_bytes.items():
            if isinstance(h, str) and isinstance(hb_val, dict):
                norm_hb[h] = {
                    "baseline_bytes": max(0, _as_int(hb_val.get("baseline_bytes"))),
                    "saved_bytes": max(0, _as_int(hb_val.get("saved_bytes"))),
                }
        if norm_hb:
            base["by_harness_bytes"] = norm_hb
    if isinstance(raw.get("last_event"), dict):
        base["last_event"] = raw["last_event"]
    shell_output = _normalise_shell_output(raw.get("shell_output"))
    if shell_output is not None:
        base["shell_output"] = shell_output
    raw_by_day = raw.get("by_day")
    norm_by_day: dict[str, dict[str, int]] = {}
    if isinstance(raw_by_day, dict):
        for d_key, d_val in raw_by_day.items():
            if isinstance(d_key, str) and len(d_key) == 10 and isinstance(d_val, dict):
                norm_by_day[d_key] = {
                    "baseline_bytes": _as_int(d_val.get("baseline_bytes")),
                    "saved_bytes": _as_int(d_val.get("saved_bytes")),
                }
    raw_started = raw.get("daily_ledger_started_at")
    if norm_by_day:
        base["by_day"] = norm_by_day
        base["daily_ledger_started_at"] = (
            raw_started
            if isinstance(raw_started, str) and len(raw_started) == 10
            else min(norm_by_day.keys())
        )
    elif "by_day" not in raw and (base["baseline_bytes"] > 0 or base["saved_bytes"] > 0):
        inst_day = str(base["installed_at"])[:10]
        upd_day = str(base["updated_at"])[:10]
        if len(inst_day) == 10 and inst_day == upd_day:
            base["by_day"] = {
                inst_day: {
                    "baseline_bytes": base["baseline_bytes"],
                    "saved_bytes": base["saved_bytes"],
                }
            }
            base["daily_ledger_started_at"] = inst_day
    return base


def load_telemetry_stats(stats_path: Path | None = None) -> dict[str, Any]:
    """Read and return normalized telemetry stats dictionary (safe defaults if file does not exist yet)."""
    target = stats_path or DEFAULT_TELEMETRY_PATH
    if not target.is_file():
        return _default_stats_dict()
    try:
        raw: Any = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _default_stats_dict()
    return _normalise_stats(raw)


def read_json_object_or_quarantine(target: Path) -> dict[str, Any] | None:
    """Load a JSON-object ledger for an in-place update.

    Returns None when the file does not exist. A file that is not a JSON object is moved
    aside as `<name>.corrupt-<UTC stamp>` (never overwritten) and None is returned, so the
    caller starts a fresh ledger without losing the evidence.
    """
    if not target.is_file():
        return None
    try:
        raw: Any = json.loads(target.read_text(encoding="utf-8"))
    except ValueError:
        raw = None
    if isinstance(raw, dict):
        return raw
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    quarantine = target.with_name(f"{target.name}.corrupt-{stamp}")
    os.replace(target, quarantine)
    warn(f"telemetry ledger {target} was not a JSON object; moved to {quarantine}")
    return None


def write_json_atomic(target: Path, payload: dict[str, Any], prefix: str) -> None:
    """Write `payload` as indented JSON via mkstemp + os.replace; re-raises OSError after removing the temp file."""
    fd, tmp_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        os.replace(tmp_path, str(target))
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _read_ledger_for_update(target: Path) -> dict[str, Any]:
    """Load stats.json for an in-place update; a corrupt file is quarantined, not overwritten."""
    raw = read_json_object_or_quarantine(target)
    return _normalise_stats(raw) if raw is not None else _default_stats_dict()


def record_telemetry_event(
    harness: str,
    event_kind: str,
    baseline_bytes: int,
    saved_bytes: int,
    stats_path: Path | None = None,
    target_day: str | None = None,
) -> Credit:
    """Best-effort ledger update that never raises; returns the bytes credited (NO_CREDIT if unwritten)."""
    try:
        if event_kind == "credit_reversals" and (int(baseline_bytes) < 0 or int(saved_bytes) < 0):
            b_bytes = min(0, int(baseline_bytes))
            s_bytes = max(b_bytes, min(0, int(saved_bytes)))
        else:
            b_bytes = max(0, int(baseline_bytes))
            s_bytes = min(b_bytes, max(0, int(saved_bytes)))
        written = _record_telemetry_event(
            harness, event_kind, b_bytes, s_bytes, stats_path, target_day
        )
    except Exception as exc:  # noqa: BLE001 - telemetry is best-effort by contract
        warn(f"telemetry event {event_kind!r} skipped: {type(exc).__name__}: {exc}")
        return NO_CREDIT
    return Credit(max(0, b_bytes), max(0, s_bytes)) if written else NO_CREDIT


def record_telemetry_count(harness: str, event_kind: str, stats_path: Path | None = None) -> None:
    """Count an intervention whose effect on output size PreToolUse cannot see; credits no bytes."""
    record_telemetry_event(harness, event_kind, 0, 0, stats_path)


def record_shell_output(
    harness: str,
    family: str,
    measurement: Measurement | None,
    outcome: str,
    stats_path: Path | None = None,
) -> None:
    """Count one shell call under its harness and command family; never raises.

    Only the family and numbers are stored, never the command or its output. Savings totals,
    events and `by_harness` are not touched.
    """
    try:
        _update_ledger(
            stats_path,
            lambda state: apply_shell_output(state, harness, family, measurement, outcome),
        )
    except Exception as exc:  # noqa: BLE001 - telemetry is best-effort by contract
        warn(f"shell output telemetry skipped: {type(exc).__name__}")


def _update_ledger(stats_path: Path | None, mutate: Callable[[dict[str, Any]], None]) -> bool:
    """Apply `mutate` to stats.json under fcntl.flock and write it atomically. True when written."""
    target = stats_path or DEFAULT_TELEMETRY_PATH
    lock_path = target.with_suffix(".lock")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "a+", encoding="utf-8") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                state = _read_ledger_for_update(target)
                state["updated_at"] = now_iso()
                mutate(state)
                write_json_atomic(target, state, prefix=".stats.")
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        return False
    return True


def _record_telemetry_event(
    harness: str,
    event_kind: str,
    baseline_delta: int,
    saved_delta: int,
    stats_path: Path | None,
    target_day: str | None = None,
) -> bool:
    """Apply signed byte deltas to stats.json; totals never go below zero. True when written."""

    def apply(state: dict[str, Any]) -> None:
        prev_baseline = int(state.get("baseline_bytes") or 0)
        prev_saved = int(state.get("saved_bytes") or 0)
        state["baseline_bytes"] = max(0, prev_baseline + baseline_delta)
        state["saved_bytes"] = min(
            state["baseline_bytes"],
            max(0, prev_saved + saved_delta),
        )
        eff_baseline_delta = state["baseline_bytes"] - prev_baseline
        eff_saved_delta = state["saved_bytes"] - prev_saved
        state["baseline_tokens"] = state["baseline_bytes"] // 4
        state["saved_tokens"] = state["saved_bytes"] // 4
        state["reduction_pct"] = (
            min(100.0, round((state["saved_bytes"] / state["baseline_bytes"]) * 100.0, 1))
            if state["baseline_bytes"] > 0
            else 0.0
        )

        by_day = state.setdefault("by_day", {})
        if not isinstance(by_day, dict):
            by_day = {}
            state["by_day"] = by_day
        utc_day = str(state.get("updated_at") or now_iso())[:10]
        if event_kind == "credit_reversals":
            day_key = target_day if (target_day and target_day in by_day) else utc_day
        else:
            day_key = (
                target_day
                if (isinstance(target_day, str) and len(target_day) == 10)
                else utc_day
            )
        day_entry = by_day.setdefault(day_key, {"baseline_bytes": 0, "saved_bytes": 0})
        day_entry["baseline_bytes"] = _as_int(day_entry.get("baseline_bytes")) + eff_baseline_delta
        day_entry["saved_bytes"] = _as_int(day_entry.get("saved_bytes")) + eff_saved_delta
        if not state.get("daily_ledger_started_at"):
            state["daily_ledger_started_at"] = day_key

        events_map = state.setdefault("events", {})
        events_map[event_kind] = int(events_map.get(event_kind) or 0) + 1

        by_h = state.setdefault("by_harness", {})
        h_entry = by_h.setdefault(harness, {"baseline_tokens": 0, "saved_tokens": 0, "hits": 0})
        by_hb = state.setdefault("by_harness_bytes", {})
        if not isinstance(by_hb, dict):
            by_hb = {}
            state["by_harness_bytes"] = by_hb
        hb_entry = by_hb.get(harness)
        if not isinstance(hb_entry, dict):
            hb_entry = {
                "baseline_bytes": max(0, _as_int(h_entry.get("baseline_tokens"))) * 4,
                "saved_bytes": max(0, _as_int(h_entry.get("saved_tokens"))) * 4,
            }
            by_hb[harness] = hb_entry
        hb_entry["baseline_bytes"] = max(0, _as_int(hb_entry.get("baseline_bytes")) + baseline_delta)
        hb_entry["saved_bytes"] = min(
            hb_entry["baseline_bytes"],
            max(0, _as_int(hb_entry.get("saved_bytes")) + saved_delta),
        )
        h_entry["baseline_tokens"] = hb_entry["baseline_bytes"] // 4
        h_entry["saved_tokens"] = hb_entry["saved_bytes"] // 4
        if saved_delta > 0:
            h_entry["hits"] = int(h_entry.get("hits") or 0) + 1
            state["last_event"] = {
                "kind": event_kind,
                "saved_tokens": saved_delta // 4,
                "harness": harness,
                "timestamp": state["updated_at"],
            }
        elif event_kind == "credit_reversals" and saved_delta < 0:
            h_entry["hits"] = max(0, int(h_entry.get("hits") or 0) - 1)
            state.pop("last_event", None)

    return _update_ledger(stats_path, apply)


_DENY_EVENT_BY_INTERVENTION = {"outline": "outlines"}


def record_file_read_outcome(
    harness: str, raw_path: str, start_line: int, end_line: int, decision: dict[str, Any],
    intervention: str | None, stats_path: Path | None = None, byte_offset: int = 0,
) -> Credit:
    """Best-effort classification of a read decision into a telemetry event; never raises."""
    try:
        return _record_file_read_outcome(harness, raw_path, start_line, end_line, decision, intervention, stats_path, byte_offset)
    except Exception as exc:  # noqa: BLE001 - telemetry is best-effort by contract
        warn(f"telemetry for {raw_path!r} skipped: {type(exc).__name__}: {exc}")
        return NO_CREDIT


def _record_file_read_outcome(
    harness: str, raw_path: str, start_line: int, end_line: int, decision: dict[str, Any],
    intervention: str | None, stats_path: Path | None, byte_offset: int = 0,
) -> Credit:
    """Record the telemetry event for a read decision; `intervention` names what the verdict did."""
    ext_low = Path(raw_path).suffix.lower()
    verdict = decision.get("decision", "allow")
    if ext_low in BINARY_MEDIA_EXTENSIONS:
        if verdict == "deny" or not os.path.isfile(os.path.realpath(raw_path)):
            return NO_CREDIT
        return record_telemetry_event(harness, "allowed_reads", 0, 0, stats_path=stats_path)

    _, max_bytes = HARNESS_READ_CAPS.get(harness, (CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES))
    capped_end = cap_end_line_for_harness(harness, start_line, end_line)
    if byte_offset > 0:
        total_slice = estimate_slice_bytes(raw_path, start_line, capped_end, byte_cap=byte_offset + max_bytes)
        req_bytes = min(max_bytes, max(0, total_slice - byte_offset))
        if req_bytes <= 0:
            return NO_CREDIT
        if verdict != "deny":
            return record_telemetry_event(harness, "allowed_reads", req_bytes, 0, stats_path=stats_path)
    else:
        req_bytes = estimate_slice_bytes(raw_path, start_line, capped_end, byte_cap=max_bytes)
        if req_bytes <= 0:
            return NO_CREDIT

    if verdict == "deny":
        kind = _DENY_EVENT_BY_INTERVENTION.get(intervention or "")
        if kind is None:
            return NO_CREDIT
        reason_bytes = len(str(decision.get("reason") or "").encode("utf-8", errors="ignore"))
        baseline_b = max(
            req_bytes,
            estimate_slice_bytes(raw_path, 1, cap_end_line_for_harness(harness, 1, -1), byte_cap=max_bytes),
        )
        return record_telemetry_event(harness, kind, baseline_b, max(0, baseline_b - reason_bytes), stats_path=stats_path)

    ov = decision.get("overwrite")
    if isinstance(ov, dict) and ov:
        target_path = str(ov.get("Path") or ov.get("AbsolutePath") or raw_path)
        raw_new_s = ov.get("StartLine")
        raw_new_e = ov.get("EndLine")
        new_s = int(raw_new_s) if raw_new_s is not None else start_line
        new_e = int(raw_new_e) if raw_new_e is not None else end_line
        trimmed_bytes = estimate_slice_bytes(target_path, new_s, cap_end_line_for_harness(harness, new_s, new_e), byte_cap=max_bytes)
        if trimmed_bytes < req_bytes or raw_new_s is not None or raw_new_e is not None:
            return record_telemetry_event(harness, "ranges_trimmed", req_bytes, max(0, req_bytes - trimmed_bytes), stats_path=stats_path)

    return record_telemetry_event(harness, "allowed_reads", req_bytes, 0, stats_path=stats_path)
