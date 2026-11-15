"""Atomic token savings telemetry ledger for Context-Guard."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, NamedTuple

fcntl: Any
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    from hooks import file_io as fcntl

from hooks.shell_output import BUCKETS, Measurement
from hooks.state_store import resolve_plugin_root, warn

MAX_SINGLE_READ_BYTES = 46080
ANTIGRAVITY_READ_MAX_LINES, ANTIGRAVITY_READ_MAX_BYTES = 800, 46_080
CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES = 2_000, 80_000
# Claude rejects a Read above 25k tokens; dense code reaches that near 60 KB, so a larger
# slice is never recorded as delivered (byte accounting keeps the 80 KB cap).
CLAUDE_COVERAGE_MAX_SLICE_BYTES = 60_000
CODEX_SHELL_READ_MAX_LINES, CODEX_SHELL_MAX_SLICE_BYTES = 2_000, 100_000
HARNESS_READ_CAPS: dict[str, tuple[int, int]] = {
    "antigravity": (ANTIGRAVITY_READ_MAX_LINES, ANTIGRAVITY_READ_MAX_BYTES),
    "claude": (CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES),
    "cursor": (CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES),
    "codex": (CODEX_SHELL_READ_MAX_LINES, CODEX_SHELL_MAX_SLICE_BYTES),
}

def cap_end_line_for_harness(harness: str, start_line: int, end_line: int) -> int:
    """Clamp `end_line` to the maximum single-call line span delivered by `harness`."""
    caps = HARNESS_READ_CAPS.get(harness, (CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES))
    line_cap_end = max(1, start_line) + caps[0] - 1
    return line_cap_end if (end_line == -1 or end_line > line_cap_end) else end_line

DEFAULT_TELEMETRY_PATH = resolve_plugin_root() / "telemetry" / "stats.json"
_EVENT_KEYS = (
    "allowed_reads", "outlines", "wide_followup_blocks", "wide_followup_retries", "multi_file_blocks",
    "multi_file_retries", "rereads_blocked", "ranges_trimmed", "cli_rewrites", "mcp_guards",
    "credit_reversals", "outline_pulls", "outputs_spooled",
)
_HARNESS_KEYS = ("antigravity", "claude", "cursor", "codex")

class Credit(NamedTuple):
    """Bytes one telemetry event added to the ledger, so a later reversal can take them back."""
    baseline_bytes: int
    saved_bytes: int

NO_CREDIT = Credit(0, 0)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def coerce_int(value: Any) -> int:
    """Coerce a ledger field that may have been hand-edited or corrupted; non-numeric counts as 0."""
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError, OverflowError):
            return 0

def coerce_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0

_as_int, _as_float = coerce_int, coerce_float

def _default_stats_dict(installed_at: str | None = None) -> dict[str, Any]:
    now_str = installed_at or now_iso()
    return {
        "installed_at": now_str, "updated_at": now_str,
        "baseline_bytes": 0, "saved_bytes": 0, "baseline_tokens": 0, "saved_tokens": 0,
        "reduction_pct": 0.0, "events": {k: 0 for k in _EVENT_KEYS},
        "by_harness": {h: {"baseline_tokens": 0, "saved_tokens": 0, "hits": 0} for h in _HARNESS_KEYS},
        "by_day": {}, "daily_ledger_started_at": None,
    }

def estimate_slice_bytes(
    file_path: str, start_line: int, end_line: int, byte_cap: int = MAX_SINGLE_READ_BYTES,
) -> int:
    """Stream-estimate byte size of requested [start_line, end_line] slice capped at `byte_cap`."""
    return measure_slice_bytes(file_path, start_line, end_line, byte_cap=byte_cap) or 0

def measure_slice_bytes(
    file_path: str, start_line: int, end_line: int, byte_cap: int = 100_001,
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

BINARY_MEDIA_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff", ".tif", ".avif", ".pdf",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".mp3", ".wav", ".ogg", ".flac",
    ".m4a", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".wasm", ".class", ".jar", ".bin",
})
SHELL_COUNTER_KEYS = (
    "count", "ok", "fail", "unknown", "tokens", "max_tokens", "spilled", "spilled_tokens",
    "sim_hits", "sim_saved_tokens",
)
SHELL_OUTCOMES = ("ok", "fail", "unknown")

def _normalise_shell_family(raw: Any) -> dict[str, Any]:
    src = raw if isinstance(raw, dict) else {}
    entry: dict[str, Any] = {key: _as_int(src.get(key)) for key in SHELL_COUNTER_KEYS}
    raw_b = src.get("buckets")
    buckets = raw_b if isinstance(raw_b, dict) else {}
    entry["buckets"] = {b: _as_int(buckets.get(b)) for b in BUCKETS}
    return entry

def _normalise_shell_output(raw: Any) -> dict[str, Any] | None:
    """Coerce the shell-output section of the ledger; None when the ledger has none."""
    if not isinstance(raw, dict):
        return None
    harnesses = raw.get("harnesses")
    h_map = {str(h): {str(f): _normalise_shell_family(v) for f, v in fams.items()}
             for h, fams in harnesses.items() if isinstance(fams, dict)} if isinstance(harnesses, dict) else {}
    return {"since": raw["since"] if isinstance(raw.get("since"), str) else "",
            "unparsed": _as_int(raw.get("unparsed")), "harnesses": h_map}

def apply_shell_output(
    state: dict[str, Any], harness: str, family: str, measurement: Measurement | None, outcome: str
) -> None:
    """Count one shell call; `measurement` None means its output was not found in the payload."""
    section = state.setdefault("shell_output", {"since": "", "unparsed": 0, "harnesses": {}})
    if not section.get("since"):
        section["since"] = state["updated_at"]
    families = section.setdefault("harnesses", {}).setdefault(harness, {})
    entry = families[family] = families.get(family) or _normalise_shell_family(None)
    entry["count"] += 1
    entry[outcome if outcome in SHELL_OUTCOMES else "unknown"] += 1
    if measurement is None:
        section["unparsed"] = int(section.get("unparsed") or 0) + 1
        return
    # `tokens` and `max_tokens` track context consumption; spilled outputs count as their preview.
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
    """Build a typed stats dict from ledger data; every field is coerced, never trusted."""
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
    if isinstance(events := raw.get("events"), dict):
        base["events"] = {k: _as_int(events.get(k)) for k in _EVENT_KEYS}
    if isinstance(by_h := raw.get("by_harness"), dict):
        for h, hv in by_h.items():
            if isinstance(hv, dict):
                base["by_harness"][h] = {k: _as_int(hv.get(k)) for k in ("baseline_tokens", "saved_tokens", "hits")}
    if isinstance(by_hb := raw.get("by_harness_bytes"), dict):
        if nhb := {h: {"baseline_bytes": max(0, _as_int(v.get("baseline_bytes"))), "saved_bytes": max(0, _as_int(v.get("saved_bytes")))}
                   for h, v in by_hb.items() if isinstance(h, str) and isinstance(v, dict)}:
            base["by_harness_bytes"] = nhb
    if isinstance(raw.get("last_event"), dict):
        base["last_event"] = raw["last_event"]
    if isinstance(rei := raw.get("recent_event_ids"), list):
        base["recent_event_ids"] = [x for x in rei if isinstance(x, str)][-128:]
    if (shell_out := _normalise_shell_output(raw.get("shell_output"))) is not None:
        base["shell_output"] = shell_out
    raw_bd, raw_start = raw.get("by_day"), raw.get("daily_ledger_started_at")
    norm_bd = ({dk: {"baseline_bytes": _as_int(dv.get("baseline_bytes")), "saved_bytes": _as_int(dv.get("saved_bytes"))}
                for dk, dv in raw_bd.items() if isinstance(dk, str) and len(dk) == 10 and isinstance(dv, dict)}
               if isinstance(raw_bd, dict) else {})
    if norm_bd:
        base["by_day"] = norm_bd
        base["daily_ledger_started_at"] = raw_start if isinstance(raw_start, str) and len(raw_start) == 10 else min(norm_bd.keys())
    elif "by_day" not in raw and (base["baseline_bytes"] > 0 or base["saved_bytes"] > 0):
        inst_d, upd_d = str(base["installed_at"])[:10], str(base["updated_at"])[:10]
        if len(inst_d) == 10 and inst_d == upd_d:
            base["by_day"] = {inst_d: {"baseline_bytes": base["baseline_bytes"], "saved_bytes": base["saved_bytes"]}}
            base["daily_ledger_started_at"] = inst_d
    return base

def load_telemetry_stats(stats_path: Path | None = None) -> dict[str, Any]:
    """Read and return normalized telemetry stats dictionary (safe defaults if missing/corrupt)."""
    target = stats_path or DEFAULT_TELEMETRY_PATH
    try:
        return _normalise_stats(json.loads(target.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return _default_stats_dict()

def read_json_object_or_quarantine(target: Path) -> dict[str, Any] | None:
    """Load a JSON-object ledger for update; move non-object files aside as .corrupt-<stamp>."""
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

def write_json_atomic(
    target: Path, payload: dict[str, Any], prefix: str, mode: int | None = None,
) -> None:
    """Write `payload` as indented JSON via mkstemp + os.replace; re-raises OSError after cleanup."""
    fd, tmp_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        if mode is not None:
            os.chmod(tmp_path, mode)
        os.replace(tmp_path, str(target))
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

def record_telemetry_event(
    harness: str, event_kind: str, baseline_bytes: int, saved_bytes: int,
    stats_path: Path | None = None, target_day: str | None = None, *, event_id: str | None = None,
) -> Credit:
    """Best-effort ledger update that never raises; returns credited bytes (NO_CREDIT if unwritten)."""
    try:
        b_raw, s_raw = int(baseline_bytes), int(saved_bytes)
        if event_kind == "credit_reversals" and (b_raw < 0 or s_raw < 0):
            b_bytes, s_bytes = min(0, b_raw), max(min(0, b_raw), min(0, s_raw))
        else:
            b_bytes, s_bytes = max(0, b_raw), min(max(0, b_raw), max(0, s_raw))
        written = _record_telemetry_event(harness, event_kind, b_bytes, s_bytes, stats_path, target_day, event_id=event_id)
    except Exception as exc:  # noqa: BLE001 - telemetry is best-effort by contract
        warn(f"telemetry event {event_kind!r} skipped: {type(exc).__name__}: {exc}")
        return NO_CREDIT
    return Credit(max(0, b_bytes), max(0, s_bytes)) if written else NO_CREDIT

def record_telemetry_count(harness: str, event_kind: str, stats_path: Path | None = None) -> None:
    """Count an intervention whose effect on output size PreToolUse cannot see; credits no bytes."""
    record_telemetry_event(harness, event_kind, 0, 0, stats_path)

def record_shell_output(
    harness: str, family: str, measurement: Measurement | None, outcome: str,
    stats_path: Path | None = None,
) -> None:
    """Count one shell call under its harness and command family; never stores commands or outputs."""
    try:
        _update_ledger(stats_path, lambda st: apply_shell_output(st, harness, family, measurement, outcome))
    except Exception as exc:  # noqa: BLE001 - telemetry is best-effort by contract
        warn(f"shell output telemetry skipped: {type(exc).__name__}")

def _update_ledger(
    stats_path: Path | None, mutate: Callable[[dict[str, Any]], bool | None], *,
    normalise_fn: Callable[[Any], dict[str, Any]] | None = None,
    prefix: str = ".stats.", file_mode: int | None = None,
) -> bool:
    """Apply `mutate` to a JSON ledger under fcntl.flock and write it atomically. True when written."""
    target = stats_path or DEFAULT_TELEMETRY_PATH
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target.with_suffix(".lock"), "a+", encoding="utf-8") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                raw = read_json_object_or_quarantine(target)
                state = _normalise_stats(raw) if normalise_fn is None else normalise_fn(raw)
                state["updated_at"] = now_iso()
                if mutate(state) is False:
                    return False
                write_json_atomic(target, state, prefix=prefix, mode=file_mode)
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        return False
    return True

def _ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    if not isinstance(val := parent.get(key), dict):
        parent[key] = val = {}
    return val

def _record_telemetry_event(
    harness: str, event_kind: str, baseline_delta: int, saved_delta: int,
    stats_path: Path | None, target_day: str | None = None, *, event_id: str | None = None,
) -> bool:
    """Apply signed byte deltas to stats.json; totals never go below zero. True when written."""
    def apply(state: dict[str, Any]) -> bool | None:
        if event_id:
            raw_rec = state.get("recent_event_ids")
            rec: list[Any] = raw_rec if isinstance(raw_rec, list) else []
            dedupe_key = f"{event_kind}:{event_id}"
            if dedupe_key in rec: return False
            state["recent_event_ids"] = (rec + [dedupe_key])[-128:]
        prev_b, prev_s = int(state.get("baseline_bytes") or 0), int(state.get("saved_bytes") or 0)
        new_b = max(0, prev_b + baseline_delta)
        new_s = min(new_b, max(0, prev_s + saved_delta))
        state["baseline_bytes"], state["saved_bytes"] = new_b, new_s
        state["baseline_tokens"], state["saved_tokens"] = new_b // 4, new_s // 4
        state["reduction_pct"] = min(100.0, round((new_s / new_b) * 100.0, 1)) if new_b > 0 else 0.0
        by_day = _ensure_dict(state, "by_day")
        utc_day = str(state.get("updated_at") or now_iso())[:10]
        day_key = (target_day if (target_day and target_day in by_day) else utc_day) if event_kind == "credit_reversals" else (
            target_day if (isinstance(target_day, str) and len(target_day) == 10) else utc_day)
        day_e = by_day.setdefault(day_key, {"baseline_bytes": 0, "saved_bytes": 0})
        day_e["baseline_bytes"] = _as_int(day_e.get("baseline_bytes")) + (new_b - prev_b)
        day_e["saved_bytes"] = _as_int(day_e.get("saved_bytes")) + (new_s - prev_s)
        state.setdefault("daily_ledger_started_at", day_key)
        if not state.get("daily_ledger_started_at"):
            state["daily_ledger_started_at"] = day_key
        events_map = _ensure_dict(state, "events")
        events_map[event_kind] = int(events_map.get(event_kind) or 0) + 1
        h_e = _ensure_dict(state, "by_harness").setdefault(harness, {"baseline_tokens": 0, "saved_tokens": 0, "hits": 0})
        by_hb = _ensure_dict(state, "by_harness_bytes")
        if not isinstance(hb_e := by_hb.get(harness), dict):
            hb_e = by_hb[harness] = {"baseline_bytes": max(0, _as_int(h_e.get("baseline_tokens"))) * 4,
                                     "saved_bytes": max(0, _as_int(h_e.get("saved_tokens"))) * 4}
        hb_e["baseline_bytes"] = max(0, _as_int(hb_e.get("baseline_bytes")) + baseline_delta)
        hb_e["saved_bytes"] = min(hb_e["baseline_bytes"], max(0, _as_int(hb_e.get("saved_bytes")) + saved_delta))
        h_e["baseline_tokens"], h_e["saved_tokens"] = hb_e["baseline_bytes"] // 4, hb_e["saved_bytes"] // 4
        if saved_delta > 0:
            h_e["hits"] = int(h_e.get("hits") or 0) + 1
            state["last_event"] = {"kind": event_kind, "saved_tokens": saved_delta // 4, "harness": harness, "timestamp": state["updated_at"]}
        elif event_kind == "credit_reversals" and saved_delta < 0:
            h_e["hits"] = max(0, int(h_e.get("hits") or 0) - 1)
            state.pop("last_event", None)
        return None
    return _update_ledger(stats_path, apply)

_DENY_EVENT_BY_INTERVENTION = {"outline": "outlines"}

def record_file_read_outcome(
    harness: str, raw_path: str, start_line: int, end_line: int, decision: dict[str, Any],
    intervention: str | None, stats_path: Path | None = None, byte_offset: int = 0,
) -> Credit:
    """Best-effort classification of a read decision into a telemetry event; never raises."""
    try:
        return _record_file_read_outcome(
            harness, raw_path, start_line, end_line, decision, intervention, stats_path, byte_offset,
        )
    except Exception as exc:  # noqa: BLE001 - telemetry is best-effort by contract
        warn(f"telemetry for {raw_path!r} skipped: {type(exc).__name__}: {exc}")
        return NO_CREDIT

def _record_file_read_outcome(
    harness: str, raw_path: str, start_line: int, end_line: int, decision: dict[str, Any],
    intervention: str | None, stats_path: Path | None, byte_offset: int = 0,
) -> Credit:
    """Record the telemetry event for a read decision; `intervention` names what the verdict did."""
    verdict = decision.get("decision", "allow")
    if Path(raw_path).suffix.lower() in BINARY_MEDIA_EXTENSIONS:
        if verdict == "deny" or not os.path.isfile(os.path.realpath(raw_path)):
            return NO_CREDIT
        return record_telemetry_event(harness, "allowed_reads", 0, 0, stats_path=stats_path)
    caps = HARNESS_READ_CAPS.get(harness, (CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES))
    max_bytes = caps[1]
    capped_end = cap_end_line_for_harness(harness, start_line, end_line)
    if byte_offset > 0:
        total_slice = estimate_slice_bytes(raw_path, start_line, capped_end, byte_cap=byte_offset + max_bytes)
        req_bytes = min(max_bytes, max(0, total_slice - byte_offset))
        if req_bytes <= 0:
            return NO_CREDIT
        if verdict != "deny":
            return record_telemetry_event(harness, "allowed_reads", req_bytes, 0, stats_path=stats_path)
    elif (req_bytes := estimate_slice_bytes(raw_path, start_line, capped_end, byte_cap=max_bytes)) <= 0:
        return NO_CREDIT
    if verdict == "deny":
        if (kind := _DENY_EVENT_BY_INTERVENTION.get(intervention or "")) is None:
            return NO_CREDIT
        reason_bytes = len(str(decision.get("reason") or "").encode("utf-8", errors="ignore"))
        full_end = cap_end_line_for_harness(harness, 1, -1)
        base_b = max(req_bytes, estimate_slice_bytes(raw_path, 1, full_end, byte_cap=max_bytes))
        return record_telemetry_event(
            harness, kind, base_b, max(0, base_b - reason_bytes), stats_path=stats_path,
        )
    ov = decision.get("overwrite")
    if isinstance(ov, dict) and ov:
        t_path = str(ov.get("Path") or ov.get("AbsolutePath") or raw_path)
        raw_ns, raw_ne = ov.get("StartLine"), ov.get("EndLine")
        ns, ne = (int(raw_ns) if raw_ns is not None else start_line), (int(raw_ne) if raw_ne is not None else end_line)
        trimmed_b = estimate_slice_bytes(t_path, ns, cap_end_line_for_harness(harness, ns, ne), byte_cap=max_bytes)
        if trimmed_b < req_bytes or raw_ns is not None or raw_ne is not None:
            return record_telemetry_event(harness, "ranges_trimmed", req_bytes, max(0, req_bytes - trimmed_b), stats_path=stats_path)
    return record_telemetry_event(harness, "allowed_reads", req_bytes, 0, stats_path=stats_path)

DEFAULT_SHADOW_PATH = resolve_plugin_root() / "telemetry" / "shadow.json"
SHADOW_SCHEMA_VERSION, SHADOW_MAX_SESSIONS, SHADOW_MAX_PATHS, SHADOW_TTL_SECONDS = 1, 16, 200, 7 * 86400

def shadow_path_for(state_dir: str | Path | None) -> Path | None:
    """Return `Path(state_dir) / 'shadow.json'` when `state_dir` is set, else None."""
    return (Path(state_dir) / "shadow.json") if state_dir else None

def pseudonymize_shadow_path(canon: str) -> str:
    """Deterministic SHA-256 path pseudonymization (not keyed HMAC) for shadow.json."""
    return hashlib.sha256(f"cg-shadow-v1:{canon}".encode("utf-8")).hexdigest()[:32]

def _prune_shadow_state(state: dict[str, Any], ts: float) -> dict[str, Any]:
    raw_s, live = state.get("sessions"), []
    for sid, sess in raw_s.items() if isinstance(raw_s, dict) else ():
        if isinstance(sid, str) and isinstance(sess, dict):
            upd = float(sess.get("updated_ts", 0.0) or 0.0)
            if ts - upd <= SHADOW_TTL_SECONDS:
                paths = sess.get("paths")
                if isinstance(paths, dict) and len(paths) > SHADOW_MAX_PATHS:
                    kept = sorted(paths.items(), key=lambda kv: float(kv[1].get("updated_ts", 0.0)))
                    sess["paths"] = dict(kept[-SHADOW_MAX_PATHS:])
                live.append((upd, sid, sess))
    kept_s = sorted(live, key=lambda x: x[0])[-SHADOW_MAX_SESSIONS:]
    state["sessions"] = {sid: sess for _, sid, sess in kept_s}
    return state

def _norm_shadow_spools(raw_sp: Any) -> dict[str, Any]:
    sp = raw_sp if isinstance(raw_sp, dict) else {}
    by_h = {h: max(0, _as_int(v)) for h, v in (sp.get("by_harness") or {}).items()
            if isinstance(h, str)} if isinstance(sp.get("by_harness"), dict) else {}
    return {"count": max(0, _as_int(sp.get("count"))), "estimated_saved_bytes": max(0, _as_int(sp.get("estimated_saved_bytes"))),
            "last_ts": sp["last_ts"] if isinstance(sp.get("last_ts"), str) else None, "by_harness": by_h}

def _normalise_shadow_ledger(raw: Any, now_ts: float | None = None) -> dict[str, Any]:
    base: dict[str, Any] = {"schema_version": SHADOW_SCHEMA_VERSION, "updated_at": now_iso(), "sessions": {}}
    if not isinstance(raw, dict) or raw.get("schema_version") != SHADOW_SCHEMA_VERSION:
        return base
    if isinstance(raw.get("updated_at"), str):
        base["updated_at"] = raw["updated_at"]
    for sid, sv in (raw.get("sessions") or {}).items() if isinstance(raw.get("sessions"), dict) else ():
        if isinstance(sid, str) and isinstance(sv, dict):
            paths = {ph: {"content_sha256": str(pv.get("content_sha256") or ""),
                          "updated_ts": float(pv.get("updated_ts", 0.0) or 0.0),
                          "reads": [[int(r[0]), int(r[1]), int(r[2]), int(r[3])]
                                    for r in (pv.get("reads") or []) if isinstance(r, list) and len(r) >= 4]}
                     for ph, pv in (sv.get("paths") or {}).items() if isinstance(ph, str) and isinstance(pv, dict)} if isinstance(sv.get("paths"), dict) else {}
            base["sessions"][sid] = {"updated_ts": float(sv.get("updated_ts", 0.0) or 0.0),
                                     "max_step": max(0, _as_int(sv.get("max_step"))),
                                     "checkpoint_step": max(0, _as_int(sv.get("checkpoint_step"))), "paths": paths}
    if isinstance(raw.get("shadow_spools"), dict):
        base["shadow_spools"] = _norm_shadow_spools(raw["shadow_spools"])
    return _prune_shadow_state(base, now_ts if now_ts is not None else time.time())

def load_shadow_ledger(shadow_path: Path | None = None, *, now_ts: float | None = None) -> dict[str, Any]:
    """Read and normalize shadow.json cleanly (pure; returns empty defaults on missing/invalid JSON)."""
    try:
        raw: Any = json.loads((shadow_path or DEFAULT_SHADOW_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = None
    return _normalise_shadow_ledger(raw, now_ts=now_ts)

def _edit_shadow_ledger(
    mutate: Callable[[dict[str, Any], float], None], *,
    state_dir: str | Path | None = None, shadow_path: Path | None = None, now_ts: float | None = None,
) -> bool:
    ts = now_ts if now_ts is not None else time.time()
    def _apply(state: dict[str, Any]) -> None:
        mutate(state, ts)
        _prune_shadow_state(state, ts)
    return _update_ledger(shadow_path or shadow_path_for(state_dir) or DEFAULT_SHADOW_PATH, _apply,
                          normalise_fn=lambda r: _normalise_shadow_ledger(r, now_ts=ts), prefix=".shadow.", file_mode=0o600)

def record_shadow_read(
    session_id: str, raw_path: str, start_line: int, end_line: int, step_idx: int,
    achievable_tier: int, content_sha256: str, *, min_tier: int = 2,
    shadow_path: Path | None = None, now_ts: float | None = None,
) -> bool:
    """Record a simulated shadow-mode read slice with 0o600 permissions; never touches stats.json."""
    ph = pseudonymize_shadow_path(os.path.realpath(raw_path))
    def _mutate(state: dict[str, Any], ts: float) -> None:
        sess = state["sessions"].setdefault(session_id, {"updated_ts": ts, "max_step": 0, "checkpoint_step": 0, "paths": {}})
        sess["updated_ts"], sess["max_step"] = ts, max(int(sess.get("max_step", 0)), int(step_idx))
        entry = sess["paths"].get(ph)
        if not isinstance(entry, dict) or entry.get("content_sha256") != content_sha256:
            entry = sess["paths"][ph] = {"content_sha256": content_sha256, "reads": [], "updated_ts": ts}
        entry["updated_ts"] = ts
        if int(achievable_tier) >= int(min_tier):
            entry["reads"].append([int(start_line), int(end_line), int(step_idx), int(achievable_tier)])
    return _edit_shadow_ledger(_mutate, shadow_path=shadow_path, now_ts=now_ts)

def record_shadow_spool(
    harness: str, spool_meta: Mapping[str, Any], *,
    state_dir: str | Path | None = None, shadow_path: Path | None = None,
) -> bool:
    """Record simulated shadow-mode output spool savings in shadow.json; never touches stats.json."""
    if not isinstance(spool_meta, Mapping):
        return False
    saved, h_key, ts_iso = max(0, _as_int(spool_meta.get("saved_bytes"))), str(harness or spool_meta.get("harness") or "unknown"), now_iso()
    def _mutate(state: dict[str, Any], _ts: float) -> None:
        sp = state["shadow_spools"] = _norm_shadow_spools(state.get("shadow_spools"))
        sp["count"] += 1
        sp["estimated_saved_bytes"] += saved
        sp["last_ts"] = ts_iso
        sp["by_harness"][h_key] = sp["by_harness"].get(h_key, 0) + 1
    return _edit_shadow_ledger(_mutate, state_dir=state_dir, shadow_path=shadow_path)

def _keep_shadow_read(r: list[int], ckpt: int | None, mstep: int | None, inc: bool) -> bool:
    return (ckpt is None or r[2] > ckpt) and not (mstep is not None and (r[2] >= mstep if inc else r[2] > mstep))

def invalidate_shadow_ledger(
    *, session_id: str | None = None, raw_path: str | None = None, content_sha256: str | None = None,
    checkpoint_step: int | None = None, max_step: int | None = None, inclusive_rewind: bool = True,
    full_compact: bool = False, shadow_path: Path | None = None, now_ts: float | None = None,
) -> bool:
    """Invalidate shadow.json entries on file edit, compaction checkpoint, or session rewind."""
    target_hash = pseudonymize_shadow_path(os.path.realpath(raw_path)) if raw_path else None
    ckpt = int(checkpoint_step) if checkpoint_step is not None else None
    mstep = int(max_step) if max_step is not None else None
    def _mutate(state: dict[str, Any], _ts: float) -> None:
        targets = [state["sessions"].get(session_id)] if session_id else list(state["sessions"].values())
        for sess in (s for s in targets if isinstance(s, dict)):
            paths = sess["paths"]
            if target_hash and target_hash in paths and (not content_sha256 or paths[target_hash].get("content_sha256") != content_sha256):
                paths.pop(target_hash, None)
            if full_compact:
                paths.clear()
            if ckpt is not None:
                sess["checkpoint_step"] = max(int(sess.get("checkpoint_step", 0)), ckpt)
            if mstep is not None:
                sess["max_step"] = min(int(sess.get("max_step", 0)), mstep)
            if not full_compact and (ckpt is not None or mstep is not None):
                for ph in list(paths):
                    if kept := [r for r in paths[ph]["reads"] if _keep_shadow_read(r, ckpt, mstep, inclusive_rewind)]:
                        paths[ph]["reads"] = kept
                    else:
                        paths.pop(ph, None)
        if full_compact and "shadow_spools" in state:
            state["shadow_spools"] = _norm_shadow_spools(None)
    return _edit_shadow_ledger(_mutate, shadow_path=shadow_path, now_ts=now_ts)
