"""Atomic token savings telemetry ledger (Imperative Shell) for Context-Guard."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from core.contracts import HARNESS_CAPABILITIES
from core.platform_io import (
    LOCK_EX, LOCK_UN, coerce_float, coerce_int, flock, now_iso,
    read_json_object_or_quarantine, resolve_plugin_root, warn, write_json_atomic,
)
from hooks import telemetry_core
from hooks.shell_output import BUCKETS, Measurement
from hooks.telemetry_core import (
    BINARY_MEDIA_EXTENSIONS, NO_CREDIT, SHADOW_MAX_PATHS, SHADOW_MAX_READS_PER_PATH,
    SHADOW_MAX_SESSIONS, SHADOW_SCHEMA_VERSION, SHADOW_TTL_SECONDS, SHELL_COUNTER_KEYS,
    SHELL_OUTCOMES, Credit, apply_shell_output, cap_end_line_for_harness,
)

ANTIGRAVITY_READ_MAX_LINES = HARNESS_CAPABILITIES["antigravity"].max_lines
ANTIGRAVITY_READ_MAX_BYTES = HARNESS_CAPABILITIES["antigravity"].max_slice_bytes
CLAUDE_CURSOR_READ_MAX_LINES = HARNESS_CAPABILITIES["claude"].max_lines
CLAUDE_CURSOR_MAX_SLICE_BYTES = HARNESS_CAPABILITIES["claude"].max_slice_bytes
CLAUDE_COVERAGE_MAX_SLICE_BYTES = HARNESS_CAPABILITIES["claude"].max_coverage_bytes
CODEX_SHELL_READ_MAX_LINES = HARNESS_CAPABILITIES["codex"].max_lines
CODEX_SHELL_MAX_SLICE_BYTES = HARNESS_CAPABILITIES["codex"].max_slice_bytes
MAX_SINGLE_READ_BYTES = ANTIGRAVITY_READ_MAX_BYTES
HARNESS_READ_CAPS: dict[str, tuple[int, int]] = {h: (c.max_lines, c.max_slice_bytes) for h, c in HARNESS_CAPABILITIES.items()}

DEFAULT_TELEMETRY_PATH = resolve_plugin_root() / "telemetry" / "stats.json"
DEFAULT_SHADOW_PATH = resolve_plugin_root() / "telemetry" / "shadow.json"
_DENY_EVENT_BY_INTERVENTION = {"outline": "outlines"}


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


def load_telemetry_stats(stats_path: Path | None = None) -> dict[str, Any]:
    """Read and return normalized telemetry stats dictionary (safe defaults if missing/corrupt)."""
    target = stats_path or DEFAULT_TELEMETRY_PATH
    try:
        return telemetry_core.normalise_stats(json.loads(target.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return telemetry_core.default_stats_dict()


def _update_ledger(
    stats_path: Path | None, mutate: Callable[[dict[str, Any]], bool | None], *,
    normalise_fn: Callable[[Any, float, str], dict[str, Any]] | None = None,
    prefix: str = ".stats.", file_mode: int | None = None,
) -> bool:
    """Apply `mutate` to a JSON ledger under flock and write it atomically. True when written."""
    target = stats_path or DEFAULT_TELEMETRY_PATH
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target.with_suffix(".lock"), "a+", encoding="utf-8") as lock_fh:
            flock(lock_fh.fileno(), LOCK_EX)
            try:
                ts_now, ts_iso = time.time(), now_iso()
                raw = read_json_object_or_quarantine(target)
                state = (
                    telemetry_core.normalise_stats(raw, now_str=ts_iso)
                    if normalise_fn is None else normalise_fn(raw, ts_now, ts_iso)
                )
                state["updated_at"] = ts_iso
                if mutate(state) is False:
                    return False
                write_json_atomic(target, state, prefix=prefix, mode=file_mode)
            finally:
                flock(lock_fh.fileno(), LOCK_UN)
    except OSError as exc:
        warn(f"telemetry ledger update failed ({target}): {type(exc).__name__}: {exc}")
        return False
    return True


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
        written = _update_ledger(
            stats_path,
            lambda st: telemetry_core.apply_telemetry_event(
                st, harness, event_kind, b_bytes, s_bytes, target_day=target_day, event_id=event_id,
            ),
        )
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


def record_reliability_failure(stats_path: Path | None = None) -> None:
    """Increment `events.reliability_failures` via `_update_ledger` without touching `by_harness`."""
    _update_ledger(stats_path, telemetry_core.apply_reliability_failure)


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
    verdict = decision.get("decision", "allow")
    if Path(raw_path).suffix.lower() in BINARY_MEDIA_EXTENSIONS:
        if verdict == "deny" or not os.path.isfile(os.path.realpath(raw_path)):
            return NO_CREDIT
        return record_telemetry_event(harness, "allowed_reads", 0, 0, stats_path=stats_path)
    max_bytes = HARNESS_CAPABILITIES.get(harness, HARNESS_CAPABILITIES["claude"]).max_slice_bytes
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
        if end_line == -1:
            full_end = cap_end_line_for_harness(harness, 1, -1)
            base_b = max(req_bytes, estimate_slice_bytes(raw_path, 1, full_end, byte_cap=max_bytes))
        else:
            base_b = req_bytes
        return record_telemetry_event(harness, kind, base_b, max(0, base_b - reason_bytes), stats_path=stats_path)
    ov = decision.get("overwrite")
    if isinstance(ov, dict) and ov:
        t_path = str(ov.get("Path") or ov.get("AbsolutePath") or raw_path)
        raw_ns, raw_ne = ov.get("StartLine"), ov.get("EndLine")
        ns = int(raw_ns) if raw_ns is not None else start_line
        ne = int(raw_ne) if raw_ne is not None else end_line
        trimmed_b = estimate_slice_bytes(t_path, ns, cap_end_line_for_harness(harness, ns, ne), byte_cap=max_bytes)
        if trimmed_b < req_bytes or raw_ns is not None or raw_ne is not None:
            return record_telemetry_event(harness, "ranges_trimmed", req_bytes, max(0, req_bytes - trimmed_b), stats_path=stats_path)
    return record_telemetry_event(harness, "allowed_reads", req_bytes, 0, stats_path=stats_path)


def shadow_path_for(state_dir: str | Path | None) -> Path | None:
    """Return `Path(state_dir) / 'shadow.json'` when `state_dir` is set, else None."""
    return (Path(state_dir) / "shadow.json") if state_dir else None


def pseudonymize_shadow_path(canon: str) -> str:
    """Deterministic SHA-256 path pseudonymization (not keyed HMAC) for shadow.json."""
    return hashlib.sha256(f"cg-shadow-v1:{canon}".encode("utf-8")).hexdigest()[:32]


def load_shadow_ledger(shadow_path: Path | None = None, *, now_ts: float | None = None) -> dict[str, Any]:
    """Read and normalize shadow.json cleanly (pure; returns empty defaults on missing/invalid JSON)."""
    try:
        raw: Any = json.loads((shadow_path or DEFAULT_SHADOW_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = None
    return telemetry_core.normalise_shadow_ledger(raw, now_ts=now_ts)


def _edit_shadow_ledger(
    mutate: Callable[[dict[str, Any], float, str], bool | None], *,
    state_dir: str | Path | None = None, shadow_path: Path | None = None, now_ts: float | None = None,
) -> bool:
    holder: list[tuple[float, str]] = []

    def _norm(raw: Any, cur_ts: float, cur_iso: str) -> dict[str, Any]:
        eff_ts = now_ts if now_ts is not None else cur_ts
        holder[:] = [(eff_ts, cur_iso)]
        return telemetry_core.normalise_shadow_ledger(raw, now_ts=eff_ts, now_str=cur_iso)

    def _apply(state: dict[str, Any]) -> bool | None:
        eff_ts, cur_iso = holder[0]
        if mutate(state, eff_ts, cur_iso) is False:
            return False
        telemetry_core.prune_shadow_state(state, eff_ts)
        return None

    target = shadow_path or shadow_path_for(state_dir) or DEFAULT_SHADOW_PATH
    return _update_ledger(target, _apply, normalise_fn=_norm, prefix=".shadow.", file_mode=0o600)


def record_shadow_read(
    session_id: str, raw_path: str, start_line: int, end_line: int, step_idx: int,
    achievable_tier: int, content_sha256: str, *, min_tier: int = 2,
    shadow_path: Path | None = None, now_ts: float | None = None,
) -> bool:
    """Record a simulated shadow-mode read slice with 0o600 permissions; never touches stats.json."""
    if int(achievable_tier) < int(min_tier):
        return False
    ph = pseudonymize_shadow_path(os.path.realpath(raw_path))
    return _edit_shadow_ledger(
        lambda st, ts, _iso: telemetry_core.apply_shadow_read(
            st, session_id, ph, start_line, end_line, step_idx, achievable_tier, content_sha256, ts, min_tier=min_tier,
        ),
        shadow_path=shadow_path, now_ts=now_ts,
    )


def record_shadow_spool(
    harness: str, spool_meta: Mapping[str, Any], *,
    state_dir: str | Path | None = None, shadow_path: Path | None = None,
) -> bool:
    """Record simulated shadow-mode output spool savings in shadow.json; never touches stats.json."""
    if not isinstance(spool_meta, Mapping):
        return False
    saved, h_key = max(0, coerce_int(spool_meta.get("saved_bytes"))), str(harness or spool_meta.get("harness") or "unknown")
    return _edit_shadow_ledger(
        lambda st, _ts, ts_iso: telemetry_core.apply_shadow_spool(st, h_key, saved, ts_iso),
        state_dir=state_dir, shadow_path=shadow_path,
    )


def invalidate_shadow_ledger(
    *, session_id: str | None = None, raw_path: str | None = None, content_sha256: str | None = None,
    checkpoint_step: int | None = None, max_step: int | None = None, inclusive_rewind: bool = True,
    full_compact: bool = False, shadow_path: Path | None = None, now_ts: float | None = None,
) -> bool:
    """Invalidate shadow.json entries on file edit, compaction checkpoint, or session rewind."""
    target_hash = pseudonymize_shadow_path(os.path.realpath(raw_path)) if raw_path else None
    ckpt = int(checkpoint_step) if checkpoint_step is not None else None
    mstep = int(max_step) if max_step is not None else None
    return _edit_shadow_ledger(
        lambda st, _ts, _iso: telemetry_core.apply_shadow_invalidation(
            st, session_id=session_id, target_hash=target_hash, content_sha256=content_sha256,
            ckpt=ckpt, mstep=mstep, inclusive_rewind=inclusive_rewind, full_compact=full_compact,
        ),
        shadow_path=shadow_path, now_ts=now_ts,
    )
