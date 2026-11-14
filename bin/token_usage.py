#!/usr/bin/env python3
"""Real token usage read offline from harness transcripts (Claude Code, Codex, Antigravity, Cursor)."""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

fcntl: Any
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    from hooks import file_io as fcntl

from hooks.json_outliners import ANTIGRAVITY_FULL_TRANSCRIPT_GLOB  # noqa: E402
from hooks.model_identity import (  # noqa: E402
    UNKNOWN_MODEL,
    detect_codex_model,
    normalize_model_label,
    pinned_model,
)
from hooks.state_store import resolve_plugin_root, warn  # noqa: E402
from hooks.telemetry import now_iso, read_json_object_or_quarantine, write_json_atomic  # noqa: E402
from bin.preamble_attribution import (  # noqa: E402
    CODEX_CLI_HARNESS,
    MalformedAttachment,
    attribute_codex_record,
    attribute_record,
    codex_session_traits,
    merge_parts,
    usage_keys,
)
from bin.transcript_parsers import (  # noqa: E402
    UsageEvent as UsageEvent,
    antigravity_model_from_record as antigravity_model_from_record,
    codex_model_from_record as codex_model_from_record,
    codex_total_counts as codex_total_counts,
    estimate_cursor_tokens as estimate_cursor_tokens,
    nonneg_int as nonneg_int,
    parse_antigravity_record as parse_antigravity_record,
    parse_claude_record as parse_claude_record,
    parse_codex_record as parse_codex_record,
    parse_utc_day as parse_utc_day,
)

_ROOT = resolve_plugin_root()
DEFAULT_USAGE_PATH = _ROOT / "telemetry" / "token_usage.json"
TRANSCRIPT_ROOTS: dict[str, Path] = {
    "antigravity": Path.home() / ".gemini" / "antigravity" / "brain",
    "claude": Path.home() / ".claude" / "projects",
    "codex": Path.home() / ".codex" / "sessions",
    "cursor": Path.home() / ".cursor" / "projects",
}
_TRANSCRIPT_GLOBS: dict[str, tuple[str, ...]] = {
    "antigravity": (ANTIGRAVITY_FULL_TRANSCRIPT_GLOB,),
    "claude": ("*/*.jsonl", "*/*/subagents/*.jsonl"),
    "codex": ("*/*/*/rollout-*.jsonl",),
    "cursor": ("*/agent-transcripts/*.json",),
}
MAX_BYTES_PER_RUN = 1024 * 1024 * 1024
USAGE_SCHEMA_VERSION = 3
PREAMBLE_HISTORY = 200
COMPONENT_USE_DAYS = 90
_ROW_COUNTS = ("input", "output", "cache_read", "cache_write")


def empty_usage_state() -> dict[str, Any]:
    """A ledger with no measurements."""
    return {
        "schema_version": USAGE_SCHEMA_VERSION,
        "cursors": {},
        "seen_ids": {},
        "cursor_estimates": {},
        "totals": {},
        "by_day": {},
        "preamble": {},
        "preamble_parts": [],
        "codex_preamble_parts": [],
        "component_use": {},
        "component_use_since": None,
        "backlog": {},
        "antigravity_coverage": {"planner": 0, "with_usage": 0},
        "antigravity_last_model": UNKNOWN_MODEL,
        "skipped_lines": 0,
        "saved_tokens_at_start": 0,
        "started_at": None,
        "updated_at": None,
    }


def restore_usage_state(path: Path) -> dict[str, Any]:
    """The ledger at `path` with missing or mistyped sections reset; a file that is not a JSON object is quarantined."""
    try:
        raw = read_json_object_or_quarantine(path) or {}
    except OSError:
        raw = {}
    state = empty_usage_state()
    if raw:
        raw_ver = raw.get("schema_version")
        state["schema_version"] = (
            raw_ver if isinstance(raw_ver, int) and not isinstance(raw_ver, bool) and raw_ver >= 0 else 0
        )
    for key, default in list(state.items()):
        if key == "schema_version":
            continue
        value = raw.get(key)
        if default is None:
            if isinstance(value, str):
                state[key] = value
        elif isinstance(value, type(default)) and not isinstance(value, bool):
            state[key] = value
    coverage = state["antigravity_coverage"]
    state["antigravity_coverage"] = {name: nonneg_int(coverage.get(name)) for name in ("planner", "with_usage")}
    state["backlog"] = {str(harness): nonneg_int(size) for harness, size in state["backlog"].items()}
    raw_ag_last = state.get("antigravity_last_model")
    stripped_ag = raw_ag_last.strip() if isinstance(raw_ag_last, str) else ""
    norm_ag_last = (
        normalize_model_label(stripped_ag)
        if stripped_ag and not stripped_ag.startswith("<")
        else UNKNOWN_MODEL
    )
    state["antigravity_last_model"] = (
        norm_ag_last if norm_ag_last not in (UNKNOWN_MODEL, "auto") else UNKNOWN_MODEL
    )
    # A non-dict row would crash the next refresh before the ledger is rewritten, so the crash would repeat.
    state["component_use"] = {day: row for day, row in state["component_use"].items() if isinstance(row, dict)}
    state["by_day"] = {
        day: {harness: totals for harness, totals in row.items() if isinstance(totals, dict)}
        for day, row in state["by_day"].items()
        if isinstance(row, dict)
    }
    return state


def list_transcripts(harness: str, root: Path) -> list[Path]:
    """Transcript files of one harness under `root`, oldest first (path breaks ties, so the order is stable)."""
    found: dict[Path, float] = {}
    for pattern in _TRANSCRIPT_GLOBS[harness]:
        try:
            matches = [path for path in root.glob(pattern) if path.is_file()]
        except OSError:
            continue
        for path in matches:
            try:
                found[path] = path.stat().st_mtime
            except OSError:
                continue
    return sorted(found, key=lambda path: (found[path], str(path)))


def _mtime_day(mtime: float) -> str:
    return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")


def _fold_into(row: dict[str, Any], event: UsageEvent) -> None:
    for name in _ROW_COUNTS:
        row[name] = nonneg_int(row.get(name)) + getattr(event, name)
    row["events"] = nonneg_int(row.get("events")) + 1
    row["total_only"] = nonneg_int(row.get("total_only")) + int(event.total_only)


def add_event(state: dict[str, Any], event: UsageEvent) -> None:
    """Add one call to the per harness|model totals and, when it has a day, to that day's per-harness row."""
    _fold_into(state["totals"].setdefault(f"{event.harness}|{event.model}", {}), event)
    if event.day:
        _fold_into(state["by_day"].setdefault(event.day, {}).setdefault(event.harness, {}), event)


def add_preamble(state: dict[str, Any], harness: str, event: UsageEvent) -> int:
    """Append a session's first-call context size, keeping the last PREAMBLE_HISTORY values; returns that size."""
    measured = event.input + event.cache_read + event.cache_write
    history = state["preamble"].setdefault(harness, [])
    history.append(measured)
    del history[:-PREAMBLE_HISTORY]
    return measured


def add_preamble_parts(state: dict[str, Any], measured: int, components: dict[str, Any]) -> None:
    """Append one Claude Code session's preamble breakdown, keeping the last PREAMBLE_HISTORY."""
    history = state["preamble_parts"]
    history.append({"measured": measured, "components": components})
    del history[:-PREAMBLE_HISTORY]


def add_codex_preamble_parts(state: dict[str, Any], measured: int, cohort: str, components: dict[str, Any]) -> None:
    """Append one Codex main-thread session's preamble breakdown, keeping the last PREAMBLE_HISTORY."""
    history = state.setdefault("codex_preamble_parts", [])
    history.append({"measured": measured, "cohort": cohort, "components": components})
    del history[:-PREAMBLE_HISTORY]


def _note_claude_record(
    state: dict[str, Any],
    cursor: dict[str, Any],
    record: dict[str, Any],
    main_thread: bool,
    seen: set[str],
    known: Counter[str],
    fallback_day: str,
) -> None:
    """Buffer a main-thread file's preamble attachments and count the plugin or server behind each tool call.

    Tool calls of a message counted in another file (a resumed copy) are skipped; the lines of one message in
    this file each carry their own content blocks, so each line is counted.
    """
    if main_thread and not cursor.get("preamble_done"):
        try:
            parts = attribute_record(record)
        except MalformedAttachment:
            state["skipped_lines"] += 1
            parts = None
        if parts:
            cursor["pending_parts"] = merge_parts(cursor.get("pending_parts"), parts)
    keys = usage_keys(record)
    if not keys:
        return
    message = record.get("message")
    message_id = str(message.get("id") or "") if isinstance(message, dict) else ""
    if message_id and known[message_id] > 0 and message_id not in seen:
        return
    row = state["component_use"].setdefault(parse_utc_day(record.get("timestamp")) or fallback_day, {})
    for key in keys:
        row[key] = nonneg_int(row.get(key)) + 1


def _event_from(
    state: dict[str, Any], harness: str, record: dict[str, Any], cursor: dict[str, Any], default_model: str
) -> UsageEvent | None:
    """Dispatch one record to its harness parser; also tracks the Codex model and the Antigravity coverage."""
    if harness == "claude":
        return parse_claude_record(record)
    if harness == "codex":
        traits = codex_session_traits(record)
        if traits is not None:
            sidechain, cohort = traits
            if sidechain:
                cursor["is_sidechain"] = True
            if cohort:
                cursor["codex_cohort"] = cohort
            return None
        if not cursor.get("preamble_done") and not cursor.get("is_sidechain"):
            codex_parts = attribute_codex_record(record)
            if codex_parts:
                cursor["codex_pending_parts"] = merge_parts(cursor.get("codex_pending_parts"), codex_parts)
        model = codex_model_from_record(record)
        if model:
            cursor["model"] = model
            return None
        total = codex_total_counts(record)
        if total is not None:
            if cursor.get("last_total") == total:
                return None
            cursor["last_total"] = total
        ev = parse_codex_record(record, cursor.get("model") or default_model)
        if ev is not None and cursor.get("is_sidechain"):
            return replace(ev, is_sidechain=True)
        return ev
    if harness == "antigravity":
        rec_type = record.get("type")
        if rec_type in ("USER_INPUT", "SYSTEM_MESSAGE"):
            content = str(record.get("content") or "")
            if rec_type == "USER_INPUT" and "<USER_REQUEST>" in content:
                cursor["is_sidechain"] = False
            elif record.get("step_index") == 0 and "<SYSTEM_MESSAGE>" in content:
                cursor["is_sidechain"] = True
            if rec_type == "USER_INPUT":
                sel_model = antigravity_model_from_record(record)
                if sel_model:
                    cursor["model"] = sel_model
                    if not cursor.get("is_sidechain"):
                        state["antigravity_last_model"] = sel_model
        if record.get("type") == "PLANNER_RESPONSE":
            state["antigravity_coverage"]["planner"] += 1
        event = parse_antigravity_record(record, cursor.get("model") or default_model)
        if event is not None:
            state["antigravity_coverage"]["with_usage"] += 1
            if event.model != UNKNOWN_MODEL:
                cursor["model"] = event.model
                if not cursor.get("is_sidechain"):
                    state["antigravity_last_model"] = event.model
            if cursor.get("is_sidechain"):
                return replace(event, is_sidechain=True)
        return event
    return None


def _id_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def known_message_ids(state: dict[str, Any]) -> Counter[str]:
    """How many files have counted each message id; any count above 0 makes the id a duplicate."""
    known: Counter[str] = Counter()
    for ids in state["seen_ids"].values():
        known.update(_id_list(ids))
    return known


def fold_jsonl_file(
    state: dict[str, Any], harness: str, path: Path, budget: int, known: Counter[str] | None = None
) -> int:
    """Fold the complete lines added to one JSONL transcript since its cursor; returns the bytes consumed.

    `known` holds the message ids counted in any file (built once per run by `ingest_transcripts`); an
    id counted elsewhere is a copy from a resumed or forked session and is skipped, and a file whose
    first main-thread call is such a copy contributes no preamble.
    For Claude Code it also buffers the preamble attachments of a main-thread file until its first call and
    counts tool calls per plugin or server (`_note_claude_record`).
    """
    if known is None:
        known = known_message_ids(state)
    try:
        stat = path.stat()
    except OSError:
        return 0
    key = str(path)
    cursor = state["cursors"].get(key)
    if not isinstance(cursor, dict) or cursor.get("inode") != stat.st_ino or stat.st_size < nonneg_int(cursor.get("offset")):
        cursor = {"inode": stat.st_ino, "offset": 0, "model": None, "preamble_done": False}
        known.subtract(_id_list(state["seen_ids"].pop(key, None)))
    offset = nonneg_int(cursor.get("offset"))
    if stat.st_size <= offset or budget <= 0:
        state["cursors"][key] = cursor
        return 0
    try:
        with path.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read(min(budget, stat.st_size - offset))
    except OSError:
        return 0
    body = chunk[: chunk.rfind(b"\n") + 1]
    if not body:
        return 0
    fixed_model = pinned_model(harness)
    if harness == "codex":
        default_model = detect_codex_model(None)
    elif harness == "antigravity":
        raw_last = state.get("antigravity_last_model")
        default_model = raw_last if isinstance(raw_last, str) and raw_last else UNKNOWN_MODEL
    else:
        default_model = UNKNOWN_MODEL
    fallback_day = _mtime_day(stat.st_mtime)
    main_thread = "subagents" not in path.parts
    seen = set(_id_list(state["seen_ids"].get(key)))
    for raw in body.splitlines():
        if not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except ValueError:
            record = None
        if not isinstance(record, dict):
            state["skipped_lines"] += 1
            continue
        if harness == "claude":
            _note_claude_record(state, cursor, record, main_thread, seen, known, fallback_day)
        event = _event_from(state, harness, record, cursor, default_model)
        if event is None:
            continue
        first_main = main_thread and not event.is_sidechain and not cursor.get("preamble_done")
        if event.message_id:
            if known[event.message_id] > 0:
                if first_main and event.message_id not in seen:
                    cursor["preamble_done"] = True
                    cursor.pop("pending_parts", None)
                continue
            seen.add(event.message_id)
            known[event.message_id] += 1
        if fixed_model:
            event = replace(event, model=fixed_model)
        if not event.day:
            event = replace(event, day=fallback_day)
        add_event(state, event)
        if first_main:
            measured = add_preamble(state, harness, event)
            cursor["preamble_done"] = True
            parts = cursor.pop("pending_parts", None)
            if parts:
                add_preamble_parts(state, measured, parts)
            codex_parts = cursor.pop("codex_pending_parts", None)
            if harness == "codex" and codex_parts:
                add_codex_preamble_parts(state, measured, str(cursor.get("codex_cohort") or CODEX_CLI_HARNESS), codex_parts)
    cursor["offset"] = offset + len(body)
    state["cursors"][key] = cursor
    if seen:
        state["seen_ids"][key] = sorted(seen)
    return len(body)


def _estimate_is_current(state: dict[str, Any], key: str, stat: Any) -> bool:
    previous = state["cursor_estimates"].get(key)
    return isinstance(previous, dict) and previous.get("inode") == stat.st_ino and previous.get("size") == stat.st_size


def fold_cursor_file(state: dict[str, Any], path: Path, budget: int = MAX_BYTES_PER_RUN) -> int:
    """Re-estimate one Cursor transcript when its inode or size changed; returns the bytes read.

    The estimate replaces the previous one. A file larger than `budget` waits for a later run; an
    unparseable file is stored with 0 tokens so it is not re-read until it changes.
    """
    try:
        stat = path.stat()
    except OSError:
        return 0
    key = str(path)
    if _estimate_is_current(state, key, stat) or stat.st_size > budget:
        return 0
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    try:
        tokens = estimate_cursor_tokens(json.loads(text))
    except ValueError:
        state["skipped_lines"] += 1
        tokens = 0
    state["cursor_estimates"][key] = {
        "inode": stat.st_ino,
        "size": stat.st_size,
        "tokens": tokens,
        "day": _mtime_day(stat.st_mtime),
    }
    return stat.st_size


def _unread_bytes(state: dict[str, Any], harness: str, path: Path) -> int:
    """Bytes of one transcript not yet folded: past the cursor offset, or the whole Cursor file when its estimate is stale."""
    try:
        stat = path.stat()
    except OSError:
        return 0
    key = str(path)
    if harness == "cursor":
        return 0 if _estimate_is_current(state, key, stat) else stat.st_size
    cursor = state["cursors"].get(key)
    offset = nonneg_int(cursor.get("offset")) if isinstance(cursor, dict) else 0
    if not isinstance(cursor, dict) or cursor.get("inode") != stat.st_ino or stat.st_size < offset:
        return stat.st_size
    return stat.st_size - offset


def _fold_harness(state: dict[str, Any], harness: str, paths: list[Path], budget: int, known: Counter[str]) -> int:
    spent = 0
    for path in paths:
        if spent >= budget:
            break
        if harness == "cursor":
            spent += fold_cursor_file(state, path, budget - spent)
        else:
            spent += fold_jsonl_file(state, harness, path, budget - spent, known)
    return spent


def ingest_transcripts(state: dict[str, Any], roots: dict[str, Path], max_bytes: int = MAX_BYTES_PER_RUN) -> int:
    """Fold transcript bytes added since the last run into `state` within `max_bytes`; returns bytes consumed.

    The budget is shared: harnesses are served from the smallest backlog up, each taking at most an
    equal share of what is left, so a share one harness does not need passes to the others. Within a
    harness the oldest files come first. Unread bytes per harness are left in `state["backlog"]`.
    """
    known = known_message_ids(state)
    listed = {harness: list_transcripts(harness, roots[harness]) for harness in sorted(roots)}
    pending = {harness: sum(_unread_bytes(state, harness, path) for path in paths) for harness, paths in listed.items()}
    waiting = sorted((harness for harness in listed if pending[harness] > 0), key=lambda harness: (pending[harness], harness))
    used = 0
    for index, harness in enumerate(waiting):
        share = (max_bytes - used) // (len(waiting) - index)
        used += _fold_harness(state, harness, listed[harness], share, known)
    state["backlog"] = {
        harness: sum(_unread_bytes(state, harness, path) for path in paths) for harness, paths in listed.items()
    }
    return used


def prune_vanished(state: dict[str, Any]) -> None:
    """Drop cursors, seen ids and Cursor estimates of transcripts that no longer exist; totals stay."""
    for section in ("cursors", "seen_ids", "cursor_estimates"):
        for key in [name for name in state[section] if not Path(name).exists()]:
            del state[section][key]


def prune_component_use(state: dict[str, Any], today: date) -> None:
    """Drop tool-call counts of malformed days and of days more than COMPONENT_USE_DAYS before `today`."""
    cutoff = (today - timedelta(days=COMPONENT_USE_DAYS)).isoformat()
    for day in [name for name in state["component_use"] if parse_utc_day(name) != name or name < cutoff]:
        del state["component_use"][day]


def migrate_usage_state(state: dict[str, Any], roots: dict[str, Path] | None = None) -> bool:
    """Reset legacy Antigravity (and Codex below v2) slices for schema upgrade while preserving other history."""
    prev_ver = nonneg_int(state.get("schema_version"))
    if prev_ver >= USAGE_SCHEMA_VERSION:
        return False
    eff_roots = roots if roots is not None else TRANSCRIPT_ROOTS
    reset_harnesses: tuple[str, ...] = ("antigravity",) if prev_ver == 2 else ("antigravity", "codex")
    prefixes = tuple(str(eff_roots[h]) for h in reset_harnesses if h in eff_roots)
    for section in ("cursors", "seen_ids"):
        state[section] = {
            k: v
            for k, v in state[section].items()
            if not (
                any(k == p or k.startswith((p + "/", p + "\\")) for p in prefixes)
                or ("antigravity" in reset_harnesses and Path(k).name in ("transcript.jsonl", "transcript_full.jsonl"))
                or ("codex" in reset_harnesses and Path(k).name.startswith("rollout-"))
            )
        }
    reset_totals = tuple(f"{h}|" for h in reset_harnesses)
    state["totals"] = {k: v for k, v in state["totals"].items() if not k.startswith(reset_totals)}
    for day in list(state["by_day"]):
        for h in reset_harnesses:
            state["by_day"][day].pop(h, None)
        if not state["by_day"][day]:
            del state["by_day"][day]
    for h in reset_harnesses:
        state["preamble"].pop(h, None)
        state["backlog"].pop(h, None)
    if "codex" in reset_harnesses:
        state["codex_preamble_parts"] = []
    state["antigravity_coverage"] = {"planner": 0, "with_usage": 0}
    state["antigravity_last_model"] = UNKNOWN_MODEL
    state["schema_version"] = USAGE_SCHEMA_VERSION
    return True


def _refresh_usage_unlocked(
    target: Path,
    roots: dict[str, Path] | None,
    max_bytes: int,
    saved_tokens_now: int,
    persist: bool = True,
) -> dict[str, Any]:
    state = restore_usage_state(target)
    eff_roots = roots if roots is not None else TRANSCRIPT_ROOTS
    migrate_usage_state(state, eff_roots)
    if state["started_at"] is None:
        state["started_at"] = now_iso()
        state["saved_tokens_at_start"] = max(0, int(saved_tokens_now))
    ingest_transcripts(state, eff_roots, max_bytes)
    prune_vanished(state)
    state["updated_at"] = now_iso()
    today = date.fromisoformat(state["updated_at"][:10])
    if state["component_use_since"] is None:
        state["component_use_since"] = today.isoformat()
    prune_component_use(state, today)
    if persist:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            write_json_atomic(target, state, prefix=".token_usage.")
        except OSError as exc:
            warn(f"token usage save skipped: {type(exc).__name__}: {exc}")
    return state


def refresh_usage(
    state_path: Path | None = None,
    roots: dict[str, Path] | None = None,
    max_bytes: int = MAX_BYTES_PER_RUN,
    saved_tokens_now: int = 0,
) -> dict[str, Any]:
    """Load the ledger, fold new transcript lines into it, persist it and return it."""
    target = state_path or DEFAULT_USAGE_PATH
    lock_path = target.with_suffix(".lock")
    lock_fh = None
    locked = False
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        lock_fh = open(lock_path, "a+", encoding="utf-8")
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        locked = True
    except OSError as exc:
        if lock_fh is not None:
            lock_fh.close()
            lock_fh = None
        warn(f"token usage lock skipped: {type(exc).__name__}: {exc}")
    if not locked:
        return _refresh_usage_unlocked(
            target,
            roots=roots,
            max_bytes=max_bytes,
            saved_tokens_now=saved_tokens_now,
            persist=False,
        )
    try:
        return _refresh_usage_unlocked(
            target, roots=roots, max_bytes=max_bytes, saved_tokens_now=saved_tokens_now
        )
    finally:
        if lock_fh is not None:
            try:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            lock_fh.close()
