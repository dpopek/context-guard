"""Direct intervention outcome telemetry and conservative delivered-line estimation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

fcntl: Any
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    from hooks import file_io as fcntl

from hooks.state_store import resolve_plugin_root, warn
from hooks.telemetry import (
    CLAUDE_COVERAGE_MAX_SLICE_BYTES, CLAUDE_CURSOR_MAX_SLICE_BYTES,
    CLAUDE_CURSOR_READ_MAX_LINES, HARNESS_READ_CAPS,
    now_iso, read_json_object_or_quarantine, write_json_atomic,
)

SCHEMA_VERSION = 3
OUTCOMES = ("applied", "targeted_followup", "full_bypass", "shell_bypass")
ROW_KEYS = ("total", *OUTCOMES)
INTERVENTION_KINDS = ("outline", "range_trim", "cli_rewrite", "outline_pull")
OUTCOMES_KINDS = INTERVENTION_KINDS
DEFAULT_OUTCOMES_PATH = resolve_plugin_root() / "telemetry" / "outcomes.json"


def ledger_path_for(state_dir: str | None) -> Path | None:
    """Isolated outcomes ledger path next to a state_dir override, or None for default global ledger."""
    return (Path(state_dir) / "outcomes.json") if state_dir else None


def default_outcomes_dict() -> dict[str, Any]:
    """Return a clean initialized outcomes ledger dictionary."""
    return {"schema_version": SCHEMA_VERSION, "updated_at": now_iso(), "by_key": {}}


def _normalise_row(raw: Any) -> dict[str, int]:
    src = raw if isinstance(raw, dict) else {}
    row: dict[str, int] = {}
    for key in ROW_KEYS:
        try:
            row[key] = max(0, int(src.get(key) or 0))
        except (TypeError, ValueError):
            row[key] = 0
    return row


def _normalise_outcomes(raw: Any) -> dict[str, Any]:
    base = default_outcomes_dict()
    if not isinstance(raw, dict):
        return base
    if isinstance(raw.get("updated_at"), str) and raw["updated_at"]:
        base["updated_at"] = raw["updated_at"]
    if "schema_version" in raw and raw.get("schema_version") != SCHEMA_VERSION:
        return base
    raw_by_key = raw.get("by_key")
    if isinstance(raw_by_key, dict):
        base["by_key"] = {str(k): _normalise_row(v) for k, v in raw_by_key.items() if isinstance(k, str) and isinstance(v, dict)}
    return base


def load_outcomes(outcomes_path: Path | None = None) -> dict[str, Any]:
    """Load and normalize outcomes ledger from disk; returns defaults when absent or corrupt."""
    target = outcomes_path or DEFAULT_OUTCOMES_PATH
    if not target.is_file():
        return default_outcomes_dict()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default_outcomes_dict()
    return _normalise_outcomes(raw)


def estimate_delivered_end_line(
    harness: str, start_line: int, end_line: int, total_lines: int, slice_bytes: int | None
) -> int | None:
    """Conservative PreToolUse estimate of the last delivered line; None when coverage is unknown."""
    if total_lines <= 0 or slice_bytes is None or slice_bytes < 0:
        return None
    max_lines, max_bytes = HARNESS_READ_CAPS.get(harness, (CLAUDE_CURSOR_READ_MAX_LINES, CLAUDE_CURSOR_MAX_SLICE_BYTES))
    if harness == "claude":
        max_bytes = CLAUDE_COVERAGE_MAX_SLICE_BYTES
    req_end = total_lines if (end_line == -1 or end_line > total_lines) else end_line
    return None if (req_end < start_line or slice_bytes > max_bytes) else min(req_end, max(1, start_line) + max_lines - 1)


def record_direct_outcome(
    harness: str, model: str, kind: str, outcome: str = "applied",
    ledger_path: Path | None = None, *, increment_total: bool = True, count: int = 1,
) -> None:
    """Atomically increment one outcome bucket under flock; best-effort and never raises."""
    if count <= 0:
        return
    try:
        target = ledger_path or DEFAULT_OUTCOMES_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        key = f"{harness or 'unknown'}|{model or 'unknown'}|{kind or 'unknown'}"
        with open(target.with_suffix(".lock"), "a+", encoding="utf-8") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                raw = read_json_object_or_quarantine(target)
                state = _normalise_outcomes(raw) if raw is not None else default_outcomes_dict()
                state["updated_at"] = now_iso()
                row = state["by_key"].setdefault(key, {k: 0 for k in ROW_KEYS})
                if increment_total:
                    row["total"] = int(row.get("total", 0) or 0) + count
                if outcome in OUTCOMES:
                    row[outcome] = int(row.get(outcome, 0) or 0) + count
                write_json_atomic(target, state, prefix=".outcomes.")
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
    except Exception as exc:  # noqa: BLE001 - telemetry is best-effort by contract
        warn(f"direct outcome telemetry skipped: {type(exc).__name__}: {exc}")
