"""Typed Layer 0 immutable domain contracts, harness capability ceilings, and unwrap helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
from typing import Any, Literal, Mapping

from core.platform_io import atomic_write_bytes, coerce_float, coerce_int

VALID_CONFIRM_TIERS: tuple[int, ...] = (1, 2)
MAX_FORMAT_JSON_BYTES: int = 512 * 1024
MAX_OUTLINE_FILE_BYTES: int = 2 * 1024 * 1024

__all__ = [
    "HARNESS_CAPABILITIES",
    "HarnessReadCaps",
    "MAX_FORMAT_JSON_BYTES",
    "MAX_OUTLINE_FILE_BYTES",
    "OutcomeWindow",
    "PendingRead",
    "PendingUnwrapWrite",
    "PlannerMeta",
    "PreparedOutline",
    "ReadInterval",
    "ShadowEntry",
    "SpoolDecision",
    "VALID_CONFIRM_TIERS",
    "WindowAction",
    "finalize_outline_text",
    "materialize_unwrap_write",
]


@dataclass(frozen=True)
class HarnessReadCaps:
    """Per-harness single-call line, slice-byte, and coverage-byte caps."""

    max_lines: int
    max_slice_bytes: int
    max_coverage_bytes: int


HARNESS_CAPABILITIES: dict[str, HarnessReadCaps] = {
    "antigravity": HarnessReadCaps(800, 46_080, 46_080),
    "claude": HarnessReadCaps(2_000, 80_000, 60_000),
    "cursor": HarnessReadCaps(2_000, 80_000, 80_000),
    "codex": HarnessReadCaps(2_000, 100_000, 100_000),
}


@dataclass(frozen=True)
class ReadInterval:
    """Confirmed read coverage interval `[start, end, step, tier]`."""

    start: int
    end: int
    step: int
    tier: int

    def to_list(self) -> list[int]:
        """Serialize interval into canonical 4-element `[start, end, step, tier]` list."""
        return [self.start, self.end, self.step, self.tier]

    @classmethod
    def from_raw(cls, raw: Any) -> ReadInterval | None:
        """Parse a 4-element interval `[start, end, step, tier]` or return None when invalid."""
        if isinstance(raw, cls):
            return raw if raw.tier in VALID_CONFIRM_TIERS else None
        if (
            not isinstance(raw, (list, tuple))
            or len(raw) < 4
            or not all(isinstance(x, int) and not isinstance(x, bool) for x in raw[:4])
            or int(raw[3]) not in VALID_CONFIRM_TIERS
        ):
            return None
        return cls(start=int(raw[0]), end=int(raw[1]), step=int(raw[2]), tier=int(raw[3]))


def _parse_optional_int(raw: Any) -> int | None:
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw) if math.isfinite(raw) else None
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        try:
            return int(stripped)
        except ValueError:
            try:
                num = float(stripped)
            except (ValueError, OverflowError):
                return None
            return int(num) if math.isfinite(num) else None
    return None


def _parse_trimmed_spans(raw: Any) -> tuple[tuple[int, int], ...]:
    if not isinstance(raw, (list, tuple)):
        return ()
    spans: list[tuple[int, int]] = []
    for item in raw:
        if (
            isinstance(item, (list, tuple))
            and len(item) >= 2
            and isinstance(item[0], int)
            and not isinstance(item[0], bool)
            and isinstance(item[1], int)
            and not isinstance(item[1], bool)
        ):
            spans.append((int(item[0]), int(item[1])))
    return tuple(spans)


@dataclass(frozen=True)
class PendingRead:
    """Pending pre-read record awaiting PostToolUse confirmation and optional range-trim credit."""

    raw_path: str = ""
    canonical_target: str = ""
    exec_start: int = 1
    exec_end: int = -1
    delivered_end: int = -1
    target_lines: int = 0
    step: int = 0
    sha256: str = ""
    expected_norm_sha256: str | None = None
    slice_bytes: int = 0
    byte_offset: int = 0
    redirect_path: str | None = None
    is_trim: bool = False
    is_redirect: bool = False
    req_bytes: int = 0
    trimmed_bytes: int = 0
    saved_bytes: int = 0
    synthetic_id: bool = False
    post_stage: str = "pending"
    credited: bool = False
    model: str = "unknown"
    ts: float = 0.0
    trimmed_start: int | None = None
    trimmed_end: int | None = None
    trimmed_spans: tuple[tuple[int, int], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible pending_reads dict."""
        out: dict[str, Any] = {
            "raw_path": self.raw_path,
            "canonical_target": self.canonical_target,
            "exec_start": self.exec_start,
            "exec_end": self.exec_end,
            "delivered_end": self.delivered_end,
            "target_lines": self.target_lines,
            "step": self.step,
            "sha256": self.sha256,
            "expected_norm_sha256": self.expected_norm_sha256,
            "slice_bytes": self.slice_bytes,
            "byte_offset": self.byte_offset,
            "redirect_path": self.redirect_path,
            "is_trim": self.is_trim,
            "is_redirect": self.is_redirect,
            "req_bytes": self.req_bytes,
            "trimmed_bytes": self.trimmed_bytes,
            "saved_bytes": self.saved_bytes,
            "synthetic_id": self.synthetic_id,
            "post_stage": self.post_stage,
            "credited": self.credited,
            "model": self.model,
            "ts": self.ts,
        }
        if self.trimmed_start is not None:
            out["trimmed_start"] = self.trimmed_start
        if self.trimmed_end is not None:
            out["trimmed_end"] = self.trimmed_end
        if self.trimmed_spans:
            out["trimmed_spans"] = [[s, e] for s, e in self.trimmed_spans]
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> PendingRead:
        """Construct a typed PendingRead from a session-state mapping with safe coercion."""
        raw_norm = raw.get("expected_norm_sha256")
        raw_redir = raw.get("redirect_path")
        return cls(
            raw_path=str(raw.get("raw_path") or ""),
            canonical_target=str(raw.get("canonical_target") or ""),
            exec_start=coerce_int(raw.get("exec_start"), 1),
            exec_end=coerce_int(raw.get("exec_end"), -1),
            delivered_end=coerce_int(raw.get("delivered_end"), -1),
            target_lines=coerce_int(raw.get("target_lines"), 0),
            step=coerce_int(raw.get("step"), 0),
            sha256=str(raw.get("sha256") or ""),
            expected_norm_sha256=raw_norm if isinstance(raw_norm, str) and raw_norm else None,
            slice_bytes=coerce_int(raw.get("slice_bytes"), 0),
            byte_offset=coerce_int(raw.get("byte_offset"), 0),
            redirect_path=raw_redir if isinstance(raw_redir, str) and raw_redir else None,
            is_trim=bool(raw.get("is_trim", False)),
            is_redirect=bool(raw.get("is_redirect", False)),
            req_bytes=coerce_int(raw.get("req_bytes"), 0),
            trimmed_bytes=coerce_int(raw.get("trimmed_bytes"), 0),
            saved_bytes=coerce_int(raw.get("saved_bytes"), 0),
            synthetic_id=bool(raw.get("synthetic_id", False)),
            post_stage=str(raw.get("post_stage") or "pending"),
            credited=bool(raw.get("credited", False)),
            model=str(raw.get("model") or "unknown"),
            ts=coerce_float(raw.get("ts"), 0.0),
            trimmed_start=_parse_optional_int(raw.get("trimmed_start")),
            trimmed_end=_parse_optional_int(raw.get("trimmed_end")),
            trimmed_spans=_parse_trimmed_spans(raw.get("trimmed_spans")),
        )


@dataclass(frozen=True)
class PendingUnwrapWrite:
    """Deferred atomic file write for an unwrapped artifact payload."""

    target_path: Path
    content: str


@dataclass(frozen=True)
class PreparedOutline:
    """In-memory outline result prepared without touching disk for unwrapped artifacts."""

    total_lines: int
    outline_text: str
    unwrapped_target: Path | None = None
    pending_write: PendingUnwrapWrite | None = None


def materialize_unwrap_write(pending: PendingUnwrapWrite | None) -> str | None:
    """Atomically persist a deferred unwrap payload to disk and return its canonical realpath."""
    if pending is None:
        return None
    try:
        atomic_write_bytes(
            pending.target_path,
            pending.content.encode("utf-8"),
            mode=0o600,
            prefix=f".{pending.target_path.name}.",
        )
        return os.path.realpath(str(pending.target_path))
    except OSError:
        return None


def finalize_outline_text(prepared: PreparedOutline, actual_unwrapped: str | None) -> str:
    """Reconcile the planned unwrapped path in `prepared.outline_text` with `actual_unwrapped`."""
    if prepared.unwrapped_target is None:
        return prepared.outline_text
    planned_canon = os.path.realpath(str(prepared.unwrapped_target))
    planned_token = f", unwrapped at {planned_canon}"
    if actual_unwrapped:
        return prepared.outline_text.replace(planned_token, f", unwrapped at {actual_unwrapped}")
    return prepared.outline_text.replace(planned_token, "")


@dataclass(frozen=True)
class PlannerMeta:
    """Typed transaction metadata passed from pure read planning to atomic commit."""

    sha256: str
    step_idx: int
    auto_increment_step: bool
    is_outline: bool
    pending_write: PendingUnwrapWrite | None = None
    outlined_total_lines: int = 0
    pending_followup_kind: str | None = None
    target_lines: int = 0
    path_arg_key: str = "Path"
    call_id: str = ""
    pending_read: PendingRead | None = None
    clear_followups: bool = False
    peer_paths: tuple[str, ...] = ()
    expected_reads_snapshot: tuple[tuple[int, int, int, int], ...] = ()


@dataclass(frozen=True)
class WindowAction:
    """Explicit transition returned by an outcomes window reconciliation predicate."""

    kind: Literal["keep", "resolve", "drop", "mutate"]
    outcome_dims: tuple[str, str, str] | None = None


@dataclass(frozen=True)
class OutcomeWindow:
    """Open regret/recovery observation window stored in the Schema v4 outcomes ledger."""

    session_id: str
    key: str
    target_path: str = ""
    kind: str = ""
    step_idx: int = 0
    expires_step: int = 0
    meta: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible open_windows entry."""
        out: dict[str, Any] = {
            "session_id": self.session_id,
            "key": self.key,
            "target_path": self.target_path,
            "kind": self.kind,
            "step_idx": int(self.step_idx),
            "expires_step": int(self.expires_step),
        }
        if self.meta:
            out["meta"] = dict(self.meta)
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], *, legacy_key: str = "") -> OutcomeWindow | None:
        """Parse an open_windows entry, recovering target_path/kind from legacy `|` keys if absent."""
        session_id = raw.get("session_id")
        key = raw.get("key")
        if not isinstance(session_id, str) or not isinstance(key, str):
            return None
        raw_tp = raw.get("target_path")
        raw_kind = raw.get("kind")
        fallback_tp = ""
        fallback_kind = key.rsplit("|", 1)[-1] if "|" in key else ""
        if legacy_key and "|" in legacy_key:
            prefix = f"{session_id}|"
            if legacy_key.startswith(prefix):
                rest = legacy_key[len(prefix) :]
                if "|" in rest:
                    fallback_tp, _, fallback_kind = rest.rpartition("|")
            else:
                parts = legacy_key.split("|")
                if len(parts) >= 3:
                    fallback_tp = "|".join(parts[1:-1])
                    fallback_kind = parts[-1]
        target_path = raw_tp if isinstance(raw_tp, str) and raw_tp else fallback_tp
        kind = raw_kind if isinstance(raw_kind, str) and raw_kind else fallback_kind
        raw_meta = raw.get("meta")
        meta: dict[str, Any] = dict(raw_meta) if isinstance(raw_meta, Mapping) else {}
        return cls(
            session_id=session_id,
            key=key,
            target_path=target_path,
            kind=kind,
            step_idx=max(0, coerce_int(raw.get("step_idx"), 0)),
            expires_step=max(0, coerce_int(raw.get("expires_step"), 0)),
            meta=meta,
        )


@dataclass(frozen=True)
class ShadowEntry:
    """Pseudonymized per-path entry stored in `shadow.json`."""

    content_sha256: str = ""
    updated_ts: float = 0.0
    reads: tuple[ReadInterval, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible `shadow.json` path entry."""
        return {
            "content_sha256": self.content_sha256,
            "updated_ts": float(self.updated_ts),
            "reads": [iv.to_list() for iv in self.reads],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ShadowEntry:
        """Deserialize a `shadow.json` path entry while coercing corrupt field types safely."""
        intervals: list[ReadInterval] = []
        raw_reads = raw.get("reads")
        if isinstance(raw_reads, (list, tuple)):
            for item in raw_reads:
                if (iv := ReadInterval.from_raw(item)) is not None:
                    intervals.append(iv)
        return cls(
            content_sha256=str(raw.get("content_sha256") or ""),
            updated_ts=coerce_float(raw.get("updated_ts"), 0.0),
            reads=tuple(intervals),
        )


@dataclass(frozen=True)
class SpoolDecision:
    """Domain-level PostToolUse spool decision decoupled from harness wire schemas."""

    harness: str
    updated_output: Any
    shape: str
    meta: dict[str, Any] = field(default_factory=dict)
