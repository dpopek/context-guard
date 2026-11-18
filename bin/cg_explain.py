#!/usr/bin/env python3
"""Diagnostic CLI and contract engine for `cg explain <event-id>`."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from policies.api import (  # noqa: E402
    EXPLAIN_SCHEMA_VERSION, RECEIPT_SCHEMA_VERSION, VALID_DELIVERY_EVIDENCE_TIERS,
    VALID_EXPLAIN_STATES, ContextReceiptV1, ExplainContractV1,
)
from policies.governor import GOVERNOR_SCHEMA_VERSION, resolve_governor_state_path  # noqa: E402
from spool.classifier import read_blob_bytes  # noqa: E402
from spool.receipts import (  # noqa: E402
    check_unsafe_link, load_receipt_rows, normalize_receipt_row, receipts_path_for, summarize_spool_lifecycle,
)
from spool.store import inspect_spool_entry, resolve_spool_dir  # noqa: E402

_LEDGER_SCHEMA_VERSION = 1
_DEFAULT_LEDGER_FILENAME = "evidence_events.json"
_POSIX_HOME_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._/-]+)?")
_WIN_HOME_RE = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z]:(?:[/\\]|\\\\)Users(?:[/\\]|\\\\)[A-Za-z0-9._-]+(?:(?:[/\\]|\\\\)[A-Za-z0-9._/\\-]+)?",
    re.IGNORECASE,
)
_LOCAL_EMAIL_RE = re.compile(r"(?:[A-Za-z0-9._%+-]+)?@[A-Za-z0-9._-]+\.local\b", re.IGNORECASE)
_ATLASSIAN_RE = re.compile(r"\b[a-z0-9.-]+\.atlassian\.net\b", re.IGNORECASE)
_GCP_PROJECT_RE = re.compile(r"\b[a-z][a-z0-9]*-[a-z][a-z0-9]*-\d{5,}(?:-[a-z0-9]+)?\b", re.IGNORECASE)
_FORBIDDEN_KEYS = frozenset({
    "prompt", "raw_prompt", "content", "tool_input", "tool_output", "command",
    "raw_command", "tool_response", "canon_root", "workspace_root", "transcript_path",
    "config_path", "repo_map_path", "state_dir", "home_dir", "spool_dir", "receipts_path", "cwd",
})


def _scrub_text(text: str) -> str:
    cleaned = text
    try:
        home_p = Path.home()
        for cand in (str(home_p), str(home_p.resolve())):
            if cand and cand not in ("/", "\\"):
                cleaned = re.sub(re.escape(cand) + r"(?:[/\\][A-Za-z0-9._/\\-]+)?", "[redacted-path]", cleaned)
    except (RuntimeError, OSError):
        pass
    cleaned = _WIN_HOME_RE.sub("[redacted-path]", _POSIX_HOME_RE.sub("[redacted-path]", cleaned))
    cleaned = _LOCAL_EMAIL_RE.sub("[redacted-email]", cleaned)
    cleaned = _ATLASSIAN_RE.sub("[redacted-domain]", cleaned)
    return _GCP_PROJECT_RE.sub("[redacted-project]", cleaned)


def _scrub_opt(val: Any) -> str | None:
    return (_scrub_text(val) or None) if isinstance(val, str) and val else None


def _scrub_obj(val: Any) -> Any:
    if isinstance(val, Mapping):
        return {
            ks: _scrub_obj(val[k]) for k in sorted(val, key=str)
            if (ks := str(k)).lower() not in _FORBIDDEN_KEYS
            and not ks.lower().endswith(("_path", "_paths", "_dir", "_dirs"))
        }
    if isinstance(val, (list, tuple)):
        return [_scrub_obj(item) for item in val]
    if isinstance(val, str):
        return _scrub_text(val)
    return val if isinstance(val, (bool, int, float)) or val is None else _scrub_text(str(val))


def _load_ledger_rows(ledger_file: Path | None) -> tuple[list[ContextReceiptV1], str | None]:
    if ledger_file is None:
        return [], None
    if check_unsafe_link(ledger_file.parent) or check_unsafe_link(ledger_file):
        return [], "unsafe_path"
    if not ledger_file.exists():
        return [], None
    raw_bytes, err = read_blob_bytes(ledger_file)
    if err == "unsafe_path":
        return [], "unsafe_path"
    if err is not None or raw_bytes is None:
        return [], None
    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError):
        return [], None
    if not isinstance(parsed, Mapping) or parsed.get("schema_version") != _LEDGER_SCHEMA_VERSION or not isinstance(parsed.get("events"), list):
        return [], None
    rows: list[ContextReceiptV1] = []
    seen: set[str] = set()
    for item in parsed["events"]:
        if not isinstance(item, Mapping):
            continue
        patched = {"schema_version": RECEIPT_SCHEMA_VERSION, "line_span": [0, 0], "byte_span": [0, 0], **item}
        norm = normalize_receipt_row(patched)
        if norm is not None and norm["event_id"] and norm["event_type"] and norm["event_id"] not in seen:
            seen.add(norm["event_id"])
            rows.append(norm)
    return rows, None


def _read_governor_context(
    state_dir: str | Path | None, spool_dir: Path, optimizer_id: str, *, isolated_spool: bool = False
) -> tuple[dict[str, Any], str | None]:
    if state_dir is not None and str(state_dir).strip():
        primary = resolve_governor_state_path(state_dir)
        candidates: list[Path] = [primary]
        if (sd_spool := Path(str(state_dir).strip()).expanduser() / "spool" / primary.name) not in candidates:
            candidates.append(sd_spool)
    elif isolated_spool and not str(os.environ.get("CONTEXT_GUARD_STATE_DIR") or "").strip():
        gov_name = resolve_governor_state_path(spool_dir).name
        primary = spool_dir / gov_name
        candidates = [primary, spool_dir.parent / gov_name]
    else:
        primary = resolve_governor_state_path(None)
        candidates = [primary, *(p for p in (spool_dir / primary.name, spool_dir.parent / primary.name) if p != primary)]
    if check_unsafe_link(primary.parent) or check_unsafe_link(primary):
        return {}, "unsafe_path"
    merged_att: dict[str, Any] = {}
    state_present, tripped, b_state, trip_count = False, False, "closed", 0
    trip_reason: str | None = None
    for idx, cand in enumerate(candidates):
        if check_unsafe_link(cand.parent) or check_unsafe_link(cand):
            if idx == 0:
                return {}, "unsafe_path"
            continue
        if not cand.exists():
            continue
        raw_bytes, err = read_blob_bytes(cand)
        if err == "unsafe_path":
            if idx == 0:
                return {}, "unsafe_path"
            continue
        try:
            parsed = json.loads(raw_bytes.decode("utf-8")) if (err is None and raw_bytes is not None) else None
        except (UnicodeDecodeError, ValueError, TypeError):
            parsed = None
        if not isinstance(parsed, Mapping) or parsed.get("schema_version") not in (None, GOVERNOR_SCHEMA_VERSION):
            continue
        state_present = True
        if isinstance((atts := parsed.get("attestations")), Mapping):
            for k, v in atts.items():
                merged_att.setdefault(str(k), v)
        if isinstance((cbs := parsed.get("circuit_breakers")), Mapping) and isinstance((raw_b := cbs.get(optimizer_id)), Mapping):
            cur_tripped = bool(raw_b.get("tripped")) or str(raw_b.get("state") or "closed") == "open"
            cur_state = "open" if cur_tripped else ("half_open" if raw_b.get("state") == "half_open" else "closed")
            raw_tc = raw_b.get("trip_count")
            cur_tc = int(raw_tc) if isinstance(raw_tc, int) and not isinstance(raw_tc, bool) and raw_tc >= 0 else (1 if cur_tripped else 0)
            if cur_tripped and not tripped:
                tripped, b_state, trip_count = True, "open", max(trip_count, cur_tc)
                trip_reason = _scrub_opt(raw_b.get("trip_reason"))
            elif not tripped:
                b_state = "half_open" if cur_state == "half_open" else b_state
                trip_count = max(trip_count, cur_tc)
    return {
        "state_present": state_present, "optimizer_id": _scrub_text(optimizer_id), "breaker_state": b_state,
        "tripped": tripped, "trip_reason": trip_reason, "trip_count": trip_count, "attestation_count": len(merged_att),
    }, None


def _error_contract(query_id: str, error: str) -> ExplainContractV1:
    return ExplainContractV1(
        schema_version=EXPLAIN_SCHEMA_VERSION, ok=False, error=error, query_id=_scrub_text(query_id),
        matched_by="not_found", event_id=None, receipt_id=None, spool_id=None, event_type=None,
        intervention=None, harness=None, session_id=None, workspace_id=None, mode=None, status=None,
        current_state="unknown", eviction_reason=None, corrupt_reason=("unsafe_path" if error == "unsafe_path" else None),
        delivery_evidence_tier="unverified", completeness="unavailable", privacy_scrubbed=True,
        spool_lifecycle={}, timeline=[], governor_context={},
    )


def _resolve_explain_paths(
    receipts_path: Path | None, spool_dir: Path | None, ledger_path: Path | None, state_dir: str | Path | None
) -> tuple[Path, Path, Path | None, str | None]:
    if spool_dir is not None:
        eff_spool = Path(spool_dir)
    elif state_dir is not None and str(state_dir).strip():
        eff_spool = resolve_spool_dir(state_dir)
    elif str(os.environ.get("CONTEXT_GUARD_SPOOL_DIR") or "").strip():
        eff_spool = resolve_spool_dir()
    elif receipts_path is not None and (Path(receipts_path).parent / "spool_index.json").exists():
        eff_spool = Path(receipts_path).parent
    else:
        eff_spool = resolve_spool_dir()
    eff_rcpt = Path(receipts_path) if receipts_path is not None else receipts_path_for(eff_spool)
    if check_unsafe_link(eff_rcpt.parent) or check_unsafe_link(eff_rcpt) or (eff_rcpt.exists() and not eff_rcpt.is_file()):
        return eff_rcpt, eff_spool, None, "unsafe_path"
    idx_p = eff_spool / "spool_index.json"
    if (
        check_unsafe_link(eff_spool)
        or (eff_spool.exists() and not eff_spool.is_dir())
        or (eff_spool.is_dir() and (check_unsafe_link(idx_p) or (idx_p.exists() and not idx_p.is_file())))
    ):
        return eff_rcpt, eff_spool, None, "unsafe_path"
    if ledger_path is not None:
        lp = Path(ledger_path)
        if check_unsafe_link(lp.parent) or check_unsafe_link(lp) or (lp.exists() and not lp.is_file()):
            return eff_rcpt, eff_spool, None, "unsafe_path"
        eff_ledger: Path | None = lp
    else:
        cand_ledger = eff_spool.parent / _DEFAULT_LEDGER_FILENAME
        if check_unsafe_link(cand_ledger) or (cand_ledger.exists() and not cand_ledger.is_file()):
            return eff_rcpt, eff_spool, None, "unsafe_path"
        eff_ledger = cand_ledger if cand_ledger.exists() else None
    if state_dir is not None and str(state_dir).strip():
        sd_p = Path(str(state_dir).strip()).expanduser()
        if check_unsafe_link(sd_p) or (sd_p.exists() and not sd_p.is_dir()):
            return eff_rcpt, eff_spool, eff_ledger, "unsafe_path"
    return eff_rcpt, eff_spool, eff_ledger, None


def _match_rows(rows: Sequence[ContextReceiptV1], q_id: str) -> tuple[str | None, ContextReceiptV1 | None]:
    checks: tuple[tuple[str, list[ContextReceiptV1]], ...] = (
        ("event_id", [r for r in rows if r["event_id"] == q_id]),
        ("receipt_id", [r for r in rows if r["receipt_id"] == q_id]),
        ("spool_id", [r for r in rows if r["spool_id"] == q_id]),
    )
    for field_name, hits in checks:
        if hits:
            ordered = sorted(enumerate(hits), key=lambda p: (int(p[1]["ts_ms"]), str(p[1]["timestamp"]), int(p[0])))
            return field_name, ordered[-1][1]
    return None, None


def _build_timeline(events: Sequence[ContextReceiptV1]) -> list[dict[str, Any]]:
    ordered = sorted(events, key=lambda r: (int(r["ts_ms"]), str(r["timestamp"]), str(r["event_id"])))
    return [
        {
            "event_id": _scrub_text(r["event_id"]), "receipt_id": _scrub_text(r["receipt_id"]),
            "event_type": _scrub_text(r["event_type"]), "timestamp": _scrub_text(r["timestamp"]),
            "status": _scrub_text(r["status"]),
            "delivery_evidence": r["delivery_evidence"] if r["delivery_evidence"] in VALID_DELIVERY_EVIDENCE_TIERS else "unverified",
            "line_span": [int(r["line_span"][0]), int(r["line_span"][1])],
            "byte_span": [int(r["byte_span"][0]), int(r["byte_span"][1])],
            "failure_kind": _scrub_opt(r["failure_kind"]), "reason": _scrub_opt(r["reason"]),
        }
        for r in ordered
    ]


def explain_intervention(
    target_id: str,
    *,
    receipts_path: Path | None = None,
    spool_dir: Path | None = None,
    ledger_path: Path | None = None,
    state_dir: str | Path | None = None,
    now_ts: float | None = None,
) -> ExplainContractV1:
    """Explain an intervention, spool lifecycle, eviction/corruption cause, and delivery evidence tier."""
    if not isinstance(target_id, str) or not target_id.strip():
        return _error_contract(target_id if isinstance(target_id, str) else "", "invalid_event_id")
    q_id = target_id.strip()
    eff_rcpt, eff_spool, eff_ledger, path_err = _resolve_explain_paths(receipts_path, spool_dir, ledger_path, state_dir)
    if path_err is not None:
        return _error_contract(q_id, path_err)

    receipt_rows = load_receipt_rows(eff_rcpt)
    ledger_rows, ledger_err = _load_ledger_rows(eff_ledger)
    if ledger_err is not None:
        return _error_contract(q_id, ledger_err)

    matched_by, primary = _match_rows(receipt_rows, q_id)
    if primary is None and ledger_rows:
        matched_by, primary = _match_rows(ledger_rows, q_id)

    isolated_spool = spool_dir is not None or receipts_path is not None or bool(str(os.environ.get("CONTEXT_GUARD_SPOOL_DIR") or "").strip())
    if primary is None:
        sp_only = inspect_spool_entry(q_id, spool_dir=eff_spool)
        if sp_only["corrupt_reason"] == "unsafe_path" and not sp_only["found"]:
            return _error_contract(q_id, "unsafe_path")
        if not sp_only["found"]:
            return _error_contract(q_id, "event_not_found")
        gov_ctx, gov_err = _read_governor_context(state_dir, eff_spool, "output_spool", isolated_spool=isolated_spool)
        if gov_err is not None:
            return _error_contract(q_id, gov_err)
        st_val = str(sp_only["current_state"])
        cur_state = st_val if st_val in VALID_EXPLAIN_STATES else "unknown"
        lifecycle_only: dict[str, Any] = _scrub_obj({
            "spool_id": q_id, "completeness": "incomplete", "delivery_evidence": "unverified",
            "recovery_calls": 0, "reliability_failures": 0,
            "created_at": sp_only["created_at"], "last_accessed_at": sp_only["last_accessed_at"],
            "evicted_at": sp_only["evicted_at"], "corrupted_at": sp_only["corrupted_at"],
            "blob_present": bool(sp_only["blob_present"]),
            "total_bytes": sp_only["total_bytes"], "total_lines": sp_only["total_lines"],
        })
        return ExplainContractV1(
            schema_version=EXPLAIN_SCHEMA_VERSION, ok=True, error=None, query_id=_scrub_text(q_id),
            matched_by="spool_id", event_id=None, receipt_id=None, spool_id=_scrub_text(q_id),
            event_type=None, intervention="output_spool", harness=None,
            session_id=_scrub_opt(sp_only.get("session_id")), workspace_id=_scrub_opt(sp_only.get("workspace_id")),
            mode=None, status=("error" if cur_state == "corrupt" else "ok"), current_state=cur_state,
            eviction_reason=_scrub_opt(sp_only.get("eviction_reason")),
            corrupt_reason=_scrub_opt(sp_only.get("corrupt_reason")),
            delivery_evidence_tier="unverified", completeness="incomplete", privacy_scrubbed=True,
            spool_lifecycle=lifecycle_only, timeline=[], governor_context=_scrub_obj(gov_ctx),
        )

    opt_id = primary["intervention"].strip() or "output_spool"
    gov_ctx, gov_err = _read_governor_context(state_dir, eff_spool, opt_id, isolated_spool=isolated_spool)
    if gov_err is not None:
        return _error_contract(q_id, gov_err)

    sid = primary["spool_id"].strip()
    seen_eids: set[str] = set()
    related: list[ContextReceiptV1] = []
    for row in (*receipt_rows, *ledger_rows):
        if (sid and row["spool_id"] == sid) or (not sid and row["event_id"] == primary["event_id"]):
            dedup_k = row["event_id"] or row["receipt_id"]
            if dedup_k and dedup_k in seen_eids:
                continue
            if dedup_k:
                seen_eids.add(dedup_k)
            related.append(row)

    if matched_by == "spool_id" and related:
        primary = sorted(enumerate(related), key=lambda p: (int(p[1]["ts_ms"]), str(p[1]["timestamp"]), int(p[0])))[-1][1]

    eviction_reason: str | None = None
    corrupt_reason: str | None = None
    if sid:
        sp_info = inspect_spool_entry(sid, spool_dir=eff_spool)
        if sp_info["corrupt_reason"] == "unsafe_path" and not sp_info["found"]:
            return _error_contract(q_id, "unsafe_path")
        fail_rows = [r for r in related if r["event_type"] == "spool_integrity_failure"]
        fail_rsn = next(((r["reason"] or "").strip() for r in reversed(fail_rows) if isinstance(r["reason"], str) and r["reason"].strip()), None)
        if sp_info["found"]:
            raw_st = str(sp_info["current_state"])
            cur_state = raw_st if raw_st in VALID_EXPLAIN_STATES else "unknown"
            eviction_reason = _scrub_opt(sp_info.get("eviction_reason"))
            corrupt_reason = _scrub_opt(sp_info.get("corrupt_reason")) or (_scrub_text(fail_rsn) if fail_rsn else None)
        elif fail_rows:
            cur_state = "corrupt"
            corrupt_reason = _scrub_text(fail_rsn) if fail_rsn else "integrity_failure"
        else:
            cur_state = "receipt_only"
        metrics = summarize_spool_lifecycle(eff_rcpt, spool_id=sid, now_ts=now_ts, extra_rows=ledger_rows)["by_spool"].get(sid) or {}
        spool_lifecycle: dict[str, Any] = _scrub_obj({
            **metrics, "spool_id": sid,
            "created_at": sp_info["created_at"], "last_accessed_at": sp_info["last_accessed_at"],
            "evicted_at": sp_info["evicted_at"], "corrupted_at": sp_info["corrupted_at"],
            "blob_present": bool(sp_info["blob_present"]),
        })
        raw_tier = str(metrics.get("delivery_evidence") or primary["delivery_evidence"] or "unverified")
        completeness = str(metrics.get("completeness") or "incomplete")
        ws_val = primary["workspace_id"] or str(sp_info.get("workspace_id") or "")
    else:
        cur_state, raw_tier, completeness, ws_val = "not_spool_backed", str(primary["delivery_evidence"] or "unverified"), "complete", primary["workspace_id"]
        spool_lifecycle = _scrub_obj({
            "spool_id": None, "completeness": "complete",
            "delivery_evidence": (raw_tier if raw_tier in VALID_DELIVERY_EVIDENCE_TIERS else "unverified"),
            "recovery_calls": 0,
            "reliability_failures": sum(1 for r in related if r["event_type"] == "spool_integrity_failure" or r["failure_kind"] == "reliability_failure"),
            "created_at": None, "last_accessed_at": None, "evicted_at": None, "corrupted_at": None, "blob_present": False,
        })

    del_tier = raw_tier if raw_tier in VALID_DELIVERY_EVIDENCE_TIERS else "unverified"
    return ExplainContractV1(
        schema_version=EXPLAIN_SCHEMA_VERSION, ok=True, error=None, query_id=_scrub_text(q_id),
        matched_by=str(matched_by or "event_id"), event_id=_scrub_opt(primary["event_id"]),
        receipt_id=_scrub_opt(primary["receipt_id"]), spool_id=_scrub_opt(sid),
        event_type=_scrub_opt(primary["event_type"]), intervention=_scrub_opt(opt_id),
        harness=_scrub_opt(primary["harness"]), session_id=_scrub_opt(primary["session_id"]),
        workspace_id=_scrub_opt(ws_val), mode=_scrub_opt(primary["mode"]), status=_scrub_opt(primary["status"]),
        current_state=cur_state, eviction_reason=eviction_reason, corrupt_reason=corrupt_reason,
        delivery_evidence_tier=del_tier,
        completeness=completeness if completeness in ("complete", "incomplete", "unavailable") else "incomplete",
        privacy_scrubbed=True, spool_lifecycle=spool_lifecycle,
        timeline=_scrub_obj(_build_timeline(related)), governor_context=_scrub_obj(gov_ctx),
    )


def render_explain_markdown(report: Mapping[str, Any]) -> str:
    """Format an `ExplainContractV1` report as human-readable scrubbed Markdown."""
    raw_s = _scrub_obj(report)
    scrubbed: Mapping[str, Any] = raw_s if isinstance(raw_s, Mapping) else {}
    qid = str(scrubbed.get("query_id") or "")
    if not scrubbed.get("ok"):
        return "\n".join([
            "# Context-Guard Intervention Explain (`FAIL`)", "",
            f"- Query ID: `{qid}`", f"- Error: `{scrubbed.get('error', 'unknown_error')}`",
            f"- Current state: `{scrubbed.get('current_state', 'unknown')}` | Completeness: `{scrubbed.get('completeness', 'unavailable')}`",
            "- Privacy scrubbed: `True`",
        ]) + "\n"
    gov = scrubbed["governor_context"] if isinstance(scrubbed.get("governor_context"), Mapping) else {}
    lc = scrubbed["spool_lifecycle"] if isinstance(scrubbed.get("spool_lifecycle"), Mapping) else {}
    lines = [
        f"# Context-Guard Intervention Explain (`{qid}`)", "",
        f"- Matched by: `{scrubbed.get('matched_by')}` | Event ID: `{scrubbed.get('event_id')}` | Receipt ID: `{scrubbed.get('receipt_id')}` | Spool ID: `{scrubbed.get('spool_id')}`",
        f"- Intervention: `{scrubbed.get('intervention')}` (`{scrubbed.get('mode')}`) | Event type: `{scrubbed.get('event_type')}` | Harness: `{scrubbed.get('harness')}` | Status: `{scrubbed.get('status')}`",
        f"- Current state: `{scrubbed.get('current_state')}` | Eviction reason: `{scrubbed.get('eviction_reason')}` | Corrupt reason: `{scrubbed.get('corrupt_reason')}`",
        f"- Delivery evidence tier: `{scrubbed.get('delivery_evidence_tier')}` | Completeness: `{scrubbed.get('completeness')}` | Privacy scrubbed: `{bool(scrubbed.get('privacy_scrubbed', True))}`",
        f"- Lifecycle: `recoveries={lc.get('recovery_calls', 0)}`, `unique_recovered_bytes={lc.get('unique_recovered_bytes', 0)}`, `blob_present={bool(lc.get('blob_present', False))}`",
        f"- Governor (`{gov.get('optimizer_id', 'output_spool')}`): `breaker={gov.get('breaker_state', 'closed')}`, `tripped={bool(gov.get('tripped', False))}`, `trip_reason={gov.get('trip_reason')}`, `attestations={gov.get('attestation_count', 0)}`",
    ]
    timeline = scrubbed.get("timeline")
    if isinstance(timeline, list) and timeline:
        lines.extend(["", "## Lifecycle Timeline", "", "| Timestamp | Event ID | Event Type | Status | Evidence | Line Span | Byte Span | Reason |", "|---|---|---|---|---|---|---|---|"])
        for item in timeline:
            if isinstance(item, Mapping):
                lines.append(
                    f"| `{item.get('timestamp', '')}` | `{item.get('event_id', '')}` | `{item.get('event_type', '')}` | "
                    f"`{item.get('status', '')}` | `{item.get('delivery_evidence', '')}` | `{item.get('line_span')}` | "
                    f"`{item.get('byte_span')}` | `{item.get('reason')}` |"
                )
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cg-explain", description="Explain a Context-Guard intervention, spool lifecycle, and delivery evidence tier.")
    parser.add_argument("event_id", help="Target event_id, receipt_id, or spool_id to explain.")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit structured ExplainContractV1 JSON output.")
    fmt.add_argument("--markdown", action="store_true", help="Emit Markdown report (default).")
    parser.add_argument("--receipts-path", type=Path, default=None, help="Override receipts.jsonl path.")
    parser.add_argument("--spool-dir", type=Path, default=None, help="Override spool directory path.")
    parser.add_argument("--ledger-path", type=Path, default=None, help="Override evidence_events.json path.")
    parser.add_argument("--state-dir", type=Path, default=None, help="Override governor state directory path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `cg explain` / `cg_explain.py`."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if len(raw_argv) >= 2 and raw_argv[0] == "explain" and not raw_argv[1].startswith("-"):
        raw_argv = raw_argv[1:]
    wants_json = "--json" in raw_argv
    try:
        ns = _build_parser().parse_args(raw_argv)
    except SystemExit as exc:
        if exc.code == 0:
            return 0
        if wants_json:
            print(json.dumps({"ok": False, "error": "invalid_arguments"}))
        return 2
    report = explain_intervention(
        str(ns.event_id),
        receipts_path=Path(ns.receipts_path).expanduser() if ns.receipts_path is not None else None,
        spool_dir=Path(ns.spool_dir).expanduser() if ns.spool_dir is not None else None,
        ledger_path=Path(ns.ledger_path).expanduser() if ns.ledger_path is not None else None,
        state_dir=Path(ns.state_dir).expanduser() if ns.state_dir is not None else None,
    )
    print(json.dumps(report, indent=2) if ns.json else render_explain_markdown(report), end=("\n" if ns.json else ""))
    return 0 if report["ok"] else (2 if report["error"] == "invalid_event_id" else 1)


if __name__ == "__main__":
    raise SystemExit(main())
