#!/usr/bin/env python3
"""Off-hot-path 100% stdlib OTLP/JSON telemetry exporter (`cg export --otel`)."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib, json, math, os, re, stat, sys, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from hooks.outcomes import load_outcomes
from hooks.state_store import resolve_plugin_root
from policies.api import RECEIPT_SCHEMA_VERSION, VALID_TURN_CORRELATIONS
from spool.receipts import atomic_write_bytes, check_unsafe_link, receipts_path_for

OTEL_EXPORT_SCHEMA_VERSION: int = 1
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)

ALLOWED_OTEL_EVENT_ATTRIBUTES: frozenset[str] = frozenset({
    "context_guard.event_id", "context_guard.receipt_id", "context_guard.event_type", "context_guard.spool_id",
    "context_guard.harness", "context_guard.intervention", "context_guard.mode", "context_guard.status",
    "context_guard.delivery_evidence", "context_guard.turn_correlation", "context_guard.original_bytes",
    "context_guard.replacement_bytes", "context_guard.line_span_start", "context_guard.line_span_end",
    "context_guard.byte_span_start", "context_guard.byte_span_end", "context_guard.source_hash",
    "context_guard.upstream_truncation", "context_guard.spool_id_referenced", "context_guard.workspace_id",
    "context_guard.session_hash", "context_guard.failure_kind", "context_guard.reason",
})
ALLOWED_OTEL_OUTCOMES_ATTRIBUTES: frozenset[str] = frozenset({
    "context_guard.event_type", "context_guard.outcomes.schema_version", "context_guard.outcomes.interventions",
    "context_guard.outcomes.confirmed_regrets", "context_guard.outcomes.suspected_regrets",
})
ALLOWED_OTEL_RESOURCE_ATTRIBUTES: frozenset[str] = frozenset({
    "service.name", "service.version", "telemetry.sdk.language", "context_guard.off_hot_path",
})
_WS_ID_RE, _HEX_HASH_RE = re.compile(r"^ws_[0-9a-f]{8,64}$"), re.compile(r"^(?:sha256:)?[0-9a-f]{12,64}$")
_POSIX_HOME_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9._-]+(?:[/\\][^\s\"',;)\]]*)?")
_WIN_HOME_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:(?:[/\\]|\\\\)Users(?:[/\\]|\\\\)[A-Za-z0-9._-]+(?:[/\\][^\s\"',;)\]]*)?", re.I)
_FILE_URI_RE = re.compile(r"file://[^\s\"',;)\]]+", re.I)
_LOCAL_EMAIL_RE = re.compile(r"[A-Za-z0-9._+-]*@[A-Za-z0-9._-]+\.(?:local)\b", re.I)
_ATLASSIAN_RE = re.compile(r"\b[a-z0-9-]+\.(?:atlassian)\.(?:net)\b", re.I)
_GCP_PROJECT_RE = re.compile(r"\b[a-z][a-z0-9]*-[a-z][a-z0-9]*-\d{5,}(?:-[a-z0-9]+)?(?::[A-Za-z0-9_.]*)?\b", re.I)

__all__ = [
    "ALLOWED_OTEL_EVENT_ATTRIBUTES", "ALLOWED_OTEL_OUTCOMES_ATTRIBUTES", "ALLOWED_OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_EXPORT_SCHEMA_VERSION", "build_otel_export_bundle", "export_otel_to_file", "main", "post_otel_http",
]

def _scrub_text(text: str) -> str:
    if not text:
        return ""
    cleaned = text
    try:
        home_p = Path.home()
        for cand in (str(home_p), str(home_p.resolve())):
            if cand and cand not in ("/", "\\"):
                cleaned = re.compile(re.escape(cand) + r"(?:[/\\][^\s\"',;)\]]*)?").sub("[redacted-path]", cleaned)
    except (RuntimeError, OSError):
        pass
    for pat, repl in (
        (_FILE_URI_RE, "[redacted-path]"), (_WIN_HOME_RE, "[redacted-path]"), (_POSIX_HOME_RE, "[redacted-path]"),
        (_LOCAL_EMAIL_RE, "[redacted-email]"), (_ATLASSIAN_RE, "[redacted-domain]"), (_GCP_PROJECT_RE, "[redacted-project]"),
    ):
        cleaned = pat.sub(repl, cleaned)
    return cleaned

def _hash_session_id(raw_session: str) -> str:
    return "sha256:" + hashlib.sha256(raw_session.encode("utf-8")).hexdigest()[:16]

def _scrub_workspace_id(raw_ws: str) -> str:
    ws = raw_ws.strip()
    return "" if not ws else (ws if _WS_ID_RE.match(ws) else "ws_" + hashlib.sha256(f"cg-ws-scrub:{ws}".encode("utf-8")).hexdigest()[:16])

def _scrub_source_hash(raw_hash: str) -> str:
    sh = raw_hash.strip()
    return "" if not sh else (sh if _HEX_HASH_RE.match(sh) else "sha256:" + hashlib.sha256(sh.encode("utf-8")).hexdigest()[:16])

def _read_service_version() -> str:
    for root in (resolve_plugin_root(), _PACKAGE_ROOT):
        manifest = root / "plugin.json"
        if not check_unsafe_link(manifest) and manifest.is_file():
            try:
                parsed = json.loads(manifest.read_text(encoding="utf-8"))
                if isinstance(parsed, Mapping) and isinstance(parsed.get("version"), str) and parsed["version"].strip():
                    return _scrub_text(parsed["version"].strip())
            except (OSError, UnicodeDecodeError, ValueError):
                continue
    return "unknown"

def _read_regular_bytes(path: Path) -> tuple[bytes | None, str | None]:
    if check_unsafe_link(path.parent) or check_unsafe_link(path) or (path.exists() and path.is_dir()):
        return None, "unsafe_path"
    if not path.exists():
        return None, "not_found"
    try:
        with os.fdopen(os.open(str(path), os.O_RDONLY | _O_FLAGS), "rb") as fh:
            return (fh.read(), None) if stat.S_ISREG(os.fstat(fh.fileno()).st_mode) else (None, "unsafe_path")
    except OSError as exc:
        return None, ("not_found" if isinstance(exc, FileNotFoundError) else "unsafe_path")

def _parse_ts_seconds(timestamp: str) -> float | None:
    try:
        return datetime.fromisoformat(timestamp.strip().replace("Z", "+00:00")).timestamp() if timestamp.strip() else None
    except ValueError:
        return None

def _nonneg_int(val: Any) -> int:
    return max(0, val) if isinstance(val, int) and not isinstance(val, bool) else 0

def _parse_span_pair(raw: Any, *, allow_none: bool) -> tuple[int, int] | None:
    if raw is None and allow_none:
        return (0, 0)
    return (int(raw[0]), int(raw[1])) if isinstance(raw, (list, tuple)) and len(raw) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in raw) else None

def _normalize_event_row(raw: Any, *, require_schema: bool) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    sv = raw.get("schema_version")
    if (require_schema and (isinstance(sv, bool) or sv != RECEIPT_SCHEMA_VERSION)) or (
        sv is not None and (isinstance(sv, bool) or sv != RECEIPT_SCHEMA_VERSION)
    ):
        return None
    eid, ev_type = str(raw.get("event_id") or raw.get("receipt_id") or "").strip(), str(raw.get("event_type") or "").strip()
    ls, bs = _parse_span_pair(raw.get("line_span"), allow_none=not require_schema), _parse_span_pair(raw.get("byte_span"), allow_none=not require_schema)
    if not eid or not ev_type or ls is None or bs is None:
        return None
    ts = str(raw.get("timestamp") or "").strip()
    parsed_ep, raw_ts_ms = _parse_ts_seconds(ts), raw.get("ts_ms")
    ts_ms = max(0, raw_ts_ms) if isinstance(raw_ts_ms, int) and not isinstance(raw_ts_ms, bool) else (
        max(0, int(round(parsed_ep * 1000))) if parsed_ep is not None else 0
    )
    ep_sec = parsed_ep if parsed_ep is not None else ((ts_ms / 1000.0) if ts_ms > 0 else None)
    raw_dur = raw.get("hook_duration_ms")
    dur_ms = float(raw_dur) if isinstance(raw_dur, (int, float)) and not isinstance(raw_dur, bool) and math.isfinite(float(raw_dur)) else 0.0
    fk = raw["failure_kind"].strip() if isinstance(raw.get("failure_kind"), str) and raw["failure_kind"].strip() else None
    reason = raw["reason"] if isinstance(raw.get("reason"), str) and raw["reason"].strip() else None
    raw_tc = raw.get("turn_correlation")
    tc = raw_tc if isinstance(raw_tc, str) and raw_tc in VALID_TURN_CORRELATIONS else "unobserved"
    mode = str(raw.get("mode") or "").strip() or ("active" if ev_type in ("spool_created", "spool_delivery_verified") else "recovery")
    status = str(raw.get("status") or "").strip() or ("error" if (ev_type == "spool_integrity_failure" or fk is not None) else "ok")
    parent_eid = raw["parent_event_id"].strip() if isinstance(raw.get("parent_event_id"), str) and raw["parent_event_id"].strip() else None
    return {
        "event_id": eid, "receipt_id": str(raw.get("receipt_id") or "").strip(), "parent_event_id": parent_eid,
        "timestamp": ts, "ts_ms": ts_ms, "epoch_s": ep_sec, "hook_duration_ms": max(0.0, dur_ms),
        "event_type": ev_type, "harness": str(raw.get("harness") or "").strip(),
        "session_id": str(raw.get("session_id") or ""), "workspace_id": str(raw.get("workspace_id") or ""),
        "turn_key": str(raw.get("turn_key") or ""), "turn_correlation": tc, "call_id": str(raw.get("call_id") or ""),
        "spool_id": str(raw.get("spool_id") or "").strip(),
        "intervention": str(raw.get("intervention") or "").strip() or "output_spool",
        "mode": mode, "status": status, "line_span": ls, "byte_span": bs, "source_hash": str(raw.get("source_hash") or ""),
        "original_bytes": _nonneg_int(raw.get("original_bytes")), "replacement_bytes": _nonneg_int(raw.get("replacement_bytes")),
        "upstream_truncation": bool(raw.get("upstream_truncation", False)),
        "delivery_evidence": str(raw.get("delivery_evidence") or "").strip(),
        "spool_id_referenced": bool(raw.get("spool_id_referenced", False)), "failure_kind": fk, "reason": reason,
    }

def _load_receipts_events(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    raw_bytes, err = _read_regular_bytes(path)
    if err is not None or raw_bytes is None:
        return [], ("unsafe_path" if err == "unsafe_path" else None)
    out: list[dict[str, Any]] = []
    for line in raw_bytes.decode("utf-8", errors="replace").splitlines():
        try:
            parsed = json.loads(line) if line.strip() else None
        except ValueError:
            continue
        if (norm := _normalize_event_row(parsed, require_schema=True)) is not None:
            out.append(norm)
    return out, None

def _load_ledger_events(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    raw_bytes, err = _read_regular_bytes(path)
    if err is not None or raw_bytes is None:
        return [], ("unsafe_path" if err == "unsafe_path" else None)
    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return [], None
    items: list[Any] = []
    if isinstance(parsed, Mapping) and parsed.get("schema_version") in (None, 1) and not isinstance(parsed.get("schema_version"), bool):
        items = parsed["events"] if isinstance(parsed.get("events"), list) else []
    elif isinstance(parsed, list):
        items = parsed
    return [norm for item in items if (norm := _normalize_event_row(item, require_schema=False)) is not None], None

def _otel_kv(key: str, val: str | int | float | bool) -> dict[str, Any]:
    if isinstance(val, bool):
        return {"key": key, "value": {"boolValue": val}}
    if isinstance(val, int):
        return {"key": key, "value": {"intValue": str(val)}}
    return {"key": key, "value": {"doubleValue": val} if isinstance(val, float) else {"stringValue": val}}

def _derive_span_id(seed_id: str) -> str:
    d = hashlib.sha256(f"cg-span:{seed_id}".encode("utf-8")).hexdigest()[:16]
    return ("0" * 15 + "1") if d == "0" * 16 else d

def _derive_trace_id(harness: str, session_hash: str, turn_key: str, call_id: str, spool_id: str) -> str:
    d = hashlib.sha256(f"cg-trace:{harness}:{session_hash}:{turn_key or call_id or spool_id}".encode("utf-8")).hexdigest()[:32]
    return ("0" * 31 + "1") if d == "0" * 32 else d

def _build_event_otel_pair(ev: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    event_id, event_type = _scrub_text(str(ev["event_id"])), _scrub_text(str(ev["event_type"]))
    harness, spool_id = _scrub_text(str(ev["harness"])), _scrub_text(str(ev["spool_id"]))
    session_hash, workspace_id = _hash_session_id(str(ev["session_id"])), _scrub_workspace_id(str(ev["workspace_id"]))
    trace_id = _derive_trace_id(harness, session_hash, str(ev["turn_key"]), str(ev["call_id"]), spool_id)
    span_id = _derive_span_id(str(ev["event_id"]))
    ls_start, ls_end = ev["line_span"]
    bs_start, bs_end = ev["byte_span"]
    status_str = _scrub_text(str(ev["status"]))
    kv_pairs: list[tuple[str, str | int | float | bool]] = [
        ("context_guard.event_id", event_id), ("context_guard.receipt_id", _scrub_text(str(ev["receipt_id"]))),
        ("context_guard.event_type", event_type), ("context_guard.spool_id", spool_id),
        ("context_guard.harness", harness), ("context_guard.intervention", _scrub_text(str(ev["intervention"]))),
        ("context_guard.mode", _scrub_text(str(ev["mode"]))), ("context_guard.status", status_str),
        ("context_guard.delivery_evidence", _scrub_text(str(ev["delivery_evidence"]))),
        ("context_guard.turn_correlation", _scrub_text(str(ev["turn_correlation"]))),
        ("context_guard.original_bytes", int(ev["original_bytes"])), ("context_guard.replacement_bytes", int(ev["replacement_bytes"])),
        ("context_guard.line_span_start", int(ls_start)), ("context_guard.line_span_end", int(ls_end)),
        ("context_guard.byte_span_start", int(bs_start)), ("context_guard.byte_span_end", int(bs_end)),
        ("context_guard.source_hash", _scrub_source_hash(str(ev["source_hash"]))),
        ("context_guard.upstream_truncation", bool(ev["upstream_truncation"])),
        ("context_guard.spool_id_referenced", bool(ev["spool_id_referenced"])),
        ("context_guard.workspace_id", workspace_id), ("context_guard.session_hash", session_hash),
    ]
    if ev.get("failure_kind") is not None:
        kv_pairs.append(("context_guard.failure_kind", _scrub_text(str(ev["failure_kind"]))))
    scrubbed_reason = _scrub_text(str(ev["reason"])) if ev.get("reason") is not None else ""
    if ev.get("reason") is not None:
        kv_pairs.append(("context_guard.reason", scrubbed_reason))
    attrs = [_otel_kv(k, v) for k, v in kv_pairs]

    start_ns = max(0, int(ev["ts_ms"])) * 1_000_000
    end_ns = start_ns + max(0, int(round(float(ev["hook_duration_ms"]) * 1_000_000)))
    is_err = status_str == "error"
    span: dict[str, Any] = {
        "traceId": trace_id, "spanId": span_id, "name": f"context_guard.{event_type}", "kind": 1,
        "startTimeUnixNano": str(start_ns), "endTimeUnixNano": str(end_ns), "attributes": attrs,
        "status": {"code": 2, "message": scrubbed_reason} if is_err else {"code": 1},
    }
    if isinstance(ev.get("parent_event_id"), str) and ev["parent_event_id"]:
        span["parentSpanId"] = _derive_span_id(str(ev["parent_event_id"]))
    log_record: dict[str, Any] = {
        "timeUnixNano": str(start_ns), "observedTimeUnixNano": str(end_ns),
        "severityNumber": 17 if is_err else 9, "severityText": "ERROR" if is_err else "INFO",
        "body": {"stringValue": event_type}, "traceId": trace_id, "spanId": span_id, "attributes": list(attrs),
    }
    return span, log_record

def _summarize_outcomes_v4(outcomes_path: Path) -> tuple[dict[str, int] | None, str | None]:
    if check_unsafe_link(outcomes_path.parent) or check_unsafe_link(outcomes_path) or (outcomes_path.exists() and outcomes_path.is_dir()):
        return None, "unsafe_path"
    doc = load_outcomes(outcomes_path)
    by_key = doc.get("by_key") if isinstance(doc, Mapping) else {}
    interventions = confirmed = suspected = 0
    if isinstance(by_key, Mapping):
        for row in by_key.values():
            if isinstance(row, Mapping):
                interventions += _nonneg_int(row.get("total"))
                if isinstance((reg := row.get("regret")), Mapping):
                    confirmed += _nonneg_int(reg.get("confirmed"))
                    suspected += _nonneg_int(reg.get("suspected"))
    raw_sv = doc.get("schema_version", 4) if isinstance(doc, Mapping) else 4
    sv = int(raw_sv) if isinstance(raw_sv, int) and not isinstance(raw_sv, bool) else 4
    return {"schema_version": sv, "interventions": interventions, "confirmed_regrets": confirmed, "suspected_regrets": suspected}, None

def _error_bundle(error: str) -> dict[str, Any]:
    return {"schema_version": OTEL_EXPORT_SCHEMA_VERSION, "ok": False, "error": error, "exported_events": 0, "privacy_scrubbed": True, "resourceSpans": [], "resourceLogs": []}

def build_otel_export_bundle(
    *, receipts_path: Path | None = None, ledger_path: Path | None = None, outcomes_path: Path | None = None,
    window_seconds: float | None = None, now_ts: float | None = None, service_name: str = "context-guard",
) -> dict[str, Any]:
    """Build a privacy-scrubbed OTLP/JSON export bundle strictly off the hook hot path."""
    rcpt_events, rcpt_err = _load_receipts_events(receipts_path if receipts_path is not None else receipts_path_for())
    if rcpt_err is not None:
        return _error_bundle(rcpt_err)
    ledger_events, led_err = _load_ledger_events(ledger_path) if ledger_path is not None else ([], None)
    if led_err is not None:
        return _error_bundle(led_err)
    outcomes_summary, out_err = _summarize_outcomes_v4(outcomes_path) if outcomes_path is not None else (None, None)
    if out_err is not None:
        return _error_bundle(out_err)

    eff_now, seen_ids, deduped = (float(now_ts) if now_ts is not None else time.time()), set(), []
    for row in (*rcpt_events, *ledger_events):
        if (eid := str(row["event_id"])) in seen_ids:
            continue
        seen_ids.add(eid)
        if window_seconds is not None and ((ep := row.get("epoch_s")) is None or (eff_now - float(ep)) > float(window_seconds)):
            continue
        deduped.append(row)
    deduped.sort(key=lambda item: (int(item["ts_ms"]), str(item["timestamp"]), str(item["event_id"])))

    version = _read_service_version()
    resource_obj = {"attributes": [
        _otel_kv("service.name", _scrub_text(service_name.strip() or "context-guard")),
        _otel_kv("service.version", version), _otel_kv("telemetry.sdk.language", "python"),
        _otel_kv("context_guard.off_hot_path", True),
    ]}
    scope_obj = {"name": "context-guard.exporter", "version": version}
    pairs = [_build_event_otel_pair(ev) for ev in deduped]
    spans, log_records = [p[0] for p in pairs], [p[1] for p in pairs]

    now_ns = str(max(0, int(round(eff_now * 1_000_000_000))))
    if outcomes_summary is not None:
        log_records.append({
            "timeUnixNano": now_ns, "observedTimeUnixNano": now_ns, "severityNumber": 9, "severityText": "INFO",
            "body": {"stringValue": "context_guard.outcomes_summary"},
            "attributes": [_otel_kv("context_guard.event_type", "outcomes_summary"), *[
                _otel_kv(f"context_guard.outcomes.{k}", outcomes_summary[k])
                for k in ("schema_version", "interventions", "confirmed_regrets", "suspected_regrets")
            ]],
        })

    bundle: dict[str, Any] = {
        "schema_version": OTEL_EXPORT_SCHEMA_VERSION, "ok": True, "exported_events": len(spans), "privacy_scrubbed": True,
        "resourceSpans": [{"resource": resource_obj, "scopeSpans": [{"scope": scope_obj, "spans": spans}]}] if spans else [],
        "resourceLogs": [{"resource": resource_obj, "scopeLogs": [{"scope": scope_obj, "logRecords": log_records}]}] if log_records else [],
    }
    if outcomes_summary is not None:
        bundle["outcomes_summary"] = outcomes_summary
        bundle["resourceMetrics"] = [{"resource": resource_obj, "scopeMetrics": [{"scope": scope_obj, "metrics": [
            {"name": f"context_guard.outcomes.{mk}", "gauge": {"dataPoints": [{"timeUnixNano": now_ns, "asInt": str(outcomes_summary[mk])}]}}
            for mk in ("interventions", "confirmed_regrets", "suspected_regrets")
        ]}]}]
    return bundle

def _render_bundle_bytes(bundle: Mapping[str, Any], *, ndjson: bool = False) -> bytes:
    if not ndjson:
        return (json.dumps(bundle, indent=2) + "\n").encode("utf-8")
    res_spans, res_logs = bundle.get("resourceSpans"), bundle.get("resourceLogs")
    spans: list[Any] = []
    logs: list[Any] = []
    resource_obj: Mapping[str, Any] = {}
    scope_obj: Mapping[str, Any] = {}
    if isinstance(res_spans, list) and res_spans and isinstance(res_spans[0], Mapping):
        if isinstance((ro := res_spans[0].get("resource")), Mapping):
            resource_obj = ro
        if isinstance((ss := res_spans[0].get("scopeSpans")), list) and ss and isinstance(ss[0], Mapping):
            if isinstance((sc := ss[0].get("scope")), Mapping):
                scope_obj = sc
            spans = list(ss[0].get("spans") or ())
    if isinstance(res_logs, list) and res_logs and isinstance(res_logs[0], Mapping):
        if isinstance((sl := res_logs[0].get("scopeLogs")), list) and sl and isinstance(sl[0], Mapping):
            logs = list(sl[0].get("logRecords") or ())
    lines = [
        json.dumps({
            "schema_version": OTEL_EXPORT_SCHEMA_VERSION, "privacy_scrubbed": True,
            "traceId": sp.get("traceId", ""), "spanId": sp.get("spanId", ""),
            "span": sp, "logRecord": logs[idx] if idx < len(logs) and isinstance(logs[idx], Mapping) else {},
            "resourceSpans": [{"resource": resource_obj, "scopeSpans": [{"scope": scope_obj, "spans": [sp]}]}],
            "resourceLogs": [{"resource": resource_obj, "scopeLogs": [{"scope": scope_obj, "logRecords": [logs[idx]] if idx < len(logs) else []}]}],
        }, separators=(",", ":"))
        for idx, sp in enumerate(spans) if isinstance(sp, Mapping)
    ]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")

def export_otel_to_file(bundle: Mapping[str, Any], output_path: Path, *, ndjson: bool = False) -> dict[str, Any]:
    """Atomically write an OTLP/JSON or NDJSON bundle to `output_path` with mode `0o600`."""
    if not bundle.get("ok"):
        return {"ok": False, "error": str(bundle.get("error") or "invalid_bundle"), "bytes_written": 0}
    out_p = Path(output_path)
    if check_unsafe_link(out_p.parent) or check_unsafe_link(out_p) or (out_p.exists() and out_p.is_dir()):
        return {"ok": False, "error": "unsafe_path", "bytes_written": 0}
    payload = _render_bundle_bytes(bundle, ndjson=ndjson)
    try:
        out_p.parent.mkdir(parents=True, exist_ok=True)
        if check_unsafe_link(out_p.parent) or check_unsafe_link(out_p):
            return {"ok": False, "error": "unsafe_path", "bytes_written": 0}
        atomic_write_bytes(out_p, payload)
    except OSError as exc:
        return {"ok": False, "error": "write_failed", "detail": _scrub_text(str(exc)), "bytes_written": 0}
    return {"ok": True, "error": None, "exported_events": int(bundle.get("exported_events", 0) or 0), "bytes_written": len(payload), "ndjson": bool(ndjson)}

def _validate_endpoint_url(endpoint: str) -> str | None:
    parsed = urllib.parse.urlparse(endpoint.strip())
    return None if (parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)) else "invalid_endpoint_scheme"

def post_otel_http(
    bundle: Mapping[str, Any], endpoint: str, *, timeout_seconds: float = 5.0, transport_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Send an opt-in OTLP/JSON HTTP(S) POST with strict URL scheme and timeout bounds."""
    clean_ep = endpoint.strip()
    if (scheme_err := _validate_endpoint_url(clean_ep)) is not None:
        return {"ok": False, "error": scheme_err, "detail": "Endpoint must be a valid http:// or https:// URL"}
    if not bundle.get("ok"):
        return {"ok": False, "error": str(bundle.get("error") or "invalid_bundle")}
    raw_to = float(timeout_seconds) if isinstance(timeout_seconds, (int, float)) and not isinstance(timeout_seconds, bool) else 5.0
    eff_timeout = min(30.0, max(0.5, raw_to if math.isfinite(raw_to) else 5.0))
    req = urllib.request.Request(
        clean_ep, data=json.dumps(bundle, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        resp = transport_fn(req, timeout=eff_timeout) if transport_fn is not None else urllib.request.urlopen(req, timeout=eff_timeout)
        if hasattr(resp, "__enter__"):
            with resp as ctx_resp:
                status_code = int(getattr(ctx_resp, "status", None) or getattr(ctx_resp, "code", None) or 200)
        else:
            status_code = int(getattr(resp, "status", None) or getattr(resp, "code", None) or 200)
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": "otel_post_failed", "status_code": int(exc.code), "detail": _scrub_text(f"HTTPError {exc.code}: {exc.reason}")}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "error": "otel_post_failed", "detail": _scrub_text(f"{type(exc).__name__}: {exc}")}
    if status_code < 200 or status_code >= 300:
        return {"ok": False, "error": "otel_post_failed", "status_code": status_code, "detail": f"HTTP {status_code}"}
    return {"ok": True, "error": None, "status_code": status_code, "exported_events": int(bundle.get("exported_events", 0) or 0), "timeout_seconds": eff_timeout}

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cg-export", description="Off-hot-path OTLP/JSON telemetry exporter.")
    p.add_argument("--otel", action="store_true", help="Export scrubbed OTLP/JSON spans and logs.")
    p.add_argument("--receipts-path", type=Path, default=None, help="Override receipts.jsonl path.")
    p.add_argument("--ledger-path", type=Path, default=None, help="Optional evidence_events.json path.")
    p.add_argument("--outcomes-path", type=Path, default=None, help="Optional outcomes.json path.")
    p.add_argument("--window-seconds", type=float, default=None, help="Trailing export window in seconds.")
    p.add_argument("--output", type=Path, default=None, help="Atomically write payload to path.")
    p.add_argument("--ndjson", action="store_true", help="Emit one scrubbed event JSON object per line.")
    p.add_argument("--endpoint", type=str, default=None, help="Opt-in HTTP/HTTPS OTLP endpoint URL.")
    p.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds (0.5..30.0).")
    p.add_argument("--service-name", type=str, default="context-guard", help="OTel service.name attribute.")
    p.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    return p

def _cli_err(code: str, detail: str | None = None, exit_code: int = 2) -> int:
    print(json.dumps({"ok": False, "error": code, **({"detail": detail} if detail else {})}))
    return exit_code

def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `cg export --otel`."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        ns = _build_parser().parse_args(raw_argv[1:] if raw_argv and raw_argv[0] == "export" else raw_argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else _cli_err("invalid_arguments")
    if not ns.otel:
        return _cli_err("invalid_arguments", "--otel flag is required")
    if ns.window_seconds is not None and (not math.isfinite(float(ns.window_seconds)) or float(ns.window_seconds) < 0.0):
        return _cli_err("invalid_arguments", "--window-seconds must be >= 0")
    if ns.endpoint is not None and (ep_err := _validate_endpoint_url(str(ns.endpoint))) is not None:
        return _cli_err(ep_err, "Endpoint must use http:// or https://")

    bundle = build_otel_export_bundle(
        receipts_path=ns.receipts_path, ledger_path=ns.ledger_path, outcomes_path=ns.outcomes_path,
        window_seconds=ns.window_seconds, service_name=str(ns.service_name),
    )
    if not bundle.get("ok"):
        print(json.dumps(bundle))
        return 1
    status_summary: dict[str, Any] = {"ok": True, "exported_events": bundle["exported_events"]}
    if ns.output is not None:
        file_res = export_otel_to_file(bundle, Path(ns.output), ndjson=bool(ns.ndjson))
        if not file_res.get("ok"):
            print(json.dumps(file_res))
            return 1
        status_summary["file"] = file_res
    if ns.endpoint is not None:
        http_res = post_otel_http(bundle, str(ns.endpoint), timeout_seconds=float(ns.timeout))
        if not http_res.get("ok"):
            print(json.dumps(http_res))
            return 2 if http_res.get("error") == "invalid_endpoint_scheme" else 1
        status_summary["http"] = http_res
    if ns.output is None and ns.endpoint is None:
        sys.stdout.write(_render_bundle_bytes(bundle, ndjson=bool(ns.ndjson)).decode("utf-8"))
        return 0
    print(json.dumps(status_summary))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
