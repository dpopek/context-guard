"""Off-hot-path 100% stdlib OTLP/JSON telemetry export engine (`cg export --otel`)."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time
from typing import Any, Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request

from core.platform_io import atomic_write_bytes, check_unsafe_link, read_plugin_version
from core.scrub import hash_session_id, scrub_source_hash, scrub_string, scrub_workspace_id
from hooks.outcomes import load_outcomes
from policies.api import RECEIPT_SCHEMA_VERSION, VALID_TURN_CORRELATIONS
from spool.receipts import receipts_path_for

OTEL_EXPORT_SCHEMA_VERSION: int = 1
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)

ALLOWED_OTEL_EVENT_ATTRIBUTES: frozenset[str] = frozenset({
    "context_guard.event_id",
    "context_guard.receipt_id",
    "context_guard.event_type",
    "context_guard.spool_id",
    "context_guard.harness",
    "context_guard.intervention",
    "context_guard.mode",
    "context_guard.status",
    "context_guard.delivery_evidence",
    "context_guard.turn_correlation",
    "context_guard.original_bytes",
    "context_guard.replacement_bytes",
    "context_guard.line_span_start",
    "context_guard.line_span_end",
    "context_guard.byte_span_start",
    "context_guard.byte_span_end",
    "context_guard.source_hash",
    "context_guard.upstream_truncation",
    "context_guard.spool_id_referenced",
    "context_guard.workspace_id",
    "context_guard.session_hash",
    "context_guard.failure_kind",
    "context_guard.reason",
})
ALLOWED_OTEL_OUTCOMES_ATTRIBUTES: frozenset[str] = frozenset({
    "context_guard.event_type",
    "context_guard.outcomes.schema_version",
    "context_guard.outcomes.interventions",
    "context_guard.outcomes.confirmed_regrets",
    "context_guard.outcomes.suspected_regrets",
})
ALLOWED_OTEL_RESOURCE_ATTRIBUTES: frozenset[str] = frozenset({
    "service.name",
    "service.version",
    "telemetry.sdk.language",
    "context_guard.off_hot_path",
})

__all__ = [
    "ALLOWED_OTEL_EVENT_ATTRIBUTES",
    "ALLOWED_OTEL_OUTCOMES_ATTRIBUTES",
    "ALLOWED_OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_EXPORT_SCHEMA_VERSION",
    "build_otel_export_bundle",
    "export_otel_to_file",
    "post_otel_http",
    "render_bundle_bytes",
    "validate_endpoint_url",
]


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
    if isinstance(raw, (list, tuple)) and len(raw) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in raw):
        return (int(raw[0]), int(raw[1]))
    return None


def _normalize_event_row(raw: Any, *, require_schema: bool) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    sv = raw.get("schema_version")
    if (require_schema and (isinstance(sv, bool) or sv != RECEIPT_SCHEMA_VERSION)) or (
        sv is not None and (isinstance(sv, bool) or sv != RECEIPT_SCHEMA_VERSION)
    ):
        return None
    eid = str(raw.get("event_id") or raw.get("receipt_id") or "").strip()
    ev_type = str(raw.get("event_type") or "").strip()
    ls = _parse_span_pair(raw.get("line_span"), allow_none=not require_schema)
    bs = _parse_span_pair(raw.get("byte_span"), allow_none=not require_schema)
    if not eid or not ev_type or ls is None or bs is None:
        return None
    ts = str(raw.get("timestamp") or "").strip()
    parsed_ep, raw_ts_ms = _parse_ts_seconds(ts), raw.get("ts_ms")
    ts_ms = (
        max(0, raw_ts_ms)
        if isinstance(raw_ts_ms, int) and not isinstance(raw_ts_ms, bool)
        else (max(0, int(round(parsed_ep * 1000))) if parsed_ep is not None else 0)
    )
    ep_sec = parsed_ep if parsed_ep is not None else ((ts_ms / 1000.0) if ts_ms > 0 else None)
    raw_dur = raw.get("hook_duration_ms")
    dur_ms = (
        float(raw_dur)
        if isinstance(raw_dur, (int, float)) and not isinstance(raw_dur, bool) and math.isfinite(float(raw_dur))
        else 0.0
    )
    fk = raw["failure_kind"].strip() if isinstance(raw.get("failure_kind"), str) and raw["failure_kind"].strip() else None
    reason = raw["reason"] if isinstance(raw.get("reason"), str) and raw["reason"].strip() else None
    raw_tc = raw.get("turn_correlation")
    tc = raw_tc if isinstance(raw_tc, str) and raw_tc in VALID_TURN_CORRELATIONS else "unobserved"
    mode = str(raw.get("mode") or "").strip() or ("active" if ev_type in ("spool_created", "spool_delivery_verified") else "recovery")
    status = str(raw.get("status") or "").strip() or ("error" if (ev_type == "spool_integrity_failure" or fk is not None) else "ok")
    parent_eid = (
        raw["parent_event_id"].strip()
        if isinstance(raw.get("parent_event_id"), str) and raw["parent_event_id"].strip()
        else None
    )
    return {
        "event_id": eid,
        "receipt_id": str(raw.get("receipt_id") or "").strip(),
        "parent_event_id": parent_eid,
        "timestamp": ts,
        "ts_ms": ts_ms,
        "epoch_s": ep_sec,
        "hook_duration_ms": max(0.0, dur_ms),
        "event_type": ev_type,
        "harness": str(raw.get("harness") or "").strip(),
        "session_id": str(raw.get("session_id") or ""),
        "workspace_id": str(raw.get("workspace_id") or ""),
        "turn_key": str(raw.get("turn_key") or ""),
        "turn_correlation": tc,
        "call_id": str(raw.get("call_id") or ""),
        "spool_id": str(raw.get("spool_id") or "").strip(),
        "intervention": str(raw.get("intervention") or "").strip() or "output_spool",
        "mode": mode,
        "status": status,
        "line_span": ls,
        "byte_span": bs,
        "source_hash": str(raw.get("source_hash") or ""),
        "original_bytes": _nonneg_int(raw.get("original_bytes")),
        "replacement_bytes": _nonneg_int(raw.get("replacement_bytes")),
        "upstream_truncation": bool(raw.get("upstream_truncation", False)),
        "delivery_evidence": str(raw.get("delivery_evidence") or "").strip(),
        "spool_id_referenced": bool(raw.get("spool_id_referenced", False)),
        "failure_kind": fk,
        "reason": reason,
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
    event_id, event_type = scrub_string(str(ev["event_id"])), scrub_string(str(ev["event_type"]))
    harness, spool_id = scrub_string(str(ev["harness"])), scrub_string(str(ev["spool_id"]))
    session_hash = hash_session_id(str(ev["session_id"]))
    workspace_id = scrub_workspace_id(str(ev["workspace_id"]))
    trace_id = _derive_trace_id(harness, session_hash, str(ev["turn_key"]), str(ev["call_id"]), spool_id)
    span_id = _derive_span_id(str(ev["event_id"]))
    ls_start, ls_end = ev["line_span"]
    bs_start, bs_end = ev["byte_span"]
    status_str = scrub_string(str(ev["status"]))
    kv_pairs: list[tuple[str, str | int | float | bool]] = [
        ("context_guard.event_id", event_id),
        ("context_guard.receipt_id", scrub_string(str(ev["receipt_id"]))),
        ("context_guard.event_type", event_type),
        ("context_guard.spool_id", spool_id),
        ("context_guard.harness", harness),
        ("context_guard.intervention", scrub_string(str(ev["intervention"]))),
        ("context_guard.mode", scrub_string(str(ev["mode"]))),
        ("context_guard.status", status_str),
        ("context_guard.delivery_evidence", scrub_string(str(ev["delivery_evidence"]))),
        ("context_guard.turn_correlation", scrub_string(str(ev["turn_correlation"]))),
        ("context_guard.original_bytes", int(ev["original_bytes"])),
        ("context_guard.replacement_bytes", int(ev["replacement_bytes"])),
        ("context_guard.line_span_start", int(ls_start)),
        ("context_guard.line_span_end", int(ls_end)),
        ("context_guard.byte_span_start", int(bs_start)),
        ("context_guard.byte_span_end", int(bs_end)),
        ("context_guard.source_hash", scrub_source_hash(str(ev["source_hash"]))),
        ("context_guard.upstream_truncation", bool(ev["upstream_truncation"])),
        ("context_guard.spool_id_referenced", bool(ev["spool_id_referenced"])),
        ("context_guard.workspace_id", workspace_id),
        ("context_guard.session_hash", session_hash),
    ]
    if ev.get("failure_kind") is not None:
        kv_pairs.append(("context_guard.failure_kind", scrub_string(str(ev["failure_kind"]))))
    scrubbed_reason = scrub_string(str(ev["reason"])) if ev.get("reason") is not None else ""
    if ev.get("reason") is not None:
        kv_pairs.append(("context_guard.reason", scrubbed_reason))
    attrs = [_otel_kv(k, v) for k, v in kv_pairs]

    start_ns = max(0, int(ev["ts_ms"])) * 1_000_000
    end_ns = start_ns + max(0, int(round(float(ev["hook_duration_ms"]) * 1_000_000)))
    is_err = status_str == "error"
    span: dict[str, Any] = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": f"context_guard.{event_type}",
        "kind": 1,
        "startTimeUnixNano": str(start_ns),
        "endTimeUnixNano": str(end_ns),
        "attributes": attrs,
        "status": {"code": 2, "message": scrubbed_reason} if is_err else {"code": 1},
    }
    if isinstance(ev.get("parent_event_id"), str) and ev["parent_event_id"]:
        span["parentSpanId"] = _derive_span_id(str(ev["parent_event_id"]))
    log_record: dict[str, Any] = {
        "timeUnixNano": str(start_ns),
        "observedTimeUnixNano": str(end_ns),
        "severityNumber": 17 if is_err else 9,
        "severityText": "ERROR" if is_err else "INFO",
        "body": {"stringValue": event_type},
        "traceId": trace_id,
        "spanId": span_id,
        "attributes": list(attrs),
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
    return {
        "schema_version": sv,
        "interventions": interventions,
        "confirmed_regrets": confirmed,
        "suspected_regrets": suspected,
    }, None


def _error_bundle(error: str) -> dict[str, Any]:
    return {
        "schema_version": OTEL_EXPORT_SCHEMA_VERSION,
        "ok": False,
        "error": error,
        "exported_events": 0,
        "privacy_scrubbed": True,
        "resourceSpans": [],
        "resourceLogs": [],
    }


def build_otel_export_bundle(
    *,
    receipts_path: Path | None = None,
    ledger_path: Path | None = None,
    outcomes_path: Path | None = None,
    window_seconds: float | None = None,
    now_ts: float | None = None,
    service_name: str = "context-guard",
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

    eff_now = float(now_ts) if now_ts is not None else time.time()
    seen_ids: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for row in (*rcpt_events, *ledger_events):
        if (eid := str(row["event_id"])) in seen_ids:
            continue
        seen_ids.add(eid)
        if window_seconds is not None and ((ep := row.get("epoch_s")) is None or (eff_now - float(ep)) > float(window_seconds)):
            continue
        deduped.append(row)
    deduped.sort(key=lambda item: (int(item["ts_ms"]), str(item["timestamp"]), str(item["event_id"])))

    version = scrub_string(read_plugin_version(default="unknown"))
    resource_obj = {
        "attributes": [
            _otel_kv("service.name", scrub_string(service_name.strip() or "context-guard")),
            _otel_kv("service.version", version),
            _otel_kv("telemetry.sdk.language", "python"),
            _otel_kv("context_guard.off_hot_path", True),
        ]
    }
    scope_obj = {"name": "context-guard.exporter", "version": version}
    pairs = [_build_event_otel_pair(ev) for ev in deduped]
    spans, log_records = [p[0] for p in pairs], [p[1] for p in pairs]

    now_ns = str(max(0, int(round(eff_now * 1_000_000_000))))
    if outcomes_summary is not None:
        log_records.append(
            {
                "timeUnixNano": now_ns,
                "observedTimeUnixNano": now_ns,
                "severityNumber": 9,
                "severityText": "INFO",
                "body": {"stringValue": "context_guard.outcomes_summary"},
                "attributes": [
                    _otel_kv("context_guard.event_type", "outcomes_summary"),
                    *[
                        _otel_kv(f"context_guard.outcomes.{k}", outcomes_summary[k])
                        for k in ("schema_version", "interventions", "confirmed_regrets", "suspected_regrets")
                    ],
                ],
            }
        )

    bundle: dict[str, Any] = {
        "schema_version": OTEL_EXPORT_SCHEMA_VERSION,
        "ok": True,
        "exported_events": len(spans),
        "privacy_scrubbed": True,
        "resourceSpans": [{"resource": resource_obj, "scopeSpans": [{"scope": scope_obj, "spans": spans}]}] if spans else [],
        "resourceLogs": [{"resource": resource_obj, "scopeLogs": [{"scope": scope_obj, "logRecords": log_records}]}] if log_records else [],
    }
    if outcomes_summary is not None:
        bundle["outcomes_summary"] = outcomes_summary
        bundle["resourceMetrics"] = [
            {
                "resource": resource_obj,
                "scopeMetrics": [
                    {
                        "scope": scope_obj,
                        "metrics": [
                            {
                                "name": f"context_guard.outcomes.{mk}",
                                "gauge": {"dataPoints": [{"timeUnixNano": now_ns, "asInt": str(outcomes_summary[mk])}]},
                            }
                            for mk in ("interventions", "confirmed_regrets", "suspected_regrets")
                        ],
                    }
                ],
            }
        ]
    return bundle


def render_bundle_bytes(bundle: Mapping[str, Any], *, ndjson: bool = False) -> bytes:
    """Serialize an OTLP/JSON export bundle as pretty JSON or NDJSON per-event lines."""
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
        json.dumps(
            {
                "schema_version": OTEL_EXPORT_SCHEMA_VERSION,
                "privacy_scrubbed": True,
                "traceId": sp.get("traceId", ""),
                "spanId": sp.get("spanId", ""),
                "span": sp,
                "logRecord": logs[idx] if idx < len(logs) and isinstance(logs[idx], Mapping) else {},
                "resourceSpans": [{"resource": resource_obj, "scopeSpans": [{"scope": scope_obj, "spans": [sp]}]}],
                "resourceLogs": [
                    {"resource": resource_obj, "scopeLogs": [{"scope": scope_obj, "logRecords": [logs[idx]] if idx < len(logs) else []}]}
                ],
            },
            separators=(",", ":"),
        )
        for idx, sp in enumerate(spans)
        if isinstance(sp, Mapping)
    ]
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def export_otel_to_file(bundle: Mapping[str, Any], output_path: Path, *, ndjson: bool = False) -> dict[str, Any]:
    """Atomically write an OTLP/JSON or NDJSON bundle to `output_path` with mode `0o600`."""
    if not bundle.get("ok"):
        return {"ok": False, "error": str(bundle.get("error") or "invalid_bundle"), "bytes_written": 0}
    out_p = Path(output_path)
    if check_unsafe_link(out_p.parent) or check_unsafe_link(out_p) or (out_p.exists() and out_p.is_dir()):
        return {"ok": False, "error": "unsafe_path", "bytes_written": 0}
    payload = render_bundle_bytes(bundle, ndjson=ndjson)
    try:
        out_p.parent.mkdir(parents=True, exist_ok=True)
        if check_unsafe_link(out_p.parent) or check_unsafe_link(out_p):
            return {"ok": False, "error": "unsafe_path", "bytes_written": 0}
        atomic_write_bytes(out_p, payload)
    except OSError as exc:
        return {"ok": False, "error": "write_failed", "detail": scrub_string(str(exc)), "bytes_written": 0}
    return {
        "ok": True,
        "error": None,
        "exported_events": int(bundle.get("exported_events", 0) or 0),
        "bytes_written": len(payload),
        "ndjson": bool(ndjson),
    }


def validate_endpoint_url(endpoint: str) -> str | None:
    """Validate opt-in OTLP endpoint uses http:// or https:// with a network location."""
    parsed = urllib.parse.urlparse(endpoint.strip())
    return None if (parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)) else "invalid_endpoint_scheme"


def post_otel_http(
    bundle: Mapping[str, Any],
    endpoint: str,
    *,
    timeout_seconds: float = 5.0,
    transport_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Send an opt-in OTLP/JSON HTTP(S) POST with strict URL scheme and timeout bounds."""
    clean_ep = endpoint.strip()
    if (scheme_err := validate_endpoint_url(clean_ep)) is not None:
        return {"ok": False, "error": scheme_err, "detail": "Endpoint must be a valid http:// or https:// URL"}
    if not bundle.get("ok"):
        return {"ok": False, "error": str(bundle.get("error") or "invalid_bundle")}
    raw_to = float(timeout_seconds) if isinstance(timeout_seconds, (int, float)) and not isinstance(timeout_seconds, bool) else 5.0
    eff_timeout = min(30.0, max(0.5, raw_to if math.isfinite(raw_to) else 5.0))
    req = urllib.request.Request(
        clean_ep,
        data=json.dumps(bundle, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = transport_fn(req, timeout=eff_timeout) if transport_fn is not None else urllib.request.urlopen(req, timeout=eff_timeout)
        if hasattr(resp, "__enter__"):
            with resp as ctx_resp:
                status_code = int(getattr(ctx_resp, "status", None) or getattr(ctx_resp, "code", None) or 200)
        else:
            status_code = int(getattr(resp, "status", None) or getattr(resp, "code", None) or 200)
    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "error": "otel_post_failed",
            "status_code": int(exc.code),
            "detail": scrub_string(f"HTTPError {exc.code}: {exc.reason}"),
        }
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "error": "otel_post_failed", "detail": scrub_string(f"{type(exc).__name__}: {exc}")}
    if status_code < 200 or status_code >= 300:
        return {"ok": False, "error": "otel_post_failed", "status_code": status_code, "detail": f"HTTP {status_code}"}
    return {
        "ok": True,
        "error": None,
        "status_code": status_code,
        "exported_events": int(bundle.get("exported_events", 0) or 0),
        "timeout_seconds": eff_timeout,
    }
