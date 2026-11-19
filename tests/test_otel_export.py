"""Contract, privacy, deterministic ID, HTTP opt-in, and hot-path AST isolation tests for `bin/cg_export.py`."""

from __future__ import annotations

import ast
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
import urllib.error
import urllib.request

import pytest

from bin import cg_export
from services import export_service
from evidence.ledger import append_durable_events
from hooks.outcomes import record_direct_outcome
from spool.receipts import append_receipt, build_receipt
from spool.store import spool_tool_output

ROOT = Path(__file__).resolve().parent.parent


def _attr_map(attrs: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in attrs:
        val_obj = item["value"]
        if "stringValue" in val_obj:
            out[str(item["key"])] = val_obj["stringValue"]
        elif "boolValue" in val_obj:
            out[str(item["key"])] = val_obj["boolValue"]
        elif "intValue" in val_obj:
            out[str(item["key"])] = int(val_obj["intValue"])
        elif "doubleValue" in val_obj:
            out[str(item["key"])] = float(val_obj["doubleValue"])
    return out


def _try_symlink(target: Path, link_path: Path) -> bool:
    try:
        os.symlink(str(target), str(link_path))
        return True
    except (OSError, NotImplementedError):
        return False


def test_otel_export_builds_valid_otlp_spans_and_logs_with_deterministic_ids(tmp_path: Path) -> None:
    empty_receipts = tmp_path / "empty_spool" / "receipts.jsonl"
    empty_bundle = export_service.build_otel_export_bundle(receipts_path=empty_receipts)
    assert empty_bundle == {
        "schema_version": export_service.OTEL_EXPORT_SCHEMA_VERSION,
        "ok": True,
        "exported_events": 0,
        "privacy_scrubbed": True,
        "resourceSpans": [],
        "resourceLogs": [],
    }

    receipts_path = tmp_path / "spool" / "receipts.jsonl"
    created = build_receipt(
        event_type="spool_created",
        harness="claude",
        session_id="sess_alpha_01",
        workspace_id="ws_0123456789abcdef",
        turn_key="turn_07",
        call_id="call_01",
        spool_id="sp_0123456789ab",
        line_span=(1, 240),
        byte_span=(0, 12800),
        upstream_truncation=False,
        delivery_evidence="replacement_emitted",
        spool_id_referenced=False,
        timestamp="2026-11-18T12:00:00Z",
        ts_ms=1_795_003_200_000,
        hook_duration_ms=4.5,
        event_id="ev_0000000000000001",
        turn_correlation="harness_native",
        source_hash="a" * 64,
        original_bytes=12800,
        replacement_bytes=640,
    )
    sliced = build_receipt(
        event_type="spool_sliced",
        harness="claude",
        session_id="sess_alpha_01",
        workspace_id="ws_0123456789abcdef",
        turn_key="turn_07",
        call_id="call_02",
        spool_id="sp_0123456789ab",
        line_span=(10, 50),
        byte_span=(400, 2100),
        delivery_evidence="delivery_verified",
        spool_id_referenced=True,
        parent_event_id="ev_0000000000000001",
        timestamp="2026-11-18T12:00:02Z",
        ts_ms=1_795_003_202_000,
        hook_duration_ms=2.0,
        event_id="ev_0000000000000002",
    )
    failed = build_receipt(
        event_type="spool_integrity_failure",
        harness="claude",
        session_id="sess_alpha_01",
        workspace_id="ws_0123456789abcdef",
        turn_key="",
        call_id="call_03",
        spool_id="sp_0123456789ab",
        line_span=(0, 0),
        byte_span=(0, 0),
        delivery_evidence="unverified",
        spool_id_referenced=True,
        failure_kind="reliability_failure",
        reason="integrity_mismatch",
        timestamp="2026-11-18T12:00:05Z",
        ts_ms=1_795_003_205_000,
        hook_duration_ms=1.25,
        event_id="ev_0000000000000003",
    )
    for row in (sliced, created, failed):
        assert append_receipt(row, receipts_path) is True

    bundle_a = export_service.build_otel_export_bundle(receipts_path=receipts_path)
    bundle_b = export_service.build_otel_export_bundle(receipts_path=receipts_path)
    assert bundle_a == bundle_b
    assert bundle_a["schema_version"] == 1
    assert bundle_a["ok"] is True
    assert bundle_a["exported_events"] == 3
    assert bundle_a["privacy_scrubbed"] is True

    manifest_version = str(json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))["version"])
    res_attrs = _attr_map(bundle_a["resourceSpans"][0]["resource"]["attributes"])
    assert set(res_attrs) == set(export_service.ALLOWED_OTEL_RESOURCE_ATTRIBUTES)
    assert res_attrs == {
        "service.name": "context-guard",
        "service.version": manifest_version,
        "telemetry.sdk.language": "python",
        "context_guard.off_hot_path": True,
    }

    spans = bundle_a["resourceSpans"][0]["scopeSpans"][0]["spans"]
    logs = bundle_a["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert len(spans) == 3
    assert len(logs) == 3

    expected_sess_hash = "sha256:" + hashlib.sha256(b"sess_alpha_01").hexdigest()[:16]
    expected_trace_turn = hashlib.sha256(f"cg-trace:claude:{expected_sess_hash}:turn_07".encode("utf-8")).hexdigest()[:32]
    expected_span_1 = hashlib.sha256(b"cg-span:ev_0000000000000001").hexdigest()[:16]
    expected_span_2 = hashlib.sha256(b"cg-span:ev_0000000000000002").hexdigest()[:16]

    assert spans[0]["traceId"] == expected_trace_turn
    assert spans[0]["spanId"] == expected_span_1
    assert len(spans[0]["traceId"]) == 32 and spans[0]["traceId"] != "0" * 32
    assert len(spans[0]["spanId"]) == 16 and spans[0]["spanId"] != "0" * 16
    assert int(spans[0]["startTimeUnixNano"]) == 1_795_003_200_000 * 1_000_000
    assert int(spans[0]["endTimeUnixNano"]) - int(spans[0]["startTimeUnixNano"]) == 4_500_000
    assert spans[0]["status"] == {"code": 1}

    assert spans[1]["traceId"] == expected_trace_turn
    assert spans[1]["spanId"] == expected_span_2
    assert spans[1]["parentSpanId"] == expected_span_1

    assert spans[2]["status"] == {"code": 2, "message": "integrity_mismatch"}
    assert logs[2]["severityNumber"] == 17
    assert logs[2]["severityText"] == "ERROR"

    for sp, lg in zip(spans, logs):
        sp_attrs = _attr_map(sp["attributes"])
        lg_attrs = _attr_map(lg["attributes"])
        assert sp_attrs == lg_attrs
        assert set(sp_attrs).issubset(export_service.ALLOWED_OTEL_EVENT_ATTRIBUTES)
        assert sp_attrs["context_guard.session_hash"] == expected_sess_hash
        assert sp["traceId"] == lg["traceId"]
        assert sp["spanId"] == lg["spanId"]
        assert lg["timeUnixNano"] == sp["startTimeUnixNano"]


def test_otel_export_deduplicates_events_and_supports_window_and_outcomes(tmp_path: Path) -> None:
    receipts_path = tmp_path / "spool" / "receipts.jsonl"
    ledger_path = tmp_path / "telemetry" / "evidence_events.json"
    outcomes_path = tmp_path / "telemetry" / "outcomes.json"

    old_ev = build_receipt(
        event_type="spool_created",
        harness="cursor",
        session_id="sess_old",
        workspace_id="ws_1111222233334444",
        turn_key="t1",
        call_id="c1",
        spool_id="sp_111122223333",
        line_span=(1, 100),
        byte_span=(0, 4096),
        delivery_evidence="replacement_emitted",
        spool_id_referenced=False,
        timestamp="2026-11-18T10:00:00Z",
        ts_ms=1_794_996_000_000,
        event_id="ev_old_000000000001",
    )
    recent_shared = build_receipt(
        event_type="spool_delivery_verified",
        harness="cursor",
        session_id="sess_new",
        workspace_id="ws_1111222233334444",
        turn_key="t2",
        call_id="c2",
        spool_id="sp_111122223333",
        line_span=(1, 100),
        byte_span=(0, 4096),
        delivery_evidence="delivery_verified",
        spool_id_referenced=True,
        timestamp="2026-11-18T11:59:30Z",
        ts_ms=1_795_003_170_000,
        event_id="ev_shared_000000002",
    )
    ledger_only = build_receipt(
        event_type="spool_sliced",
        harness="cursor",
        session_id="sess_new",
        workspace_id="ws_1111222233334444",
        turn_key="t2",
        call_id="c3",
        spool_id="sp_111122223333",
        line_span=(1, 40),
        byte_span=(0, 1200),
        delivery_evidence="delivery_verified",
        spool_id_referenced=True,
        timestamp="2026-11-18T11:59:50Z",
        ts_ms=1_795_003_190_000,
        event_id="ev_ledger_000000003",
    )
    assert append_receipt(old_ev, receipts_path) is True
    assert append_receipt(recent_shared, receipts_path) is True
    led_res = append_durable_events(ledger_path, [recent_shared, ledger_only])
    assert led_res["ok"] is True

    record_direct_outcome(
        "claude", "claude-sonnet-4-6", "output_spool", "applied", outcomes_path,
        session_id="s1", step_idx=1, call_id="call_a",
    )
    record_direct_outcome(
        "claude", "claude-sonnet-4-6", "output_spool", "applied", outcomes_path,
        recovery="full", regret="suspected", evidence="observed", session_id="s1", step_idx=2, call_id="call_b",
    )
    record_direct_outcome(
        "claude", "claude-sonnet-4-6", "outline", "applied", outcomes_path,
        recovery="full", regret="confirmed", evidence="observed", session_id="s1", step_idx=3, call_id="call_c",
    )
    raw_outcomes = json.loads(outcomes_path.read_text(encoding="utf-8"))
    raw_outcomes["policy_packs"] = ["/Users/alice/private_policy_pack"]
    outcomes_path.write_text(json.dumps(raw_outcomes), encoding="utf-8")

    full_bundle = export_service.build_otel_export_bundle(
        receipts_path=receipts_path,
        ledger_path=ledger_path,
        outcomes_path=outcomes_path,
        now_ts=1_795_003_200.0,
    )
    assert full_bundle["ok"] is True
    assert full_bundle["exported_events"] == 3
    assert full_bundle["outcomes_summary"] == {
        "schema_version": 4,
        "interventions": 3,
        "confirmed_regrets": 1,
        "suspected_regrets": 1,
    }

    windowed_bundle = export_service.build_otel_export_bundle(
        receipts_path=receipts_path,
        ledger_path=ledger_path,
        outcomes_path=outcomes_path,
        window_seconds=120.0,
        now_ts=1_795_003_200.0,
    )
    assert windowed_bundle["exported_events"] == 2
    spans = windowed_bundle["resourceSpans"][0]["scopeSpans"][0]["spans"]
    exported_ids = [_attr_map(sp["attributes"])["context_guard.event_id"] for sp in spans]
    assert exported_ids == ["ev_shared_000000002", "ev_ledger_000000003"]

    log_records = windowed_bundle["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert len(log_records) == 3
    summary_log = log_records[-1]
    assert summary_log["body"] == {"stringValue": "context_guard.outcomes_summary"}
    summary_attrs = _attr_map(summary_log["attributes"])
    assert set(summary_attrs) == set(export_service.ALLOWED_OTEL_OUTCOMES_ATTRIBUTES)
    assert summary_attrs["context_guard.outcomes.interventions"] == 3
    assert summary_attrs["context_guard.outcomes.confirmed_regrets"] == 1
    assert summary_attrs["context_guard.outcomes.suspected_regrets"] == 1

    serialized = json.dumps(windowed_bundle)
    assert "policy_packs" not in serialized
    assert "private_policy_pack" not in serialized
    assert "/Users/alice" not in serialized


def test_otel_export_never_leaks_prompts_paths_or_raw_session_ids(tmp_path: Path) -> None:
    ws_dir = tmp_path / "workspace_proj"
    ws_dir.mkdir()
    (ws_dir / ".git").mkdir()
    spool_dir = tmp_path / "spool"
    receipts_path = spool_dir / "receipts.jsonl"
    ledger_path = tmp_path / "evidence_events.json"

    secret_blob = "\n".join(
        f"LINE {idx}: SYNTHETIC_SPOOLED_STDOUT_SECRET_PAYLOAD_8842" for idx in range(1, 220)
    )
    sp_res = spool_tool_output(
        secret_blob,
        session_id="/Users/alice/.claude/sessions/raw_session_secret_99",
        call_id="call_real_spool",
        harness="claude",
        tool_name="Bash",
        workspace_root=ws_dir,
        spool_dir=spool_dir,
        receipts_path=receipts_path,
    )
    assert sp_res is not None

    local_addr = "alice@workstation" + ".local"
    priv_domain = "team-internal" + ".atlassian" + ".net"
    priv_gcp = "corp" + "-warehouse-" + "98765"
    hostile_row = {
        "schema_version": 1,
        "receipt_id": "rcpt_hostile_0001",
        "event_id": "ev_hostile_00000001",
        "timestamp": "2026-11-18T12:10:00Z",
        "ts_ms": 1_795_003_800_000,
        "event_type": "spool_integrity_failure",
        "harness": "claude",
        "session_id": r"C:\Users\bob\AppData\Local\secret_win_session",
        "workspace_id": "/Users/alice/secret_workspace_path",
        "turn_key": "turn_secret",
        "call_id": "call_hostile",
        "spool_id": "sp_abcdef012345",
        "line_span": [1, 50],
        "byte_span": [0, 2048],
        "source_hash": "/Users/alice/not_a_hex_hash",
        "original_bytes": 2048,
        "replacement_bytes": 256,
        "upstream_truncation": True,
        "delivery_evidence": "unverified",
        "spool_id_referenced": False,
        "failure_kind": "reliability_failure",
        "reason": f"failed on /Users/alice/secret/blob.txt and C:\\Users\\bob\\key.pem by {local_addr} via {priv_domain} ({priv_gcp})",
        "prompt": "SYNTHETIC_RAW_USER_PROMPT_DO_NOT_EXPORT",
        "raw_prompt": "SYNTHETIC_RAW_PROMPT_FIELD_DO_NOT_EXPORT",
        "content": "SYNTHETIC_BLOB_CONTENT_DO_NOT_EXPORT",
        "command": "cat /Users/alice/.ssh/config",
        "tool_input": {"command": "SYNTHETIC_TOOL_INPUT_SECRET"},
        "tool_output": "SYNTHETIC_TOOL_OUTPUT_SECRET",
        "canon_root": "/Users/alice/secret_workspace_path",
    }
    with open(receipts_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(hostile_row) + "\n")
    ledger_path.write_text(json.dumps({"schema_version": 1, "events": [hostile_row]}), encoding="utf-8")

    bundle = export_service.build_otel_export_bundle(receipts_path=receipts_path, ledger_path=ledger_path)
    assert bundle["ok"] is True
    assert bundle["privacy_scrubbed"] is True
    assert bundle["exported_events"] == 2

    out_ndjson = tmp_path / "export.ndjson"
    assert export_service.export_otel_to_file(bundle, out_ndjson, ndjson=True)["ok"] is True
    combined_payload = json.dumps(bundle) + "\n" + out_ndjson.read_text(encoding="utf-8")

    forbidden_substrings = (
        "SYNTHETIC_SPOOLED_STDOUT_SECRET_PAYLOAD_8842",
        "SYNTHETIC_RAW_USER_PROMPT_DO_NOT_EXPORT",
        "SYNTHETIC_RAW_PROMPT_FIELD_DO_NOT_EXPORT",
        "SYNTHETIC_BLOB_CONTENT_DO_NOT_EXPORT",
        "SYNTHETIC_TOOL_INPUT_SECRET",
        "SYNTHETIC_TOOL_OUTPUT_SECRET",
        "raw_session_secret_99",
        "secret_win_session",
        "secret_workspace_path",
        "/Users/alice",
        "/Users/alice/secret",
        r"C:\Users\bob",
        "not_a_hex_hash",
        "canon_root",
        "tool_input",
        "tool_output",
        str(ws_dir),
        local_addr,
        priv_domain,
        priv_gcp,
    )
    for forbidden in forbidden_substrings:
        assert forbidden not in combined_payload, f"Leaked forbidden token in OTel export: {forbidden}"

    spans = bundle["resourceSpans"][0]["scopeSpans"][0]["spans"]
    for sp in spans:
        attrs = _attr_map(sp["attributes"])
        assert set(attrs).issubset(export_service.ALLOWED_OTEL_EVENT_ATTRIBUTES)
        assert re.match(r"^sha256:[0-9a-f]{16}$", str(attrs["context_guard.session_hash"]))
        assert re.match(r"^ws_[0-9a-f]{16}$", str(attrs["context_guard.workspace_id"]))


def test_otel_export_atomic_file_output_ndjson_and_unsafe_link_rejection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    receipts_path = tmp_path / "spool" / "receipts.jsonl"
    for idx in (1, 2):
        row = build_receipt(
            event_type="spool_created",
            harness="antigravity",
            session_id=f"sess_{idx}",
            workspace_id="ws_abcdef0123456789",
            turn_key=f"turn_{idx}",
            call_id=f"call_{idx}",
            spool_id="sp_abcdef012345",
            line_span=(1, 80),
            byte_span=(0, 3200),
            delivery_evidence="replacement_emitted",
            spool_id_referenced=False,
            timestamp=f"2026-11-18T12:00:0{idx}Z",
            ts_ms=1_795_003_200_000 + idx * 1000,
            event_id=f"ev_000000000000001{idx}",
        )
        assert append_receipt(row, receipts_path) is True

    out_json = tmp_path / "out" / "otel_bundle.json"
    rc_file = cg_export.main(["export", "--otel", "--receipts-path", str(receipts_path), "--output", str(out_json)])
    assert rc_file == 0
    _ = capsys.readouterr()
    assert out_json.is_file()
    assert list(out_json.parent.glob("*.tmp")) == []
    if os.name != "nt":
        assert stat.S_IMODE(out_json.stat().st_mode) == 0o600
    parsed_file = json.loads(out_json.read_text(encoding="utf-8"))
    assert parsed_file["exported_events"] == 2

    rc_ndjson = cg_export.main(["--otel", "--receipts-path", str(receipts_path), "--ndjson"])
    assert rc_ndjson == 0
    ndjson_stdout = capsys.readouterr().out
    nd_lines = [ln for ln in ndjson_stdout.splitlines() if ln.strip()]
    assert len(nd_lines) == 2
    for ln in nd_lines:
        rec = json.loads(ln)
        assert rec["privacy_scrubbed"] is True
        assert len(rec["traceId"]) == 32
        assert len(rec["spanId"]) == 16
        assert len(rec["resourceSpans"][0]["scopeSpans"][0]["spans"]) == 1

    rc_missing_flag = cg_export.main(["--receipts-path", str(receipts_path)])
    assert rc_missing_flag == 2
    _ = capsys.readouterr()

    dir_target = tmp_path / "existing_dir"
    dir_target.mkdir()
    bundle = export_service.build_otel_export_bundle(receipts_path=receipts_path)
    dir_res = export_service.export_otel_to_file(bundle, dir_target)
    assert dir_res["ok"] is False and dir_res["error"] == "unsafe_path"

    victim = tmp_path / "victim.txt"
    victim.write_text("KEEP_SAFE", encoding="utf-8")
    sym_out = tmp_path / "sym_out.json"
    if _try_symlink(victim, sym_out):
        sym_res = export_service.export_otel_to_file(bundle, sym_out)
        assert sym_res["ok"] is False and sym_res["error"] == "unsafe_path"
        assert victim.read_text(encoding="utf-8") == "KEEP_SAFE"
        rc_sym_out = cg_export.main(["--otel", "--receipts-path", str(receipts_path), "--output", str(sym_out)])
        assert rc_sym_out == 1
        _ = capsys.readouterr()

    real_sub = tmp_path / "real_sub"
    real_sub.mkdir()
    sym_parent = tmp_path / "sym_parent"
    if _try_symlink(real_sub, sym_parent):
        parent_res = export_service.export_otel_to_file(bundle, sym_parent / "nested.json")
        assert parent_res["ok"] is False and parent_res["error"] == "unsafe_path"

    sym_receipts = tmp_path / "sym_receipts.jsonl"
    if _try_symlink(receipts_path, sym_receipts):
        bad_bundle = export_service.build_otel_export_bundle(receipts_path=sym_receipts)
        assert bad_bundle["ok"] is False and bad_bundle["error"] == "unsafe_path"
        rc_sym_in = cg_export.main(["--otel", "--receipts-path", str(sym_receipts)])
        assert rc_sym_in == 1
        _ = capsys.readouterr()


def test_otel_export_http_post_scheme_validation_and_transport_handling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    receipts_path = tmp_path / "receipts.jsonl"
    assert append_receipt(
        build_receipt(
            event_type="spool_created",
            harness="codex",
            session_id="sess_http",
            workspace_id="ws_fedcba9876543210",
            turn_key="t_http",
            call_id="c_http",
            spool_id="sp_fedcba987654",
            line_span=(1, 30),
            byte_span=(0, 900),
            delivery_evidence="replacement_emitted",
            spool_id_referenced=False,
            event_id="ev_http_00000000001",
        ),
        receipts_path,
    )
    bundle = export_service.build_otel_export_bundle(receipts_path=receipts_path)

    called_urls: list[str] = []

    class _FakeResponse:
        def __init__(self, status: int = 200) -> None:
            self.status = status

        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

    def _never_called(req: urllib.request.Request, timeout: float = 5.0) -> _FakeResponse:
        called_urls.append(req.full_url)
        return _FakeResponse(200)

    for bad_url in ("file:///etc/passwd", "ftp://collector.example.com/v1/traces", "javascript:alert(1)", "http://"):
        res = export_service.post_otel_http(bundle, bad_url, transport_fn=_never_called)
        assert res["ok"] is False
        assert res["error"] == "invalid_endpoint_scheme"
    assert called_urls == []

    rc_bad_scheme = cg_export.main(["--otel", "--receipts-path", str(receipts_path), "--endpoint", "file:///etc/passwd"])
    assert rc_bad_scheme == 2
    bad_scheme_out = json.loads(capsys.readouterr().out)
    assert bad_scheme_out["error"] == "invalid_endpoint_scheme"

    captured_calls: list[tuple[str, str, str, float, dict[str, Any]]] = []

    def _ok_transport(req: urllib.request.Request, timeout: float = 5.0) -> _FakeResponse:
        raw_body = req.data.decode("utf-8") if isinstance(req.data, bytes) else ""
        hdrs = {k.lower(): v for k, v in req.header_items()}
        captured_calls.append((req.full_url, req.get_method(), hdrs.get("content-type", ""), timeout, json.loads(raw_body)))
        return _FakeResponse(202)

    low_to = export_service.post_otel_http(bundle, "https://collector.example.com/v1/traces", timeout_seconds=0.05, transport_fn=_ok_transport)
    high_to = export_service.post_otel_http(bundle, "http://127.0.0.1:4318/v1/traces", timeout_seconds=120.0, transport_fn=_ok_transport)
    assert low_to["ok"] is True and low_to["status_code"] == 202 and low_to["timeout_seconds"] == 0.5
    assert high_to["ok"] is True and high_to["timeout_seconds"] == 30.0
    assert len(captured_calls) == 2
    assert captured_calls[0][1] == "POST"
    assert captured_calls[0][2] == "application/json"
    assert captured_calls[0][4]["exported_events"] == 1

    def _err_url(req: urllib.request.Request, timeout: float = 5.0) -> _FakeResponse:
        raise urllib.error.URLError("TLS cert missing at /Users/alice/.certs/client.pem")

    err_res = export_service.post_otel_http(bundle, "https://collector.example.com/v1/traces", transport_fn=_err_url)
    assert err_res["ok"] is False
    assert err_res["error"] == "otel_post_failed"
    assert "/Users/alice" not in str(err_res.get("detail", ""))
    assert "[redacted-path]" in str(err_res.get("detail", ""))

    def _err_http(req: urllib.request.Request, timeout: float = 5.0) -> _FakeResponse:
        raise urllib.error.HTTPError(req.full_url, 503, "collector unavailable /Users/alice/cfg", hdrs=Message(), fp=io.BytesIO(b""))

    http_err_res = export_service.post_otel_http(bundle, "https://collector.example.com/v1/traces", transport_fn=_err_http)
    assert http_err_res["ok"] is False and http_err_res["status_code"] == 503
    assert "/Users/alice" not in str(http_err_res.get("detail", ""))

    monkeypatch.setattr(urllib.request, "urlopen", _err_url)
    rc_net_fail = cg_export.main(["--otel", "--receipts-path", str(receipts_path), "--endpoint", "https://collector.example.com/v1/traces"])
    assert rc_net_fail == 1
    net_fail_out = json.loads(capsys.readouterr().out)
    assert net_fail_out["error"] == "otel_post_failed"
    assert "/Users/alice" not in json.dumps(net_fail_out)


def test_hot_path_modules_have_zero_otel_or_network_imports() -> None:
    forbidden_any = ("cg_export", "opentelemetry", "http", "socket", "requests", "urllib3", "grpc")
    forbidden_urllib_net = ("urllib.request", "urllib.error", "urllib.robotparser")
    violations: list[str] = []

    for pkg in ("hooks", "spool", "policies", "integrations"):
        for py_path in sorted((ROOT / pkg).glob("*.py")):
            rel = py_path.relative_to(ROOT).as_posix()
            tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=rel)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    imported = [mod, *(f"{mod}.{alias.name}".strip(".") for alias in node.names)]
                else:
                    continue
                for mod_name in imported:
                    parts = mod_name.split(".")
                    if any(tok in parts for tok in forbidden_any):
                        violations.append(f"{rel}:{node.lineno} imports {mod_name}")
                    elif any(mod_name == net_m or mod_name.startswith(f"{net_m}.") for net_m in forbidden_urllib_net):
                        violations.append(f"{rel}:{node.lineno} imports {mod_name}")
                    elif pkg != "spool" and parts[0] == "urllib":
                        violations.append(f"{rel}:{node.lineno} imports {mod_name}")
    assert violations == [], f"Hot-path modules must remain free of OTel and network imports: {violations}"

    for exp_rel in ("bin/cg_export.py", "services/export_service.py"):
        exporter_tree = ast.parse((ROOT / exp_rel).read_text(encoding="utf-8"), filename=exp_rel)
        sdk_imports = [
            alias.name
            for node in ast.walk(exporter_tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if "opentelemetry" in alias.name
        ] + [
            node.module or ""
            for node in ast.walk(exporter_tree)
            if isinstance(node, ast.ImportFrom) and "opentelemetry" in (node.module or "")
        ]
        assert sdk_imports == []
