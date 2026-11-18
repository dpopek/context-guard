"""Contract, lifecycle, state-resolution, CLI, and zero-leakage privacy tests for `cg explain`."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import time
from typing import Any
import pytest

from bin.cg_explain import explain_intervention, main as explain_main, render_explain_markdown
from evidence.ledger import ingest_context_receipts
from policies import (
    BACKEND_BENCHMARK_SCHEMA_VERSION,
    EXPLAIN_SCHEMA_VERSION,
    OTEL_EXPORT_SCHEMA_VERSION,
    VALID_DELIVERY_EVIDENCE_TIERS,
    VALID_EXPLAIN_STATES,
    BackendBenchmarkContractV1,
    ExplainContractV1,
)
from policies.governor import attest_capability, record_governor_signal
from spool.receipts import (
    append_receipt,
    build_receipt,
    load_receipt_rows,
    persist_spool_delivery_verification,
    receipts_path_for,
)
from spool.store import (
    SPOOL_TOMBSTONE_MAX_AGE_SECONDS,
    SPOOL_TTL_SECONDS,
    gc_spools,
    grep_spool,
    inspect_spool_entry,
    slice_spool,
    spool_tool_output,
)


def _setup_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path, Path]:
    home_dir = tmp_path / "home"
    ws_dir = tmp_path / "workspace"
    state_dir = tmp_path / "state"
    spool_dir = state_dir / "spool"
    home_dir.mkdir(parents=True, exist_ok=True)
    (ws_dir / ".git").mkdir(parents=True, exist_ok=True)
    spool_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.setenv("CONTEXT_GUARD_STATE_DIR", str(state_dir))
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))
    return ws_dir, state_dir, spool_dir, receipts_path_for(spool_dir)


def _oversized_output(tag: str = "payload", lines: int = 260) -> str:
    return "\n".join(f"line {idx:04d} [{tag}]: " + ("x" * 72) for idx in range(1, lines + 1))


def _link_or_mock_unsafe(link_path: Path, target_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    try:
        link_path.symlink_to(target_path)
    except OSError:
        real_lstat = os.lstat
        norm_link = os.path.normcase(os.path.abspath(str(link_path)))

        def fake_lstat(p: str | os.PathLike[str]) -> os.stat_result:
            if os.path.normcase(os.path.abspath(os.fspath(p))) == norm_link:
                base = real_lstat(str(target_path))
                mode = (base.st_mode & ~stat.S_IFMT(base.st_mode)) | stat.S_IFLNK
                return os.stat_result((
                    mode, base.st_ino, base.st_dev, base.st_nlink, base.st_uid,
                    base.st_gid, base.st_size, int(base.st_atime), int(base.st_mtime), int(base.st_ctime),
                ))
            return real_lstat(p)

        monkeypatch.setattr(os, "lstat", fake_lstat)


def test_explain_by_event_id_receipt_id_and_spool_id_full_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify full spool lifecycle explanation across event_id, receipt_id, spool_id, and governor context."""
    assert EXPLAIN_SCHEMA_VERSION == 1
    assert OTEL_EXPORT_SCHEMA_VERSION == 1
    assert BACKEND_BENCHMARK_SCHEMA_VERSION == 1
    assert VALID_DELIVERY_EVIDENCE_TIERS == ("delivery_verified", "replacement_emitted", "unverified")
    assert VALID_EXPLAIN_STATES == (
        "available", "evicting", "evicted", "corrupt", "receipt_only", "not_spool_backed", "unknown",
    )
    assert ExplainContractV1 is not None and BackendBenchmarkContractV1 is not None

    ws_dir, state_dir, spool_dir, rcpt_path = _setup_env(tmp_path, monkeypatch)
    t_base = time.time()
    spooled = spool_tool_output(
        _oversized_output("alpha"),
        session_id="sess_01",
        call_id="call_01",
        harness="claude",
        tool_name="Bash",
        workspace_root=ws_dir,
        isolation="workspace",
        turn_key="turn_01",
        turn_correlation="harness_native",
        spool_dir=spool_dir,
        receipts_path=rcpt_path,
        now_ts=t_base - 20.0,
    )
    assert spooled is not None
    contract, summary_text = spooled
    sid = contract.spool_id

    entry_info = inspect_spool_entry(sid, spool_dir=spool_dir)
    assert entry_info["found"] is True
    assert entry_info["current_state"] == "available"
    assert entry_info["blob_present"] is True
    assert entry_info["total_lines"] == 260
    assert "canon_root" not in entry_info

    rows_initial = load_receipt_rows(rcpt_path)
    assert len(rows_initial) == 1
    created_row = rows_initial[0]
    assert created_row["event_id"] != created_row["receipt_id"]

    pre_verify = explain_intervention(
        created_row["event_id"], receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir
    )
    assert pre_verify["ok"] is True
    assert pre_verify["delivery_evidence_tier"] == "replacement_emitted"
    assert pre_verify["current_state"] == "available"

    emitted = persist_spool_delivery_verification(
        {"tool_calls": [{"tool_use_id": "call_01", "tool_response": summary_text}]},
        harness="claude",
        session_id="sess_01",
        workspace_root=ws_dir,
        turn_key="turn_01",
        spool_dir=spool_dir,
        receipts_path=rcpt_path,
    )
    assert emitted == 1

    sl_res = slice_spool(
        sid, start_line=10, limit=15, workspace_root=ws_dir, session_id="sess_01",
        isolation="workspace", harness="claude", receipts_path=rcpt_path, spool_dir=spool_dir,
        now_ts=t_base + 10.0, turn_key="turn_02", turn_correlation="harness_native", call_id="call_02",
    )
    assert sl_res["ok"] is True
    gr_res = grep_spool(
        sid, "line 0042", workspace_root=ws_dir, session_id="sess_01",
        isolation="workspace", harness="claude", receipts_path=rcpt_path, spool_dir=spool_dir,
        now_ts=t_base + 20.0, turn_key="turn_02", turn_correlation="harness_native", call_id="call_03",
    )
    assert gr_res["ok"] is True and gr_res["match_count"] == 1

    attest_capability(
        "claude", "output_replacement", verification_evidence="client_hook_probe:post_tool_replace_ok",
        harness_build_id="1.0.0", state_dir=state_dir,
    )
    record_governor_signal("output_spool", "integrity_mismatch", state_dir=state_dir, harness="claude", session_id="sess_01")

    by_ev = explain_intervention(created_row["event_id"], receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert by_ev["ok"] is True
    assert by_ev["matched_by"] == "event_id"
    assert by_ev["event_id"] == created_row["event_id"]
    assert by_ev["spool_id"] == sid
    assert by_ev["current_state"] == "available"
    assert by_ev["delivery_evidence_tier"] == "delivery_verified"
    assert by_ev["completeness"] == "complete"
    assert by_ev["privacy_scrubbed"] is True
    assert by_ev["spool_lifecycle"]["recovery_calls"] == 2
    assert by_ev["spool_lifecycle"]["recovery_model_turns"] == 1
    assert by_ev["spool_lifecycle"]["blob_present"] is True
    assert [t["event_type"] for t in by_ev["timeline"]] == [
        "spool_created", "spool_delivery_verified", "spool_recovery", "spool_recovery",
    ]
    assert by_ev["governor_context"]["tripped"] is True
    assert by_ev["governor_context"]["breaker_state"] == "open"
    assert by_ev["governor_context"]["trip_reason"] == "integrity_mismatch"
    assert by_ev["governor_context"]["attestation_count"] == 1

    by_rcpt = explain_intervention(created_row["receipt_id"], receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert by_rcpt["ok"] is True
    assert by_rcpt["matched_by"] == "receipt_id"
    assert by_rcpt["receipt_id"] == created_row["receipt_id"]

    by_spool = explain_intervention(sid, receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert by_spool["ok"] is True
    assert by_spool["matched_by"] == "spool_id"
    assert by_spool["event_type"] == "spool_recovery"
    assert len(by_spool["timeline"]) == 4

    non_spool = build_receipt(
        event_type="read_dedup", harness="claude", session_id="sess_01", workspace_id="ws_01",
        turn_key="turn_03", call_id="call_09", spool_id="", line_span=(1, 20), byte_span=(0, 400),
        delivery_evidence="delivery_verified", spool_id_referenced=False, event_id="ev_non_spool_0001",
    )
    assert append_receipt(non_spool, receipts_path=rcpt_path) is True
    ns_rep = explain_intervention("ev_non_spool_0001", receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert ns_rep["ok"] is True
    assert ns_rep["current_state"] == "not_spool_backed"
    assert ns_rep["delivery_evidence_tier"] == "delivery_verified"


def test_explain_reports_evicting_evicted_and_exact_eviction_reasons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify evicting vs evicted tombstone states and exact ttl_expired, max_entries_lru, and max_bytes_lru causes."""
    ws_dir, state_dir, spool_dir, rcpt_path = _setup_env(tmp_path, monkeypatch)
    t0 = 1_700_100_000.0
    sp_ttl = spool_tool_output(
        _oversized_output("ttl"), session_id="s1", call_id="c1", harness="claude", tool_name="Bash",
        workspace_root=ws_dir, isolation="workspace", spool_dir=spool_dir, receipts_path=rcpt_path, now_ts=t0,
    )
    assert sp_ttl is not None
    sid_ttl = sp_ttl[0].spool_id
    gc_spools(max_age_seconds=SPOOL_TTL_SECONDS, spool_dir=spool_dir, now_ts=t0 + SPOOL_TTL_SECONDS + 5.0)

    rep_ttl = explain_intervention(sid_ttl, receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert rep_ttl["ok"] is True
    assert rep_ttl["current_state"] == "evicted"
    assert rep_ttl["eviction_reason"] == "ttl_expired"

    sp_e1 = spool_tool_output(
        _oversized_output("lru_entry_1"), session_id="s1", call_id="c2", harness="claude", tool_name="Bash",
        workspace_root=ws_dir, isolation="workspace", spool_dir=spool_dir, receipts_path=rcpt_path, now_ts=t0 + 100.0,
    )
    sp_e2 = spool_tool_output(
        _oversized_output("lru_entry_2"), session_id="s1", call_id="c3", harness="claude", tool_name="Bash",
        workspace_root=ws_dir, isolation="workspace", spool_dir=spool_dir, receipts_path=rcpt_path, now_ts=t0 + 110.0,
    )
    assert sp_e1 is not None and sp_e2 is not None
    gc_spools(max_entries=1, spool_dir=spool_dir, now_ts=t0 + 120.0)

    rep_entries = explain_intervention(sp_e1[0].spool_id, receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert rep_entries["current_state"] == "evicted"
    assert rep_entries["eviction_reason"] == "max_entries_lru"

    gc_spools(max_entries=10, max_total_bytes=1, spool_dir=spool_dir, now_ts=t0 + 130.0)
    rep_bytes = explain_intervention(sp_e2[0].spool_id, receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert rep_bytes["current_state"] == "evicted"
    assert rep_bytes["eviction_reason"] == "max_bytes_lru"

    # Simulate interrupted Phase-1 GC where tombstone remains in transitional 'evicting' state and no receipt exists
    idx_path = spool_dir / "spool_index.json"
    idx_doc = json.loads(idx_path.read_text(encoding="utf-8"))
    sid_evicting = "sp_0123456789ab"
    idx_doc["tombstones"][sid_evicting] = {
        "spool_id": sid_evicting,
        "state": "evicting",
        "reason": "max_bytes_lru",
        "evicted_at": t0 + 140.0,
        "workspace_id": "ws_demo",
        "session_id": "s1",
        "total_bytes": 16384,
    }
    idx_path.write_text(json.dumps(idx_doc), encoding="utf-8")

    info_evicting = inspect_spool_entry(sid_evicting, spool_dir=spool_dir)
    assert info_evicting["found"] is True
    assert info_evicting["current_state"] == "evicting"
    assert info_evicting["eviction_reason"] == "max_bytes_lru"

    rep_evicting = explain_intervention(sid_evicting, receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert rep_evicting["ok"] is True
    assert rep_evicting["matched_by"] == "spool_id"
    assert rep_evicting["current_state"] == "evicting"
    assert rep_evicting["eviction_reason"] == "max_bytes_lru"
    assert rep_evicting["completeness"] == "incomplete"
    assert rep_evicting["delivery_evidence_tier"] == "unverified"


def test_explain_reports_corrupt_and_receipt_only_states(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify corrupt detection (unexpectedly_missing, unsafe_path, integrity_mismatch) and receipt_only state."""
    ws_dir, state_dir, spool_dir, rcpt_path = _setup_env(tmp_path, monkeypatch)
    t0 = 1_700_200_000.0
    sp_miss = spool_tool_output(
        _oversized_output("missing_blob"), session_id="s1", call_id="c1", harness="claude", tool_name="Bash",
        workspace_root=ws_dir, isolation="workspace", spool_dir=spool_dir, receipts_path=rcpt_path, now_ts=t0,
    )
    assert sp_miss is not None
    sid_miss = sp_miss[0].spool_id
    (spool_dir / f"{sid_miss}.txt").unlink()

    idx_before = (spool_dir / "spool_index.json").read_text(encoding="utf-8")
    miss_info = inspect_spool_entry(sid_miss, spool_dir=spool_dir)
    assert (spool_dir / "spool_index.json").read_text(encoding="utf-8") == idx_before
    assert miss_info["current_state"] == "corrupt"
    assert miss_info["corrupt_reason"] == "unexpectedly_missing"

    rep_miss = explain_intervention(sid_miss, receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert rep_miss["current_state"] == "corrupt"
    assert rep_miss["corrupt_reason"] == "unexpectedly_missing"

    # Corrupt via unsafe blob path (symlink or directory replacing regular blob)
    sp_unsafe_blob = spool_tool_output(
        _oversized_output("unsafe_blob"), session_id="s1", call_id="c2", harness="claude", tool_name="Bash",
        workspace_root=ws_dir, isolation="workspace", spool_dir=spool_dir, receipts_path=rcpt_path, now_ts=t0 + 5.0,
    )
    assert sp_unsafe_blob is not None
    sid_ub = sp_unsafe_blob[0].spool_id
    blob_ub = spool_dir / f"{sid_ub}.txt"
    blob_ub.unlink()
    outside_target = tmp_path / "outside.txt"
    outside_target.write_text("outside", encoding="utf-8")
    _link_or_mock_unsafe(blob_ub, outside_target, monkeypatch)

    rep_ub = explain_intervention(sid_ub, receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert rep_ub["current_state"] == "corrupt"
    assert rep_ub["corrupt_reason"] == "unsafe_path"

    # Corrupt via tampered blob bytes triggering integrity_mismatch + pruned index fallback
    ws_dir2, state_dir2, spool_dir2, rcpt_path2 = _setup_env(tmp_path / "sub", monkeypatch)
    sp_tamper = spool_tool_output(
        _oversized_output("tamper"), session_id="s2", call_id="c3", harness="claude", tool_name="Bash",
        workspace_root=ws_dir2, isolation="workspace", spool_dir=spool_dir2, receipts_path=rcpt_path2, now_ts=t0,
    )
    assert sp_tamper is not None
    sid_tamper = sp_tamper[0].spool_id
    (spool_dir2 / f"{sid_tamper}.txt").write_text("tampered content\n", encoding="utf-8")
    sl_err = slice_spool(
        sid_tamper, workspace_root=ws_dir2, session_id="s2", isolation="workspace",
        harness="claude", receipts_path=rcpt_path2, spool_dir=spool_dir2, now_ts=t0 + 10.0,
    )
    assert sl_err["ok"] is False and sl_err["error"] == "integrity_mismatch"
    rep_tamper = explain_intervention(sid_tamper, receipts_path=rcpt_path2, spool_dir=spool_dir2, state_dir=state_dir2)
    assert rep_tamper["current_state"] == "corrupt"
    assert rep_tamper["corrupt_reason"] == "integrity_mismatch"
    assert rep_tamper["governor_context"]["tripped"] is True

    # Remove corrupt entry from spool_index.json -> still reports corrupt from spool_integrity_failure receipt
    idx2 = json.loads((spool_dir2 / "spool_index.json").read_text(encoding="utf-8"))
    idx2["entries"].pop(sid_tamper, None)
    (spool_dir2 / "spool_index.json").write_text(json.dumps(idx2), encoding="utf-8")
    rep_tamper_rcpt = explain_intervention(sid_tamper, receipts_path=rcpt_path2, spool_dir=spool_dir2, state_dir=state_dir2)
    assert rep_tamper_rcpt["current_state"] == "corrupt"
    assert rep_tamper_rcpt["corrupt_reason"] == "integrity_mismatch"

    # Pruned tombstone after SPOOL_TOMBSTONE_MAX_AGE_SECONDS -> receipt_only
    sp_old = spool_tool_output(
        _oversized_output("aged_out"), session_id="s2", call_id="c4", harness="claude", tool_name="Bash",
        workspace_root=ws_dir2, isolation="workspace", spool_dir=spool_dir2, receipts_path=rcpt_path2, now_ts=t0,
    )
    assert sp_old is not None
    sid_old = sp_old[0].spool_id
    gc_spools(max_age_seconds=0.0, spool_dir=spool_dir2, now_ts=t0 + 10.0)
    gc_spools(max_age_seconds=0.0, spool_dir=spool_dir2, now_ts=t0 + 20.0 + SPOOL_TOMBSTONE_MAX_AGE_SECONDS)
    assert inspect_spool_entry(sid_old, spool_dir=spool_dir2)["found"] is False

    rep_ro = explain_intervention(sid_old, receipts_path=rcpt_path2, spool_dir=spool_dir2, state_dir=state_dir2)
    assert rep_ro["ok"] is True
    assert rep_ro["current_state"] == "receipt_only"
    assert rep_ro["delivery_evidence_tier"] == "replacement_emitted"
    assert rep_ro["completeness"] == "complete"


def test_explain_delivery_evidence_tiers_and_evidence_ledger_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify all 3 delivery evidence tiers, evidence_events.json fallback, and event_id deduplication."""
    ws_dir, state_dir, spool_dir, rcpt_path = _setup_env(tmp_path, monkeypatch)
    unv = build_receipt(
        event_type="spool_recovery", harness="cursor", session_id="s_unv", workspace_id="ws_unv",
        turn_key="t1", call_id="c_unv", spool_id="sp_aaaaaaaaaaaa", line_span=(1, 10), byte_span=(0, 200),
        delivery_evidence="unverified", spool_id_referenced=True, event_id="ev_unverified_01",
    )
    append_receipt(unv, receipts_path=rcpt_path)
    rep_unv = explain_intervention("ev_unverified_01", receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert rep_unv["delivery_evidence_tier"] == "unverified"
    assert rep_unv["completeness"] == "incomplete"

    sp = spool_tool_output(
        _oversized_output("ledger_fallback"), session_id="s_led", call_id="c_led", harness="claude", tool_name="Bash",
        workspace_root=ws_dir, isolation="workspace", spool_dir=spool_dir, receipts_path=rcpt_path, now_ts=1_700_300_000.0,
    )
    assert sp is not None
    sid = sp[0].spool_id
    persist_spool_delivery_verification(
        {"tool_calls": [{"tool_use_id": "c_led", "tool_response": sp[1]}]},
        harness="claude", session_id="s_led", workspace_root=ws_dir, spool_dir=spool_dir, receipts_path=rcpt_path,
    )
    created_ev_id = [r["event_id"] for r in load_receipt_rows(rcpt_path) if r["spool_id"] == sid and r["event_type"] == "spool_created"][0]

    ledger_path = state_dir / "evidence_events.json"
    ing = ingest_context_receipts(ledger_path, rcpt_path, outcomes_path=None)
    assert ing["ok"] is True and ing["appended_count"] >= 2

    # Both receipts.jsonl and evidence_events.json exist -> timeline deduplicates by event_id
    rep_both = explain_intervention(created_ev_id, receipts_path=rcpt_path, spool_dir=spool_dir, ledger_path=ledger_path, state_dir=state_dir)
    assert len(rep_both["timeline"]) == 2
    assert len({t["event_id"] for t in rep_both["timeline"]}) == 2

    # Remove receipts.jsonl -> automatic fallback to spool_dir.parent / "evidence_events.json"
    rcpt_path.unlink()
    rep_fb = explain_intervention(created_ev_id, receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert rep_fb["ok"] is True
    assert rep_fb["matched_by"] == "event_id"
    assert rep_fb["delivery_evidence_tier"] == "delivery_verified"
    assert rep_fb["completeness"] == "complete"
    assert len(rep_fb["timeline"]) == 2


def test_explain_never_leaks_raw_blob_prompts_or_home_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify zero leakage of raw spooled blobs, prompt fields, home paths, local emails, Atlassian hosts, or GCP IDs."""
    ws_dir, state_dir, spool_dir, rcpt_path = _setup_env(tmp_path, monkeypatch)
    blob_secret = "ULTRA_SECRET_RAW_TOOL_OUTPUT_MARKER_8812"
    posix_secret_path = "/Users/alice/secret/project_notes"
    win_secret_path = "C:\\Users\\bob\\private\\credentials"
    local_email = "".join(("alice", "@", "workstation", ".", "local"))
    atlassian_host = "".join(("acme", ".", "atlassian", ".", "net"))
    gcp_proj = "-".join(("acme", "billing", "98765"))

    sp = spool_tool_output(
        _oversized_output(blob_secret),
        session_id=posix_secret_path,
        call_id="c_priv",
        harness="claude",
        tool_name="Bash",
        workspace_root=ws_dir,
        isolation="workspace",
        spool_dir=spool_dir,
        receipts_path=rcpt_path,
        now_ts=1_700_400_000.0,
    )
    assert sp is not None
    sid = sp[0].spool_id

    # Append receipt carrying sensitive tokens in reason
    noisy_reason = f"failed near {posix_secret_path} and {win_secret_path} for {local_email} on {atlassian_host} ({gcp_proj})"
    fail_rcpt = build_receipt(
        event_type="spool_integrity_failure", harness="claude", session_id=posix_secret_path,
        workspace_id=f"ws:{posix_secret_path}", turn_key="t_priv", call_id="c_priv2", spool_id=sid,
        line_span=(0, 0), byte_span=(0, 0), delivery_evidence="unverified", spool_id_referenced=True,
        failure_kind="reliability_failure", reason=noisy_reason, event_id="ev_privacy_check_01",
    )
    append_receipt(fail_rcpt, receipts_path=rcpt_path)

    report = explain_intervention("ev_privacy_check_01", receipts_path=rcpt_path, spool_dir=spool_dir, state_dir=state_dir)
    assert report["ok"] is True
    assert report["privacy_scrubbed"] is True

    # Also verify render_explain_markdown scrubs arbitrary injected forbidden keys if passed a raw dict
    injected: dict[str, Any] = {
        **report,
        "prompt": "TOP_SECRET_USER_PROMPT",
        "raw_prompt": "TOP_SECRET_RAW_PROMPT",
        "content": blob_secret,
        "tool_input": {"command": "cat /Users/alice/secret"},
        "canon_root": str(ws_dir),
    }
    json_out = json.dumps(report)
    md_out = render_explain_markdown(injected)

    for forbidden in (
        blob_secret, "/Users/alice", "project_notes", "C:\\Users\\bob", "credentials",
        local_email, "workstation.local", atlassian_host, "atlassian.net", gcp_proj, "98765",
        "TOP_SECRET_USER_PROMPT", "TOP_SECRET_RAW_PROMPT", str(ws_dir), "canon_root",
    ):
        assert forbidden not in json_out
        assert forbidden not in md_out


def test_cg_explain_cli_json_markdown_and_error_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify CLI --json, default/--markdown output, and exit codes 0 (ok), 1 (not_found/unsafe_path), and 2 (bad args)."""
    ws_dir, state_dir, spool_dir, rcpt_path = _setup_env(tmp_path, monkeypatch)
    sp = spool_tool_output(
        _oversized_output("cli_case"), session_id="s_cli", call_id="c_cli", harness="claude", tool_name="Bash",
        workspace_root=ws_dir, isolation="workspace", spool_dir=spool_dir, receipts_path=rcpt_path, now_ts=1_700_500_000.0,
    )
    assert sp is not None
    ev_id = load_receipt_rows(rcpt_path)[0]["event_id"]

    rc_json = explain_main([
        ev_id, "--json", "--receipts-path", str(rcpt_path), "--spool-dir", str(spool_dir), "--state-dir", str(state_dir),
    ])
    out_json = json.loads(capsys.readouterr().out)
    assert rc_json == 0
    assert out_json["ok"] is True and out_json["event_id"] == ev_id

    rc_md = explain_main([
        "explain", ev_id, "--markdown", "--receipts-path", str(rcpt_path), "--spool-dir", str(spool_dir),
    ])
    out_md = capsys.readouterr().out
    assert rc_md == 0
    assert "# Context-Guard Intervention Explain" in out_md
    assert "## Lifecycle Timeline" in out_md

    rc_nf = explain_main(["ev_missing_9999", "--json", "--receipts-path", str(rcpt_path), "--spool-dir", str(spool_dir)])
    out_nf = json.loads(capsys.readouterr().out)
    assert rc_nf == 1
    assert out_nf["ok"] is False and out_nf["error"] == "event_not_found" and out_nf["completeness"] == "unavailable"

    rc_bad_flag = explain_main(["--json", "--unknown-flag"])
    out_bad = json.loads(capsys.readouterr().out)
    assert rc_bad_flag == 2
    assert out_bad["ok"] is False and out_bad["error"] == "invalid_arguments"

    assert explain_main([]) == 2
    capsys.readouterr()
    assert explain_main([""]) == 2
    capsys.readouterr()
    assert explain_main([ev_id, "--json", "--markdown"]) == 2
    capsys.readouterr()

    sym_rcpt = tmp_path / "sym_receipts.jsonl"
    _link_or_mock_unsafe(sym_rcpt, rcpt_path, monkeypatch)
    rc_unsafe = explain_main([ev_id, "--json", "--receipts-path", str(sym_rcpt), "--spool-dir", str(spool_dir)])
    out_unsafe = json.loads(capsys.readouterr().out)
    assert rc_unsafe == 1
    assert out_unsafe["ok"] is False and out_unsafe["error"] == "unsafe_path"
