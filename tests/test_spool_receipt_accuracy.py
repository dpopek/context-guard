"""Tests for grep span accuracy, raw source digests, turn verification, receipt completeness, and spool outcome resolution."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

import pytest

from hooks import config, outcomes, pre_tool_use
from hooks.post_tool_use import handle_post_tool_use
from spool.classifier import classify_pre_tool_spool_followup, validate_and_normalize_spool_text
from spool.receipts import (
    RECEIPTS_FILENAME,
    RECEIPTS_KEEP_ROWS,
    RECEIPTS_MAX_BYTES,
    append_receipt,
    build_receipt,
    enrich_receipt,
    load_receipt_rows,
    summarize_receipts,
    summarize_spool_lifecycle,
)
from spool.spans import (
    classify_post_tool_recovery_outcome,
    compute_grep_span_metrics,
    interval_union_bytes,
    measure_raw_source_bytes,
    merge_spans,
    resolve_verified_turn_key,
)
from spool.store import gc_spools, grep_spool, slice_spool, spool_tool_output
from tests.helpers import read_outcomes_ledger


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    r = tmp_path / name
    (r / ".git").mkdir(parents=True, exist_ok=True)
    return r


def _big_lines(count: int = 240, tag: str = "row") -> str:
    return "\n".join(f"{tag}-{i:04d} " + ("z" * 64) for i in range(count)) + "\n"


def test_merge_spans_grep_metrics_and_receipt_enrichment(tmp_path: Path) -> None:
    """Verify merge_spans avoids bridging gaps, measures repeated context, and enriches lifecycle totals."""
    assert merge_spans([(10, 12), (2, 5), (5, 8), (0, 0), (-3, 1)]) == [(0, 1), (2, 8), (10, 12)]
    assert interval_union_bytes([(0, 10), (5, 15), (20, 30)]) == 25

    lines = [f"L{idx:03d}-" + ("a" * 20) for idx in range(160)]
    empty_m = compute_grep_span_metrics(lines, [])
    assert empty_m == {
        "merged_line_spans": [],
        "merged_byte_spans": [],
        "line_span": (0, 0),
        "byte_span": (0, 0),
        "unique_bytes": 0,
        "repeated_context_bytes": 0,
    }

    # Disjoint windows (4, 7) and (149, 152): must NOT bridge gap (149 - 7)
    disjoint = compute_grep_span_metrics(lines, [(4, 7), (149, 152)])
    assert disjoint["merged_line_spans"] == [(4, 7), (149, 152)]
    assert disjoint["line_span"] == (4, 152)
    assert disjoint["repeated_context_bytes"] == 0
    assert disjoint["unique_bytes"] == sum(e - s for s, e in disjoint["merged_byte_spans"])

    # Adjacent non-overlapping windows (0, 2) and (2, 4): repeated_context_bytes stays 0
    adj = compute_grep_span_metrics(lines, [(0, 2), (2, 4)])
    assert adj["merged_line_spans"] == [(0, 4)]
    assert adj["repeated_context_bytes"] == 0

    # Overlapping windows (8, 11) and (10, 13): repeated_context_bytes == byte length of line 10
    overlap = compute_grep_span_metrics(lines, [(8, 11), (10, 13)])
    assert overlap["merged_line_spans"] == [(8, 13)]
    assert overlap["repeated_context_bytes"] == len(lines[10].encode("utf-8"))

    # End-to-end disjoint grep + overlapping grep + empty grep + enrich_receipt roundtrip
    repo, spool_dir = _repo(tmp_path), tmp_path / "spool"
    doc_lines = [f"item-{i:04d}-" + ("q" * 64) for i in range(240)]
    doc_lines[10] = "HIT_ONE " + ("x" * 60)
    doc_lines[200] = "HIT_TWO " + ("x" * 60)
    doc_lines[202] = "HIT_TWO " + ("x" * 60)
    res = spool_tool_output(
        "\n".join(doc_lines) + "\n",
        session_id="s-grep", call_id="c-cr", harness="claude", tool_name="Bash",
        workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_000.0,
    )
    assert res is not None
    sid = res[0].spool_id
    g_disj = grep_spool(sid, "HIT_ONE|HIT_TWO", context_lines=1, workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_005.0)
    g_none = grep_spool(sid, "MISSING_TOKEN", workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_006.0)
    assert g_disj["match_count"] == 3 and g_none["match_count"] == 0

    loaded = load_receipt_rows(spool_dir / RECEIPTS_FILENAME)
    assert loaded[1]["recovered_line_spans"] == [(9, 12), (199, 204)]
    assert loaded[1]["recovered_context_bytes"] == len(doc_lines[201].encode("utf-8"))
    assert loaded[2]["recovered_byte_spans"] == []
    assert loaded[1]["blob_sha256"] == res[0].content_sha256 and loaded[1]["blob_bytes"] == res[0].total_bytes

    life = summarize_spool_lifecycle(spool_dir / RECEIPTS_FILENAME, spool_id=sid)
    expected_disj_bytes = sum(e - s for s, e in loaded[1]["recovered_byte_spans"])
    assert life["unique_recovered_bytes"] == expected_disj_bytes
    assert life["total_recovered_bytes"] == expected_disj_bytes
    assert life["repeated_context_bytes"] == len(doc_lines[201].encode("utf-8"))

    # enrich_receipt ignores invalid extras while keeping valid fields
    enriched = enrich_receipt(loaded[0], {"blob_bytes": True, "recovered_context_bytes": -1, "blob_sha256": "abc"})
    assert enriched["blob_sha256"] == "abc" and enriched["blob_bytes"] == res[0].total_bytes


def test_raw_source_bytes_crlf_normalization_and_pre_norm_cap(tmp_path: Path) -> None:
    """Verify raw pre-normalization source_hash/original_bytes differ from LF blob metadata and enforce byte cap."""
    raw_crlf = "\r\n".join(f"line-{i:04d}-" + ("m" * 64) for i in range(230)) + "\r\n"
    raw_bytes = raw_crlf.encode("utf-8")
    lf_bytes = raw_crlf.replace("\r\n", "\n").encode("utf-8")
    measured = measure_raw_source_bytes(raw_crlf)
    assert measured == (hashlib.sha256(raw_bytes).hexdigest(), len(raw_bytes))
    assert measure_raw_source_bytes(b"\xff\xfe") is None
    assert measure_raw_source_bytes("abc\x00def") is None
    assert measure_raw_source_bytes("bad\ud800") is None

    # Pre-normalization cap rejects CRLF input exceeding eff_max_bytes even if LF version fits
    assert validate_and_normalize_spool_text(raw_crlf, len(lf_bytes) + 1) is None
    assert validate_and_normalize_spool_text(raw_bytes, len(lf_bytes) + 1) is None
    assert validate_and_normalize_spool_text(raw_crlf, len(raw_bytes)) is not None

    repo, spool_dir = _repo(tmp_path), tmp_path / "spool"
    sp = spool_tool_output(
        raw_crlf, session_id="s-raw", call_id="c-raw", harness="claude", tool_name="Bash",
        workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_010.0,
    )
    assert sp is not None
    contract, _ = sp
    assert contract.total_bytes == len(lf_bytes)
    assert contract.content_sha256 == hashlib.sha256(lf_bytes).hexdigest()

    idx = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    ent = idx["entries"][contract.spool_id]
    assert ent["source_bytes"] == len(raw_bytes) and ent["source_sha256"] == measured[0]
    assert ent["total_bytes"] == len(lf_bytes) and ent["content_sha256"] == contract.content_sha256

    sl = slice_spool(contract.spool_id, start_line=1, limit=4, workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_012.0)
    assert sl["ok"] is True
    rows = load_receipt_rows(spool_dir / RECEIPTS_FILENAME)
    assert rows[0]["source_hash"] == measured[0] and rows[0]["original_bytes"] == len(raw_bytes)
    assert rows[0]["blob_sha256"] == contract.content_sha256 and rows[0]["blob_bytes"] == len(lf_bytes)
    assert rows[1]["source_hash"] == measured[0] and rows[1]["blob_sha256"] == contract.content_sha256


def test_resolve_verified_turn_key_priority_and_corrupt_transcript_fallbacks(tmp_path: Path) -> None:
    """Verify strict 5-tier turn key resolution and fail-closed transcript validation."""
    assert resolve_verified_turn_key({"stepIdx": 5, "turnId": "t1"}, {"last_step_index": 2}, "s1") == ("harness_native", "s1:step:5")
    assert resolve_verified_turn_key({"stepIdx": True, "turnId": "t-9"}, {}, "s1") == ("harness_native", "s1:turn:t-9")
    assert resolve_verified_turn_key({"turn_id": "  "}, {"last_step_index": 3}, "s1") == ("transcript_derived", "s1:transcript_step:3")

    # Large valid JSONL (>64 KiB) reads tail cleanly and extracts turn/step token
    big_tr = tmp_path / "big_tr.jsonl"
    pad_line = json.dumps({"msg": "x" * 400}) + "\n"
    big_tr.write_text((pad_line * 200) + json.dumps({"turn_id": "tail-turn-42"}) + "\n", encoding="utf-8")
    assert resolve_verified_turn_key({"transcriptPath": str(big_tr)}, {}, "s1") == ("transcript_derived", "s1:transcript:tail-turn-42")

    # Plain JSON object line without turn/step keys falls back to verified line count token
    plain_tr = tmp_path / "plain_tr.jsonl"
    plain_tr.write_text('{"role":"user"}\n{"role":"assistant"}\n', encoding="utf-8")
    assert resolve_verified_turn_key({"transcript_path": str(plain_tr)}, {}, "s1") == ("transcript_derived", "s1:transcript:n2")

    # Missing, empty, corrupt, non-object JSON, invalid UTF-8, directory, and symlink must fall through to unobserved
    empty_tr = tmp_path / "empty.jsonl"
    empty_tr.write_text("", encoding="utf-8")
    bad_tr = tmp_path / "bad.jsonl"
    bad_tr.write_text("{not-json\n", encoding="utf-8")
    arr_tr = tmp_path / "arr.jsonl"
    arr_tr.write_text("[1, 2, 3]\n", encoding="utf-8")
    bin_tr = tmp_path / "bin.jsonl"
    bin_tr.write_bytes(b"\xff\xfe\n")
    dir_tr = tmp_path / "dir.jsonl"
    dir_tr.mkdir()
    cands: list[Path] = [tmp_path / "absent.jsonl", empty_tr, bad_tr, arr_tr, bin_tr, dir_tr]
    if os.name != "nt":
        sym_tr = tmp_path / "sym.jsonl"
        sym_tr.symlink_to(plain_tr)
        cands.append(sym_tr)
    for bad_path in cands:
        assert resolve_verified_turn_key({"transcript_path": str(bad_path)}, {"auto_step_seq": 6}, "s1") == ("unobserved", "s1:step:6")


def test_receipt_completeness_diagnostics_corruption_and_multi_rotation(tmp_path: Path) -> None:
    """Verify unavailable vs incomplete states, cumulative rotation headers, and post-rotation completeness."""
    miss_sum = summarize_spool_lifecycle(tmp_path / "missing" / RECEIPTS_FILENAME)
    assert miss_sum["completeness"] == "unavailable" and miss_sum["source_status"] == "missing"
    assert miss_sum["recovery_model_turns"] is None and miss_sum["recovery_amplification"] is None
    assert miss_sum["original_bytes"] is None and miss_sum["replacement_bytes"] is None
    assert miss_sum["turn_correlation_status"] == "unobserved"

    empty_file = tmp_path / "empty.jsonl"
    empty_file.write_text("", encoding="utf-8")
    assert summarize_spool_lifecycle(empty_file)["completeness"] == "unavailable"

    bad_utf8 = tmp_path / "bad_utf8.jsonl"
    bad_utf8.write_bytes(b"\xff\xfe\xfd")
    u_sum = summarize_spool_lifecycle(bad_utf8)
    assert u_sum["completeness"] == "unavailable" and u_sum["source_status"] == "utf8_error"

    dir_path = tmp_path / "not_file.jsonl"
    dir_path.mkdir()
    assert summarize_spool_lifecycle(dir_path)["source_status"] == "not_regular_file"

    if os.name != "nt":
        sym_rcpt = tmp_path / "sym.jsonl"
        sym_rcpt.symlink_to(empty_file)
        sym_sum = summarize_spool_lifecycle(sym_rcpt)
        assert sym_sum["completeness"] == "unavailable" and sym_sum["source_status"] == "unsafe_link"

    only_corrupt = tmp_path / "only_corrupt.jsonl"
    only_corrupt.write_text("{bad\n123\n", encoding="utf-8")
    oc_sum = summarize_spool_lifecycle(only_corrupt)
    assert oc_sum["completeness"] == "incomplete" and oc_sum["corrupt_lines"] == 2 and oc_sum["original_bytes"] is None

    mixed = tmp_path / "mixed.jsonl"
    cr = build_receipt(
        event_type="spool_created", harness="claude", session_id="s1", workspace_id="ws1",
        turn_key="s1:step:1", call_id="c1", spool_id="sp_111111111111", line_span=(0, 10),
        byte_span=(0, 500), delivery_evidence="replacement_emitted", spool_id_referenced=False, original_bytes=500,
    )
    mixed.write_text(json.dumps(dict(cr)) + "\n{bad_line\n", encoding="utf-8")
    mx_sum = summarize_spool_lifecycle(mixed)
    assert mx_sum["completeness"] == "incomplete" and mx_sum["corrupt_lines"] == 1
    assert mx_sum["by_spool"]["sp_111111111111"]["completeness"] == "incomplete"

    # Multi-rotation cumulative dropped count + post-rotation spool completeness
    rot_path = tmp_path / "rot_multi.jsonl"
    pad = "p" * 2048
    seed_1 = [
        json.dumps(dict(build_receipt(
            event_type="spool_created", harness="claude", session_id="s-r", workspace_id="ws-r",
            turn_key=f"t-{i}", call_id=f"c-{i}", spool_id=f"sp_{i:012x}", line_span=(0, 10), byte_span=(0, 100),
            delivery_evidence="replacement_emitted", spool_id_referenced=False, event_id=f"ev_r1_{i}", reason=pad,
            timestamp="2026-11-10T00:00:00Z",
        )), separators=(",", ":"), sort_keys=True) + "\n"
        for i in range(RECEIPTS_KEEP_ROWS + 10)
    ]
    rot_path.write_text("".join(seed_1), encoding="utf-8")
    assert rot_path.stat().st_size > RECEIPTS_MAX_BYTES
    trig_1 = build_receipt(
        event_type="spool_created", harness="claude", session_id="s-r", workspace_id="ws-r",
        turn_key="t-new1", call_id="c-new1", spool_id="sp_aaaaaaaaaaaa", line_span=(0, 10), byte_span=(0, 200),
        delivery_evidence="replacement_emitted", spool_id_referenced=False, event_id="ev_trig_1",
        timestamp="2026-11-10T00:01:00Z",
    )
    assert append_receipt(trig_1, receipts_path=rot_path) is True
    first_meta = json.loads(rot_path.read_text(encoding="utf-8").splitlines()[0])
    assert first_meta["_meta"] == "receipts_rotation" and first_meta["dropped_rows"] == 11

    # Trigger second rotation and confirm cumulative dropped count increases
    more = [
        json.dumps(dict(build_receipt(
            event_type="spool_recovery", harness="cli", session_id="s-r", workspace_id="ws-r",
            turn_key="t-m", call_id=f"cm-{i}", spool_id="sp_aaaaaaaaaaaa", line_span=(0, 5), byte_span=(0, 50),
            delivery_evidence="unverified", spool_id_referenced=True, event_id=f"ev_r2_{i}", reason=pad,
            timestamp="2026-11-10T00:02:00Z",
        )), separators=(",", ":"), sort_keys=True) + "\n"
        for i in range(200)
    ]
    with open(rot_path, "ab") as fh:
        fh.write("".join(more).encode("utf-8"))
    trig_2 = build_receipt(
        event_type="spool_created", harness="claude", session_id="s-r", workspace_id="ws-r",
        turn_key="t-after", call_id="c-after", spool_id="sp_bbbbbbbbbbbb", line_span=(0, 10), byte_span=(0, 300),
        delivery_evidence="replacement_emitted", spool_id_referenced=False, event_id="ev_after_rot",
        original_bytes=300, timestamp="2099-01-01T00:00:00Z",
    )
    assert append_receipt(trig_2, receipts_path=rot_path) is True
    second_meta = json.loads(rot_path.read_text(encoding="utf-8").splitlines()[0])
    assert second_meta["dropped_rows"] == 11 + 201 and second_meta["retained_rows"] == RECEIPTS_KEEP_ROWS
    assert len(load_receipt_rows(rot_path)) == RECEIPTS_KEEP_ROWS
    sum7 = summarize_receipts(rot_path)
    assert sum7["receipt_count"] == RECEIPTS_KEEP_ROWS

    rot_life = summarize_spool_lifecycle(rot_path)
    assert rot_life["completeness"] == "incomplete" and rot_life["rotated"] is True
    assert rot_life["dropped_by_rotation"] == 212 and rot_life["corrupt_lines"] == 0
    assert rot_life["retained_range"] is not None and rot_life["retained_range"]["retained_rows"] == RECEIPTS_KEEP_ROWS
    assert rot_life["by_spool"]["sp_bbbbbbbbbbbb"]["completeness"] == "complete"
    assert rot_life["by_spool"]["sp_aaaaaaaaaaaa"]["completeness"] == "incomplete"


def test_pre_tool_classifier_rejects_corrupt_evicted_missing_and_invalid_blobs(tmp_path: Path) -> None:
    """Verify classify_pre_tool_spool_followup rejects non-available states and missing/invalid blobs."""
    repo, spool_dir = _repo(tmp_path), tmp_path / "spool"
    s1 = spool_tool_output(_big_lines(220, "ok"), session_id="s1", call_id="c1", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir, now_ts=100.0)
    s2 = spool_tool_output(_big_lines(220, "ev"), session_id="s1", call_id="c2", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir, now_ts=101.0)
    assert s1 is not None and s2 is not None
    sid_cor, sid_ev = s1[0].spool_id, s2[0].spool_id

    # Missing ID rejected
    assert classify_pre_tool_spool_followup("Bash", {"command": "cg-spool slice sp_000000000000"}, workspace_root=repo, spool_dir=spool_dir) is None
    # Corrupt entry rejected
    (spool_dir / f"{sid_cor}.txt").write_text("tampered\n", encoding="utf-8")
    assert slice_spool(sid_cor, workspace_root=repo, spool_dir=spool_dir)["error"] == "integrity_mismatch"
    assert classify_pre_tool_spool_followup("Bash", {"command": f"cg-spool slice {sid_cor}"}, workspace_root=repo, spool_dir=spool_dir) is None
    # Evicted tombstone rejected
    gc_spools(max_age_seconds=0.0, spool_dir=spool_dir, now_ts=200.0)
    assert classify_pre_tool_spool_followup("Bash", {"command": f"cg-spool slice {sid_ev}"}, workspace_root=repo, spool_dir=spool_dir) is None

    # Corrupt index fallback: missing blob or invalid UTF-8 blob rejected, valid UTF-8 blob allowed
    s3 = spool_tool_output(_big_lines(220, "fb"), session_id="s1", call_id="c3", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir, now_ts=300.0)
    assert s3 is not None
    sid_fb = s3[0].spool_id
    (spool_dir / "spool_index.json").write_text("{corrupt", encoding="utf-8")
    assert classify_pre_tool_spool_followup("Read", {"file_path": str(spool_dir / "sp_000000000000.txt")}, workspace_root=repo, spool_dir=spool_dir) is None
    assert classify_pre_tool_spool_followup("Read", {"file_path": str(spool_dir / f"{sid_fb}.txt")}, workspace_root=repo, spool_dir=spool_dir) is not None
    (spool_dir / f"{sid_fb}.txt").write_bytes(b"\xff\xfe\xfd")
    assert classify_pre_tool_spool_followup("Read", {"file_path": str(spool_dir / f"{sid_fb}.txt")}, workspace_root=repo, spool_dir=spool_dir) is None


def test_outcomes_multi_emission_and_failure_keeps_window_open_for_retry(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify per-call_id spool windows, PostToolUseFailure recovery rollback, and subsequent repeat regret."""
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "active", "cli_rewrites": "off"}, "regret_window_steps": 6}), encoding="utf-8")
    config.clear_config_cache()
    spool_dir = tmp_path / "spool"
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))
    sd = tmp_path / "state"
    sd.mkdir()
    big = _big_lines(240, "dup")

    # Emit identical content twice under two distinct call_ids -> 2 open windows
    r1 = handle_post_tool_use("claude", {"hook_event_name": "PostToolUse", "session_id": "sm", "tool_use_id": "em-1", "tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": big, "cwd": str(tmp_path)}, state_dir=str(sd))
    r2 = handle_post_tool_use("claude", {"hook_event_name": "PostToolUse", "session_id": "sm", "tool_use_id": "em-2", "tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": big, "cwd": str(tmp_path)}, state_dir=str(sd))
    sid_match = re.search(r"\b(sp_[0-9a-f]{12})\b", str(r1["hookSpecificOutput"]["updatedToolOutput"]))
    assert sid_match is not None
    sid = sid_match.group(1)
    assert sid in r2["hookSpecificOutput"]["updatedToolOutput"]
    # Idempotent retry of em-1 keeps exactly 2 windows
    handle_post_tool_use("claude", {"hook_event_name": "PostToolUse", "session_id": "sm", "tool_use_id": "em-1", "tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": big, "cwd": str(tmp_path)}, state_dir=str(sd))
    led1 = read_outcomes_ledger(sd)
    assert len(led1["open_windows"]) == 2
    assert f"sm|spool:{sid}|output_spool" in led1["open_windows"]
    assert f"sm|spool:{sid}|output_spool#1" in led1["open_windows"]

    # PreToolUse recovery followed by PostToolUseFailure must clear pending state & keep window open
    slice_cmd = f"cg-spool slice {sid} --start 1 --limit 50"
    pre_tool_use.evaluate_hook({"hook_event_name": "PreToolUse", "session_id": "sm", "tool_use_id": "rec-fail", "tool_name": "Bash", "tool_input": {"command": slice_cmd}, "cwd": str(tmp_path)}, state_dir=str(sd), cli_harness="claude")
    handle_post_tool_use("claude", {"hook_event_name": "PostToolUseFailure", "session_id": "sm", "tool_use_id": "rec-fail", "tool_name": "Bash", "tool_input": {"command": slice_cmd}, "error": "boom", "cwd": str(tmp_path)}, state_dir=str(sd), event_name="PostToolUseFailure")
    led_after_fail = read_outcomes_ledger(sd)
    assert len(led_after_fail["open_windows"]) == 2
    assert all("p_cid" not in w["meta"] for w in led_after_fail["open_windows"].values())

    # Succeeding recovery resolves ONE window, leaving the other open
    pre_tool_use.evaluate_hook({"hook_event_name": "PreToolUse", "session_id": "sm", "tool_use_id": "rec-ok", "tool_name": "Bash", "tool_input": {"command": slice_cmd}, "cwd": str(tmp_path)}, state_dir=str(sd), cli_harness="claude")
    handle_post_tool_use("claude", {"hook_event_name": "PostToolUse", "session_id": "sm", "tool_use_id": "rec-ok", "tool_name": "Bash", "tool_input": {"command": slice_cmd}, "tool_response": {"output": "ok", "exit_code": 0}, "cwd": str(tmp_path)}, state_dir=str(sd))
    led_mid = read_outcomes_ledger(sd)
    assert len(led_mid["open_windows"]) == 1
    assert led_mid["by_key"]["claude|unknown|output_spool"]["recovery"]["targeted"] == 1

    # Non-zero exit PostToolUse on remaining window keeps it open; subsequent repeat triggers suspected regret
    pre_tool_use.evaluate_hook({"hook_event_name": "PreToolUse", "session_id": "sm", "tool_use_id": "rec-err", "tool_name": "Bash", "tool_input": {"command": slice_cmd}, "cwd": str(tmp_path)}, state_dir=str(sd), cli_harness="claude")
    handle_post_tool_use("claude", {"hook_event_name": "PostToolUse", "session_id": "sm", "tool_use_id": "rec-err", "tool_name": "Bash", "tool_input": {"command": slice_cmd}, "tool_response": {"output": '{"ok":false,"error":"spool_corrupt"}', "exit_code": 1}, "cwd": str(tmp_path)}, state_dir=str(sd))
    assert len(read_outcomes_ledger(sd)["open_windows"]) == 1

    # Verify classify_post_tool_recovery_outcome detects integrity failure on tampered spool
    assert classify_post_tool_recovery_outcome("claude", {"tool_name": "Bash", "tool_input": {"command": slice_cmd}, "tool_response": {"output": "ok", "exit_code": 0}}, "PostToolUse", spool_dir)[0] is True
    (spool_dir / f"{sid}.txt").unlink()
    assert classify_post_tool_recovery_outcome("claude", {"tool_name": "Bash", "tool_input": {"command": slice_cmd}, "tool_response": {"output": "ok", "exit_code": 0}}, "PostToolUse", spool_dir)[0] is False

    # Repeat original command correlates remaining open window as full/suspected
    pre_tool_use.evaluate_hook({"hook_event_name": "PreToolUse", "session_id": "sm", "tool_use_id": "rep-1", "tool_name": "Bash", "tool_input": {"command": "pytest"}, "cwd": str(tmp_path)}, state_dir=str(sd), cli_harness="claude")
    final = read_outcomes_ledger(sd)
    assert final["open_windows"] == {}
    row = final["by_key"]["claude|unknown|output_spool"]
    assert row["applied"] == 2 and row["recovery"]["targeted"] == 1 and row["recovery"]["full"] == 1 and row["regret"]["suspected"] == 1
    outcomes.load_outcomes(sd / "outcomes.json")
