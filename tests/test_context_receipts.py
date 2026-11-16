"""Tests for ContextReceiptV1 contract, bounded receipt persistence, and delivery evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

import policies.api as api
from policies.api import ContextReceiptV1, RECEIPT_SCHEMA_VERSION, VALID_TURN_CORRELATIONS
from spool.receipts import (
    DEFAULT_MAX_SPOOL_ENTRY_BYTES,
    RECEIPTS_KEEP_ROWS,
    RECEIPTS_MAX_BYTES,
    append_receipt,
    build_receipt,
    derive_spool_event_id,
    find_created_receipt,
    persist_spool_delivery_verification,
    read_spool_config,
    read_spool_isolation_config,
    resolve_workspace_identity,
    same_workspace_dir,
    summarize_receipts,
    summarize_spool_lifecycle,
)


def test_context_receipt_v1_schema_contract() -> None:
    """Verify ContextReceiptV1 exports, all 29 required keys, VALID_TURN_CORRELATIONS, and build defaults."""
    assert RECEIPT_SCHEMA_VERSION == 1
    assert VALID_TURN_CORRELATIONS == ("harness_native", "transcript_derived", "unobserved")
    assert "RECEIPT_SCHEMA_VERSION" in api.__all__
    assert "ContextReceiptV1" in api.__all__
    assert "VALID_TURN_CORRELATIONS" in api.__all__

    expected_annotations = {
        "schema_version": "int",
        "receipt_id": "str",
        "event_id": "str",
        "parent_event_id": "str | None",
        "timestamp": "str",
        "ts_ms": "int",
        "hook_duration_ms": "float | None",
        "event_type": "str",
        "harness": "str",
        "session_id": "str",
        "workspace_id": "str",
        "turn_key": "str",
        "turn_correlation": "str",
        "call_id": "str",
        "tool_call_id": "str",
        "spool_id": "str",
        "intervention": "str",
        "mode": "str",
        "status": "str",
        "line_span": "tuple[int, int]",
        "byte_span": "tuple[int, int]",
        "source_hash": "str",
        "original_bytes": "int",
        "replacement_bytes": "int",
        "upstream_truncation": "bool",
        "delivery_evidence": "str",
        "spool_id_referenced": "bool",
        "failure_kind": "str | None",
        "reason": "str | None",
    }
    assert len(expected_annotations) == 29
    ann = ContextReceiptV1.__annotations__
    assert set(ann.keys()) == set(expected_annotations.keys())
    assert ContextReceiptV1.__required_keys__ == frozenset(expected_annotations.keys())
    for key, expected in expected_annotations.items():
        raw_val = ann[key]
        actual = raw_val if isinstance(raw_val, str) else getattr(raw_val, "__forward_arg__", repr(raw_val))
        assert actual == expected

    ev1 = derive_spool_event_id("spool_created", "s1", "c1", "sp_000000000001")
    ev2 = derive_spool_event_id("spool_created", "s1", "c1", "sp_000000000001")
    ev_rand_1 = derive_spool_event_id("spool_recovery", "s1", "", "sp_000000000001")
    ev_rand_2 = derive_spool_event_id("spool_recovery", "s1", "", "sp_000000000001")
    assert ev1 == ev2 and ev1.startswith("ev_") and len(ev1) == 19
    assert ev_rand_1 != ev_rand_2 and ev_rand_1.startswith("ev_") and len(ev_rand_1) == 19

    built = build_receipt(
        event_type="spool_created", harness="claude", session_id="s1", workspace_id="ws_1",
        turn_key="s1:step:1", call_id="c1", spool_id="sp_000000000001", line_span=(0, 10), byte_span=(0, 100),
        delivery_evidence="replacement_emitted", spool_id_referenced=False,
        timestamp="2026-11-16T00:00:00Z", turn_correlation="unknown_val",
    )
    assert built["event_id"] == ev1 and built["tool_call_id"] == "c1"
    assert built["mode"] == "active" and built["status"] == "ok" and built["turn_correlation"] == "unobserved"
    assert built["intervention"] == "output_spool" and built["ts_ms"] > 0

    fail_r = build_receipt(
        event_type="spool_integrity_failure", harness="mcp", session_id="s1", workspace_id="ws_1",
        turn_key="", call_id="", spool_id="sp_000000000001", line_span=(0, 0), byte_span=(0, 50),
        delivery_evidence="unverified", spool_id_referenced=True, failure_kind="reliability_failure",
    )
    assert fail_r["mode"] == "recovery" and fail_r["status"] == "error"


def test_receipts_rotate_at_limit_and_public_json_scrubs_receipt_paths_and_workspace_ids(tmp_path: Path) -> None:
    """Verify 0o600 creation, symlink refusal, atomic 512 KiB rotation, and 7-key summary."""
    rcpt_path = tmp_path / "spool" / "receipts.jsonl"
    first = build_receipt(
        event_type="spool_created",
        harness="claude",
        session_id="s-0000",
        workspace_id="ws_0123456789abcdef",
        turn_key="s-0000:step:1",
        call_id="call-0000",
        spool_id="sp_000000000000",
        line_span=(0, 220),
        byte_span=(0, 14000),
        delivery_evidence="replacement_emitted",
        spool_id_referenced=False,
        timestamp="2026-11-16T00:00:00Z",
    )
    assert append_receipt(first, receipts_path=rcpt_path) is True
    assert rcpt_path.is_file()
    if os.name != "nt":
        assert stat.S_IMODE(rcpt_path.stat().st_mode) == 0o600

    # Pre-seed valid rows just past RECEIPTS_MAX_BYTES so the next append_receipt triggers rotation.
    seed_lines: list[str] = []
    idx = 1
    total_b = rcpt_path.stat().st_size
    while total_b <= RECEIPTS_MAX_BYTES:
        row = build_receipt(
            event_type="spool_recovery",
            harness="claude",
            session_id=f"s-{idx:04d}",
            workspace_id="ws_0123456789abcdef",
            turn_key=f"s-{idx:04d}:step:1",
            call_id=f"call-{idx:04d}",
            spool_id=f"sp_{idx:012x}",
            line_span=(0, 220),
            byte_span=(0, 14000),
            delivery_evidence="unverified",
            spool_id_referenced=True,
            timestamp=f"2026-11-16T00:{(idx // 60) % 60:02d}:{idx % 60:02d}Z",
        )
        encoded = json.dumps(dict(row), separators=(",", ":"), sort_keys=True) + "\n"
        seed_lines.append(encoded)
        total_b += len(encoded.encode("utf-8"))
        idx += 1
    with open(rcpt_path, "ab") as fh:
        fh.write("".join(seed_lines).encode("utf-8"))

    extra = build_receipt(
        event_type="spool_integrity_failure",
        harness="cli",
        session_id="s-fail",
        workspace_id="ws_0123456789abcdef",
        turn_key="",
        call_id="",
        spool_id="sp_ffffffffffff",
        line_span=(0, 0),
        byte_span=(0, 128),
        delivery_evidence="unverified",
        spool_id_referenced=True,
        failure_kind="reliability_failure",
        reason="integrity_mismatch",
        timestamp="2026-11-16T23:59:59Z",
    )
    assert append_receipt(extra, receipts_path=rcpt_path) is True

    rows = [json.loads(line) for line in rcpt_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == RECEIPTS_KEEP_ROWS
    assert rows[-1]["receipt_id"] == extra["receipt_id"]
    summary = summarize_receipts(rcpt_path)
    assert set(summary.keys()) == {
        "receipt_count",
        "created_count",
        "delivery_verified_count",
        "recovery_count",
        "integrity_failures",
        "last_failure_ts",
        "last_event_ts",
    }
    assert summary["receipt_count"] == RECEIPTS_KEEP_ROWS
    assert summary["integrity_failures"] == 1
    assert summary["last_failure_ts"] == "2026-11-16T23:59:59Z"
    assert summary["last_event_ts"] == "2026-11-16T23:59:59Z"

    if os.name != "nt":
        sym_path = tmp_path / "sym_receipts.jsonl"
        target = tmp_path / "target.jsonl"
        target.write_text("", encoding="utf-8")
        sym_path.symlink_to(target)
        assert append_receipt(extra, receipts_path=sym_path) is False

    from bin.replay_benchmark import build_public_json_bundle, check_release_hygiene

    bundle = build_public_json_bundle(
        {"saved_bytes": 100, "receipts_path": str(rcpt_path), "workspace_id": "ws_0123456789abcdef"},
        {}, {"schema_version": 4}, receipt_summary=summary,
    )
    dumped = json.dumps(bundle)
    assert "receipts.jsonl" not in dumped and "ws_0123456789abcdef" not in dumped and "receipts_path" not in dumped
    assert bundle["spool_reliability"]["integrity_failures"] == 1
    assert check_release_hygiene(tmp_path, public_bundle=bundle) == []


def test_persist_spool_delivery_verification_matches_created_and_deduplicates(tmp_path: Path) -> None:
    """Verify PostToolBatch verification links parent spool_created, ignores spoofs, and deduplicates."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    spool_dir = tmp_path / "spool"
    rcpt_path = spool_dir / "receipts.jsonl"
    from spool.receipts import resolve_workspace_identity

    ws_id, _, err = resolve_workspace_identity(repo)
    assert err is None
    created = build_receipt(
        event_type="spool_created",
        harness="claude",
        session_id="sess-1",
        workspace_id=ws_id,
        turn_key="sess-1:step:2",
        call_id="call-1",
        spool_id="sp_0123456789ab",
        line_span=(0, 240),
        byte_span=(0, 18000),
        delivery_evidence="replacement_emitted",
        spool_id_referenced=False,
    )
    assert append_receipt(created, receipts_path=rcpt_path) is True
    found = find_created_receipt("sp_0123456789ab", session_id="sess-1", receipts_path=rcpt_path)
    assert found is not None and found["receipt_id"] == created["receipt_id"]

    batch_payload = {
        "session_id": "sess-1",
        "cwd": str(repo),
        "tool_calls": [
            {
                "tool_use_id": "call-1",
                "tool_response": "[CONTEXT-GUARD OUTPUT SPOOL: sp_0123456789ab | 240 lines, 18000 B | sha256=abc]",
            },
            {
                "tool_use_id": "call-spoof",
                "tool_response": "[CONTEXT-GUARD OUTPUT SPOOL: sp_deadbeefcafe | 10 lines, 100 B | sha256=bad]",
            },
        ],
    }
    added_1 = persist_spool_delivery_verification(
        batch_payload,
        harness="claude",
        session_id="sess-1",
        workspace_root=repo,
        spool_dir=spool_dir,
    )
    added_2 = persist_spool_delivery_verification(
        batch_payload,
        harness="claude",
        session_id="sess-1",
        workspace_root=repo,
        spool_dir=spool_dir,
    )
    assert added_1 == 1
    assert added_2 == 0
    summary = summarize_receipts(rcpt_path)
    assert summary["created_count"] == 1
    assert summary["delivery_verified_count"] == 1


def test_spool_recovery_receipts_exact_half_open_spans_and_never_mint_delivery_verified(
    tmp_path: Path,
) -> None:
    """Verify spool_created + slice/grep spool_recovery half-open spans without minting delivery_verified."""
    from spool.store import grep_spool, slice_spool, spool_tool_output

    repo = tmp_path / "repo_spans"
    repo.mkdir()
    (repo / ".git").mkdir()
    spool_dir = tmp_path / "spool"

    lines = [f"ł-{idx:03d} " + ("z" * 64) for idx in range(1, 221)]
    lines[9] = "needle alpha " + ("y" * 60)
    lines[11] = "needle beta " + ("y" * 60)
    text = "\n".join(lines) + "\n"
    raw_bytes = text.encode("utf-8")

    res = spool_tool_output(
        text,
        session_id="sess-span",
        call_id="call-span",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        turn_key="sess-span:step:1",
        upstream_truncation=True,
        spool_dir=spool_dir,
        now_ts=1_700_000_000.0,
    )
    assert res is not None
    sid = res[0].spool_id

    # Slice lines 10..12 (1-based) -> half-open 0-based [9, 12)
    sl = slice_spool(sid, start_line=10, limit=3, workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_005.0)
    assert sl["ok"] is True
    # Empty out-of-bounds slice -> [0, 0)
    sl_empty = slice_spool(sid, start_line=500, limit=10, workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_006.0)
    assert sl_empty["ok"] is True and sl_empty["returned_lines"] == 0
    # Grep with context=1 covering lines 10 & 12 (0-based 9 & 11) -> [8, 13)
    gr = grep_spool(sid, "needle", context_lines=1, workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_007.0)
    assert gr["ok"] is True and gr["match_count"] == 2
    # Grep with 0 matches -> [0, 0)
    gr_empty = grep_spool(sid, "NO_SUCH_MATCH", workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_008.0)
    assert gr_empty["ok"] is True and gr_empty["match_count"] == 0

    rows = [json.loads(line) for line in (spool_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 5
    created = rows[0]
    assert created["event_type"] == "spool_created"
    assert created["parent_event_id"] is None
    assert created["line_span"] == [0, 220]
    assert created["byte_span"] == [0, len(raw_bytes)]
    assert created["upstream_truncation"] is True
    assert created["delivery_evidence"] == "replacement_emitted"
    assert created["spool_id_referenced"] is False

    expected_b9_start = sum(len(lines[k].encode("utf-8")) + 1 for k in range(9))
    expected_b9_end = expected_b9_start + len("\n".join(lines[9:12]).encode("utf-8"))
    expected_b8_start = sum(len(lines[k].encode("utf-8")) + 1 for k in range(8))
    expected_b13_end = sum(len(lines[k].encode("utf-8")) + 1 for k in range(12)) + len(lines[12].encode("utf-8"))

    rec_slice, rec_empty, rec_grep, rec_grep_empty = rows[1], rows[2], rows[3], rows[4]
    for rec in (rec_slice, rec_empty, rec_grep, rec_grep_empty):
        assert rec["event_type"] == "spool_recovery"
        assert rec["parent_event_id"] == created["receipt_id"]
        assert rec["delivery_evidence"] == "unverified"
        assert rec["spool_id_referenced"] is True
    assert rec_slice["line_span"] == [9, 12]
    assert rec_slice["byte_span"] == [expected_b9_start, expected_b9_end]
    assert rec_empty["line_span"] == [0, 0] and rec_empty["byte_span"] == [0, 0]
    assert rec_grep["line_span"] == [8, 13]
    assert rec_grep["byte_span"] == [expected_b8_start, expected_b13_end]
    assert rec_grep_empty["line_span"] == [0, 0] and rec_grep_empty["byte_span"] == [0, 0]

    assert summarize_receipts(spool_dir / "receipts.jsonl")["delivery_verified_count"] == 0


def test_post_tool_use_emits_replacement_emitted_and_slice_grep_never_mint_delivery_verified(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify PostToolUse writes replacement_emitted, and slice/grep emit unverified child recovery only."""
    from hooks import config
    from hooks.post_tool_use import handle_post_tool_use
    from spool.store import grep_spool, slice_spool

    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "active"}}), encoding="utf-8")
    config.clear_config_cache()
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str((spool_dir := tmp_path / "spool")))
    repo = tmp_path / "repo_a"
    (repo / ".git").mkdir(parents=True)
    (sd := tmp_path / "sd_use").mkdir()
    raw_text = "\n".join(f"line_{i}: value {'a' * 60}" for i in range(1, 231)) + "\n"
    res = handle_post_tool_use(
        "claude",
        {"hook_event_name": "PostToolUse", "session_id": "sess-ptu", "tool_use_id": "call-ptu-1",
         "tool_name": "Bash", "tool_input": {"command": "pytest -q"}, "tool_response": raw_text,
         "cwd": str(repo), "truncated": True},
        state_dir=str(sd),
    )
    out_txt = str((res.get("hookSpecificOutput") or {}).get("updatedToolOutput") or "")
    sid = next(tok for tok in out_txt.split() if tok.startswith("sp_"))
    rcpt_path = spool_dir / "receipts.jsonl"
    rows1 = [json.loads(ln) for ln in rcpt_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(rows1) == 1
    created = rows1[0]
    assert (created["event_type"], created["delivery_evidence"], created["spool_id_referenced"]) == ("spool_created", "replacement_emitted", False)
    assert created["parent_event_id"] is None and created["turn_key"] == "sess-ptu:step:1" and created["upstream_truncation"] is True
    assert created["line_span"] == [0, 230] and created["byte_span"] == [0, len(raw_text.encode("utf-8"))]

    assert slice_spool(sid, start_line=1, limit=5, workspace_root=repo, spool_dir=spool_dir)["ok"] is True
    assert grep_spool(sid, "line_20:", workspace_root=repo, spool_dir=spool_dir)["ok"] is True
    rows2 = [json.loads(ln) for ln in rcpt_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(rows2) == 3 and rows2[0] == created
    for child in rows2[1:]:
        assert (child["event_type"], child["parent_event_id"], child["delivery_evidence"], child["spool_id_referenced"]) == (
            "spool_recovery", created["receipt_id"], "unverified", True
        )
    assert summarize_receipts(rcpt_path)["delivery_verified_count"] == 0


def test_post_tool_batch_header_match_emits_child_delivery_verified_and_ignores_spoofed_text(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify PostToolBatch hook appends deduplicated delivery_verified and ignores spoofed headers."""
    from hooks import config
    from hooks.post_tool_use import handle_post_tool_use

    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "active"}}), encoding="utf-8")
    config.clear_config_cache()
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str((spool_dir := tmp_path / "spool")))
    repo = tmp_path / "repo_b"
    (repo / ".git").mkdir(parents=True)
    (sd := tmp_path / "sd_batch").mkdir()
    raw_text = "\n".join(f"row_{i}: {'b' * 70}" for i in range(1, 221)) + "\n"
    res = handle_post_tool_use(
        "claude",
        {"hook_event_name": "PostToolUse", "session_id": "sess-bat", "tool_use_id": "call-bat-1",
         "tool_name": "Bash", "tool_input": {"command": "pytest -q"}, "tool_response": raw_text, "cwd": str(repo)},
        state_dir=str(sd),
    )
    updated_out = str((res.get("hookSpecificOutput") or {}).get("updatedToolOutput") or "")
    batch_payload = {
        "hook_event_name": "PostToolBatch", "session_id": "sess-bat", "cwd": str(repo),
        "tool_calls": [
            {"tool_name": "Bash", "tool_use_id": "call-bat-1", "tool_response": updated_out},
            {"tool_name": "Bash", "tool_use_id": "call-spoof", "tool_response": "[CONTEXT-GUARD OUTPUT SPOOL: sp_deadbeefcafe | 10 lines, 100 B]"},
        ],
    }
    handle_post_tool_use("claude", batch_payload, state_dir=str(sd), event_name="PostToolBatch")
    handle_post_tool_use("claude", batch_payload, state_dir=str(sd), event_name="PostToolBatch")
    rows = [json.loads(ln) for ln in (spool_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
    created = [r for r in rows if r["event_type"] == "spool_created"]
    verified = [r for r in rows if r["event_type"] == "spool_delivery_verified"]
    assert len(created) == 1 and len(verified) == 1
    assert verified[0]["parent_event_id"] == created[0]["receipt_id"]
    assert verified[0]["delivery_evidence"] == "delivery_verified" and verified[0]["spool_id_referenced"] is False
    assert verified[0]["line_span"] == [0, 220]


def test_regret_downgrade_never_emits_heuristic_confirmed_regret(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify heuristic regret paths emit suspected (never confirmed) and telemetry tracks reliability_failures."""
    from hooks import config, outcomes, pre_tool_use, telemetry
    from hooks.post_tool_use import handle_post_tool_use
    from tests.helpers import claude_read, read_outcomes_ledger, write_python_module

    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    for bad_doc in ({"spool": "bad"}, {"spool": {"isolation": "tenant"}}):
        cfg_path.write_text(json.dumps(bad_doc), encoding="utf-8")
        config.clear_config_cache()
        assert config.load_runtime_config(cfg_path)["config_error"]

    cfg_path.write_text(
        json.dumps({"spool": {"isolation": "workspace"}, "optimizers": {"output_spool": "active", "cli_rewrites": "auto", "range_trim": "active", "auto_outline": "off"}, "regret_window_steps": 6}),
        encoding="utf-8",
    )
    config.clear_config_cache()
    assert config.load_runtime_config(cfg_path)["config_error"] is None
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(tmp_path / "spool"))
    (sd := tmp_path / "sd_reg").mkdir()
    big_out = "\n".join(f"line {i}: {'c' * 70}" for i in range(250))

    pre_tool_use.evaluate_hook({"session_id": "sr", "tool_use_id": "r1", "tool_name": "Bash", "tool_input": {"command": "pytest tests/"}, "permission_mode": "bypassPermissions", "cwd": str(tmp_path)}, state_dir=str(sd), cli_harness="claude")
    handle_post_tool_use("claude", {"session_id": "sr", "tool_use_id": "r1", "tool_name": "Bash", "tool_input": {"command": "pytest tests/"}, "tool_response": big_out, "cwd": str(tmp_path)}, state_dir=str(sd))
    pre_tool_use.evaluate_hook({"session_id": "sr", "tool_use_id": "r2", "tool_name": "Bash", "tool_input": {"command": "pytest tests/"}, "permission_mode": "bypassPermissions", "cwd": str(tmp_path)}, state_dir=str(sd), cli_harness="claude")
    pre_tool_use.evaluate_hook({"session_id": "sr", "tool_use_id": "r3", "tool_name": "Bash", "tool_input": {"command": "pytest -vv tests/"}, "permission_mode": "bypassPermissions", "cwd": str(tmp_path)}, state_dir=str(sd), cli_harness="claude")

    mod = write_python_module(tmp_path / "trim_reg.py", funcs=26, body_lines=9)
    claude_read(mod, sd, offset=1, limit=100, session_id="sr2", tool_use_id="t1")
    claude_read(mod, sd, offset=1, limit=150, session_id="sr2", tool_use_id="t2")
    claude_read(mod, sd, offset=20, limit=40, session_id="sr2", tool_use_id="t3")

    ledger = read_outcomes_ledger(sd)
    assert all(row["regret"]["confirmed"] == 0 for row in ledger["by_key"].values())
    rt_rows = [v for k, v in ledger["by_key"].items() if k.endswith("|range_trim")]
    assert rt_rows and rt_rows[0]["recovery"]["targeted"] == 1 and rt_rows[0]["regret"]["suspected"] == 1 and rt_rows[0]["evidence"]["observed"] == 1

    telemetry.record_reliability_failure(stats_path := tmp_path / "stats_rel.json")
    st = telemetry.load_telemetry_stats(stats_path)
    assert st["events"]["reliability_failures"] == 1 and all(v["hits"] == 0 for v in st["by_harness"].values())
    assert outcomes.SCHEMA_VERSION == 4


def test_append_receipt_event_id_idempotency_and_legacy_18_key_rows(tmp_path: Path) -> None:
    """Verify event_id idempotent append deduplication and full backward compatibility for 18-key JSONL rows."""
    rcpt_path = tmp_path / "spool" / "receipts.jsonl"
    r1 = build_receipt(
        event_type="spool_created", harness="claude", session_id="s-idem", workspace_id="ws_1",
        turn_key="s-idem:step:1", call_id="c-idem", spool_id="sp_111111111111",
        line_span=(0, 100), byte_span=(0, 8000), delivery_evidence="replacement_emitted",
        spool_id_referenced=False, original_bytes=8000, replacement_bytes=240,
    )
    r2 = build_receipt(
        event_type="spool_created", harness="claude", session_id="s-idem", workspace_id="ws_1",
        turn_key="s-idem:step:1", call_id="c-idem", spool_id="sp_111111111111",
        line_span=(0, 100), byte_span=(0, 8000), delivery_evidence="replacement_emitted",
        spool_id_referenced=False, original_bytes=8000, replacement_bytes=240,
    )
    assert r1["event_id"] == r2["event_id"]
    assert append_receipt(r1, receipts_path=rcpt_path) is True
    assert append_receipt(r2, receipts_path=rcpt_path) is True
    assert len(rcpt_path.read_text(encoding="utf-8").splitlines()) == 1

    no_id_1 = build_receipt(
        event_type="spool_recovery", harness="mcp", session_id="s-idem", workspace_id="ws_1",
        turn_key="", call_id="", spool_id="sp_111111111111", line_span=(0, 5), byte_span=(0, 50),
        delivery_evidence="unverified", spool_id_referenced=True, event_id="",
    )
    no_id_2 = dict(no_id_1, receipt_id="rcpt_other")
    assert append_receipt(no_id_1, receipts_path=rcpt_path) is True
    assert append_receipt(no_id_2, receipts_path=rcpt_path) is True
    assert len(rcpt_path.read_text(encoding="utf-8").splitlines()) == 3

    legacy_path = tmp_path / "legacy_receipts.jsonl"
    legacy_created = {
        "schema_version": 1, "receipt_id": "rcpt_leg_created", "parent_event_id": None,
        "timestamp": "2026-11-16T01:00:00Z", "event_type": "spool_created", "harness": "claude",
        "session_id": "s-leg", "workspace_id": "ws_leg", "turn_key": "s-leg:step:1",
        "call_id": "c-leg", "spool_id": "sp_222222222222", "line_span": [0, 200], "byte_span": [0, 14000],
        "upstream_truncation": False, "delivery_evidence": "replacement_emitted",
        "spool_id_referenced": False, "failure_kind": None, "reason": None,
    }
    legacy_rec = {
        "schema_version": 1, "receipt_id": "rcpt_leg_rec", "parent_event_id": "rcpt_leg_created",
        "timestamp": "2026-11-16T01:00:05Z", "event_type": "spool_recovery", "harness": "mcp",
        "session_id": "s-leg", "workspace_id": "ws_leg", "turn_key": "s-leg:step:2",
        "call_id": "", "spool_id": "sp_222222222222", "line_span": [10, 20], "byte_span": [100, 600],
        "upstream_truncation": False, "delivery_evidence": "unverified",
        "spool_id_referenced": True, "failure_kind": None, "reason": None,
    }
    legacy_path.write_text(json.dumps(legacy_created) + "\n" + json.dumps(legacy_rec) + "\n", encoding="utf-8")
    loaded = find_created_receipt("sp_222222222222", receipts_path=legacy_path)
    assert loaded is not None
    assert loaded["event_id"] == "rcpt_leg_created" and loaded["tool_call_id"] == "c-leg"
    assert loaded["turn_correlation"] == "unobserved" and loaded["mode"] == "active" and loaded["status"] == "ok"
    assert loaded["ts_ms"] > 0 and loaded["original_bytes"] == 0 and loaded["replacement_bytes"] == 0

    leg_sum = summarize_receipts(legacy_path)
    assert leg_sum["created_count"] == 1 and leg_sum["recovery_count"] == 1
    leg_life = summarize_spool_lifecycle(legacy_path)
    assert leg_life["completeness"] == "complete"
    assert leg_life["original_bytes"] == 14000 and leg_life["replacement_bytes"] is None
    assert leg_life["turn_correlation_status"] == "unobserved" and leg_life["recovery_model_turns"] is None
    assert leg_life["unique_recovered_bytes"] == 500 and leg_life["total_recovered_bytes"] == 500
    assert leg_life["recovery_amplification"] == 1.0 and leg_life["delivery_evidence"] == "replacement_emitted"


def test_summarize_spool_lifecycle_intervals_turn_correlation_and_completeness(tmp_path: Path) -> None:
    """Verify interval-union amplification, turn_correlation rules, dedup, and incomplete rotated logs."""
    rcpt_path = tmp_path / "life.jsonl"
    sid_a, sid_b, sid_c = "sp_aaaaaaaaaaaa", "sp_bbbbbbbbbbbb", "sp_cccccccccccc"
    rows = [
        build_receipt(
            event_type="spool_created", harness="claude", session_id="s1", workspace_id="ws_1",
            turn_key="t0", call_id="c0", spool_id=sid_a, line_span=(0, 100), byte_span=(0, 10000),
            delivery_evidence="replacement_emitted", spool_id_referenced=False,
            original_bytes=10000, replacement_bytes=320, timestamp="2026-11-16T02:00:00Z",
        ),
        build_receipt(
            event_type="spool_delivery_verified", harness="claude", session_id="s1", workspace_id="ws_1",
            turn_key="t0", call_id="c0", spool_id=sid_a, line_span=(0, 100), byte_span=(0, 10000),
            delivery_evidence="delivery_verified", spool_id_referenced=False, timestamp="2026-11-16T02:00:01Z",
        ),
        build_receipt(
            event_type="spool_recovery", harness="mcp", session_id="s1", workspace_id="ws_1",
            turn_key="turn-1", call_id="", spool_id=sid_a, line_span=(0, 10), byte_span=(0, 100),
            delivery_evidence="unverified", spool_id_referenced=True, turn_correlation="harness_native",
            event_id="ev_rec_dup", timestamp="2026-11-16T02:00:02Z",
        ),
        build_receipt(
            event_type="spool_recovery", harness="mcp", session_id="s1", workspace_id="ws_1",
            turn_key="turn-1", call_id="", spool_id=sid_a, line_span=(0, 10), byte_span=(0, 100),
            delivery_evidence="unverified", spool_id_referenced=True, turn_correlation="harness_native",
            event_id="ev_rec_dup", timestamp="2026-11-16T02:00:02Z",
        ),
        build_receipt(
            event_type="spool_recovery", harness="mcp", session_id="s1", workspace_id="ws_1",
            turn_key="turn-1", call_id="", spool_id=sid_a, line_span=(5, 15), byte_span=(50, 150),
            delivery_evidence="unverified", spool_id_referenced=True, turn_correlation="transcript_derived",
            timestamp="2026-11-16T02:00:03Z",
        ),
        build_receipt(
            event_type="spool_recovery", harness="mcp", session_id="s1", workspace_id="ws_1",
            turn_key="turn-2", call_id="", spool_id=sid_a, line_span=(20, 30), byte_span=(200, 300),
            delivery_evidence="unverified", spool_id_referenced=True, turn_correlation="harness_native",
            timestamp="2026-11-16T02:00:04Z",
        ),
        build_receipt(
            event_type="spool_created", harness="claude", session_id="s1", workspace_id="ws_1",
            turn_key="t3", call_id="c3", spool_id=sid_b, line_span=(0, 50), byte_span=(0, 5000),
            delivery_evidence="replacement_emitted", spool_id_referenced=False,
            original_bytes=5000, replacement_bytes=200, timestamp="2026-11-16T02:00:05Z",
        ),
        build_receipt(
            event_type="spool_created", harness="claude", session_id="s1", workspace_id="ws_1",
            turn_key="t4", call_id="c4", spool_id=sid_c, line_span=(0, 50), byte_span=(0, 4000),
            delivery_evidence="replacement_emitted", spool_id_referenced=False, timestamp="2026-11-16T02:00:06Z",
        ),
        build_receipt(
            event_type="spool_recovery", harness="mcp", session_id="s1", workspace_id="ws_1",
            turn_key="t4", call_id="", spool_id=sid_c, line_span=(0, 5), byte_span=(0, 50),
            delivery_evidence="unverified", spool_id_referenced=True, turn_correlation="harness_native",
            timestamp="2026-11-16T02:00:07Z",
        ),
        build_receipt(
            event_type="spool_recovery", harness="mcp", session_id="s1", workspace_id="ws_1",
            turn_key="t5", call_id="", spool_id=sid_c, line_span=(0, 5), byte_span=(0, 50),
            delivery_evidence="unverified", spool_id_referenced=True, turn_correlation="unobserved",
            timestamp="2026-11-16T02:00:08Z",
        ),
    ]
    rcpt_path.write_text("".join(json.dumps(dict(r)) + "\n" for r in rows), encoding="utf-8")

    only_a = summarize_spool_lifecycle(rcpt_path, spool_id=sid_a)
    assert only_a["completeness"] == "complete" and only_a["recovery_calls"] == 3
    assert only_a["recovery_model_turns"] == 2 and only_a["turn_correlation_status"] == "observed"
    assert only_a["unique_recovered_bytes"] == 250 and only_a["total_recovered_bytes"] == 300
    assert only_a["recovery_amplification"] == 1.2
    assert only_a["original_bytes"] == 10000 and only_a["replacement_bytes"] == 320
    assert only_a["delivery_evidence"] == "delivery_verified"

    only_b = summarize_spool_lifecycle(rcpt_path, spool_id=sid_b)
    assert only_b["completeness"] == "complete" and only_b["recovery_calls"] == 0
    assert only_b["recovery_model_turns"] == 0 and only_b["turn_correlation_status"] == "observed"
    assert only_b["recovery_amplification"] == 0.0

    only_c = summarize_spool_lifecycle(rcpt_path, spool_id=sid_c)
    assert only_c["turn_correlation_status"] == "partial" and only_c["recovery_model_turns"] is None

    agg = summarize_spool_lifecycle(rcpt_path)
    assert agg["completeness"] == "complete" and agg["turn_correlation_status"] == "partial"
    assert agg["recovery_model_turns"] is None and agg["original_bytes"] == 19000 and agg["replacement_bytes"] == 520

    from datetime import datetime, timezone
    win_now = datetime(2026, 11, 16, 2, 0, 8, tzinfo=timezone.utc).timestamp()
    win_only = summarize_spool_lifecycle(rcpt_path, window_seconds=2.0, now_ts=win_now)
    assert win_only["completeness"] == "complete" and win_only["recovery_calls"] == 2
    assert set(win_only["by_spool"].keys()) == {sid_c}

    empty_tk_path = tmp_path / "empty_tk.jsonl"
    empty_tk_path.write_text(json.dumps(dict(build_receipt(
        event_type="spool_recovery", harness="mcp", session_id="s2", workspace_id="ws_2",
        turn_key="", call_id="", spool_id="sp_ffffffffffff", line_span=(0, 1), byte_span=(0, 20),
        delivery_evidence="unverified", spool_id_referenced=True, turn_correlation="harness_native",
    ))) + "\n", encoding="utf-8")
    etk = summarize_spool_lifecycle(empty_tk_path)
    assert etk["turn_correlation_status"] == "unobserved" and etk["recovery_model_turns"] is None

    # Rotated log missing spool_created -> incomplete (original_bytes and missing-base counts are None, never 0)
    rot_path = tmp_path / "rotated.jsonl"
    rot_rows = [
        build_receipt(
            event_type="spool_recovery", harness="mcp", session_id="s2", workspace_id="ws_2",
            turn_key="turn-r", call_id="", spool_id="sp_dddddddddddd", line_span=(0, 4), byte_span=(0, 80),
            delivery_evidence="unverified", spool_id_referenced=True, turn_correlation="unobserved",
        ),
        build_receipt(
            event_type="spool_integrity_failure", harness="mcp", session_id="s2", workspace_id="ws_2",
            turn_key="", call_id="", spool_id="sp_eeeeeeeeeeee", line_span=(0, 0), byte_span=(0, 10),
            delivery_evidence="unverified", spool_id_referenced=True, failure_kind="reliability_failure",
            reason="integrity_mismatch",
        ),
    ]
    rot_path.write_text("".join(json.dumps(dict(r)) + "\n" for r in rot_rows), encoding="utf-8")
    rot_sum = summarize_spool_lifecycle(rot_path)
    assert rot_sum["completeness"] == "incomplete" and rot_sum["original_bytes"] is None
    assert rot_sum["replacement_bytes"] is None and rot_sum["reliability_failures"] == 1
    assert rot_sum["by_spool"]["sp_eeeeeeeeeeee"]["recovery_model_turns"] is None
    assert rot_sum["by_spool"]["sp_eeeeeeeeeeee"]["recovery_amplification"] is None


def test_same_workspace_dir_and_read_spool_config_max_entry_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify same_workspace_dir dedup, zero os.getcwd calls, and max_spool_entry_bytes config validation."""
    from hooks import config

    real_repo = tmp_path / "RepoAlpha"
    sub_dir = real_repo / "pkg"
    sub_dir.mkdir(parents=True)
    (real_repo / ".git").mkdir()
    other_repo = tmp_path / "RepoBeta"
    (other_repo / ".git").mkdir(parents=True)

    roots_to_check = [str(real_repo)]
    if os.name != "nt":
        sym_repo = tmp_path / "sym_repo_alpha"
        sym_repo.symlink_to(real_repo)
        roots_to_check.append(str(sym_repo))
    case_variant = tmp_path / "repoalpha"
    if case_variant.exists():
        roots_to_check.append(str(case_variant))

    def _forbid_cwd() -> str:
        raise AssertionError("spool/receipts must never call os.getcwd")

    with monkeypatch.context() as mp:
        mp.setattr(os, "getcwd", _forbid_cwd)
        assert same_workspace_dir(None, real_repo) is False
        assert same_workspace_dir("", real_repo) is False
        assert same_workspace_dir(tmp_path / "missing_dir", real_repo) is False
        assert same_workspace_dir(real_repo, real_repo) is True
        if len(roots_to_check) >= 2:
            assert same_workspace_dir(real_repo, roots_to_check[1]) is True
            ws_id, canon, err = resolve_workspace_identity(None, workspace_roots=roots_to_check)
            assert err is None and ws_id.startswith("ws_") and same_workspace_dir(canon, real_repo)
            nar_id, nar_canon, nar_err = resolve_workspace_identity(
                Path(roots_to_check[1]) / "pkg", workspace_roots=[str(real_repo), str(other_repo)],
            )
            assert nar_err is None and nar_id.startswith("ws_") and same_workspace_dir(nar_canon, real_repo)

    assert DEFAULT_MAX_SPOOL_ENTRY_BYTES == 4 * 1024 * 1024
    assert config.DEFAULT_MAX_SPOOL_ENTRY_BYTES == DEFAULT_MAX_SPOOL_ENTRY_BYTES
    assert config.default_runtime_config()["spool"] == {
        "isolation": "workspace", "max_spool_entry_bytes": DEFAULT_MAX_SPOOL_ENTRY_BYTES,
    }
    assert read_spool_config(tmp_path / "absent.json") == ("workspace", DEFAULT_MAX_SPOOL_ENTRY_BYTES, None)

    valid_cfg = tmp_path / "valid_cfg.json"
    valid_cfg.write_text(json.dumps({"spool": {"isolation": "session", "max_spool_entry_bytes": 1024}}), encoding="utf-8")
    config.clear_config_cache()
    assert read_spool_config(valid_cfg) == ("session", 1024, None)
    assert read_spool_isolation_config(valid_cfg) == ("session", None)
    assert config.load_runtime_config(valid_cfg)["spool"] == {"isolation": "session", "max_spool_entry_bytes": 1024}

    for bad_val in (0, -1, True, False, "1024", 1.5, None):
        bad_cfg = tmp_path / "bad_cfg.json"
        bad_cfg.write_text(json.dumps({"spool": {"isolation": "workspace", "max_spool_entry_bytes": bad_val}}), encoding="utf-8")
        config.clear_config_cache()
        assert read_spool_config(bad_cfg) == ("", DEFAULT_MAX_SPOOL_ENTRY_BYTES, "invalid_spool_config")
        assert read_spool_isolation_config(bad_cfg) == ("", "invalid_spool_config")
        assert config.load_runtime_config(bad_cfg)["config_error"] == "invalid 'spool'"
