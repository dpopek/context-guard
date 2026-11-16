"""Tests for ContextReceiptV1 contract, bounded receipt persistence, and delivery evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

import policies.api as api
from policies.api import ContextReceiptV1, RECEIPT_SCHEMA_VERSION
from spool.receipts import (
    RECEIPTS_KEEP_ROWS,
    RECEIPTS_MAX_BYTES,
    append_receipt,
    build_receipt,
    find_created_receipt,
    persist_spool_delivery_verification,
    summarize_receipts,
)


def test_context_receipt_v1_schema_contract() -> None:
    """Verify ContextReceiptV1 exports, required keys, and PEP 563 string annotations."""
    assert RECEIPT_SCHEMA_VERSION == 1
    assert "RECEIPT_SCHEMA_VERSION" in api.__all__
    assert "ContextReceiptV1" in api.__all__

    expected_annotations = {
        "schema_version": "int",
        "receipt_id": "str",
        "parent_event_id": "str | None",
        "timestamp": "str",
        "event_type": "str",
        "harness": "str",
        "session_id": "str",
        "workspace_id": "str",
        "turn_key": "str",
        "call_id": "str",
        "spool_id": "str",
        "line_span": "tuple[int, int]",
        "byte_span": "tuple[int, int]",
        "upstream_truncation": "bool",
        "delivery_evidence": "str",
        "spool_id_referenced": "bool",
        "failure_kind": "str | None",
        "reason": "str | None",
    }
    ann = ContextReceiptV1.__annotations__
    assert set(ann.keys()) == set(expected_annotations.keys())
    assert ContextReceiptV1.__required_keys__ == frozenset(expected_annotations.keys())
    for key, expected in expected_annotations.items():
        raw_val = ann[key]
        actual = raw_val if isinstance(raw_val, str) else getattr(raw_val, "__forward_arg__", repr(raw_val))
        assert actual == expected


def test_receipts_rotate_at_limit_and_summarize_counts(tmp_path: Path) -> None:
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
