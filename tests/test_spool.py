from __future__ import annotations

from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

import pytest

from bin.cg_spool import main as cli_main
from core.contracts import SpoolDecision
from hooks.harness_adapter import format_post_tool_spool_response
from policies.api import HARD_INTEGRITY_FAILURE_REASONS, SpoolContractV1
from policies.governor import record_governor_signal
import spool as spool_pkg
from spool.store import (
    SPOOL_MAX_BLOB_BYTES,
    SPOOL_MIN_BYTES,
    SPOOL_SUMMARY_MAX_BYTES,
    SPOOL_TTL_SECONDS,
    classify_pre_tool_spool_followup,
    compute_command_signature,
    gc_spools,
    grep_spool,
    inspect_spool_health,
    is_verbose_override_command,
    list_spools,
    resolve_spool_dir,
    slice_spool,
    spool_post_tool_output,
    spool_tool_output,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    r = tmp_path / name
    r.mkdir(parents=True, exist_ok=True)
    return r


def make_lines_text(count: int, *, prefix: str = "line", width: int = 80, newline: str = "\n") -> str:
    """Build deterministic multi-line payload text above spool size gates."""
    pad = max(1, width - len(prefix) - 8)
    body = "x" * pad
    return newline.join(f"{prefix}-{idx:04d} {body}" for idx in range(1, count + 1)) + newline


def test_resolve_spool_dir_precedence_and_zero_home_leak_in_summary(tmp_path: Path) -> None:
    """Verify spool dir precedence and confirm summaries never leak filesystem paths."""
    repo = _repo(tmp_path)
    override_dir = tmp_path / "env_override_spool"
    state_dir = tmp_path / "state_root"
    assert resolve_spool_dir(state_dir, env={"CONTEXT_GUARD_SPOOL_DIR": str(override_dir)}) == override_dir
    assert resolve_spool_dir(state_dir, env={"CONTEXT_GUARD_SPOOL_DIR": "   "}) == state_dir / "spool"

    fallback = resolve_spool_dir(None, env={})
    assert fallback.is_absolute()
    assert fallback.parts[-2:] == ("telemetry", "spool")

    payload = make_lines_text(220)
    res = spool_tool_output(
        payload,
        session_id="sess-resolve",
        call_id="call-1",
        harness="claude",
        tool_name="Bash",
        cmd_sig="shell:pytest",
        workspace_root=repo,
        spool_dir=override_dir,
        now_ts=1_700_000_000.0,
    )
    assert res is not None
    contract, summary = res
    assert contract.spool_id.startswith("sp_")
    assert str(override_dir) not in summary
    assert override_dir.name not in summary
    assert str(tmp_path) not in summary
    assert tmp_path.name not in summary
    assert str(repo) not in summary
    assert Path.home().as_posix() not in summary


def test_spool_tool_output_thresholds_nul_max_blob_and_min_savings(tmp_path: Path) -> None:
    """Reject NUL bytes, blobs >4 MiB, undersized payloads, and tiny savings."""
    repo = _repo(tmp_path)
    spool_dir = tmp_path / "spool"

    nul_text = make_lines_text(220) + "\x00tail"
    assert spool_tool_output(nul_text, session_id="s1", call_id="c1", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir) is None

    too_big = "a" * (SPOOL_MAX_BLOB_BYTES + 1)
    assert spool_tool_output(too_big, session_id="s1", call_id="c2", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir) is None

    small_text = make_lines_text(20, width=40)
    assert len(small_text.encode("utf-8")) < SPOOL_MIN_BYTES
    assert spool_tool_output(small_text, session_id="s1", call_id="c3", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir) is None

    many_tiny_lines = "\n".join("ok" for _ in range(210)) + "\n"
    assert spool_tool_output(many_tiny_lines, session_id="s1", call_id="c4", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir) is None
    assert not spool_dir.exists() or list(spool_dir.iterdir()) == []

    large_text = make_lines_text(240, width=90)
    assert spool_tool_output(large_text, session_id="s1", call_id="c0", harness="claude", tool_name="Bash", spool_dir=spool_dir) is None
    res = spool_tool_output(large_text, session_id="s1", call_id="c5", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_010.0)
    assert res is not None
    contract, summary = res
    assert contract.total_lines == 240
    assert contract.path == str(spool_dir / f"{contract.spool_id}.txt")
    blob = spool_dir / f"{contract.spool_id}.txt"
    assert blob.exists()
    if os.name != "nt":
        assert stat.S_IMODE(blob.stat().st_mode) == 0o600
    assert len(summary.encode("utf-8")) < contract.total_bytes


def test_spool_crlf_normalization_and_binary_lf_sha256_integrity(tmp_path: Path) -> None:
    """Normalize CRLF/CR to LF before hashing and binary LF persistence."""
    assert [f.name for f in fields(SpoolContractV1)] == [
        "spool_id",
        "path",
        "total_lines",
        "total_bytes",
        "content_sha256",
    ]
    repo = _repo(tmp_path)
    spool_dir = tmp_path / "spool"
    raw_crlf = make_lines_text(220, width=75, newline="\r\n") + "lone-cr\r"
    expected_lf = raw_crlf.replace("\r\n", "\n").replace("\r", "\n")
    expected_bytes = expected_lf.encode("utf-8")
    expected_sha = hashlib.sha256(expected_bytes).hexdigest()

    res = spool_tool_output(
        raw_crlf,
        session_id="s-crlf",
        call_id="c-crlf",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_700_000_020.0,
    )
    assert res is not None
    contract, summary = res
    assert contract.total_bytes == len(expected_bytes)
    assert contract.content_sha256 == expected_sha
    assert f"sha256={expected_sha[:12]}" in summary

    stored_bytes = (spool_dir / f"{contract.spool_id}.txt").read_bytes()
    assert b"\r" not in stored_bytes
    assert stored_bytes == expected_bytes


def test_spool_summary_truncation_preserves_header_hints_and_utf8_cap(tmp_path: Path) -> None:
    """Enforce <= 3_072 UTF-8 byte summary cap while keeping header and recovery hints."""
    repo = _repo(tmp_path)
    spool_dir = tmp_path / "spool"
    multi_lines = "\n".join(f"ż€-{idx:04d}-" + ("ą" * 60) for idx in range(1, 260)) + "\n"
    res = spool_tool_output(
        multi_lines,
        session_id="s-utf8",
        call_id="c-utf8",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_700_000_030.0,
    )
    assert res is not None
    contract, summary = res
    encoded = summary.encode("utf-8")
    assert len(encoded) <= SPOOL_SUMMARY_MAX_BYTES
    assert f"[CONTEXT-GUARD OUTPUT SPOOL: {contract.spool_id}" in summary
    assert f"- CLI: cg-spool slice {contract.spool_id}" in summary
    assert "- MCP: cg_spool_slice / cg_spool_grep" in summary
    assert "--- HEAD" in summary
    assert "--- OMITTED" in summary
    assert "--- TAIL" in summary

    huge_single_line = "€" * 7_000
    res_single = spool_tool_output(
        huge_single_line,
        session_id="s-single",
        call_id="c-single",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_700_000_031.0,
    )
    assert res_single is not None
    single_contract, single_summary = res_single
    assert single_contract.total_lines == 1
    assert len(single_summary.encode("utf-8")) <= SPOOL_SUMMARY_MAX_BYTES
    assert f"[CONTEXT-GUARD OUTPUT SPOOL: {single_contract.spool_id}" in single_summary
    assert f"- CLI: cg-spool slice {single_contract.spool_id}" in single_summary


def test_slice_grep_list_and_invalid_regex_recovery(tmp_path: Path) -> None:
    """Exercise slice, grep, list, inspect_spool_health, workspace enforcement, and invalid regex."""
    repo = _repo(tmp_path)
    spool_dir = tmp_path / "spool"
    assert list_spools(spool_dir=spool_dir) == {"ok": False, "error": "workspace_unresolved"}
    empty_list = list_spools(workspace_root=repo, spool_dir=spool_dir)
    assert empty_list == {"ok": True, "count": 0, "total_bytes": 0, "entries": []}
    empty_health = inspect_spool_health(spool_dir)
    assert empty_health["spool_dir_exists"] is False
    assert empty_health["entry_count"] == 0
    assert isinstance(empty_health["summary_line"], str)

    lines_a = [f"item-{i:04d} " + ("z" * 70) for i in range(1, 221)]
    lines_a[99] = "needle MatchLine token=" + ("q" * 60)
    text_a = "\n".join(lines_a) + "\n"
    res_a = spool_tool_output(text_a, session_id="sess-A", call_id="cA", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_100.0)
    res_b = spool_tool_output(make_lines_text(210, prefix="beta"), session_id="sess-B", call_id="cB", harness="cursor", tool_name="MCP:srv:list", workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_110.0)
    assert res_a is not None and res_b is not None
    sid_a = res_a[0].spool_id
    sid_b = res_b[0].spool_id

    assert slice_spool(sid_a, spool_dir=spool_dir) == {"ok": False, "error": "workspace_unresolved"}
    assert grep_spool(sid_a, "matchline", spool_dir=spool_dir) == {"ok": False, "error": "workspace_unresolved"}

    sl = slice_spool(sid_a, start_line=99, limit=3, workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_120.0)
    assert sl["ok"] is True
    assert sl["start_line"] == 99
    assert sl["end_line"] == 101
    assert sl["returned_lines"] == 3
    assert sl["content"].splitlines()[1].startswith("needle MatchLine")

    sl_end = slice_spool(sid_a, start_line=215, end_line=220, workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_121.0)
    assert sl_end["ok"] is True
    assert sl_end["returned_lines"] == 6
    assert sl_end["truncated"] is False

    assert slice_spool("bad_id", workspace_root=repo, spool_dir=spool_dir)["error"] == "invalid_spool_id"
    assert slice_spool("sp_000000000000", workspace_root=repo, spool_dir=spool_dir)["error"] == "spool_not_found"

    gr = grep_spool(sid_a, "matchline", ignore_case=True, context_lines=1, max_matches=500, workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_122.0)
    assert gr["ok"] is True
    assert gr["match_count"] == 1
    assert gr["matches"][0]["line"] == 100
    assert len(gr["matches"][0]["before"]) == 1
    assert len(gr["matches"][0]["after"]) == 1

    bad_re = grep_spool(sid_a, "[unclosed", workspace_root=repo, spool_dir=spool_dir)
    assert bad_re["ok"] is False
    assert "invalid_regex" in bad_re["error"]

    all_spools = list_spools(workspace_root=repo, spool_dir=spool_dir)
    assert all_spools["ok"] is True
    assert all_spools["count"] == 2
    only_a = list_spools(session_id="sess-A", workspace_root=repo, spool_dir=spool_dir)
    assert only_a["count"] == 1
    assert only_a["entries"][0]["spool_id"] == sid_a
    assert sid_b != sid_a
    for entry in all_spools["entries"]:
        assert "canon_root" not in entry
        assert str(repo) not in json.dumps(entry)
        assert str(spool_dir) not in json.dumps(entry)

    health = inspect_spool_health(spool_dir, now_ts=1_700_000_125.0)
    assert health["spool_dir_exists"] is True
    assert health["entry_count"] == 2
    assert health["expired_count"] == 0
    assert health["orphan_count"] == 0
    assert "2 entries" in health["summary_line"] and "0 expired" in health["summary_line"]
    assert str(spool_dir) not in health["summary_line"]


def test_gc_evicts_expired_ttl_entry_count_and_total_bytes_lru_order(tmp_path: Path) -> None:
    """Verify TTL expiration, orphan cleanup, and LRU eviction by count and bytes."""
    repo = _repo(tmp_path)
    spool_dir = tmp_path / "spool"
    ids: list[str] = []
    for idx in range(4):
        res = spool_tool_output(
            make_lines_text(220, prefix=f"gc{idx}"),
            session_id="sess-gc",
            call_id=f"c-{idx}",
            harness="claude",
            tool_name="Bash",
            workspace_root=repo,
            spool_dir=spool_dir,
            now_ts=1_000.0 + idx * 10.0,
        )
        assert res is not None
        ids.append(res[0].spool_id)

    orphan = spool_dir / "sp_abcdef012345.txt"
    orphan.write_text("orphan blob\n", encoding="utf-8")
    os.utime(orphan, (10.0, 10.0))

    assert slice_spool(ids[0], start_line=1, limit=5, workspace_root=repo, spool_dir=spool_dir, now_ts=1_050.0)["ok"] is True

    gc_count = gc_spools(max_age_seconds=100.0, max_entries=3, max_total_bytes=50_000_000, spool_dir=spool_dir, now_ts=1_060.0)
    assert gc_count["ok"] is True
    assert gc_count["remaining_count"] == 3
    assert not orphan.exists()
    remaining_ids = {e["spool_id"] for e in list_spools(workspace_root=repo, spool_dir=spool_dir)["entries"]}
    assert ids[0] in remaining_ids
    assert ids[1] not in remaining_ids

    one_size = list_spools(workspace_root=repo, spool_dir=spool_dir)["entries"][0]["total_bytes"]
    gc_bytes = gc_spools(max_age_seconds=SPOOL_TTL_SECONDS, max_entries=10, max_total_bytes=one_size, spool_dir=spool_dir, now_ts=1_070.0)
    assert gc_bytes["ok"] is True
    assert gc_bytes["remaining_count"] == 1
    assert gc_bytes["remaining_bytes"] <= one_size

    gc_ttl = gc_spools(max_age_seconds=60.0, max_entries=10, max_total_bytes=one_size * 10, spool_dir=spool_dir, now_ts=2_000.0)
    assert gc_ttl["ok"] is True
    assert gc_ttl["remaining_count"] == 0
    assert gc_ttl["removed_count"] >= 1


def test_spool_symlink_rejection_and_corrupt_index_quarantine(tmp_path: Path) -> None:
    """Reject symlinked spool roots/files and quarantine corrupt index only on write."""
    if os.name == "nt":
        pytest.skip("POSIX symlink behavior test")

    repo = _repo(tmp_path)
    real_dir = tmp_path / "real_target"
    real_dir.mkdir()
    sym_spool_dir = tmp_path / "sym_spool"
    sym_spool_dir.symlink_to(real_dir)

    assert spool_tool_output(make_lines_text(210), session_id="s", call_id="c", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=sym_spool_dir) is None
    assert list_spools(workspace_root=repo, spool_dir=sym_spool_dir) == {"ok": False, "error": "unsafe_path"}
    assert slice_spool("sp_0123456789ab", workspace_root=repo, spool_dir=sym_spool_dir) == {"ok": False, "error": "unsafe_path"}

    spool_dir = tmp_path / "clean_spool"
    res = spool_tool_output(make_lines_text(210), session_id="s", call_id="c1", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir, now_ts=100.0)
    assert res is not None
    sid = res[0].spool_id
    blob = spool_dir / f"{sid}.txt"
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("do-not-read\n", encoding="utf-8")
    blob.unlink()
    blob.symlink_to(secret)
    assert slice_spool(sid, workspace_root=repo, spool_dir=spool_dir)["error"] == "unsafe_path"
    assert grep_spool(sid, "do-not-read", workspace_root=repo, spool_dir=spool_dir)["error"] == "unsafe_path"

    idx_path = spool_dir / "spool_index.json"
    idx_path.write_text("{broken json", encoding="utf-8")
    health = inspect_spool_health(spool_dir)
    assert health["entry_count"] == 0
    assert list(spool_dir.glob(".spool_index.corrupt.*.json")) == []

    recovered = spool_tool_output(make_lines_text(210, prefix="fresh"), session_id="s", call_id="c2", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir, now_ts=200.0)
    assert recovered is not None
    assert len(list(spool_dir.glob(".spool_index.corrupt.*.json"))) == 1
    assert list_spools(workspace_root=repo, spool_dir=spool_dir)["count"] == 1


def _build_post_tool_spool_response(
    harness: str, payload: dict[str, Any], **kwargs: Any
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    decision, meta = spool_post_tool_output(harness, payload, **kwargs)
    return format_post_tool_spool_response(harness, decision), meta


def test_build_post_tool_spool_response_claude_shapes_and_mixed_block_fail_open(tmp_path: Path) -> None:
    """Match Claude Bash/MCP output shapes exactly and fail open on mixed blocks or unresolved scope."""
    repo = _repo(tmp_path)
    spool_dir = tmp_path / "spool"
    big = make_lines_text(220, prefix="claude")

    off_resp, off_meta = _build_post_tool_spool_response(
        "claude",
        {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": big, "cwd": str(repo)},
        mode="off",
        session_id="s1",
        call_id="c0",
        spool_dir=spool_dir,
    )
    assert off_resp == {} and off_meta is None

    no_ws_resp, no_ws_meta = _build_post_tool_spool_response(
        "claude",
        {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": big},
        mode="active",
        session_id="s1",
        call_id="c0-nows",
        spool_dir=spool_dir,
    )
    assert no_ws_resp == {} and no_ws_meta is None
    assert not spool_dir.exists()

    r_str, m_str = _build_post_tool_spool_response(
        "claude",
        {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": big, "cwd": str(repo)},
        mode="active",
        session_id="s1",
        call_id="c1",
        spool_dir=spool_dir,
        now_ts=1_000.0,
    )
    assert m_str is not None
    assert r_str["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert isinstance(r_str["hookSpecificOutput"]["updatedToolOutput"], str)
    assert m_str["spool_id"] in r_str["hookSpecificOutput"]["updatedToolOutput"]
    assert m_str["workspace_id"].startswith("ws_")

    r_out, _ = _build_post_tool_spool_response(
        "claude",
        {"tool_name": "Bash", "tool_input": {"command": "ls -la"}, "tool_response": {"output": big, "exit_code": 0}, "cwd": str(repo)},
        mode="active",
        session_id="s1",
        call_id="c2",
        spool_dir=spool_dir,
        now_ts=1_001.0,
    )
    updated_out = r_out["hookSpecificOutput"]["updatedToolOutput"]
    assert isinstance(updated_out, dict)
    assert updated_out["exit_code"] == 0
    assert updated_out["output"].startswith("[CONTEXT-GUARD OUTPUT SPOOL:")

    r_stdout, _ = _build_post_tool_spool_response(
        "claude",
        {"tool_name": "Bash", "tool_input": {"command": "make"}, "tool_response": {"stdout": big, "stderr": "ok"}, "cwd": str(repo)},
        mode="active",
        session_id="s1",
        call_id="c3",
        spool_dir=spool_dir,
        now_ts=1_002.0,
    )
    assert r_stdout["hookSpecificOutput"]["updatedToolOutput"]["stderr"] == "ok"
    assert "[CONTEXT-GUARD OUTPUT SPOOL:" in r_stdout["hookSpecificOutput"]["updatedToolOutput"]["stdout"]

    r_blk, _ = _build_post_tool_spool_response(
        "claude",
        {"tool_name": "mcp__demo__dump", "tool_input": {"q": 1}, "tool_response": [{"type": "text", "text": big}], "cwd": str(repo)},
        mode="active",
        session_id="s1",
        call_id="c4",
        spool_dir=spool_dir,
        now_ts=1_003.0,
    )
    updated_blk = r_blk["hookSpecificOutput"]["updatedToolOutput"]
    assert isinstance(updated_blk, list) and len(updated_blk) == 1
    assert updated_blk[0]["type"] == "text"

    r_mixed, m_mixed = _build_post_tool_spool_response(
        "claude",
        {
            "tool_name": "mcp__demo__dump",
            "tool_input": {"q": 1},
            "tool_response": [{"type": "text", "text": big}, {"type": "image", "data": "abc"}],
            "cwd": str(repo),
        },
        mode="active",
        session_id="s1",
        call_id="c5",
        spool_dir=spool_dir,
        now_ts=1_004.0,
    )
    assert r_mixed == {} and m_mixed is None


def test_build_post_tool_spool_response_cursor_mcp_redacted_and_shadow_parity(tmp_path: Path) -> None:
    """Handle Cursor MCP rewrites, redacted skips, Cursor Shell skip, and shadow parity."""
    repo = _repo(tmp_path)
    spool_dir = tmp_path / "spool"
    big = make_lines_text(220, prefix="cursor")

    sh_resp, sh_meta = _build_post_tool_spool_response(
        "cursor",
        {"tool_name": "Shell", "tool_input": {"command": "pytest"}, "tool_output": big, "cwd": str(repo)},
        mode="active",
        session_id="cur-1",
        call_id="c1",
        spool_dir=spool_dir,
    )
    assert sh_resp == {} and sh_meta is None
    assert not spool_dir.exists()

    red_resp, red_meta = _build_post_tool_spool_response(
        "cursor",
        {"tool_name": "MCP:gh:logs", "tool_input": {"id": 1}, "tool_output": {"redacted": True, "text": big}, "cwd": str(repo)},
        mode="active",
        session_id="cur-1",
        call_id="c2",
        spool_dir=spool_dir,
    )
    assert red_resp == {} and red_meta is None

    # Shadow fails open without workspace_root / cwd.
    sh_no_ws, sh_no_ws_meta = _build_post_tool_spool_response(
        "cursor",
        {"tool_name": "MCP:gh:logs", "tool_input": {"id": 2}, "tool_output": {"text": big}},
        mode="shadow",
        session_id="cur-1",
        call_id="c3-nows",
        spool_dir=spool_dir,
    )
    assert sh_no_ws == {} and sh_no_ws_meta is None

    shadow_resp, shadow_meta = _build_post_tool_spool_response(
        "cursor",
        {"tool_name": "MCP:gh:logs", "tool_input": {"id": 2}, "tool_output": {"text": big}, "cwd": str(repo)},
        mode="shadow",
        session_id="cur-1",
        call_id="c3",
        spool_dir=spool_dir,
    )
    assert shadow_resp == {} and shadow_meta is not None
    assert not spool_dir.exists()

    act_resp, act_meta = _build_post_tool_spool_response(
        "cursor",
        {"tool_name": "MCP:gh:logs", "tool_input": {"id": 2}, "tool_output": {"text": big}, "cwd": str(repo)},
        mode="active",
        session_id="cur-1",
        call_id="c3",
        spool_dir=spool_dir,
        now_ts=2_000.0,
    )
    assert act_meta is not None
    assert isinstance(act_resp["updated_mcp_tool_output"], dict) and act_resp["updated_mcp_tool_output"]["text"].startswith("[CONTEXT-GUARD OUTPUT SPOOL:")
    assert shadow_meta["spool_id"] == act_meta["spool_id"]
    assert shadow_meta["workspace_id"] == act_meta["workspace_id"]
    assert shadow_meta["total_bytes"] == act_meta["total_bytes"]
    assert shadow_meta["summary_bytes"] == act_meta["summary_bytes"]


def test_build_post_tool_spool_response_skips_errors_reads_mutations_and_self_calls(tmp_path: Path) -> None:
    """Never spool reads/mutations, error payloads, or cg-spool self-calls."""
    repo = _repo(tmp_path)
    spool_dir = tmp_path / "spool"
    big = make_lines_text(220, prefix="skip")

    cases: list[dict[str, Any]] = [
        {"tool_name": "Read", "tool_input": {"file_path": "a.py"}, "tool_response": big},
        {"tool_name": "Grep", "tool_input": {"pattern": "x"}, "tool_response": big},
        {"tool_name": "Edit", "tool_input": {"file_path": "a.py"}, "tool_response": big},
        {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "is_error": True, "tool_response": big},
        {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": {"output": big, "exit_code": 1}},
        {"tool_name": "Bash", "tool_input": {"command": "cg-spool slice sp_0123456789ab"}, "tool_response": big},
        {"tool_name": "Bash", "tool_input": {"command": "python3 bin/cg_spool.py grep sp_0123456789ab err"}, "tool_response": big},
        {"tool_name": "mcp__context_guard__cg_spool_slice", "tool_input": {"spool_id": "sp_0123456789ab"}, "tool_response": big},
        {"tool_name": "call_mcp_tool", "tool_input": {"name": "cg_spool_list"}, "tool_response": big},
    ]
    for idx, payload in enumerate(cases):
        resp, meta = _build_post_tool_spool_response(
            "claude",
            payload,
            mode="active",
            session_id="skip-s",
            call_id=f"c-{idx}",
            workspace_root=repo,
            spool_dir=spool_dir,
        )
        assert resp == {} and meta is None
    assert not spool_dir.exists()


def test_command_signature_and_verbose_override_quoted_guard() -> None:
    """Normalize shell/MCP signatures and detect only unquoted verbose overrides."""
    expected_shell = hashlib.sha256(b"shell:pytest -k smoke").hexdigest()[:16]
    sig_cd = compute_command_signature("Bash", "cd /tmp/repo && pytest -q -k smoke")
    sig_plain = compute_command_signature("Bash", "pytest -k smoke --verbose")
    assert sig_cd == sig_plain == expected_shell

    expected_mcp = hashlib.sha256(b'mcp:mcp__srv__run:{"a":1,"b":2}').hexdigest()[:16]
    sig_mcp_a = compute_command_signature("mcp__srv__run", {"b": 2, "a": 1})
    sig_mcp_b = compute_command_signature("mcp__srv__run", {"a": 1, "b": 2})
    assert sig_mcp_a == sig_mcp_b == expected_mcp

    for noisy in ("pytest -v tests", "pytest -vv", "pytest -vvv", "pytest --verbose", "pytest --tb=long", "pytest --tb=full", "pytest --tb long", "pytest --no-quiet"):
        flagged, flag = is_verbose_override_command(noisy)
        assert flagged is True and flag == expected_shell or (flagged is True and len(flag) == 16)

    for safe in ('rg -e -v file.py', 'grep --pattern --verbose log', 'rg "-v" foo', 'pytest -k "-vv"', 'pytest "broken quote'):
        flagged, flag = is_verbose_override_command(safe)
        assert flagged is False and flag == ""


def test_classify_pre_tool_spool_followup_cli_mcp_and_direct_reads(tmp_path: Path) -> None:
    """Classify CLI, MCP, and direct-Read spool follow-ups purely read-only."""
    repo = _repo(tmp_path)
    spool_dir = tmp_path / "spool"
    res = spool_tool_output(make_lines_text(220), session_id="s-pre", call_id="c1", harness="claude", tool_name="Bash", workspace_root=repo, spool_dir=spool_dir, now_ts=500.0)
    assert res is not None
    sid = res[0].spool_id
    blob_path = spool_dir / f"{sid}.txt"

    assert classify_pre_tool_spool_followup("Bash", {"command": f"cg-spool slice {sid} --start 1 --limit 60"}, spool_dir=spool_dir) is None

    cli_sl = classify_pre_tool_spool_followup("Bash", {"command": f"cg-spool slice {sid} --start 1 --limit 60"}, workspace_root=repo, spool_dir=spool_dir)
    assert cli_sl == {"spool_id": sid, "kind": "slice", "recovery": "targeted", "regret": "none", "evidence": "observed", "requested_lines": 60}

    cli_gr = classify_pre_tool_spool_followup("Bash", {"command": f"cg-spool grep {sid} ERROR"}, workspace_root=repo, spool_dir=spool_dir)
    assert cli_gr is not None and cli_gr["kind"] == "grep" and cli_gr["regret"] == "none"

    mcp_sl = classify_pre_tool_spool_followup("call_mcp_tool", {"name": "cg_spool_slice", "arguments": {"spool_id": sid, "limit": 80}}, workspace_root=repo, spool_dir=spool_dir)
    assert mcp_sl is not None and mcp_sl["kind"] == "slice" and mcp_sl["requested_lines"] == 80

    direct_full = classify_pre_tool_spool_followup("Read", {"file_path": str(blob_path)}, workspace_root=repo, spool_dir=spool_dir)
    assert direct_full == {"spool_id": sid, "kind": "direct_read", "recovery": "full", "regret": "suspected", "evidence": "observed", "requested_lines": None}

    direct_part = classify_pre_tool_spool_followup("Read", {"file_path": str(blob_path), "limit": 40}, workspace_root=repo, spool_dir=spool_dir)
    assert direct_part is not None and direct_part["recovery"] == "targeted" and direct_part["regret"] == "none"

    (spool_dir / "spool_index.json").write_text("{bad", encoding="utf-8")
    assert classify_pre_tool_spool_followup("Read", {"file_path": str(blob_path)}, workspace_root=repo, spool_dir=spool_dir) is not None
    assert list(spool_dir.glob(".spool_index.corrupt.*.json")) == []


def test_cg_spool_cli_subcommands_json_and_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Exercise bin/cg_spool.py CLI in-process and via real subprocess."""
    spool_dir = tmp_path / "spool"
    lines = [f"row-{i:04d} " + ("m" * 70) for i in range(1, 221)]
    lines[49] = "row-0050 FINDME " + ("m" * 64)
    res = spool_tool_output("\n".join(lines) + "\n", session_id="cli-sess", call_id="c1", harness="claude", tool_name="Bash", workspace_root=REPO_ROOT, spool_dir=spool_dir, now_ts=1_000.0)
    assert res is not None
    sid = res[0].spool_id

    assert cli_main(["list", "--spool-dir", str(spool_dir), "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["count"] == 1

    assert cli_main(["slice", sid, "--start", "49", "--limit", "3", "--spool-dir", str(spool_dir), "--json"]) == 0
    sliced = json.loads(capsys.readouterr().out)
    assert sliced["returned_lines"] == 3 and "FINDME" in sliced["content"]

    assert cli_main(["grep", sid, "FINDME", "--spool-dir", str(spool_dir), "--json"]) == 0
    grepped_pos = json.loads(capsys.readouterr().out)
    assert grepped_pos["match_count"] == 1

    assert cli_main(["grep", sid, "--pattern", "FINDME", "--spool-dir", str(spool_dir)]) == 0
    assert "50:" in capsys.readouterr().out

    assert cli_main(["slice", "bad_id", "--spool-dir", str(spool_dir)]) == 1
    capsys.readouterr()

    sub = subprocess.run(
        [sys.executable, str(REPO_ROOT / "bin" / "cg_spool.py"), "gc", "--max-age", "0", "--spool-dir", str(spool_dir), "--json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert sub.returncode == 0
    gc_payload = json.loads(sub.stdout)
    assert gc_payload["ok"] is True

    bad_sub = subprocess.run(
        [sys.executable, str(REPO_ROOT / "bin" / "cg_spool.py"), "grep", sid, "[unclosed", "--spool-dir", str(spool_dir), "--json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad_sub.returncode == 1
    assert json.loads(bad_sub.stdout)["ok"] is False


def test_spool_package_exports_and_recovery_receipt_telemetry_fields(tmp_path: Path) -> None:
    """Verify spool.__init__ / spool.classifier re-exports, receipt metadata, and non-recycling after corrupt."""
    import spool
    from spool import classifier as spool_classifier
    from spool.receipts import RECEIPTS_FILENAME

    assert spool.compute_command_signature is compute_command_signature is spool_classifier.compute_command_signature
    assert spool.is_verbose_override_command is is_verbose_override_command is spool_classifier.is_verbose_override_command
    assert spool.classify_pre_tool_spool_followup is classify_pre_tool_spool_followup is spool_classifier.classify_pre_tool_spool_followup
    for attr in (
        "DEFAULT_MAX_SPOOL_ENTRY_BYTES",
        "read_spool_config",
        "same_workspace_dir",
        "derive_spool_event_id",
        "summarize_spool_lifecycle",
    ):
        assert hasattr(spool, attr)

    repo = _repo(tmp_path, "proj_exp")
    spool_dir = tmp_path / "spool"
    payload = make_lines_text(220, prefix="exp")
    res = spool_tool_output(
        payload,
        session_id="s-exp",
        call_id="c-exp-1",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        turn_key="s-exp:step:2",
        turn_correlation="harness_native",
        hook_duration_ms=1.25,
        event_id="ev_fixed_create_1",
        now_ts=1_000.0,
    )
    assert res is not None
    contract, summary = res
    sid = contract.spool_id

    sl = slice_spool(
        sid,
        start_line=1,
        limit=5,
        workspace_root=repo,
        spool_dir=spool_dir,
        turn_key="s-exp:step:3",
        turn_correlation="harness_native",
        call_id="c-slice-1",
        now_ts=1_010.0,
    )
    assert sl["ok"] is True

    rows = [json.loads(ln) for ln in (spool_dir / RECEIPTS_FILENAME).read_text(encoding="utf-8").splitlines() if ln.strip()]
    created, recovered = rows[0], rows[1]
    assert created["event_id"] == "ev_fixed_create_1"
    assert created["source_hash"] == contract.content_sha256
    assert created["original_bytes"] == contract.total_bytes
    assert created["replacement_bytes"] == len(summary.encode("utf-8"))
    assert created["turn_correlation"] == "harness_native"
    assert created["hook_duration_ms"] == 1.25
    assert recovered["turn_key"] == "s-exp:step:3"
    assert recovered["turn_correlation"] == "harness_native"
    assert recovered["call_id"] == "c-slice-1"
    assert recovered["tool_call_id"] == "c-slice-1"
    assert recovered["source_hash"] == contract.content_sha256

    # Marking existing blob corrupt forces a new generation spool_id on identical re-spool (INV-4).
    (spool_dir / f"{sid}.txt").unlink()
    assert slice_spool(sid, workspace_root=repo, spool_dir=spool_dir)["error"] == "unexpectedly_missing"
    res2 = spool_tool_output(
        payload,
        session_id="s-exp",
        call_id="c-exp-2",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_020.0,
    )
    assert res2 is not None and res2[0].spool_id != sid
    assert slice_spool(sid, workspace_root=repo, spool_dir=spool_dir) == {
        "ok": False,
        "error": "spool_corrupt",
        "corrupt_reason": "unexpectedly_missing",
    }


def test_spool_post_tool_output_domain_contract(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "dom")
    spool_dir = tmp_path / "spool"
    big = make_lines_text(220, width=90)
    assert spool_pkg.spool_post_tool_output is spool_post_tool_output

    dec_cl, meta_cl = spool_post_tool_output(
        "claude", {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": {"output": big, "exit_code": 0}},
        mode="active", session_id="s-dom", call_id="c-dom-1", workspace_root=repo, spool_dir=spool_dir, now_ts=1_000.0,
    )
    assert isinstance(dec_cl, SpoolDecision) and meta_cl is not None
    assert dec_cl.harness == "claude" and dec_cl.shape == "output" and dec_cl.meta == meta_cl
    assert isinstance(dec_cl.updated_output, dict) and dec_cl.updated_output["exit_code"] == 0
    assert "[CONTEXT-GUARD OUTPUT SPOOL:" in dec_cl.updated_output["output"]
    assert meta_cl["spool_id"] in dec_cl.updated_output["output"]
    assert "hookSpecificOutput" not in dec_cl.updated_output and "hookSpecificOutput" not in meta_cl

    dec_cu, meta_cu = spool_post_tool_output(
        "cursor", {"tool_name": "MCP:big_search", "tool_input": {"q": "abc"}, "tool_output": {"text": big}},
        mode="active", session_id="s-dom", call_id="c-dom-2", workspace_root=repo, spool_dir=spool_dir, now_ts=1_001.0,
    )
    assert isinstance(dec_cu, SpoolDecision) and meta_cu is not None
    assert dec_cu.harness == "cursor" and dec_cu.shape == "text"
    assert isinstance(dec_cu.updated_output, dict) and meta_cu["spool_id"] in dec_cu.updated_output["text"]
    assert "updated_mcp_tool_output" not in meta_cu

    dec_sh, meta_sh = spool_post_tool_output(
        "claude", {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"output": big}},
        mode="shadow", session_id="s-dom", call_id="c-dom-sh", workspace_root=repo, spool_dir=spool_dir, now_ts=1_002.0,
    )
    assert dec_sh is None and meta_sh is not None and meta_sh["saved_bytes"] > 0

    for pay, m in (
        ({"tool_name": "Bash", "tool_response": {"output": big}}, "off"),
        ({"tool_name": "Read", "tool_response": big}, "active"),
        ({"tool_name": "Bash", "is_error": True, "tool_response": {"output": big}}, "active"),
    ):
        assert spool_post_tool_output(
            "claude", pay, mode=m, session_id="s-dom", call_id="c-noop", workspace_root=repo, spool_dir=spool_dir,
        ) == (None, None)

    record_governor_signal(
        "output_spool", HARD_INTEGRITY_FAILURE_REASONS[0], state_dir=spool_dir, harness="claude", session_id="s-dom",
    )
    assert spool_post_tool_output(
        "claude", {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": {"output": big}},
        mode="active", session_id="s-dom", call_id="c-trip", workspace_root=repo, spool_dir=spool_dir,
    ) == (None, None)
