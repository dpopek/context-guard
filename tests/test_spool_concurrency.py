"""Concurrency, non-blocking I/O, UTF-8/size guard, and failure-mode tests for output spooling (Groups 1, 2, 3, 5)."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from typing import Any

import pytest

from hooks import config
from hooks.harness_adapter import format_post_tool_spool_response
from hooks.post_tool_use import handle_post_tool_use
from spool import store as spool_store
from spool.receipts import (
    RECEIPTS_FILENAME,
    RECEIPTS_KEEP_ROWS,
    RECEIPTS_MAX_BYTES,
    append_receipt,
    build_receipt,
    load_receipt_rows,
    summarize_spool_lifecycle,
)
from spool.store import (
    SPOOL_MAX_TOMBSTONES,
    gc_spools,
    grep_spool,
    list_spools,
    slice_spool,
    spool_post_tool_output,
    spool_tool_output,
)


def _build_post_tool_spool_response(
    harness: str, payload: dict[str, Any], **kwargs: Any
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    decision, meta = spool_post_tool_output(harness, payload, **kwargs)
    return format_post_tool_spool_response(harness, decision), meta


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    (repo / ".git").mkdir(exist_ok=True)
    return repo


def _lines_text(count: int, *, prefix: str = "row", width: int = 84) -> str:
    pad = "x" * max(1, width - len(prefix) - 8)
    return "\n".join(f"{prefix}-{idx:04d} {pad}" for idx in range(1, count + 1)) + "\n"


def test_group1_utf8_surrogate_cp1250_max_entry_bytes_and_multibyte_boundaries(
    isolated_user_env: Path, tmp_path: Path
) -> None:
    """Group 1: Reject invalid UTF-8 bytes, lone surrogates, and >max_spool_entry_bytes before spooling."""
    repo = _repo(tmp_path, "g1")
    spool_dir = tmp_path / "spool"

    cp1250_bytes = b"B\xb3\xb9d \x9c\xe6\xbf\n" * 2000
    assert spool_tool_output(
        cp1250_bytes,
        session_id="s-g1",
        call_id="c-cp",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
    ) is None
    for mode in ("active", "shadow"):
        assert _build_post_tool_spool_response(
            "claude",
            {"tool_name": "Bash", "tool_input": {"command": "cmd"}, "tool_response": cp1250_bytes, "cwd": str(repo)},
            mode=mode,
            session_id="s-g1",
            call_id="c-cp-hook",
            spool_dir=spool_dir,
        ) == ({}, None)

    surrogate_text = "\ud800" + _lines_text(220, prefix="sur")
    assert spool_tool_output(
        surrogate_text,
        session_id="s-g1",
        call_id="c-sur",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
    ) is None
    for mode in ("active", "shadow"):
        assert _build_post_tool_spool_response(
            "claude",
            {"tool_name": "Bash", "tool_input": {"command": "cmd"}, "tool_response": surrogate_text, "cwd": str(repo)},
            mode=mode,
            session_id="s-g1",
            call_id="c-sur-hook",
            spool_dir=spool_dir,
        ) == ({}, None)
    assert not spool_dir.exists()

    # Exact max_spool_entry_bytes boundary (limit vs limit + 1) via explicit arg and config.json
    base_bytes = _lines_text(220, prefix="lim").encode("utf-8")
    limit = len(base_bytes)
    over_bytes = base_bytes + b"Z"

    ok_res = spool_tool_output(
        base_bytes,
        session_id="s-g1",
        call_id="c-lim-ok",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        max_spool_entry_bytes=limit,
        now_ts=1_000.0,
    )
    assert ok_res is not None
    assert spool_tool_output(
        over_bytes,
        session_id="s-g1",
        call_id="c-lim-over",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        max_spool_entry_bytes=limit,
        now_ts=1_001.0,
    ) is None

    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"spool": {"isolation": "workspace", "max_spool_entry_bytes": limit}}), encoding="utf-8")
    config.clear_config_cache()
    _, sh_ok = _build_post_tool_spool_response(
        "claude",
        {"tool_name": "Bash", "tool_input": {"command": "cmd"}, "tool_response": base_bytes, "cwd": str(repo)},
        mode="shadow",
        session_id="s-g1",
        call_id="c-sh-ok",
        spool_dir=spool_dir,
    )
    assert sh_ok is not None and sh_ok["total_bytes"] == limit
    assert _build_post_tool_spool_response(
        "claude",
        {"tool_name": "Bash", "tool_input": {"command": "cmd"}, "tool_response": over_bytes, "cwd": str(repo)},
        mode="shadow",
        session_id="s-g1",
        call_id="c-sh-over",
        spool_dir=spool_dir,
    ) == ({}, None)
    assert _build_post_tool_spool_response(
        "claude",
        {"tool_name": "Bash", "tool_input": {"command": "cmd"}, "tool_response": over_bytes, "cwd": str(repo)},
        mode="active",
        session_id="s-g1",
        call_id="c-act-over",
        spool_dir=spool_dir,
    ) == ({}, None)

    # Multi-byte UTF-8 slice boundaries and half-open [start, end) byte_span (reset config limit first)
    cfg_path.write_text(json.dumps({"spool": {"isolation": "workspace"}}), encoding="utf-8")
    config.clear_config_cache()
    mb_lines = [f"żółć€🚀-{idx:04d}-" + ("ą" * 40) for idx in range(1, 221)]
    mb_text = "\n".join(mb_lines) + "\n"
    mb_res = spool_tool_output(
        mb_text,
        session_id="s-g1",
        call_id="c-mb",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_010.0,
    )
    assert mb_res is not None
    mb_sid = mb_res[0].spool_id
    sl = slice_spool(mb_sid, start_line=10, limit=3, workspace_root=repo, spool_dir=spool_dir, now_ts=1_011.0)
    assert sl["ok"] is True and sl["content"] == "\n".join(mb_lines[9:12])
    gr = grep_spool(mb_sid, "żółć€🚀-0100", workspace_root=repo, spool_dir=spool_dir, now_ts=1_012.0)
    assert gr["ok"] is True and gr["match_count"] == 1
    rows = [json.loads(ln) for ln in (spool_dir / RECEIPTS_FILENAME).read_text(encoding="utf-8").splitlines() if ln.strip()]
    sl_rcpt = [r for r in rows if r["event_type"] == "spool_recovery" and r["spool_id"] == mb_sid][0]
    exp_start = sum(len(mb_lines[k].encode("utf-8")) + 1 for k in range(9))
    exp_end = exp_start + len("\n".join(mb_lines[9:12]).encode("utf-8"))
    assert sl_rcpt["line_span"] == [9, 12]
    assert sl_rcpt["byte_span"] == [exp_start, exp_end]


def test_group2_reader_gc_race_and_windows_permission_error_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Group 2: In-flight reader finishes after concurrent GC evicts; PermissionError keeps evicting until retry."""
    repo = _repo(tmp_path, "g2")
    spool_dir = tmp_path / "spool"
    payload = _lines_text(220, prefix="race")
    payload_bytes = payload.encode("utf-8")

    seeded = spool_tool_output(
        payload,
        session_id="s-g2",
        call_id="c-g2",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_000.0,
    )
    assert seeded is not None
    sid = seeded[0].spool_id
    blob = spool_dir / f"{sid}.txt"

    reader_past_lock = threading.Event()
    allow_reader_finish = threading.Event()
    real_sha256 = hashlib.sha256
    reader_result: dict[str, Any] = {}

    def _barrier_sha256(data: bytes = b"") -> Any:
        if len(data) == len(payload_bytes) and not reader_past_lock.is_set():
            reader_past_lock.set()
            assert allow_reader_finish.wait(timeout=5.0)
        return real_sha256(data)

    def _run_reader() -> None:
        reader_result["res"] = slice_spool(
            sid, start_line=1, limit=4, workspace_root=repo, spool_dir=spool_dir, now_ts=1_050.0
        )

    with monkeypatch.context() as mp:
        mp.setattr(hashlib, "sha256", _barrier_sha256)
        t_reader = threading.Thread(target=_run_reader)
        t_reader.start()
        assert reader_past_lock.wait(timeout=5.0)

        # Concurrent GC does NOT block on reader and transitions blob -> evicting -> evicted.
        gc_res = gc_spools(max_age_seconds=0.0, spool_dir=spool_dir, now_ts=1_200.0)
        assert gc_res["ok"] is True and gc_res["removed_count"] == 1
        assert not blob.exists()
        assert slice_spool(sid, workspace_root=repo, spool_dir=spool_dir) == {
            "ok": False,
            "error": "spool_evicted",
            "eviction_reason": "ttl_expired",
            "evicted_at": 1_200.0,
        }

        allow_reader_finish.set()
        t_reader.join(timeout=5.0)

    assert not t_reader.is_alive()
    assert reader_result["res"]["ok"] is True
    assert reader_result["res"]["content"].startswith("race-0001")
    idx_after = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert sid not in idx_after["entries"]
    assert idx_after["tombstones"][sid]["state"] == "evicted"

    # Windows PermissionError simulation: keep state="evicting" without pruning until retry unlinks blob.
    win_res = spool_tool_output(
        _lines_text(220, prefix="winlock"),
        session_id="s-win",
        call_id="c-win",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=2_000.0,
    )
    assert win_res is not None
    win_sid = win_res[0].spool_id
    win_blob = spool_dir / f"{win_sid}.txt"
    real_unlink = Path.unlink

    def _perm_error_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
        if self == win_blob:
            raise PermissionError(errno.EACCES, "file open in reader")
        real_unlink(self, *args, **kwargs)

    with monkeypatch.context() as mp:
        mp.setattr(Path, "unlink", _perm_error_unlink)
        gc_win = gc_spools(max_age_seconds=10.0, spool_dir=spool_dir, now_ts=2_100.0)
        assert gc_win["ok"] is True
        assert win_blob.is_file()
        idx_win = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
        assert idx_win["tombstones"][win_sid]["state"] == "evicting"
        assert slice_spool(win_sid, workspace_root=repo, spool_dir=spool_dir) == {
            "ok": False,
            "error": "spool_evicted",
            "eviction_reason": "ttl_expired",
            "evicted_at": 2_100.0,
        }

        # Flood > SPOOL_MAX_TOMBSTONES evicted entries; "evicting" tombstone must NEVER be pruned before unlink.
        for i in range(SPOOL_MAX_TOMBSTONES + 3):
            extra = spool_tool_output(
                _lines_text(220, prefix=f"flood{i:03d}"),
                session_id="s-flood",
                call_id=f"c-fl-{i}",
                harness="claude",
                tool_name="Bash",
                workspace_root=repo,
                spool_dir=spool_dir,
                now_ts=2_200.0 + i,
            )
            assert extra is not None
        gc_spools(max_age_seconds=5.0, max_entries=0, spool_dir=spool_dir, now_ts=2_500.0)
        idx_flood = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
        assert win_sid in idx_flood["tombstones"]
        assert idx_flood["tombstones"][win_sid]["state"] == "evicting"

    # Retry once handle lock clears -> unlinks blob and transitions to evicted within SPOOL_MAX_TOMBSTONES.
    gc_retry = gc_spools(max_age_seconds=86_400.0, spool_dir=spool_dir, now_ts=2_600.0)
    assert gc_retry["ok"] is True
    assert not win_blob.exists()
    idx_final = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert idx_final["tombstones"][win_sid]["state"] == "evicted"
    assert len(idx_final["tombstones"]) <= SPOOL_MAX_TOMBSTONES


def test_group3_enospc_and_manifest_write_failure_force_passthrough(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Group 3: ENOSPC on temp write or manifest commit forces passthrough with zero summary or leaked blobs."""
    repo = _repo(tmp_path, "g3")
    spool_dir = tmp_path / "spool"
    payload = _lines_text(220, prefix="enospc")
    real_open = os.open

    def _enospc_temp_open(path: str, flags: int, *args: Any, **kwargs: Any) -> int:
        if path.endswith(".spool"):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as mp:
        mp.setattr(os, "open", _enospc_temp_open)
        assert spool_tool_output(
            payload, session_id="s-g3", call_id="c-tmp", harness="claude", tool_name="Bash",
            workspace_root=repo, spool_dir=spool_dir,
        ) is None
        assert _build_post_tool_spool_response(
            "claude",
            {"tool_name": "Bash", "tool_input": {"command": "cmd"}, "tool_response": payload, "cwd": str(repo)},
            mode="active",
            session_id="s-g3",
            call_id="c-tmp-hook",
            spool_dir=spool_dir,
        ) == ({}, None)
    assert not any(spool_dir.glob("sp_*.txt")) if spool_dir.exists() else True
    assert not (spool_dir / RECEIPTS_FILENAME).exists()

    real_atomic_write = spool_store.atomic_write_bytes

    def _fail_manifest_write(target: Path, data: bytes) -> None:
        if target.name == "spool_index.json":
            raise OSError(errno.ENOSPC, "manifest write failed")
        real_atomic_write(target, data)

    with monkeypatch.context() as mp:
        mp.setattr(spool_store, "atomic_write_bytes", _fail_manifest_write)
        assert _build_post_tool_spool_response(
            "claude",
            {"tool_name": "Bash", "tool_input": {"command": "cmd"}, "tool_response": payload, "cwd": str(repo)},
            mode="active",
            session_id="s-g3",
            call_id="c-idx-hook",
            spool_dir=spool_dir,
        ) == ({}, None)
    assert list(spool_dir.glob("*.spool")) == []
    assert list(spool_dir.glob("sp_*.txt")) == []
    assert not (spool_dir / RECEIPTS_FILENAME).exists()


def test_group5_slow_sha_on_large_spool_does_not_block_list_or_small_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Group 5: Slow SHA-256 on large spool executes outside _spool_lock so list/small recovery proceed immediately."""
    repo = _repo(tmp_path, "g5")
    spool_dir = tmp_path / "spool"
    big_text = _lines_text(700, prefix="big")
    small_text = _lines_text(210, prefix="small")
    big_bytes = big_text.encode("utf-8")

    res_big = spool_tool_output(
        big_text, session_id="s-g5", call_id="c-big", harness="claude", tool_name="Bash",
        workspace_root=repo, spool_dir=spool_dir, now_ts=1_000.0,
    )
    res_small = spool_tool_output(
        small_text, session_id="s-g5", call_id="c-small", harness="claude", tool_name="Bash",
        workspace_root=repo, spool_dir=spool_dir, now_ts=1_001.0,
    )
    assert res_big is not None and res_small is not None
    sid_big, sid_small = res_big[0].spool_id, res_small[0].spool_id

    big_hash_started = threading.Event()
    big_hash_release = threading.Event()
    real_sha256 = hashlib.sha256
    big_out: dict[str, Any] = {}

    def _slow_big_sha256(data: bytes = b"") -> Any:
        if len(data) == len(big_bytes) and not big_hash_started.is_set():
            big_hash_started.set()
            assert big_hash_release.wait(timeout=5.0)
        return real_sha256(data)

    def _read_big() -> None:
        big_out["res"] = slice_spool(
            sid_big, start_line=1, limit=5, workspace_root=repo, spool_dir=spool_dir, now_ts=1_010.0
        )

    with monkeypatch.context() as mp:
        mp.setattr(hashlib, "sha256", _slow_big_sha256)
        t_big = threading.Thread(target=_read_big)
        t_big.start()
        assert big_hash_started.wait(timeout=5.0)

        t_start = time.monotonic()
        listed = list_spools(workspace_root=repo, spool_dir=spool_dir)
        small_slice = slice_spool(
            sid_small, start_line=1, limit=3, workspace_root=repo, spool_dir=spool_dir, now_ts=1_011.0
        )
        new_write = spool_tool_output(
            _lines_text(215, prefix="concwrite"),
            session_id="s-g5",
            call_id="c-w",
            harness="claude",
            tool_name="Bash",
            workspace_root=repo,
            spool_dir=spool_dir,
            now_ts=1_012.0,
        )
        elapsed = time.monotonic() - t_start

        assert listed["ok"] is True and listed["count"] == 2
        assert small_slice["ok"] is True and small_slice["content"].startswith("small-0001")
        assert new_write is not None
        assert elapsed < 2.0

        big_hash_release.set()
        t_big.join(timeout=5.0)

    assert not t_big.is_alive()
    assert big_out["res"]["ok"] is True and big_out["res"]["content"].startswith("big-0001")


def test_post_tool_use_turn_correlation_and_hook_duration_telemetry(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify PostToolUse records turn_correlation (harness_native/transcript_derived/unobserved) and hook_duration_ms."""
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "active"}}), encoding="utf-8")
    config.clear_config_cache()
    spool_dir = tmp_path / "spool"
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))
    repo = _repo(tmp_path, "proj_tc")

    # 1. harness_native via stepIdx
    sd1 = tmp_path / "sd1"
    sd1.mkdir()
    handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "session_id": "s-tc", "tool_use_id": "c-tc-1",
            "stepIdx": 4, "tool_name": "Bash", "tool_input": {"command": "pytest"},
            "tool_response": _lines_text(220, prefix="tc1"), "cwd": str(repo),
        },
        state_dir=str(sd1),
    )

    # 2. harness_native via turnId
    handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "session_id": "s-tc", "tool_use_id": "c-tc-2",
            "turnId": "turn-native-9", "tool_name": "Bash", "tool_input": {"command": "pytest"},
            "tool_response": _lines_text(220, prefix="tc2"), "cwd": str(repo),
        },
        state_dir=str(sd1),
    )

    # 3. transcript_derived via state snapshot last_step_index
    sd2 = tmp_path / "sd2"
    sd2.mkdir()
    (sd2 / ".context_guard_state.json").write_text(
        json.dumps({"files": {}, "read_ledger_schema": 2, "last_step_index": 2}),
        encoding="utf-8",
    )
    handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "session_id": "s-tc", "tool_use_id": "c-tc-3",
            "tool_name": "Bash", "tool_input": {"command": "pytest"},
            "tool_response": _lines_text(220, prefix="tc3"), "cwd": str(repo),
        },
        state_dir=str(sd2),
    )

    # 3b. Missing payload transcript_path must fall back to unobserved
    handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "session_id": "s-tc", "tool_use_id": "c-tc-3b",
            "transcript_path": str(tmp_path / "missing_tr.jsonl"),
            "tool_name": "Bash", "tool_input": {"command": "pytest"},
            "tool_response": _lines_text(220, prefix="tc3b"), "cwd": str(repo),
        },
        state_dir=str(tmp_path / "sd3b"),
    )

    # 3c. Existing regular JSONL transcript_path yields transcript_derived
    tr_real = tmp_path / "tr_real.jsonl"
    tr_real.write_text(json.dumps({"step_index": 7, "turn_id": "turn-7"}) + "\n", encoding="utf-8")
    handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "session_id": "s-tc", "tool_use_id": "c-tc-3c",
            "transcript_path": str(tr_real),
            "tool_name": "Bash", "tool_input": {"command": "pytest"},
            "tool_response": _lines_text(220, prefix="tc3c"), "cwd": str(repo),
        },
        state_dir=str(tmp_path / "sd3c"),
    )

    # 4. unobserved
    sd3 = tmp_path / "sd3"
    sd3.mkdir()
    handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "session_id": "s-tc", "tool_use_id": "c-tc-4",
            "tool_name": "Bash", "tool_input": {"command": "pytest"},
            "tool_response": _lines_text(220, prefix="tc4"), "cwd": str(repo),
        },
        state_dir=str(sd3),
    )

    rows = [json.loads(ln) for ln in (spool_dir / RECEIPTS_FILENAME).read_text(encoding="utf-8").splitlines() if ln.strip()]
    by_call = {r["call_id"]: r for r in rows}
    assert by_call["c-tc-1"]["turn_correlation"] == "harness_native" and by_call["c-tc-1"]["turn_key"] == "s-tc:step:4"
    assert by_call["c-tc-2"]["turn_correlation"] == "harness_native" and by_call["c-tc-2"]["turn_key"] == "s-tc:turn:turn-native-9"
    assert by_call["c-tc-3"]["turn_correlation"] == "transcript_derived" and by_call["c-tc-3"]["turn_key"] == "s-tc:transcript_step:2"
    assert by_call["c-tc-3b"]["turn_correlation"] == "unobserved" and by_call["c-tc-3b"]["turn_key"] == "s-tc:step:1"
    assert by_call["c-tc-3c"]["turn_correlation"] == "transcript_derived" and by_call["c-tc-3c"]["turn_key"] == "s-tc:transcript:s7"
    assert by_call["c-tc-4"]["turn_correlation"] == "unobserved" and by_call["c-tc-4"]["turn_key"] == "s-tc:step:1"
    for cid in ("c-tc-1", "c-tc-2", "c-tc-3", "c-tc-3b", "c-tc-3c", "c-tc-4"):
        dur = by_call[cid]["hook_duration_ms"]
        assert isinstance(dur, (int, float)) and dur >= 0.0

    sid_1 = by_call["c-tc-1"]["spool_id"]
    assert slice_spool(
        sid_1, start_line=1, limit=5, workspace_root=repo, spool_dir=spool_dir,
        turn_key="s-tc:step:5", turn_correlation="harness_native", call_id="c-rec-1",
    )["ok"] is True
    life = summarize_spool_lifecycle(spool_dir / RECEIPTS_FILENAME, spool_id=sid_1)
    assert life["turn_correlation_status"] == "observed"
    assert life["recovery_model_turns"] == 1


def test_append_receipt_single_pass_rotation_and_dedup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rcpt_path = tmp_path / "spool" / RECEIPTS_FILENAME
    rcpt_path.parent.mkdir(parents=True, exist_ok=True)
    seed_count = RECEIPTS_KEEP_ROWS + 14
    pad = "x" * 2048
    seed_lines = [
        json.dumps(
            dict(
                build_receipt(
                    event_type="spool_created",
                    harness="claude",
                    session_id="s-rot",
                    workspace_id="ws-rot",
                    turn_key=f"turn-{i}",
                    call_id=f"c-rot-{i}",
                    spool_id=f"sp-rot-{i:04d}",
                    line_span=(1, 10),
                    byte_span=(0, 5000),
                    delivery_evidence="hook_output",
                    spool_id_referenced=True,
                    event_id=f"ev-rot-{i}",
                    reason=pad,
                )
            ),
            separators=(",", ":"),
            sort_keys=True,
        )
        for i in range(seed_count)
    ]
    rcpt_path.write_text("\n".join(seed_lines) + "\n", encoding="utf-8")
    assert rcpt_path.stat().st_size > RECEIPTS_MAX_BYTES

    orig_loads = json.loads
    parse_calls = 0

    def counting_loads(*args: Any, **kwargs: Any) -> Any:
        nonlocal parse_calls
        parse_calls += 1
        return orig_loads(*args, **kwargs)

    monkeypatch.setattr(json, "loads", counting_loads)
    dup_row = build_receipt(
        event_type="spool_created",
        harness="claude",
        session_id="s-rot",
        workspace_id="ws-rot",
        turn_key="turn-0",
        call_id="c-rot-0",
        spool_id="sp-rot-0000",
        line_span=(1, 10),
        byte_span=(0, 5000),
        delivery_evidence="hook_output",
        spool_id_referenced=True,
        event_id="ev-rot-0",
    )
    assert append_receipt(dup_row, receipts_path=rcpt_path) is True
    assert parse_calls == seed_count
    assert len(rcpt_path.read_text(encoding="utf-8").splitlines()) == seed_count

    parse_calls = 0
    fresh_row = build_receipt(
        event_type="spool_created",
        harness="claude",
        session_id="s-rot",
        workspace_id="ws-rot",
        turn_key="turn-new",
        call_id="c-rot-new",
        spool_id="sp-rot-new",
        line_span=(1, 10),
        byte_span=(0, 5000),
        delivery_evidence="hook_output",
        spool_id_referenced=True,
        event_id="ev-rot-new",
    )
    assert append_receipt(fresh_row, receipts_path=rcpt_path) is True
    assert parse_calls == seed_count
    after = [orig_loads(ln) for ln in rcpt_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert after[0]["_meta"] == "receipts_rotation"
    assert after[0]["dropped_rows"] == 15 and after[0]["retained_rows"] == RECEIPTS_KEEP_ROWS
    kept = [r for r in after if r.get("_meta") != "receipts_rotation"]
    assert len(kept) == RECEIPTS_KEEP_ROWS
    assert len(load_receipt_rows(rcpt_path)) == RECEIPTS_KEEP_ROWS
    assert kept[-1]["event_id"] == "ev-rot-new"


def test_slice_spool_warns_when_index_update_hits_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path, "warn")
    spool_dir = tmp_path / "spool"
    big = "".join(f"warn-line-{i:04d} payload padding to pass threshold\n" for i in range(300))
    res = spool_tool_output(
        big,
        session_id="s-warn",
        call_id="c-warn-1",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_000.0,
    )
    assert res is not None
    contract, _summary = res
    sid = contract.spool_id

    warnings: list[str] = []
    orig_atomic = spool_store.atomic_write_bytes

    def fail_index_write(target: Path, data: bytes, *, prefix: str = ".tmp.") -> None:
        if target.name == "spool_index.json":
            raise OSError("index locked")
        orig_atomic(target, data, prefix=prefix)

    monkeypatch.setattr(spool_store, "atomic_write_bytes", fail_index_write)
    monkeypatch.setattr(spool_store, "warn", warnings.append)

    ok_slice = slice_spool(sid, start_line=1, limit=5, workspace_root=repo, spool_dir=spool_dir, now_ts=1_010.0)
    assert ok_slice["ok"] is True
    assert any(sid in w and "OSError" in w for w in warnings)

    warnings.clear()
    (spool_dir / f"{sid}.txt").write_bytes(b"corrupted blob content\n")
    bad_slice = slice_spool(sid, start_line=1, limit=5, workspace_root=repo, spool_dir=spool_dir, now_ts=1_020.0)
    assert bad_slice == {"ok": False, "error": "integrity_mismatch"}
    assert any(sid in w and "OSError" in w for w in warnings)
