"""Acceptance tests for locked SHA-256 spool recovery, two-phase GC tombstones, and concurrency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

import pytest

from spool.receipts import RECEIPTS_FILENAME, resolve_workspace_identity
from spool.store import (
    SPOOL_MAX_TOMBSTONES,
    SPOOL_SCHEMA_VERSION,
    gc_spools,
    grep_spool,
    inspect_spool_health,
    list_spools,
    slice_spool,
    spool_tool_output,
)


def _make_text(count: int, *, prefix: str = "line", width: int = 84) -> str:
    pad = "x" * max(1, width - len(prefix) - 8)
    return "\n".join(f"{prefix}-{idx:04d} {pad}" for idx in range(1, count + 1)) + "\n"


def _make_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    (repo / ".git").mkdir(exist_ok=True)
    return repo


def test_ttl_eviction_writes_tombstone_and_recovery_returns_spool_evicted_without_reliability_failure(
    tmp_path: Path,
) -> None:
    """Evict expired entries into bounded tombstones and mask tombstones cross-workspace."""
    repo_a = _make_repo(tmp_path, "proj_a")
    repo_b = _make_repo(tmp_path, "proj_b")
    spool_dir = tmp_path / "spool"

    res = spool_tool_output(
        _make_text(220, prefix="ttl"),
        session_id="s-ttl",
        call_id="c-ttl",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo_a,
        spool_dir=spool_dir,
        now_ts=1_000.0,
    )
    assert res is not None
    sid = res[0].spool_id

    gc_res = gc_spools(max_age_seconds=60.0, spool_dir=spool_dir, now_ts=1_120.0)
    assert gc_res["ok"] is True
    assert gc_res["removed_count"] == 1

    callbacks: list[int] = []
    sl = slice_spool(
        sid,
        workspace_root=repo_a,
        spool_dir=spool_dir,
        on_reliability_failure=lambda: callbacks.append(1),
    )
    gr = grep_spool(
        sid,
        "ttl",
        workspace_root=repo_a,
        spool_dir=spool_dir,
        on_reliability_failure=lambda: callbacks.append(1),
    )
    assert sl == {
        "ok": False,
        "error": "spool_evicted",
        "eviction_reason": "ttl_expired",
        "evicted_at": 1_120.0,
    }
    assert gr == {
        "ok": False,
        "error": "spool_evicted",
        "eviction_reason": "ttl_expired",
        "evicted_at": 1_120.0,
    }
    assert callbacks == []

    # Cross-workspace recovery masks tombstones as spool_not_found.
    cross = slice_spool(sid, workspace_root=repo_b, spool_dir=spool_dir)
    assert cross == {"ok": False, "error": "spool_not_found"}

    health = inspect_spool_health(spool_dir, now_ts=1_120.0)
    assert health["eviction_count"] == 1
    assert health["reliability_failures"] == 0
    assert health["receipts"]["integrity_failures"] == 0

    # Tombstones cap at SPOOL_MAX_TOMBSTONES (128), pruning oldest evicted_at first.
    first_sid = sid
    for idx in range(SPOOL_MAX_TOMBSTONES + 5):
        r_i = spool_tool_output(
            _make_text(220, prefix=f"cap{idx:03d}"),
            session_id="s-cap",
            call_id=f"c-cap-{idx}",
            harness="claude",
            tool_name="Bash",
            workspace_root=repo_a,
            spool_dir=spool_dir,
            now_ts=2_000.0 + idx,
        )
        assert r_i is not None
    gc_cap = gc_spools(max_age_seconds=10.0, max_entries=0, spool_dir=spool_dir, now_ts=3_000.0)
    assert gc_cap["ok"] is True
    idx_data = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert idx_data["schema_version"] == SPOOL_SCHEMA_VERSION == 2
    assert len(idx_data["tombstones"]) == SPOOL_MAX_TOMBSTONES
    assert first_sid not in idx_data["tombstones"]


def test_tampered_payload_and_bad_utf8_fail_with_integrity_mismatch_and_record_reliability_failure(
    tmp_path: Path,
) -> None:
    """Fail closed with integrity_mismatch, reliability receipt, and callback on any corruption."""
    repo = _make_repo(tmp_path)
    spool_dir = tmp_path / "spool"

    def _seed(tag: str) -> tuple[str, Path, bytes]:
        res = spool_tool_output(
            _make_text(220, prefix=tag),
            session_id="s-int",
            call_id=f"c-{tag}",
            harness="claude",
            tool_name="Bash",
            workspace_root=repo,
            spool_dir=spool_dir,
            now_ts=5_000.0,
        )
        assert res is not None
        sid = res[0].spool_id
        blob = spool_dir / f"{sid}.txt"
        return sid, blob, blob.read_bytes()

    # 1. Same-size byte tamper (SHA-256 mismatch)
    sid_same, blob_same, raw_same = _seed("same")
    flipped = bytes([raw_same[0] ^ 0x01]) + raw_same[1:]
    blob_same.write_bytes(flipped)

    # 2. Truncated blob (byte length mismatch)
    sid_trunc, blob_trunc, raw_trunc = _seed("trunc")
    blob_trunc.write_bytes(raw_trunc[:100])

    # 3. Invalid UTF-8 bytes matching exact index length & SHA-256 (strict decode guard)
    sid_utf8, blob_utf8, raw_utf8 = _seed("utf8")
    bad_utf8 = b"\xff\xfe\x80" + raw_utf8[3:]
    blob_utf8.write_bytes(bad_utf8)
    idx_file = spool_dir / "spool_index.json"
    idx_obj = json.loads(idx_file.read_text(encoding="utf-8"))
    idx_obj["entries"][sid_utf8]["content_sha256"] = hashlib.sha256(bad_utf8).hexdigest()
    idx_obj["entries"][sid_utf8]["total_bytes"] = len(bad_utf8)
    idx_file.write_text(json.dumps(idx_obj), encoding="utf-8")

    # 4. Missing active .txt blob (unlinked without GC)
    sid_miss, blob_miss, _ = _seed("miss")
    blob_miss.unlink()

    failures: list[str] = []

    def _make_cb(target_sid: str) -> Callable[[], None]:
        return lambda: failures.append(target_sid)

    expected_errors = [
        (sid_same, "integrity_mismatch"),
        (sid_trunc, "integrity_mismatch"),
        (sid_utf8, "format_error"),
        (sid_miss, "unexpectedly_missing"),
    ]
    for bad_sid, exp_err in expected_errors:
        res = slice_spool(
            bad_sid,
            workspace_root=repo,
            spool_dir=spool_dir,
            on_reliability_failure=_make_cb(bad_sid),
        )
        assert res == {"ok": False, "error": exp_err}
        assert slice_spool(
            bad_sid,
            workspace_root=repo,
            spool_dir=spool_dir,
            on_reliability_failure=_make_cb(bad_sid),
        ) == {"ok": False, "error": "spool_corrupt", "corrupt_reason": exp_err}
        assert grep_spool(bad_sid, "line", workspace_root=repo, spool_dir=spool_dir) == {
            "ok": False,
            "error": "spool_corrupt",
            "corrupt_reason": exp_err,
        }

    assert failures == [sid_same, sid_trunc, sid_utf8, sid_miss]
    rows = [
        json.loads(line)
        for line in (spool_dir / RECEIPTS_FILENAME).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    fail_rows = [r for r in rows if r["event_type"] == "spool_integrity_failure"]
    assert len(fail_rows) == 4
    assert [fr["reason"] for fr in fail_rows] == [e for _, e in expected_errors]
    for fr in fail_rows:
        assert fr["failure_kind"] == "reliability_failure"
        assert fr["line_span"] == [0, 0]
        assert fr["spool_id_referenced"] is True
        assert fr["delivery_evidence"] == "unverified"

    assert list_spools(workspace_root=repo, spool_dir=spool_dir)["count"] == 0
    health = inspect_spool_health(spool_dir)
    assert health["entry_count"] == 0
    assert health["reliability_failures"] == 4

    # GC marks missing active blobs corrupt (unexpectedly_missing), never evicting them as tombstones (INV-5).
    sid_gc_miss, blob_gc_miss, _ = _seed("gcmiss")
    blob_gc_miss.unlink()
    gc_spools(max_age_seconds=86_400.0, spool_dir=spool_dir, now_ts=5_100.0)
    idx_after_gc = json.loads(idx_file.read_text(encoding="utf-8"))
    assert idx_after_gc["entries"][sid_gc_miss]["state"] == "corrupt"
    assert idx_after_gc["entries"][sid_gc_miss]["corrupt_reason"] == "unexpectedly_missing"
    assert sid_gc_miss not in idx_after_gc["tombstones"]
    assert slice_spool(sid_gc_miss, workspace_root=repo, spool_dir=spool_dir) == {
        "ok": False,
        "error": "spool_corrupt",
        "corrupt_reason": "unexpectedly_missing",
    }

    # Legacy v1 spool_index.json without workspace_id fails closed with workspace_mismatch in workspace mode.
    legacy_dir = tmp_path / "legacy_spool"
    legacy_dir.mkdir()
    legacy_sid = "sp_0123456789ab"
    legacy_bytes = _make_text(210, prefix="v1").encode("utf-8")
    (legacy_dir / f"{legacy_sid}.txt").write_bytes(legacy_bytes)
    (legacy_dir / "spool_index.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": {
                    legacy_sid: {
                        "spool_id": legacy_sid,
                        "filename": f"{legacy_sid}.txt",
                        "session_id": "s1",
                        "call_id": "c1",
                        "harness": "claude",
                        "tool_name": "Bash",
                        "cmd_sig": "",
                        "total_lines": 210,
                        "total_bytes": len(legacy_bytes),
                        "summary_bytes": 500,
                        "saved_bytes": 10000,
                        "content_sha256": "0" * 64,
                        "created_at": 100.0,
                        "last_accessed_at": 100.0,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    assert slice_spool(legacy_sid, workspace_root=repo, spool_dir=legacy_dir) == {
        "ok": False,
        "error": "workspace_mismatch",
    }


def test_gc_crash_between_index_save_and_blob_unlink_recovers_cleanly_on_read_and_next_gc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Commit tombstones before unlink so a crash leaves stale blobs unreadable and auto-swept next GC."""
    repo = _make_repo(tmp_path)
    spool_dir = tmp_path / "spool"
    payload_text = _make_text(220, prefix="crash")

    res = spool_tool_output(
        payload_text,
        session_id="s-crash",
        call_id="c-crash",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_000.0,
    )
    assert res is not None
    sid = res[0].spool_id
    blob = spool_dir / f"{sid}.txt"
    assert blob.is_file()

    real_unlink = Path.unlink

    def _crash_on_blob(self: Path, *args: Any, **kwargs: Any) -> None:
        if self == blob:
            raise RuntimeError("simulated crash before unlink")
        real_unlink(self, *args, **kwargs)

    with monkeypatch.context() as mp:
        mp.setattr(Path, "unlink", _crash_on_blob)
        with pytest.raises(RuntimeError, match="simulated crash"):
            gc_spools(max_age_seconds=10.0, spool_dir=spool_dir, now_ts=1_100.0)

    # Stale blob still exists on disk, yet index already committed evicting tombstone in Phase 1.
    assert blob.is_file()
    idx_mid = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert idx_mid["tombstones"][sid]["state"] == "evicting"
    assert slice_spool(sid, workspace_root=repo, spool_dir=spool_dir) == {
        "ok": False,
        "error": "spool_evicted",
        "eviction_reason": "ttl_expired",
        "evicted_at": 1_100.0,
    }

    # Next GC sweeps tombstone-tracked orphan immediately regardless of mtime and transitions to evicted.
    gc_sweep = gc_spools(max_age_seconds=86_400.0, spool_dir=spool_dir, now_ts=1_105.0)
    assert gc_sweep["ok"] is True
    assert not blob.exists()
    idx_swept = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert idx_swept["tombstones"][sid]["state"] == "evicted"

    # Re-spooling identical payload never recycles evicted ID; derives new generation spool_id (INV-4).
    res_again = spool_tool_output(
        payload_text,
        session_id="s-crash",
        call_id="c-resurrect",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_200.0,
    )
    assert res_again is not None
    new_sid = res_again[0].spool_id
    assert new_sid != sid
    assert new_sid in res_again[1]
    assert slice_spool(sid, workspace_root=repo, spool_dir=spool_dir) == {
        "ok": False,
        "error": "spool_evicted",
        "eviction_reason": "ttl_expired",
        "evicted_at": 1_100.0,
    }
    ws_id, _, err = resolve_workspace_identity(repo)
    assert err is None and ws_id
    sl_ok = slice_spool(new_sid, start_line=1, limit=5, workspace_root=repo, spool_dir=spool_dir, now_ts=1_201.0)
    assert sl_ok["ok"] is True
    assert sl_ok["content"].startswith("crash-0001")
    idx = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert new_sid in idx["entries"] and idx["entries"][new_sid]["state"] == "available"
    assert idx["entries"][new_sid]["workspace_id"] == ws_id
    assert sid in idx["tombstones"] and idx["tombstones"][sid]["state"] == "evicted"


def test_concurrent_gc_and_recovery_never_return_unverified_data(tmp_path: Path) -> None:
    """Race slice/grep against aggressive GC and writes without integrity mismatch or unverified reads."""
    repo = _make_repo(tmp_path)
    spool_dir = tmp_path / "spool"
    payloads = [_make_text(220, prefix=f"conc{i:02d}") for i in range(6)]
    seeded_ids: list[str] = []
    for idx, text in enumerate(payloads):
        res = spool_tool_output(
            text,
            session_id="s-conc",
            call_id=f"c-{idx}",
            harness="claude",
            tool_name="Bash",
            workspace_root=repo,
            spool_dir=spool_dir,
            now_ts=100.0 + idx,
        )
        assert res is not None
        seeded_ids.append(res[0].spool_id)

    errors: list[str] = []

    def _worker(round_idx: int) -> None:
        target_idx = round_idx % len(seeded_ids)
        sid = seeded_ids[target_idx]
        expected_prefix = f"conc{target_idx:02d}-0001"
        mode = round_idx % 4
        if mode == 0:
            r = slice_spool(sid, start_line=1, limit=5, workspace_root=repo, spool_dir=spool_dir, now_ts=200.0 + round_idx)
            if r["ok"]:
                if not r["content"].startswith(expected_prefix):
                    errors.append(f"corrupt slice content for {sid}")
            elif r["error"] not in ("spool_evicted", "spool_not_found"):
                errors.append(f"unexpected slice error: {r}")
        elif mode == 1:
            g = grep_spool(sid, f"conc{target_idx:02d}-0010", workspace_root=repo, spool_dir=spool_dir, now_ts=200.0 + round_idx)
            if g["ok"]:
                if g["match_count"] != 1:
                    errors.append(f"unexpected grep match count: {g}")
            elif g["error"] not in ("spool_evicted", "spool_not_found"):
                errors.append(f"unexpected grep error: {g}")
        elif mode == 2:
            gc_spools(max_age_seconds=0.0, spool_dir=spool_dir, now_ts=200.0 + round_idx)
        else:
            spool_tool_output(
                payloads[target_idx],
                session_id="s-conc",
                call_id=f"c-w-{round_idx}",
                harness="claude",
                tool_name="Bash",
                workspace_root=repo,
                spool_dir=spool_dir,
                now_ts=200.0 + round_idx,
            )

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_worker, i) for i in range(40)]
        for fut in futures:
            fut.result()

    assert errors == []
    assert os.path.isfile(spool_dir / "spool_index.json")
