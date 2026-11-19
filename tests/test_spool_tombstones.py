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


def test_dedup_rejects_bit_flipped_blob_quarantines_corrupt_and_writes_fresh_generation(tmp_path: Path) -> None:
    """Bit-flipped existing blob must never be reused by dedup; quarantine corrupt and emit fresh generation (P1-01)."""
    repo = _make_repo(tmp_path)
    spool_dir = tmp_path / "spool"
    payload = _make_text(220, prefix="dedupcorrupt")
    first = spool_tool_output(
        payload,
        session_id="s-dd",
        call_id="c-dd-1",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_000.0,
    )
    assert first is not None
    sid1 = first[0].spool_id
    assert slice_spool(sid1, start_line=1, limit=2, workspace_root=repo, spool_dir=spool_dir)["ok"] is True

    # Flip one byte inside the blob with identical byte length (stale healthy index entry).
    blob1 = spool_dir / f"{sid1}.txt"
    raw = bytearray(blob1.read_bytes())
    raw[20] = ord("Z") if raw[20] != ord("Z") else ord("Y")
    blob1.write_bytes(bytes(raw))

    second = spool_tool_output(
        payload,
        session_id="s-dd",
        call_id="c-dd-2",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_010.0,
    )
    assert second is not None
    sid2 = second[0].spool_id
    assert sid2 != sid1
    assert sid2 in second[1]
    assert slice_spool(sid2, start_line=1, limit=3, workspace_root=repo, spool_dir=spool_dir)["content"].startswith(
        "dedupcorrupt-0001"
    )
    assert slice_spool(sid1, workspace_root=repo, spool_dir=spool_dir) == {
        "ok": False,
        "error": "spool_corrupt",
        "corrupt_reason": "integrity_mismatch",
    }
    idx = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert idx["entries"][sid1]["state"] == "corrupt"
    assert idx["entries"][sid2]["state"] == "available"

    # Subsequent healthy emission deduplicates onto sid2 rather than creating sid3.
    third = spool_tool_output(
        payload,
        session_id="s-dd",
        call_id="c-dd-3",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_020.0,
    )
    assert third is not None and third[0].spool_id == sid2


def test_tombstone_expiry_and_flood_bump_id_epoch_and_never_recycle_spool_id(tmp_path: Path) -> None:
    """Pruning evicted tombstones or corrupt entries increments id_epoch so base IDs never recycle (INV-4, P1-02)."""
    repo = _make_repo(tmp_path)
    spool_dir = tmp_path / "spool"
    payload = _make_text(220, prefix="recycle")

    r0 = spool_tool_output(
        payload,
        session_id="s-ep",
        call_id="c-ep-0",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_000.0,
    )
    assert r0 is not None
    sid0 = r0[0].spool_id

    # Evict and expire tombstone past 7d retention.
    gc_spools(max_age_seconds=10.0, spool_dir=spool_dir, now_ts=1_100.0)
    gc_spools(max_age_seconds=10.0, spool_dir=spool_dir, now_ts=1_100.0 + 8 * 86_400.0)
    idx_after_ttl = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert idx_after_ttl["tombstones"] == {}
    assert idx_after_ttl["id_epoch"] >= 1

    r1 = spool_tool_output(
        payload,
        session_id="s-ep",
        call_id="c-ep-1",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=2_000_000.0,
    )
    assert r1 is not None
    sid1 = r1[0].spool_id
    assert sid1 != sid0

    # Flood > SPOOL_MAX_TOMBSTONES so sid1 tombstone is pruned by count -> epoch advances again.
    gc_spools(max_age_seconds=1.0, spool_dir=spool_dir, now_ts=2_000_010.0)
    for i in range(SPOOL_MAX_TOMBSTONES + 4):
        extra = spool_tool_output(
            _make_text(220, prefix=f"epflood{i:03d}"),
            session_id="s-ep",
            call_id=f"c-fl-{i}",
            harness="claude",
            tool_name="Bash",
            workspace_root=repo,
            spool_dir=spool_dir,
            now_ts=2_000_100.0 + i,
        )
        assert extra is not None
    gc_spools(max_age_seconds=1.0, max_entries=0, spool_dir=spool_dir, now_ts=2_001_000.0)
    idx_after_flood = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert sid1 not in idx_after_flood["tombstones"]
    assert idx_after_flood["id_epoch"] > idx_after_ttl["id_epoch"]

    r2 = spool_tool_output(
        payload,
        session_id="s-ep",
        call_id="c-ep-2",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=2_001_010.0,
    )
    assert r2 is not None
    sid2 = r2[0].spool_id
    assert sid2 not in {sid0, sid1}

    # Pruning corrupt entries beyond max_corrupt_entries also increments id_epoch.
    epoch_before_corrupt = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))["id_epoch"]
    idx_corrupt = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    for i in range(70):
        csid = f"sp_{0xA00000000000 + i:012x}"
        idx_corrupt["entries"][csid] = {
            "spool_id": csid,
            "filename": f"{csid}.txt",
            "workspace_id": "ws_0123456789abcdef",
            "session_id": "s-c",
            "total_lines": 10,
            "total_bytes": 100,
            "content_sha256": "0" * 64,
            "created_at": 10.0 + i,
            "last_accessed_at": 10.0 + i,
            "corrupted_at": 20.0 + i,
            "state": "corrupt",
            "corrupt_reason": "integrity_mismatch",
        }
    (spool_dir / "spool_index.json").write_text(json.dumps(idx_corrupt), encoding="utf-8")
    gc_spools(max_age_seconds=86_400.0, spool_dir=spool_dir, now_ts=2_001_020.0)
    idx_after_c = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    assert idx_after_c["id_epoch"] > epoch_before_corrupt


def test_concurrent_gc_delayed_unlink_respects_blob_inode_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stalled GC run pausing before unlink must not delete a newly written replacement blob at the same filename."""
    import threading
    from spool import gc as spool_gc

    repo = _make_repo(tmp_path)
    spool_dir = tmp_path / "spool"
    payload = _make_text(220, prefix="concinode")
    res = spool_tool_output(
        payload,
        session_id="s-cgc",
        call_id="c-cgc-1",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_000.0,
    )
    assert res is not None
    sid = res[0].spool_id
    blob = spool_dir / f"{sid}.txt"
    real_unlink_fn = spool_gc.unlink_blob_matching_identity
    entered = threading.Event()
    release = threading.Event()

    def _delayed_identity_unlink(
        path: Path, *, expected_identity: tuple[int, int, int] | None = None, cutoff: float | None = None
    ) -> tuple[int | None, bool]:
        if path == blob and not entered.is_set():
            entered.set()
            release.wait(timeout=5.0)
        return real_unlink_fn(path, expected_identity=expected_identity, cutoff=cutoff)

    results: list[dict[str, Any]] = []
    with monkeypatch.context() as mp:
        mp.setattr(spool_gc, "unlink_blob_matching_identity", _delayed_identity_unlink)
        t1 = threading.Thread(
            target=lambda: results.append(gc_spools(max_age_seconds=10.0, spool_dir=spool_dir, now_ts=1_100.0))
        )
        t1.start()
        assert entered.wait(timeout=5.0)
        # While t1 pauses between eviction capture and blob unlink, another actor replaces the blob with a new inode.
        blob.unlink()
        fresh = spool_dir / ".replacement.tmp"
        fresh.write_bytes(b"fresh-generation-inode")
        os.replace(str(fresh), str(blob))
        new_st = os.lstat(str(blob))
        new_ino = (int(new_st.st_dev), int(new_st.st_ino))
        release.set()
        t1.join(timeout=5.0)

    assert len(results) == 1 and results[0]["ok"] is True
    assert blob.is_file()
    assert (int(os.lstat(str(blob)).st_dev), int(os.lstat(str(blob)).st_ino)) == new_ino
    assert blob.read_bytes() == b"fresh-generation-inode"
    assert results[0]["removed_count"] == 0 and results[0]["removed_bytes"] == 0
    # Zero-inode fallback also refuses mismatched mtime_ns and removes only when mtime_ns matches.
    assert spool_gc.unlink_blob_matching_identity(blob, expected_identity=(0, 0, int(new_st.st_mtime_ns) + 1)) == (None, False)
    assert blob.is_file()


def test_gc_orphan_unlink_runs_outside_spool_lock_and_missing_evicting_counts_zero_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Orphan blobs are staged via rename under lock and unlinked lock-free; missing evicting files count 0 bytes (P2-01)."""
    repo = _make_repo(tmp_path)
    spool_dir = tmp_path / "spool"
    seed = spool_tool_output(
        _make_text(220, prefix="live"),
        session_id="s-orp",
        call_id="c-orp-1",
        harness="claude",
        tool_name="Bash",
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=10_000.0,
    )
    assert seed is not None

    orphan = spool_dir / "sp_deadbeefcafe.txt"
    orphan.write_bytes(b"orphan-payload-data\n" * 10)
    orphan_size = orphan.stat().st_size
    os.utime(orphan, (100.0, 100.0))

    unlink_checks: list[tuple[str, bool]] = []
    real_unlink = Path.unlink

    def _spy_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
        if self.parent == spool_dir and (self.name.startswith(".orphan.") or self == orphan):
            lock_free = True
            lp = spool_dir / "spool_index.lock"
            if os.name != "nt" and lp.exists():
                import fcntl

                with open(lp, "rb") as fh:
                    try:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                    except BlockingIOError:
                        lock_free = False
            unlink_checks.append((self.name, lock_free))
        real_unlink(self, *args, **kwargs)

    with monkeypatch.context() as mp:
        mp.setattr(Path, "unlink", _spy_unlink)
        gc_res = gc_spools(max_age_seconds=100.0, spool_dir=spool_dir, now_ts=10_010.0)

    assert gc_res["ok"] is True
    assert gc_res["removed_count"] == 1
    assert gc_res["removed_bytes"] == orphan_size
    assert not orphan.exists()
    assert len(unlink_checks) == 1
    assert unlink_checks[0][0].startswith(".orphan.")
    assert unlink_checks[0][1] is True

    # Missing file on evicting tombstone completes transition to evicted with 0 removed count/bytes.
    idx = json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))
    missing_sid = "sp_111122223333"
    idx["tombstones"][missing_sid] = {
        "spool_id": missing_sid,
        "state": "evicting",
        "reason": "ttl_expired",
        "evicted_at": 9_000.0,
        "workspace_id": "ws_0123456789abcdef",
        "session_id": "s-orp",
        "total_bytes": 54321,
    }
    (spool_dir / "spool_index.json").write_text(json.dumps(idx), encoding="utf-8")
    gc_miss = gc_spools(max_age_seconds=86_400.0, spool_dir=spool_dir, now_ts=10_020.0)
    assert gc_miss["ok"] is True
    assert gc_miss["removed_count"] == 0 and gc_miss["removed_bytes"] == 0
    assert json.loads((spool_dir / "spool_index.json").read_text(encoding="utf-8"))["tombstones"][missing_sid]["state"] == "evicted"
