"""Blob integrity pre-verification, generation/inode-safe GC unlinking, and lock-free orphan cleanup."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Mapping, Sequence
import uuid

from core.platform_io import check_unsafe_link
from spool.classifier import entry_scope_error, prune_evicted_tombstones

_BLOB_NAME_RE = re.compile(r"^(sp_[0-9a-f]{12})\.txt$")
if sys.platform == "win32":
    _O_FLAGS = os.O_BINARY
else:
    _O_FLAGS = os.O_NOFOLLOW


@dataclass(frozen=True)
class DedupQuery:
    """Scope and content fingerprint for deduplication candidate matching."""

    mode: str
    ws_id: str
    eff_sess: str
    canon_root: str
    sha_hex: str
    exp_bytes: int


@dataclass(frozen=True)
class GcPostLockOptions:
    """Configuration and index callbacks for lock-minimized post-eviction GC."""

    cutoff: float
    now_ts: float
    tombstone_max_age: float
    max_tombstones: int
    spool_lock: Callable[[Path], Any]
    open_index: Callable[[Path], dict[str, Any]]
    save_index: Callable[[Path, dict[str, Any]], None]


def safe_unlink(path: Path) -> None:
    """Best-effort unlink ignoring missing files or OS errors."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def probe_blob_identity(blob_path: Path) -> tuple[int, int, int] | None:
    """Return `(st_dev, st_ino, st_mtime_ns)` for a regular non-symlink blob, else None."""
    if check_unsafe_link(blob_path):
        return None
    try:
        st = os.lstat(str(blob_path))
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    return (int(st.st_dev), int(st.st_ino), int(st.st_mtime_ns))


def is_dedup_entry_match(ent: Any, query: DedupQuery) -> bool:
    """Return True when an index entry is available, matches content digest/size, and satisfies caller scope."""
    return (
        isinstance(ent, Mapping)
        and ent.get("state", "available") == "available"
        and ent.get("content_sha256") == query.sha_hex
        and ent.get("total_bytes") == query.exp_bytes
        and entry_scope_error(ent, query.mode, query.ws_id, query.eff_sess, caller_canon_root=query.canon_root) is None
    )


def find_dedup_candidate(
    entries: Mapping[str, Mapping[str, Any]],
    base_sid: str,
    query: DedupQuery,
) -> str | None:
    """Return healthy scope-matched deduplication candidate `spool_id`, preferring `base_sid` then newest match."""
    if base_sid in entries and is_dedup_entry_match(entries[base_sid], query):
        return base_sid
    cands = [sid for sid, ent in entries.items() if is_dedup_entry_match(ent, query)]
    if not cands:
        return None
    return max(cands, key=lambda sid: (float(entries[sid].get("created_at") or 0.0), sid))


def _verify_dedup_attempt(
    blob_path: Path,
    exp_bytes: int,
    exp_sha: str,
) -> tuple[bool, tuple[tuple[int, int, int, int] | None, str | None, tuple[int, int, int, int] | None]]:
    if check_unsafe_link(blob_path):
        return True, (None, "unsafe_path", None)
    try:
        l_st = os.lstat(str(blob_path))
    except FileNotFoundError:
        return True, (None, "unexpectedly_missing", None)
    except OSError:
        return True, (None, "io_error", None)
    if not stat.S_ISREG(l_st.st_mode):
        return True, (None, "unsafe_path", None)
    obs_id = (int(l_st.st_dev), int(l_st.st_ino), int(l_st.st_size), int(l_st.st_mtime_ns))
    try:
        raw_fd = os.open(str(blob_path), os.O_RDONLY | _O_FLAGS)
    except FileNotFoundError:
        return True, (None, "unexpectedly_missing", None)
    except OSError as exc:
        reason = "unsafe_path" if exc.errno in (errno.ELOOP, errno.EMLINK) else "io_error"
        return True, (None, reason, obs_id)
    try:
        fh = os.fdopen(raw_fd, "rb")
    except BaseException:
        os.close(raw_fd)
        raise
    try:
        with fh:
            f_st = os.fstat(fh.fileno())
            if not stat.S_ISREG(f_st.st_mode):
                return True, (None, "unsafe_path", obs_id)
            if (l_st.st_ino != 0 or f_st.st_ino != 0) and (f_st.st_dev, f_st.st_ino) != (l_st.st_dev, l_st.st_ino):
                return False, (None, None, None)
            f_id = (int(f_st.st_dev), int(f_st.st_ino), int(f_st.st_size), int(f_st.st_mtime_ns))
            if int(f_st.st_size) != exp_bytes:
                return True, (None, "integrity_mismatch", f_id)
            raw = fh.read(exp_bytes + 1)
    except OSError:
        return True, (None, "io_error", obs_id)
    if len(raw) != exp_bytes or hashlib.sha256(raw).hexdigest() != exp_sha:
        return True, (None, "integrity_mismatch", f_id)
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return True, (None, "format_error", f_id)
    return True, (f_id, None, f_id)


def verify_existing_blob_for_dedup(
    blob_path: Path,
    *,
    exp_bytes: int,
    exp_sha: str,
) -> tuple[tuple[int, int, int, int] | None, str | None, tuple[int, int, int, int] | None]:
    """Verify candidate dedup blob outside the lock, returning `(verified_id, fail_reason, observed_id)`."""
    for _ in range(3):
        done, result = _verify_dedup_attempt(blob_path, exp_bytes, exp_sha)
        if done:
            return result
    return None, "unsafe_path", None


def matches_stat_identity(blob_path: Path, expected: tuple[int, int, int, int]) -> bool:
    """Return True when `blob_path` is still a regular non-symlink matching `(dev, ino, size, mtime_ns)`."""
    if check_unsafe_link(blob_path):
        return False
    try:
        st = os.lstat(str(blob_path))
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    return (int(st.st_dev), int(st.st_ino), int(st.st_size), int(st.st_mtime_ns)) == expected


def _blob_identity_matches(l_st: os.stat_result, expected_identity: tuple[int, int, int]) -> bool:
    exp_dev, exp_ino, exp_mtime_ns = expected_identity
    if int(l_st.st_mtime_ns) != exp_mtime_ns:
        return False
    if (exp_dev, exp_ino) != (0, 0) and (int(l_st.st_dev), int(l_st.st_ino)) != (0, 0):
        return (int(l_st.st_dev), int(l_st.st_ino)) == (exp_dev, exp_ino)
    return True


def unlink_blob_matching_identity(
    path: Path,
    *,
    expected_identity: tuple[int, int, int] | None = None,
    cutoff: float | None = None,
) -> tuple[int | None, bool]:
    """Unlink regular non-symlink blob only if age cutoff and captured `(dev, ino, mtime_ns)` still match."""
    try:
        if check_unsafe_link(path):
            return None, False
        l_st = os.lstat(str(path))
        if not stat.S_ISREG(l_st.st_mode):
            return None, False
        if cutoff is not None and l_st.st_mtime >= cutoff:
            return None, False
        if expected_identity is not None and not _blob_identity_matches(l_st, expected_identity):
            return None, False
        sz = int(l_st.st_size)
        path.unlink()
        return sz, True
    except FileNotFoundError:
        return None, True
    except (PermissionError, OSError):
        return None, False


def _is_expired_regular_file(path: Path, cutoff: float) -> bool:
    if check_unsafe_link(path):
        return False
    try:
        st = os.lstat(str(path))
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_mtime < cutoff


def _scan_orphan_and_staged_candidates(
    eff_dir: Path,
    known_sids: set[str],
    cutoff: float,
) -> tuple[list[tuple[Path, str]], list[Path]]:
    try:
        items = list(eff_dir.iterdir())
    except OSError:
        return [], []
    orphan_candidates: list[tuple[Path, str]] = []
    stale_staged: list[Path] = []
    for item in items:
        if item.name.startswith(".orphan."):
            if _is_expired_regular_file(item, cutoff):
                stale_staged.append(item)
            continue
        if not (m := _BLOB_NAME_RE.fullmatch(item.name)) or (osid := m.group(1)) in known_sids:
            continue
        if _is_expired_regular_file(item, cutoff):
            orphan_candidates.append((item, osid))
    return orphan_candidates, stale_staged


def _stage_orphan_locked(eff_dir: Path, item: Path, cutoff: float) -> Path | None:
    if not _is_expired_regular_file(item, cutoff):
        return None
    staged = eff_dir / f".orphan.{os.getpid()}.{uuid.uuid4().hex[:12]}"
    try:
        os.replace(str(item), str(staged))
        return staged
    except OSError:
        return None


def _unlink_staged_paths(paths: Sequence[Path], cutoff: float | None = None) -> tuple[int, int]:
    rc, rb = 0, 0
    for path in paths:
        u_sz, done = unlink_blob_matching_identity(path, cutoff=cutoff)
        if done and u_sz is not None:
            rc += 1
            rb += u_sz
    return rc, rb


def run_gc_post_lock(
    eff_dir: Path,
    evicting_targets: Sequence[tuple[str, int, tuple[int, int, int] | None]],
    known_sids: set[str],
    options: GcPostLockOptions,
) -> tuple[int, int, dict[str, Any] | None]:
    """Unlink evicting blobs outside lock, stage live-absent orphans under lock, and unlink orphans outside lock."""
    rc, rb = 0, 0
    completed: list[str] = []
    for sid, _fallback_sz, expected_id in evicting_targets:
        u_sz, done = unlink_blob_matching_identity(eff_dir / f"{sid}.txt", expected_identity=expected_id)
        if done:
            completed.append(sid)
            if u_sz is not None:
                rc += 1
                rb += u_sz
    orphan_candidates, stale_staged = _scan_orphan_and_staged_candidates(eff_dir, known_sids, options.cutoff)
    if not completed and not orphan_candidates:
        s_rc, s_rb = _unlink_staged_paths(stale_staged, cutoff=options.cutoff)
        return rc + s_rc, rb + s_rb, None
    staged_orphans: list[Path] = []
    ret_index: dict[str, Any] | None = None
    with options.spool_lock(eff_dir):
        index = options.open_index(eff_dir)
        tombstones = index.setdefault("tombstones", {})
        live_sids = set(index["entries"]) | set(tombstones)
        for item, osid in orphan_candidates:
            if osid not in live_sids and (staged := _stage_orphan_locked(eff_dir, item, options.cutoff)) is not None:
                staged_orphans.append(staged)
        dirty = False
        for sid in completed:
            if isinstance((tomb := tombstones.get(sid)), dict) and tomb.get("state") == "evicting":
                tomb["state"] = "evicted"
                dirty = True
        if prune_evicted_tombstones(
            tombstones, options.now_ts, max_age=options.tombstone_max_age, max_tombstones=options.max_tombstones
        ):
            index["id_epoch"] = max(0, int(index.get("id_epoch") or 0)) + 1
            dirty = True
        if dirty:
            options.save_index(eff_dir, index)
        if completed or dirty:
            ret_index = index
    o_rc, o_rb = _unlink_staged_paths(staged_orphans)
    s_rc, s_rb = _unlink_staged_paths(stale_staged, cutoff=options.cutoff)
    return rc + o_rc + s_rc, rb + o_rb + s_rb, ret_index
