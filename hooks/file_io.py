"""Stdlib-only streaming file I/O helpers (line counting and bounded SHA-256 hashing).

This leaf module must never import anything from `hooks` or `bin` so both `hooks.outcomes`
and `hooks.shell_parser` / `hooks.read_planner` can depend on it without import cycles.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

_posix_fcntl: Any = None
try:
    import fcntl as _posix_fcntl
except ImportError:  # pragma: no cover - Windows
    pass

_win_msvcrt: Any = None
try:
    import msvcrt as _win_msvcrt
except ImportError:  # pragma: no cover - POSIX
    pass

LOCK_EX: int = int(getattr(_posix_fcntl, "LOCK_EX", 2))
LOCK_NB: int = int(getattr(_posix_fcntl, "LOCK_NB", 4))
LOCK_UN: int = int(getattr(_posix_fcntl, "LOCK_UN", 8))

SHA256_MAX_HASH_BYTES: int = 10 * 1024 * 1024  # 10 MB cap before stat fingerprint fallback
SHA256_READ_CHUNK: int = 65536  # 64 KB streaming chunks
MAX_TAIL_LINE_COUNT_BYTES: int = 2 * 1024 * 1024  # 2 MB cap for streaming line count


def flock(
    fd: int | Any,
    operation: int,
    *,
    posix_fcntl: Any = _posix_fcntl,
    win_msvcrt: Any = _win_msvcrt,
) -> None:
    """Cross-platform advisory file lock: delegates to fcntl.flock on POSIX and msvcrt.locking on Windows."""
    if posix_fcntl is not None:
        posix_fcntl.flock(fd, operation)
        return
    if win_msvcrt is None:
        return
    raw_fd = fd.fileno() if hasattr(fd, "fileno") else int(fd)
    try:
        os.lseek(raw_fd, 0, os.SEEK_SET)
    except OSError:
        pass
    if operation & LOCK_UN:
        try:
            win_msvcrt.locking(raw_fd, win_msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        return
    non_blocking = bool(operation & LOCK_NB)
    mode = win_msvcrt.LK_NBLCK if non_blocking else win_msvcrt.LK_LOCK
    try:
        win_msvcrt.locking(raw_fd, mode, 1)
    except OSError as exc:
        if non_blocking:
            raise BlockingIOError(str(exc)) from exc
        raise


def count_file_lines_streaming(
    file_path: str,
    chunk_size: int = SHA256_READ_CHUNK,
) -> int | None:
    """Count total lines in `file_path` using binary chunks, bounded at 2 MB."""
    try:
        st = os.stat(file_path)
        if not os.path.isfile(file_path) or st.st_size > MAX_TAIL_LINE_COUNT_BYTES:
            return None
        if st.st_size == 0:
            return 0
        step = chunk_size if chunk_size > 0 else SHA256_READ_CHUNK
        newlines = 0
        last_byte = b"\n"
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(step)
                if not chunk:
                    break
                newlines += chunk.count(b"\n")
                last_byte = chunk[-1:]
        return newlines if last_byte == b"\n" else newlines + 1
    except OSError:
        return None


def compute_file_sha256(path: str) -> str | None:
    """Return hex SHA-256 digest of file at `path`, or stat fingerprint if >10 MB."""
    try:
        canon = os.path.realpath(path)
        st = os.stat(canon)
        if not os.path.isfile(canon):
            return None
        if st.st_size > SHA256_MAX_HASH_BYTES:
            return f"stat:{st.st_mtime_ns}:{st.st_size}"
        digest = hashlib.sha256()
        with open(canon, "rb") as fh:
            while True:
                chunk = fh.read(SHA256_READ_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def normalize_cmd_basename(token: str) -> str:
    """Return lowercase command basename with path prefixes and Windows executable suffixes stripped."""
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for ext in (".exe", ".cmd", ".bat"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name
