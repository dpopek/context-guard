"""Stdlib-only streaming file I/O helpers (line counting, bounded SHA-256, and platform I/O exports).

This leaf module must never import anything from `hooks` or `bin` so both `hooks.outcomes`
and `hooks.shell_parser` / `hooks.read_planner` can depend on it without import cycles.
"""

from __future__ import annotations

import hashlib
import os

from core.platform_io import LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN, flock, resolve_plugin_root, warn
from core.shell_lexer import normalize_cmd_basename

SHA256_MAX_HASH_BYTES: int = 10 * 1024 * 1024
SHA256_READ_CHUNK: int = 65536
MAX_TAIL_LINE_COUNT_BYTES: int = 2 * 1024 * 1024


def count_file_lines_streaming(file_path: str, chunk_size: int = SHA256_READ_CHUNK) -> int | None:
    """Count total lines in `file_path` using binary chunks, bounded at 2 MB."""
    try:
        st = os.stat(file_path)
        if not os.path.isfile(file_path) or st.st_size > MAX_TAIL_LINE_COUNT_BYTES:
            return None
        if st.st_size == 0:
            return 0
        step = chunk_size if chunk_size > 0 else SHA256_READ_CHUNK
        newlines, last_byte = 0, b"\n"
        with open(file_path, "rb") as fh:
            while (chunk := fh.read(step)):
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
            while (chunk := fh.read(SHA256_READ_CHUNK)):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
