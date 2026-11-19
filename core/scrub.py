"""Canonical Layer 0 PII, local path, domain, and sensitive artifact scrubber."""

from __future__ import annotations

from collections.abc import Collection, Mapping
import hashlib
from pathlib import Path
import re
from typing import Any

SENSITIVE_PATH_KEYS: frozenset[str] = frozenset({
    "config_path",
    "repo_map_path",
    "workspace_root",
    "canon_root",
    "transcript_path",
    "state_dir",
    "home_dir",
    "stats_path",
    "outcomes_path",
    "usage_path",
    "update_path",
    "shadow_path",
    "spool_dir",
    "spool_path",
    "receipts_path",
    "receipts_dir",
    "cwd",
    "private_policy_stats_path",
})

SENSITIVE_FILES: tuple[str, ...] = (
    "shadow.json",
    "private_policy_stats.json",
    "spool_index.json",
    "receipts.jsonl",
)

_SENSITIVE_BUNDLE_KEYS: frozenset[str] = frozenset({
    "private_policy_stats",
    "policy_packs",
    "pack_details",
    "file_hashes",
    "tree_sha256",
    "shadow",
    "spool_index",
    "receipts_index",
    "workspace_id",
    "spool_id",
    "session_id",
})
_SENSITIVE_KEY_TOKENS: tuple[str, ...] = ("shadow", "private_policy", "policy_pack", "transcript")

_POSIX_HOME_PREFIX_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9._-]+")
_WIN_HOME_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z]:(?:[/\\]|\\\\)Users(?:[/\\]|\\\\)[A-Za-z0-9._-]+",
    re.IGNORECASE,
)
_POSIX_HOME_FULL_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9._-]+(?:[/\\][^\s\"',;)\]]*)?"
)
_WIN_HOME_FULL_RE = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z]:(?:[/\\]|\\\\)Users(?:[/\\]|\\\\)[A-Za-z0-9._-]+(?:(?:[/\\]|\\\\)[^\s\"',;)\]]*)?",
    re.IGNORECASE,
)
_FILE_URI_RE = re.compile(r"file://[^\s\"',;)\]]+", re.IGNORECASE)
_LOCAL_EMAIL_RE = re.compile(r"(?:[A-Za-z0-9._%+-]+)?@[A-Za-z0-9._-]+\.local\b", re.IGNORECASE)
_ATLASSIAN_RE = re.compile(r"\b[a-z0-9.-]+\.atlassian\.net\b", re.IGNORECASE)
_GCP_PROJECT_RE = re.compile(
    r"\b[a-z][a-z0-9]*-[a-z][a-z0-9]*-\d{5,}(?:-[a-z0-9]+)?(?::[A-Za-z0-9_.]*)?\b",
    re.IGNORECASE,
)
_WS_ID_RE = re.compile(r"^ws_[0-9a-f]{8,64}$")
_HEX_HASH_RE = re.compile(r"^(?:sha256:)?[0-9a-f]{12,64}$")
_SPOOL_ID_FIND_RE = re.compile(r"\bsp_[0-9a-f]{12}\b")
_WS_ID_FIND_RE = re.compile(r"\bws_[0-9a-f]{16}\b")

__all__ = [
    "SENSITIVE_FILES",
    "SENSITIVE_PATH_KEYS",
    "hash_session_id",
    "scrub_home_paths",
    "scrub_source_hash",
    "scrub_string",
    "scrub_value",
    "scrub_workspace_id",
]


def _home_candidates() -> list[str]:
    cands: set[str] = set()
    try:
        home_p = Path.home()
        for cand in (str(home_p), str(home_p.resolve())):
            if cand and cand not in ("/", "\\"):
                cands.add(cand)
    except (RuntimeError, OSError):
        pass
    return sorted(cands, key=len, reverse=True)


def scrub_home_paths(text: str) -> str:
    """Replace OS home directory prefixes with `[redacted-path]`, preserving trailing subpaths."""
    if not text:
        return ""
    cleaned = text
    for cand in _home_candidates():
        cleaned = cleaned.replace(cand, "[redacted-path]")
    cleaned = _POSIX_HOME_PREFIX_RE.sub("[redacted-path]", cleaned)
    return _WIN_HOME_PREFIX_RE.sub("[redacted-path]", cleaned)


def scrub_string(text: str) -> str:
    """Scrub full local home paths, file URIs, internal domains/emails, and cloud project IDs."""
    if not text:
        return ""
    cleaned = _FILE_URI_RE.sub("[redacted-path]", text)
    for cand in _home_candidates():
        cleaned = re.compile(re.escape(cand) + r"(?:[/\\][^\s\"',;)\]]*)?").sub(
            "[redacted-path]", cleaned
        )
    for pat, repl in (
        (_WIN_HOME_FULL_RE, "[redacted-path]"),
        (_POSIX_HOME_FULL_RE, "[redacted-path]"),
        (_LOCAL_EMAIL_RE, "[redacted-email]"),
        (_ATLASSIAN_RE, "[redacted-domain]"),
        (_GCP_PROJECT_RE, "[redacted-project]"),
    ):
        cleaned = pat.sub(repl, cleaned)
    return cleaned


def _scrub_sensitive_tokens(text: str) -> str:
    cleaned = scrub_string(text)
    for name in SENSITIVE_FILES:
        if name in cleaned:
            cleaned = cleaned.replace(name, "[redacted]")
    cleaned = _SPOOL_ID_FIND_RE.sub("[redacted]", cleaned)
    return _WS_ID_FIND_RE.sub("[redacted]", cleaned)


def _should_drop_key(
    key: str,
    *,
    drop_path_keys: bool,
    drop_sensitive_files: bool,
    extra_lower: frozenset[str],
) -> bool:
    kl = key.lower()
    if kl in extra_lower:
        return True
    if drop_path_keys and (kl in SENSITIVE_PATH_KEYS or kl.endswith(("_path", "_paths", "_dir", "_dirs"))):
        return True
    if drop_sensitive_files:
        if kl in _SENSITIVE_BUNDLE_KEYS:
            return True
        if any(sf in kl for sf in SENSITIVE_FILES):
            return True
        if any(tok in kl for tok in _SENSITIVE_KEY_TOKENS):
            return True
    return False


def scrub_value(
    val: Any,
    *,
    drop_path_keys: bool = True,
    drop_sensitive_files: bool = False,
    extra_drop_keys: Collection[str] = (),
) -> Any:
    """Recursively scrub strings, mappings, and sequences for safe export and fingerprinting."""
    extra_lower = frozenset(str(k).lower() for k in extra_drop_keys)

    def _walk(node: Any) -> Any:
        if isinstance(node, Mapping):
            return {
                ks: _walk(node[k])
                for k in sorted(node, key=str)
                if not _should_drop_key(
                    (ks := str(k)),
                    drop_path_keys=drop_path_keys,
                    drop_sensitive_files=drop_sensitive_files,
                    extra_lower=extra_lower,
                )
            }
        if isinstance(node, (list, tuple)):
            return [
                _walk(elem)
                for elem in node
                if not (
                    drop_sensitive_files
                    and isinstance(elem, str)
                    and any(sf in elem for sf in SENSITIVE_FILES)
                )
            ]
        if isinstance(node, str):
            return _scrub_sensitive_tokens(node) if drop_sensitive_files else scrub_string(node)
        if isinstance(node, (bool, int, float)) or node is None:
            return node
        raw_str = str(node)
        return _scrub_sensitive_tokens(raw_str) if drop_sensitive_files else scrub_string(raw_str)

    return _walk(val)


def hash_session_id(raw_session: str) -> str:
    """Return a deterministic non-reversible `sha256:<16hex>` identifier for a session ID."""
    return "sha256:" + hashlib.sha256(raw_session.encode("utf-8")).hexdigest()[:16]


def scrub_workspace_id(raw_ws: str) -> str:
    """Preserve opaque `ws_<hex>` IDs and hash any non-opaque workspace identifier."""
    ws = raw_ws.strip()
    if not ws:
        return ""
    if _WS_ID_RE.match(ws):
        return ws
    return "ws_" + hashlib.sha256(f"cg-ws-scrub:{ws}".encode("utf-8")).hexdigest()[:16]


def scrub_source_hash(raw_hash: str) -> str:
    """Preserve valid hex content digests and hash any non-hex source_hash string."""
    sh = raw_hash.strip()
    if not sh:
        return ""
    if _HEX_HASH_RE.match(sh):
        return sh
    return "sha256:" + hashlib.sha256(sh.encode("utf-8")).hexdigest()[:16]
