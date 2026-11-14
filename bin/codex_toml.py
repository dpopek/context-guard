"""Lexical TOML scanner and non-destructive `~/.codex/config.toml` synchronizer."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable

MANAGED_COMPACT_LIMIT_LINE = "model_auto_compact_token_limit = 250000 # context-guard:managed"
_CAMEL_TO_SNAKE_RE = re.compile(r"(?<!^)(?=[A-Z])")
_COMPACT_KEY_RE = re.compile(r"^[ \t]*model_auto_compact_token_limit[ \t]*=")


def compute_codex_trusted_hash(
    event_name: str, matcher: str | None, command: str, timeout: int = 600, is_async: bool = False
) -> str:
    """Return `sha256:<hex>` matching `codex-rs/config/src/fingerprint.rs` canonical JSON identity."""
    obj: dict[str, Any] = {"event_name": event_name, "hooks": [{"async": bool(is_async), "command": command, "timeout": int(timeout), "type": "command"}]}
    if matcher is not None:
        obj["matcher"] = matcher
    return "sha256:" + hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _advance_toml_state(line: str, delim: str | None, bracket_depth: int) -> tuple[str | None, int]:
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if delim is not None:
            if delim in ('"', '"""') and ch == "\\":
                i += 2
            elif line.startswith(delim, i):
                if len(delim) == 3:
                    while i + 3 < n and line[i + 3] == delim[0]:
                        i += 1
                i += len(delim)
                delim = None
            else:
                i += 1
            continue
        if ch == "#":
            break
        if line.startswith('"""', i) or line.startswith("'''", i):
            delim = line[i : i + 3]
            i += 3
        elif ch in ('"', "'"):
            delim = ch
            i += 1
        else:
            bracket_depth = max(0, bracket_depth + (1 if ch == "[" else (-1 if ch == "]" else 0)))
            i += 1
    return (delim if delim and len(delim) == 3 else None), bracket_depth


def _scan_toml_lines(lines: list[str]) -> list[tuple[bool, bool, bool, bool, bool]]:
    """Classify lines as `(is_header, is_comment, is_blank, is_compact_key, is_managed_limit)`."""
    meta: list[tuple[bool, bool, bool, bool, bool]] = []
    multiline, bracket_depth, seen_table = None, 0, False
    for line in lines:
        starts_top = multiline is None and bracket_depth == 0
        stripped = line.lstrip(" \t")
        is_header = starts_top and stripped.startswith("[")
        seen_table = seen_table or is_header
        is_compact = starts_top and not seen_table and bool(_COMPACT_KEY_RE.match(line))
        is_managed = multiline is None and line.rstrip("\r\n").endswith("# context-guard:managed")
        meta.append((is_header, multiline is None and stripped.startswith("#"), multiline is None and stripped == "", is_compact, is_managed))
        multiline, bracket_depth = _advance_toml_state(line, multiline, bracket_depth)
    return meta


def _default_atomic_write(path: Path, content: str) -> None:
    real_path = Path(os.path.realpath(str(path)))
    real_path.parent.mkdir(parents=True, exist_ok=True)
    if real_path.exists() and real_path.read_text(encoding="utf-8") == content:
        return
    fd, tmp_path = tempfile.mkstemp(prefix=f".{real_path.name}.", suffix=".tmp", dir=str(real_path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp_path, str(real_path))
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _build_hooks_state_blocks(hooks_data: dict[str, Any], esc_hooks: str) -> list[str]:
    hooks_root = hooks_data.get("hooks") if isinstance(hooks_data, dict) else None
    blocks: list[str] = []
    for event_key, groups in (hooks_root if isinstance(hooks_root, dict) else {}).items():
        if not isinstance(groups, list):
            continue
        snake_evt = _CAMEL_TO_SNAKE_RE.sub("_", str(event_key)).lower()
        for g_idx, grp in enumerate(groups):
            if not isinstance(grp, dict) or not isinstance(grp.get("hooks"), list):
                continue
            matcher = grp.get("matcher") if isinstance(grp.get("matcher"), str) else None
            for h_idx, h_obj in enumerate(grp["hooks"]):
                cmd = str(h_obj.get("command") or "") if isinstance(h_obj, dict) else ""
                if cmd:
                    thash = compute_codex_trusted_hash(
                        snake_evt, matcher, cmd, timeout=int(h_obj.get("timeout") or 600), is_async=bool(h_obj.get("async") or False)
                    )
                    blocks.append(f'[hooks.state."{esc_hooks}:{snake_evt}:{g_idx}:{h_idx}"]\ntrusted_hash = "{thash}"\n')
    return blocks


def sync_codex_config_toml(
    codex_hooks_path: Path, codex_config_path: Path, hooks_data: dict[str, Any],
    ensure_compact_limit: bool, dry_run: bool = False, *, atomic_writer: Callable[[Path, str], None] | None = None,
) -> str:
    """Non-destructively sync Context-Guard `[hooks.state]` blocks and compact token limit in Codex `config.toml`."""
    if not codex_config_path.exists():
        return "skipped (not found)"
    lines = codex_config_path.read_text(encoding="utf-8").splitlines()
    raw_hooks = str(codex_hooks_path)
    esc_hooks = raw_hooks.replace("\\", "\\\\").replace('"', '\\"')
    hdr_re = re.compile(rf'^\[hooks\.state\."(?:{re.escape(raw_hooks)}|{re.escape(esc_hooks)}):[^"\r\n]+"\]\s*(?:#.*)?$')
    meta = _scan_toml_lines(lines)
    headers = [idx for idx, rec in enumerate(meta) if rec[0]]
    drop = [False] * len(lines)
    for k, start in enumerate(headers):
        if not hdr_re.match(lines[start].strip()):
            continue
        end = headers[k + 1] if k + 1 < len(headers) else len(lines)
        cut, probe = end, end
        while end < len(lines) and probe > start + 1 and meta[probe - 1][2]:
            probe -= 1
        while end < len(lines) and probe > start + 1 and meta[probe - 1][1]:
            cut = probe = probe - 1
        drop[start:cut] = [True] * (cut - start)
    kept = [line for idx, line in enumerate(lines) if not drop[idx] and (ensure_compact_limit or not meta[idx][4])]
    while kept and kept[-1].strip() == "":
        kept.pop()
    if ensure_compact_limit:
        kept_meta = _scan_toml_lines(kept)
        if not any(rec[3] for rec in kept_meta):
            first_hdr = next((idx for idx, rec in enumerate(kept_meta) if rec[0]), None)
            ins = first_hdr if first_hdr is not None else len(kept)
            while first_hdr is not None and ins > 0 and kept_meta[ins - 1][1]:
                ins -= 1
            kept.insert(ins, MANAGED_COMPACT_LIMIT_LINE)
    blocks = _build_hooks_state_blocks(hooks_data, esc_hooks)
    parts = (["\n".join(kept)] if kept else []) + (["\n".join(blocks).rstrip("\n")] if blocks else [])
    final_toml = ("\n\n".join(parts) + "\n") if parts else ""
    if not dry_run:
        (atomic_writer or _default_atomic_write)(codex_config_path, final_toml)
    return "updated"
