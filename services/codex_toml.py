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
    obj: dict[str, Any] = {
        "event_name": event_name,
        "hooks": [{"async": bool(is_async), "command": command, "timeout": int(timeout), "type": "command"}],
    }
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
        meta.append(
            (is_header, multiline is None and stripped.startswith("#"), multiline is None and stripped == "", is_compact, is_managed)
        )
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
                        snake_evt,
                        matcher,
                        cmd,
                        timeout=int(h_obj.get("timeout") or 600),
                        is_async=bool(h_obj.get("async") or False),
                    )
                    blocks.append(f'[hooks.state."{esc_hooks}:{snake_evt}:{g_idx}:{h_idx}"]\ntrusted_hash = "{thash}"\n')
    return blocks


def sync_codex_config_toml(
    codex_hooks_path: Path,
    codex_config_path: Path,
    hooks_data: dict[str, Any],
    ensure_compact_limit: bool,
    dry_run: bool = False,
    *,
    atomic_writer: Callable[[Path, str], None] | None = None,
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


_TOML_BAD, _TOML_BARE_RE, _TOML_VAL_RE = object(), re.compile(r"[A-Za-z0-9_-]+"), re.compile(r"[^ \t\n#,\]}]+")
_TOML_WS = (re.compile(r"(?:[ \t]+|#[^\n]*)*"), re.compile(r"(?:[ \t\n]+|#[^\n]*)*"))
_TOML_ESC_RE = re.compile(r"\\([ \t]*\n[ \t\n]*|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)", re.DOTALL)
_TOML_ESC = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}
_TOML_STRS = (
    ('"""', re.compile(r'"""\n?((?:\\.|[^\\])*?)"""("{0,2})', re.DOTALL), False, True),
    ("'''", re.compile(r"'''\n?(.*?)'''('{0,2})", re.DOTALL), True, True),
    ('"', re.compile(r'"((?:\\[^\n]|[^"\\\n])*)"'), False, False),
    ("'", re.compile(r"'([^'\n]*)'"), True, False),
)


def _toml_ws(src: str, pos: int, nl: bool = False) -> int:
    return m.end() if (m := _TOML_WS[1 if nl else 0].match(src, pos)) else pos


def _unescape_basic(raw: str, ml: bool) -> str | None:
    def _sub(m: re.Match[str]) -> str:
        t = m.group(1)
        if ml and t[0] in (" ", "\t", "\n"):
            return ""
        if t in _TOML_ESC:
            return _TOML_ESC[t]
        if len(t) > 1 and t[0] in ("u", "U") and 0 <= (cp := int(t[1:], 16)) <= 0x10FFFF and not (0xD800 <= cp <= 0xDFFF):
            return chr(cp)
        raise ValueError(t)

    try:
        return _TOML_ESC_RE.sub(_sub, raw)
    except ValueError:
        return None


def _read_toml_str(src: str, pos: int) -> tuple[str | None, int]:
    for prefix, rx, is_lit, ml in _TOML_STRS:
        if src.startswith(prefix, pos):
            if (m := rx.match(src, pos)):
                raw = m.group(1) + (m.group(2) if ml else "")
                return (raw if is_lit else _unescape_basic(raw, ml)), m.end()
            return None, (len(src) if ml or (nl := src.find("\n", pos)) == -1 else nl)
    return None, pos


def _read_key_path(src: str, pos: int) -> tuple[list[str] | None, int]:
    segs: list[str] = []
    while pos < len(src):
        if src[pos] in ('"', "'") and not src.startswith(('"""', "'''"), pos):
            seg, pos = _read_toml_str(src, pos)
            if seg is None:
                return None, pos
        elif (m := _TOML_BARE_RE.match(src, pos)):
            seg, pos = m.group(0), m.end()
        else:
            return None, pos
        segs.append(seg)
        if (nxt := _toml_ws(src, pos)) >= len(src) or src[nxt] != ".":
            return segs, nxt
        pos = _toml_ws(src, nxt + 1)
    return segs or None, pos


def _read_toml_val(src: str, pos: int) -> tuple[Any, int]:
    if pos >= (n := len(src)):
        return _TOML_BAD, pos
    if (ch := src[pos]) in ('"', "'"):
        s, nxt = _read_toml_str(src, pos)
        return (_TOML_BAD if s is None else s), nxt
    if ch in ("[", "{"):
        acc: Any = [] if ch == "[" else {}
        close, pos = ("]" if ch == "[" else "}"), pos + 1
        while (pos := _toml_ws(src, pos, True)) < n:
            if src[pos] == close:
                return acc, pos + 1
            if ch == "[":
                val, nxt = _read_toml_val(src, pos)
                if isinstance(val, str):
                    acc.append(val)
            else:
                kp, kpos = _read_key_path(src, pos)
                if not kp or (kpos := _toml_ws(src, kpos, True)) >= n or src[kpos] != "=":
                    return _TOML_BAD, kpos
                val, nxt = _read_toml_val(src, _toml_ws(src, kpos + 1, True))
                if isinstance(val, str) and len(kp) == 1:
                    acc[kp[0]] = val
            if nxt == pos or (pos := _toml_ws(src, nxt, True)) >= n or src[pos] not in (",", close):
                return _TOML_BAD, pos
            if src[pos] == close:
                return acc, pos + 1
            pos += 1
        return _TOML_BAD, pos
    m = _TOML_VAL_RE.match(src, pos)
    tok, end = (m.group(0), m.end()) if m else ("", pos)
    return (True, end) if tok == "true" else ((False, end) if tok == "false" else (_TOML_BAD, end))


def parse_codex_mcp_servers(toml_text: str) -> list[dict[str, Any]]:
    """Lexically parse `[mcp_servers.<name>]` and `[mcp_servers.<name>.env]` TOML tables without tomllib."""
    src = toml_text.replace("\r\n", "\n").replace("\r", "\n")
    pos, n, section = 0, len(src), None
    servers: dict[str, dict[str, Any]] = {}
    while (pos := _toml_ws(src, pos, True)) < n:
        if src[pos] == "[":
            section = None
            if not src.startswith("[[", pos):
                kp, nxt = _read_key_path(src, _toml_ws(src, pos + 1))
                if kp and (nxt := _toml_ws(src, nxt)) < n and src[nxt] == "]" and ((tail := _toml_ws(src, nxt + 1)) >= n or src[tail] == "\n"):
                    if kp[0] == "mcp_servers" and (len(kp) == 2 or (len(kp) == 3 and kp[2] == "env")):
                        servers.setdefault(
                            kp[1],
                            {"name": kp[1], "command": None, "args": [], "url": None, "cwd": None, "enabled": True, "env": {}},
                        )
                        section = ("server" if len(kp) == 2 else "env", kp[1])
        else:
            kp, nxt = _read_key_path(src, pos)
            if kp and (nxt := _toml_ws(src, nxt)) < n and src[nxt] == "=" and (vpos := _toml_ws(src, nxt + 1)) < n and src[vpos] != "\n":
                val, vend = _read_toml_val(src, vpos)
                tail = _toml_ws(src, vend)
                if (ok := tail >= n or src[tail] == "\n") and section is not None and val is not _TOML_BAD:
                    ent = servers[section[1]]
                    if (section[0] == "env" and len(kp) == 1 and isinstance(val, str)) or (
                        section[0] == "server" and len(kp) == 2 and kp[0] == "env" and isinstance(val, str)
                    ):
                        ent["env"][kp[-1]] = val
                    elif section[0] == "server" and len(kp) == 1:
                        if (
                            (kp[0] in ("command", "url", "cwd") and isinstance(val, str))
                            or (kp[0] == "args" and isinstance(val, list))
                            or (kp[0] == "enabled" and isinstance(val, bool))
                        ):
                            ent[kp[0]] = val
                        elif kp[0] == "env" and isinstance(val, dict):
                            ent["env"].update(val)
                pos = min(n, tail + 1) if ok else (n if (nl := src.find("\n", vend)) == -1 else nl + 1)
                continue
        pos = n if (nl := src.find("\n", pos)) == -1 else nl + 1
    return list(servers.values())
