"""Pure command-signature, verbose-override, scope-check, and PreToolUse spool follow-up classifier."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shlex
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

from spool.receipts import (
    VALID_SPOOL_ISOLATIONS,
    check_unsafe_link,
    compute_scope_key,
    read_spool_config,
    receipts_path_for,
    resolve_workspace_identity,
    same_workspace_dir,
)

SPOOL_ID_RE = re.compile(r"^sp_[0-9a-f]{12}$")
_SCHEMA_VERSION = 2
_BLOB_NAME_RE = re.compile(r"^(sp_[0-9a-f]{12})\.txt$")
_LEADING_CD_RE = re.compile(r"^\s*cd\s+(?:\"[^\"]+\"|'[^']+'|[^;&|<>`\n]+?)\s*(?:&&|;)\s*(.+)$", re.DOTALL)
_SHELL_WORD_RE = re.compile(r"""(?:[^\s'"\\]|\\.|'[^']*(?:'|$)|"[^"\\]*(?:\\.[^"\\]*)*(?:"|$))+""")
_QUIET_FLAGS = frozenset({"-q", "--quiet", "--tb=short", "--no-header", "-sb", "--short", "--reporter=dot"})
_VERBOSE_FLAGS = frozenset({"-v", "-vv", "-vvv", "--verbose", "--tb=long", "--tb=full", "--no-quiet"})
_SHELL_TOOLS = frozenset({"Bash", "Shell", "run_command", "run_terminal_cmd", "shell", "exec", "exec_command"})
_READER_BINS = frozenset({"cat", "head", "tail", "sed", "awk", "less", "more", "bat", "nl"})
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


def split_lines(norm: str) -> list[str]:
    """Split normalized LF text into lines without a trailing empty line for trailing newline."""
    return (norm[:-1] if norm.endswith("\n") else norm).split("\n") if norm else []


def _strip_cd_and_split(cmd: str, *, raw_words: bool = False) -> list[str]:
    rem = cmd.strip()
    while (m := _LEADING_CD_RE.match(rem)):
        rem = m.group(1).strip()
    try:
        return [w.group(0) for w in _SHELL_WORD_RE.finditer(rem)] if raw_words else shlex.split(rem)
    except ValueError:
        return rem.split()


def read_blob_bytes(path: Path) -> tuple[bytes | None, str | None]:
    """Safely read a regular non-symlink file with O_NOFOLLOW."""
    if check_unsafe_link(path):
        return None, "unsafe_path"
    try:
        with os.fdopen(os.open(str(path), os.O_RDONLY | _O_FLAGS), "rb") as fh:
            return (fh.read(), None) if stat.S_ISREG(os.fstat(fh.fileno()).st_mode) else (None, "unsafe_path")
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            return None, "spool_not_found"
        return None, "unsafe_path" if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)) else str(exc)


def resolve_spool_scope(
    *,
    isolation: str | None = None,
    workspace_root: str | Path | None = None,
    workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None,
) -> tuple[str, str, str, str, str, str | None]:
    """Purely resolve `(mode, scope_key, workspace_id, canon_root, session_id, error)`."""
    if isolation is None:
        mode, _max_bytes, cfg_err = read_spool_config()
        if cfg_err is not None:
            return "", "", "", "", "", cfg_err
    elif not isinstance(isolation, str) or isolation not in VALID_SPOOL_ISOLATIONS:
        return "", "", "", "", "", "invalid_spool_config"
    else:
        mode = isolation
    eff_sess = session_id.strip() if isinstance(session_id, str) else ""
    if mode == "workspace":
        ws_id, canon_root, ws_err = resolve_workspace_identity(workspace_root, workspace_roots=workspace_roots)
        if ws_err is not None:
            return "", "", "", "", eff_sess, ws_err
        scope_key, sc_err = compute_scope_key("workspace", workspace_id=ws_id)
        return (mode, scope_key, ws_id, canon_root, eff_sess, sc_err) if sc_err is None else ("", "", "", "", eff_sess, sc_err)
    has_ws = (workspace_root is not None and str(workspace_root).strip() != "") or bool(workspace_roots)
    opt_ws_id, opt_canon, _ = resolve_workspace_identity(workspace_root, workspace_roots=workspace_roots) if has_ws else ("", "", None)
    if mode == "session":
        scope_key, sc_err = compute_scope_key("session", session_id=eff_sess)
        return (mode, scope_key, opt_ws_id, opt_canon, eff_sess, sc_err) if sc_err is None else ("", "", "", "", eff_sess, sc_err)
    return "global", "global", opt_ws_id, opt_canon, eff_sess, None


def entry_scope_error(
    record: Mapping[str, Any],
    mode: str,
    ws_id: str,
    sess_id: str,
    *,
    caller_canon_root: str = "",
) -> str | None:
    """Authorize `record` against caller `(mode, ws_id, sess_id, caller_canon_root)` using `same_workspace_dir`."""
    if mode == "workspace":
        rec_canon = record.get("canon_root")
        if isinstance(rec_canon, str) and rec_canon.strip():
            return None if same_workspace_dir(caller_canon_root, rec_canon) else "workspace_mismatch"
        return None if str(record.get("workspace_id") or "") == ws_id else "workspace_mismatch"
    if mode == "session":
        return None if str(record.get("session_id") or "") == sess_id else "session_mismatch"
    return None


def compute_command_signature(tool_name: str, command_or_args: str | Mapping[str, Any]) -> str:
    """Compute canonical 16-hex SHA-256 signature for shell commands or MCP tool args."""
    if isinstance(command_or_args, Mapping):
        enc = json.dumps(
            command_or_args,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=lambda o: dict(o) if isinstance(o, Mapping) else str(o),
        )
        return hashlib.sha256(f"mcp:{tool_name}:{enc}".encode("utf-8")).hexdigest()[:16]
    tokens, stripped, skip = _strip_cd_and_split(str(command_or_args or "")), [], False
    for i, tok in enumerate(tokens):
        skip, tb_pair = False if skip else (tok == "--tb" and i + 1 < len(tokens) and tokens[i + 1] in ("long", "full")), skip
        if not tb_pair and not skip and tok not in _QUIET_FLAGS and tok not in _VERBOSE_FLAGS:
            stripped.append(tok)
    return hashlib.sha256(f"shell:{' '.join(stripped)}".encode("utf-8")).hexdigest()[:16]


def is_verbose_override_command(cmd_line: str) -> tuple[bool, str]:
    """Detect unquoted verbose CLI override flags, returning `(True, base_sig)` or `(False, '')`."""
    words, skip = (_strip_cd_and_split(cmd_line, raw_words=True) if isinstance(cmd_line, str) and cmd_line.strip() else []), False
    for idx, w in enumerate(words):
        if skip or "'" in w or '"' in w:
            skip = False
        elif w in ("-e", "--pattern"):
            skip = True
        elif w in _VERBOSE_FLAGS or (w == "--tb" and idx + 1 < len(words) and words[idx + 1] in ("long", "full")):
            return True, compute_command_signature("shell", cmd_line)
    return False, ""


_INDEX_KEYS = (
    "spool_id", "filename", "workspace_id", "canon_root", "session_id", "call_id", "harness", "tool_name",
    "cmd_sig", "total_lines", "total_bytes", "summary_bytes", "saved_bytes", "content_sha256",
    "created_at", "last_accessed_at", "state", "corrupt_reason", "corrupted_at",
)


def parse_spool_index(data: Any) -> dict[str, Any] | None:
    """Validate and normalize raw decoded JSON into a schema-v2 spool index dict."""
    if not isinstance(data, dict) or isinstance((sv := data.get("schema_version")), bool) or sv not in (1, _SCHEMA_VERSION) or not isinstance(data.get("entries"), dict):
        return None
    raw_tombs = data.get("tombstones")
    if sv == _SCHEMA_VERSION and "tombstones" in data and not isinstance(raw_tombs, dict):
        return None
    entries = {
        sid: {
            **{k: v[k] for k in _INDEX_KEYS if k in v}, "spool_id": sid, "workspace_id": str(v.get("workspace_id") or ""),
            "state": v["state"] if isinstance(v.get("state"), str) and v["state"] in ("preparing", "available", "corrupt") else "available",
        }
        for sid, v in data["entries"].items() if isinstance(sid, str) and SPOOL_ID_RE.fullmatch(sid) and isinstance(v, dict)
    }
    tombstones = {
        sid: {
            "spool_id": sid, "reason": str(tv.get("reason") or "ttl_expired"), "evicted_at": float(tv.get("evicted_at") or 0.0),
            "state": tv["state"] if isinstance(tv.get("state"), str) and tv["state"] in ("evicting", "evicted") else "evicted",
            "workspace_id": str(tv.get("workspace_id") or ""), "session_id": str(tv.get("session_id") or ""),
            "total_bytes": max(0, int(tv.get("total_bytes") or 0)),
            **({"canon_root": tv["canon_root"]} if isinstance(tv.get("canon_root"), str) and tv["canon_root"].strip() else {}),
        }
        for sid, tv in (raw_tombs.items() if isinstance(raw_tombs, dict) else ())
        if isinstance(sid, str) and SPOOL_ID_RE.fullmatch(sid) and isinstance(tv, dict)
    }
    return {"schema_version": _SCHEMA_VERSION, "entries": entries, "tombstones": tombstones}


def _ro_index_state(eff_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], bool]:
    try:
        rb, _ = (None, "u") if check_unsafe_link(eff_dir) else read_blob_bytes(eff_dir / "spool_index.json")
        parsed = parse_spool_index(json.loads(rb.decode("utf-8"))) if rb is not None else None
        return (parsed["entries"], parsed["tombstones"], True) if parsed else ({}, {}, False)
    except (OSError, UnicodeDecodeError, ValueError, TypeError):
        return {}, {}, False


def _eval_followup(
    sid: str,
    kind: str,
    eff_dir: Path,
    mode: str,
    ws_id: str,
    canon_root: str,
    sess_id: str,
    s_l: int = 1,
    e_l: int | None = None,
    lim: int | None = None,
    default_lim: int | None = None,
) -> dict[str, Any] | None:
    entries, tombstones, idx_valid = _ro_index_state(eff_dir)
    ent = entries.get(sid)
    if ent is not None:
        if ent.get("state") == "preparing" or entry_scope_error(ent, mode, ws_id, sess_id, caller_canon_root=canon_root) is not None:
            return None
    elif (tomb := tombstones.get(sid)) is not None:
        if entry_scope_error(tomb, mode, ws_id, sess_id, caller_canon_root=canon_root) is not None:
            return None
    req_lines = max(1, e_l - s_l + 1) if (e_l is not None and e_l >= s_l) else (max(1, lim) if (lim is not None and lim >= 1) else default_lim)
    full = kind == "direct_read" and req_lines is None
    if not full and kind != "grep" and req_lines is not None and req_lines > 200:
        total: int | None = None
        if ent and isinstance(ent.get("total_lines"), int) and not isinstance(ent.get("total_lines"), bool) and ent["total_lines"] > 0:
            total = int(ent["total_lines"])
        elif not idx_valid and (rb := read_blob_bytes(eff_dir / f"{sid}.txt")[0]) is not None:
            try:
                total = len(split_lines(rb.decode("utf-8")))
            except UnicodeDecodeError:
                return None
        full = total is not None and total > 0 and min(req_lines, max(0, total - max(1, s_l) + 1)) > max(200, 0.8 * total)
    return {
        "spool_id": sid,
        "kind": kind,
        "recovery": "full" if full else "targeted",
        "regret": "suspected" if full else "none",
        "evidence": "observed",
        "requested_lines": req_lines,
    }


def _match_blob_path(raw_path: str, eff_dir: Path) -> str | None:
    norm = raw_path.strip().replace("\\", "/")
    try:
        if not (m := _BLOB_NAME_RE.fullmatch(norm.rsplit("/", 1)[-1])):
            return None
        parent_dir = os.path.dirname(os.path.abspath(raw_path.strip()))
        in_eff = os.path.realpath(parent_dir) == os.path.realpath(str(eff_dir)) or same_workspace_dir(parent_dir, eff_dir)
        return m.group(1) if (f"/spool/{m.group(1)}.txt" in norm or in_eff) else None
    except OSError:
        return None


def _opt_int(val: Any) -> int | None:
    return int(val) if isinstance(val, int) and not isinstance(val, bool) else None


def _cli_int(tokens: list[str], flag: str) -> int | None:
    return next(
        (
            int(t[len(flag) + 1 :]) if t.startswith(f"{flag}=") else int(tokens[i + 1])
            for i, t in enumerate(tokens)
            if (t.startswith(f"{flag}=") and t[len(flag) + 1 :].isdigit()) or (t == flag and i + 1 < len(tokens) and tokens[i + 1].isdigit())
        ),
        None,
    )


def classify_pre_tool_spool_followup(
    tool_name: str,
    tool_input: Mapping[str, Any],
    *,
    spool_dir: Path | None = None,
    workspace_root: str | Path | None = None,
    workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None,
    isolation: str | None = None,
) -> dict[str, Any] | None:
    """Pure read-only PreToolUse classifier for spool slice/grep/direct-read follow-ups."""
    try:
        mode, _sk, ws_id, canon_root, eff_sess, scope_err = resolve_spool_scope(
            isolation=isolation,
            workspace_root=workspace_root,
            workspace_roots=workspace_roots,
            session_id=session_id,
        )
        if scope_err is not None or not isinstance(tool_input, Mapping):
            return None
        eff_dir = spool_dir or receipts_path_for().parent
        if tool_name in ("call_mcp_tool", "cg_spool_slice", "cg_spool_grep") or tool_name.startswith(("mcp__", "MCP:", "mcp_")):
            leaf = (str(tool_input.get("name") or tool_input.get("tool_name") or tool_name) if tool_name == "call_mcp_tool" else tool_name).rsplit("__", 1)[-1].rsplit(":", 1)[-1]
            args = (tool_input.get("arguments") or tool_input.get("args") or tool_input) if tool_name == "call_mcp_tool" else tool_input
            if isinstance(args, Mapping) and SPOOL_ID_RE.fullmatch((sid := str(args.get("spool_id") or "").strip())) and leaf in ("cg_spool_grep", "cg_spool_slice"):
                return _eval_followup(sid, "grep" if leaf == "cg_spool_grep" else "slice", eff_dir, mode, ws_id, canon_root, eff_sess, max(1, _opt_int(args.get("start_line")) or 1), _opt_int(args.get("end_line")), _opt_int(args.get("limit")), 120)
        elif tool_name in ("Read", "read_file", "view_file") and (msid := _match_blob_path(str(tool_input.get("file_path") or tool_input.get("path") or tool_input.get("Path") or tool_input.get("AbsolutePath") or ""), eff_dir)):
            return _eval_followup(msid, "direct_read", eff_dir, mode, ws_id, canon_root, eff_sess, max(1, _opt_int(tool_input.get("StartLine") if "StartLine" in tool_input else tool_input.get("offset")) or 1), _opt_int(tool_input.get("EndLine")), _opt_int(tool_input.get("limit")))
        elif tool_name in _SHELL_TOOLS:
            rc = tool_input.get("command") or tool_input.get("cmd") or tool_input.get("CommandLine")
            tokens = _strip_cd_and_split(rc if isinstance(rc, str) else (" ".join(str(x) for x in rc) if isinstance(rc, list) else ""))
            if (cg := next((i for i, t in enumerate(tokens) if re.sub(r"\.(?:exe|cmd|bat)$", "", t.replace("\\", "/").rsplit("/", 1)[-1].lower()) in ("cg-spool", "cg_spool.py")), -1)) >= 0 and cg + 1 < len(tokens) and tokens[cg + 1] in ("grep", "slice") and (csid := next((t for t in tokens[cg + 2 :] if SPOOL_ID_RE.fullmatch(t)), "")):
                return _eval_followup(csid, "grep" if tokens[cg + 1] == "grep" else "slice", eff_dir, mode, ws_id, canon_root, eff_sess, max(1, _cli_int(tokens[cg + 2 :], "--start") or 1), _cli_int(tokens[cg + 2 :], "--end"), _cli_int(tokens[cg + 2 :], "--limit"), 120)
            if tokens and (cmd_bin := tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()) in _READER_BINS and (rsid := next((m for t in tokens[1:] if (m := _match_blob_path(t, eff_dir)) is not None), None)):
                s_l, req = 1, (max(1, val) if (val := _cli_int(tokens[1:], "--lines") or _cli_int(tokens[1:], "-n") or next((int(mm.group(1)) for t in tokens[1:] if (mm := re.fullmatch(r"-n?(\d+)", t))), None)) is not None else 10) if cmd_bin in ("head", "tail") else None
                if cmd_bin == "sed" and (ms := next((mm for t in tokens[1:] if (mm := re.fullmatch(r"(\d+),(\d+)p", t))), None)):
                    s_l, req = max(1, int(ms.group(1))), max(1, int(ms.group(2)) - max(1, int(ms.group(1))) + 1)
                return _eval_followup(rsid, "direct_read", eff_dir, mode, ws_id, canon_root, eff_sess, s_l, lim=req)
    except (OSError, ValueError, TypeError):
        pass
    return None
