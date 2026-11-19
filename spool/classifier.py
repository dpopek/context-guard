"""Pure command-signature, verbose-override, scope-check, and PreToolUse spool follow-up classifier."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import stat
import time
from typing import Any, Callable, Mapping, Sequence

from core.platform_io import check_unsafe_link
from spool.receipts import (
    DEFAULT_MAX_SPOOL_ENTRY_BYTES,
    VALID_SPOOL_ISOLATIONS,
    compute_scope_key,
    compute_scoped_spool_id,
    read_spool_config,
    receipts_path_for,
    resolve_workspace_identity,
    same_workspace_dir,
    summarize_receipts,
)
from spool.spans import grep_lines_with_spans

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
    """Safely read a regular non-symlink file with O_NOFOLLOW and lstat/fstat identity verification."""
    for _ in range(3):
        if check_unsafe_link(path):
            return None, "unsafe_path"
        try:
            l_st = os.lstat(str(path))
        except FileNotFoundError:
            return None, "spool_not_found"
        except OSError as exc:
            return None, str(exc)
        if not stat.S_ISREG(l_st.st_mode):
            return None, "unsafe_path"
        try:
            with os.fdopen(os.open(str(path), os.O_RDONLY | _O_FLAGS), "rb") as fh:
                f_st = os.fstat(fh.fileno())
                if not stat.S_ISREG(f_st.st_mode):
                    return None, "unsafe_path"
                if (l_st.st_ino != 0 or f_st.st_ino != 0) and (
                    (f_st.st_dev, f_st.st_ino) != (l_st.st_dev, l_st.st_ino)
                ):
                    continue
                return fh.read(), None
        except FileNotFoundError:
            return None, "spool_not_found"
        except OSError as exc:
            if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)):
                return None, "unsafe_path"
            return None, str(exc)
    return None, "unsafe_path"


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
    "source_sha256", "source_bytes", "created_at", "last_accessed_at", "state", "corrupt_reason", "corrupted_at",
    "blob_dev", "blob_ino", "blob_mtime_ns",
)


def _extract_blob_identity(record: Mapping[str, Any]) -> tuple[int, int, int] | None:
    dev, ino, mtime_ns = record.get("blob_dev"), record.get("blob_ino"), record.get("blob_mtime_ns")
    if (
        isinstance(dev, int) and not isinstance(dev, bool)
        and isinstance(ino, int) and not isinstance(ino, bool)
        and isinstance(mtime_ns, int) and not isinstance(mtime_ns, bool)
    ):
        return (int(dev), int(ino), int(mtime_ns))
    return None


def parse_spool_index(data: Any) -> dict[str, Any] | None:
    """Validate and normalize raw decoded JSON into a schema-v2 spool index dict."""
    if not isinstance(data, dict) or isinstance((sv := data.get("schema_version")), bool) or sv not in (1, _SCHEMA_VERSION) or not isinstance(data.get("entries"), dict):
        return None
    raw_epoch = data.get("id_epoch", 0)
    if "id_epoch" in data and (isinstance(raw_epoch, bool) or not isinstance(raw_epoch, int) or raw_epoch < 0):
        return None
    id_epoch = int(raw_epoch) if "id_epoch" in data else 0
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
            **{k: int(tv[k]) for k in ("blob_dev", "blob_ino", "blob_mtime_ns") if isinstance(tv.get(k), int) and not isinstance(tv.get(k), bool)},
        }
        for sid, tv in (raw_tombs.items() if isinstance(raw_tombs, dict) else ())
        if isinstance(sid, str) and SPOOL_ID_RE.fullmatch(sid) and isinstance(tv, dict)
    }
    return {"schema_version": _SCHEMA_VERSION, "id_epoch": id_epoch, "entries": entries, "tombstones": tombstones}


def _ro_index_state(eff_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], bool]:
    if check_unsafe_link(eff_dir):
        return {}, {}, False
    parsed, _ = read_spool_index_readonly(eff_dir / "spool_index.json")
    return (parsed["entries"], parsed["tombstones"], True) if parsed else ({}, {}, False)


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
    entries, _tombstones, idx_valid = _ro_index_state(eff_dir)
    ent = entries.get(sid)
    total: int | None = None
    if idx_valid:
        if ent is None or ent.get("state") != "available" or entry_scope_error(ent, mode, ws_id, sess_id, caller_canon_root=canon_root) is not None:
            return None
        if isinstance(ent.get("total_lines"), int) and not isinstance(ent.get("total_lines"), bool) and ent["total_lines"] > 0:
            total = int(ent["total_lines"])
    else:
        rb, r_err = read_blob_bytes(eff_dir / f"{sid}.txt")
        if r_err is not None or rb is None:
            return None
        try:
            total = len(split_lines(rb.decode("utf-8", errors="strict")))
        except UnicodeDecodeError:
            return None
    req_lines = max(1, e_l - s_l + 1) if (e_l is not None and e_l >= s_l) else (max(1, lim) if (lim is not None and lim >= 1) else default_lim)
    full = kind == "direct_read" and req_lines is None
    if not full and kind != "grep" and req_lines is not None and req_lines > 200:
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
            raw_leaf = str(tool_input.get("name") or tool_input.get("tool_name") or tool_name) if tool_name == "call_mcp_tool" else tool_name
            leaf = raw_leaf.rsplit("__", 1)[-1].rsplit(":", 1)[-1]
            args = (tool_input.get("arguments") or tool_input.get("args") or tool_input) if tool_name == "call_mcp_tool" else tool_input
            if isinstance(args, Mapping) and SPOOL_ID_RE.fullmatch((sid := str(args.get("spool_id") or "").strip())) and leaf in ("cg_spool_grep", "cg_spool_slice"):
                return _eval_followup(
                    sid, "grep" if leaf == "cg_spool_grep" else "slice", eff_dir, mode, ws_id,
                    canon_root, eff_sess, max(1, _opt_int(args.get("start_line")) or 1),
                    _opt_int(args.get("end_line")), _opt_int(args.get("limit")), 120,
                )
        elif tool_name in ("Read", "read_file", "view_file"):
            raw_fp = str(tool_input.get("file_path") or tool_input.get("path") or tool_input.get("Path") or tool_input.get("AbsolutePath") or "")
            if (msid := _match_blob_path(raw_fp, eff_dir)):
                s_val = _opt_int(tool_input.get("StartLine") if "StartLine" in tool_input else tool_input.get("offset"))
                return _eval_followup(
                    msid, "direct_read", eff_dir, mode, ws_id, canon_root, eff_sess,
                    max(1, s_val or 1), _opt_int(tool_input.get("EndLine")), _opt_int(tool_input.get("limit")),
                )
        elif tool_name in _SHELL_TOOLS:
            rc = tool_input.get("command") or tool_input.get("cmd") or tool_input.get("CommandLine")
            cmd_text = rc if isinstance(rc, str) else (" ".join(str(x) for x in rc) if isinstance(rc, list) else "")
            tokens = _strip_cd_and_split(cmd_text)
            cg = next(
                (i for i, t in enumerate(tokens) if re.sub(r"\.(?:exe|cmd|bat)$", "", t.replace("\\", "/").rsplit("/", 1)[-1].lower()) in ("cg-spool", "cg_spool.py")),
                -1,
            )
            if cg >= 0 and cg + 1 < len(tokens) and tokens[cg + 1] in ("grep", "slice"):
                tail_toks = tokens[cg + 2 :]
                if (csid := next((t for t in tail_toks if SPOOL_ID_RE.fullmatch(t)), "")):
                    return _eval_followup(
                        csid, "grep" if tokens[cg + 1] == "grep" else "slice", eff_dir, mode, ws_id, canon_root,
                        eff_sess, max(1, _cli_int(tail_toks, "--start") or 1), _cli_int(tail_toks, "--end"), _cli_int(tail_toks, "--limit"), 120,
                    )
            if tokens and (cmd_bin := tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()) in _READER_BINS:
                if (rsid := next((m for t in tokens[1:] if (m := _match_blob_path(t, eff_dir)) is not None), None)) is not None:
                    s_l, req = 1, None  # type: tuple[int, int | None]
                    if cmd_bin in ("head", "tail"):
                        val = _cli_int(tokens[1:], "--lines") or _cli_int(tokens[1:], "-n") or next(
                            (int(mm.group(1)) for t in tokens[1:] if (mm := re.fullmatch(r"-n?(\d+)", t))), None
                        )
                        req = max(1, val) if val is not None else 10
                    elif cmd_bin == "sed" and (ms := next((mm for t in tokens[1:] if (mm := re.fullmatch(r"(\d+),(\d+)p", t))), None)):
                        s_l = max(1, int(ms.group(1)))
                        req = max(1, int(ms.group(2)) - s_l + 1)
                    return _eval_followup(rsid, "direct_read", eff_dir, mode, ws_id, canon_root, eff_sess, s_l, lim=req)
    except (OSError, ValueError, TypeError):
        pass
    return None


def validate_and_normalize_spool_text(raw_text: Any, eff_max_bytes: int) -> tuple[str, bytes] | None:
    """Validate strict UTF-8 and NUL absence, normalize line endings to LF, and enforce byte ceiling."""
    if eff_max_bytes < 1 or not isinstance(raw_text, (str, bytes)):
        return None
    if isinstance(raw_text, bytes):
        if len(raw_text) > eff_max_bytes:
            return None
        try:
            raw_str = raw_text.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
    else:
        if len(raw_text) > eff_max_bytes:
            return None
        try:
            if len(raw_text.encode("utf-8", errors="strict")) > eff_max_bytes:
                return None
        except UnicodeEncodeError:
            return None
        raw_str = raw_text
    if "\x00" in raw_str:
        return None
    norm = raw_str.replace("\r\n", "\n").replace("\r", "\n")
    try:
        raw_bytes = norm.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    return (norm, raw_bytes) if len(raw_bytes) <= eff_max_bytes else None


def build_spool_summary(
    sid: str, lines: list[str], total_bytes: int, sha_hex: str, *,
    head_lines: int = 25, tail_lines: int = 15, max_bytes: int = 3_072, min_saved_bytes: int = 2_048,
) -> tuple[str, int] | None:
    """Build bounded UTF-8 head/tail summary with CLI/MCP recovery hints or return None if savings too small."""
    total_lines = len(lines)
    h, t, drop_h = min(head_lines, total_lines), min(tail_lines, max(0, total_lines - head_lines)), True

    def _fmt(sv: int, hd: list[str], tl: list[str]) -> str:
        om = max(0, total_lines - len(hd) - len(tl))
        parts = [
            f"[CONTEXT-GUARD OUTPUT SPOOL: {sid} | {total_lines} lines, {total_bytes} B | sha256={sha_hex[:12]}]",
            f"Saved {sv} B. Inspect slices without re-running:",
            f"- CLI: cg-spool slice {sid} --start 1 --limit 120 | cg-spool grep {sid} --pattern '<regex>'",
            f"- MCP: cg_spool_slice / cg_spool_grep (spool_id={sid})",
            *([f"--- HEAD (lines 1..{len(hd)}) ---", *hd] if hd else []),
            *([f"--- OMITTED ({om} lines; use cg-spool slice/grep) ---"] if om > 0 else []),
            *([f"--- TAIL (lines {total_lines - len(tl) + 1}..{total_lines}) ---", *tl] if tl else []),
        ]
        return "\n".join(parts)

    while h + t > 1 and len(_fmt(total_bytes, lines[:h], lines[-t:] if t else []).encode("utf-8")) > max_bytes:
        t, h, drop_h = (t - 1, h, not drop_h) if (t > 0 and (not drop_h or h <= 1)) else (t, max(0, h - 1), not drop_h)
    hd, tl, suf = lines[:h], (lines[-t:] if t else []), "\n...[summary truncated]"
    if len(_fmt(total_bytes, hd, tl).encode("utf-8")) > max_bytes:
        avail = max(0, max_bytes - len(_fmt(total_bytes, [""] if lines else [], []).encode("utf-8")) - len(suf.encode("utf-8")))
        hd, tl = ([lines[0].encode("utf-8")[:avail].decode("utf-8", "ignore") + suf] if (lines and avail > 0) else []), []
    summary = _fmt(max(0, total_bytes - len(_fmt(total_bytes, hd, tl).encode("utf-8"))), hd, tl)
    if len(summary.encode("utf-8")) > max_bytes:
        summary = summary.encode("utf-8")[: max_bytes - len(suf.encode("utf-8"))].decode("utf-8", "ignore") + suf
    final_saved = max(0, total_bytes - len(summary.encode("utf-8")))
    return (summary, final_saved) if final_saved >= min_saved_bytes else None


def project_spool_in_memory(
    raw_text: str | bytes, *, scope_key: str = "global", max_bytes: int = DEFAULT_MAX_SPOOL_ENTRY_BYTES,
    min_bytes: int = 12_288, min_lines: int = 200,
    head_lines: int = 25, tail_lines: int = 15, summary_max_bytes: int = 3_072, min_saved_bytes: int = 2_048,
) -> tuple[str, list[str], bytes, str, str, int] | None:
    """Validate, normalize, hash, and summarize an output payload purely in memory."""
    if (vn := validate_and_normalize_spool_text(raw_text, max_bytes)) is None:
        return None
    norm, raw_bytes = vn
    total_bytes, lines = len(raw_bytes), split_lines(norm)
    if total_bytes < min_bytes and len(lines) < min_lines:
        return None
    sha_hex = hashlib.sha256(raw_bytes).hexdigest()
    sid = compute_scoped_spool_id(scope_key, sha_hex)
    built = build_spool_summary(
        sid, lines, total_bytes, sha_hex, head_lines=head_lines, tail_lines=tail_lines,
        max_bytes=summary_max_bytes, min_saved_bytes=min_saved_bytes,
    )
    return (sid, lines, raw_bytes, sha_hex, built[0], built[1]) if built is not None else None


def has_tool_error_signal(payload: Mapping[str, Any], resp: Any) -> bool:
    """Return True if a PostToolUse payload or response signals an error or non-zero exit code."""
    if payload.get("hook_event_name") == "PostToolUseFailure" or str(payload.get("status") or "").lower() in ("error", "failed", "failure"):
        return True
    for obj in (payload, resp):
        if isinstance(obj, Mapping) and (
            obj.get("is_error") or obj.get("isError") or obj.get("error")
            or any(isinstance((v := obj.get(k)), int) and not isinstance(v, bool) and v != 0 for k in ("exit_code", "exitCode", "return_code", "returncode"))
        ):
            return True
    return False


def _decode_cursor_tool_output(resp: Any) -> Any:
    if not isinstance(resp, str) or not resp.lstrip().startswith(("{", "[")):
        return resp
    try:
        parsed = json.loads(resp)
    except ValueError:
        return resp
    return parsed if isinstance(parsed, (Mapping, list)) else resp


def _is_text_block_list(val: Any) -> bool:
    return bool(
        isinstance(val, list) and val
        and all(isinstance(b, Mapping) and b.get("type") == "text" and isinstance(b.get("text"), str) for b in val)
    )


def extract_tool_payload_text(harness: str, resp: Any, is_shell: bool) -> tuple[str | bytes | None, str | None]:
    """Extract raw tool output text/bytes and its structural shape from a PostToolUse response."""
    if harness == "cursor" and isinstance(resp, str):
        resp = _decode_cursor_tool_output(resp)
    if isinstance(resp, (str, bytes)):
        return resp, ("bytes" if isinstance(resp, bytes) else "str")
    if isinstance(resp, Mapping):
        if harness == "cursor" and (any(resp.get(k) is True for k in ("redacted", "truncated", "is_truncated", "unavailable")) or has_tool_error_signal({}, resp)):
            return None, None
        if isinstance((content := resp.get("content")), list):
            return ("\n".join(b["text"] for b in content), "mcp_content") if _is_text_block_list(content) else (None, None)
        keys = ("text", "output", "content", "stdout") if harness == "cursor" else ("output", "stdout")
        return next(((resp[k], k) for k in keys if isinstance(resp.get(k), (str, bytes))), (None, None))
    if isinstance(resp, list) and _is_text_block_list(resp):
        return "\n".join(b["text"] for b in resp), "blocks"
    return None, None


def format_spooled_tool_output(harness: str, shape: str | None, raw_resp: Any, summary: str) -> Any:
    """Shape a spooled summary back into the harness's native tool-output structure."""
    if shape == "mcp_content" and isinstance(raw_resp, Mapping):
        return {**{k: v for k, v in raw_resp.items() if k not in ("content", "structuredContent")}, "content": [{"type": "text", "text": summary}]}
    if harness == "cursor":
        if isinstance(raw_resp, Mapping) and shape in ("text", "output", "content", "stdout"):
            return {**raw_resp, str(shape): summary}
        return {"content": [{"type": "text", "text": summary}]}
    if shape in ("str", "bytes", None):
        return summary
    if shape == "blocks":
        return [{"type": "text", "text": summary}]
    return {**raw_resp, str(shape): summary} if isinstance(raw_resp, Mapping) else summary


def byte_offset_for_line(lines: list[str], idx: int) -> int:
    """Return UTF-8 byte offset of 0-based line index `idx` assuming LF line separators."""
    return sum(len(lines[k].encode("utf-8")) + 1 for k in range(idx))


def slice_verified_lines(
    lines: list[str], start_line: int, limit: int, end_line: int | None,
) -> tuple[dict[str, Any], tuple[int, int], tuple[int, int]]:
    """Compute bounded slice result fields and half-open `(line_span, byte_span)` purely."""
    total_lines, s_line = len(lines), max(1, int(start_line))
    e_clamped = min(total_lines, int(end_line) if end_line is not None else (s_line + max(1, int(limit)) - 1))
    empty = total_lines == 0 or s_line > total_lines or e_clamped < s_line
    sel = [] if empty else lines[s_line - 1 : e_clamped]
    content = "\n".join(sel)
    lspan = (0, 0) if empty else (s_line - 1, e_clamped)
    bspan = (0, 0) if empty else ((sb := byte_offset_for_line(lines, s_line - 1)), sb + len(content.encode("utf-8")))
    fields = {
        "start_line": s_line, "end_line": (s_line - 1 if empty else e_clamped), "returned_lines": len(sel),
        "total_lines": total_lines, "truncated": (False if empty else e_clamped < total_lines), "content": content,
    }
    return fields, lspan, bspan


def grep_verified_lines(
    lines: list[str], rx: re.Pattern[str], max_matches: int, context_lines: int,
) -> tuple[list[dict[str, Any]], bool, tuple[int, int], tuple[int, int]]:
    """Run bounded regex search on lines and return `(matches, truncated, line_span, byte_span)`."""
    matches, truncated, metrics = grep_lines_with_spans(lines, rx, max_matches, context_lines)
    return matches, truncated, metrics["line_span"], metrics["byte_span"]


_SELF_MCP_LEAVES = frozenset({"cg_spool_slice", "cg_spool_grep", "cg_spool_list"})
_SELF_CLI_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:cg-spool(?:\.(?:exe|cmd|bat))?|cg_spool\.py)(?![A-Za-z0-9_-])", re.I)
_SKIP_SPOOL_TOOLS = frozenset({
    "Read", "NotebookRead", "read_file", "view_file", "view_file_outline", "view_code_item", "Glob", "glob",
    "Grep", "grep_search", "find_by_name", "Edit", "Write", "MultiEdit", "NotebookEdit", "EditFile", "WriteFile",
    "StrReplace", "MultiStrReplace", "Delete", "DeleteFile", "edit_file", "write_file",
    "replace_file_content", "multi_replace_file_content", "write_to_file", "apply_patch",
})


def prepare_post_tool_spool_candidate(
    harness: str, payload: Mapping[str, Any], raw_text: str | bytes | None = None,
) -> tuple[str, Mapping[str, Any], bool, str, Any, str | bytes, str | None, bool] | None:
    """Validate and extract eligible PostToolUse spool inputs, returning None when skipped."""
    tc = payload.get("toolCall")
    tool_name = str(payload.get("tool_name") or (tc.get("name") if isinstance(tc, Mapping) else "") or "")
    raw_in: Mapping[str, Any] = payload["tool_input"] if isinstance(payload.get("tool_input"), Mapping) else (
        tc["args"] if isinstance(tc, Mapping) and isinstance(tc.get("args"), Mapping) else {}
    )
    is_shell = tool_name in _SHELL_TOOLS
    rc = raw_in.get("command") or raw_in.get("cmd") or raw_in.get("CommandLine")
    shell_cmd = rc if isinstance(rc, str) else (" ".join(str(x) for x in rc) if isinstance(rc, list) else "")
    inner = str(raw_in.get("name") or raw_in.get("tool_name") or "") if tool_name == "call_mcp_tool" else tool_name
    raw_resp = payload.get("tool_output") if harness == "cursor" else payload.get("tool_response", payload.get("tool_output"))
    if harness == "cursor":
        raw_resp = _decode_cursor_tool_output(raw_resp)
    eligible = is_shell or tool_name.startswith(("mcp__", "MCP:")) or tool_name == "call_mcp_tool"
    is_self = inner.rsplit("__", 1)[-1].rsplit(":", 1)[-1] in _SELF_MCP_LEAVES or (is_shell and bool(_SELF_CLI_RE.search(shell_cmd)))
    if not tool_name or tool_name in _SKIP_SPOOL_TOOLS or not eligible or is_self or has_tool_error_signal(payload, raw_resp):
        return None
    ext_text, shape = extract_tool_payload_text(harness, raw_resp, is_shell)
    eff_raw: str | bytes | None = raw_text if raw_text is not None else ext_text
    if not isinstance(eff_raw, (str, bytes)):
        return None
    if raw_text is not None and shape is None:
        shape = "bytes" if isinstance(raw_text, bytes) else "str"
    up_trunc = bool(payload.get("truncated") or payload.get("is_truncated") or (isinstance(raw_resp, Mapping) and (raw_resp.get("truncated") or raw_resp.get("is_truncated"))))
    if harness == "cursor" and up_trunc:
        return None
    return tool_name, raw_in, is_shell, shell_cmd, raw_resp, eff_raw, shape, up_trunc


def prune_evicted_tombstones(
    tombstones: dict[str, dict[str, Any]], now_ts: float, *, max_age: float = 7 * 86_400.0, max_tombstones: int = 128,
) -> bool:
    """Prune expired and oldest evicted tombstones in-place, preserving `evicting` tombstones."""
    dirty = False
    for old_sid in [s for s, t in tombstones.items() if t.get("state", "evicted") == "evicted" and (now_ts - float(t.get("evicted_at", 0.0))) > max_age]:
        del tombstones[old_sid]
        dirty = True
    if len(tombstones) > max_tombstones:
        evicted = sorted((s for s, t in tombstones.items() if t.get("state", "evicted") == "evicted"), key=lambda s: (float(tombstones[s].get("evicted_at", 0.0)), s))
        for old_sid in evicted[: len(tombstones) - max_tombstones]:
            del tombstones[old_sid]
            dirty = True
    return dirty


@dataclass(frozen=True)
class GcEvictionPolicy:
    """Parameters and blob probes for planning locked spool GC evictions."""

    max_age: float
    max_entries: int
    max_bytes: int
    now_ts: float
    probe_blob_corrupt: Callable[[str], str | None]
    protect: str | None = None
    tombstone_max_age: float = 7 * 86_400.0
    max_tombstones: int = 128
    max_corrupt_entries: int = 64
    probe_blob_identity: Callable[[str], tuple[int, int, int] | None] | None = None


def plan_gc_evictions(
    index: dict[str, Any],
    policy: GcEvictionPolicy,
) -> tuple[list[tuple[str, int, tuple[int, int, int] | None]], set[str], bool]:
    """Plan corrupt marks, TTL/LRU evictions, and bounded tombstones inside the spool lock."""
    entries, tombstones, dirty, pruned_any = index["entries"], index.setdefault("tombstones", {}), False, False
    for s, ent in entries.items():
        if s != policy.protect and ent.get("state", "available") == "available" and (cr := policy.probe_blob_corrupt(s)) is not None:
            ent["state"], ent["corrupt_reason"], ent["corrupted_at"], dirty = "corrupt", cr, policy.now_ts, True
    for old_c in [s for s, e in entries.items() if e.get("state") == "corrupt" and (policy.now_ts - float(e.get("corrupted_at", e.get("created_at", 0.0)))) > policy.tombstone_max_age]:
        del entries[old_c]
        dirty, pruned_any = True, True
    corrupt_sids = sorted((s for s, e in entries.items() if e.get("state") == "corrupt"), key=lambda s: (float(entries[s].get("corrupted_at", entries[s].get("created_at", 0.0))), s))
    for old_c in corrupt_sids[: max(0, len(corrupt_sids) - policy.max_corrupt_entries)]:
        del entries[old_c]
        dirty, pruned_any = True, True
    avail_sids = [s for s, e in entries.items() if e.get("state", "available") == "available"]
    evict_reasons = {s: "ttl_expired" for s in avail_sids if s != policy.protect and (policy.now_ts - float(entries[s].get("last_accessed_at", entries[s].get("created_at", 0.0)))) > policy.max_age}
    rem_c = sum(1 for s in avail_sids if s not in evict_reasons)
    rem_b = sum(max(0, int(entries[s].get("total_bytes") or 0)) for s in avail_sids if s not in evict_reasons)
    lru_order = sorted((s for s in avail_sids if s != policy.protect and s not in evict_reasons), key=lambda s: (float(entries[s].get("last_accessed_at", 0.0)), float(entries[s].get("created_at", 0.0)), s))
    for sid in lru_order:
        if rem_c <= max(0, policy.max_entries) and rem_b <= max(0, policy.max_bytes):
            break
        evict_reasons[sid] = "max_entries_lru" if rem_c > max(0, policy.max_entries) else "max_bytes_lru"
        rem_c, rem_b = rem_c - 1, rem_b - max(0, int(entries[sid].get("total_bytes") or 0))
    for sid, reason in evict_reasons.items():
        ent = entries.pop(sid)
        ident = _extract_blob_identity(ent)
        if ident is None and policy.probe_blob_identity is not None:
            ident = policy.probe_blob_identity(sid)
        tomb: dict[str, Any] = {
            "spool_id": sid,
            "state": "evicting",
            "reason": reason,
            "evicted_at": policy.now_ts,
            "workspace_id": str(ent.get("workspace_id") or ""),
            "session_id": str(ent.get("session_id") or ""),
            "total_bytes": max(0, int(ent.get("total_bytes") or 0)),
        }
        if isinstance(ent.get("canon_root"), str) and ent["canon_root"].strip():
            tomb["canon_root"] = ent["canon_root"]
        if ident is not None:
            tomb["blob_dev"], tomb["blob_ino"], tomb["blob_mtime_ns"] = ident
        tombstones[sid], dirty = tomb, True
    if prune_evicted_tombstones(tombstones, policy.now_ts, max_age=policy.tombstone_max_age, max_tombstones=policy.max_tombstones):
        dirty, pruned_any = True, True
    if pruned_any:
        index["id_epoch"] = max(0, int(index.get("id_epoch") or 0)) + 1
    evicting_targets = [
        (sid, max(0, int(t.get("total_bytes") or 0)), _extract_blob_identity(t))
        for sid, t in tombstones.items()
        if t.get("state") == "evicting"
    ]
    return evicting_targets, set(entries) | set(tombstones), dirty


def read_spool_index_readonly(idx_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read and parse `spool_index.json` purely read-only without locks or quarantine."""
    raw_bytes, err = read_blob_bytes(idx_path)
    if err == "unsafe_path":
        return None, "unsafe_path"
    try:
        parsed = parse_spool_index(json.loads(raw_bytes.decode("utf-8"))) if raw_bytes is not None else None
    except (UnicodeDecodeError, ValueError, TypeError):
        parsed = None
    return parsed, None


def _num_f(d: Mapping[str, Any], k: str) -> float | None:
    return float(d[k]) if isinstance(d.get(k), (int, float)) and not isinstance(d.get(k), bool) else None


def _num_i(d: Mapping[str, Any], k: str) -> int:
    return max(0, int(d[k])) if isinstance(d.get(k), int) and not isinstance(d.get(k), bool) else 0


def inspect_spool_entry_readonly(spool_id: str, eff_dir: Path) -> dict[str, Any]:
    """Pure read-only inspection of one `spool_id` without locks, writes, warnings, or blob reads."""
    base: dict[str, Any] = {
        "spool_id": str(spool_id or ""), "found": False, "current_state": "unknown", "eviction_reason": None,
        "corrupt_reason": None, "created_at": None, "last_accessed_at": None, "evicted_at": None,
        "corrupted_at": None, "total_bytes": 0, "total_lines": 0, "blob_present": False,
        "workspace_id": "", "session_id": "",
    }
    idx_path = eff_dir / "spool_index.json"
    if check_unsafe_link(eff_dir) or (eff_dir.exists() and not eff_dir.is_dir()) or (eff_dir.is_dir() and check_unsafe_link(idx_path)):
        return {**base, "corrupt_reason": "unsafe_path"}
    if not eff_dir.is_dir() or not isinstance(spool_id, str) or not SPOOL_ID_RE.fullmatch(spool_id):
        return base
    parsed, idx_err = read_spool_index_readonly(idx_path)
    if idx_err == "unsafe_path":
        return {**base, "corrupt_reason": "unsafe_path"}
    if parsed is None:
        return base
    blob_path = eff_dir / f"{spool_id}.txt"
    blob_unsafe, blob_is_reg = check_unsafe_link(blob_path), False
    if not blob_unsafe:
        try:
            is_r = stat.S_ISREG(os.lstat(str(blob_path)).st_mode)
            blob_is_reg, blob_unsafe = is_r, not is_r
        except FileNotFoundError:
            blob_is_reg = False
        except OSError:
            blob_unsafe = True
    if isinstance((ent := parsed["entries"].get(spool_id)), dict):
        raw_st, ent_cr = str(ent.get("state") or "available"), ent.get("corrupt_reason")
        if raw_st == "corrupt" or (raw_st == "available" and (blob_unsafe or not blob_is_reg)):
            cur_st = "corrupt"
            c_rsn: str | None = (
                str(ent_cr) if isinstance(ent_cr, str) and ent_cr
                else ("unsafe_path" if blob_unsafe else ("unexpectedly_missing" if not blob_is_reg else "corrupt"))
            )
        else:
            cur_st, c_rsn = ("available" if raw_st == "available" else "unknown"), None
        return {
            **base, "spool_id": spool_id, "found": True, "current_state": cur_st, "corrupt_reason": c_rsn,
            "created_at": _num_f(ent, "created_at"), "last_accessed_at": _num_f(ent, "last_accessed_at"),
            "corrupted_at": _num_f(ent, "corrupted_at"), "total_bytes": _num_i(ent, "total_bytes"),
            "total_lines": _num_i(ent, "total_lines"), "blob_present": blob_is_reg,
            "workspace_id": str(ent.get("workspace_id") or ""), "session_id": str(ent.get("session_id") or ""),
        }
    if isinstance((tomb := parsed["tombstones"].get(spool_id)), dict):
        t_st = str(tomb.get("state") or "evicted")
        return {
            **base, "spool_id": spool_id, "found": True, "blob_present": blob_is_reg,
            "current_state": t_st if t_st in ("evicting", "evicted") else "evicted",
            "eviction_reason": str(tomb.get("reason") or "ttl_expired"), "evicted_at": _num_f(tomb, "evicted_at"),
            "total_bytes": _num_i(tomb, "total_bytes"),
            "workspace_id": str(tomb.get("workspace_id") or ""), "session_id": str(tomb.get("session_id") or ""),
        }
    return base


def inspect_spool_health_readonly(
    eff_dir: Path, *, receipts_path: Path | None = None,
    now_ts: float | None = None, ttl_seconds: float = 86_400.0,
) -> dict[str, Any]:
    """Pure read-only spool health summary for `cg_status --doctor` (no locks/writes/warnings)."""
    rcpt_summary = summarize_receipts(receipts_path or receipts_path_for(eff_dir), now_ts=now_ts)
    verified, rel_fail = int(rcpt_summary["delivery_verified_count"]), int(rcpt_summary["integrity_failures"])
    if not eff_dir.is_dir() or check_unsafe_link(eff_dir):
        return {
            "spool_dir_exists": False, "entry_count": 0, "total_bytes": 0, "expired_count": 0,
            "orphan_count": 0, "eviction_count": 0, "receipts": rcpt_summary,
            "delivery_verified": verified, "reliability_failures": rel_fail,
            "summary_line": "0 entries, 0 B (dir absent)",
        }
    ts = float(now_ts) if now_ts is not None else time.time()
    parsed, _ = read_spool_index_readonly(eff_dir / "spool_index.json")
    entries, tombstones = (parsed["entries"], parsed["tombstones"]) if parsed else ({}, {})
    avail = [e for e in entries.values() if e.get("state", "available") == "available"]
    total_b = sum(_num_i(e, "total_bytes") for e in avail)
    expired = sum(1 for e in avail if (ts - float(e.get("last_accessed_at", e.get("created_at", 0.0)))) > ttl_seconds)
    evicted = len(tombstones)
    try:
        orphans = sum(
            1 for item in eff_dir.iterdir()
            if (m := _BLOB_NAME_RE.fullmatch(item.name)) and m.group(1) not in entries
            and not check_unsafe_link(item) and item.is_file()
        )
    except OSError:
        orphans = 0
    summary_line = (
        f"{len(avail)} entries, {total_b} B ({expired} expired, {orphans} orphans, "
        f"{evicted} evicted, {verified} verified, {rel_fail} integrity failures)"
    )
    return {
        "spool_dir_exists": True, "entry_count": len(avail), "total_bytes": total_b, "expired_count": expired,
        "orphan_count": orphans, "eviction_count": evicted, "receipts": rcpt_summary,
        "delivery_verified": verified, "reliability_failures": rel_fail, "summary_line": summary_line,
    }
