"""Content-addressed reversible output spooling, recovery, two-phase GC, and pre-tool classification."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import errno, hashlib, json, os, re, shlex, stat, time
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence
from hooks import state_store
from policies.api import SpoolContractV1
from spool.receipts import (
    VALID_SPOOL_ISOLATIONS,
    append_receipt,
    atomic_write_bytes,
    build_receipt,
    check_unsafe_link,
    compute_scope_key,
    compute_scoped_spool_id,
    find_created_receipt,
    read_spool_isolation_config,
    receipts_path_for,
    resolve_workspace_identity,
    summarize_receipts,
)

SPOOL_SCHEMA_VERSION, SPOOL_MAX_TOMBSTONES = 2, 128
SPOOL_ID_RE, SPOOL_TTL_SECONDS = re.compile(r"^sp_[0-9a-f]{12}$"), 86_400.0
SPOOL_MIN_BYTES, SPOOL_MIN_LINES, SPOOL_MIN_SAVED_BYTES, SPOOL_MAX_BLOB_BYTES = 12_288, 200, 2_048, 4 * 1024 * 1024
SPOOL_MAX_ENTRIES, SPOOL_TOTAL_BYTES_CAP, SPOOL_HEAD_LINES, SPOOL_TAIL_LINES, SPOOL_SUMMARY_MAX_BYTES = 64, 32 * 1024 * 1024, 25, 15, 3_072

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BLOB_NAME_RE = re.compile(r"^(sp_[0-9a-f]{12})\.txt$")
_LEADING_CD_RE = re.compile(r"^\s*cd\s+(?:\"[^\"]+\"|'[^']+'|[^;&|<>`\n]+?)\s*(?:&&|;)\s*(.+)$", re.DOTALL)
_SHELL_WORD_RE = re.compile(r"""(?:[^\s'"\\]|\\.|'[^']*(?:'|$)|"[^"\\]*(?:\\.[^"\\]*)*(?:"|$))+""")
_QUIET_FLAGS = frozenset({"-q", "--quiet", "--tb=short", "--no-header", "-sb", "--short", "--reporter=dot"})
_VERBOSE_FLAGS = frozenset({"-v", "-vv", "-vvv", "--verbose", "--tb=long", "--tb=full", "--no-quiet"})
_SKIP_TOOLS = frozenset({"Read", "NotebookRead", "read_file", "view_file", "view_file_outline", "view_code_item", "Glob", "glob", "Grep", "grep_search", "find_by_name", "Edit", "Write", "MultiEdit", "NotebookEdit", "EditFile", "WriteFile", "StrReplace", "MultiStrReplace", "Delete", "DeleteFile", "edit_file", "write_file", "replace_file_content", "multi_replace_file_content", "write_to_file", "apply_patch"})
_SHELL_TOOLS = frozenset({"Bash", "Shell", "run_command", "run_terminal_cmd", "shell", "exec", "exec_command"})
_READER_BINS = frozenset({"cat", "head", "tail", "sed", "awk", "less", "more", "bat", "nl"})
_SELF_MCP_LEAVES = frozenset({"cg_spool_slice", "cg_spool_grep", "cg_spool_list"})
_SELF_CLI_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:cg-spool(?:\.(?:exe|cmd|bat))?|cg_spool\.py)(?![A-Za-z0-9_-])", re.I)
_INDEX_KEYS = ("spool_id", "filename", "workspace_id", "session_id", "call_id", "harness", "tool_name", "cmd_sig", "total_lines", "total_bytes", "summary_bytes", "saved_bytes", "content_sha256", "created_at", "last_accessed_at")
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _split_lines(norm: str) -> list[str]:
    return (norm[:-1] if norm.endswith("\n") else norm).split("\n") if norm else []


def _ts_iso(now_ts: float | None) -> str | None:
    return datetime.fromtimestamp(float(now_ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if now_ts is not None else None


def _read_blob_bytes(blob_path: Path) -> tuple[bytes | None, str | None]:
    if check_unsafe_link(blob_path):
        return None, "unsafe_path"
    try:
        with os.fdopen(os.open(str(blob_path), os.O_RDONLY | _O_FLAGS), "rb") as fh:
            return (fh.read(), None) if stat.S_ISREG(os.fstat(fh.fileno()).st_mode) else (None, "unsafe_path")
    except OSError as exc:
        return (None, "spool_not_found") if isinstance(exc, FileNotFoundError) else (None, "unsafe_path" if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)) else str(exc))


@contextmanager
def _spool_lock(eff_dir: Path) -> Iterator[None]:
    lp = eff_dir / "spool_index.lock"
    if check_unsafe_link(lp):
        raise OSError("unsafe_path: spool_index.lock")
    with os.fdopen(os.open(str(lp), os.O_RDWR | os.O_CREAT | _O_FLAGS, 0o600), "a+", encoding="utf-8") as fh:
        if os.name != "nt":
            os.chmod(str(lp), 0o600)
        state_store.fcntl.flock(fh.fileno(), state_store.fcntl.LOCK_EX)
        try:
            yield
        finally:
            state_store.fcntl.flock(fh.fileno(), state_store.fcntl.LOCK_UN)


def _parse_index(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict) or isinstance((sv := data.get("schema_version")), bool) or sv not in (1, SPOOL_SCHEMA_VERSION) or not isinstance(data.get("entries"), dict):
        return None
    raw_tombs = data.get("tombstones")
    if sv == SPOOL_SCHEMA_VERSION and "tombstones" in data and not isinstance(raw_tombs, dict):
        return None
    entries = {
        sid: {**{k: v[k] for k in _INDEX_KEYS if k in v}, "spool_id": sid, "workspace_id": str(v.get("workspace_id") or "")}
        for sid, v in data["entries"].items()
        if isinstance(sid, str) and SPOOL_ID_RE.fullmatch(sid) and isinstance(v, dict)
    }
    tombstones = (
        {
            sid: {
                "spool_id": sid,
                "reason": str(tv.get("reason") or "ttl_expired"),
                "evicted_at": float(tv.get("evicted_at") or 0.0),
                "workspace_id": str(tv.get("workspace_id") or ""),
                "session_id": str(tv.get("session_id") or ""),
                "total_bytes": max(0, int(tv.get("total_bytes") or 0)),
            }
            for sid, tv in raw_tombs.items()
            if isinstance(sid, str) and SPOOL_ID_RE.fullmatch(sid) and isinstance(tv, dict)
        }
        if isinstance(raw_tombs, dict)
        else {}
    )
    return {"schema_version": SPOOL_SCHEMA_VERSION, "entries": entries, "tombstones": tombstones}


def _open_index_unlocked(eff_dir: Path) -> dict[str, Any]:
    idx_path = eff_dir / "spool_index.json"
    raw_bytes, err = _read_blob_bytes(idx_path)
    if err == "spool_not_found":
        return {"schema_version": SPOOL_SCHEMA_VERSION, "entries": {}, "tombstones": {}}
    if err == "unsafe_path" and check_unsafe_link(idx_path):
        raise OSError("unsafe_path: spool_index.json")
    try:
        if raw_bytes is not None and (parsed := _parse_index(json.loads(raw_bytes.decode("utf-8")))) is not None:
            return parsed
    except (UnicodeDecodeError, ValueError) as exc:
        err = f"{type(exc).__name__}: {exc}"
    q_path = eff_dir / f".spool_index.corrupt.{os.getpid()}.json"
    try:
        os.replace(str(idx_path), str(q_path))
        state_store.warn(f"corrupt spool_index.json ({err or 'invalid schema'}) quarantined to {q_path.name}")
    except OSError as q_exc:
        state_store.warn(f"corrupt spool_index.json ({err or 'invalid schema'}) reset: {q_exc}")
    return {"schema_version": SPOOL_SCHEMA_VERSION, "entries": {}, "tombstones": {}}


def _save_index(eff_dir: Path, index: dict[str, Any]) -> None:
    atomic_write_bytes(eff_dir / "spool_index.json", json.dumps(index, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def resolve_spool_dir(state_dir: str | Path | None = None, *, env: Mapping[str, str] | None = None) -> Path:
    """Resolve spool directory: CONTEXT_GUARD_SPOOL_DIR -> state_dir/spool -> plugin telemetry/spool."""
    eff_env = env if env is not None else os.environ
    if (ov := str(eff_env.get("CONTEXT_GUARD_SPOOL_DIR") or "").strip()):
        return Path(ov).expanduser()
    return (Path(str(state_dir).strip()).expanduser() / "spool") if (state_dir is not None and str(state_dir).strip()) else (state_store.resolve_plugin_root() / "telemetry" / "spool")


def _strip_cd_and_split(cmd: str, *, raw_words: bool = False) -> list[str]:
    rem = cmd.strip()
    while (m := _LEADING_CD_RE.match(rem)):
        rem = m.group(1).strip()
    try:
        return [w.group(0) for w in _SHELL_WORD_RE.finditer(rem)] if raw_words else shlex.split(rem)
    except ValueError:
        return rem.split()


def compute_command_signature(tool_name: str, command_or_args: str | Mapping[str, Any]) -> str:
    """Compute canonical 16-hex SHA-256 signature for shell commands or MCP tool args."""
    if isinstance(command_or_args, Mapping):
        enc = json.dumps(command_or_args, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=lambda o: dict(o) if isinstance(o, Mapping) else str(o))
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


def _resolve_write_scope(
    *, isolation: str | None = None, workspace_root: str | Path | None = None,
    workspace_roots: Sequence[str] | None = None, session_id: str | None = None,
) -> tuple[str, str, str, str, str | None]:
    """Purely resolve `(mode, scope_key, workspace_id, session_id, error)`."""
    if isolation is None:
        mode, cfg_err = read_spool_isolation_config()
        if cfg_err is not None:
            return "", "", "", "", cfg_err
    elif not isinstance(isolation, str) or isolation not in VALID_SPOOL_ISOLATIONS:
        return "", "", "", "", "invalid_spool_config"
    else:
        mode = isolation
    eff_sess = session_id.strip() if isinstance(session_id, str) else ""
    if mode == "workspace":
        ws_id, _, ws_err = resolve_workspace_identity(workspace_root, workspace_roots=workspace_roots)
        if ws_err is not None:
            return "", "", "", eff_sess, ws_err
        scope_key, sc_err = compute_scope_key("workspace", workspace_id=ws_id)
        return (mode, scope_key, ws_id, eff_sess, sc_err) if sc_err is None else ("", "", "", eff_sess, sc_err)
    has_ws = (workspace_root is not None and str(workspace_root).strip() != "") or bool(workspace_roots)
    opt_ws_id = resolve_workspace_identity(workspace_root, workspace_roots=workspace_roots)[0] if has_ws else ""
    if mode == "session":
        scope_key, sc_err = compute_scope_key("session", session_id=eff_sess)
        return (mode, scope_key, opt_ws_id, eff_sess, sc_err) if sc_err is None else ("", "", "", eff_sess, sc_err)
    return "global", "global", opt_ws_id, eff_sess, None


def _entry_scope_error(record: Mapping[str, Any], mode: str, ws_id: str, sess_id: str) -> str | None:
    if mode == "workspace":
        return None if str(record.get("workspace_id") or "") == ws_id else "workspace_mismatch"
    if mode == "session":
        return None if str(record.get("session_id") or "") == sess_id else "session_mismatch"
    return None


def _project_in_memory(raw_text: str, *, scope_key: str = "global") -> tuple[str, int, bytes, str, str, int] | None:
    norm = raw_text.replace("\r\n", "\n").replace("\r", "\n") if isinstance(raw_text, str) else ""
    if not isinstance(raw_text, str) or "\x00" in norm or len((raw_bytes := norm.encode("utf-8"))) > SPOOL_MAX_BLOB_BYTES:
        return None
    lines, total_bytes = _split_lines(norm), len(raw_bytes)
    if total_bytes < SPOOL_MIN_BYTES and len(lines) < SPOOL_MIN_LINES:
        return None
    total_lines, sha_hex = len(lines), hashlib.sha256(raw_bytes).hexdigest()
    sid = compute_scoped_spool_id(scope_key, sha_hex)
    h, t, drop_h = min(SPOOL_HEAD_LINES, total_lines), min(SPOOL_TAIL_LINES, max(0, total_lines - SPOOL_HEAD_LINES)), True

    def _fmt(sv: int, hd: list[str], tl: list[str]) -> str:
        om = max(0, total_lines - h - t)
        return "\n".join([f"[CONTEXT-GUARD OUTPUT SPOOL: {sid} | {total_lines} lines, {total_bytes} B | sha256={sha_hex[:12]}]", f"Saved {sv} B. Inspect slices without re-running:", f"- CLI: cg-spool slice {sid} --start 1 --limit 120 | cg-spool grep {sid} --pattern '<regex>'", f"- MCP: cg_spool_slice / cg_spool_grep (spool_id={sid})"] + ([f"--- HEAD (lines 1..{len(hd)}) ---", *hd] if hd else []) + ([f"--- OMITTED ({om} lines; use cg-spool slice/grep) ---"] if om > 0 else []) + ([f"--- TAIL (lines {total_lines - len(tl) + 1}..{total_lines}) ---", *tl] if tl else []))

    while h + t > 1 and len(_fmt(total_bytes, lines[:h], lines[-t:] if t else []).encode("utf-8")) > SPOOL_SUMMARY_MAX_BYTES:
        t, h, drop_h = (t - 1, h, not drop_h) if (t > 0 and (not drop_h or h <= 1)) else (t, max(0, h - 1), not drop_h)
    hd, tl, suf = lines[:h], (lines[-t:] if t else []), "\n...[summary truncated]"
    if len(_fmt(total_bytes, hd, tl).encode("utf-8")) > SPOOL_SUMMARY_MAX_BYTES:
        avail = max(0, SPOOL_SUMMARY_MAX_BYTES - len(_fmt(total_bytes, [""] if lines else [], []).encode("utf-8")) - len(suf.encode("utf-8")))
        hd, tl = ([lines[0].encode("utf-8")[:avail].decode("utf-8", "ignore") + suf] if (lines and avail > 0) else []), []
    saved = max(0, total_bytes - len(_fmt(total_bytes, hd, tl).encode("utf-8")))
    summary = _fmt(saved, hd, tl)
    if len(summary.encode("utf-8")) > SPOOL_SUMMARY_MAX_BYTES:
        summary = summary.encode("utf-8")[: SPOOL_SUMMARY_MAX_BYTES - len(suf.encode("utf-8"))].decode("utf-8", "ignore") + suf
    return (sid, total_lines, raw_bytes, sha_hex, summary, saved) if (saved := max(0, total_bytes - len(summary.encode("utf-8")))) >= SPOOL_MIN_SAVED_BYTES else None


def _unlink_blob(path: Path, cutoff: float | None = None) -> int | None:
    try:
        if check_unsafe_link(path) or not path.is_file() or (cutoff is not None and path.stat().st_mtime >= cutoff):
            return None
        sz = path.stat().st_size
        path.unlink()
        return sz
    except OSError:
        return None


def _gc_entries_unlocked(eff_dir: Path, index: dict[str, Any], *, max_age: float, max_entries: int, max_bytes: int, now_ts: float, protect: str | None = None) -> tuple[int, int, bool]:
    entries, tombstones = index["entries"], index.setdefault("tombstones", {})
    evict_reasons: dict[str, str] = {}
    for s, ent in entries.items():
        if s == protect:
            continue
        blob = eff_dir / f"{s}.txt"
        if check_unsafe_link(blob) or not blob.is_file():
            evict_reasons[s] = "missing_blob"
        elif (now_ts - float(ent.get("last_accessed_at", ent.get("created_at", 0.0)))) > max_age:
            evict_reasons[s] = "ttl_expired"
    rem_c = len(entries) - len(evict_reasons)
    rem_b = sum(max(0, int(entries[s].get("total_bytes") or 0)) for s in entries if s not in evict_reasons)
    for sid in sorted((s for s in entries if s != protect and s not in evict_reasons), key=lambda s: (float(entries[s].get("last_accessed_at", 0.0)), float(entries[s].get("created_at", 0.0)), s)):
        if rem_c <= max(0, max_entries) and rem_b <= max(0, max_bytes):
            break
        evict_reasons[sid] = "max_entries_lru" if rem_c > max(0, max_entries) else "max_bytes_lru"
        rem_c, rem_b = rem_c - 1, rem_b - max(0, int(entries[sid].get("total_bytes") or 0))
    evicted_sizes: dict[str, int] = {}
    for sid, reason in evict_reasons.items():
        ent = entries.pop(sid)
        sz = max(0, int(ent.get("total_bytes") or 0))
        evicted_sizes[sid] = sz
        tombstones[sid] = {"spool_id": sid, "reason": reason, "evicted_at": now_ts, "workspace_id": str(ent.get("workspace_id") or ""), "session_id": str(ent.get("session_id") or ""), "total_bytes": sz}
    tomb_trimmed = False
    if len(tombstones) > SPOOL_MAX_TOMBSTONES:
        tomb_trimmed = True
        for old_sid in sorted(tombstones, key=lambda s: (float(tombstones[s].get("evicted_at", 0.0)), s))[: len(tombstones) - SPOOL_MAX_TOMBSTONES]:
            del tombstones[old_sid]
    # Two-phase GC: commit tombstones atomically BEFORE unlinking any .txt blob.
    dirty = bool(evict_reasons) or tomb_trimmed
    if dirty:
        _save_index(eff_dir, index)
    rc, rb = 0, 0
    for sid in evict_reasons:
        u = _unlink_blob(eff_dir / f"{sid}.txt")
        rc, rb = rc + 1, rb + (u if u is not None else evicted_sizes[sid])
    for item in eff_dir.iterdir():
        if (m := _BLOB_NAME_RE.fullmatch(item.name)) and (osid := m.group(1)) not in entries:
            cutoff = None if osid in tombstones else (now_ts - max_age)
            if (orphan_sz := _unlink_blob(item, cutoff)) is not None:
                rc, rb = rc + 1, rb + orphan_sz
    return rc, rb, dirty


def _spool_tool_output_with_receipt(
    raw_text: str, *, session_id: str, call_id: str, harness: str, tool_name: str, cmd_sig: str = "",
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    isolation: str | None = None, turn_key: str = "", upstream_truncation: bool = False,
    spool_dir: Path | None = None, receipts_path: Path | None = None, now_ts: float | None = None,
) -> tuple[SpoolContractV1, str, str | None] | None:
    _mode, scope_key, ws_id, _eff_sess, scope_err = _resolve_write_scope(isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id)
    if scope_err is not None or (proj := _project_in_memory(raw_text, scope_key=scope_key)) is None:
        return None
    sid, total_lines, raw_bytes, sha_hex, summary, saved = proj
    eff_dir, ts = spool_dir or resolve_spool_dir(), float(now_ts) if now_ts is not None else time.time()
    try:
        if check_unsafe_link(eff_dir) or check_unsafe_link((blob_path := eff_dir / f"{sid}.txt")) or check_unsafe_link(eff_dir / "spool_index.json"):
            state_store.warn(f"refusing symlink spool target: {sid}")
            return None
        eff_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(str(eff_dir), 0o700)
        with _spool_lock(eff_dir):
            atomic_write_bytes(blob_path, raw_bytes)
            index = _open_index_unlocked(eff_dir)
            index.setdefault("tombstones", {}).pop(sid, None)
            index["entries"][sid] = {"spool_id": sid, "filename": f"{sid}.txt", "workspace_id": ws_id, "session_id": str(session_id or ""), "call_id": str(call_id or ""), "harness": str(harness or ""), "tool_name": str(tool_name or ""), "cmd_sig": str(cmd_sig or ""), "total_lines": total_lines, "total_bytes": len(raw_bytes), "summary_bytes": len(summary.encode("utf-8")), "saved_bytes": saved, "content_sha256": sha_hex, "created_at": ts, "last_accessed_at": ts}
            _rc, _rb, saved_in_gc = _gc_entries_unlocked(eff_dir, index, max_age=SPOOL_TTL_SECONDS, max_entries=SPOOL_MAX_ENTRIES, max_bytes=SPOOL_TOTAL_BYTES_CAP, now_ts=ts, protect=sid)
            if not saved_in_gc:
                _save_index(eff_dir, index)
        # Lock ordering: release _spool_lock BEFORE acquiring receipts.lock in append_receipt.
        eff_rcpt = receipts_path or receipts_path_for(eff_dir)
        existing = find_created_receipt(sid, session_id=str(session_id or ""), call_id=str(call_id or ""), receipts_path=eff_rcpt)
        receipt_id: str | None = existing["receipt_id"] if existing is not None else None
        if receipt_id is None:
            rcpt = build_receipt(
                event_type="spool_created", harness=harness, session_id=str(session_id or ""), workspace_id=ws_id,
                turn_key=turn_key, call_id=str(call_id or ""), spool_id=sid, line_span=(0, total_lines),
                byte_span=(0, len(raw_bytes)), upstream_truncation=upstream_truncation, delivery_evidence="replacement_emitted",
                spool_id_referenced=False, timestamp=_ts_iso(now_ts),
            )
            if append_receipt(rcpt, receipts_path=eff_rcpt):
                receipt_id = rcpt["receipt_id"]
        return SpoolContractV1(spool_id=sid, path=str(blob_path), total_lines=total_lines, total_bytes=len(raw_bytes), content_sha256=sha_hex), summary, receipt_id
    except (OSError, ValueError) as exc:
        state_store.warn(f"spool_tool_output skipped ({type(exc).__name__}): {exc}")
        return None


def spool_tool_output(
    raw_text: str, *, session_id: str, call_id: str, harness: str, tool_name: str, cmd_sig: str = "",
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    isolation: str | None = None, turn_key: str = "", upstream_truncation: bool = False,
    spool_dir: Path | None = None, receipts_path: Path | None = None, now_ts: float | None = None,
) -> tuple[SpoolContractV1, str] | None:
    """Persist oversized normalized UTF-8 LF tool output and emit a `spool_created` receipt."""
    res = _spool_tool_output_with_receipt(
        raw_text, session_id=session_id, call_id=call_id, harness=harness, tool_name=tool_name, cmd_sig=cmd_sig,
        workspace_root=workspace_root, workspace_roots=workspace_roots, isolation=isolation, turn_key=turn_key,
        upstream_truncation=upstream_truncation, spool_dir=spool_dir, receipts_path=receipts_path, now_ts=now_ts,
    )
    return (res[0], res[1]) if res is not None else None


def _has_error_signal(payload: Mapping[str, Any], resp: Any) -> bool:
    return payload.get("hook_event_name") == "PostToolUseFailure" or str(payload.get("status") or "").lower() in ("error", "failed", "failure") or any(isinstance(o, Mapping) and (o.get("is_error") or o.get("isError") or o.get("error") or any(isinstance((v := o.get(k)), int) and not isinstance(v, bool) and v != 0 for k in ("exit_code", "exitCode", "return_code", "returncode"))) for o in (payload, resp))


def _extract_payload_text(harness: str, resp: Any, is_shell: bool) -> tuple[str | None, str | None]:
    if harness == "cursor" and isinstance(resp, str) and is_shell:
        try:
            resp = parsed if isinstance((parsed := json.loads(resp)), Mapping) else resp
        except ValueError:
            pass
    if isinstance(resp, str):
        return resp, "str"
    if isinstance(resp, Mapping):
        if harness == "cursor" and (resp.get("redacted") is True or _has_error_signal({}, resp)):
            return None, None
        return next(((resp[k], k) for k in (("text", "output", "content", "stdout") if harness == "cursor" else ("output", "stdout")) if isinstance(resp.get(k), str)), (None, None))
    return ("\n".join(b["text"] for b in resp), "blocks") if (isinstance(resp, list) and resp and all(isinstance(b, Mapping) and b.get("type") == "text" and isinstance(b.get("text"), str) for b in resp)) else (None, None)


def build_post_tool_spool_response(
    harness: str, payload: Mapping[str, Any], *, mode: str, session_id: str, call_id: str,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    isolation: str | None = None, turn_key: str = "", spool_dir: Path | None = None,
    receipts_path: Path | None = None, now_ts: float | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Build PostToolUse spool replacement or shadow projection `(hook_response, meta)`."""
    if mode not in ("active", "shadow"):
        return {}, None
    tc = payload.get("toolCall")
    tool_name = str(payload.get("tool_name") or (tc.get("name") if isinstance(tc, Mapping) else "") or "")
    raw_in: Mapping[str, Any] = payload["tool_input"] if isinstance(payload.get("tool_input"), Mapping) else (tc["args"] if isinstance(tc, Mapping) and isinstance(tc.get("args"), Mapping) else {})
    is_shell, rc = tool_name in _SHELL_TOOLS, (raw_in.get("command") or raw_in.get("cmd") or raw_in.get("CommandLine"))
    shell_cmd = rc if isinstance(rc, str) else (" ".join(str(x) for x in rc) if isinstance(rc, list) else "")
    inner, raw_resp = (str(raw_in.get("name") or raw_in.get("tool_name") or "") if tool_name == "call_mcp_tool" else tool_name), (payload.get("tool_output") if harness == "cursor" else payload.get("tool_response", payload.get("tool_output")))
    if not tool_name or tool_name in _SKIP_TOOLS or not (is_shell or tool_name.startswith(("mcp__", "MCP:")) or tool_name == "call_mcp_tool") or inner.rsplit("__", 1)[-1].rsplit(":", 1)[-1] in _SELF_MCP_LEAVES or (is_shell and _SELF_CLI_RE.search(shell_cmd)) or _has_error_signal(payload, raw_resp):
        return {}, None
    raw_text, shape = _extract_payload_text(harness, raw_resp, is_shell)
    if not isinstance(raw_text, str):
        return {}, None
    eff_ws_root = workspace_root if workspace_root is not None else (payload.get("cwd") if isinstance(payload.get("cwd"), (str, Path)) else None)
    raw_roots = payload.get("workspace_roots")
    eff_ws_roots = workspace_roots if workspace_roots is not None else (tuple(str(r) for r in raw_roots) if isinstance(raw_roots, (list, tuple)) else None)
    _mode, scope_key, ws_id, _sess, scope_err = _resolve_write_scope(isolation=isolation, workspace_root=eff_ws_root, workspace_roots=eff_ws_roots, session_id=session_id)
    if scope_err is not None:
        return {}, None
    if mode == "shadow":
        return ({}, None) if (p := _project_in_memory(raw_text, scope_key=scope_key)) is None else ({}, {"spool_id": p[0], "total_lines": p[1], "total_bytes": len(p[2]), "summary_bytes": len(p[4].encode("utf-8")), "saved_bytes": p[5], "harness": harness, "tool_name": tool_name, "workspace_id": ws_id})
    claude_ok = harness == "claude" and (tool_name == "Bash" or tool_name.startswith("mcp__")) and shape is not None
    up_trunc = bool(payload.get("truncated") or payload.get("is_truncated") or (isinstance(raw_resp, Mapping) and (raw_resp.get("truncated") or raw_resp.get("is_truncated"))))
    if not (claude_ok or (harness == "cursor" and tool_name.startswith(("MCP:", "mcp__")))) or (spooled := _spool_tool_output_with_receipt(raw_text, session_id=session_id, call_id=call_id, harness=harness, tool_name=tool_name, cmd_sig=(cs := compute_command_signature(tool_name, shell_cmd if is_shell else raw_in)), workspace_root=eff_ws_root, workspace_roots=eff_ws_roots, isolation=isolation, turn_key=turn_key, upstream_truncation=up_trunc, spool_dir=spool_dir, receipts_path=receipts_path, now_ts=now_ts)) is None:
        return {}, None
    contract, summary, receipt_id = spooled
    updated: Any = summary if shape == "str" else ([{"type": "text", "text": summary}] if shape == "blocks" else ({**raw_resp, str(shape): summary} if isinstance(raw_resp, Mapping) else summary))
    meta: dict[str, Any] = {"contract": contract, "spool_id": contract.spool_id, "workspace_id": ws_id, "total_lines": contract.total_lines, "total_bytes": contract.total_bytes, "summary_bytes": len(summary.encode("utf-8")), "saved_bytes": contract.total_bytes - len(summary.encode("utf-8")), "cmd_sig": cs}
    if receipt_id is not None:
        meta["receipt_id"] = receipt_id
    return ({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": updated}} if claude_ok else {"updated_mcp_tool_output": summary}), meta


def _touch_and_load_lines(
    spool_id: str, spool_dir: Path | None, now_ts: float | None, *,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None, isolation: str | None = None, harness: str = "cli",
    receipts_path: Path | None = None, on_reliability_failure: Callable[[], None] | None = None,
) -> tuple[list[str], int, str, str, dict[str, Any] | None]:
    if not isinstance(spool_id, str) or not SPOOL_ID_RE.fullmatch(spool_id):
        return [], 0, "", "", {"ok": False, "error": "invalid_spool_id"}
    mode, _sk, ws_id, eff_sess, scope_err = _resolve_write_scope(isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id)
    if scope_err is not None:
        return [], 0, ws_id, eff_sess, {"ok": False, "error": scope_err}
    eff_dir = spool_dir or resolve_spool_dir()
    blob_path = eff_dir / f"{spool_id}.txt"
    if check_unsafe_link(eff_dir) or check_unsafe_link(eff_dir / "spool_index.lock") or check_unsafe_link(eff_dir / "spool_index.json") or check_unsafe_link(blob_path):
        return [], 0, ws_id, eff_sess, {"ok": False, "error": "unsafe_path"}
    if not eff_dir.is_dir():
        return [], 0, ws_id, eff_sess, {"ok": False, "error": "spool_not_found"}

    integrity_fail, obs_bytes, entry_sess, entry_ws = False, 0, eff_sess, ws_id
    lines: list[str] = []
    early_err: dict[str, Any] | None = None
    try:
        with _spool_lock(eff_dir):
            index = _open_index_unlocked(eff_dir)
            entry = index["entries"].get(spool_id)
            if entry is None:
                tomb = index.get("tombstones", {}).get(spool_id)
                if tomb is not None and _entry_scope_error(tomb, mode, ws_id, eff_sess) is None:
                    early_err = {"ok": False, "error": "spool_evicted", "eviction_reason": tomb["reason"], "evicted_at": tomb["evicted_at"]}
                else:
                    early_err = {"ok": False, "error": "spool_not_found"}
            elif (mm_err := _entry_scope_error(entry, mode, ws_id, eff_sess)) is not None:
                early_err = {"ok": False, "error": mm_err}
            else:
                entry_sess = eff_sess or str(entry.get("session_id") or "")
                entry_ws = ws_id or str(entry.get("workspace_id") or "")
                raw_bytes, rerr = _read_blob_bytes(blob_path)
                if rerr == "unsafe_path":
                    early_err = {"ok": False, "error": "unsafe_path"}
                else:
                    obs_bytes = len(raw_bytes) if raw_bytes is not None else 0
                    exp_bytes, exp_sha = entry.get("total_bytes"), entry.get("content_sha256")
                    if raw_bytes is None or not isinstance(exp_bytes, int) or isinstance(exp_bytes, bool) or obs_bytes != exp_bytes or not isinstance(exp_sha, str) or not _SHA256_RE.fullmatch(exp_sha) or hashlib.sha256(raw_bytes).hexdigest() != exp_sha:
                        integrity_fail = True
                    else:
                        try:
                            text = raw_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            integrity_fail = True
                        else:
                            lines = _split_lines(text)
                            entry["last_accessed_at"] = float(now_ts) if now_ts is not None else time.time()
                            _save_index(eff_dir, index)
    except OSError as exc:
        return [], 0, entry_ws, entry_sess, {"ok": False, "error": "unsafe_path" if "unsafe_path" in str(exc) else str(exc)}

    if early_err is not None:
        return [], 0, entry_ws, entry_sess, early_err
    if integrity_fail:
        eff_rcpt = receipts_path or receipts_path_for(eff_dir)
        parent = find_created_receipt(spool_id, receipts_path=eff_rcpt)
        append_receipt(
            build_receipt(
                event_type="spool_integrity_failure", harness=harness, session_id=entry_sess, workspace_id=entry_ws,
                turn_key="", call_id="", spool_id=spool_id, line_span=(0, 0), byte_span=(0, obs_bytes),
                delivery_evidence="unverified", spool_id_referenced=True,
                parent_event_id=(parent["receipt_id"] if parent is not None else None),
                failure_kind="reliability_failure", reason="integrity_mismatch", timestamp=_ts_iso(now_ts),
            ),
            receipts_path=eff_rcpt,
        )
        if on_reliability_failure is not None:
            on_reliability_failure()
        return [], 0, entry_ws, entry_sess, {"ok": False, "error": "integrity_mismatch"}
    return lines, obs_bytes, entry_ws, entry_sess, None


def _emit_recovery_receipt(
    spool_id: str, eff_dir: Path, receipts_path: Path | None, *,
    harness: str, session_id: str, workspace_id: str,
    line_span: tuple[int, int], byte_span: tuple[int, int], now_ts: float | None,
) -> None:
    eff_rcpt = receipts_path or receipts_path_for(eff_dir)
    parent = find_created_receipt(spool_id, receipts_path=eff_rcpt)
    append_receipt(
        build_receipt(
            event_type="spool_recovery", harness=harness, session_id=session_id, workspace_id=workspace_id,
            turn_key="", call_id="", spool_id=spool_id, line_span=line_span, byte_span=byte_span,
            delivery_evidence="unverified", spool_id_referenced=True,
            parent_event_id=(parent["receipt_id"] if parent is not None else None), timestamp=_ts_iso(now_ts),
        ),
        receipts_path=eff_rcpt,
    )


def _byte_offset(lines: list[str], idx: int) -> int:
    return sum(len(lines[k].encode("utf-8")) + 1 for k in range(idx))


def slice_spool(
    spool_id: str, *, start_line: int = 1, limit: int = 120, end_line: int | None = None,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None, isolation: str | None = None, harness: str = "cli",
    receipts_path: Path | None = None, on_reliability_failure: Callable[[], None] | None = None,
    spool_dir: Path | None = None, now_ts: float | None = None,
) -> dict[str, Any]:
    """Read a bounded line slice from a spooled blob under lock and emit a recovery receipt."""
    lines, total_bytes, ws_id, eff_sess, err = _touch_and_load_lines(
        spool_id, spool_dir, now_ts, workspace_root=workspace_root, workspace_roots=workspace_roots,
        session_id=session_id, isolation=isolation, harness=harness,
        receipts_path=receipts_path, on_reliability_failure=on_reliability_failure,
    )
    if err is not None:
        return err
    total_lines, s_line = len(lines), max(1, int(start_line))
    e_clamped = min(total_lines, int(end_line) if end_line is not None else (s_line + max(1, int(limit)) - 1))
    sel = [] if (empty := total_lines == 0 or s_line > total_lines or e_clamped < s_line) else lines[s_line - 1 : e_clamped]
    content = "\n".join(sel)
    if empty:
        lspan, bspan = (0, 0), (0, 0)
    else:
        start_b = _byte_offset(lines, s_line - 1)
        lspan, bspan = (s_line - 1, e_clamped), (start_b, start_b + len(content.encode("utf-8")))
    _emit_recovery_receipt(
        spool_id, spool_dir or resolve_spool_dir(), receipts_path,
        harness=harness, session_id=eff_sess, workspace_id=ws_id,
        line_span=lspan, byte_span=bspan, now_ts=now_ts,
    )
    return {"ok": True, "spool_id": spool_id, "start_line": s_line, "end_line": (s_line - 1 if empty else e_clamped), "returned_lines": len(sel), "total_lines": total_lines, "total_bytes": total_bytes, "truncated": (False if empty else e_clamped < total_lines), "content": content}


def grep_spool(
    spool_id: str, pattern: str, *, ignore_case: bool = False, max_matches: int = 50, context_lines: int = 0,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None, isolation: str | None = None, harness: str = "cli",
    receipts_path: Path | None = None, on_reliability_failure: Callable[[], None] | None = None,
    spool_dir: Path | None = None, now_ts: float | None = None,
) -> dict[str, Any]:
    """Regex-search a spooled blob under lock and emit a recovery receipt."""
    if not isinstance(spool_id, str) or not SPOOL_ID_RE.fullmatch(spool_id):
        return {"ok": False, "error": "invalid_spool_id"}
    _mode, _sk, _ws, _sess, scope_err = _resolve_write_scope(isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id)
    if scope_err is not None:
        return {"ok": False, "error": scope_err}
    try:
        rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except (re.error, TypeError) as exc:
        return {"ok": False, "error": f"invalid_regex: {exc}"}
    lines, _tb, ws_id, eff_sess, err = _touch_and_load_lines(
        spool_id, spool_dir, now_ts, workspace_root=workspace_root, workspace_roots=workspace_roots,
        session_id=session_id, isolation=isolation, harness=harness,
        receipts_path=receipts_path, on_reliability_failure=on_reliability_failure,
    )
    if err is not None:
        return err
    eff_max, eff_ctx, truncated = max(1, min(200, int(max_matches))), max(0, min(10, int(context_lines))), False
    matches: list[dict[str, Any]] = []
    min_0, max_0 = len(lines), 0
    for idx, line_text in enumerate(lines):
        if rx.search(line_text):
            if (truncated := len(matches) >= eff_max):
                break
            b_start, a_end = max(0, idx - eff_ctx), min(len(lines), idx + 1 + eff_ctx)
            min_0, max_0 = min(min_0, b_start), max(max_0, a_end)
            matches.append({"line": idx + 1, "text": line_text, "before": lines[b_start:idx] if eff_ctx else [], "after": lines[idx + 1 : a_end] if eff_ctx else []})
    if not matches:
        lspan, bspan = (0, 0), (0, 0)
    else:
        b_end = _byte_offset(lines, max_0 - 1) + len(lines[max_0 - 1].encode("utf-8"))
        lspan, bspan = (min_0, max_0), (_byte_offset(lines, min_0), b_end)
    _emit_recovery_receipt(
        spool_id, spool_dir or resolve_spool_dir(), receipts_path,
        harness=harness, session_id=eff_sess, workspace_id=ws_id,
        line_span=lspan, byte_span=bspan, now_ts=now_ts,
    )
    return {"ok": True, "spool_id": spool_id, "pattern": pattern, "match_count": len(matches), "truncated": truncated, "total_lines": len(lines), "matches": matches}


def _check_dir(spool_dir: Path | None, empty: dict[str, Any]) -> tuple[Path | None, dict[str, Any] | None]:
    if not (eff_dir := spool_dir or resolve_spool_dir()).is_dir():
        return None, empty
    return (None, {"ok": False, "error": "unsafe_path"}) if (check_unsafe_link(eff_dir) or check_unsafe_link(eff_dir / "spool_index.json")) else (eff_dir, None)


def list_spools(
    *, session_id: str | None = None, workspace_root: str | Path | None = None,
    workspace_roots: Sequence[str] | None = None, isolation: str | None = None, spool_dir: Path | None = None,
) -> dict[str, Any]:
    """List scope-authorized spooled entries newest-first with zero filesystem paths."""
    mode, _sk, ws_id, eff_sess, scope_err = _resolve_write_scope(isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id)
    if scope_err is not None:
        return {"ok": False, "error": scope_err}
    eff_dir, early = _check_dir(spool_dir, {"ok": True, "count": 0, "total_bytes": 0, "entries": []})
    if eff_dir is None:
        return early or {}
    with _spool_lock(eff_dir):
        entries = sorted(
            (
                dict(e)
                for e in _open_index_unlocked(eff_dir)["entries"].values()
                if _entry_scope_error(e, mode, ws_id, eff_sess) is None and (session_id is None or e.get("session_id") == session_id)
            ),
            key=lambda e: (-float(e.get("created_at", 0.0)), str(e.get("spool_id", ""))),
        )
    return {"ok": True, "count": len(entries), "total_bytes": sum(max(0, int(e.get("total_bytes") or 0)) for e in entries), "entries": entries}


def gc_spools(*, max_age_seconds: float = SPOOL_TTL_SECONDS, max_entries: int = SPOOL_MAX_ENTRIES, max_total_bytes: int = SPOOL_TOTAL_BYTES_CAP, spool_dir: Path | None = None, now_ts: float | None = None) -> dict[str, Any]:
    """Evict expired, missing, orphan, and LRU spool blobs with two-phase tombstone commit."""
    eff_dir, early = _check_dir(spool_dir, {"ok": True, "removed_count": 0, "removed_bytes": 0, "remaining_count": 0, "remaining_bytes": 0})
    if eff_dir is None:
        return early or {}
    with _spool_lock(eff_dir):
        index = _open_index_unlocked(eff_dir)
        rc, rb, _dirty = _gc_entries_unlocked(eff_dir, index, max_age=max_age_seconds, max_entries=max_entries, max_bytes=max_total_bytes, now_ts=(float(now_ts) if now_ts is not None else time.time()))
        return {"ok": True, "removed_count": rc, "removed_bytes": rb, "remaining_count": len(index["entries"]), "remaining_bytes": sum(max(0, int(e.get("total_bytes") or 0)) for e in index["entries"].values())}


def _ro_index_state(eff_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], bool]:
    try:
        rb, _ = (None, "u") if check_unsafe_link(eff_dir) else _read_blob_bytes(eff_dir / "spool_index.json")
        parsed = _parse_index(json.loads(rb.decode("utf-8"))) if rb is not None else None
        return (parsed["entries"], parsed["tombstones"], True) if parsed else ({}, {}, False)
    except (OSError, UnicodeDecodeError, ValueError, TypeError):
        return {}, {}, False


def _eval_followup(
    sid: str, kind: str, eff_dir: Path, mode: str, ws_id: str, sess_id: str,
    s_l: int = 1, e_l: int | None = None, lim: int | None = None, default_lim: int | None = None,
) -> dict[str, Any] | None:
    entries, tombstones, idx_valid = _ro_index_state(eff_dir)
    ent = entries.get(sid)
    if ent is not None:
        if _entry_scope_error(ent, mode, ws_id, sess_id) is not None:
            return None
    elif (tomb := tombstones.get(sid)) is not None:
        if _entry_scope_error(tomb, mode, ws_id, sess_id) is not None:
            return None
    req_lines = max(1, e_l - s_l + 1) if (e_l is not None and e_l >= s_l) else (max(1, lim) if (lim is not None and lim >= 1) else default_lim)
    full = kind == "direct_read" and req_lines is None
    if not full and kind != "grep" and req_lines is not None and req_lines > 200:
        total: int | None = None
        if ent and isinstance(ent.get("total_lines"), int) and not isinstance(ent.get("total_lines"), bool) and ent["total_lines"] > 0:
            total = int(ent["total_lines"])
        elif not idx_valid and (rb := _read_blob_bytes(eff_dir / f"{sid}.txt")[0]) is not None:
            try:
                total = len(_split_lines(rb.decode("utf-8")))
            except UnicodeDecodeError:
                return None
        full = total is not None and total > 0 and min(req_lines, max(0, total - max(1, s_l) + 1)) > max(200, 0.8 * total)
    return {"spool_id": sid, "kind": kind, "recovery": "full" if full else "targeted", "regret": "suspected" if full else "none", "evidence": "observed", "requested_lines": req_lines}


def _match_blob_path(raw_path: str, eff_dir: Path) -> str | None:
    norm = raw_path.strip().replace("\\", "/")
    try:
        return m.group(1) if (m := _BLOB_NAME_RE.fullmatch(norm.rsplit("/", 1)[-1])) and (f"/spool/{m.group(1)}.txt" in norm or os.path.realpath(os.path.dirname(os.path.abspath(raw_path.strip()))) == os.path.realpath(str(eff_dir))) else None
    except OSError:
        return None


def _opt_int(val: Any) -> int | None:
    return int(val) if isinstance(val, int) and not isinstance(val, bool) else None


def _cli_int(tokens: list[str], flag: str) -> int | None:
    return next((int(t[len(flag) + 1 :]) if t.startswith(f"{flag}=") else int(tokens[i + 1]) for i, t in enumerate(tokens) if (t.startswith(f"{flag}=") and t[len(flag) + 1 :].isdigit()) or (t == flag and i + 1 < len(tokens) and tokens[i + 1].isdigit())), None)


def classify_pre_tool_spool_followup(
    tool_name: str, tool_input: Mapping[str, Any], *, spool_dir: Path | None = None,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None, isolation: str | None = None,
) -> dict[str, Any] | None:
    """Pure read-only PreToolUse classifier for spool slice/grep/direct-read follow-ups."""
    try:
        mode, _sk, ws_id, eff_sess, scope_err = _resolve_write_scope(isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id)
        if scope_err is not None or not isinstance(tool_input, Mapping):
            return None
        eff_dir = spool_dir or resolve_spool_dir()
        if tool_name in ("call_mcp_tool", "cg_spool_slice", "cg_spool_grep") or tool_name.startswith(("mcp__", "MCP:", "mcp_")):
            leaf = (str(tool_input.get("name") or tool_input.get("tool_name") or tool_name) if tool_name == "call_mcp_tool" else tool_name).rsplit("__", 1)[-1].rsplit(":", 1)[-1]
            args = (tool_input.get("arguments") or tool_input.get("args") or tool_input) if tool_name == "call_mcp_tool" else tool_input
            if isinstance(args, Mapping) and SPOOL_ID_RE.fullmatch((sid := str(args.get("spool_id") or "").strip())) and leaf in ("cg_spool_grep", "cg_spool_slice"):
                return _eval_followup(sid, "grep" if leaf == "cg_spool_grep" else "slice", eff_dir, mode, ws_id, eff_sess, max(1, _opt_int(args.get("start_line")) or 1), _opt_int(args.get("end_line")), _opt_int(args.get("limit")), 120)
        elif tool_name in ("Read", "read_file", "view_file") and (msid := _match_blob_path(str(tool_input.get("file_path") or tool_input.get("path") or tool_input.get("Path") or tool_input.get("AbsolutePath") or ""), eff_dir)):
            return _eval_followup(msid, "direct_read", eff_dir, mode, ws_id, eff_sess, max(1, _opt_int(tool_input.get("StartLine") if "StartLine" in tool_input else tool_input.get("offset")) or 1), _opt_int(tool_input.get("EndLine")), _opt_int(tool_input.get("limit")))
        elif tool_name in _SHELL_TOOLS:
            rc = tool_input.get("command") or tool_input.get("cmd") or tool_input.get("CommandLine")
            tokens = _strip_cd_and_split(rc if isinstance(rc, str) else (" ".join(str(x) for x in rc) if isinstance(rc, list) else ""))
            if (cg := next((i for i, t in enumerate(tokens) if re.sub(r"\.(?:exe|cmd|bat)$", "", t.replace("\\", "/").rsplit("/", 1)[-1].lower()) in ("cg-spool", "cg_spool.py")), -1)) >= 0 and cg + 1 < len(tokens) and tokens[cg + 1] in ("grep", "slice") and (csid := next((t for t in tokens[cg + 2 :] if SPOOL_ID_RE.fullmatch(t)), "")):
                return _eval_followup(csid, "grep" if tokens[cg + 1] == "grep" else "slice", eff_dir, mode, ws_id, eff_sess, max(1, _cli_int(tokens[cg + 2 :], "--start") or 1), _cli_int(tokens[cg + 2 :], "--end"), _cli_int(tokens[cg + 2 :], "--limit"), 120)
            if tokens and (cmd_bin := tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()) in _READER_BINS and (rsid := next((m for t in tokens[1:] if (m := _match_blob_path(t, eff_dir)) is not None), None)):
                s_l, req = 1, (max(1, val) if (val := _cli_int(tokens[1:], "--lines") or _cli_int(tokens[1:], "-n") or next((int(mm.group(1)) for t in tokens[1:] if (mm := re.fullmatch(r"-n?(\d+)", t))), None)) is not None else 10) if cmd_bin in ("head", "tail") else None
                if cmd_bin == "sed" and (ms := next((mm for t in tokens[1:] if (mm := re.fullmatch(r"(\d+),(\d+)p", t))), None)):
                    s_l, req = max(1, int(ms.group(1))), max(1, int(ms.group(2)) - max(1, int(ms.group(1))) + 1)
                return _eval_followup(rsid, "direct_read", eff_dir, mode, ws_id, eff_sess, s_l, lim=req)
    except (OSError, ValueError, TypeError):
        pass
    return None


def inspect_spool_health(spool_dir: Path | None = None, *, receipts_path: Path | None = None, now_ts: float | None = None) -> dict[str, Any]:
    """Pure read-only spool health summary for `cg_status --doctor` (no locks/writes/warnings)."""
    eff_dir = spool_dir or resolve_spool_dir()
    rcpt_summary = summarize_receipts(receipts_path or receipts_path_for(eff_dir), now_ts=now_ts)
    verified, rel_fail = int(rcpt_summary["delivery_verified_count"]), int(rcpt_summary["integrity_failures"])
    if not eff_dir.is_dir() or check_unsafe_link(eff_dir):
        return {
            "spool_dir_exists": False, "entry_count": 0, "total_bytes": 0, "expired_count": 0, "orphan_count": 0,
            "eviction_count": 0, "receipts": rcpt_summary, "delivery_verified": verified, "reliability_failures": rel_fail,
            "summary_line": "0 entries, 0 B (dir absent)",
        }
    ts = float(now_ts) if now_ts is not None else time.time()
    entries, tombstones, _valid = _ro_index_state(eff_dir)
    total_b = sum(max(0, int(e.get("total_bytes") or 0)) for e in entries.values())
    expired = sum(1 for e in entries.values() if (ts - float(e.get("last_accessed_at", e.get("created_at", 0.0)))) > SPOOL_TTL_SECONDS)
    evicted = len(tombstones)
    try:
        orphans = sum(1 for item in eff_dir.iterdir() if (m := _BLOB_NAME_RE.fullmatch(item.name)) and m.group(1) not in entries and not check_unsafe_link(item) and item.is_file())
    except OSError:
        orphans = 0
    return {
        "spool_dir_exists": True, "entry_count": len(entries), "total_bytes": total_b, "expired_count": expired,
        "orphan_count": orphans, "eviction_count": evicted, "receipts": rcpt_summary,
        "delivery_verified": verified, "reliability_failures": rel_fail,
        "summary_line": f"{len(entries)} entries, {total_b} B ({expired} expired, {orphans} orphans, {evicted} evicted, {verified} verified, {rel_fail} integrity failures)",
    }
