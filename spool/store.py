"""Content-addressed reversible output spooling, non-blocking verified recovery, and three-phase GC."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import errno, hashlib, json, os, re, stat, time, uuid
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from hooks import state_store
from policies.api import SpoolContractV1
from spool.classifier import (
    SPOOL_ID_RE, classify_pre_tool_spool_followup, compute_command_signature, entry_scope_error,
    is_verbose_override_command, parse_spool_index, read_blob_bytes, resolve_spool_scope, split_lines,
)
from spool.receipts import (
    DEFAULT_MAX_SPOOL_ENTRY_BYTES, append_receipt, atomic_write_bytes, build_receipt, check_unsafe_link,
    compute_scoped_spool_id, find_created_receipt, read_spool_config, receipts_path_for, summarize_receipts,
)

SPOOL_SCHEMA_VERSION, SPOOL_MAX_TOMBSTONES, SPOOL_MAX_CORRUPT_ENTRIES = 2, 128, 64
SPOOL_TTL_SECONDS, SPOOL_TOMBSTONE_MAX_AGE_SECONDS = 86_400.0, 7 * 86_400.0
SPOOL_MIN_BYTES, SPOOL_MIN_LINES, SPOOL_MIN_SAVED_BYTES = 12_288, 200, 2_048
SPOOL_MAX_BLOB_BYTES, SPOOL_MAX_ENTRIES, SPOOL_TOTAL_BYTES_CAP = DEFAULT_MAX_SPOOL_ENTRY_BYTES, 64, 32 * 1024 * 1024
SPOOL_HEAD_LINES, SPOOL_TAIL_LINES, SPOOL_SUMMARY_MAX_BYTES = 25, 15, 3_072

_SHA256_RE, _BLOB_NAME_RE = re.compile(r"^[0-9a-f]{64}$"), re.compile(r"^(sp_[0-9a-f]{12})\.txt$")
_SKIP_TOOLS = frozenset({
    "Read", "NotebookRead", "read_file", "view_file", "view_file_outline", "view_code_item", "Glob", "glob",
    "Grep", "grep_search", "find_by_name", "Edit", "Write", "MultiEdit", "NotebookEdit", "EditFile", "WriteFile",
    "StrReplace", "MultiStrReplace", "Delete", "DeleteFile", "edit_file", "write_file",
    "replace_file_content", "multi_replace_file_content", "write_to_file", "apply_patch",
})
_SHELL_TOOLS = frozenset({"Bash", "Shell", "run_command", "run_terminal_cmd", "shell", "exec", "exec_command"})
_SELF_MCP_LEAVES = frozenset({"cg_spool_slice", "cg_spool_grep", "cg_spool_list"})
_SELF_CLI_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:cg-spool(?:\.(?:exe|cmd|bat))?|cg_spool\.py)(?![A-Za-z0-9_-])", re.I)
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _ts_iso(now_ts: float | None) -> str | None:
    return datetime.fromtimestamp(float(now_ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if now_ts is not None else None

def _safe_unlink(path: Path) -> None:
    try: path.unlink(missing_ok=True)
    except OSError: pass

@contextmanager
def _spool_lock(eff_dir: Path) -> Iterator[None]:
    lp = eff_dir / "spool_index.lock"
    if check_unsafe_link(lp):
        raise OSError("unsafe_path: spool_index.lock")
    with os.fdopen(os.open(str(lp), os.O_RDWR | os.O_CREAT | _O_FLAGS, 0o600), "a+", encoding="utf-8") as fh:
        if os.name != "nt":
            os.chmod(str(lp), 0o600)
        state_store.fcntl.flock(fh.fileno(), state_store.fcntl.LOCK_EX)
        try: yield
        finally: state_store.fcntl.flock(fh.fileno(), state_store.fcntl.LOCK_UN)

def _open_index_unlocked(eff_dir: Path) -> dict[str, Any]:
    idx_path = eff_dir / "spool_index.json"
    raw_bytes, err = read_blob_bytes(idx_path)
    if err == "spool_not_found":
        return {"schema_version": SPOOL_SCHEMA_VERSION, "entries": {}, "tombstones": {}}
    if err == "unsafe_path" and check_unsafe_link(idx_path):
        raise OSError("unsafe_path: spool_index.json")
    try:
        if raw_bytes is not None and (parsed := parse_spool_index(json.loads(raw_bytes.decode("utf-8")))) is not None:
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

def _resolve_write_cfg(
    *, isolation: str | None = None, workspace_root: str | Path | None = None,
    workspace_roots: Sequence[str] | None = None, session_id: str | None = None, max_spool_entry_bytes: int | None = None,
) -> tuple[str, str, str, str, str, int, str | None]:
    if max_spool_entry_bytes is not None:
        if isinstance(max_spool_entry_bytes, bool) or not isinstance(max_spool_entry_bytes, int) or max_spool_entry_bytes < 1:
            return "", "", "", "", "", DEFAULT_MAX_SPOOL_ENTRY_BYTES, "invalid_spool_config"
        eff_max = max_spool_entry_bytes
        if isolation is None:
            cfg_iso, _cm, cfg_err = read_spool_config()
            if cfg_err is not None: return "", "", "", "", "", eff_max, cfg_err
            isolation = cfg_iso
    else:
        cfg_iso, cfg_max, cfg_err = read_spool_config()
        if isolation is None:
            if cfg_err is not None: return "", "", "", "", "", DEFAULT_MAX_SPOOL_ENTRY_BYTES, cfg_err
            isolation = cfg_iso
        eff_max = cfg_max if cfg_err is None else DEFAULT_MAX_SPOOL_ENTRY_BYTES
    mode, sk, ws_id, cr, sess, serr = resolve_spool_scope(isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id)
    return mode, sk, ws_id, cr, sess, eff_max, serr

def _validate_and_normalize(raw_text: Any, eff_max_bytes: int) -> tuple[str, bytes] | None:
    if eff_max_bytes < 1 or not isinstance(raw_text, (str, bytes)):
        return None
    if isinstance(raw_text, bytes):
        if len(raw_text) > eff_max_bytes * 2: return None
        try: raw_str = raw_text.decode("utf-8", errors="strict")
        except UnicodeDecodeError: return None
    else:
        raw_str = raw_text
    if len(raw_str) > eff_max_bytes * 2 or "\x00" in raw_str:
        return None
    norm = raw_str.replace("\r\n", "\n").replace("\r", "\n")
    try: raw_bytes = norm.encode("utf-8", errors="strict")
    except UnicodeEncodeError: return None
    return (norm, raw_bytes) if len(raw_bytes) <= eff_max_bytes else None

def _build_summary(sid: str, lines: list[str], total_bytes: int, sha_hex: str) -> tuple[str, int] | None:
    total_lines = len(lines)
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
    return (summary, fs) if (fs := max(0, total_bytes - len(summary.encode("utf-8")))) >= SPOOL_MIN_SAVED_BYTES else None

def _project_in_memory(raw_text: str | bytes, *, scope_key: str = "global", max_bytes: int = DEFAULT_MAX_SPOOL_ENTRY_BYTES) -> tuple[str, list[str], bytes, str, str, int] | None:
    if (vn := _validate_and_normalize(raw_text, max_bytes)) is None:
        return None
    norm, raw_bytes = vn
    total_bytes, lines = len(raw_bytes), split_lines(norm)
    if total_bytes < SPOOL_MIN_BYTES and len(lines) < SPOOL_MIN_LINES:
        return None
    sha_hex = hashlib.sha256(raw_bytes).hexdigest()
    sid = compute_scoped_spool_id(scope_key, sha_hex)
    return (sid, lines, raw_bytes, sha_hex, built[0], built[1]) if (built := _build_summary(sid, lines, total_bytes, sha_hex)) is not None else None

def _unlink_blob(path: Path, cutoff: float | None = None) -> tuple[int | None, bool]:
    try:
        if check_unsafe_link(path): return None, False
        if not path.exists(): return None, True
        if not path.is_file() or (cutoff is not None and path.stat().st_mtime >= cutoff): return None, False
        sz = path.stat().st_size
        path.unlink()
        return sz, True
    except FileNotFoundError: return None, True
    except (PermissionError, OSError): return None, False

def _prune_evicted_tombstones(tombstones: dict[str, dict[str, Any]], now_ts: float) -> bool:
    dirty = False
    for old_sid in [s for s, t in tombstones.items() if t.get("state", "evicted") == "evicted" and (now_ts - float(t.get("evicted_at", 0.0))) > SPOOL_TOMBSTONE_MAX_AGE_SECONDS]:
        del tombstones[old_sid]; dirty = True
    if len(tombstones) > SPOOL_MAX_TOMBSTONES:
        evicted = sorted((s for s, t in tombstones.items() if t.get("state", "evicted") == "evicted"), key=lambda s: (float(tombstones[s].get("evicted_at", 0.0)), s))
        for old_sid in evicted[: len(tombstones) - SPOOL_MAX_TOMBSTONES]:
            del tombstones[old_sid]; dirty = True
    return dirty

def _gc_phase1_unlocked(
    eff_dir: Path, index: dict[str, Any], *, max_age: float, max_entries: int, max_bytes: int, now_ts: float, protect: str | None = None,
) -> tuple[list[tuple[str, int]], set[str], bool]:
    entries, tombstones, dirty = index["entries"], index.setdefault("tombstones", {}), False
    for s, ent in entries.items():
        if s == protect or ent.get("state", "available") != "available": continue
        if check_unsafe_link(blob := eff_dir / f"{s}.txt") or not blob.is_file():
            ent["state"], ent["corrupt_reason"], ent["corrupted_at"], dirty = "corrupt", ("unsafe_path" if check_unsafe_link(blob) else "unexpectedly_missing"), now_ts, True
    for old_c in [s for s, e in entries.items() if e.get("state") == "corrupt" and (now_ts - float(e.get("corrupted_at", e.get("created_at", 0.0)))) > SPOOL_TOMBSTONE_MAX_AGE_SECONDS]:
        del entries[old_c]; dirty = True
    corrupt_sids = sorted((s for s, e in entries.items() if e.get("state") == "corrupt"), key=lambda s: (float(entries[s].get("corrupted_at", entries[s].get("created_at", 0.0))), s))
    for old_c in corrupt_sids[: max(0, len(corrupt_sids) - SPOOL_MAX_CORRUPT_ENTRIES)]:
        del entries[old_c]; dirty = True
    avail_sids = [s for s, e in entries.items() if e.get("state", "available") == "available"]
    evict_reasons = {s: "ttl_expired" for s in avail_sids if s != protect and (now_ts - float(entries[s].get("last_accessed_at", entries[s].get("created_at", 0.0)))) > max_age}
    rem_c = sum(1 for s in avail_sids if s not in evict_reasons)
    rem_b = sum(max(0, int(entries[s].get("total_bytes") or 0)) for s in avail_sids if s not in evict_reasons)
    for sid in sorted((s for s in avail_sids if s != protect and s not in evict_reasons), key=lambda s: (float(entries[s].get("last_accessed_at", 0.0)), float(entries[s].get("created_at", 0.0)), s)):
        if rem_c <= max(0, max_entries) and rem_b <= max(0, max_bytes): break
        evict_reasons[sid] = "max_entries_lru" if rem_c > max(0, max_entries) else "max_bytes_lru"
        rem_c, rem_b = rem_c - 1, rem_b - max(0, int(entries[sid].get("total_bytes") or 0))
    for sid, reason in evict_reasons.items():
        ent = entries.pop(sid)
        tombstones[sid] = {
            "spool_id": sid, "state": "evicting", "reason": reason, "evicted_at": now_ts,
            "workspace_id": str(ent.get("workspace_id") or ""), "session_id": str(ent.get("session_id") or ""),
            "total_bytes": max(0, int(ent.get("total_bytes") or 0)),
            **({"canon_root": ent["canon_root"]} if isinstance(ent.get("canon_root"), str) and ent["canon_root"].strip() else {}),
        }
        dirty = True
    dirty = _prune_evicted_tombstones(tombstones, now_ts) or dirty
    return [(sid, max(0, int(t.get("total_bytes") or 0))) for sid, t in tombstones.items() if t.get("state") == "evicting"], set(entries) | set(tombstones), dirty

def _ro_known_sids(eff_dir: Path) -> set[str]:
    rb, _ = (None, "u") if check_unsafe_link(eff_dir) else read_blob_bytes(eff_dir / "spool_index.json")
    try:
        parsed = parse_spool_index(json.loads(rb.decode("utf-8"))) if rb is not None else None
        return (set(parsed["entries"]) | set(parsed["tombstones"])) if parsed else set()
    except (UnicodeDecodeError, ValueError, TypeError): return set()

def _run_gc_post_lock(eff_dir: Path, evicting_targets: Sequence[tuple[str, int]], known_sids: set[str], *, cutoff: float, now_ts: float) -> tuple[int, int, dict[str, Any] | None]:
    rc, rb, completed = 0, 0, []
    for sid, fallback_sz in evicting_targets:
        u_sz, done = _unlink_blob(eff_dir / f"{sid}.txt")
        if done:
            completed.append(sid)
            rc, rb = rc + 1, rb + (u_sz if u_sz is not None else fallback_sz)
    try: items = list(eff_dir.iterdir())
    except OSError: items = []
    ro_known: set[str] | None = None
    for item in items:
        if not (m := _BLOB_NAME_RE.fullmatch(item.name)) or (osid := m.group(1)) in known_sids: continue
        try:
            if check_unsafe_link(item) or not item.is_file() or item.stat().st_mtime >= cutoff: continue
        except OSError: continue
        if ro_known is None: ro_known = _ro_known_sids(eff_dir)
        if osid not in ro_known and (u_sz := _unlink_blob(item, cutoff=cutoff)[0]) is not None:
            rc, rb = rc + 1, rb + u_sz
    if not completed:
        return rc, rb, None
    with _spool_lock(eff_dir):
        index = _open_index_unlocked(eff_dir)
        tombstones, dirty = index.setdefault("tombstones", {}), False
        for sid in completed:
            if isinstance((tomb := tombstones.get(sid)), dict) and tomb.get("state") == "evicting":
                tomb["state"], dirty = "evicted", True
        if _prune_evicted_tombstones(tombstones, now_ts) or dirty:
            _save_index(eff_dir, index)
        return rc, rb, index

def _write_temp_spool(eff_dir: Path, raw_bytes: bytes) -> Path:
    tmp_path = eff_dir / f".tmp.{os.getpid()}.{uuid.uuid4().hex[:12]}.spool"
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_FLAGS, 0o600)
    try: fh = os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd); _safe_unlink(tmp_path); raise
    try:
        with fh: fh.write(raw_bytes)
        if os.name != "nt": os.chmod(str(tmp_path), 0o600)
        return tmp_path
    except BaseException:
        _safe_unlink(tmp_path); raise

def _spool_tool_output_with_receipt(
    raw_text: str | bytes, *, session_id: str, call_id: str, harness: str, tool_name: str, cmd_sig: str = "",
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    isolation: str | None = None, turn_key: str = "", upstream_truncation: bool = False,
    spool_dir: Path | None = None, receipts_path: Path | None = None, now_ts: float | None = None,
    max_spool_entry_bytes: int | None = None, turn_correlation: str = "unobserved",
    hook_duration_ms: float | None = None, event_id: str | None = None,
) -> tuple[SpoolContractV1, str, str | None] | None:
    _m, scope_key, ws_id, canon_root, _s, eff_max, scope_err = _resolve_write_cfg(
        isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id, max_spool_entry_bytes=max_spool_entry_bytes,
    )
    if scope_err is not None or (proj := _project_in_memory(raw_text, scope_key=scope_key, max_bytes=eff_max)) is None:
        return None
    base_sid, lines, raw_bytes, sha_hex, summary, saved = proj
    eff_dir, ts = spool_dir or resolve_spool_dir(), float(now_ts) if now_ts is not None else time.time()
    tmp_path: Path | None = None
    blob_path, replaced_blob, manifest_committed, reused_blob = eff_dir / f"{base_sid}.txt", False, False, False
    try:
        if check_unsafe_link(eff_dir) or check_unsafe_link(eff_dir / "spool_index.json") or check_unsafe_link(eff_dir / "spool_index.lock"):
            state_store.warn(f"refusing symlink spool target: {base_sid}"); return None
        eff_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt": os.chmod(str(eff_dir), 0o700)
        tmp_path, sid = _write_temp_spool(eff_dir, raw_bytes), base_sid
        with _spool_lock(eff_dir):
            index = _open_index_unlocked(eff_dir)
            entries, tombstones = index["entries"], index.setdefault("tombstones", {})
            base_ent = entries.get(base_sid)
            if isinstance(base_ent, dict) and base_ent.get("state", "available") == "available" and base_ent.get("content_sha256") == sha_hex and base_ent.get("total_bytes") == len(raw_bytes) and not check_unsafe_link(blob_path) and blob_path.is_file():
                reused_blob, base_ent["last_accessed_at"] = True, ts
                if canon_root and not str(base_ent.get("canon_root") or "").strip(): base_ent["canon_root"] = canon_root
            else:
                gen = 0
                while sid in entries or sid in tombstones or os.path.lexists(str(eff_dir / f"{sid}.txt")):
                    gen += 1
                    sid = compute_scoped_spool_id(f"{scope_key}:gen:{gen}", sha_hex)
                blob_path = eff_dir / f"{sid}.txt"
                if check_unsafe_link(blob_path): raise OSError(f"unsafe_path: {sid}")
                os.replace(str(tmp_path), str(blob_path))
                replaced_blob = True
                entries[sid] = {
                    "spool_id": sid, "filename": f"{sid}.txt", "workspace_id": ws_id, "canon_root": canon_root,
                    "session_id": str(session_id or ""), "call_id": str(call_id or ""), "harness": str(harness or ""),
                    "tool_name": str(tool_name or ""), "cmd_sig": str(cmd_sig or ""), "total_lines": len(lines),
                    "total_bytes": len(raw_bytes), "summary_bytes": len(summary.encode("utf-8")), "saved_bytes": saved,
                    "content_sha256": sha_hex, "created_at": ts, "last_accessed_at": ts, "state": "available",
                }
            evicting_targets, known_sids, _d = _gc_phase1_unlocked(eff_dir, index, max_age=SPOOL_TTL_SECONDS, max_entries=SPOOL_MAX_ENTRIES, max_bytes=SPOOL_TOTAL_BYTES_CAP, now_ts=ts, protect=sid)
            _save_index(eff_dir, index)
            manifest_committed = True
    except (OSError, ValueError) as exc:
        if tmp_path is not None: _safe_unlink(tmp_path)
        if replaced_blob and not manifest_committed: _safe_unlink(blob_path)
        state_store.warn(f"spool_tool_output skipped ({type(exc).__name__}): {exc}")
        return None
    if reused_blob and tmp_path is not None: _safe_unlink(tmp_path)
    if sid != base_sid and (rebuilt := _build_summary(sid, lines, len(raw_bytes), sha_hex)) is not None: summary = rebuilt[0]
    try: _run_gc_post_lock(eff_dir, evicting_targets, known_sids, cutoff=(ts - SPOOL_TTL_SECONDS), now_ts=ts)
    except OSError: pass
    # Lock ordering: release _spool_lock BEFORE acquiring receipts.lock in append_receipt.
    eff_rcpt = receipts_path or receipts_path_for(eff_dir)
    existing = find_created_receipt(sid, session_id=str(session_id or ""), call_id=str(call_id or ""), receipts_path=eff_rcpt)
    if existing is not None and (event_id is None or existing["event_id"] == event_id):
        receipt_id: str | None = existing["receipt_id"]
    else:
        rcpt = build_receipt(
            event_type="spool_created", harness=harness, session_id=str(session_id or ""), workspace_id=ws_id,
            turn_key=turn_key, call_id=str(call_id or ""), spool_id=sid, line_span=(0, len(lines)),
            byte_span=(0, len(raw_bytes)), upstream_truncation=upstream_truncation, delivery_evidence="replacement_emitted",
            spool_id_referenced=False, timestamp=_ts_iso(now_ts), event_id=event_id, hook_duration_ms=hook_duration_ms,
            turn_correlation=turn_correlation, source_hash=sha_hex, original_bytes=len(raw_bytes), replacement_bytes=len(summary.encode("utf-8")),
        )
        receipt_id = rcpt["receipt_id"] if append_receipt(rcpt, receipts_path=eff_rcpt) else None
    return SpoolContractV1(spool_id=sid, path=str(blob_path), total_lines=len(lines), total_bytes=len(raw_bytes), content_sha256=sha_hex), summary, receipt_id

def spool_tool_output(
    raw_text: str | bytes, *, session_id: str, call_id: str, harness: str, tool_name: str, cmd_sig: str = "",
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    isolation: str | None = None, turn_key: str = "", upstream_truncation: bool = False,
    spool_dir: Path | None = None, receipts_path: Path | None = None, now_ts: float | None = None,
    max_spool_entry_bytes: int | None = None, turn_correlation: str = "unobserved",
    hook_duration_ms: float | None = None, event_id: str | None = None,
) -> tuple[SpoolContractV1, str] | None:
    """Persist oversized normalized UTF-8 LF tool output and emit a `spool_created` receipt."""
    res = _spool_tool_output_with_receipt(
        raw_text, session_id=session_id, call_id=call_id, harness=harness, tool_name=tool_name, cmd_sig=cmd_sig,
        workspace_root=workspace_root, workspace_roots=workspace_roots, isolation=isolation, turn_key=turn_key,
        upstream_truncation=upstream_truncation, spool_dir=spool_dir, receipts_path=receipts_path, now_ts=now_ts,
        max_spool_entry_bytes=max_spool_entry_bytes, turn_correlation=turn_correlation, hook_duration_ms=hook_duration_ms, event_id=event_id,
    )
    return (res[0], res[1]) if res is not None else None

def _has_error_signal(payload: Mapping[str, Any], resp: Any) -> bool:
    return payload.get("hook_event_name") == "PostToolUseFailure" or str(payload.get("status") or "").lower() in ("error", "failed", "failure") or any(isinstance(o, Mapping) and (o.get("is_error") or o.get("isError") or o.get("error") or any(isinstance((v := o.get(k)), int) and not isinstance(v, bool) and v != 0 for k in ("exit_code", "exitCode", "return_code", "returncode"))) for o in (payload, resp))

def _extract_payload_text(harness: str, resp: Any, is_shell: bool) -> tuple[str | bytes | None, str | None]:
    if harness == "cursor" and isinstance(resp, str) and is_shell:
        try: resp = parsed if isinstance((parsed := json.loads(resp)), Mapping) else resp
        except ValueError: pass
    if isinstance(resp, (str, bytes)):
        return resp, ("bytes" if isinstance(resp, bytes) else "str")
    if isinstance(resp, Mapping):
        if harness == "cursor" and (resp.get("redacted") is True or _has_error_signal({}, resp)): return None, None
        keys = ("text", "output", "content", "stdout") if harness == "cursor" else ("output", "stdout")
        return next(((resp[k], k) for k in keys if isinstance(resp.get(k), (str, bytes))), (None, None))
    return ("\n".join(b["text"] for b in resp), "blocks") if (isinstance(resp, list) and resp and all(isinstance(b, Mapping) and b.get("type") == "text" and isinstance(b.get("text"), str) for b in resp)) else (None, None)

def build_post_tool_spool_response(
    harness: str, payload: Mapping[str, Any], *, mode: str, session_id: str, call_id: str,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    isolation: str | None = None, turn_key: str = "", spool_dir: Path | None = None,
    receipts_path: Path | None = None, now_ts: float | None = None,
    raw_text: str | bytes | None = None, max_spool_entry_bytes: int | None = None,
    turn_correlation: str = "unobserved", hook_duration_ms: float | None = None, event_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Build PostToolUse spool replacement or shadow projection `(hook_response, meta)`."""
    if mode not in ("active", "shadow"): return {}, None
    tc = payload.get("toolCall")
    tool_name = str(payload.get("tool_name") or (tc.get("name") if isinstance(tc, Mapping) else "") or "")
    raw_in: Mapping[str, Any] = payload["tool_input"] if isinstance(payload.get("tool_input"), Mapping) else (tc["args"] if isinstance(tc, Mapping) and isinstance(tc.get("args"), Mapping) else {})
    is_shell, rc = tool_name in _SHELL_TOOLS, (raw_in.get("command") or raw_in.get("cmd") or raw_in.get("CommandLine"))
    shell_cmd = rc if isinstance(rc, str) else (" ".join(str(x) for x in rc) if isinstance(rc, list) else "")
    inner, raw_resp = (str(raw_in.get("name") or raw_in.get("tool_name") or "") if tool_name == "call_mcp_tool" else tool_name), (payload.get("tool_output") if harness == "cursor" else payload.get("tool_response", payload.get("tool_output")))
    if not tool_name or tool_name in _SKIP_TOOLS or not (is_shell or tool_name.startswith(("mcp__", "MCP:")) or tool_name == "call_mcp_tool") or inner.rsplit("__", 1)[-1].rsplit(":", 1)[-1] in _SELF_MCP_LEAVES or (is_shell and _SELF_CLI_RE.search(shell_cmd)) or _has_error_signal(payload, raw_resp):
        return {}, None
    ext_text, shape = _extract_payload_text(harness, raw_resp, is_shell)
    eff_raw: str | bytes | None = raw_text if raw_text is not None else ext_text
    if not isinstance(eff_raw, (str, bytes)): return {}, None
    if raw_text is not None and shape is None: shape = "bytes" if isinstance(raw_text, bytes) else "str"
    eff_ws_root = workspace_root if workspace_root is not None else (payload.get("cwd") if isinstance(payload.get("cwd"), (str, Path)) else None)
    eff_ws_roots = workspace_roots if workspace_roots is not None else (tuple(str(r) for r in raw_roots) if isinstance((raw_roots := payload.get("workspace_roots")), (list, tuple)) else None)
    _m, scope_key, ws_id, _cr, _s, eff_max, scope_err = _resolve_write_cfg(isolation=isolation, workspace_root=eff_ws_root, workspace_roots=eff_ws_roots, session_id=session_id, max_spool_entry_bytes=max_spool_entry_bytes)
    if scope_err is not None: return {}, None
    if mode == "shadow":
        return ({}, None) if (p := _project_in_memory(eff_raw, scope_key=scope_key, max_bytes=eff_max)) is None else ({}, {"spool_id": p[0], "total_lines": len(p[1]), "total_bytes": len(p[2]), "summary_bytes": len(p[4].encode("utf-8")), "saved_bytes": p[5], "harness": harness, "tool_name": tool_name, "workspace_id": ws_id})
    claude_ok = harness == "claude" and (tool_name == "Bash" or tool_name.startswith("mcp__")) and shape is not None
    up_trunc = bool(payload.get("truncated") or payload.get("is_truncated") or (isinstance(raw_resp, Mapping) and (raw_resp.get("truncated") or raw_resp.get("is_truncated"))))
    if not (claude_ok or (harness == "cursor" and tool_name.startswith(("MCP:", "mcp__")))) or (spooled := _spool_tool_output_with_receipt(
        eff_raw, session_id=session_id, call_id=call_id, harness=harness, tool_name=tool_name,
        cmd_sig=(cs := compute_command_signature(tool_name, shell_cmd if is_shell else raw_in)),
        workspace_root=eff_ws_root, workspace_roots=eff_ws_roots, isolation=isolation, turn_key=turn_key,
        upstream_truncation=up_trunc, spool_dir=spool_dir, receipts_path=receipts_path, now_ts=now_ts,
        max_spool_entry_bytes=eff_max, turn_correlation=turn_correlation, hook_duration_ms=hook_duration_ms, event_id=event_id,
    )) is None:
        return {}, None
    contract, summary, receipt_id = spooled
    updated: Any = summary if shape in ("str", "bytes") else ([{"type": "text", "text": summary}] if shape == "blocks" else ({**raw_resp, str(shape): summary} if isinstance(raw_resp, Mapping) else summary))
    meta: dict[str, Any] = {"contract": contract, "spool_id": contract.spool_id, "workspace_id": ws_id, "total_lines": contract.total_lines, "total_bytes": contract.total_bytes, "summary_bytes": len(summary.encode("utf-8")), "saved_bytes": contract.total_bytes - len(summary.encode("utf-8")), "cmd_sig": cs}
    if receipt_id is not None: meta["receipt_id"] = receipt_id
    return ({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": updated}} if claude_ok else {"updated_mcp_tool_output": summary}), meta

def _open_blob_fd_locked(blob_path: Path) -> tuple[int | None, dict[str, Any] | None, bool]:
    if check_unsafe_link(blob_path): return None, {"ok": False, "error": "unsafe_path"}, False
    try: raw_fd = os.open(str(blob_path), os.O_RDONLY | _O_FLAGS)
    except FileNotFoundError: return None, None, True
    except OSError as exc: return None, {"ok": False, "error": "unsafe_path" if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)) else str(exc)}, False
    try:
        if stat.S_ISREG(os.fstat(raw_fd).st_mode): return raw_fd, None, False
        os.close(raw_fd); return None, {"ok": False, "error": "unsafe_path"}, False
    except OSError as exc:
        os.close(raw_fd); return None, {"ok": False, "error": str(exc)}, False

def _read_fd_and_verify(fd: int, exp_bytes: Any, exp_sha: Any) -> tuple[list[str], int, str | None, str | None]:
    try: fh = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd); raise
    try:
        with fh: raw_bytes = fh.read()
    except OSError as exc:
        return [], 0, None, str(exc)
    obs = len(raw_bytes)
    if not isinstance(exp_bytes, int) or isinstance(exp_bytes, bool) or obs != exp_bytes or not isinstance(exp_sha, str) or not _SHA256_RE.fullmatch(exp_sha) or hashlib.sha256(raw_bytes).hexdigest() != exp_sha:
        return [], obs, "integrity_mismatch", None
    try: return split_lines(raw_bytes.decode("utf-8", errors="strict")), obs, None, None
    except UnicodeDecodeError: return [], obs, "format_error", None

def _update_available_entry_locked(eff_dir: Path, spool_id: str, updates: Mapping[str, Any]) -> None:
    try:
        with _spool_lock(eff_dir):
            if isinstance((cur := (idx := _open_index_unlocked(eff_dir))["entries"].get(spool_id)), dict) and cur.get("state", "available") == "available":
                cur.update(updates)
                _save_index(eff_dir, idx)
    except OSError:
        pass

def _touch_and_load_lines(
    spool_id: str, spool_dir: Path | None, now_ts: float | None, *,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None, isolation: str | None = None, harness: str = "cli",
    receipts_path: Path | None = None, on_reliability_failure: Callable[[], None] | None = None,
    turn_key: str = "", turn_correlation: str = "unobserved", call_id: str = "",
) -> tuple[list[str], int, str, str, str, dict[str, Any] | None]:
    if not isinstance(spool_id, str) or not SPOOL_ID_RE.fullmatch(spool_id):
        return [], 0, "", "", "", {"ok": False, "error": "invalid_spool_id"}
    mode, _sk, ws_id, canon_root, eff_sess, scope_err = resolve_spool_scope(isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id)
    if scope_err is not None: return [], 0, ws_id, eff_sess, "", {"ok": False, "error": scope_err}
    eff_dir, blob_path = (sd := spool_dir or resolve_spool_dir()), sd / f"{spool_id}.txt"
    if check_unsafe_link(eff_dir) or check_unsafe_link(eff_dir / "spool_index.lock") or check_unsafe_link(eff_dir / "spool_index.json") or check_unsafe_link(blob_path):
        return [], 0, ws_id, eff_sess, "", {"ok": False, "error": "unsafe_path"}
    if not eff_dir.is_dir(): return [], 0, ws_id, eff_sess, "", {"ok": False, "error": "spool_not_found"}

    eff_now = float(now_ts) if now_ts is not None else time.time()
    entry_sess, entry_ws, exp_bytes, exp_sha = eff_sess, ws_id, None, None
    fd, early_err, fail_reason, marked_step1 = None, None, None, False
    try:
        with _spool_lock(eff_dir):
            index = _open_index_unlocked(eff_dir)
            entry = index["entries"].get(spool_id)
            if entry is None:
                tomb = index.get("tombstones", {}).get(spool_id)
                early_err = {"ok": False, "error": "spool_evicted", "eviction_reason": tomb["reason"], "evicted_at": tomb["evicted_at"]} if (tomb is not None and entry_scope_error(tomb, mode, ws_id, eff_sess, caller_canon_root=canon_root) is None) else {"ok": False, "error": "spool_not_found"}
            elif (mm_err := entry_scope_error(entry, mode, ws_id, eff_sess, caller_canon_root=canon_root)) is not None:
                early_err = {"ok": False, "error": mm_err}
            elif (st_val := entry.get("state", "available")) == "corrupt":
                early_err = {"ok": False, "error": "spool_corrupt", "corrupt_reason": str(entry.get("corrupt_reason") or "integrity_mismatch")}
            elif st_val == "preparing":
                early_err = {"ok": False, "error": "spool_not_found"}
            else:
                entry_sess, entry_ws, exp_bytes, exp_sha = eff_sess or str(entry.get("session_id") or ""), ws_id or str(entry.get("workspace_id") or ""), entry.get("total_bytes"), entry.get("content_sha256")
                fd, early_err, missing = _open_blob_fd_locked(blob_path)
                if missing:
                    entry["state"], entry["corrupt_reason"], entry["corrupted_at"] = "corrupt", "unexpectedly_missing", eff_now
                    _save_index(eff_dir, index)
                    fail_reason, marked_step1 = "unexpectedly_missing", True
    except OSError as exc:
        return [], 0, entry_ws, entry_sess, "", {"ok": False, "error": "unsafe_path" if "unsafe_path" in str(exc) else str(exc)}

    if early_err is not None: return [], 0, entry_ws, entry_sess, "", early_err
    obs_bytes, lines = 0, []  # type: tuple[int, list[str]]
    if fd is not None:
        lines, obs_bytes, fail_reason, io_err = _read_fd_and_verify(fd, exp_bytes, exp_sha)
        if io_err is not None: return [], 0, entry_ws, entry_sess, "", {"ok": False, "error": io_err}
    if fail_reason is not None:
        if not marked_step1:
            _update_available_entry_locked(eff_dir, spool_id, {"state": "corrupt", "corrupt_reason": fail_reason, "corrupted_at": eff_now})
        eff_rcpt = receipts_path or receipts_path_for(eff_dir)
        parent = find_created_receipt(spool_id, receipts_path=eff_rcpt)
        append_receipt(
            build_receipt(
                event_type="spool_integrity_failure", harness=harness, session_id=entry_sess, workspace_id=entry_ws,
                turn_key=turn_key, call_id=call_id, spool_id=spool_id, line_span=(0, 0), byte_span=(0, obs_bytes),
                delivery_evidence="unverified", spool_id_referenced=True, parent_event_id=(parent["receipt_id"] if parent is not None else None),
                failure_kind="reliability_failure", reason=fail_reason, timestamp=_ts_iso(now_ts),
                turn_correlation=turn_correlation, source_hash=(exp_sha if isinstance(exp_sha, str) else ""),
            ),
            receipts_path=eff_rcpt,
        )
        if on_reliability_failure is not None: on_reliability_failure()
        return [], obs_bytes, entry_ws, entry_sess, "", {"ok": False, "error": fail_reason}
    _update_available_entry_locked(eff_dir, spool_id, {"last_accessed_at": eff_now})
    return lines, obs_bytes, entry_ws, entry_sess, str(exp_sha or ""), None

def _emit_recovery_receipt(
    spool_id: str, eff_dir: Path, receipts_path: Path | None, *, harness: str, session_id: str, workspace_id: str,
    line_span: tuple[int, int], byte_span: tuple[int, int], now_ts: float | None,
    turn_key: str = "", turn_correlation: str = "unobserved", call_id: str = "", source_hash: str = "",
) -> None:
    eff_rcpt = receipts_path or receipts_path_for(eff_dir)
    parent = find_created_receipt(spool_id, receipts_path=eff_rcpt)
    append_receipt(
        build_receipt(
            event_type="spool_recovery", harness=harness, session_id=session_id, workspace_id=workspace_id,
            turn_key=turn_key, call_id=call_id, spool_id=spool_id, line_span=line_span, byte_span=byte_span,
            delivery_evidence="unverified", spool_id_referenced=True, parent_event_id=(parent["receipt_id"] if parent is not None else None),
            timestamp=_ts_iso(now_ts), turn_correlation=turn_correlation, source_hash=source_hash,
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
    turn_key: str = "", turn_correlation: str = "unobserved", call_id: str = "",
) -> dict[str, Any]:
    """Read a bounded verified line slice from a spooled blob and emit a recovery receipt."""
    lines, total_bytes, ws_id, eff_sess, exp_sha, err = _touch_and_load_lines(
        spool_id, spool_dir, now_ts, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id,
        isolation=isolation, harness=harness, receipts_path=receipts_path, on_reliability_failure=on_reliability_failure,
        turn_key=turn_key, turn_correlation=turn_correlation, call_id=call_id,
    )
    if err is not None: return err
    total_lines, s_line = len(lines), max(1, int(start_line))
    e_clamped = min(total_lines, int(end_line) if end_line is not None else (s_line + max(1, int(limit)) - 1))
    sel = [] if (empty := total_lines == 0 or s_line > total_lines or e_clamped < s_line) else lines[s_line - 1 : e_clamped]
    content = "\n".join(sel)
    lspan, bspan = ((0, 0), (0, 0)) if empty else ((s_line - 1, e_clamped), (sb := _byte_offset(lines, s_line - 1), sb + len(content.encode("utf-8"))))
    _emit_recovery_receipt(
        spool_id, spool_dir or resolve_spool_dir(), receipts_path, harness=harness, session_id=eff_sess,
        workspace_id=ws_id, line_span=lspan, byte_span=bspan, now_ts=now_ts, turn_key=turn_key,
        turn_correlation=turn_correlation, call_id=call_id, source_hash=exp_sha,
    )
    return {"ok": True, "spool_id": spool_id, "start_line": s_line, "end_line": (s_line - 1 if empty else e_clamped), "returned_lines": len(sel), "total_lines": total_lines, "total_bytes": total_bytes, "truncated": (False if empty else e_clamped < total_lines), "content": content}

def grep_spool(
    spool_id: str, pattern: str, *, ignore_case: bool = False, max_matches: int = 50, context_lines: int = 0,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None, isolation: str | None = None, harness: str = "cli",
    receipts_path: Path | None = None, on_reliability_failure: Callable[[], None] | None = None,
    spool_dir: Path | None = None, now_ts: float | None = None,
    turn_key: str = "", turn_correlation: str = "unobserved", call_id: str = "",
) -> dict[str, Any]:
    """Regex-search a verified spooled blob and emit a recovery receipt."""
    if not isinstance(spool_id, str) or not SPOOL_ID_RE.fullmatch(spool_id): return {"ok": False, "error": "invalid_spool_id"}
    _m, _sk, _ws, _cr, _s, scope_err = resolve_spool_scope(isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id)
    if scope_err is not None: return {"ok": False, "error": scope_err}
    try: rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except (re.error, TypeError) as exc: return {"ok": False, "error": f"invalid_regex: {exc}"}
    lines, _tb, ws_id, eff_sess, exp_sha, err = _touch_and_load_lines(
        spool_id, spool_dir, now_ts, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id,
        isolation=isolation, harness=harness, receipts_path=receipts_path, on_reliability_failure=on_reliability_failure,
        turn_key=turn_key, turn_correlation=turn_correlation, call_id=call_id,
    )
    if err is not None: return err
    eff_max, eff_ctx, truncated, min_0, max_0 = max(1, min(200, int(max_matches))), max(0, min(10, int(context_lines))), False, len(lines), 0
    matches: list[dict[str, Any]] = []
    for idx, line_text in enumerate(lines):
        if rx.search(line_text):
            if (truncated := len(matches) >= eff_max): break
            b_start, a_end = max(0, idx - eff_ctx), min(len(lines), idx + 1 + eff_ctx)
            min_0, max_0 = min(min_0, b_start), max(max_0, a_end)
            matches.append({"line": idx + 1, "text": line_text, "before": lines[b_start:idx] if eff_ctx else [], "after": lines[idx + 1 : a_end] if eff_ctx else []})
    lspan, bspan = ((0, 0), (0, 0)) if not matches else ((min_0, max_0), (_byte_offset(lines, min_0), _byte_offset(lines, max_0 - 1) + len(lines[max_0 - 1].encode("utf-8"))))
    _emit_recovery_receipt(
        spool_id, spool_dir or resolve_spool_dir(), receipts_path, harness=harness, session_id=eff_sess,
        workspace_id=ws_id, line_span=lspan, byte_span=bspan, now_ts=now_ts, turn_key=turn_key,
        turn_correlation=turn_correlation, call_id=call_id, source_hash=exp_sha,
    )
    return {"ok": True, "spool_id": spool_id, "pattern": pattern, "match_count": len(matches), "truncated": truncated, "total_lines": len(lines), "matches": matches}

def _check_dir(spool_dir: Path | None, empty: dict[str, Any]) -> tuple[Path | None, dict[str, Any] | None]:
    if not (eff_dir := spool_dir or resolve_spool_dir()).is_dir(): return None, empty
    return (None, {"ok": False, "error": "unsafe_path"}) if (check_unsafe_link(eff_dir) or check_unsafe_link(eff_dir / "spool_index.json")) else (eff_dir, None)

def list_spools(
    *, session_id: str | None = None, workspace_root: str | Path | None = None,
    workspace_roots: Sequence[str] | None = None, isolation: str | None = None, spool_dir: Path | None = None,
) -> dict[str, Any]:
    """List scope-authorized available spooled entries newest-first with zero filesystem paths."""
    mode, _sk, ws_id, canon_root, eff_sess, scope_err = resolve_spool_scope(isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id)
    if scope_err is not None: return {"ok": False, "error": scope_err}
    eff_dir, early = _check_dir(spool_dir, {"ok": True, "count": 0, "total_bytes": 0, "entries": []})
    if eff_dir is None: return early or {}
    with _spool_lock(eff_dir):
        entries = sorted(
            (
                {k: v for k, v in e.items() if k != "canon_root"}
                for e in _open_index_unlocked(eff_dir)["entries"].values()
                if e.get("state", "available") == "available" and entry_scope_error(e, mode, ws_id, eff_sess, caller_canon_root=canon_root) is None and (session_id is None or e.get("session_id") == session_id)
            ),
            key=lambda e: (-float(e.get("created_at", 0.0)), str(e.get("spool_id", ""))),
        )
    return {"ok": True, "count": len(entries), "total_bytes": sum(max(0, int(e.get("total_bytes") or 0)) for e in entries), "entries": entries}

def gc_spools(
    *, max_age_seconds: float = SPOOL_TTL_SECONDS, max_entries: int = SPOOL_MAX_ENTRIES,
    max_total_bytes: int = SPOOL_TOTAL_BYTES_CAP, spool_dir: Path | None = None, now_ts: float | None = None,
) -> dict[str, Any]:
    """Evict expired, corrupt-prune, orphan, and LRU spool blobs with three-phase GC outside lock."""
    eff_dir, early = _check_dir(spool_dir, {"ok": True, "removed_count": 0, "removed_bytes": 0, "remaining_count": 0, "remaining_bytes": 0})
    if eff_dir is None: return early or {}
    eff_now = float(now_ts) if now_ts is not None else time.time()
    with _spool_lock(eff_dir):
        index = _open_index_unlocked(eff_dir)
        evicting_targets, known_sids, dirty = _gc_phase1_unlocked(eff_dir, index, max_age=max_age_seconds, max_entries=max_entries, max_bytes=max_total_bytes, now_ts=eff_now)
        if dirty: _save_index(eff_dir, index)
        final_index = index
    rc, rb, updated_idx = _run_gc_post_lock(eff_dir, evicting_targets, known_sids, cutoff=(eff_now - max_age_seconds), now_ts=eff_now)
    if updated_idx is not None: final_index = updated_idx
    avail = [e for e in final_index["entries"].values() if e.get("state", "available") == "available"]
    return {"ok": True, "removed_count": rc, "removed_bytes": rb, "remaining_count": len(avail), "remaining_bytes": sum(max(0, int(e.get("total_bytes") or 0)) for e in avail)}

def inspect_spool_health(spool_dir: Path | None = None, *, receipts_path: Path | None = None, now_ts: float | None = None) -> dict[str, Any]:
    """Pure read-only spool health summary for `cg_status --doctor` (no locks/writes/warnings)."""
    eff_dir = spool_dir or resolve_spool_dir()
    rcpt_summary = summarize_receipts(receipts_path or receipts_path_for(eff_dir), now_ts=now_ts)
    verified, rel_fail = int(rcpt_summary["delivery_verified_count"]), int(rcpt_summary["integrity_failures"])
    if not eff_dir.is_dir() or check_unsafe_link(eff_dir):
        return {"spool_dir_exists": False, "entry_count": 0, "total_bytes": 0, "expired_count": 0, "orphan_count": 0, "eviction_count": 0, "receipts": rcpt_summary, "delivery_verified": verified, "reliability_failures": rel_fail, "summary_line": "0 entries, 0 B (dir absent)"}
    ts, rb = float(now_ts) if now_ts is not None else time.time(), read_blob_bytes(eff_dir / "spool_index.json")[0]
    try: parsed = parse_spool_index(json.loads(rb.decode("utf-8"))) if rb is not None else None
    except (UnicodeDecodeError, ValueError, TypeError): parsed = None
    entries, tombstones = (parsed["entries"], parsed["tombstones"]) if parsed else ({}, {})
    avail = [e for e in entries.values() if e.get("state", "available") == "available"]
    total_b, expired, evicted = sum(max(0, int(e.get("total_bytes") or 0)) for e in avail), sum(1 for e in avail if (ts - float(e.get("last_accessed_at", e.get("created_at", 0.0)))) > SPOOL_TTL_SECONDS), len(tombstones)
    try: orphans = sum(1 for item in eff_dir.iterdir() if (m := _BLOB_NAME_RE.fullmatch(item.name)) and m.group(1) not in entries and not check_unsafe_link(item) and item.is_file())
    except OSError: orphans = 0
    return {"spool_dir_exists": True, "entry_count": len(avail), "total_bytes": total_b, "expired_count": expired, "orphan_count": orphans, "eviction_count": evicted, "receipts": rcpt_summary, "delivery_verified": verified, "reliability_failures": rel_fail, "summary_line": f"{len(avail)} entries, {total_b} B ({expired} expired, {orphans} orphans, {evicted} evicted, {verified} verified, {rel_fail} integrity failures)"}
