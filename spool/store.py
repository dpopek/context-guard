"""Content-addressed reversible output spooling, non-blocking verified recovery, and three-phase GC."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable, Iterator, Mapping, Sequence
import uuid

from core.contracts import SpoolDecision
from core.platform_io import (
    LOCK_EX, LOCK_UN, atomic_write_bytes, check_unsafe_link, flock, resolve_plugin_root, warn,
)
from policies.api import SpoolContractV1
from policies.governor import is_optimizer_tripped, record_governor_signal
from spool.classifier import (
    GcEvictionPolicy, SPOOL_ID_RE, build_spool_summary, classify_pre_tool_spool_followup,
    compute_command_signature, entry_scope_error, format_spooled_tool_output,
    inspect_spool_entry_readonly, inspect_spool_health_readonly, is_verbose_override_command,
    parse_spool_index, plan_gc_evictions, prepare_post_tool_spool_candidate, project_spool_in_memory,
    read_blob_bytes, read_spool_index_readonly, resolve_spool_scope, slice_verified_lines, split_lines,
)
from spool.gc import (
    DedupQuery, GcPostLockOptions, find_dedup_candidate, is_dedup_entry_match, matches_stat_identity,
    probe_blob_identity, run_gc_post_lock, safe_unlink, verify_existing_blob_for_dedup,
)
from spool.receipts import (
    DEFAULT_MAX_SPOOL_ENTRY_BYTES, append_receipt, build_receipt, compute_scoped_spool_id,
    enrich_receipt, find_created_receipt, read_spool_config, receipts_path_for,
)
from spool.spans import grep_lines_with_spans, measure_raw_source_bytes

SPOOL_SCHEMA_VERSION = 2
SPOOL_MAX_TOMBSTONES, SPOOL_MAX_CORRUPT_ENTRIES = 128, 64
SPOOL_TTL_SECONDS, SPOOL_TOMBSTONE_MAX_AGE_SECONDS = 86_400.0, 7 * 86_400.0
SPOOL_MIN_BYTES, SPOOL_MIN_LINES, SPOOL_MIN_SAVED_BYTES = 12_288, 200, 2_048
SPOOL_MAX_BLOB_BYTES = DEFAULT_MAX_SPOOL_ENTRY_BYTES
SPOOL_MAX_ENTRIES, SPOOL_TOTAL_BYTES_CAP = 64, 32 * 1024 * 1024
SPOOL_HEAD_LINES, SPOOL_TAIL_LINES, SPOOL_SUMMARY_MAX_BYTES = 25, 15, 3_072

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _ts_iso(now_ts: float | None) -> str | None:
    if now_ts is None:
        return None
    return datetime.fromtimestamp(float(now_ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def _spool_lock(eff_dir: Path) -> Iterator[None]:
    lp = eff_dir / "spool_index.lock"
    if check_unsafe_link(lp):
        raise OSError("unsafe_path: spool_index.lock")
    with os.fdopen(os.open(str(lp), os.O_RDWR | os.O_CREAT | _O_FLAGS, 0o600), "a+", encoding="utf-8") as fh:
        if os.name != "nt":
            os.chmod(str(lp), 0o600)
        flock(fh.fileno(), LOCK_EX)
        try:
            yield
        finally:
            flock(fh.fileno(), LOCK_UN)


def _open_index_unlocked(eff_dir: Path) -> dict[str, Any]:
    idx_path = eff_dir / "spool_index.json"
    raw_bytes, err = read_blob_bytes(idx_path)
    if err == "spool_not_found":
        return {"schema_version": SPOOL_SCHEMA_VERSION, "id_epoch": 0, "entries": {}, "tombstones": {}}
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
        warn(f"corrupt spool_index.json ({err or 'invalid schema'}) quarantined to {q_path.name}")
    except OSError as q_exc:
        warn(f"corrupt spool_index.json ({err or 'invalid schema'}) reset: {q_exc}")
    return {"schema_version": SPOOL_SCHEMA_VERSION, "id_epoch": 0, "entries": {}, "tombstones": {}}


def _save_index(eff_dir: Path, index: dict[str, Any]) -> None:
    payload = json.dumps(index, separators=(",", ":"), sort_keys=True).encode("utf-8")
    atomic_write_bytes(eff_dir / "spool_index.json", payload)


def resolve_spool_dir(state_dir: str | Path | None = None, *, env: Mapping[str, str] | None = None) -> Path:
    """Resolve spool directory: CONTEXT_GUARD_SPOOL_DIR -> state_dir/spool -> plugin telemetry/spool."""
    eff_env = env if env is not None else os.environ
    if (ov := str(eff_env.get("CONTEXT_GUARD_SPOOL_DIR") or "").strip()):
        return Path(ov).expanduser()
    if state_dir is not None and str(state_dir).strip():
        return Path(str(state_dir).strip()).expanduser() / "spool"
    return resolve_plugin_root() / "telemetry" / "spool"


def _resolve_write_cfg(
    *, isolation: str | None = None, workspace_root: str | Path | None = None,
    workspace_roots: Sequence[str] | None = None, session_id: str | None = None,
    max_spool_entry_bytes: int | None = None,
) -> tuple[str, str, str, str, str, int, str | None]:
    if max_spool_entry_bytes is not None and (
        isinstance(max_spool_entry_bytes, bool)
        or not isinstance(max_spool_entry_bytes, int)
        or max_spool_entry_bytes < 1
    ):
        return "", "", "", "", "", DEFAULT_MAX_SPOOL_ENTRY_BYTES, "invalid_spool_config"
    cfg_iso, cfg_max, cfg_err = read_spool_config()
    eff_max = max_spool_entry_bytes if max_spool_entry_bytes is not None else (
        cfg_max if cfg_err is None else DEFAULT_MAX_SPOOL_ENTRY_BYTES
    )
    if isolation is None:
        if cfg_err is not None:
            return "", "", "", "", "", eff_max, cfg_err
        isolation = cfg_iso
    mode, sk, ws_id, cr, sess, serr = resolve_spool_scope(
        isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id,
    )
    return mode, sk, ws_id, cr, sess, eff_max, serr


def _project_mem(raw_text: str | bytes, scope_key: str, max_bytes: int) -> tuple[str, list[str], bytes, str, str, int] | None:
    return project_spool_in_memory(
        raw_text, scope_key=scope_key, max_bytes=max_bytes, min_bytes=SPOOL_MIN_BYTES,
        min_lines=SPOOL_MIN_LINES, head_lines=SPOOL_HEAD_LINES, tail_lines=SPOOL_TAIL_LINES,
        summary_max_bytes=SPOOL_SUMMARY_MAX_BYTES, min_saved_bytes=SPOOL_MIN_SAVED_BYTES,
    )


def _plan_gc_evictions_unlocked(
    eff_dir: Path, index: dict[str, Any], now_ts: float, *,
    limits: tuple[float, int, int] = (SPOOL_TTL_SECONDS, SPOOL_MAX_ENTRIES, SPOOL_TOTAL_BYTES_CAP),
    protect: str | None = None,
) -> tuple[list[tuple[str, int, tuple[int, int, int] | None]], set[str], bool]:
    max_age, max_entries, max_bytes = limits

    def _probe(sid: str) -> str | None:
        blob = eff_dir / f"{sid}.txt"
        return "unsafe_path" if check_unsafe_link(blob) else (None if blob.is_file() else "unexpectedly_missing")

    return plan_gc_evictions(index, GcEvictionPolicy(
        max_age=max_age, max_entries=max_entries, max_bytes=max_bytes, now_ts=now_ts,
        probe_blob_corrupt=_probe, protect=protect, tombstone_max_age=SPOOL_TOMBSTONE_MAX_AGE_SECONDS,
        max_tombstones=SPOOL_MAX_TOMBSTONES, max_corrupt_entries=SPOOL_MAX_CORRUPT_ENTRIES,
        probe_blob_identity=lambda sid: probe_blob_identity(eff_dir / f"{sid}.txt"),
    ))


def _run_gc_post_lock(
    eff_dir: Path, evicting_targets: Sequence[tuple[str, int, tuple[int, int, int] | None]],
    known_sids: set[str], *, cutoff: float, now_ts: float,
) -> tuple[int, int, dict[str, Any] | None]:
    return run_gc_post_lock(eff_dir, evicting_targets, known_sids, GcPostLockOptions(
        cutoff=cutoff, now_ts=now_ts, tombstone_max_age=SPOOL_TOMBSTONE_MAX_AGE_SECONDS,
        max_tombstones=SPOOL_MAX_TOMBSTONES, spool_lock=_spool_lock,
        open_index=_open_index_unlocked, save_index=_save_index,
    ))


def _write_temp_spool(eff_dir: Path, raw_bytes: bytes) -> Path:
    tmp_path = eff_dir / f".tmp.{os.getpid()}.{uuid.uuid4().hex[:12]}.spool"
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_FLAGS, 0o600)
    try:
        fh = os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        safe_unlink(tmp_path)
        raise
    try:
        with fh:
            fh.write(raw_bytes)
        if os.name != "nt":
            os.chmod(str(tmp_path), 0o600)
        return tmp_path
    except BaseException:
        safe_unlink(tmp_path)
        raise


@dataclass(frozen=True)
class _DedupProbe:
    cand_sid: str | None = None
    verified_id: tuple[int, int, int, int] | None = None
    fail_reason: str | None = None
    obs_id: tuple[int, int, int, int] | None = None


def _probe_dedup_candidate(eff_dir: Path, base_sid: str, query: DedupQuery) -> _DedupProbe:
    ro_idx, _ro_err = read_spool_index_readonly(eff_dir / "spool_index.json")
    cand_sid = find_dedup_candidate(ro_idx["entries"], base_sid, query) if ro_idx is not None else None
    if cand_sid is None:
        return _DedupProbe()
    verified_id, fail_reason, obs_id = verify_existing_blob_for_dedup(
        eff_dir / f"{cand_sid}.txt", exp_bytes=query.exp_bytes, exp_sha=query.sha_hex,
    )
    return _DedupProbe(cand_sid=cand_sid, verified_id=verified_id, fail_reason=fail_reason, obs_id=obs_id)


def _try_reuse_dedup_unlocked(
    eff_dir: Path, entries: dict[str, Any], probe: _DedupProbe, query: DedupQuery, ts: float,
) -> tuple[str, Path] | None:
    if probe.cand_sid is None or probe.verified_id is None:
        return None
    cand_ent = entries.get(probe.cand_sid)
    cand_blob = eff_dir / f"{probe.cand_sid}.txt"
    if not (isinstance(cand_ent, dict) and is_dedup_entry_match(cand_ent, query) and matches_stat_identity(cand_blob, probe.verified_id)):
        return None
    cand_ent["last_accessed_at"] = ts
    if query.canon_root and not str(cand_ent.get("canon_root") or "").strip():
        cand_ent["canon_root"] = query.canon_root
    return probe.cand_sid, cand_blob


def _mark_corrupt_dedup_unlocked(
    eff_dir: Path, entries: dict[str, Any], probe: _DedupProbe, query: DedupQuery, ts: float,
) -> None:
    if probe.cand_sid is None or probe.fail_reason not in ("integrity_mismatch", "format_error", "unexpectedly_missing", "unsafe_path"):
        return
    bad_ent = entries.get(probe.cand_sid)
    if not (isinstance(bad_ent, dict) and is_dedup_entry_match(bad_ent, query)):
        return
    cand_blob = eff_dir / f"{probe.cand_sid}.txt"
    still_bad = (
        (probe.fail_reason == "unexpectedly_missing" and not cand_blob.exists())
        or (probe.fail_reason == "unsafe_path" and check_unsafe_link(cand_blob))
        or (probe.obs_id is not None and matches_stat_identity(cand_blob, probe.obs_id))
    )
    if still_bad:
        bad_ent["state"], bad_ent["corrupt_reason"], bad_ent["corrupted_at"] = "corrupt", probe.fail_reason, ts


def _write_and_register_blob_unlocked(
    eff_dir: Path, index: dict[str, Any], tmp_path: Path | None, row_template: dict[str, Any], scope_key: str,
) -> tuple[str, Path]:
    entries, tombstones = index["entries"], index.setdefault("tombstones", {})
    id_epoch = max(0, int(index.get("id_epoch") or 0))
    gen, sha_hex, base_sid = 0, str(row_template["content_sha256"]), str(row_template["spool_id"])
    sid = base_sid if id_epoch == 0 else compute_scoped_spool_id(f"{scope_key}:e{id_epoch}:g0", sha_hex)
    while sid in entries or sid in tombstones or os.path.lexists(str(eff_dir / f"{sid}.txt")):
        gen += 1
        prefix = f"{scope_key}:gen:{gen}" if id_epoch == 0 else f"{scope_key}:e{id_epoch}:g{gen}"
        sid = compute_scoped_spool_id(prefix, sha_hex)
    blob_path = eff_dir / f"{sid}.txt"
    if check_unsafe_link(blob_path):
        raise OSError(f"unsafe_path: {sid}")
    if tmp_path is None:
        raise OSError(f"missing temp spool: {sid}")
    os.replace(str(tmp_path), str(blob_path))
    try:
        b_ident = probe_blob_identity(blob_path)
        ent_row = {**row_template, "spool_id": sid, "filename": f"{sid}.txt"}
        if b_ident is not None:
            ent_row["blob_dev"], ent_row["blob_ino"], ent_row["blob_mtime_ns"] = b_ident
        entries[sid] = ent_row
    except BaseException:
        safe_unlink(blob_path)
        raise
    return sid, blob_path


def _commit_spool_once_locked(
    eff_dir: Path, probe: _DedupProbe, query: DedupQuery, tmp_path: Path | None, row_and_scope: tuple[dict[str, Any], str],
) -> tuple[str, Path, bool, list[tuple[str, int, tuple[int, int, int] | None]], set[str]] | None:
    row_template, scope_key = row_and_scope
    ts = float(row_template["last_accessed_at"])
    with _spool_lock(eff_dir):
        index = _open_index_unlocked(eff_dir)
        entries = index["entries"]
        reused = _try_reuse_dedup_unlocked(eff_dir, entries, probe, query, ts)
        if probe.verified_id is not None and reused is None:
            return None
        reused_blob = reused is not None
        if reused is not None:
            sid, blob_path = reused
        else:
            _mark_corrupt_dedup_unlocked(eff_dir, entries, probe, query, ts)
            sid, blob_path = _write_and_register_blob_unlocked(eff_dir, index, tmp_path, row_template, scope_key)
        try:
            evicting_targets, known_sids, _d = _plan_gc_evictions_unlocked(eff_dir, index, ts, protect=sid)
            _save_index(eff_dir, index)
        except BaseException:
            if not reused_blob:
                safe_unlink(blob_path)
            raise
    return sid, blob_path, reused_blob, evicting_targets, known_sids


def _spool_tool_output_with_receipt(
    raw_text: str | bytes, *, session_id: str, call_id: str, harness: str, tool_name: str, cmd_sig: str = "",
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    isolation: str | None = None, turn_key: str = "", upstream_truncation: bool = False,
    spool_dir: Path | None = None, receipts_path: Path | None = None, now_ts: float | None = None,
    max_spool_entry_bytes: int | None = None, turn_correlation: str = "unobserved",
    hook_duration_ms: float | None = None, event_id: str | None = None,
) -> tuple[SpoolContractV1, str, str | None] | None:
    mode, scope_key, ws_id, canon_root, eff_sess, eff_max, scope_err = _resolve_write_cfg(
        isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots,
        session_id=session_id, max_spool_entry_bytes=max_spool_entry_bytes,
    )
    if scope_err is not None or (proj := _project_mem(raw_text, scope_key, eff_max)) is None:
        return None
    base_sid, lines, raw_bytes, sha_hex, summary, saved = proj
    raw_meta = measure_raw_source_bytes(raw_text)
    source_sha256, source_bytes = raw_meta if raw_meta is not None else (sha_hex, len(raw_bytes))
    eff_dir, ts = spool_dir or resolve_spool_dir(), float(now_ts) if now_ts is not None else time.time()
    tmp_path: Path | None = None
    committed: tuple[str, Path, bool, list[tuple[str, int, tuple[int, int, int] | None]], set[str]] | None = None
    try:
        if check_unsafe_link(eff_dir) or check_unsafe_link(eff_dir / "spool_index.json") or check_unsafe_link(eff_dir / "spool_index.lock"):
            warn(f"refusing symlink spool target: {base_sid}")
            return None
        eff_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(str(eff_dir), 0o700)
        query = DedupQuery(mode=mode, ws_id=ws_id, eff_sess=eff_sess, canon_root=canon_root, sha_hex=sha_hex, exp_bytes=len(raw_bytes))
        probe = _probe_dedup_candidate(eff_dir, base_sid, query)
        row_template: dict[str, Any] = {
            "spool_id": base_sid, "filename": f"{base_sid}.txt", "workspace_id": ws_id, "canon_root": canon_root,
            "session_id": str(session_id or ""), "call_id": str(call_id or ""), "harness": str(harness or ""),
            "tool_name": str(tool_name or ""), "cmd_sig": str(cmd_sig or ""), "total_lines": len(lines),
            "total_bytes": len(raw_bytes), "summary_bytes": len(summary.encode("utf-8")), "saved_bytes": saved,
            "content_sha256": sha_hex, "source_sha256": source_sha256, "source_bytes": source_bytes,
            "created_at": ts, "last_accessed_at": ts, "state": "available",
        }
        for _attempt in range(2):
            if probe.verified_id is None and tmp_path is None:
                tmp_path = _write_temp_spool(eff_dir, raw_bytes)
            committed = _commit_spool_once_locked(eff_dir, probe, query, tmp_path, (row_template, scope_key))
            if committed is None:
                probe = _DedupProbe()
                continue
            tmp_path = tmp_path if committed[2] else None
            break
    except (OSError, ValueError) as exc:
        if tmp_path is not None:
            safe_unlink(tmp_path)
        warn(f"spool_tool_output skipped ({type(exc).__name__}): {exc}")
        return None
    if committed is None:
        if tmp_path is not None:
            safe_unlink(tmp_path)
        return None
    sid, blob_path, reused_blob, evicting_targets, known_sids = committed
    if reused_blob and tmp_path is not None:
        safe_unlink(tmp_path)
    if sid != base_sid and (rebuilt := build_spool_summary(
        sid, lines, len(raw_bytes), sha_hex, head_lines=SPOOL_HEAD_LINES, tail_lines=SPOOL_TAIL_LINES,
        max_bytes=SPOOL_SUMMARY_MAX_BYTES, min_saved_bytes=SPOOL_MIN_SAVED_BYTES,
    )) is not None:
        summary = rebuilt[0]
    try:
        _run_gc_post_lock(eff_dir, evicting_targets, known_sids, cutoff=(ts - SPOOL_TTL_SECONDS), now_ts=ts)
    except OSError:
        pass
    # Lock ordering: release _spool_lock BEFORE acquiring receipts.lock in append_receipt.
    eff_rcpt = receipts_path or receipts_path_for(eff_dir)
    existing = find_created_receipt(sid, session_id=str(session_id or ""), call_id=str(call_id or ""), receipts_path=eff_rcpt)
    if existing is not None and (event_id is None or existing["event_id"] == event_id):
        receipt_id: str | None = existing["receipt_id"]
    else:
        rcpt = enrich_receipt(
            build_receipt(
                event_type="spool_created", harness=harness, session_id=str(session_id or ""), workspace_id=ws_id,
                turn_key=turn_key, call_id=str(call_id or ""), spool_id=sid, line_span=(0, len(lines)),
                byte_span=(0, len(raw_bytes)), upstream_truncation=upstream_truncation,
                delivery_evidence="replacement_emitted", spool_id_referenced=False, timestamp=_ts_iso(now_ts),
                event_id=event_id, hook_duration_ms=hook_duration_ms, turn_correlation=turn_correlation,
                source_hash=source_sha256, original_bytes=source_bytes, replacement_bytes=len(summary.encode("utf-8")),
            ),
            {"blob_sha256": sha_hex, "blob_bytes": len(raw_bytes)},
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
        max_spool_entry_bytes=max_spool_entry_bytes, turn_correlation=turn_correlation,
        hook_duration_ms=hook_duration_ms, event_id=event_id,
    )
    return (res[0], res[1]) if res is not None else None


def spool_post_tool_output(
    harness: str, payload: Mapping[str, Any], *, mode: str, session_id: str, call_id: str,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    isolation: str | None = None, turn_key: str = "", spool_dir: Path | None = None,
    receipts_path: Path | None = None, now_ts: float | None = None,
    raw_text: str | bytes | None = None, max_spool_entry_bytes: int | None = None,
    turn_correlation: str = "unobserved", hook_duration_ms: float | None = None, event_id: str | None = None,
) -> tuple[SpoolDecision | None, dict[str, Any] | None]:
    """Evaluate PostToolUse spooling purely in domain terms, returning `(SpoolDecision | None, meta | None)`."""
    if mode not in ("active", "shadow") or is_optimizer_tripped("output_spool", state_dir=spool_dir or resolve_spool_dir()):
        return None, None
    if (cand := prepare_post_tool_spool_candidate(harness, payload, raw_text)) is None:
        return None, None
    tool_name, raw_in, is_shell, shell_cmd, raw_resp, eff_raw, shape, up_trunc = cand
    eff_ws_root = workspace_root if workspace_root is not None else (payload.get("cwd") if isinstance(payload.get("cwd"), (str, Path)) else None)
    eff_ws_roots = workspace_roots if workspace_roots is not None else (tuple(str(r) for r in raw_roots) if isinstance((raw_roots := payload.get("workspace_roots")), (list, tuple)) else None)
    _m, scope_key, ws_id, _cr, _s, eff_max, scope_err = _resolve_write_cfg(
        isolation=isolation, workspace_root=eff_ws_root, workspace_roots=eff_ws_roots,
        session_id=session_id, max_spool_entry_bytes=max_spool_entry_bytes,
    )
    if scope_err is not None:
        return None, None
    if mode == "shadow":
        if (proj := _project_mem(eff_raw, scope_key, eff_max)) is None:
            return None, None
        return None, {
            "spool_id": proj[0], "total_lines": len(proj[1]), "total_bytes": len(proj[2]),
            "summary_bytes": len(proj[4].encode("utf-8")), "saved_bytes": proj[5],
            "harness": harness, "tool_name": tool_name, "workspace_id": ws_id,
        }
    claude_ok = harness == "claude" and (tool_name == "Bash" or tool_name.startswith("mcp__")) and shape is not None
    if not (claude_ok or (harness == "cursor" and tool_name.startswith(("MCP:", "mcp__")))):
        return None, None
    cmd_sig = compute_command_signature(tool_name, shell_cmd if is_shell else raw_in)
    spooled = _spool_tool_output_with_receipt(
        eff_raw, session_id=session_id, call_id=call_id, harness=harness, tool_name=tool_name, cmd_sig=cmd_sig,
        workspace_root=eff_ws_root, workspace_roots=eff_ws_roots, isolation=isolation, turn_key=turn_key,
        upstream_truncation=up_trunc, spool_dir=spool_dir, receipts_path=receipts_path, now_ts=now_ts,
        max_spool_entry_bytes=eff_max, turn_correlation=turn_correlation, hook_duration_ms=hook_duration_ms, event_id=event_id,
    )
    if spooled is None:
        return None, None
    contract, summary, receipt_id = spooled
    updated_out = format_spooled_tool_output(harness, shape, raw_resp, summary)
    sum_bytes = len(summary.encode("utf-8"))
    meta: dict[str, Any] = {
        "contract": contract, "spool_id": contract.spool_id, "workspace_id": ws_id, "total_lines": contract.total_lines,
        "total_bytes": contract.total_bytes, "summary_bytes": sum_bytes, "saved_bytes": contract.total_bytes - sum_bytes, "cmd_sig": cmd_sig,
    }
    if receipt_id is not None:
        meta["receipt_id"] = receipt_id
    return SpoolDecision(harness=harness, updated_output=updated_out, shape=str(shape), meta=meta), meta


def _open_blob_fd_locked(blob_path: Path) -> tuple[int | None, dict[str, Any] | None, bool]:
    """Open `blob_path` with O_NOFOLLOW, verify regular file + lstat/fstat match, and retry on swap."""
    for _ in range(3):
        if check_unsafe_link(blob_path):
            return None, {"ok": False, "error": "unsafe_path"}, False
        try:
            l_st = os.lstat(str(blob_path))
        except FileNotFoundError:
            return None, None, True
        except OSError as exc:
            return None, {"ok": False, "error": str(exc)}, False
        if not stat.S_ISREG(l_st.st_mode):
            return None, {"ok": False, "error": "unsafe_path"}, False
        try:
            raw_fd = os.open(str(blob_path), os.O_RDONLY | _O_FLAGS)
        except FileNotFoundError:
            return None, None, True
        except OSError as exc:
            err = "unsafe_path" if exc.errno in (errno.ELOOP, getattr(errno, "EMLINK", -1)) else str(exc)
            return None, {"ok": False, "error": err}, False
        try:
            f_st = os.fstat(raw_fd)
            if not stat.S_ISREG(f_st.st_mode):
                os.close(raw_fd)
                return None, {"ok": False, "error": "unsafe_path"}, False
            if (l_st.st_ino != 0 or f_st.st_ino != 0) and (
                (f_st.st_dev, f_st.st_ino) != (l_st.st_dev, l_st.st_ino)
            ):
                os.close(raw_fd)
                continue
            return raw_fd, None, False
        except OSError as exc:
            os.close(raw_fd)
            return None, {"ok": False, "error": str(exc)}, False
    return None, {"ok": False, "error": "unsafe_path"}, False


def _read_fd_and_verify(
    fd: int, exp_bytes: Any, exp_sha: Any,
) -> tuple[list[str], int, str | None, str | None]:
    """Read an already-opened blob fd, verify fstat regularity, size, SHA-256, and strict UTF-8."""
    try:
        fh = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    try:
        with fh:
            f_st = os.fstat(fh.fileno())
            if not stat.S_ISREG(f_st.st_mode):
                return [], 0, None, "unsafe_path"
            valid_len = isinstance(exp_bytes, int) and not isinstance(exp_bytes, bool) and exp_bytes >= 0
            cap = (exp_bytes + 1) if valid_len else (SPOOL_MAX_BLOB_BYTES + 1)
            if f_st.st_size > cap:
                return [], int(f_st.st_size), "integrity_mismatch", None
            raw_bytes = fh.read(cap)
    except OSError as exc:
        return [], 0, None, str(exc)
    obs = len(raw_bytes)
    sha_ok = isinstance(exp_sha, str) and bool(_SHA256_RE.fullmatch(exp_sha))
    if not valid_len or obs != exp_bytes or not sha_ok or hashlib.sha256(raw_bytes).hexdigest() != exp_sha:
        return [], obs, "integrity_mismatch", None
    try:
        return split_lines(raw_bytes.decode("utf-8", errors="strict")), obs, None, None
    except UnicodeDecodeError:
        return [], obs, "format_error", None


def _update_available_entry_locked(eff_dir: Path, spool_id: str, updates: Mapping[str, Any]) -> None:
    try:
        with _spool_lock(eff_dir):
            idx = _open_index_unlocked(eff_dir)
            cur = idx["entries"].get(spool_id)
            if isinstance(cur, dict) and cur.get("state", "available") == "available":
                cur.update(updates)
                _save_index(eff_dir, idx)
    except OSError as exc:
        warn(f"failed to update spool index for {spool_id}: {type(exc).__name__}: {exc}")


def _rcpt_target_and_parent(spool_id: str, eff_dir: Path, receipts_path: Path | None) -> tuple[Path, str | None]:
    eff_rcpt = receipts_path or receipts_path_for(eff_dir)
    parent = find_created_receipt(spool_id, receipts_path=eff_rcpt)
    return eff_rcpt, (parent["receipt_id"] if parent is not None else None)


def _open_locked_entry_blob(
    eff_dir: Path, blob_path: Path, spool_id: str, *, mode: str, ws_id: str, eff_sess: str, canon_root: str, eff_now: float,
) -> tuple[int | None, str, str, Any, Any, str, dict[str, Any] | None, str | None, bool]:
    entry_sess, entry_ws, exp_bytes, exp_sha, src_sha = eff_sess, ws_id, None, None, ""
    with _spool_lock(eff_dir):
        index = _open_index_unlocked(eff_dir)
        entry = index["entries"].get(spool_id)
        if entry is None:
            tomb = index.get("tombstones", {}).get(spool_id)
            err_d = (
                {"ok": False, "error": "spool_evicted", "eviction_reason": tomb["reason"], "evicted_at": tomb["evicted_at"]}
                if (tomb is not None and entry_scope_error(tomb, mode, ws_id, eff_sess, caller_canon_root=canon_root) is None)
                else {"ok": False, "error": "spool_not_found"}
            )
            return None, entry_sess, entry_ws, exp_bytes, exp_sha, src_sha, err_d, None, False
        if (mm_err := entry_scope_error(entry, mode, ws_id, eff_sess, caller_canon_root=canon_root)) is not None:
            return None, entry_sess, entry_ws, exp_bytes, exp_sha, src_sha, {"ok": False, "error": mm_err}, None, False
        if (st_val := entry.get("state", "available")) == "corrupt":
            err_d = {"ok": False, "error": "spool_corrupt", "corrupt_reason": str(entry.get("corrupt_reason") or "integrity_mismatch")}
            return None, entry_sess, entry_ws, exp_bytes, exp_sha, src_sha, err_d, None, False
        if st_val == "preparing":
            return None, entry_sess, entry_ws, exp_bytes, exp_sha, src_sha, {"ok": False, "error": "spool_not_found"}, None, False
        entry_sess = eff_sess or str(entry.get("session_id") or "")
        entry_ws = ws_id or str(entry.get("workspace_id") or "")
        exp_bytes, exp_sha = entry.get("total_bytes"), entry.get("content_sha256")
        src_sha = str(entry.get("source_sha256") or exp_sha or "")
        fd, early_err, missing = _open_blob_fd_locked(blob_path)
        if missing:
            entry["state"], entry["corrupt_reason"], entry["corrupted_at"] = "corrupt", "unexpectedly_missing", eff_now
            _save_index(eff_dir, index)
            return None, entry_sess, entry_ws, exp_bytes, exp_sha, src_sha, early_err, "unexpectedly_missing", True
        return fd, entry_sess, entry_ws, exp_bytes, exp_sha, src_sha, early_err, None, False


def _touch_and_load_lines(
    spool_id: str, spool_dir: Path | None, now_ts: float | None, *,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None, isolation: str | None = None, harness: str = "cli",
    receipts_path: Path | None = None, on_reliability_failure: Callable[[], None] | None = None,
    turn_key: str = "", turn_correlation: str = "unobserved", call_id: str = "",
) -> tuple[list[str], int, str, str, str, str, dict[str, Any] | None]:
    if not isinstance(spool_id, str) or not SPOOL_ID_RE.fullmatch(spool_id):
        return [], 0, "", "", "", "", {"ok": False, "error": "invalid_spool_id"}
    mode, _sk, ws_id, canon_root, eff_sess, scope_err = resolve_spool_scope(
        isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id,
    )
    if scope_err is not None:
        return [], 0, ws_id, eff_sess, "", "", {"ok": False, "error": scope_err}
    eff_dir, blob_path = (sd := spool_dir or resolve_spool_dir()), sd / f"{spool_id}.txt"
    if check_unsafe_link(eff_dir) or check_unsafe_link(eff_dir / "spool_index.lock") or check_unsafe_link(eff_dir / "spool_index.json") or check_unsafe_link(blob_path):
        return [], 0, ws_id, eff_sess, "", "", {"ok": False, "error": "unsafe_path"}
    if not eff_dir.is_dir():
        return [], 0, ws_id, eff_sess, "", "", {"ok": False, "error": "spool_not_found"}
    eff_now, fd = float(now_ts) if now_ts is not None else time.time(), None  # type: tuple[float, int | None]
    try:
        try:
            fd, entry_sess, entry_ws, exp_bytes, exp_sha, src_sha, early_err, fail_reason, marked_step1 = _open_locked_entry_blob(
                eff_dir, blob_path, spool_id, mode=mode, ws_id=ws_id, eff_sess=eff_sess, canon_root=canon_root, eff_now=eff_now,
            )
        except OSError as exc:
            return [], 0, ws_id, eff_sess, "", "", {"ok": False, "error": "unsafe_path" if "unsafe_path" in str(exc) else str(exc)}
        if early_err is not None:
            return [], 0, entry_ws, entry_sess, "", "", early_err
        obs_bytes, lines = 0, []  # type: tuple[int, list[str]]
        if fd is not None:
            hand_off, fd = fd, None
            lines, obs_bytes, fail_reason, io_err = _read_fd_and_verify(hand_off, exp_bytes, exp_sha)
            if io_err is not None:
                return [], 0, entry_ws, entry_sess, "", "", {"ok": False, "error": io_err}
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    if fail_reason is not None:
        if not marked_step1:
            _update_available_entry_locked(eff_dir, spool_id, {"state": "corrupt", "corrupt_reason": fail_reason, "corrupted_at": eff_now})
        eff_rcpt, parent_id = _rcpt_target_and_parent(spool_id, eff_dir, receipts_path)
        blob_sha = exp_sha if isinstance(exp_sha, str) else ""
        rcpt = enrich_receipt(
            build_receipt(
                event_type="spool_integrity_failure", harness=harness, session_id=entry_sess, workspace_id=entry_ws,
                turn_key=turn_key, call_id=call_id, spool_id=spool_id, line_span=(0, 0), byte_span=(0, obs_bytes),
                delivery_evidence="unverified", spool_id_referenced=True, parent_event_id=parent_id,
                failure_kind="reliability_failure", reason=fail_reason, timestamp=_ts_iso(now_ts),
                turn_correlation=turn_correlation, source_hash=src_sha or blob_sha,
            ),
            {"blob_sha256": blob_sha, **({"blob_bytes": exp_bytes} if isinstance(exp_bytes, int) and not isinstance(exp_bytes, bool) and exp_bytes >= 0 else {})},
        )
        append_receipt(rcpt, receipts_path=eff_rcpt)
        if on_reliability_failure is not None:
            on_reliability_failure()
        record_governor_signal("output_spool", fail_reason, state_dir=eff_dir, harness=harness, session_id=entry_sess)
        return [], obs_bytes, entry_ws, entry_sess, "", "", {"ok": False, "error": fail_reason}
    _update_available_entry_locked(eff_dir, spool_id, {"last_accessed_at": eff_now})
    return lines, obs_bytes, entry_ws, entry_sess, str(exp_sha or ""), src_sha, None


def slice_spool(
    spool_id: str, *, start_line: int = 1, limit: int = 120, end_line: int | None = None,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None, isolation: str | None = None, harness: str = "cli",
    receipts_path: Path | None = None, on_reliability_failure: Callable[[], None] | None = None,
    spool_dir: Path | None = None, now_ts: float | None = None,
    turn_key: str = "", turn_correlation: str = "unobserved", call_id: str = "",
) -> dict[str, Any]:
    """Read a bounded verified line slice from a spooled blob and emit a recovery receipt."""
    lines, total_bytes, ws_id, eff_sess, exp_sha, src_sha, err = _touch_and_load_lines(
        spool_id, spool_dir, now_ts, workspace_root=workspace_root, workspace_roots=workspace_roots,
        session_id=session_id, isolation=isolation, harness=harness, receipts_path=receipts_path,
        on_reliability_failure=on_reliability_failure, turn_key=turn_key, turn_correlation=turn_correlation, call_id=call_id,
    )
    if err is not None:
        return err
    fields, lspan, bspan = slice_verified_lines(lines, start_line, limit, end_line)
    eff_rcpt, parent_id = _rcpt_target_and_parent(spool_id, spool_dir or resolve_spool_dir(), receipts_path)
    rcpt = enrich_receipt(
        build_receipt(
            event_type="spool_recovery", harness=harness, session_id=eff_sess, workspace_id=ws_id,
            turn_key=turn_key, call_id=call_id, spool_id=spool_id, line_span=lspan, byte_span=bspan,
            delivery_evidence="unverified", spool_id_referenced=True, parent_event_id=parent_id,
            timestamp=_ts_iso(now_ts), turn_correlation=turn_correlation, source_hash=src_sha or exp_sha,
        ),
        {"blob_sha256": exp_sha, "blob_bytes": total_bytes},
    )
    append_receipt(rcpt, receipts_path=eff_rcpt)
    return {"ok": True, "spool_id": spool_id, "total_bytes": total_bytes, **fields}


def grep_spool(
    spool_id: str, pattern: str, *, ignore_case: bool = False, max_matches: int = 50, context_lines: int = 0,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    session_id: str | None = None, isolation: str | None = None, harness: str = "cli",
    receipts_path: Path | None = None, on_reliability_failure: Callable[[], None] | None = None,
    spool_dir: Path | None = None, now_ts: float | None = None,
    turn_key: str = "", turn_correlation: str = "unobserved", call_id: str = "",
) -> dict[str, Any]:
    """Regex-search a verified spooled blob and emit a recovery receipt."""
    if not isinstance(spool_id, str) or not SPOOL_ID_RE.fullmatch(spool_id):
        return {"ok": False, "error": "invalid_spool_id"}
    _m, _sk, _ws, _cr, _s, scope_err = resolve_spool_scope(
        isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id,
    )
    if scope_err is not None:
        return {"ok": False, "error": scope_err}
    try:
        rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except (re.error, TypeError) as exc:
        return {"ok": False, "error": f"invalid_regex: {exc}"}
    lines, total_bytes, ws_id, eff_sess, exp_sha, src_sha, err = _touch_and_load_lines(
        spool_id, spool_dir, now_ts, workspace_root=workspace_root, workspace_roots=workspace_roots,
        session_id=session_id, isolation=isolation, harness=harness, receipts_path=receipts_path,
        on_reliability_failure=on_reliability_failure, turn_key=turn_key, turn_correlation=turn_correlation, call_id=call_id,
    )
    if err is not None:
        return err
    matches, truncated, metrics = grep_lines_with_spans(lines, rx, max_matches, context_lines)
    eff_rcpt, parent_id = _rcpt_target_and_parent(spool_id, spool_dir or resolve_spool_dir(), receipts_path)
    rcpt = enrich_receipt(
        build_receipt(
            event_type="spool_recovery", harness=harness, session_id=eff_sess, workspace_id=ws_id,
            turn_key=turn_key, call_id=call_id, spool_id=spool_id, line_span=metrics["line_span"], byte_span=metrics["byte_span"],
            delivery_evidence="unverified", spool_id_referenced=True, parent_event_id=parent_id,
            timestamp=_ts_iso(now_ts), turn_correlation=turn_correlation, source_hash=src_sha or exp_sha,
        ),
        {
            "recovered_line_spans": metrics["merged_line_spans"],
            "recovered_byte_spans": metrics["merged_byte_spans"],
            "recovered_context_bytes": metrics["repeated_context_bytes"],
            "blob_sha256": exp_sha,
            "blob_bytes": total_bytes,
        },
    )
    append_receipt(rcpt, receipts_path=eff_rcpt)
    return {"ok": True, "spool_id": spool_id, "pattern": pattern, "match_count": len(matches), "truncated": truncated, "total_lines": len(lines), "matches": matches}


def _check_dir(spool_dir: Path | None, empty: dict[str, Any]) -> tuple[Path | None, dict[str, Any] | None]:
    if not (eff_dir := spool_dir or resolve_spool_dir()).is_dir():
        return None, empty
    if check_unsafe_link(eff_dir) or check_unsafe_link(eff_dir / "spool_index.json"):
        return None, {"ok": False, "error": "unsafe_path"}
    return eff_dir, None


def list_spools(
    *, session_id: str | None = None, workspace_root: str | Path | None = None,
    workspace_roots: Sequence[str] | None = None, isolation: str | None = None, spool_dir: Path | None = None,
) -> dict[str, Any]:
    """List scope-authorized available spooled entries newest-first with zero filesystem paths."""
    mode, _sk, ws_id, canon_root, eff_sess, scope_err = resolve_spool_scope(
        isolation=isolation, workspace_root=workspace_root, workspace_roots=workspace_roots, session_id=session_id,
    )
    if scope_err is not None:
        return {"ok": False, "error": scope_err}
    eff_dir, early = _check_dir(spool_dir, {"ok": True, "count": 0, "total_bytes": 0, "entries": []})
    if eff_dir is None:
        return early or {}
    with _spool_lock(eff_dir):
        entries = sorted(
            (
                {k: v for k, v in e.items() if k not in ("canon_root", "blob_dev", "blob_ino", "blob_mtime_ns")}
                for e in _open_index_unlocked(eff_dir)["entries"].values()
                if e.get("state", "available") == "available"
                and entry_scope_error(e, mode, ws_id, eff_sess, caller_canon_root=canon_root) is None
                and (session_id is None or e.get("session_id") == session_id)
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
    if eff_dir is None:
        return early or {}
    eff_now = float(now_ts) if now_ts is not None else time.time()
    with _spool_lock(eff_dir):
        index = _open_index_unlocked(eff_dir)
        evicting_targets, known_sids, dirty = _plan_gc_evictions_unlocked(
            eff_dir, index, eff_now, limits=(max_age_seconds, max_entries, max_total_bytes),
        )
        if dirty:
            _save_index(eff_dir, index)
        final_index = index
    rc, rb, updated_idx = _run_gc_post_lock(eff_dir, evicting_targets, known_sids, cutoff=(eff_now - max_age_seconds), now_ts=eff_now)
    if updated_idx is not None:
        final_index = updated_idx
    avail = [e for e in final_index["entries"].values() if e.get("state", "available") == "available"]
    return {"ok": True, "removed_count": rc, "removed_bytes": rb, "remaining_count": len(avail), "remaining_bytes": sum(max(0, int(e.get("total_bytes") or 0)) for e in avail)}


def inspect_spool_entry(spool_id: str, *, spool_dir: Path | None = None) -> dict[str, Any]:
    """Pure read-only inspection of one `spool_id` without locks, writes, warnings, or blob reads."""
    return inspect_spool_entry_readonly(spool_id, spool_dir or resolve_spool_dir())


def inspect_spool_health(
    spool_dir: Path | None = None, *, receipts_path: Path | None = None, now_ts: float | None = None,
) -> dict[str, Any]:
    """Pure read-only spool health summary for `cg_status --doctor` (no locks/writes/warnings)."""
    return inspect_spool_health_readonly(spool_dir or resolve_spool_dir(), receipts_path=receipts_path, now_ts=now_ts, ttl_seconds=SPOOL_TTL_SECONDS)
