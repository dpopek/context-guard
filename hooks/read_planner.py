"""Silent range-trim and machine-artifact auto-outline planner for Context-Guard PreToolUse."""
from __future__ import annotations

import copy, hashlib, json, math, os, re, time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping, NamedTuple

from core.contracts import (HARNESS_CAPABILITIES, PendingRead, PendingUnwrapWrite, PlannerMeta, PreparedOutline,
                            finalize_outline_text, materialize_unwrap_write)
from core.platform_io import warn
from hooks import config, file_io, json_outliners, outcomes, session_lifecycle, state_store, telemetry
from hooks.state_store import StatePersistenceError, merge_intervals
from hooks.telemetry_core import BINARY_MEDIA_EXTENSIONS, cap_end_line_for_harness
from integrations.atlassian_twg import prepare_twg_stdout_outline

TRANSCRIPT_OUTLINE_LINE_THRESHOLD, FOLLOWUP_TARGETED_MAX_LINES, MAX_TIER2_LINES = 8, 250, 2000
_READ_GUTTER_RE = re.compile(r"^\s*\d+(?:→|\t)")

class FileReadOutcome(NamedTuple):
    """Result of evaluating one file read against the session ledger."""
    decision: dict[str, Any]
    intervention: str | None = None
    effective_step_idx: int = 0
    followup_resolution: tuple[str, str] | None = None

class PlannedFileRead(NamedTuple):
    """Pure planned verdict paired with deferred ledger/unwrap commit metadata."""
    outcome: FileReadOutcome
    needs_commit: bool = False
    state_dir_path: Path | None = None
    canon: str = ""
    meta: PlannerMeta | None = None
    locked_state_fn: Callable[[Path], Any] = state_store.locked_state
    unwrap_writer: Callable[[PendingUnwrapWrite | None], str | None] = materialize_unwrap_write

def normalize_read_body_fingerprint(text: str) -> str:
    """Normalize CRLF/CR, strip uniform `cat -n` gutters, and hash UTF-8 body lines."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    non_empty = [ln for ln in lines if ln != ""]
    if non_empty and all(_READ_GUTTER_RE.match(ln) for ln in non_empty):
        lines = [_READ_GUTTER_RE.sub("", ln, count=1) if ln != "" else "" for ln in lines]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()

def normalize_effective_bounds(req_start: int, req_end: int, target_lines: int) -> tuple[int, int] | None:
    """Normalize 1-based `[req_start, req_end]` against `target_lines`; `None` on invalid/past-EOF."""
    if req_start <= 0 or req_end < -1 or (req_end != -1 and req_end < req_start):
        return None
    if target_lines <= 0:
        return (req_start, req_end)
    return None if req_start > target_lines else (req_start, target_lines if req_end == -1 else req_end)

def normalize_recorded_ranges(recorded_ranges: list[list[int]], target_lines: int) -> list[list[int]]:
    """Validate 4-tuples `[s, e, step, tier]`, normalize `-1` endpoints, drop invalid."""
    return [[b[0], b[1], int(e[2]), int(e[3])] for e in recorded_ranges
            if state_store.is_valid_read_interval(e) and (b := normalize_effective_bounds(int(e[0]), int(e[1]), target_lines))]

def _collapse_qualified_reads(recorded: list[list[int]], t_lines: int, min_tier: int) -> list[list[int]]:
    qual = [r for r in normalize_recorded_ranges(recorded, t_lines) if r[3] >= min_tier]
    if not (merged := merge_intervals(qual)):
        return []
    spans = sorted(([m[0], math.inf if m[1] == -1 else m[1], m[2]] for m in merged), key=lambda x: x[0])
    union: list[list[float | int]] = [list(spans[0])]
    for ns, ne, st in spans[1:]:
        if union[-1][1] + 1 >= ns:
            union[-1][1], union[-1][2] = max(union[-1][1], ne), max(int(union[-1][2]), int(st))
        else:
            union.append([ns, ne, st])
    return [[int(u[0]), -1 if u[1] == math.inf else int(u[1]), int(u[2])] for u in union]

def covering_read_step(recorded_ranges: list[list[int]], req_start: int, req_end: int, target_lines: int = 0, *, min_tier: int = 2) -> int | None:
    """Step of qualifying recorded reads covering `[req_start, req_end]`, or `None` when uncovered."""
    if not (bounds := normalize_effective_bounds(req_start, req_end, target_lines)):
        return None
    es, ee = bounds
    return next((st for rs, re_, st in _collapse_qualified_reads(recorded_ranges, target_lines, min_tier)
                 if rs <= es and (re_ == -1 or (ee != -1 and re_ >= ee))), None)

def trim_partially_covered_range(reads: list[list[int]], req_start: int, req_end: int, target_lines: int = 0, *, min_tier: int = 2) -> tuple[int, int] | None:
    """Trim leading or trailing overlap against qualifying (`tier >= min_tier`) already-read intervals."""
    bounds = normalize_effective_bounds(req_start, req_end, target_lines)
    if bounds is None or bounds[1] == -1:
        return None
    eff_s, eff_e = bounds
    ns, ne = eff_s, eff_e
    for rs, re_, _ in _collapse_qualified_reads(reads, target_lines, min_tier):
        if re_ == -1: ne = min(ne, rs - 1) if rs <= ne else ne
        elif rs <= ns <= re_ < ne: ns = re_ + 1
        elif ns < rs <= ne <= re_: ne = rs - 1
    return (ns, ne) if (ns, ne) != (eff_s, eff_e) and ns <= ne else None

def _prepare_special(canon: str, special: json_outliners.SpecialReadTarget, twg_active: bool, start_line: int, end_line: int, sdir: Path) -> PreparedOutline | None:
    fp, st_size = Path(canon), os.path.getsize(canon)
    if special.is_mcp_step_output: return json_outliners.prepare_mcp_step_outline(fp, st_size)
    if twg_active: return prepare_twg_stdout_outline(fp, st_size, cache_dir=sdir / "twg_cache")
    if special.is_transcript_log and (tr := json_outliners.build_transcript_jsonl_outline(fp, st_size, 10 * 1024 * 1024, start_line=start_line, end_line=end_line)) and tr[0] > TRANSCRIPT_OUTLINE_LINE_THRESHOLD:
        return PreparedOutline(total_lines=tr[0], outline_text=tr[1])
    return None

def mirror_unwrapped_entry(
    files_map: dict[str, Any], actual_unwrapped: str, eff_step: int, mark_outlined: bool = False, total_lines: int = 0,
    read_interval: list[int] | None = None, pending_followup_kind: str | None = None, mirror_source: str | None = None,
) -> None:
    """Mirror outline markers and confirmed 4-tuple read intervals onto an unwrapped target."""
    if not actual_unwrapped or not os.path.isfile(actual_unwrapped): return
    u_sha = file_io.compute_file_sha256(actual_unwrapped) or ""
    ex = files_map.get(actual_unwrapped)
    if not isinstance(ex, dict) or ex.get("sha256") != u_sha: ex = {"sha256": u_sha, "reads": []}
    if mark_outlined: ex.update({"outlined": True, "outlined_step": eff_step, **({"outlined_total_lines": total_lines} if total_lines > 0 else {})})
    for k, v in (("pending_followup_kind", pending_followup_kind), ("mirror_source", mirror_source)):
        if v is not None: ex[k] = v
    if read_interval is not None and state_store.is_valid_read_interval(read_interval) and isinstance((reads := ex.setdefault("reads", [])), list):
        reads.append(list(read_interval[:4]))
    files_map[actual_unwrapped] = ex

def _slice_norm_fingerprint(read_target: str, pending_content: str | None, es: int, de: int | None, byte_offset: int, slice_bytes: int, target_sha: str | None, max_cov_bytes: int = 60_000) -> str | None:
    if byte_offset > 0 or not target_sha or de is None or de < es or es < 1 or (de - es + 1) > MAX_TIER2_LINES or slice_bytes > max_cov_bytes:
        return None
    try:
        if pending_content is not None: sel = pending_content.splitlines()[es - 1 : de]
        else:
            with open(read_target, "r", encoding="utf-8", errors="replace") as fh:
                sel = [ln.rstrip("\r\n") for n, ln in enumerate(fh, 1) if es <= n <= de]
        return normalize_read_body_fingerprint("\n".join(sel)) if len(sel) == (de - es + 1) else None
    except OSError: return None

def _followup_outcome(entry: dict[str, Any], files_map: dict[str, Any], peers: tuple[str, ...], s: int, e: int, t_lines: int) -> tuple[str, str] | None:
    p_kind = entry.get("pending_followup_kind") or next((pe.get("pending_followup_kind") for o in peers if isinstance((pe := files_map.get(o)), dict) and pe.get("pending_followup_kind") is not None), None)
    if p_kind not in ("outline", "outline_pull"): return None
    span = (e if e != -1 else t_lines) - s + 1
    tgt = not (s == 1 and e == -1) and (e != -1 or t_lines > 0) and span <= FOLLOWUP_TARGETED_MAX_LINES
    return str(p_kind), ("targeted_followup" if tgt else "full_bypass")

def _prepare_step_and_entry(state: dict[str, Any], canon: str, sha256: str, step_idx: int, auto_inc: bool, *, persist: bool) -> tuple[int, dict[str, Any], dict[str, Any]]:
    prev_max = int(state.get("max_tool_step_idx") or 0)
    if not auto_inc and 0 < step_idx < prev_max: session_lifecycle.prune_state_on_rewind(state, step_idx, inclusive=True)
    eff_step = (int(state.get("auto_step_seq") or 0) + 1) if (auto_inc and step_idx <= 0) else step_idx
    if persist:
        if auto_inc and step_idx <= 0: state["auto_step_seq"] = eff_step
        if eff_step > int(state.get("max_tool_step_idx") or 0): state["max_tool_step_idx"] = eff_step
    fmap: dict[str, Any] = state.setdefault("files", {}) if persist else (rf if isinstance((rf := state.get("files")), dict) else {})
    raw_e = fmap.get(canon)
    return eff_step, fmap, (dict(raw_e) if isinstance(raw_e, dict) and raw_e.get("sha256") == sha256 else {"sha256": sha256, "reads": []})

def _measure_pending_lines(p_lines: list[str], s: int, e: int) -> int:
    if s < 1 or s > len(p_lines): return 0
    return sum(len(ln.encode("utf-8")) for ln in p_lines[s - 1 : (len(p_lines) if e == -1 else min(len(p_lines), e))])

def _measure_slice(read_target: str, p_lines: list[str] | None, s: int, e: int) -> int:
    return (telemetry.measure_slice_bytes(read_target, s, e) or 0) if p_lines is None else _measure_pending_lines(p_lines, s, e)

def _snapshot_reads(reads: list[Any]) -> tuple[tuple[int, int, int, int], ...]:
    return tuple((int(r[0]), int(r[1]), int(r[2]), int(r[3])) for r in reads if state_store.is_valid_read_interval(r))

def _compute_trim_spans(start_line: int, eff_e: int, trimmed: tuple[int, int] | None) -> tuple[int | None, int | None, tuple[tuple[int, int], ...]]:
    if trimmed is None: return None, None, ()
    es, ee = trimmed
    spans = ([(start_line, es - 1)] if es > start_line else []) + ([(ee + 1, eff_e)] if eff_e > 0 and ee < eff_e else [])
    return (spans[0][0], spans[0][1], tuple(spans)) if spans else (None, None, ())

def decide_file_read(
    *, raw_path: str, canon: str, sha256: str, target_lines: int, state: Mapping[str, Any], start_line: int, end_line: int,
    byte_offset: int, step_idx: int, allow_auto_outline: bool = True, path_arg_key: str = "Path", auto_increment_step: bool = False,
    harness: str = "antigravity", read_tool: str = "read_file", can_trim: bool = True, can_redirect_path: bool = True,
    call_id: str = "", synthetic_id: bool | None = None, model: str = "unknown", min_tier: int = 2,
    special: json_outliners.SpecialReadTarget | None = None, prepared: PreparedOutline | None = None, twg_active: bool = False,
    unwrapped_exists: bool = False, unwrapped_lines: int = 0, unwrapped_sha256: str = "", planned_unwrapped_path: str | None = None,
    now_ts: float = 0.0, slice_measurer: Callable[[str, list[str] | None, int, int], int] | None = None,
    slice_fingerprinter: Callable[[str, str | None, int, int | None, int, int, str, int], str | None] | None = None,
    state_dir_path: Path | None = None, locked_state_fn: Callable[[Path], Any] = state_store.locked_state,
    unwrap_writer: Callable[[PendingUnwrapWrite | None], str | None] = materialize_unwrap_write,
) -> PlannedFileRead:
    """Compute a `PlannedFileRead` purely in memory with zero disk I/O or wall-clock calls."""
    eff_step, files_map, entry = _prepare_step_and_entry(copy.deepcopy(dict(state)), canon, sha256, step_idx, auto_increment_step, persist=False)
    reads = [r for r in (entry.get("reads") or []) if state_store.is_valid_read_interval(r)]
    expected_reads = _snapshot_reads(reads)
    is_mcp, is_tr = bool(special and special.is_mcp_step_output), bool(special and special.is_transcript_log)
    t_ok = (not is_tr) or end_line == -1 or (end_line - start_line + 1) > TRANSCRIPT_OUTLINE_LINE_THRESHOLD
    if (is_mcp or twg_active or is_tr) and prepared is not None and byte_offset == 0 and (allow_auto_outline or twg_active) and not entry.get("outlined") and (is_tr or not any(int(r[2]) != eff_step for r in reads)) and t_ok:
        pw = prepared.pending_write if can_redirect_path else None
        ot = finalize_outline_text(prepared, (planned_unwrapped_path or str(pw.target_path)) if pw is not None else None)
        is_inl, base = bool(twg_active and "— full payload inline)" in ot), os.path.basename(canon) or canon
        fa = raw_path or base
        hint = (f"Use `sed -n 'START,ENDp' {fa}` to read specific line ranges." if harness == "codex"
                else f"Call `Read` with targeted `offset` and `limit` for `{fa}`." if harness in ("claude", "cursor")
                else f"Call `{read_tool}` with targeted `StartLine` and `EndLine` for `{fa}`.")
        reason = (f"CONTEXT-GUARD TWG INLINE READ: {base} ({prepared.total_lines} lines) delivered inline to avoid out-of-workspace prompts:\n\n{ot}\n\nNo further `read_file` call is needed for this file."
                  if is_inl else f"CONTEXT-GUARD AUTO-OUTLINE: {base} has {prepared.total_lines} lines. Full-file read intercepted to save tokens. Structural outline:\n\n{ot}\n\n{hint}")
        meta = PlannerMeta(sha256=sha256, step_idx=step_idx, auto_increment_step=auto_increment_step, is_outline=True, pending_write=pw,
                           outlined_total_lines=int(prepared.total_lines), pending_followup_kind=None if is_inl else "outline",
                           path_arg_key=path_arg_key, call_id=call_id, expected_reads_snapshot=expected_reads)
        return PlannedFileRead(FileReadOutcome({"decision": "deny", "reason": reason}, "outline", eff_step), True, state_dir_path, canon, meta, locked_state_fn, unwrap_writer)

    redir_p, redir_pw, pend_text, t_lines, t_sha = None, None, None, target_lines, sha256
    if can_redirect_path and (is_mcp or twg_active) and (start_line > 1 or end_line != -1 or not allow_auto_outline or twg_active):
        if unwrapped_exists and isinstance((pu := entry.get("unwrapped_path")), str) and pu:
            redir_p, t_lines, t_sha = pu, (unwrapped_lines or target_lines), (unwrapped_sha256 or sha256)
        elif prepared is not None and prepared.pending_write is not None:
            redir_pw = prepared.pending_write
            redir_p, pend_text, reads = (planned_unwrapped_path or str(redir_pw.target_path)), str(redir_pw.content), []
    read_target = redir_p or canon
    p_lines = pend_text.splitlines(keepends=True) if pend_text is not None else None
    if p_lines is not None and pend_text is not None: t_lines, t_sha = len(p_lines), hashlib.sha256(pend_text.encode("utf-8")).hexdigest()
    caps = HARNESS_CAPABILITIES.get(harness)
    cap_0 = caps.max_lines if caps is not None else t_lines
    max_cov = caps.max_coverage_bytes if caps is not None else HARNESS_CAPABILITIES["claude"].max_coverage_bytes
    probe_e = min(t_lines, cap_0) if (start_line == 1 and end_line == -1 and t_lines > 0) else end_line
    trimmed = trim_partially_covered_range(reads, start_line, probe_e, target_lines=t_lines, min_tier=min_tier) if can_trim and byte_offset == 0 else None
    if trimmed is not None and t_lines > 0 and trimmed[0] > t_lines: trimmed = None
    es, ee = trimmed or (start_line, end_line)
    eff_e = t_lines if (t_lines > 0 and probe_e == -1) else (min(probe_e, t_lines) if (t_lines > 0 and probe_e > 0) else probe_e)
    t_start, t_end, t_spans = _compute_trim_spans(start_line, eff_e, trimmed)
    cap_e, cap_re = cap_end_line_for_harness(harness, es, ee), cap_end_line_for_harness(harness, start_line, end_line)
    if slice_measurer is not None:
        slice_b = slice_measurer(read_target, p_lines, es, cap_e)
        req_b = slice_b if trimmed is None else slice_measurer(read_target, p_lines, start_line, cap_re)
    else:
        slice_b = _measure_pending_lines(p_lines, es, cap_e) if p_lines is not None else 0
        req_b = slice_b if trimmed is None else (_measure_pending_lines(p_lines, start_line, cap_re) if p_lines is not None else 0)
    deliv_end = outcomes.estimate_delivered_end_line(harness, es, ee, t_lines, slice_b)
    exp_norm = (_slice_norm_fingerprint("", pend_text, es, deliv_end, byte_offset, slice_b, t_sha, max_cov) if pend_text is not None
                else (slice_fingerprinter(read_target, None, es, deliv_end, byte_offset, slice_b, t_sha, max_cov) if slice_fingerprinter is not None else None))
    peers = tuple(p for p in (entry.get("unwrapped_path"), entry.get("mirror_source"), redir_p) if isinstance(p, str))
    fu = None if byte_offset else _followup_outcome(entry, files_map, peers, start_line, end_line, t_lines)
    ow: dict[str, Any] = {"StartLine": trimmed[0], "EndLine": trimmed[1]} if trimmed is not None else {}
    if redir_p: ow[path_arg_key] = redir_p
    dec: dict[str, Any] = {"decision": "allow", **({"overwrite": ow} if ow else {})}
    synth = (not bool(call_id)) if synthetic_id is None else bool(synthetic_id)
    pending_read = PendingRead(
        raw_path=raw_path, canonical_target=canon, exec_start=es, exec_end=ee, delivered_end=deliv_end if deliv_end is not None else -1,
        target_lines=t_lines, step=eff_step, sha256=t_sha, expected_norm_sha256=exp_norm, slice_bytes=slice_b, byte_offset=byte_offset,
        redirect_path=redir_p, is_trim=trimmed is not None, is_redirect=redir_p is not None, req_bytes=req_b, trimmed_bytes=slice_b,
        saved_bytes=max(0, req_b - slice_b) if trimmed is not None else 0, synthetic_id=synth, post_stage="pending", credited=False,
        model=model, ts=float(now_ts), trimmed_start=t_start, trimmed_end=t_end, trimmed_spans=t_spans)
    meta = PlannerMeta(sha256=sha256, step_idx=step_idx, auto_increment_step=auto_increment_step, is_outline=False,
                       pending_write=redir_pw, target_lines=t_lines, path_arg_key=path_arg_key, call_id=call_id,
                       pending_read=pending_read, clear_followups=(byte_offset == 0), peer_paths=peers, expected_reads_snapshot=expected_reads)
    return PlannedFileRead(FileReadOutcome(dec, ("range_trim" if trimmed is not None else None), eff_step, fu), True, state_dir_path, canon, meta, locked_state_fn, unwrap_writer)

def plan_file_read_verdict(
    state_dir_path: Path, raw_path: str, start_line: int, end_line: int, byte_offset: int, step_idx: int,
    allow_auto_outline: bool = True, path_arg_key: str = "Path", auto_increment_step: bool = False,
    harness: str = "antigravity", read_tool: str = "read_file", can_trim: bool | None = None,
    can_redirect_path: bool = True, locked_state_fn: Callable[[Path], Any] = state_store.locked_state,
    unwrap_writer: Callable[[PendingUnwrapWrite | None], str | None] = materialize_unwrap_write, *,
    call_id: str = "", synthetic_id: bool | None = None, model: str = "unknown", min_tier: int | None = None,
) -> PlannedFileRead:
    """Gather disk metadata/state snapshot and delegate planning to pure `decide_file_read`."""
    canon = os.path.realpath(raw_path)
    if not os.path.isfile(canon) or Path(canon).suffix.lower() in BINARY_MEDIA_EXTENSIONS: return PlannedFileRead(FileReadOutcome({"decision": "allow"}))
    sha256, target_stat = file_io.stat_and_compute_file_sha256(canon)
    if sha256 is None: return PlannedFileRead(FileReadOutcome({"decision": "allow"}))
    special = json_outliners.classify_special_read_target(canon)
    cfg = config.load_runtime_config() if (can_trim is None or min_tier is None or special.is_twg_stdout) else {}
    eff_trim = can_trim if can_trim is not None else (cfg.get("optimizers") or {}).get("range_trim") != "off"
    eff_tier = min_tier if min_tier is not None else (1 if cfg.get("read_confirm_policy", "strict") == "bounded" else 2)
    twg_act = special.is_twg_stdout and (cfg.get("integrations") or {}).get("atlassian_twg") == "active"
    is_special = special.is_mcp_step_output or twg_act or special.is_transcript_log
    prepared = _prepare_special(canon, special, twg_act, start_line, end_line, state_dir_path) if is_special and byte_offset == 0 else None
    if locked_state_fn is state_store.locked_state:
        state = state_store.read_state_snapshot(state_dir_path)
    else:
        with locked_state_fn(state_dir_path) as txn: state = json.loads(json.dumps(txn.state))
    _, _, pre_entry = _prepare_step_and_entry(copy.deepcopy(state), canon, sha256, step_idx, auto_increment_step, persist=False)
    pu = pre_entry.get("unwrapped_path")
    unwrapped_exists = isinstance(pu, str) and os.path.isfile(pu)
    u_lines = (file_io.count_file_lines_streaming(pu) or 0) if unwrapped_exists and isinstance(pu, str) else 0
    u_sha_opt, u_stat = file_io.stat_and_compute_file_sha256(pu) if unwrapped_exists and isinstance(pu, str) else (None, None)
    u_sha = u_sha_opt or ""
    planned_unwrap = os.path.realpath(str(prepared.pending_write.target_path)) if prepared is not None and prepared.pending_write is not None else None
    planned = decide_file_read(
        raw_path=raw_path, canon=canon, sha256=sha256, target_lines=file_io.count_file_lines_streaming(canon) or 0, state=state,
        start_line=start_line, end_line=end_line, byte_offset=byte_offset, step_idx=step_idx, allow_auto_outline=allow_auto_outline,
        path_arg_key=path_arg_key, auto_increment_step=auto_increment_step, harness=harness, read_tool=read_tool, can_trim=eff_trim,
        can_redirect_path=can_redirect_path, call_id=call_id, synthetic_id=synthetic_id, model=model, min_tier=eff_tier, special=special,
        prepared=prepared, twg_active=twg_act, unwrapped_exists=unwrapped_exists, unwrapped_lines=u_lines, unwrapped_sha256=u_sha,
        planned_unwrapped_path=planned_unwrap, now_ts=time.time(), slice_measurer=_measure_slice, slice_fingerprinter=_slice_norm_fingerprint,
        state_dir_path=state_dir_path, locked_state_fn=locked_state_fn, unwrap_writer=unwrap_writer)
    if planned.meta is None:
        return planned
    pr = planned.meta.pending_read
    eff_r_stat = u_stat if (planned.meta.pending_write is None and pr is not None and pr.is_redirect) else None
    return planned._replace(meta=replace(planned.meta, target_stat=target_stat, redirect_stat=eff_r_stat))

def _strip_dangling_redirect(dec: dict[str, Any], rec: dict[str, Any], path_arg_key: str) -> None:
    if isinstance((ow := dec.get("overwrite")), dict):
        cleaned = {k: v for k, v in ow.items() if k != path_arg_key}
        if cleaned: dec["overwrite"] = cleaned
        else: dec.pop("overwrite", None)
    rec["redirect_path"], rec["is_redirect"] = None, False

def _verify_file_pre_lock(
    path: str,
    expected_sha: str,
    expected_stat: tuple[int, int, int, int] | None,
    *,
    force_hash: bool,
) -> tuple[bool, tuple[int, int, int, int] | None]:
    if not force_hash and expected_stat is not None:
        cur_stat = file_io.stat_file_identity(path)
        return (cur_stat == expected_stat, cur_stat)
    cur_sha, cur_stat = file_io.stat_and_compute_file_sha256(path)
    return (cur_sha is not None and cur_sha == expected_sha, cur_stat)

def _verify_pre_lock_targets(
    canon: str,
    meta: PlannerMeta,
) -> tuple[str | None, tuple[int, int, int, int] | None, tuple[int, int, int, int] | None]:
    pr = meta.pending_read
    mutating = meta.is_outline or (pr is not None and (pr.is_trim or pr.is_redirect))
    ok_target, t_stat = _verify_file_pre_lock(canon, meta.sha256, meta.target_stat, force_hash=mutating)
    if not ok_target:
        return ("target sha256 changed", None, None)
    r_stat: tuple[int, int, int, int] | None = None
    if meta.pending_write is None and pr is not None and pr.is_redirect and pr.redirect_path:
        ok_redir, r_stat = _verify_file_pre_lock(
            pr.redirect_path, pr.sha256 or meta.sha256, meta.redirect_stat, force_hash=True,
        )
        if not ok_redir:
            return ("unwrapped redirect target changed", None, None)
    return (None, t_stat, r_stat)

def _detect_toctou_mismatch(
    state: dict[str, Any],
    canon: str,
    meta: PlannerMeta,
    verified_stats: tuple[tuple[int, int, int, int] | None, tuple[int, int, int, int] | None],
) -> str | None:
    t_stat, r_stat = verified_stats
    if t_stat is None or file_io.stat_file_identity(canon) != t_stat:
        return "target sha256 changed"
    _, _, chk_entry = _prepare_step_and_entry(copy.deepcopy(state), canon, meta.sha256, meta.step_idx, meta.auto_increment_step, persist=False)
    if _snapshot_reads(chk_entry.get("reads") or []) != meta.expected_reads_snapshot:
        return "recorded reads changed"
    if meta.is_outline and bool(chk_entry.get("outlined")):
        return "file already outlined"
    pr = meta.pending_read
    if meta.pending_write is None and pr is not None and pr.is_redirect and pr.redirect_path:
        if r_stat is None or file_io.stat_file_identity(pr.redirect_path) != r_stat:
            return "unwrapped redirect target changed"
    return None

def commit_planned_file_read(planned: PlannedFileRead) -> FileReadOutcome:
    """Persist unwrap files, pending reads, and step watermarks for an approved `PlannedFileRead`."""
    if not planned.needs_commit or planned.state_dir_path is None or planned.meta is None: return planned.outcome
    meta, o = planned.meta, planned.outcome
    pre_err, t_stat, r_stat = _verify_pre_lock_targets(planned.canon, meta)
    if pre_err is not None:
        warn(f"commit_planned_file_read aborted stale plan ({planned.canon}): {pre_err}")
        return FileReadOutcome({"decision": "allow"}, effective_step_idx=o.effective_step_idx)
    try:
        with planned.locked_state_fn(planned.state_dir_path) as txn:
            if (stale := _detect_toctou_mismatch(txn.state, planned.canon, meta, (t_stat, r_stat))) is not None:
                warn(f"commit_planned_file_read aborted stale plan ({planned.canon}): {stale}")
                return FileReadOutcome({"decision": "allow"}, effective_step_idx=o.effective_step_idx)
            eff_step, files_map, entry = _prepare_step_and_entry(txn.state, planned.canon, meta.sha256, meta.step_idx, meta.auto_increment_step, persist=True)
            actual = planned.unwrap_writer(meta.pending_write) if meta.pending_write is not None else None
            if meta.pending_write is not None and not actual:
                warn(f"unwrap_writer returned None for {planned.canon}; stripping dangling redirect")
            if meta.is_outline:
                out_l = (file_io.count_file_lines_streaming(actual) if actual else 0) or int(meta.outlined_total_lines)
                entry.update({"outlined": True, "outlined_step": eff_step, "outlined_total_lines": out_l})
                entry.pop("pending_followup_kind", None)
                if (pk := meta.pending_followup_kind) is not None: entry["pending_followup_kind"] = pk
                if actual:
                    entry["unwrapped_path"] = actual
                    mirror_unwrapped_entry(files_map, actual, eff_step, mark_outlined=True, total_lines=out_l, pending_followup_kind=pk, mirror_source=planned.canon if pk else None)
                dec = dict(o.decision)
                if meta.pending_write is not None and not actual and isinstance(dec.get("reason"), str):
                    dec["reason"] = dec["reason"].replace(f", unwrapped at {os.path.realpath(str(meta.pending_write.target_path))}", "")
                files_map[planned.canon] = entry
                txn.dirty = True
                if not txn.save():
                    warn(f"allowing unguarded read of {planned.canon}: outline marker not persisted")
                    return FileReadOutcome({"decision": "allow"}, effective_step_idx=eff_step)
                return FileReadOutcome(dec, intervention="outline", effective_step_idx=eff_step)
            if meta.pending_read is None: return FileReadOutcome({"decision": "allow"}, effective_step_idx=eff_step)
            dec, rec = dict(o.decision), meta.pending_read.to_dict()
            if meta.pending_write is not None and not actual:
                _strip_dangling_redirect(dec, rec, meta.path_arg_key)
                rec["sha256"], rec["expected_norm_sha256"] = meta.sha256, None
            elif actual:
                entry["unwrapped_path"], entry["reads"] = actual, []
                rl = file_io.count_file_lines_streaming(actual) or int(meta.target_lines)
                mirror_unwrapped_entry(files_map, actual, eff_step, mark_outlined=True, total_lines=rl)
                rec["redirect_path"], rec["sha256"] = actual, (file_io.compute_file_sha256(actual) or rec["sha256"])
                if isinstance(dec.get("overwrite"), dict): dec["overwrite"] = dict(dec["overwrite"], **{meta.path_arg_key: actual})
            for tgt in ((entry, *(files_map.get(p) for p in meta.peer_paths)) if meta.clear_followups else ()):
                if isinstance(tgt, dict): tgt.pop("pending_followup_kind", None); tgt.pop("outline_pull_step", None)
            rec["step"] = eff_step
            eff_id = str(meta.call_id or f"__synth__:{eff_step}:{rec['exec_start']}:{rec['exec_end']}")
            session_lifecycle.store_pending_read(entry, eff_id, rec, float(rec.get("ts") or time.time()))
            files_map[planned.canon] = entry
            txn.dirty = True
            if not txn.save():
                warn(f"commit_planned_file_read fallback ({planned.canon}): failed to persist session state")
                return FileReadOutcome({"decision": "allow"}, effective_step_idx=eff_step)
            return FileReadOutcome(dec, o.intervention, eff_step, o.followup_resolution)
    except (StatePersistenceError, OSError) as exc:
        warn(f"commit_planned_file_read fallback ({planned.canon}): {exc}")
        return FileReadOutcome({"decision": "allow"}, effective_step_idx=o.effective_step_idx)

def handle_file_read_verdict(state_dir_path: Path, *args: Any, **kw: Any) -> FileReadOutcome:
    """Plan and immediately commit a file-read verdict for existing standalone callers."""
    pl = plan_file_read_verdict(state_dir_path, *args, **kw)
    return commit_planned_file_read(pl) if pl.needs_commit else pl.outcome
