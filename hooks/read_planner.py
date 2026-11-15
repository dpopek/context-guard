"""Silent range-trim and machine-artifact auto-outline planner for Context-Guard PreToolUse."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, NamedTuple

from hooks import config, file_io, json_outliners, outcomes, session_lifecycle, state_store, telemetry
from hooks.state_store import merge_intervals
from integrations.atlassian_twg import prepare_twg_stdout_outline

TRANSCRIPT_OUTLINE_LINE_THRESHOLD = 8
FOLLOWUP_TARGETED_MAX_LINES = 250
MAX_TIER2_LINES = 2000
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
    meta: dict[str, Any] = {}
    locked_state_fn: Callable[[Path], Any] = state_store.locked_state
    unwrap_writer: Callable[[Any], str | None] = json_outliners.materialize_unwrap_write

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
    return [
        [b[0], b[1], int(e[2]), int(e[3])] for e in recorded_ranges
        if state_store.is_valid_read_interval(e)
        and (b := normalize_effective_bounds(int(e[0]), int(e[1]), target_lines))
    ]

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

def covering_read_step(
    recorded_ranges: list[list[int]], req_start: int, req_end: int, target_lines: int = 0,
    *, min_tier: int = 2,
) -> int | None:
    """Step of qualifying recorded reads covering `[req_start, req_end]`, or `None` when uncovered."""
    if not (bounds := normalize_effective_bounds(req_start, req_end, target_lines)):
        return None
    es, ee = bounds
    return next(
        (st for rs, re_, st in _collapse_qualified_reads(recorded_ranges, target_lines, min_tier)
         if rs <= es and (re_ == -1 or (ee != -1 and re_ >= ee))), None,
    )

def trim_partially_covered_range(
    reads: list[list[int]], req_start: int, req_end: int, target_lines: int = 0, *, min_tier: int = 2,
) -> tuple[int, int] | None:
    """Trim leading or trailing overlap against qualifying (`tier >= min_tier`) already-read intervals."""
    bounds = normalize_effective_bounds(req_start, req_end, target_lines)
    if bounds is None or bounds[1] == -1:
        return None
    eff_s, eff_e = bounds
    ns, ne = eff_s, eff_e
    for rs, re_, _ in _collapse_qualified_reads(reads, target_lines, min_tier):
        if re_ == -1:
            ne = min(ne, rs - 1) if rs <= ne else ne
        elif rs <= ns <= re_ < ne:
            ns = re_ + 1
        elif ns < rs <= ne <= re_:
            ne = rs - 1
    return (ns, ne) if (ns, ne) != (eff_s, eff_e) and ns <= ne else None

def _prepare_special(
    canon: str, special: Any, twg_active: bool, start_line: int, end_line: int, sdir: Path,
) -> json_outliners.PreparedOutline | None:
    fp, st_size = Path(canon), os.path.getsize(canon)
    if special.is_mcp_step_output:
        return json_outliners.prepare_mcp_step_outline(fp, st_size)
    if twg_active:
        return prepare_twg_stdout_outline(fp, st_size, cache_dir=sdir / "twg_cache")
    if special.is_transcript_log and (tr := json_outliners.build_transcript_jsonl_outline(
        fp, st_size, 10 * 1024 * 1024, start_line=start_line, end_line=end_line,
    )) and tr[0] > TRANSCRIPT_OUTLINE_LINE_THRESHOLD:
        return json_outliners.PreparedOutline(total_lines=tr[0], outline_text=tr[1])
    return None

def mirror_unwrapped_entry(
    files_map: dict[str, Any], actual_unwrapped: str, eff_step: int, mark_outlined: bool = False,
    total_lines: int = 0, read_interval: list[int] | None = None,
    pending_followup_kind: str | None = None, mirror_source: str | None = None,
) -> None:
    """Mirror outline markers and confirmed 4-tuple read intervals onto an unwrapped target."""
    if not actual_unwrapped or not os.path.isfile(actual_unwrapped):
        return
    u_sha = file_io.compute_file_sha256(actual_unwrapped) or ""
    ex = files_map.get(actual_unwrapped)
    if not isinstance(ex, dict) or ex.get("sha256") != u_sha:
        ex = {"sha256": u_sha, "reads": []}
    if mark_outlined:
        extra = {"outlined_total_lines": total_lines} if total_lines > 0 else {}
        ex.update({"outlined": True, "outlined_step": eff_step, **extra})
    for k, v in (("pending_followup_kind", pending_followup_kind), ("mirror_source", mirror_source)):
        if v is not None:
            ex[k] = v
    if read_interval is not None and state_store.is_valid_read_interval(read_interval):
        if isinstance((reads := ex.setdefault("reads", [])), list):
            reads.append(list(read_interval[:4]))
    files_map[actual_unwrapped] = ex

def _slice_norm_fingerprint(
    read_target: str, pending_content: str | None, es: int, de: int | None,
    byte_offset: int, slice_bytes: int, target_sha: str | None,
) -> str | None:
    if (byte_offset > 0 or not target_sha or de is None or de < es or es < 1
            or (de - es + 1) > MAX_TIER2_LINES or slice_bytes > telemetry.CLAUDE_COVERAGE_MAX_SLICE_BYTES):
        return None
    try:
        if pending_content is not None:
            sel = pending_content.splitlines()[es - 1 : de]
        else:
            with open(read_target, "r", encoding="utf-8", errors="replace") as fh:
                sel = [ln.rstrip("\r\n") for n, ln in enumerate(fh, 1) if es <= n <= de]
        if len(sel) == (de - es + 1):
            return normalize_read_body_fingerprint("\n".join(sel))
    except OSError:
        pass
    return None

def _followup_outcome(
    entry: dict[str, Any], files_map: dict[str, Any], peers: tuple[str, ...], s: int, e: int, t_lines: int,
) -> tuple[str, str] | None:
    p_kind = entry.get("pending_followup_kind") or next(
        (pe.get("pending_followup_kind") for o in peers
         if isinstance((pe := files_map.get(o)), dict) and pe.get("pending_followup_kind") is not None), None,
    )
    if p_kind not in ("outline", "outline_pull"):
        return None
    span = (e if e != -1 else t_lines) - s + 1
    tgt = not (s == 1 and e == -1) and (e != -1 or t_lines > 0) and span <= FOLLOWUP_TARGETED_MAX_LINES
    return str(p_kind), ("targeted_followup" if tgt else "full_bypass")

def _prepare_step_and_entry(
    state: dict[str, Any], canon: str, sha256: str, step_idx: int, auto_inc: bool, *, persist: bool,
) -> tuple[int, dict[str, Any], dict[str, Any]]:
    prev_max = int(state.get("max_tool_step_idx") or 0)
    if not auto_inc and 0 < step_idx < prev_max:
        session_lifecycle.prune_state_on_rewind(state, step_idx, inclusive=True)
    eff_step = (int(state.get("auto_step_seq") or 0) + 1) if (auto_inc and step_idx <= 0) else step_idx
    if persist:
        if auto_inc and step_idx <= 0:
            state["auto_step_seq"] = eff_step
        if eff_step > int(state.get("max_tool_step_idx") or 0):
            state["max_tool_step_idx"] = eff_step
    fmap: dict[str, Any] = state.setdefault("files", {}) if persist else (
        rf if isinstance((rf := state.get("files")), dict) else {}
    )
    raw_e = fmap.get(canon)
    ent = (
        dict(raw_e) if isinstance(raw_e, dict) and raw_e.get("sha256") == sha256
        else {"sha256": sha256, "reads": []}
    )
    return eff_step, fmap, ent

def _measure_slice(read_target: str, p_lines: list[str] | None, s: int, e: int) -> int:
    if p_lines is None:
        return telemetry.measure_slice_bytes(read_target, s, e) or 0
    if s < 1 or s > len(p_lines):
        return 0
    stop = len(p_lines) if e == -1 else min(len(p_lines), e)
    return sum(len(ln.encode("utf-8")) for ln in p_lines[s - 1 : stop])

def plan_file_read_verdict(
    state_dir_path: Path, raw_path: str, start_line: int, end_line: int, byte_offset: int, step_idx: int,
    allow_auto_outline: bool = True, path_arg_key: str = "Path", auto_increment_step: bool = False,
    harness: str = "antigravity", read_tool: str = "read_file", can_trim: bool | None = None,
    can_redirect_path: bool = True, locked_state_fn: Callable[[Path], Any] = state_store.locked_state,
    unwrap_writer: Callable[[Any], str | None] = json_outliners.materialize_unwrap_write, *,
    call_id: str = "", synthetic_id: bool | None = None, model: str = "unknown", min_tier: int | None = None,
) -> PlannedFileRead:
    """Plan a file-read decision purely in memory without disk writes or state mutations."""
    canon = os.path.realpath(raw_path)
    if not os.path.isfile(canon) or Path(canon).suffix.lower() in telemetry.BINARY_MEDIA_EXTENSIONS:
        return PlannedFileRead(FileReadOutcome({"decision": "allow"}))
    if (sha256 := file_io.compute_file_sha256(canon)) is None:
        return PlannedFileRead(FileReadOutcome({"decision": "allow"}))
    special = json_outliners.classify_special_read_target(canon)
    need_cfg = can_trim is None or min_tier is None or special.is_twg_stdout
    cfg = config.load_runtime_config() if need_cfg else {}
    eff_trim = can_trim if can_trim is not None else (cfg.get("optimizers") or {}).get("range_trim") != "off"
    eff_tier = min_tier if min_tier is not None else (
        1 if cfg.get("read_confirm_policy", "strict") == "bounded" else 2
    )
    twg_act = special.is_twg_stdout and (cfg.get("integrations") or {}).get("atlassian_twg") == "active"
    is_special = special.is_mcp_step_output or twg_act or special.is_transcript_log
    prepared = (
        _prepare_special(canon, special, twg_act, start_line, end_line, state_dir_path)
        if is_special and byte_offset == 0 else None
    )
    if locked_state_fn is state_store.locked_state:
        state = state_store.read_state_snapshot(state_dir_path)
    else:
        with locked_state_fn(state_dir_path) as txn:
            state = json.loads(json.dumps(txn.state))
    eff_step, files_map, entry = _prepare_step_and_entry(
        state, canon, sha256, step_idx, auto_increment_step, persist=False,
    )
    reads = [r for r in (entry.get("reads") or []) if state_store.is_valid_read_interval(r)]
    is_tr = special.is_transcript_log
    t_ok = (not is_tr) or end_line == -1 or (end_line - start_line + 1) > TRANSCRIPT_OUTLINE_LINE_THRESHOLD
    if (
        is_special and prepared is not None and byte_offset == 0 and (allow_auto_outline or twg_act)
        and not entry.get("outlined") and (is_tr or not any(int(r[2]) != eff_step for r in reads)) and t_ok
    ):
        pw = prepared.pending_write if can_redirect_path else None
        ot = json_outliners.finalize_outline_text(
            prepared, os.path.realpath(str(pw.target_path)) if pw else None,
        )
        is_inl, base = bool(twg_act and "— full payload inline)" in ot), os.path.basename(canon) or canon
        fa = raw_path or base
        hint = (
            f"Use `sed -n 'START,ENDp' {fa}` to read specific line ranges." if harness == "codex" else
            f"Call `Read` with targeted `offset` and `limit` for `{fa}`." if harness in ("claude", "cursor")
            else f"Call `{read_tool}` with targeted `StartLine` and `EndLine` for `{fa}`."
        )
        reason = (
            f"CONTEXT-GUARD TWG INLINE READ: {base} ({prepared.total_lines} lines) delivered inline to avoid "
            f"out-of-workspace prompts:\n\n{ot}\n\nNo further `read_file` call is needed for this file."
            if is_inl else f"CONTEXT-GUARD AUTO-OUTLINE: {base} has {prepared.total_lines} lines. "
            f"Full-file read intercepted to save tokens. Structural outline:\n\n{ot}\n\n{hint}"
        )
        meta = {
            "sha": sha256, "step": step_idx, "inc": auto_increment_step, "ol": True,
            "pw": pw, "out_l": int(prepared.total_lines), "pk_name": None if is_inl else "outline",
        }
        out = FileReadOutcome({"decision": "deny", "reason": reason}, "outline", eff_step)
        return PlannedFileRead(out, True, state_dir_path, canon, meta, locked_state_fn, unwrap_writer)
    redir_p, redir_pw, pend_text = None, None, None
    if can_redirect_path and (special.is_mcp_step_output or twg_act) and (
        start_line > 1 or end_line != -1 or not allow_auto_outline or twg_act
    ):
        if isinstance((pu := entry.get("unwrapped_path")), str) and os.path.isfile(pu):
            redir_p = pu
        elif prepared is not None and prepared.pending_write is not None:
            redir_pw = prepared.pending_write
            redir_p, pend_text, reads = os.path.realpath(str(redir_pw.target_path)), str(redir_pw.content), []
    read_target = redir_p or canon
    p_lines = pend_text.splitlines(keepends=True) if pend_text is not None else None
    t_lines = len(p_lines) if p_lines is not None else (file_io.count_file_lines_streaming(read_target) or 0)
    t_sha = sha256 if (pend_text is None and read_target == canon) else (
        hashlib.sha256(pend_text.encode("utf-8")).hexdigest() if pend_text is not None
        else (file_io.compute_file_sha256(read_target) or sha256)
    )
    cap_0 = telemetry.HARNESS_READ_CAPS.get(harness, (t_lines, 0))[0]
    probe_e = min(t_lines, cap_0) if (start_line == 1 and end_line == -1 and t_lines > 0) else end_line
    trimmed = (
        trim_partially_covered_range(reads, start_line, probe_e, target_lines=t_lines, min_tier=eff_tier)
        if eff_trim and byte_offset == 0 else None
    )
    if trimmed is not None and t_lines > 0 and trimmed[0] > t_lines:
        trimmed = None
    es, ee = trimmed or (start_line, end_line)
    cap_e = telemetry.cap_end_line_for_harness(harness, es, ee)
    cap_re = telemetry.cap_end_line_for_harness(harness, start_line, end_line)
    slice_b = _measure_slice(read_target, p_lines, es, cap_e)
    req_b = slice_b if trimmed is None else _measure_slice(read_target, p_lines, start_line, cap_re)
    deliv_end = outcomes.estimate_delivered_end_line(harness, es, ee, t_lines, slice_b)
    exp_norm = _slice_norm_fingerprint(read_target, pend_text, es, deliv_end, byte_offset, slice_b, t_sha)
    peers = tuple(p for p in (entry.get("unwrapped_path"), entry.get("mirror_source"), redir_p)
                  if isinstance(p, str))
    fu = None if byte_offset else _followup_outcome(entry, files_map, peers, start_line, end_line, t_lines)
    ow: dict[str, Any] = {"StartLine": trimmed[0], "EndLine": trimmed[1]} if trimmed is not None else {}
    if redir_p:
        ow[path_arg_key] = redir_p
    dec: dict[str, Any] = {"decision": "allow", **({"overwrite": ow} if ow else {})}
    synth = (not bool(call_id)) if synthetic_id is None else bool(synthetic_id)
    pending_record = {
        "raw_path": raw_path, "canonical_target": canon, "exec_start": es, "exec_end": ee,
        "delivered_end": deliv_end if deliv_end is not None else -1, "target_lines": t_lines,
        "step": eff_step, "sha256": t_sha, "expected_norm_sha256": exp_norm, "slice_bytes": slice_b,
        "byte_offset": byte_offset, "redirect_path": redir_p, "is_trim": trimmed is not None,
        "is_redirect": redir_p is not None, "req_bytes": req_b, "trimmed_bytes": slice_b,
        "saved_bytes": max(0, req_b - slice_b) if trimmed is not None else 0, "synthetic_id": synth,
        "post_stage": "pending", "credited": False, "model": model, "ts": time.time(),
    }
    meta = {"sha": sha256, "step": step_idx, "inc": auto_increment_step, "ol": False, "pw": redir_pw,
            "rl": t_lines, "pk": path_arg_key, "cid": call_id, "pending": pending_record,
            "clr": (byte_offset == 0), "peers": peers}
    out = FileReadOutcome(dec, ("range_trim" if trimmed is not None else None), eff_step, fu)
    return PlannedFileRead(out, True, state_dir_path, canon, meta, locked_state_fn, unwrap_writer)

def commit_planned_file_read(planned: PlannedFileRead) -> FileReadOutcome:
    """Persist unwrap files, pending reads, and step watermarks for an approved `PlannedFileRead`."""
    if not planned.needs_commit or planned.state_dir_path is None:
        return planned.outcome
    meta, o = planned.meta, planned.outcome
    try:
        with planned.locked_state_fn(planned.state_dir_path) as txn:
            eff_step, files_map, entry = _prepare_step_and_entry(
                txn.state, planned.canon, str(meta["sha"]), int(meta["step"]),
                bool(meta["inc"]), persist=True,
            )
            actual = planned.unwrap_writer(meta["pw"]) if meta["pw"] is not None else None
            if meta["ol"]:
                out_l = (file_io.count_file_lines_streaming(actual) if actual else 0) or int(meta["out_l"])
                entry.update({"outlined": True, "outlined_step": eff_step, "outlined_total_lines": out_l})
                entry.pop("pending_followup_kind", None)
                if (pk := meta["pk_name"]) is not None:
                    entry["pending_followup_kind"] = pk
                if actual:
                    entry["unwrapped_path"] = actual
                    mirror_unwrapped_entry(
                        files_map, actual, eff_step, mark_outlined=True, total_lines=out_l,
                        pending_followup_kind=pk, mirror_source=planned.canon if pk else None,
                    )
                files_map[planned.canon] = entry
                if not txn.save():
                    msg = f"allowing unguarded read of {planned.canon}: outline marker not persisted"
                    state_store.warn(msg)
                    return FileReadOutcome({"decision": "allow"}, effective_step_idx=eff_step)
                return FileReadOutcome(o.decision, intervention="outline", effective_step_idx=eff_step)
            dec, rec = dict(o.decision), dict(meta["pending"])
            if actual:
                entry["unwrapped_path"], entry["reads"] = actual, []
                rl = file_io.count_file_lines_streaming(actual) or int(meta["rl"])
                mirror_unwrapped_entry(files_map, actual, eff_step, mark_outlined=True, total_lines=rl)
                rec["redirect_path"] = actual
                rec["sha256"] = file_io.compute_file_sha256(actual) or rec["sha256"]
                if isinstance(dec.get("overwrite"), dict):
                    dec["overwrite"] = dict(dec["overwrite"], **{meta["pk"]: actual})
            for tgt in ((entry, *(files_map.get(p) for p in meta["peers"])) if meta["clr"] else ()):
                if isinstance(tgt, dict):
                    tgt.pop("pending_followup_kind", None)
                    tgt.pop("outline_pull_step", None)
            rec["step"] = eff_step
            eff_id = str(meta["cid"] or f"__synth__:{eff_step}:{rec['exec_start']}:{rec['exec_end']}")
            session_lifecycle.store_pending_read(entry, eff_id, rec, float(rec.get("ts") or time.time()))
            files_map[planned.canon] = entry
            txn.dirty = True
            return FileReadOutcome(dec, o.intervention, eff_step, o.followup_resolution)
    except OSError as exc:
        state_store.warn(f"commit_planned_file_read fallback ({planned.canon}): {exc}")
        return FileReadOutcome({"decision": "allow"}, effective_step_idx=o.effective_step_idx)

def handle_file_read_verdict(state_dir_path: Path, *args: Any, **kw: Any) -> FileReadOutcome:
    """Plan and immediately commit a file-read verdict for existing standalone callers."""
    pl = plan_file_read_verdict(state_dir_path, *args, **kw)
    return commit_planned_file_read(pl) if pl.needs_commit else pl.outcome
