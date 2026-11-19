"""Accurate grep span merging, raw source byte hashing, turn verification, and recovery outcome helpers."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence

from core.platform_io import check_unsafe_link

_SPOOL_ID_RE = re.compile(r"^sp_[0-9a-f]{12}$")
_SPOOL_ID_TOKEN_RE = re.compile(r"\b(sp_[0-9a-f]{12})\b")
_BLOB_TOKEN_RE = re.compile(r"(sp_[0-9a-f]{12})\.txt(?![A-Za-z0-9_])")
_SELF_CLI_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:cg-spool(?:\.(?:exe|cmd|bat))?|cg_spool\.py)(?![A-Za-z0-9_-])", re.I)
_EXIT_LINE_RE = re.compile(r"(?:^|\n)Exit code (-?\d+)\s*$")
_TRANSCRIPT_TAIL_BYTES = 65_536
_PENDING_META_KEYS = ("p_cid", "p_rec", "p_reg", "p_step")

if sys.platform == "win32":
    _O_FLAGS = os.O_BINARY
else:
    _O_FLAGS = os.O_NOFOLLOW


def merge_spans(spans: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and merge overlapping or adjacent half-open spans without bridging gaps."""
    norm = sorted(
        (max(0, int(s)), max(0, int(e)))
        for s, e in spans
        if int(e) > max(0, int(s))
    )
    if not norm:
        return []
    merged: list[tuple[int, int]] = [norm[0]]
    for s, e in norm[1:]:
        prev_s, prev_e = merged[-1]
        if s <= prev_e:
            merged[-1] = (prev_s, max(prev_e, e))
        else:
            merged.append((s, e))
    return merged


def interval_union_bytes(spans: Sequence[tuple[int, int]]) -> int:
    """Compute unique covered bytes over possibly overlapping half-open spans."""
    return sum(e - s for s, e in merge_spans(spans))


def _line_byte_offsets(lines: Sequence[str]) -> tuple[list[int], list[int]]:
    offsets: list[int] = []
    lengths: list[int] = []
    cur = 0
    for line_text in lines:
        offsets.append(cur)
        blen = len(line_text.encode("utf-8"))
        lengths.append(blen)
        cur += blen + 1
    return offsets, lengths


def _line_span_bytes(offsets: Sequence[int], lengths: Sequence[int], start: int, end: int) -> tuple[int, int]:
    return (offsets[start], offsets[end - 1] + lengths[end - 1])


def compute_grep_span_metrics(lines: Sequence[str], match_windows: Sequence[tuple[int, int]]) -> dict[str, Any]:
    """Compute disjoint merged spans, envelope spans, unique bytes, and repeated context bytes."""
    n_lines = len(lines)
    valid = [
        (max(0, int(s)), min(n_lines, int(e)))
        for s, e in match_windows
        if min(n_lines, int(e)) > max(0, int(s))
    ]
    if not valid:
        return {
            "merged_line_spans": [],
            "merged_byte_spans": [],
            "line_span": (0, 0),
            "byte_span": (0, 0),
            "unique_bytes": 0,
            "repeated_context_bytes": 0,
        }
    offsets, lengths = _line_byte_offsets(lines)
    win_byte_spans = [_line_span_bytes(offsets, lengths, s, e) for s, e in valid]
    raw_window_bytes = sum(e - s for s, e in win_byte_spans)
    unique_win_bytes = interval_union_bytes(win_byte_spans)
    merged_line_spans = merge_spans(valid)
    merged_byte_spans = [_line_span_bytes(offsets, lengths, s, e) for s, e in merged_line_spans]
    return {
        "merged_line_spans": merged_line_spans,
        "merged_byte_spans": merged_byte_spans,
        "line_span": (merged_line_spans[0][0], merged_line_spans[-1][1]),
        "byte_span": (merged_byte_spans[0][0], merged_byte_spans[-1][1]),
        "unique_bytes": interval_union_bytes(merged_byte_spans),
        "repeated_context_bytes": max(0, raw_window_bytes - unique_win_bytes),
    }


def grep_lines_with_spans(
    lines: Sequence[str],
    rx: re.Pattern[str],
    max_matches: int,
    context_lines: int,
) -> tuple[list[dict[str, Any]], bool, dict[str, Any]]:
    """Run bounded regex search on lines and return `(matches, truncated, span_metrics)`."""
    eff_max = max(1, min(200, int(max_matches)))
    eff_ctx = max(0, min(10, int(context_lines)))
    truncated = False
    matches: list[dict[str, Any]] = []
    windows: list[tuple[int, int]] = []
    for idx, line_text in enumerate(lines):
        if not rx.search(line_text):
            continue
        if len(matches) >= eff_max:
            truncated = True
            break
        b_start, a_end = max(0, idx - eff_ctx), min(len(lines), idx + 1 + eff_ctx)
        windows.append((b_start, a_end))
        matches.append({
            "line": idx + 1,
            "text": line_text,
            "before": list(lines[b_start:idx]) if eff_ctx else [],
            "after": list(lines[idx + 1 : a_end]) if eff_ctx else [],
        })
    return matches, truncated, compute_grep_span_metrics(lines, windows)


def _normalize_span_list(raw: Any) -> list[tuple[int, int]] | None:
    if not isinstance(raw, (list, tuple)):
        return None
    out: list[tuple[int, int]] = []
    for item in raw:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            return None
        s, e = item[0], item[1]
        if isinstance(s, bool) or not isinstance(s, int) or isinstance(e, bool) or not isinstance(e, int):
            return None
        if s < 0 or e < s:
            return None
        out.append((int(s), int(e)))
    return out


def extract_optional_receipt_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    """Extract and validate optional additive `ContextReceiptV1` fields when present."""
    extra: dict[str, Any] = {}
    for span_key in ("recovered_line_spans", "recovered_byte_spans"):
        if span_key in row and (parsed := _normalize_span_list(row.get(span_key))) is not None:
            extra[span_key] = parsed
    for int_key in ("recovered_context_bytes", "blob_bytes"):
        val = row.get(int_key)
        if isinstance(val, int) and not isinstance(val, bool) and val >= 0:
            extra[int_key] = int(val)
    if isinstance((b_sha := row.get("blob_sha256")), str) and b_sha:
        extra["blob_sha256"] = b_sha
    return extra


def measure_raw_source_bytes(raw_text: str | bytes) -> tuple[str, int] | None:
    """Hash and size exact received UTF-8 bytes prior to newline normalization."""
    if isinstance(raw_text, bytes):
        try:
            decoded = raw_text.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
        if "\x00" in decoded:
            return None
        return hashlib.sha256(raw_text).hexdigest(), len(raw_text)
    if isinstance(raw_text, str):
        if "\x00" in raw_text:
            return None
        try:
            encoded = raw_text.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return None
        return hashlib.sha256(encoded).hexdigest(), len(encoded)
    return None


def _read_regular_tail_bytes(path: Path, max_bytes: int) -> tuple[bytes | None, bool]:
    if check_unsafe_link(path):
        return None, False
    try:
        l_st = os.lstat(str(path))
    except OSError:
        return None, False
    if not stat.S_ISREG(l_st.st_mode) or l_st.st_size <= 0:
        return None, False
    try:
        fd = os.open(str(path), os.O_RDONLY | _O_FLAGS)
    except OSError:
        return None, False
    try:
        with os.fdopen(fd, "rb") as fh:
            f_st = os.fstat(fh.fileno())
            if not stat.S_ISREG(f_st.st_mode) or f_st.st_size <= 0:
                return None, False
            if (l_st.st_ino != 0 or f_st.st_ino != 0) and (f_st.st_dev, f_st.st_ino) != (l_st.st_dev, l_st.st_ino):
                return None, False
            trimmed = int(f_st.st_size) > max_bytes
            if trimmed:
                fh.seek(int(f_st.st_size) - max_bytes)
            return fh.read(max_bytes), trimmed
    except OSError:
        return None, False


def _token_from_transcript_objs(objs: Sequence[Mapping[str, Any]]) -> str:
    for obj in reversed(objs):
        for sk in ("step_index", "stepIdx", "step", "turn_index"):
            sv = obj.get(sk)
            if isinstance(sv, int) and not isinstance(sv, bool) and sv >= 0:
                return f"s{sv}"
        for ik in ("turn_id", "turnId", "uuid", "id", "request_id", "call_id"):
            iv = obj.get(ik)
            if isinstance(iv, int) and not isinstance(iv, bool) and iv > 0:
                return str(iv)
            if isinstance(iv, str) and (cleaned := re.sub(r"[^A-Za-z0-9._:-]", "_", iv.strip())[:48]):
                return cleaned
    return f"n{len(objs)}"


def _verified_transcript_token(raw_path: str) -> str | None:
    if not raw_path.strip():
        return None
    raw_bytes, trimmed = _read_regular_tail_bytes(Path(raw_path.strip()).expanduser(), _TRANSCRIPT_TAIL_BYTES)
    if raw_bytes is None:
        return None
    if trimmed and b"\n" in raw_bytes:
        raw_bytes = raw_bytes.split(b"\n", 1)[1]
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    objs: list[Mapping[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except (ValueError, TypeError):
            return None
        if not isinstance(parsed, dict):
            return None
        objs.append(parsed)
    return _token_from_transcript_objs(objs) if objs else None


def resolve_verified_turn_key(payload: Mapping[str, Any], snap: Mapping[str, Any], sess_id: str) -> tuple[str, str]:
    """Resolve `(turn_correlation, turn_key)` strictly from verified native or transcript evidence."""
    clean_sess = str(sess_id or "default")
    rs = payload.get("stepIdx")
    if isinstance(rs, int) and not isinstance(rs, bool) and rs > 0:
        return "harness_native", f"{clean_sess}:step:{rs}"
    tid_raw = payload.get("turn_id") if payload.get("turn_id") is not None else payload.get("turnId")
    if isinstance(tid_raw, str) and tid_raw.strip():
        return "harness_native", f"{clean_sess}:turn:{' '.join(tid_raw.split())[:128]}"
    if isinstance(tid_raw, int) and not isinstance(tid_raw, bool) and tid_raw > 0:
        return "harness_native", f"{clean_sess}:turn:{tid_raw}"
    lsi = snap.get("last_step_index")
    if isinstance(lsi, int) and not isinstance(lsi, bool) and lsi >= 0:
        return "transcript_derived", f"{clean_sess}:transcript_step:{lsi}"
    p_tr = payload.get("transcript_path") if isinstance(payload.get("transcript_path"), str) else payload.get("transcriptPath")
    tr_cand = p_tr if (isinstance(p_tr, str) and p_tr.strip()) else snap.get("transcript_path")
    if isinstance(tr_cand, str) and (token := _verified_transcript_token(tr_cand)) is not None:
        return "transcript_derived", f"{clean_sess}:transcript:{token}"
    snap_s = snap.get("auto_step_seq")
    seq = int(snap_s) if isinstance(snap_s, int) and not isinstance(snap_s, bool) and snap_s > 0 else 1
    return "unobserved", f"{clean_sess}:step:{max(1, seq)}"


def _payload_tool_name_and_input(payload: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
    tc = payload.get("toolCall")
    if isinstance(tc, Mapping):
        tn = str(payload.get("tool_name") or tc.get("name") or "")
        ti = payload.get("tool_input") if isinstance(payload.get("tool_input"), Mapping) else tc.get("args")
        return tn, ti if isinstance(ti, Mapping) else {}
    ti = payload.get("tool_input")
    return str(payload.get("tool_name") or ""), ti if isinstance(ti, Mapping) else {}


def extract_recovery_spool_id(payload: Mapping[str, Any]) -> str:
    """Extract a `sp_<12hex>` ID from a spool slice/grep/direct-read tool call payload."""
    tn, ti = _payload_tool_name_and_input(payload)
    args = ti.get("arguments") or ti.get("args") or ti if tn == "call_mcp_tool" else ti
    if isinstance(args, Mapping):
        raw_sid = str(args.get("spool_id") or "").strip()
        if _SPOOL_ID_RE.fullmatch(raw_sid):
            return raw_sid
    for key in ("file_path", "path", "Path", "AbsolutePath"):
        if isinstance((fp := ti.get(key)), str) and (m := _BLOB_TOKEN_RE.search(fp)):
            return m.group(1)
    rc = ti.get("command") or ti.get("cmd") or ti.get("CommandLine")
    cmd_text = rc if isinstance(rc, str) else (" ".join(str(x) for x in rc) if isinstance(rc, list) else "")
    if _SELF_CLI_RE.search(cmd_text) and (m := _SPOOL_ID_TOKEN_RE.search(cmd_text)):
        return m.group(1)
    if (m := _BLOB_TOKEN_RE.search(cmd_text)):
        return m.group(1)
    return ""


def _text_signals_spool_failure(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, Mapping) and (obj.get("ok") is False or bool(obj.get("error"))):
                return True
        except (ValueError, TypeError):
            pass
    if (m := _EXIT_LINE_RE.search(stripped)) and int(m.group(1)) != 0:
        return True
    low = stripped.lower()
    return low.startswith("error:") or any(
        tok in low for tok in ("spool_corrupt", "integrity_mismatch", "unexpectedly_missing", "spool_evicted")
    )


def _response_indicates_failure(raw_resp: Any) -> bool:
    if isinstance(raw_resp, str):
        return _text_signals_spool_failure(raw_resp)
    if isinstance(raw_resp, list):
        return any(
            isinstance(blk, Mapping) and isinstance(blk.get("text"), str) and _text_signals_spool_failure(blk["text"])
            for blk in raw_resp
        )
    if not isinstance(raw_resp, Mapping):
        return False
    if raw_resp.get("isError") is True or raw_resp.get("is_error") is True or raw_resp.get("ok") is False:
        return True
    if raw_resp.get("error"):
        return True
    for ck in ("exit_code", "exitCode", "returncode"):
        code = raw_resp.get(ck)
        if isinstance(code, int) and not isinstance(code, bool) and code != 0:
            return True
    if isinstance((content := raw_resp.get("content")), list) and _response_indicates_failure(content):
        return True
    return any(isinstance((v := raw_resp.get(k)), str) and _text_signals_spool_failure(v) for k in ("output", "stdout", "stderr", "text", "content"))


def _receipt_tail_has_failure(rcpt_path: Path, call_id: str, spool_id: str) -> bool:
    rcpt_bytes, trimmed = _read_regular_tail_bytes(rcpt_path, _TRANSCRIPT_TAIL_BYTES)
    if rcpt_bytes is None:
        return False
    if trimmed and b"\n" in rcpt_bytes:
        rcpt_bytes = rcpt_bytes.split(b"\n", 1)[1]
    for ln in rcpt_bytes.decode("utf-8", errors="ignore").splitlines():
        try:
            row = json.loads(ln) if ln.strip() else None
        except (ValueError, TypeError):
            continue
        if (
            isinstance(row, Mapping)
            and row.get("event_type") == "spool_integrity_failure"
            and row.get("call_id") == call_id
            and (not spool_id or row.get("spool_id") == spool_id)
        ):
            return True
    return False


def _index_marks_unavailable(idx_path: Path, spool_id: str) -> bool:
    idx_bytes, _ = _read_regular_tail_bytes(idx_path, 4 * 1024 * 1024)
    if idx_bytes is None:
        return False
    try:
        idx = json.loads(idx_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError, TypeError):
        return False
    if not isinstance(idx, Mapping) or not isinstance((entries := idx.get("entries")), Mapping):
        return False
    ent = entries.get(spool_id)
    return not isinstance(ent, Mapping) or ent.get("state", "available") != "available"


def has_spool_integrity_failure(spool_id: str, call_id: str, spool_dir: Path) -> bool:
    """Return True when `spool_id` is unsafe, missing, corrupt/evicted, or recorded an integrity failure."""
    if not _SPOOL_ID_RE.fullmatch(spool_id):
        return False
    if check_unsafe_link(spool_dir) or not spool_dir.is_dir():
        return True
    blob_path = spool_dir / f"{spool_id}.txt"
    if check_unsafe_link(blob_path) or not blob_path.is_file():
        return True
    if _index_marks_unavailable(spool_dir / "spool_index.json", spool_id):
        return True
    return bool(call_id and _receipt_tail_has_failure(spool_dir / "receipts.jsonl", call_id, spool_id))


def _extract_payload_call_id(payload: Mapping[str, Any]) -> str:
    raw_tc = payload.get("toolCall")
    tc: Mapping[str, Any] = raw_tc if isinstance(raw_tc, Mapping) else {}
    for k in ("tool_use_id", "call_id", "tool_call_id", "callId"):
        if isinstance((v := payload.get(k)), str) and v.strip():
            return v.strip()
    return str(tc.get("id") or tc.get("callId") or "").strip()


def classify_post_tool_recovery_outcome(
    harness: str,
    payload: Mapping[str, Any],
    event_name: str = "PostToolUse",
    spool_dir: Path | None = None,
) -> tuple[bool, str]:
    """Classify `(succeeded, spool_id)` for PostToolUse / PostToolUseFailure recovery resolution."""
    sid = extract_recovery_spool_id(payload)
    if event_name == "PostToolUseFailure" or payload.get("is_error") is True or bool(payload.get("error")):
        return False, sid
    raw_resp = payload.get("tool_output") if harness == "cursor" else payload.get("tool_response", payload.get("tool_output", payload.get("result")))
    if harness == "cursor" and isinstance(raw_resp, str):
        try:
            raw_resp = json.loads(raw_resp)
        except (ValueError, TypeError):
            pass
    if _response_indicates_failure(raw_resp):
        return False, sid
    cid = _extract_payload_call_id(payload)
    if spool_dir is not None and sid and has_spool_integrity_failure(sid, cid, spool_dir):
        return False, sid
    return True, sid


def select_spool_win_key(
    open_wins: Mapping[str, Any],
    session_id: str,
    spool_id: str,
    step_idx: int | None = None,
    call_id: str = "",
) -> str | None:
    """Pick at most one matching open `output_spool` window key for follow-up or resolution."""
    cands: list[tuple[tuple[int, int, int], str]] = []
    target_path = f"spool:{spool_id}" if spool_id else ""
    for idx, (wk, w) in enumerate(open_wins.items()):
        if not isinstance(w, Mapping) or w.get("session_id") != session_id or w.get("kind") != "output_spool":
            continue
        if target_path and w.get("target_path") != target_path:
            continue
        if step_idx is not None and step_idx > 0 and step_idx > int(w.get("expires_step", 0)):
            continue
        raw_wm = w.get("meta")
        wm: Mapping[str, Any] = raw_wm if isinstance(raw_wm, Mapping) else {}
        if call_id and wm.get("p_cid") != call_id:
            continue
        pref = 0 if wm.get("p_cid") else 1
        cands.append(((pref, int(w.get("step_idx", 0)), idx), str(wk)))
    return max(cands, key=lambda item: item[0])[1] if cands else None


def apply_pending_followup_meta(win: dict[str, Any], req: Mapping[str, Any]) -> None:
    """Attach bounded pending follow-up metadata (`p_cid`, `p_rec`, `p_reg`, `p_step`) onto a window."""
    wm = win.get("meta")
    meta = dict(wm) if isinstance(wm, Mapping) else {}
    meta["p_cid"] = str(req.get("call_id") or "")[:160]
    meta["p_rec"] = str(req.get("recovery") or "targeted")
    meta["p_reg"] = str(req.get("regret") or "none")
    raw_step = req.get("step_idx")
    meta["p_step"] = int(raw_step) if isinstance(raw_step, int) and not isinstance(raw_step, bool) else 0
    win["meta"] = meta


def clear_pending_followup_meta(win: dict[str, Any]) -> bool:
    """Remove pending follow-up keys from a window so it remains open for subsequent retries."""
    wm = win.get("meta")
    if not isinstance(wm, dict):
        return False
    removed = False
    for key in _PENDING_META_KEYS:
        if key in wm:
            wm.pop(key, None)
            removed = True
    return removed


def parse_ts_seconds(timestamp: str | None) -> float | None:
    """Parse ISO-8601 UTC timestamp string into epoch seconds or None."""
    if not isinstance(timestamp, str) or not timestamp.strip():
        return None
    try:
        return datetime.fromisoformat(timestamp.strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def is_strictly_after_ts(created: Mapping[str, Any], rotated_at: str | None) -> bool:
    """Return True when `created` timestamp is strictly later than `rotated_at`."""
    if (rot_ep := parse_ts_seconds(rotated_at)) is None:
        return False
    c_ms = created.get("ts_ms")
    if isinstance(c_ms, int) and not isinstance(c_ms, bool) and c_ms > 0:
        return (c_ms / 1000.0) > rot_ep
    c_ep = parse_ts_seconds(created.get("timestamp"))
    return c_ep is not None and c_ep > rot_ep


def recovery_byte_spans(row: Mapping[str, Any]) -> Sequence[tuple[int, int]]:
    """Return detailed `recovered_byte_spans` when present, else legacy `(byte_span,)`."""
    if "recovered_byte_spans" in row and isinstance((spans := row.get("recovered_byte_spans")), (list, tuple)):
        return spans
    bs = row.get("byte_span")
    return ((int(bs[0]), int(bs[1])),) if isinstance(bs, (list, tuple)) and len(bs) == 2 else ()


def filter_lifecycle_events(
    source_rows: Sequence[Any],
    spool_id: str | None,
    window_seconds: float | None,
    eff_now: float,
) -> tuple[list[Any], dict[str, list[Any]]]:
    """Filter receipt rows by spool_id and time window while deduplicating non-empty event_id."""
    seen_ids: set[str] = set()
    deduped: list[Any] = []
    by_sid: dict[str, list[Any]] = {}
    for row in source_rows:
        if spool_id is not None and row["spool_id"] != spool_id:
            continue
        if window_seconds is not None:
            ep = parse_ts_seconds(row["timestamp"])
            if ep is None and row["ts_ms"] > 0:
                ep = float(row["ts_ms"]) / 1000.0
            if ep is None or (eff_now - ep) > window_seconds:
                continue
        eid = row["event_id"]
        if eid:
            if eid in seen_ids:
                continue
            seen_ids.add(eid)
        deduped.append(row)
        by_sid.setdefault(row["spool_id"], []).append(row)
    return deduped, by_sid


def can_reuse_outcome_window(w: Mapping[str, Any], kind: str, step_idx: int, cm: Mapping[str, Any]) -> bool:
    """Return True when an existing open window may be overwritten instead of creating a sibling key."""
    if kind == "range_trim":
        return int(w.get("step_idx", -1)) == int(step_idx) and (w.get("meta") or {}) == cm
    if kind == "output_spool":
        cid = cm.get("call_id")
        return isinstance(cid, str) and bool(cid) and isinstance((wm := w.get("meta")), Mapping) and wm.get("call_id") == cid
    return True


def should_close_outcome_window(w: Mapping[str, Any], current_step: int | None, force_all: bool, rewind_step: int | None) -> bool:
    """Return True when an open window should expire, rewind-close, or stay open for an in-flight call."""
    if force_all or (rewind_step is not None and int(w.get("step_idx", 0)) >= rewind_step):
        return True
    if current_step is None or current_step < int(w.get("expires_step", 0)):
        return False
    raw_wm = w.get("meta")
    wm: Mapping[str, Any] = raw_wm if isinstance(raw_wm, Mapping) else {}
    return not (wm.get("p_rec") and current_step == int(w.get("expires_step", 0)) and int(wm.get("p_step") or 0) >= current_step)


def pop_spool_followup_in_state(
    open_wins: dict[str, Any],
    session_id: str,
    spool_id: str,
    step_idx: int,
) -> str | None:
    """Pop at most one matching open `output_spool` window and return its row key."""
    if (wk := select_spool_win_key(open_wins, session_id, spool_id, step_idx)) is None:
        return None
    return str(open_wins.pop(wk)["key"])


def mark_spool_followup_request_in_state(
    open_wins: dict[str, Any],
    session_id: str,
    spool_id: str,
    req: Mapping[str, Any],
) -> bool:
    """Attach pending follow-up request metadata to one open `output_spool` window."""
    raw_step = req.get("step_idx")
    step_val = int(raw_step) if isinstance(raw_step, int) and not isinstance(raw_step, bool) else None
    if (wk := select_spool_win_key(open_wins, session_id, spool_id, step_val)) is None:
        return False
    apply_pending_followup_meta(open_wins[wk], req)
    return True


def resolve_spool_window_in_state(
    open_wins: dict[str, Any],
    session_id: str,
    call_id: str,
    succeeded: bool,
    spool_id: str = "",
) -> tuple[str, str, str] | None:
    """Resolve or clear one pending `output_spool` window; returns `(win_key, rec, reg)` on resolution."""
    cands = open_wins if call_id else {
        k: v for k, v in open_wins.items()
        if isinstance(v, Mapping) and isinstance((m := v.get("meta")), Mapping) and "p_rec" in m and not m.get("p_cid")
    }
    if (wk := select_spool_win_key(cands, session_id, spool_id, None, call_id)) is None:
        return None
    if succeeded:
        w = open_wins.pop(wk)
        wm = w.get("meta") if isinstance(w.get("meta"), Mapping) else {}
        return str(w["key"]), str(wm.get("p_rec") or "targeted"), str(wm.get("p_reg") or "none")
    return ("", "", "") if clear_pending_followup_meta(open_wins[wk]) else None
