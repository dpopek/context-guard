"""Workspace identity canonicalization, isolation config, unsafe link checks, and ContextReceiptV1 JSONL storage."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib, json, os, re, stat, time, urllib.parse, uuid
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence
from hooks import state_store
from policies.api import ContextReceiptV1, RECEIPT_SCHEMA_VERSION, VALID_TURN_CORRELATIONS

VALID_SPOOL_ISOLATIONS: tuple[str, ...] = ("workspace", "session", "global")
DEFAULT_MAX_SPOOL_ENTRY_BYTES = 4 * 1024 * 1024
RECEIPTS_FILENAME, RECEIPTS_LOCK_FILENAME, RECEIPTS_MAX_BYTES, RECEIPTS_KEEP_ROWS = "receipts.jsonl", "receipts.lock", 512 * 1024, 256
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
_ROOT_MARKERS = (".git", ".hg", ".jj", ".context-guard-root")
_UNRESOLVED_TMPL_RE = re.compile(r"\$\{[^}]+\}")
_SPOOL_HEADER_RE = re.compile(r"\[CONTEXT-GUARD OUTPUT SPOOL:\s*(sp_[0-9a-f]{12})")

def check_unsafe_link(path: Path) -> bool:
    """Return True if `path` is a symlink, Windows reparse point, or cannot be safely statted."""
    try:
        st = os.lstat(str(path))
        return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError as exc:
        return not isinstance(exc, FileNotFoundError)

def atomic_write_bytes(target: Path, data: bytes) -> None:
    """Atomically write `data` to `target` with mode `0o600` using O_NOFOLLOW temp + os.replace."""
    tmp = target.parent / f".{target.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    try:
        with os.fdopen(os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_FLAGS, 0o600), "wb") as fh:
            fh.write(data)
        if os.name != "nt":
            os.chmod(str(tmp), 0o600)
        os.replace(str(tmp), str(target))
    except OSError:
        tmp.unlink(missing_ok=True)
        raise

def _home_norm() -> str:
    try: return os.path.normcase(str(Path(h).resolve())) if os.path.isabs(h := str(Path.home())) else ""
    except (RuntimeError, OSError): return ""

def read_spool_config(config_path: Path | None = None) -> tuple[str, int, str | None]:
    """Read `spool` config purely, returning `(isolation, max_spool_entry_bytes, error_or_None)`."""
    if config_path is not None:
        eff = config_path
    elif (ov := str(os.environ.get("CONTEXT_GUARD_CONFIG_PATH") or "").strip()):
        eff = Path(ov).expanduser()
    else:
        cands = [Path.home() / ".config"] + [Path(raw.strip()).expanduser() for var in (("XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA") if os.name == "nt" else ("XDG_CONFIG_HOME",)) if (raw := os.environ.get(var) or "").strip()]
        eff = next((p / "context-guard" / "config.json" for p in cands if (p / "context-guard" / "config.json").exists()), cands[0] / "context-guard" / "config.json")
    if check_unsafe_link(eff) or not eff.is_file():
        return "workspace", DEFAULT_MAX_SPOOL_ENTRY_BYTES, None
    try:
        raw = json.loads(eff.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return "workspace", DEFAULT_MAX_SPOOL_ENTRY_BYTES, None
    if not isinstance(raw, dict) or "spool" not in raw:
        return "workspace", DEFAULT_MAX_SPOOL_ENTRY_BYTES, None
    if not isinstance((sc := raw["spool"]), dict):
        return "", DEFAULT_MAX_SPOOL_ENTRY_BYTES, "invalid_spool_config"
    iso = sc.get("isolation", "workspace")
    if not isinstance(iso, str) or iso not in VALID_SPOOL_ISOLATIONS:
        return "", DEFAULT_MAX_SPOOL_ENTRY_BYTES, "invalid_spool_config"
    max_bytes = DEFAULT_MAX_SPOOL_ENTRY_BYTES
    if "max_spool_entry_bytes" in sc:
        raw_max = sc["max_spool_entry_bytes"]
        if isinstance(raw_max, bool) or not isinstance(raw_max, int) or raw_max < 1:
            return "", DEFAULT_MAX_SPOOL_ENTRY_BYTES, "invalid_spool_config"
        max_bytes = raw_max
    return iso, max_bytes, None


def read_spool_isolation_config(config_path: Path | None = None) -> tuple[str, str | None]:
    """Read `spool.isolation` mode purely, returning `(mode, error_or_None)`."""
    iso, _max_bytes, err = read_spool_config(config_path)
    return iso, err

def _normalize_raw_path(raw: str | Path | None) -> tuple[str | None, str | None]:
    if not isinstance(raw, (str, Path)) or not (s := str(raw).strip()) or _UNRESOLVED_TMPL_RE.search(s):
        return None, "workspace_unresolved"
    if s.lower().startswith("file:"):
        parsed = urllib.parse.urlparse(s)
        if parsed.scheme.lower() != "file" or parsed.netloc.lower() not in ("", "localhost"):
            return None, "workspace_unresolved"
        s = urllib.parse.unquote(parsed.path or "")
        s = s[1:] if re.match(r"^/[A-Za-z]:(?:[/\\]|$)", s) else s
        if not s or _UNRESOLVED_TMPL_RE.search(s):
            return None, "workspace_unresolved"
    try:
        canon = str(Path(s).resolve()) if os.path.isabs(s) else ""
    except (RuntimeError, OSError):
        return None, "workspace_unresolved"
    if not canon or not os.path.isdir(canon):
        return None, "workspace_unresolved"
    p, cn, hn = Path(canon), os.path.normcase(canon), _home_norm()
    an = os.path.normcase(p.anchor) if p.anchor else ""
    return (None, "workspace_unresolved") if ((an and cn == an) or len(p.parts) <= 1 or (hn and cn == hn)) else (canon, None)

def _find_project_root(canon_dir: str) -> str:
    hn, cur = _home_norm(), Path(canon_dir)
    an = os.path.normcase(cur.anchor) if cur.anchor else ""
    while cur.parent != cur and not ((an and os.path.normcase(str(cur)) == an) or (hn and os.path.normcase(str(cur)) == hn)):
        if any((cur / m).exists() for m in _ROOT_MARKERS):
            return str(cur)
        cur = cur.parent
    return canon_dir

def same_workspace_dir(path_a: str | Path | None, path_b: str | Path | None) -> bool:
    """Return True when both paths refer to the same physical directory via `os.path.samefile`."""
    if not isinstance(path_a, (str, Path)) or not isinstance(path_b, (str, Path)):
        return False
    sa, sb = str(path_a), str(path_b)
    if not sa.strip() or not sb.strip():
        return False
    try:
        return os.path.samefile(sa, sb)
    except (OSError, ValueError, TypeError):
        return False


def _is_under(child: str, parent: str) -> bool:
    if not child.strip() or not parent.strip():
        return False
    cur = Path(child)
    while True:
        if same_workspace_dir(cur, parent):
            return True
        if cur.parent == cur:
            break
        cur = cur.parent
    try:
        return os.path.commonpath([os.path.normcase(child), os.path.normcase(parent)]) == os.path.normcase(parent)
    except ValueError:
        return False


def resolve_workspace_identity(explicit_path: str | Path | None, *, workspace_roots: Sequence[str] | None = None) -> tuple[str, str, str | None]:
    """Canonicalize explicit path or workspace_roots to `(workspace_id, canon_root, error)`."""
    def _wid(r: str) -> str:
        return "ws_" + hashlib.sha256(f"cg-ws-v1:{os.path.normcase(r)}".encode("utf-8")).hexdigest()[:16]
    exp_id, exp_root = "", ""
    if explicit_path is not None and not (isinstance(explicit_path, str) and not explicit_path.strip()):
        canon, err = _normalize_raw_path(explicit_path)
        if err is not None or canon is None:
            return "", "", err or "workspace_unresolved"
        exp_root = _find_project_root(canon)
        exp_id = _wid(exp_root)
    if workspace_roots:
        unique_roots: list[str] = []
        for rr in workspace_roots:
            canon_rr, rerr = _normalize_raw_path(rr)
            if rerr is not None or canon_rr is None:
                continue
            pr = _find_project_root(canon_rr)
            if not any(same_workspace_dir(pr, existing) for existing in unique_roots):
                unique_roots.append(pr)
        if not unique_roots:
            return "", "", "workspace_unresolved"
        if len(unique_roots) == 1:
            o_root = unique_roots[0]
            o_id = _wid(o_root)
            return (exp_id, exp_root, None) if (exp_root and _is_under(exp_root, o_root)) else (o_id, o_root, None)
        if exp_root and (
            any(same_workspace_dir(exp_root, rr) for rr in unique_roots)
            or len([rr for rr in unique_roots if _is_under(exp_root, rr)]) == 1
        ):
            return exp_id, exp_root, None
        return "", "", "workspace_ambiguous"
    return (exp_id, exp_root, None) if exp_root else ("", "", "workspace_unresolved")

def compute_scope_key(isolation: str, *, workspace_id: str | None = None, session_id: str | None = None) -> tuple[str, str | None]:
    """Return domain separation key `(scope_key, error)` for the configured isolation mode."""
    if isolation == "workspace":
        return (f"ws:{workspace_id.strip()}", None) if isinstance(workspace_id, str) and workspace_id.strip() else ("", "workspace_unresolved")
    if isolation == "session":
        return (f"sess:{session_id.strip()}", None) if isinstance(session_id, str) and session_id.strip() else ("", "session_unresolved")
    return ("global", None) if isolation == "global" else ("", "invalid_spool_config")

def compute_scoped_spool_id(scope_key: str, content_sha256: str) -> str:
    """Derive domain-separated `sp_<12hex>` ID from `(scope_key, content_sha256)`."""
    return "sp_" + hashlib.sha256(f"{scope_key}:{content_sha256}".encode("utf-8")).hexdigest()[:12]

def receipts_path_for(spool_dir: Path | None = None) -> Path:
    """Resolve `receipts.jsonl` sibling path in `spool_dir` or default spool root."""
    if spool_dir is not None:
        return spool_dir / RECEIPTS_FILENAME
    if (ov := str(os.environ.get("CONTEXT_GUARD_SPOOL_DIR") or "").strip()):
        return Path(ov).expanduser() / RECEIPTS_FILENAME
    return state_store.resolve_plugin_root() / "telemetry" / "spool" / RECEIPTS_FILENAME

def derive_spool_event_id(event_type: str, session_id: str, call_id: str, spool_id: str) -> str:
    """Derive deterministic `ev_<16hex>` ID when session_id and call_id are non-empty, else random."""
    if isinstance(session_id, str) and session_id.strip() and isinstance(call_id, str) and call_id.strip():
        digest = hashlib.sha256(f"{event_type}:{session_id}:{call_id}:{spool_id}".encode("utf-8")).hexdigest()[:16]
        return f"ev_{digest}"
    return f"ev_{uuid.uuid4().hex[:16]}"


def _parse_ts_seconds(timestamp: str | None) -> float | None:
    if not isinstance(timestamp, str) or not timestamp.strip():
        return None
    try:
        return datetime.fromisoformat(timestamp.strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def build_receipt(
    *,
    event_type: str,
    harness: str,
    session_id: str,
    workspace_id: str,
    turn_key: str,
    call_id: str,
    spool_id: str,
    line_span: tuple[int, int],
    byte_span: tuple[int, int],
    upstream_truncation: bool = False,
    delivery_evidence: str,
    spool_id_referenced: bool,
    parent_event_id: str | None = None,
    failure_kind: str | None = None,
    reason: str | None = None,
    timestamp: str | None = None,
    event_id: str | None = None,
    tool_call_id: str | None = None,
    ts_ms: int | None = None,
    hook_duration_ms: float | None = None,
    intervention: str = "output_spool",
    mode: str | None = None,
    status: str | None = None,
    turn_correlation: str = "unobserved",
    source_hash: str = "",
    original_bytes: int = 0,
    replacement_bytes: int = 0,
) -> ContextReceiptV1:
    """Construct a schema-v1 `ContextReceiptV1` record."""
    eff_sess = str(session_id or "")
    eff_call = str(call_id or "")
    now_sec = time.time()
    eff_ts = timestamp or datetime.fromtimestamp(now_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if ts_ms is not None and not isinstance(ts_ms, bool):
        eff_ts_ms = int(ts_ms)
    elif timestamp:
        parsed_ep = _parse_ts_seconds(eff_ts)
        eff_ts_ms = int(round(parsed_ep * 1000)) if parsed_ep is not None else int(now_sec * 1000)
    else:
        eff_ts_ms = int(now_sec * 1000)
    eff_ev_id = str(event_id) if event_id is not None else derive_spool_event_id(event_type, eff_sess, eff_call, spool_id)
    eff_tc_id = str(tool_call_id) if tool_call_id is not None else eff_call
    eff_dur = float(hook_duration_ms) if isinstance(hook_duration_ms, (int, float)) and not isinstance(hook_duration_ms, bool) else None
    eff_mode = str(mode) if mode is not None else ("active" if event_type in ("spool_created", "spool_delivery_verified") else "recovery")
    eff_status = str(status) if status is not None else ("error" if (event_type == "spool_integrity_failure" or failure_kind is not None) else "ok")
    eff_tc = turn_correlation if turn_correlation in VALID_TURN_CORRELATIONS else "unobserved"
    return ContextReceiptV1(
        schema_version=RECEIPT_SCHEMA_VERSION,
        receipt_id="rcpt_" + uuid.uuid4().hex[:16],
        event_id=eff_ev_id,
        parent_event_id=parent_event_id,
        timestamp=eff_ts,
        ts_ms=eff_ts_ms,
        hook_duration_ms=eff_dur,
        event_type=event_type,
        harness=str(harness or ""),
        session_id=eff_sess,
        workspace_id=str(workspace_id or ""),
        turn_key=str(turn_key or ""),
        turn_correlation=eff_tc,
        call_id=eff_call,
        tool_call_id=eff_tc_id,
        spool_id=spool_id,
        intervention=str(intervention or "output_spool"),
        mode=eff_mode,
        status=eff_status,
        line_span=(int(line_span[0]), int(line_span[1])),
        byte_span=(int(byte_span[0]), int(byte_span[1])),
        source_hash=str(source_hash or ""),
        original_bytes=max(0, int(original_bytes)),
        replacement_bytes=max(0, int(replacement_bytes)),
        upstream_truncation=bool(upstream_truncation),
        delivery_evidence=delivery_evidence,
        spool_id_referenced=bool(spool_id_referenced),
        failure_kind=failure_kind,
        reason=reason,
    )

@contextmanager
def _receipts_lock(parent_dir: Path) -> Iterator[None]:
    lp = parent_dir / RECEIPTS_LOCK_FILENAME
    if check_unsafe_link(lp):
        raise OSError("unsafe_path: receipts.lock")
    with os.fdopen(os.open(str(lp), os.O_RDWR | os.O_CREAT | _O_FLAGS, 0o600), "a+", encoding="utf-8") as fh:
        if os.name != "nt":
            os.chmod(str(lp), 0o600)
        state_store.fcntl.flock(fh.fileno(), state_store.fcntl.LOCK_EX)
        try:
            yield
        finally:
            state_store.fcntl.flock(fh.fileno(), state_store.fcntl.LOCK_UN)

def _normalize_receipt_row(r: Mapping[str, Any]) -> ContextReceiptV1 | None:
    sv = r.get("schema_version")
    ls = r.get("line_span")
    bs = r.get("byte_span")
    if (
        isinstance(sv, bool)
        or sv != RECEIPT_SCHEMA_VERSION
        or not isinstance(ls, (list, tuple))
        or len(ls) != 2
        or not isinstance(bs, (list, tuple))
        or len(bs) != 2
    ):
        return None
    ev = str(r.get("event_type") or "")
    ts = str(r.get("timestamp") or "")
    call_id = str(r.get("call_id") or "")
    fk = r["failure_kind"] if isinstance(r.get("failure_kind"), str) else None
    raw_ts_ms = r.get("ts_ms")
    if isinstance(raw_ts_ms, int) and not isinstance(raw_ts_ms, bool):
        ts_ms = raw_ts_ms
    else:
        parsed_ep = _parse_ts_seconds(ts)
        ts_ms = int(round(parsed_ep * 1000)) if parsed_ep is not None else 0
    raw_dur = r.get("hook_duration_ms")
    dur = float(raw_dur) if isinstance(raw_dur, (int, float)) and not isinstance(raw_dur, bool) else None
    raw_tc = r.get("turn_correlation")
    tc = raw_tc if isinstance(raw_tc, str) and raw_tc in VALID_TURN_CORRELATIONS else "unobserved"
    raw_mode = r.get("mode")
    mode = raw_mode if isinstance(raw_mode, str) and raw_mode else ("active" if ev in ("spool_created", "spool_delivery_verified") else "recovery")
    raw_status = r.get("status")
    status = raw_status if isinstance(raw_status, str) and raw_status else ("error" if (ev == "spool_integrity_failure" or fk is not None) else "ok")
    raw_ob = r.get("original_bytes")
    ob = max(0, raw_ob) if isinstance(raw_ob, int) and not isinstance(raw_ob, bool) else 0
    raw_rb = r.get("replacement_bytes")
    rb = max(0, raw_rb) if isinstance(raw_rb, int) and not isinstance(raw_rb, bool) else 0
    raw_tc_id = r.get("tool_call_id")
    tc_id = raw_tc_id if isinstance(raw_tc_id, str) else call_id
    return ContextReceiptV1(
        schema_version=RECEIPT_SCHEMA_VERSION,
        receipt_id=str(r.get("receipt_id") or ""),
        event_id=str(r.get("event_id") or r.get("receipt_id") or ""),
        parent_event_id=r["parent_event_id"] if isinstance(r.get("parent_event_id"), str) else None,
        timestamp=ts,
        ts_ms=ts_ms,
        hook_duration_ms=dur,
        event_type=ev,
        harness=str(r.get("harness") or ""),
        session_id=str(r.get("session_id") or ""),
        workspace_id=str(r.get("workspace_id") or ""),
        turn_key=str(r.get("turn_key") or ""),
        turn_correlation=tc,
        call_id=call_id,
        tool_call_id=tc_id,
        spool_id=str(r.get("spool_id") or ""),
        intervention=str(r.get("intervention") or "output_spool"),
        mode=mode,
        status=status,
        line_span=(int(ls[0]), int(ls[1])),
        byte_span=(int(bs[0]), int(bs[1])),
        source_hash=str(r.get("source_hash") or ""),
        original_bytes=ob,
        replacement_bytes=rb,
        upstream_truncation=bool(r.get("upstream_truncation", False)),
        delivery_evidence=str(r.get("delivery_evidence") or ""),
        spool_id_referenced=bool(r.get("spool_id_referenced", False)),
        failure_kind=fk,
        reason=r["reason"] if isinstance(r.get("reason"), str) else None,
    )


def _read_receipt_rows(eff_path: Path) -> list[ContextReceiptV1]:
    if check_unsafe_link(eff_path.parent) or check_unsafe_link(eff_path) or not eff_path.is_file():
        return []
    try:
        with os.fdopen(os.open(str(eff_path), os.O_RDONLY | _O_FLAGS), "rb") as fh:
            raw_text = fh.read().decode("utf-8") if stat.S_ISREG(os.fstat(fh.fileno()).st_mode) else ""
    except (OSError, UnicodeDecodeError):
        return []
    rows: list[ContextReceiptV1] = []
    for line in raw_text.splitlines():
        try:
            r = json.loads(line) if line.strip() else None
            if isinstance(r, dict) and (row := _normalize_receipt_row(r)) is not None:
                rows.append(row)
        except (ValueError, TypeError):
            continue
    return rows


def append_receipt(receipt: Mapping[str, Any], receipts_path: Path | None = None) -> bool:
    """Append one `ContextReceiptV1` row under `receipts.lock` with atomic 512 KiB rotation."""
    eff = receipts_path or receipts_path_for()
    if check_unsafe_link(eff.parent) or check_unsafe_link(eff):
        return False
    try:
        eff.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(str(eff.parent), 0o700)
        line_bytes = (json.dumps(dict(receipt), separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        raw_eid = receipt.get("event_id")
        eid = raw_eid if isinstance(raw_eid, str) and raw_eid.strip() else ""
        with _receipts_lock(eff.parent):
            if check_unsafe_link(eff):
                return False
            if eid and any(row["event_id"] == eid for row in _read_receipt_rows(eff)):
                return True
            with os.fdopen(os.open(str(eff), os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_FLAGS, 0o600), "ab") as fh:
                if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                    return False
                if os.name != "nt":
                    os.chmod(str(eff), 0o600)
                fh.write(line_bytes)
                fh.flush()
                cur_size = os.fstat(fh.fileno()).st_size
            if cur_size > RECEIPTS_MAX_BYTES:
                atomic_write_bytes(
                    eff,
                    "".join(
                        json.dumps(dict(r), separators=(",", ":"), sort_keys=True) + "\n"
                        for r in _read_receipt_rows(eff)[-RECEIPTS_KEEP_ROWS:]
                    ).encode("utf-8"),
                )
        return True
    except (OSError, ValueError, TypeError):
        return False

def find_created_receipt(spool_id: str, *, session_id: str | None = None, call_id: str | None = None, receipts_path: Path | None = None) -> ContextReceiptV1 | None:
    """Return the latest matching `spool_created` receipt without mutating state."""
    return next((r for r in reversed(_read_receipt_rows(receipts_path or receipts_path_for())) if r["event_type"] == "spool_created" and r["spool_id"] == spool_id and (session_id is None or r["session_id"] == session_id) and (call_id is None or r["call_id"] == call_id)), None)

def summarize_receipts(receipts_path: Path | None = None, *, window_seconds: float | None = None, now_ts: float | None = None) -> dict[str, Any]:
    """Summarize `receipts.jsonl` counts and timestamps purely read-only."""
    eff_now, counts = float(now_ts) if now_ts is not None else time.time(), {"receipt_count": 0, "created_count": 0, "delivery_verified_count": 0, "recovery_count": 0, "integrity_failures": 0}
    last_ev: str | None = None
    last_fail: str | None = None
    last_ev_ep, last_fail_ep, ev_map = -1.0, -1.0, {"spool_created": "created_count", "spool_delivery_verified": "delivery_verified_count", "spool_recovery": "recovery_count"}
    for row in _read_receipt_rows(receipts_path or receipts_path_for()):
        try:
            ep: float | None = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp() if row["timestamp"] else None
        except ValueError:
            ep = None
        if window_seconds is not None and (ep is None or (eff_now - ep) > window_seconds):
            continue
        counts["receipt_count"] += 1
        if (ek := ev_map.get(ev := row["event_type"])):
            counts[ek] += 1
        if ev == "spool_integrity_failure" or row["failure_kind"] == "reliability_failure":
            counts["integrity_failures"] += 1
            if (ep or 0.0) >= last_fail_ep:
                last_fail_ep, last_fail = (ep or 0.0), row["timestamp"]
        if (ep or 0.0) >= last_ev_ep:
            last_ev_ep, last_ev = (ep or 0.0), row["timestamp"]
    return {**counts, "last_failure_ts": last_fail, "last_event_ts": last_ev}


def _interval_union_bytes(spans: Sequence[tuple[int, int]]) -> int:
    intervals = sorted((max(0, int(s)), max(0, int(e))) for s, e in spans if int(e) > max(0, int(s)))
    if not intervals:
        return 0
    total = 0
    cur_s, cur_e = intervals[0]
    for s, e in intervals[1:]:
        if s <= cur_e:
            if e > cur_e:
                cur_e = e
        else:
            total += cur_e - cur_s
            cur_s, cur_e = s, e
    return total + (cur_e - cur_s)


def _summarize_events(
    events: Sequence[ContextReceiptV1],
    *,
    completeness: str,
    unique_bytes: int,
    original_bytes: int | None,
    replacement_bytes: int | None,
) -> dict[str, Any]:
    recoveries = [r for r in events if r["event_type"] == "spool_recovery"]
    rec_calls = len(recoveries)
    obs_recoveries = [
        r for r in recoveries
        if r["turn_correlation"] in ("harness_native", "transcript_derived") and r["turn_key"].strip()
    ]
    rec_turns: int | None
    tc_status: str
    if rec_calls == 0:
        if completeness == "complete":
            tc_status, rec_turns = "observed", 0
        else:
            tc_status, rec_turns = "unobserved", None
    elif len(obs_recoveries) == rec_calls:
        tc_status = "observed"
        rec_turns = len({r["turn_key"].strip() for r in recoveries})
    elif not obs_recoveries:
        tc_status, rec_turns = "unobserved", None
    else:
        tc_status, rec_turns = "partial", None

    total_rec_bytes = sum(max(0, int(r["byte_span"][1]) - int(r["byte_span"][0])) for r in recoveries)
    if unique_bytes > 0:
        amplification: float | None = round(total_rec_bytes / unique_bytes, 4)
    elif rec_calls == 0 and completeness == "complete":
        amplification = 0.0
    else:
        amplification = None

    evidences = {r["delivery_evidence"] for r in events}
    if "delivery_verified" in evidences:
        del_ev = "delivery_verified"
    elif "replacement_emitted" in evidences:
        del_ev = "replacement_emitted"
    else:
        del_ev = "unverified"

    rel_failures = sum(
        1 for r in events if r["event_type"] == "spool_integrity_failure" or r["failure_kind"] == "reliability_failure"
    )
    return {
        "completeness": completeness,
        "recovery_calls": rec_calls,
        "recovery_model_turns": rec_turns,
        "turn_correlation_status": tc_status,
        "unique_recovered_bytes": unique_bytes,
        "total_recovered_bytes": total_rec_bytes,
        "recovery_amplification": amplification,
        "original_bytes": original_bytes,
        "replacement_bytes": replacement_bytes,
        "delivery_evidence": del_ev,
        "reliability_failures": rel_failures,
    }


def summarize_spool_lifecycle(
    receipts_path: Path | None = None,
    *,
    spool_id: str | None = None,
    window_seconds: float | None = None,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Compute deduplicated per-spool and aggregate lifecycle metrics from `receipts.jsonl`."""
    eff_now = float(now_ts) if now_ts is not None else time.time()
    seen_ids: set[str] = set()
    deduped: list[ContextReceiptV1] = []
    by_sid_events: dict[str, list[ContextReceiptV1]] = {}
    for row in _read_receipt_rows(receipts_path or receipts_path_for()):
        if spool_id is not None and row["spool_id"] != spool_id:
            continue
        if window_seconds is not None:
            ep = _parse_ts_seconds(row["timestamp"])
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
        by_sid_events.setdefault(row["spool_id"], []).append(row)

    by_spool: dict[str, dict[str, Any]] = {}
    for sid, ev_list in by_sid_events.items():
        created = next((r for r in reversed(ev_list) if r["event_type"] == "spool_created"), None)
        comp = "complete" if created is not None else "incomplete"
        orig_b = (created["original_bytes"] if created["original_bytes"] > 0 else max(0, created["byte_span"][1])) if created is not None else None
        repl_b = (created["replacement_bytes"] if created["replacement_bytes"] > 0 else None) if created is not None else None
        uniq_b = _interval_union_bytes([r["byte_span"] for r in ev_list if r["event_type"] == "spool_recovery"])
        by_spool[sid] = _summarize_events(
            ev_list, completeness=comp, unique_bytes=uniq_b, original_bytes=orig_b, replacement_bytes=repl_b
        )

    agg_comp = "complete" if all(m["completeness"] == "complete" for m in by_spool.values()) else "incomplete"
    agg_uniq = sum(int(m["unique_recovered_bytes"]) for m in by_spool.values())
    agg_orig = sum(int(m["original_bytes"]) for m in by_spool.values() if m["original_bytes"] is not None) if agg_comp == "complete" else None
    known_repl = [int(m["replacement_bytes"]) for m in by_spool.values() if m["replacement_bytes"] is not None]
    agg_repl = sum(known_repl) if (agg_comp == "complete" and known_repl) else None
    agg = _summarize_events(
        deduped, completeness=agg_comp, unique_bytes=agg_uniq, original_bytes=agg_orig, replacement_bytes=agg_repl
    )
    return {**agg, "by_spool": by_spool}

def persist_spool_delivery_verification(
    payload: Mapping[str, Any], *, harness: str, session_id: str,
    workspace_root: str | Path | None = None, workspace_roots: Sequence[str] | None = None,
    turn_key: str = "", spool_dir: Path | None = None, receipts_path: Path | None = None,
) -> int:
    """Scan `PostToolBatch` responses and emit deduplicated `spool_delivery_verified` child receipts."""
    iso_mode, iso_err = read_spool_isolation_config()
    if not isinstance((tool_calls := payload.get("tool_calls")), list) or not tool_calls or iso_err is not None:
        return 0
    has_ws = (workspace_root is not None and str(workspace_root).strip() != "") or bool(workspace_roots)
    caller_ws_id = resolve_workspace_identity(workspace_root, workspace_roots=workspace_roots)[0] if has_ws else ""
    if has_ws and not caller_ws_id:
        return 0
    eff_path = receipts_path or receipts_path_for(spool_dir)
    existing = _read_receipt_rows(eff_path)
    verified = {(r["parent_event_id"], r["spool_id"]) for r in existing if r["event_type"] == "spool_delivery_verified"}
    created_by_sid: dict[str, list[ContextReceiptV1]] = {}
    for r in existing:
        if r["event_type"] == "spool_created":
            created_by_sid.setdefault(r["spool_id"], []).append(r)
    emitted = 0
    for item in tool_calls:
        if not isinstance(item, Mapping) or item.get("is_error"):
            continue
        resp = item.get("tool_response")
        text = resp if isinstance(resp, str) else ("\n".join(str(resp[k]) for k in ("output", "stdout", "text", "content") if isinstance(resp.get(k), str)) if isinstance(resp, Mapping) else ("\n".join(b["text"] for b in resp if isinstance(b, Mapping) and isinstance(b.get("text"), str)) if isinstance(resp, list) else ""))
        cid = str(item.get("tool_use_id") or item.get("call_id") or item.get("tool_call_id") or item.get("callId") or "")
        for m in _SPOOL_HEADER_RE.finditer(text):
            sid = m.group(1)
            created = next((c for c in reversed(created_by_sid.get(sid) or ()) if (not cid or not c["call_id"] or c["call_id"] == cid)), None)
            if created is None or (iso_mode == "session" and created["session_id"] != session_id):
                continue
            if (has_ws and (iso_mode == "workspace" or created["workspace_id"]) and created["workspace_id"] != caller_ws_id) or (not has_ws and (not session_id or created["session_id"] != session_id or (created["call_id"] and cid != created["call_id"]))):
                continue
            if (key := (created["receipt_id"], sid)) not in verified and append_receipt(build_receipt(event_type="spool_delivery_verified", harness=harness, session_id=session_id or created["session_id"], workspace_id=created["workspace_id"] or caller_ws_id, turn_key=turn_key or created["turn_key"], call_id=cid or created["call_id"], spool_id=sid, line_span=created["line_span"], byte_span=created["byte_span"], upstream_truncation=bool(item.get("truncated") or item.get("is_truncated")), delivery_evidence="delivery_verified", spool_id_referenced=False, parent_event_id=created["receipt_id"]), receipts_path=eff_path):
                verified.add(key); emitted += 1
    return emitted
