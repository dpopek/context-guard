"""Direct intervention outcome telemetry (Schema v4) and conservative delivered-line estimation."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from hooks import telemetry as tel
from hooks.state_store import resolve_plugin_root, warn
from hooks.telemetry import write_json_atomic

SCHEMA_VERSION, STEP_LEDGER_MAX_ENTRIES, ARCHIVED_STEP_KEYS_MAX = 4, 128, 512
RECOVERY_KEYS = ("none", "targeted", "full", "pending_or_unknown")
REGRET_KEYS = ("none", "suspected", "confirmed", "unknown")
EVIDENCE_KEYS = ("observed", "heuristic", "replay", "causal_ab")
_DIM_KEYS = (("recovery", RECOVERY_KEYS), ("regret", REGRET_KEYS), ("evidence", EVIDENCE_KEYS))
OUTCOMES = ("applied", "targeted_followup", "full_bypass", "shell_bypass")
INTERVENTION_KINDS = OUTCOMES_KINDS = ("outline", "range_trim", "cli_rewrite", "outline_pull", "output_spool")
DEFAULT_OUTCOMES_PATH = resolve_plugin_root() / "telemetry" / "outcomes.json"
_LEGACY_DIMS = {"targeted_followup": ("targeted", "unknown", "heuristic"),
                **dict.fromkeys(("full_bypass", "shell_bypass"), ("full", "suspected", "heuristic"))}

def ledger_path_for(state_dir: str | None) -> Path | None:
    """Isolated outcomes ledger path next to a state_dir override, or None for default ledger."""
    return (Path(state_dir) / "outcomes.json") if state_dir else None

def _nni(val: Any) -> int:
    return max(0, tel.coerce_int(val))

def _imap(raw: Any) -> dict[str, int]:
    return {k: _nni(v) for k, v in raw.items() if isinstance(k, str)} if isinstance(raw, Mapping) else {}

def _default_row() -> dict[str, Any]:
    return {"total": 0, "applied": 0, "weighted_turns": 0.0, "archived_weighted_turns": 0.0,
            **{d: {k: 0 for k in ks} for d, ks in _DIM_KEYS}}

def default_outcomes_dict() -> dict[str, Any]:
    """Return a clean initialized Schema v4 outcomes ledger dictionary."""
    return {"schema_version": SCHEMA_VERSION, "updated_at": tel.now_iso(), "by_key": {}, "step_ledger": {},
            "archived_max_step_by_session": {}, "archived_step_keys": [], "open_windows": {},
            "unattributed_anon": {"total": 0, "by_key": {}}, "late_unattributed": {"total": 0, "by_key": {}}}

def _normalise_row(src: Mapping[str, Any], v3: bool = False) -> dict[str, Any]:
    row = _default_row()
    row["total"], row["applied"] = _nni(src.get("total")), _nni(src.get("applied"))
    if v3:
        targ, full = _nni(src.get("targeted_followup")), _nni(src.get("full_bypass")) + _nni(src.get("shell_bypass"))
        row["recovery"]["targeted"], row["recovery"]["full"] = targ, full
        row["regret"]["unknown"], row["regret"]["suspected"] = targ, full
        row["evidence"]["heuristic"], row["legacy_v3"] = targ + full, True
        return row
    for dim, keys in _DIM_KEYS:
        if isinstance(rd := src.get(dim), Mapping):
            row[dim] = {k: _nni(rd.get(k)) for k in keys}
    for wk in ("archived_weighted_turns", "weighted_turns"):
        row[wk] = round(max(0.0, tel.coerce_float(src.get(wk))), 6)
    return {**row, "legacy_v3": True} if src.get("legacy_v3") else row

def _recompute_weighted_turns(state: dict[str, Any]) -> None:
    active: dict[str, float] = {}
    for evs in state["step_ledger"].values():
        share = 1.0 / len(evs) if evs else 0.0
        for item in evs:
            active[item["key"]] = active.get(item["key"], 0.0) + share
    for key, row in state["by_key"].items():
        row["weighted_turns"] = round(tel.coerce_float(row.get("archived_weighted_turns")) + active.get(key, 0.0), 6)

def _clean_meta(meta: Any) -> dict[str, Any]:
    if not isinstance(meta, Mapping):
        return {}
    items = ((k, v[:160] if isinstance(v, str) else v) for k, v in meta.items()
             if isinstance(k, str) and k and (isinstance(v, (bool, int, str)) or (isinstance(v, float) and math.isfinite(v))))
    return dict(list(items)[:8])

def _normalise_outcomes(raw: Any) -> dict[str, Any]:
    base = default_outcomes_dict()
    if not isinstance(raw, dict) or (ver := raw.get("schema_version")) not in (3, SCHEMA_VERSION):
        return base
    base["updated_at"] = ua if isinstance(ua := raw.get("updated_at"), str) and ua else base["updated_at"]
    if isinstance(rbk := raw.get("by_key"), dict):
        base["by_key"] = {str(k): _normalise_row(v, ver == 3) for k, v in rbk.items() if isinstance(k, str) and isinstance(v, dict)}
    if ver == 3:
        return base
    for sk, evs in rs.items() if isinstance(rs := raw.get("step_ledger"), dict) else ():
        if isinstance(sk, str) and ":" in sk and isinstance(evs, list):
            if d := {e: {"event_id": e, "key": k} for it in evs if isinstance(it, dict)
                     and isinstance(e := it.get("event_id"), str) and e and isinstance(k := it.get("key"), str)}:
                base["step_ledger"][sk] = list(d.values())
    base["archived_max_step_by_session"] = _imap(raw.get("archived_max_step_by_session"))
    if isinstance(ak := raw.get("archived_step_keys"), list):
        base["archived_step_keys"] = [x for x in ak if isinstance(x, str)][-ARCHIVED_STEP_KEYS_MAX:]
    if isinstance(ow := raw.get("open_windows"), dict):
        for wk, wv in ow.items():
            if isinstance(wk, str) and isinstance(wv, dict) and isinstance(k := wv.get("key"), str) and isinstance(sid := wv.get("session_id"), str):
                cm = _clean_meta(wv.get("meta"))
                base["open_windows"][wk] = {"session_id": sid, "key": k, "step_idx": _nni(wv.get("step_idx")),
                                            "expires_step": _nni(wv.get("expires_step")), **({"meta": cm} if cm else {})}
    for bn in ("unattributed_anon", "late_unattributed"):
        if isinstance(rb := raw.get(bn), Mapping):
            base[bn] = {"total": _nni(rb.get("total")), "by_key": _imap(rb.get("by_key"))}
    if base["step_ledger"]:
        _recompute_weighted_turns(base)
    return base

def load_outcomes(outcomes_path: Path | None = None) -> dict[str, Any]:
    """Load and normalize outcomes ledger from disk; returns defaults when absent or corrupt."""
    try:
        return _normalise_outcomes(json.loads((outcomes_path or DEFAULT_OUTCOMES_PATH).read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return default_outcomes_dict()

def compute_regret_rates(row: Mapping[str, Any]) -> dict[str, Any]:
    """Compute pure regret rates over resolved counts (none+suspected+confirmed), excluding unknown."""
    reg: Mapping[str, Any] = r if isinstance(r := row.get("regret"), Mapping) else {}
    n, s, c = _nni(reg.get("none")), _nni(reg.get("suspected")), _nni(reg.get("confirmed"))
    res = n + s + c
    return {"resolved": res, "confirmed_regret_rate": (c / res) if res else 0.0,
            "suspected_regret_rate": ((c + s) / res) if res else 0.0}

def estimate_delivered_end_line(harness: str, start_line: int, end_line: int, total_lines: int, slice_bytes: int | None) -> int | None:
    """Conservative PreToolUse estimate of the last delivered line; None when coverage is unknown."""
    if total_lines <= 0 or slice_bytes is None or slice_bytes < 0:
        return None
    max_lines, cap_b = tel.HARNESS_READ_CAPS.get(harness, tel.HARNESS_READ_CAPS["claude"])
    max_b = tel.CLAUDE_COVERAGE_MAX_SLICE_BYTES if harness == "claude" else cap_b
    req_end = total_lines if (end_line == -1 or end_line > total_lines) else end_line
    return None if (req_end < start_line or slice_bytes > max_b) else min(req_end, max(1, start_line) + max_lines - 1)

def _evict_step_ledger(state: dict[str, Any]) -> None:
    steps, ak = state["step_ledger"], state["archived_step_keys"]
    while len(steps) > STEP_LEDGER_MAX_ENTRIES:
        old_evs = steps.pop(old_key := next(iter(steps)))
        share = 1.0 / len(old_evs) if old_evs else 0.0
        for item in old_evs:
            r = state["by_key"].setdefault(item["key"], _default_row())
            r["archived_weighted_turns"] = round(tel.coerce_float(r.get("archived_weighted_turns")) + share, 6)
        sess, _, step_s = old_key.rpartition(":")
        if sess and step_s.isdigit():
            state["archived_max_step_by_session"][sess] = max(state["archived_max_step_by_session"].get(sess, -1), int(step_s))
        if old_key not in ak:
            ak.append(old_key)
            del ak[: max(0, len(ak) - ARCHIVED_STEP_KEYS_MAX)]

def _apply_row_outcome(state: dict[str, Any], key: str, outcome: str = "", inc_total: bool = False,
                       count: int = 1, rec: str | None = None, reg: str | None = None, evi: str | None = None) -> None:
    row = state["by_key"].setdefault(key, _default_row())
    if inc_total: row["total"] = _nni(row.get("total")) + count
    if outcome == "applied": row["applied"] = _nni(row.get("applied")) + count
    if rec is None and reg is None and evi is None and outcome in _LEGACY_DIMS:
        rec, reg, evi = _LEGACY_DIMS[outcome]
    for (dim, keys), val in zip(_DIM_KEYS, (rec, reg, evi)):
        if val in keys: row[dim][val] = _nni(row[dim].get(val)) + count

def _bump_bucket(state: dict[str, Any], name: str, key: str, count: int) -> None:
    state[name]["total"] += count
    state[name]["by_key"][key] = state[name]["by_key"].get(key, 0) + count

def _mutate_outcomes_state(
    state: dict[str, Any], key: str, outcome: str, inc_total: bool, count: int, rec: str | None,
    reg: str | None, evi: str | None, session_id: str | None, step_idx: int | None, call_id: str | None,
) -> bool:
    if not inc_total:
        _apply_row_outcome(state, key, outcome, False, count, rec, reg, evi)
        return True
    if not (isinstance(call_id, str) and call_id and isinstance(session_id, str) and session_id and step_idx is not None):
        _bump_bucket(state, "unattributed_anon", key, count)
        _apply_row_outcome(state, key, outcome, True, count, rec, reg, evi)
        return True
    s_int, step_key = int(step_idx), f"{session_id}:{int(step_idx)}"
    if step_key in state["archived_step_keys"] or s_int <= state["archived_max_step_by_session"].get(session_id, -1):
        _bump_bucket(state, "late_unattributed", key, count)
        return True
    evs, event_id = state["step_ledger"].setdefault(step_key, []), f"{call_id}:{key.rsplit('|', 1)[-1]}"
    if any(item.get("event_id") == event_id for item in evs):
        return False
    evs.append({"event_id": event_id, "key": key})
    _apply_row_outcome(state, key, outcome, True, count, rec, reg, evi)
    _evict_step_ledger(state)
    _recompute_weighted_turns(state)
    return True

def _real(p: str) -> str:
    try: return os.path.realpath(p) if p else ""
    except OSError: return p

def _reconcile_windows(
    session_id: str, pred: Callable[[str, str, dict[str, Any]], tuple[str, str, str] | bool | None],
    *, ledger_path: Path | None = None, step_idx: int | None = None,
) -> bool:
    if not (ledger_path or DEFAULT_OUTCOMES_PATH).is_file():
        return False
    changed = [False]
    def _step(st: dict[str, Any], _key: str) -> bool:
        for wk in list(st["open_windows"]):
            if not isinstance(w := st["open_windows"].get(wk), dict) or w.get("session_id") != session_id: continue
            if step_idx is not None and step_idx > 0 and step_idx > int(w.get("expires_step", 0)): continue
            p = wk.split("|")
            if (res := pred("|".join(p[1:-1]) if len(p) >= 3 else "", p[-1] if len(p) >= 3 else "", w)) is None: continue
            if isinstance(res, tuple):
                _apply_row_outcome(st, w["key"], "", False, 1, *res)
                st["open_windows"].pop(wk, None)
            elif res is True:
                st["open_windows"].pop(wk, None)
            changed[0] = True
        return changed[0]
    record_direct_outcome("", "", "", ledger_path=ledger_path, count=0, _mut=_step)
    return changed[0]

def record_direct_outcome(
    harness: str, model: str, kind: str, outcome: str = "applied", ledger_path: Path | None = None,
    *, increment_total: bool = True, count: int = 1, recovery: str | None = None, regret: str | None = None,
    evidence: str | None = None, session_id: str | None = None, step_idx: int | None = None,
    call_id: str | None = None, _mut: Callable[[dict[str, Any], str], bool] | None = None,
) -> None:
    """Atomically record one Schema v4 outcome event or window transition under flock; never raises."""
    if count <= 0 and _mut is None:
        return
    try:
        target = ledger_path or DEFAULT_OUTCOMES_PATH
        key = f"{harness or 'unknown'}|{model or 'unknown'}|{kind or 'unknown'}"
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target.with_suffix(".lock"), "a+", encoding="utf-8") as lock_fh:
            tel.fcntl.flock(lock_fh.fileno(), tel.fcntl.LOCK_EX)
            try:
                state = _normalise_outcomes(tel.read_json_object_or_quarantine(target))
                changed = _mut(state, key) if _mut is not None else _mutate_outcomes_state(
                    state, key, outcome, increment_total, count, recovery, regret, evidence, session_id, step_idx, call_id)
                if not changed: return
                state["updated_at"] = tel.now_iso()
                write_json_atomic(target, state, prefix=".outcomes.")
            finally: tel.fcntl.flock(lock_fh.fileno(), tel.fcntl.LOCK_UN)
    except Exception as exc:  # noqa: BLE001 - telemetry is best-effort by contract
        warn(f"direct outcome telemetry skipped: {type(exc).__name__}: {exc}")

def open_outcome_window(harness: str, model: str, kind: str, session_id: str, target_path: str, step_idx: int,
                        regret_window_steps: int = 8, ledger_path: Path | None = None, *, meta: Mapping[str, Any] | None = None) -> None:
    """Register an open regret observation window through the locked outcomes writer."""
    cm = _clean_meta(meta)
    def _open(st: dict[str, Any], key: str) -> bool:
        st["open_windows"][f"{session_id}|{target_path}|{kind}"] = {
            "session_id": session_id, "key": key, "step_idx": int(step_idx),
            "expires_step": int(step_idx) + max(1, int(regret_window_steps)), **({"meta": dict(cm)} if cm else {})}
        return True
    record_direct_outcome(harness, model, kind, ledger_path=ledger_path, count=0, _mut=_open)

def close_outcome_windows(session_id: str, current_step: int | None = None, *, force_all: bool = False,
                          rewind_step: int | None = None, ledger_path: Path | None = None) -> None:
    """Close expired, compacted, rewound, or ended windows into none/none/observed."""
    _reconcile_windows(session_id, lambda _wp, _k, w: ("none", "none", "observed") if (
        force_all or (current_step is not None and current_step >= int(w.get("expires_step", 0)))
        or (rewind_step is not None and int(w.get("step_idx", 0)) >= rewind_step)) else None, ledger_path=ledger_path)

def consume_outcome_windows(session_id: str, target_paths: tuple[str, ...] | list[str] | str, *,
                            kind: str | None = None, ledger_path: Path | None = None) -> None:
    """Drop resolved open regret windows for `target_paths` so recovery.none is never double-counted."""
    raw = (target_paths,) if isinstance(target_paths, str) else tuple(target_paths)
    if cands := {x for p in raw if isinstance(p, str) and p for x in (p, _real(p)) if x}:
        _reconcile_windows(session_id, lambda wp, k, _w: True if (kind is None or k == kind) and (wp in cands or _real(wp) in cands) else None, ledger_path=ledger_path)

def record_spool_followup(session_id: str, spool_id: str, recovery: str, regret: str, step_idx: int, *,
                          evidence: str = "observed", ledger_path: Path | None = None) -> bool:
    """Resolve an open output_spool window by spool_id with observed recovery/regret."""
    return bool(spool_id) and _reconcile_windows(session_id, lambda wp, k, _w: (
        (recovery, regret, evidence) if k == "output_spool" and wp == f"spool:{spool_id}" else None), ledger_path=ledger_path, step_idx=step_idx)

def record_spool_command_repeat(session_id: str, cmd_sig: str, step_idx: int, *, ledger_path: Path | None = None) -> bool:
    """Resolve matching open output_spool windows as full/suspected/observed on repeat command."""
    return bool(cmd_sig) and _reconcile_windows(session_id, lambda _wp, k, w: (
        ("full", "suspected", "observed") if k == "output_spool" and isinstance(m := w.get("meta"), Mapping) and m.get("cmd_sig") == cmd_sig else None),
        ledger_path=ledger_path, step_idx=step_idx)

def record_cli_verbose_regret(session_id: str, base_sig: str, step_idx: int, *, ledger_path: Path | None = None) -> bool:
    """Resolve matching open cli_rewrite window as full/suspected/observed on verbose override."""
    return bool(base_sig) and _reconcile_windows(session_id, lambda wp, k, _w: (
        ("full", "suspected", "observed") if k == "cli_rewrite" and wp == f"cli:{base_sig}" else None), ledger_path=ledger_path, step_idx=step_idx)

def _trim_overlaps(meta: Any, req_start: int, req_end: int | None, is_shell_bypass: bool) -> bool:
    if isinstance(meta, Mapping) and isinstance(ts := meta.get("trimmed_start"), int) and not isinstance(ts, bool):
        if isinstance(te := meta.get("trimmed_end"), int) and not isinstance(te, bool) and te >= ts > 0:
            return max(1, int(req_start)) <= te and (req_end is None or req_end == -1 or int(req_end) >= ts)
    return bool(is_shell_bypass)

def record_range_trim_regret(session_id: str, canon_path: str, req_start: int, req_end: int | None, step_idx: int, *,
                             is_shell_bypass: bool = False, ledger_path: Path | None = None) -> bool:
    """Resolve matching open range_trim windows as targeted/suspected/observed on omitted-span overlap or bypass."""
    return bool(tr := _real(canon_path)) and _reconcile_windows(session_id, lambda wp, k, w: (
        ("targeted", "suspected", "observed") if k == "range_trim" and _real(str(w.get("target_path") or wp)) == tr
        and _trim_overlaps(w.get("meta"), req_start, req_end, is_shell_bypass) else None), ledger_path=ledger_path, step_idx=step_idx)

def _on_mutation_win(wp: str, k: str, w: dict[str, Any], mut_real: set[str]) -> tuple[str, str, str] | bool | None:
    if k == "cli_rewrite" or (k == "range_trim" and _real(str(w.get("target_path") or wp)) in mut_real):
        return ("none", "none", "observed")
    if k == "output_spool" and isinstance(m := w.get("meta"), dict) and m.get("cmd_sig"):
        m["cmd_sig"] = ""
        return False
    return None

def reconcile_mutation_windows(session_id: str, mutated_paths: Iterable[str], *, ledger_path: Path | None = None) -> None:
    """Close cli_rewrite & matching range_trim windows on file edit, and clear spool cmd_sig."""
    mut_real = {_real(p) for p in mutated_paths if isinstance(p, str) and p} - {""}
    _reconcile_windows(session_id, lambda wp, k, w: _on_mutation_win(wp, k, w, mut_real), ledger_path=ledger_path)

def dispatch_direct_outcome(
    fn: Callable[..., Any], harness: str, model: str, kind: str, outcome: str = "applied", ledger_path: Path | None = None,
    *, increment_total: bool = True, count: int = 1, session_id: str | None = None, step_idx: int | None = None, call_id: str | None = None,
) -> None:
    """Call `record_direct_outcome` (real or legacy-mocked) with Schema v4 attribution fallback."""
    try:
        fn(harness, model, kind, outcome, ledger_path, increment_total=increment_total, count=count, session_id=session_id, step_idx=step_idx, call_id=call_id)
    except TypeError:
        if fn is record_direct_outcome:
            raise
        for _ in range(max(1, count)):
            fn(harness, model, kind, outcome, ledger_path, increment_total=increment_total)
