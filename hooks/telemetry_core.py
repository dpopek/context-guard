"""Pure functional core for Context-Guard stats and shadow telemetry ledgers (zero I/O or locks)."""

from __future__ import annotations

from collections.abc import Sequence
import time
from typing import Any, NamedTuple

from core.contracts import HARNESS_CAPABILITIES
from core.platform_io import coerce_float, coerce_int, now_iso
from hooks.shell_output import BUCKETS, Measurement

EVENT_KEYS = (
    "allowed_reads", "outlines", "wide_followup_blocks", "wide_followup_retries", "multi_file_blocks",
    "multi_file_retries", "rereads_blocked", "ranges_trimmed", "cli_rewrites", "mcp_guards",
    "credit_reversals", "outline_pulls", "outputs_spooled", "reliability_failures",
)
HARNESS_KEYS = ("antigravity", "claude", "cursor", "codex")
BINARY_MEDIA_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff", ".tif", ".avif", ".pdf",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".mp3", ".wav", ".ogg", ".flac",
    ".m4a", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".wasm", ".class", ".jar", ".bin",
})
SHELL_COUNTER_KEYS = (
    "count", "ok", "fail", "unknown", "tokens", "max_tokens", "spilled", "spilled_tokens",
    "sim_hits", "sim_saved_tokens",
)
SHELL_OUTCOMES = ("ok", "fail", "unknown")

SHADOW_SCHEMA_VERSION, SHADOW_MAX_SESSIONS, SHADOW_MAX_PATHS = 1, 16, 200
SHADOW_MAX_READS_PER_PATH, SHADOW_TTL_SECONDS = 64, 7 * 86400


class Credit(NamedTuple):
    """Bytes one telemetry event added to the ledger, so a later reversal can take them back."""

    baseline_bytes: int
    saved_bytes: int


NO_CREDIT = Credit(0, 0)


def cap_end_line_for_harness(harness: str, start_line: int, end_line: int) -> int:
    """Clamp `end_line` to the maximum single-call line span delivered by `harness`."""
    caps = HARNESS_CAPABILITIES.get(harness, HARNESS_CAPABILITIES["claude"])
    line_cap_end = max(1, start_line) + caps.max_lines - 1
    return line_cap_end if (end_line == -1 or end_line > line_cap_end) else end_line


def default_stats_dict(installed_at: str | None = None) -> dict[str, Any]:
    """Return a clean initialized stats.json ledger dictionary."""
    now_str = installed_at or now_iso()
    return {
        "installed_at": now_str, "updated_at": now_str,
        "baseline_bytes": 0, "saved_bytes": 0, "baseline_tokens": 0, "saved_tokens": 0,
        "reduction_pct": 0.0, "events": {k: 0 for k in EVENT_KEYS},
        "by_harness": {h: {"baseline_tokens": 0, "saved_tokens": 0, "hits": 0} for h in HARNESS_KEYS},
        "by_day": {}, "daily_ledger_started_at": None,
    }


def normalise_shell_family(raw: Any) -> dict[str, Any]:
    """Normalize one command-family shell output stats entry."""
    src = raw if isinstance(raw, dict) else {}
    entry: dict[str, Any] = {key: coerce_int(src.get(key)) for key in SHELL_COUNTER_KEYS}
    buckets = raw_b if isinstance((raw_b := src.get("buckets")), dict) else {}
    entry["buckets"] = {b: coerce_int(buckets.get(b)) for b in BUCKETS}
    return entry


def normalise_shell_output(raw: Any) -> dict[str, Any] | None:
    """Coerce the shell-output section of the ledger; None when the ledger has none."""
    if not isinstance(raw, dict):
        return None
    harnesses = raw.get("harnesses")
    h_map = (
        {str(h): {str(f): normalise_shell_family(v) for f, v in fams.items()}
         for h, fams in harnesses.items() if isinstance(fams, dict)}
        if isinstance(harnesses, dict) else {}
    )
    return {
        "since": raw["since"] if isinstance(raw.get("since"), str) else "",
        "unparsed": coerce_int(raw.get("unparsed")), "harnesses": h_map,
    }


def apply_shell_output(
    state: dict[str, Any], harness: str, family: str, measurement: Measurement | None, outcome: str,
) -> None:
    """Count one shell call; `measurement` None means its output was not found in the payload."""
    section = state.setdefault("shell_output", {"since": "", "unparsed": 0, "harnesses": {}})
    if not section.get("since"):
        section["since"] = state["updated_at"]
    families = section.setdefault("harnesses", {}).setdefault(harness, {})
    entry = families[family] = families.get(family) or normalise_shell_family(None)
    entry["count"] += 1
    entry[outcome if outcome in SHELL_OUTCOMES else "unknown"] += 1
    if measurement is None:
        section["unparsed"] = coerce_int(section.get("unparsed")) + 1
        return
    # `tokens` and `max_tokens` track context consumption; spilled outputs count as their preview.
    entry["tokens"] += measurement.context_tokens
    entry["max_tokens"] = max(entry["max_tokens"], measurement.context_tokens)
    entry["buckets"][measurement.bucket] += 1
    if measurement.spilled:
        entry["spilled"] += 1
        entry["spilled_tokens"] += measurement.tokens
    if measurement.sim_hit:
        entry["sim_hits"] += 1
        entry["sim_saved_tokens"] += measurement.sim_saved_tokens


def normalise_stats(raw: Any, *, now_str: str | None = None) -> dict[str, Any]:
    """Build a typed stats dict from ledger data, preserving unknown event keys safely."""
    base = default_stats_dict(installed_at=now_str)
    if not isinstance(raw, dict):
        return base
    for key in ("installed_at", "updated_at"):
        if isinstance(raw.get(key), str) and raw[key]:
            base[key] = raw[key]
    for key in ("baseline_bytes", "saved_bytes", "baseline_tokens", "saved_tokens"):
        if key in raw:
            base[key] = coerce_int(raw[key])
    if "reduction_pct" in raw:
        base["reduction_pct"] = coerce_float(raw["reduction_pct"])
    if isinstance((events := raw.get("events")), dict):
        norm_events = {k: max(0, coerce_int(events.get(k))) for k in EVENT_KEYS}
        for k, v in events.items():
            if isinstance(k, str) and k and k not in norm_events:
                norm_events[k] = max(0, coerce_int(v))
        base["events"] = norm_events
    if isinstance((by_h := raw.get("by_harness")), dict):
        for h, hv in by_h.items():
            if isinstance(h, str) and isinstance(hv, dict):
                base["by_harness"][h] = {k: coerce_int(hv.get(k)) for k in ("baseline_tokens", "saved_tokens", "hits")}
    if isinstance((by_hb := raw.get("by_harness_bytes")), dict):
        if nhb := {h: {"baseline_bytes": max(0, coerce_int(v.get("baseline_bytes"))), "saved_bytes": max(0, coerce_int(v.get("saved_bytes")))}
                   for h, v in by_hb.items() if isinstance(h, str) and isinstance(v, dict)}:
            base["by_harness_bytes"] = nhb
    if isinstance(raw.get("last_event"), dict):
        base["last_event"] = raw["last_event"]
    if isinstance((rei := raw.get("recent_event_ids")), list):
        base["recent_event_ids"] = [x for x in rei if isinstance(x, str)][-128:]
    if (shell_out := normalise_shell_output(raw.get("shell_output"))) is not None:
        base["shell_output"] = shell_out
    raw_bd, raw_start = raw.get("by_day"), raw.get("daily_ledger_started_at")
    norm_bd = (
        {dk: {"baseline_bytes": coerce_int(dv.get("baseline_bytes")), "saved_bytes": coerce_int(dv.get("saved_bytes"))}
         for dk, dv in raw_bd.items() if isinstance(dk, str) and len(dk) == 10 and isinstance(dv, dict)}
        if isinstance(raw_bd, dict) else {}
    )
    if norm_bd:
        base["by_day"] = norm_bd
        base["daily_ledger_started_at"] = raw_start if isinstance(raw_start, str) and len(raw_start) == 10 else min(norm_bd.keys())
    elif "by_day" not in raw and (base["baseline_bytes"] > 0 or base["saved_bytes"] > 0):
        inst_d, upd_d = str(base["installed_at"])[:10], str(base["updated_at"])[:10]
        if len(inst_d) == 10 and inst_d == upd_d:
            base["by_day"] = {inst_d: {"baseline_bytes": base["baseline_bytes"], "saved_bytes": base["saved_bytes"]}}
            base["daily_ledger_started_at"] = inst_d
    return base


def ensure_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    """Return nested dict at `parent[key]`, initializing `{}` if missing or non-dict."""
    if not isinstance((val := parent.get(key)), dict):
        parent[key] = val = {}
    return val


def apply_telemetry_event(
    state: dict[str, Any], harness: str, event_kind: str, baseline_delta: int, saved_delta: int,
    target_day: str | None = None, *, event_id: str | None = None, fallback_day_iso: str | None = None,
) -> bool:
    """Apply signed byte deltas to `state` in memory; returns False if duplicate `event_id`."""
    if event_id:
        rec: list[Any] = raw_rec if isinstance((raw_rec := state.get("recent_event_ids")), list) else []
        dedupe_key = f"{event_kind}:{event_id}"
        if dedupe_key in rec:
            return False
        state["recent_event_ids"] = (rec + [dedupe_key])[-128:]
    prev_b, prev_s = coerce_int(state.get("baseline_bytes")), coerce_int(state.get("saved_bytes"))
    new_b = max(0, prev_b + baseline_delta)
    new_s = min(new_b, max(0, prev_s + saved_delta))
    state["baseline_bytes"], state["saved_bytes"] = new_b, new_s
    state["baseline_tokens"], state["saved_tokens"] = new_b // 4, new_s // 4
    state["reduction_pct"] = min(100.0, round((new_s / new_b) * 100.0, 1)) if new_b > 0 else 0.0
    by_day = ensure_dict(state, "by_day")
    utc_day = str(state.get("updated_at") or fallback_day_iso or "")[:10]
    if event_kind == "credit_reversals":
        day_key = target_day if (target_day and target_day in by_day) else utc_day
    else:
        day_key = target_day if (isinstance(target_day, str) and len(target_day) == 10) else utc_day
    day_e = by_day.setdefault(day_key, {"baseline_bytes": 0, "saved_bytes": 0})
    day_e["baseline_bytes"] = coerce_int(day_e.get("baseline_bytes")) + (new_b - prev_b)
    day_e["saved_bytes"] = coerce_int(day_e.get("saved_bytes")) + (new_s - prev_s)
    if not state.get("daily_ledger_started_at"):
        state["daily_ledger_started_at"] = day_key
    events_map = ensure_dict(state, "events")
    events_map[event_kind] = coerce_int(events_map.get(event_kind)) + 1
    h_e = ensure_dict(state, "by_harness").setdefault(harness, {"baseline_tokens": 0, "saved_tokens": 0, "hits": 0})
    by_hb = ensure_dict(state, "by_harness_bytes")
    if not isinstance((hb_e := by_hb.get(harness)), dict):
        hb_e = by_hb[harness] = {"baseline_bytes": max(0, coerce_int(h_e.get("baseline_tokens"))) * 4, "saved_bytes": max(0, coerce_int(h_e.get("saved_tokens"))) * 4}
    hb_e["baseline_bytes"] = max(0, coerce_int(hb_e.get("baseline_bytes")) + baseline_delta)
    hb_e["saved_bytes"] = min(hb_e["baseline_bytes"], max(0, coerce_int(hb_e.get("saved_bytes")) + saved_delta))
    h_e["baseline_tokens"], h_e["saved_tokens"] = hb_e["baseline_bytes"] // 4, hb_e["saved_bytes"] // 4
    if saved_delta > 0:
        h_e["hits"] = coerce_int(h_e.get("hits")) + 1
        state["last_event"] = {"kind": event_kind, "saved_tokens": saved_delta // 4, "harness": harness, "timestamp": state.get("updated_at") or fallback_day_iso or ""}
    elif event_kind == "credit_reversals" and saved_delta < 0:
        h_e["hits"] = max(0, coerce_int(h_e.get("hits")) - 1)
        state.pop("last_event", None)
    return True


def apply_reliability_failure(state: dict[str, Any]) -> None:
    """Increment `events.reliability_failures` in `state` without touching `by_harness`."""
    ev = ensure_dict(state, "events")
    ev["reliability_failures"] = coerce_int(ev.get("reliability_failures")) + 1


def _is_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)


def merge_shadow_reads(reads: Sequence[Any], max_reads: int = SHADOW_MAX_READS_PER_PATH) -> list[list[int]]:
    """Coalesce adjacent/overlapping `[start, end, step, tier]` shadow intervals per tier and cap LRU."""
    by_tier: dict[int, list[tuple[int, float, int]]] = {}
    for item in reads:
        if isinstance(item, (list, tuple)) and len(item) >= 4 and all(_is_int(x) for x in item[:4]):
            by_tier.setdefault(int(item[3]), []).append(
                (int(item[0]), float("inf") if int(item[1]) == -1 else float(item[1]), int(item[2]))
            )
    if not by_tier:
        return []
    out: list[list[int]] = []
    for tier, parsed in by_tier.items():
        parsed.sort(key=lambda iv: (iv[0], iv[1]))
        merged: list[list[float | int]] = [[parsed[0][0], parsed[0][1], parsed[0][2]]]
        for nxt_s, nxt_e, nxt_step in parsed[1:]:
            if merged[-1][1] + 1 >= nxt_s:
                merged[-1][1] = max(merged[-1][1], nxt_e)
                merged[-1][2] = max(int(merged[-1][2]), nxt_step)
            else:
                merged.append([nxt_s, nxt_e, nxt_step])
        out.extend([int(m[0]), -1 if m[1] == float("inf") else int(m[1]), int(m[2]), tier] for m in merged)
    if len(out) > max_reads:
        out = sorted(out, key=lambda item: (item[2], item[0]))[-max_reads:]
    out.sort(key=lambda item: (item[0], float("inf") if item[1] == -1 else float(item[1]), item[3]))
    return out


def prune_shadow_state(state: dict[str, Any], ts: float) -> dict[str, Any]:
    """Enforce TTL, max-200 paths/session, and max-16 sessions with safe float coercion."""
    raw_s, live = state.get("sessions"), []
    for sid, sess in raw_s.items() if isinstance(raw_s, dict) else ():
        if isinstance(sid, str) and isinstance(sess, dict):
            upd = coerce_float(sess.get("updated_ts"), 0.0)
            if ts - upd <= SHADOW_TTL_SECONDS:
                paths = sess.get("paths")
                if isinstance(paths, dict):
                    valid = [(ph, pv) for ph, pv in paths.items() if isinstance(ph, str) and isinstance(pv, dict)]
                    if len(valid) > SHADOW_MAX_PATHS:
                        sess["paths"] = dict(sorted(valid, key=lambda kv: coerce_float(kv[1].get("updated_ts"), 0.0))[-SHADOW_MAX_PATHS:])
                    elif len(valid) != len(paths):
                        sess["paths"] = dict(valid)
                else:
                    sess["paths"] = {}
                live.append((upd, sid, sess))
    state["sessions"] = {sid: sess for _, sid, sess in sorted(live, key=lambda x: x[0])[-SHADOW_MAX_SESSIONS:]}
    return state


def norm_shadow_spools(raw_sp: Any) -> dict[str, Any]:
    """Normalize the global `shadow_spools` counter map."""
    sp = raw_sp if isinstance(raw_sp, dict) else {}
    raw_bh = sp.get("by_harness")
    by_h = {h: max(0, coerce_int(v)) for h, v in raw_bh.items() if isinstance(h, str)} if isinstance(raw_bh, dict) else {}
    return {
        "count": max(0, coerce_int(sp.get("count"))), "by_harness": by_h,
        "estimated_saved_bytes": max(0, coerce_int(sp.get("estimated_saved_bytes"))),
        "last_ts": sp["last_ts"] if isinstance(sp.get("last_ts"), str) else None,
    }


def normalise_shadow_ledger(raw: Any, now_ts: float | None = None, *, now_str: str | None = None) -> dict[str, Any]:
    """Normalize shadow.json safely against corrupt field types and enforce retention caps."""
    base: dict[str, Any] = {"schema_version": SHADOW_SCHEMA_VERSION, "updated_at": now_str or now_iso(), "sessions": {}}
    if not isinstance(raw, dict) or raw.get("schema_version") != SHADOW_SCHEMA_VERSION:
        return base
    if isinstance(raw.get("updated_at"), str) and raw["updated_at"]:
        base["updated_at"] = raw["updated_at"]
    for sid, sv in raw.get("sessions", {}).items() if isinstance(raw.get("sessions"), dict) else ():
        if isinstance(sid, str) and isinstance(sv, dict):
            paths: dict[str, Any] = {}
            if isinstance((raw_paths := sv.get("paths")), dict):
                for ph, pv in raw_paths.items():
                    if isinstance(ph, str) and isinstance(pv, dict):
                        rr = pv.get("reads")
                        paths[ph] = {
                            "content_sha256": rs if isinstance((rs := pv.get("content_sha256")), str) else "",
                            "updated_ts": coerce_float(pv.get("updated_ts"), 0.0),
                            "reads": merge_shadow_reads(rr) if isinstance(rr, (list, tuple)) else [],
                        }
            base["sessions"][sid] = {
                "updated_ts": coerce_float(sv.get("updated_ts"), 0.0),
                "max_step": max(0, coerce_int(sv.get("max_step"))),
                "checkpoint_step": max(0, coerce_int(sv.get("checkpoint_step"))),
                "paths": paths,
            }
    if isinstance(raw.get("shadow_spools"), dict):
        base["shadow_spools"] = norm_shadow_spools(raw["shadow_spools"])
    return prune_shadow_state(base, now_ts if now_ts is not None else time.time())


def keep_shadow_read(r: list[int], ckpt: int | None, mstep: int | None, inc: bool) -> bool:
    """Return True iff shadow interval `r` survives checkpoint `ckpt` and rewind `mstep`."""
    return (ckpt is None or r[2] > ckpt) and not (mstep is not None and (r[2] >= mstep if inc else r[2] > mstep))


def apply_shadow_read(
    state: dict[str, Any], session_id: str, path_hash: str, start_line: int, end_line: int,
    step_idx: int, achievable_tier: int, content_sha256: str, ts: float, *, min_tier: int = 2,
) -> bool:
    """Record one shadow read slice into `state`; skips LRU insertion when `achievable_tier < min_tier`."""
    if int(achievable_tier) < int(min_tier):
        return False
    sess = state["sessions"].setdefault(session_id, {"updated_ts": ts, "max_step": 0, "checkpoint_step": 0, "paths": {}})
    sess["updated_ts"], sess["max_step"] = ts, max(coerce_int(sess.get("max_step")), int(step_idx))
    entry = sess["paths"].get(path_hash)
    if not isinstance(entry, dict) or entry.get("content_sha256") != content_sha256:
        entry = sess["paths"][path_hash] = {"content_sha256": content_sha256, "reads": [], "updated_ts": ts}
    entry["updated_ts"] = ts
    reads: list[Any] = list(raw_r) if isinstance((raw_r := entry.get("reads")), list) else []
    reads.append([int(start_line), int(end_line), int(step_idx), int(achievable_tier)])
    entry["reads"] = merge_shadow_reads(reads)
    return True


def apply_shadow_spool(state: dict[str, Any], harness: str, saved_bytes: int, ts_iso: str) -> None:
    """Record one simulated output spool savings entry into `state['shadow_spools']`."""
    sp = state["shadow_spools"] = norm_shadow_spools(state.get("shadow_spools"))
    sp["count"] += 1
    sp["estimated_saved_bytes"] += max(0, int(saved_bytes))
    sp["last_ts"] = ts_iso
    sp["by_harness"][harness] = coerce_int(sp["by_harness"].get(harness)) + 1


def apply_shadow_invalidation(
    state: dict[str, Any], *, session_id: str | None = None, target_hash: str | None = None,
    content_sha256: str | None = None, ckpt: int | None = None, mstep: int | None = None,
    inclusive_rewind: bool = True, full_compact: bool = False,
) -> None:
    """Invalidate shadow sessions/paths on edit, compaction, or rewind; only global compact resets spools."""
    targets = [state["sessions"].get(session_id)] if session_id else list(state["sessions"].values())
    for sess in (s for s in targets if isinstance(s, dict)):
        paths = sess.setdefault("paths", {})
        if not isinstance(paths, dict):
            sess["paths"] = paths = {}
        if target_hash and target_hash in paths and (
            not content_sha256 or paths[target_hash].get("content_sha256") != content_sha256
        ):
            paths.pop(target_hash, None)
        if full_compact:
            paths.clear()
        if ckpt is not None:
            sess["checkpoint_step"] = max(coerce_int(sess.get("checkpoint_step")), ckpt)
        if mstep is not None:
            sess["max_step"] = min(coerce_int(sess.get("max_step")), mstep)
        if not full_compact and (ckpt is not None or mstep is not None):
            for ph in list(paths):
                if kept := [r for r in paths[ph].get("reads", []) if keep_shadow_read(r, ckpt, mstep, inclusive_rewind)]:
                    paths[ph]["reads"] = kept
                else:
                    paths.pop(ph, None)
    if full_compact and session_id is None and "shadow_spools" in state:
        state["shadow_spools"] = norm_shadow_spools(None)
