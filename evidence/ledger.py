"""Durable deduplicated ContextReceiptV1 event ledger, capability evidence, and Cursor conformance gate."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib, json, os, re, stat, tempfile
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from hooks import file_io, harness_adapter, outcomes, post_tool_use, state_store
from policies.api import (
    ADAPTER_CONTRACT_VERSION, CapabilityAttestationKey, CapabilityRequirementV1,
    EvidenceEnvironmentMetadataV1, HARNESS_OUTPUT_CAPABILITIES, RECEIPT_SCHEMA_VERSION,
    VALID_CAPABILITY_EVIDENCE_LEVELS, VALID_TURN_CORRELATIONS,
)
from spool import receipts as spool_receipts

EVENT_LEDGER_SCHEMA_VERSION: int = 1
DEFAULT_EVENT_LEDGER_FILENAME: str = "evidence_events.json"
REQUIRED_EVIDENCE_CAPABILITIES: tuple[str, ...] = (
    "pre_tool_interception", "output_replacement", "native_fail_closed",
    "content_verified_reads", "prompt_cache_telemetry",
)

_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
_POSIX_HOME_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9._-]+")
_WIN_HOME_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:(?:[/\\]|\\\\)Users(?:[/\\]|\\\\)[A-Za-z0-9._-]+", re.I)
_PATH_SCRUB_KEYS = frozenset({
    "config_path", "repo_map_path", "workspace_root", "transcript_path", "state_dir", "home_dir",
    "stats_path", "outcomes_path", "usage_path", "update_path", "shadow_path", "spool_dir", "receipts_path", "cwd",
})
_CAPABILITY_RANK = {level: idx for idx, level in enumerate(VALID_CAPABILITY_EVIDENCE_LEVELS)}

__all__ = [
    "DEFAULT_EVENT_LEDGER_FILENAME", "EVENT_LEDGER_SCHEMA_VERSION", "REQUIRED_EVIDENCE_CAPABILITIES",
    "append_durable_events", "build_capability_attestation_key", "collect_environment_metadata",
    "compute_hook_config_fingerprint", "derive_outcomes_from_ledger", "ingest_context_receipts",
    "resolve_capability_requirement", "run_cursor_cli_conformance",
]


def _utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scrub_home_paths(text: str) -> str:
    cleaned = text
    try:
        home_p = Path.home()
        for cand in (str(home_p), str(home_p.resolve())):
            if cand and cand not in ("/", "\\"):
                cleaned = cleaned.replace(cand, "[redacted-path]")
    except (RuntimeError, OSError):
        pass
    return _WIN_HOME_RE.sub("[redacted-path]", _POSIX_HOME_RE.sub("[redacted-path]", cleaned))


def _scrub_value(val: Any) -> Any:
    if isinstance(val, Mapping):
        return {
            ks: _scrub_value(val[k]) for k in sorted(val, key=str)
            if (ks := str(k)).lower() not in _PATH_SCRUB_KEYS and not ks.lower().endswith(("_path", "_paths", "_dir", "_dirs"))
        }
    if isinstance(val, (list, tuple)):
        return [_scrub_value(item) for item in val]
    if isinstance(val, str):
        return _scrub_home_paths(val)
    return val if isinstance(val, (bool, int, float)) or val is None else _scrub_home_paths(str(val))


def _lock_path_for(ledger_path: Path) -> Path:
    return ledger_path.with_suffix(".lock")


def _any_unsafe_link(*paths: Path) -> bool:
    return any(spool_receipts.check_unsafe_link(p) for p in paths)


def _write_error(error: str) -> dict[str, Any]:
    return {"ok": False, "error": error, "appended_count": 0, "duplicate_count": 0, "invalid_count": 0, "total_events": 0, "corrupt_source_lines": 0}


def _derive_empty(completeness: str, *, ok: bool, error: str | None = None, corrupt_lines: int = 0) -> dict[str, Any]:
    res: dict[str, Any] = {
        "ok": ok, "schema_version": EVENT_LEDGER_SCHEMA_VERSION, "completeness": completeness,
        "totals": None, "by_group": {}, "reliability_failures": 0, "event_count": 0,
        "corrupt_source_lines": corrupt_lines, "missing_created_spool_ids": [], "migrated_outcomes_baseline": None,
    }
    if error is not None:
        res["error"] = error
    return res


def _read_regular_bytes(path: Path) -> tuple[bytes | None, str | None]:
    if spool_receipts.check_unsafe_link(path.parent) or spool_receipts.check_unsafe_link(path):
        return None, "unsafe_path"
    if not path.exists():
        return None, "not_found"
    try:
        with os.fdopen(os.open(str(path), os.O_RDONLY | _O_FLAGS), "rb") as fh:
            return (fh.read(), None) if stat.S_ISREG(os.fstat(fh.fileno()).st_mode) else (None, "unsafe_path")
    except FileNotFoundError:
        return None, "not_found"
    except OSError:
        return None, "unsafe_path"


@contextmanager
def _ledger_lock(lock_path: Path) -> Iterator[None]:
    if spool_receipts.check_unsafe_link(lock_path):
        raise OSError("unsafe_path: evidence ledger lock")
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT | _O_FLAGS, 0o600)
    with os.fdopen(fd, "a+", encoding="utf-8") as fh:
        if os.name != "nt":
            os.chmod(str(lock_path), 0o600)
        file_io.flock(fh.fileno(), file_io.LOCK_EX)
        try:
            yield
        finally:
            file_io.flock(fh.fileno(), file_io.LOCK_UN)


def _nonneg_int(raw: Any, default: int = 0) -> int:
    return max(0, raw) if isinstance(raw, int) and not isinstance(raw, bool) else default


def _normalize_span(raw: Any) -> list[int] | None:
    if raw is None:
        return [0, 0]
    if not isinstance(raw, (list, tuple)) or len(raw) != 2 or any(isinstance(x, bool) or not isinstance(x, int) for x in raw):
        return None
    return [int(raw[0]), int(raw[1])]


def _normalize_ledger_event(raw: Any) -> tuple[str, dict[str, Any]] | None:
    if not isinstance(raw, Mapping):
        return None
    sv = raw.get("schema_version")
    if sv is not None and (isinstance(sv, bool) or sv != RECEIPT_SCHEMA_VERSION):
        return None
    eid = raw["event_id"].strip() if isinstance(raw.get("event_id"), str) else ""
    rid = raw["receipt_id"].strip() if isinstance(raw.get("receipt_id"), str) else ""
    dedup_key = eid or rid
    raw_type = raw.get("event_type")
    if not dedup_key or not isinstance(raw_type, str) or not raw_type.strip():
        return None
    ls, bs = _normalize_span(raw.get("line_span")), _normalize_span(raw.get("byte_span"))
    if ls is None or bs is None:
        return None
    ev_type, fk = raw_type.strip(), (raw["failure_kind"] if isinstance(raw.get("failure_kind"), str) else None)
    raw_tc, raw_dur, call_id = raw.get("turn_correlation"), raw.get("hook_duration_ms"), str(raw.get("call_id") or "")
    event: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION, "receipt_id": rid, "event_id": dedup_key,
        "parent_event_id": raw["parent_event_id"] if isinstance(raw.get("parent_event_id"), str) else None,
        "timestamp": str(raw.get("timestamp") or ""), "ts_ms": _nonneg_int(raw.get("ts_ms")),
        "hook_duration_ms": float(raw_dur) if isinstance(raw_dur, (int, float)) and not isinstance(raw_dur, bool) else None,
        "event_type": ev_type, "harness": str(raw.get("harness") or "").strip() or "unknown",
        "session_id": str(raw.get("session_id") or ""), "workspace_id": str(raw.get("workspace_id") or ""),
        "turn_key": str(raw.get("turn_key") or ""),
        "turn_correlation": raw_tc if isinstance(raw_tc, str) and raw_tc in VALID_TURN_CORRELATIONS else "unobserved",
        "call_id": call_id, "tool_call_id": raw["tool_call_id"] if isinstance(raw.get("tool_call_id"), str) else call_id,
        "spool_id": str(raw.get("spool_id") or ""), "intervention": str(raw.get("intervention") or "").strip() or "output_spool",
        "mode": str(raw.get("mode") or "") or ("active" if ev_type in ("spool_created", "spool_delivery_verified") else "recovery"),
        "status": str(raw.get("status") or "") or ("error" if (ev_type == "spool_integrity_failure" or fk is not None) else "ok"),
        "line_span": ls, "byte_span": bs, "source_hash": str(raw.get("source_hash") or ""),
        "original_bytes": _nonneg_int(raw.get("original_bytes")), "replacement_bytes": _nonneg_int(raw.get("replacement_bytes")),
        "upstream_truncation": bool(raw.get("upstream_truncation", False)), "delivery_evidence": str(raw.get("delivery_evidence") or ""),
        "spool_id_referenced": bool(raw.get("spool_id_referenced", False)), "failure_kind": fk,
        "reason": raw["reason"] if isinstance(raw.get("reason"), str) else None,
    }
    if isinstance((raw_model := raw.get("model")), str) and raw_model.strip():
        event["model"] = raw_model.strip()
    return dedup_key, event


def _is_nonempty_baseline(raw: Any) -> bool:
    if not isinstance(raw, Mapping) or not raw:
        return False
    if "by_key" not in raw:
        return True
    if isinstance((by_key := raw.get("by_key")), Mapping) and len(by_key) > 0:
        return True
    return any(isinstance((bm := raw.get(b)), Mapping) and _nonneg_int(bm.get("total")) > 0 for b in ("unattributed_anon", "late_unattributed"))


def _normalize_baseline(raw: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if raw is None or not _is_nonempty_baseline(raw):
        return None
    scrubbed = _scrub_value(raw)
    return dict(scrubbed) if isinstance(scrubbed, Mapping) and _is_nonempty_baseline(scrubbed) else None


def _empty_ledger_doc() -> dict[str, Any]:
    return {
        "schema_version": EVENT_LEDGER_SCHEMA_VERSION, "updated_at": _utc_now_iso_z(),
        "events": [], "seen_event_ids": [], "migrated_outcomes_baseline": None, "corrupt_source_lines": 0,
    }


def _load_existing_ledger(ledger_path: Path) -> tuple[dict[str, Any], bool, str | None]:
    raw_bytes, err = _read_regular_bytes(ledger_path)
    if err is not None or raw_bytes is None:
        return _empty_ledger_doc(), False, None if err == "not_found" else (err or "read_error")
    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return _empty_ledger_doc(), True, "corrupt_ledger"
    if not isinstance(parsed, dict) or parsed.get("schema_version") != EVENT_LEDGER_SCHEMA_VERSION:
        return _empty_ledger_doc(), True, "corrupt_ledger"
    doc = _empty_ledger_doc()
    if isinstance(parsed.get("updated_at"), str) and parsed["updated_at"].strip():
        doc["updated_at"] = parsed["updated_at"].strip()
    seen_list = list(dict.fromkeys(r.strip() for r in (parsed.get("seen_event_ids") or ()) if isinstance(r, str) and r.strip()))
    seen_set, added, events = set(seen_list), set(), []
    for item in parsed.get("events") or ():
        if (norm := _normalize_ledger_event(item)) is not None:
            eid, ev = norm
            if eid not in seen_set:
                seen_set.add(eid)
                seen_list.append(eid)
            if eid not in added:
                added.add(eid)
                events.append(ev)
    doc["events"], doc["seen_event_ids"] = events, seen_list
    raw_base = parsed.get("migrated_outcomes_baseline")
    doc["migrated_outcomes_baseline"] = _normalize_baseline(raw_base) if isinstance(raw_base, Mapping) else None
    doc["corrupt_source_lines"] = _nonneg_int(parsed.get("corrupt_source_lines"))
    return doc, True, None


def _derive_from_doc(doc: Mapping[str, Any]) -> dict[str, Any]:
    deduped: list[dict[str, Any]] = list(doc.get("events") or ())
    corrupt_lines, baseline = _nonneg_int(doc.get("corrupt_source_lines")), doc.get("migrated_outcomes_baseline")
    has_baseline = _is_nonempty_baseline(baseline)
    created_sids = {str(e.get("spool_id") or "") for e in deduped if e.get("event_type") == "spool_created"} - {""}
    dep_sids = {str(e.get("spool_id") or "") for e in deduped if e.get("event_type") in ("spool_recovery", "spool_delivery_verified")} - {""}
    missing_created = sorted(sid for sid in dep_sids if sid not in created_sids)
    completeness = "incomplete" if (corrupt_lines > 0 or missing_created) else ("migrated_with_baseline" if has_baseline else "complete")
    by_group: dict[str, dict[str, int]] = {}
    for ev in deduped:
        gkey = f"{str(ev.get('harness') or '').strip() or 'unknown'}|{str(ev.get('model') or '').strip() or 'unknown'}|{str(ev.get('intervention') or '').strip() or 'output_spool'}"
        row = by_group.setdefault(gkey, {"created": 0, "delivery_verified": 0, "recoveries": 0, "reliability_failures": 0, "total_events": 0})
        row["total_events"] += 1
        ev_type = str(ev.get("event_type") or "")
        for kind_ev, col in (("spool_created", "created"), ("spool_delivery_verified", "delivery_verified"), ("spool_recovery", "recoveries")):
            if ev_type == kind_ev:
                row[col] += 1
        if ev_type == "spool_integrity_failure" or ev.get("failure_kind") == "reliability_failure":
            row["reliability_failures"] += 1
    totals = {k: sum(g[k] for g in by_group.values()) for k in ("created", "delivery_verified", "recoveries", "reliability_failures")}
    totals["total_events"] = len(deduped)
    return {
        "ok": True, "schema_version": EVENT_LEDGER_SCHEMA_VERSION, "completeness": completeness,
        "totals": totals, "by_group": {k: by_group[k] for k in sorted(by_group)},
        "reliability_failures": totals["reliability_failures"], "event_count": len(deduped),
        "corrupt_source_lines": corrupt_lines, "missing_created_spool_ids": missing_created,
        "migrated_outcomes_baseline": dict(baseline) if isinstance(baseline, Mapping) and has_baseline else None,
    }


def _unsafe_ledger_target(ledger_path: Path, lock_path: Path) -> bool:
    return _any_unsafe_link(ledger_path.parent, ledger_path, lock_path) or (ledger_path.exists() and ledger_path.is_dir()) or (lock_path.exists() and lock_path.is_dir())


def _write_ledger_events(
    ledger_path: Path, events: Sequence[Mapping[str, Any]], *,
    migrated_outcomes: Mapping[str, Any] | None = None, corrupt_source_lines: int = 0, from_ingest: bool = False,
) -> dict[str, Any]:
    lock_path = _lock_path_for(ledger_path)
    if _unsafe_ledger_target(ledger_path, lock_path):
        return _write_error("unsafe_path")
    parent_existed = ledger_path.parent.exists()
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    if not parent_existed and os.name != "nt":
        os.chmod(str(ledger_path.parent), 0o700)
    if _unsafe_ledger_target(ledger_path, lock_path):
        return _write_error("unsafe_path")

    with _ledger_lock(lock_path):
        if _unsafe_ledger_target(ledger_path, lock_path):
            return _write_error("unsafe_path")
        doc, existed_on_disk, load_err = _load_existing_ledger(ledger_path)
        if load_err == "unsafe_path":
            return _write_error("unsafe_path")
        if load_err == "corrupt_ledger" and existed_on_disk:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            os.replace(str(ledger_path), str(ledger_path.with_name(f"{ledger_path.name}.corrupt-{stamp}")))
            existed_on_disk = False
        seen_ids, appended, duplicates, invalid = set(doc["seen_event_ids"]), 0, 0, 0
        for raw_ev in events:
            if (norm := _normalize_ledger_event(raw_ev)) is None:
                invalid += 1
            elif norm[0] in seen_ids:
                duplicates += 1
            else:
                seen_ids.add(norm[0])
                doc["seen_event_ids"].append(norm[0])
                doc["events"].append(norm[1])
                appended += 1
        prev_corrupt, eff_corrupt = _nonneg_int(doc.get("corrupt_source_lines")), max(0, int(corrupt_source_lines))
        new_corrupt = max(prev_corrupt, eff_corrupt) if (from_ingest and (duplicates > 0 or (appended == 0 and prev_corrupt >= eff_corrupt))) else (prev_corrupt + eff_corrupt)
        norm_base = _normalize_baseline(migrated_outcomes) if migrated_outcomes is not None else None
        if (not existed_on_disk) or appended > 0 or (norm_base is not None and norm_base != doc.get("migrated_outcomes_baseline")) or new_corrupt != prev_corrupt:
            if norm_base is not None:
                doc["migrated_outcomes_baseline"] = norm_base
            doc["corrupt_source_lines"], doc["updated_at"] = new_corrupt, _utc_now_iso_z()
            spool_receipts.atomic_write_bytes(ledger_path, (json.dumps(doc, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8"))
        derived = _derive_from_doc(doc)
        return {
            "ok": True, "appended_count": appended, "duplicate_count": duplicates, "invalid_count": invalid,
            "total_events": len(doc["events"]), "corrupt_source_lines": doc["corrupt_source_lines"],
            "completeness": derived["completeness"], "has_migrated_baseline": doc["migrated_outcomes_baseline"] is not None,
        }


def append_durable_events(
    ledger_path: Path, events: Sequence[Mapping[str, Any]], *, migrated_outcomes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically append deduplicated ContextReceiptV1 events under flock and write mode 0o600."""
    return _write_ledger_events(Path(ledger_path), events, migrated_outcomes=migrated_outcomes)


def ingest_context_receipts(
    ledger_path: Path, receipts_path: Path, *, outcomes_path: Path | None = None,
) -> dict[str, Any]:
    """Ingest receipts.jsonl and optional Outcomes v4 baseline into the durable deduplicated ledger."""
    eff_ledger, eff_receipts = Path(ledger_path), Path(receipts_path)
    eff_outcomes = Path(outcomes_path) if outcomes_path is not None else None
    if _any_unsafe_link(eff_ledger.parent, eff_ledger, _lock_path_for(eff_ledger), eff_receipts.parent, eff_receipts) or (
        eff_outcomes is not None and _any_unsafe_link(eff_outcomes.parent, eff_outcomes)
    ):
        return _write_error("unsafe_path")
    parsed_events: list[dict[str, Any]] = []
    corrupt_lines = 0
    receipts_bytes, rc_err = _read_regular_bytes(eff_receipts)
    if rc_err not in (None, "not_found"):
        return _write_error(rc_err or "unsafe_path")
    if receipts_bytes is not None:
        try:
            text = receipts_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text, corrupt_lines = "", corrupt_lines + 1
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    parsed_events.append(obj)
                else:
                    corrupt_lines += 1
            except ValueError:
                corrupt_lines += 1
    baseline: dict[str, Any] | None = None
    if eff_outcomes is not None:
        out_bytes, out_err = _read_regular_bytes(eff_outcomes)
        if out_err not in (None, "not_found"):
            return _write_error(out_err or "unsafe_path")
        if out_bytes is not None:
            try:
                if isinstance(json.loads(out_bytes.decode("utf-8")), dict):
                    baseline = _normalize_baseline(outcomes.load_outcomes(eff_outcomes))
                else:
                    corrupt_lines += 1
            except (UnicodeDecodeError, ValueError):
                corrupt_lines += 1
    if rc_err == "not_found" and baseline is None and corrupt_lines == 0:
        derived = derive_outcomes_from_ledger(eff_ledger)
        return {
            "ok": bool(derived.get("ok", True)), "appended_count": 0, "duplicate_count": 0, "invalid_count": 0,
            "total_events": int(derived.get("event_count") or 0), "corrupt_source_lines": int(derived.get("corrupt_source_lines") or 0),
            "completeness": derived["completeness"], "has_migrated_baseline": derived.get("migrated_outcomes_baseline") is not None,
        }
    return _write_ledger_events(eff_ledger, parsed_events, migrated_outcomes=baseline, corrupt_source_lines=corrupt_lines, from_ingest=True)


def derive_outcomes_from_ledger(ledger_path: Path) -> dict[str, Any]:
    """Deterministically derive Outcomes v4 aggregates and completeness from a durable event ledger."""
    eff_ledger = Path(ledger_path)
    if _any_unsafe_link(eff_ledger.parent, eff_ledger, _lock_path_for(eff_ledger)):
        return _derive_empty("unavailable", ok=False, error="unsafe_path")
    doc, existed, load_err = _load_existing_ledger(eff_ledger)
    if not existed and load_err is None:
        return _derive_empty("unavailable", ok=True)
    if load_err is not None:
        is_unsafe = load_err == "unsafe_path"
        return _derive_empty("unavailable" if is_unsafe else "incomplete", ok=False, error=load_err, corrupt_lines=0 if is_unsafe else 1)
    return _derive_from_doc(doc)


def compute_hook_config_fingerprint(
    harness_id: str, runtime_cfg: Mapping[str, Any] | None = None, hook_payload: Mapping[str, Any] | None = None,
) -> str:
    """Compute canonical sha256:<64hex> fingerprint of Context-Guard config and scrubbed hook registration."""
    rt_out: dict[str, Any] = {}
    if isinstance(runtime_cfg, Mapping):
        base = _scrub_value({k: v for k, v in runtime_cfg.items() if k != "policy_packs"})
        if isinstance(base, Mapping):
            rt_out.update(base)
        packs = [
            {
                "id": str(e.get("id") or ""), "enabled": bool(e.get("enabled", True)), "kind": str(e.get("kind") or "security"),
                "scopes": list(e.get("scopes") or ()), "tree_sha256": str(e.get("tree_sha256") or ""),
                "settings": _scrub_value(e.get("settings")) if isinstance(e.get("settings"), Mapping) else {},
            }
            for e in (runtime_cfg.get("policy_packs") or ()) if isinstance(e, Mapping)
        ]
        if packs:
            rt_out["policy_packs"] = sorted(packs, key=lambda item: item["id"])
    canonical = {"harness_id": str(harness_id or "").strip().lower() or "unknown", "runtime_cfg": rt_out, "hook_payload": _scrub_value(hook_payload) if isinstance(hook_payload, Mapping) else {}}
    return "sha256:" + hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def build_capability_attestation_key(
    harness_id: str, capability_id: str, *, harness_build_id: str = "unavailable",
    adapter_version: str = ADAPTER_CONTRACT_VERSION, hook_config_fingerprint: str,
) -> CapabilityAttestationKey:
    """Construct CapabilityAttestationKey without implying runtime verification."""
    return CapabilityAttestationKey(
        harness_id=_scrub_home_paths(str(harness_id or "").strip()) or "unknown",
        harness_build_id=_scrub_home_paths(str(harness_build_id or "").strip()) or "unavailable",
        adapter_version=str(adapter_version or "").strip() or ADAPTER_CONTRACT_VERSION,
        hook_config_fingerprint=str(hook_config_fingerprint or "").strip(),
        capability_id=str(capability_id or "").strip(),
    )


def _static_capability_ceiling(harness_id: str, capability_id: str) -> str:
    caps = HARNESS_OUTPUT_CAPABILITIES.get(harness_id)
    if caps is None:
        return "unsupported"
    flags = {
        "pre_tool_interception": True, "output_replacement": caps.can_replace_tool_output,
        "native_fail_closed": caps.has_native_fail_closed_hook, "content_verified_reads": caps.supports_content_verified_reads,
        "prompt_cache_telemetry": harness_id != "cursor",
    }
    return "harness_exposed" if flags.get(capability_id, False) else "unsupported"


def resolve_capability_requirement(
    key: CapabilityAttestationKey, *, claimed_level: str = "harness_exposed",
    runtime_probe_passed: bool = False, verification_evidence: str | None = None,
) -> CapabilityRequirementV1:
    """Resolve conservative CapabilityRequirementV1; key presence alone never upgrades to runtime_verified."""
    has_evidence = isinstance(verification_evidence, str) and bool(verification_evidence.strip())
    eff_claim = claimed_level if claimed_level in _CAPABILITY_RANK else "unsupported"
    ceiling = _static_capability_ceiling(key.harness_id, key.capability_id)
    if eff_claim == "runtime_verified" and bool(runtime_probe_passed) and has_evidence:
        evidence_level, runtime_verified = "runtime_verified", True
        source = _scrub_home_paths(verification_evidence.strip()) if verification_evidence is not None else "runtime_probe"
    else:
        capped_claim = "harness_exposed" if eff_claim == "runtime_verified" else eff_claim
        evidence_level = VALID_CAPABILITY_EVIDENCE_LEVELS[min(_CAPABILITY_RANK[capped_claim], _CAPABILITY_RANK[ceiling])]
        runtime_verified = False
        if eff_claim == "runtime_verified":
            source = f"downgraded_without_runtime_probe:{key.harness_id}:{evidence_level}"
        elif has_evidence and verification_evidence is not None:
            source = _scrub_home_paths(verification_evidence.strip())
        else:
            source = f"static_contract:{key.harness_id}:{evidence_level}"
    return CapabilityRequirementV1(
        capability_id=key.capability_id, evidence_level=evidence_level,
        attestation_key=asdict(key), verification_source=source, runtime_verified=runtime_verified,
    )


def _read_manifest_version(plugin_root: Path | None = None) -> str:
    root = Path(plugin_root) if plugin_root is not None else state_store.resolve_plugin_root()
    manifest = root / "plugin.json"
    if plugin_root is None and not manifest.is_file():
        manifest = Path(__file__).resolve().parent.parent / "plugin.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if isinstance(data, Mapping) and isinstance(data.get("version"), str) and data["version"].strip():
            return data["version"].strip()
    except (OSError, ValueError, TypeError):
        pass
    return "unavailable"


def collect_environment_metadata(
    harness_id: str, *, model_id: str, harness_build_id: str | None = None,
    runtime_cfg: Mapping[str, Any] | None = None, hook_payload: Mapping[str, Any] | None = None,
    runtime_verifications: Mapping[str, str] | None = None, plugin_root: Path | None = None,
) -> EvidenceEnvironmentMetadataV1:
    """Collect full EvidenceEnvironmentMetadataV1 with manifest context_guard_version and capability evidence."""
    clean_harness = _scrub_home_paths(str(harness_id or "").strip().lower()) or "unknown"
    clean_build = _scrub_home_paths(str(harness_build_id or "").strip()) or "unavailable"
    clean_model = _scrub_home_paths(str(model_id or "").strip()) or "unknown"
    fingerprint = compute_hook_config_fingerprint(clean_harness, runtime_cfg=runtime_cfg, hook_payload=hook_payload)
    verifications = runtime_verifications if isinstance(runtime_verifications, Mapping) else {}
    reqs: list[CapabilityRequirementV1] = []
    for cap_id in REQUIRED_EVIDENCE_CAPABILITIES:
        key = build_capability_attestation_key(clean_harness, cap_id, harness_build_id=clean_build, adapter_version=ADAPTER_CONTRACT_VERSION, hook_config_fingerprint=fingerprint)
        ev_str = verifications.get(cap_id)
        if isinstance(ev_str, str) and ev_str.strip():
            reqs.append(resolve_capability_requirement(key, claimed_level="runtime_verified", runtime_probe_passed=True, verification_evidence=ev_str.strip()))
        else:
            reqs.append(resolve_capability_requirement(key, claimed_level="harness_exposed"))
    return EvidenceEnvironmentMetadataV1(
        harness_id=clean_harness, harness_build_id=clean_build, adapter_version=ADAPTER_CONTRACT_VERSION,
        hook_config_fingerprint=fingerprint, context_guard_version=_read_manifest_version(plugin_root=plugin_root),
        model_id=clean_model, attestation_key_implies_runtime_verified=False, required_capabilities=reqs,
    )


def _cursor_error(error: str) -> dict[str, Any]:
    return {"ok": False, "harness_id": "cursor", "admitted": False, "comparisons_blocked": True, "cache_attribution_status": "excluded_missing_telemetry", "error": error}


def _run_cursor_conformance_in_dir(root: Path) -> dict[str, Any]:
    if spool_receipts.check_unsafe_link(root):
        return _cursor_error("unsafe_path")
    root.mkdir(parents=True, exist_ok=True)
    state_dir, spool_dir, cfg_path, sample_file = root / "state", root / "spool", root / "config.json", root / "sample.py"
    if _any_unsafe_link(state_dir, spool_dir, cfg_path, sample_file):
        return _cursor_error("unsafe_path")
    sample_lines = ("line_1 = 1", "line_2 = 2", "line_3 = 3")
    sample_text = "\n".join(sample_lines) + "\n"
    sample_file.write_text(sample_text, encoding="utf-8")
    cfg_path.write_text("{}", encoding="utf-8")
    norm_shell = harness_adapter.normalize_pre_tool_payload({"session_id": "cu-conf", "call_id": "cu-sh-1", "tool_name": "Shell", "tool_input": {"command": "pytest -q"}, "cwd": str(root)}, cli_harness="cursor")
    norm_read = harness_adapter.normalize_pre_tool_payload({"session_id": "cu-conf", "call_id": "cu-rd-1", "tool_name": "Read", "tool_input": {"file_path": str(sample_file), "offset": 1, "limit": 3}, "cwd": str(root)}, cli_harness="cursor")
    norm_mcp = harness_adapter.normalize_pre_tool_payload({"session_id": "cu-conf", "call_id": "cu-mcp-1", "tool_name": "MCP:acme_srv:list_items", "tool_input": {"limit": 10}, "cwd": str(root)}, cli_harness="cursor")
    deny_out = harness_adapter.format_pre_tool_output({"decision": "deny", "reason": "conformance_block"}, norm_shell)
    deny_hso = deny_out.get("hookSpecificOutput") if isinstance(deny_out, Mapping) else None
    file_sha = file_io.compute_file_sha256(str(sample_file)) or ""
    norm_sha = hashlib.sha256("\n".join(sample_lines).encode("utf-8")).hexdigest()
    canon_sample = os.path.realpath(str(sample_file))
    with state_store.locked_state(state_dir) as txn:
        txn.state.setdefault("files", {})[canon_sample] = {
            "sha256": file_sha, "reads": [],
            "pending_reads": {"cu-rd-1": {"exec_start": 1, "delivered_end": 3, "slice_bytes": len(sample_text.encode("utf-8")), "byte_offset": 0, "step": 1, "sha256": file_sha, "expected_norm_sha256": norm_sha, "is_trim": False, "synthetic_id": False}},
        }
        txn.dirty = True
    saved_env = {k: os.environ.get(k) for k in ("CONTEXT_GUARD_CONFIG_PATH", "CONTEXT_GUARD_SPOOL_DIR")}
    try:
        os.environ["CONTEXT_GUARD_CONFIG_PATH"], os.environ["CONTEXT_GUARD_SPOOL_DIR"] = str(cfg_path), str(spool_dir)
        post_tool_use.handle_post_tool_use("cursor", {"session_id": "cu-conf", "call_id": "cu-rd-1", "tool_name": "Read", "tool_input": {"file_path": str(sample_file), "offset": 1, "limit": 3}, "tool_output": sample_text, "cwd": str(root)}, stats_path=root / "telemetry_stats.json", state_dir=state_dir)
    finally:
        for k, v in saved_env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    confirmed_reads = ((state_store.read_state_snapshot(state_dir).get("files") or {}).get(canon_sample) or {}).get("reads") or []
    caps, runtime_caps = HARNESS_OUTPUT_CAPABILITIES.get("cursor"), harness_adapter.probe_runtime_capabilities("cursor")
    fingerprint = compute_hook_config_fingerprint("cursor", runtime_cfg={}, hook_payload={"hooks": {"preToolUse": [{"command": "python3 hooks/pre_tool_use.py --harness cursor", "matcher": "Shell|Read", "failClosed": True}]}})
    checks = {
        "normalize_shell": norm_shell.harness == "cursor" and norm_shell.canonical_tool == "run_command",
        "normalize_read": norm_read.harness == "cursor" and norm_read.canonical_tool == "read_file",
        "normalize_mcp": norm_mcp.harness == "cursor" and norm_mcp.canonical_tool == "MCP:acme_srv:list_items",
        "format_deny": isinstance(deny_hso, Mapping) and deny_hso.get("permissionDecision") == "deny" and deny_hso.get("permissionDecisionReason") == "conformance_block",
        "post_tool_read_tier2": [1, 3, 1, 2] in confirmed_reads,
        "supports_content_verified_reads": bool(caps is not None and caps.supports_content_verified_reads and runtime_caps.content_verified_reads_supported),
        "hook_config_fingerprint": fingerprint.startswith("sha256:") and len(fingerprint) == 71,
    }
    all_passed = all(checks.values())
    return {
        "ok": all_passed, "harness_id": "cursor", "admitted": all_passed, "comparisons_blocked": not all_passed,
        "cache_attribution_status": "excluded_missing_telemetry", "hook_config_fingerprint": fingerprint,
        "harness_output_capabilities": {
            "can_replace_tool_output": bool(caps.can_replace_tool_output) if caps is not None else False,
            "has_native_fail_closed_hook": bool(caps.has_native_fail_closed_hook) if caps is not None else False,
            "supports_apply_patch_block": bool(caps.supports_apply_patch_block) if caps is not None else False,
            "supports_content_verified_reads": bool(caps.supports_content_verified_reads) if caps is not None else False,
        },
        "checks": checks,
    }


def run_cursor_cli_conformance(work_dir: Path | None = None) -> dict[str, Any]:
    """Run isolated Cursor CLI hook conformance tests and confirm missing cache telemetry handling."""
    if work_dir is not None:
        return _run_cursor_conformance_in_dir(Path(work_dir))
    with tempfile.TemporaryDirectory(prefix="cg_cursor_conf_") as td:
        return _run_cursor_conformance_in_dir(Path(td))
