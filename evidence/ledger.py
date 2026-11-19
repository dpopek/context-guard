"""Durable deduplicated ContextReceiptV1 event ledger, capability evidence, and Cursor conformance gate."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib, json, os, stat, tempfile
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from core.platform_io import read_plugin_version, utc_now_iso_z
from core.scrub import scrub_home_paths, scrub_value
from hooks import config as hooks_config, file_io, harness_adapter, outcomes, post_tool_use, state_store
from policies import governor as policies_governor
from policies.api import (
    ADAPTER_CONTRACT_VERSION, CapabilityAttestationKey, CapabilityRequirementV1, CircuitBreakerStateV1,
    EvidenceEnvironmentMetadataV1, GOVERNOR_SCHEMA_VERSION, HARNESS_OUTPUT_CAPABILITIES,
    NON_TRIPPING_SIGNALS, RECEIPT_SCHEMA_VERSION, VALID_CAPABILITY_EVIDENCE_LEVELS, VALID_TURN_CORRELATIONS,
)
from spool import receipts as spool_receipts

EVENT_LEDGER_SCHEMA_VERSION: int = 1
DEFAULT_EVENT_LEDGER_FILENAME: str = "evidence_events.json"
REQUIRED_EVIDENCE_CAPABILITIES: tuple[str, ...] = (
    "pre_tool_interception", "output_replacement", "native_fail_closed",
    "content_verified_reads", "prompt_cache_telemetry",
)

_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
_CAPABILITY_RANK = {level: idx for idx, level in enumerate(VALID_CAPABILITY_EVIDENCE_LEVELS)}

__all__ = [
    "DEFAULT_EVENT_LEDGER_FILENAME", "EVENT_LEDGER_SCHEMA_VERSION", "REQUIRED_EVIDENCE_CAPABILITIES",
    "append_durable_events", "build_capability_attestation_key", "collect_environment_metadata",
    "compute_hook_config_fingerprint", "derive_outcomes_from_ledger", "ingest_context_receipts",
    "resolve_capability_requirement", "run_cursor_cli_conformance", "run_governor_release_gates",
]


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
    scrubbed = scrub_value(raw)
    return dict(scrubbed) if isinstance(scrubbed, Mapping) and _is_nonempty_baseline(scrubbed) else None


def _empty_ledger_doc() -> dict[str, Any]:
    return {
        "schema_version": EVENT_LEDGER_SCHEMA_VERSION, "updated_at": utc_now_iso_z(),
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
            doc["corrupt_source_lines"], doc["updated_at"] = new_corrupt, utc_now_iso_z()
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
            except ValueError:
                corrupt_lines += 1
                continue
            if not isinstance(obj, dict):
                corrupt_lines += 1
            elif obj.get("_meta") != "receipts_rotation":
                parsed_events.append(obj)
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
        base = scrub_value({k: v for k, v in runtime_cfg.items() if k != "policy_packs"})
        if isinstance(base, Mapping):
            rt_out.update(base)
        packs = [
            {
                "id": str(e.get("id") or ""), "enabled": bool(e.get("enabled", True)), "kind": str(e.get("kind") or "security"),
                "scopes": list(e.get("scopes") or ()), "tree_sha256": str(e.get("tree_sha256") or ""),
                "settings": scrub_value(e.get("settings")) if isinstance(e.get("settings"), Mapping) else {},
            }
            for e in (runtime_cfg.get("policy_packs") or ()) if isinstance(e, Mapping)
        ]
        if packs:
            rt_out["policy_packs"] = sorted(packs, key=lambda item: item["id"])
    canonical = {
        "harness_id": str(harness_id or "").strip().lower() or "unknown",
        "runtime_cfg": rt_out,
        "hook_payload": scrub_value(hook_payload) if isinstance(hook_payload, Mapping) else {},
    }
    return "sha256:" + hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def build_capability_attestation_key(
    harness_id: str, capability_id: str, *, harness_build_id: str = "unavailable",
    adapter_version: str = ADAPTER_CONTRACT_VERSION, hook_config_fingerprint: str,
) -> CapabilityAttestationKey:
    """Construct CapabilityAttestationKey without implying runtime verification."""
    return CapabilityAttestationKey(
        harness_id=scrub_home_paths(str(harness_id or "").strip()) or "unknown",
        harness_build_id=scrub_home_paths(str(harness_build_id or "").strip()) or "unavailable",
        adapter_version=str(adapter_version or "").strip() or ADAPTER_CONTRACT_VERSION,
        hook_config_fingerprint=str(hook_config_fingerprint or "").strip(),
        capability_id=str(capability_id or "").strip(),
    )


def _static_capability_ceiling(harness_id: str, capability_id: str) -> str:
    clean_harness = str(harness_id or "").strip().lower()
    caps = HARNESS_OUTPUT_CAPABILITIES.get(clean_harness)
    if caps is None:
        return "unsupported"
    flags = {
        "pre_tool_interception": True, "output_replacement": caps.can_replace_tool_output,
        "native_fail_closed": caps.has_native_fail_closed_hook, "content_verified_reads": caps.supports_content_verified_reads,
        "prompt_cache_telemetry": clean_harness != "cursor",
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
    if ceiling == "unsupported":
        source = (
            scrub_home_paths(verification_evidence.strip())
            if (eff_claim != "runtime_verified" and has_evidence and verification_evidence is not None)
            else f"static_contract:{key.harness_id}:unsupported"
        )
        return CapabilityRequirementV1(
            capability_id=key.capability_id,
            evidence_level="unsupported",
            attestation_key=asdict(key),
            verification_source=source,
            runtime_verified=False,
        )
    if eff_claim == "provider_supported" or policies_governor.is_provider_only_evidence(verification_evidence):
        ev_label = (
            scrub_home_paths(verification_evidence.strip())
            if (has_evidence and verification_evidence is not None)
            else "provider_supported"
        )
        return CapabilityRequirementV1(
            capability_id=key.capability_id,
            evidence_level="provider_supported",
            attestation_key=asdict(key),
            verification_source=f"provider_only_rejected:{key.harness_id}:{ev_label}",
            runtime_verified=False,
        )
    if eff_claim == "runtime_verified" and bool(runtime_probe_passed) and has_evidence:
        evidence_level, runtime_verified = "runtime_verified", True
        source = scrub_home_paths(verification_evidence.strip()) if verification_evidence is not None else "runtime_probe"
    else:
        capped_claim = "harness_exposed" if eff_claim == "runtime_verified" else eff_claim
        evidence_level = VALID_CAPABILITY_EVIDENCE_LEVELS[min(_CAPABILITY_RANK[capped_claim], _CAPABILITY_RANK[ceiling])]
        runtime_verified = False
        if eff_claim == "runtime_verified":
            source = f"downgraded_without_runtime_probe:{key.harness_id}:{evidence_level}"
        elif has_evidence and verification_evidence is not None:
            source = scrub_home_paths(verification_evidence.strip())
        else:
            source = f"static_contract:{key.harness_id}:{evidence_level}"
    return CapabilityRequirementV1(
        capability_id=key.capability_id, evidence_level=evidence_level,
        attestation_key=asdict(key), verification_source=source, runtime_verified=runtime_verified,
    )


def collect_environment_metadata(
    harness_id: str, *, model_id: str, harness_build_id: str | None = None,
    runtime_cfg: Mapping[str, Any] | None = None, hook_payload: Mapping[str, Any] | None = None,
    runtime_verifications: Mapping[str, str] | None = None, plugin_root: Path | None = None,
) -> EvidenceEnvironmentMetadataV1:
    """Collect full EvidenceEnvironmentMetadataV1 with manifest context_guard_version and capability evidence."""
    clean_harness = scrub_home_paths(str(harness_id or "").strip().lower()) or "unknown"
    clean_build = scrub_home_paths(str(harness_build_id or "").strip()) or "unavailable"
    clean_model = scrub_home_paths(str(model_id or "").strip()) or "unknown"
    fingerprint = compute_hook_config_fingerprint(clean_harness, runtime_cfg=runtime_cfg, hook_payload=hook_payload)
    verifications = runtime_verifications if isinstance(runtime_verifications, Mapping) else {}
    reqs: list[CapabilityRequirementV1] = []
    for cap_id in REQUIRED_EVIDENCE_CAPABILITIES:
        key = build_capability_attestation_key(clean_harness, cap_id, harness_build_id=clean_build, adapter_version=ADAPTER_CONTRACT_VERSION, hook_config_fingerprint=fingerprint)
        ev_str = verifications.get(cap_id)
        if isinstance(ev_str, str) and policies_governor.is_provider_only_evidence(ev_str):
            reqs.append(resolve_capability_requirement(key, claimed_level="provider_supported", runtime_probe_passed=False, verification_evidence=ev_str.strip()))
        elif isinstance(ev_str, str) and ev_str.strip():
            reqs.append(resolve_capability_requirement(key, claimed_level="runtime_verified", runtime_probe_passed=True, verification_evidence=ev_str.strip()))
        else:
            reqs.append(resolve_capability_requirement(key, claimed_level="harness_exposed"))
    return EvidenceEnvironmentMetadataV1(
        harness_id=clean_harness, harness_build_id=clean_build, adapter_version=ADAPTER_CONTRACT_VERSION,
        hook_config_fingerprint=fingerprint, context_guard_version=read_plugin_version(plugin_root=plugin_root),
        model_id=clean_model, attestation_key_implies_runtime_verified=False, required_capabilities=reqs,
    )


def _cursor_error(error: str) -> dict[str, Any]:
    return {
        "ok": False, "harness_id": "cursor", "admitted": False, "comparisons_blocked": True,
        "cache_attribution_status": "excluded_missing_telemetry", "verification_scope": "adapter_contract_only",
        "adapter_conformance_passed": False, "live_client_executed": False, "runtime_verified": False, "error": error,
    }


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
    norm_shell = harness_adapter.normalize_pre_tool_payload(
        {"session_id": "cu-conf", "call_id": "cu-sh-1", "tool_name": "Shell", "tool_input": {"command": "pytest -q"}, "cwd": str(root)},
        cli_harness="cursor",
    )
    norm_read = harness_adapter.normalize_pre_tool_payload(
        {"session_id": "cu-conf", "call_id": "cu-rd-1", "tool_name": "Read", "tool_input": {"file_path": str(sample_file), "offset": 1, "limit": 3}, "cwd": str(root)},
        cli_harness="cursor",
    )
    norm_mcp = harness_adapter.normalize_pre_tool_payload(
        {"session_id": "cu-conf", "call_id": "cu-mcp-1", "tool_name": "MCP:acme_srv:list_items", "tool_input": {"limit": 10}, "cwd": str(root)},
        cli_harness="cursor",
    )
    deny_out = harness_adapter.format_pre_tool_output({"decision": "deny", "reason": "conformance_block"}, norm_shell)
    deny_hso = deny_out.get("hookSpecificOutput") if isinstance(deny_out, Mapping) else None
    file_sha = file_io.compute_file_sha256(str(sample_file)) or ""
    norm_sha = hashlib.sha256("\n".join(sample_lines).encode("utf-8")).hexdigest()
    canon_sample = os.path.realpath(str(sample_file))
    with state_store.locked_state(state_dir) as txn:
        txn.state.setdefault("files", {})[canon_sample] = {
            "sha256": file_sha,
            "reads": [],
            "pending_reads": {
                "cu-rd-1": {
                    "exec_start": 1, "delivered_end": 3, "slice_bytes": len(sample_text.encode("utf-8")),
                    "byte_offset": 0, "step": 1, "sha256": file_sha, "expected_norm_sha256": norm_sha,
                    "is_trim": False, "synthetic_id": False,
                },
            },
        }
        txn.dirty = True
    saved_env = {k: os.environ.get(k) for k in ("CONTEXT_GUARD_CONFIG_PATH", "CONTEXT_GUARD_SPOOL_DIR")}
    try:
        os.environ["CONTEXT_GUARD_CONFIG_PATH"], os.environ["CONTEXT_GUARD_SPOOL_DIR"] = str(cfg_path), str(spool_dir)
        hooks_config.clear_config_cache()
        post_tool_use.handle_post_tool_use(
            "cursor",
            {
                "session_id": "cu-conf", "call_id": "cu-rd-1", "tool_name": "Read",
                "tool_input": {"file_path": str(sample_file), "offset": 1, "limit": 3},
                "tool_output": sample_text, "cwd": str(root),
            },
            stats_path=root / "telemetry_stats.json",
            state_dir=state_dir,
        )
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        hooks_config.clear_config_cache()
    confirmed_reads = ((state_store.read_state_snapshot(state_dir).get("files") or {}).get(canon_sample) or {}).get("reads") or []
    caps, runtime_caps = HARNESS_OUTPUT_CAPABILITIES.get("cursor"), harness_adapter.probe_runtime_capabilities("cursor")
    fingerprint = compute_hook_config_fingerprint(
        "cursor",
        runtime_cfg={},
        hook_payload={"hooks": {"preToolUse": [{"command": "python3 hooks/pre_tool_use.py --harness cursor", "matcher": "Shell|Read", "failClosed": True}]}},
    )
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
        "cache_attribution_status": "excluded_missing_telemetry", "verification_scope": "adapter_contract_only",
        "adapter_conformance_passed": all_passed, "live_client_executed": False, "runtime_verified": False,
        "hook_config_fingerprint": fingerprint,
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


def _run_builtin_release_gates() -> tuple[dict[str, bool], list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="cg_gov_replay_") as td:
        root = Path(td)
        static_cfg: dict[str, Any] = {
            "read_confirm_policy": "bounded", "policy_packs": [], "legacy_security_keys": (),
            "optimizers": {"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "off"},
        }
        parity_out = policies_governor.apply_runtime_governor(static_cfg, "antigravity", state_dir=root / "empty", payload={"tool_name": "view_file"})
        g_parity = parity_out == static_cfg and parity_out["optimizers"] == static_cfg["optimizers"]

        d_prov = root / "prov"
        c_prov = policies_governor.evaluate_capability_contract(
            policies_governor.build_capability_attestation_key("claude", "dynamic_tool_mutation", hook_config_fingerprint="sha256:" + "0" * 64),
            claimed_level="provider_supported", verification_evidence="provider_api:tool_search",
        )
        att_prov = policies_governor.attest_capability("claude", "dynamic_tool_mutation", verification_evidence="model_api:tools", state_dir=d_prov)
        gov_prov = policies_governor.evaluate_governor("claude", runtime_cfg={"optimizers": {"dynamic_tool_mutation": "active", "output_spool": "active"}}, state_dir=d_prov)
        g_provider = bool(
            c_prov["provider_only_rejected"] and not c_prov["runtime_verified"]
            and att_prov["provider_only_rejected"] and not att_prov["runtime_verified"]
            and gov_prov["decisions"]["dynamic_tool_mutation"]["selected_mode"] != "active"
        )

        d_upg = root / "upg"
        policies_governor.attest_capability("claude", "output_replacement", verification_evidence="client_spool_ok", harness_build_id="1.0.0", adapter_version="harness_adapter_v1", state_dir=d_upg)
        ok_b1 = policies_governor.evaluate_governor("claude", harness_build_id="1.0.0", state_dir=d_upg)["capabilities"]["output_replacement"]["runtime_verified"]
        inv_b2 = policies_governor.evaluate_governor("claude", harness_build_id="2.0.0", state_dir=d_upg)["capabilities"]["output_replacement"]
        inv_ad = policies_governor.evaluate_governor("claude", harness_build_id="1.0.0", adapter_version="harness_adapter_v2", state_dir=d_upg)["capabilities"]["output_replacement"]
        g_upgrade = bool(
            ok_b1 and not inv_b2["runtime_verified"] and inv_b2["invalidated_reason"] == "build_changed"
            and not inv_ad["runtime_verified"] and inv_ad["invalidated_reason"] == "adapter_changed"
        )

        d_cfg, cfg_a = root / "cfg", {"optimizers": {"output_spool": "active"}}
        cfg_b = {"optimizers": {"output_spool": "active"}, "read_confirm_policy": "bounded"}
        policies_governor.attest_capability("claude", "output_replacement", verification_evidence="client_spool_ok", runtime_cfg=cfg_a, state_dir=d_cfg)
        inv_cfg = policies_governor.evaluate_governor("claude", runtime_cfg=cfg_b, state_dir=d_cfg)["capabilities"]["output_replacement"]
        inv_unk = policies_governor.evaluate_governor("claude", runtime_cfg=cfg_a, state_dir=d_cfg, payload_known=False)
        g_config = bool(
            not inv_cfg["runtime_verified"] and inv_cfg["invalidated_reason"] == "config_fingerprint_changed"
            and inv_unk["capabilities"]["output_replacement"]["invalidated_reason"] == "unknown_payload"
            and inv_unk["decisions"]["output_spool"]["selected_mode"] == "passthrough"
        )

        d_brk = root / "brk"
        soft_st: CircuitBreakerStateV1 | None = None
        for sig in NON_TRIPPING_SIGNALS:
            soft_st = policies_governor.record_governor_signal("output_spool", sig, state_dir=d_brk)
        hard_st = policies_governor.record_governor_signal("output_spool", "integrity_mismatch", state_dir=d_brk)
        g_breaker = bool(
            soft_st is not None and soft_st["ignored_signals"] == len(NON_TRIPPING_SIGNALS) and not soft_st["tripped"]
            and policies_governor.is_optimizer_tripped("output_spool", state_dir=d_brk) and hard_st["tripped"] and hard_st["state"] == "open"
        )

        bad_r = policies_governor.reset_circuit_breaker("output_spool", state_dir=d_brk)
        empty_r = policies_governor.reset_circuit_breaker("output_spool", state_dir=d_brk, verification_passed=True, verification_evidence="   ")
        still_open = policies_governor.is_optimizer_tripped("output_spool", state_dir=d_brk)
        good_r = policies_governor.reset_circuit_breaker("output_spool", state_dir=d_brk, verification_passed=True, verification_evidence="spool_verified")
        g_hysteresis = bool(
            not bad_r["ok"] and bad_r["error"] == "hysteresis_requires_verification_or_operator_reset"
            and not empty_r["ok"] and still_open and good_r["ok"] and not policies_governor.is_optimizer_tripped("output_spool", state_dir=d_brk)
        )

        sec_cfg: dict[str, Any] = {
            "policy_packs": [{"id": "sec_guard", "enabled": True, "kind": "security", "scopes": ["shell_command"]}],
            "legacy_security_keys": ("restricted_bq_datasets",),
            "optimizers": {"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "active"},
        }
        policies_governor.record_governor_signal("output_spool", "guarantee_loss", state_dir=d_brk)
        bad_payload: Any = "unknown"
        sec_out = policies_governor.apply_runtime_governor(sec_cfg, "antigravity", state_dir=d_brk, payload=bad_payload)
        sec_eval = policies_governor.evaluate_governor("antigravity", runtime_cfg=sec_cfg, state_dir=d_brk, payload_known=False)
        g_security = bool(
            not sec_eval["security_enforcement_lowered"] and sec_out["policy_packs"] == sec_cfg["policy_packs"]
            and sec_out["legacy_security_keys"] == sec_cfg["legacy_security_keys"]
            and all(v == "off" for v in sec_out["optimizers"].values())
        )

        ev_fail = policies_governor.evaluate_governor(
            "claude", runtime_cfg={"optimizers": {"output_spool": "active"}},
            evidence_gate_required=True, evidence_report={"gate_verdict": {"ok": False}}, state_dir=root / "ev",
        )
        ev_pass = policies_governor.evaluate_governor(
            "claude", runtime_cfg={"optimizers": {"output_spool": "active"}},
            evidence_gate_required=True, evidence_report={"gate_verdict": {"ok": True}}, state_dir=root / "ev",
        )
        g_evidence = bool(
            not ev_fail["evidence_gate_passed"] and ev_fail["decisions"]["output_spool"]["selected_mode"] == "shadow"
            and ev_fail["decisions"]["output_spool"]["reason"] == "evidence_gate_not_passed"
            and ev_pass["evidence_gate_passed"] and ev_pass["decisions"]["output_spool"]["selected_mode"] == "active"
        )

    gates = {
        "static_config_parity": g_parity, "provider_only_rejected": g_provider,
        "harness_upgrade_invalidation": g_upgrade, "config_change_invalidation": g_config,
        "breaker_trips_only_on_hard_failures": g_breaker, "hysteresis_enforced": g_hysteresis,
        "security_never_lowered": g_security, "evidence_gate_enforced": g_evidence,
    }
    return gates, [{"id": name, "gate": name, "passed": passed} for name, passed in gates.items()]


def run_governor_release_gates(scenarios: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Deterministically verify all 8 Governor release gates (and optional custom scenarios) in isolation."""
    gates, results = _run_builtin_release_gates()
    custom_ok = True
    if scenarios is not None:
        with tempfile.TemporaryDirectory(prefix="cg_gov_custom_") as td:
            for idx, raw in enumerate(scenarios):
                if not isinstance(raw, Mapping):
                    custom_ok = False
                    results.append({"id": f"custom_{idx}", "gate": "custom", "passed": False})
                    continue
                raw_cfg, raw_rep = raw.get("runtime_cfg"), raw.get("evidence_report")
                res = policies_governor.evaluate_governor(
                    str(raw.get("harness_id") or "claude"),
                    runtime_cfg=raw_cfg if isinstance(raw_cfg, Mapping) else None,
                    state_dir=Path(td) / f"s_{idx}",
                    harness_build_id=str(raw.get("harness_build_id") or "unavailable"),
                    adapter_version=str(raw.get("adapter_version") or ADAPTER_CONTRACT_VERSION),
                    payload_known=bool(raw.get("payload_known", True)),
                    require_runtime_verified=bool(raw.get("require_runtime_verified", False)),
                    evidence_report=raw_rep if isinstance(raw_rep, Mapping) else None,
                    evidence_gate_required=bool(raw.get("evidence_gate_required", False)),
                )
                exp_modes, passed = raw.get("expected_modes"), not res["security_enforcement_lowered"]
                if isinstance(exp_modes, Mapping):
                    passed = passed and all(
                        opt in res["decisions"] and res["decisions"][opt]["selected_mode"] == mode
                        for opt, mode in exp_modes.items()
                    )
                custom_ok = custom_ok and passed
                results.append({"id": str(raw.get("id") or f"custom_{idx}"), "gate": "custom", "passed": passed})
    passed_count = sum(1 for v in gates.values() if v)
    return {
        "schema_version": GOVERNOR_SCHEMA_VERSION, "ok": bool(passed_count == 8 and custom_ok),
        "checks_passed": passed_count, "checks_total": 8, "gates": gates, "scenarios": results,
    }
