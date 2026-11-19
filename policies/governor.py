"""Capability-Aware Adaptive Governor, attestation validation, and hysteresis circuit breakers."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import hashlib, json, os, stat
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, TypeVar

from core.platform_io import (
    LOCK_EX, LOCK_UN, atomic_write_bytes, check_unsafe_link, flock, resolve_plugin_root, utc_now_iso_z, warn,
)
from core.scrub import scrub_home_paths, scrub_value
from policies.api import (
    ADAPTER_CONTRACT_VERSION, CAPABILITY_CONTRACT_SCHEMA_VERSION, GOVERNOR_SCHEMA_VERSION,
    HARD_INTEGRITY_FAILURE_REASONS, HARNESS_OUTPUT_CAPABILITIES,
    VALID_CAPABILITY_EVIDENCE_LEVELS, CapabilityAttestationKey, CapabilityContractV1,
    CircuitBreakerStateV1, GovernorContractV1, OptimizerDecisionV1,
)

DEFAULT_GOVERNOR_STATE_FILENAME: str = "governor_state.json"
GOVERNED_OPTIMIZERS: tuple[str, ...] = ("range_trim", "auto_outline", "cli_rewrites", "output_spool")
GOVERNED_CAPABILITIES: tuple[str, ...] = (
    "pre_tool_interception", "output_replacement", "native_fail_closed",
    "content_verified_reads", "prompt_cache_telemetry", "dynamic_tool_mutation",
)
OPTIMIZER_REQUIRED_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "range_trim": ("pre_tool_interception", "content_verified_reads"),
    "auto_outline": ("pre_tool_interception",),
    "cli_rewrites": ("pre_tool_interception",),
    "output_spool": ("pre_tool_interception", "output_replacement"),
    "dynamic_tool_mutation": ("dynamic_tool_mutation",),
}

_T = TypeVar("_T")
_LOCK_FILENAME = "governor_state.lock"
_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
_PROVIDER_PREFIXES = ("model_api:", "provider_api:", "upstream_provider:")
_CAP_RANK = {lvl: idx for idx, lvl in enumerate(VALID_CAPABILITY_EVIDENCE_LEVELS)}
_HARD_REASONS = frozenset(HARD_INTEGRITY_FAILURE_REASONS)
_DEFAULT_MODES: dict[str, str] = {
    "range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "off",
}
_KNOWN_HOOK_EVENTS = frozenset({
    "PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch",
    "PreCompact", "SessionEnd", "PreInvocation",
    "preToolUse", "postToolUse", "postToolUseFailure", "preCompact", "sessionEnd",
})

__all__ = [
    "DEFAULT_GOVERNOR_STATE_FILENAME", "GOVERNED_CAPABILITIES", "GOVERNED_OPTIMIZERS",
    "OPTIMIZER_REQUIRED_CAPABILITIES", "apply_runtime_governor", "attest_capability",
    "build_capability_attestation_key", "compute_hook_config_fingerprint",
    "evaluate_capability_contract", "evaluate_governor", "is_optimizer_tripped",
    "is_provider_only_evidence", "record_governor_signal", "reset_circuit_breaker",
    "resolve_governor_state_path",
]


def _norm_harness(harness_id: str | None) -> str:
    return scrub_home_paths(str(harness_id or "").strip().lower()) or "unknown"


def is_provider_only_evidence(evidence: str | None) -> bool:
    """Return True when evidence references only an upstream model or provider API."""
    return isinstance(evidence, str) and evidence.strip().lower().startswith(_PROVIDER_PREFIXES)


def _clean_evidence(raw: Any) -> str | None:
    if isinstance(raw, str):
        stripped = raw.strip()
        if stripped:
            return scrub_home_paths(stripped)
    return None


def _static_ceiling(harness_id: str, capability_id: str) -> str:
    caps = HARNESS_OUTPUT_CAPABILITIES.get(harness_id)
    if caps is None:
        return "unsupported"
    flags = {
        "pre_tool_interception": True, "output_replacement": caps.can_replace_tool_output,
        "native_fail_closed": caps.has_native_fail_closed_hook,
        "content_verified_reads": caps.supports_content_verified_reads, "prompt_cache_telemetry": harness_id != "cursor",
    }
    return "harness_exposed" if flags.get(capability_id, False) else "unsupported"


def _supports_runtime_attestation(key: CapabilityAttestationKey, ceiling: str) -> bool:
    if ceiling != "unsupported":
        return True
    # Dynamic tool mutation has no static exposure level, yet is client-attestable on known harnesses.
    return key.capability_id == "dynamic_tool_mutation" and key.harness_id in HARNESS_OUTPUT_CAPABILITIES


def _make_breaker(
    opt_id: str, *, state: str = "closed", tripped: bool = False, trip_reason: str | None = None,
    trip_count: int = 0, tripped_at: str | None = None, last_verified_at: str | None = None,
    ignored_signals: int = 0, req_reset: bool = False,
) -> CircuitBreakerStateV1:
    return CircuitBreakerStateV1(
        optimizer_id=opt_id, state=state, tripped=tripped, trip_reason=trip_reason,
        trip_count=trip_count, tripped_at=tripped_at, last_verified_at=last_verified_at,
        ignored_signals=ignored_signals, requires_verification_or_operator_reset=req_reset,
    )


def _normalize_breaker(optimizer_id: str, raw: Mapping[str, Any] | None) -> CircuitBreakerStateV1:
    if not isinstance(raw, Mapping):
        return _make_breaker(optimizer_id)
    tripped = bool(raw.get("tripped")) or str(raw.get("state") or "closed") == "open"
    state = "open" if tripped else ("half_open" if raw.get("state") == "half_open" else "closed")
    tc, ig, raw_reason = raw.get("trip_count"), raw.get("ignored_signals"), raw.get("trip_reason")
    trip_reason = str(raw_reason) if tripped and isinstance(raw_reason, str) and raw_reason else None
    trip_count = int(tc) if isinstance(tc, int) and not isinstance(tc, bool) and tc >= 0 else (1 if tripped else 0)
    tripped_at = str(raw["tripped_at"]) if tripped and isinstance(raw.get("tripped_at"), str) else None
    last_ver = str(raw["last_verified_at"]) if isinstance(raw.get("last_verified_at"), str) else None
    ignored = int(ig) if isinstance(ig, int) and not isinstance(ig, bool) and ig >= 0 else 0
    return _make_breaker(
        optimizer_id, state=state, tripped=tripped, trip_reason=trip_reason, trip_count=trip_count,
        tripped_at=tripped_at, last_verified_at=last_ver, ignored_signals=ignored,
        req_reset=bool(raw.get("requires_verification_or_operator_reset")) or tripped,
    )


def _empty_state_doc() -> dict[str, Any]:
    return {"schema_version": GOVERNOR_SCHEMA_VERSION, "attestations": {}, "circuit_breakers": {}}


def _normalize_state_dir(raw: str | Path) -> Path:
    path = Path(str(raw).strip()).expanduser()
    return path.parent if (path.name == "spool" and path.parent != path) else path


def resolve_governor_state_path(state_dir: str | Path | None = None) -> Path:
    """Resolve the single canonical `governor_state.json`, normalizing trailing `spool` to its parent."""
    if state_dir is not None and str(state_dir).strip():
        return _normalize_state_dir(state_dir) / DEFAULT_GOVERNOR_STATE_FILENAME
    if (env_state := str(os.environ.get("CONTEXT_GUARD_STATE_DIR") or "").strip()):
        return _normalize_state_dir(env_state) / DEFAULT_GOVERNOR_STATE_FILENAME
    return resolve_plugin_root() / "telemetry" / DEFAULT_GOVERNOR_STATE_FILENAME


def _path_absent(path: Path) -> bool:
    try:
        os.lstat(str(path))
        return False
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _has_unsafe_links(state_file: Path) -> bool:
    return (
        check_unsafe_link(state_file.parent)
        or check_unsafe_link(state_file)
        or check_unsafe_link(state_file.parent / _LOCK_FILENAME)
    )


def _open_fd_stream(path: Path, flags: int, mode_str: str, perms: int = 0o600) -> Any:
    fd = os.open(str(path), flags, perms)
    try:
        return os.fdopen(fd, mode_str, encoding="utf-8" if "b" not in mode_str else None)
    except BaseException:
        os.close(fd)
        raise


def _read_state_file_safe(state_file: Path) -> tuple[dict[str, Any], str | None, str | None]:
    if _has_unsafe_links(state_file):
        return _empty_state_doc(), "unsafe_path", f"unsafe link rejected for governor state {state_file}"
    try:
        fh = _open_fd_stream(state_file, os.O_RDONLY | _O_FLAGS, "rb")
    except FileNotFoundError:
        return _empty_state_doc(), None, None
    except OSError as exc:
        return _empty_state_doc(), "corrupt", f"unreadable governor state {state_file}: {type(exc).__name__}"
    try:
        with fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return _empty_state_doc(), "unsafe_path", f"non-regular governor state rejected: {state_file}"
            parsed = json.loads(fh.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
        return _empty_state_doc(), "corrupt", f"corrupt governor_state.json at {state_file}: {type(exc).__name__}"
    if not isinstance(parsed, dict):
        return _empty_state_doc(), "corrupt", f"invalid governor_state.json root at {state_file}"
    atts, cbs = parsed.get("attestations"), parsed.get("circuit_breakers")
    return {
        "schema_version": GOVERNOR_SCHEMA_VERSION,
        "attestations": dict(atts) if isinstance(atts, Mapping) else {},
        "circuit_breakers": dict(cbs) if isinstance(cbs, Mapping) else {},
    }, None, None


@contextmanager
def _governor_lock(state_dir_path: Path) -> Iterator[None]:
    lp = state_dir_path / _LOCK_FILENAME
    if check_unsafe_link(lp):
        raise OSError("unsafe_path: governor_state.lock")
    with _open_fd_stream(lp, os.O_RDWR | os.O_CREAT | _O_FLAGS, "a+") as fh:
        if os.name != "nt":
            os.chmod(str(lp), 0o600)
        flock(fh.fileno(), LOCK_EX)
        try:
            yield
        finally:
            flock(fh.fileno(), LOCK_UN)


def _mutate_state_file(state_file: Path, mutator: Callable[[dict[str, Any]], _T]) -> tuple[_T | None, str | None]:
    if _has_unsafe_links(state_file):
        warn(f"unsafe link rejected for governor state {state_file}")
        return None, "unsafe_path"
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        if _has_unsafe_links(state_file):
            warn(f"unsafe link rejected for governor state {state_file}")
            return None, "unsafe_path"
        with _governor_lock(state_file.parent):
            doc, err, warn_msg = _read_state_file_safe(state_file)
            if warn_msg:
                warn(warn_msg)
            if err == "unsafe_path":
                return None, "unsafe_path"
            result = mutator(doc)
            payload = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            atomic_write_bytes(state_file, payload)
            return result, None
    except OSError as exc:
        err_code = "unsafe_path" if "unsafe_path" in str(exc) else "io_error"
        warn(f"governor state mutation failed ({err_code}): {type(exc).__name__}")
        return None, err_code


def compute_hook_config_fingerprint(
    harness_id: str, runtime_cfg: Mapping[str, Any] | None = None, hook_payload: Mapping[str, Any] | None = None,
) -> str:
    """Compute canonical `sha256:<64hex>` fingerprint of Context-Guard config and scrubbed hook registration."""
    rt_out: dict[str, Any] = {}
    if isinstance(runtime_cfg, Mapping):
        base = scrub_value({k: v for k, v in runtime_cfg.items() if k != "policy_packs"})
        if isinstance(base, Mapping):
            rt_out.update(base)
        packs = sorted((
            {
                "id": str(e.get("id") or ""), "enabled": bool(e.get("enabled", True)),
                "kind": str(e.get("kind") or "security"), "scopes": list(e.get("scopes") or ()),
                "tree_sha256": str(e.get("tree_sha256") or ""),
                "settings": scrub_value(e.get("settings")) if isinstance(e.get("settings"), Mapping) else {},
            }
            for e in (runtime_cfg.get("policy_packs") or ()) if isinstance(e, Mapping)
        ), key=lambda item: str(item["id"]))
        if packs:
            rt_out["policy_packs"] = packs
    canonical = {
        "harness_id": _norm_harness(harness_id), "runtime_cfg": rt_out,
        "hook_payload": scrub_value(hook_payload) if isinstance(hook_payload, Mapping) else {},
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def build_capability_attestation_key(
    harness_id: str, capability_id: str, *, harness_build_id: str = "unavailable",
    adapter_version: str = ADAPTER_CONTRACT_VERSION, hook_config_fingerprint: str,
) -> CapabilityAttestationKey:
    """Construct `CapabilityAttestationKey` without implying runtime verification."""
    return CapabilityAttestationKey(
        harness_id=_norm_harness(harness_id),
        harness_build_id=scrub_home_paths(str(harness_build_id or "").strip()) or "unavailable",
        adapter_version=str(adapter_version or "").strip() or ADAPTER_CONTRACT_VERSION,
        hook_config_fingerprint=str(hook_config_fingerprint or "").strip(),
        capability_id=str(capability_id or "").strip(),
    )


def _cap_contract(
    key: CapabilityAttestationKey, *, level: str, evidence: str | None = None, verified_at: str | None = None,
    runtime_verified: bool = False, provider_only_rejected: bool = False, invalidated_reason: str | None = None,
) -> CapabilityContractV1:
    return CapabilityContractV1(
        schema_version=CAPABILITY_CONTRACT_SCHEMA_VERSION, capability_id=key.capability_id,
        evidence_level=level, attestation_key=asdict(key), verification_evidence=evidence,
        verified_at=verified_at, runtime_verified=runtime_verified,
        provider_only_rejected=provider_only_rejected, invalidated_reason=invalidated_reason,
    )


def _check_stored_invalidation(
    key: CapabilityAttestationKey, stored: Mapping[str, Any] | None, payload_known: bool,
) -> str | None:
    if not payload_known:
        return "unknown_payload"
    if not isinstance(stored, Mapping):
        return None
    skey_raw = stored.get("attestation_key")
    skey = skey_raw if isinstance(skey_raw, Mapping) else (stored if "harness_build_id" in stored else None)
    if isinstance(skey, Mapping):
        checks = (
            ("harness_id", key.harness_id, "harness_changed"),
            ("harness_build_id", key.harness_build_id, "build_changed"),
            ("adapter_version", key.adapter_version, "adapter_changed"),
            ("hook_config_fingerprint", key.hook_config_fingerprint, "config_fingerprint_changed"),
            ("capability_id", key.capability_id, "attestation_invalidated"),
        )
        for fname, exp, rsn in checks:
            if fname in skey and str(skey.get(fname) or "") != exp:
                return rsn
    prev_inv = stored.get("invalidated_reason")
    return prev_inv.strip() if isinstance(prev_inv, str) and prev_inv.strip() and not stored.get("runtime_verified") else None


def evaluate_capability_contract(
    key: CapabilityAttestationKey, *, stored_attestation: Mapping[str, Any] | None = None,
    claimed_level: str | None = None, verification_evidence: str | None = None, payload_known: bool = True,
) -> CapabilityContractV1:
    """Evaluate `CapabilityContractV1` enforcing static ceilings, provider-only rejection, and key invalidation."""
    ceiling = _static_ceiling(key.harness_id, key.capability_id)
    clean_ev = _clean_evidence(verification_evidence)
    stored_ev = _clean_evidence(stored_attestation.get("verification_evidence") if isinstance(stored_attestation, Mapping) else None)
    stored_rej = bool(stored_attestation.get("provider_only_rejected")) if isinstance(stored_attestation, Mapping) else False
    inv_reason = _check_stored_invalidation(key, stored_attestation, payload_known)
    ev_is_prov = is_provider_only_evidence(clean_ev) or (clean_ev is None and is_provider_only_evidence(stored_ev))
    if not payload_known:
        is_prov_rej = bool(claimed_level == "provider_supported" or ev_is_prov or key.capability_id == "dynamic_tool_mutation")
        return _cap_contract(key, level="unsupported", provider_only_rejected=is_prov_rej, invalidated_reason="unknown_payload")
    if not _supports_runtime_attestation(key, ceiling):
        return _cap_contract(
            key, level="unsupported",
            provider_only_rejected=bool(claimed_level == "provider_supported" or ev_is_prov),
            invalidated_reason=inv_reason,
        )
    if claimed_level == "provider_supported" or is_provider_only_evidence(clean_ev) or (clean_ev is None and (stored_rej or is_provider_only_evidence(stored_ev))):
        return _cap_contract(
            key, level="provider_supported", evidence=clean_ev or stored_ev,
            provider_only_rejected=True, invalidated_reason=inv_reason,
        )
    if clean_ev is not None and (claimed_level is None or claimed_level == "runtime_verified"):
        return _cap_contract(key, level="runtime_verified", evidence=clean_ev, verified_at=utc_now_iso_z(), runtime_verified=True)
    if (
        inv_reason is None and isinstance(stored_attestation, Mapping)
        and bool(stored_attestation.get("runtime_verified")) and stored_ev is not None
        and (claimed_level is None or claimed_level == "runtime_verified")
    ):
        v_at = stored_attestation.get("verified_at")
        return _cap_contract(
            key, level="runtime_verified", evidence=stored_ev,
            verified_at=str(v_at) if isinstance(v_at, str) and v_at else utc_now_iso_z(), runtime_verified=True,
        )
    eff_claim = "harness_exposed" if (claimed_level not in _CAP_RANK or claimed_level == "runtime_verified") else str(claimed_level)
    level = VALID_CAPABILITY_EVIDENCE_LEVELS[min(_CAP_RANK[eff_claim], _CAP_RANK[ceiling])]
    return _cap_contract(
        key, level=level, provider_only_rejected=(key.capability_id == "dynamic_tool_mutation"), invalidated_reason=inv_reason,
    )


def attest_capability(
    harness_id: str, capability_id: str, *, verification_evidence: str, harness_build_id: str = "unavailable",
    adapter_version: str = ADAPTER_CONTRACT_VERSION, runtime_cfg: Mapping[str, Any] | None = None,
    hook_payload: Mapping[str, Any] | None = None, state_dir: str | Path | None = None,
) -> CapabilityContractV1:
    """Persist a client-side `CapabilityContractV1` attestation or reject provider-only evidence safely."""
    clean_harness = _norm_harness(harness_id)
    fp = compute_hook_config_fingerprint(clean_harness, runtime_cfg=runtime_cfg, hook_payload=hook_payload)
    key = build_capability_attestation_key(
        clean_harness, capability_id, harness_build_id=harness_build_id,
        adapter_version=adapter_version, hook_config_fingerprint=fp,
    )
    clean_ev = _clean_evidence(verification_evidence)
    if clean_ev is None:
        return evaluate_capability_contract(key, claimed_level="runtime_verified", verification_evidence=None)
    contract = evaluate_capability_contract(key, claimed_level="runtime_verified", verification_evidence=clean_ev)

    def _store(doc: dict[str, Any]) -> CapabilityContractV1:
        doc.setdefault("attestations", {})[key.capability_id] = dict(contract)
        return contract

    stored, err = _mutate_state_file(resolve_governor_state_path(state_dir), _store)
    if err is None and stored is not None:
        return stored
    return _cap_contract(
        key, level="unsupported", provider_only_rejected=bool(contract["provider_only_rejected"]),
        invalidated_reason=err or "io_error",
    )


def _apply_breaker_update(
    state_dir: str | Path | None, mutator: Callable[[dict[str, Any]], CircuitBreakerStateV1],
) -> tuple[CircuitBreakerStateV1 | None, str | None]:
    return _mutate_state_file(resolve_governor_state_path(state_dir), mutator)


def record_governor_signal(
    optimizer_id: str, signal: str, *, state_dir: str | Path | None = None,
    harness: str = "claude", session_id: str = "default", detail: str | None = None,
) -> CircuitBreakerStateV1:
    """Record a runtime signal; trip circuit breaker strictly on `HARD_INTEGRITY_FAILURE_REASONS`."""
    _ = (harness, session_id, detail)
    opt_id, sig, now_iso = str(optimizer_id or "").strip() or "unknown", str(signal or "").strip(), utc_now_iso_z()
    is_hard = sig in _HARD_REASONS

    def _apply(doc: dict[str, Any]) -> CircuitBreakerStateV1:
        breakers = doc.setdefault("circuit_breakers", {})
        cur = _normalize_breaker(opt_id, breakers.get(opt_id) if isinstance(breakers.get(opt_id), Mapping) else None)
        if is_hard:
            updated = _make_breaker(
                opt_id, state="open", tripped=True, trip_reason=sig, trip_count=cur["trip_count"] + 1,
                tripped_at=now_iso, last_verified_at=cur["last_verified_at"],
                ignored_signals=cur["ignored_signals"], req_reset=True,
            )
        else:
            updated = _make_breaker(
                opt_id, state=cur["state"], tripped=cur["tripped"], trip_reason=cur["trip_reason"],
                trip_count=cur["trip_count"], tripped_at=cur["tripped_at"], last_verified_at=cur["last_verified_at"],
                ignored_signals=cur["ignored_signals"] + 1, req_reset=cur["requires_verification_or_operator_reset"],
            )
        breakers[opt_id] = dict(updated)
        return updated

    res, err = _apply_breaker_update(state_dir, _apply)
    if err is None and res is not None:
        return res
    return _make_breaker(
        opt_id, state="open", tripped=True, trip_reason=err or "unsafe_path",
        trip_count=1, tripped_at=now_iso, req_reset=True,
    )


def _load_governor_state(
    state_dir: str | Path | None,
) -> tuple[dict[str, Mapping[str, Any]], dict[str, CircuitBreakerStateV1], str | None]:
    state_file = resolve_governor_state_path(state_dir)
    if _path_absent(state_file):
        return {}, {}, None
    doc, err, _warn_msg = _read_state_file_safe(state_file)
    if err is not None:
        breakers = {
            opt_id: _make_breaker(opt_id, state="open", tripped=True, trip_reason=err, trip_count=1, req_reset=True)
            for opt_id in GOVERNED_OPTIMIZERS
        }
        return {}, breakers, err
    attestations = {
        cap_id: rec for cap_id, rec in (doc.get("attestations") or {}).items()
        if isinstance(cap_id, str) and isinstance(rec, Mapping)
    }
    breakers = {
        opt_id: _normalize_breaker(opt_id, rec)
        for opt_id, rec in (doc.get("circuit_breakers") or {}).items()
        if isinstance(opt_id, str) and isinstance(rec, Mapping)
    }
    return attestations, breakers, None


def reset_circuit_breaker(
    optimizer_id: str, *, state_dir: str | Path | None = None, verification_passed: bool = False,
    verification_evidence: str | None = None, operator_reset: bool = False, operator_reason: str | None = None,
) -> dict[str, Any]:
    """Close an open circuit breaker only when verification passed or an operator provided a reason."""
    opt_id = str(optimizer_id or "").strip() or "unknown"
    has_ver = (
        bool(verification_passed) and isinstance(verification_evidence, str)
        and bool(verification_evidence.strip()) and not is_provider_only_evidence(verification_evidence)
    )
    has_op = bool(operator_reset) and isinstance(operator_reason, str) and bool(operator_reason.strip())
    if not (has_ver or has_op):
        _, breakers, _ = _load_governor_state(state_dir)
        return {
            "ok": False, "error": "hysteresis_requires_verification_or_operator_reset",
            "optimizer_id": opt_id, "breaker": breakers.get(opt_id) or _make_breaker(opt_id),
        }

    now_iso = utc_now_iso_z()

    def _reset(doc: dict[str, Any]) -> CircuitBreakerStateV1:
        breakers = doc.setdefault("circuit_breakers", {})
        cur = _normalize_breaker(opt_id, breakers.get(opt_id) if isinstance(breakers.get(opt_id), Mapping) else None)
        updated = _make_breaker(
            opt_id, state="closed", tripped=False, trip_reason=None, trip_count=cur["trip_count"],
            tripped_at=None, last_verified_at=now_iso, ignored_signals=cur["ignored_signals"], req_reset=False,
        )
        breakers[opt_id] = dict(updated)
        return updated

    res, err = _apply_breaker_update(state_dir, _reset)
    if err is not None or res is None:
        return {"ok": False, "error": err or "unsafe_path", "optimizer_id": opt_id, "breaker": _make_breaker(opt_id)}
    return {"ok": True, "optimizer_id": opt_id, "reset_mode": "verification" if has_ver else "operator", "breaker": res}


def is_optimizer_tripped(optimizer_id: str, *, state_dir: str | Path | None = None) -> bool:
    """Return True if `optimizer_id` has an open circuit breaker or unsafe/corrupt governor state."""
    opt_id = str(optimizer_id or "").strip() or "unknown"
    if _path_absent(resolve_governor_state_path(state_dir)):
        return False
    _, breakers, compromised = _load_governor_state(state_dir)
    if compromised is not None:
        return True
    entry = breakers.get(opt_id)
    return bool(entry is not None and (entry["tripped"] or entry["state"] == "open"))


def _resolve_gov_options(
    runtime_cfg: Mapping[str, Any] | None, harness_build_id: str, adapter_version: str,
    require_runtime_verified: bool, evidence_report: Mapping[str, Any] | None, evidence_gate_required: bool,
) -> tuple[str, str, bool, Mapping[str, Any] | None, bool]:
    gov_raw = runtime_cfg.get("governor") if isinstance(runtime_cfg, Mapping) else None
    gov: Mapping[str, Any] = gov_raw if isinstance(gov_raw, Mapping) else {}
    raw_build, raw_adapter, gov_report = gov.get("harness_build_id"), gov.get("adapter_version"), gov.get("evidence_report")
    eff_build = str(raw_build).strip() if (harness_build_id == "unavailable" and isinstance(raw_build, str) and raw_build.strip()) else harness_build_id
    eff_adapter = str(raw_adapter).strip() if (adapter_version == ADAPTER_CONTRACT_VERSION and isinstance(raw_adapter, str) and raw_adapter.strip()) else adapter_version
    eff_report = evidence_report if isinstance(evidence_report, Mapping) else (gov_report if isinstance(gov_report, Mapping) else None)
    return (
        eff_build, eff_adapter, bool(require_runtime_verified or gov.get("require_runtime_verified", False)),
        eff_report, bool(evidence_gate_required or gov.get("evidence_gate_required", False)),
    )


def _decide_optimizer(
    opt_id: str, configured_mode: str, *, read_confirm_policy: str, capabilities: Mapping[str, CapabilityContractV1],
    breaker: CircuitBreakerStateV1, payload_known: bool, require_runtime_verified: bool,
    evidence_gate_required: bool, evidence_gate_passed: bool,
) -> OptimizerDecisionV1:
    req_caps: tuple[str, ...] = (
        ("pre_tool_interception",) if (opt_id == "range_trim" and read_confirm_policy == "bounded")
        else OPTIMIZER_REQUIRED_CAPABILITIES.get(opt_id, ("pre_tool_interception",))
    )
    min_level = "runtime_verified" if (require_runtime_verified or opt_id == "dynamic_tool_mutation") else "harness_exposed"
    min_rank = _CAP_RANK[min_level]
    obs_level = VALID_CAPABILITY_EVIDENCE_LEVELS[min(_CAP_RANK.get(capabilities[c]["evidence_level"], 0) for c in req_caps)] if req_caps else "unsupported"
    pre_ok = _CAP_RANK.get(capabilities["pre_tool_interception"]["evidence_level"], 0) >= _CAP_RANK["harness_exposed"]

    def _dec(sel: str, eff_cfg: str, rsn: str, dng: bool) -> OptimizerDecisionV1:
        return OptimizerDecisionV1(
            optimizer_id=opt_id, configured_mode=configured_mode, selected_mode=sel,
            effective_config_mode=eff_cfg, reason=rsn, required_capabilities=list(req_caps),
            min_evidence_level=min_level, observed_evidence_level=obs_level, breaker_state=breaker["state"], downgraded=dng,
        )

    if configured_mode in ("off", "passthrough"):
        return _dec("passthrough", "off", "configured_off", False)
    if not payload_known:
        return _dec("passthrough", "off", "unknown_payload", True)
    if breaker["tripped"] or breaker["state"] == "open":
        return _dec("passthrough", "off", f"circuit_breaker_open:{breaker['trip_reason'] or 'tripped'}", True)
    if configured_mode == "shadow":
        return _dec("shadow", "shadow", "configured_shadow", False) if pre_ok else _dec("passthrough", "off", "capability_unverified:pre_tool_interception", True)
    failing = [
        c for c in req_caps
        if _CAP_RANK.get(capabilities[c]["evidence_level"], 0) < min_rank
        or (capabilities[c]["provider_only_rejected"] and not capabilities[c]["runtime_verified"])
    ]
    if failing:
        first, sel = failing[0], ("shadow" if pre_ok else "passthrough")
        is_prov = capabilities[first]["provider_only_rejected"] and capabilities[first]["evidence_level"] == "provider_supported"
        reason = f"provider_only_rejected:{first}" if is_prov else f"capability_unverified:{first}"
        return _dec(sel, "shadow" if sel == "shadow" else "off", reason, True)
    if evidence_gate_required and not evidence_gate_passed and opt_id in ("output_spool", "dynamic_tool_mutation"):
        sel = "shadow" if pre_ok else "passthrough"
        return _dec(sel, "shadow" if sel == "shadow" else "off", "evidence_gate_not_passed", True)
    reason = "capabilities_verified" if obs_level == "runtime_verified" else "harness_capabilities_satisfied"
    return _dec("active", configured_mode, reason, False)


def evaluate_governor(
    harness_id: str, *, runtime_cfg: Mapping[str, Any] | None = None, state_dir: str | Path | None = None,
    harness_build_id: str = "unavailable", adapter_version: str = ADAPTER_CONTRACT_VERSION,
    hook_payload: Mapping[str, Any] | None = None, payload_known: bool = True,
    require_runtime_verified: bool = False, evidence_report: Mapping[str, Any] | None = None,
    evidence_gate_required: bool = False,
) -> GovernorContractV1:
    """Evaluate all governed capabilities, circuit breakers, and optimizer mode decisions."""
    clean_harness = _norm_harness(harness_id)
    eff_build, eff_adapter, eff_req_rt, eff_report, eff_gate_req = _resolve_gov_options(
        runtime_cfg, harness_build_id, adapter_version, require_runtime_verified, evidence_report, evidence_gate_required,
    )
    fp = compute_hook_config_fingerprint(clean_harness, runtime_cfg=runtime_cfg, hook_payload=hook_payload)
    stored_att, loaded_brk, compromised = _load_governor_state(state_dir)
    capabilities = {
        cap_id: evaluate_capability_contract(
            build_capability_attestation_key(
                clean_harness, cap_id, harness_build_id=eff_build, adapter_version=eff_adapter, hook_config_fingerprint=fp,
            ),
            stored_attestation=stored_att.get(cap_id), payload_known=bool(payload_known),
        )
        for cap_id in GOVERNED_CAPABILITIES
    }
    verdict = eff_report.get("gate_verdict") if isinstance(eff_report, Mapping) else None
    ev_gate_passed = bool(isinstance(verdict, Mapping) and verdict.get("ok")) if isinstance(eff_report, Mapping) else (not eff_gate_req)
    raw_opts_val = runtime_cfg.get("optimizers") if isinstance(runtime_cfg, Mapping) else None
    raw_opts: Mapping[str, Any] = raw_opts_val if isinstance(raw_opts_val, Mapping) else {}
    read_policy = str(runtime_cfg.get("read_confirm_policy") or "strict").strip().lower() if isinstance(runtime_cfg, Mapping) else "strict"
    opt_ids = list(GOVERNED_OPTIMIZERS) + (["dynamic_tool_mutation"] if "dynamic_tool_mutation" in raw_opts else [])
    circuit_breakers: dict[str, CircuitBreakerStateV1] = {}
    decisions: dict[str, OptimizerDecisionV1] = {}
    effective_optimizers: dict[str, str] = {}
    for opt_id in opt_ids:
        if opt_id in loaded_brk:
            brk = loaded_brk[opt_id]
        elif compromised is not None:
            brk = _make_breaker(opt_id, state="open", tripped=True, trip_reason=compromised, trip_count=1, req_reset=True)
        else:
            brk = _make_breaker(opt_id)
        cfg_mode = str(raw_opts.get(opt_id, _DEFAULT_MODES.get(opt_id, "off"))).strip().lower()
        dec = _decide_optimizer(
            opt_id, cfg_mode, read_confirm_policy=read_policy, capabilities=capabilities, breaker=brk,
            payload_known=bool(payload_known), require_runtime_verified=eff_req_rt,
            evidence_gate_required=eff_gate_req, evidence_gate_passed=ev_gate_passed,
        )
        circuit_breakers[opt_id], decisions[opt_id], effective_optimizers[opt_id] = brk, dec, dec["effective_config_mode"]
    return GovernorContractV1(
        schema_version=GOVERNOR_SCHEMA_VERSION, evaluated_at=utc_now_iso_z(), harness_id=clean_harness,
        harness_build_id=eff_build, adapter_version=eff_adapter, hook_config_fingerprint=fp,
        payload_known=bool(payload_known), evidence_gate_passed=ev_gate_passed,
        security_enforcement_lowered=False, capabilities=capabilities, circuit_breakers=circuit_breakers,
        decisions=decisions, effective_optimizers=effective_optimizers,
    )


def _is_known_hook_payload(payload: Any) -> bool:
    if payload is None:
        return True
    if not isinstance(payload, Mapping):
        return False
    for key in ("tool_name", "toolName"):
        val = payload.get(key)
        if isinstance(val, str) and bool(val.strip()):
            return True
    tc = payload.get("toolCall")
    if isinstance(tc, Mapping):
        tc_name = tc.get("name")
        if isinstance(tc_name, str) and bool(tc_name.strip()):
            return True
    for key in ("hook_event_name", "event"):
        ev_val = payload.get(key)
        if isinstance(ev_val, str) and ev_val in _KNOWN_HOOK_EVENTS:
            return True
    for key in ("results", "items", "batch", "tool_calls", "toolCalls"):
        if isinstance(payload.get(key), list):
            return True
    return any(isinstance(payload.get(key), Mapping) for key in ("hooks", "hook_payload"))


def _extract_payload_build_id(payload: Mapping[str, Any] | None) -> str:
    if not isinstance(payload, Mapping):
        return "unavailable"
    for key in (
        "harness_build_id", "cursor_version", "claude_version",
        "codex_version", "antigravity_version", "client_version",
    ):
        val = payload.get(key)
        if isinstance(val, str) and (clean := val.strip()):
            return clean
    return "unavailable"


def apply_runtime_governor(
    runtime_cfg: Mapping[str, Any], harness_id: str, *,
    state_dir: str | Path | None = None, payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply governor decisions to `runtime_cfg['optimizers']` with O(1) static parity fast path."""
    payload_known = _is_known_hook_payload(payload)
    raw_opts = runtime_cfg.get("optimizers")
    has_dyn = (
        isinstance(raw_opts, Mapping)
        and str(raw_opts.get("dynamic_tool_mutation") or "off").strip().lower() not in ("off", "passthrough", "")
    )
    if payload_known and not has_dyn and not isinstance(runtime_cfg.get("governor"), Mapping):
        if _path_absent(resolve_governor_state_path(state_dir)):
            return dict(runtime_cfg)
    hook_payload: Mapping[str, Any] | None = None
    if isinstance(payload, Mapping):
        if isinstance(payload.get("hooks"), Mapping):
            hook_payload = {"hooks": payload["hooks"]}
        elif isinstance(payload.get("hook_payload"), Mapping):
            hook_payload = payload["hook_payload"]
    contract = evaluate_governor(
        harness_id, runtime_cfg=runtime_cfg, state_dir=state_dir,
        harness_build_id=_extract_payload_build_id(payload),
        hook_payload=hook_payload, payload_known=payload_known,
    )
    out = dict(runtime_cfg)
    new_opts = dict(raw_opts) if isinstance(raw_opts, Mapping) else {}
    new_opts.update(contract["effective_optimizers"])
    out["optimizers"] = new_opts
    return out
