"""Capability-Aware Adaptive Governor, attestation validation, and hysteresis circuit breakers."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib, json, os, re, stat, tempfile
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence, TypeVar

from hooks.file_io import LOCK_EX, LOCK_UN, flock
from hooks.state_store import resolve_plugin_root, warn
from policies.api import (
    ADAPTER_CONTRACT_VERSION, CAPABILITY_CONTRACT_SCHEMA_VERSION, GOVERNOR_SCHEMA_VERSION,
    HARD_INTEGRITY_FAILURE_REASONS, HARNESS_OUTPUT_CAPABILITIES, NON_TRIPPING_SIGNALS,
    VALID_CAPABILITY_EVIDENCE_LEVELS, CapabilityAttestationKey, CapabilityContractV1,
    CircuitBreakerStateV1, GovernorContractV1, OptimizerDecisionV1,
)
from spool.receipts import atomic_write_bytes, check_unsafe_link

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
_LOCK_FILENAME, _O_FLAGS = "governor_state.lock", getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
_PROVIDER_PREFIXES = ("model_api:", "provider_api:", "upstream_provider:")
_CAP_RANK = {lvl: idx for idx, lvl in enumerate(VALID_CAPABILITY_EVIDENCE_LEVELS)}
_HARD_REASONS = frozenset(HARD_INTEGRITY_FAILURE_REASONS)
_POSIX_HOME_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9._-]+")
_WIN_HOME_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:(?:[/\\]|\\\\)Users(?:[/\\]|\\\\)[A-Za-z0-9._-]+", re.I)
_PATH_SCRUB_KEYS = frozenset({
    "config_path", "repo_map_path", "workspace_root", "transcript_path", "state_dir", "home_dir",
    "stats_path", "outcomes_path", "usage_path", "update_path", "shadow_path", "spool_dir", "receipts_path", "cwd",
})
_DEFAULT_MODES: dict[str, str] = {"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "off"}

__all__ = [
    "DEFAULT_GOVERNOR_STATE_FILENAME", "GOVERNED_CAPABILITIES", "GOVERNED_OPTIMIZERS",
    "OPTIMIZER_REQUIRED_CAPABILITIES", "apply_runtime_governor", "attest_capability",
    "build_capability_attestation_key", "compute_hook_config_fingerprint",
    "evaluate_capability_contract", "evaluate_governor", "is_optimizer_tripped",
    "record_governor_signal", "replay_governor_decisions", "reset_circuit_breaker", "resolve_governor_state_path",
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
        return {ks: _scrub_value(val[k]) for k in sorted(val, key=str)
                if (ks := str(k)).lower() not in _PATH_SCRUB_KEYS and not ks.lower().endswith(("_path", "_paths", "_dir", "_dirs"))}
    if isinstance(val, (list, tuple)):
        return [_scrub_value(item) for item in val]
    if isinstance(val, str):
        return _scrub_home_paths(val)
    return val if isinstance(val, (bool, int, float)) or val is None else _scrub_home_paths(str(val))

def _norm_harness(harness_id: str | None) -> str:
    return _scrub_home_paths(str(harness_id or "").strip().lower()) or "unknown"

def _is_provider_evidence(evidence: str | None) -> bool:
    return isinstance(evidence, str) and evidence.strip().lower().startswith(_PROVIDER_PREFIXES)

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

def _make_breaker(
    opt_id: str, *, state: str = "closed", tripped: bool = False, trip_reason: str | None = None,
    trip_count: int = 0, tripped_at: str | None = None, last_verified_at: str | None = None,
    ignored_signals: int = 0, req_reset: bool = False,
) -> CircuitBreakerStateV1:
    return CircuitBreakerStateV1(
        optimizer_id=opt_id, state=state, tripped=tripped, trip_reason=trip_reason, trip_count=trip_count,
        tripped_at=tripped_at, last_verified_at=last_verified_at, ignored_signals=ignored_signals,
        requires_verification_or_operator_reset=req_reset,
    )

def _normalize_breaker(optimizer_id: str, raw: Mapping[str, Any] | None) -> CircuitBreakerStateV1:
    if not isinstance(raw, Mapping):
        return _make_breaker(optimizer_id)
    tripped = bool(raw.get("tripped")) or str(raw.get("state") or "closed") == "open"
    state = "open" if tripped else ("half_open" if raw.get("state") == "half_open" else "closed")
    tc, ig = raw.get("trip_count"), raw.get("ignored_signals")
    return _make_breaker(
        optimizer_id, state=state, tripped=tripped,
        trip_reason=str(raw["trip_reason"]) if tripped and isinstance(raw.get("trip_reason"), str) and raw["trip_reason"] else None,
        trip_count=int(tc) if isinstance(tc, int) and not isinstance(tc, bool) and tc >= 0 else (1 if tripped else 0),
        tripped_at=str(raw["tripped_at"]) if tripped and isinstance(raw.get("tripped_at"), str) else None,
        last_verified_at=str(raw["last_verified_at"]) if isinstance(raw.get("last_verified_at"), str) else None,
        ignored_signals=int(ig) if isinstance(ig, int) and not isinstance(ig, bool) and ig >= 0 else 0,
        req_reset=bool(raw.get("requires_verification_or_operator_reset")) or tripped,
    )

def _empty_state_doc() -> dict[str, Any]:
    return {"schema_version": GOVERNOR_SCHEMA_VERSION, "attestations": {}, "circuit_breakers": {}}

def resolve_governor_state_path(state_dir: str | Path | None = None) -> Path:
    """Resolve `governor_state.json` under `state_dir`, `CONTEXT_GUARD_STATE_DIR`, or plugin telemetry."""
    if state_dir is not None and str(state_dir).strip():
        return Path(str(state_dir).strip()).expanduser() / DEFAULT_GOVERNOR_STATE_FILENAME
    if (env_state := str(os.environ.get("CONTEXT_GUARD_STATE_DIR") or "").strip()):
        return Path(env_state).expanduser() / DEFAULT_GOVERNOR_STATE_FILENAME
    return resolve_plugin_root() / "telemetry" / DEFAULT_GOVERNOR_STATE_FILENAME

def _path_absent(path: Path) -> bool:
    try:
        os.lstat(str(path))
        return False
    except FileNotFoundError:
        return True
    except OSError:
        return False

def _candidate_state_paths(state_dir: str | Path | None) -> list[Path]:
    primary = resolve_governor_state_path(state_dir)
    pdir, paths = primary.parent, [primary]
    if pdir.name == "spool":
        paths.append(pdir.parent / DEFAULT_GOVERNOR_STATE_FILENAME)
    elif not _path_absent((child := pdir / "spool" / DEFAULT_GOVERNOR_STATE_FILENAME)):
        paths.append(child)
    if state_dir is None and (env_spool := str(os.environ.get("CONTEXT_GUARD_SPOOL_DIR") or "").strip()):
        if (sp := Path(env_spool).expanduser() / DEFAULT_GOVERNOR_STATE_FILENAME) not in paths and not _path_absent(sp):
            paths.append(sp)
    return paths

def _has_unsafe_links(state_file: Path) -> bool:
    return check_unsafe_link(state_file.parent) or check_unsafe_link(state_file) or check_unsafe_link(state_file.parent / _LOCK_FILENAME)

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
    return {
        "schema_version": GOVERNOR_SCHEMA_VERSION,
        "attestations": dict(parsed["attestations"]) if isinstance(parsed.get("attestations"), Mapping) else {},
        "circuit_breakers": dict(parsed["circuit_breakers"]) if isinstance(parsed.get("circuit_breakers"), Mapping) else {},
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
            atomic_write_bytes(state_file, json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
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
        if isinstance((base := _scrub_value({k: v for k, v in runtime_cfg.items() if k != "policy_packs"})), Mapping):
            rt_out.update(base)
        packs = sorted((
            {"id": str(e.get("id") or ""), "enabled": bool(e.get("enabled", True)), "kind": str(e.get("kind") or "security"),
             "scopes": list(e.get("scopes") or ()), "tree_sha256": str(e.get("tree_sha256") or ""),
             "settings": _scrub_value(e.get("settings")) if isinstance(e.get("settings"), Mapping) else {}}
            for e in (runtime_cfg.get("policy_packs") or ()) if isinstance(e, Mapping)
        ), key=lambda item: item["id"])
        if packs:
            rt_out["policy_packs"] = packs
    canonical = {"harness_id": _norm_harness(harness_id), "runtime_cfg": rt_out, "hook_payload": _scrub_value(hook_payload) if isinstance(hook_payload, Mapping) else {}}
    return "sha256:" + hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()

def build_capability_attestation_key(
    harness_id: str, capability_id: str, *, harness_build_id: str = "unavailable",
    adapter_version: str = ADAPTER_CONTRACT_VERSION, hook_config_fingerprint: str,
) -> CapabilityAttestationKey:
    """Construct `CapabilityAttestationKey` without implying runtime verification."""
    return CapabilityAttestationKey(
        harness_id=_norm_harness(harness_id),
        harness_build_id=_scrub_home_paths(str(harness_build_id or "").strip()) or "unavailable",
        adapter_version=str(adapter_version or "").strip() or ADAPTER_CONTRACT_VERSION,
        hook_config_fingerprint=str(hook_config_fingerprint or "").strip(), capability_id=str(capability_id or "").strip(),
    )

def _cap_contract(
    key: CapabilityAttestationKey, *, level: str, evidence: str | None = None, verified_at: str | None = None,
    runtime_verified: bool = False, provider_only_rejected: bool = False, invalidated_reason: str | None = None,
) -> CapabilityContractV1:
    return CapabilityContractV1(
        schema_version=CAPABILITY_CONTRACT_SCHEMA_VERSION, capability_id=key.capability_id, evidence_level=level,
        attestation_key=asdict(key), verification_evidence=evidence, verified_at=verified_at,
        runtime_verified=runtime_verified, provider_only_rejected=provider_only_rejected, invalidated_reason=invalidated_reason,
    )

def _check_stored_invalidation(key: CapabilityAttestationKey, stored: Mapping[str, Any] | None, payload_known: bool) -> str | None:
    if not payload_known:
        return "unknown_payload"
    if not isinstance(stored, Mapping):
        return None
    skey_raw = stored.get("attestation_key")
    skey = skey_raw if isinstance(skey_raw, Mapping) else (stored if "harness_build_id" in stored else None)
    if isinstance(skey, Mapping):
        for fname, exp, rsn in (("harness_id", key.harness_id, "harness_changed"), ("harness_build_id", key.harness_build_id, "build_changed"),
                                ("adapter_version", key.adapter_version, "adapter_changed"), ("hook_config_fingerprint", key.hook_config_fingerprint, "config_fingerprint_changed"),
                                ("capability_id", key.capability_id, "attestation_invalidated")):
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
    clean_ev = _scrub_home_paths(verification_evidence.strip()) if isinstance(verification_evidence, str) and verification_evidence.strip() else None
    stored_ev_raw = stored_attestation.get("verification_evidence") if isinstance(stored_attestation, Mapping) else None
    stored_ev = _scrub_home_paths(stored_ev_raw.strip()) if isinstance(stored_ev_raw, str) and stored_ev_raw.strip() else None
    stored_rej = bool(stored_attestation.get("provider_only_rejected")) if isinstance(stored_attestation, Mapping) else False
    inv_reason = _check_stored_invalidation(key, stored_attestation, payload_known)
    ev_is_prov = _is_provider_evidence(clean_ev) or (clean_ev is None and _is_provider_evidence(stored_ev))
    if not payload_known:
        return _cap_contract(key, level="unsupported", provider_only_rejected=bool(claimed_level == "provider_supported" or ev_is_prov or key.capability_id == "dynamic_tool_mutation"), invalidated_reason="unknown_payload")
    if claimed_level == "provider_supported" or _is_provider_evidence(clean_ev) or (clean_ev is None and (stored_rej or _is_provider_evidence(stored_ev))):
        return _cap_contract(key, level="provider_supported", evidence=clean_ev or stored_ev, provider_only_rejected=True, invalidated_reason=inv_reason)
    if clean_ev is not None and (claimed_level is None or claimed_level == "runtime_verified"):
        return _cap_contract(key, level="runtime_verified", evidence=clean_ev, verified_at=_utc_now_iso_z(), runtime_verified=True)
    if inv_reason is None and isinstance(stored_attestation, Mapping) and bool(stored_attestation.get("runtime_verified")) and stored_ev is not None and (claimed_level is None or claimed_level == "runtime_verified"):
        v_at = stored_attestation.get("verified_at")
        return _cap_contract(key, level="runtime_verified", evidence=stored_ev, verified_at=str(v_at) if isinstance(v_at, str) and v_at else _utc_now_iso_z(), runtime_verified=True)
    eff_claim = "harness_exposed" if (claimed_level not in _CAP_RANK or claimed_level == "runtime_verified") else str(claimed_level)
    level = VALID_CAPABILITY_EVIDENCE_LEVELS[min(_CAP_RANK[eff_claim], _CAP_RANK[ceiling])]
    return _cap_contract(key, level=level, provider_only_rejected=(key.capability_id == "dynamic_tool_mutation"), invalidated_reason=inv_reason)

def attest_capability(
    harness_id: str, capability_id: str, *, verification_evidence: str, harness_build_id: str = "unavailable",
    adapter_version: str = ADAPTER_CONTRACT_VERSION, runtime_cfg: Mapping[str, Any] | None = None,
    hook_payload: Mapping[str, Any] | None = None, state_dir: str | Path | None = None,
) -> CapabilityContractV1:
    """Persist a client-side `CapabilityContractV1` attestation or reject provider-only evidence safely."""
    clean_harness = _norm_harness(harness_id)
    fp = compute_hook_config_fingerprint(clean_harness, runtime_cfg=runtime_cfg, hook_payload=hook_payload)
    key = build_capability_attestation_key(clean_harness, capability_id, harness_build_id=harness_build_id, adapter_version=adapter_version, hook_config_fingerprint=fp)
    clean_ev = _scrub_home_paths(verification_evidence.strip()) if isinstance(verification_evidence, str) and verification_evidence.strip() else None
    if clean_ev is None:
        return evaluate_capability_contract(key, claimed_level="runtime_verified", verification_evidence=None)
    contract = evaluate_capability_contract(key, claimed_level="runtime_verified", verification_evidence=clean_ev)
    stored, err = _mutate_state_file(resolve_governor_state_path(state_dir), lambda doc: (doc.setdefault("attestations", {}).__setitem__(key.capability_id, dict(contract)), contract)[1])
    return stored if (err is None and stored is not None) else _cap_contract(key, level="unsupported", provider_only_rejected=bool(contract["provider_only_rejected"]), invalidated_reason=err or "io_error")

def _apply_breaker_update(state_dir: str | Path | None, mutator: Callable[[dict[str, Any]], CircuitBreakerStateV1]) -> tuple[CircuitBreakerStateV1 | None, str | None]:
    primary_res: CircuitBreakerStateV1 | None = None
    primary_err: str | None = None
    for idx, target in enumerate(_candidate_state_paths(state_dir)):
        res, err = _mutate_state_file(target, mutator)
        if idx == 0:
            primary_res, primary_err = res, err
    return primary_res, primary_err

def record_governor_signal(
    optimizer_id: str, signal: str, *, state_dir: str | Path | None = None,
    harness: str = "claude", session_id: str = "default", detail: str | None = None,
) -> CircuitBreakerStateV1:
    """Record a runtime signal; trip circuit breaker strictly on `HARD_INTEGRITY_FAILURE_REASONS`."""
    _ = (harness, session_id, detail)
    opt_id, sig, now_iso = str(optimizer_id or "").strip() or "unknown", str(signal or "").strip(), _utc_now_iso_z()
    is_hard = sig in _HARD_REASONS

    def _apply(doc: dict[str, Any]) -> CircuitBreakerStateV1:
        breakers = doc.setdefault("circuit_breakers", {})
        cur = _normalize_breaker(opt_id, breakers.get(opt_id) if isinstance(breakers.get(opt_id), Mapping) else None)
        updated = (_make_breaker(opt_id, state="open", tripped=True, trip_reason=sig, trip_count=cur["trip_count"] + 1, tripped_at=now_iso, last_verified_at=cur["last_verified_at"], ignored_signals=cur["ignored_signals"], req_reset=True)
                   if is_hard else _make_breaker(opt_id, state=cur["state"], tripped=cur["tripped"], trip_reason=cur["trip_reason"], trip_count=cur["trip_count"], tripped_at=cur["tripped_at"], last_verified_at=cur["last_verified_at"], ignored_signals=cur["ignored_signals"] + 1, req_reset=cur["requires_verification_or_operator_reset"]))
        breakers[opt_id] = dict(updated)
        return updated

    res, err = _apply_breaker_update(state_dir, _apply)
    return res if (err is None and res is not None) else _make_breaker(opt_id, state="open", tripped=True, trip_reason=err or "unsafe_path", trip_count=1, tripped_at=now_iso, req_reset=True)

def _load_merged_state(state_dir: str | Path | None) -> tuple[dict[str, Mapping[str, Any]], dict[str, CircuitBreakerStateV1], str | None]:
    attestations: dict[str, Mapping[str, Any]] = {}
    breakers: dict[str, CircuitBreakerStateV1] = {}
    compromised: str | None = None
    for path in _candidate_state_paths(state_dir):
        if _path_absent(path):
            continue
        doc, err, _warn_msg = _read_state_file_safe(path)
        if err is not None:
            compromised = err
            continue
        for cap_id, rec in (doc.get("attestations") or {}).items():
            if isinstance(cap_id, str) and isinstance(rec, Mapping) and cap_id not in attestations:
                attestations[cap_id] = rec
        for opt_id, rec in (doc.get("circuit_breakers") or {}).items():
            if isinstance(opt_id, str) and isinstance(rec, Mapping):
                cand, prev = _normalize_breaker(opt_id, rec), breakers.get(opt_id)
                if prev is None or (cand["tripped"] and not prev["tripped"]) or (cand["tripped"] == prev["tripped"] and (cand["trip_count"] + cand["ignored_signals"]) > (prev["trip_count"] + prev["ignored_signals"])):
                    breakers[opt_id] = cand
    if compromised is not None:
        attestations = {}
        for opt_id in set(GOVERNED_OPTIMIZERS) | set(breakers):
            prev = breakers.get(opt_id) or _make_breaker(opt_id)
            breakers[opt_id] = _make_breaker(opt_id, state="open", tripped=True, trip_reason=compromised, trip_count=max(1, prev["trip_count"]), tripped_at=prev["tripped_at"], last_verified_at=prev["last_verified_at"], ignored_signals=prev["ignored_signals"], req_reset=True)
    return attestations, breakers, compromised

def reset_circuit_breaker(
    optimizer_id: str, *, state_dir: str | Path | None = None, verification_passed: bool = False,
    verification_evidence: str | None = None, operator_reset: bool = False, operator_reason: str | None = None,
) -> dict[str, Any]:
    """Close an open circuit breaker only when verification passed or an operator provided a reason."""
    opt_id = str(optimizer_id or "").strip() or "unknown"
    has_ver = bool(verification_passed) and isinstance(verification_evidence, str) and bool(verification_evidence.strip()) and not _is_provider_evidence(verification_evidence)
    has_op = bool(operator_reset) and isinstance(operator_reason, str) and bool(operator_reason.strip())
    if not (has_ver or has_op):
        _, breakers, _ = _load_merged_state(state_dir)
        return {"ok": False, "error": "hysteresis_requires_verification_or_operator_reset", "optimizer_id": opt_id, "breaker": breakers.get(opt_id) or _make_breaker(opt_id)}

    now_iso = _utc_now_iso_z()

    def _reset(doc: dict[str, Any]) -> CircuitBreakerStateV1:
        breakers = doc.setdefault("circuit_breakers", {})
        cur = _normalize_breaker(opt_id, breakers.get(opt_id) if isinstance(breakers.get(opt_id), Mapping) else None)
        updated = _make_breaker(opt_id, state="closed", tripped=False, trip_reason=None, trip_count=cur["trip_count"], tripped_at=None, last_verified_at=now_iso, ignored_signals=cur["ignored_signals"], req_reset=False)
        breakers[opt_id] = dict(updated)
        return updated

    res, err = _apply_breaker_update(state_dir, _reset)
    if err is not None or res is None:
        return {"ok": False, "error": err or "unsafe_path", "optimizer_id": opt_id, "breaker": _make_breaker(opt_id)}
    return {"ok": True, "optimizer_id": opt_id, "reset_mode": "verification" if has_ver else "operator", "breaker": res}

def is_optimizer_tripped(optimizer_id: str, *, state_dir: str | Path | None = None) -> bool:
    """Return True if `optimizer_id` has an open circuit breaker or unsafe/corrupt governor state."""
    opt_id = str(optimizer_id or "").strip() or "unknown"
    if all(_path_absent(p) for p in _candidate_state_paths(state_dir)):
        return False
    _, breakers, compromised = _load_merged_state(state_dir)
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
    eff_build = str(gov["harness_build_id"]).strip() if (harness_build_id == "unavailable" and isinstance(gov.get("harness_build_id"), str) and gov["harness_build_id"].strip()) else harness_build_id
    eff_adapter = str(gov["adapter_version"]).strip() if (adapter_version == ADAPTER_CONTRACT_VERSION and isinstance(gov.get("adapter_version"), str) and gov["adapter_version"].strip()) else adapter_version
    eff_report = evidence_report if isinstance(evidence_report, Mapping) else (gov.get("evidence_report") if isinstance(gov.get("evidence_report"), Mapping) else None)
    return eff_build, eff_adapter, bool(require_runtime_verified or gov.get("require_runtime_verified", False)), eff_report, bool(evidence_gate_required or gov.get("evidence_gate_required", False))

def _decide_optimizer(
    opt_id: str, configured_mode: str, *, read_confirm_policy: str, capabilities: Mapping[str, CapabilityContractV1],
    breaker: CircuitBreakerStateV1, payload_known: bool, require_runtime_verified: bool,
    evidence_gate_required: bool, evidence_gate_passed: bool,
) -> OptimizerDecisionV1:
    req_caps = ("pre_tool_interception",) if (opt_id == "range_trim" and read_confirm_policy == "bounded") else OPTIMIZER_REQUIRED_CAPABILITIES.get(opt_id, ("pre_tool_interception",))
    min_level = "runtime_verified" if (require_runtime_verified or opt_id == "dynamic_tool_mutation") else "harness_exposed"
    min_rank = _CAP_RANK[min_level]
    obs_level = VALID_CAPABILITY_EVIDENCE_LEVELS[min(_CAP_RANK.get(capabilities[c]["evidence_level"], 0) for c in req_caps)] if req_caps else "unsupported"
    pre_ok = _CAP_RANK.get(capabilities["pre_tool_interception"]["evidence_level"], 0) >= _CAP_RANK["harness_exposed"]

    def _dec(sel: str, eff_cfg: str, rsn: str, dng: bool) -> OptimizerDecisionV1:
        return OptimizerDecisionV1(optimizer_id=opt_id, configured_mode=configured_mode, selected_mode=sel, effective_config_mode=eff_cfg, reason=rsn, required_capabilities=list(req_caps), min_evidence_level=min_level, observed_evidence_level=obs_level, breaker_state=breaker["state"], downgraded=dng)

    if configured_mode in ("off", "passthrough"):
        return _dec("passthrough", "off", "configured_off", False)
    if not payload_known:
        return _dec("passthrough", "off", "unknown_payload", True)
    if breaker["tripped"] or breaker["state"] == "open":
        return _dec("passthrough", "off", f"circuit_breaker_open:{breaker['trip_reason'] or 'tripped'}", True)
    if configured_mode == "shadow":
        return _dec("shadow", "shadow", "configured_shadow", False) if pre_ok else _dec("passthrough", "off", "capability_unverified:pre_tool_interception", True)
    if (failing := [c for c in req_caps if _CAP_RANK.get(capabilities[c]["evidence_level"], 0) < min_rank or (capabilities[c]["provider_only_rejected"] and not capabilities[c]["runtime_verified"])]):
        first, sel = failing[0], ("shadow" if pre_ok else "passthrough")
        reason = f"provider_only_rejected:{first}" if capabilities[first]["provider_only_rejected"] and capabilities[first]["evidence_level"] == "provider_supported" else f"capability_unverified:{first}"
        return _dec(sel, "shadow" if sel == "shadow" else "off", reason, True)
    if evidence_gate_required and not evidence_gate_passed and opt_id in ("output_spool", "dynamic_tool_mutation"):
        sel = "shadow" if pre_ok else "passthrough"
        return _dec(sel, "shadow" if sel == "shadow" else "off", "evidence_gate_not_passed", True)
    return _dec("active", configured_mode, "capabilities_verified" if obs_level == "runtime_verified" else "harness_capabilities_satisfied", False)

def evaluate_governor(
    harness_id: str, *, runtime_cfg: Mapping[str, Any] | None = None, state_dir: str | Path | None = None,
    harness_build_id: str = "unavailable", adapter_version: str = ADAPTER_CONTRACT_VERSION,
    hook_payload: Mapping[str, Any] | None = None, payload_known: bool = True,
    require_runtime_verified: bool = False, evidence_report: Mapping[str, Any] | None = None, evidence_gate_required: bool = False,
) -> GovernorContractV1:
    """Evaluate all governed capabilities, circuit breakers, and optimizer mode decisions."""
    clean_harness = _norm_harness(harness_id)
    eff_build, eff_adapter, eff_req_rt, eff_report, eff_gate_req = _resolve_gov_options(runtime_cfg, harness_build_id, adapter_version, require_runtime_verified, evidence_report, evidence_gate_required)
    fp = compute_hook_config_fingerprint(clean_harness, runtime_cfg=runtime_cfg, hook_payload=hook_payload)
    stored_att, loaded_brk, _comp = _load_merged_state(state_dir)
    capabilities = {
        cap_id: evaluate_capability_contract(build_capability_attestation_key(clean_harness, cap_id, harness_build_id=eff_build, adapter_version=eff_adapter, hook_config_fingerprint=fp), stored_attestation=stored_att.get(cap_id), payload_known=bool(payload_known))
        for cap_id in GOVERNED_CAPABILITIES
    }
    verdict = eff_report.get("gate_verdict") if isinstance(eff_report, Mapping) else None
    ev_gate_passed = bool(isinstance(verdict, Mapping) and verdict.get("ok")) if isinstance(eff_report, Mapping) else (not eff_gate_req)
    raw_opts_val = runtime_cfg.get("optimizers") if isinstance(runtime_cfg, Mapping) else None
    raw_opts: Mapping[str, Any] = raw_opts_val if isinstance(raw_opts_val, Mapping) else {}
    read_policy = str(runtime_cfg.get("read_confirm_policy") or "strict").strip().lower() if isinstance(runtime_cfg, Mapping) else "strict"
    opt_ids = list(GOVERNED_OPTIMIZERS) + (["dynamic_tool_mutation"] if "dynamic_tool_mutation" in raw_opts else [])
    circuit_breakers, decisions, effective_optimizers = {}, {}, {}
    for opt_id in opt_ids:
        brk = loaded_brk.get(opt_id) or _make_breaker(opt_id)
        dec = _decide_optimizer(opt_id, str(raw_opts.get(opt_id, _DEFAULT_MODES.get(opt_id, "off"))).strip().lower(), read_confirm_policy=read_policy, capabilities=capabilities, breaker=brk, payload_known=bool(payload_known), require_runtime_verified=eff_req_rt, evidence_gate_required=eff_gate_req, evidence_gate_passed=ev_gate_passed)
        circuit_breakers[opt_id], decisions[opt_id], effective_optimizers[opt_id] = brk, dec, dec["effective_config_mode"]
    return GovernorContractV1(
        schema_version=GOVERNOR_SCHEMA_VERSION, evaluated_at=_utc_now_iso_z(), harness_id=clean_harness,
        harness_build_id=eff_build, adapter_version=eff_adapter, hook_config_fingerprint=fp,
        payload_known=bool(payload_known), evidence_gate_passed=ev_gate_passed, security_enforcement_lowered=False,
        capabilities=capabilities, circuit_breakers=circuit_breakers, decisions=decisions, effective_optimizers=effective_optimizers,
    )

def apply_runtime_governor(
    runtime_cfg: Mapping[str, Any], harness_id: str, *, state_dir: str | Path | None = None, payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply governor decisions to `runtime_cfg['optimizers']` with O(1) static parity fast path."""
    payload_known = payload is None or isinstance(payload, Mapping)
    if payload_known and not isinstance(runtime_cfg.get("governor"), Mapping):
        if all(_path_absent(p) for p in _candidate_state_paths(state_dir)):
            return dict(runtime_cfg)
    hook_payload = ({"hooks": payload["hooks"]} if isinstance(payload.get("hooks"), Mapping) else (payload["hook_payload"] if isinstance(payload.get("hook_payload"), Mapping) else None)) if isinstance(payload, Mapping) else None
    contract = evaluate_governor(harness_id, runtime_cfg=runtime_cfg, state_dir=state_dir, hook_payload=hook_payload, payload_known=payload_known)
    out = dict(runtime_cfg)
    raw_opts = runtime_cfg.get("optimizers")
    new_opts = dict(raw_opts) if isinstance(raw_opts, Mapping) else {}
    new_opts.update(contract["effective_optimizers"])
    out["optimizers"] = new_opts
    return out

def _run_builtin_release_gates() -> tuple[dict[str, bool], list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="cg_gov_replay_") as td:
        root = Path(td)
        static_cfg: dict[str, Any] = {"read_confirm_policy": "bounded", "policy_packs": [], "legacy_security_keys": (), "optimizers": {"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "off"}}
        parity_out = apply_runtime_governor(static_cfg, "antigravity", state_dir=root / "empty", payload={"tool_name": "view_file"})
        g_parity = parity_out == static_cfg and parity_out["optimizers"] == static_cfg["optimizers"]

        d_prov = root / "prov"
        c_prov = evaluate_capability_contract(build_capability_attestation_key("claude", "dynamic_tool_mutation", hook_config_fingerprint="sha256:" + "0" * 64), claimed_level="provider_supported", verification_evidence="provider_api:tool_search")
        att_prov = attest_capability("claude", "dynamic_tool_mutation", verification_evidence="model_api:tools", state_dir=d_prov)
        gov_prov = evaluate_governor("claude", runtime_cfg={"optimizers": {"dynamic_tool_mutation": "active", "output_spool": "active"}}, state_dir=d_prov)
        g_provider = bool(c_prov["provider_only_rejected"] and not c_prov["runtime_verified"] and att_prov["provider_only_rejected"] and not att_prov["runtime_verified"] and gov_prov["decisions"]["dynamic_tool_mutation"]["selected_mode"] != "active")

        d_upg = root / "upg"
        attest_capability("claude", "output_replacement", verification_evidence="client_spool_ok", harness_build_id="1.0.0", adapter_version="harness_adapter_v1", state_dir=d_upg)
        ok_b1 = evaluate_governor("claude", harness_build_id="1.0.0", state_dir=d_upg)["capabilities"]["output_replacement"]["runtime_verified"]
        inv_b2 = evaluate_governor("claude", harness_build_id="2.0.0", state_dir=d_upg)["capabilities"]["output_replacement"]
        inv_ad = evaluate_governor("claude", harness_build_id="1.0.0", adapter_version="harness_adapter_v2", state_dir=d_upg)["capabilities"]["output_replacement"]
        g_upgrade = bool(ok_b1 and not inv_b2["runtime_verified"] and inv_b2["invalidated_reason"] == "build_changed" and not inv_ad["runtime_verified"] and inv_ad["invalidated_reason"] == "adapter_changed")

        d_cfg, cfg_a, cfg_b = root / "cfg", {"optimizers": {"output_spool": "active"}}, {"optimizers": {"output_spool": "active"}, "read_confirm_policy": "bounded"}
        attest_capability("claude", "output_replacement", verification_evidence="client_spool_ok", runtime_cfg=cfg_a, state_dir=d_cfg)
        inv_cfg = evaluate_governor("claude", runtime_cfg=cfg_b, state_dir=d_cfg)["capabilities"]["output_replacement"]
        inv_unk = evaluate_governor("claude", runtime_cfg=cfg_a, state_dir=d_cfg, payload_known=False)
        g_config = bool(not inv_cfg["runtime_verified"] and inv_cfg["invalidated_reason"] == "config_fingerprint_changed" and inv_unk["capabilities"]["output_replacement"]["invalidated_reason"] == "unknown_payload" and inv_unk["decisions"]["output_spool"]["selected_mode"] == "passthrough")

        d_brk, soft_st = root / "brk", _make_breaker("output_spool")
        for sig in NON_TRIPPING_SIGNALS:
            soft_st = record_governor_signal("output_spool", sig, state_dir=d_brk)
        hard_st = record_governor_signal("output_spool", "integrity_mismatch", state_dir=d_brk)
        g_breaker = bool(soft_st["ignored_signals"] == len(NON_TRIPPING_SIGNALS) and not soft_st["tripped"] and is_optimizer_tripped("output_spool", state_dir=d_brk) and hard_st["tripped"] and hard_st["state"] == "open")

        bad_r, empty_r = reset_circuit_breaker("output_spool", state_dir=d_brk), reset_circuit_breaker("output_spool", state_dir=d_brk, verification_passed=True, verification_evidence="   ")
        still_open = is_optimizer_tripped("output_spool", state_dir=d_brk)
        good_r = reset_circuit_breaker("output_spool", state_dir=d_brk, verification_passed=True, verification_evidence="spool_verified")
        g_hysteresis = bool(not bad_r["ok"] and bad_r["error"] == "hysteresis_requires_verification_or_operator_reset" and not empty_r["ok"] and still_open and good_r["ok"] and not is_optimizer_tripped("output_spool", state_dir=d_brk))

        sec_cfg: dict[str, Any] = {"policy_packs": [{"id": "sec_guard", "enabled": True, "kind": "security", "scopes": ["shell_command"]}], "legacy_security_keys": ("restricted_bq_datasets",), "optimizers": {"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "active"}}
        record_governor_signal("output_spool", "guarantee_loss", state_dir=d_brk)
        bad_payload: Any = "unknown"
        sec_out, sec_eval = apply_runtime_governor(sec_cfg, "antigravity", state_dir=d_brk, payload=bad_payload), evaluate_governor("antigravity", runtime_cfg=sec_cfg, state_dir=d_brk, payload_known=False)
        g_security = bool(not sec_eval["security_enforcement_lowered"] and sec_out["policy_packs"] == sec_cfg["policy_packs"] and sec_out["legacy_security_keys"] == sec_cfg["legacy_security_keys"] and all(v == "off" for v in sec_out["optimizers"].values()))

        ev_fail = evaluate_governor("claude", runtime_cfg={"optimizers": {"output_spool": "active"}}, evidence_gate_required=True, evidence_report={"gate_verdict": {"ok": False}}, state_dir=root / "ev")
        ev_pass = evaluate_governor("claude", runtime_cfg={"optimizers": {"output_spool": "active"}}, evidence_gate_required=True, evidence_report={"gate_verdict": {"ok": True}}, state_dir=root / "ev")
        g_evidence = bool(not ev_fail["evidence_gate_passed"] and ev_fail["decisions"]["output_spool"]["selected_mode"] == "shadow" and ev_fail["decisions"]["output_spool"]["reason"] == "evidence_gate_not_passed" and ev_pass["evidence_gate_passed"] and ev_pass["decisions"]["output_spool"]["selected_mode"] == "active")

    gates = {"static_config_parity": g_parity, "provider_only_rejected": g_provider, "harness_upgrade_invalidation": g_upgrade, "config_change_invalidation": g_config, "breaker_trips_only_on_hard_failures": g_breaker, "hysteresis_enforced": g_hysteresis, "security_never_lowered": g_security, "evidence_gate_enforced": g_evidence}
    return gates, [{"id": name, "gate": name, "passed": passed} for name, passed in gates.items()]

def replay_governor_decisions(scenarios: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
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
                res = evaluate_governor(
                    str(raw.get("harness_id") or "claude"), runtime_cfg=raw.get("runtime_cfg") if isinstance(raw.get("runtime_cfg"), Mapping) else None,
                    state_dir=Path(td) / f"s_{idx}", harness_build_id=str(raw.get("harness_build_id") or "unavailable"),
                    adapter_version=str(raw.get("adapter_version") or ADAPTER_CONTRACT_VERSION), payload_known=bool(raw.get("payload_known", True)),
                    require_runtime_verified=bool(raw.get("require_runtime_verified", False)),
                    evidence_report=raw.get("evidence_report") if isinstance(raw.get("evidence_report"), Mapping) else None,
                    evidence_gate_required=bool(raw.get("evidence_gate_required", False)),
                )
                exp_modes, passed = raw.get("expected_modes"), not res["security_enforcement_lowered"]
                if isinstance(exp_modes, Mapping):
                    passed = passed and all(opt in res["decisions"] and res["decisions"][opt]["selected_mode"] == mode for opt, mode in exp_modes.items())
                custom_ok = custom_ok and passed
                results.append({"id": str(raw.get("id") or f"custom_{idx}"), "gate": "custom", "passed": passed})
    passed_count = sum(1 for v in gates.values() if v)
    return {"schema_version": GOVERNOR_SCHEMA_VERSION, "ok": bool(passed_count == 8 and custom_ok), "checks_passed": passed_count, "checks_total": 8, "gates": gates, "scenarios": results}
