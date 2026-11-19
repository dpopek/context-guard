"""Context-Guard public Policy API v1 contracts and harness capability tables."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, TypedDict

POLICY_API_VERSION = 1

ALL_SECURITY_SCOPES: tuple[str, ...] = ("file_mutation", "shell_command", "mcp_call")
VALID_POLICY_KINDS: tuple[str, ...] = ("security", "optimization")
VALID_POLICY_MODES: tuple[str, ...] = ("active", "shadow", "off")
VALID_TURN_CORRELATIONS: tuple[str, ...] = ("harness_native", "transcript_derived", "unobserved")


@dataclass(frozen=True)
class PolicyDecision:
    """Pure decision produced by evaluating a tool call against a policy pack."""

    decision: str
    reason: str | None = None
    overwrite: Mapping[str, Any] | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyContext:
    """Immutable PreToolUse evaluation context passed into PolicyPackManifest.evaluate()."""

    harness: str
    call_id: str
    canonical_tool: str
    canonical_args: Mapping[str, Any]
    mutated_paths: tuple[str, ...]
    original_tool_name: str
    tool_input: Mapping[str, Any]
    cwd: str | None
    session_id: str
    step_idx: int
    state_dir: str | None
    settings: Mapping[str, Any] = field(default_factory=dict)
    permission_mode: str | None = None
    session_state_snapshot: Mapping[str, Any] = field(default_factory=dict)
    raw_command: str | None = None


@dataclass(frozen=True)
class PolicyPostContext:
    """PostToolUse / PostToolUseFailure / PostToolBatch completion notification context."""

    harness: str
    call_id: str
    canonical_tool: str
    canonical_args: Mapping[str, Any]
    mutated_paths: tuple[str, ...]
    original_tool_name: str
    tool_input: Mapping[str, Any]
    succeeded: bool
    error: str | None
    cwd: str | None
    state_dir: str | None
    settings: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InstallerHookSpec:
    """Optional host lifecycle hook command contributed by a policy pack during --install."""

    harness: str
    event_name: str
    command: str
    matcher: str | None = None
    timeout: int = 10


@dataclass(frozen=True)
class HarnessOutputCapabilities:
    """Static capability flags describing what each agentic harness supports reliably."""

    can_replace_tool_output: bool
    has_native_fail_closed_hook: bool
    supports_apply_patch_block: bool
    supports_content_verified_reads: bool


HARNESS_OUTPUT_CAPABILITIES: dict[str, HarnessOutputCapabilities] = {
    "claude": HarnessOutputCapabilities(
        can_replace_tool_output=True,
        has_native_fail_closed_hook=True,
        supports_apply_patch_block=True,
        supports_content_verified_reads=True,
    ),
    "cursor": HarnessOutputCapabilities(
        can_replace_tool_output=False,
        has_native_fail_closed_hook=True,
        supports_apply_patch_block=True,
        supports_content_verified_reads=True,
    ),
    "antigravity": HarnessOutputCapabilities(
        can_replace_tool_output=False,
        has_native_fail_closed_hook=False,
        supports_apply_patch_block=True,
        supports_content_verified_reads=False,
    ),
    "codex": HarnessOutputCapabilities(
        can_replace_tool_output=False,
        has_native_fail_closed_hook=False,
        supports_apply_patch_block=False,
        supports_content_verified_reads=False,
    ),
}


@dataclass(frozen=True)
class RuntimeCapabilities:
    """Live runtime harness capabilities detected on the host machine."""

    harness: str
    harness_version: str | None
    native_fail_closed_supported: bool
    content_verified_reads_supported: bool


@dataclass(frozen=True)
class SpoolContractV1:
    """Active reversible output spool contract returned by ``spool.store.spool_tool_output``."""

    spool_id: str
    path: str
    total_lines: int
    total_bytes: int
    content_sha256: str


RECEIPT_SCHEMA_VERSION: int = 1


class _ContextReceiptV1Required(TypedDict):
    """Required schema v1 receipt fields."""

    schema_version: int
    receipt_id: str
    event_id: str
    parent_event_id: str | None
    timestamp: str
    ts_ms: int
    hook_duration_ms: float | None
    event_type: str
    harness: str
    session_id: str
    workspace_id: str
    turn_key: str
    turn_correlation: str
    call_id: str
    tool_call_id: str
    spool_id: str
    intervention: str
    mode: str
    status: str
    line_span: tuple[int, int]
    byte_span: tuple[int, int]
    source_hash: str
    original_bytes: int
    replacement_bytes: int
    upstream_truncation: bool
    delivery_evidence: str
    spool_id_referenced: bool
    failure_kind: str | None
    reason: str | None


class ContextReceiptV1(_ContextReceiptV1Required, total=False):
    """Schema v1 receipt emitted on spool creation, delivery verification, recovery, and failures."""

    recovered_line_spans: list[tuple[int, int]]
    recovered_byte_spans: list[tuple[int, int]]
    recovered_context_bytes: int
    blob_sha256: str
    blob_bytes: int


@dataclass(frozen=True)
class PolicyPackManifest:
    """Public registration contract exported as PACK_MANIFEST by external policy packs."""

    pack_id: str
    api_version: int
    kind: str
    covered_domains: tuple[str, ...]
    evaluate: Callable[[PolicyContext], PolicyDecision | None]
    harness_matchers: Mapping[str, str] = field(default_factory=dict)
    installer_hooks: tuple[InstallerHookSpec, ...] = ()
    on_pre_decision: Callable[[PolicyContext, PolicyDecision | None], None] | None = None
    on_tool_completed: Callable[[PolicyPostContext], None] | None = None
    on_session_transition: Callable[[str, dict[str, Any], Mapping[str, Any]], None] | None = None
    inspect_config: Callable[[Mapping[str, Any]], list[str]] | None = None


EVIDENCE_SCHEMA_VERSION: int = 1
ADAPTER_CONTRACT_VERSION: str = "harness_adapter_v1"
VALID_CAPABILITY_EVIDENCE_LEVELS: tuple[str, ...] = (
    "unsupported",
    "provider_supported",
    "harness_exposed",
    "runtime_verified",
)
VALID_EVAL_TIERS: tuple[str, ...] = (
    "offline_replay",
    "small_live_pilot",
    "release_evaluation",
)
VALID_RUN_OUTCOME_CLASSES: tuple[str, ...] = (
    "passed",
    "failed_attempt",
    "external_noise",
)


@dataclass(frozen=True)
class CapabilityAttestationKey:
    """Attestation tuple binding capability claims to exact harness, build, adapter, and hook config."""

    harness_id: str
    harness_build_id: str
    adapter_version: str
    hook_config_fingerprint: str
    capability_id: str


class CapabilityRequirementV1(TypedDict):
    """Required capability record with explicit evidence level; key presence never implies runtime_verified."""

    capability_id: str
    evidence_level: str
    attestation_key: dict[str, str]
    verification_source: str
    runtime_verified: bool


class EvidenceEnvironmentMetadataV1(TypedDict):
    """Mandatory environment and capability provenance attached to every Evidence Engine artifact."""

    harness_id: str
    harness_build_id: str
    adapter_version: str
    hook_config_fingerprint: str
    context_guard_version: str
    model_id: str
    attestation_key_implies_runtime_verified: bool
    required_capabilities: list[CapabilityRequirementV1]


class EvidenceContractV1(TypedDict):
    """Schema v1 evidence report produced by offline replay, small live pilot, and release evaluation."""

    schema_version: int
    campaign_id: str
    tier: str
    generated_at: str
    statistical_proof: bool
    trajectory_claim: str
    environment: EvidenceEnvironmentMetadataV1
    arms: list[str]
    budget_contract: dict[str, Any]
    arm_summaries: dict[str, dict[str, Any]]
    paired_comparisons: list[dict[str, Any]]
    disclosed_failures: list[dict[str, Any]]
    uncertainty_bounds: dict[str, Any]
    gate_verdict: dict[str, Any]


CAPABILITY_CONTRACT_SCHEMA_VERSION: int = 1
GOVERNOR_SCHEMA_VERSION: int = 1
VALID_GOVERNOR_MODES: tuple[str, ...] = ("active", "shadow", "passthrough")
VALID_BREAKER_STATES: tuple[str, ...] = ("closed", "open", "half_open")
HARD_INTEGRITY_FAILURE_REASONS: tuple[str, ...] = (
    "integrity_mismatch", "unexpectedly_missing", "corrupt",
    "format_error", "guarantee_loss", "attestation_invalidated", "unknown_payload",
)
NON_TRIPPING_SIGNALS: tuple[str, ...] = (
    "suspected_regret", "repeat_after_spool", "verbose_override",
    "reread_trimmed_range", "chunk_thrashing", "high_recovery_amplification",
    "ttl_expired", "max_entries_lru", "max_bytes_lru",
)


class CapabilityContractV1(TypedDict):
    """Runtime capability verification contract bound to a CapabilityAttestationKey."""

    schema_version: int
    capability_id: str
    evidence_level: str
    attestation_key: dict[str, str]
    verification_evidence: str | None
    verified_at: str | None
    runtime_verified: bool
    provider_only_rejected: bool
    invalidated_reason: str | None


class CircuitBreakerStateV1(TypedDict):
    """Per-optimizer hysteresis circuit breaker state persisted in governor_state.json."""

    optimizer_id: str
    state: str
    tripped: bool
    trip_reason: str | None
    trip_count: int
    tripped_at: str | None
    last_verified_at: str | None
    ignored_signals: int
    requires_verification_or_operator_reset: bool


class OptimizerDecisionV1(TypedDict):
    """Deterministic governor decision for one optimizer against verified capabilities."""

    optimizer_id: str
    configured_mode: str
    selected_mode: str
    effective_config_mode: str
    reason: str
    required_capabilities: list[str]
    min_evidence_level: str
    observed_evidence_level: str
    breaker_state: str
    downgraded: bool


class GovernorContractV1(TypedDict):
    """Schema v1 full governor evaluation contract covering capabilities, breakers, and decisions."""

    schema_version: int
    evaluated_at: str
    harness_id: str
    harness_build_id: str
    adapter_version: str
    hook_config_fingerprint: str
    payload_known: bool
    evidence_gate_passed: bool
    security_enforcement_lowered: bool
    capabilities: dict[str, CapabilityContractV1]
    circuit_breakers: dict[str, CircuitBreakerStateV1]
    decisions: dict[str, OptimizerDecisionV1]
    effective_optimizers: dict[str, str]


EXPLAIN_SCHEMA_VERSION: int = 1
OTEL_EXPORT_SCHEMA_VERSION: int = 1
BACKEND_BENCHMARK_SCHEMA_VERSION: int = 1
VALID_DELIVERY_EVIDENCE_TIERS: tuple[str, ...] = ("delivery_verified", "replacement_emitted", "unverified")
VALID_EXPLAIN_STATES: tuple[str, ...] = (
    "available", "evicting", "evicted", "corrupt", "receipt_only", "not_spool_backed", "unknown",
)


class ExplainContractV1(TypedDict):
    """Schema v1 intervention and spool lifecycle explanation contract."""

    schema_version: int
    ok: bool
    error: str | None
    query_id: str
    matched_by: str
    event_id: str | None
    receipt_id: str | None
    spool_id: str | None
    event_type: str | None
    intervention: str | None
    harness: str | None
    session_id: str | None
    workspace_id: str | None
    mode: str | None
    status: str | None
    current_state: str
    eviction_reason: str | None
    corrupt_reason: str | None
    delivery_evidence_tier: str
    completeness: str
    privacy_scrubbed: bool
    spool_lifecycle: dict[str, Any]
    timeline: list[dict[str, Any]]
    governor_context: dict[str, Any]


class BackendBenchmarkContractV1(TypedDict):
    """Schema v1 Read Ledger storage backend benchmark and migration-gate contract."""

    schema_version: int
    ok: bool
    active_backend: str
    read_ledger_schema: int
    operations: int
    p95_budget_ms: float
    p99_budget_ms: float
    limits_exposed: bool
    alternatives_evaluated: bool
    migration_performed: bool
    decision: str
    json_lock: dict[str, Any]
    alternatives: dict[str, dict[str, Any]]


DOCTOR_SCHEMA_VERSION: int = 1
CONFORMANCE_SCHEMA_VERSION: int = 1
PLATFORM_MATRIX_SCHEMA_VERSION: int = 1
DEPRECATION_POLICY_VERSION: int = 1
MIN_DEPRECATION_MINOR_RELEASES: int = 2
SUPPORTED_HARNESS_IDS: tuple[str, ...] = ("antigravity", "claude", "cursor", "codex")
CORE_SCHEMA_VERSIONS: dict[str, int] = {
    "policy_api": POLICY_API_VERSION,
    "read_ledger": 2,
    "mutated_repos": 2,
    "spool_index": 2,
    "context_receipt": RECEIPT_SCHEMA_VERSION,
    "outcomes": 4,
    "token_usage": 3,
    "event_ledger": 1,
    "evidence_report": EVIDENCE_SCHEMA_VERSION,
    "capability_contract": CAPABILITY_CONTRACT_SCHEMA_VERSION,
    "governor_state": GOVERNOR_SCHEMA_VERSION,
    "explain_report": EXPLAIN_SCHEMA_VERSION,
    "otel_export": OTEL_EXPORT_SCHEMA_VERSION,
    "backend_benchmark": BACKEND_BENCHMARK_SCHEMA_VERSION,
    "doctor_report": DOCTOR_SCHEMA_VERSION,
    "conformance_report": CONFORMANCE_SCHEMA_VERSION,
    "platform_matrix": PLATFORM_MATRIX_SCHEMA_VERSION,
}


class DeprecationPolicyV1(TypedDict):
    """Schema v1 Policy API v1 freeze, schema deprecation, migration, and rollback policy."""

    schema_version: int
    policy_api_version: int
    policy_api_v2_mandated: bool
    external_sdk_shipped: bool
    min_deprecation_minor_releases: int
    additive_fields_non_breaking: bool
    unknown_major_policy_pack_behavior: str
    corrupt_or_future_telemetry_store_behavior: str
    backward_compatible_migrations: list[str]
    rollback_paths: list[str]
    active_deprecations: list[str]


class HarnessCapabilityMatrixRowV1(TypedDict):
    """Schema v1 verified capability and limitation contract row for one supported harness."""

    harness_id: str
    display_name: str
    config_surfaces: list[str]
    lifecycle_hooks: list[str]
    can_replace_tool_output: bool
    has_native_fail_closed_hook: bool
    supports_apply_patch_block: bool
    supports_content_verified_reads: bool
    default_range_trim_mode: str
    output_spool_delivery: str
    cli_rewrite_gate: str
    cache_telemetry: str
    turn_correlation_ceiling: str
    verified_guarantees: list[str]
    documented_limitations: list[str]


class PlatformMatrixContractV1(TypedDict):
    """Schema v1 4-harness capability & limitation matrix, schema registry, and effectiveness contract."""

    schema_version: int
    policy_api_version: int
    adapter_contract_version: str
    core_schema_versions: dict[str, int]
    harnesses: dict[str, HarnessCapabilityMatrixRowV1]
    deprecation_policy: DeprecationPolicyV1
    effectiveness_summary: dict[str, Any]


class ConformanceContractV1(TypedDict):
    """Schema v1 10-gate platform conformance report covering adapters, policy packs, migrations, and rollback."""

    schema_version: int
    ok: bool
    checked_at: str
    policy_api_version: int
    adapter_contract_version: str
    core_schema_versions: dict[str, int]
    harnesses_checked: list[str]
    adapter_conformance: dict[str, dict[str, Any]]
    baseline_policy_pack_conformance: dict[str, Any]
    migration_and_rollback_conformance: dict[str, Any]
    platform_matrix: PlatformMatrixContractV1
    gates: dict[str, bool]
    gates_passed: int
    gates_total: int
    failed_gates: list[str]


__all__ = [
    "ADAPTER_CONTRACT_VERSION", "ALL_SECURITY_SCOPES", "BACKEND_BENCHMARK_SCHEMA_VERSION",
    "BackendBenchmarkContractV1", "CAPABILITY_CONTRACT_SCHEMA_VERSION", "CONFORMANCE_SCHEMA_VERSION",
    "CORE_SCHEMA_VERSIONS", "CapabilityAttestationKey", "CapabilityContractV1", "CapabilityRequirementV1",
    "CircuitBreakerStateV1", "ConformanceContractV1", "ContextReceiptV1", "DEPRECATION_POLICY_VERSION",
    "DOCTOR_SCHEMA_VERSION", "DeprecationPolicyV1", "EVIDENCE_SCHEMA_VERSION", "EXPLAIN_SCHEMA_VERSION",
    "EvidenceContractV1", "EvidenceEnvironmentMetadataV1", "ExplainContractV1", "GOVERNOR_SCHEMA_VERSION",
    "GovernorContractV1", "HARD_INTEGRITY_FAILURE_REASONS", "HARNESS_OUTPUT_CAPABILITIES",
    "HarnessCapabilityMatrixRowV1", "HarnessOutputCapabilities", "InstallerHookSpec",
    "MIN_DEPRECATION_MINOR_RELEASES", "NON_TRIPPING_SIGNALS", "OTEL_EXPORT_SCHEMA_VERSION",
    "OptimizerDecisionV1", "PLATFORM_MATRIX_SCHEMA_VERSION", "POLICY_API_VERSION",
    "PlatformMatrixContractV1", "PolicyContext", "PolicyDecision", "PolicyPackManifest",
    "PolicyPostContext", "RECEIPT_SCHEMA_VERSION", "RuntimeCapabilities", "SUPPORTED_HARNESS_IDS",
    "SpoolContractV1", "VALID_BREAKER_STATES", "VALID_CAPABILITY_EVIDENCE_LEVELS",
    "VALID_DELIVERY_EVIDENCE_TIERS", "VALID_EVAL_TIERS", "VALID_EXPLAIN_STATES",
    "VALID_GOVERNOR_MODES", "VALID_POLICY_KINDS", "VALID_POLICY_MODES",
    "VALID_RUN_OUTCOME_CLASSES", "VALID_TURN_CORRELATIONS",
]
