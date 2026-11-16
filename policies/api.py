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


class ContextReceiptV1(TypedDict):
    """Schema v1 receipt emitted on spool creation, delivery verification, recovery, and failures."""

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


__all__ = [
    "ADAPTER_CONTRACT_VERSION",
    "ALL_SECURITY_SCOPES",
    "CapabilityAttestationKey",
    "CapabilityRequirementV1",
    "ContextReceiptV1",
    "EVIDENCE_SCHEMA_VERSION",
    "EvidenceContractV1",
    "EvidenceEnvironmentMetadataV1",
    "HARNESS_OUTPUT_CAPABILITIES",
    "HarnessOutputCapabilities",
    "InstallerHookSpec",
    "POLICY_API_VERSION",
    "PolicyContext",
    "PolicyDecision",
    "PolicyPackManifest",
    "PolicyPostContext",
    "RECEIPT_SCHEMA_VERSION",
    "RuntimeCapabilities",
    "SpoolContractV1",
    "VALID_CAPABILITY_EVIDENCE_LEVELS",
    "VALID_EVAL_TIERS",
    "VALID_POLICY_KINDS",
    "VALID_POLICY_MODES",
    "VALID_RUN_OUTCOME_CLASSES",
    "VALID_TURN_CORRELATIONS",
]
