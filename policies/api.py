"""Context-Guard public Policy API v1 contracts and harness capability tables."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

POLICY_API_VERSION = 1

ALL_SECURITY_SCOPES: tuple[str, ...] = ("file_mutation", "shell_command", "mcp_call")
VALID_POLICY_KINDS: tuple[str, ...] = ("security", "optimization")
VALID_POLICY_MODES: tuple[str, ...] = ("active", "shadow", "off")


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


__all__ = [
    "ALL_SECURITY_SCOPES",
    "HARNESS_OUTPUT_CAPABILITIES",
    "HarnessOutputCapabilities",
    "InstallerHookSpec",
    "POLICY_API_VERSION",
    "PolicyContext",
    "PolicyDecision",
    "PolicyPackManifest",
    "PolicyPostContext",
    "RuntimeCapabilities",
    "SpoolContractV1",
    "VALID_POLICY_KINDS",
    "VALID_POLICY_MODES",
]
