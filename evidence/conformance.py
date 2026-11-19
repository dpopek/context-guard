"""Platform conformance suite, 4-harness capability matrix, and deprecation/migration contracts."""

from __future__ import annotations

from contextlib import contextmanager
import json, os, tempfile
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from core.platform_io import utc_now_iso_z
from core.scrub import scrub_home_paths
from services.installer_service import check_status, install_all, uninstall_all
from services.migration_guard import RollbackJournal, StagedPackTransaction
from services.replay_benchmark import run_deterministic_benchmark, run_deterministic_replay
from services.token_usage import USAGE_SCHEMA_VERSION, migrate_usage_state, restore_usage_state
from evidence.ledger import (
    EVENT_LEDGER_SCHEMA_VERSION,
    derive_outcomes_from_ledger,
    ingest_context_receipts,
    run_cursor_cli_conformance,
    run_governor_release_gates,
)
from evidence.metrics import is_verified_live_campaign_artifact
from evidence.runner import run_offline_evidence_replay
from hooks import config as hooks_config, outcomes, state_store
from hooks.harness_adapter import (
    can_rewrite_shell_command, detect_harness, extract_apply_patch_paths, format_pre_tool_output,
    normalize_line_bounds, normalize_pre_tool_payload, probe_runtime_capabilities,
)
from hooks.policy_engine import (
    PolicyPackLoadError, apply_policy_packs, apply_policy_packs_with_records, clear_pack_cache,
    infer_tool_scopes, load_verified_policy_pack, notify_session_transition, reconcile_post_transform,
    run_post_tool_hooks, run_pre_decision_hooks, verify_security_policies_post_transform,
)
from policies.api import (
    ADAPTER_CONTRACT_VERSION, BACKEND_BENCHMARK_SCHEMA_VERSION, CAPABILITY_CONTRACT_SCHEMA_VERSION,
    CONFORMANCE_SCHEMA_VERSION, CORE_SCHEMA_VERSIONS, DEPRECATION_POLICY_VERSION, DOCTOR_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION, EXPLAIN_SCHEMA_VERSION, GOVERNOR_SCHEMA_VERSION, HARNESS_OUTPUT_CAPABILITIES,
    MIN_DEPRECATION_MINOR_RELEASES, OTEL_EXPORT_SCHEMA_VERSION, PLATFORM_MATRIX_SCHEMA_VERSION,
    POLICY_API_VERSION, RECEIPT_SCHEMA_VERSION, SUPPORTED_HARNESS_IDS, VALID_EVAL_TIERS,
    ConformanceContractV1, DeprecationPolicyV1, HarnessCapabilityMatrixRowV1, PlatformMatrixContractV1, PolicyPostContext,
)
from spool.receipts import receipts_path_for
from spool.store import SPOOL_SCHEMA_VERSION, inspect_spool_entry, spool_tool_output

__all__ = [
    "build_capability_limitation_matrix", "build_deprecation_policy", "render_conformance_markdown",
    "render_platform_matrix_markdown", "replay_governor_decisions", "run_adapter_conformance_suite",
    "run_baseline_policy_pack_conformance", "run_migration_and_rollback_conformance", "run_platform_conformance_suite",
]

_ISO_ENV_KEYS = (
    "CONTEXT_GUARD_HOME", "CONTEXT_GUARD_CONFIG_PATH", "CONTEXT_GUARD_STATE_DIR", "CONTEXT_GUARD_SPOOL_DIR",
    "CONTEXT_GUARD_WORKSPACE_ROOT", "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA", "PATH",
)
_GATE_ORDER: tuple[str, ...] = (
    "policy_api_v1_frozen", "core_schema_versions_synced", "capability_matrix_complete_and_honest",
    "adapter_conformance_4_harnesses", "baseline_security_pack_conformance",
    "baseline_optimization_pack_reconciliation", "tamper_and_unknown_major_fail_closed",
    "backward_compatible_migrations_ok", "rollback_paths_verified", "effectiveness_and_limitations_published",
)


def _scrub_paths(text: str) -> str:
    return scrub_home_paths(text).replace("[redacted-path]", "~")


@contextmanager
def _isolated_env(root: Path, cfg_path: Path, state_dir: Path, spool_dir: Path, *, extra_bin: Path | None = None) -> Iterator[None]:
    saved = {k: os.environ.get(k) for k in _ISO_ENV_KEYS}
    fake_home = root / "isolated_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    hooks_config.clear_config_cache()
    clear_pack_cache()
    try:
        os.environ.pop("CONTEXT_GUARD_HOME", None)
        os.environ.pop("CONTEXT_GUARD_WORKSPACE_ROOT", None)
        os.environ["CONTEXT_GUARD_CONFIG_PATH"], os.environ["CONTEXT_GUARD_STATE_DIR"] = str(cfg_path), str(state_dir)
        os.environ["CONTEXT_GUARD_SPOOL_DIR"] = str(spool_dir)
        os.environ["HOME"] = os.environ["USERPROFILE"] = str(fake_home)
        os.environ["XDG_CONFIG_HOME"] = str(root / "xdg")
        os.environ["APPDATA"], os.environ["LOCALAPPDATA"] = str(root / "appdata"), str(root / "localappdata")
        if extra_bin is not None:
            cur = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{extra_bin}{os.pathsep}{cur}" if cur else str(extra_bin)
        yield
    finally:
        for k, prev in saved.items():
            os.environ.pop(k, None) if prev is None else os.environ.__setitem__(k, prev)
        hooks_config.clear_config_cache()
        clear_pack_cache()


def _build_live_schema_versions() -> dict[str, int]:
    return {
        "policy_api": POLICY_API_VERSION, "read_ledger": state_store.READ_LEDGER_SCHEMA,
        "mutated_repos": state_store.MUTATED_REPOS_SCHEMA, "spool_index": SPOOL_SCHEMA_VERSION,
        "context_receipt": RECEIPT_SCHEMA_VERSION, "outcomes": outcomes.SCHEMA_VERSION,
        "token_usage": USAGE_SCHEMA_VERSION, "event_ledger": EVENT_LEDGER_SCHEMA_VERSION,
        "evidence_report": EVIDENCE_SCHEMA_VERSION, "capability_contract": CAPABILITY_CONTRACT_SCHEMA_VERSION,
        "governor_state": GOVERNOR_SCHEMA_VERSION, "explain_report": EXPLAIN_SCHEMA_VERSION,
        "otel_export": OTEL_EXPORT_SCHEMA_VERSION, "backend_benchmark": BACKEND_BENCHMARK_SCHEMA_VERSION,
        "doctor_report": DOCTOR_SCHEMA_VERSION, "conformance_report": CONFORMANCE_SCHEMA_VERSION,
        "platform_matrix": PLATFORM_MATRIX_SCHEMA_VERSION,
    }


def build_deprecation_policy() -> DeprecationPolicyV1:
    """Return a fresh Schema v1 Policy API v1 freeze, migration, and rollback policy."""
    return {
        "schema_version": DEPRECATION_POLICY_VERSION, "policy_api_version": POLICY_API_VERSION,
        "policy_api_v2_mandated": False, "external_sdk_shipped": False,
        "min_deprecation_minor_releases": MIN_DEPRECATION_MINOR_RELEASES, "additive_fields_non_breaking": True,
        "unknown_major_policy_pack_behavior": "reject_fail_closed",
        "corrupt_or_future_telemetry_store_behavior": "quarantine_or_passthrough_zero_crash",
        "backward_compatible_migrations": [
            "read_ledger_v1_to_v2", "outcomes_v3_to_v4", "spool_index_v1_to_v2",
            "token_usage_legacy_to_v3", "receipts_to_evidence_ledger_v1",
        ],
        "rollback_paths": [
            "staged_pack_transaction_rollback", "rollback_journal_lifo", "ide_updater_git_reset_keep",
            "install_harnesses_uninstall", "git_tag_checkout_reinstall",
        ],
        "active_deprecations": [],
    }


def _hspec(
    name: str, surfaces: list[str], hooks: list[str], trim: str, spool: str, rewrite: str,
    cache: str, corr: str, guar: list[str], lim: list[str],
) -> dict[str, Any]:
    return {
        "display_name": name, "config_surfaces": surfaces, "lifecycle_hooks": hooks,
        "default_range_trim_mode": trim, "output_spool_delivery": spool, "cli_rewrite_gate": rewrite,
        "cache_telemetry": cache, "turn_correlation_ceiling": corr,
        "verified_guarantees": guar, "documented_limitations": lim,
    }


_HARNESS_SPECS: dict[str, dict[str, Any]] = {
    "antigravity": _hspec(
        "Google Antigravity", ["hooks.json", "rules/AGENTS.md", "vscode-extension"], ["PreInvocation", "PreToolUse", "PostToolUse"],
        "strict (0 trims until bounded opt-in)", "unsupported_no_post_tool_replacement", "allowed_non_interactive",
        "transcript_usage_when_present", "harness_native",
        ["PreToolUse exit 2 and decision=deny enforce fail-closed security and policy blocks.",
         "PreInvocation executes O(delta) transcript compaction detection (80/200 steps) and state pruning.",
         "Default read_confirm_policy=strict performs zero unverified range_trim cuts without content-verified reads."],
        ["PostToolUse cannot replace tool output payloads (can_replace_tool_output=false; output_spool replacement unavailable).",
         "Read hooks lack content-verified slice confirmation (supports_content_verified_reads=false; range_trim requires explicit bounded mode)."],
    ),
    "claude": _hspec(
        "Claude Code", ["~/.claude/settings.json", "~/.claude/CLAUDE.md"],
        ["PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch", "PreCompact", "SessionEnd"],
        "strict (tier-2 content-verified reads)", "native_post_tool_replacement_and_cg_spool_cli",
        "auto_approved_permission_modes_only (bypassPermissions, dontAsk, auto)",
        "transcript_cache_read_and_cache_creation_tokens", "transcript_derived",
        ["PostToolUse supports reversible output_spool replacement with SHA-256 verified cg-spool recovery.",
         "Tier-2 content-verified reads enable strict range_trim and auto_outline without stale-slice blind spots.",
         "CLI vs Desktop (mcp:ccd_*) sessions and subagents stay isolated across session state and usage ledgers."],
        ["Native onFailure=block fail-closed hook requires Claude CLI >= 2.1.295; older versions degrade and are flagged by cg doctor.",
         "Silent CLI flag rewrites stay suppressed outside AUTO_APPROVED_PERMISSION_MODES to preserve interactive approval prompts."],
    ),
    "cursor": _hspec(
        "Cursor", ["~/.cursor/hooks.json", "~/.cursor/mcp.json", "vscode-extension"], ["preToolUse", "postToolUse", "preCompact"],
        "strict (tier-2 content-verified reads)", "shadow_or_mcp_cli_only_no_post_tool_replacement",
        "auto_approved_permission_modes_only (bypassPermissions, dontAsk, auto)", "excluded_missing_telemetry", "transcript_derived",
        ["Native failClosed=true preToolUse hook enforces deterministic policy blocks.",
         "Tier-2 content-verified reads confirm delivered line slices in postToolUse.",
         "Missing Cursor CLI prompt-cache breakdown is reported honestly as excluded_missing_telemetry (never synthetic 0)."],
        ["postToolUse cannot replace tool output payloads in-band (can_replace_tool_output=false; spool recovery relies on MCP/CLI).",
         "Cursor CLI transcripts omit granular cache read/write token counters (cache_attribution_status=excluded_missing_telemetry)."],
    ),
    "codex": _hspec(
        "OpenAI Codex", ["~/.codex/hooks.json", "~/.codex/config.toml", "~/.codex/AGENTS.md"], ["PreToolUse", "PostToolUse", "PreCompact"],
        "strict (0 trims until bounded opt-in)", "unsupported_no_post_tool_replacement",
        "disabled_preserves_command_approval_integrity", "rollout_cached_input_tokens", "transcript_derived",
        ["PreToolUse intercepts shell and standard file/MCP tool calls when [features].hooks=true is enabled.",
         "Codex config.toml synchronization preserves trusted workspace hashes and compaction limits.",
         "Silent shell CLI rewrites remain disabled by contract so interactive command approval prompts never drift."],
        ["Native apply_patch bypasses PreToolUse interception upstream (supports_apply_patch_block=false).",
         "Hook execution requires [features].hooks=true and a trusted working directory (Codex trust gate / #27833), without PostToolUse output replacement."],
    ),
}


def build_capability_limitation_matrix(
    *, include_offline_benchmarks: bool | None = None, include_live_effectiveness: bool = False,
    live_campaign_artifact: Mapping[str, Any] | None = None,
) -> PlatformMatrixContractV1:
    """Build the authoritative 4-harness capability/limitation matrix and effectiveness summary."""
    run_offline = include_offline_benchmarks if include_offline_benchmarks is not None else bool(include_live_effectiveness)
    live_ok = is_verified_live_campaign_artifact(live_campaign_artifact)
    harnesses: dict[str, HarnessCapabilityMatrixRowV1] = {
        hid: {
            "harness_id": hid, "display_name": str((spec := _HARNESS_SPECS[hid])["display_name"]),
            "config_surfaces": list(spec["config_surfaces"]), "lifecycle_hooks": list(spec["lifecycle_hooks"]),
            "can_replace_tool_output": bool((caps := HARNESS_OUTPUT_CAPABILITIES[hid]).can_replace_tool_output),
            "has_native_fail_closed_hook": bool(caps.has_native_fail_closed_hook),
            "supports_apply_patch_block": bool(caps.supports_apply_patch_block),
            "supports_content_verified_reads": bool(caps.supports_content_verified_reads),
            "default_range_trim_mode": str(spec["default_range_trim_mode"]),
            "output_spool_delivery": str(spec["output_spool_delivery"]),
            "cli_rewrite_gate": str(spec["cli_rewrite_gate"]), "cache_telemetry": str(spec["cache_telemetry"]),
            "turn_correlation_ceiling": str(spec["turn_correlation_ceiling"]),
            "verified_guarantees": list(spec["verified_guarantees"]), "documented_limitations": list(spec["documented_limitations"]),
        }
        for hid in SUPPORTED_HARNESS_IDS
    }
    eff: dict[str, Any] = {
        "primary_release_metric": "Cost per Passed Run", "evaluation_tiers": list(VALID_EVAL_TIERS),
        "offline_replay_statistical_proof": False, "offline_replay_scope": "deterministic_contract_integrity_and_latency_only",
        "outcomes_cost_impact_semantics": "observational_1_over_k_step_weighted_non_causal",
        "failed_attempts_excluded": False, "endogenous_ttl_cache_misses_excluded": False,
        "cursor_cli_cache_policy": "excluded_missing_telemetry", "offline_benchmarks_included": bool(run_offline),
        "live_benchmarks_included": live_ok, "live_campaign_status": "verified_live_campaign" if live_ok else "not_included",
        "methodological_limitations": [
            "Local deterministic replay and 1-iteration benchmark are offline checks (statistical_proof=false), not live effectiveness proof.",
            "Outcomes v4 Estimated Cost Impact uses observational 1/k step-weighted attribution and is never causal A/B proof.",
            "Failed attempts and endogenous TTL prompt-cache misses are never excluded from Cost per Passed Run.",
            "Cursor CLI cache attribution is reported as excluded_missing_telemetry rather than coerced to 0.",
        ],
    }
    if run_offline:
        rep, bench, ev = run_deterministic_replay(), run_deterministic_benchmark(iterations=1), run_offline_evidence_replay()
        v_map = v if isinstance((v := ev.get("gate_verdict")), Mapping) else {}
        c_map = c if isinstance((c := v_map.get("checks")), Mapping) else {}
        be_map = b if isinstance((b := bench.get("backend_evaluation")), Mapping) else {}
        eff["deterministic_replay"] = {
            "ok": bool(rep.get("ok")), "read_ledger_schema": int(rep.get("read_ledger_schema", 0) or 0),
            "outcomes_schema": int(rep.get("outcomes_schema", 0) or 0),
            "modes_checked": [str(m.get("mode")) for m in (rep.get("modes") or []) if isinstance(m, Mapping)],
        }
        eff["latency_benchmark"] = {
            "ok": bool(bench.get("ok")), "in_process_latency_ms": dict(bench.get("in_process_latency_ms") or {}),
            "subprocess_latency_ms": dict(bench.get("subprocess_latency_ms") or {}),
            "savings_pct": float(bench.get("savings_pct", 0.0) or 0.0), "backend_decision": str(be_map.get("decision") or ""),
        }
        eff["offline_evidence_replay"] = {
            "ok": bool(v_map.get("ok")), "tier": str(ev.get("tier") or ""), "statistical_proof": bool(ev.get("statistical_proof")),
            "arms": list(ev.get("arms") or []), "hardening_gate_ok": bool(c_map.get("hardening_gate_ok")),
        }
    return {
        "schema_version": PLATFORM_MATRIX_SCHEMA_VERSION, "policy_api_version": POLICY_API_VERSION,
        "adapter_contract_version": ADAPTER_CONTRACT_VERSION, "core_schema_versions": dict(CORE_SCHEMA_VERSIONS),
        "harnesses": harnesses, "deprecation_policy": build_deprecation_policy(), "effectiveness_summary": eff,
    }


def run_adapter_conformance_suite() -> dict[str, dict[str, Any]]:
    """Run deterministic 4-harness adapter normalization, verdict, permission, and capability conformance."""
    ws = "/workspace/project"
    exp_a, exp_b, exp_c = str(Path(ws) / "src/a.py"), str(Path(ws) / "src/b.py"), str(Path(ws) / "src/c.py")
    bounds_ok = (
        normalize_line_bounds(5, 20) == (5, 20, False) and normalize_line_bounds(20, 5) == (20, -1, True)
        and normalize_line_bounds(None, None, offset_raw=10, limit_raw=5, has_start_key=False, has_end_key=False) == (10, 14, False)
    )
    ag_rd = normalize_pre_tool_payload({"toolCall": {"name": "read_file", "args": {"Path": "src/a.py", "StartLine": 1, "EndLine": 25}, "id": "ag-1"}, "cwd": ws, "stepIdx": 2})
    ag_vw = normalize_pre_tool_payload({"toolCall": {"name": "view_file", "args": {"AbsolutePath": "src/a.py"}, "id": "ag-2"}, "cwd": ws})
    ag_mut = normalize_pre_tool_payload({"toolCall": {"name": "write_file", "args": {"Path": "src/b.py"}, "id": "ag-3"}, "cwd": ws})
    ag_sh = normalize_pre_tool_payload({"toolCall": {"name": "run_command", "args": {"CommandLine": "pytest -q"}, "id": "ag-4"}, "cwd": ws})
    ag_mcp = normalize_pre_tool_payload({"toolCall": {"name": "mcp_srv_tool", "args": {"q": "1"}, "id": "ag-5"}, "cwd": ws})
    ag_rc, ag_st = probe_runtime_capabilities("antigravity"), HARNESS_OUTPUT_CAPABILITIES["antigravity"]
    ag_checks = {
        "detect_harness": detect_harness({"toolCall": {"name": "read_file", "args": {}}, "stepIdx": 1}, env={}) == "antigravity",
        "normalize_read": ag_rd.canonical_tool == "read_file" and ag_rd.canonical_args.get("Path") == exp_a and ag_vw.canonical_tool == "view_file",
        "normalize_mutation": ag_mut.canonical_tool == "write_file" and ag_mut.mutated_paths == (exp_b,),
        "normalize_shell": ag_sh.canonical_tool == "run_command" and ag_sh.canonical_args.get("CommandLine") == "pytest -q",
        "normalize_mcp": "mcp_call" in infer_tool_scopes(ag_mcp), "line_bounds": bounds_ok,
        "format_verdicts": (
            format_pre_tool_output({"decision": "deny", "reason": "r"}, ag_sh) == {"decision": "deny", "reason": "r"}
            and format_pre_tool_output({"decision": "allow", "overwrite": {"StartLine": 5}}, ag_rd)
            == {"decision": "allow", "overwrite": {"StartLine": 5}}
        ),
        "rewrite_permission_gate": can_rewrite_shell_command(ag_sh) is True,
        "runtime_capabilities": ag_rc.native_fail_closed_supported == ag_st.has_native_fail_closed_hook and ag_rc.content_verified_reads_supported == ag_st.supports_content_verified_reads,
    }
    cl_rd = normalize_pre_tool_payload({"tool_name": "Read", "tool_input": {"file_path": "src/a.py", "offset": 10, "limit": 20}, "cwd": ws, "tool_use_id": "cl-1"}, cli_harness="claude")
    cl_nb = normalize_pre_tool_payload({"tool_name": "NotebookRead", "tool_input": {"notebook_path": "src/a.py", "cell_id": "cell-1"}, "cwd": ws}, cli_harness="claude")
    cl_ed = normalize_pre_tool_payload({"tool_name": "Edit", "tool_input": {"file_path": "src/b.py"}, "cwd": ws}, cli_harness="claude")
    cl_wr = normalize_pre_tool_payload({"tool_name": "Write", "tool_input": {"file_path": "src/c.py"}, "cwd": ws}, cli_harness="claude")
    cl_sh_auto = normalize_pre_tool_payload({"tool_name": "Bash", "tool_input": {"command": "git status"}, "permission_mode": "bypassPermissions", "cwd": ws}, cli_harness="claude")
    cl_sh_ask = normalize_pre_tool_payload({"tool_name": "Bash", "tool_input": {"command": "git status"}, "permission_mode": "default", "cwd": ws}, cli_harness="claude")
    cl_mcp = normalize_pre_tool_payload({"tool_name": "mcp__srv__tool", "tool_input": {}, "cwd": ws}, cli_harness="claude")
    cl_ow = format_pre_tool_output({"decision": "allow", "overwrite": {"StartLine": 15, "EndLine": 24}}, cl_rd).get("hookSpecificOutput", {})
    cl_deny = format_pre_tool_output({"decision": "deny", "reason": "blocked"}, cl_sh_auto).get("hookSpecificOutput", {})
    cl_old, cl_new, cl_st = probe_runtime_capabilities("claude", "2.1.200"), probe_runtime_capabilities("claude", "2.1.295"), HARNESS_OUTPUT_CAPABILITIES["claude"]
    cl_checks = {
        "detect_harness": detect_harness({"tool_name": "Read", "tool_input": {}, "transcript_path": "/tmp/.claude/projects/s.jsonl"}, env={}) == "claude",
        "normalize_read": cl_rd.canonical_tool == "read_file" and cl_rd.canonical_args == {"Path": exp_a, "StartLine": 10, "EndLine": 29} and cl_nb.canonical_tool == "NotebookRead",
        "normalize_mutation": cl_ed.canonical_tool == "edit_file" and cl_ed.mutated_paths == (exp_b,) and cl_wr.canonical_tool == "write_file" and cl_wr.mutated_paths == (exp_c,),
        "normalize_shell": cl_sh_auto.canonical_tool == "run_command" and cl_sh_auto.canonical_args == {"CommandLine": "git status"},
        "normalize_mcp": "mcp_call" in infer_tool_scopes(cl_mcp), "line_bounds": bounds_ok,
        "format_verdicts": (
            format_pre_tool_output({"decision": "allow"}, cl_rd) == {}
            and cl_deny.get("permissionDecision") == "deny"
            and cl_ow.get("updatedInput", {}).get("offset") == 15
            and cl_ow.get("updatedInput", {}).get("limit") == 10
        ),
        "rewrite_permission_gate": can_rewrite_shell_command(cl_sh_auto) is True and can_rewrite_shell_command(cl_sh_ask) is False,
        "runtime_capabilities": (
            cl_old.native_fail_closed_supported is False
            and cl_new.native_fail_closed_supported is True
            and cl_new.content_verified_reads_supported == cl_st.supports_content_verified_reads
        ),
    }
    cu_cli = run_cursor_cli_conformance()
    cu_rd = normalize_pre_tool_payload({"tool_name": "Read", "tool_input": {"path": "src/a.py", "StartLine": 2, "EndLine": 8}, "cwd": ws}, cli_harness="cursor")
    cu_mut = normalize_pre_tool_payload({"tool_name": "Write", "tool_input": {"path": "src/b.py"}, "cwd": ws}, cli_harness="cursor")
    cu_sh_auto = normalize_pre_tool_payload({"tool_name": "Shell", "tool_input": {"command": "pytest"}, "permission_mode": "auto", "cwd": ws}, cli_harness="cursor")
    cu_sh_ask = normalize_pre_tool_payload({"tool_name": "Shell", "tool_input": {"command": "pytest"}, "cwd": ws}, cli_harness="cursor")
    cu_mcp = normalize_pre_tool_payload({"tool_name": "MCP:tool", "tool_input": {}, "cwd": ws}, cli_harness="cursor")
    cu_ow = format_pre_tool_output({"decision": "allow", "overwrite": {"CommandLine": "pytest -q"}}, cu_sh_auto).get("hookSpecificOutput", {})
    cu_rc, cu_st = probe_runtime_capabilities("cursor"), HARNESS_OUTPUT_CAPABILITIES["cursor"]
    cu_checks = {
        "detect_harness": detect_harness({"tool_name": "Read", "tool_input": {}, "cursor_version": "1.0.0"}, env={}) == "cursor",
        "normalize_read": cu_rd.canonical_tool == "read_file" and cu_rd.canonical_args == {"Path": exp_a, "StartLine": 2, "EndLine": 8},
        "normalize_mutation": cu_mut.canonical_tool == "write_file" and cu_mut.mutated_paths == (exp_b,),
        "normalize_shell": cu_sh_auto.canonical_tool == "run_command" and cu_sh_auto.canonical_args == {"CommandLine": "pytest"},
        "normalize_mcp": "mcp_call" in infer_tool_scopes(cu_mcp), "line_bounds": bounds_ok,
        "format_verdicts": cu_ow.get("permissionDecision") == "allow" and cu_ow.get("updatedInput", {}).get("command") == "pytest -q",
        "rewrite_permission_gate": can_rewrite_shell_command(cu_sh_auto) is True and can_rewrite_shell_command(cu_sh_ask) is False,
        "runtime_capabilities": cu_rc.native_fail_closed_supported == cu_st.has_native_fail_closed_hook and cu_rc.content_verified_reads_supported == cu_st.supports_content_verified_reads,
        "cursor_cli_conformance": bool(cu_cli.get("ok")) and cu_cli.get("cache_attribution_status") == "excluded_missing_telemetry",
    }
    patch_txt = "*** Begin Patch\n*** Update File: src/b.py\n@@\n-x\n+y\n*** Add File: src/c.py\n+z\n*** End Patch\n"
    cx_rd = normalize_pre_tool_payload({"tool_name": "read_file", "tool_input": {"path": "src/a.py", "offset": 1, "limit": 12}, "cwd": ws}, cli_harness="codex")
    cx_ap = normalize_pre_tool_payload({"tool_name": "apply_patch", "tool_input": {"patch": patch_txt}, "cwd": ws}, cli_harness="codex")
    cx_sh = normalize_pre_tool_payload({"tool_name": "exec_command", "tool_input": {"cmd": "git diff"}, "permission_mode": "auto", "cwd": ws}, cli_harness="codex")
    cx_mcp = normalize_pre_tool_payload({"tool_name": "mcp_srv_tool", "tool_input": {}, "cwd": ws}, cli_harness="codex")
    cx_ow = format_pre_tool_output({"decision": "allow", "overwrite": {"CommandLine": "git diff --stat"}}, cx_sh).get("hookSpecificOutput", {})
    cx_rc, cx_st = probe_runtime_capabilities("codex"), HARNESS_OUTPUT_CAPABILITIES["codex"]
    cx_checks = {
        "detect_harness": detect_harness({"tool_name": "exec_command", "tool_input": {}}, env={"CODEX_CI": "1"}) == "codex",
        "normalize_read": cx_rd.canonical_tool == "read_file" and cx_rd.canonical_args == {"Path": exp_a, "StartLine": 1, "EndLine": 12},
        "normalize_mutation": cx_ap.canonical_tool == "edit_file" and cx_ap.mutated_paths == (exp_b, exp_c) and extract_apply_patch_paths(patch_txt, cwd=ws) == [exp_b, exp_c],
        "normalize_shell": cx_sh.canonical_tool == "run_command" and cx_sh.canonical_args == {"CommandLine": "git diff"},
        "normalize_mcp": "mcp_call" in infer_tool_scopes(cx_mcp), "line_bounds": bounds_ok,
        "format_verdicts": cx_ow.get("permissionDecision") == "allow" and cx_ow.get("updatedInput", {}).get("cmd") == "git diff --stat",
        "rewrite_permission_gate": can_rewrite_shell_command(cx_sh) is False,
        "runtime_capabilities": cx_rc.native_fail_closed_supported is False and cx_rc.content_verified_reads_supported is False and cx_st.supports_apply_patch_block is False,
    }
    return {
        "antigravity": {"ok": all(ag_checks.values()), "harness_id": "antigravity", "checks": ag_checks},
        "claude": {"ok": all(cl_checks.values()), "harness_id": "claude", "checks": cl_checks},
        "cursor": {
            "ok": all(cu_checks.values()), "harness_id": "cursor", "cache_attribution_status": str(cu_cli.get("cache_attribution_status") or ""),
            "verification_scope": "adapter_contract_only", "adapter_conformance_passed": bool(cu_cli.get("ok")), "runtime_verified": False, "checks": cu_checks,
        },
        "codex": {"ok": all(cx_checks.values()), "harness_id": "codex", "checks": cx_checks},
    }


_SEC_PACK_SRC = (
    "from __future__ import annotations\nfrom pathlib import Path\n"
    "from policies.api import ALL_SECURITY_SCOPES, PolicyDecision, PolicyPackManifest\n"
    "def evaluate(ctx):\n"
    "    if 'rm -rf /forbidden' in str(ctx.canonical_args.get('CommandLine') or ''): return PolicyDecision(decision='deny', reason='forbidden_command')\n"
    "    if any(str(p).endswith('forbidden.txt') for p in ctx.mutated_paths): return PolicyDecision(decision='deny', reason='forbidden_path')\n"
    "    return None\n"
    "def on_pre_decision(ctx, dec):\n"
    "    if ctx.state_dir:\n"
    "        p = Path(ctx.state_dir) / 'pack_hooks.log'\n"
    "        p.write_text((p.read_text(encoding='utf-8') if p.is_file() else '') + f\"pre:{dec.decision if dec else 'none'}\\n\", encoding='utf-8')\n"
    "def on_tool_completed(post_ctx):\n"
    "    if post_ctx.state_dir:\n"
    "        p = Path(post_ctx.state_dir) / 'pack_hooks.log'\n"
    "        p.write_text((p.read_text(encoding='utf-8') if p.is_file() else '') + f'post:{post_ctx.canonical_tool}:{post_ctx.succeeded}\\n', encoding='utf-8')\n"
    "def on_session_transition(event, state, settings): state.setdefault('transitions', []).append(event)\n"
    "def inspect_config(settings): return ['empty_guard_tag'] if settings.get('guard_tag') == '' else []\n"
    "PACK_MANIFEST = PolicyPackManifest(\n"
    "    pack_id='baseline_sec', api_version=1, kind='security', covered_domains=ALL_SECURITY_SCOPES,\n"
    "    evaluate=evaluate, on_pre_decision=on_pre_decision, on_tool_completed=on_tool_completed,\n"
    "    on_session_transition=on_session_transition, inspect_config=inspect_config,\n"
    ")\n"
)
_OPT_PACK_SRC = (
    "from __future__ import annotations\nfrom policies.api import PolicyDecision, PolicyPackManifest\n"
    "def evaluate(ctx):\n"
    "    cmd = str(ctx.canonical_args.get('CommandLine') or '')\n"
    "    if cmd == 'run_safe_opt': return PolicyDecision(decision='allow', overwrite={'CommandLine': 'run_safe_opt --quiet'})\n"
    "    if cmd == 'run_unsafe_opt': return PolicyDecision(decision='allow', overwrite={'CommandLine': 'rm -rf /forbidden'})\n"
    "    return None\n"
    "PACK_MANIFEST = PolicyPackManifest(pack_id='baseline_opt', api_version=1, kind='optimization', covered_domains=(), evaluate=evaluate)\n"
)
_SCOPED_PACK_TPL = (
    "from __future__ import annotations\nfrom policies.api import PolicyPackManifest\n"
    "def evaluate(ctx): return None\n"
    "PACK_MANIFEST = PolicyPackManifest(pack_id='{pid}', api_version={ver}, kind='security', covered_domains=('shell_command',), evaluate=evaluate)\n"
)


def _stage_and_commit(src: Path, cfg_path: Path) -> None:
    tx = StagedPackTransaction(src, config_path=cfg_path)
    tx.prepare()
    tx.validate()
    tx.activate()
    tx.commit()
    hooks_config.clear_config_cache()


def _run_packs_in_dir(root: Path) -> dict[str, Any]:
    cfg_path, state_dir, spool_dir, ws_dir = root / "cfg" / "config.json", root / "state", root / "spool", root / "ws"
    sec_src, opt_src, v2_src, scoped_src = root / "src_sec", root / "src_opt", root / "src_v2", root / "src_scoped"
    for d in (cfg_path.parent, state_dir, spool_dir, ws_dir, sec_src, opt_src, v2_src, scoped_src):
        d.mkdir(parents=True, exist_ok=True)
    (sec_src / "pack.py").write_text(_SEC_PACK_SRC, encoding="utf-8")
    (opt_src / "pack.py").write_text(_OPT_PACK_SRC, encoding="utf-8")
    (v2_src / "pack.py").write_text(_SCOPED_PACK_TPL.format(pid="future_v2", ver=2), encoding="utf-8")
    (scoped_src / "pack.py").write_text(_SCOPED_PACK_TPL.format(pid="scoped_sec", ver=1), encoding="utf-8")

    with _isolated_env(root, cfg_path, state_dir, spool_dir):
        _stage_and_commit(sec_src, cfg_path)
        rt_sec = hooks_config.load_runtime_config(cfg_path)
        manifest = load_verified_policy_pack((rt_sec.get("policy_packs") or [{}])[0], config_path=cfg_path, cwd=str(ws_dir))
        insp_bad = manifest.inspect_config({"guard_tag": ""}) if manifest.inspect_config else []
        insp_ok = manifest.inspect_config({"guard_tag": "ok"}) if manifest.inspect_config else ["missing"]
        bad_sh = normalize_pre_tool_payload({"tool_name": "Bash", "tool_input": {"command": "rm -rf /forbidden"}, "cwd": str(ws_dir)}, cli_harness="claude")
        safe_sh = normalize_pre_tool_payload({"tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": str(ws_dir)}, cli_harness="claude")
        dec_deny, recs_deny, _, _ = apply_policy_packs_with_records(bad_sh, rt_sec, state_dir_path=state_dir)
        dec_allow, recs_allow, _, _ = apply_policy_packs_with_records(safe_sh, rt_sec, state_dir_path=state_dir)
        p2_bad = verify_security_policies_post_transform(bad_sh, rt_sec, state_dir_path=state_dir)
        p2_good = verify_security_policies_post_transform(safe_sh, rt_sec, state_dir_path=state_dir)
        pre_cb_ok = run_pre_decision_hooks(recs_deny) and run_pre_decision_hooks(recs_allow)
        run_post_tool_hooks(PolicyPostContext(
            harness="claude", call_id="c-1", canonical_tool="run_command", canonical_args={"CommandLine": "git status"},
            mutated_paths=(), original_tool_name="Bash", tool_input={"command": "git status"},
            succeeded=True, error=None, cwd=str(ws_dir), state_dir=str(state_dir),
        ), rt_sec)
        sess_state: dict[str, Any] = {}
        notify_session_transition("compaction", sess_state, rt_sec)
        hook_log = (state_dir / "pack_hooks.log").read_text(encoding="utf-8") if (state_dir / "pack_hooks.log").is_file() else ""

        _stage_and_commit(opt_src, cfg_path)
        rt_both = hooks_config.load_runtime_config(cfg_path)
        n_safe_opt = normalize_pre_tool_payload({"tool_name": "Bash", "tool_input": {"command": "run_safe_opt"}, "cwd": str(ws_dir)}, cli_harness="claude")
        n_unsafe_opt = normalize_pre_tool_payload({"tool_name": "Bash", "tool_input": {"command": "run_unsafe_opt"}, "cwd": str(ws_dir)}, cli_harness="claude")
        _, _, cand_safe, ow_safe = apply_policy_packs_with_records(n_safe_opt, rt_both, state_dir_path=state_dir)
        _, _, cand_unsafe, ow_unsafe = apply_policy_packs_with_records(n_unsafe_opt, rt_both, state_dir_path=state_dir)
        rec_safe, _ = reconcile_post_transform(cand_safe, rt_both, fallback_norm=n_safe_opt, state_dir_path=state_dir)
        rec_discard, _ = reconcile_post_transform(cand_unsafe, rt_both, fallback_norm=n_unsafe_opt, state_dir_path=state_dir)
        rec_deny, rec_deny_payload = reconcile_post_transform(cand_unsafe, rt_both, fallback_norm=bad_sh, state_dir_path=state_dir)

        cfg_before_v2, tx_v2, v2_rejected = cfg_path.read_bytes(), StagedPackTransaction(v2_src, config_path=cfg_path), False
        tx_v2.prepare()
        try:
            tx_v2.validate()
        except PolicyPackLoadError:
            v2_rejected = True
        v2_clean = v2_rejected and cfg_path.read_bytes() == cfg_before_v2 and not [
            p.name for p in (cfg_path.parent / "policies").iterdir() if p.name.startswith(".staging-")
        ]

        scoped_cfg_path = root / "scoped_cfg" / "config.json"
        scoped_cfg_path.parent.mkdir(parents=True, exist_ok=True)
        scoped_cfg_path.write_text(json.dumps({"policy_packs": [{"id": "scoped_sec", "scopes": ["shell_command"]}]}), encoding="utf-8")
        _stage_and_commit(scoped_src, scoped_cfg_path)
        rt_scoped = hooks_config.load_runtime_config(scoped_cfg_path)
        live_pack_py = scoped_cfg_path.parent / "policies" / "scoped_sec" / "pack.py"
        live_pack_py.write_bytes(live_pack_py.read_bytes() + b"\n")
        clear_pack_cache()
        tamper_load_err = False
        try:
            load_verified_policy_pack((rt_scoped.get("policy_packs") or [{}])[0], config_path=scoped_cfg_path, cwd=str(ws_dir))
        except PolicyPackLoadError:
            tamper_load_err = True
        n_read = normalize_pre_tool_payload({"tool_name": "Read", "tool_input": {"file_path": "a.py"}, "cwd": str(ws_dir)}, cli_harness="claude")
        n_write = normalize_pre_tool_payload({"tool_name": "Write", "tool_input": {"file_path": "a.py"}, "cwd": str(ws_dir)}, cli_harness="claude")
        tamper_sh_dec = apply_policy_packs(safe_sh, rt_scoped, state_dir_path=state_dir)
        tamper_rd_dec = apply_policy_packs(n_read, rt_scoped, state_dir_path=state_dir)
        tamper_wr_dec = apply_policy_packs(n_write, rt_scoped, state_dir_path=state_dir)

    checks = {
        "pass1_deny": isinstance(dec_deny, Mapping) and dec_deny.get("decision") == "deny" and dec_allow is None,
        "post_transform_verify": isinstance(p2_bad, Mapping) and p2_bad.get("decision") == "deny" and p2_good is None,
        "callbacks_fired": bool(pre_cb_ok and "pre:deny" in hook_log and "post:run_command:True" in hook_log and sess_state.get("transitions") == ["compaction"]),
        "inspect_config_validated": insp_bad == ["empty_guard_tag"] and insp_ok == [],
        "pass2_safe_allow": ow_safe == {"CommandLine": "run_safe_opt --quiet"} and rec_safe == "allow",
        "pass2_unsafe_discard": ow_unsafe == {"CommandLine": "rm -rf /forbidden"} and rec_discard == "discard",
        "pass2_both_bad_deny": rec_deny == "deny" and isinstance(rec_deny_payload, Mapping) and rec_deny_payload.get("decision") == "deny",
        "tamper_in_scope_denied": tamper_load_err and isinstance(tamper_sh_dec, Mapping) and tamper_sh_dec.get("decision") == "deny",
        "tamper_out_of_scope_allowed": tamper_rd_dec is None and tamper_wr_dec is None,
        "api_v2_rejected_cleanly": v2_clean,
    }
    sec_ok = bool(checks["pass1_deny"] and checks["post_transform_verify"] and checks["callbacks_fired"] and checks["inspect_config_validated"])
    opt_ok = bool(checks["pass2_safe_allow"] and checks["pass2_unsafe_discard"] and checks["pass2_both_bad_deny"])
    tamper_ok = bool(checks["tamper_in_scope_denied"] and checks["tamper_out_of_scope_allowed"] and checks["api_v2_rejected_cleanly"])
    return {
        "ok": sec_ok and opt_ok and tamper_ok, "security_pack_ok": sec_ok,
        "optimization_reconciliation_ok": opt_ok, "tamper_and_unknown_major_ok": tamper_ok, "checks": checks,
    }


def _in_work_dir(work_dir: Path | None, prefix: str, fn: Any) -> Any:
    if work_dir is not None:
        (wd := Path(work_dir).resolve()).mkdir(parents=True, exist_ok=True)
        return fn(wd)
    with tempfile.TemporaryDirectory(prefix=prefix) as td:
        return fn(Path(td).resolve())


def run_baseline_policy_pack_conformance(work_dir: Path | None = None) -> dict[str, Any]:
    """Verify Policy API v1 security/optimization packs, Pass-2 reconciliation, tamper, and api_version=2 rejection."""
    res: dict[str, Any] = _in_work_dir(work_dir, "cg_pack_conf_", _run_packs_in_dir)
    return res


def _run_migrations_in_dir(root: Path) -> dict[str, Any]:
    cfg_path, state_dir, spool_dir = root / "cfg" / "config.json", root / "state", root / "spool"
    h_root, shims_dir = root / "harnesses", root / "harnesses" / "bin"
    for d in (cfg_path.parent, state_dir, spool_dir, shims_dir):
        d.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text("{}", encoding="utf-8")
    schemas_synced = dict(CORE_SCHEMA_VERSIONS) == _build_live_schema_versions() and len(CORE_SCHEMA_VERSIONS) == 17

    with _isolated_env(root, cfg_path, state_dir, spool_dir, extra_bin=shims_dir):
        v1_dir, bad_state_dir = root / "ledger_v1", root / "ledger_corrupt"
        bad_spool_dir, v1_spool_dir, ws_dir = root / "spool_bad", root / "spool_v1", root / "ws_spool"
        j_file, j_live, j_stage = root / "rb_file.txt", root / "rb_live", root / "rb_stage"
        rb_cfg, rb_src = root / "rb_pack" / "config.json", root / "rb_pack_src"
        cl_cfg, cu_cfg = h_root / "claude" / "settings.json", h_root / "cursor" / "hooks.json"
        cu_mcp, cx_hooks, cx_toml = h_root / "cursor" / "mcp.json", h_root / "codex" / "hooks.json", h_root / "codex" / "config.toml"
        for d in (v1_dir, bad_state_dir, bad_spool_dir, v1_spool_dir, ws_dir / ".git", j_live, j_stage, rb_cfg.parent, rb_src, cl_cfg.parent, cu_cfg.parent, cx_hooks.parent):
            d.mkdir(parents=True, exist_ok=True)

        state_store.state_file_in(v1_dir).write_text(json.dumps({
            "schema_version": 1, "read_ledger_schema": 1, "mutated_repos_schema": 1, "mutated_repos": ["legacy"],
            "files": {"sample.py": {"reads": [[1, 40, 1]], "pending_reads": {"c1": {"step": 1}}}},
        }), encoding="utf-8")
        with state_store.locked_state(v1_dir) as txn:
            v1_migrated = txn.state.get("read_ledger_schema") == state_store.READ_LEDGER_SCHEMA and txn.state["files"]["sample.py"]["reads"] == []
        persisted_v2 = json.loads(state_store.state_file_in(v1_dir).read_text(encoding="utf-8")).get("read_ledger_schema") == 2

        state_store.state_file_in(bad_state_dir).write_text("{corrupt-json", encoding="utf-8")
        with state_store.locked_state(bad_state_dir) as txn_bad:
            corrupt_reset = txn_bad.state.get("read_ledger_schema") == 2 and txn_bad.state.get("files") == {}
        quarantine_exists = (bad_state_dir / ".context_guard_state.json.corrupt").is_file()

        out_v3_path, out_bad_path = root / "outcomes_v3.json", root / "outcomes_bad.json"
        out_v3_path.write_text(
            json.dumps({
                "schema_version": 3,
                "by_key": {"claude|sonnet|outline": {"total": 5, "applied": 5, "targeted_followup": 2, "full_bypass": 1, "shell_bypass": 0}},
            }),
            encoding="utf-8",
        )
        out_bad_path.write_text("{bad-outcomes", encoding="utf-8")
        out_v4 = outcomes.load_outcomes(out_v3_path)
        out_row = (out_v4.get("by_key") or {}).get("claude|sonnet|outline") or {}
        out_ok = (
            out_v4.get("schema_version") == outcomes.SCHEMA_VERSION and out_row.get("legacy_v3") is True
            and (out_row.get("recovery") or {}).get("targeted") == 2
            and outcomes.load_outcomes(out_bad_path).get("schema_version") == outcomes.SCHEMA_VERSION
        )

        (bad_spool_dir / "spool_index.json").write_text("{corrupt-spool", encoding="utf-8")
        (v1_spool_dir / "spool_index.json").write_text(json.dumps({"schema_version": 1, "entries": {}}), encoding="utf-8")
        rcpt_path = receipts_path_for(spool_dir)
        sp_created = spool_tool_output(
            "\n".join(f"mig_line_{i:04d}: " + ("x" * 70) for i in range(240)) + "\n",
            session_id="mig-sess", call_id="mig-call-1", harness="claude", tool_name="Bash",
            workspace_root=ws_dir, isolation="workspace", spool_dir=spool_dir, receipts_path=rcpt_path,
        )
        if sp_created is None:
            spool_ok = False
        else:
            (spool_dir / f"{sp_created[0].spool_id}.txt").unlink()
            sp_missing = inspect_spool_entry(sp_created[0].spool_id, spool_dir=spool_dir)
            spool_ok = (
                sp_missing.get("current_state") == "corrupt" and sp_missing.get("corrupt_reason") == "unexpectedly_missing"
                and inspect_spool_entry("sp_000000000001", spool_dir=bad_spool_dir).get("found") is False
                and inspect_spool_entry("sp_000000000001", spool_dir=v1_spool_dir).get("found") is False
            )

        usage_v1_path, usage_bad_path = root / "usage_v1.json", root / "usage_bad.json"
        usage_v1_path.write_text(
            json.dumps({"schema_version": 1, "totals": {"claude|sonnet": {"input": 120, "output": 30, "cache_read": 60, "cache_write": 15}, "antigravity|old": {"input": 50}}}),
            encoding="utf-8",
        )
        usage_bad_path.write_text("[1, 2, 3]", encoding="utf-8")
        u_state = restore_usage_state(usage_v1_path)
        u_mig = migrate_usage_state(u_state, roots={})
        usage_ok = (
            u_mig is True and u_state.get("schema_version") == USAGE_SCHEMA_VERSION
            and (u_state.get("totals") or {}).get("claude|sonnet", {}).get("input") == 120
            and "antigravity|old" not in (u_state.get("totals") or {})
            and isinstance(restore_usage_state(usage_bad_path).get("totals"), Mapping)
        )

        ev_ledger_path = root / "evidence_events.json"
        ing_res = ingest_context_receipts(ev_ledger_path, rcpt_path, outcomes_path=out_v3_path)
        ev_ledger_ok = bool(ing_res.get("ok") and int(ing_res.get("total_events") or 0) >= 1 and ing_res.get("has_migrated_baseline") and derive_outcomes_from_ledger(ev_ledger_path).get("ok"))

        j_file.write_bytes(b"original\n")
        (j_live / "old.txt").write_text("old", encoding="utf-8")
        (j_stage / "new.txt").write_text("new", encoding="utf-8")
        journal = RollbackJournal()
        journal.record_file_backup(j_file)
        j_file.write_bytes(b"mutated\n")
        journal.swap_directory(j_stage, j_live)
        journal.rollback()
        journal_ok = j_file.read_bytes() == b"original\n" and (j_live / "old.txt").is_file() and not (j_live / "new.txt").exists()

        rb_cfg.write_bytes(b"{}\n")
        (rb_src / "pack.py").write_text(_SCOPED_PACK_TPL.format(pid="rb_pack", ver=1), encoding="utf-8")
        tx_rb = StagedPackTransaction(rb_src, config_path=rb_cfg)
        tx_rb.prepare()
        tx_rb.validate()
        tx_rb.activate()
        activated_ok = (rb_cfg.parent / "policies" / "rb_pack" / "pack.py").is_file()
        tx_rb.rollback()
        tx_rb_ok = activated_ok and rb_cfg.read_bytes() == b"{}\n" and not (rb_cfg.parent / "policies" / "rb_pack").exists()

        inst_md = h_root / "CLAUDE.md"
        cl_cfg.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
        cu_cfg.write_text("{}", encoding="utf-8")
        cx_hooks.write_text("{}", encoding="utf-8")
        cx_toml.write_text("", encoding="utf-8")
        inst_md.write_text("# User Notes\n", encoding="utf-8")
        install_all(
            claude_settings_path=cl_cfg, cursor_hooks_path=cu_cfg, codex_hooks_path=cx_hooks,
            codex_config_path=cx_toml, shim_bin_dir=shims_dir, instruction_files=(inst_md,),
            claude_version=(2, 1, 295), cursor_mcp_path=cu_mcp,
        )
        st_on = check_status(claude_settings_path=cl_cfg, cursor_hooks_path=cu_cfg, codex_hooks_path=cx_hooks, shim_bin_dir=shims_dir, cursor_mcp_path=cu_mcp)
        uninstall_all(
            claude_settings_path=cl_cfg, cursor_hooks_path=cu_cfg, codex_hooks_path=cx_hooks,
            codex_config_path=cx_toml, shim_bin_dir=shims_dir, instruction_files=(inst_md,), cursor_mcp_path=cu_mcp,
        )
        st_off = check_status(claude_settings_path=cl_cfg, cursor_hooks_path=cu_cfg, codex_hooks_path=cx_hooks, shim_bin_dir=shims_dir, cursor_mcp_path=cu_mcp)
        shim_ok = os.name == "nt" or (bool(st_on.get("cg_shim")) and not bool(st_off.get("cg_shim")))
        installer_ok = (
            bool(st_on.get("claude") and st_on.get("cursor") and st_on.get("codex"))
            and not st_off.get("claude") and not st_off.get("cursor") and not st_off.get("codex")
            and json.loads(cl_cfg.read_text(encoding="utf-8")).get("theme") == "dark" and shim_ok
        )

    checks = {
        "core_schema_versions_match_live": schemas_synced, "read_ledger_v1_to_v2": bool(v1_migrated and persisted_v2),
        "read_ledger_corrupt_quarantine": bool(corrupt_reset and quarantine_exists), "outcomes_v3_to_v4": out_ok,
        "spool_corrupt_resilience": spool_ok, "token_usage_legacy_to_v3": usage_ok,
        "receipts_to_evidence_ledger_v1": ev_ledger_ok, "rollback_journal_lifo": journal_ok,
        "staged_pack_rollback": tx_rb_ok, "installer_install_status_uninstall": installer_ok,
    }
    migrations_ok = bool(
        checks["read_ledger_v1_to_v2"] and checks["read_ledger_corrupt_quarantine"] and checks["outcomes_v3_to_v4"]
        and checks["spool_corrupt_resilience"] and checks["token_usage_legacy_to_v3"] and checks["receipts_to_evidence_ledger_v1"]
    )
    rollback_ok = bool(checks["rollback_journal_lifo"] and checks["staged_pack_rollback"] and checks["installer_install_status_uninstall"])
    return {
        "ok": bool(schemas_synced and migrations_ok and rollback_ok), "core_schema_versions_synced": schemas_synced,
        "migrations_ok": migrations_ok, "rollback_ok": rollback_ok, "checks": checks,
    }


def run_migration_and_rollback_conformance(work_dir: Path | None = None) -> dict[str, Any]:
    """Verify live CORE_SCHEMA_VERSIONS sync, store migrations, corrupt resilience, and rollback paths."""
    res: dict[str, Any] = _in_work_dir(work_dir, "cg_mig_conf_", _run_migrations_in_dir)
    return res


def _run_suite_in_dir(root: Path) -> ConformanceContractV1:
    matrix = build_capability_limitation_matrix(include_offline_benchmarks=True)
    dep, harnesses, eff = matrix["deprecation_policy"], matrix["harnesses"], matrix["effectiveness_summary"]
    adapters, packs, mig = run_adapter_conformance_suite(), run_baseline_policy_pack_conformance(work_dir=root / "packs"), run_migration_and_rollback_conformance(work_dir=root / "migrations")
    matrix_ok = set(harnesses) == set(SUPPORTED_HARNESS_IDS) and harnesses["cursor"]["cache_telemetry"] == "excluded_missing_telemetry" and all(
        (r := harnesses[h])["can_replace_tool_output"] == (c := HARNESS_OUTPUT_CAPABILITIES[h]).can_replace_tool_output
        and r["has_native_fail_closed_hook"] == c.has_native_fail_closed_hook and r["supports_apply_patch_block"] == c.supports_apply_patch_block
        and r["supports_content_verified_reads"] == c.supports_content_verified_reads
        and len(r["verified_guarantees"]) >= 3 and len(r["documented_limitations"]) >= 2 for h in SUPPORTED_HARNESS_IDS
    )
    eff_ok = bool(
        eff.get("offline_benchmarks_included") is True and eff.get("live_benchmarks_included") is False
        and eff.get("primary_release_metric") == "Cost per Passed Run"
        and eff.get("offline_replay_statistical_proof") is False and eff.get("failed_attempts_excluded") is False
        and eff.get("endogenous_ttl_cache_misses_excluded") is False and len(eff.get("methodological_limitations") or ()) >= 3
        and all(bool((eff.get(k) or {}).get("ok")) for k in ("deterministic_replay", "latency_benchmark", "offline_evidence_replay"))
    )
    gates: dict[str, bool] = {
        "policy_api_v1_frozen": bool(
            POLICY_API_VERSION == 1 and dep["policy_api_version"] == 1
            and dep["policy_api_v2_mandated"] is False and dep["external_sdk_shipped"] is False
            and dep["min_deprecation_minor_releases"] >= 2 and dep["additive_fields_non_breaking"] is True
        ),
        "core_schema_versions_synced": bool(mig.get("core_schema_versions_synced") and len(CORE_SCHEMA_VERSIONS) == 17),
        "capability_matrix_complete_and_honest": bool(matrix_ok),
        "adapter_conformance_4_harnesses": bool(
            set(adapters) == set(SUPPORTED_HARNESS_IDS)
            and all(bool(adapters[h].get("ok")) for h in SUPPORTED_HARNESS_IDS)
            and adapters["cursor"].get("cache_attribution_status") == "excluded_missing_telemetry"
            and adapters["cursor"].get("verification_scope") == "adapter_contract_only"
            and adapters["cursor"].get("runtime_verified") is False
        ),
        "baseline_security_pack_conformance": bool(packs.get("security_pack_ok")),
        "baseline_optimization_pack_reconciliation": bool(packs.get("optimization_reconciliation_ok")),
        "tamper_and_unknown_major_fail_closed": bool(packs.get("tamper_and_unknown_major_ok")),
        "backward_compatible_migrations_ok": bool(mig.get("migrations_ok")),
        "rollback_paths_verified": bool(mig.get("rollback_ok")),
        "effectiveness_and_limitations_published": eff_ok,
    }
    passed = sum(1 for k in _GATE_ORDER if gates.get(k))
    failed = sorted([str(k) for k, v in gates.items() if not v], key=lambda x: str(x))
    return {
        "schema_version": CONFORMANCE_SCHEMA_VERSION, "ok": passed == len(_GATE_ORDER), "checked_at": utc_now_iso_z(),
        "policy_api_version": POLICY_API_VERSION, "adapter_contract_version": ADAPTER_CONTRACT_VERSION,
        "core_schema_versions": dict(CORE_SCHEMA_VERSIONS), "harnesses_checked": list(SUPPORTED_HARNESS_IDS),
        "adapter_conformance": adapters, "baseline_policy_pack_conformance": packs,
        "migration_and_rollback_conformance": mig, "platform_matrix": matrix, "gates": gates,
        "gates_passed": passed, "gates_total": len(_GATE_ORDER), "failed_gates": failed,
    }


def run_platform_conformance_suite(work_dir: Path | None = None) -> ConformanceContractV1:
    """Execute the full 10-gate platform conformance suite in an isolated temporary directory."""
    res: ConformanceContractV1 = _in_work_dir(work_dir, "cg_platform_conf_", _run_suite_in_dir)
    return res


def replay_governor_decisions(scenarios: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Deterministically verify all 8 Governor release gates (and optional custom scenarios) in isolation."""
    return run_governor_release_gates(scenarios)


def render_platform_matrix_markdown(matrix: Mapping[str, Any]) -> str:
    """Format a PlatformMatrixContractV1 dictionary as a clean, path-scrubbed Markdown report."""
    dep = d if isinstance((d := matrix.get("deprecation_policy")), Mapping) else {}
    eff = e if isinstance((e := matrix.get("effectiveness_summary")), Mapping) else {}
    harnesses = h if isinstance((h := matrix.get("harnesses")), Mapping) else {}
    schemas = s if isinstance((s := matrix.get("core_schema_versions")), Mapping) else {}
    lines = [
        "# Context-Guard Platform Capability & Limitation Matrix", "",
        (
            f"- Policy API Version: `{matrix.get('policy_api_version', POLICY_API_VERSION)}` "
            f"(frozen; v2 mandated: `{bool(dep.get('policy_api_v2_mandated'))}`, "
            f"external SDK: `{bool(dep.get('external_sdk_shipped'))}`)"
        ),
        f"- Adapter Contract: `{matrix.get('adapter_contract_version', ADAPTER_CONTRACT_VERSION)}` | Core Schemas Registered: `{len(schemas)}`",
        (
            f"- Deprecation Notice Floor: `>= {int(dep.get('min_deprecation_minor_releases', MIN_DEPRECATION_MINOR_RELEASES))} "
            f"minor releases` | Unknown Major Pack: `{dep.get('unknown_major_policy_pack_behavior', '')}`"
        ),
        "", "## 4-Harness Capability Matrix", "",
        "| Harness | Replace Output | Native Fail-Closed | Block `apply_patch` | Content-Verified Reads | Cache Telemetry | Turn Correlation |",
        "|---|---|---|---|---|---|---|",
    ]
    for hid in SUPPORTED_HARNESS_IDS:
        if isinstance((row := harnesses.get(hid)), Mapping):
            lines.append(
                f"| `{hid}` ({row.get('display_name', hid)}) | `{bool(row.get('can_replace_tool_output'))}` | "
                f"`{bool(row.get('has_native_fail_closed_hook'))}` | `{bool(row.get('supports_apply_patch_block'))}` | "
                f"`{bool(row.get('supports_content_verified_reads'))}` | `{row.get('cache_telemetry', '')}` | `{row.get('turn_correlation_ceiling', '')}` |"
            )
    lines.extend(["", "## Verified Guarantees & Documented Limitations", ""])
    for hid in SUPPORTED_HARNESS_IDS:
        if isinstance((row := harnesses.get(hid)), Mapping):
            lines.append(f"### `{hid}` — {row.get('display_name', hid)}")
            lines.extend(f"- Guarantee: {g}" for g in (row.get("verified_guarantees") or ()))
            lines.extend(f"- Limitation: {lim}" for lim in (row.get("documented_limitations") or ()))
            lines.append("")
    lines.extend([
        "## Effectiveness Contract & Methodological Limitations", "",
        f"- Primary release metric: `{eff.get('primary_release_metric', 'Cost per Passed Run')}` | Offline statistical proof: `{bool(eff.get('offline_replay_statistical_proof'))}` | Offline checks: `{bool(eff.get('offline_benchmarks_included'))}` | Live benchmarks: `{bool(eff.get('live_benchmarks_included'))}`",
        *(f"- {lim}" for lim in (eff.get("methodological_limitations") or ())),
    ])
    return _scrub_paths("\n".join(lines).rstrip() + "\n")


def render_conformance_markdown(report: Mapping[str, Any]) -> str:
    """Format a ConformanceContractV1 dictionary as a clean, path-scrubbed Markdown report."""
    gates = g if isinstance((g := report.get("gates")), Mapping) else {}
    adapters = a if isinstance((a := report.get("adapter_conformance")), Mapping) else {}
    failed = [str(x) for x in (report.get("failed_gates") or ())]
    lines = [
        "# Context-Guard Platform Conformance Report", "",
        f"- Verdict: `{'PASS' if report.get('ok') else 'FAIL'}` "
        f"(`{int(report.get('gates_passed', 0) or 0)}/{int(report.get('gates_total', 10) or 10)}` gates) | "
        f"Checked: `{report.get('checked_at', '')}`",
        f"- Policy API Version: `{report.get('policy_api_version', POLICY_API_VERSION)}` | Adapter Contract: `{report.get('adapter_contract_version', ADAPTER_CONTRACT_VERSION)}`",
        f"- Failed Gates: `{', '.join(failed) if failed else 'none'}`",
        "", "## Conformance Gates (10)", "", "| Gate | Status |", "|---|---|",
    ]
    for gate_name in _GATE_ORDER:
        if gate_name in gates:
            lines.append(f"| `{gate_name}` | `{'PASS' if gates.get(gate_name) else 'FAIL'}` |")
    for extra_key in sorted([str(k) for k in gates if k not in _GATE_ORDER], key=lambda x: str(x)):
        lines.append(f"| `{extra_key}` | `{'PASS' if gates.get(extra_key) else 'FAIL'}` |")
    lines.extend(["", "## 4-Harness Adapter Conformance", ""])
    for hid in SUPPORTED_HARNESS_IDS:
        if isinstance((h_res := adapters.get(hid)), Mapping):
            c_len = len(ch) if isinstance((ch := h_res.get("checks")), Mapping) else 0
            lines.append(f"- `{hid}`: `{'PASS' if h_res.get('ok') else 'FAIL'}` (`{c_len}` adapter checks)")
    return _scrub_paths("\n".join(lines) + "\n")
