"""Contract tests for Policy API v1 freeze, schema registry, 4-harness matrix, and platform conformance."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from services.token_usage import USAGE_SCHEMA_VERSION
from evidence.conformance import (
    build_capability_limitation_matrix,
    build_deprecation_policy,
    render_conformance_markdown,
    render_platform_matrix_markdown,
    run_adapter_conformance_suite,
    run_baseline_policy_pack_conformance,
    run_migration_and_rollback_conformance,
    run_platform_conformance_suite,
)
from evidence.ledger import EVENT_LEDGER_SCHEMA_VERSION
from hooks import outcomes, state_store
import policies
from policies import api as policies_api
from spool.store import SPOOL_SCHEMA_VERSION


def test_policy_api_v1_frozen_and_public_exports_complete() -> None:
    assert policies.POLICY_API_VERSION == 1
    assert policies_api.POLICY_API_VERSION == 1
    assert set(policies.__all__) == set(policies_api.__all__)

    required_symbols = {
        "POLICY_API_VERSION",
        "RECEIPT_SCHEMA_VERSION",
        "VALID_TURN_CORRELATIONS",
        "ContextReceiptV1",
        "DOCTOR_SCHEMA_VERSION",
        "CONFORMANCE_SCHEMA_VERSION",
        "PLATFORM_MATRIX_SCHEMA_VERSION",
        "DEPRECATION_POLICY_VERSION",
        "MIN_DEPRECATION_MINOR_RELEASES",
        "SUPPORTED_HARNESS_IDS",
        "CORE_SCHEMA_VERSIONS",
        "DeprecationPolicyV1",
        "HarnessCapabilityMatrixRowV1",
        "PlatformMatrixContractV1",
        "ConformanceContractV1",
    }
    assert required_symbols.issubset(set(policies.__all__))
    for name in policies.__all__:
        assert hasattr(policies, name), f"policies missing export {name}"
        assert getattr(policies, name) is getattr(policies_api, name)
    assert policies.SUPPORTED_HARNESS_IDS == ("antigravity", "claude", "cursor", "codex")


def test_core_schema_versions_match_live_module_constants() -> None:
    expected = {
        "policy_api": policies_api.POLICY_API_VERSION,
        "read_ledger": state_store.READ_LEDGER_SCHEMA,
        "mutated_repos": state_store.MUTATED_REPOS_SCHEMA,
        "spool_index": SPOOL_SCHEMA_VERSION,
        "context_receipt": policies_api.RECEIPT_SCHEMA_VERSION,
        "outcomes": outcomes.SCHEMA_VERSION,
        "token_usage": USAGE_SCHEMA_VERSION,
        "event_ledger": EVENT_LEDGER_SCHEMA_VERSION,
        "evidence_report": policies_api.EVIDENCE_SCHEMA_VERSION,
        "capability_contract": policies_api.CAPABILITY_CONTRACT_SCHEMA_VERSION,
        "governor_state": policies_api.GOVERNOR_SCHEMA_VERSION,
        "explain_report": policies_api.EXPLAIN_SCHEMA_VERSION,
        "otel_export": policies_api.OTEL_EXPORT_SCHEMA_VERSION,
        "backend_benchmark": policies_api.BACKEND_BENCHMARK_SCHEMA_VERSION,
        "doctor_report": policies_api.DOCTOR_SCHEMA_VERSION,
        "conformance_report": policies_api.CONFORMANCE_SCHEMA_VERSION,
        "platform_matrix": policies_api.PLATFORM_MATRIX_SCHEMA_VERSION,
    }
    assert len(expected) == 17
    assert policies.CORE_SCHEMA_VERSIONS == expected
    assert policies.CORE_SCHEMA_VERSIONS["policy_api"] == 1
    assert policies.CORE_SCHEMA_VERSIONS["read_ledger"] == 2
    assert policies.CORE_SCHEMA_VERSIONS["mutated_repos"] == 2
    assert policies.CORE_SCHEMA_VERSIONS["spool_index"] == 2
    assert policies.CORE_SCHEMA_VERSIONS["outcomes"] == 4
    assert policies.CORE_SCHEMA_VERSIONS["token_usage"] == 3


def test_deprecation_policy_contract_invariants() -> None:
    first = build_deprecation_policy()
    assert first["schema_version"] == 1
    assert first["policy_api_version"] == 1
    assert first["policy_api_v2_mandated"] is False
    assert first["external_sdk_shipped"] is False
    assert first["min_deprecation_minor_releases"] >= 2
    assert first["additive_fields_non_breaking"] is True
    assert first["unknown_major_policy_pack_behavior"] == "reject_fail_closed"
    assert first["corrupt_or_future_telemetry_store_behavior"] == "quarantine_or_passthrough_zero_crash"
    assert first["active_deprecations"] == []
    assert set(first["backward_compatible_migrations"]) == {
        "read_ledger_v1_to_v2",
        "outcomes_v3_to_v4",
        "spool_index_v1_to_v2",
        "token_usage_legacy_to_v3",
        "receipts_to_evidence_ledger_v1",
    }
    assert set(first["rollback_paths"]) == {
        "staged_pack_transaction_rollback",
        "rollback_journal_lifo",
        "ide_updater_git_reset_keep",
        "install_harnesses_uninstall",
        "git_tag_checkout_reinstall",
    }

    first["backward_compatible_migrations"].append("synthetic_mutation")
    first["rollback_paths"].append("synthetic_rollback")
    second = build_deprecation_policy()
    assert "synthetic_mutation" not in second["backward_compatible_migrations"]
    assert "synthetic_rollback" not in second["rollback_paths"]


def test_capability_limitation_matrix_covers_all_four_harnesses_honestly() -> None:
    static_matrix = build_capability_limitation_matrix(include_live_effectiveness=False)
    assert static_matrix["schema_version"] == 1
    assert static_matrix["policy_api_version"] == 1
    assert static_matrix["adapter_contract_version"] == policies.ADAPTER_CONTRACT_VERSION
    assert static_matrix["core_schema_versions"] == policies.CORE_SCHEMA_VERSIONS
    assert set(static_matrix["harnesses"]) == {"antigravity", "claude", "cursor", "codex"}

    for hid, row in static_matrix["harnesses"].items():
        caps = policies.HARNESS_OUTPUT_CAPABILITIES[hid]
        assert row["harness_id"] == hid
        assert row["can_replace_tool_output"] is caps.can_replace_tool_output
        assert row["has_native_fail_closed_hook"] is caps.has_native_fail_closed_hook
        assert row["supports_apply_patch_block"] is caps.supports_apply_patch_block
        assert row["supports_content_verified_reads"] is caps.supports_content_verified_reads
        assert len(row["verified_guarantees"]) >= 3
        assert len(row["documented_limitations"]) >= 2

    cl_lim = " ".join(static_matrix["harnesses"]["claude"]["documented_limitations"])
    cu_row = static_matrix["harnesses"]["cursor"]
    ag_lim = " ".join(static_matrix["harnesses"]["antigravity"]["documented_limitations"])
    cx_lim = " ".join(static_matrix["harnesses"]["codex"]["documented_limitations"])
    assert "2.1.295" in cl_lim
    assert cu_row["cache_telemetry"] == "excluded_missing_telemetry"
    assert "excluded_missing_telemetry" in " ".join(cu_row["documented_limitations"])
    assert "bounded" in ag_lim
    assert "apply_patch" in cx_lim and "27833" in cx_lim
    assert {h: static_matrix["harnesses"][h]["turn_correlation_ceiling"] for h in policies.SUPPORTED_HARNESS_IDS} == {
        "antigravity": "harness_native",
        "claude": "transcript_derived",
        "cursor": "transcript_derived",
        "codex": "transcript_derived",
    }
    assert all(
        static_matrix["harnesses"][h]["turn_correlation_ceiling"] in policies.VALID_TURN_CORRELATIONS
        for h in policies.SUPPORTED_HARNESS_IDS
    )

    eff_static = static_matrix["effectiveness_summary"]
    assert eff_static["live_benchmarks_included"] is False
    assert eff_static["primary_release_metric"] == "Cost per Passed Run"
    assert eff_static["offline_replay_statistical_proof"] is False
    assert eff_static["failed_attempts_excluded"] is False
    assert eff_static["endogenous_ttl_cache_misses_excluded"] is False

    live_matrix = build_capability_limitation_matrix(include_live_effectiveness=True)
    eff_live = live_matrix["effectiveness_summary"]
    assert eff_live["live_benchmarks_included"] is True
    assert eff_live["deterministic_replay"]["ok"] is True
    assert eff_live["latency_benchmark"]["ok"] is True
    assert eff_live["offline_evidence_replay"]["ok"] is True


def test_adapter_conformance_suite_passes_all_harnesses() -> None:
    res = run_adapter_conformance_suite()
    assert set(res) == {"antigravity", "claude", "cursor", "codex"}
    required_checks = {
        "detect_harness",
        "normalize_read",
        "normalize_mutation",
        "normalize_shell",
        "normalize_mcp",
        "line_bounds",
        "format_verdicts",
        "rewrite_permission_gate",
        "runtime_capabilities",
    }
    for hid in ("antigravity", "claude", "cursor", "codex"):
        h_report = res[hid]
        assert h_report["ok"] is True, f"{hid} failed adapter conformance: {h_report}"
        checks = h_report["checks"]
        assert required_checks.issubset(set(checks))
        assert all(bool(v) for v in checks.values())
    assert res["cursor"]["cache_attribution_status"] == "excluded_missing_telemetry"
    assert res["cursor"]["checks"]["cursor_cli_conformance"] is True


def test_baseline_policy_pack_conformance_security_and_optimization(tmp_path: Path) -> None:
    tracked_env = (
        "CONTEXT_GUARD_HOME",
        "CONTEXT_GUARD_CONFIG_PATH",
        "CONTEXT_GUARD_STATE_DIR",
        "CONTEXT_GUARD_SPOOL_DIR",
        "CONTEXT_GUARD_WORKSPACE_ROOT",
    )
    env_before = {k: os.environ.get(k) for k in tracked_env}
    res = run_baseline_policy_pack_conformance(tmp_path)
    env_after = {k: os.environ.get(k) for k in tracked_env}

    assert env_after == env_before
    assert res["ok"] is True
    assert res["security_pack_ok"] is True
    assert res["optimization_reconciliation_ok"] is True
    assert res["tamper_and_unknown_major_ok"] is True
    checks = res["checks"]
    for key in (
        "pass1_deny",
        "post_transform_verify",
        "callbacks_fired",
        "inspect_config_validated",
        "pass2_safe_allow",
        "pass2_unsafe_discard",
        "pass2_both_bad_deny",
        "tamper_in_scope_denied",
        "tamper_out_of_scope_allowed",
        "api_v2_rejected_cleanly",
    ):
        assert checks[key] is True, f"policy pack check failed: {key}"


def test_migration_and_rollback_conformance_across_stores_and_installer(tmp_path: Path) -> None:
    tracked_env = (
        "CONTEXT_GUARD_HOME",
        "CONTEXT_GUARD_CONFIG_PATH",
        "CONTEXT_GUARD_STATE_DIR",
        "CONTEXT_GUARD_SPOOL_DIR",
        "PATH",
    )
    env_before = {k: os.environ.get(k) for k in tracked_env}
    res = run_migration_and_rollback_conformance(tmp_path)
    env_after = {k: os.environ.get(k) for k in tracked_env}

    assert env_after == env_before
    assert res["ok"] is True
    assert res["core_schema_versions_synced"] is True
    assert res["migrations_ok"] is True
    assert res["rollback_ok"] is True
    checks = res["checks"]
    for key in (
        "core_schema_versions_match_live",
        "read_ledger_v1_to_v2",
        "read_ledger_corrupt_quarantine",
        "outcomes_v3_to_v4",
        "spool_corrupt_resilience",
        "token_usage_legacy_to_v3",
        "receipts_to_evidence_ledger_v1",
        "rollback_journal_lifo",
        "staged_pack_rollback",
        "installer_install_status_uninstall",
    ):
        assert checks[key] is True, f"migration/rollback check failed: {key}"


def test_platform_conformance_suite_all_ten_gates_and_markdown(tmp_path: Path) -> None:
    report = run_platform_conformance_suite(tmp_path)
    assert report["schema_version"] == 1
    assert report["ok"] is True
    assert report["policy_api_version"] == 1
    assert report["adapter_contract_version"] == policies.ADAPTER_CONTRACT_VERSION
    assert report["gates_total"] == 10
    assert report["gates_passed"] == 10
    assert report["failed_gates"] == []

    expected_gates = {
        "policy_api_v1_frozen",
        "core_schema_versions_synced",
        "capability_matrix_complete_and_honest",
        "adapter_conformance_4_harnesses",
        "baseline_security_pack_conformance",
        "baseline_optimization_pack_reconciliation",
        "tamper_and_unknown_major_fail_closed",
        "backward_compatible_migrations_ok",
        "rollback_paths_verified",
        "effectiveness_and_limitations_published",
    }
    assert set(report["gates"]) == expected_gates
    assert all(report["gates"][g] is True for g in expected_gates)

    md_conf = render_conformance_markdown(report)
    md_matrix = render_platform_matrix_markdown(report["platform_matrix"])
    assert "# Context-Guard Platform Conformance Report" in md_conf
    assert "`PASS` (`10/10` gates)" in md_conf
    for gate_name in expected_gates:
        assert f"`{gate_name}`" in md_conf

    assert "# Context-Guard Platform Capability & Limitation Matrix" in md_matrix
    for hid in ("antigravity", "claude", "cursor", "codex"):
        assert f"`{hid}`" in md_matrix

    home_str = str(Path.home())
    assert home_str not in json.dumps(report)
    assert home_str not in md_conf
    assert home_str not in md_matrix

    synthetic_leak: dict[str, Any] = {
        **report,
        "checked_at": "/Users/alice/secret_dir",
    }
    scrubbed_md = render_conformance_markdown(synthetic_leak)
    assert "/Users/alice" not in scrubbed_md
    assert "~/secret_dir" in scrubbed_md
