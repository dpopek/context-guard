"""Tests for Evidence Engine contracts, durable deduplicated ledger, capability evidence, and Cursor conformance."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import stat
from typing import Any

import pytest

from evidence import ledger as ev_ledger
from evidence.ledger import (
    DEFAULT_EVENT_LEDGER_FILENAME,
    EVENT_LEDGER_SCHEMA_VERSION,
    REQUIRED_EVIDENCE_CAPABILITIES,
    append_durable_events,
    build_capability_attestation_key,
    collect_environment_metadata,
    compute_hook_config_fingerprint,
    derive_outcomes_from_ledger,
    ingest_context_receipts,
    resolve_capability_requirement,
    run_cursor_cli_conformance,
)
from hooks import outcomes
import policies
from policies import api as policies_api
from policies.api import (
    ADAPTER_CONTRACT_VERSION,
    CapabilityAttestationKey,
    CapabilityRequirementV1,
    EVIDENCE_SCHEMA_VERSION,
    EvidenceContractV1,
    EvidenceEnvironmentMetadataV1,
    VALID_CAPABILITY_EVIDENCE_LEVELS,
    VALID_EVAL_TIERS,
    VALID_RUN_OUTCOME_CLASSES,
)
from spool import receipts as spool_receipts

REPO_ROOT = Path(__file__).resolve().parent.parent


def _repo_manifest_version() -> str:
    return str(json.loads((REPO_ROOT / "plugin.json").read_text(encoding="utf-8"))["version"])


def test_policies_api_exports_evidence_contracts() -> None:
    """Verify all Evidence Engine constants and TypedDicts are exported in policies and policies.api."""
    expected_exports = {
        "EVIDENCE_SCHEMA_VERSION",
        "ADAPTER_CONTRACT_VERSION",
        "VALID_CAPABILITY_EVIDENCE_LEVELS",
        "VALID_EVAL_TIERS",
        "VALID_RUN_OUTCOME_CLASSES",
        "CapabilityAttestationKey",
        "CapabilityRequirementV1",
        "EvidenceEnvironmentMetadataV1",
        "EvidenceContractV1",
    }
    assert expected_exports.issubset(set(policies_api.__all__))
    assert expected_exports.issubset(set(policies.__all__))
    assert EVIDENCE_SCHEMA_VERSION == 1
    assert ADAPTER_CONTRACT_VERSION == "harness_adapter_v1"
    assert VALID_CAPABILITY_EVIDENCE_LEVELS == (
        "unsupported",
        "provider_supported",
        "harness_exposed",
        "runtime_verified",
    )
    assert VALID_EVAL_TIERS == ("offline_replay", "small_live_pilot", "release_evaluation")
    assert VALID_RUN_OUTCOME_CLASSES == ("passed", "failed_attempt", "external_noise")
    assert DEFAULT_EVENT_LEDGER_FILENAME == "evidence_events.json"
    assert EVENT_LEDGER_SCHEMA_VERSION == 1
    assert REQUIRED_EVIDENCE_CAPABILITIES == (
        "pre_tool_interception",
        "output_replacement",
        "native_fail_closed",
        "content_verified_reads",
        "prompt_cache_telemetry",
    )
    assert set(CapabilityRequirementV1.__required_keys__) == {
        "capability_id",
        "evidence_level",
        "attestation_key",
        "verification_source",
        "runtime_verified",
    }
    assert set(EvidenceEnvironmentMetadataV1.__required_keys__) == {
        "harness_id",
        "harness_build_id",
        "adapter_version",
        "hook_config_fingerprint",
        "context_guard_version",
        "model_id",
        "attestation_key_implies_runtime_verified",
        "required_capabilities",
    }
    assert set(EvidenceContractV1.__required_keys__) == {
        "schema_version",
        "campaign_id",
        "tier",
        "generated_at",
        "statistical_proof",
        "trajectory_claim",
        "environment",
        "arms",
        "budget_contract",
        "arm_summaries",
        "paired_comparisons",
        "disclosed_failures",
        "uncertainty_bounds",
        "gate_verdict",
    }


def test_durable_ledger_deduplicates_events_and_derives_outcomes_deterministically(tmp_path: Path) -> None:
    """Verify 0o600 persistence, event_id/receipt_id deduplication, idempotent ingest, and baseline migration."""
    ledger_path = tmp_path / "evidence" / DEFAULT_EVENT_LEDGER_FILENAME
    receipts_path = tmp_path / "spool" / "receipts.jsonl"
    outcomes_path = tmp_path / "outcomes.json"

    r_created = spool_receipts.build_receipt(
        event_type="spool_created",
        harness="claude",
        session_id="sess_01",
        workspace_id="ws_0123456789abcdef",
        turn_key="sess_01:step:1",
        call_id="call_01",
        spool_id="sp_000000000001",
        line_span=(0, 220),
        byte_span=(0, 14000),
        delivery_evidence="replacement_emitted",
        spool_id_referenced=False,
        timestamp="2026-11-16T10:00:00Z",
    )
    r_verified = spool_receipts.build_receipt(
        event_type="spool_delivery_verified",
        harness="claude",
        session_id="sess_01",
        workspace_id="ws_0123456789abcdef",
        turn_key="sess_01:step:1",
        call_id="call_01",
        spool_id="sp_000000000001",
        line_span=(0, 220),
        byte_span=(0, 14000),
        delivery_evidence="delivery_verified",
        spool_id_referenced=False,
        parent_event_id=r_created["receipt_id"],
        timestamp="2026-11-16T10:00:01Z",
    )
    r_recovery = spool_receipts.build_receipt(
        event_type="spool_recovery",
        harness="claude",
        session_id="sess_01",
        workspace_id="ws_0123456789abcdef",
        turn_key="sess_01:step:2",
        call_id="call_02",
        spool_id="sp_000000000001",
        line_span=(1, 80),
        byte_span=(0, 4096),
        delivery_evidence="unverified",
        spool_id_referenced=True,
        timestamp="2026-11-16T10:00:02Z",
    )
    r_failure = spool_receipts.build_receipt(
        event_type="spool_integrity_failure",
        harness="cursor",
        session_id="sess_02",
        workspace_id="ws_0123456789abcdef",
        turn_key="sess_02:step:1",
        call_id="call_03",
        spool_id="sp_000000000002",
        line_span=(0, 0),
        byte_span=(0, 100),
        delivery_evidence="unverified",
        spool_id_referenced=True,
        failure_kind="reliability_failure",
        reason="integrity_mismatch",
        timestamp="2026-11-16T10:00:03Z",
    )
    receipts_path.parent.mkdir(parents=True, exist_ok=True)
    receipts_path.write_text(
        "\n".join(json.dumps(dict(r)) for r in (r_created, r_verified, r_recovery, r_failure, r_created)) + "\n",
        encoding="utf-8",
    )

    first_ingest = ingest_context_receipts(ledger_path, receipts_path)
    assert first_ingest["ok"] is True
    assert first_ingest["appended_count"] == 4
    assert first_ingest["duplicate_count"] == 1
    assert first_ingest["invalid_count"] == 0
    assert first_ingest["total_events"] == 4
    assert first_ingest["completeness"] == "complete"
    if os.name != "nt":
        assert stat.S_IMODE(ledger_path.stat().st_mode) == 0o600

    raw_doc = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert set(raw_doc.keys()) == {
        "schema_version",
        "updated_at",
        "events",
        "seen_event_ids",
        "migrated_outcomes_baseline",
        "corrupt_source_lines",
    }
    assert raw_doc["schema_version"] == EVENT_LEDGER_SCHEMA_VERSION
    assert raw_doc["corrupt_source_lines"] == 0

    derived_1 = derive_outcomes_from_ledger(ledger_path)
    assert derived_1["completeness"] == "complete"
    assert derived_1["totals"] == {
        "created": 1,
        "delivery_verified": 1,
        "recoveries": 1,
        "reliability_failures": 1,
        "total_events": 4,
    }
    assert derived_1["reliability_failures"] == 1
    assert derived_1["by_group"] == {
        "claude|unknown|output_spool": {
            "created": 1,
            "delivery_verified": 1,
            "recoveries": 1,
            "reliability_failures": 0,
            "total_events": 3,
        },
        "cursor|unknown|output_spool": {
            "created": 0,
            "delivery_verified": 0,
            "recoveries": 0,
            "reliability_failures": 1,
            "total_events": 1,
        },
    }

    second_ingest = ingest_context_receipts(ledger_path, receipts_path)
    assert second_ingest["ok"] is True
    assert second_ingest["appended_count"] == 0
    assert second_ingest["duplicate_count"] == 5
    assert derive_outcomes_from_ledger(ledger_path) == derived_1

    fallback_ev = {
        "event_id": "",
        "receipt_id": "rcpt_fallback_001",
        "event_type": "spool_created",
        "harness": "claude",
        "model": "claude-sonnet-4-6",
        "spool_id": "sp_000000000003",
        "intervention": "output_spool",
    }
    invalid_ev = {"event_id": "", "receipt_id": "", "event_type": "spool_created", "harness": "claude"}
    direct_res = append_durable_events(ledger_path, [fallback_ev, fallback_ev, invalid_ev])
    assert direct_res["ok"] is True
    assert direct_res["appended_count"] == 1
    assert direct_res["duplicate_count"] == 1
    assert direct_res["invalid_count"] == 1
    assert direct_res["total_events"] == 5

    outcomes.record_direct_outcome("claude", "claude-sonnet-4-6", "outline", "applied", outcomes_path)
    migrated_res = ingest_context_receipts(ledger_path, receipts_path, outcomes_path=outcomes_path)
    assert migrated_res["ok"] is True
    assert migrated_res["appended_count"] == 0
    assert migrated_res["completeness"] == "migrated_with_baseline"
    assert migrated_res["has_migrated_baseline"] is True

    after_nil = append_durable_events(ledger_path, [], migrated_outcomes=None)
    assert after_nil["completeness"] == "migrated_with_baseline"
    derived_mig = derive_outcomes_from_ledger(ledger_path)
    assert derived_mig["completeness"] == "migrated_with_baseline"
    assert derived_mig["by_group"]["claude|claude-sonnet-4-6|output_spool"]["created"] == 1
    assert derived_mig["migrated_outcomes_baseline"] is not None


def test_durable_ledger_reports_unavailable_and_incomplete_never_zero(tmp_path: Path) -> None:
    """Verify missing ledgers return unavailable/None and corrupt lines or orphan recoveries report incomplete."""
    missing_ledger = tmp_path / "missing_dir" / DEFAULT_EVENT_LEDGER_FILENAME
    missing_res = derive_outcomes_from_ledger(missing_ledger)
    assert missing_res["ok"] is True
    assert missing_res["completeness"] == "unavailable"
    assert missing_res["totals"] is None
    assert missing_res["by_group"] == {}
    assert missing_res["reliability_failures"] == 0
    assert not missing_ledger.parent.exists()

    no_src_ingest = ingest_context_receipts(missing_ledger, tmp_path / "absent_receipts.jsonl")
    assert no_src_ingest["completeness"] == "unavailable"
    assert not missing_ledger.exists()

    corrupt_receipts = tmp_path / "corrupt_receipts.jsonl"
    valid_created = spool_receipts.build_receipt(
        event_type="spool_created",
        harness="claude",
        session_id="s_ok",
        workspace_id="ws_1",
        turn_key="s_ok:step:1",
        call_id="c_ok",
        spool_id="sp_aaaaaaaaaaaa",
        line_span=(0, 10),
        byte_span=(0, 500),
        delivery_evidence="replacement_emitted",
        spool_id_referenced=False,
    )
    corrupt_receipts.write_text(
        json.dumps(dict(valid_created)) + "\n{bad_json_line\n12345\n",
        encoding="utf-8",
    )
    corrupt_ledger = tmp_path / "corrupt_ledger.json"
    ing_1 = ingest_context_receipts(corrupt_ledger, corrupt_receipts)
    assert ing_1["ok"] is True
    assert ing_1["appended_count"] == 1
    assert ing_1["corrupt_source_lines"] == 2
    assert ing_1["completeness"] == "incomplete"
    ing_2 = ingest_context_receipts(corrupt_ledger, corrupt_receipts)
    assert ing_2["appended_count"] == 0
    assert ing_2["corrupt_source_lines"] == 2
    derived_c = derive_outcomes_from_ledger(corrupt_ledger)
    assert derived_c["completeness"] == "incomplete"
    assert derived_c["corrupt_source_lines"] == 2

    orphan_ledger = tmp_path / "orphan_ledger.json"
    orphan_recovery = {
        "event_id": "ev_orphan_01",
        "event_type": "spool_recovery",
        "harness": "claude",
        "spool_id": "sp_111111111111",
    }
    append_durable_events(orphan_ledger, [orphan_recovery])
    derived_orphan = derive_outcomes_from_ledger(orphan_ledger)
    assert derived_orphan["completeness"] == "incomplete"
    assert derived_orphan["missing_created_spool_ids"] == ["sp_111111111111"]
    assert derived_orphan["totals"]["recoveries"] == 1

    bad_file = tmp_path / "broken_events.json"
    bad_file.write_text("{corrupt", encoding="utf-8")
    broken_derived = derive_outcomes_from_ledger(bad_file)
    assert broken_derived["ok"] is False
    assert broken_derived["completeness"] == "incomplete"
    assert broken_derived["totals"] is None


def test_durable_ledger_rejects_unsafe_symlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify symlinks and reparse points on ledger, lock, receipts, outcomes, and conformance dir fail closed."""
    sample_ev = {"event_id": "ev_safe_1", "event_type": "spool_created", "harness": "claude", "spool_id": "sp_222222222222"}

    if os.name != "nt":
        target_ledger = tmp_path / "target_ledger.json"
        target_ledger.write_text("SENTINEL", encoding="utf-8")
        sym_ledger = tmp_path / "sym_ledger.json"
        sym_ledger.symlink_to(target_ledger)
        res_sym_w = append_durable_events(sym_ledger, [sample_ev])
        assert res_sym_w["ok"] is False and res_sym_w["error"] == "unsafe_path"
        assert target_ledger.read_text(encoding="utf-8") == "SENTINEL"
        res_sym_r = derive_outcomes_from_ledger(sym_ledger)
        assert res_sym_r["ok"] is False and res_sym_r["error"] == "unsafe_path"
        assert res_sym_r["completeness"] == "unavailable" and res_sym_r["totals"] is None

        lock_target = tmp_path / "real.lock"
        lock_target.write_text("", encoding="utf-8")
        locked_ledger = tmp_path / "locked_ledger.json"
        locked_ledger.with_suffix(".lock").symlink_to(lock_target)
        res_lock = append_durable_events(locked_ledger, [sample_ev])
        assert res_lock["ok"] is False and res_lock["error"] == "unsafe_path"
        assert not locked_ledger.exists()

        rc_target = tmp_path / "real_receipts.jsonl"
        rc_target.write_text("", encoding="utf-8")
        sym_rc = tmp_path / "sym_receipts.jsonl"
        sym_rc.symlink_to(rc_target)
        out_ledger = tmp_path / "out_ledger.json"
        res_rc = ingest_context_receipts(out_ledger, sym_rc)
        assert res_rc["ok"] is False and res_rc["error"] == "unsafe_path"

        sym_dir = tmp_path / "sym_workdir"
        real_dir = tmp_path / "real_workdir"
        real_dir.mkdir()
        sym_dir.symlink_to(real_dir)
        conf_sym = run_cursor_cli_conformance(sym_dir)
        assert conf_sym["ok"] is False and conf_sym["error"] == "unsafe_path"
        assert conf_sym["admitted"] is False and conf_sym["comparisons_blocked"] is True

    blocked = tmp_path / "win_reparse_ledger.json"
    monkeypatch.setattr(spool_receipts, "check_unsafe_link", lambda p: Path(p) == blocked)
    res_mock = append_durable_events(blocked, [sample_ev])
    assert res_mock["ok"] is False and res_mock["error"] == "unsafe_path"
    assert not blocked.exists()
    res_mock_r = derive_outcomes_from_ledger(blocked)
    assert res_mock_r["ok"] is False and res_mock_r["error"] == "unsafe_path"


def test_capability_attestation_key_alone_never_proves_runtime_verified() -> None:
    """Verify CapabilityAttestationKey never implies runtime_verified and static ceilings cap unverified claims."""
    cfg_a = {"optimizers": {"range_trim": "active", "output_spool": "active"}, "config_path": "/Users/alice/.config/context-guard/config.json"}
    cfg_b = {"config_path": "/Users/bob/.config/context-guard/config.json", "optimizers": {"output_spool": "active", "range_trim": "active"}}
    hook_a = {"hooks": {"preToolUse": [{"command": "python3 /Users/alice/cg/hooks/pre_tool_use.py --harness cursor", "failClosed": True}]}}
    hook_b = {"hooks": {"preToolUse": [{"failClosed": True, "command": "python3 /Users/bob/cg/hooks/pre_tool_use.py --harness cursor"}]}}
    fp_a = compute_hook_config_fingerprint("cursor", cfg_a, hook_a)
    fp_b = compute_hook_config_fingerprint("cursor", cfg_b, hook_b)
    assert fp_a.startswith("sha256:") and len(fp_a) == 71
    assert fp_a == fp_b

    hook_changed = {"hooks": {"preToolUse": [{"command": "python3 /Users/bob/cg/hooks/pre_tool_use.py --harness cursor", "failClosed": False}]}}
    assert compute_hook_config_fingerprint("cursor", cfg_b, hook_changed) != fp_a

    key = build_capability_attestation_key(
        "cursor",
        "content_verified_reads",
        harness_build_id="cursor-2.1.0",
        hook_config_fingerprint=fp_a,
    )
    assert isinstance(key, CapabilityAttestationKey)
    assert key.adapter_version == ADAPTER_CONTRACT_VERSION

    no_probe = resolve_capability_requirement(key, claimed_level="runtime_verified", runtime_probe_passed=False, verification_evidence="probe_ok")
    assert no_probe["runtime_verified"] is False
    assert no_probe["evidence_level"] == "harness_exposed"
    assert no_probe["attestation_key"] == asdict(key)

    empty_ev = resolve_capability_requirement(key, claimed_level="runtime_verified", runtime_probe_passed=True, verification_evidence="   ")
    assert empty_ev["runtime_verified"] is False
    assert empty_ev["evidence_level"] == "harness_exposed"

    verified = resolve_capability_requirement(key, claimed_level="runtime_verified", runtime_probe_passed=True, verification_evidence="cursor_cli_conformance_tier2")
    assert verified["runtime_verified"] is True
    assert verified["evidence_level"] == "runtime_verified"
    assert verified["verification_source"] == "cursor_cli_conformance_tier2"

    cursor_out_key = build_capability_attestation_key("cursor", "output_replacement", hook_config_fingerprint=fp_a)
    assert resolve_capability_requirement(cursor_out_key)["evidence_level"] == "unsupported"
    cursor_cache_key = build_capability_attestation_key("cursor", "prompt_cache_telemetry", hook_config_fingerprint=fp_a)
    assert resolve_capability_requirement(cursor_cache_key)["evidence_level"] == "unsupported"
    claude_out_key = build_capability_attestation_key("claude", "output_replacement", hook_config_fingerprint=fp_a)
    assert resolve_capability_requirement(claude_out_key)["evidence_level"] == "harness_exposed"
    ag_fc_key = build_capability_attestation_key("antigravity", "native_fail_closed", hook_config_fingerprint=fp_a)
    assert resolve_capability_requirement(ag_fc_key)["evidence_level"] == "unsupported"
    codex_cv_key = build_capability_attestation_key("codex", "content_verified_reads", hook_config_fingerprint=fp_a)
    assert resolve_capability_requirement(codex_cv_key)["evidence_level"] == "unsupported"


def test_environment_metadata_reads_manifest_version_and_scrubs_home_paths(tmp_path: Path) -> None:
    """Verify context_guard_version is read dynamically from plugin.json and home paths are scrubbed."""
    expected_version = _repo_manifest_version()
    custom_home_leak = "/Users/" + "custom_dev_x/bin/cursor"
    win_home_leak = r"C:\Users\dev\AppData\Local\cursor"
    env_meta = collect_environment_metadata(
        "cursor",
        model_id="claude-sonnet-4-6",
        harness_build_id=f"build:{custom_home_leak}",
        runtime_cfg={
            "config_path": f"{custom_home_leak}/config.json",
            "policy_packs": [{"id": "sec_pack", "enabled": True, "kind": "security", "path": f"{win_home_leak}/pack.py"}],
        },
        hook_payload={"hooks": {"preToolUse": [{"command": f"python3 {win_home_leak}/pre_tool_use.py"}]}},
        runtime_verifications={"content_verified_reads": f"verified_in:{Path.home()}/probe"},
    )
    assert env_meta["context_guard_version"] == expected_version
    assert env_meta["attestation_key_implies_runtime_verified"] is False
    assert len(env_meta["required_capabilities"]) == len(REQUIRED_EVIDENCE_CAPABILITIES)
    assert env_meta["hook_config_fingerprint"].startswith("sha256:")

    serialized = json.dumps(env_meta)
    assert "custom_dev_x" not in serialized
    assert "/Users/" not in serialized
    assert "/home/" not in serialized
    assert r"C:\Users" not in serialized
    assert str(Path.home()) not in serialized

    custom_root = tmp_path / "custom_plugin"
    custom_root.mkdir()
    (custom_root / "plugin.json").write_text(json.dumps({"version": "9.8.1"}), encoding="utf-8")
    custom_meta = collect_environment_metadata("claude", model_id="claude-sonnet-4-6", plugin_root=custom_root)
    assert custom_meta["context_guard_version"] == "9.8.1"
    assert all(cap["runtime_verified"] is False for cap in custom_meta["required_capabilities"])


def test_cursor_cli_conformance_gate_admits_cursor_with_missing_cache_excluded(tmp_path: Path) -> None:
    """Verify isolated Cursor CLI conformance validates hooks, tier-2 read verification, and cache exclusion."""
    default_res = run_cursor_cli_conformance()
    assert default_res["ok"] is True
    assert default_res["harness_id"] == "cursor"
    assert default_res["admitted"] is True
    assert default_res["comparisons_blocked"] is False
    assert default_res["cache_attribution_status"] == "excluded_missing_telemetry"
    assert default_res["harness_output_capabilities"]["supports_content_verified_reads"] is True
    assert default_res["harness_output_capabilities"]["can_replace_tool_output"] is False
    assert default_res["hook_config_fingerprint"].startswith("sha256:")
    assert all(default_res["checks"].values())

    work_dir = tmp_path / "cursor_work"
    dir_res = run_cursor_cli_conformance(work_dir=work_dir)
    assert dir_res["ok"] is True and dir_res["admitted"] is True
    assert (work_dir / "state" / ".context_guard_state.json").is_file()

    cursor_env = collect_environment_metadata(
        "cursor",
        model_id="claude-sonnet-4-6",
        runtime_verifications={"content_verified_reads": "cursor_cli_conformance_tier2"},
    )
    by_cap = {c["capability_id"]: c for c in cursor_env["required_capabilities"]}
    assert by_cap["content_verified_reads"]["evidence_level"] == "runtime_verified"
    assert by_cap["content_verified_reads"]["runtime_verified"] is True
    assert by_cap["output_replacement"]["evidence_level"] == "unsupported"
    assert by_cap["prompt_cache_telemetry"]["evidence_level"] == "unsupported"
    assert ev_ledger.EVENT_LEDGER_SCHEMA_VERSION == 1
