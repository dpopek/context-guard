"""Contract, capability attestation, hysteresis breaker, and release-gate tests for policies.governor."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from evidence.conformance import replay_governor_decisions
from hooks import config as hooks_config, policy_engine, post_tool_use, pre_tool_use
import policies
from policies import api as policies_api, governor as policies_governor
from policies.api import (
    ADAPTER_CONTRACT_VERSION,
    CAPABILITY_CONTRACT_SCHEMA_VERSION,
    GOVERNOR_SCHEMA_VERSION,
    HARD_INTEGRITY_FAILURE_REASONS,
    NON_TRIPPING_SIGNALS,
    VALID_BREAKER_STATES,
    VALID_GOVERNOR_MODES,
    CapabilityContractV1,
    CircuitBreakerStateV1,
    GovernorContractV1,
    OptimizerDecisionV1,
)
from policies.governor import (
    DEFAULT_GOVERNOR_STATE_FILENAME,
    GOVERNED_CAPABILITIES,
    GOVERNED_OPTIMIZERS,
    OPTIMIZER_REQUIRED_CAPABILITIES,
    apply_runtime_governor,
    attest_capability,
    build_capability_attestation_key,
    compute_hook_config_fingerprint,
    evaluate_capability_contract,
    evaluate_governor,
    is_optimizer_tripped,
    is_provider_only_evidence,
    record_governor_signal,
    reset_circuit_breaker,
    resolve_governor_state_path,
)


def test_policies_exports_and_governor_constants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    expected = {
        "CAPABILITY_CONTRACT_SCHEMA_VERSION",
        "GOVERNOR_SCHEMA_VERSION",
        "VALID_GOVERNOR_MODES",
        "VALID_BREAKER_STATES",
        "HARD_INTEGRITY_FAILURE_REASONS",
        "NON_TRIPPING_SIGNALS",
        "CapabilityContractV1",
        "CircuitBreakerStateV1",
        "OptimizerDecisionV1",
        "GovernorContractV1",
    }
    assert expected.issubset(set(policies_api.__all__))
    assert expected.issubset(set(policies.__all__))
    for name in expected:
        assert getattr(policies, name) is getattr(policies_api, name)

    assert CAPABILITY_CONTRACT_SCHEMA_VERSION == 1
    assert GOVERNOR_SCHEMA_VERSION == 1
    assert VALID_GOVERNOR_MODES == ("active", "shadow", "passthrough")
    assert VALID_BREAKER_STATES == ("closed", "open", "half_open")
    assert set(HARD_INTEGRITY_FAILURE_REASONS) == {
        "integrity_mismatch", "unexpectedly_missing", "corrupt", "format_error",
        "guarantee_loss", "attestation_invalidated", "unknown_payload",
    }
    assert "suspected_regret" in NON_TRIPPING_SIGNALS
    assert "chunk_thrashing" in NON_TRIPPING_SIGNALS
    assert "ttl_expired" in NON_TRIPPING_SIGNALS

    assert set(CapabilityContractV1.__required_keys__) == {
        "schema_version", "capability_id", "evidence_level", "attestation_key",
        "verification_evidence", "verified_at", "runtime_verified",
        "provider_only_rejected", "invalidated_reason",
    }
    assert set(CircuitBreakerStateV1.__required_keys__) == {
        "optimizer_id", "state", "tripped", "trip_reason", "trip_count",
        "tripped_at", "last_verified_at", "ignored_signals",
        "requires_verification_or_operator_reset",
    }
    assert set(OptimizerDecisionV1.__required_keys__) == {
        "optimizer_id", "configured_mode", "selected_mode", "effective_config_mode",
        "reason", "required_capabilities", "min_evidence_level",
        "observed_evidence_level", "breaker_state", "downgraded",
    }
    assert set(GovernorContractV1.__required_keys__) == {
        "schema_version", "evaluated_at", "harness_id", "harness_build_id",
        "adapter_version", "hook_config_fingerprint", "payload_known",
        "evidence_gate_passed", "security_enforcement_lowered", "capabilities",
        "circuit_breakers", "decisions", "effective_optimizers",
    }
    assert DEFAULT_GOVERNOR_STATE_FILENAME == "governor_state.json"
    assert GOVERNED_OPTIMIZERS == ("range_trim", "auto_outline", "cli_rewrites", "output_spool")
    assert GOVERNED_CAPABILITIES == (
        "pre_tool_interception", "output_replacement", "native_fail_closed",
        "content_verified_reads", "prompt_cache_telemetry", "dynamic_tool_mutation",
    )
    assert set(OPTIMIZER_REQUIRED_CAPABILITIES) == {
        "range_trim", "auto_outline", "cli_rewrites", "output_spool", "dynamic_tool_mutation",
    }
    assert resolve_governor_state_path(tmp_path / "custom") == tmp_path / "custom" / "governor_state.json"
    monkeypatch.setenv("CONTEXT_GUARD_STATE_DIR", str(tmp_path / "env_state"))
    assert resolve_governor_state_path() == tmp_path / "env_state" / "governor_state.json"
    assert "is_provider_only_evidence" in policies_governor.__all__
    assert is_provider_only_evidence("provider_api:tools") is True
    assert is_provider_only_evidence("client_probe_ok") is False


def test_capability_contract_evidence_levels_and_provider_only_rejection(tmp_path: Path) -> None:
    cfg_a = {"optimizers": {"output_spool": "active"}, "config_path": "/Users/alice/.config/context-guard/config.json"}
    cfg_b = {"config_path": "C:\\Users\\bob\\config.json", "optimizers": {"output_spool": "active"}}
    hook_a = {"hooks": {"preToolUse": [{"command": "python3 /Users/alice/cg/hooks/pre_tool_use.py", "failClosed": True}]}}
    hook_b = {"hooks": {"preToolUse": [{"failClosed": True, "command": "python3 /Users/bob/cg/hooks/pre_tool_use.py"}]}}
    fp_a = compute_hook_config_fingerprint("claude", cfg_a, hook_a)
    fp_b = compute_hook_config_fingerprint("claude", cfg_b, hook_b)
    assert fp_a.startswith("sha256:") and len(fp_a) == 71
    assert fp_a == fp_b

    # All 4 evidence levels across harnesses and dynamic_tool_mutation
    k_claude_out = build_capability_attestation_key("claude", "output_replacement", hook_config_fingerprint=fp_a)
    assert evaluate_capability_contract(k_claude_out)["evidence_level"] == "harness_exposed"
    assert evaluate_capability_contract(k_claude_out, claimed_level="unsupported")["evidence_level"] == "unsupported"
    assert evaluate_capability_contract(k_claude_out, claimed_level="runtime_verified", verification_evidence="  ")["evidence_level"] == "harness_exposed"

    for bad_harness, bad_cap in (
        ("cursor", "output_replacement"),
        ("cursor", "prompt_cache_telemetry"),
        ("antigravity", "content_verified_reads"),
        ("antigravity", "native_fail_closed"),
        ("codex", "content_verified_reads"),
        ("codex", "output_replacement"),
        ("unknown_cli", "pre_tool_interception"),
    ):
        c_un = evaluate_capability_contract(build_capability_attestation_key(bad_harness, bad_cap, hook_config_fingerprint=fp_a))
        assert c_un["evidence_level"] == "unsupported"
        assert c_un["runtime_verified"] is False

    # Provider-only evidence prefixes and claimed_level="provider_supported" rejected
    k_dyn = build_capability_attestation_key("claude", "dynamic_tool_mutation", hook_config_fingerprint=fp_a)
    unattested_dyn = evaluate_capability_contract(k_dyn)
    assert unattested_dyn["evidence_level"] == "unsupported"
    assert unattested_dyn["provider_only_rejected"] is True
    assert unattested_dyn["runtime_verified"] is False

    for ev_prefix in ("model_api:tool_search", "provider_api:tool_search", "upstream_provider:beta"):
        rej = evaluate_capability_contract(k_dyn, claimed_level="runtime_verified", verification_evidence=ev_prefix)
        assert rej["provider_only_rejected"] is True
        assert rej["runtime_verified"] is False
        assert rej["evidence_level"] == "provider_supported"

        sdir = tmp_path / ev_prefix.split(":")[0]
        persisted_rej = attest_capability("claude", "dynamic_tool_mutation", verification_evidence=ev_prefix, state_dir=sdir)
        assert persisted_rej["provider_only_rejected"] is True
        assert persisted_rej["runtime_verified"] is False
        gov_rej = evaluate_governor("claude", runtime_cfg={"optimizers": {"dynamic_tool_mutation": "active", "output_spool": "active"}}, state_dir=sdir)
        assert gov_rej["decisions"]["dynamic_tool_mutation"]["selected_mode"] != "active"

    # Client-side attestation upgrades to runtime_verified and scrubs home paths
    att_dir = tmp_path / "attested"
    att_ok = attest_capability(
        "claude", "output_replacement",
        verification_evidence="client_probe_verified:/Users/alice/probe.log",
        harness_build_id="2.1.300", runtime_cfg=cfg_a, hook_payload=hook_a, state_dir=att_dir,
    )
    assert att_ok["runtime_verified"] is True
    assert att_ok["provider_only_rejected"] is False
    assert att_ok["evidence_level"] == "runtime_verified"
    assert "alice" not in (att_ok["verification_evidence"] or "")
    state_file = resolve_governor_state_path(att_dir)
    assert state_file.is_file()
    if os.name != "nt":
        assert (state_file.stat().st_mode & 0o777) == 0o600

    dyn_ok = attest_capability("claude", "dynamic_tool_mutation", verification_evidence="client_tool_registry_verified", state_dir=att_dir)
    assert dyn_ok["runtime_verified"] is True
    assert dyn_ok["provider_only_rejected"] is False


def test_attestation_invalidation_on_harness_build_adapter_config_and_unknown_payload(tmp_path: Path) -> None:
    cfg_a = {"optimizers": {"output_spool": "active"}, "read_confirm_policy": "strict"}
    hook_a = {"hooks": {"PostToolUse": [{"command": "python3 /Users/dev/cg/hooks/post_tool_use.py"}]}}
    sdir = tmp_path / "att_inv"

    for cap_id, ev in (
        ("pre_tool_interception", "client_pre_tool_hook_verified"),
        ("output_replacement", "client_spool_roundtrip_passed"),
    ):
        attest_capability(
            "claude", cap_id,
            verification_evidence=ev,
            harness_build_id="claude-1.0.0",
            adapter_version=ADAPTER_CONTRACT_VERSION,
            runtime_cfg=cfg_a,
            hook_payload=hook_a,
            state_dir=sdir,
        )
    valid = evaluate_governor(
        "claude", runtime_cfg=cfg_a, state_dir=sdir,
        harness_build_id="claude-1.0.0", adapter_version=ADAPTER_CONTRACT_VERSION,
        hook_payload=hook_a, require_runtime_verified=True,
    )
    assert valid["capabilities"]["pre_tool_interception"]["runtime_verified"] is True
    assert valid["capabilities"]["output_replacement"]["runtime_verified"] is True
    assert valid["capabilities"]["output_replacement"]["invalidated_reason"] is None
    assert valid["decisions"]["output_spool"]["selected_mode"] == "active"

    # Harness changed
    ch_harness = evaluate_governor("cursor", runtime_cfg=cfg_a, state_dir=sdir, harness_build_id="claude-1.0.0", hook_payload=hook_a)
    assert ch_harness["capabilities"]["output_replacement"]["invalidated_reason"] == "harness_changed"
    assert ch_harness["capabilities"]["output_replacement"]["runtime_verified"] is False

    # Build changed
    ch_build = evaluate_governor("claude", runtime_cfg=cfg_a, state_dir=sdir, harness_build_id="claude-2.0.0", hook_payload=hook_a, require_runtime_verified=True)
    assert ch_build["capabilities"]["output_replacement"]["invalidated_reason"] == "build_changed"
    assert ch_build["capabilities"]["output_replacement"]["runtime_verified"] is False
    assert ch_build["decisions"]["output_spool"]["selected_mode"] == "shadow"

    # Adapter changed
    ch_adapter = evaluate_governor("claude", runtime_cfg=cfg_a, state_dir=sdir, harness_build_id="claude-1.0.0", adapter_version="harness_adapter_v2", hook_payload=hook_a, require_runtime_verified=True)
    assert ch_adapter["capabilities"]["output_replacement"]["invalidated_reason"] == "adapter_changed"
    assert ch_adapter["capabilities"]["output_replacement"]["runtime_verified"] is False

    # Config / hook payload changed
    cfg_b = {"optimizers": {"output_spool": "active"}, "read_confirm_policy": "bounded"}
    ch_cfg = evaluate_governor("claude", runtime_cfg=cfg_b, state_dir=sdir, harness_build_id="claude-1.0.0", hook_payload=hook_a, require_runtime_verified=True)
    assert ch_cfg["capabilities"]["output_replacement"]["invalidated_reason"] == "config_fingerprint_changed"

    hook_b = {"hooks": {"PostToolUse": [{"command": "python3 /Users/dev/cg/hooks/post_tool_use.py --extra"}]}}
    ch_hook = evaluate_governor("claude", runtime_cfg=cfg_a, state_dir=sdir, harness_build_id="claude-1.0.0", hook_payload=hook_b)
    assert ch_hook["capabilities"]["output_replacement"]["invalidated_reason"] == "config_fingerprint_changed"

    # Unknown payload invalidates guarantees and forces safe passthrough
    unk = evaluate_governor("claude", runtime_cfg=cfg_a, state_dir=sdir, harness_build_id="claude-1.0.0", hook_payload=hook_a, payload_known=False)
    assert unk["payload_known"] is False
    assert unk["capabilities"]["output_replacement"]["invalidated_reason"] == "unknown_payload"
    assert unk["capabilities"]["output_replacement"]["runtime_verified"] is False
    assert unk["decisions"]["output_spool"]["selected_mode"] == "passthrough"
    assert unk["decisions"]["range_trim"]["selected_mode"] == "passthrough"
    assert unk["effective_optimizers"]["output_spool"] == "off"

    # Optional runtime_cfg["governor"] section overrides
    gov_cfg = {**cfg_a, "governor": {"harness_build_id": "claude-2.0.0", "require_runtime_verified": True}}
    from_cfg = apply_runtime_governor(gov_cfg, "claude", state_dir=sdir, payload={"tool_name": "Bash"})
    assert from_cfg["optimizers"]["output_spool"] == "shadow"


def test_governor_deterministic_mode_selection_and_evidence_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Fast O(1) parity path performs zero disk reads when no governor_state.json and no "governor" section exist
    empty_state = tmp_path / "empty_state"
    static_cfg = {
        "read_confirm_policy": "bounded",
        "optimizers": {"range_trim": "active", "auto_outline": "active", "cli_rewrites": "force", "output_spool": "off"},
        "policy_packs": [{"id": "sec", "enabled": True, "kind": "security"}],
        "legacy_security_keys": ("restricted_bq_datasets",),
    }

    def _forbid_json_loads(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("fast O(1) parity path must perform zero disk JSON reads")

    monkeypatch.setattr(json, "loads", _forbid_json_loads)
    parity = apply_runtime_governor(static_cfg, "antigravity", state_dir=empty_state, payload={"tool_name": "view_file"})
    assert parity == static_cfg
    assert parity is not static_cfg
    monkeypatch.undo()

    # Antigravity and Codex with strict read_confirm_policy downgrade range_trim active -> shadow
    for h in ("antigravity", "codex"):
        dec = evaluate_governor(h, runtime_cfg={"read_confirm_policy": "strict", "optimizers": {"range_trim": "active", "output_spool": "active", "cli_rewrites": "auto"}}, state_dir=empty_state)
        assert dec["decisions"]["range_trim"]["selected_mode"] == "shadow"
        assert dec["decisions"]["range_trim"]["reason"] == "capability_unverified:content_verified_reads"
        assert dec["decisions"]["range_trim"]["downgraded"] is True
        assert dec["decisions"]["output_spool"]["selected_mode"] == "shadow"
        assert dec["decisions"]["output_spool"]["reason"] == "capability_unverified:output_replacement"
        assert dec["decisions"]["cli_rewrites"]["selected_mode"] == "active"
        assert dec["decisions"]["cli_rewrites"]["effective_config_mode"] == "auto"

    # Antigravity with bounded read_confirm_policy retains range_trim="active"
    bounded_ag = evaluate_governor("antigravity", runtime_cfg={"read_confirm_policy": "bounded", "optimizers": {"range_trim": "active"}}, state_dir=empty_state)
    assert bounded_ag["decisions"]["range_trim"]["selected_mode"] == "active"
    assert bounded_ag["decisions"]["range_trim"]["downgraded"] is False

    # Cursor downgrades output_spool="active" -> "shadow" while Claude allows "active"
    cur_dec = evaluate_governor("cursor", runtime_cfg={"optimizers": {"output_spool": "active", "range_trim": "active"}}, state_dir=empty_state)
    assert cur_dec["decisions"]["output_spool"]["selected_mode"] == "shadow"
    assert cur_dec["decisions"]["range_trim"]["selected_mode"] == "active"

    cl_dec = evaluate_governor("claude", runtime_cfg={"optimizers": {"output_spool": "active", "cli_rewrites": "force"}}, state_dir=empty_state)
    assert cl_dec["decisions"]["output_spool"]["selected_mode"] == "active"
    assert cl_dec["decisions"]["cli_rewrites"]["effective_config_mode"] == "force"

    # Unknown harness without pre_tool_interception drops to passthrough
    unk_h = evaluate_governor("mystery_harness", runtime_cfg={"optimizers": {"output_spool": "active", "auto_outline": "shadow"}}, state_dir=empty_state)
    assert unk_h["decisions"]["output_spool"]["selected_mode"] == "passthrough"
    assert unk_h["decisions"]["auto_outline"]["selected_mode"] == "passthrough"

    # EvidenceContractV1 gate enforcement
    ev_fail = evaluate_governor(
        "claude", runtime_cfg={"optimizers": {"output_spool": "active", "cli_rewrites": "auto"}},
        evidence_gate_required=True, evidence_report={"gate_verdict": {"ok": False}}, state_dir=empty_state,
    )
    assert ev_fail["evidence_gate_passed"] is False
    assert ev_fail["decisions"]["output_spool"]["selected_mode"] == "shadow"
    assert ev_fail["decisions"]["output_spool"]["reason"] == "evidence_gate_not_passed"
    assert ev_fail["decisions"]["cli_rewrites"]["selected_mode"] == "active"

    ev_missing = evaluate_governor("claude", runtime_cfg={"optimizers": {"output_spool": "active"}}, evidence_gate_required=True, state_dir=empty_state)
    assert ev_missing["evidence_gate_passed"] is False
    assert ev_missing["decisions"]["output_spool"]["selected_mode"] == "shadow"

    ev_pass = evaluate_governor(
        "claude", runtime_cfg={"optimizers": {"output_spool": "active"}},
        evidence_gate_required=True, evidence_report={"gate_verdict": {"ok": True}}, state_dir=empty_state,
    )
    assert ev_pass["evidence_gate_passed"] is True
    assert ev_pass["decisions"]["output_spool"]["selected_mode"] == "active"


def test_circuit_breaker_trips_only_on_hard_failures_with_hysteresis(tmp_path: Path) -> None:
    sdir = tmp_path / "state"
    spool_dir = sdir / "spool"

    # All NON_TRIPPING_SIGNALS increment ignored_signals without tripping
    for idx, sig in enumerate(NON_TRIPPING_SIGNALS, 1):
        st = record_governor_signal("output_spool", sig, state_dir=sdir)
        assert st["tripped"] is False
        assert st["state"] == "closed"
        assert st["ignored_signals"] == idx
        assert is_optimizer_tripped("output_spool", state_dir=sdir) is False

    # Hard failure reported via spool_dir writes to the unified parent state/governor_state.json
    hard_st = record_governor_signal("output_spool", "integrity_mismatch", state_dir=spool_dir, harness="claude", session_id="s1")
    assert hard_st["tripped"] is True
    assert hard_st["state"] == "open"
    assert hard_st["trip_reason"] == "integrity_mismatch"
    assert hard_st["requires_verification_or_operator_reset"] is True
    assert is_optimizer_tripped("output_spool", state_dir=spool_dir) is True
    assert is_optimizer_tripped("output_spool", state_dir=sdir) is True
    assert not (spool_dir / DEFAULT_GOVERNOR_STATE_FILENAME).exists()
    assert (sdir / DEFAULT_GOVERNOR_STATE_FILENAME).is_file()

    # Soft signal while open preserves open state (hysteresis)
    after_soft = record_governor_signal("output_spool", "suspected_regret", state_dir=sdir)
    assert after_soft["tripped"] is True
    assert after_soft["state"] == "open"

    # Failed resets keep breaker open
    bad_reset_cases: tuple[tuple[bool, str | None, bool, str | None], ...] = (
        (False, None, False, None),
        (True, "", False, None),
        (True, "provider_api:ok", False, None),
        (False, "valid_evidence", False, None),
        (False, None, True, "   "),
        (False, None, False, "manual override"),
    )
    for vp, ve, opr, opr_rsn in bad_reset_cases:
        res_bad = reset_circuit_breaker(
            "output_spool",
            state_dir=sdir,
            verification_passed=vp,
            verification_evidence=ve,
            operator_reset=opr,
            operator_reason=opr_rsn,
        )
        assert res_bad["ok"] is False
        assert res_bad["error"] == "hysteresis_requires_verification_or_operator_reset"
        assert is_optimizer_tripped("output_spool", state_dir=sdir) is True
        assert is_optimizer_tripped("output_spool", state_dir=spool_dir) is True

    # Valid verification reset closes the unified canonical breaker state
    res_ver = reset_circuit_breaker("output_spool", state_dir=sdir, verification_passed=True, verification_evidence="spool_roundtrip_ok")
    assert res_ver["ok"] is True
    assert res_ver["reset_mode"] == "verification"
    assert res_ver["breaker"]["state"] == "closed"
    assert res_ver["breaker"]["tripped"] is False
    assert res_ver["breaker"]["last_verified_at"] is not None
    assert is_optimizer_tripped("output_spool", state_dir=sdir) is False
    assert is_optimizer_tripped("output_spool", state_dir=spool_dir) is False

    # Every HARD_INTEGRITY_FAILURE_REASONS trips, and operator_reset recovers
    for reason in HARD_INTEGRITY_FAILURE_REASONS:
        r_dir = tmp_path / f"hard_{reason}"
        tripped = record_governor_signal("range_trim", reason, state_dir=r_dir)
        assert tripped["tripped"] is True and tripped["trip_reason"] == reason
        assert is_optimizer_tripped("range_trim", state_dir=r_dir) is True
        res_op = reset_circuit_breaker("range_trim", state_dir=r_dir, operator_reset=True, operator_reason="verified_after_inspection")
        assert res_op["ok"] is True and res_op["reset_mode"] == "operator"
        assert is_optimizer_tripped("range_trim", state_dir=r_dir) is False


def test_security_enforcement_never_lowered_and_unsafe_links_rejected(tmp_path: Path) -> None:
    sdir = tmp_path / "sec_state"
    sec_cfg: dict[str, Any] = {
        "read_confirm_policy": "strict",
        "optimizers": {"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "active"},
        "policy_packs": [{"id": "corp_guard", "enabled": True, "kind": "security", "scopes": ["shell_command", "file_mutation"]}],
        "legacy_security_keys": ("restricted_bq_datasets", "enforce_governance_policy"),
    }
    record_governor_signal("output_spool", "guarantee_loss", state_dir=sdir)
    bad_payload: Any = ["unexpected_list_payload"]
    out = apply_runtime_governor(sec_cfg, "antigravity", state_dir=sdir, payload=bad_payload)
    assert out["policy_packs"] == sec_cfg["policy_packs"]
    assert out["legacy_security_keys"] == sec_cfg["legacy_security_keys"]
    assert all(v == "off" for v in out["optimizers"].values())
    assert sec_cfg["optimizers"]["output_spool"] == "active"

    gov = evaluate_governor("antigravity", runtime_cfg=sec_cfg, state_dir=sdir, payload_known=False)
    assert gov["security_enforcement_lowered"] is False

    # Corrupt governor_state.json fails safe without raising
    corrupt_dir = tmp_path / "corrupt"
    corrupt_dir.mkdir()
    (corrupt_dir / DEFAULT_GOVERNOR_STATE_FILENAME).write_text("{broken json", encoding="utf-8")
    assert is_optimizer_tripped("output_spool", state_dir=corrupt_dir) is True
    out_corrupt = apply_runtime_governor(sec_cfg, "claude", state_dir=corrupt_dir, payload={"tool_name": "Bash"})
    assert out_corrupt["optimizers"]["output_spool"] == "off"
    assert out_corrupt["policy_packs"] == sec_cfg["policy_packs"]

    # Unsafe symlinks rejected safely
    if not hasattr(os, "symlink"):
        pytest.skip("os.symlink unavailable")
    sym_dir = tmp_path / "sym_dir"
    sym_dir.mkdir()
    real_target = tmp_path / "outside_target.json"
    real_target.write_text('{"sentinel": true}', encoding="utf-8")
    try:
        (sym_dir / DEFAULT_GOVERNOR_STATE_FILENAME).symlink_to(real_target)
    except OSError:
        pytest.skip("symlink creation requires elevated privilege on this platform")

    assert is_optimizer_tripped("output_spool", state_dir=sym_dir) is True
    sig_sym = record_governor_signal("output_spool", "integrity_mismatch", state_dir=sym_dir)
    assert sig_sym["tripped"] is True and sig_sym["trip_reason"] == "unsafe_path"
    assert json.loads(real_target.read_text(encoding="utf-8")) == {"sentinel": True}

    rst_sym = reset_circuit_breaker("output_spool", state_dir=sym_dir, operator_reset=True, operator_reason="test")
    assert rst_sym["ok"] is False and rst_sym["error"] == "unsafe_path"
    att_sym = attest_capability("claude", "output_replacement", verification_evidence="probe_ok", state_dir=sym_dir)
    assert att_sym["runtime_verified"] is False and att_sym["invalidated_reason"] == "unsafe_path"


def test_replay_governor_decisions_passes_all_release_gates() -> None:
    assert not hasattr(policies_governor, "replay_governor_decisions")
    res_a = replay_governor_decisions()
    res_b = replay_governor_decisions()
    assert res_a == res_b
    assert res_a["schema_version"] == GOVERNOR_SCHEMA_VERSION
    assert res_a["ok"] is True
    assert res_a["checks_passed"] == 8
    assert res_a["checks_total"] == 8
    expected_gates = {
        "static_config_parity",
        "provider_only_rejected",
        "harness_upgrade_invalidation",
        "config_change_invalidation",
        "breaker_trips_only_on_hard_failures",
        "hysteresis_enforced",
        "security_never_lowered",
        "evidence_gate_enforced",
    }
    assert set(res_a["gates"]) == expected_gates
    assert all(res_a["gates"][k] is True for k in expected_gates)
    assert len(res_a["scenarios"]) == 8
    assert all(item["passed"] is True for item in res_a["scenarios"])

    custom_ok = replay_governor_decisions([
        {"id": "cursor_spool_shadow", "harness_id": "cursor", "runtime_cfg": {"optimizers": {"output_spool": "active"}}, "expected_modes": {"output_spool": "shadow"}},
    ])
    assert custom_ok["ok"] is True
    custom_fail = replay_governor_decisions([
        {"id": "cursor_spool_cannot_activate", "harness_id": "cursor", "runtime_cfg": {"optimizers": {"output_spool": "active"}}, "expected_modes": {"output_spool": "active"}},
    ])
    assert custom_fail["ok"] is False


def test_evaluate_capability_contract_enforces_static_ceiling_upper_bound(tmp_path: Path) -> None:
    fp = compute_hook_config_fingerprint("codex", {"optimizers": {"output_spool": "active"}})
    unsupported_pairs = (
        ("codex", "output_replacement"),
        ("cursor", "output_replacement"),
        ("cursor", "prompt_cache_telemetry"),
        ("antigravity", "content_verified_reads"),
        ("unknown_cli", "pre_tool_interception"),
        ("unknown_cli", "dynamic_tool_mutation"),
    )
    for harness_id, capability_id in unsupported_pairs:
        key = build_capability_attestation_key(harness_id, capability_id, hook_config_fingerprint=fp)
        direct = evaluate_capability_contract(
            key, claimed_level="runtime_verified", verification_evidence="custom_probe_ok",
        )
        assert direct["evidence_level"] == "unsupported"
        assert direct["runtime_verified"] is False

        unclaimed = evaluate_capability_contract(key, verification_evidence="custom_probe_ok")
        assert unclaimed["evidence_level"] == "unsupported"
        assert unclaimed["runtime_verified"] is False

        stored_tamper: dict[str, Any] = {
            "schema_version": CAPABILITY_CONTRACT_SCHEMA_VERSION,
            "capability_id": capability_id,
            "evidence_level": "runtime_verified",
            "attestation_key": {
                "harness_id": key.harness_id,
                "harness_build_id": key.harness_build_id,
                "adapter_version": key.adapter_version,
                "hook_config_fingerprint": key.hook_config_fingerprint,
                "capability_id": key.capability_id,
            },
            "verification_evidence": "custom_probe_ok",
            "verified_at": "2026-01-01T00:00:00Z",
            "runtime_verified": True,
            "provider_only_rejected": False,
            "invalidated_reason": None,
        }
        from_stored = evaluate_capability_contract(key, stored_attestation=stored_tamper)
        assert from_stored["evidence_level"] == "unsupported"
        assert from_stored["runtime_verified"] is False

    persisted = attest_capability(
        "codex", "output_replacement", verification_evidence="custom_probe_ok", state_dir=tmp_path,
    )
    assert persisted["evidence_level"] == "unsupported"
    assert persisted["runtime_verified"] is False
    gov = evaluate_governor("codex", runtime_cfg={"optimizers": {"output_spool": "active"}}, state_dir=tmp_path)
    assert gov["capabilities"]["output_replacement"]["evidence_level"] == "unsupported"
    assert gov["capabilities"]["output_replacement"]["runtime_verified"] is False
    assert gov["decisions"]["output_spool"]["selected_mode"] == "shadow"


def test_resolve_governor_state_path_unifies_spool_subdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir = tmp_path / "state"
    spool_dir = state_dir / "spool"
    expected = state_dir / DEFAULT_GOVERNOR_STATE_FILENAME

    assert resolve_governor_state_path(state_dir) == expected
    assert resolve_governor_state_path(spool_dir) == expected
    assert resolve_governor_state_path(f"{spool_dir}{os.sep}") == expected
    assert resolve_governor_state_path(state_dir / "spool_alt") == state_dir / "spool_alt" / DEFAULT_GOVERNOR_STATE_FILENAME

    monkeypatch.setenv("CONTEXT_GUARD_STATE_DIR", str(spool_dir))
    assert resolve_governor_state_path() == expected

    tripped = record_governor_signal("output_spool", "integrity_mismatch", state_dir=spool_dir)
    assert tripped["tripped"] is True
    assert expected.is_file()
    assert not (spool_dir / DEFAULT_GOVERNOR_STATE_FILENAME).exists()
    assert is_optimizer_tripped("output_spool", state_dir=state_dir) is True
    assert is_optimizer_tripped("output_spool", state_dir=spool_dir) is True


def _write_cfg_file(home_dir: Path, payload: dict[str, Any]) -> Path:
    cfg_path = home_dir / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    hooks_config.clear_config_cache()
    policy_engine.clear_pack_cache()
    return cfg_path


def _write_sec_pack(home_dir: Path, pack_id: str, blocked_token: str) -> dict[str, Any]:
    pack_dir = home_dir / ".config" / "context-guard" / "policies" / pack_id
    pack_dir.mkdir(parents=True, exist_ok=True)
    src = (
        "from __future__ import annotations\n"
        "from policies.api import ALL_SECURITY_SCOPES, PolicyDecision, PolicyPackManifest\n\n"
        "def evaluate(ctx):\n"
        "    cmd = str(ctx.canonical_args.get('CommandLine') or ctx.canonical_args.get('command') or '')\n"
        f"    return PolicyDecision(decision='deny', reason='blocked by {pack_id}') if {blocked_token!r} in cmd else None\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        f"    pack_id={pack_id!r}, api_version=1, kind='security',\n"
        "    covered_domains=ALL_SECURITY_SCOPES, evaluate=evaluate, harness_matchers={},\n"
        ")\n"
    ).encode("utf-8")
    entry_file = pack_dir / "pack.py"
    entry_file.write_bytes(src)
    fh = hashlib.sha256(src).hexdigest()
    return {
        "id": pack_id, "path": str(entry_file), "enabled": True, "kind": "security",
        "scopes": ["file_mutation", "shell_command", "mcp_call"],
        "file_hashes": {"pack.py": fh},
        "tree_sha256": hashlib.sha256(f"pack.py:{fh}\n".encode("utf-8")).hexdigest(),
    }


def test_load_runtime_config_validates_governor_and_dynamic_tool_mutation(isolated_user_env: Path) -> None:
    cfg_path = _write_cfg_file(isolated_user_env, {"read_confirm_policy": "strict"})
    plain = hooks_config.load_runtime_config(cfg_path)
    assert plain["config_error"] is None
    assert "governor" not in plain
    assert "dynamic_tool_mutation" not in plain["optimizers"]
    assert "governor" not in hooks_config.REQUIRED_CONFIG_KEYS

    _write_cfg_file(
        isolated_user_env,
        {
            "optimizers": {"output_spool": "active", "dynamic_tool_mutation": "active"},
            "governor": {
                "harness_build_id": " 2.1.0 ", "adapter_version": " harness_adapter_v1 ",
                "require_runtime_verified": True, "evidence_gate_required": False,
                "evidence_report": {"gate_verdict": {"ok": True}},
            },
        },
    )
    valid = hooks_config.load_runtime_config(cfg_path)
    assert valid["config_error"] is None
    assert valid["optimizers"]["dynamic_tool_mutation"] == "active"
    assert valid["governor"] == {
        "harness_build_id": "2.1.0", "adapter_version": "harness_adapter_v1",
        "require_runtime_verified": True, "evidence_gate_required": False,
        "evidence_report": {"gate_verdict": {"ok": True}},
    }

    _write_cfg_file(isolated_user_env, {"governor": {"harness_build_id": None, "require_runtime_verified": True}})
    nullable = hooks_config.load_runtime_config(cfg_path)
    assert nullable["config_error"] is None and nullable["governor"] == {"require_runtime_verified": True}

    bad_cases: tuple[tuple[dict[str, Any], str], ...] = (
        ({"governor": "bad"}, "invalid 'governor': expected object"),
        ({"governor": {"harness_build_id": "   "}}, "invalid 'governor.harness_build_id'"),
        ({"governor": {"adapter_version": 123}}, "invalid 'governor.adapter_version'"),
        ({"governor": {"require_runtime_verified": "true"}}, "invalid 'governor.require_runtime_verified'"),
        ({"governor": {"evidence_gate_required": 1}}, "invalid 'governor.evidence_gate_required'"),
        ({"governor": {"evidence_report": ["bad"]}}, "invalid 'governor.evidence_report'"),
        ({"optimizers": {"dynamic_tool_mutation": "bogus"}}, "invalid 'optimizers.dynamic_tool_mutation'"),
    )
    for raw_cfg, expected_err in bad_cases:
        _write_cfg_file(isolated_user_env, raw_cfg)
        assert hooks_config.load_runtime_config(cfg_path)["config_error"] == expected_err


def test_e2e_config_governor_downgrades_hooks_while_enforcing_security_packs(
    isolated_user_env: Path, tmp_path: Path,
) -> None:
    ws = tmp_path / "ws"
    (ws / ".git").mkdir(parents=True)
    pack_entry = _write_sec_pack(isolated_user_env, "gov_sec", "forbidden_gov_cmd")
    big_out = "\n".join(f"line {i}: " + ("x" * 80) for i in range(260))

    # 1. require_runtime_verified=True + dynamic_tool_mutation=active with empty state_dir
    _write_cfg_file(
        isolated_user_env,
        {
            "optimizers": {"output_spool": "active", "dynamic_tool_mutation": "active"},
            "governor": {"require_runtime_verified": True},
            "policy_packs": [pack_entry],
        },
    )
    loaded_rt = hooks_config.load_runtime_config()
    assert loaded_rt["config_error"] is None
    assert loaded_rt["optimizers"]["dynamic_tool_mutation"] == "active"
    assert loaded_rt["governor"]["require_runtime_verified"] is True

    empty_rt = tmp_path / "empty_rt"
    empty_rt.mkdir()
    gov_rt = apply_runtime_governor(loaded_rt, "claude", state_dir=empty_rt, payload={"tool_name": "Bash"})
    assert gov_rt["optimizers"]["output_spool"] == "shadow"
    assert gov_rt["optimizers"]["dynamic_tool_mutation"] == "shadow"
    ev_rt = evaluate_governor("claude", runtime_cfg=loaded_rt, state_dir=empty_rt)
    assert ev_rt["decisions"]["dynamic_tool_mutation"]["downgraded"] is True

    pre_deny = pre_tool_use.evaluate_hook(
        {"tool_name": "Bash", "tool_input": {"command": "echo forbidden_gov_cmd"}, "session_id": "s-rt", "cwd": str(ws)},
        state_dir=str(empty_rt), cli_harness="claude",
    )
    assert pre_deny["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "blocked by gov_sec" in pre_deny["hookSpecificOutput"]["permissionDecisionReason"]
    post_rt = post_tool_use.handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "tool_name": "Bash",
            "tool_input": {"command": "pytest"}, "tool_response": {"stdout": big_out},
            "session_id": "s-rt", "cwd": str(ws),
        },
        state_dir=str(empty_rt),
    )
    assert post_rt == {}
    assert (empty_rt / "shadow.json").is_file()

    # 2. evidence_gate_required=True without evidence_report downgrades output_spool -> shadow
    _write_cfg_file(
        isolated_user_env,
        {
            "optimizers": {"output_spool": "active"},
            "governor": {"evidence_gate_required": True},
            "policy_packs": [pack_entry],
        },
    )
    loaded_ev = hooks_config.load_runtime_config()
    assert loaded_ev["governor"]["evidence_gate_required"] is True
    empty_ev = tmp_path / "empty_ev"
    empty_ev.mkdir()
    pre_deny_ev = pre_tool_use.evaluate_hook(
        {"tool_name": "Bash", "tool_input": {"command": "echo forbidden_gov_cmd"}, "session_id": "s-ev", "cwd": str(ws)},
        state_dir=str(empty_ev), cli_harness="claude",
    )
    assert pre_deny_ev["hookSpecificOutput"]["permissionDecision"] == "deny"
    post_ev = post_tool_use.handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "tool_name": "Bash",
            "tool_input": {"command": "pytest"}, "tool_response": {"stdout": big_out},
            "session_id": "s-ev", "cwd": str(ws),
        },
        state_dir=str(empty_ev),
    )
    assert post_ev == {}
    assert (empty_ev / "shadow.json").is_file()

    # Passing evidence_report ok=True activates output_spool through config.json
    _write_cfg_file(
        isolated_user_env,
        {
            "optimizers": {"output_spool": "active"},
            "governor": {"evidence_gate_required": True, "evidence_report": {"gate_verdict": {"ok": True}}},
        },
    )
    post_pass = post_tool_use.handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "tool_name": "Bash",
            "tool_input": {"command": "pytest"}, "tool_response": {"stdout": big_out},
            "session_id": "s-ev-ok", "cwd": str(ws),
        },
        state_dir=str(tmp_path / "empty_ev_ok"),
    )
    assert "CONTEXT-GUARD OUTPUT SPOOL" in post_pass["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


def test_unknown_dict_payloads_and_client_build_version_invalidation(tmp_path: Path) -> None:
    sec_cfg: dict[str, Any] = {
        "read_confirm_policy": "strict",
        "optimizers": {"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "active"},
        "policy_packs": [{"id": "corp_guard", "enabled": True, "kind": "security", "scopes": ["shell_command"]}],
        "legacy_security_keys": ("restricted_bq_datasets",),
    }
    att_dir = tmp_path / "att_unk"
    for cap_id in ("pre_tool_interception", "output_replacement", "content_verified_reads"):
        attest_capability("claude", cap_id, verification_evidence=f"ok:{cap_id}", runtime_cfg=sec_cfg, state_dir=att_dir)

    assert apply_runtime_governor(sec_cfg, "claude", state_dir=att_dir, payload={"tool_name": "Bash"})["optimizers"]["output_spool"] == "active"
    for bad_payload in ({}, {"unknown_schema": 1}, {"tool_name": 123}, {"tool_name": "   "}, {"toolCall": {"name": 99}}, {"hook_event_name": "BogusEvent"}):
        out = apply_runtime_governor(sec_cfg, "claude", state_dir=att_dir, payload=bad_payload)
        assert all(v == "off" for v in out["optimizers"].values())
        assert out["policy_packs"] == sec_cfg["policy_packs"]
        assert out["legacy_security_keys"] == sec_cfg["legacy_security_keys"]

    # Client build versions (cursor_version and claude_version) invalidate prior build attestations
    cur_cfg: dict[str, Any] = {
        "read_confirm_policy": "strict",
        "optimizers": {"range_trim": "active"},
        "governor": {"require_runtime_verified": True},
    }
    cur_dir = tmp_path / "cur_build"
    for cap_id in ("pre_tool_interception", "content_verified_reads"):
        attest_capability("cursor", cap_id, verification_evidence=f"probe:{cap_id}", harness_build_id="2.1.0", runtime_cfg=cur_cfg, state_dir=cur_dir)
    cur_same = apply_runtime_governor(cur_cfg, "cursor", state_dir=cur_dir, payload={"tool_name": "Read", "cursor_version": "2.1.0"})
    assert cur_same["optimizers"]["range_trim"] == "active"
    cur_upg = apply_runtime_governor(cur_cfg, "cursor", state_dir=cur_dir, payload={"tool_name": "Read", "cursor_version": "2.2.0"})
    assert cur_upg["optimizers"]["range_trim"] == "shadow"
    assert evaluate_governor("cursor", runtime_cfg=cur_cfg, state_dir=cur_dir, harness_build_id="2.2.0")["capabilities"]["content_verified_reads"]["invalidated_reason"] == "build_changed"

    cl_cfg: dict[str, Any] = {
        "read_confirm_policy": "strict",
        "optimizers": {"output_spool": "active"},
        "governor": {"require_runtime_verified": True},
    }
    cl_dir = tmp_path / "cl_build"
    for cap_id in ("pre_tool_interception", "output_replacement"):
        attest_capability("claude", cap_id, verification_evidence=f"probe:{cap_id}", harness_build_id="2.1.0", runtime_cfg=cl_cfg, state_dir=cl_dir)
    cl_same = apply_runtime_governor(cl_cfg, "claude", state_dir=cl_dir, payload={"tool_name": "Bash", "claude_version": "2.1.0"})
    assert cl_same["optimizers"]["output_spool"] == "active"
    cl_upg = apply_runtime_governor(cl_cfg, "claude", state_dir=cl_dir, payload={"tool_name": "Bash", "claude_version": "2.2.0"})
    assert cl_upg["optimizers"]["output_spool"] == "shadow"
    assert evaluate_governor("claude", runtime_cfg=cl_cfg, state_dir=cl_dir, harness_build_id="2.2.0")["capabilities"]["output_replacement"]["invalidated_reason"] == "build_changed"
