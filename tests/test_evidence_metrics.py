"""Unit and contract tests for Evidence Engine metrics, causal guards, and matrix planning."""

from __future__ import annotations

import math

import pytest

from bin.tariffs import compute_turn_tariff_cost_usd
from evidence.metrics import (
    EXTERNAL_NOISE_REASONS,
    compute_arm_summary,
    compute_paired_comparison,
    plan_evaluation_matrix,
    validate_run_record,
    wilson_interval_95,
)


def _passed_run(
    task_id: str,
    *,
    repeat_idx: int = 0,
    cost_usd: float | None = 0.10,
    turns: int = 3,
    latency_ms: float | None = 1200.0,
    harness: str = "claude",
    model_id: str = "claude-sonnet-4-6",
    fresh_input_tokens: int | None = 1000,
    output_tokens: int | None = 200,
    cache_read_tokens: int | None = 5000,
    cache_write_tokens: int | None = 500,
) -> dict[str, object]:
    rec: dict[str, object] = {
        "run_id": f"{harness}_{task_id}_r{repeat_idx}",
        "task_id": task_id,
        "repeat_idx": repeat_idx,
        "harness": harness,
        "model_id": model_id,
        "outcome_class": "passed",
        "passed": True,
        "turns": turns,
        "latency_ms": latency_ms,
        "fresh_input_tokens": fresh_input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": cache_read_tokens,
        "cache_write_tokens": cache_write_tokens,
    }
    if cost_usd is not None:
        rec["cost_usd"] = cost_usd
    return rec


def test_cost_per_passed_run_undefined_on_zero_passes_and_unavailable_without_costs() -> None:
    zero_pass_runs = [
        {"task_id": "task_01", "outcome_class": "failed_attempt", "passed": False, "cost_usd": 0.25, "turns": 4},
        {"task_id": "task_02", "outcome_class": "failed_attempt", "passed": False, "cost_usd": 0.35, "turns": 5},
    ]
    zero_summary = compute_arm_summary("baseline", zero_pass_runs, bootstrap_iters=200)
    assert zero_summary["passed_runs"] == 0
    assert zero_summary["headline_runs"] == 2
    assert zero_summary["pass_rate"] == 0.0
    assert zero_summary["cost_per_passed_run"] is None
    assert zero_summary["cost_per_passed_run_status"] == "undefined"
    assert zero_summary["cost_per_passed_run_ci_95"]["unbounded_high"] is True
    assert zero_summary["cost_per_passed_run_ci_95"]["ci_95_high"] is None
    assert zero_summary["total_headline_cost_usd"] == pytest.approx(0.60)

    empty_summary = compute_arm_summary("baseline", [], bootstrap_iters=200)
    assert empty_summary["cost_per_passed_run"] is None
    assert empty_summary["cost_per_passed_run_status"] == "undefined"
    assert empty_summary["pass_rate"] is None

    missing_cost_runs = [
        _passed_run("task_01", cost_usd=0.10),
        {"task_id": "task_02", "outcome_class": "failed_attempt", "passed": False, "turns": 2},
    ]
    unavail_summary = compute_arm_summary("baseline", missing_cost_runs, bootstrap_iters=200)
    assert unavail_summary["passed_runs"] == 1
    assert unavail_summary["missing_cost_runs"] == 1
    assert unavail_summary["cost_per_passed_run"] is None
    assert unavail_summary["cost_per_passed_run_status"] == "unavailable"
    assert unavail_summary["cost_evidence"] == "unavailable"
    assert unavail_summary["total_headline_cost_usd"] is None


def test_endogenous_ttl_misses_and_failed_attempts_cannot_hide_under_external_noise() -> None:
    bad_cases = [
        {"task_id": "task_01", "outcome_class": "external_noise", "failure_reason": "upstream_5xx", "turns": 2, "cost_usd": 0.40},
        {"task_id": "task_02", "outcome_class": "external_noise", "failure_reason": "upstream_5xx", "turns": 0, "ttl_cache_misses": 1, "cost_usd": 0.30},
        {"task_id": "task_03", "outcome_class": "external_noise", "failure_reason": "upstream_5xx", "turns": 0, "reliability_failures": 1, "cost_usd": 0.20},
        {"task_id": "task_04", "outcome_class": "external_noise", "failure_reason": "upstream_5xx", "turns": 0, "passed": True, "cost_usd": 0.15},
        {"task_id": "task_05", "outcome_class": "external_noise", "failure_reason": "wrong_answer", "turns": 0, "cost_usd": 0.25},
    ]
    for raw in bad_cases:
        norm, violations = validate_run_record(raw)
        assert norm["outcome_class"] == "failed_attempt"
        assert norm["passed"] is False
        assert "endogenous_cost_cannot_be_excluded_as_external_noise" in violations

    runs = [
        _passed_run("task_01", cost_usd=0.20),
        {
            "task_id": "task_02", "outcome_class": "external_noise", "failure_reason": "upstream_5xx",
            "turns": 1, "ttl_cache_misses": 2, "cost_usd": 0.60,
        },
        {
            "task_id": "task_03", "outcome_class": "failed_attempt", "passed": False,
            "turns": 4, "ttl_cache_misses": 1, "cost_usd": 0.40,
        },
    ]
    summary = compute_arm_summary("context_guard", runs, bootstrap_iters=200)
    assert summary["headline_runs"] == 3
    assert summary["passed_runs"] == 1
    assert summary["failed_attempts"] == 2
    assert summary["external_noise"]["count"] == 0
    assert summary["ttl_cache_misses"] == 3
    assert summary["total_headline_cost_usd"] == pytest.approx(1.20)
    assert summary["cost_per_passed_run"] == pytest.approx(1.20)
    assert summary["cost_per_passed_run_status"] == "defined"
    assert len(summary["contract_violations"]) == 1


def test_exogenous_external_noise_is_separated_and_disclosed() -> None:
    assert "upstream_5xx" in EXTERNAL_NOISE_REASONS
    assert "harness_binary_missing" in EXTERNAL_NOISE_REASONS
    runs = [
        _passed_run("task_01", cost_usd=0.30),
        _passed_run("task_02", cost_usd=0.50),
        {
            "run_id": "noise_01",
            "task_id": "task_03",
            "outcome_class": "external_noise",
            "passed": False,
            "failure_reason": "rate_limit_exhausted_pre_turn",
            "turns": 0,
            "ttl_cache_misses": 0,
            "reliability_failures": 0,
            "cost_usd": 0.05,
        },
        {
            "run_id": "noise_02",
            "task_id": "task_04",
            "outcome_class": "external_noise",
            "passed": False,
            "failure_reason": "dns_failure",
            "turns": 0,
            "ttl_cache_misses": 0,
            "reliability_failures": 0,
            "cost_usd": 0.00,
        },
    ]
    summary = compute_arm_summary("baseline", runs, bootstrap_iters=200)
    assert summary["raw_runs"] == 4
    assert summary["headline_runs"] == 2
    assert summary["passed_runs"] == 2
    assert summary["pass_rate"] == pytest.approx(1.0)
    assert summary["total_headline_cost_usd"] == pytest.approx(0.80)
    assert summary["cost_per_passed_run"] == pytest.approx(0.40)
    assert summary["all_runs_raw_cost_usd"] == pytest.approx(0.85)
    assert summary["external_noise"]["count"] == 2
    assert summary["external_noise"]["cost_usd"] == pytest.approx(0.05)
    assert summary["external_noise"]["reasons"] == {
        "dns_failure": 1,
        "rate_limit_exhausted_pre_turn": 1,
    }
    assert summary["contract_violations"] == []
    disclosed_ids = {entry["run_id"] for entry in summary["disclosed_failures"]}
    assert disclosed_ids == {"noise_01", "noise_02"}


def test_wilson_interval_cluster_bootstrap_and_conditional_paired_cost() -> None:
    assert wilson_interval_95(0, 0) == (None, None)
    assert wilson_interval_95(0, -5) == (None, None)
    low_0, high_0 = wilson_interval_95(0, 10)
    assert low_0 == 0.0 and high_0 is not None and 0.0 < high_0 < 0.35
    low_10, high_10 = wilson_interval_95(10, 10)
    assert low_10 is not None and 0.65 < low_10 < 1.0 and high_10 == 1.0
    low_mid, high_mid = wilson_interval_95(9, 12)
    assert low_mid is not None and high_mid is not None and low_mid < 0.75 < high_mid

    base_runs = [
        _passed_run("task_01", repeat_idx=0, cost_usd=0.20),
        _passed_run("task_02", repeat_idx=0, cost_usd=0.30),
        _passed_run("task_03", repeat_idx=0, cost_usd=0.40),
        _passed_run("task_04", repeat_idx=0, cost_usd=0.50),
    ]
    treat_runs = [
        _passed_run("task_01", repeat_idx=0, cost_usd=0.10),
        _passed_run("task_02", repeat_idx=0, cost_usd=0.15),
        {"task_id": "task_03", "repeat_idx": 0, "outcome_class": "failed_attempt", "passed": False, "cost_usd": 0.45, "turns": 5},
        {"task_id": "task_04", "repeat_idx": 0, "outcome_class": "failed_attempt", "passed": False, "cost_usd": 0.50, "turns": 6},
    ]

    cmp_a = compute_paired_comparison("baseline", "context_guard", base_runs, treat_runs, seed=77, bootstrap_iters=400)
    cmp_b = compute_paired_comparison("baseline", "context_guard", base_runs, treat_runs, seed=77, bootstrap_iters=400)
    assert cmp_a == cmp_b

    # Baseline: 4/4 passes -> $1.40 / 4 = $0.35; Treatment: 2/4 passes -> $1.20 / 2 = $0.60
    assert cmp_a["unconditional"]["pass_rate_delta"] == pytest.approx(-0.5)
    assert cmp_a["unconditional"]["cost_per_passed_run_delta_usd"] == pytest.approx(0.25)
    # Treatment has 2 failing tasks out of 4 -> P(all 4 drawn fail) = (0.5)^4 = 6.25% -> zero-pass resamples > 0
    treat_ci = cmp_a["treatment_summary"]["cost_per_passed_run_ci_95"]
    assert treat_ci["zero_pass_resamples"] > 0
    assert treat_ci["unbounded_high"] is True
    assert treat_ci["ci_95_high"] is None
    assert treat_ci["ci_95_low"] is not None

    base_ci = cmp_a["baseline_summary"]["cost_per_passed_run_ci_95"]
    assert base_ci["zero_pass_resamples"] == 0
    assert base_ci["unbounded_high"] is False
    assert base_ci["ci_95_low"] <= 0.35 <= base_ci["ci_95_high"]

    # Conditional shared passes only match (task_01, 0) and (task_02, 0), creating illusion of savings ($0.125 vs $0.25)
    paired = cmp_a["paired_cost_on_shared_passes"]
    assert paired["conditional_on_shared_passes"] is True
    assert "selection_bias_warning" in paired and "unconditional" in paired["selection_bias_warning"].lower()
    assert paired["pass_rates_differ"] is True
    assert paired["matched_pair_count"] == 4
    assert paired["shared_pass_count"] == 2
    assert paired["baseline_mean_cost_usd"] == pytest.approx(0.25)
    assert paired["treatment_mean_cost_usd"] == pytest.approx(0.125)
    assert paired["mean_cost_delta_usd"] == pytest.approx(-0.125)


def test_plan_evaluation_matrix_pilot_and_release_budget_scaling() -> None:
    pilot = plan_evaluation_matrix("small_live_pilot")
    assert pilot["tasks"] == 6
    assert pilot["arms"] == ["baseline", "context_guard"]
    assert pilot["repeats"] == 3
    assert pilot["total_runs"] == 36
    assert pilot["statistical_proof"] is False
    assert pilot["gate_role"] == "fast_regression_gate"

    rel_default = plan_evaluation_matrix("release_evaluation")
    assert rel_default["tasks"] == 12
    assert rel_default["arms"] == ["baseline", "context_guard", "context_guard_rtk"]
    assert rel_default["repeats"] == 2
    assert rel_default["total_runs"] == 72
    assert rel_default["statistical_proof"] is True

    rel_max = plan_evaluation_matrix("release_evaluation", task_count=15)
    assert rel_max["total_runs"] == 90

    # Recommended repeats from (1.96 * 0.25 / 0.10)^2 = 24.01 -> ceil 25, capped by budget $36 / (12*3*$0.20=$7.20) = 5
    capped = plan_evaluation_matrix(
        "release_evaluation",
        max_budget_usd=36.0,
        est_run_cost_usd=0.20,
        observed_cost_sd_usd=0.25,
        target_ci_half_width_usd=0.10,
    )
    assert capped["recommended_repeats"] == 25
    assert capped["repeats"] == 5
    assert capped["total_runs"] == 180
    assert capped["budget_capped"] is True
    assert capped["within_budget"] is True
    assert capped["estimated_total_cost_usd"] == pytest.approx(36.0)

    over_budget = plan_evaluation_matrix(
        "release_evaluation",
        max_budget_usd=5.0,
        est_run_cost_usd=0.20,
        observed_cost_sd_usd=0.25,
        target_ci_half_width_usd=0.10,
    )
    assert over_budget["repeats"] == 1
    assert over_budget["total_runs"] == 36
    assert over_budget["budget_capped"] is True
    assert over_budget["within_budget"] is False
    assert over_budget["estimated_total_cost_usd"] == pytest.approx(7.20)


def test_cursor_missing_cache_telemetry_does_not_block_cost_and_quality_comparisons() -> None:
    cursor_base = [
        _passed_run(
            "task_01", harness="cursor", model_id="claude-sonnet-4-6", cost_usd=None,
            turns=4, latency_ms=900.0, fresh_input_tokens=2000, output_tokens=400,
            cache_read_tokens=None, cache_write_tokens=None,
        ),
        _passed_run(
            "task_02", harness="cursor", model_id="claude-sonnet-4-6", cost_usd=0.04,
            turns=6, latency_ms=1500.0, fresh_input_tokens=3000, output_tokens=500,
            cache_read_tokens=None, cache_write_tokens=None,
        ),
    ]
    cursor_cg = [
        _passed_run(
            "task_01", harness="cursor", model_id="claude-sonnet-4-6", cost_usd=None,
            turns=3, latency_ms=700.0, fresh_input_tokens=1000, output_tokens=200,
            cache_read_tokens=None, cache_write_tokens=None,
        ),
        _passed_run(
            "task_02", harness="cursor", model_id="claude-sonnet-4-6", cost_usd=0.02,
            turns=4, latency_ms=1100.0, fresh_input_tokens=1500, output_tokens=300,
            cache_read_tokens=None, cache_write_tokens=None,
        ),
    ]
    cmp_res = compute_paired_comparison("baseline", "context_guard", cursor_base, cursor_cg, bootstrap_iters=200)
    assert cmp_res["comparisons_blocked"] is False
    assert cmp_res["cache_comparison_status"] == "excluded_missing_telemetry"
    assert cmp_res["baseline_summary"]["cache_attribution_status"] == "excluded_missing_telemetry"
    assert cmp_res["baseline_summary"]["tokens"]["cache_read_tokens"] is None
    assert cmp_res["baseline_summary"]["tokens"]["cache_write_tokens"] is None
    assert cmp_res["baseline_summary"]["cost_per_passed_run_status"] == "defined"
    assert cmp_res["treatment_summary"]["cost_per_passed_run_status"] == "defined"
    assert cmp_res["unconditional"]["cost_per_passed_run_delta_usd"] < 0.0
    assert cmp_res["unconditional"]["latency_p50_delta_ms"] < 0.0
    assert cmp_res["unconditional"]["turns_mean_delta"] < 0.0


def test_tariff_cost_estimation_recovery_and_validation_edge_cases() -> None:
    est_rec, est_viol = validate_run_record({
        "task_id": "task_01",
        "model_id": "claude-sonnet-4-6",
        "outcome_class": "passed",
        "fresh_input_tokens": 1000,
        "cache_write_tokens": 400,
        "cache_read_tokens": 2000,
        "output_tokens": 500,
        "recovery_calls": 3,
        "unique_recovered_bytes": 1000,
        "total_recovered_bytes": 2500,
        "latency_s": 1.25,
    })
    expected_usd = compute_turn_tariff_cost_usd(
        "claude-sonnet-4-6", input_tokens=1000, cache_write_tokens=400, cache_read_tokens=2000, output_tokens=500
    )
    assert est_viol == []
    assert est_rec["cost_evidence"] == "estimated"
    assert est_rec["cost_usd"] == pytest.approx(expected_usd)
    assert est_rec["latency_ms"] == pytest.approx(1250.0)
    assert est_rec["recovery_amplification"] == pytest.approx(2.5)
    assert est_rec["recovery_model_turns"] is None

    unpriced_rec, _ = validate_run_record({
        "task_id": "task_02", "model_id": "custom-model-v1", "passed": True, "fresh_input_tokens": 500,
    })
    assert unpriced_rec["cost_usd"] is None
    assert unpriced_rec["cost_evidence"] == "unavailable"

    total_only_rec, _ = validate_run_record({
        "task_id": "task_03", "model_id": "claude-sonnet-4-6", "passed": True,
        "fresh_input_tokens": 500, "total_only": True,
    })
    assert total_only_rec["cost_usd"] is None
    assert total_only_rec["cache_attribution_status"] == "excluded_missing_telemetry"

    bad_rec, bad_viol = validate_run_record({
        "task_id": "task_04", "outcome_class": "passed", "passed": False,
        "cost_usd": math.nan, "turns": -1,
    })
    assert bad_rec["outcome_class"] == "failed_attempt"
    assert bad_rec["passed"] is False
    assert bad_rec["cost_usd"] is None
    assert "invalid_cost_usd" in bad_viol
    assert "invalid_turns" in bad_viol
    assert "inconsistent_outcome_and_passed_flag" in bad_viol


def test_plan_evaluation_matrix_offline_replay_and_invalid_inputs() -> None:
    offline = plan_evaluation_matrix("offline_replay")
    assert offline["statistical_proof"] is False
    assert offline["gate_role"] == "deterministic_contract_replay"
    assert offline["total_runs"] == 12

    for bad_call in (
        lambda: plan_evaluation_matrix("unknown_tier"),
        lambda: plan_evaluation_matrix("small_live_pilot", task_count=0),
        lambda: plan_evaluation_matrix("small_live_pilot", repeats=True),
        lambda: plan_evaluation_matrix("release_evaluation", max_budget_usd=-1.0),
        lambda: plan_evaluation_matrix("release_evaluation", observed_cost_sd_usd=0.1, target_ci_half_width_usd=0.0),
    ):
        with pytest.raises(ValueError):
            bad_call()
