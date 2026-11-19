"""Evidence Engine statistical metrics, causal guards, and evaluation matrix planner."""

from __future__ import annotations

import math
import random
from typing import Any, Mapping, Sequence

from services.tariffs import compute_turn_tariff_cost_usd
from policies.api import VALID_EVAL_TIERS, VALID_RUN_OUTCOME_CLASSES

EXTERNAL_NOISE_REASONS: tuple[str, ...] = (
    "upstream_5xx",
    "network_unreachable",
    "dns_failure",
    "harness_binary_missing",
    "rate_limit_exhausted_pre_turn",
)

_WILSON_Z_95: float = 1.959963984540054
_MIN_BOOTSTRAP_ITERS: int = 200
_SELECTION_BIAS_WARNING: str = (
    "Conditional on shared passes only; do not treat as unconditional causal savings when pass rates differ."
)
_PILOT_ARMS: tuple[str, ...] = ("baseline", "context_guard")
_RELEASE_ARMS: tuple[str, ...] = ("baseline", "context_guard", "context_guard_rtk")
_INT_SPECS: tuple[tuple[str, tuple[str, ...], str, int | None], ...] = (
    ("repeat_idx", ("repeat_idx",), "invalid_repeat_idx", 0),
    ("turns", ("turns",), "invalid_turns", 0),
    ("ttl_cache_misses", ("ttl_cache_misses", "ttl_misses"), "invalid_ttl_cache_misses", 0),
    ("reliability_failures", ("reliability_failures", "integrity_failures"), "invalid_reliability_failures", 0),
    ("recovery_calls", ("recovery_calls",), "invalid_recovery_calls", 0),
    ("recovery_model_turns", ("recovery_model_turns",), "invalid_recovery_model_turns", None),
    ("unique_recovered_bytes", ("unique_recovered_bytes",), "invalid_recovered_bytes", 0),
    ("total_recovered_bytes", ("total_recovered_bytes",), "invalid_recovered_bytes", 0),
)
_TOKEN_SPECS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("fresh_input_tokens", ("fresh_input_tokens", "fresh_input", "input_tokens", "input")),
    ("output_tokens", ("output_tokens", "output")),
    ("cache_read_tokens", ("cache_read_tokens", "cache_read", "cache_read_input_tokens")),
    ("cache_write_tokens", ("cache_write_tokens", "cache_write", "cache_creation_input_tokens")),
)

__all__ = [
    "EXTERNAL_NOISE_REASONS", "compute_arm_summary", "compute_paired_comparison",
    "plan_evaluation_matrix", "validate_run_record", "wilson_interval_95",
]


def _pick(raw: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    return next((raw[k] for k in keys if k in raw and raw[k] is not None), None)


def _parse_int(raw: Mapping[str, Any], keys: tuple[str, ...]) -> tuple[int | None, bool]:
    val = _pick(raw, keys)
    if val is None:
        return None, False
    return (int(val), False) if (not isinstance(val, bool) and isinstance(val, int) and val >= 0) else (None, True)


def _parse_float(raw: Mapping[str, Any], keys: tuple[str, ...]) -> tuple[float | None, bool]:
    val = _pick(raw, keys)
    if val is None:
        return None, False
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None, True
    fval = float(val)
    return (fval, False) if (math.isfinite(fval) and fval >= 0.0) else (None, True)


def _clean_str(raw: Mapping[str, Any], keys: tuple[str, ...], default: str = "") -> str:
    val = _pick(raw, keys)
    return (val.strip() or default) if isinstance(val, str) else default


def _quantile(sorted_vals: Sequence[float], q: float) -> float:
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    pos = q * (len(sorted_vals) - 1)
    lo, hi = int(math.floor(pos)), int(math.ceil(pos))
    return float(sorted_vals[lo]) * (1.0 - (pos - lo)) + float(sorted_vals[hi]) * (pos - lo)


def _resolve_run_cost(
    raw: Mapping[str, Any], *, model_id: str, tokens: Mapping[str, int | None], total_only: bool
) -> tuple[float | None, str, str | None]:
    if "cost_usd" in raw and raw["cost_usd"] is not None:
        val, invalid = _parse_float(raw, ("cost_usd",))
        return (None, "unavailable", "invalid_cost_usd") if (invalid or val is None) else (round(val, 9), "measured", None)
    if any(tokens[k] is not None for k, _ in _TOKEN_SPECS) and not total_only:
        est = compute_turn_tariff_cost_usd(
            model_id,
            input_tokens=tokens["fresh_input_tokens"] or 0,
            cache_write_tokens=tokens["cache_write_tokens"] or 0,
            cache_read_tokens=tokens["cache_read_tokens"] or 0,
            output_tokens=tokens["output_tokens"] or 0,
            total_only=False,
        )
        if est is not None:
            return round(float(est), 9), "estimated", None
    return None, "unavailable", None


def _classify_outcome(
    raw: Mapping[str, Any], *, ints: Mapping[str, int | None], invalid_fields: set[str],
    failure_reason: str | None, violations: list[str],
) -> tuple[str, bool]:
    raw_outcome, raw_passed = raw.get("outcome_class"), raw.get("passed")
    passed_flag: bool | None = raw_passed if isinstance(raw_passed, bool) else None
    if raw_passed is not None and not isinstance(raw_passed, bool):
        violations.append("invalid_passed_flag")
        passed_flag = False
    if raw_outcome is None:
        passed = bool(passed_flag) if passed_flag is not None else False
        return ("passed" if passed else "failed_attempt"), passed
    if not isinstance(raw_outcome, str) or raw_outcome not in VALID_RUN_OUTCOME_CLASSES:
        violations.append("invalid_outcome_class")
        return "failed_attempt", False
    if raw_outcome == "external_noise":
        violates = (
            bool(invalid_fields & {"turns", "ttl_cache_misses", "reliability_failures"})
            or any(int(ints[k] or 0) > 0 for k in ("turns", "ttl_cache_misses", "reliability_failures"))
            or passed_flag is True or failure_reason not in EXTERNAL_NOISE_REASONS
        )
        if violates:
            violations.append("endogenous_cost_cannot_be_excluded_as_external_noise")
            return "failed_attempt", False
        return "external_noise", False
    if raw_outcome == "passed":
        if passed_flag is False:
            violations.append("inconsistent_outcome_and_passed_flag")
            return "failed_attempt", False
        return "passed", True
    if passed_flag is True:
        violations.append("inconsistent_outcome_and_passed_flag")
    return "failed_attempt", False


def validate_run_record(raw: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Normalize one run record and enforce exogenous-noise vs endogenous-failure separation."""
    raw_map: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    violations: list[str] = [] if isinstance(raw, Mapping) else ["invalid_run_record"]
    ints: dict[str, int | None] = {}
    invalid_fields: set[str] = set()
    for name, keys, err_tag, default in _INT_SPECS:
        val, inv = _parse_int(raw_map, keys)
        if inv:
            invalid_fields.add(name)
            if err_tag not in violations:
                violations.append(err_tag)
        ints[name] = val if val is not None else default

    tokens: dict[str, int | None] = {}
    tok_inv = False
    for name, keys in _TOKEN_SPECS:
        val, inv = _parse_int(raw_map, keys)
        tok_inv = tok_inv or inv
        tokens[name] = val
    if tok_inv:
        violations.append("invalid_token_count")

    rec_amp_val, rec_amp_inv = _parse_float(raw_map, ("recovery_amplification",))
    if rec_amp_inv:
        violations.append("invalid_recovery_amplification")
    uniq_b, tot_b = int(ints["unique_recovered_bytes"] or 0), int(ints["total_recovered_bytes"] or 0)
    rec_amp = round(rec_amp_val, 4) if rec_amp_val is not None else (round(tot_b / uniq_b, 4) if uniq_b > 0 else None)

    latency_ms, lat_inv = _parse_float(raw_map, ("latency_ms", "duration_ms"))
    if latency_ms is None and not lat_inv:
        lat_s, lat_inv = _parse_float(raw_map, ("latency_s", "duration_s"))
        latency_ms = lat_s * 1000.0 if lat_s is not None else None
    if lat_inv:
        violations.append("invalid_latency")
    latency_ms = round(latency_ms, 3) if latency_ms is not None else None

    model_id = _clean_str(raw_map, ("model_id", "model"), "unknown")
    total_only = raw_map.get("total_only") is True
    cost_usd, cost_evidence, cost_err = _resolve_run_cost(raw_map, model_id=model_id, tokens=tokens, total_only=total_only)
    if cost_err:
        violations.append(cost_err)

    cache_excluded = (
        raw_map.get("cache_attribution_status") == "excluded_missing_telemetry"
        or raw_map.get("cache_telemetry_available") is False
        or total_only or tokens["cache_read_tokens"] is None or tokens["cache_write_tokens"] is None
    )
    failure_reason = _clean_str(raw_map, ("failure_reason",)) or None
    outcome_class, passed = _classify_outcome(
        raw_map, ints=ints, invalid_fields=invalid_fields, failure_reason=failure_reason, violations=violations
    )
    normalized: dict[str, Any] = {
        "run_id": _clean_str(raw_map, ("run_id",)), "task_id": _clean_str(raw_map, ("task_id",)),
        "arm": _clean_str(raw_map, ("arm",)), "repeat_idx": ints["repeat_idx"],
        "harness": _clean_str(raw_map, ("harness", "harness_id"), "unknown").lower(),
        "model_id": model_id, "outcome_class": outcome_class, "passed": passed,
        "failure_reason": failure_reason, "turns": ints["turns"], "latency_ms": latency_ms,
        "cost_usd": cost_usd, "cost_evidence": cost_evidence, **tokens, "total_only": total_only,
        "cache_attribution_status": "excluded_missing_telemetry" if cache_excluded else "included",
        "ttl_cache_misses": ints["ttl_cache_misses"], "reliability_failures": ints["reliability_failures"],
        "recovery_calls": ints["recovery_calls"], "recovery_model_turns": ints["recovery_model_turns"],
        "unique_recovered_bytes": uniq_b, "total_recovered_bytes": tot_b,
        "recovery_amplification": rec_amp, "contract_violations": list(violations),
    }
    return normalized, violations


def wilson_interval_95(successes: int, total: int) -> tuple[float | None, float | None]:
    """Return 95% Wilson score binomial confidence interval `(low, high)` or `(None, None)` when total <= 0."""
    if isinstance(successes, bool) or isinstance(total, bool) or total <= 0:
        return None, None
    n, s = int(total), max(0, min(int(total), int(successes)))
    p_hat, z2 = s / n, _WILSON_Z_95 * _WILSON_Z_95
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    margin = (_WILSON_Z_95 / denom) * math.sqrt((p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * n * n)))
    return round(max(0.0, min(1.0, center - margin)), 6), round(max(0.0, min(1.0, center + margin)), 6)


def _build_cluster_map(runs: Sequence[Mapping[str, Any]]) -> dict[str, list[Mapping[str, Any]]]:
    clusters: dict[str, list[Mapping[str, Any]]] = {}
    for idx, rec in enumerate(runs):
        tid = str(rec.get("task_id") or "").strip()
        rid = str(rec.get("run_id") or "").strip()
        key = tid or (f"__run:{rid}" if rid else f"__idx:{idx}")
        clusters.setdefault(key, []).append(rec)
    return clusters


def _ci_payload(
    ci_low: float | None, ci_high: float | None, *, iters: int, seed: int, clusters: int,
    unbounded_high: bool | None = None, zero_pass: int | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ci_95_low": ci_low, "ci_95_high": ci_high, "bootstrap_iters": iters,
        "seed": seed, "cluster_count": clusters, "method": "cluster_bootstrap_by_task_id",
    }
    if unbounded_high is not None:
        out["unbounded_high"] = unbounded_high
    if zero_pass is not None:
        out["zero_pass_resamples"] = zero_pass
    return out


def _bootstrap_arm_cis(
    headline_runs: Sequence[Mapping[str, Any]], *, all_costs_known: bool, passed_runs: int, seed: int, bootstrap_iters: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    iters, seed_i = max(_MIN_BOOTSTRAP_ITERS, int(bootstrap_iters)), int(seed)
    if not headline_runs:
        return (
            _ci_payload(None, None, iters=iters, seed=seed_i, clusters=0, unbounded_high=True, zero_pass=iters),
            _ci_payload(None, None, iters=iters, seed=seed_i, clusters=0),
        )
    clusters = _build_cluster_map(headline_runs)
    stats = [
        (sum(float(r["cost_usd"] or 0.0) for r in grp), sum(1 for r in grp if r["passed"]), len(grp))
        for cid in sorted(clusters) for grp in (clusters[cid],)
    ]
    k, rng = len(stats), random.Random(seed_i)
    cost_ratios: list[float] = []
    pass_rates: list[float] = []
    zero_pass = 0
    for _ in range(iters):
        drawn = rng.choices(stats, k=k)
        c_sum, p_sum, n_sum = sum(x[0] for x in drawn), sum(x[1] for x in drawn), sum(x[2] for x in drawn)
        pass_rates.append(p_sum / n_sum)
        if p_sum == 0:
            zero_pass += 1
        elif all_costs_known:
            cost_ratios.append(c_sum / p_sum)
    pass_rates.sort()
    pass_ci = _ci_payload(round(_quantile(pass_rates, 0.025), 6), round(_quantile(pass_rates, 0.975), 6), iters=iters, seed=seed_i, clusters=k)
    if passed_runs == 0:
        return _ci_payload(None, None, iters=iters, seed=seed_i, clusters=k, unbounded_high=True, zero_pass=iters), pass_ci
    if not all_costs_known:
        return _ci_payload(None, None, iters=iters, seed=seed_i, clusters=k, unbounded_high=False, zero_pass=zero_pass), pass_ci
    cost_ratios.sort()
    unbounded = zero_pass > 0 or not cost_ratios
    return _ci_payload(
        round(_quantile(cost_ratios, 0.025), 9) if cost_ratios else None,
        None if unbounded else round(_quantile(cost_ratios, 0.975), 9),
        iters=iters, seed=seed_i, clusters=k, unbounded_high=unbounded, zero_pass=zero_pass,
    ), pass_ci


def _quantile_summary(vals: Sequence[float], digits: int) -> dict[str, float | None]:
    if not vals:
        return {"mean": None, "p50": None, "p95": None}
    return {
        "mean": round(sum(vals) / len(vals), digits),
        "p50": round(_quantile(vals, 0.50), digits),
        "p95": round(_quantile(vals, 0.95), digits),
    }


def _summarize_operational_metrics(headline_runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    n = len(headline_runs)
    turns_list = [int(r["turns"]) for r in headline_runs]
    turns_sorted = sorted(float(t) for t in turns_list)
    latencies = sorted(float(r["latency_ms"]) for r in headline_runs if r["latency_ms"] is not None)
    cache_inc = [r for r in headline_runs if r["cache_attribution_status"] == "included"]
    cache_exc = n - len(cache_inc)
    cache_status = "unavailable" if n == 0 else (
        "excluded_missing_telemetry" if cache_exc == n else ("partial" if cache_exc > 0 else "included")
    )
    fresh_vals = [int(r["fresh_input_tokens"]) for r in headline_runs if r["fresh_input_tokens"] is not None]
    out_vals = [int(r["output_tokens"]) for r in headline_runs if r["output_tokens"] is not None]
    fresh_sum = sum(fresh_vals) if len(fresh_vals) == n and n > 0 else None
    out_sum = sum(out_vals) if len(out_vals) == n and n > 0 else None
    if cache_status == "included":
        cr_sum: int | None = sum(int(r["cache_read_tokens"]) for r in cache_inc)
        cw_sum: int | None = sum(int(r["cache_write_tokens"]) for r in cache_inc)
        denom = (cr_sum or 0) + (cw_sum or 0) + (fresh_sum or 0)
        hit_ratio: float | None = round((cr_sum or 0) / denom, 6) if denom > 0 else 0.0
    else:
        cr_sum, cw_sum, hit_ratio = None, None, None
    ttl_misses = sum(int(r["ttl_cache_misses"]) for r in headline_runs)
    rec_calls = sum(int(r["recovery_calls"]) for r in headline_runs)
    uniq_b = sum(int(r["unique_recovered_bytes"]) for r in headline_runs)
    tot_b = sum(int(r["total_recovered_bytes"]) for r in headline_runs)
    rec_turns = [int(r["recovery_model_turns"]) for r in headline_runs if r["recovery_model_turns"] is not None]
    lat_q = _quantile_summary(latencies, 3)
    return {
        "cache_attribution_status": cache_status, "ttl_cache_misses": ttl_misses,
        "reliability_failures": sum(int(r["reliability_failures"]) for r in headline_runs),
        "turns": {"total": sum(turns_list), **_quantile_summary(turns_sorted, 4)},
        "latency_ms": {
            "count": len(latencies),
            "status": "unavailable" if not latencies else ("measured" if len(latencies) == n else "partial"),
            **lat_q, "p99": round(_quantile(latencies, 0.99), 3) if latencies else None,
        },
        "tokens": {
            "fresh_input_tokens": fresh_sum, "output_tokens": out_sum, "cache_read_tokens": cr_sum,
            "cache_write_tokens": cw_sum, "cache_hit_ratio": hit_ratio, "cache_attribution_status": cache_status,
            "excluded_missing_telemetry_runs": cache_exc, "ttl_cache_misses": ttl_misses,
        },
        "recovery": {
            "recovery_calls": rec_calls,
            "recovery_model_turns": sum(rec_turns) if len(rec_turns) == n and n > 0 else None,
            "unique_recovered_bytes": uniq_b, "total_recovered_bytes": tot_b,
            "recovery_amplification": round(tot_b / uniq_b, 4) if uniq_b > 0 else None,
            "recovery_fragmentation_rate": round(rec_calls / n, 4) if n > 0 else None,
        },
    }


def _summarize_arm_internal(
    arm: str, runs: Sequence[Mapping[str, Any]], *, seed: int = 42, bootstrap_iters: int = 1000
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    normalized_all: list[dict[str, Any]] = []
    headline_runs: list[dict[str, Any]] = []
    ext_runs: list[dict[str, Any]] = []
    disclosed_failures: list[dict[str, Any]] = []
    contract_violations: list[dict[str, Any]] = []
    for raw in runs:
        norm, v_list = validate_run_record(raw)
        norm["arm"] = norm["arm"] or str(arm)
        normalized_all.append(norm)
        if v_list:
            contract_violations.append({"arm": str(arm), "run_id": norm["run_id"], "task_id": norm["task_id"], "repeat_idx": norm["repeat_idx"], "violations": list(v_list)})
        (ext_runs if norm["outcome_class"] == "external_noise" else headline_runs).append(norm)
        if not norm["passed"] or v_list or norm["reliability_failures"] > 0:
            disclosed_failures.append({
                "arm": str(arm), "run_id": norm["run_id"], "task_id": norm["task_id"], "repeat_idx": norm["repeat_idx"],
                "outcome_class": norm["outcome_class"], "failure_reason": norm["failure_reason"], "cost_usd": norm["cost_usd"],
                "turns": norm["turns"], "ttl_cache_misses": norm["ttl_cache_misses"],
                "reliability_failures": norm["reliability_failures"], "contract_violations": list(v_list),
            })

    n_head, passed_runs = len(headline_runs), sum(1 for r in headline_runs if r["passed"])
    w_low, w_high = wilson_interval_95(passed_runs, n_head)
    missing_cost = sum(1 for r in headline_runs if r["cost_usd"] is None)
    all_costs_known = n_head > 0 and missing_cost == 0
    total_cost = round(sum(float(r["cost_usd"]) for r in headline_runs), 9) if all_costs_known else None
    cppr_status = "undefined" if passed_runs == 0 else ("unavailable" if total_cost is None else "defined")
    cppr = round(total_cost / passed_runs, 9) if (cppr_status == "defined" and total_cost is not None) else None
    cost_ev = "unavailable" if (not headline_runs or missing_cost > 0) else ("estimated" if any(r["cost_evidence"] == "estimated" for r in headline_runs) else "measured")
    raw_known = [float(r["cost_usd"]) for r in normalized_all if r["cost_usd"] is not None]
    ext_known = [float(r["cost_usd"]) for r in ext_runs if r["cost_usd"] is not None]
    ext_reasons: dict[str, int] = {}
    for r in ext_runs:
        reason = str(r.get("failure_reason") or "unknown")
        ext_reasons[reason] = ext_reasons.get(reason, 0) + 1
    cost_ci, pass_ci = _bootstrap_arm_cis(
        headline_runs, all_costs_known=all_costs_known, passed_runs=passed_runs, seed=seed, bootstrap_iters=bootstrap_iters
    )
    return {
        "arm": str(arm), "raw_runs": len(normalized_all), "headline_runs": n_head,
        "passed_runs": passed_runs, "failed_attempts": n_head - passed_runs,
        "pass_rate": round(passed_runs / n_head, 6) if n_head > 0 else None,
        "pass_rate_ci_95": {"low": w_low, "high": w_high, "method": "wilson_95"},
        "pass_rate_cluster_ci_95": pass_ci, "cost_per_passed_run": cppr,
        "cost_per_passed_run_status": cppr_status, "cost_per_passed_run_ci_95": cost_ci,
        "total_headline_cost_usd": total_cost,
        "all_runs_raw_cost_usd": round(sum(raw_known), 9) if raw_known else None,
        "cost_evidence": cost_ev, "missing_cost_runs": missing_cost, **_summarize_operational_metrics(headline_runs),
        "external_noise": {"count": len(ext_runs), "cost_usd": 0.0 if not ext_runs else (round(sum(ext_known), 9) if ext_known else None), "reasons": dict(sorted(ext_reasons.items()))},
        "contract_violations": contract_violations, "disclosed_failures": disclosed_failures,
    }, headline_runs


def compute_arm_summary(
    arm: str, runs: Sequence[Mapping[str, Any]], *, seed: int = 42, bootstrap_iters: int = 1000
) -> dict[str, Any]:
    """Compute Cost per Passed Run, Pass Rate, latency quantiles, cache/TTL, recovery, and 95% CIs."""
    summary, _headline = _summarize_arm_internal(arm, runs, seed=seed, bootstrap_iters=bootstrap_iters)
    return summary


def _bootstrap_paired_delta(
    base_headline: Sequence[Mapping[str, Any]], treat_headline: Sequence[Mapping[str, Any]],
    *, base_status: str, treat_status: str, seed: int, bootstrap_iters: int,
) -> dict[str, Any]:
    iters, seed_i, method = max(_MIN_BOOTSTRAP_ITERS, int(bootstrap_iters)), int(seed), "paired_cluster_bootstrap_by_task_id"
    if base_status != "defined" or treat_status != "defined":
        return {"ci_95_low": None, "ci_95_high": None, "unbounded": base_status == "undefined" or treat_status == "undefined",
                "bootstrap_iters": iters, "seed": seed_i, "method": method}
    by_b, by_t = _build_cluster_map(base_headline), _build_cluster_map(treat_headline)
    paired = [
        (sum(float(r["cost_usd"] or 0.0) for r in by_b.get(tid, ())), sum(1 for r in by_b.get(tid, ()) if r["passed"]),
         sum(float(r["cost_usd"] or 0.0) for r in by_t.get(tid, ())), sum(1 for r in by_t.get(tid, ()) if r["passed"]))
        for tid in sorted(set(by_b) | set(by_t))
    ]
    rng, deltas, b_zero, t_zero = random.Random(seed_i), [], 0, 0
    for _ in range(iters):
        drawn = rng.choices(paired, k=len(paired))
        bc, bp, tc, tp = sum(x[0] for x in drawn), sum(x[1] for x in drawn), sum(x[2] for x in drawn), sum(x[3] for x in drawn)
        b_zero += int(bp == 0)
        t_zero += int(tp == 0)
        if bp > 0 and tp > 0:
            deltas.append((tc / tp) - (bc / bp))
    deltas.sort()
    return {
        "ci_95_low": None if (b_zero > 0 or not deltas) else round(_quantile(deltas, 0.025), 9),
        "ci_95_high": None if (t_zero > 0 or not deltas) else round(_quantile(deltas, 0.975), 9),
        "unbounded": b_zero > 0 or t_zero > 0 or not deltas, "bootstrap_iters": iters, "seed": seed_i, "method": method,
    }


def _opt_diff(a: Any, b: Any, digits: int = 6) -> float | None:
    return None if (a is None or b is None) else round(float(b) - float(a), digits)


def compute_paired_comparison(
    baseline_arm: str, treatment_arm: str,
    baseline_runs: Sequence[Mapping[str, Any]], treatment_runs: Sequence[Mapping[str, Any]],
    *, seed: int = 42, bootstrap_iters: int = 1000,
) -> dict[str, Any]:
    """Compute unconditional arm deltas and explicitly labeled conditional shared-pass paired cost."""
    base_sum, base_head = _summarize_arm_internal(baseline_arm, baseline_runs, seed=seed, bootstrap_iters=bootstrap_iters)
    treat_sum, treat_head = _summarize_arm_internal(treatment_arm, treatment_runs, seed=seed, bootstrap_iters=bootstrap_iters)
    b_cppr, t_cppr = base_sum["cost_per_passed_run"], treat_sum["cost_per_passed_run"]
    cppr_ok = b_cppr is not None and t_cppr is not None
    statuses = (base_sum["cache_attribution_status"], treat_sum["cache_attribution_status"])
    cache_cmp = next((s for s in ("excluded_missing_telemetry", "unavailable", "partial") if s in statuses), "included")

    b_pairs = {(r["task_id"], r["repeat_idx"]): r for r in base_head if r["task_id"]}
    t_pairs = {(r["task_id"], r["repeat_idx"]): r for r in treat_head if r["task_id"]}
    matched_keys = sorted(set(b_pairs) & set(t_pairs))
    shared = [
        (b_pairs[k], t_pairs[k]) for k in matched_keys
        if b_pairs[k]["passed"] and t_pairs[k]["passed"]
        and b_pairs[k]["cost_usd"] is not None and t_pairs[k]["cost_usd"] is not None
    ]
    b_mean: float | None = round(sum(float(b["cost_usd"]) for b, _ in shared) / len(shared), 9) if shared else None
    t_mean: float | None = round(sum(float(t["cost_usd"]) for _, t in shared) / len(shared), 9) if shared else None
    s_delta: float | None = round((t_mean or 0.0) - (b_mean or 0.0), 9) if shared else None
    s_pct: float | None = round(((t_mean - b_mean) / b_mean) * 100.0, 4) if (b_mean and t_mean is not None) else None

    return {
        "baseline_arm": str(baseline_arm), "treatment_arm": str(treatment_arm),
        "baseline_summary": base_sum, "treatment_summary": treat_sum,
        "comparisons_blocked": False, "cache_comparison_status": cache_cmp,
        "unconditional": {
            "pass_rate_delta": _opt_diff(base_sum["pass_rate"], treat_sum["pass_rate"]),
            "cost_per_passed_run_delta_usd": round(t_cppr - b_cppr, 9) if cppr_ok else None,
            "cost_per_passed_run_ratio": round(t_cppr / b_cppr, 6) if (cppr_ok and b_cppr > 0.0) else None,
            "cost_per_passed_run_pct_change": round(((t_cppr - b_cppr) / b_cppr) * 100.0, 4) if (cppr_ok and b_cppr > 0.0) else None,
            "cost_per_passed_run_delta_ci_95": _bootstrap_paired_delta(
                base_head, treat_head, base_status=base_sum["cost_per_passed_run_status"],
                treat_status=treat_sum["cost_per_passed_run_status"], seed=seed, bootstrap_iters=bootstrap_iters,
            ),
            "latency_p50_delta_ms": _opt_diff(base_sum["latency_ms"]["p50"], treat_sum["latency_ms"]["p50"], 3),
            "latency_p95_delta_ms": _opt_diff(base_sum["latency_ms"]["p95"], treat_sum["latency_ms"]["p95"], 3),
            "turns_mean_delta": _opt_diff(base_sum["turns"]["mean"], treat_sum["turns"]["mean"], 4),
            "ttl_cache_misses_delta": treat_sum["ttl_cache_misses"] - base_sum["ttl_cache_misses"],
            "reliability_failures_delta": treat_sum["reliability_failures"] - base_sum["reliability_failures"],
        },
        "paired_cost_on_shared_passes": {
            "conditional_on_shared_passes": True, "selection_bias_warning": _SELECTION_BIAS_WARNING,
            "pass_rates_differ": base_sum["pass_rate"] != treat_sum["pass_rate"],
            "matched_pair_count": len(matched_keys), "shared_pass_count": len(shared),
            "status": "defined" if shared else "unavailable",
            "baseline_mean_cost_usd": b_mean, "treatment_mean_cost_usd": t_mean,
            "mean_cost_delta_usd": s_delta, "mean_cost_pct_change": s_pct,
        },
    }


def _check_opt_num(val: int | float | None, name: str, *, integer: bool = False, min_val: float = 0.0, strict_gt: bool = False) -> Any:
    if val is None:
        return None
    if isinstance(val, bool) or (integer and not isinstance(val, int)) or (not integer and not isinstance(val, (int, float))):
        raise ValueError(f"{name} must be {'an integer' if integer else 'numeric'}")
    fval = float(val)
    if (not math.isfinite(fval)) or (fval <= min_val if strict_gt else fval < min_val):
        raise ValueError(f"{name} out of valid range")
    return int(val) if integer else fval


def plan_evaluation_matrix(
    tier: str, *, task_count: int | None = None, repeats: int | None = None, max_budget_usd: float | None = None,
    est_run_cost_usd: float | None = None, observed_cost_sd_usd: float | None = None,
    target_ci_half_width_usd: float | None = None,
) -> dict[str, Any]:
    """Build deterministic Small Live Pilot (6x2x3=36) or Release Evaluation (12-15x3x2=72-90) plan."""
    tier_specs: dict[str, tuple[int, tuple[str, ...], int, bool, str]] = {
        "offline_replay": (6, _PILOT_ARMS, 1, False, "deterministic_contract_replay"),
        "small_live_pilot": (6, _PILOT_ARMS, 3, False, "fast_regression_gate"),
        "release_evaluation": (12, _RELEASE_ARMS, 2, True, "release_ab_gate"),
    }
    if tier not in VALID_EVAL_TIERS or tier not in tier_specs:
        raise ValueError(f"Unsupported evaluation tier: {tier!r}")
    def_tasks, arms, def_repeats, proof, gate_role = tier_specs[tier]
    tasks = _check_opt_num(task_count, "task_count", integer=True, min_val=1) or def_tasks
    exp_rep = _check_opt_num(repeats, "repeats", integer=True, min_val=1)
    budget = _check_opt_num(max_budget_usd, "max_budget_usd", min_val=0.0)
    run_cost = _check_opt_num(est_run_cost_usd, "est_run_cost_usd", min_val=0.0)
    sd = _check_opt_num(observed_cost_sd_usd, "observed_cost_sd_usd", min_val=0.0)
    hw = _check_opt_num(target_ci_half_width_usd, "target_ci_half_width_usd", min_val=0.0, strict_gt=True)

    if sd is not None and hw is not None:
        formula_rep = max(1, math.ceil((1.96 * sd / hw) ** 2))
        desired_rep = max(formula_rep, exp_rep) if exp_rep is not None else formula_rep
        formula_used: str | None = "(1.96 * observed_cost_sd_usd / target_ci_half_width_usd) ** 2"
    else:
        desired_rep, formula_used = (exp_rep if exp_rep is not None else def_repeats), None

    eff_rep, budget_capped = desired_rep, False
    if budget is not None and run_cost is not None and run_cost > 0.0:
        affordable = math.floor(budget / (tasks * len(arms) * run_cost))
        if affordable < 1:
            eff_rep, budget_capped = 1, True
        elif affordable < desired_rep:
            eff_rep, budget_capped = affordable, True

    total_runs = tasks * len(arms) * eff_rep
    est_total = round(total_runs * run_cost, 6) if run_cost is not None else None
    within_budget = (est_total <= budget + 1e-12) if (budget is not None and est_total is not None) else None
    return {
        "tier": tier, "gate_role": gate_role, "statistical_proof": proof,
        "tasks": tasks, "arms": list(arms), "arm_count": len(arms),
        "repeats": eff_rep, "recommended_repeats": desired_rep, "total_runs": total_runs,
        "budget_capped": budget_capped, "within_budget": within_budget,
        "max_budget_usd": budget, "est_run_cost_usd": run_cost,
        "estimated_total_cost_usd": est_total, "observed_cost_sd_usd": sd,
        "target_ci_half_width_usd": hw, "formula": formula_used,
    }
