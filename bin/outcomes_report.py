"""Outcomes Schema v4 cost attribution (`1/k` step-weighted, budget-capped) and Markdown rendering."""

from __future__ import annotations

import math
from typing import Any, Mapping

from bin.tariffs import TARIFF_EFFECTIVE_DATE, attribute_turn_cost, resolve_model_tariff

COST_ATTRIBUTION_BASIS = (
    "1/k step-weighted share of mean (harness, model) API list event cost; "
    "non-causal approximation; per-call_id join deferred to v4.6.0"
)


def _safe_nonneg_float(val: Any) -> float:
    try:
        num = float(val or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, num) if math.isfinite(num) else 0.0


def _pct_label(part: int, total: int) -> str:
    return f"{round(part * 100 / total)}%" if total > 0 else "n/a"


def compute_associated_model_costs(
    outcomes_state: Mapping[str, Any] | None,
    usage_state: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Compute dimensionless step weights and budget-capped associated model cost USD per row."""
    by_key = outcomes_state.get("by_key") if isinstance(outcomes_state, Mapping) else {}
    if not isinstance(by_key, Mapping):
        by_key = {}
    totals = usage_state.get("totals") if isinstance(usage_state, Mapping) else {}
    attributed = attribute_turn_cost(totals if isinstance(totals, Mapping) else {})

    raw_rows: dict[str, dict[str, Any]] = {}
    group_raw_sums: dict[str, float] = {}
    total_weighted = 0.0

    for key, row in sorted(by_key.items()):
        if not isinstance(key, str) or not isinstance(row, Mapping):
            continue
        harness, _, rest = key.partition("|")
        model, _, _kind = rest.partition("|")
        group_key = f"{harness}|{model}"
        w_steps = round(_safe_nonneg_float(row.get("weighted_turns")), 6)
        total_weighted += w_steps
        g_info = attributed.get(group_key)
        mean_ev = g_info.get("mean_event_cost_usd") if g_info else None
        unpriced = resolve_model_tariff(model) is None
        raw_usd = (w_steps * float(mean_ev)) if (mean_ev is not None and not unpriced) else None
        if raw_usd is not None:
            group_raw_sums[group_key] = group_raw_sums.get(group_key, 0.0) + raw_usd
        raw_rows[key] = {
            "group_key": group_key,
            "weighted_intervention_steps": w_steps,
            "raw_cost_usd": raw_usd,
            "unpriced": unpriced,
        }

    groups: dict[str, dict[str, Any]] = {}
    any_capped = False
    for group_key, raw_sum in sorted(group_raw_sums.items()):
        measured = (attributed.get(group_key) or {}).get("measured_cost_usd")
        alpha = min(1.0, float(measured) / raw_sum) if (measured is not None and raw_sum > 0.0) else 1.0
        capped = alpha < 1.0
        if capped:
            any_capped = True
        groups[group_key] = {
            "measured_cost_usd": round(float(measured), 6) if measured is not None else None,
            "raw_sum_usd": round(raw_sum, 6),
            "alpha": alpha,
            "budget_capped": capped,
        }

    per_key_out: dict[str, dict[str, Any]] = {}
    priced_total = 0.0
    has_priced = False
    for key, entry in raw_rows.items():
        g_key = entry["group_key"]
        grp = groups.get(g_key)
        alpha = grp["alpha"] if grp else 1.0
        capped = bool(grp["budget_capped"]) if grp else False
        raw_usd = entry["raw_cost_usd"]
        est_usd = round(raw_usd * alpha, 6) if raw_usd is not None else None
        if est_usd is not None:
            priced_total += est_usd
            has_priced = True
        per_key_out[key] = {
            "weighted_intervention_steps": entry["weighted_intervention_steps"],
            "raw_cost_usd": round(raw_usd, 6) if raw_usd is not None else None,
            "estimated_associated_model_cost_usd": est_usd,
            "budget_capped": capped,
            "unpriced": entry["unpriced"],
        }

    return {
        "tariff_effective_date": TARIFF_EFFECTIVE_DATE,
        "basis": COST_ATTRIBUTION_BASIS,
        "causal_ab": {"status": "not_run"},
        "weighted_intervention_steps": round(total_weighted, 6),
        "estimated_associated_model_cost_usd": round(priced_total, 6) if has_priced else None,
        "budget_capped": any_capped,
        "by_key": per_key_out,
        "groups": groups,
    }


def _dim_int(row: Mapping[str, Any], dim: str, field: str) -> int:
    sub = row.get(dim)
    if isinstance(sub, Mapping):
        try:
            return max(0, int(sub.get(field) or 0))
        except (TypeError, ValueError):
            return 0
    return 0


def render_outcomes_report(
    ledger: Mapping[str, Any],
    usage_state: Mapping[str, Any] | None = None,
    *,
    receipt_summary: Mapping[str, Any] | None = None,
) -> str:
    """Render Schema v4 Markdown table of outcomes and estimated associated model costs (no paths)."""
    lines = ["# 🛡️ Context-Guard Intervention Outcomes", ""]
    by_key = ledger.get("by_key") if isinstance(ledger, Mapping) else {}
    if not isinstance(by_key, Mapping) or not by_key:
        lines.append("No interventions recorded yet.")
    else:
        costs = compute_associated_model_costs(ledger, usage_state)
        lines.append(
            "| Harness | Model | Kind | Interventions | Targeted recovery | Full recovery | "
            "Suspected regret | Confirmed regret | Weighted steps | Est. associated model cost |"
        )
        lines.append("|---|---|---|---:|---:|---:|---:|---:|---:|---:|")
        for key in sorted(by_key):
            row = by_key[key]
            if not isinstance(row, Mapping):
                continue
            harness, _, rest = key.partition("|")
            model, _, kind = rest.partition("|")
            total = max(0, int(row.get("total") or 0))
            rec_t = _dim_int(row, "recovery", "targeted")
            rec_f = _dim_int(row, "recovery", "full")
            reg_s = _dim_int(row, "regret", "suspected")
            reg_c = _dim_int(row, "regret", "confirmed")
            if kind in ("outline", "outline_pull", "output_spool") or any((rec_t, rec_f, reg_s, reg_c)):
                cols = [f"{c:,} ({_pct_label(c, total)})" for c in (rec_t, rec_f, reg_s, reg_c)]
            else:
                cols = ["—", "—", "—", "—"]
            cost_row = costs["by_key"].get(key) or {}
            w_steps = float(cost_row.get("weighted_intervention_steps") or 0.0)
            est_usd = cost_row.get("estimated_associated_model_cost_usd")
            if est_usd is not None:
                cost_cell = f"${est_usd:.4f}" + (" (capped)" if cost_row.get("budget_capped") else "")
            elif cost_row.get("unpriced"):
                cost_cell = "n/a (unpriced)"
            else:
                cost_cell = "—"
            lines.append("| " + " | ".join([harness, model, kind, f"{total:,}", *cols, f"{w_steps:.2f}", cost_cell]) + " |")
        unattr = (ledger.get("unattributed_anon") or {}).get("total", 0) if isinstance(ledger, Mapping) else 0
        late = (ledger.get("late_unattributed") or {}).get("total", 0) if isinstance(ledger, Mapping) else 0
        if unattr or late:
            lines.append(f"\n_Unattributed interventions: {int(unattr):,} · Late post-archive: {int(late):,}_")
        lines.append(f"\n_Basis: {COST_ATTRIBUTION_BASIS}_")
        lines.append(f"_Causal A/B: {costs['causal_ab']['status']} · Tariff date: {TARIFF_EFFECTIVE_DATE}_")
    if isinstance(receipt_summary, Mapping):
        rc_tot = max(0, int(receipt_summary.get("receipt_count") or 0))
        rc_cr = max(0, int(receipt_summary.get("created_count") or 0))
        rc_ver = max(0, int(receipt_summary.get("delivery_verified_count") or 0))
        rc_rec = max(0, int(receipt_summary.get("recovery_count") or 0))
        rc_fail = max(0, int(receipt_summary.get("integrity_failures") or 0))
        lines.append(
            f"\n_Spool Receipts & Integrity: {rc_tot:,} total · {rc_cr:,} created · "
            f"{rc_ver:,} delivery_verified · {rc_rec:,} recovery · {rc_fail:,} integrity_failures_"
        )
    lines.append("")
    schema_v = ledger.get("schema_version", 4) if isinstance(ledger, Mapping) else 4
    upd = (ledger.get("updated_at") or "never") if isinstance(ledger, Mapping) else "never"
    lines.append(f"_Schema: v{schema_v} · updated: {upd}_")
    return "\n".join(lines) + "\n"
