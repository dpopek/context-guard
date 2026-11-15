"""Tests for VS Code extension cost_insights.js, Schema v4 outcomes, and non-counterfactual rendering."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXT_DIR = ROOT / "vscode-extension"


def _run_node(script_body: str) -> dict:
    proc = subprocess.run(
        ["node", "-e", script_body, str(EXT_DIR)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return json.loads(proc.stdout.strip())


def test_cost_insights_schema_v4_budget_cap_unpriced_and_non_causal() -> None:
    script = r"""
const path = require("path");
const ci = require(path.resolve(process.argv[1], "cost_insights.js"));
const vm = require(path.resolve(process.argv[1], "view_model.js"));
const { renderWebviewHtml } = require(path.resolve(process.argv[1], "renderers.js"));

const usage = {
  totals: {
    "claude|claude-sonnet-4-6": { events: 10, input: 1000000, cache_write: 0, cache_read: 0, output: 0, total_only: 0 },
    "codex|unknown": { events: 5, input: 1000000, cache_write: 0, cache_read: 0, output: 0, total_only: 0 },
  },
  by_day: { "2026-11-10": { claude: { input: 100000, cache_read: 0, cache_write: 0, events: 10 } } },
};
const outcomesV4 = {
  schema_version: 4,
  by_key: {
    "claude|claude-sonnet-4-6|outline": {
      total: 6, applied: 6,
      recovery: { none: 3, targeted: 2, full: 1, pending_or_unknown: 0 },
      regret: { none: 3, suspected: 1, confirmed: 0, unknown: 2 },
      evidence: { observed: 3, heuristic: 3, replay: 0, causal_ab: 0 },
      weighted_turns: 6.0,
      archived_weighted_turns: 0.0,
    },
    "claude|claude-sonnet-4-6|outline_pull": {
      total: 8, applied: 8,
      recovery: { none: 8, targeted: 0, full: 0, pending_or_unknown: 0 },
      regret: { none: 8, suspected: 0, confirmed: 0, unknown: 0 },
      evidence: { observed: 8, heuristic: 0, replay: 0, causal_ab: 0 },
      weighted_turns: 8.0,
      archived_weighted_turns: 0.0,
    },
    "codex|unknown|range_trim": {
      total: 2, applied: 2,
      recovery: { none: 0, targeted: 0, full: 0, pending_or_unknown: 0 },
      regret: { none: 0, suspected: 0, confirmed: 0, unknown: 0 },
      evidence: { observed: 0, heuristic: 0, replay: 0, causal_ab: 0 },
      weighted_turns: 2.0,
      archived_weighted_turns: 0.0,
    },
  },
};
const stats = { saved_tokens: 50000, baseline_tokens: 100000, reduction_pct: 50.0, by_day: { "2026-11-10": { saved_bytes: 200000 } } };
const impact = ci.summarizeOutcomesCostImpact(outcomesV4, usage);
const insights = vm.summarizeV4Insights(stats, usage, outcomesV4, { ok: true, registeredCount: 4, totalHarnesses: 4 });
const html = renderWebviewHtml("0.0.0", stats, insights);

const unpricedOnly = ci.summarizeOutcomesCostImpact(
  { schema_version: 4, by_key: { "codex|custom-unpriced|outline": { total: 1, weighted_turns: 1 } } },
  { totals: { "codex|custom-unpriced": { events: 2, input: 100000, total_only: 0 } } }
);
const htmlUnpriced = renderWebviewHtml("0.0.0", stats, vm.summarizeV4Insights(stats, { totals: {} }, { schema_version: 4, by_key: { "codex|custom-unpriced|outline": { total: 1, weighted_turns: 1 } } }, null));
console.log(JSON.stringify({ impact, insights, html, unpricedOnly, htmlUnpriced }));
"""
    res = _run_node(script)
    impact = res["impact"]
    assert impact["costImpactLabel"] == "Estimated Cost Impact (non-counterfactual)"
    assert impact["tariff_effective_date"] == "2026-11-01"
    assert impact["causal_ab"] == {"status": "not_run"}
    assert impact["budget_capped"] is True
    assert impact["estimated_associated_model_cost_usd"] == pytest.approx(3.0)
    assert impact["weighted_intervention_steps"] == pytest.approx(16.0)
    assert impact["by_key"]["codex|unknown|range_trim"]["estimated_associated_model_cost_usd"] is None

    insights = res["insights"]
    assert insights["estimated_associated_model_cost_usd"] == pytest.approx(3.0)
    assert insights["weighted_intervention_steps"] == pytest.approx(16.0)
    assert insights["sunsetVerdict"]["denials"] == 6
    assert "Estimated Cost Impact (non-counterfactual)" in res["html"]
    assert "NaN" not in res["html"] and "Infinity" not in res["html"]
    assert res["unpricedOnly"]["estimated_associated_model_cost_usd"] is None
    assert "n/a (unpriced)" in res["htmlUnpriced"]


def test_cost_insights_handles_nan_infinity_and_legacy_v1_v2_safely() -> None:
    script = r"""
const path = require("path");
const ci = require(path.resolve(process.argv[1], "cost_insights.js"));
const bad = ci.summarizeOutcomesCostImpact(
  {
    schema_version: 4,
    by_key: { "claude|claude-sonnet-4-6|outline": { total: 1, weighted_turns: NaN, archived_weighted_turns: Infinity } },
  },
  { totals: { "claude|claude-sonnet-4-6": { events: NaN, input: Infinity, total_only: 0 } } }
);
const legacy = ci.summarizeOutcomesCostImpact({ schema_version: 2, by_key: { "claude|claude-sonnet-4-6|outline": { total: 5, weighted_turns: 5 } } }, {});
console.log(JSON.stringify({ bad, legacy }));
"""
    res = _run_node(script)
    assert res["bad"]["weighted_intervention_steps"] == 0
    assert res["bad"]["estimated_associated_model_cost_usd"] is None
    assert res["legacy"]["weighted_intervention_steps"] == 0
    assert res["legacy"]["by_key"] == {}
