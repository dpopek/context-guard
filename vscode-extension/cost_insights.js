"use strict";

const ISO_DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const INPUT_USD_PER_MILLION = 4.0;
const COST_BASIS_NOTE = "approx.: saved tokens × $4/M input (Claude Opus 5.5 list price), priced once";
const TARGET_WINDOW_DAYS = 30;
const CACHE_READ_PRICE_RATIO = 0.1;
const DENIAL_KINDS = new Set(["outline", "reread_block", "shell_block", "wide_followup"]);
const TARIFF_EFFECTIVE_DATE = "2026-11-01";
const COST_ATTRIBUTION_BASIS = "1/k step-weighted share of mean (harness, model) API list event cost; non-causal approximation; per-call_id join deferred to a future release";

const OPUS_RATE = [15.0, 18.75, 1.5, 75.0];
const SONNET_RATE = [3.0, 3.75, 0.3, 15.0];
const MODEL_TARIFFS_PER_M = {
  "claude-opus-4-6": OPUS_RATE, "claude-opus-4-5": OPUS_RATE, "claude-opus-4-1": OPUS_RATE, "claude-opus-4": OPUS_RATE,
  "claude-sonnet-4-6": SONNET_RATE, "claude-sonnet-4-5": SONNET_RATE, "claude-sonnet-4": SONNET_RATE,
  "claude-haiku-4-5": [1.0, 1.25, 0.1, 5.0], "claude-3-5-haiku": [0.8, 1.0, 0.08, 4.0],
  "gpt-5.4": [2.5, 2.5, 0.25, 15.0], "gpt-5-mini": [0.25, 0.25, 0.025, 2.0], "gpt-5": [1.25, 1.25, 0.125, 10.0],
  "gpt-4.1-mini": [0.4, 0.4, 0.1, 1.6], "gpt-4.1": [2.0, 2.0, 0.5, 8.0], "gpt-4o-mini": [0.15, 0.15, 0.075, 0.6],
  "gpt-4o": [2.5, 2.5, 1.25, 10.0], "o4-mini": [1.1, 1.1, 0.275, 4.4], o3: [2.0, 2.0, 0.5, 8.0],
  "gemini-3.1-pro": [2.0, 2.0, 0.2, 12.0], "gemini-3-flash": [0.5, 0.5, 0.05, 3.0],
  "gemini-2.5-pro": [1.25, 1.25, 0.3125, 10.0], "gemini-2.5-flash": [0.3, 0.3, 0.075, 2.5],
};
const SORTED_PREFIXES = Object.keys(MODEL_TARIFFS_PER_M).sort((a, b) => b.length - a.length);
const PROVIDER_PREFIXES = ["models/", "anthropic/", "openai/", "google/"];

function finiteNonNeg(value) {
  if (typeof value === "boolean") return 0;
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function clampNonNegativeInt(value) { return Math.round(finiteNonNeg(value)); }
function round6(num) { return Number.isFinite(num) ? Math.round(num * 1000000) / 1000000 : 0; }

function estimateCostUsd(tokens, ratePerMillion = INPUT_USD_PER_MILLION) {
  return ((finiteNonNeg(tokens) / 1000000) * finiteNonNeg(ratePerMillion)).toFixed(2);
}

function parseIsoDayUtcMs(dayStr) {
  if (typeof dayStr !== "string" || !ISO_DAY_RE.test(dayStr)) return null;
  const ms = Date.parse(`${dayStr}T00:00:00Z`);
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 10) === dayStr ? ms : null;
}

function dayDiffInclusive(since, until) {
  const s = parseIsoDayUtcMs(since);
  const u = parseIsoDayUtcMs(until);
  return s !== null && u !== null && u >= s ? Math.round((u - s) / 86400000) + 1 : 0;
}

function validIsoDayKeys(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return [];
  return Object.keys(obj).filter((d) => parseIsoDayUtcMs(d) !== null && obj[d] && typeof obj[d] === "object" && !Array.isArray(obj[d])).sort();
}

function sumUsageWindow(usageByDay, usageDays, since, until) {
  let realInput = 0;
  let events = 0;
  for (const day of usageDays) {
    if ((since && day < since) || (until && day > until)) continue;
    for (const row of Object.values(usageByDay[day])) {
      if (!row || typeof row !== "object") continue;
      realInput += clampNonNegativeInt(row.input) + clampNonNegativeInt(row.cache_read) + clampNonNegativeInt(row.cache_write);
      events += clampNonNegativeInt(row.events);
    }
  }
  return { realInput, events };
}

function resolveModelTariff(model) {
  if (typeof model !== "string") return null;
  let norm = model.trim().toLowerCase();
  for (const pfx of PROVIDER_PREFIXES) {
    if (norm.startsWith(pfx)) { norm = norm.slice(pfx.length); break; }
  }
  if (!norm || norm === "unknown") return null;
  if (MODEL_TARIFFS_PER_M[norm]) return MODEL_TARIFFS_PER_M[norm];
  for (const cand of SORTED_PREFIXES) {
    if (norm.startsWith(`${cand}-`) || norm.startsWith(`${cand}.`) || norm.startsWith(`${cand}:`)) return MODEL_TARIFFS_PER_M[cand];
  }
  return null;
}

function computeGroupCostMetrics(totals) {
  const out = {};
  if (!totals || typeof totals !== "object") return out;
  for (const [key, row] of Object.entries(totals)) {
    if (!key.includes("|") || !row || typeof row !== "object") continue;
    const events = clampNonNegativeInt(row.events);
    const rates = resolveModelTariff(key.slice(key.indexOf("|") + 1));
    if (!rates || events <= 0 || clampNonNegativeInt(row.total_only) >= events) {
      out[key] = { events, measuredCostUsd: null, meanEventCostUsd: null };
      continue;
    }
    const [pIn, pCw, pCr, pOut] = rates;
    const measured = (finiteNonNeg(row.input) * pIn + finiteNonNeg(row.cache_write) * pCw +
      finiteNonNeg(row.cache_read) * pCr + finiteNonNeg(row.output) * pOut) / 1000000.0;
    out[key] = { events, measuredCostUsd: measured, meanEventCostUsd: measured / events };
  }
  return out;
}

function isSupportedOutcomes(outcomes) {
  return Boolean(
    outcomes && typeof outcomes === "object" &&
    (outcomes.schema_version === undefined || outcomes.schema_version === 3 || outcomes.schema_version === 4) &&
    outcomes.by_key && typeof outcomes.by_key === "object"
  );
}

function computeSunsetVerdict(norm, tokenUsage, outcomes) {
  const usageByDay = tokenUsage && typeof tokenUsage.by_day === "object" && !Array.isArray(tokenUsage.by_day) ? tokenUsage.by_day : {};
  const usageDays = validIsoDayKeys(usageByDay);
  if (!usageDays.length) return null;
  const statsDays = validIsoDayKeys(norm.byDay);
  const byDayTotalEvents = sumUsageWindow(usageByDay, usageDays, "", null).events;
  let windowDays = 0, saved = 0, realInput = 0, windowEvents = 0;
  if (statsDays.length) {
    const since = statsDays[0] > usageDays[0] ? statsDays[0] : usageDays[0];
    const until = statsDays[statsDays.length - 1] < usageDays[usageDays.length - 1] ? statsDays[statsDays.length - 1] : usageDays[usageDays.length - 1];
    if (since <= until) {
      windowDays = dayDiffInclusive(since, until);
      let savedBytesSum = 0;
      for (const d of statsDays) {
        if (d >= since && d <= until) {
          const sb = typeof norm.byDay[d].saved_bytes === "boolean" ? 0 : Number(norm.byDay[d].saved_bytes);
          if (Number.isFinite(sb)) savedBytesSum += Math.trunc(sb);
        }
      }
      saved = Math.floor(Math.max(0, savedBytesSum) / 4);
      ({ realInput, events: windowEvents } = sumUsageWindow(usageByDay, usageDays, since, until));
    }
  } else {
    const rawStart = tokenUsage && typeof tokenUsage.started_at === "string" ? tokenUsage.started_at.slice(0, 10) : "";
    const since = parseIsoDayUtcMs(rawStart) !== null ? rawStart : "";
    windowDays = since ? dayDiffInclusive(since, usageDays[usageDays.length - 1]) : 0;
    saved = Math.max(0, clampNonNegativeInt(norm.savedTokens) - clampNonNegativeInt(tokenUsage && tokenUsage.saved_tokens_at_start));
    const win = sumUsageWindow(usageByDay, usageDays, since, null);
    realInput = win.realInput;
    if (since) windowEvents = win.events;
  }
  let denials = 0, denialTokens = 0;
  if (isSupportedOutcomes(outcomes)) {
    const totals = tokenUsage && typeof tokenUsage.totals === "object" ? tokenUsage.totals : {};
    const callsByH = {}, cacheByH = {};
    for (const [tk, row] of Object.entries(totals)) {
      if (!row || typeof row !== "object") continue;
      const h = String(tk).split("|")[0];
      callsByH[h] = (callsByH[h] || 0) + clampNonNegativeInt(row.events);
      cacheByH[h] = (cacheByH[h] || 0) + clampNonNegativeInt(row.cache_read);
    }
    for (const [key, row] of Object.entries(outcomes.by_key)) {
      if (!row || typeof row !== "object") continue;
      const parts = String(key).split("|");
      if (!DENIAL_KINDS.has(parts[parts.length - 1])) continue;
      const cnt = clampNonNegativeInt(row.total) + clampNonNegativeInt(row.repeats);
      if (!cnt) continue;
      denials += cnt;
      if (callsByH[parts[0]] > 0 && cacheByH[parts[0]] > 0) {
        denialTokens += cnt * (cacheByH[parts[0]] / callsByH[parts[0]]) * CACHE_READ_PRICE_RATIO;
      }
    }
  }
  let roundedDenialTokens = Math.floor(denialTokens);
  if (windowEvents > 0 && windowEvents < byDayTotalEvents) {
    roundedDenialTokens = Math.floor((roundedDenialTokens * windowEvents) / byDayTotalEvents);
  }
  const netSaved = saved - roundedDenialTokens;
  const denom = realInput + Math.max(0, netSaved);
  const netSharePct = denom > 0 ? Math.round((netSaved / denom) * 10000) / 100 : 0;
  const status = windowDays < TARGET_WINDOW_DAYS ? "collecting_30d_window" : netSharePct < 0.5 ? "sunset_candidate" : "net_positive";
  return { windowDays, targetDays: TARGET_WINDOW_DAYS, netSaved, netSharePct, denials, denialTokens: roundedDenialTokens, status };
}

function summarizeOutcomesCostImpact(outcomes, tokenUsage) {
  const base = {
    costImpactLabel: "Estimated Cost Impact (non-counterfactual)", tariff_effective_date: TARIFF_EFFECTIVE_DATE,
    basis: COST_ATTRIBUTION_BASIS, causal_ab: { status: "not_run" }, weighted_intervention_steps: 0,
    estimated_associated_model_cost_usd: null, budget_capped: false, unpriced: false, by_key: {},
  };
  if (!isSupportedOutcomes(outcomes)) return base;
  const metrics = computeGroupCostMetrics(tokenUsage && tokenUsage.totals);
  const rawRows = {}, groupRawSums = {};
  let totalWeighted = 0, anyUnpriced = false;
  for (const key of Object.keys(outcomes.by_key).sort()) {
    const row = outcomes.by_key[key];
    if (!row || typeof row !== "object") continue;
    const parts = String(key).split("|");
    const gKey = `${parts[0] || "unknown"}|${parts[1] || "unknown"}`;
    const w = round6(finiteNonNeg(row.weighted_turns));
    totalWeighted += w;
    const unpriced = resolveModelTariff(parts[1] || "unknown") === null;
    if (unpriced && w > 0) anyUnpriced = true;
    const g = metrics[gKey];
    const rawUsd = g && g.meanEventCostUsd !== null && !unpriced ? w * g.meanEventCostUsd : null;
    if (rawUsd !== null) groupRawSums[gKey] = (groupRawSums[gKey] || 0) + rawUsd;
    rawRows[key] = { gKey, w, rawUsd, unpriced };
  }
  const alphas = {};
  let anyCapped = false;
  for (const [gKey, rawSum] of Object.entries(groupRawSums)) {
    const measured = metrics[gKey] ? metrics[gKey].measuredCostUsd : null;
    const alpha = measured !== null && rawSum > 0 ? Math.min(1.0, measured / rawSum) : 1.0;
    if (alpha < 1.0) anyCapped = true;
    alphas[gKey] = alpha;
  }
  let pricedSum = 0, hasPriced = false;
  for (const [key, entry] of Object.entries(rawRows)) {
    const alpha = alphas[entry.gKey] !== undefined ? alphas[entry.gKey] : 1.0;
    const est = entry.rawUsd !== null ? round6(entry.rawUsd * alpha) : null;
    if (est !== null) { pricedSum += est; hasPriced = true; }
    base.by_key[key] = { weighted_intervention_steps: entry.w, estimated_associated_model_cost_usd: est, budget_capped: alpha < 1.0, unpriced: entry.unpriced };
  }
  base.weighted_intervention_steps = round6(totalWeighted);
  base.estimated_associated_model_cost_usd = hasPriced ? round6(pricedSum) : null;
  base.budget_capped = anyCapped;
  base.unpriced = anyUnpriced;
  return base;
}

module.exports = {
  ISO_DAY_RE, INPUT_USD_PER_MILLION, COST_BASIS_NOTE, TARGET_WINDOW_DAYS, CACHE_READ_PRICE_RATIO, DENIAL_KINDS,
  TARIFF_EFFECTIVE_DATE, COST_ATTRIBUTION_BASIS, finiteNonNeg, clampNonNegativeInt, estimateCostUsd,
  parseIsoDayUtcMs, dayDiffInclusive, validIsoDayKeys, sumUsageWindow, resolveModelTariff,
  computeSunsetVerdict, summarizeOutcomesCostImpact,
};
