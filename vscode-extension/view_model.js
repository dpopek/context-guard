"use strict";

const HARNESS_ORDER = ["antigravity", "claude", "cursor", "codex"];
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const ISO_DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const INPUT_USD_PER_MILLION = 4.0;
const COST_BASIS_NOTE = "approx.: saved tokens × $4/M input (Claude Opus 5.5 list price), priced once";
const RECENT_PREAMBLE_WINDOW = 10;
const TARGET_WINDOW_DAYS = 30;
const CACHE_READ_PRICE_RATIO = 0.1;
const DENIAL_KINDS = new Set(["outline", "reread_block", "shell_block", "wide_followup"]);

const PROTECTION_LAYERS = [
  { key: "outlines", shortLabel: "Outline", fullLabel: "AST, Markup & Diff Outlines", eventLabel: "AST, Markup & Diff Outline", codicon: "$(symbol-structure)", emoji: "🧬" },
  { key: "ranges_trimmed", shortLabel: "Trim", fullLabel: "Overlapping Ranges Trimmed", eventLabel: "Overlapping Range Trimmed", codicon: "$(filter)", emoji: "✂️" },
  { key: "cli_rewrites", shortLabel: "CLI", fullLabel: "Quiet CLI Flag Rewrites", eventLabel: "Quiet CLI Flag Rewrite", codicon: "$(terminal)", emoji: "🔇" },
  { key: "outline_pulls", shortLabel: "Outline CLI", fullLabel: "Voluntary Outlines (cg-outline)", eventLabel: "Voluntary Outline (cg-outline)", codicon: "$(list-tree)", emoji: "🧭" },
  { key: "mcp_guards", shortLabel: "Guard", fullLabel: "Local-Repo & BigQuery MCP Guards", eventLabel: "Local-Repo & BQ MCP Guard", codicon: "$(lock)", emoji: "🔒" },
  { key: "allowed_reads", shortLabel: "Allow", fullLabel: "Unmodified Allowed Reads", eventLabel: "Unmodified Allowed Read", codicon: "$(check)", emoji: "✅", compactHidden: true },
];

const EVENT_SHORT_LABELS = {
  wide_followup_blocks: "Wide", wide_followup_retries: "Wide",
  multi_file_blocks: "Batch", multi_file_retries: "Batch",
  rereads_blocked: "Re-Read", credit_reversals: "Reversal",
};

const EVENT_FULL_LABELS = {
  wide_followup_blocks: "Wide Follow-Up Read Blocked", wide_followup_retries: "Wide Follow-Up Read Blocked",
  multi_file_blocks: "Multi-File Batch Read Blocked", multi_file_retries: "Multi-File Batch Read Blocked",
  rereads_blocked: "Duplicate Re-Read Blocked", credit_reversals: "Credit Reversal After Bypass",
};

for (const layer of PROTECTION_LAYERS) {
  EVENT_SHORT_LABELS[layer.key] = layer.shortLabel;
  EVENT_FULL_LABELS[layer.key] = layer.eventLabel;
}

const WEBVIEW_CSP_META =
  '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\';">';

function isValidSemver(value) {
  return typeof value === "string" && SEMVER_RE.test(value);
}

function escapeHtml(raw) {
  return String(raw == null ? "" : raw)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeMarkdownCodeSpan(raw) {
  return escapeHtml(raw).replace(/[`\r\n]+/g, " ");
}

function escapeMarkdownText(raw) {
  return String(raw == null ? "" : raw)
    .replace(/[\r\n]+/g, " ")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/([\\`*_{}[\]()#|$~!])/g, "\\$1");
}

function finiteNonNeg(value) {
  if (typeof value === "boolean") return 0;
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function clampNonNegativeInt(value) {
  return Math.round(finiteNonNeg(value));
}

function normalizeStats(raw) {
  const s = raw && typeof raw === "object" ? raw : {};
  const savedTokens = finiteNonNeg(s.saved_tokens);
  const baselineTokens = finiteNonNeg(s.baseline_tokens);
  const hasRawActual = s.actual_tokens != null && typeof s.actual_tokens !== "boolean" && s.actual_tokens !== "";
  const rawActual = hasRawActual ? Number(s.actual_tokens) : NaN;
  const actualTokens = Number.isFinite(rawActual)
    ? finiteNonNeg(rawActual)
    : Math.max(0, baselineTokens - savedTokens);
  const reductionPct = Math.min(100, finiteNonNeg(s.reduction_pct));

  const rawEvents = s.events && typeof s.events === "object" ? s.events : {};
  const events = {};
  for (const layer of PROTECTION_LAYERS) {
    events[layer.key] = clampNonNegativeInt(rawEvents[layer.key]);
  }
  for (const [k, v] of Object.entries(rawEvents)) {
    if (!(k in events)) events[k] = clampNonNegativeInt(v);
  }

  const rawByHarness = s.by_harness && typeof s.by_harness === "object" ? s.by_harness : {};
  const harnesses = {};
  for (const h of HARNESS_ORDER) {
    const hObj = rawByHarness[h] && typeof rawByHarness[h] === "object" ? rawByHarness[h] : {};
    const hits = clampNonNegativeInt(hObj.hits);
    const bTok = finiteNonNeg(hObj.baseline_tokens);
    const sTok = finiteNonNeg(hObj.saved_tokens);
    const hPctNum = bTok > 0 ? Math.min(100, (sTok / bTok) * 100) : 0;
    harnesses[h] = { hits, baselineTokens: bTok, savedTokens: sTok, reductionPct: hPctNum };
  }

  const rawLast = s.last_event && typeof s.last_event === "object" ? s.last_event : null;
  const lastEvent = rawLast
    ? {
        kind: typeof rawLast.kind === "string" && rawLast.kind ? rawLast.kind : "outlines",
        harness: typeof rawLast.harness === "string" && rawLast.harness ? rawLast.harness : "agent",
        savedTokens: finiteNonNeg(rawLast.saved_tokens),
      }
    : null;

  return {
    savedTokens,
    baselineTokens,
    actualTokens,
    reductionPct,
    installedAt: typeof s.installed_at === "string" && s.installed_at ? s.installed_at : null,
    updatedAt: typeof s.updated_at === "string" && s.updated_at ? s.updated_at : null,
    events,
    harnesses,
    lastEvent,
    byDay: s.by_day && typeof s.by_day === "object" ? s.by_day : {},
  };
}

function isLayerVisible(layer, _events, includeCompactHidden = false) {
  if (!layer) return false;
  return includeCompactHidden || !layer.compactHidden;
}

function formatCompactTokens(tokens) {
  const val = finiteNonNeg(tokens);
  if (val >= 1000000) return `${(val / 1000000).toFixed(1)}M`;
  if (val >= 1000) return `${(val / 1000).toFixed(1)}k`;
  return String(Math.round(val));
}

function formatContextWindows(tokens, windowSize = 200000) {
  const val = finiteNonNeg(tokens);
  const win = finiteNonNeg(windowSize) || 200000;
  return (val / win).toFixed(1);
}

function formatStatusBarIdleText(stats) {
  const saved = stats ? finiteNonNeg(stats.saved_tokens) : 0;
  if (!(saved > 0)) return "$(shield) 0 tok · 0%";
  const savedStr = formatCompactTokens(saved);
  const pctInt = Math.round(Math.min(100, finiteNonNeg(stats.reduction_pct)));
  return `$(shield) -${savedStr} · ${pctInt}%`;
}

function formatStatusBarPulseText(stats, deltaTokens, eventKind) {
  const deltaStr = formatCompactTokens(deltaTokens);
  const label = EVENT_SHORT_LABELS[eventKind] || "Saved";
  const pctInt = Math.round(Math.min(100, finiteNonNeg(stats && stats.reduction_pct)));
  return `$(zap) -${deltaStr} (${label}) · ${pctInt}%`;
}

function formatBlockGauge(pct, width = 5) {
  const clamped = Math.min(100, finiteNonNeg(pct));
  const safeWidth = Math.round(finiteNonNeg(width)) || 5;
  let filled = Math.round((clamped / 100) * safeWidth);
  if (clamped > 0 && filled === 0) filled = 1;
  filled = Math.min(safeWidth, Math.max(0, filled));
  return "▰".repeat(filled) + "▱".repeat(safeWidth - filled);
}

function estimateCostUsd(tokens, ratePerMillion = INPUT_USD_PER_MILLION) {
  const val = finiteNonNeg(tokens);
  const rate = finiteNonNeg(ratePerMillion);
  return ((val / 1000000) * rate).toFixed(2);
}

function cleanNonNegInts(values) {
  if (!Array.isArray(values)) return [];
  const out = [];
  for (const v of values) {
    if (typeof v === "boolean" || v === null || typeof v === "object") continue;
    if (typeof v === "string" && !v.trim()) continue;
    const num = Number(v);
    if (Number.isFinite(num) && num >= 0) out.push(Math.round(num));
  }
  return out;
}

function medianInt(values) {
  const sorted = cleanNonNegInts(values).sort((a, b) => a - b);
  if (!sorted.length) return 0;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid] : Math.floor((sorted[mid - 1] + sorted[mid]) / 2);
}

function hasClaudeDesktopMcp(components) {
  if (!components || typeof components !== "object") return false;
  return ["deferred_tools", "mcp_instructions"].some((section) => {
    const row = components[section];
    return row && typeof row === "object" && Object.keys(row).some((k) => k.startsWith("mcp:ccd_"));
  });
}

function summarizeSeries(series) {
  const clean = cleanNonNegInts(series);
  if (!clean.length) return null;
  const recent = clean.slice(-RECENT_PREAMBLE_WINDOW);
  return {
    sessions: clean.length,
    median: medianInt(clean),
    recentMedian: medianInt(recent),
    last: clean[clean.length - 1],
  };
}

function buildPreambleInsights(stats, norm, tokenUsage) {
  const preambleRaw = tokenUsage && typeof tokenUsage.preamble === "object" ? tokenUsage.preamble : {};
  const parts = Array.isArray(tokenUsage && tokenUsage.preamble_parts) ? tokenUsage.preamble_parts : [];
  const codexParts = Array.isArray(tokenUsage && tokenUsage.codex_preamble_parts) ? tokenUsage.codex_preamble_parts : [];
  const codexBucket = (c) => (c === "codex (desktop)" ? "codex (desktop)" : "codex (cli)");
  const claudeCli = [];
  const claudeDesktop = [];
  const codexCohorts = {};
  const lastCohortByBase = {};
  for (const entry of parts) {
    if (!entry || typeof entry !== "object") continue;
    const measured = clampNonNegativeInt(entry.measured);
    if (!measured || !entry.components || typeof entry.components !== "object") continue;
    const cohort = typeof entry.cohort === "string" ? entry.cohort : "";
    const harness = typeof entry.harness === "string" ? entry.harness : "";
    if (cohort.startsWith("codex") || harness === "codex") {
      const bucket = codexBucket(cohort);
      (codexCohorts[bucket] = codexCohorts[bucket] || []).push(measured);
      lastCohortByBase.codex = bucket;
    } else if (hasClaudeDesktopMcp(entry.components)) {
      claudeDesktop.push(measured);
      lastCohortByBase.claude = "claude (desktop)";
    } else {
      claudeCli.push(measured);
      lastCohortByBase.claude = "claude (cli)";
    }
  }
  for (const entry of codexParts) {
    if (!entry || typeof entry !== "object") continue;
    const measured = clampNonNegativeInt(entry.measured);
    if (!measured || !entry.components || typeof entry.components !== "object") continue;
    const bucket = codexBucket(typeof entry.cohort === "string" ? entry.cohort : "");
    (codexCohorts[bucket] = codexCohorts[bucket] || []).push(measured);
    lastCohortByBase.codex = bucket;
  }
  const rawSummaries = {};
  for (const [h, vals] of Object.entries(preambleRaw)) {
    if (!Array.isArray(vals)) continue;
    const s = summarizeSeries(vals);
    if (s) rawSummaries[h] = s;
  }
  const byHarness = {};
  if (rawSummaries.antigravity) byHarness.antigravity = rawSummaries.antigravity;
  if (claudeCli.length || claudeDesktop.length) {
    if (claudeCli.length) byHarness["claude (cli)"] = summarizeSeries(claudeCli);
    if (claudeDesktop.length) byHarness["claude (desktop)"] = summarizeSeries(claudeDesktop);
  } else if (rawSummaries.claude) {
    byHarness.claude = rawSummaries.claude;
  }
  if (Object.keys(codexCohorts).length) {
    for (const key of ["codex (cli)", "codex (desktop)"]) {
      if (codexCohorts[key]) {
        const s = summarizeSeries(codexCohorts[key]);
        if (s) byHarness[key] = s;
      }
    }
  } else if (rawSummaries.codex) {
    byHarness.codex = rawSummaries.codex;
  }
  if (rawSummaries.cursor) byHarness.cursor = rawSummaries.cursor;
  for (const [h, s] of Object.entries(rawSummaries)) {
    if (h !== "antigravity" && h !== "claude" && h !== "codex" && h !== "cursor") byHarness[h] = s;
  }
  const rawLastHarness =
    stats && stats.last_event && typeof stats.last_event.harness === "string" ? stats.last_event.harness : "";
  const preferred = rawLastHarness || (norm.lastEvent && norm.lastEvent.harness) || "";
  let lastKey = preferred && byHarness[preferred] ? preferred : null;
  if (!lastKey && preferred && lastCohortByBase[preferred] && byHarness[lastCohortByBase[preferred]]) {
    lastKey = lastCohortByBase[preferred];
  }
  if (!lastKey && preferred) {
    lastKey = Object.keys(byHarness).find((k) => k === preferred || k.startsWith(`${preferred} (`)) || null;
  }
  if (!lastKey) lastKey = Object.keys(byHarness)[0] || null;
  const preambleLast = lastKey ? { harness: lastKey, ...byHarness[lastKey] } : null;
  return { byHarness, preambleLast };
}

function summarizeCacheHit(tokenUsage) {
  const totals = tokenUsage && typeof tokenUsage.totals === "object" ? tokenUsage.totals : null;
  if (!totals) return { cacheHitPct: null, cacheHitLabel: "n/a" };
  let input = 0;
  let cacheRead = 0;
  let cacheWrite = 0;
  for (const row of Object.values(totals)) {
    if (!row || typeof row !== "object") continue;
    const events = clampNonNegativeInt(row.events);
    const totalOnly = clampNonNegativeInt(row.total_only);
    if (events > 0 && totalOnly >= events) continue;
    input += clampNonNegativeInt(row.input);
    cacheRead += clampNonNegativeInt(row.cache_read);
    cacheWrite += clampNonNegativeInt(row.cache_write);
  }
  const denom = input + cacheRead + cacheWrite;
  if (!denom) return { cacheHitPct: null, cacheHitLabel: "n/a" };
  const pct = Math.round((cacheRead / denom) * 1000) / 10;
  return { cacheHitPct: pct, cacheHitLabel: `${pct.toFixed(1)}%` };
}

function parseIsoDayUtcMs(dayStr) {
  if (typeof dayStr !== "string" || !ISO_DAY_RE.test(dayStr)) return null;
  const ms = Date.parse(`${dayStr}T00:00:00Z`);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString().slice(0, 10) === dayStr ? ms : null;
}

function dayDiffInclusive(since, until) {
  const sinceMs = parseIsoDayUtcMs(since);
  const untilMs = parseIsoDayUtcMs(until);
  if (sinceMs === null || untilMs === null || untilMs < sinceMs) return 0;
  return Math.round((untilMs - sinceMs) / 86400000) + 1;
}

function validIsoDayKeys(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return [];
  return Object.keys(obj)
    .filter((d) => parseIsoDayUtcMs(d) !== null && obj[d] && typeof obj[d] === "object" && !Array.isArray(obj[d]))
    .sort();
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

function computeSunsetVerdict(norm, tokenUsage, outcomes) {
  const usageByDay =
    tokenUsage && typeof tokenUsage.by_day === "object" && !Array.isArray(tokenUsage.by_day) ? tokenUsage.by_day : {};
  const usageDays = validIsoDayKeys(usageByDay);
  if (!usageDays.length) return null;
  const statsDays = validIsoDayKeys(norm.byDay);
  const byDayTotalEvents = sumUsageWindow(usageByDay, usageDays, "", null).events;
  let windowDays = 0;
  let saved = 0;
  let realInput = 0;
  let windowEvents = 0;
  if (statsDays.length) {
    const since = statsDays[0] > usageDays[0] ? statsDays[0] : usageDays[0];
    const until = statsDays[statsDays.length - 1] < usageDays[usageDays.length - 1] ? statsDays[statsDays.length - 1] : usageDays[usageDays.length - 1];
    if (since <= until) {
      windowDays = dayDiffInclusive(since, until);
      let savedBytesSum = 0;
      for (const d of statsDays) {
        if (d >= since && d <= until) {
          const rawSb = norm.byDay[d].saved_bytes;
          const sb = typeof rawSb === "boolean" ? 0 : Number(rawSb);
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
    realInput = sumUsageWindow(usageByDay, usageDays, since, null).realInput;
  }
  let denials = 0;
  let denialTokens = 0;
  let totalsEvents = 0;
  if (
    outcomes &&
    typeof outcomes === "object" &&
    (outcomes.schema_version === undefined || outcomes.schema_version === 3) &&
    outcomes.by_key &&
    typeof outcomes.by_key === "object"
  ) {
    const totals = tokenUsage && typeof tokenUsage.totals === "object" ? tokenUsage.totals : {};
    const callsByHarness = {};
    const cacheReadByHarness = {};
    for (const [tk, row] of Object.entries(totals)) {
      if (!row || typeof row !== "object") continue;
      const harness = String(tk).split("|")[0];
      const evCount = clampNonNegativeInt(row.events);
      totalsEvents += evCount;
      callsByHarness[harness] = (callsByHarness[harness] || 0) + evCount;
      cacheReadByHarness[harness] = (cacheReadByHarness[harness] || 0) + clampNonNegativeInt(row.cache_read);
    }
    for (const [key, row] of Object.entries(outcomes.by_key)) {
      if (!row || typeof row !== "object") continue;
      const parts = String(key).split("|");
      const kind = parts[parts.length - 1];
      if (!DENIAL_KINDS.has(kind)) continue;
      const harness = parts[0];
      const count = clampNonNegativeInt(row.total) + clampNonNegativeInt(row.repeats);
      if (!count) continue;
      denials += count;
      if (callsByHarness[harness] > 0 && cacheReadByHarness[harness] > 0) {
        denialTokens += count * (cacheReadByHarness[harness] / callsByHarness[harness]) * CACHE_READ_PRICE_RATIO;
      }
    }
  }
  const totalEvents = Math.max(totalsEvents, byDayTotalEvents);
  let roundedDenialTokens = Math.floor(denialTokens);
  if (windowEvents > 0 && windowEvents < totalEvents) {
    roundedDenialTokens = Math.floor((roundedDenialTokens * windowEvents) / totalEvents);
  }
  const netSaved = saved - roundedDenialTokens;
  const denom = realInput + Math.max(0, netSaved);
  const netSharePct = denom > 0 ? Math.round((netSaved / denom) * 10000) / 100 : 0;
  const status =
    windowDays < TARGET_WINDOW_DAYS ? "collecting_30d_window" : netSharePct < 0.5 ? "sunset_candidate" : "net_positive";
  return { windowDays, targetDays: TARGET_WINDOW_DAYS, netSaved, netSharePct, denials, denialTokens: roundedDenialTokens, status };
}

function normalizeDoctor(doctor) {
  if (!doctor || typeof doctor !== "object" || typeof doctor.ok !== "boolean") {
    return { ok: null, registeredCount: 0, totalHarnesses: 0, statusLabel: "n/a" };
  }
  const registeredCount = clampNonNegativeInt(doctor.registeredCount);
  const totalHarnesses = clampNonNegativeInt(doctor.totalHarnesses);
  return {
    ok: doctor.ok,
    registeredCount,
    totalHarnesses,
    statusLabel: doctor.ok ? `OK (${registeredCount}/${totalHarnesses})` : "FAIL",
  };
}

function summarizeV4Insights(stats, tokenUsage, outcomes, doctor) {
  const norm = normalizeStats(stats);
  const { cacheHitPct, cacheHitLabel } = summarizeCacheHit(tokenUsage);
  const { byHarness, preambleLast } = buildPreambleInsights(stats, norm, tokenUsage);
  const sunsetVerdict = computeSunsetVerdict(norm, tokenUsage, outcomes);
  return {
    cacheHitPct,
    cacheHitLabel,
    preambleLast,
    preambleByHarness: byHarness,
    sunsetVerdict,
    doctor: normalizeDoctor(doctor),
  };
}

module.exports = {
  HARNESS_ORDER,
  PROTECTION_LAYERS,
  EVENT_SHORT_LABELS,
  EVENT_FULL_LABELS,
  SEMVER_RE,
  WEBVIEW_CSP_META,
  INPUT_USD_PER_MILLION,
  COST_BASIS_NOTE,
  RECENT_PREAMBLE_WINDOW,
  isValidSemver,
  isLayerVisible,
  escapeHtml,
  escapeMarkdownCodeSpan,
  escapeMarkdownText,
  finiteNonNeg,
  parseIsoDayUtcMs,
  normalizeStats,
  formatCompactTokens,
  formatContextWindows,
  formatStatusBarIdleText,
  formatStatusBarPulseText,
  formatBlockGauge,
  estimateCostUsd,
  summarizeV4Insights,
};
