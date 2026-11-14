const HARNESS_ORDER = ["antigravity", "claude", "cursor", "codex"];

const PROTECTION_LAYERS = [
  {
    key: "outlines",
    shortLabel: "Outline",
    fullLabel: "AST, Markup & Diff Outlines",
    eventLabel: "AST, Markup & Diff Outline",
    codicon: "$(symbol-structure)",
    emoji: "🧬",
  },
  {
    key: "wide_followup_blocks",
    retryKey: "wide_followup_retries",
    shortLabel: "Wide",
    fullLabel: "Wide Follow-Up Reads Blocked",
    eventLabel: "Wide Follow-Up Read Blocked",
    codicon: "$(RequestChanges)",
    emoji: "📏",
    legacy: true,
  },
  {
    key: "multi_file_blocks",
    retryKey: "multi_file_retries",
    shortLabel: "Batch",
    fullLabel: "Multi-File Batch Reads Blocked",
    eventLabel: "Multi-File Batch Read Blocked",
    codicon: "$(files)",
    emoji: "📚",
    legacy: true,
  },
  {
    key: "rereads_blocked",
    shortLabel: "Re-Read",
    fullLabel: "Duplicate Re-Reads Blocked",
    eventLabel: "Duplicate Re-Read Blocked",
    codicon: "$(DiffIgnored)",
    emoji: "🛑",
    legacy: true,
  },
  {
    key: "ranges_trimmed",
    shortLabel: "Trim",
    fullLabel: "Overlapping Ranges Trimmed",
    eventLabel: "Overlapping Range Trimmed",
    codicon: "$(filter)",
    emoji: "✂️",
  },
  {
    key: "cli_rewrites",
    shortLabel: "CLI",
    fullLabel: "Quiet CLI Flag Rewrites",
    eventLabel: "Quiet CLI Flag Rewrite",
    codicon: "$(terminal)",
    emoji: "🔇",
  },
  {
    key: "outline_pulls",
    shortLabel: "Outline CLI",
    fullLabel: "Voluntary Outlines (cg-outline)",
    eventLabel: "Voluntary Outline (cg-outline)",
    codicon: "$(list-tree)",
    emoji: "🧭",
  },
  {
    key: "mcp_guards",
    shortLabel: "Guard",
    fullLabel: "Local-Repo & BigQuery MCP Guards",
    eventLabel: "Local-Repo & BQ MCP Guard",
    codicon: "$(lock)",
    emoji: "🔒",
  },
  {
    key: "allowed_reads",
    shortLabel: "Allow",
    fullLabel: "Unmodified Allowed Reads",
    eventLabel: "Unmodified Allowed Read",
    codicon: "$(check)",
    emoji: "✅",
    compactHidden: true,
  },
  {
    key: "credit_reversals",
    shortLabel: "Reversal",
    fullLabel: "Credits Taken Back After Bypass",
    eventLabel: "Credit Reversal After Bypass",
    codicon: "$(history)",
    emoji: "↩️",
    legacy: true,
  },
];

const EVENT_SHORT_LABELS = {};
const EVENT_FULL_LABELS = {};
for (const layer of PROTECTION_LAYERS) {
  EVENT_SHORT_LABELS[layer.key] = layer.shortLabel;
  EVENT_FULL_LABELS[layer.key] = layer.eventLabel;
  if (layer.retryKey) {
    EVENT_SHORT_LABELS[layer.retryKey] = layer.shortLabel;
    EVENT_FULL_LABELS[layer.retryKey] = layer.eventLabel;
  }
}

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

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

function normalizeStats(raw) {
  const s = raw && typeof raw === "object" ? raw : {};
  const savedTokens = Math.max(0, Number(s.saved_tokens) || 0);
  const baselineTokens = Math.max(0, Number(s.baseline_tokens) || 0);
  const rawActual = s.actual_tokens != null ? Number(s.actual_tokens) : NaN;
  const actualTokens = Number.isFinite(rawActual)
    ? Math.max(0, rawActual)
    : Math.max(0, baselineTokens - savedTokens);
  const reductionPct = Math.min(100, Math.max(0, Number(s.reduction_pct) || 0));

  const rawEvents = s.events && typeof s.events === "object" ? s.events : {};
  const events = {};
  for (const layer of PROTECTION_LAYERS) {
    events[layer.key] = Math.max(0, Math.round(Number(rawEvents[layer.key]) || 0));
    if (layer.retryKey) {
      events[layer.retryKey] = Math.max(0, Math.round(Number(rawEvents[layer.retryKey]) || 0));
    }
  }

  const rawByHarness = s.by_harness && typeof s.by_harness === "object" ? s.by_harness : {};
  const harnesses = {};
  for (const h of HARNESS_ORDER) {
    const hObj = rawByHarness[h] && typeof rawByHarness[h] === "object" ? rawByHarness[h] : {};
    const hits = Math.max(0, Math.round(Number(hObj.hits) || 0));
    const bTok = Math.max(0, Number(hObj.baseline_tokens) || 0);
    const sTok = Math.max(0, Number(hObj.saved_tokens) || 0);
    const hPctNum = bTok > 0 ? Math.min(100, Math.max(0, (sTok / bTok) * 100)) : 0;
    harnesses[h] = {
      hits,
      baselineTokens: bTok,
      savedTokens: sTok,
      reductionPct: hPctNum,
    };
  }

  const rawLast = s.last_event && typeof s.last_event === "object" ? s.last_event : null;
  const lastEvent = rawLast
    ? {
        kind: typeof rawLast.kind === "string" && rawLast.kind ? rawLast.kind : "outlines",
        harness: typeof rawLast.harness === "string" && rawLast.harness ? rawLast.harness : "agent",
        savedTokens: Math.max(0, Number(rawLast.saved_tokens) || 0),
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
  };
}

function isLayerVisible(layer, events, includeCompactHidden = false) {
  if (!includeCompactHidden && layer.compactHidden) {
    return false;
  }
  if (layer.legacy) {
    return Boolean((events && events[layer.key] > 0) || (layer.retryKey && events && events[layer.retryKey] > 0));
  }
  return true;
}

module.exports = {
  HARNESS_ORDER,
  PROTECTION_LAYERS,
  EVENT_SHORT_LABELS,
  EVENT_FULL_LABELS,
  SEMVER_RE,
  WEBVIEW_CSP_META,
  isValidSemver,
  isLayerVisible,
  escapeHtml,
  escapeMarkdownCodeSpan,
  normalizeStats,
};
