"use strict";

const {
  HARNESS_ORDER,
  PROTECTION_LAYERS,
  EVENT_FULL_LABELS,
  COST_BASIS_NOTE,
  WEBVIEW_CSP_META,
  isLayerVisible,
  escapeHtml,
  escapeMarkdownCodeSpan,
  normalizeStats,
  formatCompactTokens,
  formatContextWindows,
  formatBlockGauge,
  estimateCostUsd,
} = require("./view_model");

// The only commands the status bar tooltip links to; the tooltip trusts nothing else.
const TOOLTIP_COMMANDS = ["contextGuard.refresh", "contextGuard.showReport", "contextGuard.update"];

function formatSignedCompactTokens(value) {
  const num = Number(value) || 0;
  const formatted = formatCompactTokens(Math.abs(num));
  return num >= 0 ? `+${formatted}` : `-${formatted}`;
}

function insightsView(insights) {
  const src = insights && typeof insights === "object" ? insights : {};
  const cacheHit = src.cacheHitLabel ? String(src.cacheHitLabel) : "n/a";
  const docLabel = src.doctor && src.doctor.statusLabel ? String(src.doctor.statusLabel) : "n/a";
  const verdict = src.sunsetVerdict && typeof src.sunsetVerdict === "object" ? src.sunsetVerdict : null;
  const verdictStatus = verdict && verdict.status ? String(verdict.status) : "n/a";
  const verdictDetail =
    verdict && verdict.windowDays != null && verdict.targetDays != null
      ? `${verdict.windowDays}/${verdict.targetDays}d (${formatSignedCompactTokens(verdict.netSaved)} tok)`
      : "";
  const preLast = src.preambleLast && typeof src.preambleLast === "object" ? src.preambleLast : null;
  const byHarness =
    src.preambleByHarness && typeof src.preambleByHarness === "object" ? src.preambleByHarness : {};
  return { hasInsights: Boolean(insights), cacheHit, docLabel, verdictStatus, verdictDetail, preLast, byHarness };
}

function buildTooltipMarkdown(MarkdownStringCls, version, stats, updateLine = "", insights = null) {
  const md = new MarkdownStringCls();
  md.isTrusted = { enabledCommands: TOOLTIP_COMMANDS };
  md.supportThemeIcons = true;
  if (updateLine) {
    md.appendMarkdown(`${updateLine}\n\n`);
  }
  const safeVer = escapeMarkdownCodeSpan(version || "0.0.0");
  if (!stats) {
    md.appendMarkdown(
      `**$(shield) Context-Guard v${safeVer}**\n\nNo telemetry events recorded yet. Token savings will appear automatically as you work.\n\n[$(graph) Open Dashboard](command:contextGuard.showReport)`
    );
    return md;
  }
  const norm = normalizeStats(stats);
  const savedTok = norm.savedTokens;
  const pctNum = norm.reductionPct;
  const pct = pctNum.toFixed(1);
  const gauge = formatBlockGauge(pctNum, 10);
  const costUsd = estimateCostUsd(savedTok);
  const ctxWindows = formatContextWindows(savedTok);
  const ev = norm.events;
  const lastEv = norm.lastEvent;
  const installedAt = escapeMarkdownCodeSpan(
    norm.installedAt ? String(norm.installedAt).slice(0, 16).replace("T", " ") : "unknown"
  );

  md.appendMarkdown(`### $(shield) Context-Guard v${safeVer} — \`-${formatCompactTokens(savedTok)} tok\` (**-${pct}%**)\n\n`);
  md.appendMarkdown(
    `\`${gauge}\` &nbsp; **API Savings:** \`≈$${costUsd}\` *(${COST_BASIS_NOTE})* &nbsp;&bull;&nbsp; **Ctx Windows (200k):** \`~${ctxWindows}x\` *(since ${installedAt})*\n\n`
  );
  if (insights) {
    const iv = insightsView(insights);
    const preText = iv.preLast
      ? `\`${formatCompactTokens(iv.preLast.last)}\` (Recent (10): \`${formatCompactTokens(iv.preLast.recentMedian)}\`, \`${escapeMarkdownCodeSpan(iv.preLast.harness)}\`)`
      : "`n/a`";
    const verdictSuffix = iv.verdictDetail ? ` *(${escapeMarkdownCodeSpan(iv.verdictDetail)})*` : "";
    md.appendMarkdown(
      `**Cache Hit:** \`${escapeMarkdownCodeSpan(iv.cacheHit)}\` &nbsp;&bull;&nbsp; **Preamble (Last):** ${preText} &nbsp;&bull;&nbsp; **Doctor:** \`${escapeMarkdownCodeSpan(iv.docLabel)}\` &nbsp;&bull;&nbsp; **30d Verdict:** \`${escapeMarkdownCodeSpan(iv.verdictStatus)}\`${verdictSuffix}\n\n`
    );
  }
  if (lastEv && lastEv.savedTokens > 0) {
    const fullLabel = EVENT_FULL_LABELS[lastEv.kind] || "Guard Intervention";
    const hName = escapeMarkdownCodeSpan(lastEv.harness || "agent");
    md.appendMarkdown(
      `$(zap) **Last Hit:** ${fullLabel} (\`-${formatCompactTokens(lastEv.savedTokens)} tok\` via \`${hName}\`)\n\n`
    );
  }
  md.appendMarkdown(`| Protection Layer | Hits |\n|---|---:|\n`);
  for (const layer of PROTECTION_LAYERS) {
    if (!isLayerVisible(layer, ev, false)) continue;
    const countStr = (ev[layer.key] || 0).toLocaleString();
    md.appendMarkdown(`| ${layer.codicon} ${layer.fullLabel} | **${countStr}** |\n`);
  }
  md.appendMarkdown("\n");

  md.appendMarkdown(`| Harness | Saved | Reduction |\n|---|---:|---|\n`);
  for (const h of HARNESS_ORDER) {
    const hObj = norm.harnesses[h];
    const hPctNum = hObj.reductionPct;
    const hGauge = formatBlockGauge(hPctNum, 5);
    md.appendMarkdown(
      `| \`${escapeMarkdownCodeSpan(h)}\` | -${formatCompactTokens(hObj.savedTokens)} | \`${hGauge}\` **-${hPctNum.toFixed(1)}%** |\n`
    );
  }
  md.appendMarkdown(
    `\n[$(graph) Open Full Dashboard](command:contextGuard.showReport) &nbsp;&bull;&nbsp; [$(refresh) Refresh](command:contextGuard.refresh)`
  );
  return md;
}

function renderSidebarHtml(version, stats, insights = null) {
  const norm = normalizeStats(stats);
  const savedTok = norm.savedTokens;
  const baseTok = norm.baselineTokens;
  const actualTok = norm.actualTokens;
  const pctNum = norm.reductionPct;
  const pct = pctNum.toFixed(1);
  const costUsd = estimateCostUsd(savedTok);
  const ev = norm.events;
  const safeVer = escapeHtml(version || "0.0.0");

  const radius = 34;
  const circumference = (2 * Math.PI * radius).toFixed(2);
  const dashOffset = (circumference * (1 - pctNum / 100)).toFixed(2);

  const harnessBars = HARNESS_ORDER
    .map((h) => {
      const hObj = norm.harnesses[h];
      const hPctNum = hObj.reductionPct;
      return `<div class="h-item">
        <div class="h-header">
          <span class="h-name">${escapeHtml(h)} <span class="h-hits">(${hObj.hits})</span></span>
          <span class="h-val">-${formatCompactTokens(hObj.savedTokens)} <strong>-${hPctNum.toFixed(1)}%</strong></span>
        </div>
        <div class="bar-bg"><div class="bar-fill" style="width:${hPctNum}%"></div></div>
      </div>`;
    })
    .join("");

  const layerRows = PROTECTION_LAYERS.filter((layer) => isLayerVisible(layer, ev, false))
    .map((layer) => {
      const countStr = (ev[layer.key] || 0).toLocaleString();
      return `<tr><td>${layer.emoji} ${escapeHtml(layer.fullLabel)}</td><td class="num">${countStr}</td></tr>`;
    })
    .join("\n      ");

  let v4Cards = "";
  if (insights) {
    const iv = insightsView(insights);
    const preVal = iv.preLast ? `${escapeHtml(formatCompactTokens(iv.preLast.last))} tok` : "n/a";
    const preSub = iv.preLast
      ? `Recent (10): ${escapeHtml(formatCompactTokens(iv.preLast.recentMedian))} (${escapeHtml(iv.preLast.harness)})`
      : "Recent (10): n/a";
    v4Cards = `
  <div class="kpi-grid">
    <div class="kpi-card"><div class="kpi-lbl">Cache Hit</div><div class="kpi-val">${escapeHtml(iv.cacheHit)}</div></div>
    <div class="kpi-card"><div class="kpi-lbl">Preamble (Last)</div><div class="kpi-val">${preVal}</div><div class="kpi-lbl">${preSub}</div></div>
    <div class="kpi-card"><div class="kpi-lbl">Doctor</div><div class="kpi-val">${escapeHtml(iv.docLabel)}</div></div>
    <div class="kpi-card"><div class="kpi-lbl">30d Verdict</div><div class="kpi-val">${escapeHtml(iv.verdictStatus)}</div>${iv.verdictDetail ? `<div class="kpi-lbl">${escapeHtml(iv.verdictDetail)}</div>` : ""}</div>
  </div>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
${WEBVIEW_CSP_META}
<style>
  body { font-family: var(--vscode-font-family, sans-serif); font-size: 12px; padding: 10px 12px; margin: 0; color: var(--vscode-foreground); background: transparent; }
  .hero { display: flex; align-items: center; gap: 12px; padding: 12px; border: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.25)); border-radius: 8px; background: var(--vscode-editorWidget-background, rgba(128,128,128,0.08)); margin-bottom: 10px; }
  .donut-wrap { position: relative; width: 82px; height: 82px; flex-shrink: 0; }
  .donut-svg { transform: rotate(-90deg); width: 82px; height: 82px; }
  .donut-bg { fill: none; stroke: var(--vscode-panel-border, rgba(128,128,128,0.22)); stroke-width: 7; }
  .donut-fg { fill: none; stroke: var(--vscode-testing-iconPassed, #4ec9b0); stroke-width: 7; stroke-linecap: round; stroke-dasharray: ${circumference}; stroke-dashoffset: ${dashOffset}; }
  .donut-center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; line-height: 1.1; }
  .donut-pct { font-size: 15px; font-weight: 700; color: var(--vscode-testing-iconPassed, #4ec9b0); }
  .donut-lbl { font-size: 9px; text-transform: uppercase; opacity: 0.7; margin-top: 2px; }
  .hero-right { flex: 1; min-width: 0; }
  .hero-title { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.75; }
  .hero-tokens { font-size: 20px; font-weight: 700; margin: 2px 0 4px; white-space: nowrap; }
  .cost-pill { display: inline-block; font-size: 10.5px; font-weight: 600; padding: 2px 7px; border-radius: 10px; background: var(--vscode-badge-background, rgba(78,201,176,0.16)); color: var(--vscode-testing-iconPassed, #4ec9b0); }
  .kpi-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-bottom: 10px; }
  .kpi-card { padding: 6px 8px; border-radius: 6px; border: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.18)); background: var(--vscode-editorWidget-background, rgba(128,128,128,0.05)); }
  .kpi-lbl { font-size: 10px; opacity: 0.7; }
  .kpi-val { font-size: 13px; font-weight: 600; margin-top: 2px; font-variant-numeric: tabular-nums; }
  h3 { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.8; margin: 12px 0 6px; padding-bottom: 4px; border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.2)); }
  .h-item { margin-bottom: 7px; }
  .h-header { display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 3px; }
  .h-name { font-family: var(--vscode-editor-font-family, monospace); font-weight: 600; }
  .h-hits { opacity: 0.65; font-weight: 400; }
  .h-val { font-variant-numeric: tabular-nums; }
  .bar-bg { width: 100%; height: 5px; border-radius: 3px; background: var(--vscode-panel-border, rgba(128,128,128,0.22)); overflow: hidden; }
  .bar-fill { height: 100%; background: var(--vscode-testing-iconPassed, #4ec9b0); }
  table { width: 100%; border-collapse: collapse; font-size: 11.5px; }
  td { padding: 4px 2px; border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.12)); }
  .num { text-align: right; font-variant-numeric: tabular-nums; font-weight: 600; }
</style>
</head>
<body>
  <div class="hero">
    <div class="donut-wrap">
      <svg class="donut-svg" viewBox="0 0 82 82">
        <circle class="donut-bg" cx="41" cy="41" r="${radius}"></circle>
        <circle class="donut-fg" cx="41" cy="41" r="${radius}"></circle>
      </svg>
      <div class="donut-center">
        <span class="donut-pct">-${pct}%</span>
        <span class="donut-lbl">Saved</span>
      </div>
    </div>
    <div class="hero-right">
      <div class="hero-title">🛡️ Context-Guard v${safeVer}</div>
      <div class="hero-tokens">-${formatCompactTokens(savedTok)} tok</div>
      <span class="cost-pill" title="${escapeHtml(COST_BASIS_NOTE)}">≈$${costUsd} saved (approx.)</span>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card"><div class="kpi-lbl">Baseline Read</div><div class="kpi-val">${formatCompactTokens(baseTok)} tok</div></div>
    <div class="kpi-card"><div class="kpi-lbl">Actual Sent</div><div class="kpi-val">${formatCompactTokens(actualTok)} tok</div></div>
  </div>${v4Cards}

  <h3>By Harness</h3>
  ${harnessBars}

  <h3>By Protection Layer</h3>
  <table>
    <tbody>
      ${layerRows}
    </tbody>
  </table>
</body>
</html>`;
}

function renderWebviewHtml(version, stats, insights = null) {
  const norm = normalizeStats(stats);
  const savedTok = norm.savedTokens;
  const baseTok = norm.baselineTokens;
  const actualTok = norm.actualTokens;
  const pct = norm.reductionPct.toFixed(1);
  const costUsd = estimateCostUsd(savedTok);
  const ev = norm.events;
  const safeVer = escapeHtml(version || "0.0.0");

  const harnessRows = HARNESS_ORDER
    .map((h) => {
      const hObj = norm.harnesses[h];
      const hPctNum = hObj.reductionPct;
      const hGauge = formatBlockGauge(hPctNum, 5);
      return `<tr><td><code>${escapeHtml(h)}</code></td><td>${hObj.hits.toLocaleString()}</td><td>${hObj.baselineTokens.toLocaleString()}</td><td>-${hObj.savedTokens.toLocaleString()}</td><td><code>${hGauge}</code> <strong>-${hPctNum.toFixed(1)}%</strong></td></tr>`;
    })
    .join("");

  const mechanismRows = PROTECTION_LAYERS.filter((layer) => isLayerVisible(layer, ev, true))
    .map((layer) => {
      const countStr = (ev[layer.key] || 0).toLocaleString();
      return `<tr><td>${escapeHtml(layer.fullLabel)} (<code>${escapeHtml(layer.key)}</code>)</td><td>${countStr}</td></tr>`;
    })
    .join("\n      ");

  let v4Cards = "";
  let preambleSection = "";
  if (insights) {
    const iv = insightsView(insights);
    const preVal = iv.preLast ? `${escapeHtml(formatCompactTokens(iv.preLast.last))} tok` : "n/a";
    const preSub = iv.preLast
      ? `Recent (10): ${escapeHtml(formatCompactTokens(iv.preLast.recentMedian))} &bull; ${escapeHtml(iv.preLast.harness)}`
      : "Recent (10): n/a";
    v4Cards = `
    <div class="card"><div class="label">Cache Hit</div><div class="value">${escapeHtml(iv.cacheHit)}</div></div>
    <div class="card"><div class="label">Preamble (Last)</div><div class="value">${preVal}</div><div class="label">${preSub}</div></div>
    <div class="card"><div class="label">Doctor</div><div class="value">${escapeHtml(iv.docLabel)}</div></div>
    <div class="card"><div class="label">30d Verdict</div><div class="value">${escapeHtml(iv.verdictStatus)}</div>${iv.verdictDetail ? `<div class="label">${escapeHtml(iv.verdictDetail)}</div>` : ""}</div>`;
    const preEntries = Object.entries(iv.byHarness);
    if (preEntries.length) {
      const preRows = preEntries
        .map(([h, row]) => {
          const r = row && typeof row === "object" ? row : {};
          return `<tr><td><code>${escapeHtml(h)}</code></td><td>${Number(r.sessions || 0).toLocaleString()}</td><td>${formatCompactTokens(r.median)}</td><td>${formatCompactTokens(r.recentMedian)}</td><td>${formatCompactTokens(r.last)}</td></tr>`;
        })
        .join("\n      ");
      preambleSection = `
  <h2>Session Preamble by Harness</h2>
  <table>
    <thead><tr><th>Harness</th><th>Sessions</th><th>Median</th><th>Recent (10)</th><th>Last</th></tr></thead>
    <tbody>
      ${preRows}
    </tbody>
  </table>`;
    }
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
${WEBVIEW_CSP_META}
<style>
  body { font-family: var(--vscode-font-family, sans-serif); padding: 24px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
  h1, h2 { border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 8px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin: 20px 0; }
  .card { padding: 14px; border: 1px solid var(--vscode-panel-border); border-radius: 8px; background: var(--vscode-editorWidget-background); }
  .card .label { font-size: 12px; opacity: 0.8; }
  .card .value { font-size: 22px; font-weight: 700; margin-top: 6px; }
  .accent { color: var(--vscode-testing-iconPassed, #4ec9b0); }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--vscode-panel-border); }
  th { opacity: 0.85; }
</style>
</head>
<body>
  <h1>🛡️ Context-Guard v${safeVer} — Cumulative Token Savings</h1>
  <p>Installed since: <code>${escapeHtml(norm.installedAt || "N/A")}</code> &bull; Last updated: <code>${escapeHtml(norm.updatedAt || "N/A")}</code></p>
  <div class="cards">
    <div class="card"><div class="label">Tokens Saved</div><div class="value accent">-${savedTok.toLocaleString()} (${formatCompactTokens(savedTok)})</div></div>
    <div class="card"><div class="label">Overall Reduction</div><div class="value accent">-${pct}%</div></div>
    <div class="card"><div class="label">API Cost Saved (approx.)</div><div class="value accent">≈$${costUsd}</div><div class="label">${escapeHtml(COST_BASIS_NOTE)}</div></div>
    <div class="card"><div class="label">Baseline vs Actual</div><div class="value">${formatCompactTokens(baseTok)} &rarr; ${formatCompactTokens(actualTok)}</div></div>${v4Cards}
  </div>
  <h2>Protection Breakdown by Mechanism</h2>
  <table>
    <thead><tr><th>Mechanism</th><th>Count</th></tr></thead>
    <tbody>
      ${mechanismRows}
    </tbody>
  </table>
  <h2>Savings by Harness</h2>
  <table>
    <thead><tr><th>Harness</th><th>Interceptions</th><th>Baseline Tokens</th><th>Saved Tokens</th><th>Reduction</th></tr></thead>
    <tbody>${harnessRows}</tbody>
  </table>${preambleSection}
</body>
</html>`;
}

module.exports = {
  TOOLTIP_COMMANDS,
  buildTooltipMarkdown,
  renderSidebarHtml,
  renderWebviewHtml,
};
