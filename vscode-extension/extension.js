const vscode = require("vscode");
const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const viewModel = require("./view_model");
const {
  HARNESS_ORDER,
  PROTECTION_LAYERS,
  EVENT_SHORT_LABELS,
  EVENT_FULL_LABELS,
  WEBVIEW_CSP_META,
  isValidSemver,
  isLayerVisible,
  escapeMarkdownCodeSpan,
  normalizeStats,
} = viewModel;

const VERSION = require("./package.json").version;

function resolvePluginRoot(env = process.env, extDir = __dirname, homeDir = os.homedir()) {
  const effectiveHome = typeof homeDir === "string" && homeDir ? homeDir : os.homedir();
  if (env && typeof env.CONTEXT_GUARD_HOME === "string") {
    const rawEnv = env.CONTEXT_GUARD_HOME.trim();
    if (rawEnv) {
      if (rawEnv === "~") {
        return path.resolve(effectiveHome);
      }
      if (rawEnv.startsWith("~/") || rawEnv.startsWith("~\\")) {
        return path.resolve(effectiveHome, rawEnv.slice(2));
      }
      return path.resolve(rawEnv);
    }
  }
  if (typeof extDir === "string" && extDir) {
    try {
      const breadcrumbPath = path.join(extDir, "plugin_root.json");
      if (fs.existsSync(breadcrumbPath)) {
        const parsed = JSON.parse(fs.readFileSync(breadcrumbPath, "utf8"));
        if (parsed && typeof parsed.plugin_root === "string" && parsed.plugin_root.trim()) {
          return path.resolve(parsed.plugin_root.trim());
        }
      }
    } catch (_err) {
      // Fail open on missing, unreadable, or malformed plugin_root.json.
    }
    try {
      const parentDir = path.resolve(extDir, "..");
      if (
        fs.existsSync(path.join(parentDir, "plugin.json")) &&
        fs.existsSync(path.join(parentDir, "hooks", "pre_tool_use.py"))
      ) {
        return parentDir;
      }
    } catch (_err) {
      // Ignore filesystem probe errors and fall through to home fallback.
    }
  }
  return path.join(effectiveHome, ".gemini", "config", "plugins", "context-guard");
}

let PLUGIN_ROOT = resolvePluginRoot();
let STATS_PATH = path.join(PLUGIN_ROOT, "telemetry", "stats.json");
let UPDATE_PATH = path.join(PLUGIN_ROOT, "telemetry", "update.json");
let UPDATE_LOCK_PATH = path.join(PLUGIN_ROOT, "telemetry", "update.lock");
const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const UPDATE_RETRY_BACKOFF_MS = 60 * 60 * 1000;
const UPDATE_STEP_TIMEOUT_MS = 120000;
const STDERR_TAIL_CHARS = 500;
// The only commands the status bar tooltip links to; the tooltip trusts nothing else.
const TOOLTIP_COMMANDS = ["contextGuard.refresh", "contextGuard.showReport", "contextGuard.update"];

let statusBarItem = null;
let updateInFlight = false;
let watchListener = null;
let updateWatchListener = null;
let extensionContext = null;
let pulseTimer = null;
let lastPulseBody = "";
let lastSeenSavedTokens = null;
let activeReportPanel = null;
const activeWebviewViews = new Set();
const pendingNoticeKeys = new Set();

function refreshPluginPaths() {
  PLUGIN_ROOT = resolvePluginRoot();
  STATS_PATH = path.join(PLUGIN_ROOT, "telemetry", "stats.json");
  UPDATE_PATH = path.join(PLUGIN_ROOT, "telemetry", "update.json");
  UPDATE_LOCK_PATH = path.join(PLUGIN_ROOT, "telemetry", "update.lock");
}

function formatCompactTokens(tokens) {
  const val = Math.max(0, Number(tokens) || 0);
  if (val >= 1000000) {
    return (val / 1000000).toFixed(1) + "M";
  }
  if (val >= 1000) {
    return (val / 1000).toFixed(1) + "k";
  }
  return String(Math.round(val));
}

function formatContextWindows(tokens, windowSize = 200000) {
  const val = Math.max(0, Number(tokens) || 0);
  return (val / windowSize).toFixed(1);
}

function formatStatusBarIdleText(stats) {
  if (!stats || !(Number(stats.saved_tokens) > 0)) {
    return "$(shield) 0 tok · 0%";
  }
  const savedStr = formatCompactTokens(stats.saved_tokens);
  const pctInt = Math.round(Math.min(100, Math.max(0, Number(stats.reduction_pct) || 0)));
  return `$(shield) -${savedStr} · ${pctInt}%`;
}

function formatStatusBarPulseText(stats, deltaTokens, eventKind) {
  const deltaStr = formatCompactTokens(deltaTokens);
  const label = EVENT_SHORT_LABELS[eventKind] || "Saved";
  const pctInt = Math.round(Math.min(100, Math.max(0, Number(stats && stats.reduction_pct) || 0)));
  return `$(zap) -${deltaStr} (${label}) · ${pctInt}%`;
}

function formatBlockGauge(pct, width = 5) {
  const clamped = Math.min(100, Math.max(0, Number(pct) || 0));
  let filled = Math.round((clamped / 100) * width);
  if (clamped > 0 && filled === 0) {
    filled = 1;
  }
  filled = Math.min(width, Math.max(0, filled));
  return "▰".repeat(filled) + "▱".repeat(width - filled);
}

// Saved tokens are input tokens that never entered the context. Each one is priced once at the
// Claude Opus 5.5 list input rate (Anthropic API, October 2026). Prompt caching makes re-reads
// cheaper and every later turn re-sends the context, so the figure is an approximation, not a bill;
// subscription plans are not billed per token at all.
const INPUT_USD_PER_MILLION = 4.0;
const COST_BASIS_NOTE = "approx.: saved tokens × $4/M input (Claude Opus 5.5 list price), priced once";

function estimateCostUsd(tokens, ratePerMillion = INPUT_USD_PER_MILLION) {
  const val = Math.max(0, Number(tokens) || 0);
  return ((val / 1000000) * ratePerMillion).toFixed(2);
}

function escapeHtml(raw) {
  return viewModel.escapeHtml(raw);
}

function loadStats() {
  try {
    if (!fs.existsSync(STATS_PATH)) {
      return null;
    }
    const raw = fs.readFileSync(STATS_PATH, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    console.warn(`context-guard: telemetry unreadable (${STATS_PATH}): ${err}`);
    return null;
  }
}

function loadUpdate() {
  try {
    return JSON.parse(fs.readFileSync(UPDATE_PATH, "utf8"));
  } catch (_err) {
    return null; // absent until the first release check finishes
  }
}

function updateBadge(update) {
  const state = update && update.state;
  if (
    state === "update_available" &&
    isValidSemver(update.latest) &&
    (!update.local || isValidSemver(update.local))
  ) {
    return {
      prefix: "$(cloud-download) ",
      tooltipLine: `$(cloud-download) **Update available:** \`${escapeMarkdownCodeSpan(update.local || "?")}\` → \`${escapeMarkdownCodeSpan(update.latest)}\` &nbsp; [Update](command:contextGuard.update)`,
    };
  }
  if (
    state === "install_pending" &&
    (!update.local || isValidSemver(update.local)) &&
    (!update.installed || update.installed === "none" || isValidSemver(update.installed))
  ) {
    return {
      prefix: "$(cloud-download) ",
      tooltipLine: `$(cloud-download) **Installer not run** for \`${escapeMarkdownCodeSpan(update.local || "?")}\` (installed: \`${escapeMarkdownCodeSpan(update.installed || "none")}\`) &nbsp; [Run installer](command:contextGuard.update)`,
    };
  }
  return { prefix: "", tooltipLine: "" };
}

function updateNotice(update) {
  const state = update && update.state;
  if (
    state === "update_available" &&
    isValidSemver(update.latest) &&
    (!update.local || isValidSemver(update.local))
  ) {
    return {
      key: `contextGuard.notified.update.${update.latest}`,
      message: `Context-Guard ${update.latest} is available (you have ${update.local || "an older version"}).`,
      button: "Update",
    };
  }
  if (state === "install_pending" && isValidSemver(update.local)) {
    return {
      key: `contextGuard.notified.install.${update.local}`,
      message: `Context-Guard ${update.local} is checked out but the installer has not run for it.`,
      button: "Run installer",
    };
  }
  return null;
}

function pythonCandidates(platform = process.platform, env = process.env) {
  const candidates = [];
  if (env && typeof env.CONTEXT_GUARD_PYTHON === "string" && env.CONTEXT_GUARD_PYTHON.trim()) {
    candidates.push([env.CONTEXT_GUARD_PYTHON.trim(), []]);
  }
  if (platform === "win32") {
    candidates.push(["python", []], ["py", ["-3"]], ["python3", []]);
  } else {
    candidates.push(["python3", []], ["python", []]);
  }
  return candidates;
}

// Installs the release tag, never the tip of main. A local commit or a diverged checkout stops the
// fast-forward merge with nothing changed; the flow never forces, stashes or resets.
function updateSteps(state, pluginRoot, latest) {
  const rawScript = path.join(pluginRoot, "bin", "install_harnesses.py");
  const scriptPath = typeof pluginRoot === "string" && pluginRoot.startsWith("/") ? rawScript.replace(/\\/g, "/") : rawScript;
  const installer = ["python3", [scriptPath, "--install"]];
  if (state === "update_available") {
    if (!isValidSemver(latest)) {
      return [];
    }
    const tag = `v${latest}`;
    return [
      ["git", ["-C", pluginRoot, "fetch", "origin", "tag", tag, "--no-tags"]],
      ["git", ["-C", pluginRoot, "merge", "--ff-only", tag]],
      installer,
    ];
  }
  if (state === "install_pending") {
    return [installer];
  }
  return [];
}

function isUpdateStale(update, nowMs) {
  const checked = update && typeof update.checked_at === "string" ? Date.parse(update.checked_at) : NaN;
  return !Number.isFinite(checked) || nowMs - checked >= UPDATE_CHECK_INTERVAL_MS;
}

function isUpdateAttemptRecent(lockPath = UPDATE_LOCK_PATH, nowMs = Date.now()) {
  try {
    const stat = fs.statSync(lockPath);
    return Number.isFinite(stat.mtimeMs) && nowMs - stat.mtimeMs < UPDATE_RETRY_BACKOFF_MS;
  } catch (_err) {
    return false;
  }
}

function tailText(text, limit) {
  const trimmed = String(text || "").trim();
  return trimmed.length > limit ? `…${trimmed.slice(-limit)}` : trimmed;
}

function spawnUpdateCheckIfStale(update) {
  const nowMs = Date.now();
  if (!isUpdateStale(update, nowMs) || isUpdateAttemptRecent(UPDATE_LOCK_PATH, nowMs)) {
    return;
  }
  const scriptPath = path.join(PLUGIN_ROOT, "bin", "update_check.py");
  const cands = pythonCandidates();
  const trySpawn = (idx) => {
    if (idx >= cands.length) {
      return;
    }
    const [pyBin, prefixArgs] = cands[idx];
    const child = childProcess.spawn(pyBin, [...prefixArgs, scriptPath], {
      detached: true,
      stdio: "ignore",
    });
    child.on("error", (err) => {
      if (idx + 1 < cands.length) {
        trySpawn(idx + 1);
      } else {
        console.warn(`context-guard: update check not started: ${err}`);
      }
    });
    child.unref();
  };
  trySpawn(0);
}

function updateStepEnv(baseEnv) {
  const env = baseEnv || {};
  return {
    ...env,
    GIT_TERMINAL_PROMPT: "0",
    GCM_INTERACTIVE: "never",
    GIT_SSH_COMMAND: env.GIT_SSH_COMMAND || "ssh -o BatchMode=yes",
  };
}

function runUpdateStep([command, args]) {
  const options = { timeout: UPDATE_STEP_TIMEOUT_MS, env: updateStepEnv(process.env) };
  const attempts =
    command === "python3"
      ? pythonCandidates().map(([pyBin, prefixArgs]) => [pyBin, [...prefixArgs, ...args]])
      : [[command, args]];
  return new Promise((resolve, reject) => {
    const tryExec = (idx, lastErrMsg) => {
      if (idx >= attempts.length) {
        reject(new Error(lastErrMsg));
        return;
      }
      const [cmdBin, cmdArgs] = attempts[idx];
      childProcess.execFile(cmdBin, cmdArgs, options, (err, _stdout, stderr) => {
        if (err) {
          const msg = `${cmdBin} ${cmdArgs.join(" ")}: ${tailText(stderr || err.message, STDERR_TAIL_CHARS)}`;
          if (idx + 1 < attempts.length && (err.code === "ENOENT" || err.code === 9009)) {
            tryExec(idx + 1, msg);
          } else {
            reject(new Error(msg));
          }
        } else {
          resolve();
        }
      });
    };
    tryExec(0, `${command} ${args.join(" ")}: failed`);
  });
}

async function runUpdate() {
  if (updateInFlight) {
    vscode.window.showInformationMessage("Context-Guard update is already running.");
    return false;
  }
  const update = loadUpdate();
  const steps = updateSteps(update && update.state, PLUGIN_ROOT, update && update.latest);
  if (steps.length === 0) {
    vscode.window.showInformationMessage("Context-Guard is up to date.");
    return false;
  }
  updateInFlight = true;
  try {
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "Updating Context-Guard…" },
      async () => {
        for (const step of steps) {
          await runUpdateStep(step);
        }
      }
    );
  } catch (err) {
    vscode.window.showErrorMessage(`Context-Guard update stopped: ${err.message}`);
    return false;
  } finally {
    updateInFlight = false;
  }
  updateStatusBar();
  const choice = await vscode.window.showInformationMessage(
    "Context-Guard updated. Reload the window to load the new version.",
    "Reload Window"
  );
  if (choice === "Reload Window") {
    vscode.commands.executeCommand("workbench.action.reloadWindow");
  }
  return true;
}

function notifyUpdateOnce(update) {
  const notice = updateNotice(update);
  if (
    !notice ||
    !extensionContext ||
    extensionContext.globalState.get(notice.key) ||
    pendingNoticeKeys.has(notice.key)
  ) {
    return;
  }
  pendingNoticeKeys.add(notice.key);
  vscode.window.showInformationMessage(notice.message, notice.button).then(
    async (choice) => {
      pendingNoticeKeys.delete(notice.key);
      if (choice === notice.button) {
        const ok = await runUpdate();
        if (ok && extensionContext) {
          await extensionContext.globalState.update(notice.key, true);
        }
      }
    },
    () => {
      pendingNoticeKeys.delete(notice.key);
    }
  );
}

function buildTooltipMarkdown(stats, updateLine = "") {
  const md = new vscode.MarkdownString();
  md.isTrusted = { enabledCommands: TOOLTIP_COMMANDS };
  md.supportThemeIcons = true;
  if (updateLine) {
    md.appendMarkdown(`${updateLine}\n\n`);
  }
  if (!stats) {
    md.appendMarkdown(
      `**$(shield) Context-Guard v${VERSION}**\n\nNo telemetry events recorded yet. Token savings will appear automatically as you work.\n\n[$(graph) Open Dashboard](command:contextGuard.showReport)`
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

  md.appendMarkdown(`### $(shield) Context-Guard v${VERSION} — \`-${formatCompactTokens(savedTok)} tok\` (**-${pct}%**)\n\n`);
  md.appendMarkdown(
    `\`${gauge}\` &nbsp; **API Savings:** \`≈$${costUsd}\` *(${COST_BASIS_NOTE})* &nbsp;&bull;&nbsp; **Ctx Windows (200k):** \`~${ctxWindows}x\` *(since ${installedAt})*\n\n`
  );
  if (lastEv && lastEv.savedTokens > 0) {
    const fullLabel = EVENT_FULL_LABELS[lastEv.kind] || "Guard Intervention";
    const hName = escapeMarkdownCodeSpan(lastEv.harness || "agent");
    md.appendMarkdown(
      `$(zap) **Last Hit:** ${fullLabel} (\`-${formatCompactTokens(lastEv.savedTokens)} tok\` via \`${hName}\`)\n\n`
    );
  }
  md.appendMarkdown(`| Protection Layer | Hits |\n|---|---:|\n`);
  for (const layer of PROTECTION_LAYERS) {
    if (!isLayerVisible(layer, ev, false)) {
      continue;
    }
    const countStr = (ev[layer.key] || 0).toLocaleString();
    const retryCount = layer.retryKey ? ev[layer.retryKey] || 0 : 0;
    const cellStr = retryCount > 0 ? `**${countStr}** *(${retryCount.toLocaleString()} retry)*` : `**${countStr}**`;
    md.appendMarkdown(`| ${layer.codicon} ${layer.fullLabel} | ${cellStr} |\n`);
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

function renderSidebarHtml(stats) {
  const norm = normalizeStats(stats);
  const savedTok = norm.savedTokens;
  const baseTok = norm.baselineTokens;
  const actualTok = norm.actualTokens;
  const pctNum = norm.reductionPct;
  const pct = pctNum.toFixed(1);
  const costUsd = estimateCostUsd(savedTok);
  const ev = norm.events;

  const radius = 34;
  const circumference = (2 * Math.PI * radius).toFixed(2);
  const dashOffset = (circumference * (1 - pctNum / 100)).toFixed(2);

  const harnessBars = HARNESS_ORDER
    .map((h) => {
      const hObj = norm.harnesses[h];
      const hits = hObj.hits;
      const sTok = hObj.savedTokens;
      const hPctNum = hObj.reductionPct;
      const hPct = hPctNum.toFixed(1);
      return `<div class="h-item">
        <div class="h-header">
          <span class="h-name">${escapeHtml(h)} <span class="h-hits">(${hits})</span></span>
          <span class="h-val">-${formatCompactTokens(sTok)} <strong>-${hPct}%</strong></span>
        </div>
        <div class="bar-bg"><div class="bar-fill" style="width:${hPctNum}%"></div></div>
      </div>`;
    })
    .join("");

  const layerRows = PROTECTION_LAYERS.filter((layer) => isLayerVisible(layer, ev, false))
    .map((layer) => {
      const countStr = (ev[layer.key] || 0).toLocaleString();
      const retryCount = layer.retryKey ? ev[layer.retryKey] || 0 : 0;
      const valStr = retryCount > 0 ? `${countStr} (${retryCount.toLocaleString()} retry)` : countStr;
      return `<tr><td>${layer.emoji} ${escapeHtml(layer.fullLabel)}</td><td class="num">${valStr}</td></tr>`;
    })
    .join("\n      ");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
${WEBVIEW_CSP_META}
<style>
  body {
    font-family: var(--vscode-font-family, sans-serif);
    font-size: 12px;
    padding: 10px 12px;
    margin: 0;
    color: var(--vscode-foreground);
    background: transparent;
  }
  .hero {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px;
    border: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.25));
    border-radius: 8px;
    background: var(--vscode-editorWidget-background, rgba(128,128,128,0.08));
    margin-bottom: 10px;
  }
  .donut-wrap {
    position: relative;
    width: 82px;
    height: 82px;
    flex-shrink: 0;
  }
  .donut-svg {
    transform: rotate(-90deg);
    width: 82px;
    height: 82px;
  }
  .donut-bg {
    fill: none;
    stroke: var(--vscode-panel-border, rgba(128,128,128,0.22));
    stroke-width: 7;
  }
  .donut-fg {
    fill: none;
    stroke: var(--vscode-testing-iconPassed, #4ec9b0);
    stroke-width: 7;
    stroke-linecap: round;
    stroke-dasharray: ${circumference};
    stroke-dashoffset: ${dashOffset};
  }
  .donut-center {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    line-height: 1.1;
  }
  .donut-pct {
    font-size: 15px;
    font-weight: 700;
    color: var(--vscode-testing-iconPassed, #4ec9b0);
  }
  .donut-lbl {
    font-size: 9px;
    text-transform: uppercase;
    opacity: 0.7;
    margin-top: 2px;
  }
  .hero-right {
    flex: 1;
    min-width: 0;
  }
  .hero-title {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    opacity: 0.75;
  }
  .hero-tokens {
    font-size: 20px;
    font-weight: 700;
    margin: 2px 0 4px;
    white-space: nowrap;
  }
  .cost-pill {
    display: inline-block;
    font-size: 10.5px;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 10px;
    background: var(--vscode-badge-background, rgba(78,201,176,0.16));
    color: var(--vscode-testing-iconPassed, #4ec9b0);
  }
  .kpi-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
    margin-bottom: 12px;
  }
  .kpi-card {
    padding: 6px 8px;
    border-radius: 6px;
    border: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.18));
    background: var(--vscode-editorWidget-background, rgba(128,128,128,0.05));
  }
  .kpi-lbl {
    font-size: 10px;
    opacity: 0.7;
  }
  .kpi-val {
    font-size: 13px;
    font-weight: 600;
    margin-top: 2px;
    font-variant-numeric: tabular-nums;
  }
  h3 {
    font-size: 10.5px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    opacity: 0.8;
    margin: 12px 0 6px;
    padding-bottom: 4px;
    border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.2));
  }
  .h-item {
    margin-bottom: 7px;
  }
  .h-header {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    margin-bottom: 3px;
  }
  .h-name {
    font-family: var(--vscode-editor-font-family, monospace);
    font-weight: 600;
  }
  .h-hits {
    opacity: 0.65;
    font-weight: 400;
  }
  .h-val {
    font-variant-numeric: tabular-nums;
  }
  .bar-bg {
    width: 100%;
    height: 5px;
    border-radius: 3px;
    background: var(--vscode-panel-border, rgba(128,128,128,0.22));
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    background: var(--vscode-testing-iconPassed, #4ec9b0);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11.5px;
  }
  td {
    padding: 4px 2px;
    border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.12));
  }
  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
    font-weight: 600;
  }
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
      <div class="hero-title">🛡️ Context-Guard v${VERSION}</div>
      <div class="hero-tokens">-${formatCompactTokens(savedTok)} tok</div>
      <span class="cost-pill" title="${escapeHtml(COST_BASIS_NOTE)}">≈$${costUsd} saved (approx.)</span>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card"><div class="kpi-lbl">Baseline Read</div><div class="kpi-val">${formatCompactTokens(baseTok)} tok</div></div>
    <div class="kpi-card"><div class="kpi-lbl">Actual Sent</div><div class="kpi-val">${formatCompactTokens(actualTok)} tok</div></div>
  </div>

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

function updateStatusBar(options = {}) {
  const stats = loadStats();
  const update = loadUpdate();
  const badge = updateBadge(update);
  const currentSaved = stats ? Math.max(0, Number(stats.saved_tokens) || 0) : 0;
  if (statusBarItem) {
    const isPulseHit =
      Boolean(options.fromWatch) &&
      lastSeenSavedTokens !== null &&
      currentSaved > lastSeenSavedTokens;

    if (isPulseHit) {
      const delta = currentSaved - lastSeenSavedTokens;
      const kind =
        stats && stats.last_event && stats.last_event.kind ? stats.last_event.kind : "outlines";
      lastPulseBody = formatStatusBarPulseText(stats, delta, kind);
      statusBarItem.text = badge.prefix + lastPulseBody;
      statusBarItem.color = new vscode.ThemeColor("testing.iconPassed");
      lastSeenSavedTokens = currentSaved;
      if (pulseTimer) {
        clearTimeout(pulseTimer);
      }
      pulseTimer = setTimeout(() => {
        pulseTimer = null;
        lastPulseBody = "";
        if (statusBarItem) {
          const latest = loadStats();
          statusBarItem.text = updateBadge(loadUpdate()).prefix + formatStatusBarIdleText(latest);
          statusBarItem.color = undefined;
        }
      }, 4000);
    } else if (pulseTimer && lastPulseBody) {
      statusBarItem.text = badge.prefix + lastPulseBody;
      if (options.fromWatch) {
        lastSeenSavedTokens = currentSaved;
      }
    } else {
      statusBarItem.text = badge.prefix + formatStatusBarIdleText(stats);
      statusBarItem.color = undefined;
      lastSeenSavedTokens = currentSaved;
    }
    statusBarItem.tooltip = buildTooltipMarkdown(stats, badge.tooltipLine);
    statusBarItem.show();
  }
  if (activeWebviewViews.size > 0) {
    const sidebarHtml = renderSidebarHtml(stats);
    for (const view of activeWebviewViews) {
      try {
        view.webview.html = sidebarHtml;
      } catch (_err) {
        // Ignore disposed views
      }
    }
  }
  if (activeReportPanel) {
    try {
      activeReportPanel.webview.html = renderWebviewHtml(stats);
    } catch (_err) {
      activeReportPanel = null;
    }
  }
  notifyUpdateOnce(update);
  return { stats, update };
}

function renderWebviewHtml(stats) {
  const norm = normalizeStats(stats);
  const savedTok = norm.savedTokens;
  const baseTok = norm.baselineTokens;
  const actualTok = norm.actualTokens;
  const pct = norm.reductionPct.toFixed(1);
  const costUsd = estimateCostUsd(savedTok);
  const ev = norm.events;

  const harnessRows = HARNESS_ORDER
    .map((h) => {
      const hObj = norm.harnesses[h];
      const hits = hObj.hits;
      const bTok = hObj.baselineTokens;
      const sTok = hObj.savedTokens;
      const hPctNum = hObj.reductionPct;
      const hGauge = formatBlockGauge(hPctNum, 5);
      return `<tr><td><code>${escapeHtml(h)}</code></td><td>${hits.toLocaleString()}</td><td>${bTok.toLocaleString()}</td><td>-${sTok.toLocaleString()}</td><td><code>${hGauge}</code> <strong>-${hPctNum.toFixed(1)}%</strong></td></tr>`;
    })
    .join("");

  const mechanismRows = PROTECTION_LAYERS.filter((layer) => isLayerVisible(layer, ev, true))
    .map((layer) => {
    const countStr = (ev[layer.key] || 0).toLocaleString();
    const retryCount = layer.retryKey ? ev[layer.retryKey] || 0 : 0;
    const countCell =
      retryCount > 0 ? `${countStr} (${retryCount.toLocaleString()} retry)` : countStr;
    const keyCode = layer.retryKey
      ? `<code>${escapeHtml(layer.key)}</code> / <code>${escapeHtml(layer.retryKey)}</code>`
      : `<code>${escapeHtml(layer.key)}</code>`;
    return `<tr><td>${escapeHtml(layer.fullLabel)} (${keyCode})</td><td>${countCell}</td></tr>`;
  }).join("\n      ");

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
  <h1>🛡️ Context-Guard v${VERSION} — Cumulative Token Savings</h1>
  <p>Installed since: <code>${escapeHtml(norm.installedAt || "N/A")}</code> &bull; Last updated: <code>${escapeHtml(norm.updatedAt || "N/A")}</code></p>
  <div class="cards">
    <div class="card"><div class="label">Tokens Saved</div><div class="value accent">-${savedTok.toLocaleString()} (${formatCompactTokens(savedTok)})</div></div>
    <div class="card"><div class="label">Overall Reduction</div><div class="value accent">-${pct}%</div></div>
    <div class="card"><div class="label">API Cost Saved (approx.)</div><div class="value accent">≈$${costUsd}</div><div class="label">${escapeHtml(COST_BASIS_NOTE)}</div></div>
    <div class="card"><div class="label">Baseline vs Actual</div><div class="value">${formatCompactTokens(baseTok)} &rarr; ${formatCompactTokens(actualTok)}</div></div>
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
  </table>
</body>
</html>`;
}

function createSidebarProvider() {
  return {
    resolveWebviewView(webviewView) {
      webviewView.webview.options = { enableScripts: false };
      activeWebviewViews.add(webviewView);
      webviewView.webview.html = renderSidebarHtml(loadStats());
      webviewView.onDidDispose(() => {
        activeWebviewViews.delete(webviewView);
      });
      webviewView.onDidChangeVisibility(() => {
        if (webviewView.visible) {
          webviewView.webview.html = renderSidebarHtml(loadStats());
        }
      });
    },
  };
}

function _cleanupExtensionState() {
  if (pulseTimer) {
    clearTimeout(pulseTimer);
    pulseTimer = null;
  }
  lastPulseBody = "";
  if (watchListener) {
    fs.unwatchFile(STATS_PATH, watchListener);
    watchListener = null;
  }
  if (updateWatchListener) {
    fs.unwatchFile(UPDATE_PATH, updateWatchListener);
    updateWatchListener = null;
  }
  activeWebviewViews.clear();
  pendingNoticeKeys.clear();
  activeReportPanel = null;
  statusBarItem = null;
  lastSeenSavedTokens = null;
  updateInFlight = false;
  extensionContext = null;
}

function activate(context) {
  _cleanupExtensionState();
  refreshPluginPaths();
  extensionContext = context;
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 1000);
  statusBarItem.name = "Context-Guard Token Savings";
  statusBarItem.command = "contextGuard.showReport";
  context.subscriptions.push(statusBarItem);

  const sidebarProvider = createSidebarProvider();
  if (typeof vscode.window.registerWebviewViewProvider === "function") {
    context.subscriptions.push(
      vscode.window.registerWebviewViewProvider("contextGuard.sidebarView", sidebarProvider),
      vscode.window.registerWebviewViewProvider("contextGuard.explorerView", sidebarProvider)
    );
  }

  const cmdDisposable = vscode.commands.registerCommand("contextGuard.showReport", () => {
    if (activeReportPanel) {
      activeReportPanel.webview.html = renderWebviewHtml(loadStats());
      if (typeof activeReportPanel.reveal === "function") {
        activeReportPanel.reveal(vscode.ViewColumn.One);
      }
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "contextGuardReport",
      "Context-Guard Token Savings",
      vscode.ViewColumn.One,
      { enableScripts: false }
    );
    activeReportPanel = panel;
    if (typeof panel.onDidDispose === "function") {
      panel.onDidDispose(() => {
        if (activeReportPanel === panel) {
          activeReportPanel = null;
        }
      });
    }
    panel.webview.html = renderWebviewHtml(loadStats());
  });
  const refreshDisposable = vscode.commands.registerCommand("contextGuard.refresh", () => {
    updateStatusBar();
  });
  const updateDisposable = vscode.commands.registerCommand("contextGuard.update", () => {
    runUpdate();
  });
  context.subscriptions.push(cmdDisposable, refreshDisposable, updateDisposable);

  const initial = updateStatusBar();
  spawnUpdateCheckIfStale(initial.update);

  watchListener = () => {
    updateStatusBar({ fromWatch: true });
  };
  fs.watchFile(STATS_PATH, { interval: 2500 }, watchListener);
  updateWatchListener = () => {
    updateStatusBar();
  };
  fs.watchFile(UPDATE_PATH, { interval: 2500 }, updateWatchListener);

  context.subscriptions.push({
    dispose: () => {
      _cleanupExtensionState();
    },
  });
}

function deactivate() {
  _cleanupExtensionState();
}

module.exports = {
  activate,
  deactivate,
  updateStatusBar,
  formatCompactTokens,
  formatContextWindows,
  formatStatusBarIdleText,
  formatStatusBarPulseText,
  formatBlockGauge,
  estimateCostUsd,
  COST_BASIS_NOTE,
  escapeHtml,
  escapeMarkdownCodeSpan,
  isValidSemver,
  normalizeStats,
  HARNESS_ORDER,
  PROTECTION_LAYERS,
  WEBVIEW_CSP_META,
  buildTooltipMarkdown,
  renderSidebarHtml,
  renderWebviewHtml,
  updateBadge,
  updateNotice,
  updateSteps,
  updateStepEnv,
  TOOLTIP_COMMANDS,
  isUpdateStale,
  isUpdateAttemptRecent,
  tailText,
  resolvePluginRoot,
  pythonCandidates,
};
