"use strict";

const vscode = require("vscode");
const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");
const viewModel = require("./view_model");
const updater = require("./updater");
const renderers = require("./renderers");

const {
  HARNESS_ORDER,
  PROTECTION_LAYERS,
  COST_BASIS_NOTE,
  WEBVIEW_CSP_META,
  isValidSemver,
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
} = viewModel;

const {
  resolvePluginRoot,
  updateBadge,
  updateNotice,
  pythonCandidates,
  updateSteps,
  isUpdateStale,
  isUpdateAttemptRecent,
  tailText,
  updateStepEnv,
  runUpdateStep,
  spawnUpdateCheckIfStale,
  probeDoctor,
} = updater;

const { TOOLTIP_COMMANDS } = renderers;
const VERSION = require("./package.json").version;

let PLUGIN_ROOT = resolvePluginRoot();
let STATS_PATH = path.join(PLUGIN_ROOT, "telemetry", "stats.json");
let UPDATE_PATH = path.join(PLUGIN_ROOT, "telemetry", "update.json");
let UPDATE_LOCK_PATH = path.join(PLUGIN_ROOT, "telemetry", "update.lock");
let USAGE_PATH = path.join(PLUGIN_ROOT, "telemetry", "token_usage.json");
let OUTCOMES_PATH = path.join(PLUGIN_ROOT, "telemetry", "outcomes.json");

let statusBarItem = null;
let updateInFlight = false;
let refreshUsageInFlight = false;
let watchListener = null;
let updateWatchListener = null;
let usageWatchListener = null;
let extensionContext = null;
let pulseTimer = null;
let lastPulseBody = "";
let lastSeenSavedTokens = null;
let activeReportPanel = null;
const activeWebviewViews = new Set();
const pendingNoticeKeys = new Set();
const jsonCache = new Map();
const DOCTOR_CACHE_TTL_MS = 30000;
let doctorCache = null;

function invalidateDoctorCache() {
  doctorCache = null;
}

function getCachedDoctor() {
  const now = Date.now();
  if (doctorCache && doctorCache.root === PLUGIN_ROOT && now - doctorCache.atMs < DOCTOR_CACHE_TTL_MS) {
    return doctorCache.value;
  }
  const value = probeDoctor(PLUGIN_ROOT);
  doctorCache = { root: PLUGIN_ROOT, atMs: now, value };
  return value;
}

function refreshPluginPaths() {
  PLUGIN_ROOT = resolvePluginRoot();
  STATS_PATH = path.join(PLUGIN_ROOT, "telemetry", "stats.json");
  UPDATE_PATH = path.join(PLUGIN_ROOT, "telemetry", "update.json");
  UPDATE_LOCK_PATH = path.join(PLUGIN_ROOT, "telemetry", "update.lock");
  USAGE_PATH = path.join(PLUGIN_ROOT, "telemetry", "token_usage.json");
  OUTCOMES_PATH = path.join(PLUGIN_ROOT, "telemetry", "outcomes.json");
  jsonCache.clear();
  invalidateDoctorCache();
}

function loadJsonFailOpen(filePath, warnLabel = "") {
  try {
    const st = fs.statSync(filePath);
    const cached = jsonCache.get(filePath);
    if (
      cached &&
      cached.ino === st.ino &&
      cached.mtimeMs === st.mtimeMs &&
      cached.ctimeMs === st.ctimeMs &&
      cached.size === st.size
    ) {
      return cached.data;
    }
    const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
    jsonCache.set(filePath, { ino: st.ino, mtimeMs: st.mtimeMs, ctimeMs: st.ctimeMs, size: st.size, data });
    return data;
  } catch (err) {
    jsonCache.delete(filePath);
    if (err && err.code !== "ENOENT" && warnLabel) {
      console.warn(`context-guard: ${warnLabel} unreadable (${filePath}): ${err}`);
    }
    return null;
  }
}

const loadStats = () => loadJsonFailOpen(STATS_PATH, "telemetry");
const loadUpdate = () => loadJsonFailOpen(UPDATE_PATH);
const loadTokenUsage = () => loadJsonFailOpen(USAGE_PATH);
const loadOutcomes = () => loadJsonFailOpen(OUTCOMES_PATH);

function computeInsights(stats) {
  return summarizeV4Insights(stats, loadTokenUsage(), loadOutcomes(), getCachedDoctor());
}

function buildTooltipMarkdown(stats, updateLine = "", insights = undefined) {
  const resolvedInsights = insights === undefined ? computeInsights(stats) : insights;
  return renderers.buildTooltipMarkdown(vscode.MarkdownString, VERSION, stats, updateLine, resolvedInsights);
}

function renderSidebarHtml(stats, insights = undefined) {
  const resolvedInsights = insights === undefined ? computeInsights(stats) : insights;
  return renderers.renderSidebarHtml(VERSION, stats, resolvedInsights);
}

function renderWebviewHtml(stats, insights = undefined) {
  const resolvedInsights = insights === undefined ? computeInsights(stats) : insights;
  return renderers.renderWebviewHtml(VERSION, stats, resolvedInsights);
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
    invalidateDoctorCache();
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

function triggerBackgroundUsageRefresh() {
  if (refreshUsageInFlight) return;
  const scriptPath = path.join(PLUGIN_ROOT, "bin", "cg_status.py");
  if (!fs.existsSync(scriptPath)) return;
  const cands = pythonCandidates();
  refreshUsageInFlight = true;
  const tryExec = (idx) => {
    if (idx >= cands.length) {
      refreshUsageInFlight = false;
      console.warn("context-guard: background usage refresh not started: no python candidate");
      return;
    }
    const [pyBin, prefixArgs] = cands[idx];
    childProcess.execFile(pyBin, [...prefixArgs, scriptPath, "--usage"], { timeout: 15000, windowsHide: true }, (err) => {
      if (err && idx + 1 < cands.length && (err.code === "ENOENT" || err.code === 9009)) {
        tryExec(idx + 1);
        return;
      }
      refreshUsageInFlight = false;
      if (err) {
        console.warn(`context-guard: background usage refresh failed: ${err}`);
        return;
      }
      if (statusBarItem) updateStatusBar();
    });
  };
  tryExec(0);
}

function triggerUsageRefreshIfStale(maxAgeMs = 600000) {
  try {
    const st = fs.statSync(USAGE_PATH);
    if (Number.isFinite(st.mtimeMs) && Date.now() - st.mtimeMs < maxAgeMs) return;
  } catch (_err) {
    // Missing or unreadable token_usage.json triggers background refresh.
  }
  triggerBackgroundUsageRefresh();
}

function updateStatusBar(options = {}) {
  const stats = loadStats();
  const update = loadUpdate();
  const badge = updateBadge(update);
  const insights = computeInsights(stats);
  const currentSaved = stats ? finiteNonNeg(stats.saved_tokens) : 0;
  if (statusBarItem) {
    const isPulseHit =
      Boolean(options.fromWatch) &&
      lastSeenSavedTokens !== null &&
      currentSaved > lastSeenSavedTokens;

    if (isPulseHit) {
      const delta = currentSaved - lastSeenSavedTokens;
      const kind = stats && stats.last_event && stats.last_event.kind ? stats.last_event.kind : "outlines";
      lastPulseBody = formatStatusBarPulseText(stats, delta, kind);
      statusBarItem.text = badge.prefix + lastPulseBody;
      statusBarItem.color = new vscode.ThemeColor("testing.iconPassed");
      lastSeenSavedTokens = currentSaved;
      if (pulseTimer) clearTimeout(pulseTimer);
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
      if (options.fromWatch) lastSeenSavedTokens = currentSaved;
    } else {
      statusBarItem.text = badge.prefix + formatStatusBarIdleText(stats);
      statusBarItem.color = undefined;
      lastSeenSavedTokens = currentSaved;
    }
    statusBarItem.tooltip = buildTooltipMarkdown(stats, badge.tooltipLine, insights);
    statusBarItem.show();
  }
  if (activeWebviewViews.size > 0) {
    const sidebarHtml = renderSidebarHtml(stats, insights);
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
      activeReportPanel.webview.html = renderWebviewHtml(stats, insights);
    } catch (_err) {
      activeReportPanel = null;
    }
  }
  notifyUpdateOnce(update);
  return { stats, update };
}

function createSidebarProvider() {
  return {
    resolveWebviewView(webviewView) {
      webviewView.webview.options = { enableScripts: false };
      activeWebviewViews.add(webviewView);
      webviewView.webview.html = renderSidebarHtml(loadStats());
      triggerUsageRefreshIfStale();
      webviewView.onDidDispose(() => {
        activeWebviewViews.delete(webviewView);
      });
      webviewView.onDidChangeVisibility(() => {
        if (webviewView.visible) {
          webviewView.webview.html = renderSidebarHtml(loadStats());
          triggerUsageRefreshIfStale();
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
  if (usageWatchListener) {
    fs.unwatchFile(USAGE_PATH, usageWatchListener);
    usageWatchListener = null;
  }
  activeWebviewViews.clear();
  pendingNoticeKeys.clear();
  jsonCache.clear();
  invalidateDoctorCache();
  activeReportPanel = null;
  statusBarItem = null;
  lastSeenSavedTokens = null;
  updateInFlight = false;
  refreshUsageInFlight = false;
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
    triggerUsageRefreshIfStale();
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
        if (activeReportPanel === panel) activeReportPanel = null;
      });
    }
    panel.webview.html = renderWebviewHtml(loadStats());
  });
  const refreshDisposable = vscode.commands.registerCommand("contextGuard.refresh", () => {
    invalidateDoctorCache();
    updateStatusBar();
    triggerBackgroundUsageRefresh();
  });
  const updateDisposable = vscode.commands.registerCommand("contextGuard.update", () => runUpdate());
  context.subscriptions.push(cmdDisposable, refreshDisposable, updateDisposable);

  const initial = updateStatusBar();
  spawnUpdateCheckIfStale(initial.update, PLUGIN_ROOT, UPDATE_LOCK_PATH);
  triggerUsageRefreshIfStale();

  watchListener = () => {
    updateStatusBar({ fromWatch: true });
  };
  fs.watchFile(STATS_PATH, { interval: 2500 }, watchListener);
  updateWatchListener = () => {
    updateStatusBar();
  };
  fs.watchFile(UPDATE_PATH, { interval: 2500 }, updateWatchListener);
  usageWatchListener = () => {
    updateStatusBar();
  };
  fs.watchFile(USAGE_PATH, { interval: 2500 }, usageWatchListener);

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
  escapeMarkdownText,
  finiteNonNeg,
  parseIsoDayUtcMs,
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
  probeDoctor,
  summarizeV4Insights,
};
