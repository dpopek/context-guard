"""Tests for VS Code / Cursor / Antigravity extension view model, lifecycle, and installation."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from bin import install_harnesses

ROOT = Path(__file__).resolve().parent.parent
EXT_DIR = ROOT / "vscode-extension"


def test_view_model_normalization_semver_escaping_and_csp(tmp_path: Path) -> None:
    view_model_path = EXT_DIR / "view_model.js"
    assert view_model_path.is_file(), "vscode-extension/view_model.js must exist"

    script = r"""
const path = require("path");
const Module = require("module");
const origLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === "vscode") {
    return {
      MarkdownString: class {
        constructor() { this.value = ""; this.isTrusted = false; this.supportThemeIcons = false; }
        appendMarkdown(s) { this.value += s; }
      },
      ThemeColor: class { constructor(id) { this.id = id; } },
      StatusBarAlignment: { Right: 2 },
      ViewColumn: { One: 1 },
      ProgressLocation: { Notification: 15 },
      window: {},
      commands: {},
    };
  }
  return origLoad.apply(this, arguments);
};

const vm = require(path.resolve(process.argv[1], "view_model.js"));
const ext = require(path.resolve(process.argv[1], "extension.js"));

const layerKeys = vm.PROTECTION_LAYERS.map((l) => l.key);
const retryKeys = vm.PROTECTION_LAYERS.filter((l) => l.retryKey).map((l) => l.retryKey);
const norm = vm.normalizeStats({
  saved_tokens: 800,
  baseline_tokens: 1000,
  actual_tokens: 0,
  reduction_pct: 145.2,
  installed_at: "2026-11-08T10:00:00Z",
  updated_at: "2026-11-08T11:00:00Z",
  events: {
    outlines: 10,
    wide_followup_blocks: 4,
    wide_followup_retries: 1,
    multi_file_blocks: 3,
    multi_file_retries: 2,
    rereads_blocked: 5,
    ranges_trimmed: 6,
    cli_rewrites: 7,
    mcp_guards: 8,
    allowed_reads: 20,
    credit_reversals: 2,
  },
  by_harness: {
    antigravity: { hits: -3, baseline_tokens: 1000, saved_tokens: -50 },
    claude: { hits: 5, baseline_tokens: 500, saved_tokens: 900 },
  },
  last_event: {
    kind: "wide_followup_blocks",
    harness: "codex` [evil](command:contextGuard.update) `\nnext",
    saved_tokens: 300,
  },
});

const rawStats = {
  saved_tokens: 800,
  baseline_tokens: 1000,
  actual_tokens: 0,
  reduction_pct: 145.2,
  installed_at: "2026-11-08` [evil](command:contextGuard.update)",
  updated_at: "2026-11-08T11:00:00Z",
  events: norm.events,
  by_harness: {
    antigravity: { hits: -3, baseline_tokens: 1000, saved_tokens: -50 },
    claude: { hits: 5, baseline_tokens: 500, saved_tokens: 900 },
  },
  last_event: {
    kind: "wide_followup_blocks",
    harness: "codex` [evil](command:contextGuard.update) `\nnext",
    saved_tokens: 300,
  },
};

const sidebarHtml = ext.renderSidebarHtml(rawStats);
const webviewHtml = ext.renderWebviewHtml(rawStats);
const tooltipHtml = ext.buildTooltipMarkdown(rawStats).value;
const v4Stats = {
  saved_tokens: 400,
  baseline_tokens: 1000,
  reduction_pct: 40.0,
  events: { outlines: 5, ranges_trimmed: 12, cli_rewrites: 8, outline_pulls: 15, mcp_guards: 2, allowed_reads: 40 },
};
const v4Sidebar = ext.renderSidebarHtml(v4Stats);
const v4Webview = ext.renderWebviewHtml(v4Stats);
const v4Tooltip = ext.buildTooltipMarkdown(v4Stats).value;
const pulseWide = ext.formatStatusBarPulseText(rawStats, 300, "wide_followup_blocks");
const pulseBatch = ext.formatStatusBarPulseText(rawStats, 300, "multi_file_blocks");
const pulseRev = ext.formatStatusBarPulseText(rawStats, 300, "credit_reversals");

const badUpdate1 = { state: "update_available", local: "3.5.0", latest: "3.99.0:refs/heads/main" };
const badUpdate2 = { state: "update_available", local: "3.5.0` [pwn](command:contextGuard.update) `", latest: "3.99.0" };
const badInstall = { state: "install_pending", local: "../evil", installed: "3.5.0`x`" };
const goodUpdate = { state: "update_available", local: "3.5.0", latest: "3.99.0" };

console.log(JSON.stringify({
  layerKeys,
  retryKeys,
  actualTokens: norm.actualTokens,
  reductionPct: norm.reductionPct,
  agHarness: norm.harnesses.antigravity,
  claudeHarness: norm.harnesses.claude,
  sidebarHasCsp: sidebarHtml.includes("http-equiv=\"Content-Security-Policy\""),
  webviewHasCsp: webviewHtml.includes("http-equiv=\"Content-Security-Policy\""),
  sidebarHasZeroActual: sidebarHtml.includes(">0 tok<"),
  webviewHasZeroActual: webviewHtml.includes("&rarr; 0<"),
  webviewClampedPct: webviewHtml.includes("-100.0%"),
  sidebarNoDoubleMinus: !/--\d/.test(sidebarHtml) && !sidebarHtml.includes("width:-"),
  webviewNoDoubleMinus: !/--\d/.test(webviewHtml),
  sidebarHasWide: sidebarHtml.includes("Wide Follow-Up") && sidebarHtml.includes("Multi-File Batch") && sidebarHtml.includes("Credit"),
  webviewHasWide: webviewHtml.includes("wide_followup_blocks") && webviewHtml.includes("multi_file_blocks") && webviewHtml.includes("credit_reversals"),
  tooltipHasOutlinePulls: tooltipHtml.includes("Voluntary Outlines (cg-outline)"),
  v4HasOutlinePulls: v4Sidebar.includes("Voluntary Outlines (cg-outline)") && v4Webview.includes("Voluntary Outlines (cg-outline)") && v4Tooltip.includes("Voluntary Outlines (cg-outline)"),
  v4HidesLegacy: !/Wide Follow-Up|Multi-File Batch|Duplicate Re-Reads|Credits Taken Back/.test(v4Sidebar + v4Webview + v4Tooltip),
  pulseWide,
  pulseBatch,
  pulseRev,
  semverGood: vm.isValidSemver("3.99.0") && vm.isValidSemver("9.99.0-rc.1"),
  semverBad: !vm.isValidSemver("3.99.0:refs/heads/main") && !vm.isValidSemver("../evil") && !vm.isValidSemver("v3.99.0"),
  badSteps: ext.updateSteps("update_available", "/tmp/cg", "3.99.0:refs/heads/main"),
  badBadge1: ext.updateBadge(badUpdate1),
  badBadge2: ext.updateBadge(badUpdate2),
  badNotice1: ext.updateNotice(badUpdate1),
  badNoticeInstall: ext.updateNotice(badInstall),
  goodStepsLen: ext.updateSteps("update_available", "/tmp/cg", "3.99.0").length,
  goodBadge: ext.updateBadge(goodUpdate),
  escapedCodeSpan: vm.escapeMarkdownCodeSpan("a`b\nc\rd<e>"),
}));
"""
    proc = subprocess.run(
        ["node", "-e", script, str(EXT_DIR)],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout.strip())
    assert data["layerKeys"] == [
        "outlines",
        "wide_followup_blocks",
        "multi_file_blocks",
        "rereads_blocked",
        "ranges_trimmed",
        "cli_rewrites",
        "outline_pulls",
        "mcp_guards",
        "allowed_reads",
        "credit_reversals",
    ]
    assert data["tooltipHasOutlinePulls"] is True
    assert data["v4HasOutlinePulls"] is True
    assert data["v4HidesLegacy"] is True
    assert data["retryKeys"] == ["wide_followup_retries", "multi_file_retries"]
    assert data["actualTokens"] == 0
    assert data["reductionPct"] == 100.0
    assert data["agHarness"] == {
        "hits": 0,
        "baselineTokens": 1000,
        "savedTokens": 0,
        "reductionPct": 0.0,
    }
    assert data["claudeHarness"] == {
        "hits": 5,
        "baselineTokens": 500,
        "savedTokens": 900,
        "reductionPct": 100.0,
    }
    assert data["sidebarHasCsp"] is True
    assert data["webviewHasCsp"] is True
    assert data["sidebarHasZeroActual"] is True
    assert data["webviewHasZeroActual"] is True
    assert data["webviewClampedPct"] is True
    assert data["sidebarNoDoubleMinus"] is True
    assert data["webviewNoDoubleMinus"] is True
    assert data["sidebarHasWide"] is True
    assert data["webviewHasWide"] is True
    assert "(Wide)" in data["pulseWide"]
    assert "(Batch)" in data["pulseBatch"]
    assert "(Reversal)" in data["pulseRev"]
    assert data["semverGood"] is True
    assert data["semverBad"] is True
    assert data["badSteps"] == []
    assert data["badBadge1"] == {"prefix": "", "tooltipLine": ""}
    assert data["badBadge2"] == {"prefix": "", "tooltipLine": ""}
    assert data["badNotice1"] is None
    assert data["badNoticeInstall"] is None
    assert data["goodStepsLen"] == 3
    assert data["goodBadge"]["prefix"] == "$(cloud-download) "
    assert "`" not in data["escapedCodeSpan"]
    assert "\n" not in data["escapedCodeSpan"]
    assert "\r" not in data["escapedCodeSpan"]

    synthetic_plugin = tmp_path / "synthetic_plugin"
    (synthetic_plugin / "vscode-extension").mkdir(parents=True)
    (synthetic_plugin / "vscode-extension" / "package.json").write_text(
        (EXT_DIR / "package.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (synthetic_plugin / "vscode-extension" / "extension.js").write_text(
        (EXT_DIR / "extension.js").read_text(encoding="utf-8"), encoding="utf-8"
    )
    ext_install_dir = tmp_path / "extensions"
    ext_install_dir.mkdir(parents=True)
    res = install_harnesses.install_ide_extension(synthetic_plugin, ext_install_dir, dry_run=False)
    assert res == "updated"
    installed_dirs = list(ext_install_dir.glob("advox.context-guard-statusbar-*"))
    assert len(installed_dirs) == 1
    assert (installed_dirs[0] / "extension.js").is_file()
    assert (installed_dirs[0] / "view_model.js").is_file()


def test_extension_lifecycle_pulse_race_notify_latch_and_singleton_report_panel(
    tmp_path: Path,
) -> None:
    plugin_dir = tmp_path / "cg_plugin"
    telemetry_dir = plugin_dir / "telemetry"
    telemetry_dir.mkdir(parents=True)
    stats_path = telemetry_dir / "stats.json"

    stats_path.write_text(
        json.dumps({"saved_tokens": 1000, "baseline_tokens": 2000, "reduction_pct": 50.0}),
        encoding="utf-8",
    )

    script = r"""
const fs = require("fs");
const path = require("path");
const childProcess = require("child_process");
const Module = require("module");

const pluginDir = process.argv[1];
const extDir = process.argv[2];
process.env.CONTEXT_GUARD_HOME = pluginDir;

let nextToastChoice = undefined;
let createdPanels = [];
let registeredCommands = {};
let statusBarCreated = null;
let spawnedCount = 0;
let execShouldFail = false;

const flushMicrotasks = async () => {
  for (let i = 0; i < 6; i++) {
    await new Promise((r) => setImmediate(r));
  }
};

childProcess.spawn = function() {
  spawnedCount += 1;
  return { on: () => {}, unref: () => {} };
};
childProcess.execFile = function(cmd, args, opts, cb) {
  if (execShouldFail) {
    cb(new Error("simulated git failure"), "", "git fetch failed");
  } else {
    cb(null, "ok", "");
  }
};

const origLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === "vscode") {
    return {
      MarkdownString: class {
        constructor() { this.value = ""; this.isTrusted = false; this.supportThemeIcons = false; }
        appendMarkdown(s) { this.value += s; }
      },
      ThemeColor: class { constructor(id) { this.id = id; } },
      StatusBarAlignment: { Right: 2 },
      ViewColumn: { One: 1 },
      ProgressLocation: { Notification: 15 },
      window: {
        createStatusBarItem: () => {
          statusBarCreated = {
            text: "",
            tooltip: null,
            color: undefined,
            shown: false,
            show() { this.shown = true; },
          };
          return statusBarCreated;
        },
        registerWebviewViewProvider: () => ({ dispose: () => {} }),
        createWebviewPanel: (viewType, title, col, opts) => {
          const panel = {
            viewType,
            title,
            revealed: 0,
            disposeHandler: null,
            webview: { html: "", options: opts },
            reveal() { this.revealed += 1; },
            onDidDispose(fn) { this.disposeHandler = fn; },
          };
          createdPanels.push(panel);
          return panel;
        },
        showInformationMessage: (msg, btn) => {
          if (msg.includes("Reload the window")) {
            return Promise.resolve(undefined);
          }
          return Promise.resolve(nextToastChoice);
        },
        showErrorMessage: () => Promise.resolve(undefined),
        withProgress: async (_opts, task) => await task(),
      },
      commands: {
        registerCommand: (name, fn) => {
          registeredCommands[name] = fn;
          return { dispose: () => {} };
        },
        executeCommand: () => {},
      },
    };
  }
  return origLoad.apply(this, arguments);
};

const ext = require(path.resolve(extDir, "extension.js"));

(async () => {
  const globalStore = {};
  const ctx = {
    subscriptions: [],
    globalState: {
      get: (k) => globalStore[k],
      update: async (k, v) => { globalStore[k] = v; },
    },
  };

  const lockPath = path.join(pluginDir, "telemetry", "update.lock");
  fs.writeFileSync(lockPath, "");
  ext.activate(ctx);
  const spawnedDuringFreshLock = spawnedCount;

  const statsPath = path.join(pluginDir, "telemetry", "stats.json");
  const updatePath = path.join(pluginDir, "telemetry", "update.json");
  fs.writeFileSync(statsPath, JSON.stringify({
    saved_tokens: 1500,
    baseline_tokens: 2500,
    reduction_pct: 60.0,
    last_event: { kind: "outlines", harness: "antigravity", saved_tokens: 500 },
  }));
  ext.updateStatusBar({ fromWatch: true });
  const textDuringPulseBeforeUpdate = statusBarCreated.text;

  fs.writeFileSync(updatePath, JSON.stringify({
    state: "update_available",
    local: "3.5.0",
    latest: "3.99.0",
    checked_at: new Date().toISOString(),
  }));
  nextToastChoice = undefined;
  ext.updateStatusBar();
  const textDuringPulseAfterUpdate = statusBarCreated.text;

  await flushMicrotasks();
  const latchedAfterDismiss = Boolean(globalStore["contextGuard.notified.update.3.99.0"]);

  execShouldFail = true;
  nextToastChoice = "Update";
  ext.updateStatusBar();
  await flushMicrotasks();
  const latchedAfterFailedUpdate = Boolean(globalStore["contextGuard.notified.update.3.99.0"]);

  execShouldFail = false;
  nextToastChoice = "Update";
  ext.updateStatusBar();
  await flushMicrotasks();
  const latchedAfterSuccess = Boolean(globalStore["contextGuard.notified.update.3.99.0"]);

  registeredCommands["contextGuard.showReport"]();
  registeredCommands["contextGuard.showReport"]();
  const panelCount = createdPanels.length;
  const panelRevealed = createdPanels[0] ? createdPanels[0].revealed : 0;

  fs.writeFileSync(statsPath, JSON.stringify({
    saved_tokens: 9000,
    baseline_tokens: 10000,
    reduction_pct: 90.0,
  }));
  ext.updateStatusBar();
  const panelRefreshedHtml = createdPanels[0] ? createdPanels[0].webview.html : "";

  ext.deactivate();

  console.log(JSON.stringify({
    spawnedDuringFreshLock,
    recentLockCheck: ext.isUpdateAttemptRecent(lockPath, Date.now()),
    textDuringPulseBeforeUpdate,
    textDuringPulseAfterUpdate,
    latchedAfterDismiss,
    latchedAfterFailedUpdate,
    latchedAfterSuccess,
    panelCount,
    panelRevealed,
    panelRefreshed: panelRefreshedHtml.includes("-9,000") && panelRefreshedHtml.includes("-90.0%"),
  }));
})();
"""
    proc = subprocess.run(
        ["node", "-e", script, str(plugin_dir), str(EXT_DIR)],
        capture_output=True,
        text=True,
        check=True,
    )
    out = json.loads(proc.stdout.strip())
    assert out["spawnedDuringFreshLock"] == 0
    assert out["recentLockCheck"] is True
    assert "$(zap)" in out["textDuringPulseBeforeUpdate"]
    assert out["textDuringPulseAfterUpdate"].startswith("$(cloud-download) $(zap)")
    assert out["latchedAfterDismiss"] is False
    assert out["latchedAfterFailedUpdate"] is False
    assert out["latchedAfterSuccess"] is True
    assert out["panelCount"] == 1
    assert out["panelRevealed"] == 1
    assert out["panelRefreshed"] is True


def test_install_ide_extension_writes_plugin_root_json_and_extension_js_resolves_it(
    tmp_path: Path,
) -> None:
    custom_plugin_root = tmp_path / "custom-plugin-root"
    (custom_plugin_root / "vscode-extension").mkdir(parents=True)
    (custom_plugin_root / "hooks").mkdir(parents=True)
    ext_version = json.loads((EXT_DIR / "package.json").read_text(encoding="utf-8"))["version"]
    (custom_plugin_root / "plugin.json").write_text(
        json.dumps({"version": ext_version}), encoding="utf-8"
    )
    (custom_plugin_root / "hooks" / "pre_tool_use.py").write_text("# stub\n", encoding="utf-8")
    shutil.copy2(
        EXT_DIR / "package.json",
        custom_plugin_root / "vscode-extension" / "package.json",
    )
    shutil.copy2(
        EXT_DIR / "extension.js",
        custom_plugin_root / "vscode-extension" / "extension.js",
    )

    extensions_dir = tmp_path / "ide-extensions"
    extensions_dir.mkdir()
    (extensions_dir / "extensions.json").write_text("[]\n", encoding="utf-8")

    dry_status = install_harnesses.install_ide_extension(
        custom_plugin_root, extensions_dir, dry_run=True
    )
    assert dry_status == "updated"
    assert list(extensions_dir.glob("advox.context-guard-statusbar-*")) == []

    real_status = install_harnesses.install_ide_extension(
        custom_plugin_root, extensions_dir, dry_run=False
    )
    assert real_status == "updated"
    installed_ext_dir = extensions_dir / f"advox.context-guard-statusbar-{ext_version}"
    breadcrumb = installed_ext_dir / "plugin_root.json"
    assert breadcrumb.is_file()
    assert json.loads(breadcrumb.read_text(encoding="utf-8")) == {
        "plugin_root": str(custom_plugin_root.resolve())
    }

    corrupt_ext_dir = tmp_path / "corrupt-container" / "ext"
    corrupt_ext_dir.mkdir(parents=True)
    (corrupt_ext_dir / "plugin_root.json").write_text("{malformed-json", encoding="utf-8")

    fake_home = tmp_path / "fake-ide-home"
    node_script = (
        "const Module = require('module');"
        "const orig = Module._load;"
        "Module._load = (req, parent, isMain) => req === 'vscode' ? {} : orig(req, parent, isMain);"
        f"const ext = require({json.dumps(str(installed_ext_dir / 'extension.js'))});"
        "console.log(JSON.stringify({"
        "  exported: typeof ext.resolvePluginRoot,"
        f"  fromBreadcrumb: ext.resolvePluginRoot({{}}, {json.dumps(str(installed_ext_dir))}, {json.dumps(str(fake_home))}),"
        f"  fromEnvOverride: ext.resolvePluginRoot({{CONTEXT_GUARD_HOME: '~/override-cg'}}, {json.dumps(str(installed_ext_dir))}, {json.dumps(str(fake_home))}),"
        f"  fromDevCheckout: ext.resolvePluginRoot({{}}, {json.dumps(str(EXT_DIR))}, {json.dumps(str(fake_home))}),"
        f"  fromCorruptFallback: ext.resolvePluginRoot({{}}, {json.dumps(str(corrupt_ext_dir))}, {json.dumps(str(fake_home))})"
        "}));"
    )
    proc = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, check=True)
    resolved = json.loads(proc.stdout.strip())
    assert resolved["exported"] == "function"
    assert resolved["fromBreadcrumb"] == str(custom_plugin_root.resolve())
    assert resolved["fromEnvOverride"] == str((fake_home / "override-cg").resolve())
    assert resolved["fromDevCheckout"] == str(ROOT.resolve())
    assert resolved["fromCorruptFallback"] == str(
        fake_home / ".gemini" / "config" / "plugins" / "context-guard"
    )


def test_sync_codex_config_toml_section_at_line_zero_and_brackets_in_values(tmp_path: Path) -> None:
    codex_hooks = tmp_path / "hooks.json"
    codex_config = tmp_path / "config.toml"
    state_header = f'[hooks.state."{codex_hooks}:pre_tool_use:0:0"]'
    codex_config.write_text(
        f'[mcp_servers.demo]\nargs = ["--flag"]\n\n{state_header}\ntrusted_hash = "sha256:old"\nextra_arr = ["[a]", "[b]"]\n\n[other_table]\nkey = "val"\n',
        encoding="utf-8",
    )
    hooks_data = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "^(Bash)$",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "/usr/bin/python3 /custom/hooks/pre_tool_use.py",
                        }
                    ],
                }
            ]
        }
    }
    res = install_harnesses.sync_codex_config_toml(
        codex_hooks_path=codex_hooks,
        codex_config_path=codex_config,
        hooks_data=hooks_data,
        ensure_compact_limit=True,
        dry_run=False,
    )
    assert res == "updated"
    text = codex_config.read_text(encoding="utf-8")
    assert text.index("model_auto_compact_token_limit = 250000") < text.index("[mcp_servers.demo]")
    assert 'extra_arr = ["[a]", "[b]"]' not in text
    assert "[other_table]" in text


def test_custom_context_guard_home_dir_status_idempotency_and_corrupt_json_isolation(
    tmp_path: Path,
) -> None:
    from bin import harness_status

    custom_root = tmp_path / "my-custom-cg-folder"
    (custom_root / "hooks").mkdir(parents=True)
    (custom_root / "bin").mkdir(parents=True)
    (custom_root / "plugin.json").write_text('{"version": "3.5.0"}\n', encoding="utf-8")

    claude_cfg = tmp_path / "claude_settings.json"
    cursor_cfg = tmp_path / "cursor_hooks.json"
    codex_cfg = tmp_path / "codex_hooks.json"
    codex_toml = tmp_path / "codex_config.toml"
    claude_cfg.write_text("{}\n", encoding="utf-8")
    cursor_cfg.write_text("{}\n", encoding="utf-8")
    codex_cfg.write_text("{}\n", encoding="utf-8")
    codex_toml.write_text("", encoding="utf-8")

    install_harnesses.install_all(
        plugin_root=custom_root,
        claude_settings_path=claude_cfg,
        cursor_hooks_path=cursor_cfg,
        codex_hooks_path=codex_cfg,
        codex_config_path=codex_toml,
        cursor_extensions_dir=None,
        antigravity_extensions_dir=None,
        antigravity_ide_extensions_dir=None,
    )
    status = harness_status.check_status(claude_cfg, cursor_cfg, codex_cfg)
    assert status == {"claude": True, "cursor": True, "codex": True}

    install_harnesses.install_all(
        plugin_root=custom_root,
        claude_settings_path=claude_cfg,
        cursor_hooks_path=cursor_cfg,
        codex_hooks_path=codex_cfg,
        codex_config_path=codex_toml,
        cursor_extensions_dir=None,
        antigravity_extensions_dir=None,
        antigravity_ide_extensions_dir=None,
    )
    claude_data = json.loads(claude_cfg.read_text(encoding="utf-8"))
    cursor_data = json.loads(cursor_cfg.read_text(encoding="utf-8"))
    assert len(claude_data["hooks"]["PreToolUse"]) == 1
    assert len(cursor_data["hooks"]["preToolUse"]) == 1

    claude_cfg.write_text("{corrupt json", encoding="utf-8")
    cursor_cfg.write_text("{}\n", encoding="utf-8")
    res = install_harnesses.install_all(
        plugin_root=custom_root,
        claude_settings_path=claude_cfg,
        cursor_hooks_path=cursor_cfg,
        codex_hooks_path=codex_cfg,
        codex_config_path=codex_toml,
        cursor_extensions_dir=None,
        antigravity_extensions_dir=None,
        antigravity_ide_extensions_dir=None,
    )
    assert res["claude"].startswith("error")
    assert res["cursor"] == "updated"


def test_windows_python_resolution_and_codex_toml_backslash_escaping(tmp_path: Path) -> None:
    assert (
        install_harnesses.resolve_python_command(
            os_name="nt", which_fn=lambda cmd: "C:\\Python312\\python.exe" if cmd == "python" else None
        )
        == "python"
    )
    assert (
        install_harnesses.resolve_python_command(
            os_name="nt", which_fn=lambda cmd: "C:\\Windows\\py.exe" if cmd == "py" else None
        )
        == "py -3"
    )
    assert (
        install_harnesses.resolve_python_command(
            os_name="posix", which_fn=lambda cmd: "/usr/bin/python" if cmd == "python" else None
        )
        == "python"
    )
    assert (
        install_harnesses.format_hook_script_path(Path("C:/Users/Jan Kowalski/hooks/pre_tool_use.py"))
        == '"C:/Users/Jan Kowalski/hooks/pre_tool_use.py"'
    )

    codex_config = tmp_path / "config.toml"
    win_hooks_str = r"C:\Users\Alice\.codex\hooks.json"
    codex_config.write_text(
        f'[hooks.state."{win_hooks_str}:pre_tool_use:0:0"]\ntrusted_hash = "sha256:stale"\n',
        encoding="utf-8",
    )
    hooks_data = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "^(Bash)$",
                    "hooks": [{"type": "command", "command": "python C:/cg/hooks/pre_tool_use.py"}],
                }
            ]
        }
    }
    status = install_harnesses.sync_codex_config_toml(
        codex_hooks_path=Path(win_hooks_str),
        codex_config_path=codex_config,
        hooks_data=hooks_data,
        ensure_compact_limit=True,
        dry_run=False,
    )
    assert status == "updated"
    rendered = codex_config.read_text(encoding="utf-8")
    assert "sha256:stale" not in rendered
    assert r'[hooks.state."C:\\Users\\Alice\\.codex\\hooks.json:pre_tool_use:0:0"]' in rendered


def test_vscode_extension_python_candidates_and_windows_fallback(tmp_path: Path) -> None:
    ext_js = ROOT / "vscode-extension" / "extension.js"
    node_script = tmp_path / "test_win_ext.js"
    node_script.write_text(
        f"""
const assert = require("assert");
const Module = require("module");
const origLoad = Module._load;
Module._load = function(request, parent, isMain) {{
  if (request === "vscode") {{
    return {{
      window: {{
        createStatusBarItem: () => ({{ show() {{}} }}),
        showInformationMessage: async () => undefined,
        showErrorMessage: async () => undefined,
        withProgress: async (_o, fn) => fn(),
      }},
      commands: {{ registerCommand: () => ({{ dispose() {{}} }}), executeCommand: () => undefined }},
      StatusBarAlignment: {{ Right: 2 }},
      ProgressLocation: {{ Notification: 15 }},
      ViewColumn: {{ One: 1 }},
      ThemeColor: function(id) {{ this.id = id; }},
    }};
  }}
  return origLoad(request, parent, isMain);
}};
const ext = require({json.dumps(str(ext_js))});
assert.strictEqual(typeof ext.pythonCandidates, "function");
const winCands = ext.pythonCandidates("win32", {{}});
assert.deepStrictEqual(winCands[0], ["python", []]);
assert.deepStrictEqual(winCands[1], ["py", ["-3"]]);
const customCands = ext.pythonCandidates("linux", {{ CONTEXT_GUARD_PYTHON: "/opt/py/bin/python3" }});
assert.deepStrictEqual(customCands[0], ["/opt/py/bin/python3", []]);
console.log("WIN_EXT_OK");
""",
        encoding="utf-8",
    )
    proc = subprocess.run(["node", str(node_script)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert "WIN_EXT_OK" in proc.stdout

