"""Tests for v4.x IDE extension insights, doctor probe, and modular HTML/Markdown renderers."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXT_DIR = ROOT / "vscode-extension"

_VSCODE_MOCK = r"""
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
"""


def _run_node(script_body: str, *args: str) -> dict:
    proc = subprocess.run(
        ["node", "-e", _VSCODE_MOCK + "\n" + script_body, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return json.loads(proc.stdout.strip())


def test_summarize_v4_insights_cache_preamble_verdict_and_doctor() -> None:
    stats = {
        "saved_tokens": 50_000,
        "baseline_tokens": 100_000,
        "reduction_pct": 50.0,
        "by_day": {"2026-11-10": {"saved_bytes": 200_000}, "2026-11-13": {"saved_bytes": 100_000}},
        "last_event": {"kind": "outline_pulls", "harness": "antigravity", "saved_tokens": 1200},
    }
    token_usage = {
        "totals": {
            "claude|opus": {"input": 100, "cache_read": 900, "cache_write": 0, "events": 10, "total_only": 0},
            "codex|gpt": {"input": 500, "cache_read": 0, "cache_write": 0, "events": 2, "total_only": 2},
            "antigravity|flash": {"input": 100, "cache_read": 900, "cache_write": 0, "events": 5, "total_only": 0},
        },
        "by_day": {
            "2026-11-10": {"claude": {"input": 100_000, "cache_read": 800_000, "cache_write": 0}},
            "2026-11-13": {"antigravity": {"input": 100_000, "cache_read": 9_000_000, "cache_write": 0}},
        },
        "preamble": {
            "antigravity": [60_000] * 12 + [17_500] * 10,
            "claude": [30_500, 30_200, 82_000],
        },
        "preamble_parts": [
            {"measured": 30_500, "components": {"skills": {"superpowers": 2000}}},
            {"measured": 30_200, "components": {"skills": {"superpowers": 2000}}},
            {"measured": 82_000, "components": {"deferred_tools": {"mcp:ccd_session": 200}}},
        ],
    }
    outcomes_v3 = {
        "schema_version": 3,
        "by_key": {"claude|opus|outline": {"total": 2, "repeats": 0}},
    }
    outcomes_legacy = {
        "schema_version": 2,
        "by_key": {"claude|opus|outline": {"total": 99}},
    }
    script = r"""
const path = require("path");
const vm = require(path.resolve(process.argv[1], "view_model.js"));
const stats = JSON.parse(process.argv[2]);
const usage = JSON.parse(process.argv[3]);
const outV3 = JSON.parse(process.argv[4]);
const outLegacy = JSON.parse(process.argv[5]);
const docOk = { ok: true, registeredCount: 4, totalHarnesses: 4 };
const docFail = { ok: false, registeredCount: 1, totalHarnesses: 4 };
console.log(JSON.stringify({
  full: vm.summarizeV4Insights(stats, usage, outV3, docOk),
  legacy: vm.summarizeV4Insights(stats, usage, outLegacy, docFail),
  empty: vm.summarizeV4Insights(null, null, null, null),
}));
"""
    res = _run_node(
        script,
        str(EXT_DIR),
        json.dumps(stats),
        json.dumps(token_usage),
        json.dumps(outcomes_v3),
        json.dumps(outcomes_legacy),
    )
    full = res["full"]
    assert full["cacheHitLabel"] == "90.0%"
    assert full["preambleLast"]["harness"] == "antigravity"
    assert full["preambleLast"]["last"] == 17_500
    assert full["preambleLast"]["recentMedian"] == 17_500
    assert full["preambleByHarness"]["claude (cli)"]["recentMedian"] == 30_350
    assert full["preambleByHarness"]["claude (desktop)"]["last"] == 82_000
    assert full["sunsetVerdict"]["status"] == "collecting_30d_window"
    assert full["sunsetVerdict"]["windowDays"] == 4
    assert full["sunsetVerdict"]["netSaved"] < 75_000
    assert full["doctor"]["statusLabel"] == "OK (4/4)"

    legacy = res["legacy"]
    assert legacy["sunsetVerdict"]["netSaved"] == 75_000
    assert legacy["doctor"]["statusLabel"] == "FAIL"

    empty = res["empty"]
    assert empty["cacheHitLabel"] == "n/a"
    assert empty["preambleLast"] is None
    assert empty["doctor"]["statusLabel"] == "n/a"


def test_probe_doctor_reads_configs_and_fails_open(tmp_path: Path) -> None:
    plugin_root = tmp_path / "cg"
    home_dir = tmp_path / "home"
    (plugin_root / "telemetry").mkdir(parents=True)
    (plugin_root / "plugin.json").write_text('{"version":"3.99.0"}\n', encoding="utf-8")
    (plugin_root / "hooks.json").write_text("{}\n", encoding="utf-8")
    (home_dir / ".claude").mkdir(parents=True)
    (home_dir / ".cursor").mkdir(parents=True)
    (home_dir / ".codex").mkdir(parents=True)
    (home_dir / ".claude" / "settings.json").write_text(
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": "python3 /opt/cg/hooks/pre_tool_use.py"}]}]}}),
        encoding="utf-8",
    )
    (home_dir / ".cursor" / "hooks.json").write_text("{not-json", encoding="utf-8")
    (home_dir / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {"note": "context-guard"}}), encoding="utf-8")

    missing_root = tmp_path / "absent"
    script = r"""
const path = require("path");
const updater = require(path.resolve(process.argv[1], "updater.js"));
console.log(JSON.stringify({
  healthy: updater.probeDoctor(process.argv[2], process.argv[3]),
  missing: updater.probeDoctor(process.argv[4], process.argv[3]),
}));
"""
    res = _run_node(script, str(EXT_DIR), str(plugin_root), str(home_dir), str(missing_root))
    healthy = res["healthy"]
    assert healthy["ok"] is True
    assert healthy["harnesses"] == {"antigravity": True, "claude": True, "cursor": False, "codex": False}
    assert healthy["registeredCount"] == 2
    assert healthy["totalHarnesses"] == 4

    missing = res["missing"]
    assert missing["ok"] is False
    assert missing["harnesses"]["antigravity"] is False

    if sys.platform != "win32":
        ro_plugin = tmp_path / "ro-cg"
        (ro_plugin / "telemetry").mkdir(parents=True)
        (ro_plugin / "plugin.json").write_text('{"version":"3.99.0"}\n', encoding="utf-8")
        (ro_plugin / "hooks.json").write_text("{}\n", encoding="utf-8")
        os.chmod(ro_plugin / "telemetry", 0o555)
        try:
            ro_res = _run_node(
                "const u=require(require('path').resolve(process.argv[1],'updater.js')); console.log(JSON.stringify(u.probeDoctor(process.argv[2], process.argv[3])));",
                str(EXT_DIR),
                str(ro_plugin),
                str(home_dir),
            )
            assert ro_res["telemetryWritable"] is False
            assert ro_res["ok"] is False
        finally:
            os.chmod(ro_plugin / "telemetry", 0o755)


def test_renderers_surface_v4_insights_with_csp_and_escaping() -> None:
    stats = {
        "saved_tokens": 12_500,
        "baseline_tokens": 25_000,
        "reduction_pct": 50.0,
        "events": {"outlines": 4, "outline_pulls": 7, "cli_rewrites": 3},
        "last_event": {"kind": "outline_pulls", "harness": "claude<script>", "saved_tokens": 900},
    }
    insights = {
        "cacheHitPct": 93.4,
        "cacheHitLabel": "93.4%",
        "preambleLast": {"harness": "claude<script>", "last": 19_200, "recentMedian": 18_800, "sessions": 12},
        "preambleByHarness": {
            "antigravity": {"sessions": 12, "median": 31_000, "recentMedian": 18_800, "last": 19_200},
            "claude (cli)": {"sessions": "bad", "median": 30_100, "recentMedian": 29_900, "last": 29_800},
        },
        "sunsetVerdict": {
            "windowDays": 31,
            "targetDays": 30,
            "netSaved": 420_000,
            "netSharePct": 1.25,
            "denials": 2,
            "denialTokens": 12_000,
            "status": "net_positive",
        },
        "doctor": {"ok": True, "registeredCount": 4, "totalHarnesses": 4, "statusLabel": "OK (4/4)"},
    }
    script = r"""
const path = require("path");
const ext = require(path.resolve(process.argv[1], "extension.js"));
const vscode = require("vscode");
const stats = JSON.parse(process.argv[2]);
const insights = JSON.parse(process.argv[3]);
const renderers = require(path.resolve(process.argv[1], "renderers.js"));
const md = renderers.buildTooltipMarkdown(vscode.MarkdownString, "3.99.0", stats, "", insights).value;
const sidebar = renderers.renderSidebarHtml("3.99.0", stats, insights);
const webview = renderers.renderWebviewHtml("3.99.0", stats, insights);
console.log(JSON.stringify({ md, sidebar, webview, reexported: typeof ext.renderSidebarHtml === "function" }));
"""
    res = _run_node(script, str(EXT_DIR), json.dumps(stats), json.dumps(insights))
    assert res["reexported"] is True
    for rendered in (res["md"], res["sidebar"], res["webview"]):
        assert "93.4%" in rendered
        assert "19.2k" in rendered or "19,200" in rendered
        assert "OK (4/4)" in rendered
        assert "net_positive" in rendered
        assert "<script>" not in rendered
    assert "Content-Security-Policy" in res["sidebar"]
    assert "Content-Security-Policy" in res["webview"]
    assert "antigravity" in res["webview"]
    assert "claude (cli)" in res["webview"]
    assert "NaN" not in res["webview"]


def test_v4_insights_codex_cohorts_sunset_parity_and_refresh_runtime(tmp_path: Path) -> None:
    stats_codex = {
        "saved_tokens": 50_000,
        "by_day": {"2026-10-01": {"saved_bytes": 4_000}, "2026-11-05": {"saved_bytes": 0}},
        "last_event": {"kind": "outline_pulls", "harness": "codex", "saved_tokens": 200},
    }
    usage_codex = {
        "totals": {"codex|gpt": {"input": 100_000, "cache_read": 900_000, "cache_write": 0, "events": 10, "total_only": 0}},
        "by_day": {
            "2026-10-01": {"codex": {"input": 100_000, "cache_read": 400_000, "cache_write": 0}},
            "2026-11-05": {"codex": {"input": 100_000, "cache_read": 400_000, "cache_write": 0}},
        },
        "preamble_parts": [
            {"measured": 30_500, "components": {"skills": {"superpowers": 2000}}},
            {"measured": 82_000, "components": {"deferred_tools": {"mcp:ccd_session": 200}}},
        ],
        "codex_preamble_parts": [
            {"measured": 22_000, "cohort": "codex (cli)", "components": {"system_prompt": {"core": 5_000}}},
            {"measured": 41_000, "cohort": "codex (desktop)", "components": {"deferred_tools": {"mcp:app": 10_000}}},
        ],
    }
    stats_claude = {
        "saved_tokens": 10_000,
        "by_day": {"2026-11-12": {"saved_bytes": 4_000}, "2026-11-13": {"saved_bytes": 4_000}},
        "last_event": {"kind": "outline_pulls", "harness": "claude", "saved_tokens": 100},
    }
    usage_backfill = {
        **usage_codex,
        "started_at": "2026-09-01T00:00:00Z",
        "by_day": {
            "2026-09-01": {"claude": {"input": 500_000, "cache_read": 0, "cache_write": 0}},
            "2026-11-12": {"claude": {"input": 100_000, "cache_read": 400_000, "cache_write": 0}},
            "2026-11-13": {"claude": {"input": 100_000, "cache_read": 400_000, "cache_write": 0}},
        },
    }
    stats_disjoint = {"saved_tokens": 5_000, "by_day": {"2026-11-14": {"saved_bytes": 4_000}}}
    usage_disjoint = {
        "by_day": {"2026-10-01": {"claude": {"input": 100_000, "cache_read": 0, "cache_write": 0}}},
    }
    outcomes_repeats = {
        "schema_version": 3,
        "by_key": {"codex|gpt|outline": {"total": 2, "repeats": 3}},
    }

    script = r"""
const path = require("path");
const vm = require(path.resolve(process.argv[1], "view_model.js"));
const [sCodex, uCodex, sClaude, uBackfill, sDisjoint, uDisjoint, outRep] = process.argv.slice(2).map((s) => JSON.parse(s));
console.log(JSON.stringify({
  codexLowShare: vm.summarizeV4Insights(sCodex, uCodex, null, null),
  backfillAndClaude: vm.summarizeV4Insights(sClaude, uBackfill, outRep, null),
  disjoint: vm.summarizeV4Insights(sDisjoint, uDisjoint, null, null),
}));
"""
    res = _run_node(
        script,
        str(EXT_DIR),
        json.dumps(stats_codex),
        json.dumps(usage_codex),
        json.dumps(stats_claude),
        json.dumps(usage_backfill),
        json.dumps(stats_disjoint),
        json.dumps(usage_disjoint),
        json.dumps(outcomes_repeats),
    )
    codex_low = res["codexLowShare"]
    assert codex_low["preambleByHarness"]["codex (cli)"]["last"] == 22_000
    assert codex_low["preambleByHarness"]["codex (desktop)"]["last"] == 41_000
    assert codex_low["preambleLast"]["harness"] == "codex (desktop)"
    assert codex_low["preambleLast"]["last"] == 41_000
    assert codex_low["sunsetVerdict"]["windowDays"] == 36
    assert 0 < codex_low["sunsetVerdict"]["netSharePct"] < 0.5
    assert codex_low["sunsetVerdict"]["status"] == "sunset_candidate"

    backfill = res["backfillAndClaude"]
    assert backfill["preambleLast"]["harness"] == "claude (desktop)"
    assert backfill["preambleLast"]["last"] == 82_000
    assert backfill["sunsetVerdict"]["windowDays"] == 2
    assert backfill["sunsetVerdict"]["status"] == "collecting_30d_window"
    assert backfill["sunsetVerdict"]["denials"] == 5

    disjoint = res["disjoint"]
    assert disjoint["sunsetVerdict"]["windowDays"] == 0
    assert disjoint["sunsetVerdict"]["netSaved"] <= 0
    assert disjoint["sunsetVerdict"]["status"] == "collecting_30d_window"

    plugin_dir = tmp_path / "cg-plugin"
    (plugin_dir / "bin").mkdir(parents=True)
    (plugin_dir / "telemetry").mkdir(parents=True)
    (plugin_dir / "plugin.json").write_text('{"version":"3.99.0"}\n', encoding="utf-8")
    (plugin_dir / "bin" / "cg_status.py").write_text("# stub\n", encoding="utf-8")
    (plugin_dir / "telemetry" / "stats.json").write_text('{"saved_tokens":100}\n', encoding="utf-8")
    (plugin_dir / "telemetry" / "update.json").write_text(
        '{"state":"up_to_date","checked_at":"2099-01-01T00:00:00Z"}\n', encoding="utf-8"
    )

    runtime_script = r"""
const Module = require("module");
const path = require("path");
const fs = require("fs");
const childProcess = require("child_process");

const registered = {};
const unwatched = [];
const warns = [];
const execCalls = [];
let pendingCb = null;

console.warn = (...args) => warns.push(args.join(" "));
fs.watchFile = () => {};
fs.unwatchFile = (target) => unwatched.push(path.basename(target));
childProcess.execFile = (bin, args, opts, cb) => {
  execCalls.push({ bin, args: [...args] });
  if (args.includes("--usage")) {
    pendingCb = cb;
  } else {
    cb(null, "", "");
  }
};

const origLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === "vscode") {
    return {
      MarkdownString: class { constructor() { this.value = ""; } appendMarkdown(s) { this.value += s; } },
      ThemeColor: class { constructor(id) { this.id = id; } },
      StatusBarAlignment: { Right: 2 },
      ViewColumn: { One: 1 },
      ProgressLocation: { Notification: 15 },
      window: {
        createStatusBarItem: () => ({ show() {}, text: "", tooltip: "", name: "", command: "" }),
        registerWebviewViewProvider: () => ({ dispose() {} }),
        showInformationMessage: async () => undefined,
      },
      commands: {
        registerCommand: (id, fn) => { registered[id] = fn; return { dispose() {} }; },
      },
    };
  }
  return origLoad.apply(this, arguments);
};

process.env.CONTEXT_GUARD_HOME = process.argv[2];
const ext = require(path.resolve(process.argv[1], "extension.js"));
const context = { subscriptions: [] };
ext.activate(context);

registered["contextGuard.refresh"]();
registered["contextGuard.refresh"]();
const afterSecondRefresh = execCalls.length;
const firstErr = new Error("missing");
firstErr.code = "ENOENT";
pendingCb(firstErr);
const afterFallback = execCalls.length;
while (pendingCb && execCalls.length < 12) {
  const cb = pendingCb;
  pendingCb = null;
  cb(new Error("boom"));
}
registered["contextGuard.refresh"]();
const restartedCount = execCalls.length;
if (pendingCb) pendingCb(null, "", "");
ext.deactivate();

console.log(JSON.stringify({
  afterSecondRefresh,
  afterFallback,
  restartedCount,
  warns,
  unwatched,
  lastArgs: execCalls[0] ? execCalls[0].args : [],
}));
"""
    proc = subprocess.run(
        ["node", "-e", runtime_script, str(EXT_DIR), str(plugin_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    rt = json.loads(proc.stdout.strip())
    assert rt["afterSecondRefresh"] == 1
    assert rt["afterFallback"] == 2
    assert rt["restartedCount"] == rt["afterFallback"] + 1
    assert any("context-guard:" in w for w in rt["warns"])
    assert "--usage" in rt["lastArgs"]
    assert {"stats.json", "update.json", "token_usage.json"}.issubset(set(rt["unwatched"]))


def test_view_model_finite_non_neg_iso_days_zero_series_and_canonical_order() -> None:
    script = r"""
const path = require("path");
const vm = require(path.resolve(process.argv[1], "view_model.js"));
const ext = require(path.resolve(process.argv[1], "extension.js"));
const badNorm = vm.normalizeStats({
  saved_tokens: Infinity,
  baseline_tokens: true,
  actual_tokens: Infinity,
  reduction_pct: Infinity,
  by_harness: { antigravity: { hits: true, baseline_tokens: Infinity, saved_tokens: NaN } },
  last_event: { kind: "outlines", harness: "claude", saved_tokens: Infinity },
});
const usage = {
  preamble: { cursor: [100], custom: [50], antigravity: [0, 100, 200], zero_only: [0], bad: [null, true, false, -5] },
  preamble_parts: [
    { measured: 30000, components: { skills: { a: 1 } } },
    { measured: 40000, components: { deferred_tools: { "mcp:ccd_x": 1 } } },
  ],
  codex_preamble_parts: [
    { measured: 20000, cohort: "codex (cli)", components: { system_prompt: { c: 1 } } },
    { measured: 25000, cohort: "codex (desktop)", components: { system_prompt: { c: 1 } } },
  ],
};
const insights = vm.summarizeV4Insights({}, usage, null, null);
console.log(JSON.stringify({
  hasExports: typeof vm.finiteNonNeg === "function" && vm.finiteNonNeg === ext.finiteNonNeg
    && typeof vm.parseIsoDayUtcMs === "function" && vm.parseIsoDayUtcMs === ext.parseIsoDayUtcMs,
  fnn: [vm.finiteNonNeg(true), vm.finiteNonNeg(false), vm.finiteNonNeg(NaN), vm.finiteNonNeg(Infinity),
        vm.finiteNonNeg(-Infinity), vm.finiteNonNeg(-5), vm.finiteNonNeg(0), vm.finiteNonNeg("abc"),
        vm.finiteNonNeg(42.5), vm.finiteNonNeg("12")],
  badNorm,
  compactInf: vm.formatCompactTokens(Infinity),
  idleInf: vm.formatStatusBarIdleText({ saved_tokens: Infinity, reduction_pct: true }),
  idleBool: vm.formatStatusBarIdleText({ saved_tokens: true, reduction_pct: 50 }),
  pulseInf: vm.formatStatusBarPulseText({ reduction_pct: Infinity }, NaN, "outlines"),
  ctxInf: vm.formatContextWindows(Infinity),
  gaugeInf: vm.formatBlockGauge(Infinity),
  costInf: vm.estimateCostUsd(Infinity),
  days: [vm.parseIsoDayUtcMs("2026-11-14") !== null, vm.parseIsoDayUtcMs("2024-02-29") !== null,
         vm.parseIsoDayUtcMs("2026-99-99"), vm.parseIsoDayUtcMs("2026-02-29"), vm.parseIsoDayUtcMs("2026-02-30"),
         vm.parseIsoDayUtcMs("bad"), vm.parseIsoDayUtcMs(null)],
  zeroMedian: insights.preambleByHarness.antigravity,
  zeroOnly: insights.preambleByHarness.zero_only,
  badDropped: "bad" in insights.preambleByHarness,
  harnessKeys: Object.keys(insights.preambleByHarness),
  layerNoLegacy: vm.isLayerVisible({ key: "outlines", legacy: true }, {}, false),
}));
"""
    res = _run_node(script, str(EXT_DIR))
    assert res["hasExports"] is True
    assert res["fnn"] == [0, 0, 0, 0, 0, 0, 0, 0, 42.5, 12]
    assert res["badNorm"]["savedTokens"] == 0
    assert res["badNorm"]["baselineTokens"] == 0
    assert res["badNorm"]["actualTokens"] == 0
    assert res["badNorm"]["reductionPct"] == 0
    assert res["badNorm"]["harnesses"]["antigravity"] == {
        "hits": 0, "baselineTokens": 0, "savedTokens": 0, "reductionPct": 0
    }
    assert res["badNorm"]["lastEvent"]["savedTokens"] == 0
    assert res["compactInf"] == "0"
    assert res["idleInf"] == "$(shield) 0 tok · 0%"
    assert res["idleBool"] == "$(shield) 0 tok · 0%"
    assert res["pulseInf"] == "$(zap) -0 (Outline) · 0%"
    assert res["ctxInf"] == "0.0"
    assert res["gaugeInf"] == "▱▱▱▱▱"
    assert res["costInf"] == "0.00"
    assert res["days"] == [True, True, None, None, None, None, None]
    assert res["zeroMedian"] == {"sessions": 3, "median": 100, "recentMedian": 100, "last": 200}
    assert res["zeroOnly"] == {"sessions": 1, "median": 0, "recentMedian": 0, "last": 0}
    assert res["badDropped"] is False
    assert res["harnessKeys"] == [
        "antigravity", "claude (cli)", "claude (desktop)", "codex (cli)", "codex (desktop)", "cursor", "custom", "zero_only"
    ]
    assert res["layerNoLegacy"] is True


def test_sunset_verdict_python_parity_proration_missing_start_and_schema() -> None:
    script = r"""
const path = require("path");
const vm = require(path.resolve(process.argv[1], "view_model.js"));
const baseUsage = {
  totals: { "claude|opus": { input: 100000, cache_read: 1000000, cache_write: 0, events: 100 } },
  by_day: {
    "2026-10-01": { claude: { input: 50000, cache_read: 500000, cache_write: 0, events: 75 } },
    "2026-11-10": { claude: { input: 50000, cache_read: 500000, cache_write: 0, events: 25 } },
  },
};
const statsNoDays = { saved_tokens: 50000 };
const statsOverlap = { saved_tokens: 50000, by_day: { "2026-11-10": { saved_bytes: 200000 }, "2026-99-99": { saved_bytes: 999999 } } };
const outcomesNoVer = { by_key: { "claude|opus|outline": { total: 10, repeats: 0 } } };
const outcomesNullVer = { schema_version: null, by_key: { "claude|opus|outline": { total: 10, repeats: 0 } } };
console.log(JSON.stringify({
  noStart: vm.summarizeV4Insights(statsNoDays, baseUsage, null, null).sunsetVerdict,
  badStart: vm.summarizeV4Insights(statsNoDays, { ...baseUsage, started_at: "2026-99-99T00:00:00Z" }, null, null).sunsetVerdict,
  validStart: vm.summarizeV4Insights(statsNoDays, { ...baseUsage, started_at: "2026-10-01T00:00:00Z" }, null, null).sunsetVerdict,
  startedProrated: vm.summarizeV4Insights(statsNoDays, { ...baseUsage, started_at: "2026-11-10T00:00:00Z" }, outcomesNoVer, null).sunsetVerdict,
  totalsLarger: vm.summarizeV4Insights(
    { saved_tokens: 50000, by_day: { "2026-10-01": { saved_bytes: 100000 }, "2026-11-10": { saved_bytes: 100000 } } },
    { ...baseUsage, totals: { "claude|opus": { input: 100000, cache_read: 1000000, cache_write: 0, events: 200 } } },
    outcomesNoVer,
    null,
  ).sunsetVerdict,
  proratedUndefSchema: vm.summarizeV4Insights(statsOverlap, baseUsage, outcomesNoVer, null).sunsetVerdict,
  ignoredNullSchema: vm.summarizeV4Insights(statsOverlap, baseUsage, outcomesNullVer, null).sunsetVerdict,
}));
"""
    res = _run_node(script, str(EXT_DIR))
    from services.usage_report import denial_overhead, savings_share, sunset_verdict

    base_u = {
        "totals": {"claude|opus": {"input": 100000, "cache_read": 1000000, "cache_write": 0, "events": 100}},
        "by_day": {
            "2026-10-01": {"claude": {"input": 50000, "cache_read": 500000, "cache_write": 0, "events": 75}},
            "2026-11-10": {"claude": {"input": 50000, "cache_read": 500000, "cache_write": 0, "events": 25}},
        },
    }
    py_started = sunset_verdict(
        savings_share({**base_u, "started_at": "2026-11-10T00:00:00Z"}, 50000, {"saved_tokens": 50000}),
        denial_overhead(base_u, {"by_key": {"claude|opus|outline": {"total": 10, "repeats": 0}}}),
    )
    assert res["startedProrated"]["netSaved"] == py_started["net_saved"] == 50000 - 2500
    assert res["startedProrated"]["netSharePct"] == py_started["net_share_pct"]
    assert res["totalsLarger"]["denialTokens"] == 5000
    assert res["noStart"]["windowDays"] == 0
    assert res["badStart"]["windowDays"] == 0
    assert res["validStart"]["windowDays"] == 41
    assert res["proratedUndefSchema"]["windowDays"] == 1
    assert res["proratedUndefSchema"]["denials"] == 10
    assert res["proratedUndefSchema"]["denialTokens"] == 2500
    assert res["proratedUndefSchema"]["netSaved"] == 50000 - 2500
    assert res["ignoredNullSchema"]["denials"] == 0
    assert res["ignoredNullSchema"]["denialTokens"] == 0


def test_renderers_tooltip_escaping_and_non_finite_verdict_guards() -> None:
    script = r"""
const path = require("path");
const vscode = require("vscode");
const vm = require(path.resolve(process.argv[1], "view_model.js"));
const renderers = require(path.resolve(process.argv[1], "renderers.js"));
const ext = require(path.resolve(process.argv[1], "extension.js"));
const stats = {
  saved_tokens: 1000,
  baseline_tokens: 2000,
  reduction_pct: 50,
  installed_at: "2026-11[x](command:contextGuard.update)",
};
const insights = {
  cacheHitLabel: "90.0%",
  doctor: { statusLabel: "OK (4/4)" },
  sunsetVerdict: { windowDays: NaN, targetDays: 30, netSaved: Infinity, status: "collecting_30d_window" },
};
const mdEmpty = renderers.buildTooltipMarkdown(vscode.MarkdownString, "3.99.0[pwn](command:contextGuard.update)<img src=x>", null).value;
const mdFull = renderers.buildTooltipMarkdown(vscode.MarkdownString, "3.99.0[pwn](command:contextGuard.update)<img src=x>", stats, "", insights).value;
const sidebar = renderers.renderSidebarHtml("3.99.0", stats, insights);
const webview = renderers.renderWebviewHtml("3.99.0", stats, insights);
console.log(JSON.stringify({
  exported: typeof vm.escapeMarkdownText === "function" && vm.escapeMarkdownText === ext.escapeMarkdownText
    && typeof renderers.escapeMarkdownText === "function",
  mdEmpty,
  mdFull,
  sidebar,
  webview,
  codeSpan: vm.escapeMarkdownCodeSpan("a`b\rc\nd&<e>"),
}));
"""
    res = _run_node(script, str(EXT_DIR))
    assert res["exported"] is True
    for text in (res["mdEmpty"], res["mdFull"]):
        assert "[pwn](command:" not in text
        assert "<img" not in text
    assert "[x](command:" not in res["mdFull"]
    for out in (res["mdFull"], res["sidebar"], res["webview"]):
        assert "NaN" not in out
        assert "Infinity" not in out
    assert "&amp;&lt;e&gt;" in res["codeSpan"]


def test_extension_json_cache_doctor_ttl_stale_usage_refresh_and_update_promise(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "cg-cache"
    (plugin_dir / "bin").mkdir(parents=True)
    (plugin_dir / "telemetry").mkdir(parents=True)
    (plugin_dir / "plugin.json").write_text('{"version":"3.99.0"}\n', encoding="utf-8")
    (plugin_dir / "hooks.json").write_text("{}\n", encoding="utf-8")
    (plugin_dir / "bin" / "cg_status.py").write_text("# stub\n", encoding="utf-8")
    (plugin_dir / "telemetry" / "stats.json").write_text('{"saved_tokens":100,"baseline_tokens":200}\n', encoding="utf-8")
    (plugin_dir / "telemetry" / "update.json").write_text('{"state":"current","checked_at":"2099-01-01T00:00:00Z"}\n', encoding="utf-8")
    usage_path = plugin_dir / "telemetry" / "token_usage.json"
    usage_path.write_text('{"totals":{},"by_day":{}}\n', encoding="utf-8")

    script = r"""
const Module = require("module");
const path = require("path");
const fs = require("fs");
const childProcess = require("child_process");

const registered = {};
let sidebarProvider = null;
const execCalls = [];
let statProbeCount = 0;
let readStatsCount = 0;
let fakeNow = 1000000;
Date.now = () => fakeNow;

const origReadFileSync = fs.readFileSync.bind(fs);
fs.readFileSync = (p, enc) => {
  if (String(p).endsWith("stats.json")) readStatsCount += 1;
  return origReadFileSync(p, enc);
};
const origExistsSync = fs.existsSync.bind(fs);
fs.existsSync = (p) => {
  if (String(p).endsWith("plugin.json")) statProbeCount += 1;
  return origExistsSync(p);
};
fs.watchFile = () => {};
fs.unwatchFile = () => {};
childProcess.execFile = (bin, args, opts, cb) => {
  execCalls.push({ bin, args: [...args], opts: { ...opts } });
  if (cb) cb(null, "", "");
};

const origLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === "vscode") {
    return {
      MarkdownString: class { constructor() { this.value = ""; } appendMarkdown(s) { this.value += s; } },
      ThemeColor: class { constructor(id) { this.id = id; } },
      StatusBarAlignment: { Right: 2 },
      ViewColumn: { One: 1 },
      ProgressLocation: { Notification: 15 },
      window: {
        createStatusBarItem: () => ({ show() {}, text: "", tooltip: "", name: "", command: "" }),
        registerWebviewViewProvider: (id, prov) => { if (id === "contextGuard.sidebarView") sidebarProvider = prov; return { dispose() {} }; },
        createWebviewPanel: () => ({ webview: { html: "" }, onDidDispose() {}, reveal() {} }),
        showInformationMessage: async () => undefined,
        showErrorMessage: async () => undefined,
        withProgress: async (_o, fn) => fn(),
      },
      commands: { registerCommand: (id, fn) => { registered[id] = fn; return { dispose() {} }; }, executeCommand: () => {} },
    };
  }
  return origLoad.apply(this, arguments);
};

process.env.CONTEXT_GUARD_HOME = process.argv[2];
const ext = require(path.resolve(process.argv[1], "extension.js"));
const statsPath = path.join(process.argv[2], "telemetry", "stats.json");
const usagePath = path.join(process.argv[2], "telemetry", "token_usage.json");

(async () => {
  const freshAtMs = fs.statSync(usagePath).mtimeMs;
  fakeNow = freshAtMs + 1000;
  const ctx = { subscriptions: [], globalState: { get: () => false, update: async () => {} } };
  ext.activate(ctx);
  const execAfterFreshActivate = execCalls.length;
  ext.updateStatusBar();
  const readAfterCacheHit = readStatsCount;
  const probesAfterCacheHit = statProbeCount;

  fakeNow = freshAtMs + 31000;
  ext.updateStatusBar();
  const probesAfterTtlExpiry = statProbeCount;

  fs.writeFileSync(statsPath, '{"saved_tokens":250,"baseline_tokens":500}\n');
  ext.updateStatusBar();
  const readAfterOverwrite = readStatsCount;
  fs.unlinkSync(statsPath);
  const afterUnlink = ext.updateStatusBar();

  fakeNow = freshAtMs + 700000;
  let visCb = null;
  sidebarProvider.resolveWebviewView({
    webview: { options: {}, html: "" },
    visible: true,
    onDidDispose() {},
    onDidChangeVisibility(cb) { visCb = cb; },
  });
  const execAfterStaleSidebar = execCalls.length;
  visCb();
  const execAfterVisibility = execCalls.length;
  registered["contextGuard.showReport"]();
  const execAfterShowReport = execCalls.length;

  const probesBeforeRefresh = statProbeCount;
  registered["contextGuard.refresh"]();
  const probesAfterRefresh = statProbeCount;

  const updatePromise = registered["contextGuard.update"]();
  const isPromise = updatePromise && typeof updatePromise.then === "function";
  const updateResult = await updatePromise;

  const updatePath = path.join(process.argv[2], "telemetry", "update.json");
  fs.writeFileSync(updatePath, '{"state":"install_pending","local":"3.99.0","checked_at":"2099-01-01T00:00:00Z"}\n');
  const probesBeforeRunUpdate = statProbeCount;
  const runUpdateOk = await registered["contextGuard.update"]();
  const probesAfterRunUpdate = statProbeCount;

  fs.writeFileSync(statsPath, '{"saved_tokens":250,"baseline_tokens":500}\n');
  ext.updateStatusBar();
  ext.deactivate();
  const readsBeforeReactivate = readStatsCount;
  const probesBeforeReactivate = statProbeCount;
  ext.activate(ctx);
  const readsAfterReactivate = readStatsCount;
  const probesAfterReactivate = statProbeCount;
  ext.deactivate();

  console.log(JSON.stringify({
    execAfterFreshActivate,
    readAfterCacheHit,
    probesAfterCacheHit,
    probesAfterTtlExpiry,
    readAfterOverwrite,
    afterUnlinkNull: afterUnlink.stats === null,
    execAfterStaleSidebar,
    execAfterVisibility,
    execAfterShowReport,
    probesBeforeRefresh,
    probesAfterRefresh,
    isPromise,
    updateResult,
    runUpdateOk,
    probesBeforeRunUpdate,
    probesAfterRunUpdate,
    readsBeforeReactivate,
    readsAfterReactivate,
    probesBeforeReactivate,
    probesAfterReactivate,
    allUsageWindowsHide: execCalls.filter((c) => c.args.includes("--usage")).every((c) => c.opts.windowsHide === true),
  }));
})();
"""
    proc = subprocess.run(
        ["node", "-e", script, str(EXT_DIR), str(plugin_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    res = json.loads(proc.stdout.strip())
    assert res["execAfterFreshActivate"] == 0
    assert res["readAfterCacheHit"] == 1
    assert res["probesAfterCacheHit"] == 1
    assert res["probesAfterTtlExpiry"] == 2
    assert res["readAfterOverwrite"] == 2
    assert res["afterUnlinkNull"] is True
    assert res["execAfterStaleSidebar"] == 1
    assert res["execAfterVisibility"] == 2
    assert res["execAfterShowReport"] == 3
    assert res["probesAfterRefresh"] > res["probesBeforeRefresh"]
    assert res["isPromise"] is True
    assert res["updateResult"] is False
    assert res["runUpdateOk"] is True
    assert res["probesAfterRunUpdate"] > res["probesBeforeRunUpdate"]
    assert res["readsAfterReactivate"] > res["readsBeforeReactivate"]
    assert res["probesAfterReactivate"] > res["probesBeforeReactivate"]
    assert res["allUsageWindowsHide"] is True

