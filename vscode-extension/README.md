# Context-Guard Token Savings

Live token savings telemetry, status bar indicator, SVG donut ring side panel, and interactive analytics report for **Context-Guard** across **Google Antigravity IDE** and **Cursor IDE**.

---

## Overview

**Context-Guard** is a zero-prompt security guard, silent range-trim, and multi-harness telemetry plugin for **Google Antigravity**, **Claude Code**, **Cursor IDE**, and **OpenAI Codex CLI/App** using pure Python 3.9+ standard library hooks.

This companion IDE extension reads `~/.gemini/config/plugins/context-guard/telemetry/stats.json` and `update.json` in real time to surface cumulative token and cost savings directly in your editor.

---

## IDE Extension Features

### 1. Live Status Bar Pill & 4-Second Intervention Pulse
- **Idle Pill:** Shows `$(shield) -<saved> · <pct>%` in the status bar (plus `$(cloud-download)` when an update or installer run is pending).
- **Live Pulse:** Flashes `$(zap) -<delta> (<layer>) · <pct>%` for 4 seconds whenever a `PreToolUse` intervention saves tokens.
- **Rich Hover Breakdown:** Displays saved/baseline tokens, API cost saved (`≈ $USD`), `200k` windows saved, per-harness bars, and quick actions.

### 2. Activity Bar & Explorer Side Panels (`SVG Donut Ring`)
- **Activity Bar View (`Token Savings`)** and **Explorer Section (`Context-Guard Savings`)**:
  - Interactive SVG donut gauge showing token reduction percentage and saved token total.
  - KPI cards for **Context Windows Saved (`200k`)**, **Est. API Saved (`$USD`)**, **Baseline Volume**, and **Total Interventions**.
  - **Last Guard Hit** live banner with relative timestamp and harness badge.
  - **By Harness** progress bars and **Guard Interventions** breakdown across protection layers.

### 3. Interactive Token Savings Report (`contextGuard.showReport`)
- Click the status bar pill or run **`Context-Guard: Show Token Savings Report`** from the Command Palette to open the full Webview dashboard.

### 4. Safe One-Click Release Updates (`contextGuard.update`)
- Checks `origin` for newer `vX.Y.Z` release tags in the background at most once per 24 hours.
- Clicking **Update** fast-forwards the plugin clone (`git merge --ff-only vX.Y.Z`) and runs `install_harnesses.py --install` with live `installedTimestamp` metadata.

---

## Core Context-Guard Engine Layers

- **Voluntary Outlining & Artifact Unwrap (`PreToolUse`):** Provides `cg-outline` for source files, unwraps `>=16 KB` MCP JSON outputs, summarizes `>=6 KB` TWG `stdout*.json`, and indexes `transcript*.jsonl`.
- **Silent Overlap Trimming (`PreToolUse`):** Tracks `SHA-256` hashes and `[StartLine, EndLine]` intervals in `.context_guard_state.json`, silently trimming overlapping bounded reads without blocking workflow.
- **Quiet CLI Rewrites:** Injects quiet flags (`pytest -q`, `git status -sb`, `cargo test -q`, `vitest`, `grep`, `twg`) in Antigravity and auto-approved Claude/Cursor (`bypassPermissions`/`dontAsk`/`auto`).
- **Local-First GitLab, BigQuery & Governance Guards (`PreToolUse`):** Redirects remote GitLab lookups to local clones, enforces authorized BigQuery datasets fail-closed, and guards governance assets.
- **Two-Stage Auto-Compact Sensor & Preamble Attribution:** Tracks transcript steps (`O(delta)`) in Antigravity, resets caches on compaction, measures shell bytes, and splits CLI vs Desktop preamble overhead.

---

## Commands

| Command ID | Title | Description |
| :--- | :--- | :--- |
| `contextGuard.showReport` | `Context-Guard: Show Token Savings Report` | Opens the full token savings Webview report. |
| `contextGuard.refresh` | `Context-Guard: Refresh Token Savings` | Reloads `telemetry/stats.json` and refreshes all UI views. |
| `contextGuard.update` | `Context-Guard: Update` | Fast-forwards to the latest release tag and re-runs the multi-harness installer. |

---

## CLI Utilities

```bash
# Short summary, Claude HUD, full Markdown report, or raw JSON
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --short
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --claude-hud
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --markdown
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --json

# Intervention outcomes matrix, real token usage / preamble audit, and environment doctor
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --outcomes
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --usage
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --doctor

# Install, uninstall, preview (--dry-run), or check multi-harness status
python3 ~/.gemini/config/plugins/context-guard/bin/install_harnesses.py --install
python3 ~/.gemini/config/plugins/context-guard/bin/install_harnesses.py --install --dry-run
python3 ~/.gemini/config/plugins/context-guard/bin/install_harnesses.py --status
python3 ~/.gemini/config/plugins/context-guard/bin/install_harnesses.py --uninstall
```
