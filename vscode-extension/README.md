# Context-Guard Token Savings

Live token savings telemetry, status bar indicator, SVG donut ring side panel, and interactive analytics report for **Context-Guard** across **Google Antigravity IDE** and **Cursor IDE**.

---

## Overview

**Context-Guard (v4.7.0)** is a zero-prompt Policy API v1 host, verified Read Ledger v2 (`range_trim`), reversible output spooler, preamble/MCP budget advisor, Evidence Engine, and multi-harness telemetry plugin for **Google Antigravity**, **Claude Code**, **Cursor IDE**, and **OpenAI Codex CLI/App** using pure Python 3.9+ stdlib hooks.

This companion IDE extension reads `telemetry/stats.json`, `token_usage.json`, `outcomes.json` (Outcomes Schema v4), and `update.json` from your installed Context-Guard checkout (auto-refreshing missing or stale `token_usage.json` via `cg_status.py --usage`) to surface token savings and v4.5 insights in your editor.

---

## IDE Extension Features

### 1. Live Status Bar Pill & 4-Second Intervention Pulse
- **Idle Pill:** Shows `$(shield) -<saved> · <pct>%` in the status bar (plus `$(cloud-download)` when an update or installer run is pending).
- **Live Pulse:** Flashes `$(zap) -<delta> (<layer>) · <pct>%` for 4 seconds whenever a `PreToolUse` intervention saves tokens.
- **Rich Hover Breakdown:** Displays saved/baseline tokens, **Estimated Cost Impact (non-counterfactual)**, `Cache Hit %`, `Preamble (Last)` with `Recent (10)`, `Doctor` (`--doctor` parity), and 30-day `sunset_verdict`.

### 2. Activity Bar & Explorer Side Panels (`SVG Donut Ring`)
- **Activity Bar View (`Token Savings`)** and **Explorer Section (`Context-Guard Savings`)**:
  - Interactive SVG donut gauge showing token reduction percentage and saved token total.
  - KPI cards for **Baseline Read**, **Actual Sent**, **Cache Hit %**, **Preamble (Last)** with **Recent (10)** median, **Doctor**, and **30d Verdict**.
  - **By Harness** progress bars and **By Protection Layer** breakdown across v4.5 layers, plus **Estimated Cost Impact (non-counterfactual)**.

### 3. Interactive Token Savings Report (`contextGuard.showReport`)
- Open from status bar or Command Palette for Outcomes Schema v4, **Estimated Cost Impact (non-counterfactual)**, `Cache Hit %`, `Doctor` (`NATIVE_FAIL_CLOSED_DRIFT`), and `sunset_verdict`.
- Automatically refreshes missing or stale (`>= 10 min`) `token_usage.json` in the background via `cg_status.py --usage` on startup, sidebar open, and report view.

### 4. Safe One-Click Release Updates (`contextGuard.update`)
- Checks `origin` for newer `vX.Y.Z` release tags in the background at most once per 24 hours.
- Runs a dirty-tree precheck, fast-forwards (`git merge --ff-only vX.Y.Z`), re-runs `install_harnesses.py --install`, and rolls back via `git reset --keep` (never `git reset --hard`) on failure.

---

## Core Context-Guard Engine Layers

- **Outlining & Artifact Unwrap (`PreToolUse`):** Provides `cg-outline`, unwraps `>=16 KB` MCP JSON, summarizes opt-in integration JSON (`>=6 KB`), and indexes `transcript*.jsonl`.
- **Reversible Output Spooling (`PostToolUse`):** Opt-in (`"output_spool": "active"`) replaces huge Claude/Cursor outputs with summaries, locked SHA-256 `cg-spool` recovery, workspace isolation, and `receipts.jsonl`.
- **Read Ledger v2 (`PreToolUse`):** Tracks `SHA-256` hashes, spans, and `confirm_tier` in `.context_guard_state.json`; default `"strict"` yields `0` savings on Antigravity/Codex unless `"bounded"`.
- **Guardrailed Quiet CLI Rewrites:** Trims noisy test/grep boilerplate (`pytest -q`, `git status -sb`, `cargo test -q`, `vitest`, `grep`, opt-in integrations) without overriding explicit user flags.
- **Verified Policy API v1 (`PreToolUse`):** Evaluates external `policy_packs` pinned by `file_hashes` and `tree_sha256` in memory, with Pass-2 security checks and Stage-2 scoped fail-closed fallbacks.
- **Two-Stage Auto-Compact Sensor & Preamble Attribution:** Tracks transcript steps (`O(delta)`) in Antigravity, resets caches on compaction, measures shell bytes, and splits CLI vs Desktop preamble overhead.

---

## Commands

| Command ID | Title | Description |
| :--- | :--- | :--- |
| `contextGuard.showReport` | `Context-Guard: Show Token Savings Report` | Opens the full token savings Webview report. |
| `contextGuard.refresh` | `Context-Guard: Refresh Token Savings` | Reloads `telemetry/stats.json` and refreshes all UI views. |
| `contextGuard.update` | `Context-Guard: Update` | Fast-forwards safely (`git reset --keep` rollback) and re-runs the installer. |

---

## CLI Utilities

```bash
CG_DIR="${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}"

# Unified CLI: passive preamble/MCP budget audit, Evidence Engine replay, doctor, status, spool, and outline
python3 "$CG_DIR/bin/cg.py" budget --preamble --mcp --recommendations
python3 "$CG_DIR/bin/cg.py" eval --offline-replay
python3 "$CG_DIR/bin/cg.py" doctor

# Short summary, Claude HUD, full Markdown report, or raw JSON
python3 "$CG_DIR/bin/cg_status.py" --short
python3 "$CG_DIR/bin/cg_status.py" --claude-hud
python3 "$CG_DIR/bin/cg_status.py" --markdown
python3 "$CG_DIR/bin/cg_status.py" --json

# Intervention outcomes matrix, real token usage / preamble audit, and environment doctor
python3 "$CG_DIR/bin/cg_status.py" --outcomes
python3 "$CG_DIR/bin/cg_status.py" --usage
python3 "$CG_DIR/bin/cg_status.py" --doctor

# Install, uninstall, preview (--dry-run), or check multi-harness status
python3 "$CG_DIR/bin/install_harnesses.py" --install
python3 "$CG_DIR/bin/install_harnesses.py" --install --dry-run
python3 "$CG_DIR/bin/install_harnesses.py" --status
python3 "$CG_DIR/bin/install_harnesses.py" --uninstall
```
