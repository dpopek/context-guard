---
name: context-audit
description: Run an on-demand Context-Guard token savings, intervention outcome, session preamble, and duplicate skill hygiene audit across Antigravity, Claude Code, Cursor, and OpenAI Codex.
---

# Context-Guard Audit Skill (`context-audit`)

Use this skill when the user asks to inspect token savings, audit session preamble overhead, check intervention outcomes (`outcomes.json`), or diagnose duplicate skills / harness hook status.

## Workflow

1. **Run the Full Markdown Token & Preamble Report:**
   ```bash
   python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --markdown
   ```
   Review:
   - Cumulative token reduction (`saved_tokens`, `reduction_pct`, `200k` context windows saved).
   - **Protection Breakdown by Mechanism** (`outlines`, `ranges_trimmed`, `cli_rewrites`, `outline_pulls`, `mcp_guards`, `allowed_reads`; legacy counters appear only when non-zero).
   - **Savings by Harness & Shell Command Output** (per-harness baseline/saved volume plus bounded vs. spilled shell command families when present).
   - **Token Usage & Real Savings Share** (real transcript totals per harness/model, common UTC day horizon `[since, until]`, and 30-day sunset ROI check).
   - **Session Preamble & Candidates** (always-on `CLAUDE.md`/`AGENTS.md`, memory index, skills listing, and unused MCP servers/plugins).

2. **Inspect Intervention Outcomes (`outcomes.json`):**
   ```bash
   python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --outcomes
   ```
   Review the v3 (`SCHEMA_VERSION = 3`) 7-column breakdown: `Interventions`, `Targeted follow-up` %, `Full bypass` %, and `Shell bypass` % per `Harness`, `Model`, and `Kind` (`outline`, `outline_pull`, `range_trim`, `cli_rewrite`; follow-up/bypass rates apply to `outline` and `outline_pull`, and bounded Codex CLI shell reads via `sed -n`, `head`, or `tail` `<= 250` lines resolve as `targeted_followup` rather than `shell_bypass`).

3. **Run Environment & Skill Hygiene Doctor:**
   ```bash
   python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --doctor
   ```
   Verify:
   - Python runtime (`>= 3.9`), file locking (`flock`), writable telemetry directory, and harness registration (`antigravity`, `claude`, `cursor`, `codex`).
   - **Skill hygiene:** Report any duplicate skill names detected within `.gemini` or `.claude` ecosystems.
