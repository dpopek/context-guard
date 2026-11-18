---
name: context-audit
description: Run an on-demand Context-Guard token savings, intervention outcome, session preamble, and duplicate skill hygiene audit across Antigravity, Claude Code, Cursor, and OpenAI Codex.
---

# Context-Guard Audit Skill (`context-audit`)

Use this skill when the user asks to inspect token savings, audit session preamble overhead, check intervention outcomes (`outcomes.json`), or diagnose duplicate skills / harness hook status.

## Workflow

If Context-Guard is cloned outside `~/.gemini/config/plugins/context-guard`, run `bin/cg_status.py` from the checkout directory two levels above this `SKILL.md` (or set `CONTEXT_GUARD_HOME`).

1. **Run the Full Markdown Token & Preamble Report:**
   ```bash
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg_status.py" --markdown
   ```
   Review:
   - Cumulative token reduction (`saved_tokens`, `reduction_pct`, `200k` context windows saved).
   - **Protection Breakdown by Mechanism** (`outlines`, `ranges_trimmed`, `cli_rewrites`, `outline_pulls`, `mcp_guards`, `allowed_reads`; legacy counters appear only when non-zero).
   - **Savings by Harness & Shell Command Output** (per-harness baseline/saved volume plus bounded vs. spilled shell command families when present).
   - **Token Usage & Real Savings Share** (real transcript totals per harness/model, common UTC day horizon `[since, until]`, and 30-day sunset ROI check).
   - **Session Preamble & Candidates** (always-on `CLAUDE.md`/`AGENTS.md`, memory index, skills listing, and unused MCP servers/plugins).

2. **Inspect Intervention Outcomes (`outcomes.json`):**
   ```bash
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg_status.py" --outcomes
   ```
   Review the v4 (`SCHEMA_VERSION = 4`) 10-column breakdown: `Harness`, `Model`, `Kind`, `Interventions`, `Targeted recovery`, `Full recovery`, `Suspected regret`, `Confirmed regret`, `Weighted steps`, and `Est. associated model cost` (bounded non-counterfactual `1/k` step-weighted attribution). Note regret/attribution telemetry fields (`confirmed_regret_rate`, `suspected_regret_rate`, `unattributed_anon`, `late_unattributed`), 30-day `sunset_verdict` (`net_saved`), and default `"strict"` `read_confirm_policy` asymmetry (`0` `range_trim` savings on Antigravity/Codex unless `"bounded"`).

3. **Run Environment & Security Doctor:**
   ```bash
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg_status.py" --doctor
   ```
   Verify:
   - Python runtime (`>= 3.9`), file locking (`flock`), writable telemetry directory, and harness registration (`antigravity`, `claude`, `cursor`, `codex`).
   - Native fail-closed security sync (`NATIVE_FAIL_CLOSED_DRIFT`, `degraded Claude < 2.1.295`, and `Codex trust / #27833`).
   - **Skill hygiene:** Report any duplicate skill names detected within `.gemini` or `.claude` ecosystems.

4. **Deterministic Replay, Benchmark & Public JSON (`replay_benchmark.py`):**
   ```bash
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg_status.py" --replay
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg_status.py" --benchmark
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg_status.py" --public-json
   ```
   Evaluate the built-in isolated deterministic synthetic corpus (`--replay`, `--benchmark`) without mutating live state, and export scrubbed OSS snapshots (`--public-json`).

5. **Passive Preamble & MCP Budget Advisor (`cg budget`):**
   ```bash
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg.py" budget --preamble --mcp --recommendations
   ```
   Review:
   - Strictly read-only 4-harness audit cleanly separating `measured`, `estimated`, and `unavailable` figures (never emitting `0` when schemas or usage telemetry are absent).
   - Always-on instruction, memory-index, and skill bytes, duplicate skills, MCP tool overlaps, and non-mutating `minimal-core` / `full-integrations` profiles (note prompt-cache `cache_read` caveats).
   - Use opt-in `--mcp --probe --probe-timeout 3` only when live local stdio `tools/list` schema probing is explicitly requested.

6. **Evidence Engine & Hardening Gate (`cg eval`):**
   ```bash
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg.py" eval --offline-replay
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg.py" eval --cursor-conformance
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg.py" eval --governor-check
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg.py" eval --hardening-check
   ```
   Review:
   - Deterministic `EvidenceContractV1` offline replay (zero network or live LLM spawns), `CapabilityAttestationKey` provenance, Cursor CLI conformance (`excluded_missing_telemetry` cache handling), 8-gate Adaptive Governor verification (`--governor-check`), and 8-gate explainability, off-hot-path OTel, benchmark, and safe-migration hardening verification (`--hardening-check`).
   - Use `--pilot --plan`, `--release --plan`, or `--ledger-verify` to plan isolated campaigns or verify durable `evidence_events.json` Outcomes v4 derivation.

7. **Intervention Explainability & Off-Hot-Path OTel Export (`cg explain` / `cg export`):**
   ```bash
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg.py" explain <event-id>
   python3 "${CONTEXT_GUARD_HOME:-~/.gemini/config/plugins/context-guard}/bin/cg.py" export --otel
   ```
   Inspect scrubbed per-intervention spool lifecycle states (`available`, `evicting`, `evicted`, `corrupt`, `receipt_only`, `not_spool_backed`), exact eviction/corruption reasons, and delivery evidence tiers via `cg.py explain <event-id>` (`--json`), or export privacy-scrubbed 100% stdlib OTLP/JSON telemetry strictly off the hook hot path via `cg.py export --otel` (`--output`, `--ndjson`, `--endpoint`).
