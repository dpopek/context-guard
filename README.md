# Context-Guard (v5.0.0)

Zero-prompt Policy API v1 reliability platform, Read Ledger v2 (`range_trim`), reversible output spooler, artifact unwrapper, budget advisor, Evidence Engine, Adaptive Governor, and off-hot-path OTel exporter for **Antigravity**, **Claude Code**, **Cursor IDE**, and **OpenAI Codex** (`macOS`, `Linux`, `Windows`).

Pure Python 3.9+ stdlib: `cg-outline` (21 extensions, optional `tree-sitter-language-pack`), `policy_packs`, `cg-spool`, Outcomes v4, `cg doctor`, `cg budget`, `cg eval`, `cg explain`, and `cg export --otel`.

---

## Multi-Harness Support Matrix

| Harness | Config | Hooks | Read Caps | Compaction | Status UI |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Antigravity** | `hooks.json` | `PreInvocation`, `PreToolUse`, `PostToolUse` | `800` L (`45 KB`) | `O(delta)` `PreInvocation` (`80`/`200`) | IDE Bar & Panel |
| **Claude Code** | `~/.claude/settings.json` | `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `PreCompact`, `SessionEnd`, `statusLine` | `2,000` L (`80 KB`) | `autoCompactWindow` + `PreCompact` | `statusLine` HUD |
| **Cursor IDE** | `~/.cursor/hooks.json` | `preToolUse`, `postToolUse`, `preCompact` | `2,000` L (`80 KB`) | Native + `preCompact` | IDE Bar & Panel |
| **OpenAI Codex** | `~/.codex/hooks.json`, `config.toml` | `PreToolUse`, `PostToolUse`, `PreCompact` | `Bash` / `exec_command` | `model_auto_compact_token_limit` + `PreCompact` | `cg_status.py` |

---

## Machine-Artifact `AUTO-OUTLINE` & Unwrap (`PreToolUse`)

Code/Markdown reads never block; `cg-outline <path>` covers 21 extensions, and `AUTO-OUTLINE` unwraps bloated artifacts:

| Target | Trigger | Action |
| :--- | :--- | :--- |
| **Wrapped JSON MCP** (`.system_generated/steps/<N>/output.txt`) | `>= 16 KB` 1-line `"content"` | Unwraps `"content"` (`output_formatted.json` for tables); redirects reads. |
| **Tabular Rows MCP** (`rows[]`) | `>= 16 KB` JSON `rows[]` | Unwraps to `output_formatted.json`; returns count, schema, 3-row preview. |
| **Generic JSON List/Items** | `>= 16 KB` array or `items`/`results`/`values` | Unwraps to `output_formatted.json`; returns count, keys, preview. |
| **Integrations** (`integrations/atlassian_twg.py`) | `>= 6 KB` when `"atlassian_twg": "active"` | Summarizes issue/doc JSON and extracts text to sibling files. |
| **Transcripts** (`.system_generated/logs/transcript*.jsonl`) | `>= 16 KB` unbounded or `> 8` L | Streams step index (`step_index`, `type`, `tools=[...]`, bytes). |

---

## Core Guard & Telemetry Layers

### 1. Read Ledger v2 & Silent `range_trim`
- Tracks 64 KB `SHA-256` hashes (`10 MB` cap), `[StartLine, EndLine]`, and `confirm_tier` (`0`/`1`/`2`) in `.context_guard_state.json` (`READ_LEDGER_SCHEMA = 2`).
- **Strict Default:** `"read_confirm_policy": "strict"` trusts `confirm_tier == 2` only (Claude `PostToolBatch`, Cursor `tool_output`); Antigravity/Codex need `"bounded"`.
- **Shadow Mode:** `"shadow"` logs counterfactual savings to `0o600` `telemetry/shadow.json`, invalidated on edit, compaction, or rewind.

### 2. Verified Policy API v1 & Security (`policies/api.py`, `policies/loader.py`)
- Normalizes MCP calls across Antigravity (`mcp_<server>_<tool>`), Claude/Codex (`mcp__<server>__<tool>`), Cursor (`MCP:<tool>`), and `call_mcp_tool`.
- Loads verified packs from memory (`file_hashes` + `tree_sha256`) with Stage-2 scoped fallbacks and `verify_security_policies_post_transform`.
- **Fail-Closed:** Claude `>= 2.1.295` `"onFailure": "block"`; Cursor `"failClosed": true` (`NATIVE_FAIL_CLOSED_DRIFT`); Antigravity `exit 2`; Codex `[features].hooks = true`.

### 3. Guardrailed Quiet CLI Rewrites (`PreToolUse`)

Trims noisy test/grep boilerplate unless explicit verbosity flags (`-v`/`--verbose`/`--tb=long`/`--tb=full`/`--no-quiet`) are present:

| Command | Injected Flags (Antigravity, Claude, Cursor) | Guardrails |
| :--- | :--- | :--- |
| `grep -r`/`grep -rn` | `-I --exclude-dir={...}` + minified/lock exclusions | Skipped on `--include`/`--exclude` or lock target. |
| `pytest`, `poetry`/`uv run pytest` | `-q --tb=short --no-header` (`cd <dir> &&` aware) | Skipped on `-v`, `-q`, `--tb`, `--no-header`, `--`, pipes. |
| `git status` | `-sb` (`cd <dir> &&` aware) | Skipped if flags or path args are supplied. |
| `cargo test` | `-q` (`cd <dir> &&` aware) | Skipped on verbosity flags, `--`, or pipes. |
| `vitest` | `--reporter=dot` | Skipped on output flags, `--`, or pipes. |
| Integrations | Opt-in rewriters via `integrations.*` | Off by default (`"atlassian_twg": "off"`, `"cursor_spool_mcp": "off"`). |

### 4. Auto-Compact Sensor & Preamble Attribution
- Scans `transcript*.jsonl` (`O(delta)`), emitting `AUTO-COMPACT SENSOR` (`>= 80` steps / `512 KB`) and `HARD STOP` (`>= 200` / `1024 KB`).
- Splits `claude (cli)`/`(desktop)` (`mcp:ccd_*`) and `codex (cli)`/`(desktop)`, scores `Recent (10)` hygiene, and computes 30-day `sunset_verdict` in `--usage`.
- **Budget Advisor (`cg budget`):** Audits 4-harness preambles and MCP servers read-only (`measured`/`estimated`/`unavailable`); `--probe` runs opt-in stdio `tools/list`.

### 5. Reversible Output Spooling & Regret (`spool/`)
- **Opt-In Spooling:** `"output_spool": "active"` checks UTF-8 and `max_spool_entry_bytes` (`4 MiB`), swapping `>= 12,288` B / `200`-line outputs for `<= 3,072` B summaries (`"shadow"` logs `shadow_spools`).
- **Recovery & GC:** Stores `sp_<12hex>.txt` (`24h` TTL, `64` entries, `32 MB`) across `available`/`evicting`/`evicted`/`corrupt`; verifies SHA-256 and unlinks unlocked.
- **Scoped Access:** `cg-spool` (`--workspace`/`--workspace-root`, `--session`) and MCP (`roots/list` + `--workspace-root`) enforce `os.path.samefile()` and emit `ContextReceiptV1`.

### 6. Evidence, Governor, Hardening & Platform Conformance (`evidence/`, `bin/cg_explain.py`, `bin/cg_export.py`)
- **Ledger & Governor:** Deduplicates `evidence_events.json`, derives Outcomes v4, emits `EvidenceContractV1`/`CapabilityAttestationKey`, gates Cursor CLI, and trips hysteresis breakers.
- **Explain, OTel & Hardening:** `cg explain <event-id>` inspects lifecycles/evictions (`ExplainContractV1`); `cg export --otel` emits off-hot-path stdlib OTLP/JSON; `--hardening-check` verifies 8 gates.
- **Frozen Platform & Conformance:** Freezes `POLICY_API_VERSION = 1` (no v2/SDK) + 17 `CORE_SCHEMA_VERSIONS`; `cg doctor --contracts` and `cg eval --conformance` / `--platform-matrix` verify 10 gates.

---

## Architecture & Module Inventory

Enforced by `tests/test_module_boundaries.py` and `tests/test_version_source.py`:
- **Zero Cycles & Slim Footprint:** `Tarjan SCC == 0` (`hooks`/`spool`/`policies`/`integrations` never import `evidence`); `.py <= 800` LOC; `hooks/*.py < 6,800` LOC.
- **Lock Ordering:** Independent locks + `os.replace` across state, `stats`, `outcomes`, `token_usage`, `receipts`, `evidence_events`, `update`, and `update_refresh`.

| Module | Layer | Responsibility |
| :--- | :--- | :--- |
| `policies/api.py` | Policy | `POLICY_API_VERSION = 1`, `CORE_SCHEMA_VERSIONS`, `DeprecationPolicyV1`, `ConformanceContractV1`, `ExplainContractV1`. |
| `policies/governor.py` | Policy | Capability-aware governor (`CapabilityAttestationKey`, hysteresis breakers, `replay_governor_decisions`). |
| `policies/loader.py` | Policy | Verified pack loader (`file_hashes`, `tree_sha256` byte checks). |
| `integrations/atlassian_twg.py` | Integration | Opt-in CLI rewriter and JSON stdout summarizer (`"atlassian_twg": "active"`). |
| `spool/receipts.py` | Spool | Workspace `samefile` identity, link checks, `receipts.jsonl`, `load_receipt_rows`, lifecycle stats. |
| `spool/store.py` | Spool | Write-once blobs, UTF-8/byte guard, unlocked `slice`/`grep`/`list`/`gc`, `inspect_spool_entry`. |
| `spool/classifier.py` | Spool | Stateless command signatures, verbose overrides, pre-tool follow-up classifier. |
| `spool/mcp_server.py` | Spool | Dual-framed (`Content-Length` + NDJSON) stdio MCP (`cg_spool_*`) and `.cursor/mcp.json` sync. |
| `evidence/ledger.py` | Evidence | Deduplicated `evidence_events.json`, Outcomes v4 derivation, attestation keys, Cursor gate. |
| `evidence/metrics.py` | Evidence | `Cost per Passed Run`, noise guard, Wilson/bootstrap CIs, Pilot/Release matrix planner. |
| `evidence/runner.py` | Evidence | Campaign controls, isolated executor, offline replay, 8-gate `run_explainability_hardening_gate`. |
| `evidence/conformance.py` | Evidence | 4-harness capability matrix, deprecation policy, 10-gate conformance suite. |
| `hooks/policy_engine.py` | Hooks | Evaluates verified packs, Pass-2 fallbacks, lifecycle dispatch. |
| `hooks/pre_tool_use.py` | Hooks | Policy API v1 passes, `range_trim`, CLI rewrites, regret tracking, telemetry. |
| `hooks/pre_invocation.py` | Hooks | Antigravity incremental `O(delta)` transcript scanner and auto-compact sensor. |
| `hooks/pre_compact.py` | Hooks | `PreCompact` / `preCompact` read-cache, `shadow_spools`, `policy_state` reset. |
| `hooks/post_tool_use.py` | Hooks | `PostToolUse` / `postToolUse` spooling, `range_trim` confirmation, `on_tool_completed`. |
| `hooks/session_end.py` | Hooks | Clears `pending_reads`, closes windows, emits session-end events. |
| `hooks/harness_adapter.py` | Hooks | Normalizes payloads (`Read`, `Bash`, `exec_command`, `apply_patch`), permissions, verdicts. |
| `hooks/read_planner.py` | Hooks | Silent `range_trim` overlap trimmer, slice caps, machine-artifact outline planner. |
| `hooks/shell_parser.py` | Hooks | Quiet CLI rewriter, `cg-outline` detector, shell-read analyzer. |
| `hooks/session_lifecycle.py` | Hooks | Checkpoint compaction (`apply_compaction_boundary`) and rewind pruning. |
| `hooks/state_store.py` | Hooks | State dir resolution, subagent isolation, locked JSON persistence. |
| `hooks/file_io.py` | Hooks | Streaming 64 KB `SHA-256` hashing (`10 MB` fallback), line counter, `tail -n`. |
| `hooks/config.py` | Hooks | Stat-keyed loader for `~/.config/context-guard/config.json`. |
| `hooks/outline.py` | Outliners | AST/regex/tree-sitter code outliner across 21 extensions (`<= 2 MB`). |
| `hooks/markup_outliners.py` | Outliners | Outliners for `.phtml`, `.vue`, `.xml`, `.md`/`.mdx`, `.diff`/`.patch`, `.json`, `.yaml`. |
| `hooks/json_outliners.py` | Outliners | Unwrappers for MCP JSON envelopes, tabular rows, `transcript*.jsonl`. |
| `hooks/telemetry.py` | Telemetry | Atomic ledger (`telemetry/stats.json`), slice estimator, daily rollup, `shadow.json`. |
| `hooks/outcomes.py` | Telemetry | `O(1)` Outcomes v4 (`outcomes.json`) for `output_spool`, `cli_rewrite`, `range_trim`. |
| `hooks/shell_output.py` | Telemetry | Extracts shell stdout/stderr, classifies command families, updates `stats.json`. |
| `hooks/model_identity.py` | Telemetry | Canonical model slugs (Antigravity, Claude, Codex) and `model_labels` overrides. |
| `bin/cg.py` | CLI | Unified `cg` dispatcher (`budget`, `doctor`, `eval`, `explain`, `export`, `status`, `spool`, `outline`, `help`). |
| `bin/cg_eval.py` | CLI | Evidence Engine CLI (`cg-eval`) for replay, `--conformance`, `--platform-matrix`, governor, `--hardening-check`. |
| `bin/cg_explain.py` | CLI | Scrubbed intervention explainer (`cg explain <event-id>`) across receipts, spools, and ledger. |
| `bin/cg_export.py` | CLI | Off-hot-path stdlib OTLP/JSON exporter (`cg export --otel`, `--ndjson`, `--endpoint`). |
| `bin/cg_budget.py` | CLI | Budget Advisor CLI (`cg-budget`) for `--preamble`, `--mcp`, `--recommendations`, `--probe`. |
| `bin/cg_status.py` | CLI | Status CLI (`--short`, `--claude-hud`, `--markdown`, `--json`, `--outcomes`, `--usage`, `--doctor`, `--replay`, `--benchmark`, `--public-json`). |
| `bin/cg_spool.py` | CLI | Spool CLI/MCP entrypoint (`cg-spool`) for `slice`, `grep`, `list`, `gc`, `mcp`. |
| `bin/mcp_inventory.py` | CLI | Passive 4-harness MCP inventory, redaction, overlap checks, `--probe` runner. |
| `bin/budget_advisor.py` | CLI | Preamble measurements, `session_profiles`, non-mutating recommendations. |
| `bin/install_harnesses.py` | CLI | Multi-harness installer (`--install`, `--uninstall`, `--status`, `--dry-run`, `--pack-source`). |
| `bin/migration_guard.py` | CLI | Staged pack transaction (`StagedPackTransaction`), rollback journal, preflight checks. |
| `bin/replay_benchmark.py` | CLI | Deterministic `--replay`, `p50`/`p95`/`p99` `--benchmark`, conditional backend eval, hygiene. |
| `bin/codex_toml.py` | CLI | Lexical TOML scanner for `~/.codex/config.toml` sync and `[mcp_servers]` discovery. |
| `bin/harness_status.py` | CLI | Cycle-free status verifier and matcher merger across Claude, Cursor, Codex. |
| `bin/outline.py` | CLI | CLI wrapper around `hooks/outline.py` (`cg-outline`). |
| `bin/instruction_block.py` | CLI | `cg`, `cg-budget`, `cg-eval`, `cg-outline`, `cg-spool` shims and rule block. |
| `bin/update_check.py` | CLI | Non-blocking `origin` tag checker (`update.json`/`install.json`, `--force`). |
| `bin/token_usage.py` | CLI | Incremental session log reader (`token_usage.json` v3) across 4 harnesses. |
| `bin/transcript_parsers.py` | CLI | Stateless record parsers and UTC day normalizer for 4-harness logs. |
| `bin/preamble_attribution.py` | CLI | Measures always-on instruction files, splits CLI/Desktop, computes `sunset_verdict`. |
| `bin/usage_report.py` | CLI | Formats real token usage, cache share, preamble breakdowns, sunset advice. |
| `bin/outcomes_report.py` | CLI | Formats Schema v4 outcomes and `"Estimated Cost Impact (non-counterfactual)"`. |
| `bin/tariffs.py` | CLI | Bundled model token tariff tables (`TARIFF_EFFECTIVE_DATE`) for cost estimates. |
| `vscode-extension/extension.js` | IDE | Status bar pill, 4s pulse, report panel, `update.lock` backoff, updater trigger. |
| `vscode-extension/view_model.js` | IDE | Telemetry normalization, v4.x insights summary, SemVer validation, CSP. |
| `vscode-extension/updater.js` | IDE | Self-updater with dirty precheck, `git reset --keep` rollback, `plugin_root.json`. |
| `vscode-extension/renderers.js` | IDE | Escaped tooltip Markdown, sidebar SVG donut HTML, dashboard report views. |
| `vscode-extension/cost_insights.js` | IDE | Formats bounded non-counterfactual cost estimates and model insights. |

---

## Installation & Multi-Harness Setup

Clone anywhere (`~/.gemini/config/plugins/context-guard` for Antigravity; `CONTEXT_GUARD_HOME` overrides):

```bash
CG_DIR=~/tools/context-guard  # or unpack dist/context-guard-v5.0.0.zip
git clone https://github.com/dpopek/context-guard.git "$CG_DIR"
python3 "$CG_DIR/bin/install_harnesses.py" --install  # hooks + advox.context-guard-statusbar-5.0.0
python3 "$CG_DIR/bin/install_harnesses.py" --status   # also: --dry-run, --pack-source <dir>, --uninstall
```

---

## CLI Reference

```bash
cg doctor --contracts --json                  # env, security & Policy API v1 contracts
cg eval --conformance                         # 10-gate suite (--platform-matrix, --offline-replay)
cg eval --hardening-check                     # 8 gates (--governor-check, --cursor-conformance, --ledger-verify, --pilot/--release --plan)
cg explain <event-id>                         # scrubbed spool lifecycle & tier (--json)
cg export --otel --output /tmp/otel.json      # off-hot-path OTLP/JSON (--ndjson, --endpoint)
cg budget --preamble --mcp --recommendations  # passive audit (--probe --probe-timeout 3)
cg status --short                             # or: cg help [cmd], cg spool list --json, cg outline <file>
python3 "$CG_DIR/bin/cg_status.py" --short    # --claude-hud, --markdown, --json, --outcomes, --usage
python3 "$CG_DIR/bin/cg_status.py" --doctor   # --replay, --benchmark, --public-json
python3 "$CG_DIR/bin/cg_status.py" --json --stats-path /tmp/stats.json --outcomes-path /tmp/outcomes.json --usage-path /tmp/token_usage.json --update-path /tmp/update.json
cg-outline path/to/file.py                    # or python3 "$CG_DIR/bin/outline.py"
cg-spool list --workspace . --json            # slice/grep (--workspace/--workspace-root, --session), gc
```

---

## Configuration Reference (`~/.config/context-guard/config.json`)

Optional (`CONTEXT_GUARD_CONFIG_PATH`). Absent = universal optimizers only; malformed = scoped fail-closed.

| Key | Default | Description |
| :--- | :--- | :--- |
| `"read_confirm_policy"` | `"strict"` | Read confirmation mode (`"strict"` or `"bounded"`). |
| `"optimizers"` | `{"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "off"}` | Modes (`active`/`shadow`/`off`; `cli_rewrites`: `auto`/`force`/`shadow`/`off`). |
| `"integrations"` | `{"atlassian_twg": "off", "cursor_spool_mcp": "off"}` | Opt-in adapters (`"atlassian_twg"`, `"cursor_spool_mcp"`: `"active"`/`"off"`). |
| `"spool"` | `{"isolation": "workspace", "max_spool_entry_bytes": 4194304}` | Spool isolation (`"workspace"`/`"session"`/`"global"`) and byte cap. |
| `"regret_window_steps"` | `2` | Positive integer regret attribution horizon across steps. |
| `"policy_packs"` | `[]` | Verified Policy API v1 packs (`file_hashes`, `tree_sha256`, `scopes`). |
| `"model_labels"` | `{}` | Harness-to-model overrides (`antigravity`, `claude`, `cursor`, `codex`). |
| `"workspace_root"` | `null` | Optional workspace root passed to `InstallerHookSpec` and packs. |
| `"repo_map_path"` | `null` | Optional repository map path exposed to verified packs. |

---

## Running Tests

```bash
mypy spool evidence hooks bin policies integrations tests
pytest tests/ -q
```

---

## Roadmap & License

See [ROADMAP.md](ROADMAP.md) (Part III) for frozen Policy API v1, 4-harness capability matrix, migrations, rollback, and `v4.5.2`–`v5.0.0` freeze details. [MIT License](LICENSE).
