# Context-Guard (v5.2.0)

Zero-prompt Policy API v1 reliability platform, Read Ledger v2 (`range_trim`), reversible output spooler, artifact unwrapper, budget advisor, Evidence Engine, Adaptive Governor, and off-hot-path OTel exporter for **Antigravity**, **Claude Code**, **Cursor IDE**, and **OpenAI Codex** (`macOS`, `Linux`, `Windows`).

Pure Python 3.9+ stdlib 8-layer DAG: `cg-outline` (21 extensions, optional `tree-sitter-language-pack`), `policy_packs`, `cg-spool`, Outcomes v4, `cg doctor`, `cg budget`, `cg eval`, `cg explain`, and `cg export --otel`.

## Multi-Harness Support Matrix

| Harness | Config | Hooks | Read Caps | Compaction | Status UI |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Antigravity** | `hooks.json` | `PreInvocation`, `PreToolUse`, `PostToolUse` | `800` L (`45 KB`) | `O(delta)` `PreInvocation` (`80`/`200`) | IDE Bar & Panel |
| **Claude Code** | `~/.claude/settings.json` | `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `PreCompact`, `SessionEnd`, `statusLine` | `2,000` L (`80 KB`) | `autoCompactWindow` + `PreCompact` | `statusLine` HUD |
| **Cursor IDE** | `~/.cursor/hooks.json` | `preToolUse`, `postToolUse`, `preCompact` | `2,000` L (`80 KB`) | Native + `preCompact` | IDE Bar & Panel |
| **OpenAI Codex** | `~/.codex/hooks.json`, `config.toml` | `PreToolUse`, `PostToolUse`, `PreCompact` | `Bash` / `exec_command` | `model_auto_compact_token_limit` + `PreCompact` | `cg_status.py` |

## Machine-Artifact `AUTO-OUTLINE` & Unwrap (`PreToolUse`)

Code/Markdown reads never block; `cg-outline <path>` covers 21 extensions, and `AUTO-OUTLINE` unwraps bloated artifacts:

| Target | Trigger | Action |
| :--- | :--- | :--- |
| **Wrapped JSON MCP** (`.system_generated/steps/<N>/output.txt`) | `>= 16 KB` 1-line `"content"` | Unwraps `"content"` (`output_formatted.json` for tables); redirects reads. |
| **Tabular Rows MCP** (`rows[]`) | `>= 16 KB` JSON `rows[]` | Unwraps to `output_formatted.json`; returns count, schema, 3-row preview. |
| **Generic JSON List/Items** | `>= 16 KB` array or `items`/`results`/`values` | Unwraps to `output_formatted.json`; returns count, keys, preview. |
| **Integrations** (`integrations/atlassian_twg.py`) | `>= 6 KB` when `"atlassian_twg": "active"` | Summarizes issue/doc JSON and extracts text to sibling files. |
| **Transcripts** (`.system_generated/logs/transcript*.jsonl`) | `>= 16 KB` unbounded or `> 8` L | Streams step index (`step_index`, `type`, `tools=[...]`, bytes). |

## Core Guard & Telemetry Layers

### 1. Read Ledger v2 & Silent `range_trim`
- Tracks 64 KB `SHA-256` hashes (`10 MB` cap), `[StartLine, EndLine]`, and `confirm_tier` (`0`/`1`/`2`) in `.context_guard_state.json` (`READ_LEDGER_SCHEMA = 2`) with TOCTOU verification.
- **Strict Default:** `"read_confirm_policy": "strict"` trusts `confirm_tier == 2` only (Claude `PostToolBatch`, Cursor `tool_output`); Antigravity/Codex require `"bounded"`.
- **Shadow Mode:** `"shadow"` logs counterfactual savings to `0o600` `telemetry/shadow.json`, invalidated on edit, compaction, or rewind.

### 2. Verified Policy API v1 & Security (`policies/api.py`, `policies/loader.py`)
- Normalizes MCP calls across Antigravity (`mcp_<server>_<tool>`), Claude/Codex (`mcp__<server>__<tool>`), Cursor (`MCP:<tool>`), and `call_mcp_tool`.
- Loads verified packs from memory (`file_hashes` + `tree_sha256`) with Stage-2 scoped canonicalized fallbacks and `verify_security_policies_post_transform`.
- **Repeat-Block Escalation (`policies/repeat_deny.py`):** A second same-rule pack deny within 600 s tells the agent to stop and report to the operator (skips retry-to-proceed denies; fail-open).
- **Fail-Closed:** Claude `>= 2.1.295` `"onFailure": "block"`; Cursor `"failClosed": true` (`NATIVE_FAIL_CLOSED_DRIFT`); Antigravity `exit 2`; Codex `[features].hooks = true`.

### 3. Guardrailed Quiet CLI Rewrites (`PreToolUse`)

Trims noisy test/grep boilerplate unless verbosity flags (`-v`/`--verbose`/`--tb=long`/`--tb=full`/`--no-quiet`) are present:

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
- **Budget Advisor (`cg budget`):** Audits preambles and MCPs read-only (`measured`/`estimated`/`unavailable`); `--probe` runs opt-in stdio `tools/list`.

### 5. Reversible Output Spooling & Regret (`spool/`)
- **Opt-In Spooling:** `"output_spool": "active"` (UTF-8, `max_spool_entry_bytes` `4 MiB`) swaps `>= 12,288` B / `200`-line shell (MCP: bytes only) outputs for `<= 3,072` B summaries (`"shadow"` logs `shadow_spools`).
- **Recovery & GC:** Stores `sp_<12hex>.txt` (raw `source_sha256` + `blob_sha256`, `24h`/`64`/`32 MB` GC) across `available`/`evicting`/`evicted`/`corrupt`; checks fd SHA-256 and unlinks off-lock.
- **Scoped Access & Spans:** `cg-spool`/MCP (`--workspace-root`) enforce `os.path.samefile()`; `spool/spans.py` tracks grep spans, source digests, verified turns, and `complete`/`incomplete` `ContextReceiptV1`.

### 6. Evidence, Governor, Hardening & Conformance (`evidence/`, `services/`, `bin/`)
- **Ledger, Outcomes & Governor:** Deduplicates `evidence_events.json`, resolves verified spool outcomes, enforces `plan_completeness` / `uncertainty_proof_ok` and `_static_capability_ceiling`, and trips breakers.
- **Explain, OTel & Hardening:** `cg explain <event-id>` inspects `ExplainContractV1` lifecycles; `cg export --otel` emits parent-linked per-signal OTLP/HTTP (`partialSuccess`); `--hardening-check` runs 8 gates.
- **Platform & Conformance:** Freezes `POLICY_API_VERSION = 1` + 17 `CORE_SCHEMA_VERSIONS`; `--contracts`, `--conformance` & `--platform-matrix` verify 10 gates (`offline_benchmarks_included`, `adapter_contract_only`).

## Architecture & Module Inventory

Enforced by `tests/test_module_boundaries.py` and `tests/test_version_source.py`:
- **8-Layer DAG:** `Tarjan File/Package SCC == 0` (`core` -> `policies` -> `spool`/`integrations` -> `hooks` -> `services` -> `evidence` -> `bin`).
- **Hygiene & Ceilings:** `0` prod `assert`s/`X as X`, `.py <= 800` LOC (`bin/* <= 350`), `hooks/*.py < 6,800` LOC, independent locks + `os.replace`.

| Module | Layer | Responsibility |
| :--- | :--- | :--- |
| `core/platform_io.py` | Core | Cross-OS `flock`, atomic I/O, quarantine, `warn`. |
| `core/contracts.py` | Core | `HARNESS_CAPABILITIES`, `PendingRead`, `PlannerMeta`, `SpoolDecision`. |
| `core/scrub.py` | Core | Canonical PII, path, domain, artifact scrubber. |
| `core/shell_lexer.py` | Core | Shell prep, segmentation, tokenization, unwrapping. |
| `policies/api.py` | Policy | `POLICY_API_VERSION = 1`, `CORE_SCHEMA_VERSIONS`, contracts. |
| `policies/governor.py` | Policy | Governor modes, static ceilings, state path, breakers. |
| `policies/loader.py` | Policy | Verified pack loader (`file_hashes`, `tree_sha256`). |
| `policies/repeat_deny.py` | Policy | Session-scoped repeat-deny escalation note (fail-open). |
| `spool/receipts.py` | Spool | Workspace `samefile`, link checks, `receipts.jsonl`. |
| `spool/store.py` | Spool | Write-once blobs, UTF-8/byte guard, fd-safe GC, inspect. |
| `spool/gc.py` | Spool | Dedup blob verification, epoch/inode GC, orphan staging. |
| `spool/spans.py` | Spool | Grep span metrics, raw source digests, verified turn keys. |
| `spool/classifier.py` | Spool | Command signatures, verbose overrides, follow-ups. |
| `spool/mcp_server.py` | Spool | Dual-framed stdio MCP and `.cursor/mcp.json` sync. |
| `integrations/atlassian_twg.py` | Integration | Opt-in CLI rewriter & JSON summarizer (`"atlassian_twg"`). |
| `hooks/policy_engine.py` | Hooks | Pack evaluation, canonical Pass-2 fallbacks, hooks. |
| `hooks/pre_tool_use.py` | Hooks | Policy passes, `range_trim`, CLI rewrites, regret. |
| `hooks/pre_invocation.py` | Hooks | Antigravity `O(delta)` scan, compact sensor, probes. |
| `hooks/pre_compact.py` | Hooks | `PreCompact` read-cache, `shadow_spools`, policy reset. |
| `hooks/post_tool_use.py` | Hooks | `PostToolUse`/`PostToolBatch` spooling, confirm, outcomes. |
| `hooks/session_end.py` | Hooks | Clears `pending_reads`, closes windows, unlocked end. |
| `hooks/harness_adapter.py` | Hooks | 4-harness payload & spool normalization (`delete_file`). |
| `hooks/read_planner.py` | Hooks | Pure `decide_file_read`, TOCTOU commits, unwrap plan. |
| `hooks/shell_parser.py` | Hooks | Quiet CLI rewriter, `cg-outline` detector, read parser. |
| `hooks/session_lifecycle.py` | Hooks | Checkpoint compaction and rewind state pruning. |
| `hooks/state_store.py` | Hooks | State dir, subagents, `StatePersistenceError`, RO. |
| `hooks/file_io.py` | Hooks | Streaming 64 KB `SHA-256` (`10 MB`), lines, `tail -n`. |
| `hooks/config.py` | Hooks | Pure stat-keyed `config.json` loader & path resolver. |
| `hooks/drift_probe.py` | Hooks | Claude CLI probe and security drift/corruption checks. |
| `hooks/outline.py` | Outliners | AST/regex/tree-sitter outliner across 21 exts (`<= 2 MB`). |
| `hooks/markup_outliners.py` | Outliners | Outliners for `.phtml`/`.vue`/`.xml`/`.md`/`.diff`/`.json`/`.yaml`. |
| `hooks/json_outliners.py` | Outliners | Unwrappers for MCP JSON envelopes, rows, transcripts. |
| `hooks/telemetry_core.py` | Telemetry | Pure core for stats, daily rollups, `shadow` state. |
| `hooks/telemetry.py` | Telemetry | Locked shell for `stats.json`, `shadow.json`, slice caps. |
| `hooks/outcomes.py` | Telemetry | `O(1)` Outcomes v4 (`outcomes.json`), `WindowAction`. |
| `hooks/shell_output.py` | Telemetry | Shell stdout/stderr extraction and `stats.json` updates. |
| `hooks/model_identity.py` | Telemetry | Canonical model slugs (AG/Claude/Codex) & labels. |
| `services/installer_service.py` | Services | Multi-harness installer/uninstaller with `RollbackJournal`. |
| `services/migration_guard.py` | Services | `StagedPackTransaction`, rollback journal, preflight. |
| `services/harness_status.py` | Services | Cycle-free status verifier and matcher merger. |
| `services/codex_toml.py` | Services | Lexical TOML scanner for `~/.codex/config.toml`. |
| `services/instruction_block.py` | Services | `cg*` PATH shims and managed instruction rule blocks. |
| `services/status_service.py` | Services | Status line, Claude HUD, Markdown/JSON, doctor. |
| `services/explain_service.py` | Services | Scrubbed intervention explainer (`ExplainContractV1`). |
| `services/export_service.py` | Services | Off-hot-path stdlib OTLP/JSON and NDJSON exporter. |
| `services/replay_benchmark.py` | Services | `--replay`, `--benchmark`, Schema v4 totals, hygiene. |
| `services/mcp_inventory.py` | Services | Passive 4-harness MCP inventory, overlaps, `--probe`. |
| `services/budget_advisor.py` | Services | Preamble measurements, `session_profiles`, advice. |
| `services/token_usage.py` | Services | Incremental log reader (`token_usage.json` v3). |
| `services/transcript_parsers.py` | Services | Stateless record parsers & UTC normalizer for 4 CLIs. |
| `services/preamble_attribution.py` | Services | Instruction sizing, CLI/Desktop split, `sunset_verdict`. |
| `services/usage_report.py` | Services | Formats token usage, cache share, preambles, sunset. |
| `services/outcomes_report.py` | Services | Outcomes v4 & `"Estimated Cost Impact (non-counterfactual)"`. |
| `services/tariffs.py` | Services | Bundled model token tariff tables (`TARIFF_EFFECTIVE_DATE`). |
| `evidence/ledger.py` | Evidence | Deduplicated `evidence_events.json`, static ceilings. |
| `evidence/metrics.py` | Evidence | `Cost per Passed Run`, noise guard, CIs, matrix plan. |
| `evidence/runner.py` | Evidence | Campaign controls, isolated executor, 8-gate check. |
| `evidence/conformance.py` | Evidence | 4-harness matrix, `replay_governor_decisions`, 10 gates. |
| `bin/cg.py` | CLI | Unified `cg` (`doctor`, `eval`, `explain`, `export`, `budget`, `status`, `spool`, `outline`, `help`). |
| `bin/cg_eval.py` | CLI | Evidence CLI (`--conformance`, `--platform-matrix`, `--hardening-check`). |
| `bin/cg_explain.py` | CLI | Thin CLI entrypoint for `cg explain <event-id>`. |
| `bin/cg_export.py` | CLI | Thin CLI entrypoint for `cg export --otel`, `--ndjson`, `--endpoint`. |
| `bin/cg_budget.py` | CLI | Budget CLI (`--preamble`, `--mcp`, `--recommendations`, `--probe`). |
| `bin/cg_status.py` | CLI | Status CLI (`--short`, `--claude-hud`, `--markdown`, `--json`, `--outcomes`, `--usage`, `--doctor`, `--replay`, `--benchmark`, `--public-json`). |
| `bin/cg_spool.py` | CLI | Spool CLI/MCP (`slice`, `grep`, `list`, `gc`, `mcp`). |
| `bin/install_harnesses.py` | CLI | Installer CLI (`--install`, `--uninstall`, `--status`, `--dry-run`, `--pack-source`). |
| `bin/outline.py` | CLI | CLI wrapper around `hooks/outline.py` (`cg-outline`). |
| `bin/update_check.py` | CLI | Non-blocking `origin` tag checker (`update.json`). |
| `vscode-extension/extension.js` | IDE | Status pill, 4s pulse, report panel, `update.lock` backoff. |
| `vscode-extension/view_model.js` | IDE | Normalization, `outputs_spooled`/`reliability_failures`, CSP. |
| `vscode-extension/updater.js` | IDE | Self-updater, dirty precheck, `git reset --keep`. |
| `vscode-extension/renderers.js` | IDE | Escaped tooltip Markdown, SVG donut HTML, reports. |
| `vscode-extension/cost_insights.js` | IDE | Bounded non-counterfactual cost estimates and insights. |

## Installation & Multi-Harness Setup

Clone anywhere (`~/.gemini/config/plugins/context-guard` for Antigravity; `CONTEXT_GUARD_HOME` overrides):

```bash
CG_DIR=~/tools/context-guard  # or unpack dist/context-guard-v5.2.0.zip
git clone https://github.com/dpopek/context-guard.git "$CG_DIR"
python3 "$CG_DIR/bin/install_harnesses.py" --install  # hooks + advox.context-guard-statusbar-5.2.0
python3 "$CG_DIR/bin/install_harnesses.py" --status   # also: --dry-run, --pack-source <dir>, --uninstall
```

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

## Running Tests

```bash
mypy core policies spool integrations hooks services evidence bin tests
pytest tests/ -q
```

## Roadmap & License

See [ROADMAP.md](ROADMAP.md) (Part III & IV) for frozen Policy API v1, 8-layer DAG, 4-harness matrix, migrations, rollback, and `v4.5.2`–`v5.2.0` details. [MIT License](LICENSE).
