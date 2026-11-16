# Context-Guard (v4.5.3)

Zero-prompt policy host, Read Ledger v2 (`range_trim`), reversible output spooling, artifact unwrapper, and telemetry plugin for **Antigravity**, **Claude Code**, **Cursor IDE**, and **OpenAI Codex** (`macOS`, `Linux`, `Windows`).

Pure Python 3.9+ stdlib hooks: `cg-outline <path>` (21 extensions, optional `tree-sitter-language-pack`), Read Ledger v2, `cg-spool` recovery, Policy API v1 packs, Outcomes v4, and `--replay` / `--benchmark`.

---

## Multi-Harness Support Matrix

| Harness | Config File | Registered Hooks | Read Caps | Compaction Integration | Live Status UI |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Antigravity** | `hooks.json` | `PreInvocation`, `PreToolUse`, `PostToolUse` | `800` lines (`45 KB`) | `O(delta)` `PreInvocation` (`80`/`200` steps) | IDE Status Bar & Side Panel |
| **Claude Code** | `~/.claude/settings.json` | `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `PreCompact`, `SessionEnd`, `statusLine` | `2,000` lines (`80 KB`) | Native `autoCompactWindow` + `PreCompact` | `statusLine` ANSI HUD |
| **Cursor IDE** | `~/.cursor/hooks.json` | `preToolUse`, `postToolUse`, `preCompact` | `2,000` lines (`80 KB`) | Native compaction + `preCompact` | IDE Status Bar & Side Panel |
| **OpenAI Codex** | `~/.codex/hooks.json` & `config.toml` | `PreToolUse`, `PostToolUse`, `PreCompact` | `Bash` / `exec_command` | `model_auto_compact_token_limit` + `PreCompact` | CLI `cg_status.py` |

---

## Machine-Artifact `AUTO-OUTLINE` & Unwrap (`PreToolUse`)

Code/Markdown reads never block; `cg-outline <path>` outlines 21 extensions on demand, while `AUTO-OUTLINE` intercepts bloated artifacts and transcripts:

| Target Type | Trigger Threshold | Action & Output |
| :--- | :--- | :--- |
| **Wrapped JSON-String MCP Envelope** (`.system_generated/steps/<N>/output.txt`) | `>= 16 KB` 1-line JSON with `"content"` | Unwraps `"content"` to sibling `<safe_name>` (`output_formatted.json` for tabular JSON); redirects follow-ups. |
| **Tabular Rows MCP** (`rows[]` JSON) | `>= 16 KB` JSON with `rows[]` | Unwraps to `output_formatted.json`; returns row count, schema, and 3-row preview. |
| **Generic JSON List/Items MCP** | `>= 16 KB` JSON array or `items`/`results`/`values` | Unwraps to `output_formatted.json`; returns item count, keys, and preview. |
| **Opt-In Integrations** (`integrations/atlassian_twg.py`) | `>= 6 KB` (`6,144` B; inline `< 6 KB`) when `"atlassian_twg": "active"` | Summarizes structured issue/doc JSON stdout and extracts plain-text content to sibling files. |
| **Conversation Transcripts** (`.system_generated/logs/transcript*.jsonl`) | `>= 16 KB` unbounded or span `> 8` lines | Streams step index (`step_index`, `type`, `tools=[...]`, byte sizes) with span markers. |

---

## Core Guard & Telemetry Layers

### 1. Read Ledger v2 & Silent `range_trim`
- Tracks 64 KB `SHA-256` hashes (`10 MB` fallback), `[StartLine, EndLine]` spans, and `confirm_tier` (`0`/`1`/`2`) in `.context_guard_state.json` (`READ_LEDGER_SCHEMA = 2`).
- **Strict Default (`spec §7.5`):** `"read_confirm_policy": "strict"` trusts only `confirm_tier == 2` (Claude `PostToolBatch`, Cursor `tool_output`); Antigravity/Codex yield `0` `range_trim` unless `"bounded"`.
- **Shadow Mode:** `"shadow"` logs counterfactual savings to `0o600` `telemetry/shadow.json` after post-tool confirmation, invalidated on edit, compaction, or rewind.

### 2. Verified Policy API v1 & Security Boundaries (`policies/api.py`, `policies/loader.py`)
- Normalizes tool/MCP calls across Antigravity (`mcp_<server>_<tool>`), Claude/Codex (`mcp__<server>__<tool>`), Cursor (`MCP:<tool>`), and `call_mcp_tool`.
- Loads verified packs from in-memory bytes (`file_hashes` + `tree_sha256`), enforcing Stage-2 scoped fail-closed fallbacks and `verify_security_policies_post_transform`.
- **Platform Fail-Closed:** Claude `>= 2.1.295` sets `"onFailure": "block"`; Cursor sets `"failClosed": true` (`NATIVE_FAIL_CLOSED_DRIFT`); Antigravity exits `2`; Codex uses `[features].hooks = true`.

### 3. Guardrailed Quiet CLI Rewrites (`PreToolUse`)

Trims noisy test/grep boilerplate without overriding explicit user flags (`-v`/`--verbose`/`--tb=long`/`--tb=full`/`--no-quiet`):

| CLI Command | Injected Flags (Antigravity `run_command`; auto-approved Claude/Cursor `Bash`/`Shell`) | Guardrails |
| :--- | :--- | :--- |
| `grep -r` / `grep -rn` | `-I --exclude-dir={...}` + minified/lock exclusions | Skipped if explicit `--include`/`--exclude` or lock/minified target is passed. |
| `pytest`, `poetry`/`uv run pytest` | `-q --tb=short --no-header` (supports `cd <dir> &&`) | Skipped if `-v`, `-q`, `--tb`, `--no-header`, `--`, or pipes are present. |
| `git status` | `-sb` (supports `cd <dir> &&`) | Skipped if flags or args are already supplied. |
| `cargo test` | `-q` (supports `cd <dir> &&`) | Skipped if verbosity flags, `--`, or pipes are present. |
| `vitest` | `--reporter=dot` | Skipped if output flags, `--`, or pipes exist. |
| Optional integrations | Registered opt-in rewriters via `integrations.*` | Disabled by default (`"integrations": {"atlassian_twg": "off", "cursor_spool_mcp": "off"}`). |

### 4. Two-Stage Auto-Compact Sensor & Multi-Harness Preamble Attribution
- Scans `transcript*.jsonl` (`O(delta)`), emitting `AUTO-COMPACT SENSOR` (`>= 80` steps or `512 KB`) and `AUTO-COMPACT HARD STOP` (`>= 200` steps or `1024 KB`).
- Splits `claude (cli)`/`(desktop)` (`mcp:ccd_*`) and `codex (cli)`/`(desktop)`, scores `Recent (10)` preamble hygiene, and computes 30-day `sunset_verdict` in `--usage`.

### 5. Reversible Output Spooling & Multi-Step Regret (`spool/store.py`, `spool/classifier.py`, `spool/receipts.py`, `spool/mcp_server.py`)
- **Opt-In Spooling:** `"output_spool": "active"` enforces UTF-8 and `max_spool_entry_bytes` (`4 MiB`), swapping outputs (`>= 12,288` B / `200` lines) for `<= 3,072` B summaries; `"shadow"` logs `shadow_spools`.
- **Non-Blocking Recovery & GC:** Holds `sp_<12hex>.txt` (`24h` TTL, `64` entries, `32 MB`) across `available`/`evicting`/`evicted`/`corrupt` states; verifies SHA-256 and unlinks outside `_spool_lock`.
- **Scoped Recovery (Logical Boundary):** `cg-spool` (`--workspace`/`--workspace-root`, `--session`) and MCP (`roots/list` + `--workspace-root`) enforce `os.path.samefile()` workspace boundaries under one OS user.
- **Receipts & Regret (`hooks/outcomes.py`):** Emits `ContextReceiptV1` (`turn_correlation`, `recovery_amplification`, `delivery_verified`) and tracks `suspected` follow-up regret reconciled on edits.

---

## Architecture & Module Inventory

Enforced by `tests/test_module_boundaries.py` and `tests/test_version_source.py`:
- **Zero Import Cycles & Slim Footprint:** `Tarjan SCC == 0`; every `.py <= 800` LOC; `hooks/*.py` total `< 6,800` LOC.
- **Lock Ordering:** Independent non-truncating locks + `os.replace` across `.context_guard_state.lock`, `stats.lock`, `outcomes.lock`, `token_usage.lock`, `receipts.lock`, `update.lock`, and `update_refresh.lock`.

| Module | Layer | Responsibility |
| :--- | :--- | :--- |
| `policies/api.py` | Policy API | `POLICY_API_VERSION = 1` contracts (`PolicyPackManifest`, `PolicyContext`, `PolicyDecision`, `InstallerHookSpec`, `SpoolContractV1`, `ContextReceiptV1`). |
| `policies/loader.py` | Policy API | Verified pack directory, `file_hashes`, and `tree_sha256` in-memory byte loader. |
| `integrations/atlassian_twg.py` | Integration | Opt-in CLI rewriter and JSON stdout summarizer (`"atlassian_twg": "active"`). |
| `spool/receipts.py` | Output Spool | Workspace `samefile` identity, config/link checks, `receipts.jsonl`, and `summarize_spool_lifecycle`. |
| `spool/store.py` | Output Spool | Write-once blobs, UTF-8/`max_spool_entry_bytes` guard, and non-blocking `slice`/`grep`/`list`/`gc`. |
| `spool/classifier.py` | Output Spool | Stateless command signatures, verbose overrides, and pre-tool spool follow-up classifier. |
| `spool/mcp_server.py` | Output Spool | Dual-framed (`Content-Length` + NDJSON) stdio MCP server (`cg_spool_*`) and atomic `.cursor/mcp.json` sync. |
| `hooks/policy_engine.py` | Hook Core | Evaluates verified packs, Pass-2 fallbacks, and lifecycle dispatch. |
| `hooks/pre_tool_use.py` | Hook Entry | Runs Policy API v1 passes, silent `range_trim`, CLI rewrites, regret tracking, and telemetry. |
| `hooks/pre_invocation.py` | Hook Entry | Antigravity incremental `O(delta)` transcript scanner, session hooks, and auto-compact sensor. |
| `hooks/pre_compact.py` | Hook Entry | `PreCompact` / `preCompact` read-cache, `shadow_spools`, and `policy_state` reset hook. |
| `hooks/post_tool_use.py` | Hook Entry | `PostToolUse` / `postToolUse` output spooling, `range_trim` confirmation, and `on_tool_completed`. |
| `hooks/session_end.py` | Hook Entry | Clears `pending_reads`, closes open windows, and emits session-end events. |
| `hooks/harness_adapter.py` | Normalization | Normalizes tool payloads (`Read`, `Bash`, `exec_command`, `apply_patch`), permission modes, and verdicts. |
| `hooks/read_planner.py` | Core Engine | Silent `range_trim` overlap trimmer, slice caps, and machine-artifact outline planner. |
| `hooks/shell_parser.py` | Core Engine | Quiet CLI flag rewriter, `cg-outline` detector, and shell-read analyzer. |
| `hooks/session_lifecycle.py` | State & Cache | Checkpoint compaction (`apply_compaction_boundary`) and rewind (`prune_state_on_rewind`) pruning. |
| `hooks/state_store.py` | State & Cache | State dir resolution (`resolve_state_dir`), subagent isolation, and locked JSON persistence. |
| `hooks/file_io.py` | State & Cache | Streaming 64 KB `SHA-256` hashing (`10 MB` fallback), line counter, and `tail -n` reader. |
| `hooks/config.py` | State & Cache | Stat-keyed loader for `~/.config/context-guard/config.json`. |
| `hooks/outline.py` | Outliners | AST/regex/tree-sitter code outliner across 21 extensions (`<= 2 MB`). |
| `hooks/markup_outliners.py` | Outliners | Outliners for `.phtml`, `.vue`, `.xml`, `.md`/`.mdx`, `.diff`/`.patch`, `.json`, `.yaml`. |
| `hooks/json_outliners.py` | Outliners | Unwrappers/summarizers for MCP JSON envelopes, tabular rows, and `transcript*.jsonl`. |
| `hooks/telemetry.py` | Telemetry | Atomic savings ledger (`telemetry/stats.json`), slice estimator, daily rollup, and `telemetry/shadow.json`. |
| `hooks/outcomes.py` | Telemetry | `O(1)` Outcomes Schema v4 ledger (`outcomes.json`) for `output_spool`, `cli_rewrite`, and `range_trim` correlation. |
| `hooks/shell_output.py` | Telemetry | Extracts shell stdout/stderr, classifies command families, and updates `stats.json`. |
| `hooks/model_identity.py` | Telemetry | Resolves canonical model slugs (Antigravity, Claude, Codex) and `model_labels` overrides. |
| `bin/cg_status.py` | CLI & UI | Status CLI (`--short`, `--claude-hud`, `--markdown`, `--json`, `--outcomes`, `--usage`, `--doctor`, `--replay`, `--benchmark`, `--public-json`). |
| `bin/cg_spool.py` | CLI & UI | CLI and stdio MCP entrypoint (`cg-spool`) for `slice`, `grep`, `list`, `gc`, and `mcp`. |
| `bin/install_harnesses.py` | CLI & UI | Multi-harness hook, MCP, and IDE installer (`--install`, `--uninstall`, `--status`, `--dry-run`, `--pack-source`). |
| `bin/migration_guard.py` | CLI & UI | Staged pack transaction (`StagedPackTransaction`), rollback journal, and migration preflight (`--pack-source`). |
| `bin/replay_benchmark.py` | CLI & UI | Deterministic `--replay`, `--benchmark`, `--public-json` exporter, and release hygiene/secret checks. |
| `bin/codex_toml.py` | CLI & UI | Lexical TOML scanner for non-destructive `~/.codex/config.toml` sync. |
| `bin/harness_status.py` | CLI & UI | Cycle-free status verifier and matcher merger across Claude Code, Cursor, and Codex configs. |
| `bin/outline.py` | CLI & UI | CLI wrapper around `hooks/outline.py` (`cg-outline`). |
| `bin/instruction_block.py` | CLI & UI | `cg-outline` + `cg-spool` shims and instruction-file rule block. |
| `bin/update_check.py` | CLI & UI | Non-blocking `origin` tag checker (`update.json` / `install.json`, `--force`). |
| `bin/token_usage.py` | CLI & UI | Incremental session log reader (`token_usage.json` v3) with model carry-over across all 4 harnesses. |
| `bin/transcript_parsers.py` | CLI & UI | Stateless record parsers and UTC day normalizer for Claude, Codex, Antigravity, and Cursor logs. |
| `bin/preamble_attribution.py` | CLI & UI | Measures always-on instruction files, separates CLI/Desktop apps, and computes `sunset_verdict`. |
| `bin/usage_report.py` | CLI & UI | Formats real token usage, cache read share, preamble breakdowns, and sunset advice. |
| `bin/outcomes_report.py` | CLI & UI | Formats Schema v4 follow-up outcomes and `"Estimated Cost Impact (non-counterfactual)"` (`1/k` step share). |
| `bin/tariffs.py` | CLI & UI | Bundled model token tariff tables (`TARIFF_EFFECTIVE_DATE`) for non-counterfactual cost estimates. |
| `vscode-extension/extension.js` | IDE Extension | Status bar pill, 4s pulse, report panel, `update.lock` backoff, and one-click updater. |
| `vscode-extension/view_model.js` | IDE Extension | Telemetry normalization, v4.x insights summarization, SemVer validation, and CSP. |
| `vscode-extension/updater.js` | IDE Extension | Self-update runner with dirty precheck, `git reset --keep` rollback, `plugin_root.json` resolver, and `probeDoctor`. |
| `vscode-extension/renderers.js` | IDE Extension | Escaped tooltip Markdown, sidebar SVG donut HTML, and dashboard report views. |
| `vscode-extension/cost_insights.js` | IDE Extension | Formats bounded non-counterfactual cost estimates and model insights. |

---

## Installation & Multi-Harness Setup

Clone anywhere (`~/.gemini/config/plugins/context-guard` for Antigravity; `CONTEXT_GUARD_HOME` overrides path):

```bash
CG_DIR=~/tools/context-guard  # or unpack dist/context-guard-v4.5.3.zip
git clone https://github.com/dpopek/context-guard.git "$CG_DIR"
python3 "$CG_DIR/bin/install_harnesses.py" --install  # hooks + advox.context-guard-statusbar-4.5.3
python3 "$CG_DIR/bin/install_harnesses.py" --status   # also: --dry-run, --pack-source <dir>, --uninstall
```

---

## CLI Reference (`cg_status.py`, `cg_spool.py` & `outline.py`)

```bash
python3 "$CG_DIR/bin/cg_status.py" --short       # also: --claude-hud, --markdown, --json, --outcomes, --usage
python3 "$CG_DIR/bin/cg_status.py" --doctor      # health check; --replay, --benchmark, --public-json
python3 "$CG_DIR/bin/cg_status.py" --json \
  --stats-path /tmp/stats.json --outcomes-path /tmp/outcomes.json \
  --usage-path /tmp/token_usage.json --update-path /tmp/update.json
cg-outline path/to/file.py                       # or python3 "$CG_DIR/bin/outline.py"
cg-spool list --workspace . --json               # or python3 "$CG_DIR/bin/cg_spool.py" list --json
cg-spool slice <spool_id> --start 1 --limit 120   # bounded recovery (--workspace/--workspace-root, --session)
cg-spool grep <spool_id> --pattern '<regex>'      # regex search (--workspace/--workspace-root, --session)
cg-spool gc --json                                # evict expired/LRU spools (evicting -> evicted)
```

---

## Configuration Reference (`~/.config/context-guard/config.json`)

Optional per-user config (override via `CONTEXT_GUARD_CONFIG_PATH`). Absent = universal optimizers only; malformed = fail closed on scoped tool calls.

| Key | Default | Description |
| :--- | :--- | :--- |
| `"read_confirm_policy"` | `"strict"` | Read confirmation mode (`"strict"` or `"bounded"`). |
| `"optimizers"` | `{"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "off"}` | Optimizer modes (`active`/`shadow`/`off`; `cli_rewrites`: `auto`/`force`/`shadow`/`off`). |
| `"integrations"` | `{"atlassian_twg": "off", "cursor_spool_mcp": "off"}` | Opt-in external/MCP adapters (`"atlassian_twg"`, `"cursor_spool_mcp"`: `"active"` or `"off"`). |
| `"spool"` | `{"isolation": "workspace", "max_spool_entry_bytes": 4194304}` | Spool isolation (`"workspace"`, `"session"`, or `"global"`) and pre-write byte cap. |
| `"regret_window_steps"` | `2` | Positive integer tracking follow-up regret attribution horizon across steps. |
| `"policy_packs"` | `[]` | Verified Policy API v1 packs pinned by `file_hashes` + `tree_sha256` and declared `scopes`. |
| `"model_labels"` | `{}` | Harness-to-model label overrides (`antigravity`, `claude`, `cursor`, `codex`) for `outcomes.json`. |
| `"workspace_root"` | `null` | Optional workspace root passed to `InstallerHookSpec` command templates and verified packs. |
| `"repo_map_path"` | `null` | Optional repository map path surfaced to external verified policy packs. |

---

## Running Tests

```bash
mypy spool hooks bin policies integrations tests
pytest tests/ -q
```

---

## Roadmap & License

See [ROADMAP.md](ROADMAP.md) for the `v4.5.2`–`v5.0.0` Architectural Freeze roadmap. Released under the [MIT License](LICENSE).
