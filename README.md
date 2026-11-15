# Context-Guard (v4.3.0)

Zero-prompt policy host, silent range-trim, machine-artifact unwrapper, and multi-harness telemetry plugin for **Google Antigravity**, **Claude Code**, **Cursor IDE**, and **OpenAI Codex CLI/App** across **macOS, Linux, and Windows**.

Combines voluntary `cg-outline <path>` structural AST outlining (`Python 3.9+` stdlib + optional `tree-sitter-language-pack`), silent `range_trim` overlap trimming, machine-artifact unwrapping, verified Policy API v1 packs, and cross-harness preamble attribution.

---

## Multi-Harness Support Matrix

| Harness | Config File | Registered Hooks | Read Caps | Compaction Integration | Live Status UI |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Antigravity** | `hooks.json` | `PreInvocation`, `PreToolUse`, `PostToolUse` | `800` lines (`45 KB`) | `O(delta)` `PreInvocation` (`80`/`200` steps) | IDE Status Bar & Side Panel |
| **Claude Code** | `~/.claude/settings.json` | `SessionStart`, `PreToolUse`, `PostToolUse`, `PreCompact`, `Stop` | `2,000` lines (`80 KB`) | Native `autoCompactWindow` + `PreCompact` | `statusLine` ANSI HUD |
| **Cursor IDE** | `~/.cursor/hooks.json` | `sessionStart`, `preToolUse`, `postToolUse`, `preCompact`, `stop` | `2,000` lines (`80 KB`) | Native compaction + `preCompact` | IDE Status Bar & Side Panel |
| **OpenAI Codex** | `~/.codex/hooks.json` & `config.toml` | `SessionStart`, `PreToolUse`, `PostToolUse`, `PreCompact`, `Stop` | `Bash` / `exec_command` | `model_auto_compact_token_limit` + `PreCompact` | CLI `cg_status.py` |

---

## Machine-Artifact `AUTO-OUTLINE` & Unwrap (`PreToolUse`)

Source code and Markdown reads never block; `cg-outline <path>` handles on-demand structural outlining across 21 extensions. `AUTO-OUTLINE` intercepts bloated machine artifacts and transcripts:

| Target Type | Trigger Threshold | Action & Output |
| :--- | :--- | :--- |
| **Wrapped JSON-String MCP Envelope** (`.system_generated/steps/<N>/output.txt`) | `>= 16 KB` 1-line JSON with `"content"` | Unwraps `"content"` to sibling `<safe_name>` (`output_formatted.json` for tabular JSON); redirects follow-ups automatically. |
| **Tabular Rows MCP** (`rows[]` JSON) | `>= 16 KB` JSON with `rows[]` | Unwraps to `output_formatted.json`; returns row count, schema, and 3-row preview. |
| **Generic JSON List/Items MCP** | `>= 16 KB` JSON array or `items`/`results`/`values` | Unwraps to `output_formatted.json`; returns item count, keys, and sample preview. |
| **Opt-In Integrations** (`integrations/atlassian_twg.py`) | `>= 6 KB` (`6,144` B; inline `< 6 KB`) when `"atlassian_twg": "active"` | Summarizes structured issue/doc JSON stdout and extracts plain-text content to sibling files. |
| **Conversation Transcripts** (`.system_generated/logs/transcript*.jsonl`) | `>= 16 KB` unbounded or span `> 8` lines | Streams step index (`step_index`, `type`, `tools=[...]`, byte sizes) with span markers. |

---

## Core Guard & Telemetry Layers

### 1. Silent `range_trim` & Rewind-Resilient Cache
- Tracks streaming 64 KB `SHA-256` hashes (`10 MB` stat fallback) and `[StartLine, EndLine]` spans in `.context_guard_state.json`.
- Silently trims partially overlapping bounded reads via `overwrite` / `updatedInput` (`range_trim`) to uncovered lines; invalidates on edits (`edit_file`, `Edit`, `StrReplace`, `apply_patch`).

### 2. Verified Policy API v1 & Two-Pass Execution (`policies/api.py`, `policies/loader.py`)
- Normalizes tool and MCP calls across Antigravity (`mcp_<server>_<tool>`), Claude/Codex (`mcp__<server>__<tool>`), Cursor (`MCP:<tool>`), and `call_mcp_tool`.
- Loads external security and optimization packs strictly from verified in-memory bytes (`file_hashes` + `tree_sha256` under trusted roots), enforcing Stage-2 scoped fail-closed fallbacks on config or pack errors.
- Pass-2 security verification (`verify_security_policies_post_transform`) re-checks pack or optimizer rewrites before allowing execution.

### 3. Lossless Quiet CLI Rewrites (`PreToolUse`)

| CLI Command | Injected Flags (Antigravity `run_command`; auto-approved Claude/Cursor `Bash`/`Shell`: `bypassPermissions`/`dontAsk`/`auto`) | Guardrails |
| :--- | :--- | :--- |
| `grep -r` / `grep -rn` | `-I --exclude-dir={...}` + minified/lock exclusions | Skipped if explicit `--include`/`--exclude` or lock/minified target is passed. |
| `pytest`, `poetry`/`uv run pytest` | `-q --tb=short --no-header` (supports `cd <dir> &&`) | Skipped if `-v`, `-q`, `--tb`, `--no-header`, `--`, or pipes are present. |
| `git status` | `-sb` (supports `cd <dir> &&`) | Skipped if flags or args are already supplied. |
| `cargo test` | `-q` (supports `cd <dir> &&`) | Skipped if verbosity flags, `--`, or pipes are present. |
| `vitest` | `--reporter=dot` | Skipped if output flags, `--`, or pipes exist. |
| Optional integrations | Registered opt-in rewriters via `integrations.*` | Disabled by default (`"integrations": {"atlassian_twg": "off"}`). |

### 4. Two-Stage Auto-Compact Sensor & Multi-Harness Preamble Attribution
- Incrementally scans `transcript.jsonl` / `transcript_full.jsonl` (`O(delta)`), injecting `AUTO-COMPACT SENSOR` (`>= 80` steps or `512 KB`) and `AUTO-COMPACT HARD STOP` (`>= 200` steps or `1024 KB`).
- Splits `claude (cli)` vs `claude (desktop)` (`mcp:ccd_*`), `codex (cli)` vs `codex (desktop)`, scores `Recent (10)` preamble hygiene, estimates Antigravity overhead, and computes 30-day `sunset_verdict` in `--usage`.

---

## Architecture & Module Inventory

Enforced by `tests/test_module_boundaries.py` and `tests/test_version_source.py`:
- **Zero Import Cycles & Slim Footprint:** `Tarjan SCC == 0`; every `.py <= 800` LOC; `hooks/*.py` total `< 6,800` LOC.
- **Lock Ordering:** Independent non-truncating file locks + atomic `os.replace` across `.context_guard_state.lock`, `stats.lock`, `outcomes.lock`, `token_usage.lock`, `update.lock`, and `update_refresh.lock`.

| Module | Layer | Responsibility |
| :--- | :--- | :--- |
| `policies/api.py` | Policy API | Public `POLICY_API_VERSION = 1` dataclasses (`PolicyPackManifest`, `PolicyContext`, `PolicyDecision`, `InstallerHookSpec`). |
| `policies/loader.py` | Policy API | Zero-TOCTOU whole-pack directory, hash, and `tree_sha256` verifier + in-memory byte loader. |
| `integrations/atlassian_twg.py` | Integration | Optional opt-in CLI rewriter and JSON stdout summarizer (`"integrations": {"atlassian_twg": "active"}`). |
| `hooks/policy_engine.py` | Hook Core | Evaluates verified packs with two-pass verification, scoped fail-closed fallbacks, and lifecycle dispatch. |
| `hooks/pre_tool_use.py` | Hook Entry | Orchestrates Policy API v1 passes, silent `range_trim`, CLI rewrites, and telemetry. |
| `hooks/pre_invocation.py` | Hook Entry | Antigravity incremental `O(delta)` transcript scanner, session transition hooks, and auto-compact sensor. |
| `hooks/pre_compact.py` | Hook Entry | Claude Code, Cursor, and Codex `PreCompact` / `preCompact` read-cache and `policy_state` reset hook. |
| `hooks/post_tool_use.py` | Hook Entry | `PostToolUse` / `postToolUse` hook measuring shell output bytes and dispatching `on_tool_completed`. |
| `hooks/session_end.py` | Hook Entry | `SessionEnd` hook clearing transient `pending_reads` state and emitting session-end policy events. |
| `hooks/harness_adapter.py` | Normalization | Normalizes tool payloads (`Read`, `Bash`, `exec_command`, `apply_patch`), permission modes, and verdicts. |
| `hooks/read_planner.py` | Core Engine | Silent `range_trim` overlap trimmer, slice caps, and machine-artifact outline planner. |
| `hooks/shell_parser.py` | Core Engine | Lossless quiet CLI flag rewriter, voluntary `cg-outline` detector, and bounded shell-read analyzer. |
| `hooks/session_lifecycle.py` | State & Cache | Checkpoint compaction (`apply_compaction_boundary`) and rewind (`prune_state_on_rewind`) pruning. |
| `hooks/state_store.py` | State & Cache | State dir resolution (`resolve_state_dir`), subagent isolation, and locked JSON persistence. |
| `hooks/file_io.py` | State & Cache | Streaming 64 KB `SHA-256` hashing (`10 MB` stat fallback), line counter, and `tail -n` reader. |
| `hooks/config.py` | State & Cache | Stat-keyed `(realpath, st_mtime_ns, st_size)` universal loader for `~/.config/context-guard/config.json`. |
| `hooks/outline.py` | Outliners | Structural AST/regex/tree-sitter code outliner across 21 file extensions (`<= 2 MB`). |
| `hooks/markup_outliners.py` | Outliners | Outliners for `.phtml`, `.vue`, `.xml`, `.md`/`.mdx` headings, `.diff`/`.patch`, `.json`, `.yaml`. |
| `hooks/json_outliners.py` | Outliners | Unwrappers/summarizers for wrapped MCP JSON envelopes, tabular rows, and `transcript*.jsonl`. |
| `hooks/telemetry.py` | Telemetry | Atomic cumulative token savings ledger (`telemetry/stats.json`), slice-byte estimator, and daily rollup. |
| `hooks/outcomes.py` | Telemetry | `O(1)` intervention outcome ledger (`outcomes.json` v3: follow-ups and bypasses) and delivered-line estimation. |
| `hooks/shell_output.py` | Telemetry | Extracts shell stdout/stderr, classifies command families, and updates `stats.json`. |
| `hooks/model_identity.py` | Telemetry | Resolves canonical model slugs (Antigravity transcript/sibling fallback, Claude, Codex) and harness `model_labels` overrides. |
| `bin/cg_status.py` | CLI & UI | Status CLI (`--short`, `--claude-hud`, `--markdown`, `--json`, `--outcomes`, `--usage`, `--doctor`). |
| `bin/install_harnesses.py` | CLI & UI | Multi-harness hook & IDE extension installer (`--install`, `--uninstall`, `--status`, `--dry-run`, `--pack-source`). |
| `bin/migration_guard.py` | CLI & UI | Staged pack transaction, rollback journal, and migration preflight safety checks (`--pack-source`). |
| `bin/codex_toml.py` | CLI & UI | Lexical TOML scanner for non-destructive `~/.codex/config.toml` sync. |
| `bin/harness_status.py` | CLI & UI | Cycle-free status verifier and dynamic matcher merger across Claude Code, Cursor, and OpenAI Codex configs. |
| `bin/outline.py` | CLI & UI | CLI wrapper around `hooks/outline.py` (`cg-outline`). |
| `bin/instruction_block.py` | CLI & UI | `cg-outline` shim and instruction-file rule block. |
| `bin/update_check.py` | CLI & UI | Non-blocking `origin` release tag checker (`update.json` / `install.json`, `--force`). |
| `bin/token_usage.py` | CLI & UI | Incremental session log reader (`token_usage.json` v3) with Antigravity cross-session model carry-over across all 4 harnesses. |
| `bin/transcript_parsers.py` | CLI & UI | Stateless record parsers and UTC day normalizer for Claude, Codex, Antigravity, and Cursor logs. |
| `bin/preamble_attribution.py` | CLI & UI | Measures always-on instruction files, separates CLI/Desktop apps, and computes `sunset_verdict`. |
| `bin/usage_report.py` | CLI & UI | Formats real token usage, cache read share, preamble breakdowns, and sunset advice. |
| `bin/outcomes_report.py` | CLI & UI | Formats per-rule follow-up outcomes and estimated delivered cost insights (`--json`, `--rules`). |
| `bin/tariffs.py` | CLI & UI | Loads bundled model token tariff tables and computes USD/saved cost estimates (`pricing_table.json`). |
| `vscode-extension/extension.js` | IDE Extension | Status bar pill, 4s pulse, report panel, `update.lock` backoff, and one-click updater. |
| `vscode-extension/view_model.js` | IDE Extension | Pure telemetry normalization, v4.x insights summarization, SemVer validation, and CSP. |
| `vscode-extension/updater.js` | IDE Extension | Self-update runner, `plugin_root.json` resolver, and harness `probeDoctor`. |
| `vscode-extension/renderers.js` | IDE Extension | Escaped tooltip Markdown, sidebar SVG donut HTML, and dashboard report views. |
| `vscode-extension/cost_insights.js` | IDE Extension | Summarizes and formats cost savings and model attribution insights for extension views. |

---

## Installation & Multi-Harness Setup

Context-Guard runs from wherever you clone it: the installer points every harness hook at that checkout. Pick any directory; `~/.gemini` is needed only if you use Antigravity.

```bash
# 1. Clone anywhere (or unpack dist/context-guard-v4.3.0.zip there)
CG_DIR=~/tools/context-guard
git clone https://github.com/dpopek/context-guard.git "$CG_DIR"

# 2. Install hooks (Claude Code, Codex, Cursor, Antigravity) & advox.context-guard-statusbar-4.3.0 extension
python3 "$CG_DIR/bin/install_harnesses.py" --install

# Check status, preview dry-run, stage verified policy packs, or uninstall cleanly
python3 "$CG_DIR/bin/install_harnesses.py" --status
python3 "$CG_DIR/bin/install_harnesses.py" --install --dry-run
python3 "$CG_DIR/bin/install_harnesses.py" --install --pack-source /path/to/policy-packs
python3 "$CG_DIR/bin/install_harnesses.py" --uninstall
```

- **Antigravity users:** clone into Antigravity's plugin directory instead (`CG_DIR=~/.gemini/config/plugins/context-guard`) so Antigravity loads it as a plugin.
- **Moving the checkout:** hooks store the checkout path, so re-run `--install` after moving or re-cloning it.
- `CG_DIR` is only a shell variable for these commands; `CONTEXT_GUARD_HOME` overrides the checkout location at runtime for the installer and every hook.

---

## CLI Reference (`cg_status.py` & `outline.py`)

```bash
python3 "$CG_DIR/bin/cg_status.py" --short
python3 "$CG_DIR/bin/cg_status.py" --claude-hud
python3 "$CG_DIR/bin/cg_status.py" --markdown
python3 "$CG_DIR/bin/cg_status.py" --json
python3 "$CG_DIR/bin/cg_status.py" --outcomes
python3 "$CG_DIR/bin/cg_status.py" --usage
python3 "$CG_DIR/bin/cg_status.py" --doctor
python3 "$CG_DIR/bin/cg_status.py" --json \
  --stats-path /tmp/stats.json --outcomes-path /tmp/outcomes.json \
  --usage-path /tmp/token_usage.json --update-path /tmp/update.json
cg-outline path/to/file.py  # or python3 "$CG_DIR/bin/outline.py"
```

---

## Configuration Reference (`~/.config/context-guard/config.json`)

Optional per-user config (override via `CONTEXT_GUARD_CONFIG_PATH`). Absent = default universal optimizers only; malformed = fail closed on scoped tool calls.

| Key | Default | Description |
| :--- | :--- | :--- |
| `"read_confirm_policy"` | `"strict"` | Read confirmation mode (`"strict"` or `"bounded"`). |
| `"optimizers"` | `{"range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto", "output_spool": "off"}` | Optimizer modes (`active`/`shadow`/`off`; `cli_rewrites`: `auto`/`force`/`off`). |
| `"integrations"` | `{"atlassian_twg": "off"}` | Opt-in external CLI/artifact integration adapters (`active` or `off`). |
| `"regret_window_steps"` | `2` | Positive integer tracking follow-up regret attribution horizon across steps. |
| `"policy_packs"` | `[]` | Verified Policy API v1 packs pinned by `file_hashes` + `tree_sha256` and declared `scopes`. |
| `"model_labels"` | `{}` | Mapping of harness keys (`antigravity`, `claude`, `cursor`, `codex`) to pinned model labels for `outcomes.json` reports. |
| `"workspace_root"` | `null` | Optional workspace root passed to `InstallerHookSpec` command templates and verified packs. |
| `"repo_map_path"` | `null` | Optional repository map path surfaced to external verified policy packs. |

---

## Running Tests

```bash
mypy hooks bin policies integrations tests
pytest tests/ -q
```

---

## License

Released under the [MIT License](LICENSE).
