# Context-Guard (v4.1.2)

Zero-prompt security guard, silent range-trim, machine-artifact unwrapper, and multi-harness telemetry plugin for **Google Antigravity**, **Claude Code**, **Cursor IDE**, and **OpenAI Codex CLI/App** across **macOS, Linux, and Windows**.

Combines voluntary `cg-outline <path>` structural AST outlining (`Python 3.9+` stdlib + optional `tree-sitter-language-pack`), silent `range_trim` overlap trimming, machine-artifact unwrapping, fail-closed BigQuery/GitLab/Governance guards, and cross-harness preamble attribution.

---

## Multi-Harness Support Matrix

| Harness | Config File | Registered Hooks | Read Caps | Compaction Integration | Live Status UI |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Antigravity** | `hooks.json` | `PreInvocation`, `PreToolUse` | `800` lines (`45 KB`) | `O(delta)` `PreInvocation` (`80`/`200` steps) | IDE Status Bar & Side Panel |
| **Claude Code** | `~/.claude/settings.json` | `SessionStart`, `PreToolUse`, `PostToolUse`, `PreCompact`, `Stop` | `2,000` lines (`80 KB`) | Native `autoCompactWindow` + `PreCompact` | `statusLine` ANSI HUD |
| **Cursor IDE** | `~/.cursor/hooks.json` | `sessionStart`, `preToolUse`, `postToolUse`, `preCompact`, `stop` | `2,000` lines (`80 KB`) | Native compaction + `preCompact` | IDE Status Bar & Side Panel |
| **OpenAI Codex** | `~/.codex/hooks.json` & `config.toml` | `SessionStart`, `PreToolUse`, `PostToolUse`, `PreCompact`, `Stop` | `Bash` / `exec_command` | `model_auto_compact_token_limit` + `PreCompact` | CLI `cg_status.py` |

---

## Machine-Artifact `AUTO-OUTLINE` & Unwrap (`PreToolUse`)

Source code and Markdown reads never block; `cg-outline <path>` handles on-demand structural outlining across 21 extensions. `AUTO-OUTLINE` intercepts only bloated machine artifacts:

| Target Type | Trigger Threshold | Action & Output |
| :--- | :--- | :--- |
| **GitLab `get_file_contents` MCP** (`.system_generated/steps/<N>/output.txt`) | `>= 16 KB` 1-line JSON envelope | Unwraps `"content"` to `output_unwrapped.<ext>`; redirects follow-ups automatically. |
| **BigQuery Tabular MCP** (`execute_sql*`, `get_query_results`) | `>= 16 KB` JSON with `rows[]` | Unwraps to `output_formatted.json`; returns row count, schema, and 3-row preview. |
| **Generic JSON List/Items MCP** | `>= 16 KB` JSON array or `items`/`results`/`values` | Unwraps to `output_formatted.json`; returns item count, keys, and sample preview. |
| **TWG Jira & Confluence** (`/twg/*/stdout.json`, `stdout.compact.json`) | `>= 6 KB` (`6,144` B; inline `< 6 KB`) | Summarizes issues/fields (`required=True` first) and extracts ADF plain text to sibling file. |
| **Conversation Transcripts** (`.system_generated/logs/transcript*.jsonl`) | `>= 16 KB` unbounded or span `> 8` lines | Streams step index (`step_index`, `type`, `tools=[...]`, byte sizes) with span markers. |

---

## Core Guard & Telemetry Layers

### 1. Silent `range_trim` & Rewind-Resilient Cache
- Tracks streaming 64 KB `SHA-256` hashes (`10 MB` stat fallback) and `[StartLine, EndLine]` spans in `.context_guard_state.json`.
- Silently trims partially overlapping bounded reads via `overwrite` / `updatedInput` (`range_trim`) to uncovered lines; invalidates on edits (`edit_file`, `Edit`, `StrReplace`, `apply_patch`).

### 2. Fail-Closed Local-First GitLab, BigQuery & Governance Guards
- Normalizes MCP calls across Antigravity (`mcp_<server>_<tool>`), Claude/Codex (`mcp__<server>__<tool>`), Cursor (`MCP:<tool>`), and `call_mcp_tool`.
- Blocks remote GitLab lookups on first attempt when `repo_map_path` resolves locally; hard-blocks `restricted_bq_datasets` across MCP, `bq`, and Python SDK in favor of `allowed_bq_views_dataset`.
- Opt-in `enforce_governance_policy` blocks governance tampering, git hook/env bypasses (`--no-verify`, `HUSKY=0`, `core.hooksPath`), and mass staging, while recording `mutated_repos` for file writes.

### 3. Lossless Quiet CLI Rewrites (`PreToolUse`)

| CLI Command | Injected Flags (Antigravity `run_command`; auto-approved Claude/Cursor `Bash`/`Shell`: `bypassPermissions`/`dontAsk`/`auto`) | Guardrails |
| :--- | :--- | :--- |
| `grep -r` / `grep -rn` | `-I --exclude-dir={...}` + minified/lock exclusions | Skipped if explicit `--include`/`--exclude` or lock/minified target is passed. |
| `twg <subcommand>` | Strips `TWG_AGENT_DEFAULTS=1` / `~/.local/bin/twg` -> `twg` | Preserves single-quoted `'...'` args. |
| `pytest`, `poetry`/`uv run pytest` | `-q --tb=short --no-header` (supports `cd <dir> &&`) | Skipped if `-v`, `-q`, `--tb`, `--no-header`, `--`, or pipes are present. |
| `git status` | `-sb` (supports `cd <dir> &&`) | Skipped if flags or args are already supplied. |
| `cargo test` | `-q` (supports `cd <dir> &&`) | Skipped if verbosity flags, `--`, or pipes are present. |
| `vitest` | `--reporter=dot` | Skipped if output flags, `--`, or pipes exist. |

### 4. Two-Stage Auto-Compact Sensor & Multi-Harness Preamble Attribution
- Incrementally scans `transcript.jsonl` / `transcript_full.jsonl` (`O(delta)`), injecting `AUTO-COMPACT SENSOR` (`>= 80` steps or `512 KB`) and `AUTO-COMPACT HARD STOP` (`>= 200` steps or `1024 KB`).
- Splits `claude (cli)` vs `claude (desktop)` (`mcp:ccd_*`), `codex (cli)` vs `codex (desktop)`, estimates Antigravity filesystem preamble overhead, excludes subagents, and computes 30-day `sunset_verdict` in `--usage`.

---

## Architecture & Module Inventory

Enforced by `tests/test_module_boundaries.py` and `tests/test_version_source.py`:
- **Zero Import Cycles & Slim Footprint:** `Tarjan SCC == 0`; every `.py <= 800` LOC; `hooks/*.py` total `< 6,800` LOC.
- **Lock Ordering:** Independent non-truncating file locks + atomic `os.replace` across `.context_guard_state.lock`, `stats.lock`, `outcomes.lock`, `token_usage.lock`, `update.lock`, and `update_refresh.lock`.

| Module | Layer | Responsibility |
| :--- | :--- | :--- |
| `hooks/pre_tool_use.py` | Hook Entry | Orchestrates fail-closed guards, silent `range_trim`, CLI rewrites, and telemetry. |
| `hooks/pre_invocation.py` | Hook Entry | Antigravity incremental `O(delta)` transcript scanner and two-stage auto-compact sensor. |
| `hooks/pre_compact.py` | Hook Entry | Claude Code, Cursor, and Codex `PreCompact` / `preCompact` read-cache reset hook. |
| `hooks/post_tool_use.py` | Hook Entry | `PostToolUse` / `postToolUse` hook recording shell output bytes and token usage. |
| `hooks/harness_adapter.py` | Normalization | Normalizes tool payloads (`Read`, `Bash`, `exec_command`, `apply_patch`), permission modes, and verdicts. |
| `hooks/read_planner.py` | Core Engine | Silent `range_trim` overlap trimmer, slice caps, and machine-artifact outline planner. |
| `hooks/shell_parser.py` | Core Engine | Lossless quiet CLI flag rewriter, voluntary `cg-outline` detector, and bounded shell-read analyzer. |
| `hooks/local_repo_guard.py` | Core Engine | Local-First GitLab lookup guard and hard BigQuery `ai_views` dataset enforcement. |
| `hooks/governance_guard.py` | Core Engine | Governance path guard, git/env bypass blocker, shell/SDK BigQuery gate, and `mutated_repos`. |
| `hooks/session_lifecycle.py` | State & Cache | Checkpoint compaction (`apply_compaction_boundary`) and rewind (`prune_state_on_rewind`) pruning. |
| `hooks/state_store.py` | State & Cache | State dir resolution (`resolve_state_dir`), subagent isolation, and locked JSON persistence. |
| `hooks/file_io.py` | State & Cache | Streaming 64 KB `SHA-256` hashing (`10 MB` stat fallback), line counter, and `tail -n` reader. |
| `hooks/config.py` | State & Cache | Stat-keyed `(realpath, st_mtime_ns, st_size)` loader for `~/.config/context-guard/config.json`. |
| `hooks/outline.py` | Outliners | Structural AST/regex/tree-sitter code outliner across 21 file extensions (`<= 2 MB`). |
| `hooks/markup_outliners.py` | Outliners | Outliners for `.phtml`, `.vue`, `.xml`, `.md`/`.mdx` headings, `.diff`/`.patch`, `.json`, `.yaml`. |
| `hooks/json_outliners.py` | Outliners | Unwrappers/summarizers for MCP `output.txt`, TWG `stdout*.json`, and `transcript*.jsonl`. |
| `hooks/telemetry.py` | Telemetry | Atomic cumulative token savings ledger (`telemetry/stats.json`), slice-byte estimator, and daily rollup. |
| `hooks/outcomes.py` | Telemetry | `O(1)` intervention outcome ledger (`outcomes.json` v3: follow-ups and bypasses) and delivered-line estimation. |
| `hooks/shell_output.py` | Telemetry | Extracts shell stdout/stderr, classifies command families, and updates `stats.json`. |
| `hooks/model_identity.py` | Telemetry | Resolves canonical model slugs (Antigravity transcript/sibling fallback, Claude, Codex) and harness `model_labels` overrides. |
| `bin/cg_status.py` | CLI & UI | Status CLI (`--short`, `--claude-hud`, `--markdown`, `--json`, `--outcomes`, `--usage`, `--doctor`). |
| `bin/install_harnesses.py` | CLI & UI | Multi-harness hook & IDE extension installer (`--install`, `--uninstall`, `--status`, `--dry-run`). |
| `bin/harness_status.py` | CLI & UI | Cycle-free status verifier across Claude Code, Cursor, and OpenAI Codex configs. |
| `bin/outline.py` | CLI & UI | CLI wrapper around `hooks/outline.py` (`cg-outline`). |
| `bin/instruction_block.py` | CLI & UI | `cg-outline` shim and instruction-file rule block. |
| `bin/update_check.py` | CLI & UI | Non-blocking `origin` release tag checker (`update.json` / `install.json`, `--force`). |
| `bin/token_usage.py` | CLI & UI | Incremental session log reader (`token_usage.json` v3) with Antigravity cross-session model carry-over across all 4 harnesses. |
| `bin/transcript_parsers.py` | CLI & UI | Stateless record parsers and UTC day normalizer for Claude, Codex, Antigravity, and Cursor logs. |
| `bin/preamble_attribution.py` | CLI & UI | Measures always-on instruction files, separates CLI/Desktop apps, and computes `sunset_verdict`. |
| `bin/usage_report.py` | CLI & UI | Formats real token usage, cache read share, preamble breakdowns, and sunset advice. |
| `vscode-extension/extension.js` | IDE Extension | Status bar pill, 4s pulse, report panel, `update.lock` backoff, and one-click updater. |
| `vscode-extension/view_model.js` | IDE Extension | Pure telemetry normalization, SemVer validation, and CSP. |

---

## Installation & Multi-Harness Setup

```bash
# 1. Clone into Antigravity Plugins Directory (or unpack dist/context-guard-v4.1.2.zip)
git clone https://github.com/dpopek/context-guard.git ~/.gemini/config/plugins/context-guard

# 2. Install hooks & advox.context-guard-statusbar-4.1.2 extension across all harnesses
python3 ~/.gemini/config/plugins/context-guard/bin/install_harnesses.py --install

# Check status, preview dry-run, or uninstall cleanly
python3 ~/.gemini/config/plugins/context-guard/bin/install_harnesses.py --status
python3 ~/.gemini/config/plugins/context-guard/bin/install_harnesses.py --install --dry-run
python3 ~/.gemini/config/plugins/context-guard/bin/install_harnesses.py --uninstall
```

---

## CLI Reference (`cg_status.py` & `outline.py`)

```bash
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --short
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --claude-hud
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --markdown
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --json
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --outcomes
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --usage
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --doctor
python3 ~/.gemini/config/plugins/context-guard/bin/cg_status.py --json \
  --stats-path /tmp/stats.json --outcomes-path /tmp/outcomes.json \
  --usage-path /tmp/token_usage.json --update-path /tmp/update.json
cg-outline path/to/file.py  # or python3 .../bin/outline.py
```

---

## Configuration Reference (`~/.config/context-guard/config.json`)

Optional per-user config (override via `CONTEXT_GUARD_CONFIG_PATH`). Absent = MCP guards disabled; malformed = fail closed.

| Key | Default | Description |
| :--- | :--- | :--- |
| `"workspace_root"` | `null` | Root workspace path for `repo_map_path`, `mutated_repos`, and `SessionStart`/`Stop` guard wiring. |
| `"repo_map_path"` | `null` | Path to `local_repository_map.json` for Local-First GitLab MCP interception. |
| `"repo_map_doc"` | `"docs/local_repository_map.md"` | Repository map path cited in GitLab block messages. |
| `"restricted_bq_datasets"` | `[]` | Raw BigQuery datasets hard-blocked across MCP, `bq` CLI, and Python SDK. |
| `"allowed_bq_views_dataset"` | `""` | Authorized BigQuery dataset permitted without restriction. |
| `"allowed_bq_views_hint"` | `"authorized views"` | Dataset pattern shown in BigQuery block messages. |
| `"bq_schema_doc"` | `""` | Schema doc path cited in BigQuery block messages. |
| `"allow_bq_raw_ddl_maintenance"` | `false` | Operator boolean allowing raw BigQuery DDL/queries when `true` (non-bool fails closed). |
| `"enforce_governance_policy"` | `false` | Opt-in boolean enabling governance path, git hook/env bypass, and mass-staging blocks. |
| `"allow_governance_mutations"` | `false` | Operator boolean allowing edits/writes to governance, hook, and baseline paths. |
| `"model_labels"` | `{}` | Mapping of harness keys (`antigravity`, `claude`, `cursor`, `codex`) to pinned model labels for `outcomes.json` reports. |

---

## Running Tests

```bash
mypy hooks bin tests
pytest tests/ -q
```

---

## License

Released under the [MIT License](LICENSE).
