# Changelog

All notable changes to **Context-Guard** are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.2.1] - 2026-11-14

### Fixed
- **IDE Codex & last-session cohorts:** Read `codex_preamble_parts` and resolve `preambleLast` to the latest cohort.
- **IDE 30d verdict parity:** Intersect common `by_day` window, count denial repeats, and use `<0.5%` threshold.
- **IDE refresh & doctor hardening:** Require `pre_tool_use.py` in `probeDoctor`, warn on failure, and guard non-numeric counts.
- **Codex preamble edge cases:** Clear tool snapshot on `tools: []` and return `{}` from `cap_parts_to_measured` if `<= 0`.

## [4.2.0] - 2026-11-14

### Added
- **Recent preamble window:** Track `Recent (10)` sliding median in `usage_report.py` and drive hygiene warnings from current sessions.
- **Modular v4.x IDE extension:** Split `vscode-extension/` into `view_model.js`, `updater.js`, `renderers.js`, and `extension.js`.
- **Dashboard & doctor insights:** Surface `Cache Hit`, `Preamble (Last)`, `Recent (10)`, `probeDoctor`, and `30d Verdict` in IDE views.

### Changed
- **IDE protection layers:** Remove legacy block/reread/reversal layers from `PROTECTION_LAYERS` while keeping label fallbacks.
- **IDE extension installer:** Bundle all non-entry `vscode-extension/*.js` modules automatically inside `install_ide_extension`.

### Fixed
- **Codex preamble attribution:** Replace repeated `additional_tools` snapshots, deduplicate message blocks, and scale overflow to measured.

## [4.1.4] - 2026-11-14

### Changed
- **Checkout-neutral docs:** Document installing from any `$CG_DIR` path in `README.md`, extension docs, and `SKILL.md`.
- **Node 24 GitHub Actions:** Upgrade `checkout`, `setup-python`, and `setup-node` to `@v7` (`node24` runtime) in `ci.yml`.

## [4.1.3] - 2026-11-14

### Fixed
- **Windows shell tokenization:** Preserve backslashes on Windows/drive paths and strip .exe/.cmd/.bat in shell_parser.
- **Windows test isolation:** Mirror HOME to USERPROFILE in test fixtures and guard NTFS-invalid filenames in tests.

### Added
- **Public push guard:** Added executable .githooks/pre-push blocking pre-orphan branches and .local emails on GitHub.

## [4.1.2] - 2026-11-14

### Added
- **MIT open-source license:** Added root `LICENSE` (`MIT`) and `"license": "MIT"` to `plugin.json` and `package.json`.

### Changed
- **Privacy leak gate:** Replaced plaintext token regex in `test_module_boundaries.py` with structural and config-driven checks.
- **Generic test fixtures:** Replaced workspace-specific fixture names in tests and `AGENTS.md` with generic public examples.

## [4.1.1] - 2026-11-14

### Added
- **Codex CLI bounded shell attribution:** Attribute `sed -n`, `head`, and `tail` follow-ups (<= 250 lines) to `targeted_followup`.
- **Multi-target `cg-outline` telemetry:** Scale `outline_pull` applied and total counts by resolved file target count.
- **Lifecycle tracking for `outline_pull`:** Stamp `outline_pull_step` for checkpoint compaction and rewind pruning.

### Fixed
- **Shell parser boundaries & safety:** Respect `;`/`&&`/`||`/`\n`/`&`, skip `<` redirections, and exclude `sed -i` from reads.
- **Oversized Antigravity sidechains:** Handle >64 KB line-1 `<SYSTEM_MESSAGE>` headers and fall back to `transcript_full.jsonl`.
- **Permission mode guard:** Protect `can_rewrite_shell_command` against `None` or non-string `permission_mode` values.
- **Documentation & skill sync:** Align `README.md`, `vscode-extension/README.md`, and `SKILL.md` with current hook behavior.

## [4.1.0] - 2026-11-13

### Added
- **Permission-safe `cli_rewrites`:** Enabled Claude/Cursor CLI rewrites in `bypassPermissions`/`dontAsk`/`auto` modes (`updatedInput`).
- **Antigravity model attribution:** Added `<USER_SETTINGS_CHANGE>` parsing, sibling fallback (skipping sidechains), and session cache.
- **Usage schema v3 (`USAGE_SCHEMA_VERSION = 3`):** Carried over `antigravity_last_model` across sessions and migrated v2 ledgers.

### Changed
- **Outcomes schema v3 (`SCHEMA_VERSION = 3`):** Replaced window coverage with O(1) follow-up, full bypass, and shell bypass telemetry.
- **7-column `cg_status.py --outcomes`:** Simplified outcomes table to show interventions, targeted follow-ups, and full/shell bypasses.
- **Stateless parsers (`bin/transcript_parsers.py`):** Extracted transcript record parsers and `parse_utc_day` from `bin/token_usage.py`.

## [4.0.2] - 2026-11-13

### Fixed
- **Schema v2 `mutated_repos` self-heal:** Purged legacy unversioned `mutated_repos` on ledger open and stamped `mutated_repos_schema: 2`.
- **Nested worktree attribution:** Isolated `.claude/.codex/.cursor/.worktrees` and ignored non-git folders in `_map_path_to_repo`.

## [4.0.1] - 2026-11-13

### Fixed
- **Antigravity MCP preamble estimate:** Counted lazy tool-name listings (skipping disabled servers), `config/AGENTS.md`, and plugin rules.
- **Usage & outcome ledger v2 migrations:** Re-folded Antigravity/Codex cursors and dropped legacy v1 `outcomes.json` denials from ROI.
- **IDE extension layer alignment:** Added `outline_pulls` to tooltip/sidebar/report views and hid zero-count retired v3.x block layers.

## [4.0.0] - 2026-11-13

### Added
- **Multi-harness preamble attribution:** Separated `codex (cli)` vs `codex (desktop)` and measured Antigravity instruction/skill overhead.
- **30-day sunset verdict:** `cg_status.py --usage` reports net token ROI and recommends keeping or retiring read optimization.
- **Sidechain exclusion:** Excluded subagent and Guardian review JSONL files from Codex token telemetry so preamble medians stay accurate.

### Changed
- **Zero-block source reads (`PreToolUse`):** Source and Markdown reads allow always while keeping silent `range_trim`.
- **Machine-artifact `AUTO-OUTLINE`:** Scoped outlining to MCP `output.txt >= 16 KB`, TWG `stdout*.json >= 6 KB`, and transcripts.
- **Hook footprint slimmed `-43%`:** Consolidated `hooks/*.py` under `6,800` LOC while preserving fail-closed security guards.

### Removed
- **Retired blocking optimizer layers:** Removed `read_policy`, `codex_shell_guard`, `shell_lexer`, `ledger_types`, and legacy config keys.

## [3.15.9] - 2026-11-13

### Fixed
- Protected `.codex/rules/` and `~/.codex/hooks/` paths in `governance_guard` against direct and shell/inline-script tampering.

## [3.15.8] - 2026-11-13

### Fixed
- **Write-only `mutated_repos`:** Restricted `record_mutated_repos_in_state` to file-write tools so shell loops never taint repo scope.

## [3.15.7] - 2026-11-12

### Added
- **Claude preamble split:** Separated `claude (cli)` and `claude (desktop)` (`mcp:ccd_*`) medians, breakdowns, and hygiene warnings.
- **Checkout telemetry warning:** `cg_status.py` warns on `stderr` when run from a checkout without `stats.json` alongside live telemetry.

## [3.15.6] - 2026-11-11

### Fixed
- **Outline accuracy (TS):** Lists accessors, generic methods and `declare` forms; spans ignore braces in parameter and return types.
- **Outline accuracy (Rust, Go, PHP):** Lifetimes no longer break block ends; bodiless Go types, PHP enums and abstract methods are listed.
- **Tree-sitter backend:** Go type declarations, PHP traits and TS abstract classes get their own range lines.

## [3.15.5] - 2026-11-11

### Added
- **Magento 1 XML outliner:** Added `<global>`, `<frontend>`, `<adminhtml>`, `<crontab>`, `<models>`, `<events>` to `outline_xml`.

### Fixed
- **Inline `open()` false positive:** Allowed read-only `open()` in inline scripts; only write modes (`w`/`a`/`+`) block.

## [3.15.4] - 2026-11-11

### Fixed
- **Windows `normcase` & hot-path I/O:** Fixed `ntpath.normcase` slash matching for `CONTEXT_GUARD_CONFIG_PATH` and skipped idle `realpath`.

## [3.15.3] - 2026-11-11

### Fixed
- **Windows repo-prefix resolution:** Stripped synthetic leading `/` before Windows drive letters (`C:/...`) in repo-scoped path checks.

## [3.15.2] - 2026-11-11

### Changed
- **Opt-in governance:** Added `enforce_governance_policy` (`false` default) so default installs never block external projects.
- **Repo-scoped paths:** Allowed `tests/baselines`, `scripts/audit`, and `scripts/hooks` in Git repos without Guard Core markers.
- **Universal rules & CLI:** Cleaned local leaks from `rules/AGENTS.md`, added root `AGENTS.md`, and dropped `npm`/`pnpm --silent`.

### Fixed
- **Inline script accuracy:** Removed false-positive `->`/`=>`/`.replace()` triggers and protected `CONTEXT_GUARD_CONFIG_PATH`.

## [3.15.1] - 2026-11-11

### Fixed
- **Worktree & SDD writes:** Narrowed `.claude`/`.codex` guards to config/hook files so `.claude/worktrees/*` and SDD dirs remain writable.
- **Data heredocs:** Stripped inert `cat`/`tee` heredoc bodies in shell guards while keeping `sh`/`bash`/`python` heredoc checks.
- **Shell variables:** Resolved `$VAR`/`${VAR}` targets and `cp` destinations so scratchpad redirects work and indirect hook writes fail.

## [3.15.0] - 2026-11-11

### Added
- **Governance guard:** Added `governance_guard.py` blocking edits, symlink writes, and shell mutations on audit/hook paths.
- **Shell bypass blocker:** Blocked `--no-verify`, `-n`, `core.hooksPath`, `HUSKY=0`, `SKIP`, `ALLOW_*`, and `git add .`/`-A`.
- **Mutated repos ledger:** Recorded workspace repos modified by edits or non-readonly commands in `state["mutated_repos"]`.
- **Operator flags:** Added fail-closed boolean keys `allow_bq_raw_ddl_maintenance` and `allow_governance_mutations`.
- **Stop-guard installer:** Wired workspace `SessionStart` and `Stop` hooks across Claude, Cursor, and Codex.

### Changed
- **Hard BigQuery gate:** Removed 2nd-attempt raw dataset bypass; enforced Zero-Trust blocks across MCP, `bq` CLI, and SDK.
- **Test diagnostics:** Rewrote `vitest` to `--reporter=dot` and left direct `jest` stderr intact without `--silent`.

### Fixed
- **Guard hardening:** Hardened subshell/brace parsing, quote escaping, git `-s`/`-u`, `GIT_CONFIG_*`, and `bq --dataset_id`.
- **Scope and readonly hardening:** Blocked `--capture-baseline`, `git -o`, `uniq` outfiles, `sed w`, and tracked inline script paths.
- **Sub-repo & Windows parity:** Stripped heredoc bodies in repo tracking and preserved Windows `Path` semantics in shim tests.

## [3.14.0] - 2026-11-11

### Added
- **Outline pull:** `cg-outline <path>` (or `outline.py`) is allowed in every harness and counted as `outline_pulls`.
- **Outline rule:** The installer adds a `cg-outline` shim and, when it is on `PATH`, a marked rule to the global instruction files.
- **Pull follow-up:** `cg_status --markdown` shows pulls per harness and whether the next read of the file was bounded or wide.

### Changed
- **Codex outline:** The Codex outline gate follows `enforcement.outline`; other Codex gates still always block.

## [3.13.3] - 2026-11-10

### Changed
- **Allow reasons:** Relaxed outlines report `below_min_bytes`, `full_text_ext` or `bounded_read`, not `unclassified`.

## [3.13.2] - 2026-11-10

### Changed
- **Prose and diffs pass:** `.md`/`.mdx`/`.diff`/`.patch` reads skip the size-threshold outline outside `block` mode.
- **No dead advisories:** `advise` acts as `off` on Antigravity and Cursor, which cannot deliver the hint.

## [3.13.1] - 2026-11-10

### Changed
- **Bounded reads pass:** Reads spanning at most `wide_followup_limit` lines skip the size-threshold outline.

## [3.13.0] - 2026-11-10

### Added
- **Enforcement modes:** Added `enforcement` (`block`/`advise`/`off`) and `outline_block_min_bytes` config keys.
- **Advisory allow:** Claude adapter emits `additionalContext` for `advice` decisions, without `permissionDecision`.

### Changed
- **Advisories by default:** Blocking read interventions are advisory or off by default; old behaviour via `enforcement`.
- **Overhead report:** `--usage` estimates the extra-turn cost of denials from real cache reads; not deducted from savings.
- **Advisories report:** `--usage` lists advisory counts in a separate row, never credited as saved.
- **Outline off by default:** Full reads below `outline_block_min_bytes` pass silently; larger files still outline.
- **Advisory re-reads:** Re-reads now allow with a hint by default.
- **Advisory shell reads:** Shell file reads now allow with a hint by default; Codex is unchanged.
- **Inline Python:** `enforcement.inline_python` defaults to `off`; its detection also matches scripts that edit files.

### Fixed
- **Read ledger:** Claude reads above 60 KB are no longer recorded as delivered; the harness rejects them.
- **CLI rewrites:** `grep` in excluded dirs, `yarn test` and `twg` with relative files are left alone; pnpm flag moved.
- **Installer:** Install and uninstall remove only Context-Guard handlers; other tools' hooks in the same group stay.
- **Codex rewrite:** Trimmed `sed` ranges expand a leading `~` instead of quoting it.

## [3.12.0] - 2026-11-09

### Added
- **Instruction-file bypass:** Bypassed `AUTO-OUTLINE` on `SKILL.md`/`AGENTS.md`/`CLAUDE.md` (`<= 400` LOC) while keeping re-read guards.
- **Expanded outliners:** Added `.html`, `.css`, `.toml`, `.sh` outliners, Markdown `[table]`/`[N code blocks]`, and Python docstrings.
- **Signed daily ledger & `savings_share`:** Added `stats.json["by_day"]`, `credited_day` reversals, and `[since, until]` common window.
- **Skill hygiene & `context-audit`:** Added `find_duplicate_skills`, `--doctor` `skill_hygiene`, `skills/context-audit`, and WCAG icons.

### Fixed
- **Canonical EOF & retry bounds:** Normalized `end_line == -1` to `total_lines` before `merge_intervals` and one-shot `reread_retry`.
- **Antigravity edit matcher & Claude Bash:** Added `replace_file_content`/`write_to_file` matchers and scoped CLI rewrites to Antigravity.
- **Phase B GitLab & UTC `_day()`:** Enforced fail-closed config vs fail-open runtime `OSError`, Python 3.9 UTC `_day()`, and model pin.

## [3.11.8] - 2026-11-09

### Added
- **Environment doctor & UX (`Etap 3B`):** Added `cg_status.py --doctor`, `normalize_line_bounds`, and CLI `sys.path` bootstrap.
- **Golden Corpus benchmark (`Etap 3C`):** Added `test_golden_corpus_benchmark.py` verifying `>= 75%` reduction across 20 fixtures.

### Changed
- **Module decomposition (`Etap 2B, 3A`):** Extracted `shell_lexer.py` and `read_policy.py`, capping all prod files at `<= 800` LOC.

## [3.11.7] - 2026-11-08

### Added
- **Multi-OS compatibility (`OS-1..OS-4`):** Windows `msvcrt.locking` fallback, XDG/APPDATA config, and GitHub Actions CI matrix.
- **Static typing & fuzzing:** Added `pyproject.toml` (`mypy` py3.9 across darwin/linux/win32), shell fuzzer, and `< 10 ms` latency gate.
- **Boundary & pre-commit hardening:** Enforced PEP 563, Python 3.9 runtime AST gates, `pre_tool_use.py <= 800` LOC, and pre-commit `mypy`.

## [3.11.6] - 2026-11-08

### Changed
- **Test suite topology (`T2, T3, T10`):** Dissolved 6 wave files into domain modules and capped every `tests/*.py` at `<= 800` LOC.
- **Contract boundaries (`T5–T9`):** Migrated all tests to `pytest`, promoted 28 public symbols, and unified `tests/helpers.py`.
- **Mechanical AST gates (`T1, T4`):** Enforced `<= 800` test LOC, zero `TestCase`, zero private `_` accesses, and mandatory assertions.

## [3.11.5] - 2026-11-08

### Fixed
- **Outcomes & lifecycle (`D1, D4, D9, D10`):** Hoisted shell I/O out of lock, guarded post-TTL credit, and unified consent bounds.
- **Outliners (`D3, D5`):** Unified `find_block_end`, achieved Tree-sitter symbol parity, and annotated BigQuery unwrap paths.
- **Shell parser (`D2, D6, D7, D8`):** Added `tail -n +K` offsets, POSIX `'...'` quotes, iterative braces, and `""`/`"|"` split fix.

## [3.11.4] - 2026-11-08

### Added
- **Extension view model (`D1, D3, D4`):** Extracted `vscode-extension/view_model.js` with all 11 counters, SemVer guard, and Webview CSP.

### Fixed
- **Extension lifecycle (`D2, D6`):** Fixed `pulseTimer` badge race, `notifyUpdateOnce` latch, singleton report, and lock backoff.
- **CLI & TOML hardening (`D5, D6, D7, D8`):** Fixed Codex `[table]` at line 0, custom `CONTEXT_GUARD_HOME`, lock fallback, and `--json`.
- **Telemetry & ledger wiring (`D9, D10`):** Fixed `NO_CREDIT` reversal, `byte_offset` on denied reads, and wired `SessionLedger`.

## [3.11.3] - 2026-11-07

### Added
- **Doc-sync & conciseness gates:** Added AST/module/flag/config sync tests (`<= 18 KB`, bullets `<= 220` chars) and `.githooks/pre-commit`.

### Changed
- **Concise README & manifest:** Restructured `README.md` (`32 KB -> 14 KB`), `vscode-extension/README.md`, and `plugin.json` into tables.

## [3.11.2] - 2026-11-07

### Changed
- **Concise headline changelog:** Reformatted `CHANGELOG.md` into scannable `- **Topic:** ...` bullets (`<= 140` chars enforced by CI test).

### Fixed
- **IDE extension `Last Updated` timestamp:** Stamped live `int(time.time() * 1000)` into `extensions.json` and installed `package.json`.

## [3.11.1] - 2026-11-07

### Fixed
- **Python 3.9 runtime compatibility:** Removed 3.10+ `@dataclass(slots=True)` args for macOS `/usr/bin/python3` GUI hook runners.
- **Compatibility guard:** Added AST and `/usr/bin/python3` subprocess smoke tests in `tests/test_py39_runtime_compat.py`.

## [3.11.0] - 2026-11-07

### Added
- **Plugin root resolution (`DEF-07`):** Unified `resolve_plugin_root()` (`CONTEXT_GUARD_HOME` + `plugin_root.json` breadcrumb).
- **Stat-keyed config cache (`DEF-11`):** Shared `(realpath, mtime_ns, size)` cache in `hooks/config.py`.
- **Architecture boundaries (`DEF-11`):** Tarjan zero-cycle (`SCC == 0`) and monolith LOC ceiling tests.

### Changed
- **Modularized hook architecture (`DEF-11`):** Extracted `file_io`, `shell_parser`, `read_planner`, `codex_shell_guard`, `harness_status`.

### Fixed
- **Concurrency step tracking (`DEF-06`):** Propagated lock-assigned `effective_step_idx` and `transcriptPath` support.
- **Non-truncating file locks (`DEF-08`):** Switched `update_check` and `token_usage` to `"a+"` `flock` with fail-open `OSError` guards.
- **Non-interactive git updates (`DEF-08`):** Defaulted `GIT_SSH_COMMAND` to `ssh -o BatchMode=yes` in IDE updater.

## [3.10.0] - 2026-11-07

### Added
- **Unified session lifecycle (`DEF-05`):** Extracted `hooks/session_lifecycle.py` for rewind and checkpoint compaction transitions.
- **Typed session ledger (`DEF-10`):** Added stdlib `@dataclass` models in `hooks/ledger_types.py` for `.context_guard_state.json`.

### Changed
- **Pure read planner (`DEF-10`):** Decoupled in-memory `plan_file_read` from deferred state mutation and disk unwrap writes.

### Fixed
- **Rewind watermark guard (`DEF-05`):** Prevented `prune_state_on_rewind` from raising `max_step_idx` on invocation rewinds.
- **Speculative unwrap prevention (`DEF-10`):** Suppressed disk writes on `<6 KB` TWG payloads and denied multi-file batches.

## [3.9.1] - 2026-11-07

### Fixed
- **BigQuery SQL guard (`DEF-01`):** Matched quoted dataset qualifiers, validated MCP prefixes, and added `NotebookRead`.
- **Non-Codex shell guard (`DEF-02`):** Blocked chained/piped/`nl`/`gsed` file reads and preserved open `shell_block` pendings.
- **`ByteOffset` bypass guard (`DEF-03`):** Required matching session `sha256` and `byte_offset >= 46,080` for continuation reads.
- **Harness slice calibration (`DEF-04`, `DEF-09`):** Capped `end_line` per harness and tracked exact `by_harness_bytes`.
- **Corrupt state quarantine (`DEF-12`):** Quarantined corrupt `.context_guard_state.json` files with `warn()` diagnostics.

## [3.9.0] - 2026-11-06

### Added
- **Codex shell brace & glob expansion:** Supported `{a,b}`, `{START..END}`, `*`, `?`, and `[...]` in `parse_shell_file_reads`.
- **Codex multi-file byte budget:** Added `codex_multi_file_max_bytes` (`16 KB` default) with bounded retry consents.

## [3.8.0] - 2026-11-05

### Added
- **Wide follow-up guard:** Added `wide_followup_limit` (`200` lines default) with multi-slot retry consents and range hints.
- **TypeScript module outlining:** Extended `AUTO-OUTLINE` to `.mts` and `.cts` files.

### Fixed
- **Read-cache & byte calibration:** Excluded binary/media files from savings and scoped subagent state under `subagents/`.

## [3.7.1] - 2026-11-03

### Fixed
- **Hook error isolation:** Wrapped telemetry and `stderr` diagnostics so pipe errors never flip `deny` decisions or exit `120`.
- **Fail-closed BigQuery gate:** Isolated mandatory BigQuery SQL guard from fail-open optimizers on corrupt `config.json`.

## [3.7.0] - 2026-11-01

### Added
- **Release update notifications:** Added git tag update badge and one-click updater in IDE status bar and Claude HUD.
- **Extension marketplace metadata:** Bundled `README.md`, `CHANGELOG.md`, and icon into installed IDE extensions.

### Changed
- **Subagent `view_file` outlining:** Enabled `AUTO-OUTLINE` for subagent `view_file` calls (`context-guard: full-reads` opts out).

## [3.6.0] - 2026-11-01

### Added
- **`PostToolUse` shell telemetry:** Measured shell output volume and potential head+tail savings across Claude, Codex, and Cursor.
- **Real token usage audit (`cg_status --usage`):** Reported transcript token usage and session preamble overhead per MCP/plugin.

### Changed
- **Honest status fallback:** Displayed `CG: n/a` on unreadable telemetry and labeled Opus USD savings as approximations.

## [3.5.0] - 2026-10-31

### Added
- **Allow-reason telemetry:** Recorded `allow_breakdown` reasons and file extensions in `stats.json` and `cg_status --markdown`.

### Fixed
- **Credit reversals:** Reversed intervention savings credit (`credit_reversals`) when an agent subsequently reads the full file.
- **Guard ledger fallback:** Prevented infinite retry loops when the GitLab or BigQuery guard ledger cannot be written.
- **Harness-aware shell hints:** Named the active harness read tool in shell file-read deny messages.

## [3.4.1] - 2026-10-31

### Fixed
- **Zero-credit rewrites:** Counted quiet CLI flag rewrites and MCP guard denies without synthetic byte credits.
- **Deterministic harness detection:** Prioritized payload fields over environment variables in `detect_harness`.

## [3.4.0] - 2026-10-31

### Added
- **Intervention outcome telemetry (`cg_status --outcomes`):** Tracked 8-step post-intervention outcomes per `harness x model`.
- **Model identity detection:** Resolved active model from Claude transcripts, Codex rollouts, and `model_labels` config.

## [3.3.2] - 2026-10-30

### Fixed
- **Codex shell chain parsing:** Supported `&&` chains, multi-range `sed -n`, benign read-only helpers, and `cd` resolution.
- **Codex top-probe outlining:** Intercepted `sed -n '1,120p'` and `head -n 120` probes on files `>250` LOC with AST outlines.
- **Markdown heading outlines:** Preserved `# Heading` symbols in `NON_SYMBOL_OUTLINE_PREFIXES`.
- **Inline Python read blocker:** Blocked heredoc (`python3 - <<'PY'`) and flagged (`-uc`) inline file reads.

## [3.3.1] - 2026-10-30

### Fixed
- **Transactional multi-file shell reads:** Evaluated multi-file Codex shell reads atomically under a single state lock.
- **Invocation watermark separation:** Preserved `max_inv_steps` across tool-side `prune_state_on_rewind` calls.
- **BigQuery DDL guard:** Blocked `CREATE VIEW` bypasses and dataset-level DDL against restricted datasets.

## [3.3.0] - 2026-10-30

### Added
- **IDE status bar live pulse:** Added compact idle badge (`$(shield)`) and 4-second green intervention pulse (`$(zap)`).
- **`Read`-before-`Edit` escape hatch:** Allowed immediate repeat `Read` of a blocked range to prevent edit deadlocks.
- **Externalized guard config:** Moved repo map and BigQuery dataset settings to `~/.config/context-guard/config.json`.

### Fixed
- **Shell rewrite safety:** Added `shlex.quote` path escaping, skipped `nl|sed` rewrites, and preserved `pytest -vv`/`--tb=long`.

## [3.2.0] - 2026-10-29

### Added
- **SVG Donut Ring side panel:** Added Activity Bar and Explorer webview panels with KPI cards and per-harness gauges.
- **Markup & data outliners:** Added `AUTO-OUTLINE` support for `.md`, `.phtml`, `.vue`, `.xml`, `.diff`, `.json`, and `.yaml`.
- **Chunk probe interception:** Outlined `offset=1, limit<=150` top-of-file probes in Claude Code and Cursor.

## [3.1.0] - 2026-10-29

### Added
- **Token savings telemetry (`stats.json`):** Added `flock`-backed cumulative byte/token savings ledger and `cg_status.py`.
- **IDE status bar extension:** Bundled `advox.context-guard-statusbar` and Claude Code `statusLine` HUD installer.

## [3.0.0] - 2026-10-29

### Added
- **Multi-harness architecture:** Unified `PreToolUse` across Antigravity, Claude Code, Cursor IDE, and OpenAI Codex.
- **Codex Smart Shell-Read:** Added `cat`/`nl`/`head`/`sed -n` interception, range trimming, and `apply_patch` invalidation.
- **Native compaction hook:** Added `hooks/pre_compact.py` for Claude Code, Cursor, and Codex cache resets.
