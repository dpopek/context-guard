# Changelog

All notable changes to **Context-Guard** are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Repeat-block escalation (`policies/repeat_deny.py`):** Same-rule pack deny within 600 s adds a stop-and-report-to-operator note.

### Changed
- **MCP spool gate (`spool/store.py`):** MCP outputs spool only at `>= 12,288` B; the `200`-line gate now applies to shell only.

## [5.2.0] - 2026-11-19

### Added
- **Spool span & turn helpers (`spool/spans.py`):** Added grep span merging, raw source hashing, turn verification, and recovery helpers.
- **Additive receipt metadata (`policies/api.py`, `spool/`):** Added optional span, context-byte, and blob digest `ContextReceiptV1` fields.

### Changed
- **Release docs sync (`README.md`, `vscode-extension/`):** Synced `v5.2.0` manifests, `spool/spans.py` inventory, and contract docs.

### Fixed
- **Grep spans & raw digests (`spool/store.py`, `spool/classifier.py`):** Hash raw bytes pre-normalization and compute merged grep spans.
- **Receipt completeness (`spool/receipts.py`, `evidence/ledger.py`):** Write rotation markers and mark missing/corrupt logs `incomplete`.
- **Per-emission spool outcomes (`hooks/`):** Key `output_spool` windows by `call_id` and resolve recovery outcomes on `PostToolUse`.
- **Campaign proof gating (`evidence/`):** Enforce `(arm, task_id, repeat_idx)` plan completeness and `uncertainty_proof_ok` checks.
- **Conformance matrix (`evidence/conformance.py`, `bin/cg_eval.py`):** Separate offline checks and mark Cursor `adapter_contract_only`.
- **OTLP correlation & export (`services/export_service.py`):** Link parent spans across turns and handle per-signal HTTP `partialSuccess`.
- **Governor config & payloads (`hooks/`, `policies/`, `evidence/`):** Keep `governor`/`dynamic_tool_mutation`, payload & provider gates.
- **Cursor MCP spool (`spool/`, `hooks/harness_adapter.py`):** Decode Cursor JSON payloads, skip errors/redacted, emit dict output.
- **Lock-free read ledger (`hooks/file_io.py`, `hooks/read_planner.py`):** Check SHA-256 pre-lock and `(dev, ino, size, mtime_ns)` in lock.
- **Boundary gate & roadmap (`tests/`, `ROADMAP.md`):** Enforce `bin/*.py <= 350` LOC ceiling and update moved `services/` references.
- **Spool dedup integrity (`spool/store.py`, `spool/gc.py`):** Verify dedup blobs off-lock, quarantine corrupt blobs, and write fresh IDs.
- **Spool GC epoch & inode (`spool/gc.py`, `spool/store.py`):** Bump `id_epoch` on prune and check `(dev, ino, mtime_ns)` before unlinking.
- **Lock-free orphan GC (`spool/gc.py`, `spool/store.py`):** Rename expired orphans under lock, unlink off-lock, and count `0 B` if missing.
- **MCP workspace pinning (`spool/mcp_server.py`, `spool/receipts.py`):** Keep `--workspace` authoritative over `roots/list` with narrowing.
- **Atomic standard install rollback (`services/`):** Disarm `RollbackJournal.commit()` before cleanup and roll back install errors.

## [5.1.0] - 2026-11-19

### Added
- **Layer 0 foundation (`core/`):** Added `platform_io.py`, `contracts.py`, `scrub.py`, and `shell_lexer.py` with zero internal imports.
- **Service layer (`services/`):** Extracted 18 off-hot-path modules (`installer`, `status`, `explain`, `export`, usage, replay).
- **Hook core & drift probe (`hooks/`):** Split pure `telemetry_core.py` functional core and `drift_probe.py` out of `config.py`.
- **8-layer DAG & AST gates (`tests/`):** Enforced package Tarjan SCC == 0, strict layer edges, zero `assert`s, and zero `X as X` facades.

### Changed
- **Thin CLI entrypoints (`bin/`):** Slimmed all 10 CLI scripts (`cg*.py`, `install_harnesses`, `outline`, `update_check`) <= 350 LOC.
- **Unified contracts (`hooks/`, `spool/`):** Consolidated `HARNESS_CAPABILITIES`, `PendingRead`, `PlannerMeta`, and shared `warn`.
- **Evidence & governor split (`evidence/`, `policies/`):** Moved `replay_governor_decisions` into `evidence/conformance.py`.
- **Extension & docs (`vscode-extension/`, `README.md`):** Added `outputs_spooled`/`reliability_failures` cards and synced `v5.1.0` docs.

### Fixed
- **Transactional read planner (`hooks/`):** Added `StatePersistenceError`, inside-lock TOCTOU checks, and read-only snapshot fallback.
- **Outcomes & shadow integrity (`hooks/`):** Fixed `step_idx=0` eviction, pipe keys, `trimmed_spans`, and bounded outline byte caps.
- **Security & lock hygiene (`hooks/`, `spool/`, `evidence/`):** Moved probes off locks, enforced `_static_ceiling`, fixed GC race.
- **Installer & CLI exit codes (`services/`, `bin/`):** Wrapped default installs in `RollbackJournal` and fixed non-zero CLI error exits.
- **CI typing & Windows portability (`core/`, `hooks/`, `tests/`):** Fixed Py3.13 mypy, drive-less `\Users\` scrub, and macOS CI jitter.

## [5.0.0] - 2026-11-18

### Added
- **Platform contracts (`policies/api.py`):** Exported `CORE_SCHEMA_VERSIONS`, `DeprecationPolicyV1`, and `ConformanceContractV1`.
- **Platform conformance (`evidence/conformance.py`):** Added 4-harness capability matrix and 10-gate adapter/pack/rollback suite.
- **Eval conformance CLI (`bin/cg_eval.py`, `ci.yml`):** Added `--conformance` and `--platform-matrix` modes plus Multi-OS CI gates.
- **Cohesive CLI help & doctor (`bin/cg.py`):** Added `cg help [cmd]` and `cg doctor` `--json`/`--markdown`/`--contracts` support.
- **Conformance & CLI tests (`tests/`):** Added `test_platform_conformance.py` and `test_cli_cohesion.py` contract test suites.
- **Platform reference (`ROADMAP.md`):** Added Part III covering CLI contracts, 4-harness matrix, migrations, rollback, and evidence.

### Changed
- **Policy API v1 freeze (`policies/`):** Synced `policies.__all__` exports and froze `POLICY_API_VERSION = 1` without SDK bloat.
- **Release docs & audit skill (`README.md`, `SKILL.md`):** Synced `v5.0.0` CLI ergonomics, conformance checks, and module docs.

## [4.9.0] - 2026-11-18

### Added
- **Explain & bench contracts (`policies/api.py`):** Exported `ExplainContractV1`, `BackendBenchmarkContractV1`, and tier/state enums.
- **Intervention explainer (`bin/cg_explain.py`, `spool/`):** Added `cg explain <event-id>` for lifecycles, evictions, and tiers.
- **Off-hot-path OTel export (`bin/cg_export.py`):** Added 100% stdlib `cg export --otel` OTLP/JSON exporter with zero prompt leaks.
- **Latency & backend eval (`bin/replay_benchmark.py`):** Added `p50`/`p95`/`p99` percentiles and conditional backend benchmark.
- **Hardening gate & CLI (`evidence/runner.py`, `bin/cg_eval.py`, `ci.yml`):** Added 8-gate `cg eval --hardening-check` and CI step.
- **Operational hardening tests (`tests/test_operational_hardening.py`):** Added 6-domain resilience and safe-migration contracts.

### Changed
- **Unified `cg` CLI (`bin/cg.py`):** Wired `explain` and `export` subcommands into the `cg` dispatcher while keeping `hooks/*` untouched.
- **Offline replay & docs (`evidence/runner.py`, `README.md`, `ROADMAP.md`):** Wired `hardening_gate_ok` and synced `v4.9.0` docs.

## [4.8.0] - 2026-11-16

### Added
- **Governor contracts (`policies/api.py`):** Exported `CapabilityContractV1`, `CircuitBreakerStateV1`, and `GovernorContractV1`.
- **Adaptive Governor (`policies/governor.py`):** Added capability attestation, fingerprint invalidation, and hysteresis breakers.
- **Governor CLI (`bin/cg_eval.py`, `ci.yml`):** Added `cg eval --governor-check` JSON/Markdown check and Multi-OS CI smoke step.

### Changed
- **Hook & spool wiring (`pre_tool_use.py`, `post_tool_use.py`, `spool/store.py`):** Wired governor modes and integrity breaker trips.
- **Evidence & docs (`evidence/runner.py`, `README.md`, `ROADMAP.md`):** Added `governor_replay_ok` check and synced `v4.8.0` docs.

## [4.7.0] - 2026-11-16

### Added
- **Evidence contracts (`policies/api.py`, `policies/__init__.py`):** Exported `EvidenceContractV1` and `CapabilityAttestationKey`.
- **Durable ledger (`evidence/ledger.py`):** Added `evidence_events.json` dedup, Outcomes v4 derivation, and Cursor conformance gate.
- **Evidence metrics (`evidence/metrics.py`):** Added `Cost per Passed Run`, noise guard, Wilson/bootstrap CIs, and matrix planner.
- **Campaign runner (`evidence/runner.py`):** Added isolated offline replay, control checks, and workspace-isolated execution.
- **Eval CLI (`bin/cg_eval.py`, `bin/cg.py`):** Added `cg eval` / `cg-eval` (`--offline-replay`, `--pilot`, `--release`).

### Changed
- **Shims & installer (`instruction_block.py`, `install_harnesses.py`):** Wired `cg-eval` shim into install, backup, and status.
- **CI & docs (`pyproject.toml`, `README.md`, `ROADMAP.md`, `SKILL.md`):** Enabled `evidence/` checks and synced `v4.7.0` docs.

## [4.6.0] - 2026-11-16

### Added
- **Unified `cg` CLI (`bin/cg.py`, `bin/instruction_block.py`):** Dispatches `budget`, `doctor`, `status`, `spool`, `outline`, and shims.
- **Passive MCP inventory (`bin/mcp_inventory.py`):** Scans 4-harness configs with redaction, overlaps, and opt-in `--probe`.
- **Budget advisor (`bin/budget_advisor.py`, `bin/cg_budget.py`):** Audits preambles, `session_profiles`, and safe advice.
- **Read-only snapshot & TOML (`token_usage.py`, `codex_toml.py`):** Added `read_usage_snapshot` and `parse_codex_mcp_servers`.
- **Bundled spool schema (`spool/mcp_server.py`):** Exported `SPOOL_MCP_TOOL_SCHEMAS` for zero-subprocess Cursor spool sizing.

### Changed
- **Installer status (`bin/install_harnesses.py`):** Wired `cg_shim` and `cg_budget_shim` into `check_status` and rollback backups.
- **Docs & audit skill (`README.md`, `ROADMAP.md`, `SKILL.md`):** Documented `cg budget`, `--probe`, and v4.6.0 modules.
- **English roadmap (`ROADMAP.md`, `AGENTS.md`):** Translated Architectural Freeze roadmap to English as canonical language.

## [4.5.3] - 2026-11-16

### Added
- **Spool classifier split (`spool/classifier.py`):** Extracted command signatures, verbose overrides, and follow-up classifier.
- **Pre-write spool cap (`hooks/config.py`, `spool/store.py`):** Added `max_spool_entry_bytes` (4 MiB) and strict UTF-8 check.
- **Symlink & alias parity (`spool/receipts.py`):** Added `same_workspace_dir` (`os.path.samefile`) and `workspace_roots` deduplication.
- **Full `ContextReceiptV1` (`policies/api.py`, `spool/receipts.py`):** Added `event_id` dedup, `turn_correlation`, and lifecycle metrics.
- **`--workspace-root` flag (`bin/cg_spool.py`, `spool/mcp_server.py`):** Added `--workspace-root` CLI alias and Cursor MCP config check.

### Changed
- **Non-blocking read/GC (`spool/store.py`):** Moved SHA-256 verification, strict UTF-8 decode, and `unlink` outside `_spool_lock`.
- **Monotonic spool states (`spool/store.py`):** Enforced `preparing`/`available`/`evicting`/`evicted` and `corrupt` without ID reuse.
- **Turn correlation hooks (`hooks/post_tool_use.py`):** Recorded `hook_duration_ms` and `turn_correlation` across `PostToolUse` spools.
- **Architectural Freeze closeout (`README.md`, `ROADMAP.md`):** Closed `INV-1`..`INV-7` and Milestone A/B gates ahead of `v4.6.0`.

### Fixed
- **Failure classification (`spool/store.py`):** Separated `format_error`, `unexpectedly_missing`, and `spool_corrupt` from evictions.
- **Windows GC retry (`spool/store.py`):** Retained `evicting` tombstones on `PermissionError`/`EBUSY` until retry unlinks the blob.

## [4.5.2] - 2026-11-16

### Added
- **`ContextReceiptV1` & receipts (`policies/api.py`, `spool/receipts.py`):** Bounded `0o600` `receipts.jsonl` with 512 KiB rotation.
- **Two-phase GC tombstones (`spool/store.py`):** Schema v2 commits up to 128 tombstones before unlinking to surface `spool_evicted`.
- **Workspace isolation (`spool/receipts.py`, `bin/cg_spool.py`):** Canonical `.git` root hashing plus `--workspace` and `--session`.
- **MCP `roots/list` handshake (`spool/mcp_server.py`):** FIFO replay queue, `list_changed` invalidation, and fail-closed scope checks.
- **Cursor `--workspace` & doctor checks (`bin/harness_status.py`, `bin/cg_status.py`):** Flags `cursor_mcp_stale` and failures.
- **Architectural Freeze roadmap (`ROADMAP.md`):** Added `v4.5.2`–`v5.0.0` roadmap, release gates, and review notes.

### Changed
- **Locked spool recovery (`spool/store.py`):** Verifies byte length, 64-hex SHA-256, and strict UTF-8 inside `spool_index.lock`.
- **Delivery evidence (`hooks/post_tool_use.py`):** Separates `replacement_emitted` from Claude `PostToolBatch` `delivery_verified`.
- **Epistemic regret downgrade (`hooks/outcomes.py`):** Downgraded 3 heuristic regret helpers from `confirmed` to `suspected`.
- **Hygiene & scrubbing (`bin/replay_benchmark.py`):** Scrubs `receipts.jsonl`, `workspace_id`, `spool_id`; emits `spool_reliability`.

### Fixed
- **Windows Python 3.9 canonicalization (`spool/receipts.py`):** Use `Path.resolve()` so absolute roots skip `os.getcwd()`.

## [4.5.1] - 2026-11-15

### Fixed
- **Multi-OS CI `mypy >= 2.0` (`ci.yml`):** Pass `--python-version ${{ matrix.python-version }}` to all 4 `mypy` runs.
- **Windows `pwsh` fail-fast (`ci.yml`):** Split static, lint, and smoke checks into single-command steps so failures abort.

## [4.5.0] - 2026-11-15

### Added
- **Reversible output spool (`spool/store.py`, `bin/cg_spool.py`):** Content-addressed blobs, head/tail summaries, and `cg-spool` CLI.
- **Stdio MCP spool (`spool/mcp_server.py`):** Exposes `cg_spool_slice`/`grep`/`list` over NDJSON/LSP and syncs Cursor `mcp.json`.
- **Multi-step regret (`hooks/outcomes.py`):** Added `output_spool`, `cli_rewrite` verbose override, and `range_trim` overlap correlation.
- **Spool telemetry & doctor (`hooks/telemetry.py`, `bin/cg_status.py`):** Added `outputs_spooled`, `shadow_spools`, and health checks.

### Changed
- **PostToolUse spooling (`hooks/post_tool_use.py`, `bin/harness_status.py`):** Sync Claude `Bash|mcp__.*` and Cursor MCP spool matchers.
- **Installer & shim sync (`bin/install_harnesses.py`, `bin/instruction_block.py`):** Manages `cg-spool` shim and `"cursor_spool_mcp"`.
- **Replay & scrubbing (`bin/replay_benchmark.py`):** Added `post_spool` / `spool_slice_recovery` steps and spool path scrubbing.
- **CI & boundary gates (`pyproject.toml`, `tests/`):** Enforced mypy, ruff, Python 3.9, and acyclic DAG checks across `spool/`.

## [4.4.1] - 2026-11-15

### Changed
- **Benchmark latency split (`bin/replay_benchmark.py`):** Separated in-process engine vs subprocess `PreToolUse` E2E latency.
- **Shadow Mode (`hooks/pre_tool_use.py`, `hooks/post_tool_use.py`):** Record `shadow.json` slices after post-tool confirmation.
- **Docs (`README.md`):** Renamed `Lossless` to `Guardrailed Quiet CLI Rewrites`; clarified `--benchmark` and Shadow Mode.

### Fixed
- **Legacy domain guard (`hooks/policy_engine.py`):** Check security pack `covered_domains` against `legacy_security_keys`.
- **Reversible IDE cleanup (`bin/migration_guard.py`):** Stage old extension removals in `RollbackJournal` for `install_harnesses.py`.

## [4.4.0] - 2026-11-15

### Added
- **Policy API v1 (`policies/api.py`, `policies/loader.py`):** Zero-TOCTOU in-memory byte loader verifying `file_hashes` and `tree_sha256`.
- **Transactional migration (`bin/migration_guard.py`):** Added `StagedPackTransaction`, rollback journal, and `--pack-source`.
- **Read Ledger v2 (`READ_LEDGER_SCHEMA = 2`):** Three-tier `confirm_tier` checks via Claude `PostToolBatch` and Cursor `tool_output`.
- **Outcomes Schema v4 (`hooks/outcomes.py`):** Added `step_ledger`, recovery/regret/evidence tiers, and `unattributed_anon` tracking.
- **Shadow evaluation (`hooks/telemetry.py`):** Added `0o600` `telemetry/shadow.json` counterfactual log cleared on edit/compact/rewind.
- **Cost & replay CLI (`bin/tariffs.py`, `bin/replay_benchmark.py`):** Added bounded cost insights, `--replay`, and `--benchmark`.
- **Hygiene & doctor gates:** Added `NATIVE_FAIL_CLOSED_DRIFT` in `--doctor` plus OSS release hygiene and git-history secret scans.

### Changed
- **Default `"strict"` policy:** Restricts `range_trim` to `confirm_tier == 2` (`0` savings on Antigravity/Codex unless `"bounded"`).
- **Pass-2 & native fail-closed:** Enforced 4-case Pass-2 security verification, Claude `onFailure: "block"`, and Cursor `failClosed: true`.
- **Outcomes & cost reporting (`bin/outcomes_report.py`):** Conservative `v3 -> v4` migration and non-counterfactual `1/k` cost share.
- **Safe IDE updater (`vscode-extension/updater.js`):** Added dirty-tree precheck and rollback via `git reset --keep`.

### Fixed
- **Windows binary pack loader (`policies/loader.py`):** Pass `O_BINARY` to `os.open` so CRLF packs keep exact SHA-256.

### Removed
- **Bundled workspace guards:** Moved workspace-specific guard logic into external Policy API v1 packs for a universal OSS core.

## [4.3.0] - 2026-11-14

### Added
- **Command normalizer (`hooks/file_io.py`):** Exported `normalize_cmd_basename` handling POSIX/Windows paths and `.exe`/`.cmd`/`.bat`.
- **Lexical Codex TOML sync (`bin/codex_toml.py`):** Extracted cycle-free TOML scanner preserving multiline strings, arrays, and comments.
- **Doctor & CI/AST gates:** Added `verify_harness_hooks`, win32 `python3` stub checks, `node --check`, and Windows/attribute AST gates.

### Changed
- **Eager MCP matcher (`hooks.json`):** Added `mcp_gitlab_.*` and BigQuery MCP server patterns to `PreToolUse` matchers.
- **IDE activation & CI permissions:** Restricted `activationEvents` to `["onStartupFinished"]` and scoped CI to `contents: read`.
- **Outliner compaction (`hooks/json_outliners.py`):** Slimmed `hooks/*.py` to `6,737` LOC and generalized `items`/`results`/`values` lists.

### Fixed
- **SQL & shell guards:** Added GoogleSQL `strip_sql_comments`, wrapper/`.exe` heredocs, bypass depth caps, and linear `O(N)` `sed`.
- **Harness adapters:** Extracted Antigravity `cwd`, preserved `"path"`/`"Path"` `updatedInput`, and split Windows `raw_name` envelopes.
- **Model & read planner accuracy:** Stopped Antigravity scan `to Auto`, scanned Codex tails first, and capped unbounded overlap probes.
- **Installer & Windows CLI:** Preserved symlinks via `realpath`, emitted RFC 8089 URIs, and replaced `select` stdin with daemon threads.
- **Rewind telemetry & sunset:** Reconciled rewinds/coverage, multiline skill YAML, and 1:1 Python/JS `sunset_verdict` proration.
- **IDE extension hardening:** Guarded `NaN`/dates, escaped Markdown prose, cached JSON/doctor probes, and auto-refreshed stale usage.

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
