# Context-Guard — Development Roadmap `v4.5.2`–`v5.1.0` and Architectural Freeze Record

**Status:** `ARCHITECTURAL FREEZE` — `v5.0.0` contracts frozen; `v5.1.0` architectural remediation & 8-layer DAG enforced  
**Date:** November 19, 2026  
**Analysis baseline:** `v4.5.1`, commit `54045e2f793893a895c8693f61c1ac63f0c7ed01` (`7/7` green Multi-OS CI jobs per reported verification); `v5.1.0` builds on `v5.0.0` (`7278094`)  
**Supported harnesses:** Claude Code, Cursor, OpenAI Codex, Google Antigravity  
**Document purpose:** authoring specifications, TDD plans, issues, and acceptance criteria for releases

> [!NOTE]
> **Repository state in `v5.1.0`:** Building on the frozen `v5.0.0` **Stable Context Reliability Platform** (`POLICY_API_VERSION = 1`, `CORE_SCHEMA_VERSIONS`, `DeprecationPolicyV1`, `PlatformMatrixContractV1`, and 10-gate `cg eval --conformance`), `v5.1.0` enforces a strict **8-layer acyclic DAG** (`core` -> `policies` -> `spool`/`integrations` -> `hooks` -> `services` -> `evidence` -> `bin`, with `Tarjan Package SCC == 0`, `Tarjan File SCC == 0`, zero production `assert`s, and zero `X as X` facades), adds the Layer 0 `core/` foundation and Layer 4 `services/` package (keeping all 10 `bin/*.py` CLI entrypoints `<= 350` LOC and `hooks/*.py < 6,800` LOC), extracts the pure `hooks/telemetry_core.py` and `hooks/drift_probe.py` modules, moves `replay_governor_decisions` to `evidence/conformance.py`, and hardens transactional read-planner TOCTOU checks, `StatePersistenceError` semantics, read-only state fallbacks, Outcomes v4 `step_idx=0` eviction, spool GC races, and `RollbackJournal` installs. See **Part IV** below.

---

## Part I — Architectural Review and Architectural Freeze Decision

The roadmap earns a **9.5/10** rating and is ready for **Architectural Freeze** after introducing five targeted adjustments within the `v4.5.2`–`v4.7.0` contracts. Anchoring the plan in the actual `v4.5.1` state (`54045e2`, a full `7/7` green Multi-OS CI suite, existing spool `slice`/`grep`/`list`/`gc`, and Outcomes v4) protected the project from the second-system effect — instead of rewriting working foundations, the document first seals integrity and access isolation, and only then builds the measurement and adaptation layers.

### Strongest Foundations of the Document

* **No second-system effect:** Keeping Policy API v1, Read Ledger, and the JSON + lock manifest until `v4.9.0` benchmarks protects the stability of all 7 Multi-OS CI jobs.
* **Proper risk sequencing:** Sealing spool integrity and workspace isolation in `v4.5.2` precedes A/B evaluations (`v4.7.0`) and automated decision-making (`v4.8.0`).
* **Parallelizable post-stabilization work:** Independence of `v4.6.0` (Advisor) from `v4.7.0` (Offline Replay) allows fast delivery of a user-visible CLI capability without stalling evaluation work.
* **Release discipline:** Three independent gates (Contract, Reliability, Evidence) and conditional Governor activation tie plugin evolution to hard measurements.

### Five Contract Adjustments Before Architectural Freeze

#### 1. Read-time UTF-8 validation vs. false integrity error (`v4.5.2` A.4)

Enforcing strict UTF-8 decoding (without `errors="replace"`) only during `slice` and `grep` operations while returning `integrity_mismatch` breaks the `v4.5.2` definition of done on real CLI tool outputs. System logs on Windows (`CP1250`/`CP852`), byte dumps in `pytest` assertions, or `git diff` on mixed-encoding files can contain byte sequences that are not valid UTF-8. If the write path accepts such a buffer, computes a valid `content_sha256`, and returns a summary to the agent, only for `slice` to reject the read with `integrity_mismatch`, the plugin itself cuts the agent off from uncorrupted data and in `v4.8.0` would trip the circuit breaker falsely. UTF-8 validity must be checked **before payload replacement on write** (invalid UTF-8 triggers immediate passthrough or marks the asset in the manifest as binary), reserving `integrity_mismatch` strictly for `total_bytes` or `content_sha256` mismatches.

#### 2. Default scope split for `v4.5.2` and manifest lock hygiene (`v4.5.2` A–E)

The contingency rule in section 5 separating P0 fixes from `ContextReceiptV1` should become the primary plan. Items A, B, and C (`SHA-256` verification, tombstones under concurrent GC, and `workspace_id` isolation in the MCP server) close security and data-consistency gaps, whereas items D and E (the new `ContextReceiptV1` log and changing regret classification in Outcomes v4) represent telemetry expansion that changes report semantics and belongs in a separate `v4.5.3` release. In addition, while retaining the JSON + lock backend, the `v4.5.2` specification must forbid holding the manifest lock during `SHA-256` hashing of payload files and define an upper `max_spool_entry_bytes` ceiling so a single multi-hundred-megabyte log dump does not degrade latency for every `slice` call.

#### 3. Cross-OS `workspace_id` canonicalization between hook and MCP server (`v4.5.2` C)

Basing default isolation on a canonical project directory is the right security boundary, but on macOS, Linux, and Windows a short-lived hook process and a long-lived MCP server in Cursor can easily compute different identifiers for the same repository. Symbolic links on macOS (`/var` vs. `/private/var`), Windows drive-letter casing (`C:\Repo` vs. `c:\repo`), and differences between the MCP `roots/list` protocol and static `.cursor/mcp.json` configuration would cause `slice` and `grep` to deny access to a session's own resources. The `v4.5.2` contract should mandate a single shared canonicalization helper (`realpath` combined with case normalization on case-insensitive filesystems) plus cross-platform CI tests verifying hook writes and MCP reads across all supported OS runners.

#### 4. Passive vs. active MCP schema inventory (`v4.6.0`)

Local client configuration files contain launch commands for MCP servers, not the tool JSON schemas themselves — those are generated dynamically upon `tools/list`. If `cg budget --mcp` spawned configured MCP servers by default to fetch schemas, it would violate the zero-side-effects principle (servers may require live auth tokens, open network connections, or hang the CLI). In `v4.6.0`, default mode should analyze only passive sources (session transcripts, local harness definition caches, and instruction files, reporting missing schemas as `unavailable`), while active `tools/list` querying belongs behind an explicit `--probe` flag with a strict timeout.

#### 5. Single source of truth for Outcomes v4 and early capability key capture (`v4.5.2`–`v4.7.0`)

Because `v4.5.1` already ships Outcomes v4, adding `ContextReceiptV1` alongside it risks maintaining two independent event pipelines that could diverge in `v4.7.0`. The architecture should state explicitly that `ContextReceiptV1` is intended as the single low-level raw event log, from which aggregated Outcomes metrics can be deterministically derived once durability and deduplication requirements are met. At the same time, a minimal `CapabilityAttestationKey` fingerprint (harness ID, build, adapter version, and hook config hash) should be recorded in measurement artifacts starting in the `v4.7.0` Evidence Engine so A/B runs include the full metadata set required later by Governor rules in `v4.8.0`.

| Release | Section in Document | Recommended Adjustment | Rationale |
| :--- | :--- | :--- | :--- |
| `v4.5.2` | UTF-8 validation in `slice` and `grep` | Validate UTF-8 on spool write | Eliminates false `integrity_mismatch` |
| `v4.5.2` | Release scope and JSON lock | Split Receipt into `v4.5.3`, hash outside lock | Fast P0 fix and low p99 latency |
| `v4.5.2` | MCP `workspace_id` isolation | Shared path canonicalization and Multi-OS tests | Consistent hook–MCP authorization |
| `v4.6.0` | `cg budget --mcp` inventory | Passive read by default, active `--probe` opt-in | Zero side effects during audit |
| `v4.7.0` | Evidence Engine artifacts | Record `CapabilityAttestationKey` in reports | Ready input for `v4.8.0` rules |

After incorporating pre-spool UTF-8 validation, Multi-OS `workspace_id` path canonicalization, and passive default `cg budget --mcp` behavior, the roadmap was marked **Frozen** with the two architectural reservations clarified below.

### Decision: Accepting Adjustments with Two Architectural Reservations

The Context-Guard roadmap from `v4.5.2` to `v5.0.0` was approved for **Architectural Freeze**. All five proposed adjustments have sound technical justification and improve execution feasibility; in particular, splitting `v4.5.2` as a focused bugfix release decouples integrity fixes from building new telemetry.

Two reservations clarified in the technical contracts:

1. `ContextReceiptV1` cannot serve as the sole source of truth if persisted as best-effort JSONL. A durable, deduplicatable event store or formal migration of existing Outcomes v4 is required first.
2. Workspace isolation must rely on a trustworthy project identity source. A shared `realpath()` function alone does not solve the case of a global MCP server that does not know which project originated a call.

#### Updated Release Sequence

| Version | Final Scope | Exit Criterion |
| :--- | :--- | :--- |
| `4.5.2` | Recovery integrity, tombstones, workspace isolation, payload limits | Safe reads, GC, and Multi-OS parity |
| `4.5.3` | `ContextReceiptV1`, regret adjustment, recovery correlation | Consistent event semantics without Outcomes v4 regressions |
| `4.6.0` | Preamble & MCP Advisor: passive audit, optional `--probe` | Zero side effects in default mode |
| `4.7.0` | Evidence Engine: offline replay and staged live A/B | Credible results and complete environment metadata |
| `4.8.0` | Capability Negotiation and conservative Governor | No activation on unverified capabilities |
| `4.9.0` | Explainability, hardening, optional OTel export | Reproducible decisions and operational resilience |
| `5.0.0` | Policy API, schema, and compatibility stabilization | Stable public contract |

#### 1. `v4.5.2` — exact technical contract

* **UTF-8 validation before spooling:** Because `slice` and `grep` are text operations, they must not accept resources they cannot faithfully reconstruct later. Full binary resource support is out of scope for `4.5.2` because it would require a dedicated recovery interface rather than existing text operations. If a harness passes an already-decoded string to the hook, Context-Guard cannot reconstruct the original upstream byte stream — the integrity guarantee covers the exact representation it actually received.

| Condition | Behavior |
| :--- | :--- |
| Source bytes are not valid UTF-8 | Passthrough without spooling |
| Size exceeds `max_spool_entry_bytes` | Passthrough |
| `SHA-256` or length mismatch during recovery | `integrity_mismatch` |
| `SHA-256` matches, but stored text violates encoding contract | `decode_error` or `format_error` |
| Upstream already delivered text with replacement characters | Do not claim integrity of raw upstream bytes |

* **Off-lock hashing, zero GC race:**
  1. Under a short lock, read manifest state, asset version, expected hash and length, and open a handle to the payload file.
  2. Release the lock. Read bytes from the open handle and verify length, `SHA-256`, and encoding.
  3. Return only verified contents. GC must respect in-flight reads or safely defer physical deletion (on Windows an open handle may prevent `unlink()`, so GC leaves the entry for retry; on POSIX an open file descriptor continues reading data after directory unlink). Combine this with `max_spool_entry_bytes` enforced before spooling starts.

#### 2. Workspace isolation — one additional critical condition

Shared canonicalization on both sides is necessary: `realpath()` resolves symlinks, and `normcase()` normalizes drive/path casing on Windows. On macOS, `normcase()` does not alter case despite potentially case-insensitive filesystems, so comparisons between existing directories must verify true filesystem object identity via `os.path.samefile()`. Because newer MCP protocol versions (`2026-07-28+`) deprecate `roots/list`, and `roots` themselves provide project metadata rather than an access-control boundary, the following model applies:

| Scenario | Decision |
| :--- | :--- |
| MCP server launched with a trustworthy, pinned workspace | Access scoped strictly to its assets |
| Multi-root server with unambiguously resolved per-call scope | Access to the corresponding workspace |
| Global server without call origin identity | Deny rather than falling back to `global` |
| `global` mode explicitly chosen by the user | Access per explicit configuration |

#### 3. `v4.5.3` — `ContextReceipt` vs. existing Outcomes v4

The target principle "raw events are the source of truth; Outcomes are an aggregated view" requires staged migration and cannot rely on optional JSONL as an authoritative ledger:

| Stage | Source of Truth | Context Receipt Role |
| :--- | :--- | :--- |
| `v4.5.2` | Existing manifest and Outcomes v4 | No new contract |
| `v4.5.3` | Existing durable stores, shared `event_id` semantics | Unified event format and diagnostic log |
| `v4.7.0` | Durable, deduplicatable event log or equivalent mechanism | Basis for deterministic Outcomes aggregation and offline replay |

In `4.5.3`, a logical event is created once and dispatched to stores (avoiding independent re-interpretation of the same intervention across two modules). A failure writing auxiliary JSONL must never lose recovery data, and Outcomes reconstruction must report data completeness.

#### 4. `v4.6` and `v4.7` — two adjustments frozen immediately

* **Preamble Advisor (passive by default):** `cg budget --mcp` analyzes configs, known schemas, transcripts, and local data without launching external processes; `--probe` is a separate, explicit diagnostic with potential side effects.
* **Evidence Engine (environment traceability):** Live and offline experiments record at least `harness_id`, `harness_build_id`, `adapter_version`, `hook_config_fingerprint`, `context_guard_version`, `model_id`, and the required capabilities plus their evidence level; the mere presence of `CapabilityAttestationKey` does not prove `runtime_verified`.

#### Final Architectural Freeze status

| Decision | Status |
| :--- | :--- |
| `v4.5.2` / `v4.5.3` split | Approved |
| UTF-8 validation before spooling | Approved |
| `max_spool_entry_bytes` + off-lock hashing | Approved with stable-handle requirement |
| Shared workspace canonicalization | Approved; requires trustworthy MCP caller identity |
| Passive `cg budget --mcp` | Approved |
| Capability metadata in Evidence Engine | Approved |
| `ContextReceipt` as future source for Outcomes aggregation | Directionally approved; migration requires durable log |

The document is placed at the repository root as [ROADMAP.md](ROADMAP.md) (due to the release-hygiene rule disallowing a `docs/` directory). Ongoing work follows the frozen release contract below.

---

## Part II — Final Development Roadmap `v4.5.2`–`v5.0.0`

### 1. Product Direction

Context-Guard is evolving from a collection of token optimizations into a local **Trust + Evidence + Adaptation** layer responsible for safely transforming agent context, recovering full information, measuring impact honestly, and selecting strategies within each harness's verified capabilities.

* **Trust:** transformation must never silently deprive an agent of needed data within the declared retention window. Integrity, isolation, and failure-mode safety take precedence over savings.
* **Evidence:** separate output-size reduction, real billing cost, cache effects, extra turns, and task completion. Correlation is not causal proof.
* **Adaptation:** optimization activation is deterministic and bounded by verified capabilities; hard failures lead to safe fallback.

**Explicit non-goals:** yet another large CLI filter library, a bespoke ML compressor, a mandatory cloud service, default remote telemetry, a new agent memory system, or a sprawling SDK for nonexistent third-party extension authors.

### 2. Baseline State and Constraints

In `v4.5.1`, Policy API v1, Read Ledger, Outcomes v4, Reversible Output Spool (`slice` / `grep` / `list` / `gc`), harness integrations, shadow mode, and replay/benchmark foundations already exist. We do not rebuild these modules from scratch.

Every release upholds these invariants:

* **Correctness before compression:** without a safe recovery path, passthrough applies.
* **Local-first:** data and policies stay local; raw payloads never go to telemetry by default.
* **Harness-bounded claims:** guarantees hold strictly at the observable boundary of the specific client.
* **Backward compatibility:** protect Policy API v1, Read Ledger, existing installs, and migrations.
* **Measured / estimated / unavailable:** missing data means neither zero savings nor zero errors.
* **Release gates:** Contract, Reliability, Evidence, and full Multi-OS CI; never push a release tag before all gates pass.
* **Repository budgets:** uphold Python 3.9+ compatibility, LOC/topology ceilings, and existing repository gates; extract new spool logic into dedicated modules rather than bloating hook entrypoints.

### 3. Frozen Release Sequence

| Release | Primary Goal | Deliverables | Gate Condition |
| :--- | :--- | :--- | :--- |
| `v4.5.2` | Spool Reliability | Byte integrity, safe GC, tombstones, workspace isolation, payload limits | Seven invariants and five Multi-OS test groups |
| `v4.5.3` | ContextReceipt & Outcome Semantics | Receipt V1, `suspected` regret correction, recovery correlation | Zero double-counting and zero Outcomes v4 regressions |
| `v4.6.0` | Preamble & MCP Budget Advisor | Passive audit, recommendations, optional `--probe` | Zero side effects in default mode |
| `v4.7.0` | Evidence Engine | Offline replay, controlled live A/B, cost & quality metrics | Reproducible methodology with explicit uncertainty |
| `v4.8.0` | Capability-Aware Governor | Runtime capability attestation, `active` / `shadow` / `passthrough`, circuit breaker | Zero decisions exceeding attested capabilities |
| `v4.9.0` | Explainability & Hardening | `cg explain`, retention, diagnostics, optional OTel export | Operational resilience and auditability |
| `v5.0.0` | Stable Reliability Platform | Stable contracts, CLI, and compatibility matrix | Safe migrations, documented guarantees |

No calendar dates are committed. Releases advance by passing quality gates rather than hitting calendar deadlines.

### 4. `v4.5.2` — Detailed Release Contract (P0/P1)

**Goal:** harden the existing spool with zero structural changes to Read Ledger or Outcomes v4. New Context Receipt work and regret reclassification remain separated from P0 fixes.

#### 4.1. Reading and Writing Data

* On `str` input: `.encode("utf-8", errors="strict")`; on raw bytes: validate `.decode("utf-8", errors="strict")`. Lone surrogates and invalid byte sequences trigger passthrough without creating a spool entry.
* Enforce configurable `max_spool_entry_bytes` before expensive transformation. Exceeding the limit triggers passthrough. The default value is test-calibrated rather than an architectural promise.
* Payloads are write-once per unique `spool_id`: write temp file, verify, `os.replace()` on the same filesystem, then commit manifest in `available` state.
* Compacted output may only be emitted after both payload and manifest commit succeed. Earlier failure emits the untouched original output.
* Before returning any slice, `slice` / `grep` verify full `total_bytes` and `content_sha256`, then strictly UTF-8 decode the full payload. Slicing respects full character or line boundaries; byte offsets are half-open `[start, end)`.
* Size/hash failure yields `integrity_mismatch`; valid bytes failing format/UTF-8 contract (unreachable after valid writes) yield `format_error` rather than false `integrity_mismatch`. Missing file in `available` state yields `unexpectedly_missing`.
* `source_hash` covers the exact bytes received by Context-Guard; it does not promise upstream did not truncate output earlier.

#### 4.2. Locks, GC, and Consistency

**Read protocol:**

1. Under brief `_spool_lock`, read state and metadata, authorize access, and open a file handle to the immutable payload.
2. Release the lock; read full bytes from the open handle, verify length, `SHA-256`, and UTF-8.
3. Return only verified data and close the handle safely. Reads opened before state flips to `evicting` may complete.

**GC protocol:**

1. Under `_spool_lock`, atomically transition to `evicting` with reason `ttl_expired`, `max_entries_lru`, or `max_bytes_lru`.
2. Release the lock and execute `os.unlink()` outside the critical section.
3. After successful removal, atomically transition to `evicted` (tombstone). On Windows `PermissionError`, retain `evicting` and retry later.
4. Subsequent reads seeing `evicting` or `evicted` return `evicted` with reason, not `unexpectedly_missing`.
5. After crash/restart, GC finalizes incomplete evictions and cleans orphaned payloads. Tombstones live in a count- and time-bounded registry (roughly `128` entries and `7–14` days, finalized in spec).

Never compute `SHA-256` or execute `os.unlink()` under `_spool_lock`. Heavy decoding and formatting also stay outside the critical section. Never assume `os.replace()` alone guarantees power-loss durability; any durability claim requires explicit file/directory sync semantics in spec.

**States:** `preparing` (strictly internal, never exposed), `available`, `evicting`, `evicted`, `corrupt`. Post-`available` state transitions are monotonic; never reuse a `spool_id`.

#### 4.3. Workspace and MCP Isolation

**Modes:** `workspace` (default), `session` (requires trustworthy identifier), `global` (explicit opt-in).

* Hooks write entries tagged with a reliably resolved workspace root; never trust a root supplied in model arguments.
* The MCP `workspace` server starts with pinned `--workspace-root` / `--workspace`; the directory resolves at startup without calling `os.getcwd()`. Without confirmed workspace identity, `slice`, `grep`, and `list` deny access and must never authorize using model-supplied root arguments.
* Persist both `workspace_id` and canonical root. Verify real directory identity via `os.path.samefile()` rather than string equality alone.
* Test symlinks, Windows drive-letter casing, macOS case-insensitivity, deleted/moved roots, and multi-root setups. Missing trustworthy identity always fails closed — never falls back to `global`.
* This provides logical project isolation for the same OS user, not a sandbox against co-privileged local processes. Manifests containing absolute paths require restrictive file permissions and must never be exported by default.

#### 4.4. Seven Tag-Blocking Invariants

* **INV-1 — Passthrough before mutation:** never emit a summary before size/UTF-8 validation and committing `available` state.
* **INV-2 — Full verification:** every recovered slice comes from a complete file verified by length, `SHA-256`, and strict UTF-8.
* **INV-3 — Short lock:** hashing and physical `unlink` never execute under `_spool_lock`.
* **INV-4 — Monotonic states:** `available` → `evicting` → `evicted` or transition to `corrupt`; no return to `available` and no ID recycling.
* **INV-5 — Eviction ≠ corruption:** `unexpectedly_missing` only applies when manifest says `available`; evictions return their explicit reason.
* **INV-6 — Fail-closed workspace:** missing verified root or mismatched `samefile()` results in denial, never silent global access.
* **INV-7 — Untouched Outcomes v4:** zero structural changes to Outcomes v4 and Read Ledger in `v4.5.2`.

#### 4.5. Behavior Matrix

| Manifest | Payload | `slice` / `grep` | Subsequent GC | Classification |
| :--- | :--- | :--- | :--- | :--- |
| `available` | valid hash and size | return data | TTL/LRU per policy | `OK` |
| `available` | invalid hash/size | `integrity_mismatch` | mark `corrupt` | `reliability failure` |
| `available` | missing | `unexpectedly_missing` | mark `corrupt` | `reliability failure` |
| `evicting` | present or locked | `evicted` + `reason` | retry `unlink` | retention loss, not corruption |
| `evicted` | missing | `evicted` + `reason` | tombstone retention | retention loss, not corruption |
| `corrupt` | any | deny recovery | quarantine/cleanup per policy | `reliability failure` |

#### 4.6. Five Release-Blocking Test Groups

1. **Bytes and UTF-8:** bit flip, extra byte, non-UTF-8 CP1250 bytes, lone surrogate, `max_spool_entry_bytes + 1` ceiling, multibyte characters, and `[start,end)` boundaries. Invalid input triggers passthrough; corrupted stored bytes trigger recovery denial.
2. **Reader/GC race:** barrier after handle open; concurrent `evicting`; active reader completes while new reads deny; both POSIX behavior and Windows `PermissionError` with retry after handle close.
3. **Crash and write failures:** `ENOSPC`, permission errors, and manifest failures force raw output emission; restart after `evicting` completes eviction without false corruption.
4. **Multi-OS MCP/workspace:** project A cannot read project B via `slice`/`grep`/`list`; missing workspace ID fails closed; symlinks, casing variants, multi-root, and deleted roots.
5. **Hot-path contention:** artificially slow SHA on a large payload does not block `list()` or small recoveries on lock; measure p95/p99 with CI-grounded thresholds rather than arbitrary wall-clock promises.

**Release gate `v4.5.2`:** `INV-1`–`INV-7`, all five test groups, full Multi-OS matrix, zero install/uninstall regressions. Do not bundle telemetry redesign into this release.

### 5. `v4.5.3` — `ContextReceiptV1` and Outcome Semantics

**Goal:** establish a single event contract without forcing immediate migration across all legacy stores.

* `ContextReceiptV1`: `schema_version`, `event_id`, `event_type`, `parent_event_id`, `session_id`, `tool_call_id`, `spool_id`, optional `turn_key` and `turn_correlation`, `ts_ms`, `hook_duration_ms`, `harness`, `intervention`, `mode`, `status`, `source_hash`, byte sizes, recovered `[start,end)` ranges, plus `delivery_evidence` and `upstream_truncation`.
* `turn_correlation` accepts at least `harness_native`, `transcript_derived`, and `unobserved`. Never report `recovery_model_turns` as measured when correlation is unobserved.
* Distinguish `replacement_emitted` from `delivery_verified`. A subsequent `slice` / `grep` call proves the handle was used, not that the original replacement was delivered to the model.
* `repeat_after_spool`, `verbose_override`, and `reread_trimmed_range` receive `regret=suspected` with `evidence=observed`. Targeted recovery alone is not regret; integrity failure belongs to `reliability_failure`.
* Resource lifecycle metrics: `recovery_calls`, `recovery_model_turns` (when observable), `unique_recovered_bytes`, `total_recovered_bytes`, `recovery_amplification`, with cost and failures tracked separately. Repeated recovery suggests chunk fragmentation, not automatic optimization blame.
* **Transitional design:** Outcomes v4 stays the durable operational aggregate store; diagnostic rotated JSONL does not automatically become an authoritative event log. One logical event is created once with a stable ID; downstream deduplicates. Missing receipt data is marked `incomplete`, never zero.
* Only once a complete, durable, deduplicatable event log with migration exists can Outcomes be derived solely and deterministically from raw events. Do not force that migration in `v4.5.3`.

**Release gate:** deterministic deduplication and correlation tests, zero double-counting, historical Outcomes compatibility, accurate classifiers, and zero mandatory persistence of raw prompts.

### 6. `v4.6.0` — Preamble & MCP Budget Advisor

**Goal:** deliver a safe, user-facing feature that operates strictly read-only by default.

* Target commands: `cg budget --preamble`, `cg budget --mcp`, `cg budget --recommendations`.
* Default sources: configs, local instruction files, transcripts, and existing schema definition caches; never spawn MCP servers or issue `tools/list` during standard `cg budget`.
* Missing schemas and cache counters report `unavailable`. Token and cost estimates must be explicitly labeled `estimated`.
* `--probe` is a separate explicit mode with timeouts, resource bounds, identification of probed servers, and clear warnings that even `tools/list` may start processes or network connections.
* Analyze schema/tool overlaps and provide conservative startup profile recommendations without auto-mutating MCP sets or claiming "guaranteed savings".

**Release gate:** default audit triggers zero external processes or network traffic and mutates nothing; `measured` / `estimated` / `unavailable` fields remain cleanly separated.

### 7. `v4.7.0` — Evidence Engine

**Goal:** measure cost and end-to-end task quality impact rather than raw token-reduction percentages alone.

* **Offline Replay:** deterministic verification of transformations, integrity, latency, and contracts against reference records; never pretend replay reproduces live model trajectories.
* **Small Live Pilot:** roughly `6 tasks × 2 configs × 3 repeats = 36 runs`; a fast regression gate for obvious failures, not statistical proof.
* **Release Evaluation:** roughly `12–15 tasks × 3 configs × 2 repeats = 72–90 runs/harness`; baseline, Context-Guard, and Context-Guard + RTK. Scale sample size strictly per budget and observed uncertainty.
* **Primary metric:** `Cost per Passed Run` = total cost of all runs / passed run count (explicitly `undefined` at zero passes), alongside `Pass Rate`, paired cost on shared passes (explicitly conditional), turns, latency, cache read/write/fresh input tokens, TTL misses, recovery fragmentation, and confirmed `reliability_failures`.
* Never exclude endogenous TTL cache misses or failed-attempt costs from the headline A/B metric. Separate external noise clearly.
* Experiments require isolated workspaces, pinned CLI and model versions, identical budgets, pass criteria, and reported uncertainty bounds.
* Every artifact records: `harness_id`, `harness_build_id`, `adapter_version`, `hook_config_fingerprint`, `context_guard_version`, `model_id`, required capabilities, and their evidence levels. Presence of `CapabilityAttestationKey` alone never proves `runtime_verified`.
* Admit Cursor CLI after contract conformance tests; missing cache telemetry excludes fine-grained cache attribution without blocking all comparisons.

**Release gate:** reproducible reports, disclosed failures, zero unsupported causal claims, complete metadata.

### 8. `v4.8.0` — Capability-Aware Adaptive Governor

**Goal:** deterministically select `active`, `shadow`, or `passthrough` for optimizers.

* `CapabilityContractV1` distinguishes `unsupported`, `provider_supported`, `harness_exposed`, and `runtime_verified`.
* Attestation binds `(harness_id, harness_build_id, adapter_version, hook_config_fingerprint, capability_id)` plus verification evidence. Changes to build, adapter, relevant config, or unknown payloads invalidate prior guarantees.
* Never infer harness support from model API capabilities alone. Dynamic tool-list mutation requires verification against the actual client rather than only the upstream provider.
* Circuit breaker trips on hard integrity failures and guarantee loss, never merely on `suspected_regret` or chunk thrashing.
* Hysteresis: after a confirmed failure, re-enable only after passing verification tests or explicit operator action. The Governor never lowers security policy enforcement.

**Release gate:** parity tests against static config, decision replay, harness-upgrade invalidation tests, and fail-safe downgrade; gate default activation on Evidence Engine results.

### 9. `v4.9.0` — Explainability & Operational Hardening

**Goal:** allow operators to explain any specific intervention and audit telemetry completeness.

* `cg explain <event-id>`; diagnostics covering `spool_id` lifecycle, current state, eviction reasons, and delivery-evidence tier.
* Export compatible events to OTel strictly off the hot path (`cg export --otel`), with zero mandatory heavy dependencies inside hooks.
* Test harness upgrades, resumed sessions, retention boundaries, disk failures, permission errors, and concurrency.
* Benchmark JSON + lock vs. SQLite WAL and segmented JSONL only if measurements expose limits of the existing backend. Zero unrequested Read Ledger migrations.

**Release gate:** explainability without raw prompt leakage, measured p50/p95/p99 latency, reproducible behavior, and safe migrations.

### 10. `v5.0.0` — Stable Context Reliability Platform

**Goal:** stabilize public contracts and ergonomics rather than shipping features to justify a major version number.

* Cohesive CLI: `doctor`, `budget`, `explain`, `eval`.
* Stable Policy API and core contracts, schema versioning, deprecation policy, and backward-compatible migrations.
* Published capability and limitation matrix across Claude Code, Cursor, Codex, and Antigravity.
* Adapter and baseline policy-pack conformance suite; full external SDK only if real demand warrants it.
* No mandate to invent Policy API v2 if v1 satisfies all requirements.

**Release gate:** green Multi-OS CI, documented guarantees, migrations and rollback paths, and published effectiveness evidence including limitations.

### 11. Cross-Cutting Contracts

| Contract | First Introduced | Invariant |
| :--- | :--- | :--- |
| `SpoolLifecycleV1` | `v4.5.2` | Zero data loss within declared retention; planned eviction is not corruption |
| `WorkspaceAccessV1` | `v4.5.2` | Trustworthy MCP process root; zero implicit `global` access |
| `ContextReceiptV1` | `v4.5.3` | Correlation and proof; raw data remains outside ledger |
| `OutcomeSemanticsV1` | `v4.5.3` | `suspected ≠ confirmed`; missing telemetry `≠ zero` |
| `EvidenceContractV1` | `v4.7.0` | Full cost of attempts per pass; explicit uncertainty |
| `CapabilityContractV1` | Metadata in `v4.7.0`; runtime in `v4.8.0` | Build/adapter changes invalidate attestation |

### 12. Implementation Hand-Off Plan (Next Step)

* **Milestone A — spec-first, `v4.5.2` / closeout prior to `v4.6.0`:**
  1. Freeze public/operational error codes, manifest states, permission rules, and half-open range semantics.
  2. Add five contract test groups: encoding/hash, GC races, crash recovery, workspace/MCP isolation, and lock contention.
  3. Implement write-once persistence, payload size cap, and fail-safe passthrough (with pre-spool UTF-8 validation).
  4. Implement verified reads opening payload handles under short locks while hashing off-lock.
  5. Implement `evicting` → `evicted`, tombstones, and restart reconciliation.
  6. Implement pinned workspace root resolution, shared canonicalization, `samefile()`, and fail-closed denial on missing identity.
  7. Pass full Multi-OS CI, migration/rollback checks, and latency benchmarks before tagging.
* **Milestone B — `v4.5.3`:** Context Receipt, regret refinement, recovery correlation, event idempotency, and completeness reporting.
* **Milestone C — `v4.6.0` onward:** execute release scopes per Section 3 without reopening settled strategy.

### Change Control Rules

Status **ARCHITECTURAL FREEZE** locks release ordering, functional scopes, and core invariants. It does not freeze numeric thresholds, backend storage formats, or adapter internals if empirical testing uncovers constraints.

Modifying a frozen contract requires:

1. A concrete failing test or new empirical evidence.
2. Backward-compatibility assessment.
3. Updating [ROADMAP.md](ROADMAP.md).
4. Re-passing the **Contract Gate**.

**Final decision:** the top priority at the `v4.5.2`/`v4.5.3` boundary was full closure of integrity invariants, non-blocking hashing/GC, and `samefile()` workspace isolation before starting `v4.6.0` (`Preamble & MCP Budget Advisor`).

---

## Part III — `v5.0.0` Platform Reference: Guarantees, Capability & Limitation Matrix, Schema Versioning, Migrations, Rollback & Effectiveness Evidence

Part III records the authoritative public contracts, harness boundaries, migration invariants, operational rollback procedures, and effectiveness methodology shipped in `v5.0.0` (`policies/api.py`, `evidence/conformance.py`, `bin/cg.py`, `bin/cg_eval.py`). Programmatic equivalents are exported via `cg doctor --contracts --json`, `cg eval --platform-matrix --json`, and `cg eval --conformance --json`.

### 1. Cohesive CLI Contract (`cg` Dispatcher & Subcommands)

All operator workflows route through `bin/cg.py` (`cg <command> [args...]`, `-h`/`--help`, `-V`/`--version`) with passive, non-mutating, zero-network defaults. The four primary diagnostic pillars (`doctor`, `budget`, `explain`, `eval`) share mutually exclusive `--json` / `--markdown` output flags (defaulting to Markdown) and deterministic exit codes (`0` / `1` / `2`).

| Command | Key Flags & Modes | Output Formats | Exit Codes (`0` / `1` / `2`) | Default Side-Effect Posture |
| :--- | :--- | :--- | :--- | :--- |
| `cg doctor` | `[--contracts] [--json \| --markdown]` | Markdown (default), JSON (`DOCTOR_SCHEMA_VERSION = 1`) | `0` healthy; `1` environment/harness drift; `2` invalid CLI args | Strictly read-only; probes local Python, `flock`, telemetry dir, harness hooks, and schema contracts (`cg_status.py --doctor` stays 100% backward-compatible Markdown) |
| `cg budget` | `[--preamble] [--mcp] [--recommendations] [--probe] [--probe-server <id>] [--probe-timeout <sec>] [--harness <id>] [--workspace <dir>] [--home <dir>] [--usage-path <file>] [--json \| --markdown]` | Markdown (default), JSON | `0` audit emitted; `2` invalid flags / `--probe` without `--mcp` or `--recommendations` / invalid timeout | Strictly passive read-only by default (never spawns MCP servers); stdio `tools/list` probing runs only when `--probe` is explicitly passed |
| `cg explain` | `<event-id> [--receipts-path <file>] [--spool-dir <dir>] [--ledger-path <file>] [--state-dir <dir>] [--json \| --markdown]` | Markdown (default), JSON (`ExplainContractV1`, schema `1`) | `0` matched & explained; `1` unmatched ID / read error; `2` invalid CLI args or `invalid_event_id` | Strictly read-only & privacy-scrubbed; zero raw prompt, blob, or operator home-path leakage |
| `cg eval` | `[--offline-replay \| --pilot \| --release \| --cursor-conformance \| --ledger-verify \| --governor-check \| --hardening-check \| --conformance \| --platform-matrix] [--plan] [--runs-file <file>] [--output <file>] [--json \| --markdown]` | Markdown (default), JSON (`EvidenceContractV1` / `ConformanceContractV1` / `PlatformMatrixContractV1`) | `0` gate/report passed; `1` failed gate, verification error, or missing input file; `2` invalid flag combination (e.g., `--conformance --plan`) or unsafe symlink `--output` | Isolated temp-dir execution; zero live LLM calls or network traffic (`--output` enforces `check_unsafe_link` atomic writes) |
| `cg export` | `--otel [--receipts-path <file>] [--ledger-path <file>] [--outcomes-path <file>] [--window-seconds <sec>] [--output <file>] [--ndjson] [--endpoint <url>] [--timeout <sec>] [--service-name <name>] [--json]` | OTLP/JSON (default), NDJSON (`--ndjson`), status JSON (`OTEL_EXPORT_SCHEMA_VERSION = 1`) | `0` exported; `1` source/write/HTTP failure; `2` missing `--otel`, invalid args, or `invalid_endpoint_scheme` | Strictly off-hot-path 100% stdlib exporter; reads local ledgers only unless `--endpoint http(s)://...` is explicitly supplied |
| `cg status` | `[--short \| --claude-hud \| --markdown \| --json \| --public-json \| --outcomes \| --usage \| --doctor \| --replay \| --benchmark] [--stats-path <file>] [--outcomes-path <file>] [--usage-path <file>]` | Short status line (default), Markdown, JSON, scrubbed public JSON | `0` status/report rendered (`1` on failed `--doctor`, `--replay`, or `--benchmark`) | Read-only telemetry formatting (`--replay` and `--benchmark` run inside isolated temporary directories) |
| `cg spool` | `<slice \| grep \| list \| gc \| mcp> [--workspace <dir>] [--session <id>] [--spool-dir <dir>] [--json]` | Human text (default), JSON (`--json`), or JSON-RPC 2.0 stdio (`mcp`) | `0` operation succeeded; `1` access denied, integrity/eviction error, or invalid `cg-spool` args | Enforces `samefile()` workspace isolation and off-lock SHA-256 verification on `slice`/`grep`; `gc` transitions `available -> evicting -> evicted` |
| `cg outline` | `<file1> [<file2> ...]` | Line-numbered structural symbol outline (`L<start>-L<end>`) | `0` all files outlined; `1` missing arguments or missing file | Pure read-only AST / Tree-sitter / lexical symbol extraction |
| `cg help` | `[budget \| doctor \| eval \| explain \| export \| status \| spool \| outline]` | Help text on `stdout` | `0` top-level or known subcommand help; `1` unknown subcommand (error on `stderr`) | Pure help delegation (`cg help <cmd>` forwards `["--help"]` to the target subcommand) |

* **JSON invalid-argument invariant:** Across `cg doctor`, `cg budget`, `cg explain`, and `cg eval`, passing `--json` alongside invalid CLI flags emits `{"ok": false, "error": "invalid_arguments"}` on `stdout` and exits with code `2`.

### 2. Frozen Policy API v1, Core Schema Registry & Deprecation Policy

`v5.0.0` freezes **`POLICY_API_VERSION = 1`** and **`ADAPTER_CONTRACT_VERSION = "harness_adapter_v1"`** (`policies/api.py`, re-exported completely in `policies/__init__.py`).

* **Why Policy API v2 is not created (`policy_api_v2_mandated = False`):** Policy API v1 (`PolicyDecision`, `PolicyContext`, `PolicyPostContext`, `PolicyPackManifest`, `ALL_SECURITY_SCOPES`, two-pass `reconcile_post_transform` security/optimization reconciliation, and `StagedPackTransaction` SHA-256 tree verification) satisfies every multi-harness security and optimization requirement without structural gaps. Bumping `POLICY_API_VERSION` to `2` solely to match the `v5.0.0` release tag would break verified policy packs for zero functional benefit.
* **Why no external SDK is shipped (`external_sdk_shipped = False`):** `policies.api` is a compact, zero-dependency Python 3.9+ `stdlib` module with frozen `dataclass` and `TypedDict` contracts. Publishing a separate PyPI SDK package without external third-party pack ecosystem demand would introduce version-skew and packaging maintenance overhead while violating the roadmap's anti-bloat constraint.

#### 17-Entry `CORE_SCHEMA_VERSIONS` Registry

| `CORE_SCHEMA_VERSIONS` Key | Version | Source Constant | Governed Artifact / Public Contract |
| :--- | :---: | :--- | :--- |
| `"policy_api"` | `1` | `policies.api.POLICY_API_VERSION` | `PolicyPackManifest`, `PolicyContext`, `PolicyPostContext`, `PolicyDecision` |
| `"read_ledger"` | `2` | `hooks.state_store.READ_LEDGER_SCHEMA` | Per-session `.context_guard_state.json` (`json_lock` backend) |
| `"mutated_repos"` | `2` | `hooks.state_store.MUTATED_REPOS_SCHEMA` | Mutated repository tracking inside session state |
| `"spool_index"` | `2` | `spool.store.SPOOL_SCHEMA_VERSION` | `spool_index.json` lifecycle states & eviction tombstones |
| `"context_receipt"` | `1` | `policies.api.RECEIPT_SCHEMA_VERSION` | `ContextReceiptV1` rows in `receipts.jsonl` |
| `"outcomes"` | `4` | `hooks.outcomes.SCHEMA_VERSION` | `outcomes.json` intervention/regret/attribution ledger |
| `"token_usage"` | `3` | `services.token_usage.USAGE_SCHEMA_VERSION` | `token_usage.json` per-harness/model transcript ledger |
| `"event_ledger"` | `1` | `evidence.ledger.EVENT_LEDGER_SCHEMA_VERSION` | Deduplicated `evidence_events.json` durable event log |
| `"evidence_report"` | `1` | `policies.api.EVIDENCE_SCHEMA_VERSION` | `EvidenceContractV1` offline/pilot/release evaluation output |
| `"capability_contract"` | `1` | `policies.api.CAPABILITY_CONTRACT_SCHEMA_VERSION` | `CapabilityContractV1` & `CapabilityAttestationKey` records |
| `"governor_state"` | `1` | `policies.api.GOVERNOR_SCHEMA_VERSION` | `GovernorContractV1` & `CircuitBreakerStateV1` state |
| `"explain_report"` | `1` | `policies.api.EXPLAIN_SCHEMA_VERSION` | `ExplainContractV1` (`cg explain <event-id>`) |
| `"otel_export"` | `1` | `policies.api.OTEL_EXPORT_SCHEMA_VERSION` | Scrubbed OTLP/JSON export bundle (`cg export --otel`) |
| `"backend_benchmark"` | `1` | `policies.api.BACKEND_BENCHMARK_SCHEMA_VERSION` | `BackendBenchmarkContractV1` Read Ledger storage benchmark |
| `"doctor_report"` | `1` | `policies.api.DOCTOR_SCHEMA_VERSION` | `cg doctor` JSON diagnostic envelope |
| `"conformance_report"` | `1` | `policies.api.CONFORMANCE_SCHEMA_VERSION` | `ConformanceContractV1` (`cg eval --conformance`) |
| `"platform_matrix"` | `1` | `policies.api.PLATFORM_MATRIX_SCHEMA_VERSION` | `PlatformMatrixContractV1` (`cg eval --platform-matrix`) |

#### `DeprecationPolicyV1` Rules (`DEPRECATION_POLICY_VERSION = 1`)

* **Advance notice (`min_deprecation_minor_releases = 2`):** Removing or renaming any public CLI flag, JSON contract key, or `policies.api` export requires at least `2` minor releases of advance deprecation notice (`active_deprecations = []` in `v5.0.0`).
* **Additive evolution (`additive_fields_non_breaking = True`):** Adding optional fields to JSON reports or `TypedDict` contracts is non-breaking within the same schema major version; consumers must ignore unrecognized keys.
* **Unknown major policy pack fail-closed (`unknown_major_policy_pack_behavior = "reject_fail_closed"`):** A policy pack declaring `api_version != 1` (e.g., `2` or `99`) raises `PolicyPackLoadError` during `StagedPackTransaction.validate()`, removes `.staging-*`, and leaves `config.json` byte-for-byte untouched. Post-activation byte tampering of an active `security` pack triggers `PolicyPackLoadError` in the loader and enforces Stage-2 scoped fail-closed `deny` for tools within the pack's `scopes` while allowing out-of-scope reads.
* **Telemetry store resilience (`corrupt_or_future_telemetry_store_behavior = "quarantine_or_passthrough_zero_crash"`):** Corrupt JSON or unrecognized future `schema_version` values in `.context_guard_state.json`, `outcomes.json`, `spool_index.json`, or `token_usage.json` fall back to empty/quarantined state or raw passthrough with zero hook crashes.

### 3. Published 4-Harness Capability & Limitation Matrix (`PlatformMatrixContractV1`)

Boolean capability flags in `PlatformMatrixContractV1` derive directly from `HARNESS_OUTPUT_CAPABILITIES` (`policies/api.py`) and runtime probes in `hooks/harness_adapter.py`, guaranteeing zero drift between documentation and runtime enforcement.

| Dimension | Claude Code (`claude`) | Cursor (`cursor`) | OpenAI Codex (`codex`) | Google Antigravity (`antigravity`) |
| :--- | :--- | :--- | :--- | :--- |
| **Config & hook surfaces** | `~/.claude/settings.json`, `statusLine` HUD | `~/.cursor/hooks.json`, `~/.cursor/mcp.json`, VS Code statusbar ext | `~/.codex/hooks.json`, `~/.codex/config.toml` (`[features].hooks = true`) | `plugin.json`, `hooks.json`, IDE statusbar ext |
| **Lifecycle hooks wired** | `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `PreCompact`, `SessionEnd` | `preToolUse`, `postToolUse`, `preCompact` | `PreToolUse`, `PostToolUse`, `PreCompact` | `PreInvocation`, `PreToolUse`, `PostToolUse` |
| **`can_replace_tool_output`** | `True` (`PostToolUse` payload replacement) | `False` | `False` | `False` |
| **`has_native_fail_closed_hook`** | `True` (`"onFailure": "block"` on CLI `>= 2.1.295`; `False` below `2.1.295`) | `True` (`"failClosed": true`) | `False` (blocks via `PreToolUse` `deny` / `exit 2`) | `False` (blocks via `PreToolUse` `decision="deny"` / `exit 2`) |
| **`supports_apply_patch_block`** | `True` | `True` | `False` (built-in `apply_patch` bypasses `PreToolUse`) | `True` |
| **`supports_content_verified_reads`** | `True` (`PostToolBatch` / `PostToolUse` body verification) | `True` (`postToolUse` read confirmation) | `False` | `False` |
| **`range_trim` (`"strict"` vs `"bounded"`)** | Active under default `"strict"` (verified reads) | Active under default `"strict"` (verified reads) | `0` trims under default `"strict"`; requires explicit `"bounded"` opt-in | `0` trims under default `"strict"`; requires explicit `"bounded"` opt-in |
| **`output_spool` delivery** | Inline `PostToolUse` `Bash`/`mcp__*` replacement (`updatedToolOutput`) + `PostToolBatch` `delivery_verified` + `cg-spool` CLI | No in-band `Shell` replacement (`"shadow"` projection; `updated_mcp_tool_output` on MCP calls) + `cursor_spool_mcp` (`cg-spool mcp` stdio) & `cg-spool` CLI (`shadow_or_mcp_cli_only_no_post_tool_replacement`) | Unsupported in-band (`unsupported_no_post_tool_replacement`: `"active"` governor-gated to `"passthrough"`, `"shadow"` projects in-memory, `cg-spool` CLI reads existing workspace spools) | Unsupported in-band (`unsupported_no_post_tool_replacement`: `"active"` governor-gated to `"passthrough"`, `"shadow"` projects in-memory, `cg-spool` CLI reads existing workspace spools) |
| **CLI rewrite permission gate** | Allowed only in `AUTO_APPROVED_PERMISSION_MODES` (`bypassPermissions`, `dontAsk`, `auto`) | Allowed only in `AUTO_APPROVED_PERMISSION_MODES` (`bypassPermissions`, `dontAsk`, `auto`) | Disabled (`False`) to preserve interactive command-approval prompt integrity | Enabled (`True`) on `run_command` |
| **Cache telemetry availability** | Measured (`cache_read`, `cache_creation`, fresh tokens; CLI vs Desktop `mcp:ccd_*` split) | `excluded_missing_telemetry` on Cursor CLI (granular cache split absent; never coerced to `0`) | Measured from local Codex session logs (`cached_input_tokens`) | Measured from local Antigravity trajectory logs |
| **`turn_correlation` ceiling** | `transcript_derived` (`harness_native` when `turn_id` present; `unobserved` without transcript) | `transcript_derived` (`harness_native` when `turn_id` present; `unobserved` without transcript) | `transcript_derived` (`harness_native` when `turn_id` present; `unobserved` without transcript) | `harness_native` (`stepIdx > 0` in hook payload) |

#### Critical Per-Harness Guarantees & Documented Limitations

* **Claude Code (`claude`):** Full `PostToolUse` output replacement and `PostToolBatch` delivery verification (`delivery_verified`); CLI vs Desktop (`mcp:ccd_*`) session attribution stays segregated. **Limitation:** Native `"onFailure": "block"` requires Claude CLI `>= 2.1.295`; older versions degrade `native_fail_closed_supported` to `False` in `probe_runtime_capabilities()` and surface a warning in `cg doctor`. Silent CLI flag rewrites stay off in interactive permission modes.
* **Cursor (`cursor`):** Native `"failClosed": true` hook enforcement and content-verified reads under `"strict"` policy. **Limitation:** `postToolUse` cannot replace `Shell` tool output in-band (`can_replace_tool_output == False`, leaving `"shadow"` projection for shell and `updated_mcp_tool_output` for MCP calls, with recovery via workspace-pinned `cursor_spool_mcp` stdio or `cg-spool` CLI); Cursor CLI lacks granular prompt-cache read/write counters and reports `cache_attribution_status = "excluded_missing_telemetry"` rather than fabricating `0`.
* **Google Antigravity (`antigravity`):** Native `stepIdx` (`harness_native` turn correlation), `PreInvocation` `O(delta)` (`80`/`200`-step) compaction warnings, and `PreToolUse` security blocking (`decision="deny"`). **Limitation:** Neither `PostToolUse` output replacement nor content-verified read bodies are exposed (`supports_content_verified_reads == False`); default `"read_confirm_policy": "strict"` intentionally produces `0` `range_trim` interventions as a safety guarantee unless `"bounded"` is explicitly configured.
* **OpenAI Codex (`codex`):** `PreToolUse` Read/Bash normalization, `PreCompact` state preservation, and `PostToolUse` shell telemetry. **Limitation:** Built-in `apply_patch` file mutations bypass `PreToolUse` (`supports_apply_patch_block == False`); hooks execute only when `[features].hooks = true` is set in `~/.codex/config.toml` and the repository directory is trusted in Codex (`Codex trust / #27833`); silent CLI flag rewrites are disabled so user approval prompts always match the exact executed command.

### 4. Backward-Compatible Migrations & Operational Rollback Paths

#### Backward-Compatible Store & Schema Migrations (`backward_compatible_migrations`)

| Migration ID | Store / Artifact | Upgrade Path & Failure-Safe Behavior |
| :--- | :--- | :--- |
| `read_ledger_v1_to_v2` | `.context_guard_state.json` | Automatically upgrades `schema_version: 1` -> `READ_LEDGER_SCHEMA = 2` on access via `state_store.locked_state` while retaining the `json_lock` backend; corrupt JSON resets cleanly to an empty ledger without hook failure. |
| `outcomes_v3_to_v4` | `outcomes.json` | `outcomes.load_outcomes()` migrates historical `schema_version: 3` files in memory to `SCHEMA_VERSION = 4`, preserving all counters and setting `legacy_v3 = True`. |
| `spool_index_v1_to_v2` | `spool_index.json` | Upgrades legacy/missing state metadata to `SPOOL_SCHEMA_VERSION = 2` monotonic states (`available`, `evicting`, `evicted`, `corrupt`) and bounded tombstones; missing or corrupted payload blobs report `unexpectedly_missing` / `corrupt` via `inspect_spool_entry()` without raising exceptions. |
| `token_usage_legacy_to_v3` | `token_usage.json` | `token_usage.restore_usage_state()` normalizes legacy usage ledgers and sanitizes malformed inner rows into `USAGE_SCHEMA_VERSION = 3`. |
| `receipts_to_evidence_ledger_v1` | `receipts.jsonl` -> `evidence_events.json` | `cg eval --ledger-verify` deduplicates `ContextReceiptV1` (`schema_version = 1`) streams into durable `evidence_events.json` (`EVENT_LEDGER_SCHEMA_VERSION = 1`) for deterministic Outcomes v4 derivation with zero double-counting. |

#### Operational Rollback Paths (`rollback_paths`) & Recovery Commands

| Rollback Path ID | Mechanism | Exact Scope & Guarantee |
| :--- | :--- | :--- |
| `staged_pack_transaction_rollback` | `StagedPackTransaction` (`services/migration_guard.py`) | Stages `*.py` into `.staging-<pack_id>-<pid>`, validates SHA-256 hashes, `POLICY_API_VERSION == 1`, and `preflight_migration_check()` before touching live files; validation or activation failure removes `.staging-*` and restores `config.json` + `policies/<pack_id>` atomically. |
| `rollback_journal_lifo` | `RollbackJournal` (`services/migration_guard.py`) | Records pre-mutation file bytes/permissions (`0o600`), directory swaps, and staged directory removals; reverts every operation in strict LIFO order on exception or `--dry-run`. |
| `ide_updater_git_reset_keep` | `executeManagedUpdate` (`vscode-extension/updater.js`) | Refuses dirty working trees, records `prevHead`, runs `git fetch` + `git merge --ff-only v<latest>` + `install_harnesses.py --install`, and automatically runs `git -C <plugin_root> reset --keep <prevHead>` if any step fails. |
| `install_harnesses_uninstall` | `python3 bin/install_harnesses.py --uninstall` | Idempotently removes Context-Guard hooks, `statusLine`, `cursor_spool_mcp`, IDE statusbar extensions, CLI shims (`cg`, `cg-outline`, `cg-spool`, `cg-budget`, `cg-eval`), and managed `outline-pull` instruction blocks while preserving unrelated user hooks. |
| `git_tag_checkout_reinstall` | Git tag checkout + installer re-sync | Downgrades runtime code, shims, and harness configs cleanly to the prior release: `git -C ~/.gemini/config/plugins/context-guard checkout v4.9.0 && python3 ~/.gemini/config/plugins/context-guard/bin/install_harnesses.py --install`. |

* **Automated 10-Gate Conformance Verification (`cg eval --conformance`):** Multi-OS CI continuously verifies `policy_api_v1_frozen`, `core_schema_versions_synced`, `capability_matrix_complete_and_honest`, `adapter_conformance_4_harnesses`, `baseline_security_pack_conformance`, `baseline_optimization_pack_reconciliation`, `tamper_and_unknown_major_fail_closed`, `backward_compatible_migrations_ok`, `rollback_paths_verified`, and `effectiveness_and_limitations_published`.

### 5. Published Effectiveness Evidence & Methodological Limitations

Context-Guard separates deterministic mechanism verification from live stochastic LLM evaluation so token-reduction counters are never misrepresented as causal billing or pass-rate proof.

| Evidence Tier / Command | What It Proves | Explicit Methodological Limitations |
| :--- | :--- | :--- |
| **Deterministic Offline Replay** (`cg_status.py --replay`, `cg eval --offline-replay`, `--governor-check`, `--hardening-check`, `--conformance`) | Proves deterministic multi-harness hook decisions (`outline`, `range_trim`, `cli_rewrite`, `output_spool`, security `deny`), SHA-256 spool integrity, Adaptive Governor circuit-breaker invariants, scrubbed explainability/OTel export, and 10-gate platform conformance in isolated temp directories. | Carries **`statistical_proof = false`**. Offline replay evaluates a fixed synthetic tool-call corpus and **does not** simulate multi-turn LLM reasoning trajectories, model retry behavior, prompt-cache TTL dynamics, or autonomous `cg-spool` recovery choices. |
| **Latency & Storage Backend Benchmark** (`cg_status.py --benchmark`, `BackendBenchmarkContractV1`) | Measures cold/warm hook latency percentiles (`min`, `p50`, `p95`, `p99`) and verifies Read Ledger v2 `json_lock` stays within `p95`/`p99` budgets (`decision = "retain_json_lock"`, `migration_performed = False`), benchmarking `sqlite_wal` and `segmented_jsonl` only when thresholds are exceeded or forced. | Reflects local OS file-locking and filesystem serialization overhead on synthetic ledgers rather than end-to-end LLM API network latency. |
| **Small Live Pilot** (`cg eval --pilot`, `small_live_pilot`: `6 tasks x 2 configs x 3 repeats = 36 runs`) | Provides a fast, workspace-isolated live smoke gate to catch gross pass-rate drops, broken recovery loops, or runaway turn amplification before full evaluation. | Sample size (`36` runs) is underpowered for narrow confidence intervals and is a regression gate, **not** statistical proof of net cost reduction. |
| **Release Evaluation** (`cg eval --release`, `release_evaluation`: `12-15 tasks x 3 configs x 2 repeats = 72-90 runs/harness`) | Measures **`Cost per Passed Run`** (`total_cost_usd_all_attempts / passed_runs`, `undefined` at `0` passes) across Baseline, Context-Guard, and Context-Guard + RTK with Wilson pass-rate intervals, bootstrap CIs, and pinned `CapabilityAttestationKey` provenance. | Results hold strictly for the attested `(harness_id, harness_build_id, adapter_version, hook_config_fingerprint, model_id)` tuple and task distribution; upgrading the harness CLI or changing models invalidates prior capability/cost claims. |
| **Observational Outcomes Attribution** (`cg_status.py --outcomes`, `outcomes.json` v4) | Tracks live per-harness/model intervention counts, targeted vs. full spool recovery, `suspected` vs. `confirmed` regret, 30-day `sunset_verdict`, and `Est. associated model cost`. | **`Estimated Cost Impact` is observational `1/k` step-weighted transcript attribution, never causal counterfactual A/B proof.** Failed attempts (`failed_attempt`) and endogenous prompt-cache `TTL cache misses` are **never** excluded from `Cost per Passed Run`, and missing telemetry (e.g., Cursor CLI `excluded_missing_telemetry`) is never reported as `0`. |

---

## Part IV — `v5.1.0` Architectural Hardening & 8-Layer Acyclic DAG

While preserving frozen `POLICY_API_VERSION = 1` and all 17 `CORE_SCHEMA_VERSIONS` entries from `v5.0.0`, `v5.1.0` eliminates cross-layer cycles, duplicate utilities, lock-held subprocess calls, and silent write/integrity edge cases across the codebase.

### 1. Enforced 8-Layer Acyclic Dependency Graph (`Tarjan Package SCC == 0`)

```text
Layer 0: core/          -> {}                                                           (platform_io, contracts, scrub, shell_lexer)
Layer 1: policies/      -> {core}                                                       (Policy API v1, loader, governor)
Layer 2: spool/         -> {core, policies}                                             (domain spool store, receipts, classifier, MCP)
Layer 2: integrations/  -> {core}                                                       (opt-in CLI/JSON adapters; zero hooks.*)
Layer 3: hooks/         -> {core, policies, spool, integrations}                        (hook pipeline, functional telemetry_core, drift_probe)
Layer 4: services/      -> {core, policies, spool, integrations, hooks}                 (18 off-hot-path application & reporting services)
Layer 5: evidence/      -> {core, policies, spool, integrations, hooks, services}       (ledger, metrics, runner, conformance)
Layer 6: bin/           -> {core, policies, spool, integrations, hooks, services, evidence} (10 thin CLI entrypoints <= 350 LOC each)
```

Mechanical AST checks in `tests/test_module_boundaries.py` enforce `Tarjan Package SCC == 0` (including lazy function/class imports), `Tarjan File SCC == 0`, strict layer direction, `0` production `assert` statements, `0` `X as X` identity re-export aliases, `bin/*.py <= 350` LOC, and `hooks/*.py < 6,800` LOC.

### 2. Core Reliability & Concurrency Hardening Delivered in `v5.1.0`

* **Transactional Read Planner & State Persistence (`hooks/state_store.py`, `hooks/read_planner.py`, `hooks/pre_tool_use.py`):** Raises `StatePersistenceError` when `locked_state` fails to flush dirty mutations, falls back cleanly on read-only `state_dir` snapshots (`LOCK_SH`/unlocked `warn`), verifies `sha256` and `reads` inside `locked_state` to abort stale trims on concurrent mutations, strips dangling redirects if unwrap fails, merges Pass-1 `pack_ow` decisions, and keeps `PreToolUse` fail-open for planner I/O vs. fail-closed for security packs.
* **Functional Telemetry Core & Outcomes Integrity (`hooks/telemetry_core.py`, `hooks/telemetry.py`, `hooks/outcomes.py`, `hooks/post_tool_use.py`):** Extracts pure `telemetry_core`, prevents `step_idx <= 0` eviction blackholes and `|` key collisions in `open_windows`, supports dual-ended `trimmed_spans`, preserves global `shadow_spools` on per-session compaction, skips `tier=0` LRU pollution, unifies read caps in `core.contracts.HARNESS_CAPABILITIES`, and routes `PostToolUse` `state_dir=None` outcomes to `DEFAULT_OUTCOMES_PATH`.
* **Lock Hygiene, Spool GC & Security Ceilings (`hooks/drift_probe.py`, `spool/store.py`, `policies/governor.py`, `evidence/`):** Moves `subprocess` drift probes and session transition hooks outside `locked_state`, closes spool GC vs. read verification races via locked file descriptors, enforces `_static_capability_ceiling` in both `governor` and `evidence/ledger.py`, moves `replay_governor_decisions` into `evidence/conformance.py`, and clears `hooks.config` cache around isolated env-mutating runs.
* **Service Extraction, Rollback & CLI Exit Parity (`services/`, `bin/`, `vscode-extension/`):** Moves 13 non-CLI modules and 4 extracted service modules (`installer_service`, `explain_service`, `export_service`, `status_service`) into `services/`, wraps default `install_all` in `RollbackJournal`, aggregates Schema v4 `outcomes.by_key` in `services/replay_benchmark.py`, returns exit code `1` on installer/`cg_status.py` errors (keeping `--claude-hud` fail-open `0`), and adds `outputs_spooled` and `reliability_failures` cards to `vscode-extension/view_model.js`.
