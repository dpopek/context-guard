# Context-Guard — Development Roadmap `v4.5.2`–`v5.0.0` and Architectural Freeze Record

**Status:** `ARCHITECTURAL FREEZE` — approved direction; implementation details subject to contract tests  
**Date:** November 16, 2026  
**Analysis baseline:** `v4.5.1`, commit `54045e2f793893a895c8693f61c1ac63f0c7ed01` (`7/7` green Multi-OS CI jobs per reported verification)  
**Supported harnesses:** Claude Code, Cursor, OpenAI Codex, Google Antigravity  
**Document purpose:** authoring specifications, TDD plans, issues, and acceptance criteria for upcoming releases

> [!NOTE]
> **Repository state in `v4.6.0`:** Following the closure of the Architectural Freeze (`INV-1`–`INV-7`) in `v4.5.3`, `v4.6.0` delivered the **Preamble & MCP Budget Advisor**: passive, read-only `cg budget` auditing (`--preamble`, `--mcp`, `--recommendations`) for Antigravity, Claude Code, Cursor, and Codex with explicit `measured` / `estimated` / `unavailable` separation, secret and home-path redaction, duplicate and MCP tool overlap detection, cautious session profiles (`minimal-core`, `full-integrations`), explicit opt-in `--probe` stdio `tools/list` inspection, and a unified `cg` dispatcher (with `cg` and `cg-budget` shims), opening the gate for `v4.7.0` work.

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
