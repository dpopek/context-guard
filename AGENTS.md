# Context-Guard Repository Engineering Rules (`AGENTS.md`)

This repository builds **Context-Guard**, a universal, cross-OS (`macOS`, `Linux`, `Windows`), multi-harness (`Google Antigravity`, `Claude Code`, `Cursor IDE`, `OpenAI Codex`) token optimization plugin distributed to external developers and heterogeneous engineering teams.

## 1. Universal Plugin Isolation & Zero Local Leakage Policy (MANDATORY)

Under **NO** circumstances may author-specific, company-specific, or local-workspace constraints affect default plugin behavior or leak into other developers' projects:

1. **Non-Blocking Universal Defaults:** A default installation (with `~/.config/context-guard/config.json` absent or using default values) **MUST NEVER** block file writes, directory creation, Git staging/commits (`git add .`, `git add -A`, `.husky/*`, `.githooks/*`), test snapshots (`tests/baselines/*`), project scripts (`scripts/hooks/*`, `scripts/audit/*`, `scripts/ci/*`), or worktree workflows across any project stack (`PHP`, `JS/TS`, `Python`, `Go`, `Rust`, `Docker`, etc.).
2. **Strict Opt-In for Policy & Environment Guards:**
   - Workspace governance rules (`enforce_governance_policy`), Local-First GitLab interception (`repo_map_path`), and BigQuery dataset isolation (`restricted_bq_datasets`) **MUST** remain `false` / empty by default and activate strictly when explicitly configured in `~/.config/context-guard/config.json`.
   - Even when `enforce_governance_policy: true` is enabled on an operator's machine, generic project subdirectories (`scripts/audit/`, `scripts/hooks/`, `tests/baselines/`, `scripts/ci/run-quality-suite.sh`) inside non-guarded Git repositories (repositories with `.git` that do not carry Guard Core markers) **MUST** remain writable.
3. **Zero Hardcoded Local Paths or Private Tooling:**
   - Production code (`hooks/*`, `bin/*`, `vscode-extension/*`) and exported user rules (`rules/AGENTS.md`) **MUST NOT** hardcode personal home subdirectories (e.g. `~/workspace`), company/client repository names, internal dataset names, or private local CLIs/auth paths.
   - `rules/AGENTS.md` is injected globally into every end-user project in Antigravity: keep it strictly limited to universal token/context discipline rules. Repository maintenance rules for developing `context-guard` belong exclusively in this root `AGENTS.md`.
4. **Lossless CLI Rewrites Only:** `rewrite_quiet_cli_flags` (`hooks/shell_parser.py`) **MUST NOT** inject flags (such as `jest --silent`, `npm test --silent`, or `pnpm --silent test`) that suppress failure diagnostics or stderr output in arbitrary user test runners.
5. **Mechanical Verification:** Every rule above is enforced by `tests/test_universal_isolation.py` and `tests/test_module_boundaries.py`. Never weaken or delete those assertions.

## 2. Architecture, Runtime Compatibility & Conciseness Gates

1. **Python 3.9+ Pure `stdlib` Runtime:** All `hooks/*.py` and `bin/*.py` modules must run on `Python 3.9+` using 100% Python standard library (`from __future__ import annotations`, zero bare `except:`, zero unguarded Unix-only imports) and pass `mypy --python-version 3.9 --platform darwin/linux/win32 hooks bin`.
2. **Acyclic Module Graph & File Size Ceilings:**
   - `Tarjan SCC == 0` across `hooks/*` and `bin/*` (`tests/test_module_boundaries.py`).
   - Every file in `hooks/*.py`, `bin/*.py`, and `tests/*.py` must stay `<= 800` LOC (`hooks/outline.py < 680` LOC).
   - Tests must use plain `pytest` functions (no `unittest.TestCase`), never access private `_` symbols from `hooks/*` or `bin/*`, never hardcode the manifest version string, and avoid chronological wave filenames.
3. **Documentation Synchronization & Conciseness Gate (`tests/test_version_source.py` & `.githooks/pre-commit`):**
   - Every change to `hooks/*.py`, `bin/*.py`, `vscode-extension/*`, `plugin.json`, or `hooks.json` **MUST** keep `README.md`, `vscode-extension/README.md`, and `CHANGELOG.md` synchronized (`README.md <= 18,000` B, `vscode-extension/README.md <= 6,500` B, README bullets `<= 220` chars, `CHANGELOG.md` bullets `<= 140` chars, `plugin.json["description"]` `80..300` chars).
   - Every production module (`hooks/*.py`, `bin/*.py`, `vscode-extension/*.js`), CLI flag (`cg_status.py`, `install_harnesses.py`), and `REQUIRED_CONFIG_KEYS` entry must be documented in `README.md`.
