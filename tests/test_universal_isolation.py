"""Regression gates guaranteeing zero local-environment leakage in default plugin installs."""

from __future__ import annotations

import json
import ntpath
import os
import re
from pathlib import Path
from typing import Any

import pytest

from hooks import config as guard_config
from hooks.governance_guard import is_protected_governance_path
from hooks.local_repo_guard import load_guard_config
from hooks.pre_tool_use import evaluate_hook
from hooks.shell_parser import rewrite_quiet_cli_flags

ROOT = Path(__file__).resolve().parent.parent


def assert_allowed(res: dict[str, Any], harness: str) -> None:
    if harness == "antigravity":
        assert res.get("decision") == "allow", f"Expected Antigravity allow, got: {res}"
    else:
        hso = res.get("hookSpecificOutput")
        if isinstance(hso, dict):
            assert hso.get("permissionDecision") != "deny", f"Unexpected {harness} deny: {res}"
        else:
            assert res == {}, f"Expected empty allow dict for {harness}, got: {res}"


def assert_denied(res: dict[str, Any], harness: str, expected_substr: str = "") -> None:
    if harness == "antigravity":
        assert res.get("decision") == "deny", f"Expected Antigravity deny, got: {res}"
        reason = str(res.get("reason") or "")
    else:
        hso = res.get("hookSpecificOutput")
        assert isinstance(hso, dict), f"Expected {harness} hookSpecificOutput, got: {res}"
        assert hso.get("permissionDecision") == "deny", f"Expected {harness} deny, got: {res}"
        reason = str(hso.get("permissionDecisionReason") or "")
    if expected_substr:
        assert expected_substr.lower() in reason.lower(), f"Missing {expected_substr!r} in {reason!r}"


def _shell_call(harness: str, command: str, cwd: Path) -> dict[str, Any]:
    if harness == "antigravity":
        return {
            "conversationId": "c-univ",
            "stepIdx": 1,
            "cwd": str(cwd),
            "toolCall": {"name": "run_command", "args": {"CommandLine": command}},
        }
    tool_name = {"claude": "Bash", "cursor": "Shell", "codex": "exec_command"}[harness]
    inp = {"cmd": command} if harness == "codex" else {"command": command}
    return {
        "session_id": f"s-{harness}",
        "tool_name": tool_name,
        "tool_input": inp,
        "cwd": str(cwd),
    }


def _write_call(harness: str, target_path: Path, cwd: Path) -> dict[str, Any]:
    if harness == "antigravity":
        return {
            "conversationId": "c-univ",
            "stepIdx": 1,
            "cwd": str(cwd),
            "toolCall": {"name": "write_file", "args": {"Path": str(target_path)}},
        }
    if harness == "claude":
        return {
            "session_id": "s-claude",
            "tool_name": "Write",
            "tool_input": {"file_path": str(target_path)},
            "cwd": str(cwd),
        }
    if harness == "cursor":
        return {
            "session_id": "s-cursor",
            "tool_name": "StrReplace",
            "tool_input": {"path": str(target_path)},
            "cwd": str(cwd),
        }
    rel = target_path.relative_to(cwd).as_posix()
    patch = f"*** Begin Patch\n*** Add File: {rel}\n+ok\n*** End Patch"
    return {
        "session_id": "s-codex",
        "tool_name": "apply_patch",
        "tool_input": {"patch": patch},
        "cwd": str(cwd),
    }


def test_default_install_without_config_never_blocks_project_files_or_git_workflows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_config.clear_config_cache()
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(tmp_path / "absent_config.json"))
    cfg = load_guard_config()
    assert cfg["enforce_governance_policy"] is False

    project = tmp_path / "external-webapp"
    project.mkdir()
    state_dir = str(tmp_path / "state")

    normal_project_targets = (
        project / ".husky" / "pre-commit",
        project / ".githooks" / "pre-commit",
        project / "scripts" / "audit" / "seo_audit.py",
        project / "scripts" / "hooks" / "post_deploy.sh",
        project / "tests" / "baselines" / "home_snapshot.json",
        project / "scripts" / "ci" / "run-quality-suite.sh",
        project / ".claude" / "settings.local.json",
    )
    normal_shell_commands = (
        "git add .",
        "git add -A",
        'git commit -m "chore: initial setup" --no-verify',
        'SKIP=eslint git commit -m "wip"',
        "HUSKY=0 git commit -m 'wip'",
        f"echo 'npx lint-staged' > {project / '.husky' / 'pre-commit'}",
    )

    for harness in ("antigravity", "claude", "cursor", "codex"):
        for target in normal_project_targets:
            res = evaluate_hook(
                _write_call(harness, target, project),
                state_dir=state_dir,
                cli_harness=harness,
            )
            assert_allowed(res, harness)
        for cmd in normal_shell_commands:
            res_sh = evaluate_hook(
                _shell_call(harness, cmd, project),
                state_dir=state_dir,
                cli_harness=harness,
            )
            assert_allowed(res_sh, harness)


def test_bigquery_isolation_works_independently_when_governance_policy_is_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_config.clear_config_cache()
    cfg_path = tmp_path / "bq_only_config.json"
    cfg_path.write_text(
        json.dumps(
            {
                "restricted_bq_datasets": ["raw_orders_private"],
                "allowed_bq_views_dataset": "ai_views",
                "allowed_bq_views_hint": "ai_views.*",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    state_dir = str(tmp_path / "state")
    project = tmp_path / "analytics-proj"
    project.mkdir()

    # Git add . and .husky edits remain allowed because enforce_governance_policy is False
    assert_allowed(
        evaluate_hook(_shell_call("claude", "git add .", project), state_dir=state_dir, cli_harness="claude"),
        "claude",
    )
    assert_allowed(
        evaluate_hook(
            _write_call("claude", project / ".husky" / "pre-commit", project),
            state_dir=state_dir,
            cli_harness="claude",
        ),
        "claude",
    )

    # BigQuery raw dataset queries are still hard-blocked
    assert_denied(
        evaluate_hook(
            _shell_call("claude", 'bq query "SELECT * FROM raw_orders_private.orders"', project),
            state_dir=state_dir,
            cli_harness="claude",
        ),
        "claude",
        "ai-views",
    )

    # Non-boolean enforce_governance_policy fails closed
    cfg_path.write_text(json.dumps({"enforce_governance_policy": "yes"}), encoding="utf-8")
    guard_config.clear_config_cache()
    assert load_guard_config()["config_error"] == "invalid 'enforce_governance_policy': expected boolean"


def test_enforce_governance_policy_allows_generic_dirs_in_unguarded_git_repos_while_protecting_guarded_repos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_config.clear_config_cache()
    ws_root = tmp_path / "workspace"
    ws_root.mkdir()
    cfg_path = tmp_path / "gov_config.json"
    cfg_path.write_text(
        json.dumps({"workspace_root": str(ws_root), "enforce_governance_policy": True}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    assert load_guard_config()["enforce_governance_policy"] is True
    state_dir = str(tmp_path / "state")

    # 1. Unguarded client git repository (e.g. Magento / React storefront without Guard Core)
    client_repo = ws_root / "client-storefront"
    (client_repo / ".git").mkdir(parents=True)
    for generic_rel in (
        "tests/baselines/checkout.json",
        "scripts/audit/hyva_templates.php",
        "scripts/hooks/cache_warm.sh",
        "scripts/ci/run-quality-suite.sh",
    ):
        assert_allowed(
            evaluate_hook(
                _write_call("claude", client_repo / generic_rel, client_repo),
                state_dir=state_dir,
                cli_harness="claude",
            ),
            "claude",
        )
    # Actual git/harness hooks and guard manifests in client_repo remain protected under policy
    for real_gov_rel in (".githooks/pre-commit", ".husky/pre-commit", ".claude/settings.json", "guard_manifest.json"):
        assert_denied(
            evaluate_hook(
                _write_call("claude", client_repo / real_gov_rel, client_repo),
                state_dir=state_dir,
                cli_harness="claude",
            ),
            "claude",
            "governance",
        )

    # 2. Guarded repository (has .git + scripts/audit/guard_manifest.json)
    guarded_repo = ws_root / "core-platform"
    (guarded_repo / ".git").mkdir(parents=True)
    (guarded_repo / "scripts" / "audit").mkdir(parents=True)
    (guarded_repo / "scripts" / "audit" / "guard_manifest.json").write_text("{}", encoding="utf-8")
    for guarded_rel in (
        "tests/baselines/refactoring_slop.json",
        "scripts/audit/ai_slop_scanner.py",
        "scripts/hooks/antigravity_stop_guard.py",
        "scripts/ci/run-quality-suite.sh",
    ):
        assert_denied(
            evaluate_hook(
                _write_call("claude", guarded_repo / guarded_rel, guarded_repo),
                state_dir=state_dir,
                cli_harness="claude",
            ),
            "claude",
            "governance",
        )

    # 3. Workspace-level scripts/hooks/ and operator config.json remain protected
    assert_denied(
        evaluate_hook(
            _write_call("claude", ws_root / "scripts" / "hooks" / "claude_stop_guard.py", ws_root),
            state_dir=state_dir,
            cli_harness="claude",
        ),
        "claude",
        "governance",
    )
    assert_denied(
        evaluate_hook(
            _write_call("claude", cfg_path, ws_root),
            state_dir=state_dir,
            cli_harness="claude",
        ),
        "claude",
        "governance",
    )

    # 4. Windows drive-letter paths & ntpath.normcase (which flips "/" -> "\\") preserve symmetric governance checks
    if os.name == "nt":
        win_raw = str(client_repo / "tests" / "baselines" / "checkout.json")
    else:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "C:" / "Users" / "dev" / "client-storefront" / ".git").mkdir(parents=True)
        win_raw = r"C:\Users\dev\client-storefront\tests\baselines\checkout.json"
    assert is_protected_governance_path(win_raw, cwd=None, workspace_root=None) is None
    with monkeypatch.context() as mp_nt:
        mp_nt.setattr(os.path, "normcase", ntpath.normcase)
        assert is_protected_governance_path(str(cfg_path), cwd=str(ws_root), workspace_root=ws_root) == "context_guard_config"


def test_inline_scripts_with_type_arrows_comparisons_and_str_replace_do_not_false_positive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_config.clear_config_cache()
    ws_root = tmp_path / "workspace"
    ws_root.mkdir()
    cfg_path = tmp_path / "gov_config.json"
    cfg_path.write_text(
        json.dumps({"workspace_root": str(ws_root), "enforce_governance_policy": True}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    assert load_guard_config()["enforce_governance_policy"] is True
    state_dir = str(tmp_path / "state")

    benign_inline_cmds = (
        'python3 -c "def fmt(s: str) -> str: return s.replace(\'a\', \'b\'); print(fmt(\'.husky\'))"',
        'python3 -c "x = 5; print(x >= 2, \'guard_manifest.json\')"',
        'node -e "const f = (s) => s.replace(/x/, \'y\'); console.log(f(\'.githooks\'))"',
        'python3 -c "import json; print(json.load(open(\'/Users/dev/.config/context-guard/config.json\')))"',
        'python3 -c "open(\'.husky/pre-commit\', \'r\').read()"',
        'python3 -c "open(\'.husky/pre-commit\', mode=\'rb\').read()"',
    )
    for cmd in benign_inline_cmds:
        assert_allowed(
            evaluate_hook(_shell_call("claude", cmd, ws_root), state_dir=state_dir, cli_harness="claude"),
            "claude",
        )

    malicious_inline_cmds = (
        'python3 -c "import os; os.replace(\'/tmp/x\', \'.husky/pre-commit\')"',
        'python3 -c "open(\'.husky/pre-commit\', \'w\').write(\'exit 0\')"',
        'python3 -c "open(\'.husky/pre-commit\', \'a\')"',
        'python3 -c "open(\'.husky/pre-commit\', mode=\'w+\')"',
        "bash <<'EOF'\necho 'exit 0' > .husky/pre-commit\nEOF",
    )
    for cmd in malicious_inline_cmds:
        assert_denied(
            evaluate_hook(_shell_call("claude", cmd, ws_root), state_dir=state_dir, cli_harness="claude"),
            "claude",
            "governance",
        )


def test_exported_rules_agents_md_and_root_agents_md_enforce_universal_isolation() -> None:
    root_agents = ROOT / "AGENTS.md"
    assert root_agents.is_file(), "Root AGENTS.md with universal plugin isolation constitution must exist"
    root_text = root_agents.read_text(encoding="utf-8")
    assert "Universal Plugin Isolation" in root_text
    assert "test_version_source.py" in root_text

    exported_rules = (ROOT / "rules" / "AGENTS.md").read_text(encoding="utf-8")
    leaked_tokens = (
        "twg",
        "auth.conf",
        "Teamwork Graph",
        "test_version_source.py",
        "vscode-extension/README.md",
        "local_repository_map.md",
        "repos/<category>",
    )
    for tok in leaked_tokens:
        assert tok not in exported_rules, (
            f"Exported rules/AGENTS.md must stay universal across all user projects; leaked {tok!r}"
        )

    antigravity_home_re = re.compile(r'Path\.home\(\)\s*/\s*["\']Antigravity["\']')
    for folder in ("hooks", "bin"):
        for py_path in sorted((ROOT / folder).glob("*.py")):
            src = py_path.read_text(encoding="utf-8")
            assert antigravity_home_re.search(src) is None, (
                f"Hardcoded ~/Antigravity workspace path found in {py_path.relative_to(ROOT)}"
            )


def test_npm_and_pnpm_test_commands_are_not_silenced() -> None:
    for cmd in (
        "npm test",
        "npm run test",
        "pnpm test",
        "pnpm run test",
        "cd /repo && npm test",
        "cd /repo && pnpm test",
    ):
        assert rewrite_quiet_cli_flags(cmd) is None
