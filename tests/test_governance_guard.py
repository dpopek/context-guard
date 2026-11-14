"""Hermetic multi-harness tests for governance path protection, shell bypass, BigQuery hard gate, and CLI diagnostics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hooks import config as guard_config
from hooks import pre_tool_use
from hooks.governance_guard import check_shell_protected_writes, is_protected_governance_path
from hooks.local_repo_guard import load_guard_config
from hooks.pre_tool_use import evaluate_hook
from hooks.shell_parser import rewrite_quiet_cli_flags
from hooks.state_store import STATE_FILENAME

FIVE_RAW_DATASETS = [
    "raw_orders_svc",
    "raw_catalog_svc",
    "raw_customers_svc",
    "raw_pricing_svc",
    "analytics_regional_ops",
]


def _write_cfg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra: dict[str, Any] | None = None,
) -> tuple[Path, Path, str]:
    guard_config.clear_config_cache()
    ws_root = tmp_path / "workspace"
    ws_root.mkdir(parents=True, exist_ok=True)
    state_dir = tmp_path / "state"
    cfg_path = tmp_path / "test_cg_config.json"
    doc: dict[str, Any] = {
        "workspace_root": str(ws_root),
        "enforce_governance_policy": True,
        "restricted_bq_datasets": list(FIVE_RAW_DATASETS),
        "allowed_bq_views_dataset": "ai_views",
        "allowed_bq_views_hint": "ai_views.v_sales_orders",
    }
    if extra:
        doc.update(extra)
    cfg_path.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    return ws_root, cfg_path, str(state_dir)


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


def assert_allowed(res: dict[str, Any], harness: str) -> None:
    if harness == "antigravity":
        assert res.get("decision") == "allow", f"Expected Antigravity allow, got: {res}"
    else:
        hso = res.get("hookSpecificOutput")
        if isinstance(hso, dict):
            assert hso.get("permissionDecision") != "deny", f"Unexpected {harness} deny: {res}"
        else:
            assert res == {}, f"Expected empty allow dict for {harness}, got: {res}"


def _shell_payload(harness: str, command: str, cwd: str | None = None) -> dict[str, Any]:
    if harness == "antigravity":
        return {
            "conversationId": "conv-gov",
            "stepIdx": 1,
            "toolCall": {"name": "run_command", "args": {"CommandLine": command}},
        }
    tool_name = {
        "claude": "Bash",
        "cursor": "Shell",
        "codex": "exec_command",
    }[harness]
    inp: dict[str, Any] = {"cmd": command} if harness == "codex" else {"command": command}
    payload: dict[str, Any] = {
        "session_id": f"sess-{harness}",
        "transcript_path": f"/tmp/.{harness}/session.jsonl",
        "tool_name": tool_name,
        "tool_input": inp,
    }
    if cwd is not None:
        payload["cwd"] = cwd
    return payload


def test_blocks_direct_file_edits_and_apply_patch_to_governance_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)
    repo = ws_root / "alpha-service"
    repo.mkdir()

    protected_rel_paths = (
        "scripts/audit/ai_slop_scanner.py",
        "scripts/audit/guard_manifest.json",
        "guard_manifest.json",
        "tests/baselines/foo.json",
        ".githooks/pre-commit",
        ".husky/pre-commit",
        ".agent-verification-token.json",
        ".agent-failure-streak.json",
        "scripts/ci/verify_agent_state.py",
        "scripts/ci/run-quality-suite.sh",
    )

    for rel in protected_rel_paths:
        abs_target = str(repo / rel)
        # 1. Antigravity edit_file & write_file
        ag_edit = evaluate_hook(
            {
                "conversationId": "c1",
                "stepIdx": 1,
                "toolCall": {"name": "edit_file", "args": {"Path": abs_target}},
            },
            state_dir=state_dir,
        )
        assert_denied(ag_edit, "antigravity", "governance")

        # 2. Claude Edit & Write
        for claude_tool in ("Edit", "Write"):
            cl_res = evaluate_hook(
                {
                    "session_id": "s-cl",
                    "tool_name": claude_tool,
                    "tool_input": {"file_path": abs_target},
                    "cwd": str(repo),
                },
                state_dir=state_dir,
                cli_harness="claude",
            )
            assert_denied(cl_res, "claude", "governance")

        # 3. Cursor StrReplace
        cu_res = evaluate_hook(
            {
                "session_id": "s-cu",
                "tool_name": "StrReplace",
                "tool_input": {"path": rel},
                "cwd": str(repo),
            },
            state_dir=state_dir,
            cli_harness="cursor",
        )
        assert_denied(cu_res, "cursor", "governance")

        # 4. Codex apply_patch
        patch_body = f"*** Begin Patch\n*** Update File: {rel}\n@@\n-old\n+new\n*** End Patch"
        cx_res = evaluate_hook(
            {
                "session_id": "s-cx",
                "tool_name": "apply_patch",
                "tool_input": {"patch": patch_body},
                "cwd": str(repo),
            },
            state_dir=state_dir,
            cli_harness="codex",
        )
        assert_denied(cx_res, "codex", "governance")

    # Normal application source edits remain allowed
    ok_res = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 2,
            "toolCall": {"name": "edit_file", "args": {"Path": str(repo / "src" / "app.py")}},
        },
        state_dir=state_dir,
    )
    assert_allowed(ok_res, "antigravity")


def test_blocks_shell_sed_redirect_and_inline_python_targeting_protected_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)
    repo = ws_root / "alpha-service"
    repo.mkdir()

    malicious_cmds = (
        f"sed -i '' 's/ceiling/999/' {repo}/scripts/audit/ai_slop_scanner.py",
        f"echo '{{}}' > {repo}/tests/baselines/x.json",
        f"echo '{{}}' >> {repo}/.agent-verification-token.json",
        f"cat /tmp/fake.json | tee {repo}/guard_manifest.json",
        f"cp /tmp/fake.json {repo}/scripts/audit/guard_manifest.json",
        f"rm -f {repo}/.githooks/pre-commit",
        f"chmod -x {repo}/scripts/ci/run-quality-suite.sh",
        f"git -C {repo} checkout -- tests/baselines/x.json",
        f"git -C {repo} restore scripts/audit/ai_slop_scanner.py",
        "python3 -c \"open('scripts/audit/guard_manifest.json', 'w').write('{}')\"",
        "python3 - <<'EOF'\nfrom pathlib import Path\nPath('tests/baselines/b.json').write_text('{}')\nEOF",
    )

    for cmd in malicious_cmds:
        for harness in ("antigravity", "claude", "cursor", "codex"):
            res = evaluate_hook(
                _shell_payload(harness, cmd, cwd=str(repo)),
                state_dir=state_dir,
                cli_harness=harness,
            )
            assert_denied(res, harness, "governance")


def test_resolves_repos_symlink_when_checking_protected_governance_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)
    real_repo = ws_root / "alpha-screener"
    (real_repo / "scripts" / "audit").mkdir(parents=True)
    scanner = real_repo / "scripts" / "audit" / "ai_slop_scanner.py"
    scanner.write_text("# guard\n", encoding="utf-8")

    symlink_parent = ws_root / "repos" / "core"
    symlink_parent.mkdir(parents=True)
    symlink_repo = symlink_parent / "alpha-screener"
    symlink_repo.symlink_to(real_repo, target_is_directory=True)

    symlink_target = symlink_repo / "scripts" / "audit" / "ai_slop_scanner.py"
    ag_res = evaluate_hook(
        {
            "conversationId": "c-sym",
            "stepIdx": 1,
            "toolCall": {"name": "edit_file", "args": {"Path": str(symlink_target)}},
        },
        state_dir=state_dir,
    )
    assert_denied(ag_res, "antigravity", "governance")

    sed_res = evaluate_hook(
        _shell_payload("claude", f"sed -i '' 's/guard/noop/' {symlink_target}", cwd=str(ws_root)),
        state_dir=state_dir,
        cli_harness="claude",
    )
    assert_denied(sed_res, "claude", "governance")


def test_blocks_all_git_hook_and_env_bypass_vectors_across_four_harnesses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)
    bypass_commands = (
        'git commit -m "bypass" --no-verify',
        'git push origin feat/x --no-verify',
        'git merge main --no-verify',
        'git rebase main --no-verify',
        'git cherry-pick abc1234 --no-verify',
        'git commit -n -m "short flag"',
        'git commit -anm "clustered short flag"',
        'git -c core.hooksPath=/dev/null commit -m "hooksPath"',
        'git config core.hooksPath /dev/null',
        'HUSKY=0 git commit -m "husky off"',
        'HUSKY_SKIP_HOOKS=1 git commit -m "husky skip"',
        'SKIP=all git commit -m "pre-commit skip"',
        'PRE_COMMIT_ALLOW_NO_CONFIG=1 git commit -m "no cfg"',
        'ALLOW_ASSERTION_REDUCTION=1 git commit -m "tamper"',
        'ALLOW_TEST_DELETION=1 git commit -m "delete test"',
        'ALLOW_CUSTOM_VERIFY_CMD=1 python3 scripts/ci/verify_agent_state.py --cmd true',
        'SKIP_AGENT_GUARD=1 git commit -m "skip guard"',
        'python3 scripts/ci/verify_agent_state.py --reset-circuit-breaker',
        'git add .',
        'git add -A',
        'git add --all',
    )

    for cmd in bypass_commands:
        for harness in ("antigravity", "claude", "cursor", "codex"):
            res = evaluate_hook(
                _shell_payload(harness, cmd, cwd=str(ws_root)),
                state_dir=state_dir,
                cli_harness=harness,
            )
            assert_denied(res, harness)


def test_allows_no_verify_substring_inside_quoted_commit_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)
    safe_commands = (
        'git commit -m "fix: block --no-verify and HUSKY=0"',
        "git commit -am 'chore: document --no-verify, --reset-circuit-breaker, and core.hooksPath'",
        "git log -n 5 --oneline",
        "git clean -n",
        "git config --global --get core.hooksPath",
        "git config --list",
        "git add src/feature.py tests/test_feature.py",
    )

    for cmd in safe_commands:
        for harness in ("antigravity", "claude", "cursor", "codex"):
            res = evaluate_hook(
                _shell_payload(harness, cmd, cwd=str(ws_root)),
                state_dir=state_dir,
                cli_harness=harness,
            )
            assert_allowed(res, harness)


def test_blocks_all_five_bigquery_raw_datasets_in_mcp_without_second_attempt_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)

    for ds in FIVE_RAW_DATASETS:
        sql = f"SELECT * FROM `acme-analytics-prod.{ds}.events` LIMIT 10"
        ag_payload = {
            "conversationId": "c-bq",
            "stepIdx": 1,
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "bigquery",
                    "ToolName": "execute_sql_readonly",
                    "Arguments": {"query": sql},
                },
            },
        }
        first = evaluate_hook(ag_payload, state_dir=state_dir)
        second = evaluate_hook(ag_payload, state_dir=state_dir)
        assert_denied(first, "antigravity", "ai_views")
        assert_denied(second, "antigravity", "ai_views")
        assert "repeat this exact bigquery call" not in first["reason"].lower()

        cl_payload = {
            "session_id": "s-bq",
            "tool_name": "mcp__bigquery__execute_sql_readonly",
            "tool_input": {"query": sql},
        }
        cl_first = evaluate_hook(cl_payload, state_dir=state_dir, cli_harness="claude")
        cl_second = evaluate_hook(cl_payload, state_dir=state_dir, cli_harness="claude")
        assert_denied(cl_first, "claude", "ai_views")
        assert_denied(cl_second, "claude", "ai_views")


def test_blocks_bigquery_raw_datasets_in_shell_bq_cli_and_python_sdk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)

    blocked_shell_cmds = (
        "bq query --use_legacy_sql=false 'SELECT * FROM raw_customers_svc.users LIMIT 5'",
        "bq query 'SELECT * FROM acme-prod-100001:raw_catalog_svc.products LIMIT 5'",
        "bq head -n 10 acme-prod-100001:raw_pricing_svc.prices",
        'python3 -c "from google.cloud import bigquery; bigquery.Client().query(\'SELECT * FROM raw_orders_svc.orders\')"',
        'python3 -c "import pandas_gbq; pandas_gbq.read_gbq(\'SELECT * FROM analytics_regional_ops.kpi\')"',
    )
    for cmd in blocked_shell_cmds:
        for harness in ("antigravity", "claude", "cursor", "codex"):
            res = evaluate_hook(
                _shell_payload(harness, cmd, cwd=str(ws_root)),
                state_dir=state_dir,
                cli_harness=harness,
            )
            assert_denied(res, harness, "ai_views")

    allowed_shell_cmds = (
        "bq query --use_legacy_sql=false 'SELECT * FROM ai_views.v_sales_orders LIMIT 5'",
        'python3 -c "from google.cloud import bigquery; bigquery.Client().query(\'SELECT * FROM ai_views.v_sales_orders\')"',
    )
    for cmd in allowed_shell_cmds:
        res_ok = evaluate_hook(_shell_payload("antigravity", cmd), state_dir=state_dir)
        assert_allowed(res_ok, "antigravity")


def test_allows_bigquery_raw_ddl_only_when_config_flag_explicitly_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _cfg, state_dir = _write_cfg(
        tmp_path, monkeypatch, extra={"allow_bq_raw_ddl_maintenance": True}
    )
    ddl_sql = (
        "CREATE OR REPLACE VIEW `acme-prod.ai_views.v_sales_orders` AS "
        "SELECT id FROM `acme-prod.raw_orders_svc.orders`"
    )
    mcp_res = evaluate_hook(
        {
            "conversationId": "c-ddl",
            "stepIdx": 1,
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "bigquery",
                    "ToolName": "execute_sql",
                    "Arguments": {"query": ddl_sql},
                },
            },
        },
        state_dir=state_dir,
    )
    assert_allowed(mcp_res, "antigravity")

    shell_res = evaluate_hook(
        _shell_payload("antigravity", f'bq query "{ddl_sql}"', cwd=str(ws_root)),
        state_dir=state_dir,
    )
    assert_allowed(shell_res, "antigravity")

    # Non-boolean string "yes" MUST fail closed for both MCP and shell BQ calls
    _write_cfg(tmp_path, monkeypatch, extra={"allow_bq_raw_ddl_maintenance": "yes"})
    bad_cfg = load_guard_config()
    assert bad_cfg["config_error"] == "invalid 'allow_bq_raw_ddl_maintenance': expected boolean"

    mcp_bad = evaluate_hook(
        {
            "conversationId": "c-ddl-bad",
            "stepIdx": 2,
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "bigquery",
                    "ToolName": "execute_sql",
                    "Arguments": {"query": ddl_sql},
                },
            },
        },
        state_dir=state_dir,
    )
    assert_denied(mcp_bad, "antigravity", "config error")

    shell_bad = evaluate_hook(
        _shell_payload("antigravity", f'bq query "{ddl_sql}"', cwd=str(ws_root)),
        state_dir=state_dir,
    )
    assert_denied(shell_bad, "antigravity", "config error")


def test_readonly_shell_commands_do_not_pollute_mutated_repos_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)
    for repo_name in ("alpha-app", "web-frontend", "core-service"):
        repo_dir = ws_root / repo_name
        (repo_dir / ".git").mkdir(parents=True)
        (repo_dir / "src").mkdir(parents=True)
        (repo_dir / "README.md").write_text("# readme\n", encoding="utf-8")
        (repo_dir / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")

    sym_dir = ws_root / "repos" / "core"
    sym_dir.mkdir(parents=True)
    (sym_dir / "alpha-app").symlink_to(ws_root / "alpha-app", target_is_directory=True)

    readonly_cmds = (
        f"git -C {ws_root / 'alpha-app'} status",
        f"grep -rn foo {ws_root / 'web-frontend'}",
        f"sed -n '1,20p' {ws_root / 'core-service' / 'README.md'}",
    )
    for cmd in readonly_cmds:
        evaluate_hook(
            _shell_payload("codex", cmd, cwd=str(ws_root)),
            state_dir=state_dir,
            cli_harness="codex",
        )

    state_file = Path(state_dir) / STATE_FILENAME
    if state_file.is_file():
        data_before = json.loads(state_file.read_text(encoding="utf-8"))
        assert data_before.get("mutated_repos", []) == []

    # Now mutate via symlink repos/core/alpha-app/src/a.py -> records "alpha-app"
    sym_file = sym_dir / "alpha-app" / "src" / "a.py"
    edit_res = evaluate_hook(
        {
            "conversationId": "c-mut",
            "stepIdx": 4,
            "toolCall": {"name": "edit_file", "args": {"Path": str(sym_file)}},
        },
        state_dir=state_dir,
    )
    assert_allowed(edit_res, "antigravity")
    data_after = json.loads(state_file.read_text(encoding="utf-8"))
    assert data_after.get("mutated_repos") == ["alpha-app"]


def test_vitest_and_jest_quiet_flags_preserve_stderr_failure_diagnostics() -> None:
    assert rewrite_quiet_cli_flags("vitest run") == "vitest run --reporter=dot"
    assert rewrite_quiet_cli_flags("npx vitest run") == "npx vitest run --reporter=dot"
    assert rewrite_quiet_cli_flags("npx vitest run --reporter=verbose") is None
    assert rewrite_quiet_cli_flags("jest foo.test.ts") is None
    assert rewrite_quiet_cli_flags("npx jest src/order.test.ts") is None
    assert rewrite_quiet_cli_flags("npm test") is None
    assert rewrite_quiet_cli_flags("pnpm test") is None


def test_allow_governance_mutations_config_and_fail_closed_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _cfg, state_dir = _write_cfg(
        tmp_path, monkeypatch, extra={"allow_governance_mutations": True}
    )
    protected = ws_root / "alpha-app" / "scripts" / "audit" / "ai_slop_scanner.py"
    allow_edit = evaluate_hook(
        {
            "conversationId": "c-gov-ok",
            "stepIdx": 1,
            "toolCall": {"name": "edit_file", "args": {"Path": str(protected)}},
        },
        state_dir=state_dir,
    )
    assert_allowed(allow_edit, "antigravity")

    # Even with allow_governance_mutations=True, --no-verify stays blocked
    still_blocked = evaluate_hook(
        _shell_payload("antigravity", 'git commit -m "x" --no-verify'),
        state_dir=state_dir,
    )
    assert_denied(still_blocked, "antigravity")

    # Non-boolean allow_governance_mutations fails closed
    _write_cfg(tmp_path, monkeypatch, extra={"allow_governance_mutations": 1})
    assert load_guard_config()["config_error"] == "invalid 'allow_governance_mutations': expected boolean"
    bad_edit = evaluate_hook(
        {
            "conversationId": "c-gov-bad",
            "stepIdx": 2,
            "toolCall": {"name": "edit_file", "args": {"Path": str(protected)}},
        },
        state_dir=state_dir,
    )
    assert_denied(bad_edit, "antigravity")

    # Unexpected internal error in governance gate fails closed when targeting protected paths
    _write_cfg(tmp_path, monkeypatch)

    def _boom(*_a: Any, **_kw: Any) -> dict[str, Any] | None:
        raise RuntimeError("simulated internal guard failure")

    monkeypatch.setattr(pre_tool_use, "evaluate_governance_and_shell_guards", _boom, raising=False)
    err_res = evaluate_hook(
        {
            "conversationId": "c-gov-err",
            "stepIdx": 3,
            "toolCall": {"name": "edit_file", "args": {"Path": str(protected)}},
        },
        state_dir=state_dir,
    )
    assert_denied(err_res, "antigravity")


def test_governance_guard_public_api_exports(tmp_path: Path) -> None:
    from hooks.governance_guard import (
        PROTECTED_GOVERNANCE_SUFFIXES,
        check_shell_bigquery_raw,
        check_shell_bypass_vectors,
        check_shell_protected_writes,
        evaluate_governance_and_shell_guards,
        is_protected_governance_path,
        is_readonly_shell_command,
        record_mutated_repos_in_state,
    )

    assert len(PROTECTED_GOVERNANCE_SUFFIXES) >= 8
    assert is_protected_governance_path("~/.git-hooks/pre-commit") == "git_hooks"
    assert is_protected_governance_path("~/.cursor/hooks.json") == "harness_config"
    assert is_protected_governance_path("~/.config/context-guard/config.json") == "context_guard_config"
    assert is_protected_governance_path(str(tmp_path / "src" / "main.py")) is None
    assert check_shell_bypass_vectors("git commit --no-verify -m x") is not None
    assert check_shell_protected_writes("rm -f guard_manifest.json", cwd=str(tmp_path)) is not None
    assert (
        check_shell_bigquery_raw(
            "bq query 'SELECT 1 FROM raw_x.t'",
            {"restricted_bq_datasets": ("raw_x",), "allowed_bq_views_hint": "ai_views.*"},
        )
        is not None
    )
    assert is_readonly_shell_command("git status && ls -la | head -n 5") is True
    assert is_readonly_shell_command("rm -rf build") is False
    assert callable(evaluate_governance_and_shell_guards)
    assert callable(record_mutated_repos_in_state)


def test_subshell_and_brace_group_cannot_bypass_shell_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hooks.governance_guard import (
        check_shell_bigquery_raw,
        check_shell_bypass_vectors,
        check_shell_protected_writes,
        is_readonly_shell_command,
    )

    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)
    for bypass_cmd in (
        "(git commit --no-verify -m x)",
        "{ git commit --no-verify -m x; }",
        "(! git commit -n -m x)",
    ):
        assert check_shell_bypass_vectors(bypass_cmd) is not None, bypass_cmd
        res = evaluate_hook(_shell_payload("claude", bypass_cmd, cwd=str(ws_root)), state_dir=state_dir)
        assert_denied(res, "claude")

    for write_cmd in (
        "(rm -f guard_manifest.json)",
        "(echo '{}' > guard_manifest.json)",
        "{ echo '{}' > tests/baselines/x.json; }",
        "{ echo '{}'; } > guard_manifest.json",
    ):
        assert check_shell_protected_writes(write_cmd, cwd=str(ws_root), workspace_root=ws_root) is not None, write_cmd

    bq_cfg = {"restricted_bq_datasets": ("raw_sales_svc",), "allowed_bq_views_hint": "ai_views.*"}
    for bq_cmd in (
        "(bq query 'SELECT * FROM raw_sales_svc.orders')",
        "{ bq query 'SELECT * FROM raw_sales_svc.orders'; }",
    ):
        assert check_shell_bigquery_raw(bq_cmd, bq_cfg) is not None, bq_cmd

    assert is_readonly_shell_command("(git status)") is True
    assert is_readonly_shell_command("{ git status; }") is True


def test_double_quote_apostrophe_and_quoted_subshell_parens_do_not_desync_lexer() -> None:
    from hooks.governance_guard import check_shell_bypass_vectors, is_readonly_shell_command

    assert check_shell_bypass_vectors('echo "don\'t" && $(git commit --no-verify -m x)') is not None
    assert is_readonly_shell_command('echo "don\'t" && ls $(rm -rf alpha-screener/src)') is False
    assert check_shell_bypass_vectors('git commit -m "$(printf \')\')" --no-verify') is not None
    assert check_shell_bypass_vectors('git commit -m "$(printf \')\')"') is None


def test_git_boolean_short_flags_and_git_config_env_cannot_bypass_hooks() -> None:
    from hooks.governance_guard import check_shell_bypass_vectors

    for blocked in (
        "git commit -s --no-verify -m x",
        "git push -u --no-verify origin main",
        "git commit -u --no-verify -m x",
        "git commit -sn -m x",
        "GIT_CONFIG_PARAMETERS=\"'core.hooksPath=/dev/null'\" git commit -m x",
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x",
        "export GIT_CONFIG_KEY_0=core.hooksPath",
    ):
        assert check_shell_bypass_vectors(blocked) is not None, blocked

    assert check_shell_bypass_vectors('git commit -s -m "mention --no-verify"') is None
    assert check_shell_bypass_vectors("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=CI git status") is None


def test_clustered_sed_inplace_and_dot_segments_without_cwd_are_blocked() -> None:
    from hooks.governance_guard import check_shell_protected_writes, is_protected_governance_path, is_readonly_shell_command

    assert check_shell_protected_writes("sed -Ei '' 's/a/b/' scripts/audit/ai_slop_scanner.py") is not None
    assert check_shell_protected_writes("sed -ri 's/a/b/' scripts/audit/ai_slop_scanner.py") is not None
    assert is_readonly_shell_command("sed -ni '1,5p' README.md") is False
    assert is_protected_governance_path("scripts/./audit/ai_slop_scanner.py", cwd=None, workspace_root=None) == "audit_guard"
    assert is_protected_governance_path("sub/../.githooks/pre-commit", cwd=None, workspace_root=None) == "git_hooks"


def test_bq_global_flags_and_dataset_id_flag_blocked_for_restricted_datasets() -> None:
    from hooks.governance_guard import check_shell_bigquery_raw

    bq_cfg = {"restricted_bq_datasets": ("raw_sales_svc",), "allowed_bq_views_hint": "ai_views.*"}
    for blocked_cmd in (
        "bq --location EU query 'SELECT * FROM raw_sales_svc.orders'",
        "bq --project_id sample-proj query 'SELECT * FROM raw_sales_svc.orders'",
        "bq --dataset_id=raw_sales_svc query 'SELECT * FROM orders'",
        "bq query --dataset_id raw_sales_svc 'SELECT * FROM orders'",
        "bq head -d sample-proj:raw_sales_svc orders",
    ):
        assert check_shell_bigquery_raw(blocked_cmd, bq_cfg) is not None, blocked_cmd

    assert check_shell_bigquery_raw("bq --location EU --dataset_id=ai_views query 'SELECT * FROM v_sales_orders'", bq_cfg) is None


def test_slash_tokens_do_not_pollute_mutated_repos_and_fail_closed_covers_all_mutating_or_shell_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hooks.governance_guard import payload_may_require_fail_closed_guard
    from hooks.harness_adapter import normalize_pre_tool_payload

    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)
    (ws_root / "alpha-screener" / ".git").mkdir(parents=True)
    (ws_root / "notes.txt").write_text("hello\n", encoding="utf-8")

    for non_repo_cmd in ("git push origin feat/x", "sed -i.bak 's/a/b/' notes.txt", "curl -s https://example.com/api/v1/health"):
        assert_allowed(evaluate_hook(_shell_payload("claude", non_repo_cmd, cwd=str(ws_root)), state_dir=state_dir), "claude")

    state_file = Path(state_dir) / STATE_FILENAME
    if state_file.is_file():
        recorded = json.loads(state_file.read_text(encoding="utf-8")).get("mutated_repos", [])
        assert recorded == [], f"Unexpected false-positive repos recorded: {recorded}"

    norm_shell = normalize_pre_tool_payload(_shell_payload("claude", "echo hello", cwd=str(ws_root)))
    norm_edit = normalize_pre_tool_payload({"toolCall": {"name": "edit_file", "args": {"Path": str(ws_root / "alpha-screener" / "app.py")}}})
    norm_bq = normalize_pre_tool_payload({"toolCall": {"name": "call_mcp_tool", "args": {"ServerName": "bigquery", "ToolName": "execute_sql_readonly", "Arguments": {"query": "SELECT 1"}}}})
    norm_read = normalize_pre_tool_payload({"toolCall": {"name": "read_file", "args": {"Path": str(ws_root / "notes.txt")}}})
    assert payload_may_require_fail_closed_guard(norm_shell) is True
    assert payload_may_require_fail_closed_guard(norm_edit) is True
    assert payload_may_require_fail_closed_guard(norm_bq) is True
    assert payload_may_require_fail_closed_guard(norm_read) is False

    def _boom(*_a: Any, **_kw: Any) -> dict[str, Any] | None:
        raise RuntimeError("simulated guard crash")

    monkeypatch.setattr(pre_tool_use, "evaluate_governance_and_shell_guards", _boom, raising=False)
    assert_denied(evaluate_hook(_shell_payload("claude", "echo hello", cwd=str(ws_root)), state_dir=state_dir), "claude")
    assert_denied(evaluate_hook({"toolCall": {"name": "edit_file", "args": {"Path": str(ws_root / "alpha-screener" / "app.py")}}}, state_dir=state_dir), "antigravity")


def test_inline_shell_mutations_baseline_tamper_and_readonly_edge_vectors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hooks.governance_guard import is_readonly_shell_command

    ws_root, _cfg, state_dir = _write_cfg(tmp_path, monkeypatch)
    for rname in ("alpha-screener", "beta-portal", "gamma-service", "delta-worker"):
        (ws_root / rname / "src").mkdir(parents=True)
        (ws_root / rname / ".git").mkdir()

    # 1. --capture-baseline is blocked as stop_guard_baseline_tamper
    for tamper_cmd in (
        "python3 scripts/hooks/antigravity_stop_guard.py --capture-baseline",
        "bash -c 'python3 /tmp/antigravity_stop_guard.py --capture-baseline --session-id s1'",
    ):
        assert_denied(evaluate_hook(_shell_payload("claude", tamper_cmd, cwd=str(ws_root)), state_dir=state_dir), "claude", "--capture-baseline")

    # 2. Mutating readonly-bypass edge commands are classified non-readonly
    for bad_ro in (
        "git diff HEAD --output=alpha-screener/src/x.py",
        "git log -n 1 -o alpha-screener/src/x.patch",
        "uniq README.md alpha-screener/src/out.txt",
        "sed -n '1,5w alpha-screener/src/x.py' README.md",
        "sed -n 's/a/b/w alpha-screener/src/x.py' README.md",
        "sed -n -f rules.sed alpha-screener/src/x.py",
    ):
        assert is_readonly_shell_command(bad_ro) is False, f"Must not treat as readonly: {bad_ro}"
    assert is_readonly_shell_command("uniq alpha-screener/src/x.py") is True
    assert is_readonly_shell_command("sed -n '/workflow/p' alpha-screener/src/x.py") is True

    # 3. Shell commands (loops, inline scripts, redirects, -C) never pollute mutated_repos; structured writes do
    for shell_cmd in (
        'for r in alpha-screener beta-portal gamma-service; do grep -rn foo "$r"; done',
        'python3 -c \'open("alpha-screener/src/x.py","w").write("1")\'',
        'bash -c "echo x > beta-portal/src/a.ts"',
        "echo x 1>gamma-service/src/a.txt",
        "git -Cdelta-worker checkout -- src/a.py",
    ):
        assert_allowed(evaluate_hook(_shell_payload("claude", shell_cmd, cwd=str(ws_root)), state_dir=state_dir), "claude")

    state_file = Path(state_dir) / STATE_FILENAME
    if state_file.is_file():
        assert json.loads(state_file.read_text(encoding="utf-8")).get("mutated_repos", []) == []

    patch_payload = {"session_id": "s-patch", "agent_id": "sub-writer", "cwd": str(ws_root), "tool_name": "apply_patch", "tool_input": "*** Begin Patch\n*** Update File: beta-portal/src/a.ts\n@@\n-x\n+y\n*** End Patch"}
    assert_allowed(evaluate_hook(patch_payload, state_dir=state_dir, cli_harness="codex"), "codex")
    sub_files = list((Path(state_dir) / "subagents").glob(f"*/{STATE_FILENAME}"))
    assert len(sub_files) == 1
    assert json.loads(sub_files[0].read_text(encoding="utf-8")).get("mutated_repos") == ["beta-portal"]

    sub_repo = ws_root / "legacy" / "storefront-m1"
    (sub_repo / ".git").mkdir(parents=True, exist_ok=True)
    sub_state = str(tmp_path / "sub_state")
    for sub_cmd in ('git commit -m "chore: align with alpha-screener"', f"cat <<'EOF' > notes.md\nSee {ws_root / 'beta-portal/src/a.ts'} and gamma-service\nEOF"):
        assert_allowed(evaluate_hook(_shell_payload("claude", sub_cmd, cwd=str(sub_repo)), state_dir=sub_state), "claude")
    if (Path(sub_state) / STATE_FILENAME).is_file():
        assert json.loads((Path(sub_state) / STATE_FILENAME).read_text(encoding="utf-8")).get("mutated_repos", []) == []
    edit_sub = {"session_id": "s-sub", "cwd": str(sub_repo), "tool_name": "Edit", "tool_input": {"file_path": str(sub_repo / "notes.md")}}
    assert_allowed(evaluate_hook(edit_sub, state_dir=sub_state, cli_harness="claude"), "claude")
    assert json.loads((Path(sub_state) / STATE_FILENAME).read_text(encoding="utf-8")).get("mutated_repos") == ["legacy/storefront-m1"]
    win_cmd = r"sed -i '' 's/a/b/' C:\Users\alice\repo\scripts\audit\ai_slop_scanner.py"
    assert_denied(evaluate_hook(_shell_payload("claude", win_cmd, cwd=str(ws_root)), state_dir=state_dir), "claude", "governance")


def test_codex_rules_dir_is_protected_governance_path(tmp_path: Path) -> None:
    assert is_protected_governance_path("~/.codex/rules/governance.rules") == "harness_config"
    assert is_protected_governance_path(str(tmp_path / ".codex" / "rules" / "project.rules")) == "harness_config"
    assert is_protected_governance_path("~/.codex/hooks/guard.sh") == "harness_config"
    assert is_protected_governance_path(str(tmp_path / ".codex" / "worktrees" / "wt1" / "app.py")) is None
    assert check_shell_protected_writes("echo x > ~/.codex/rules/governance.rules") is not None
    assert check_shell_protected_writes('python3 -c "open(\'.codex/rules/default.rules\', \'w\').write(\'x\')"') is not None
