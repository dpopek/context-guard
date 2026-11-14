"""Tests for Claude/Codex/Cursor worktree & SDD directory writes, data heredocs, and shell variable resolution."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hooks import config as guard_config
from hooks.pre_tool_use import evaluate_hook
from hooks.state_store import STATE_FILENAME


def _setup_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    guard_config.clear_config_cache()
    ws_root = tmp_path / "workspace"
    ws_root.mkdir(parents=True, exist_ok=True)
    state_dir = tmp_path / "state"
    cfg_path = tmp_path / "cg_config.json"
    cfg_path.write_text(
        json.dumps({"workspace_root": str(ws_root), "enforce_governance_policy": True}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    return ws_root, str(state_dir)


def assert_claude_allowed(res: dict[str, Any]) -> None:
    hso = res.get("hookSpecificOutput")
    if isinstance(hso, dict):
        assert hso.get("permissionDecision") != "deny", f"Unexpected Claude deny: {res}"
    else:
        assert res == {}, f"Expected empty Claude allow response, got: {res}"


def assert_claude_denied(res: dict[str, Any], expected_substr: str = "") -> None:
    hso = res.get("hookSpecificOutput")
    assert isinstance(hso, dict), f"Expected Claude hookSpecificOutput deny, got: {res}"
    assert hso.get("permissionDecision") == "deny", f"Expected Claude deny, got: {res}"
    if expected_substr:
        reason = str(hso.get("permissionDecisionReason") or "")
        assert expected_substr.lower() in reason.lower(), f"Missing {expected_substr!r} in {reason!r}"


def _claude_bash(command: str, cwd: Path) -> dict[str, Any]:
    return {
        "session_id": "sess-wt-sdd",
        "transcript_path": "/tmp/.claude/wt-session.jsonl",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(cwd),
    }


def test_allows_writes_inside_claude_codex_and_cursor_worktrees_and_sdd_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, state_dir = _setup_cfg(tmp_path, monkeypatch)
    repo = ws_root / "legacy" / "storefront-m1"
    main_sdd = repo / ".superpowers" / "sdd" / "2026-10-27-hyva-migration"
    wt_root = repo / ".claude" / "worktrees" / "migration-plan-f3dddf"
    wt_sdd = wt_root / ".superpowers" / "sdd" / "2026-10-27-hyva-migration"
    main_sdd.mkdir(parents=True)
    wt_sdd.mkdir(parents=True)

    src_brief = main_sdd / "task-card-a1-fix2-brief.md"
    src_brief.write_text("# Brief\n", encoding="utf-8")
    wt_brief = wt_sdd / "task-card-a1-fix2-brief.md"

    # 1. Direct Write and Edit inside .claude/worktrees/<branch>/.superpowers/sdd/...
    for tool_name in ("Write", "Edit"):
        res = evaluate_hook(
            {
                "session_id": "sess-wt-sdd",
                "tool_name": tool_name,
                "tool_input": {"file_path": str(wt_brief)},
                "cwd": str(wt_sdd),
            },
            state_dir=state_dir,
            cli_harness="claude",
        )
        assert_claude_allowed(res)

    # 2. Shell cp with variable assignment into .claude/worktrees/<branch>/.superpowers/sdd/...
    cp_cmd = (
        f"W={wt_sdd} && cp {src_brief} \"$W/task-card-a1-fix2-brief.md\" "
        "&& wc -l \"$W/task-card-a1-fix2-brief.md\""
    )
    assert_claude_allowed(
        evaluate_hook(_claude_bash(cp_cmd, wt_sdd), state_dir=state_dir, cli_harness="claude")
    )

    # 3. Shell redirection to /tmp scratchpad via $S while cwd is inside .claude/worktrees/...
    scratch = tmp_path / "scratchpad"
    scratch.mkdir()
    redir_cmd = (
        f"S={scratch}; awk '{{print}}' {src_brief} > \"$S/task-card-a1-fix2-brief.md\" "
        f"&& touch {wt_sdd / 'card-a-blog-hyva.md'} && echo docs-writable"
    )
    assert_claude_allowed(
        evaluate_hook(_claude_bash(redir_cmd, wt_sdd), state_dir=state_dir, cli_harness="claude")
    )

    # 4. Inline Python script writing to .claude/worktrees/...
    py_cmd = f'python3 -c "from pathlib import Path; Path(\'{wt_brief}\').write_text(\'ok\')"'
    assert_claude_allowed(
        evaluate_hook(_claude_bash(py_cmd, wt_sdd), state_dir=state_dir, cli_harness="claude")
    )

    # 5. Codex and Cursor worktree checkouts are also writable
    for wt_file in (
        repo / ".codex" / "worktrees" / "feat-a" / "app" / "Blog.php",
        repo / ".cursor" / "worktrees" / "feat-b" / "app" / "Blog.php",
        repo / ".claude" / "plans" / "hyva-plan.md",
    ):
        res_ag = evaluate_hook(
            {
                "conversationId": "c-wt",
                "stepIdx": 1,
                "toolCall": {"name": "write_file", "args": {"Path": str(wt_file)}},
            },
            state_dir=state_dir,
        )
        assert res_ag.get("decision") == "allow", f"Expected allow for {wt_file}, got {res_ag}"


def test_still_blocks_actual_harness_configs_and_governance_paths_inside_worktrees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, state_dir = _setup_cfg(tmp_path, monkeypatch)
    repo = ws_root / "legacy" / "storefront-m1"
    wt_root = repo / ".claude" / "worktrees" / "migration-plan-f3dddf"

    protected_targets = (
        repo / ".claude" / "settings.json",
        repo / ".claude" / "settings.local.json",
        repo / ".claude" / "hooks.json",
        repo / ".claude" / "hooks" / "stop_hook.py",
        wt_root / ".claude" / "settings.json",
        wt_root / ".claude" / "hooks" / "pre_tool.sh",
        wt_root / "scripts" / "audit" / "ai_slop_scanner.py",
        wt_root / ".githooks" / "pre-commit",
        wt_root / "guard_manifest.json",
        repo / ".codex" / "hooks.json",
        repo / ".codex" / "config.toml",
        repo / ".codex" / "hooks" / "stop.py",
        repo / ".cursor" / "hooks.json",
        repo / ".cursor" / "hooks" / "guard.sh",
        repo / ".agents" / "hooks.json",
        repo / ".agents" / "hooks" / "guard.py",
    )

    for target in protected_targets:
        res = evaluate_hook(
            {
                "session_id": "sess-wt-sdd",
                "tool_name": "Write",
                "tool_input": {"file_path": str(target)},
                "cwd": str(wt_root),
            },
            state_dir=state_dir,
            cli_harness="claude",
        )
        assert_claude_denied(res, "governance")

    # Inline Python targeting actual .claude/settings.json or .codex/hooks.json stays denied
    for bad_py in (
        f'python3 -c "from pathlib import Path; Path(\'{repo}/.claude/settings.json\').write_text(\'{{}}\')"',
        f'python3 -c "from pathlib import Path; Path(\'{repo}/.codex/hooks.json\').write_text(\'{{}}\')"',
    ):
        assert_claude_denied(
            evaluate_hook(_claude_bash(bad_py, wt_root), state_dir=state_dir, cli_harness="claude"),
            "governance",
        )


def test_allows_sdd_markdown_heredoc_mentioning_governance_commands_while_blocking_exec_heredocs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, state_dir = _setup_cfg(tmp_path, monkeypatch)
    repo = ws_root / "legacy" / "storefront-m1"
    sdd_dir = repo / ".claude" / "worktrees" / "wt-1" / ".superpowers" / "sdd"
    sdd_dir.mkdir(parents=True)

    safe_doc_heredoc = (
        f"cat <<'EOF' > {sdd_dir / 'brief.md'}\n"
        "## Rules\n"
        "git commit --no-verify -m bad\n"
        "git add .\n"
        "rm -f .githooks/pre-commit\n"
        "EOF"
    )
    assert_claude_allowed(
        evaluate_hook(_claude_bash(safe_doc_heredoc, sdd_dir), state_dir=state_dir, cli_harness="claude")
    )

    blocked_heredocs = (
        f"cat <<'EOF' > {repo / '.githooks' / 'pre-commit'}\n#!/bin/sh\nexit 0\nEOF",
        "bash <<'EOF'\ngit commit --no-verify -m bypass\nEOF",
        "sh <<'EOF'\necho x > .githooks/pre-commit\nEOF",
        "cat <<'EOF' | bash\ngit add .\nEOF",
    )
    for bad_cmd in blocked_heredocs:
        assert_claude_denied(
            evaluate_hook(_claude_bash(bad_cmd, repo), state_dir=state_dir, cli_harness="claude"),
            "governance",
        )


def test_expands_shell_variables_for_protected_and_scratchpad_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, state_dir = _setup_cfg(tmp_path, monkeypatch)
    repo = ws_root / "legacy" / "storefront-m1"
    audit_cwd = repo / "scripts" / "audit"
    audit_cwd.mkdir(parents=True)

    # Variable indirection targeting protected paths must be blocked
    for indirect_attack in (
        'G=.githooks && echo x > "$G/pre-commit"',
        'D=scripts/audit; rm -f "${D}/ai_slop_scanner.py"',
        'echo x > "$UNSET_ROOT/.githooks/pre-commit"',
    ):
        assert_claude_denied(
            evaluate_hook(_claude_bash(indirect_attack, repo), state_dir=state_dir, cli_harness="claude"),
            "governance",
        )

    # Scratchpad variable redirects are allowed even when cwd is inside a protected directory
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for safe_var_cmd in (
        f'S={scratch}; echo ok > "$S/brief.md"',
        'echo ok > "$TMPDIR/brief.md"',
    ):
        assert_claude_allowed(
            evaluate_hook(_claude_bash(safe_var_cmd, audit_cwd), state_dir=state_dir, cli_harness="claude")
        )


def test_nested_worktree_writes_never_attribute_parent_main_checkout_and_non_git_dirs_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, state_dir = _setup_cfg(tmp_path, monkeypatch)
    main_repo = ws_root / "alpha-service"
    (main_repo / ".git").mkdir(parents=True)

    wt_git = main_repo / ".claude" / "worktrees" / "feat-iso"
    wt_git.mkdir(parents=True)
    (wt_git / ".git").write_text("gitdir: /tmp/fake-gitdir-1\n", encoding="utf-8")

    wt_pruned = main_repo / ".codex" / "worktrees" / "feat-pruned"
    wt_pruned.mkdir(parents=True)

    wt_dot = main_repo / ".worktrees" / "feat-dot"
    wt_dot.mkdir(parents=True)

    wt_custom = main_repo / "wt-local"
    wt_custom.mkdir(parents=True)
    (wt_custom / ".git").write_text("gitdir: /tmp/fake-gitdir-2\n", encoding="utf-8")

    non_git_tests = ws_root / "tests"
    non_git_tests.mkdir(parents=True)

    for wt_target in (
        wt_git / "app.py",
        wt_pruned / "app.py",
        wt_dot / "app.py",
        wt_custom / "app.py",
        non_git_tests / "scratch.py",
    ):
        res = evaluate_hook(
            {
                "conversationId": "c-nested-wt",
                "stepIdx": 2,
                "toolCall": {"name": "edit_file", "args": {"Path": str(wt_target)}},
            },
            state_dir=state_dir,
        )
        assert res.get("decision") == "allow"

    state_data = json.loads((Path(state_dir) / STATE_FILENAME).read_text(encoding="utf-8"))
    assert state_data.get("mutated_repos_schema") == 2
    assert "alpha-service" not in state_data.get("mutated_repos", [])
    assert "tests" not in state_data.get("mutated_repos", [])
    assert state_data.get("mutated_repos") == [
        "alpha-service/.claude/worktrees/feat-iso",
        "alpha-service/.codex/worktrees/feat-pruned",
        "alpha-service/.worktrees/feat-dot",
        "alpha-service/wt-local",
    ]


def test_legacy_unversioned_mutated_repos_self_heals_on_read_shell_and_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws_root, _ = _setup_cfg(tmp_path, monkeypatch)
    gamma = ws_root / "gamma-worker"
    (gamma / ".git").mkdir(parents=True)
    gamma_app = gamma / "app.py"
    gamma_app.write_text("x = 1\n", encoding="utf-8")

    legacy_payload = json.dumps(
        {"files": {}, "mutated_repos": ["alpha-service", "beta-portal", "tests"]}
    )
    state_shell = tmp_path / "state_shell"
    state_read = tmp_path / "state_read"
    state_write = tmp_path / "state_write"
    for sdir in (state_shell, state_read, state_write):
        sdir.mkdir(parents=True, exist_ok=True)
        (sdir / STATE_FILENAME).write_text(legacy_payload, encoding="utf-8")

    res_shell = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 5,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "echo ok"}},
        },
        state_dir=str(state_shell),
    )
    assert res_shell.get("decision") == "allow"
    shell_state = json.loads((state_shell / STATE_FILENAME).read_text(encoding="utf-8"))
    assert "mutated_repos" not in shell_state
    assert shell_state.get("mutated_repos_schema") == 2

    res_read = evaluate_hook(
        {
            "session_id": "s-read",
            "tool_name": "Read",
            "tool_input": {"file_path": str(gamma_app)},
            "cwd": str(ws_root),
        },
        state_dir=str(state_read),
        cli_harness="claude",
    )
    assert_claude_allowed(res_read)
    read_state = json.loads((state_read / STATE_FILENAME).read_text(encoding="utf-8"))
    assert "mutated_repos" not in read_state
    assert read_state.get("mutated_repos_schema") == 2

    res_write = evaluate_hook(
        {
            "session_id": "s-write",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(gamma_app)},
            "cwd": str(ws_root),
        },
        state_dir=str(state_write),
        cli_harness="claude",
    )
    assert_claude_allowed(res_write)
    write_state = json.loads((state_write / STATE_FILENAME).read_text(encoding="utf-8"))
    assert write_state.get("mutated_repos") == ["gamma-worker"]
    assert write_state.get("mutated_repos_schema") == 2


def test_google_cloud_bigquery_from_import_and_nested_shell_bq_recursion() -> None:
    from hooks.governance_guard import check_shell_bigquery_raw

    bq_cfg = {"restricted_bq_datasets": ("raw_orders",), "allowed_bq_views_hint": "ai_views.*"}
    for blocked in (
        'python3 -c "from google.cloud.bigquery import Client; Client().query(\'SELECT * FROM raw_orders.t\')"',
        'bash -c "bq query --dataset_id=raw_orders \'SELECT * FROM t\'"',
        'sh -lc "bq query \'SELECT * FROM raw_orders.t\'"',
        r'C:\Google\BQ.CMD query "SELECT * FROM raw_orders.t"',
    ):
        hit = check_shell_bigquery_raw(blocked, bq_cfg)
        assert hit is not None and "ai-views block" in hit.lower(), f"Expected BQ block for {blocked!r}"
    assert check_shell_bigquery_raw('bash -c "bq query --dataset_id=ai_views \'SELECT 1\'"', bq_cfg) is None


def test_nested_shell_depth_limit_fails_closed_for_writes_and_bigquery(tmp_path: Path) -> None:
    from hooks.governance_guard import check_shell_bigquery_raw, check_shell_protected_writes

    def _nest(levels: int, inner: str) -> str:
        cmd = inner
        for _ in range(levels):
            escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
            cmd = f'bash -c "{escaped}"'
        return cmd

    deep_10 = _nest(10, "echo ok")
    write_hit = check_shell_protected_writes(deep_10, cwd=str(tmp_path), workspace_root=tmp_path)
    bq_hit = check_shell_bigquery_raw(deep_10, {"restricted_bq_datasets": ("raw_orders",)})
    assert write_hit is not None and "nested shell depth limit exceeded" in write_hit.lower()
    assert bq_hit is not None and "nested shell depth limit exceeded" in bq_hit.lower()

    shallow_4 = _nest(4, "echo ok")
    assert check_shell_protected_writes(shallow_4, cwd=str(tmp_path), workspace_root=tmp_path) is None
    assert check_shell_bigquery_raw(shallow_4, {"restricted_bq_datasets": ("raw_orders",)}) is None


def test_wrapper_commands_timeout_nice_env_and_windows_cmd_basenames(tmp_path: Path) -> None:
    from hooks.governance_guard import (
        check_shell_bypass_vectors,
        check_shell_protected_writes,
        is_readonly_shell_command,
    )

    ws_root = tmp_path / "workspace"
    repo = ws_root / "guarded"
    (repo / ".git").mkdir(parents=True)
    for bypassed in (
        "timeout 10 git commit --no-verify -m x",
        "timeout -s KILL 5 git commit --no-verify -m x",
        "nice -n 10 git commit --no-verify -m x",
        "env -i SKIP=1 git commit -m x",
        r"C:\Git\bin\GIT.EXE commit --no-verify -m x",
    ):
        assert check_shell_bypass_vectors(bypassed) is not None, f"Expected bypass block for {bypassed!r}"

    for write_cmd in (
        "timeout -s KILL 5 rm -f .githooks/pre-commit",
        "nice -n 10 rm -f .githooks/pre-commit",
        r"C:\bin\RM.EXE -f .githooks/pre-commit",
    ):
        assert check_shell_protected_writes(write_cmd, cwd=str(repo), workspace_root=ws_root) is not None, write_cmd

    assert is_readonly_shell_command(r"C:\bin\CAT.EXE app.py") is True


def test_inline_script_and_heredoc_writes_follow_cd_effective_cwd(tmp_path: Path) -> None:
    from hooks.governance_guard import check_shell_protected_writes

    ws_root = tmp_path / "workspace"
    guarded = ws_root / "guarded-repo"
    unguarded = ws_root / "unguarded-repo"
    (guarded / ".git").mkdir(parents=True)
    (guarded / "guard_manifest.json").write_text("{}", encoding="utf-8")
    (unguarded / ".git").mkdir(parents=True)

    cd_to_guarded_inline = (
        f"cd {guarded} && python3 -c \"from pathlib import Path; "
        "Path('scripts/audit/ai_slop_scanner.py').write_text('x')\""
    )
    assert check_shell_protected_writes(cd_to_guarded_inline, cwd=str(unguarded), workspace_root=ws_root) is not None

    cd_to_unguarded_inline = (
        f"cd {unguarded} && python3 -c \"from pathlib import Path; "
        "Path('scripts/audit/custom_check.py').write_text('x')\""
    )
    assert check_shell_protected_writes(cd_to_unguarded_inline, cwd=str(guarded), workspace_root=ws_root) is None

    cd_to_guarded_heredoc = (
        f"cd {guarded} && python3 <<'PY'\n"
        "from pathlib import Path\n"
        "Path('scripts/audit/ai_slop_scanner.py').write_text('x')\n"
        "PY"
    )
    assert check_shell_protected_writes(cd_to_guarded_heredoc, cwd=str(unguarded), workspace_root=ws_root) is not None

    direct_heredoc = "python3 <<'PY'\nopen('.githooks/pre-commit', 'w').write('x')\nPY"
    assert check_shell_protected_writes(direct_heredoc, cwd=str(guarded), workspace_root=ws_root) is not None


def test_sed_readonly_check_linear_time_on_1200_slashes_and_preserves_workflow_subst() -> None:
    import time
    from hooks.governance_guard import is_readonly_shell_command

    assert is_readonly_shell_command("sed -n 's/workflow/task/gp' app.py") is True
    assert is_readonly_shell_command("sed -n 's/a/b/w out.txt' app.py") is False

    for pathological in (
        f"sed -n '{'s' + '/' * 1200}' app.py",
        f"sed -n '{'s/' + chr(92) * 34}' app.py",
    ):
        t0 = time.perf_counter()
        assert is_readonly_shell_command(pathological) is True
        assert (time.perf_counter() - t0) < 0.25


def test_heredoc_wrappers_windows_exe_piped_heredoc_and_bypass_depth_cap(tmp_path: Path) -> None:
    from hooks.governance_guard import check_shell_bypass_vectors, check_shell_protected_writes

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    payload = "from pathlib import Path\nPath('.githooks/pre-commit').write_text('x')\nPY"
    for hdr in (
        "timeout 30 python3 <<'PY'",
        "timeout -k 5 -- 30 python3 <<'PY'",
        "nice -n 10 python3 <<'PY'",
        "env -i python3 <<'PY'",
        "sudo -u root python3 <<'PY'",
        "command -p python3 <<'PY'",
        r"C:\Python312\python.exe <<'PY'",
        "C:/Python312/python3.12.exe <<'PY'",
        "cat <<'PY' | timeout 30 python3",
        "cd /tmp\ncat <<'PY' | nice -n 5 python3 -",
    ):
        assert check_shell_protected_writes(f"{hdr}\n{payload}", cwd=str(repo), workspace_root=tmp_path) is not None, hdr

    assert check_shell_bypass_vectors("command -v git") is None
    assert check_shell_bypass_vectors("command -p -v git") is None
    assert check_shell_bypass_vectors("command -p git commit -n -m bypass") is not None

    nested = "true"
    for _ in range(10):
        nested = f'bash -c "{nested.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'
    hit = check_shell_bypass_vectors(nested)
    assert hit is not None and "depth limit" in hit.lower()
