"""CLI rewrites must trim output without changing what the command finds or runs."""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from hooks import config as guard_config
from hooks.harness_adapter import (
    AUTO_APPROVED_PERMISSION_MODES,
    can_rewrite_shell_command,
    format_pre_tool_output,
    normalize_pre_tool_payload,
)
from hooks.pre_tool_use import evaluate_hook, main as pre_tool_use_main
from hooks.shell_parser import rewrite_quiet_cli_flags
from hooks.telemetry import load_telemetry_stats
from integrations.atlassian_twg import rewrite_twg_cli_command
from tests.helpers import read_outcomes_ledger


def test_grep_inside_an_excluded_directory_is_left_alone() -> None:
    assert rewrite_quiet_cli_flags("grep -rn useState node_modules/react/index.js") is None
    assert rewrite_quiet_cli_flags("grep -rn foo ./.venv/lib/python3.11/site-packages/pkg") is None
    assert rewrite_quiet_cli_flags('grep -rn "node_modules" src') is not None
    assert "--exclude-dir=node_modules" in (rewrite_quiet_cli_flags("grep -rn foo src") or "")


def test_package_manager_test_commands_pass_through_without_silent_flag() -> None:
    assert rewrite_quiet_cli_flags("npm test") is None
    assert rewrite_quiet_cli_flags("pnpm test") is None
    assert rewrite_quiet_cli_flags("pnpm run test") is None
    assert rewrite_quiet_cli_flags("cd /repo && pnpm test") is None
    assert rewrite_quiet_cli_flags("yarn test") is None


def test_twg_keeps_cd_when_an_argument_is_a_relative_file(tmp_path: Path, isolated_user_env: Path) -> None:
    _ = isolated_user_env
    assert rewrite_quiet_cli_flags("cd /repo && twg jira workitem get PROJ-1 --output json") is None
    assert rewrite_quiet_cli_flags("cd /repo && twg jira workitem get PROJ-1 --output json", enable_atlassian_twg=True) == (
        "twg jira workitem get PROJ-1 --output json"
    )
    assert rewrite_twg_cli_command("cd /repo && twg jira workitem get PROJ-1 --output json") == (
        "twg jira workitem get PROJ-1 --output json"
    )
    for cmd in (
        "cd /repo && twg jira workitem update PROJ-1 --fields-json @payload.json",
        "cd /repo && twg artifacts share ./out/report.html",
        "cd /repo && twg artifacts share out/report.csv",
    ):
        assert rewrite_quiet_cli_flags(cmd) is None
        assert rewrite_quiet_cli_flags(cmd, enable_atlassian_twg=True) is None
        assert rewrite_twg_cli_command(cmd) is None
    assert rewrite_quiet_cli_flags("cd /repo && twg artifacts share /abs/report.html", enable_atlassian_twg=True) == (
        "twg artifacts share /abs/report.html"
    )
    res_off = evaluate_hook(
        {
            "conversationId": "c-twg-off",
            "stepIdx": 1,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "TWG_AGENT_DEFAULTS=1 ~/.local/bin/twg jira status"}},
        },
        state_dir=str(tmp_path / "state"),
    )
    assert res_off == {"decision": "allow"}


def test_can_rewrite_shell_command_enforces_harness_and_permission_mode() -> None:
    assert AUTO_APPROVED_PERMISSION_MODES == frozenset({"bypassPermissions", "dontAsk", "auto"})

    ag_norm = normalize_pre_tool_payload(
        {"conversationId": "ag-1", "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}}},
        cli_harness="antigravity",
    )
    assert ag_norm.permission_mode is None
    assert can_rewrite_shell_command(ag_norm) is True

    for harness, tool in (("claude", "Bash"), ("cursor", "Shell"), ("cursor", "Bash"), ("cursor", "run_terminal_cmd")):
        for mode in ("bypassPermissions", "dontAsk", "auto", "  auto  "):
            for key in ("permission_mode", "permissionMode"):
                norm = normalize_pre_tool_payload(
                    {"session_id": "s1", "tool_name": tool, "tool_input": {"command": "git status"}, key: mode},
                    cli_harness=harness,
                )
                assert norm.permission_mode == mode.strip()
                assert can_rewrite_shell_command(norm) is True

        for blocked_mode in ("default", "acceptEdits", "plan"):
            norm_blocked = normalize_pre_tool_payload(
                {"session_id": "s1", "tool_name": tool, "tool_input": {"command": "git status"}, "permission_mode": blocked_mode},
                cli_harness=harness,
            )
            assert norm_blocked.permission_mode == blocked_mode
            assert can_rewrite_shell_command(norm_blocked) is False

        for unsafe_raw in (None, "", "   ", True, False, 123, {"mode": "auto"}, ["bypassPermissions"]):
            payload: dict[str, Any] = {"session_id": "s1", "tool_name": tool, "tool_input": {"command": "git status"}}
            if unsafe_raw is not None:
                payload["permission_mode"] = unsafe_raw
            norm_none = normalize_pre_tool_payload(payload, cli_harness=harness)
            assert norm_none.permission_mode is None
            assert can_rewrite_shell_command(norm_none) is False

    for codex_tool, codex_input in (("exec_command", {"cmd": "git status"}), ("Bash", {"command": "git status"})):
        codex_norm = normalize_pre_tool_payload(
            {"session_id": "cx-1", "tool_name": codex_tool, "tool_input": codex_input, "permission_mode": "bypassPermissions"},
            cli_harness="codex",
        )
        assert codex_norm.permission_mode == "bypassPermissions"
        assert can_rewrite_shell_command(codex_norm) is False


@pytest.mark.parametrize(
    ("harness", "tool_name", "extra"),
    [
        ("claude", "Bash", {}),
        ("claude", "Bash", {"permission_mode": ""}),
        ("claude", "Bash", {"permission_mode": "default"}),
        ("claude", "Bash", {"permission_mode": "acceptEdits"}),
        ("claude", "Bash", {"permission_mode": "plan"}),
        ("claude", "Bash", {"permission_mode": True}),
        ("claude", "Bash", {"permission_mode": 42}),
        ("claude", "Bash", {"permission_mode": {"mode": "bypassPermissions"}}),
        ("cursor", "Shell", {}),
        ("cursor", "Shell", {"permission_mode": ""}),
        ("cursor", "Shell", {"permission_mode": "default"}),
        ("cursor", "Shell", {"permissionMode": "acceptEdits"}),
        ("cursor", "Bash", {"permission_mode": "plan"}),
    ],
)
def test_claude_and_cursor_skip_cli_rewrite_when_permission_mode_is_interactive_or_missing(
    tmp_path: Path, harness: str, tool_name: str, extra: dict[str, Any]
) -> None:
    state_dir = tmp_path / "state"
    for cmd in ("pytest tests/", "git status"):
        payload: dict[str, Any] = {"session_id": "s-int", "tool_name": tool_name, "tool_input": {"command": cmd}, **extra}
        res = evaluate_hook(payload, state_dir=str(state_dir), cli_harness=harness)
        assert res == {}

    stats = load_telemetry_stats(state_dir / "telemetry_stats.json")
    assert stats["events"]["cli_rewrites"] == 0
    assert read_outcomes_ledger(state_dir)["by_key"] == {}


@pytest.mark.parametrize(
    ("harness", "tool_name", "perm_key", "perm_val"),
    [
        ("claude", "Bash", "permission_mode", "bypassPermissions"),
        ("claude", "Bash", "permission_mode", "dontAsk"),
        ("claude", "Bash", "permissionMode", "auto"),
        ("cursor", "Shell", "permission_mode", "bypassPermissions"),
        ("cursor", "Shell", "permissionMode", "dontAsk"),
        ("cursor", "Bash", "permission_mode", "  auto  "),
    ],
)
def test_claude_and_cursor_rewrite_cli_flags_when_permission_mode_auto_approved(
    tmp_path: Path, harness: str, tool_name: str, perm_key: str, perm_val: str
) -> None:
    state_dir = tmp_path / "state"
    transcript = tmp_path / "claude.jsonl"
    transcript.write_text(json.dumps({"message": {"model": "claude-sonnet-4-6"}}) + "\n", encoding="utf-8")
    expected_model = "claude-sonnet-4-6" if harness == "claude" else "unknown"

    cases = (
        ("pytest tests/", "pytest tests/ -q --tb=short --no-header"),
        ("git status", "git status -sb"),
    )
    for idx, (cmd, expected_cmd) in enumerate(cases, start=1):
        payload: dict[str, Any] = {
            "session_id": "s-auto",
            "tool_name": tool_name,
            "tool_input": {"command": cmd},
            perm_key: perm_val,
        }
        if harness == "claude":
            payload["transcript_path"] = str(transcript)
        res = evaluate_hook(payload, state_dir=str(state_dir), cli_harness=harness)
        assert res == {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": {"command": expected_cmd},
            }
        }
        stats = load_telemetry_stats(state_dir / "telemetry_stats.json")
        assert stats["events"]["cli_rewrites"] == idx
        assert stats["baseline_bytes"] == 0
        assert stats["saved_bytes"] == 0

    ledger = read_outcomes_ledger(state_dir)
    row = ledger["by_key"][f"{harness}|{expected_model}|cli_rewrite"]
    assert row["total"] == 2
    assert row["applied"] == 2


def test_codex_never_rewrites_cli_flags_even_in_bypass_mode(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    for tool_name, tool_input in (
        ("exec_command", {"cmd": "pytest tests/"}),
        ("exec_command", {"cmd": "git status"}),
        ("Bash", {"command": "pytest tests/"}),
    ):
        res = evaluate_hook(
            {
                "session_id": "cx-bypass",
                "tool_name": tool_name,
                "tool_input": tool_input,
                "permission_mode": "bypassPermissions",
            },
            state_dir=str(state_dir),
            cli_harness="codex",
        )
        assert res == {}

    stats = load_telemetry_stats(state_dir / "telemetry_stats.json")
    assert stats["events"]["cli_rewrites"] == 0
    assert read_outcomes_ledger(state_dir)["by_key"] == {}


def test_cli_rewrite_updated_input_preserves_command_keys_and_skips_unrewritten_commands(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    res_cursor_cmd = evaluate_hook(
        {
            "session_id": "s-keys",
            "tool_name": "Shell",
            "tool_input": {"command": "git status", "working_directory": "/repo"},
            "permissionMode": "auto",
        },
        state_dir=str(state_dir),
        cli_harness="cursor",
    )
    assert res_cursor_cmd["hookSpecificOutput"]["updatedInput"] == {
        "command": "git status -sb",
        "working_directory": "/repo",
    }

    res_cmd_alias = evaluate_hook(
        {
            "session_id": "s-keys",
            "tool_name": "Shell",
            "tool_input": {"cmd": "git status", "timeout": 5000},
            "permission_mode": "bypassPermissions",
        },
        state_dir=str(state_dir),
        cli_harness="cursor",
    )
    assert res_cmd_alias["hookSpecificOutput"]["updatedInput"] == {"cmd": "git status -sb", "timeout": 5000}

    res_cmdline = evaluate_hook(
        {
            "session_id": "s-keys",
            "tool_name": "Bash",
            "tool_input": {"CommandLine": "git status"},
            "permission_mode": "dontAsk",
        },
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert res_cmdline["hookSpecificOutput"]["updatedInput"] == {"CommandLine": "git status -sb"}

    norm_mixed = normalize_pre_tool_payload(
        {
            "session_id": "s-keys",
            "tool_name": "Shell",
            "tool_input": {"command": "", "cmd": "git status"},
            "permissionMode": "auto",
        },
        cli_harness="cursor",
    )
    assert format_pre_tool_output({"decision": "allow", "overwrite": {"CommandLine": "git status -sb"}}, norm_mixed) == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": {"command": "", "cmd": "git status -sb"},
        }
    }

    res_noop = evaluate_hook(
        {
            "session_id": "s-keys",
            "tool_name": "Bash",
            "tool_input": {"command": "echo ok"},
            "permission_mode": "bypassPermissions",
        },
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert res_noop == {}

    # Auto-detected Cursor payload without explicit cli_harness
    res_cursor_auto = evaluate_hook(
        {
            "session_id": "s-keys",
            "cursor_version": "2.0",
            "tool_name": "Shell",
            "tool_input": {"command": "git status"},
            "permissionMode": "auto",
        },
        state_dir=str(state_dir),
    )
    assert res_cursor_auto["hookSpecificOutput"]["updatedInput"] == {"command": "git status -sb"}

    # Non-str permission_mode must fail closed even if camelCase permissionMode is set
    res_malformed_dual = evaluate_hook(
        {
            "session_id": "s-keys",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "permission_mode": False,
            "permissionMode": "bypassPermissions",
        },
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert res_malformed_dual == {}

    # Antigravity keeps rewriting without permission_mode
    res_ag = evaluate_hook(
        {
            "conversationId": "ag-rew",
            "stepIdx": 1,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}},
        },
        state_dir=str(state_dir),
    )
    assert res_ag == {"decision": "allow", "overwrite": {"CommandLine": "git status -sb"}}
    assert load_telemetry_stats(state_dir / "telemetry_stats.json")["events"]["cli_rewrites"] == 5


def test_dual_key_permission_mode_and_command_fallback_edge_cases(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    blocked_pms: tuple[Any, ...] = ("   ", "\t", 0, False, {}, [], "default")
    for blocked_pm in blocked_pms:
        norm_fail = normalize_pre_tool_payload(
            {
                "session_id": "s-dual",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "permission_mode": blocked_pm,
                "permissionMode": "bypassPermissions",
            },
            cli_harness="claude",
        )
        assert can_rewrite_shell_command(norm_fail) is False
        assert (
            evaluate_hook(
                {
                    "session_id": "s-dual",
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status"},
                    "permission_mode": blocked_pm,
                    "permissionMode": "bypassPermissions",
                },
                state_dir=str(state_dir),
                cli_harness="claude",
            )
            == {}
        )

    for unset_pm in (None, ""):
        res_fallback = evaluate_hook(
            {
                "session_id": "s-dual",
                "tool_name": "Shell",
                "tool_input": {"command": "git status"},
                "permission_mode": unset_pm,
                "permissionMode": "auto",
            },
            state_dir=str(state_dir),
            cli_harness="cursor",
        )
        assert res_fallback["hookSpecificOutput"]["updatedInput"] == {"command": "git status -sb"}

    norm_empty_both = normalize_pre_tool_payload(
        {
            "session_id": "s-dual",
            "tool_name": "Shell",
            "tool_input": {"command": "", "cmd": ""},
            "permissionMode": "auto",
        },
        cli_harness="cursor",
    )
    assert format_pre_tool_output(
        {"decision": "allow", "overwrite": {"CommandLine": "git status -sb"}},
        norm_empty_both,
    )["hookSpecificOutput"]["updatedInput"] == {"command": "git status -sb", "cmd": ""}

    norm_all_cmdline = normalize_pre_tool_payload(
        {
            "session_id": "s-dual",
            "tool_name": "Bash",
            "tool_input": {"command": "", "cmd": "", "CommandLine": "git status"},
            "permission_mode": "auto",
        },
        cli_harness="claude",
    )
    assert format_pre_tool_output(
        {"decision": "allow", "overwrite": {"CommandLine": "git status -sb"}},
        norm_all_cmdline,
    )["hookSpecificOutput"]["updatedInput"] == {"command": "", "cmd": "", "CommandLine": "git status -sb"}

    res_none_cmd = evaluate_hook(
        {
            "session_id": "s-dual",
            "tool_name": "Shell",
            "tool_input": {"command": None, "cmd": "git status"},
            "permissionMode": "auto",
        },
        state_dir=str(state_dir),
        cli_harness="cursor",
    )
    assert res_none_cmd["hookSpecificOutput"]["updatedInput"] == {"command": None, "cmd": "git status -sb"}


def test_governance_and_bigquery_denies_precede_bypass_permission_cli_rewrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_config.clear_config_cache()
    try:
        ws_root = tmp_path / "workspace"
        ws_root.mkdir()
        cfg_path = tmp_path / "cg_config.json"
        cfg_path.write_text(
            json.dumps(
                {
                    "workspace_root": str(ws_root),
                    "enforce_governance_policy": True,
                    "restricted_bq_datasets": ["raw_warehouse"],
                    "allowed_bq_views_dataset": "ai_views",
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
        state_dir = tmp_path / "state"

        for harness, tool in (("claude", "Bash"), ("cursor", "Shell")):
            res_gov = evaluate_hook(
                {
                    "session_id": "s-gov",
                    "tool_name": tool,
                    "tool_input": {"command": "git commit -m test --no-verify"},
                    "permission_mode": "bypassPermissions",
                },
                state_dir=str(state_dir),
                cli_harness=harness,
            )
            assert res_gov["hookSpecificOutput"]["permissionDecision"] == "deny"

            res_bq = evaluate_hook(
                {
                    "session_id": "s-gov",
                    "tool_name": tool,
                    "tool_input": {"command": 'bq query "SELECT * FROM raw_warehouse.orders"'},
                    "permission_mode": "bypassPermissions",
                },
                state_dir=str(state_dir),
                cli_harness=harness,
            )
            assert res_bq["hookSpecificOutput"]["permissionDecision"] == "deny"

        assert load_telemetry_stats(state_dir / "telemetry_stats.json")["events"]["cli_rewrites"] == 0
        assert read_outcomes_ledger(state_dir)["by_key"] == {}
    finally:
        guard_config.clear_config_cache()


def test_pre_tool_use_main_cli_and_telemetry_resilience(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "conversation_id": "cur-cli",
                    "tool_name": "Shell",
                    "tool_input": {"command": "git status"},
                    "permissionMode": "auto",
                }
            )
        ),
    )
    assert pre_tool_use_main(["--harness", "cursor"]) == 0
    out_cursor = json.loads(capsys.readouterr().out)
    assert out_cursor == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": {"command": "git status -sb"},
        }
    }

    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "session_id": "cl-cli",
                    "tool_name": "Bash",
                    "tool_input": {"command": "pytest tests/"},
                    "permission_mode": "default",
                }
            )
        ),
    )
    assert pre_tool_use_main(["--harness", "claude"]) == 0
    assert json.loads(capsys.readouterr().out) == {}

    # Telemetry write failure must never break or suppress an auto-approved rewrite decision.
    bad_state_dir = tmp_path / "unwritable"
    bad_state_dir.mkdir()
    (bad_state_dir / "telemetry_stats.json").mkdir()
    (bad_state_dir / "outcomes.json").mkdir()
    res_resilient = evaluate_hook(
        {
            "session_id": "s-err",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "permission_mode": "bypassPermissions",
        },
        state_dir=str(bad_state_dir),
        cli_harness="claude",
    )
    capsys.readouterr()
    assert res_resilient == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": {"command": "git status -sb"},
        }
    }


def test_twg_noncanonical_re_does_not_mangle_similar_prefixes_or_home_paths() -> None:
    assert rewrite_quiet_cli_flags("~twg status", enable_atlassian_twg=True) is None
    assert rewrite_quiet_cli_flags("/Users/dev" + "twg status", enable_atlassian_twg=True) is None
    assert rewrite_quiet_cli_flags("/home/alice" + "twg status", enable_atlassian_twg=True) is None
    assert rewrite_quiet_cli_flags("/home/alice/.local/bin/twg status") is None
    assert rewrite_quiet_cli_flags("/home/alice/.local/bin/twg status", enable_atlassian_twg=True) == "twg status"
    assert rewrite_quiet_cli_flags("~/.local/bin/twg jira --help", enable_atlassian_twg=True) == "twg jira --help"
    assert (
        rewrite_quiet_cli_flags("TWG_AGENT_DEFAULTS=1 /Users/dev/.local/bin/twg jira status", enable_atlassian_twg=True)
        == "twg jira status"
    )
    assert rewrite_twg_cli_command("TWG_AGENT_DEFAULTS=1 /Users/dev/.local/bin/twg jira status") == "twg jira status"


def test_unquoted_text_handles_escaped_quotes_in_outline_and_cli_rewrites() -> None:
    from hooks.shell_parser import is_outline_pull

    assert is_outline_pull('cg-outline "a\\" && cat b.py"') is True
    assert is_outline_pull('cg-outline \\"a && cat b.py" \\"') is False
    assert rewrite_quiet_cli_flags('pytest \\"a && echo hi" \\"') is None
    assert rewrite_quiet_cli_flags('grep -n "\\" -r \\"" src/main.py') is None
    assert rewrite_quiet_cli_flags('grep -rn "foo\\"bar" src/') is not None
