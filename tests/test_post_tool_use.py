"""PostToolUse shell-output hook: payload shapes per harness, privacy, and the never-fail entry point."""
from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from hooks.post_tool_use import ShellCall, handle_post_tool_use, main, normalise_payload
from hooks.telemetry import load_telemetry_stats


def _bash(command: str = "git log", **extra: Any) -> dict[str, Any]:
    return {"tool_name": "Bash", "tool_input": {"command": command}, **extra}


def test_claude_success_joins_stdout_and_stderr() -> None:
    payload = _bash(
        hook_event_name="PostToolUse",
        tool_response={"stdout": "out\n", "stderr": "err\n", "interrupted": False, "isImage": False},
    )
    assert normalise_payload("claude", payload) == ShellCall("git log", "out\nerr\n", "ok")


def test_claude_failure_with_exit_line_is_fail() -> None:
    payload = _bash("npm test", hook_event_name="PostToolUseFailure", error="Exit code 2\nboom\n")
    assert normalise_payload("claude", payload) == ShellCall("npm test", "boom\n", "fail")


def test_claude_failure_without_exit_line_is_unknown() -> None:
    payload = _bash(hook_event_name="PostToolUseFailure", error="spawn failed")
    assert normalise_payload("claude", payload) == ShellCall("git log", "spawn failed", "unknown")


def test_claude_response_without_streams_is_unparsed() -> None:
    payload = _bash(hook_event_name="PostToolUse", tool_response="weird")
    assert normalise_payload("claude", payload) == ShellCall("git log", None, "unknown")


@pytest.mark.parametrize(
    "response, expected",
    [
        ({"output": "o", "exit_code": 0}, ("o", "ok")),
        ({"output": "o", "exit_code": 1}, ("o", "fail")),
        ({"stdout": "a", "stderr": "b"}, ("ab", "unknown")),
        ("plain text", ("plain text", "unknown")),
        (["odd"], (None, "unknown")),
    ],
)
def test_codex_shapes(response: Any, expected: tuple[str | None, str]) -> None:
    call = normalise_payload(
        "codex", {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": response}
    )
    assert call is not None
    assert (call.output, call.outcome) == expected


def test_codex_list_command_keeps_the_script_argument_whole() -> None:
    call = normalise_payload(
        "codex",
        {"tool_name": "shell", "tool_input": {"command": ["bash", "-lc", "git diff"]}, "tool_response": "x"},
    )
    assert call is not None
    assert call.command == "bash -lc 'git diff'"


@pytest.mark.parametrize(
    "tool_output, expected",
    [
        (json.dumps({"stdout": "o", "exitCode": 0}), ("o", "ok")),
        (json.dumps({"stdout": "o", "exitCode": 3}), ("o", "fail")),
        ("not json", (None, "unknown")),
        (json.dumps([1]), (None, "unknown")),
    ],
)
def test_cursor_shapes(tool_output: str, expected: tuple[str | None, str]) -> None:
    call = normalise_payload(
        "cursor", {"tool_name": "Shell", "tool_input": {"command": "ls"}, "tool_output": tool_output}
    )
    assert call is not None
    assert (call.output, call.outcome) == expected


def test_non_shell_tools_and_unknown_harnesses_are_ignored() -> None:
    assert normalise_payload("claude", {"tool_name": "Read", "tool_input": {"file_path": "/a"}}) is None
    assert normalise_payload("antigravity", _bash()) is None


def test_handle_records_family_and_size(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    payload = _bash("git log -5", hook_event_name="PostToolUse", tool_response={"stdout": "a" * 1200, "stderr": ""})
    assert handle_post_tool_use("claude", payload, stats) == {}
    entry = load_telemetry_stats(stats)["shell_output"]["harnesses"]["claude"]["git_log"]
    assert (entry["count"], entry["ok"], entry["tokens"], entry["buckets"]["1-5k"]) == (1, 1, 300, 1)


def test_handle_counts_unparsed_payloads(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    payload = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": ["odd"]}
    handle_post_tool_use("codex", payload, stats)
    section = load_telemetry_stats(stats)["shell_output"]
    assert section["unparsed"] == 1
    assert section["harnesses"]["codex"]["list"]["unknown"] == 1


def test_handle_ignores_non_shell_tools(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    assert handle_post_tool_use("claude", {"tool_name": "Read"}, stats) == {}
    assert not stats.exists()


def test_no_command_or_output_text_is_persisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_cmd = "SENTINEL_CMD_7f3a"  # gitleaks:allow - test sentinel, not a credential
    secret_out = "SENTINEL_OUT_9c1e"
    payload = _bash(
        f"grep {secret_cmd} .",
        hook_event_name="PostToolUse",
        tool_response={"stdout": secret_out * 1000, "stderr": ""},
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    assert main(["--harness", "claude"]) == 0
    assert capsys.readouterr().out == "{}\n"
    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert files, "the hook should have written the ledger"
    for path in files:
        data = path.read_bytes()
        assert secret_cmd.encode() not in data
        assert secret_out.encode() not in data


@pytest.mark.parametrize("stdin", ["", "not json", "[1, 2]", "null"])
def test_entry_point_always_prints_an_empty_object(
    stdin: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    assert main(["--harness", "codex"]) == 0
    assert capsys.readouterr().out == "{}\n"


def test_entry_point_swallows_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import hooks.post_tool_use as hook_mod

    def boom(_command: str) -> str:
        raise RuntimeError("bad")

    monkeypatch.setattr(hook_mod, "classify_family", boom)
    payload = _bash(hook_event_name="PostToolUse", tool_response={"stdout": "x", "stderr": ""})
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    assert main(["--harness", "claude"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "{}\n"
    assert "shell output hook failed: RuntimeError" in captured.err
    assert "bad" not in captured.err
    assert not [p for p in tmp_path.rglob("*") if p.is_file()], "no ledger should be written on failure"


def test_entry_point_survives_bare_harness_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = _bash(hook_event_name="PostToolUse", tool_response={"stdout": "x", "stderr": ""})
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    assert main(["--harness"]) == 0
    assert capsys.readouterr().out == "{}\n"


def test_codex_cmd_key_is_the_command() -> None:
    call = normalise_payload(
        "codex", {"tool_name": "exec_command", "tool_input": {"cmd": "git diff"}, "tool_response": "x"}
    )
    assert call is not None
    assert call.command == "git diff"


def test_command_key_falls_back_to_command_line() -> None:
    call = normalise_payload(
        "codex", {"tool_name": "exec", "tool_input": {"CommandLine": "ls"}, "tool_response": "x"}
    )
    assert call is not None
    assert call.command == "ls"


def test_cursor_run_terminal_cmd_matches_shell() -> None:
    base = {"tool_input": {"command": "ls"}, "tool_output": json.dumps({"stdout": "o", "exitCode": 0})}
    assert normalise_payload("cursor", {"tool_name": "run_terminal_cmd", **base}) == normalise_payload(
        "cursor", {"tool_name": "Shell", **base}
    )


def test_codex_exec_command_is_classified_end_to_end(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    payload = {"tool_name": "exec_command", "tool_input": {"cmd": "git diff"}, "tool_response": "a" * 400}
    handle_post_tool_use("codex", payload, stats)
    families = load_telemetry_stats(stats)["shell_output"]["harnesses"]["codex"]
    assert families["git_diff"]["count"] == 1
    assert "other" not in families
