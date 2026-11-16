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


def test_post_tool_use_deferred_range_trim_outcomes_and_shadow_invalidation(tmp_path: Path) -> None:
    import os
    from hooks import outcomes, pre_tool_use, telemetry

    src = tmp_path / "mod.py"
    lines = [f"v_{i} = {i}" for i in range(1, 251)]
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")
    sd = tmp_path / "st"
    sd.mkdir()

    # Real tool_use_id via Claude PostToolBatch attributes deferred range_trim outcome to step_ledger
    pre_tool_use.evaluate_hook({"session_id": "s1", "tool_use_id": "id-1", "tool_name": "Read", "tool_input": {"file_path": str(src), "offset": 1, "limit": 80}}, state_dir=str(sd), cli_harness="claude")
    handle_post_tool_use("claude", {"session_id": "s1", "tool_calls": [{"tool_name": "Read", "tool_use_id": "id-1", "tool_input": {"file_path": str(src), "offset": 1, "limit": 80}, "tool_response": "\n".join(lines[:80])}]}, state_dir=str(sd), event_name="PostToolBatch")
    pre_tool_use.evaluate_hook({"session_id": "s1", "tool_use_id": "id-trim", "tool_name": "Read", "tool_input": {"file_path": str(src), "offset": 1, "limit": 180}}, state_dir=str(sd), cli_harness="claude")
    handle_post_tool_use("claude", {"session_id": "s1", "tool_calls": [{"tool_name": "Read", "tool_use_id": "id-trim", "tool_input": {"file_path": str(src), "offset": 81, "limit": 100}, "tool_response": "\n".join(lines[80:180])}]}, state_dir=str(sd), event_name="PostToolBatch")

    out_doc = outcomes.load_outcomes(sd / "outcomes.json")
    assert any(any(ev.get("event_id") == "id-trim:range_trim" for ev in evs) for evs in out_doc["step_ledger"].values())
    assert out_doc["unattributed_anon"]["total"] == 0

    # Synthetic call_id (missing tool_use_id) produces tier 0 / synthetic fallback -> unattributed_anon on Cursor single read
    pre_tool_use.evaluate_hook({"session_id": "s2", "tool_name": "Read", "tool_input": {"file_path": str(src), "offset": 1, "limit": 80}}, state_dir=str(sd), cli_harness="cursor")
    handle_post_tool_use("cursor", {"session_id": "s2", "tool_name": "Read", "tool_input": {"file_path": str(src), "offset": 1, "limit": 80}, "tool_output": "\n".join(lines[:80])}, state_dir=str(sd))

    # PostToolUse Edit and Codex apply_patch invalidate shadow.json even in a fresh state_dir
    sd_fresh = tmp_path / "st_fresh"
    sd_fresh.mkdir()
    sp = telemetry.shadow_path_for(sd_fresh)
    assert sp is not None
    canon = os.path.realpath(str(src))
    telemetry.record_shadow_read("sx", canon, 1, 50, 1, 2, "sha1", shadow_path=sp)
    handle_post_tool_use("claude", {"session_id": "sx", "tool_name": "Edit", "tool_input": {"file_path": str(src)}, "tool_response": "ok"}, state_dir=str(sd_fresh))
    assert telemetry.load_shadow_ledger(sp)["sessions"].get("sx", {}).get("paths", {}) == {}

    telemetry.record_shadow_read("sy", canon, 1, 50, 1, 0, "sha2", min_tier=0, shadow_path=sp)
    handle_post_tool_use("codex", {"session_id": "sy", "tool_name": "apply_patch", "cwd": str(tmp_path), "tool_input": {"patch": f"*** Begin Patch\n*** Update File: {src.name}\n@@\n*** End Patch"}, "tool_response": "ok"}, state_dir=str(sd_fresh))
    assert telemetry.load_shadow_ledger(sp)["sessions"].get("sy", {}).get("paths", {}) == {}


@pytest.mark.parametrize("policy", ["strict", "bounded"])
def test_shadow_mode_records_only_confirmed_claude_batch_reads(
    policy: str, isolated_user_env: Path, tmp_path: Path
) -> None:
    import os
    from hooks import config, pre_tool_use, telemetry
    from tests.helpers import read_session_state

    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(
        json.dumps(
            {
                "read_confirm_policy": policy,
                "optimizers": {"range_trim": "shadow", "auto_outline": "shadow", "cli_rewrites": "shadow"},
            }
        ),
        encoding="utf-8",
    )
    config.clear_config_cache()

    src = tmp_path / "mod.py"
    lines = [f"v_{i} = {i}" for i in range(1, 251)]
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")
    sd = tmp_path / f"st_{policy}"
    sd.mkdir()
    sp = telemetry.shadow_path_for(sd)
    assert sp is not None
    canon_ph = telemetry.pseudonymize_shadow_path(os.path.realpath(str(src)))
    stats_file, outcomes_file = sd / "telemetry_stats.json", sd / "outcomes.json"

    def _pre(cid: str) -> bytes:
        pre_tool_use.evaluate_hook(
            {
                "session_id": "s1",
                "tool_use_id": cid,
                "tool_name": "Read",
                "tool_input": {"file_path": str(src), "offset": 1, "limit": 80},
            },
            state_dir=str(sd),
            cli_harness="claude",
        )
        return stats_file.read_bytes()

    # Claude PostToolUse alone (provisional) does NOT add reads
    s_before = _pre("id-prov")
    handle_post_tool_use(
        "claude",
        {
            "session_id": "s1",
            "tool_use_id": "id-prov",
            "tool_name": "Read",
            "tool_input": {"file_path": str(src), "offset": 1, "limit": 80},
            "tool_response": "\n".join(lines[:80]),
        },
        state_dir=str(sd),
        event_name="PostToolUse",
    )
    assert telemetry.load_shadow_ledger(sp)["sessions"]["s1"]["paths"][canon_ph]["reads"] == []
    assert stats_file.read_bytes() == s_before and not outcomes_file.exists()

    # PostToolUseFailure does NOT add reads
    s_before = _pre("id-fail")
    handle_post_tool_use(
        "claude",
        {
            "session_id": "s1",
            "tool_use_id": "id-fail",
            "tool_name": "Read",
            "tool_input": {"file_path": str(src), "offset": 1, "limit": 80},
            "error": "read failed",
        },
        state_dir=str(sd),
        event_name="PostToolUseFailure",
    )
    assert telemetry.load_shadow_ledger(sp)["sessions"]["s1"]["paths"][canon_ph]["reads"] == []
    assert stats_file.read_bytes() == s_before and not outcomes_file.exists()

    # PostToolBatch with mismatched or redacted text does NOT add reads
    s_before = _pre("id-mismatch")
    handle_post_tool_use(
        "claude",
        {
            "session_id": "s1",
            "tool_calls": [
                {
                    "tool_name": "Read",
                    "tool_use_id": "id-mismatch",
                    "tool_input": {"file_path": str(src), "offset": 1, "limit": 80},
                    "tool_response": "\n".join(["tampered"] * 80),
                }
            ],
        },
        state_dir=str(sd),
        event_name="PostToolBatch",
    )
    assert telemetry.load_shadow_ledger(sp)["sessions"]["s1"]["paths"][canon_ph]["reads"] == []
    assert stats_file.read_bytes() == s_before and not outcomes_file.exists()

    s_before = _pre("id-redacted")
    handle_post_tool_use(
        "claude",
        {
            "session_id": "s1",
            "tool_calls": [
                {
                    "tool_name": "Read",
                    "tool_use_id": "id-redacted",
                    "tool_input": {"file_path": str(src), "offset": 1, "limit": 80},
                    "tool_response": "[REDACTED]",
                }
            ],
        },
        state_dir=str(sd),
        event_name="PostToolBatch",
    )
    assert telemetry.load_shadow_ledger(sp)["sessions"]["s1"]["paths"][canon_ph]["reads"] == []
    assert stats_file.read_bytes() == s_before and not outcomes_file.exists()

    # PostToolBatch with matching content fingerprint records [1, 80, step, 2] and leaves stats/outcomes untouched
    s_before = _pre("id-ok")
    pending_step = int(
        read_session_state(sd)["files"][os.path.realpath(str(src))]["pending_reads"]["id-ok"]["step"]
    )
    handle_post_tool_use(
        "claude",
        {
            "session_id": "s1",
            "tool_calls": [
                {
                    "tool_name": "Read",
                    "tool_use_id": "id-ok",
                    "tool_input": {"file_path": str(src), "offset": 1, "limit": 80},
                    "tool_response": "\n".join(lines[:80]),
                }
            ],
        },
        state_dir=str(sd),
        event_name="PostToolBatch",
    )
    assert telemetry.load_shadow_ledger(sp)["sessions"]["s1"]["paths"][canon_ph]["reads"] == [
        [1, 80, pending_step, 2]
    ]
    assert stats_file.read_bytes() == s_before
    assert load_telemetry_stats(stats_file)["events"]["ranges_trimmed"] == 0
    assert not outcomes_file.exists()


def _write_spool_cfg(home_dir: Path, **optimizers: str) -> None:
    from hooks import config

    cfg_path = home_dir / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"optimizers": optimizers}), encoding="utf-8")
    config.clear_config_cache()


def test_output_spool_off_keeps_post_tool_use_and_main_empty(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sd = tmp_path / "sd_off"
    sd.mkdir()
    big_out = "\n".join(f"line {i}: {'x' * 80}" for i in range(300))
    payload = _bash("pytest -q tests/", session_id="s-off", tool_use_id="cid-off-1", hook_event_name="PostToolUse", tool_response=big_out)
    assert handle_post_tool_use("claude", payload, state_dir=str(sd)) == {}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    capsys.readouterr()
    assert main(["--harness", "claude", "--state-dir", str(sd)]) == 0
    assert json.loads(capsys.readouterr().out) == {}
    stats = load_telemetry_stats(sd / "telemetry_stats.json")
    assert stats["events"]["outputs_spooled"] == 0
    assert not (sd / "outcomes.json").exists()


def test_active_spool_claude_bash_and_mcp_records_stats_window_and_main_stdout(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.helpers import read_outcomes_ledger, read_session_state

    _write_spool_cfg(isolated_user_env, output_spool="active", range_trim="active")
    sd = tmp_path / "sd_active"
    big_out = "\n".join(f"FAILED tests/test_mod.py::test_case_{i} - {'payload_' * 10}" for i in range(300))
    # Omitting cwd in default workspace isolation mode fails open ({}) without writing spools
    assert handle_post_tool_use(
        "claude",
        _bash("pytest tests/", session_id="s-act", tool_use_id="cid-no-cwd", hook_event_name="PostToolUse", tool_response=big_out),
        state_dir=str(sd),
    ) == {}
    assert load_telemetry_stats(sd / "telemetry_stats.json")["events"]["outputs_spooled"] == 0
    bash_payload = _bash(
        "pytest tests/",
        session_id="s-act",
        tool_use_id="cid-bash-1",
        hook_event_name="PostToolUse",
        tool_response=big_out,
        cwd=str(tmp_path),
    )
    # Bash-first session (state_dir does not yet exist): main() must emit replaced output JSON and bump auto_step_seq >= 1
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(bash_payload)))
    capsys.readouterr()
    assert main(["--harness", "claude", "--state-dir", str(sd)]) == 0
    emitted = json.loads(capsys.readouterr().out)
    updated_text = emitted["hookSpecificOutput"]["updatedToolOutput"]
    assert "cg-spool" in updated_text and len(updated_text) < len(big_out)

    stats = load_telemetry_stats(sd / "telemetry_stats.json")
    assert stats["events"]["outputs_spooled"] == 1
    assert stats["by_harness"]["claude"]["hits"] == 1
    assert stats["by_harness"]["claude"]["saved_tokens"] > 0
    assert stats["last_event"]["kind"] == "outputs_spooled"
    assert stats["saved_bytes"] > 0
    assert read_session_state(sd)["auto_step_seq"] >= 1

    # Duplicate PostToolUse delivery with identical call_id deduplicates outputs_spooled and updates window idempotently
    assert handle_post_tool_use("claude", bash_payload, state_dir=str(sd))["hookSpecificOutput"]["updatedToolOutput"] == updated_text
    assert load_telemetry_stats(sd / "telemetry_stats.json")["events"]["outputs_spooled"] == 1
    ledger = read_outcomes_ledger(sd)
    spool_wins = [w for w in ledger["open_windows"].values() if w["key"].endswith("|output_spool")]
    assert len(spool_wins) == 1 and spool_wins[0]["step_idx"] >= 1
    assert spool_wins[0]["meta"]["total_lines"] == 300

    # MCP PostToolUse spools list-of-text-blocks responses, while failures skip spooling
    mcp_payload = {
        "hook_event_name": "PostToolUse",
        "session_id": "s-act",
        "tool_use_id": "cid-mcp-1",
        "tool_name": "mcp__srv__query",
        "tool_input": {"q": "select *"},
        "tool_response": [{"type": "text", "text": big_out}],
        "cwd": str(tmp_path),
    }
    mcp_res = handle_post_tool_use("claude", mcp_payload, state_dir=str(sd))
    assert isinstance(mcp_res["hookSpecificOutput"]["updatedToolOutput"], list)
    assert load_telemetry_stats(sd / "telemetry_stats.json")["events"]["outputs_spooled"] == 2

    fail_payload = _bash("pytest tests/", session_id="s-act", tool_use_id="cid-fail", hook_event_name="PostToolUseFailure", error=big_out)
    assert handle_post_tool_use("claude", fail_payload, state_dir=str(sd)) == {}


def test_shadow_spool_and_post_tool_batch_trim_window(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    from hooks import telemetry
    from tests.helpers import claude_read, read_outcomes_ledger, write_python_module

    spool_dir = tmp_path / "shadow_spool_check"
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))
    _write_spool_cfg(isolated_user_env, output_spool="shadow", range_trim="active", auto_outline="off")
    sd = tmp_path / "sd_shadow"
    sd.mkdir()
    big_out = "\n".join(f"row_{i}: {'d' * 75}" for i in range(300))

    # Omitting cwd in shadow workspace mode also fails open without recording shadow_spools or writing blobs
    assert handle_post_tool_use(
        "claude",
        _bash("pytest tests/", session_id="s-sh", tool_use_id="cid-sh-0", hook_event_name="PostToolUse", tool_response=big_out),
        state_dir=str(sd),
    ) == {}
    assert not (sd / "shadow.json").exists()

    res = handle_post_tool_use(
        "claude",
        _bash("pytest tests/", session_id="s-sh", tool_use_id="cid-sh-1", hook_event_name="PostToolUse", tool_response=big_out, cwd=str(tmp_path)),
        state_dir=str(sd),
    )
    assert res == {}
    assert not any(spool_dir.glob("sp_*.txt")) if spool_dir.exists() else True
    assert load_telemetry_stats(sd / "telemetry_stats.json")["events"]["outputs_spooled"] == 0
    assert not (sd / "outcomes.json").exists()

    sh = telemetry.load_shadow_ledger(telemetry.shadow_path_for(sd))
    assert sh["shadow_spools"]["count"] == 1
    assert sh["shadow_spools"]["estimated_saved_bytes"] > 0
    assert sh["shadow_spools"]["by_harness"] == {"claude": 1}

    # PostToolBatch skips spooling while still confirming reads and opening trimmed-prefix range_trim window
    src = write_python_module(tmp_path / "trim_mod.py", funcs=25, body_lines=9)
    canon = os.path.realpath(str(src))
    claude_read(src, sd, offset=1, limit=100, session_id="s-sh")
    out2 = claude_read(src, sd, offset=1, limit=150, session_id="s-sh")
    assert out2["hookSpecificOutput"]["updatedInput"]["offset"] == 101

    batch_res = handle_post_tool_use(
        "claude",
        {"session_id": "s-sh", "tool_calls": [{"tool_name": "Bash", "tool_use_id": "b-skip", "tool_input": {"command": "pytest"}, "tool_response": big_out}]},
        state_dir=str(sd),
        event_name="PostToolBatch",
    )
    assert batch_res == {}
    assert telemetry.load_shadow_ledger(telemetry.shadow_path_for(sd))["shadow_spools"]["count"] == 1
    wins = read_outcomes_ledger(sd)["open_windows"]
    trim_key = f"s-sh|{canon}|range_trim"
    assert [k for k, w in wins.items() if w["key"].endswith("|range_trim")] == [trim_key]
    assert wins[trim_key]["meta"] == {"trimmed_start": 1, "trimmed_end": 100}
