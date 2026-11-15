"""Regression and subprocess tests for telemetry/stderr isolation, read-only resilience, and Policy API v1 fail-closed."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from bin import token_usage, update_check
from hooks import config as guard_config
from hooks import policy_engine, post_tool_use, pre_compact, pre_invocation, pre_tool_use, state_store
from hooks.harness_adapter import NormalizedToolCall

REPO_ROOT = Path(__file__).resolve().parent.parent


class ExplodingStrError(RuntimeError):
    """Exception whose string and repr conversions themselves raise RuntimeError."""

    def __str__(self) -> str:
        raise RuntimeError("str() exploded")

    def __repr__(self) -> str:
        raise RuntimeError("repr() exploded")


def _raise_exploding(*_args: Any, **_kwargs: Any) -> Any:
    raise ExplodingStrError("boom")


def _assert_is_deny_output(output: dict[str, Any], harness: str) -> None:
    if harness == "antigravity":
        assert output.get("decision") == "deny"
        assert isinstance(output.get("reason"), str) and output["reason"]
    else:
        hso = output.get("hookSpecificOutput")
        assert isinstance(hso, dict), f"expected hookSpecificOutput deny for {harness}, got {output}"
        assert hso.get("permissionDecision") == "deny"
        assert isinstance(hso.get("permissionDecisionReason"), str) and hso["permissionDecisionReason"]


def _build_read_payload(harness: str, file_path: Path, step_idx: int) -> dict[str, Any]:
    if harness == "antigravity":
        return {
            "conversationId": "conv-p0",
            "stepIdx": step_idx,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(file_path), "StartLine": 1, "EndLine": 10},
            },
        }
    return {
        "session_id": "sess-p0",
        "transcript_path": f"/tmp/.{harness}/session.jsonl",
        "tool_name": "Read",
        "tool_input": {"file_path": str(file_path), "offset": 1, "limit": 10},
    }


def _write_verified_pack(
    pack_dir: Path,
    pack_id: str,
    pack_src: str,
    *,
    scopes: list[str],
    fallback_matchers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pack_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(pack_dir.parent, 0o700)
    os.chmod(pack_dir, 0o700)
    pack_file = pack_dir / "pack.py"
    raw = pack_src.encode("utf-8")
    pack_file.write_bytes(raw)
    os.chmod(pack_file, 0o600)
    file_sha = hashlib.sha256(raw).hexdigest()
    tree_sha = hashlib.sha256(f"pack.py:{file_sha}\n".encode("utf-8")).hexdigest()
    return {
        "id": pack_id,
        "path": str(pack_file),
        "enabled": True,
        "kind": "security",
        "scopes": scopes,
        "fallback_matchers": dict(fallback_matchers or {}),
        "file_hashes": {"pack.py": file_sha},
        "tree_sha256": tree_sha,
        "settings": {},
    }


def _configure_acme_mcp_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, raise_pre_oserror: bool = False) -> Path:
    guard_config.clear_config_cache()
    hook_block = (
        "def on_pre(ctx, dec):\n"
        "    raise OSError('disk full on retry ledger')\n\n"
        if raise_pre_oserror
        else ""
    )
    hook_kw = ", on_pre_decision=on_pre" if raise_pre_oserror else ""
    pack_src = (
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n\n"
        + hook_block
        + "def evaluate(ctx):\n"
        "    args = ctx.canonical_args\n"
        "    nested = args.get('Arguments') if isinstance(args.get('Arguments'), dict) else args\n"
        "    if not isinstance(nested, dict):\n"
        "        return PolicyDecision(decision='deny', reason='Blocked: malformed MCP payload')\n"
        "    sql = nested.get('query')\n"
        "    if not isinstance(sql, str) or 'acme_private_ds' in sql:\n"
        "        return PolicyDecision(decision='deny', reason='Blocked: query restricted')\n"
        "    if 'retryable_gate' in sql:\n"
        "        return PolicyDecision(decision='deny', reason='Retryable lookup denied', metadata={'fail_open_if_retry_unsaved': True})\n"
        "    return None\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        "    pack_id='acme-mcp-sec', api_version=POLICY_API_VERSION,\n"
        f"    kind='security', covered_domains=('synthetic-mcp',), evaluate=evaluate{hook_kw},\n"
        ")\n"
    )
    entry = _write_verified_pack(
        tmp_path / "policies" / f"acme_{'oserr' if raise_pre_oserror else 'std'}",
        "acme-mcp-sec",
        pack_src,
        scopes=["mcp_call"],
        fallback_matchers={"mcp_tool_regex": r"^mcp__?acme_db(?:__|$)"},
    )
    cfg_path = tmp_path / f"cfg_{'oserr' if raise_pre_oserror else 'std'}.json"
    cfg_path.write_text(json.dumps({"policy_packs": [entry]}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    guard_config.clear_config_cache()
    return cfg_path


def _build_mcp_payload(harness: str, sql: str | None, malformed_args: bool = False) -> dict[str, Any]:
    if harness == "antigravity":
        arguments: dict[str, Any] = {
            "ServerName": "acme_db",
            "ToolName": "execute_sql_readonly",
            "Arguments": "not-a-dict" if malformed_args else ({"query": sql} if sql is not None else {}),
        }
        return {
            "conversationId": "conv-mcp",
            "stepIdx": 1,
            "toolCall": {"name": "call_mcp_tool", "args": arguments},
        }
    tool_input: Any = {} if malformed_args or sql is None else {"query": sql}
    return {
        "session_id": "sess-mcp",
        "transcript_path": f"/tmp/.{harness}/session.jsonl",
        "tool_name": "mcp__acme_db__execute_sql_readonly",
        "tool_input": tool_input,
    }


def test_run_telemetry_safely_survives_broken_str_closed_stringio_and_failing_warn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed_stream = io.StringIO()
    closed_stream.close()
    monkeypatch.setattr(sys, "stderr", closed_stream)

    state_store.warn(ExplodingStrError("unprintable"))
    state_store.run_telemetry_safely(_raise_exploding, context="unit_closed_stderr")

    def _broken_warn(msg: object) -> None:
        warn_calls.append(str(msg))
        raise RuntimeError("warn itself exploded")

    warn_calls: list[str] = []
    monkeypatch.setattr(state_store, "warn", _broken_warn)
    state_store.run_telemetry_safely(_raise_exploding, context="unit_broken_warn")
    assert closed_stream.closed is True
    assert warn_calls == ["unit_broken_warn error ignored after decision (ExplodingStrError)"]


@pytest.mark.parametrize("harness", ["antigravity", "claude", "cursor", "codex"])
def test_telemetry_failure_preserves_deny_allow_and_overwrite_across_all_harnesses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
) -> None:
    mcp_steps_dir = tmp_path / ".system_generated" / "steps" / "1"
    mcp_steps_dir.mkdir(parents=True)
    mcp_output = mcp_steps_dir / "output.txt"
    mcp_output.write_text(
        json.dumps({"file_name": "payload.py", "content": "\n".join(f"x_{i} = {i}" for i in range(1500))}),
        encoding="utf-8",
    )

    large_file = tmp_path / "large.py"
    large_file.write_text(
        "\n".join(f"def fn_{i}() -> int:\n    return {i}\n" for i in range(120)) + "\n",
        encoding="utf-8",
    )

    state_clean = tmp_path / f"state_clean_{harness}"
    state_fault = tmp_path / f"state_fault_{harness}"
    state_clean.mkdir()
    state_fault.mkdir()

    p_first = _build_read_payload(harness, large_file, step_idx=1)
    pre_tool_use.evaluate_hook(p_first, state_dir=str(state_clean), cli_harness=harness)
    pre_tool_use.evaluate_hook(p_first, state_dir=str(state_fault), cli_harness=harness)

    p2_deny = _build_read_payload(harness, mcp_output, step_idx=2)
    expected_deny = pre_tool_use.evaluate_hook(p2_deny, state_dir=str(state_clean), cli_harness=harness)
    _assert_is_deny_output(expected_deny, harness)

    if harness == "antigravity":
        p_overlap = {
            "conversationId": "conv-p0",
            "stepIdx": 3,
            "toolCall": {"name": "read_file", "args": {"Path": str(large_file), "StartLine": 5, "EndLine": 40}},
        }
        p_cmd_rewrite = {
            "conversationId": "conv-p0",
            "stepIdx": 4,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest tests/"}},
        }
        p_edit = {
            "conversationId": "conv-p0",
            "stepIdx": 5,
            "toolCall": {"name": "edit_file", "args": {"Path": str(large_file)}},
        }
    else:
        p_overlap = {
            "session_id": "sess-p0",
            "transcript_path": f"/tmp/.{harness}/session.jsonl",
            "tool_name": "Read",
            "tool_input": {"file_path": str(large_file), "offset": 5, "limit": 36},
        }
        p_cmd_rewrite = {
            "session_id": "sess-p0",
            "transcript_path": f"/tmp/.{harness}/session.jsonl",
            "tool_name": "Bash",
            "tool_input": {"command": "pytest tests/"},
        }
        p_edit = {
            "session_id": "sess-p0",
            "transcript_path": f"/tmp/.{harness}/session.jsonl",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(large_file)},
        }

    expected_overlap = pre_tool_use.evaluate_hook(p_overlap, state_dir=str(state_clean), cli_harness=harness)
    expected_rewrite = pre_tool_use.evaluate_hook(p_cmd_rewrite, state_dir=str(state_clean), cli_harness=harness)
    expected_edit = pre_tool_use.evaluate_hook(p_edit, state_dir=str(state_clean), cli_harness=harness)

    closed_stderr = io.StringIO()
    closed_stderr.close()
    monkeypatch.setattr(sys, "stderr", closed_stderr)
    monkeypatch.setattr(pre_tool_use, "record_file_read_outcome", _raise_exploding)
    monkeypatch.setattr(pre_tool_use, "record_direct_outcome", _raise_exploding)
    monkeypatch.setattr(pre_tool_use, "record_telemetry_count", _raise_exploding)

    assert pre_tool_use.evaluate_hook(p2_deny, state_dir=str(state_fault), cli_harness=harness) == expected_deny
    assert pre_tool_use.evaluate_hook(p_overlap, state_dir=str(state_fault), cli_harness=harness) == expected_overlap
    assert pre_tool_use.evaluate_hook(p_cmd_rewrite, state_dir=str(state_fault), cli_harness=harness) == expected_rewrite
    assert pre_tool_use.evaluate_hook(p_edit, state_dir=str(state_fault), cli_harness=harness) == expected_edit


@pytest.mark.parametrize("harness", ["antigravity", "claude", "cursor", "codex"])
def test_security_pack_mandatory_gate_never_falls_through_on_bad_str_or_hook_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
) -> None:
    closed_stderr = io.StringIO()
    closed_stderr.close()
    monkeypatch.setattr(sys, "stderr", closed_stderr)
    _configure_acme_mcp_pack(tmp_path, monkeypatch, raise_pre_oserror=False)

    malformed_payload = _build_mcp_payload(harness, sql=None, malformed_args=True)
    res_malformed = pre_tool_use.evaluate_hook(malformed_payload, state_dir=str(tmp_path), cli_harness=harness)
    _assert_is_deny_output(res_malformed, harness)
    if harness != "antigravity":
        for bad_tool_input in ("not-a-dict", None, [1, 2]):
            non_dict_payload = {
                "session_id": "sess-mcp",
                "transcript_path": f"/tmp/.{harness}/session.jsonl",
                "tool_name": "mcp__acme_db__execute_sql_readonly",
                "tool_input": bad_tool_input,
            }
            res_non_dict = pre_tool_use.evaluate_hook(
                non_dict_payload, state_dir=str(tmp_path), cli_harness=harness
            )
            _assert_is_deny_output(res_non_dict, harness)

    inf_payload = {**_build_mcp_payload(harness, sql="SELECT * FROM acme_private_ds.orders"), "stepIdx": float("inf")}
    res_inf = pre_tool_use.evaluate_hook(inf_payload, state_dir=str(tmp_path), cli_harness=harness)
    _assert_is_deny_output(res_inf, harness)

    sql_payload = _build_mcp_payload(harness, sql="SELECT * FROM acme_private_ds.orders")
    with monkeypatch.context() as mp_norm:
        mp_norm.setattr(pre_tool_use, "normalize_pre_tool_payload", _raise_exploding)
        res_norm_sec = pre_tool_use.evaluate_hook(sql_payload, state_dir=str(tmp_path), cli_harness=harness)
        _assert_is_deny_output(res_norm_sec, harness)

        empty_cfg = tmp_path / "empty_allow.json"
        empty_cfg.write_text("{}", encoding="utf-8")
        mp_norm.setenv("CONTEXT_GUARD_CONFIG_PATH", str(empty_cfg))
        guard_config.clear_config_cache()
        safe_read = _build_read_payload(harness, tmp_path / "any.py", step_idx=1)
        res_norm_read = pre_tool_use.evaluate_hook(safe_read, state_dir=str(tmp_path), cli_harness=harness)
        assert res_norm_read == ({"decision": "allow"} if harness == "antigravity" else {})

    _configure_acme_mcp_pack(tmp_path, monkeypatch, raise_pre_oserror=False)
    with monkeypatch.context() as mp_apply:
        mp_apply.setattr(pre_tool_use, "apply_policy_packs_with_records", _raise_exploding)
        res_exc = pre_tool_use.evaluate_hook(sql_payload, state_dir=str(tmp_path), cli_harness=harness)
        _assert_is_deny_output(res_exc, harness)

    with monkeypatch.context() as mp_fmt:
        mp_fmt.setattr(pre_tool_use, "format_pre_tool_output", _raise_exploding)
        res_fmt_exc = pre_tool_use.evaluate_hook(sql_payload, state_dir=str(tmp_path), cli_harness=harness)
        _assert_is_deny_output(res_fmt_exc, harness)

    # Disk OSError in on_pre_decision downgrades fail_open_if_retry_unsaved denies while non-retryable stays blocked
    _configure_acme_mcp_pack(tmp_path, monkeypatch, raise_pre_oserror=True)
    retry_payload = _build_mcp_payload(harness, sql="retryable_gate")
    res_retry = pre_tool_use.evaluate_hook(retry_payload, state_dir=str(tmp_path), cli_harness=harness)
    assert res_retry == ({"decision": "allow"} if harness == "antigravity" else {})
    res_hard = pre_tool_use.evaluate_hook(sql_payload, state_dir=str(tmp_path), cli_harness=harness)
    _assert_is_deny_output(res_hard, harness)


def test_load_runtime_config_distinguishes_filenotfound_from_permission_directory_and_schema_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_config.clear_config_cache()
    scoped_call = NormalizedToolCall(
        harness="claude",
        canonical_tool="call_mcp_tool",
        canonical_args={"ServerName": "acme_db", "ToolName": "execute_sql_readonly"},
        original_tool_name="mcp__acme_db__execute_sql_readonly",
        original_tool_input={},
        session_id="sess-cfg",
        step_idx=1,
        cwd="/tmp",
        artifact_dir=None,
        mutated_paths=(),
    )

    missing_cfg = tmp_path / "absent_dir" / "config.json"
    cfg_missing = guard_config.load_runtime_config(missing_cfg)
    assert cfg_missing.get("config_error") is None
    assert policy_engine.apply_policy_packs(scoped_call, cfg_missing) is None

    empty_cfg = tmp_path / "empty_config.json"
    empty_cfg.write_text("{}", encoding="utf-8")
    cfg_empty = guard_config.load_runtime_config(empty_cfg)
    assert cfg_empty.get("config_error") is None
    assert policy_engine.apply_policy_packs(scoped_call, cfg_empty) is None

    perm_cfg = tmp_path / "perm_config.json"
    perm_cfg.write_text("{}", encoding="utf-8")
    orig_read_text = Path.read_text

    def _deny_perm(self: Path, *args: Any, **kwargs: Any) -> str:
        if self == perm_cfg:
            raise PermissionError(13, "Permission denied", str(self))
        return orig_read_text(self, *args, **kwargs)

    guard_config.clear_config_cache()
    monkeypatch.setattr(Path, "read_text", _deny_perm)
    cfg_perm = guard_config.load_runtime_config(perm_cfg)
    assert cfg_perm.get("config_error")
    res_perm = policy_engine.apply_policy_packs(scoped_call, cfg_perm)
    assert res_perm is not None and res_perm["decision"] == "deny"
    assert "CONFIG ERROR" in res_perm["reason"]
    monkeypatch.undo()

    guard_config.clear_config_cache()
    dir_cfg = tmp_path / "dir_as_config.json"
    dir_cfg.mkdir()
    res_dir = policy_engine.apply_policy_packs(scoped_call, guard_config.load_runtime_config(dir_cfg))
    assert res_dir is not None and res_dir["decision"] == "deny"

    guard_config.clear_config_cache()
    bad_utf8_cfg = tmp_path / "bad_utf8.json"
    bad_utf8_cfg.write_bytes(b"\xff\xfe\x00\x00")
    res_utf8 = policy_engine.apply_policy_packs(scoped_call, guard_config.load_runtime_config(bad_utf8_cfg))
    assert res_utf8 is not None and res_utf8["decision"] == "deny"

    for idx, content in enumerate(["{corrupt", '["list_not_dict"]']):
        guard_config.clear_config_cache()
        bad_json_cfg = tmp_path / f"bad_json_{idx}.json"
        bad_json_cfg.write_text(content, encoding="utf-8")
        res_bad = policy_engine.apply_policy_packs(scoped_call, guard_config.load_runtime_config(bad_json_cfg))
        assert res_bad is not None and res_bad["decision"] == "deny"

    mistyped_payloads: list[dict[str, Any]] = [
        {"read_confirm_policy": "invalid"},
        {"optimizers": "not-dict"},
        {"optimizers": {"range_trim": "nope"}},
        {"optimizers": {"cli_rewrites": 123}},
        {"integrations": {"atlassian_twg": "yes"}},
        {"regret_window_steps": False},
        {"policy_packs": "not-list"},
        {"model_labels": []},
    ]
    for idx, doc in enumerate(mistyped_payloads):
        guard_config.clear_config_cache()
        schema_cfg = tmp_path / f"schema_{idx}.json"
        schema_cfg.write_text(json.dumps(doc), encoding="utf-8")
        res_schema = policy_engine.apply_policy_packs(scoped_call, guard_config.load_runtime_config(schema_cfg))
        assert res_schema is not None and res_schema["decision"] == "deny", f"expected deny for mistyped doc {doc}"


def _run_with_closed_stderr_pipe(
    cmd: list[str], stdin_data: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    r_fd, w_fd = os.pipe()
    os.close(r_fd)
    try:
        return subprocess.run(
            cmd,
            input=stdin_data.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=w_fd,
            env=env,
            check=False,
        )
    finally:
        os.close(w_fd)


def test_post_tool_use_and_single_stdout_json_invariants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed_stderr = io.StringIO()
    closed_stderr.close()
    monkeypatch.setattr(sys, "stderr", closed_stderr)
    with monkeypatch.context() as mp:
        mp.setattr(post_tool_use, "record_shell_output", _raise_exploding)
        res = post_tool_use.handle_post_tool_use(
            "claude",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "pytest"},
                "tool_response": {"stdout": "1 passed\n"},
            },
        )
        assert res == {}

    with monkeypatch.context() as mp:
        out_buf = io.StringIO()
        mp.setattr(sys, "stdin", io.StringIO("{malformed"))
        mp.setattr(sys, "stdout", out_buf)
        mp.setattr(post_tool_use, "warn", _raise_exploding)
        assert post_tool_use.main(["--harness", "claude"]) == 0
        assert out_buf.getvalue() == "{}\n"

    class _BrokenFlushStdout:
        def __init__(self) -> None:
            self.writes: list[str] = []

        def write(self, data: str) -> int:
            self.writes.append(data)
            return len(data)

        def flush(self) -> None:
            raise BrokenPipeError("stdout pipe broken during flush")

    _configure_acme_mcp_pack(tmp_path, monkeypatch, raise_pre_oserror=False)
    mcp_stdin = json.dumps(
        {
            "conversationId": "c-stdout",
            "artifactDirectoryPath": str(tmp_path),
            "stepIdx": 1,
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "acme_db",
                    "ToolName": "execute_sql_readonly",
                    "Arguments": {"query": "SELECT * FROM acme_private_ds.orders"},
                },
            },
        }
    )
    for hook_fn, raw_in in (
        (lambda: pre_tool_use.main([]), mcp_stdin),
        (pre_compact.main, "{}"),
        (pre_invocation.main, "{}"),
    ):
        broken_out = _BrokenFlushStdout()
        with monkeypatch.context() as mp:
            mp.setattr(sys, "stdin", io.StringIO(raw_in))
            mp.setattr(sys, "stdout", broken_out)
            assert hook_fn() == 0
            assert len(broken_out.writes) == 1, f"double stdout JSON emission: {broken_out.writes}"


def test_real_subprocess_with_closed_stderr_pipe_exits_zero_with_valid_single_json_on_all_hooks(
    tmp_path: Path,
) -> None:
    fake_home = tmp_path / "fake_home"
    fake_plugin_root = fake_home / ".gemini" / "config" / "plugins" / "context-guard"
    telemetry_dir = fake_plugin_root / "telemetry"
    telemetry_dir.mkdir(parents=True)
    stats_ledger = telemetry_dir / "stats.json"
    outcomes_ledger = telemetry_dir / "outcomes.json"
    sub_env = {
        **os.environ,
        "HOME": str(fake_home),
        "CONTEXT_GUARD_HOME": str(fake_plugin_root),
    }

    def _seed_corrupt_ledgers() -> None:
        stats_ledger.write_text("[1, 2]\n", encoding="utf-8")
        outcomes_ledger.write_text("[1, 2]\n", encoding="utf-8")

    sample = tmp_path / "sample.py"
    sample.write_text("a = 1\nb = 2\n", encoding="utf-8")
    mcp_step_dir = tmp_path / ".system_generated" / "steps" / "9"
    mcp_step_dir.mkdir(parents=True)
    mcp_output = mcp_step_dir / "output.txt"
    mcp_output.write_text(
        json.dumps({"file_name": "step_out.py", "content": "\n".join(f"row_{i} = {i}" for i in range(1500))}),
        encoding="utf-8",
    )
    state_dir_allow = tmp_path / "state_allow"
    state_dir_allow.mkdir()
    state_dir_deny = tmp_path / "state_deny"
    state_dir_deny.mkdir()

    p_allow = {
        "conversationId": "pipe-conv",
        "artifactDirectoryPath": str(state_dir_allow),
        "stepIdx": 1,
        "toolCall": {"name": "read_file", "args": {"Path": str(sample), "StartLine": 1, "EndLine": 2}},
    }
    p2_deny = {
        "conversationId": "pipe-conv",
        "artifactDirectoryPath": str(state_dir_deny),
        "stepIdx": 2,
        "toolCall": {"name": "read_file", "args": {"Path": str(mcp_output)}},
    }

    def _assert_warns_when_open_and_survives_closed_pipe(
        cmd: list[str], stdin_payload: str, state_setup: Any = None
    ) -> bytes:
        _seed_corrupt_ledgers()
        if state_setup is not None:
            state_setup()
        open_proc = subprocess.run(
            cmd,
            input=stdin_payload.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=sub_env,
            check=False,
        )
        assert open_proc.returncode == 0
        assert b"context-guard:" in open_proc.stderr, (
            f"expected warn() diagnostic on stderr for {cmd[1]}, got {open_proc.stderr!r}"
        )
        _seed_corrupt_ledgers()
        if state_setup is not None:
            state_setup()
        closed_proc = _run_with_closed_stderr_pipe(cmd, stdin_payload, env=sub_env)
        assert closed_proc.returncode == 0, f"expected 0 (not 120), got {closed_proc.returncode}"
        assert closed_proc.stdout.count(b"\n") == 1
        return closed_proc.stdout

    def _reset_allow_dir() -> None:
        state_file = state_dir_allow / ".context_guard_state.json"
        if state_file.exists():
            state_file.unlink()

    out_allow = _assert_warns_when_open_and_survives_closed_pipe(
        [sys.executable, str(REPO_ROOT / "hooks" / "pre_tool_use.py")],
        json.dumps(p_allow),
        state_setup=_reset_allow_dir,
    )
    assert json.loads(out_allow.decode("utf-8"))["decision"] == "allow"

    def _reset_deny_dir() -> None:
        sf = state_dir_deny / ".context_guard_state.json"
        if sf.exists():
            sf.unlink()

    out_deny = _assert_warns_when_open_and_survives_closed_pipe(
        [sys.executable, str(REPO_ROOT / "hooks" / "pre_tool_use.py")],
        json.dumps(p2_deny),
        state_setup=_reset_deny_dir,
    )
    assert json.loads(out_deny.decode("utf-8"))["decision"] == "deny"

    out_malformed_pre = _assert_warns_when_open_and_survives_closed_pipe(
        [sys.executable, str(REPO_ROOT / "hooks" / "pre_tool_use.py")],
        "{malformed-json",
    )
    assert json.loads(out_malformed_pre.decode("utf-8"))["decision"] == "allow"

    out_post = _assert_warns_when_open_and_survives_closed_pipe(
        [sys.executable, str(REPO_ROOT / "hooks" / "post_tool_use.py")],
        "{malformed-json",
    )
    assert out_post.strip() == b"{}"

    def _prime_compact_error() -> None:
        compact_dir = tmp_path / "state_compact"
        sf = compact_dir / ".context_guard_state.json"
        if sf.exists() and sf.is_file():
            sf.unlink()
        sf.mkdir(parents=True, exist_ok=True)

    out_compact = _assert_warns_when_open_and_survives_closed_pipe(
        [sys.executable, str(REPO_ROOT / "hooks" / "pre_compact.py")],
        json.dumps({"artifactDirectoryPath": str(tmp_path / "state_compact")}),
        state_setup=_prime_compact_error,
    )
    assert out_compact.strip() == b"{}"

    inv_dir = tmp_path / "inv_state"
    inv_dir.mkdir()
    (inv_dir / ".context_guard_state.json").mkdir()
    out_inv = _assert_warns_when_open_and_survives_closed_pipe(
        [sys.executable, str(REPO_ROOT / "hooks" / "pre_invocation.py")],
        json.dumps({"artifactDirectoryPath": str(inv_dir), "initialNumSteps": 5}),
    )
    assert out_inv.strip() == b"{}"

    _seed_corrupt_ledgers()
    _reset_deny_dir()
    dirty_buffer_probe = (
        f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r}); "
        "from hooks import pre_tool_use\n"
        "try:\n"
        "    sys.stderr.write('prior buffered write\\n')\n"
        "    sys.stderr.flush()\n"
        "except OSError:\n"
        "    pass\n"
        "raise SystemExit(pre_tool_use.main([]))\n"
    )
    proc_dirty = _run_with_closed_stderr_pipe(
        [sys.executable, "-c", dirty_buffer_probe],
        json.dumps(p2_deny),
        env=sub_env,
    )
    assert proc_dirty.returncode == 0, f"dirty stderr buffer caused exit {proc_dirty.returncode}"
    assert json.loads(proc_dirty.stdout.decode("utf-8"))["decision"] == "deny"


def test_readonly_telemetry_dir_fails_open_without_raising_or_truncating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "ro-plugin"
    (root / ".git").mkdir(parents=True)
    telemetry_dir = root / "telemetry"
    telemetry_dir.mkdir(parents=True)
    (root / "plugin.json").write_text(json.dumps({"version": "9.5.0"}), encoding="utf-8")

    usage_path = telemetry_dir / "token_usage.json"
    seed_usage = token_usage.empty_usage_state()
    seed_usage["started_at"] = "2026-11-01T00:00:00Z"
    usage_before = json.dumps(seed_usage, indent=2) + "\n"
    usage_path.write_text(usage_before, encoding="utf-8")

    update_path = telemetry_dir / "update.json"
    update_before = (
        json.dumps(
            {
                "checked_at": "2026-11-01T00:00:00Z",
                "installed": "9.4.0",
                "local": "9.5.0",
                "latest": "9.5.0",
                "state": "install_pending",
                "remote_error": None,
            },
            indent=2,
        )
        + "\n"
    )
    update_path.write_text(update_before, encoding="utf-8")

    install_path = telemetry_dir / "install.json"
    install_before = (
        json.dumps({"version": "9.4.0", "installed_at": "2026-11-01T00:00:00Z"}, indent=2) + "\n"
    )
    install_path.write_text(install_before, encoding="utf-8")

    claude_dir = tmp_path / "ro-transcripts" / "claude" / "proj"
    claude_dir.mkdir(parents=True)
    (claude_dir / "s.jsonl").write_text(
        json.dumps(
            {
                "type": "assistant",
                "timestamp": "2026-11-07T10:00:00Z",
                "isSidechain": False,
                "message": {
                    "id": "msg-ro-1",
                    "role": "assistant",
                    "model": "claude-sonnet-4-5",
                    "usage": {
                        "input_tokens": 120,
                        "output_tokens": 15,
                        "cache_read_input_tokens": 0,
                        "cache_creation_input_tokens": 0,
                    },
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    roots = {
        "antigravity": tmp_path / "ro-transcripts" / "antigravity",
        "claude": tmp_path / "ro-transcripts" / "claude",
        "codex": tmp_path / "ro-transcripts" / "codex",
        "cursor": tmp_path / "ro-transcripts" / "cursor",
    }

    now = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)

    def _fake_git(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="abcdef1234567890\trefs/tags/v9.5.0\n",
            stderr="",
        )

    monkeypatch.setattr(update_check, "run_git", _fake_git)
    monkeypatch.setattr(update_check, "hooks_registered", lambda: True)

    for ro_file in (usage_path, update_path, install_path):
        ro_file.chmod(0o444)
    telemetry_dir.chmod(0o555)
    try:
        usage_res = token_usage.refresh_usage(state_path=usage_path, roots=roots)
        assert usage_res["totals"]["claude|claude-sonnet-4-5"]["input"] == 120

        refreshed = update_check.refresh_update_state(
            root,
            now,
            run_git=_fake_git,
            force=True,
            hooks_registered=lambda: True,
        )
        assert refreshed["latest"] == "9.5.0"

        installed_state = update_check.record_install(root, now)
        assert isinstance(installed_state, dict)

        update_check.remove_install_record(root)

        assert update_check.main(["--plugin-root", str(root), "--force"]) == 0
        capsys.readouterr()

        assert usage_path.read_text(encoding="utf-8") == usage_before
        assert update_path.read_text(encoding="utf-8") == update_before
        assert install_path.read_text(encoding="utf-8") == install_before
    finally:
        telemetry_dir.chmod(0o755)
        for ro_file in (usage_path, update_path, install_path):
            if ro_file.exists():
                ro_file.chmod(0o666)
