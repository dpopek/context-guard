"""Shared synthetic builders and hook invocation helpers for Context-Guard tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hooks import outcomes
from hooks.pre_tool_use import evaluate_hook
from hooks.state_store import STATE_FILENAME


def write_python_module(
    path: Path, funcs: int = 20, body_lines: int = 9, pad: int = 0
) -> Path:
    """Create a synthetic Python source file (20 * 11 = 220 lines by default)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if pad > 0:
        inner = max(1, body_lines - 1) if body_lines != 9 else 1
        chunks = [
            f"def func_{idx}():\n"
            + "".join(f"    v_{j} = '{'x' * pad}_{idx}_{j}'\n" for j in range(inner))
            for idx in range(funcs)
        ]
    else:
        chunks = [
            f"def func_{idx}(x: int) -> int:\n"
            + "".join(f"    v_{j} = x + {idx} + {j}\n" for j in range(body_lines))
            + f"    return v_{body_lines - 1}\n"
            for idx in range(funcs)
        ]
    path.write_text("".join(chunks), encoding="utf-8")
    return path


def claude_read(
    path: Path | str,
    state_dir: Path | str,
    offset: int | None = None,
    limit: int | None = None,
    *,
    session_id: str = "s1",
) -> dict[str, Any]:
    """Evaluate a Claude Code `Read` tool call and return the raw hook response dictionary."""
    tool_input: dict[str, Any] = {"file_path": str(path)}
    if offset is not None:
        tool_input["offset"] = offset
    if limit is not None:
        tool_input["limit"] = limit
    return evaluate_hook(
        {
            "hook_event_name": "PreToolUse",
            "session_id": session_id,
            "tool_name": "Read",
            "tool_input": tool_input,
        },
        state_dir=str(state_dir),
        cli_harness="claude",
    )


def claude_decision(
    path: Path | str,
    state_dir: Path | str,
    offset: int | None = None,
    limit: int | None = None,
    *,
    session_id: str = "s1",
) -> str:
    """Evaluate a Claude Code `Read` tool call and return `'allow'` or `'deny'`."""
    out = claude_read(path, state_dir, offset=offset, limit=limit, session_id=session_id)
    hso = out.get("hookSpecificOutput") or {}
    return str(hso.get("permissionDecision", "allow"))


def codex_bash(
    command: str,
    state_dir: Path | str,
    *,
    cwd: Path | str | None = None,
    session_id: str = "s1",
) -> dict[str, Any]:
    """Evaluate an OpenAI Codex `Bash` tool call and return the raw hook response dictionary."""
    payload: dict[str, Any] = {
        "hook_event_name": "PreToolUse",
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    if cwd is not None:
        payload["cwd"] = str(cwd)
    return evaluate_hook(payload, state_dir=str(state_dir), cli_harness="codex")


def codex_bash_verdict(
    state_dir: Path | str,
    command: str,
    *,
    cwd: Path | str | None = None,
    session_id: str = "s1",
) -> tuple[str, str, dict[str, Any]]:
    """Evaluate a Codex `Bash` tool call and return `(decision, reason, hookSpecificOutput)`."""
    res = codex_bash(command, state_dir, cwd=cwd, session_id=session_id)
    hso = res.get("hookSpecificOutput") or {}
    return (
        str(hso.get("permissionDecision", "allow")),
        str(hso.get("permissionDecisionReason", "")),
        hso,
    )


def ag_read(
    path: Path | str,
    state_dir: Path | str,
    *,
    start_line: int | None = None,
    end_line: int | None = None,
    step_idx: int = 1,
    conv_id: str = "c1",
    tool_name: str = "read_file",
) -> dict[str, Any]:
    """Evaluate an Antigravity `read_file` or `view_file` tool call."""
    args: dict[str, Any] = {"Path": str(path)}
    if start_line is not None:
        args["StartLine"] = start_line
    if end_line is not None:
        args["EndLine"] = end_line
    return evaluate_hook(
        {
            "conversationId": conv_id,
            "trajectoryStepIndex": step_idx,
            "toolCall": {"name": tool_name, "arguments": args},
        },
        state_dir=str(state_dir),
        cli_harness="antigravity",
    )


def read_session_state(state_dir: Path | str) -> dict[str, Any]:
    """Load `.context_guard_state.json` from `state_dir`."""
    return json.loads((Path(state_dir) / STATE_FILENAME).read_text(encoding="utf-8"))


def read_outcomes_ledger(state_dir: Path | str) -> dict[str, Any]:
    """Load `telemetry_outcomes.json` from `state_dir`."""
    return outcomes.load_outcomes(outcomes.ledger_path_for(str(state_dir)))
