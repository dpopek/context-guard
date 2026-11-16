"""Shared synthetic builders and hook invocation helpers for Context-Guard tests."""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

from hooks import outcomes
from hooks.post_tool_use import handle_post_tool_use
from hooks.pre_tool_use import evaluate_hook
from hooks.state_store import STATE_FILENAME

_HELPER_CALL_SEQ = itertools.count(1)


def _read_lines_slice(path: Path, start_line: int, end_line: int | None) -> str:
    if not path.is_file():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    stop = len(lines) if end_line is None or end_line < 0 else min(len(lines), end_line)
    return "\n".join(lines[max(0, start_line - 1) : stop])


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
    confirm: bool = True,
    tool_use_id: str | None = None,
    cwd: Path | str | None = None,
) -> dict[str, Any]:
    """Evaluate a Claude Code `Read` tool call and optionally confirm delivery via `PostToolBatch`."""
    tool_input: dict[str, Any] = {"file_path": str(path)}
    if offset is not None:
        tool_input["offset"] = offset
    if limit is not None:
        tool_input["limit"] = limit
    cid = tool_use_id or f"toolu_helper_{next(_HELPER_CALL_SEQ)}"
    pre_payload: dict[str, Any] = {
        "hook_event_name": "PreToolUse",
        "session_id": session_id,
        "tool_name": "Read",
        "tool_input": tool_input,
        "tool_use_id": cid,
    }
    if cwd is not None:
        pre_payload["cwd"] = str(cwd)
    out = evaluate_hook(
        pre_payload,
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    hso = out.get("hookSpecificOutput") or {}
    if confirm and hso.get("permissionDecision") != "deny":
        updated = hso.get("updatedInput") if isinstance(hso.get("updatedInput"), dict) else {}
        eff_in = updated or tool_input
        exec_path = Path(str(eff_in.get("file_path") or path))
        eff_start = int(eff_in.get("offset") or 1)
        eff_end = (eff_start + int(eff_in["limit"]) - 1) if eff_in.get("limit") is not None else None
        if (Path(state_dir) / STATE_FILENAME).is_file():
            for entry in read_session_state(state_dir).get("files", {}).values():
                pending = (entry.get("pending_reads") or {}).get(cid) if isinstance(entry, dict) else None
                if isinstance(pending, dict):
                    exec_path = Path(str(pending.get("redirect_path") or pending.get("canonical_target") or exec_path))
                    eff_start, eff_end = int(pending["exec_start"]), int(pending["delivered_end"])
                    break
        body = _read_lines_slice(exec_path, eff_start, eff_end)
        batch_payload: dict[str, Any] = {
            "hook_event_name": "PostToolBatch",
            "session_id": session_id,
            "tool_calls": [
                {
                    "tool_name": "Read",
                    "tool_use_id": cid,
                    "tool_input": eff_in,
                    "tool_response": body,
                    "is_error": False,
                }
            ],
        }
        if cwd is not None:
            batch_payload["cwd"] = str(cwd)
        handle_post_tool_use(
            "claude",
            batch_payload,
            state_dir=str(state_dir),
            event_name="PostToolBatch",
        )
    return out


def claude_decision(
    path: Path | str,
    state_dir: Path | str,
    offset: int | None = None,
    limit: int | None = None,
    *,
    session_id: str = "s1",
    confirm: bool = True,
) -> str:
    """Evaluate a Claude Code `Read` tool call and return `'allow'` or `'deny'`."""
    out = claude_read(path, state_dir, offset=offset, limit=limit, session_id=session_id, confirm=confirm)
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
    confirm: bool = True,
    call_id: str | None = None,
) -> dict[str, Any]:
    """Evaluate an Antigravity `read_file` or `view_file` tool call and optionally emit `PostToolUse`."""
    args: dict[str, Any] = {"Path": str(path)}
    if start_line is not None:
        args["StartLine"] = start_line
    if end_line is not None:
        args["EndLine"] = end_line
    eff_cid = call_id or f"ag_helper_{next(_HELPER_CALL_SEQ)}"
    out = evaluate_hook(
        {
            "conversationId": conv_id,
            "stepIdx": step_idx,
            "toolCall": {"id": eff_cid, "name": tool_name, "args": args},
        },
        state_dir=str(state_dir),
        cli_harness="antigravity",
    )
    if confirm and out.get("decision") != "deny":
        handle_post_tool_use(
            "antigravity",
            {
                "conversationId": conv_id,
                "stepIdx": step_idx,
                "toolCall": {"id": eff_cid, "name": tool_name, "args": args},
            },
            state_dir=str(state_dir),
            event_name="PostToolUse",
        )
    return out


def confirm_read_slice(
    harness: str,
    state_dir: Path | str,
    file_path: Path | str,
    start_line: int,
    end_line: int,
    call_id: str,
    *,
    session_id: str = "s1",
) -> dict[str, Any]:
    """Emit a synthetic Read confirmation event (`PostToolBatch` for Claude, `PostToolUse` for Cursor/AG)."""
    body = _read_lines_slice(Path(file_path), start_line, end_line)
    if harness == "claude":
        payload: dict[str, Any] = {
            "hook_event_name": "PostToolBatch",
            "session_id": session_id,
            "tool_calls": [{"tool_name": "Read", "tool_use_id": call_id, "tool_input": {"file_path": str(file_path)}, "tool_response": body, "is_error": False}],
        }
        return handle_post_tool_use("claude", payload, state_dir=str(state_dir), event_name="PostToolBatch")
    if harness == "cursor":
        payload = {"session_id": session_id, "tool_name": "Read", "call_id": call_id, "tool_input": {"file_path": str(file_path)}, "tool_output": body}
        return handle_post_tool_use("cursor", payload, state_dir=str(state_dir), event_name="PostToolUse")
    payload = {"conversationId": session_id, "toolCall": {"id": call_id, "name": "read_file", "args": {"Path": str(file_path)}}}
    return handle_post_tool_use("antigravity", payload, state_dir=str(state_dir), event_name="PostToolUse")


def read_session_state(state_dir: Path | str) -> dict[str, Any]:
    """Load `.context_guard_state.json` from `state_dir`."""
    return json.loads((Path(state_dir) / STATE_FILENAME).read_text(encoding="utf-8"))


def read_outcomes_ledger(state_dir: Path | str) -> dict[str, Any]:
    """Load `telemetry_outcomes.json` from `state_dir`."""
    return outcomes.load_outcomes(outcomes.ledger_path_for(str(state_dir)))
