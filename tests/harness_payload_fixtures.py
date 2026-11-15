"""Realistic multi-harness Pre/Post tool payload builders for read-confirmation tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def format_claude_read_gutter(lines: list[str], start_line: int = 1, sep: str = "→") -> str:
    """Format lines with Claude Code Read gutter (`cat -n` style)."""
    return "\n".join(f"{start_line + idx:6d}{sep}{line}" for idx, line in enumerate(lines))


def claude_pre_read_payload(
    path: str | Path,
    *,
    offset: int | None = None,
    limit: int | None = None,
    tool_use_id: str = "toolu_claude_01",
    tool_name: str = "Read",
    session_id: str = "sess-claude-01",
    transcript_path: str | Path | None = None,
) -> dict[str, Any]:
    """Build a realistic Claude Code PreToolUse Read payload."""
    tool_input: dict[str, Any] = {"file_path": str(path)}
    if offset is not None:
        tool_input["offset"] = offset
    if limit is not None:
        tool_input["limit"] = limit
    payload: dict[str, Any] = {
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "tool_input": tool_input,
    }
    if transcript_path is not None:
        payload["transcript_path"] = str(transcript_path)
    return payload


def claude_post_read_payload(
    path: str | Path,
    *,
    tool_use_id: str = "toolu_claude_01",
    start_line: int = 1,
    num_lines: int = 10,
    total_lines: int = 20,
    content: str | None = None,
    is_error: bool = False,
    truncated: bool = False,
    tool_name: str = "Read",
    session_id: str = "sess-claude-01",
) -> dict[str, Any]:
    """Build a Claude Code PostToolUse payload (metadata-first, provisional only)."""
    file_meta: dict[str, Any] = {
        "filePath": str(path),
        "startLine": start_line,
        "numLines": num_lines,
        "totalLines": total_lines,
    }
    if content is not None:
        file_meta["content"] = content
    tool_response: dict[str, Any] = {"type": "text", "file": file_meta}
    if is_error:
        tool_response["is_error"] = True
    if truncated:
        tool_response["truncated"] = True
    return {
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "tool_input": {"file_path": str(path), "offset": start_line, "limit": num_lines},
        "tool_response": tool_response,
    }


def claude_batch_read_item(
    path: str | Path,
    *,
    tool_use_id: str = "toolu_claude_01",
    response: str | list[dict[str, Any]] = "",
    start_line: int = 1,
    limit: int | None = None,
    is_error: bool = False,
    truncated: bool = False,
    tool_name: str = "Read",
) -> dict[str, Any]:
    """Build one `tool_calls` element inside Claude Code's official `PostToolBatch` payload."""
    tool_input: dict[str, Any] = {"file_path": str(path), "offset": start_line}
    if limit is not None:
        tool_input["limit"] = limit
    item: dict[str, Any] = {
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "tool_input": tool_input,
        "tool_response": response,
    }
    if is_error:
        item["is_error"] = True
    if truncated:
        item["truncated"] = True
    return item


def claude_post_batch_payload(
    tool_calls: list[dict[str, Any]],
    *,
    session_id: str = "sess-claude-01",
) -> dict[str, Any]:
    """Build Claude Code's official `PostToolBatch` hook payload."""
    return {
        "session_id": session_id,
        "hook_event_name": "PostToolBatch",
        "tool_calls": tool_calls,
    }


def claude_post_failure_payload(
    path: str | Path,
    *,
    tool_use_id: str = "toolu_claude_01",
    error: str = "File not found",
    tool_name: str = "Read",
    session_id: str = "sess-claude-01",
) -> dict[str, Any]:
    """Build a Claude Code `PostToolUseFailure` payload."""
    return {
        "session_id": session_id,
        "hook_event_name": "PostToolUseFailure",
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "tool_input": {"file_path": str(path)},
        "error": error,
    }


def cursor_pre_read_payload(
    path: str | Path,
    *,
    offset: int | None = None,
    limit: int | None = None,
    call_id: str | None = "cur_01",
    tool_name: str = "Read",
    conversation_id: str = "conv-cursor-01",
) -> dict[str, Any]:
    """Build a Cursor IDE preToolUse payload."""
    tool_input: dict[str, Any] = {"file_path": str(path)}
    if offset is not None:
        tool_input["offset"] = offset
    if limit is not None:
        tool_input["limit"] = limit
    payload: dict[str, Any] = {
        "conversation_id": conversation_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
    }
    if call_id is not None:
        payload["call_id"] = call_id
    return payload


def cursor_post_read_payload(
    path: str | Path,
    *,
    call_id: str | None = "cur_01",
    tool_output: Any = "",
    offset: int = 1,
    limit: int | None = None,
    status: str = "success",
    error: str | None = None,
    tool_name: str = "Read",
    truncated: bool = False,
    conversation_id: str = "conv-cursor-01",
) -> dict[str, Any]:
    """Build a Cursor IDE postToolUse payload."""
    tool_input: dict[str, Any] = {"file_path": str(path), "offset": offset}
    if limit is not None:
        tool_input["limit"] = limit
    payload: dict[str, Any] = {
        "conversation_id": conversation_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_output": tool_output,
        "status": status,
    }
    if call_id is not None:
        payload["call_id"] = call_id
    if error is not None:
        payload["error"] = error
    if truncated:
        payload["truncated"] = True
    return payload


def ag_pre_read_payload(
    path: str | Path,
    *,
    start_line: int | None = None,
    end_line: int | None = None,
    step_idx: int = 1,
    call_id: str | None = "ag_call_01",
    byte_offset: int = 0,
    conversation_id: str = "conv-ag-01",
    transcript_path: str | Path | None = None,
) -> dict[str, Any]:
    """Build an Antigravity PreToolUse `read_file` payload."""
    args: dict[str, Any] = {"Path": str(path)}
    if start_line is not None:
        args["StartLine"] = start_line
    if end_line is not None:
        args["EndLine"] = end_line
    if byte_offset > 0:
        args["ByteOffset"] = byte_offset
    tool_call: dict[str, Any] = {"name": "read_file", "args": args}
    if call_id is not None:
        tool_call["id"] = call_id
    payload: dict[str, Any] = {
        "conversationId": conversation_id,
        "stepIdx": step_idx,
        "toolCall": tool_call,
    }
    if transcript_path is not None:
        payload["artifactDirectoryPath"] = str(transcript_path)
    return payload


def ag_post_read_payload(
    path: str | Path,
    *,
    call_id: str | None = "ag_call_01",
    step_idx: int = 1,
    start_line: int = 1,
    end_line: int = 10,
    byte_offset: int = 0,
    error: str | None = None,
    tool_name: str = "read_file",
    conversation_id: str = "conv-ag-01",
) -> dict[str, Any]:
    """Build an Antigravity PostToolUse `read_file` payload (no response body by platform)."""
    args: dict[str, Any] = {"Path": str(path), "StartLine": start_line, "EndLine": end_line}
    if byte_offset > 0:
        args["ByteOffset"] = byte_offset
    tool_call: dict[str, Any] = {"name": tool_name, "args": args}
    if call_id is not None:
        tool_call["id"] = call_id
    payload: dict[str, Any] = {
        "conversationId": conversation_id,
        "stepIdx": step_idx,
        "toolCall": tool_call,
    }
    if error is not None:
        payload["error"] = error
    return payload


def codex_pre_shell_payload(
    command: str,
    *,
    call_id: str = "cod_01",
    tool_name: str = "exec_command",
    session_id: str = "sess-codex-01",
) -> dict[str, Any]:
    """Build a Codex PreToolUse shell payload."""
    return {
        "session_id": session_id,
        "tool_name": tool_name,
        "call_id": call_id,
        "tool_input": {"cmd": command},
    }


def codex_post_shell_payload(
    output: str = "",
    *,
    command: str = "cat a.py",
    call_id: str = "cod_01",
    exit_code: int = 0,
    tool_name: str = "exec_command",
    error: str | None = None,
    session_id: str = "sess-codex-01",
) -> dict[str, Any]:
    """Build a Codex PostToolUse shell payload."""
    payload: dict[str, Any] = {
        "session_id": session_id,
        "tool_name": tool_name,
        "call_id": call_id,
        "tool_input": {"cmd": command},
        "tool_response": {"output": output, "exit_code": exit_code},
    }
    if error is not None:
        payload["error"] = error
    return payload
