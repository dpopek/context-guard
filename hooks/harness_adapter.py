"""Multi-Harness PreToolUse adapter for Antigravity, Claude Code, Cursor, and OpenAI Codex."""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from hooks.file_io import count_file_lines_streaming

__all__ = [
    "AUTO_APPROVED_PERMISSION_MODES", "HarnessName", "NormalizedToolCall", "can_rewrite_shell_command",
    "count_file_lines_streaming", "detect_harness", "extract_apply_patch_paths", "format_pre_tool_output",
    "normalize_line_bounds", "normalize_pre_tool_payload",
]

HarnessName = Literal["antigravity", "claude", "cursor", "codex"]
AUTO_APPROVED_PERMISSION_MODES: frozenset[str] = frozenset({"bypassPermissions", "dontAsk", "auto"})
_APPLY_PATCH_HEADER_RE = re.compile(r"^\*\*\*\s+(?:Update|Add|Delete)\s+File:\s+(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class NormalizedToolCall:
    """Normalized representation of a PreToolUse event across all 4 harnesses."""

    harness: HarnessName
    canonical_tool: str
    canonical_args: dict[str, Any]
    original_tool_name: str
    original_tool_input: dict[str, Any]
    session_id: str
    step_idx: int
    cwd: str | None
    artifact_dir: str | None
    mutated_paths: tuple[str, ...] = ()
    permission_mode: str | None = None


def detect_harness(payload: dict[str, Any], cli_harness: str | None = None, env: dict[str, str] | None = None) -> HarnessName:
    """Identify the calling agentic harness from CLI flag, payload structure, or environment."""
    harnesses: tuple[HarnessName, ...] = ("antigravity", "claude", "cursor", "codex")
    for h in harnesses:
        if cli_harness == h:
            return h
    if "toolCall" in payload or "stepIdx" in payload or "artifactDirectoryPath" in payload or "tool_name" not in payload:
        return "antigravity"
    transcript = str(payload.get("transcript_path") or payload.get("transcriptPath") or "")
    path_hints: tuple[tuple[str, HarnessName], ...] = (("codex", "codex"), ("cursor", "cursor"), ("claude", "claude"))
    for needle, h in path_hints:
        if f"/.{needle}/" in transcript or f"\\.{needle}\\" in transcript:
            return h
    if "cursor_version" in payload or "workspace_roots" in payload:
        return "cursor"
    env_map = env if env is not None else os.environ
    env_hints: tuple[tuple[str, HarnessName], ...] = (("CODEX_", "codex"), ("CLAUDE_", "claude"), ("CURSOR_", "cursor"))
    for prefix, h in env_hints:
        if any(key.startswith(prefix) for key in env_map):
            return h
    return "claude"


def _resolve_with_cwd(raw_path: str, cwd: str | None) -> str:
    cleaned = raw_path.strip()
    if not cleaned:
        return ""
    return cleaned if (os.path.isabs(cleaned) or cleaned.startswith("/") or not cwd) else str(Path(cwd) / cleaned)


def extract_apply_patch_paths(tool_input: dict[str, Any] | str, cwd: str | None = None) -> list[str]:
    """Extract target file paths from Codex `apply_patch` input."""
    if isinstance(tool_input, str):
        patch_text = tool_input
    elif isinstance(tool_input, dict):
        patch_text = str(tool_input.get("patch") or tool_input.get("input") or tool_input.get("diff") or tool_input.get("raw") or "")
    else:
        return []

    paths: list[str] = []
    seen: set[str] = set()
    for match in _APPLY_PATCH_HEADER_RE.finditer(patch_text):
        if not (raw_p := match.group(1).strip()):
            continue
        resolved = _resolve_with_cwd(raw_p, cwd)
        if resolved not in seen:
            seen.add(resolved)
            paths.append(resolved)
    return paths


def _safe_finite_int(raw: Any, default: int = 0) -> int:
    """Coerce ints and finite floats to int without raising on bool, NaN, or Infinity."""
    if isinstance(raw, bool):
        return default
    if isinstance(raw, int):
        return raw
    return int(raw) if isinstance(raw, float) and math.isfinite(raw) else default


def normalize_line_bounds(
    start_raw: Any, end_raw: Any, *, offset_raw: Any = None, limit_raw: Any = None,
    has_start_key: bool = True, has_end_key: bool = True,
) -> tuple[int, int, bool]:
    """Normalize StartLine/EndLine or offset/limit into `(start_line, end_line, is_inverted_end)`."""
    if has_start_key and offset_raw is None:
        s_val = _safe_finite_int(start_raw, default=0)
        start_line = s_val if s_val >= 1 else 1
    else:
        off_val = _safe_finite_int(offset_raw, default=0)
        start_line = max(1, off_val) if off_val >= 1 else 1

    is_inverted_end = False
    if has_end_key and limit_raw is None:
        e_val = _safe_finite_int(end_raw, default=-1)
        if isinstance(end_raw, int) and not isinstance(end_raw, bool) and e_val != -1 and e_val < start_line:
            is_inverted_end = True
        end_line = e_val if e_val >= start_line else -1
    else:
        lim_val = _safe_finite_int(limit_raw, default=0)
        end_line = start_line + lim_val - 1 if lim_val >= 1 else -1
    return start_line, end_line, is_inverted_end


def normalize_pre_tool_payload(
    payload: dict[str, Any],
    cli_harness: str | None = None,
    env: dict[str, str] | None = None,
) -> NormalizedToolCall:
    """Normalize an incoming PreToolUse JSON payload into a canonical representation."""
    harness = detect_harness(payload, cli_harness=cli_harness, env=env)

    if harness == "antigravity":
        tool_call = payload.get("toolCall")
        if not isinstance(tool_call, dict):
            tool_call = {}
        raw_tool = str(tool_call.get("name") or "")
        raw_args = tool_call.get("args")
        orig_args = dict(raw_args) if isinstance(raw_args, dict) else {}
        step_idx = _safe_finite_int(payload.get("stepIdx"), default=0)
        session_id = str(payload.get("conversationId") or "default")
        cwd_raw = payload.get("cwd")
        cwd = cwd_raw.strip() if isinstance(cwd_raw, str) and cwd_raw.strip() else None
        artifact_dir_raw = payload.get("artifactDirectoryPath")
        artifact_dir = artifact_dir_raw.strip() if isinstance(artifact_dir_raw, str) and artifact_dir_raw.strip() else None
        ag_args = dict(orig_args)
        for path_field in ("Path", "TargetFile", "AbsolutePath"):
            val = ag_args.get(path_field)
            if isinstance(val, str) and val.strip():
                ag_args[path_field] = _resolve_with_cwd(val, cwd)
        mutated: tuple[str, ...] = ()
        ag_canonical = raw_tool
        if raw_tool in ("edit_file", "write_file", "replace_file_content", "multi_replace_file_content", "write_to_file"):
            p = ag_args.get("Path") or ag_args.get("TargetFile") or ag_args.get("AbsolutePath")
            if isinstance(p, str) and p.strip():
                mutated = (p.strip(),)
            ag_canonical = "edit_file" if raw_tool in ("edit_file", "replace_file_content", "multi_replace_file_content") else "write_file"
        return NormalizedToolCall(
            harness="antigravity", canonical_tool=ag_canonical, canonical_args=ag_args,
            original_tool_name=raw_tool, original_tool_input=orig_args, session_id=session_id,
            step_idx=step_idx, cwd=cwd, artifact_dir=artifact_dir, mutated_paths=mutated,
        )

    raw_tool = str(payload.get("tool_name") or "")
    raw_input = payload.get("tool_input")
    orig_input: dict[str, Any] = dict(raw_input) if isinstance(raw_input, dict) else ({"patch": raw_input} if isinstance(raw_input, str) else {})
    session_id = str(payload.get("session_id") or payload.get("conversation_id") or payload.get("conversationId") or "default")
    cwd_raw = payload.get("cwd")
    cwd = cwd_raw.strip() if isinstance(cwd_raw, str) and cwd_raw.strip() else None
    step_idx = _safe_finite_int(payload.get("stepIdx"), default=0)
    raw_pm = payload.get("permission_mode")
    perm_raw = raw_pm if raw_pm not in (None, "") else payload.get("permissionMode")
    permission_mode = perm_raw.strip() if isinstance(perm_raw, str) and perm_raw.strip() else None

    def _build(canonical_tool: str, canonical_args: dict[str, Any], mutated_paths: tuple[str, ...] = ()) -> NormalizedToolCall:
        return NormalizedToolCall(
            harness=harness, canonical_tool=canonical_tool, canonical_args=canonical_args,
            original_tool_name=raw_tool, original_tool_input=orig_input, session_id=session_id,
            step_idx=step_idx, cwd=cwd, artifact_dir=None, mutated_paths=mutated_paths, permission_mode=permission_mode,
        )

    if raw_tool in ("Read", "NotebookRead", "read_file", "view_file"):
        raw_path = str(orig_input.get("file_path") or orig_input.get("notebook_path") or orig_input.get("path") or orig_input.get("Path") or orig_input.get("AbsolutePath") or "")
        resolved_path = _resolve_with_cwd(raw_path, cwd)
        cell_id_raw = orig_input.get("cell_id") if raw_tool == "NotebookRead" else None
        if isinstance(cell_id_raw, str) and cell_id_raw.strip():
            return _build("NotebookRead", {"Path": resolved_path, "cell_id": cell_id_raw.strip()})
        start_line, end_line, _ = normalize_line_bounds(
            orig_input.get("StartLine"), orig_input.get("EndLine"),
            offset_raw=orig_input.get("offset"), limit_raw=orig_input.get("limit"),
            has_start_key="StartLine" in orig_input, has_end_key="EndLine" in orig_input,
        )
        return _build("view_file" if raw_tool == "view_file" else "read_file", {"Path": resolved_path, "StartLine": start_line, "EndLine": end_line})

    if raw_tool in ("Edit", "MultiEdit", "Write", "NotebookEdit", "StrReplace", "MultiStrReplace", "EditFile", "WriteFile", "DeleteFile", "edit_file", "write_file", "replace_file_content", "multi_replace_file_content", "write_to_file"):
        raw_path = str(
            orig_input.get("file_path") or orig_input.get("notebook_path") or orig_input.get("path")
            or orig_input.get("relative_workspace_path") or orig_input.get("Path")
            or orig_input.get("TargetFile") or orig_input.get("AbsolutePath") or ""
        )
        resolved_path = _resolve_with_cwd(raw_path, cwd)
        canonical_tool = "edit_file" if ("edit" in raw_tool.lower() or "replace" in raw_tool.lower()) else "write_file"
        return _build(canonical_tool, {"Path": resolved_path}, (resolved_path,) if resolved_path else ())

    if raw_tool == "apply_patch":
        patch_paths = tuple(extract_apply_patch_paths(orig_input, cwd=cwd))
        return _build("edit_file", {"Path": patch_paths[0] if patch_paths else ""}, patch_paths)

    if raw_tool in ("Bash", "shell", "Shell", "exec", "exec_command", "run_command", "run_terminal_cmd"):
        cmd_val = orig_input.get("command") or orig_input.get("cmd") or orig_input.get("CommandLine") or ""
        return _build("run_command", {"CommandLine": str(cmd_val)})

    return _build(raw_tool, dict(orig_input))


def can_rewrite_shell_command(norm: NormalizedToolCall) -> bool:
    """Return True only when rewriting shell flags will not bypass an interactive prompt."""
    return norm.harness == "antigravity" or (
        norm.harness in ("claude", "cursor")
        and isinstance(norm.permission_mode, str)
        and norm.permission_mode in AUTO_APPROVED_PERMISSION_MODES
    )


def format_pre_tool_output(decision: dict[str, Any], norm: NormalizedToolCall) -> dict[str, Any]:
    """Translate internal Antigravity decision dict into target harness stdout JSON."""
    if norm.harness == "antigravity":
        return decision

    verdict = decision.get("decision", "allow")
    if verdict == "deny":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": str(decision.get("reason") or "Blocked by Context-Guard."),
            }
        }

    overwrite = decision.get("overwrite")
    if verdict == "allow" and isinstance(overwrite, dict) and overwrite:
        updated = dict(norm.original_tool_input)
        if norm.canonical_tool in ("read_file", "view_file") and norm.original_tool_name == "NotebookRead":
            if "Path" in overwrite:
                updated["notebook_path"] = overwrite["Path"]
        elif norm.canonical_tool in ("read_file", "view_file"):
            if "Path" in overwrite:
                path_key = "path" if ("path" in updated and "file_path" not in updated) else "file_path"
                updated[path_key] = overwrite["Path"]
            if "StartLine" in overwrite or "EndLine" in overwrite:
                new_start = int(overwrite.get("StartLine", norm.canonical_args.get("StartLine", 1)))
                new_end = int(overwrite.get("EndLine", norm.canonical_args.get("EndLine", -1)))
                if "StartLine" in norm.original_tool_input or "EndLine" in norm.original_tool_input:
                    if "StartLine" in overwrite:
                        updated["StartLine"] = new_start
                    if "EndLine" in overwrite:
                        updated["EndLine"] = new_end
                else:
                    updated["offset"] = new_start
                    if new_end != -1 and new_end >= new_start:
                        updated["limit"] = new_end - new_start + 1
        elif norm.canonical_tool == "run_command" and "CommandLine" in overwrite:
            cmd_key = next(
                (k for k in ("command", "cmd", "CommandLine") if updated.get(k)),
                next((k for k in ("command", "cmd", "CommandLine") if k in updated), "command"),
            )
            updated[cmd_key] = overwrite["CommandLine"]
        else:
            updated.update(overwrite)

        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": updated}}

    # Unmodified allow MUST return empty dict {} so native Bash permission prompts are preserved
    return {}
