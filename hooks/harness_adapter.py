"""Multi-Harness PreToolUse adapter for Antigravity, Claude Code, Cursor, and OpenAI Codex."""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from hooks.file_io import count_file_lines_streaming
from policies.api import HARNESS_OUTPUT_CAPABILITIES, RuntimeCapabilities

__all__ = [
    "AUTO_APPROVED_PERMISSION_MODES", "HarnessName", "NormalizedToolCall", "can_rewrite_shell_command",
    "count_file_lines_streaming", "detect_harness", "extract_apply_patch_paths",
    "format_pre_tool_output", "normalize_line_bounds", "normalize_pre_tool_payload",
    "probe_runtime_capabilities",
]

HarnessName = Literal["antigravity", "claude", "cursor", "codex"]
AUTO_APPROVED_PERMISSION_MODES: frozenset[str] = frozenset({"bypassPermissions", "dontAsk", "auto"})
_APPLY_PATCH_HEADER_RE = re.compile(
    r"^\*\*\*\s+(?:(?:Update|Add|Delete)\s+File|Move\s+to):\s+(.+?)\s*$", re.MULTILINE,
)
_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")

def _parse_semver(version: str | None) -> tuple[int, int, int] | None:
    m = _SEMVER_RE.search(version) if isinstance(version, str) else None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None

def _extract_call_id(*candidates: Any) -> tuple[str, bool]:
    for raw in candidates:
        if isinstance(raw, str) and raw.strip():
            return raw.strip(), False
    return "", True

def probe_runtime_capabilities(harness: HarnessName | str, version: str | None = None) -> RuntimeCapabilities:
    """Return runtime capability flags for `harness`, enforcing known CLI version thresholds."""
    static = HARNESS_OUTPUT_CAPABILITIES.get(str(harness))
    native_fc = bool(static.has_native_fail_closed_hook) if static is not None else False
    if str(harness) == "claude" and (parsed := _parse_semver(version)) is not None:
        native_fc = parsed >= (2, 1, 295)
    cv_reads = bool(static.supports_content_verified_reads) if static is not None else False
    return RuntimeCapabilities(
        harness=str(harness), harness_version=version,
        native_fail_closed_supported=native_fc, content_verified_reads_supported=cv_reads,
    )


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
    call_id: str = ""
    has_synthetic_call_id: bool = False
    workspace_roots: tuple[str, ...] = ()


_AG_MUTATION_TOOLS = frozenset((
    "edit_file", "write_file", "replace_file_content", "multi_replace_file_content", "write_to_file",
))
_STD_EDIT_WRITE_TOOLS = frozenset((
    "Edit", "MultiEdit", "Write", "NotebookEdit", "StrReplace", "MultiStrReplace",
    "EditFile", "WriteFile", "DeleteFile", "edit_file", "write_file",
    "replace_file_content", "multi_replace_file_content", "write_to_file",
))

_READ_PATH_KEYS = ("file_path", "notebook_path", "path", "Path", "AbsolutePath")
_EDIT_PATH_KEYS = (*_READ_PATH_KEYS[:3], "relative_workspace_path", "Path", "TargetFile", "AbsolutePath")


def _clean_str(raw: Any) -> str | None:
    return raw.strip() if isinstance(raw, str) and raw.strip() else None

def _first_str(src: dict[str, Any], *keys: str) -> str:
    return next((str(v) for k in keys if (v := src.get(k))), "")

def detect_harness(
    payload: dict[str, Any], cli_harness: str | None = None, env: dict[str, str] | None = None,
) -> HarnessName:
    """Identify the calling agentic harness from CLI flag, payload structure, or environment."""
    harnesses: tuple[HarnessName, ...] = ("antigravity", "claude", "cursor", "codex")
    for h in harnesses:
        if cli_harness == h:
            return h
    if (
        any(k in payload for k in ("toolCall", "stepIdx", "artifactDirectoryPath"))
        or "tool_name" not in payload
    ):
        return "antigravity"
    tr = str(payload.get("transcript_path") or payload.get("transcriptPath") or "")
    for needle, h in (("codex", "codex"), ("cursor", "cursor"), ("claude", "claude")):
        if f"/.{needle}/" in tr or f"\\.{needle}\\" in tr:
            return h
    if "cursor_version" in payload or "workspace_roots" in payload:
        return "cursor"
    env_map = env if env is not None else os.environ
    for prefix, h in (("CODEX_", "codex"), ("CLAUDE_", "claude"), ("CURSOR_", "cursor")):
        if any(key.startswith(prefix) for key in env_map):
            return h
    return "claude"

def _resolve_with_cwd(raw_path: str, cwd: str | None) -> str:
    if not (cl := raw_path.strip()):
        return ""
    if os.path.isabs(cl) or cl.startswith("/") or not cwd:
        return cl
    return str(Path(cwd) / cl)

def extract_apply_patch_paths(tool_input: dict[str, Any] | str, cwd: str | None = None) -> list[str]:
    """Extract target file paths from Codex `apply_patch` input."""
    if isinstance(tool_input, str):
        patch_text = tool_input
    elif isinstance(tool_input, dict):
        patch_text = _first_str(tool_input, "patch", "input", "diff", "raw")
    else:
        return []
    paths: list[str] = []
    seen: set[str] = set()
    for match in _APPLY_PATCH_HEADER_RE.finditer(patch_text):
        if (raw_p := match.group(1).strip()) and (res := _resolve_with_cwd(raw_p, cwd)) not in seen:
            seen.add(res)
            paths.append(res)
    return paths

def _safe_finite_int(raw: Any, default: int = 0) -> int:
    """Coerce ints and finite floats to int without raising on bool, NaN, or Infinity."""
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    return int(raw) if isinstance(raw, float) and math.isfinite(raw) else default

def normalize_line_bounds(
    start_raw: Any, end_raw: Any, *, offset_raw: Any = None, limit_raw: Any = None,
    has_start_key: bool = True, has_end_key: bool = True,
) -> tuple[int, int, bool]:
    """Normalize StartLine/EndLine or offset/limit into `(start_line, end_line, is_inverted_end)`."""
    s_raw = start_raw if (has_start_key and offset_raw is None) else offset_raw
    start_line = s_val if (s_val := _safe_finite_int(s_raw, default=0)) >= 1 else 1
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
    payload: dict[str, Any], cli_harness: str | None = None, env: dict[str, str] | None = None,
) -> NormalizedToolCall:
    """Normalize an incoming PreToolUse JSON payload into a canonical representation."""
    harness = detect_harness(payload, cli_harness=cli_harness, env=env)
    raw_wr = payload.get("workspace_roots")
    ws_roots = tuple(r.strip() for r in raw_wr if isinstance(r, str) and r.strip()) if isinstance(raw_wr, (list, tuple)) else ()
    if harness == "antigravity":
        tc = raw if isinstance((raw := payload.get("toolCall")), dict) else {}
        raw_tool = str(tc.get("name") or "")
        orig_args = dict(raw_a) if isinstance((raw_a := tc.get("args")), dict) else {}
        cwd, art_dir = _clean_str(payload.get("cwd")), _clean_str(payload.get("artifactDirectoryPath"))
        ag_args = dict(orig_args)
        for pf in ("Path", "TargetFile", "AbsolutePath"):
            if (cl := _clean_str(ag_args.get(pf))):
                ag_args[pf] = _resolve_with_cwd(cl, cwd)
        mutated: tuple[str, ...] = ()
        ag_canon = raw_tool
        if raw_tool in _AG_MUTATION_TOOLS:
            p = _clean_str(ag_args.get("Path") or ag_args.get("TargetFile") or ag_args.get("AbsolutePath"))
            mutated = (p,) if p else ()
            is_ed = raw_tool in ("edit_file", "replace_file_content", "multi_replace_file_content")
            ag_canon = "edit_file" if is_ed else "write_file"
        cid, synth = _extract_call_id(tc.get("id"), tc.get("callId"), payload.get("call_id"))
        return NormalizedToolCall(
            harness="antigravity", canonical_tool=ag_canon, canonical_args=ag_args,
            original_tool_name=raw_tool, original_tool_input=orig_args,
            session_id=str(payload.get("conversationId") or "default"),
            step_idx=_safe_finite_int(payload.get("stepIdx"), default=0), cwd=cwd, artifact_dir=art_dir,
            mutated_paths=mutated, call_id=cid, has_synthetic_call_id=synth, workspace_roots=ws_roots,
        )
    raw_tool, raw_in = str(payload.get("tool_name") or ""), payload.get("tool_input")
    orig_in: dict[str, Any] = dict(raw_in) if isinstance(raw_in, dict) else (
        {"patch": raw_in} if isinstance(raw_in, str) else {}
    )
    sess_id = _first_str(payload, "session_id", "conversation_id", "conversationId") or "default"
    cwd, step_idx = _clean_str(payload.get("cwd")), _safe_finite_int(payload.get("stepIdx"), default=0)
    raw_pm = payload.get("permission_mode")
    perm_mode = _clean_str(raw_pm if raw_pm not in (None, "") else payload.get("permissionMode"))
    cid, is_synth = _extract_call_id(
        payload.get("tool_use_id"), payload.get("call_id"),
        payload.get("tool_call_id"), payload.get("callId"),
    )

    def _build(
        c_tool: str, c_args: dict[str, Any], mut: tuple[str, ...] = (),
    ) -> NormalizedToolCall:
        return NormalizedToolCall(
            harness=harness, canonical_tool=c_tool, canonical_args=c_args, original_tool_name=raw_tool,
            original_tool_input=orig_in, session_id=sess_id, step_idx=step_idx, cwd=cwd,
            artifact_dir=None, mutated_paths=mut, permission_mode=perm_mode,
            call_id=cid, has_synthetic_call_id=is_synth, workspace_roots=ws_roots,
        )

    if raw_tool in ("Read", "NotebookRead", "read_file", "view_file"):
        res_p = _resolve_with_cwd(_first_str(orig_in, *_READ_PATH_KEYS), cwd)
        if raw_tool == "NotebookRead" and (cid_nb := _clean_str(orig_in.get("cell_id"))):
            return _build("NotebookRead", {"Path": res_p, "cell_id": cid_nb})
        s_line, e_line, _ = normalize_line_bounds(
            orig_in.get("StartLine"), orig_in.get("EndLine"),
            offset_raw=orig_in.get("offset"), limit_raw=orig_in.get("limit"),
            has_start_key="StartLine" in orig_in, has_end_key="EndLine" in orig_in,
        )
        c_tool = "view_file" if raw_tool == "view_file" else "read_file"
        return _build(c_tool, {"Path": res_p, "StartLine": s_line, "EndLine": e_line})
    if raw_tool in _STD_EDIT_WRITE_TOOLS:
        res_p = _resolve_with_cwd(_first_str(orig_in, *_EDIT_PATH_KEYS), cwd)
        is_ed = "edit" in raw_tool.lower() or "replace" in raw_tool.lower()
        return _build("edit_file" if is_ed else "write_file", {"Path": res_p}, (res_p,) if res_p else ())
    if raw_tool == "apply_patch":
        patch_paths = tuple(extract_apply_patch_paths(orig_in, cwd=cwd))
        return _build("edit_file", {"Path": patch_paths[0] if patch_paths else ""}, patch_paths)
    if raw_tool in ("Bash", "shell", "Shell", "exec", "exec_command", "run_command", "run_terminal_cmd"):
        return _build("run_command", {"CommandLine": _first_str(orig_in, "command", "cmd", "CommandLine")})
    return _build(raw_tool, dict(orig_in))

def can_rewrite_shell_command(norm: NormalizedToolCall) -> bool:
    """Return True only when rewriting shell flags will not bypass an interactive prompt."""
    return norm.harness == "antigravity" or (
        norm.harness in ("claude", "cursor") and str(norm.permission_mode) in AUTO_APPROVED_PERMISSION_MODES
    )

def _pre_out(perm: str, **extra: Any) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": perm, **extra}}

def format_pre_tool_output(decision: dict[str, Any], norm: NormalizedToolCall) -> dict[str, Any]:
    """Translate internal Antigravity decision dict into target harness stdout JSON."""
    if norm.harness == "antigravity":
        return decision
    verdict = decision.get("decision", "allow")
    if verdict == "deny":
        reason = str(decision.get("reason") or "Blocked by Context-Guard.")
        return _pre_out("deny", permissionDecisionReason=reason)
    if verdict != "allow" or not isinstance((ow := decision.get("overwrite")), dict) or not ow:
        return {}
    updated = dict(norm.original_tool_input)
    if norm.canonical_tool in ("read_file", "view_file"):
        if "Path" in ow:
            p_key = "notebook_path" if norm.original_tool_name == "NotebookRead" else next(
                (k for k in ("file_path", "path", "Path") if k in updated), "file_path",
            )
            updated[p_key] = ow["Path"]
        if norm.original_tool_name != "NotebookRead" and ("StartLine" in ow or "EndLine" in ow):
            ns = int(ow.get("StartLine", norm.canonical_args.get("StartLine", 1)))
            ne = int(ow.get("EndLine", norm.canonical_args.get("EndLine", -1)))
            if "StartLine" in norm.original_tool_input or "EndLine" in norm.original_tool_input:
                for k, v in (("StartLine", ns), ("EndLine", ne)):
                    if k in ow:
                        updated[k] = v
            else:
                updated["offset"] = ns
                if ne != -1 and ne >= ns:
                    updated["limit"] = ne - ns + 1
    elif norm.canonical_tool == "run_command" and "CommandLine" in ow:
        keys = ("command", "cmd", "CommandLine")
        ck = next((k for k in keys if updated.get(k)), next((k for k in keys if k in updated), "command"))
        updated[ck] = ow["CommandLine"]
    else:
        updated.update(ow)
    return _pre_out("allow", updatedInput=updated)
