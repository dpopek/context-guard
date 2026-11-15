#!/usr/bin/env python3
"""PostToolUse hook for Claude Code, Codex and Cursor: measures shell output size, never changes it."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_PLUGIN_ROOT = str(Path(__file__).resolve().parent.parent)
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from hooks.config import load_runtime_config
from hooks.harness_adapter import normalize_pre_tool_payload
from hooks.policy_engine import run_post_tool_hooks
from hooks.shell_output import classify_family, measure
from hooks.state_store import emit_json_and_sanitize_stdio, resolve_state_dir, run_telemetry_safely
from hooks.telemetry import record_shell_output, warn
from policies.api import PolicyPostContext

# Tool names each harness uses for a shell command (Codex names mirror the installer's PreToolUse matcher).
_SHELL_TOOLS = {
    "claude": frozenset(("Bash",)),
    "codex": frozenset(("Bash", "shell", "exec_command", "exec")),
    "cursor": frozenset(("Shell", "run_terminal_cmd")),
}
_EXIT_LINE_RE = re.compile(r"^Exit code -?\d+$")


@dataclass(frozen=True)
class ShellCall:
    """One shell call as the hook sees it; `output` None means it was not found in the payload."""

    command: str
    output: str | None
    outcome: str


def _command_of(payload: dict[str, Any]) -> str:
    tool_input = payload.get("tool_input")
    command = None
    if isinstance(tool_input, dict):
        # Same keys as hooks/harness_adapter.py: Claude and Cursor use `command`, Codex `cmd`, others `CommandLine`.
        command = tool_input.get("command") or tool_input.get("cmd") or tool_input.get("CommandLine")
    if isinstance(command, str):
        return command
    if isinstance(command, list):
        return shlex.join(str(part) for part in command)
    return ""


def _output_of(data: dict[str, Any]) -> str | None:
    """`output`, else stdout + stderr; None when the dict carries neither."""
    if isinstance(data.get("output"), str):
        return data["output"]
    streams = [data.get(key) for key in ("stdout", "stderr")]
    if not any(isinstance(s, str) for s in streams):
        return None
    return "".join(s for s in streams if isinstance(s, str))


def _exit_outcome(code: Any) -> str:
    if isinstance(code, bool) or not isinstance(code, int):
        return "unknown"
    return "ok" if code == 0 else "fail"


def _claude_call(payload: dict[str, Any]) -> ShellCall:
    command = _command_of(payload)
    if payload.get("hook_event_name") == "PostToolUseFailure":
        error = payload.get("error")
        if not isinstance(error, str):
            return ShellCall(command, None, "unknown")
        first, _, rest = error.partition("\n")
        if _EXIT_LINE_RE.match(first.strip()):
            return ShellCall(command, rest, "fail")
        return ShellCall(command, error, "unknown")
    response = payload.get("tool_response")
    output = _output_of(response) if isinstance(response, dict) else None
    return ShellCall(command, output, "ok" if output is not None else "unknown")


def _codex_call(payload: dict[str, Any]) -> ShellCall:
    command = _command_of(payload)
    response = payload.get("tool_response")
    if isinstance(response, str):
        return ShellCall(command, response, "unknown")
    if isinstance(response, dict):
        output = _output_of(response)
        if output is not None:
            return ShellCall(command, output, _exit_outcome(response.get("exit_code")))
    return ShellCall(command, None, "unknown")


def _cursor_call(payload: dict[str, Any]) -> ShellCall:
    command = _command_of(payload)
    data = payload.get("tool_output")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return ShellCall(command, None, "unknown")
    if isinstance(data, dict):
        output = _output_of(data)
        if output is not None:
            return ShellCall(command, output, _exit_outcome(data.get("exitCode")))
    return ShellCall(command, None, "unknown")


_CALL_BUILDERS = {"claude": _claude_call, "codex": _codex_call, "cursor": _cursor_call}


def normalise_payload(harness: str, payload: dict[str, Any]) -> ShellCall | None:
    """The shell call in a PostToolUse payload; None for non-shell tools or an unknown harness."""
    if payload.get("tool_name") not in _SHELL_TOOLS.get(harness, frozenset()):
        return None
    return _CALL_BUILDERS[harness](payload)


def handle_post_tool_use(
    harness: str, payload: dict[str, Any], stats_path: Path | None = None
) -> dict[str, Any]:
    """Record shell output telemetry and invoke policy pack PostToolUse hooks cleanly."""
    try:
        call = normalise_payload(harness, payload)
        if call is not None:
            measurement = measure(call.output, harness) if call.output is not None else None
            record_shell_output(harness, classify_family(call.command), measurement, call.outcome, stats_path)
        runtime_cfg = load_runtime_config()
        packs = runtime_cfg.get("policy_packs") or ()
        if any(isinstance(p, dict) and p.get("enabled", True) for p in packs):
            norm = normalize_pre_tool_payload(payload, cli_harness=harness)
            state_dir_path = resolve_state_dir(payload, None)
            tool_resp = payload.get("tool_response") or payload.get("toolResponse") or payload.get("result")
            err_val = payload.get("error") or (tool_resp.get("error") if isinstance(tool_resp, dict) else None)
            succeeded = not bool(err_val) and payload.get("is_error") is not True
            post_ctx = PolicyPostContext(
                harness=norm.harness,
                call_id=norm.call_id,
                canonical_tool=norm.canonical_tool,
                canonical_args=norm.canonical_args,
                mutated_paths=norm.mutated_paths,
                original_tool_name=norm.original_tool_name,
                tool_input=norm.original_tool_input,
                succeeded=succeeded,
                error=str(err_val) if err_val else None,
                cwd=norm.cwd,
                state_dir=str(state_dir_path),
            )
            run_post_tool_hooks(post_ctx, runtime_cfg)
    except Exception as exc:  # noqa: BLE001 - measurement must never fail; log class name only (never output text)
        err = exc
        run_telemetry_safely(
            lambda: warn(f"shell output hook failed: {type(err).__name__}"),
            context="post_tool_use_shell_output",
        )
    return {}


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: read the PostToolUse JSON from stdin, record it, always print `{}` and exit 0."""
    try:
        parser = argparse.ArgumentParser(
            description="Context-Guard shell output measurement hook.",
            add_help=False,
        )
        parser.add_argument("--harness", default="claude")
        args, _ = parser.parse_known_args(argv)
        raw_input = sys.stdin.read()
        payload = json.loads(raw_input) if raw_input.strip() else {}
        if isinstance(payload, dict):
            handle_post_tool_use(args.harness, payload)
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - measurement must never fail the tool call
        # Argument errors (SystemExit) skip recording: no harness is known. Only the class name is
        # reported; the message may carry command or output text.
        err = exc
        run_telemetry_safely(
            lambda: warn(f"shell output hook failed: {type(err).__name__}"),
            context="post_tool_use_main",
        )
    return emit_json_and_sanitize_stdio({})


if __name__ == "__main__":
    raise SystemExit(main())
