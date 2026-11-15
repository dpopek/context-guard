"""Cycle-free harness registration status detector and matcher constants."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

DEFAULT_CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"
DEFAULT_CURSOR_HOOKS = Path.home() / ".cursor" / "hooks.json"
DEFAULT_CODEX_HOOKS = Path.home() / ".codex" / "hooks.json"

CLAUDE_MATCHER = "Read|NotebookRead|Edit|MultiEdit|Write|NotebookEdit|Bash"
CURSOR_MATCHER = (
    "Shell|Read|Edit|Write|StrReplace|MultiStrReplace|EditFile|WriteFile|DeleteFile|"
    "read_file|edit_file|write_file|run_terminal_cmd"
)
CODEX_MATCHER = "^(Bash|shell|exec_command|exec|apply_patch|Edit|Write|mcp__.*)$"


def merge_harness_matcher(
    base_matcher: str, extras: Sequence[str], *, regex_anchored: bool = False
) -> str:
    """Merge non-empty pipe-delimited policy pack matcher patterns onto a base harness matcher."""

    def _split_parts(pattern: str) -> list[str]:
        inner = pattern.strip()
        if regex_anchored and inner.startswith("^(") and inner.endswith(")$"):
            inner = inner[2:-2]
        return [part.strip() for part in inner.split("|") if part.strip()]

    seen: set[str] = set()
    merged: list[str] = []
    for raw in (base_matcher, *extras):
        if not isinstance(raw, str) or not raw.strip():
            continue
        for part in _split_parts(raw):
            if part not in seen:
                seen.add(part)
                merged.append(part)
    joined = "|".join(merged)
    return f"^({joined})$" if regex_anchored and joined else joined


_PRE_TOOL_USE_TARGET_RE = re.compile(
    r'"((?:\\"|[^"\r\n])*?(?:/|\\)hooks(?:/|\\)pre_tool_use\.py)"'
    r"|'([^'\r\n]*?(?:/|\\)hooks(?:/|\\)pre_tool_use\.py)'"
    r"|(\S*?(?:/|\\)hooks(?:/|\\)pre_tool_use\.py)"
)


def _extract_hook_commands(hooks_obj: dict[str, Any]) -> list[str]:
    cmds: list[str] = []
    for groups in hooks_obj.values():
        if not isinstance(groups, list):
            continue
        for grp in groups:
            if isinstance(grp, str):
                cmds.append(grp)
                continue
            if not isinstance(grp, dict):
                continue
            if isinstance(grp.get("command"), str):
                cmds.append(grp["command"])
            nested = grp.get("hooks")
            if isinstance(nested, list):
                for item in nested:
                    if isinstance(item, dict) and isinstance(item.get("command"), str):
                        cmds.append(item["command"])
    return cmds


def _is_pre_tool_use_command(cmd: str) -> bool:
    return ("/hooks/pre_tool_use.py" in cmd) or ("\\hooks\\pre_tool_use.py" in cmd)


def _extract_pre_tool_use_target(cmd: str) -> str | None:
    match = _PRE_TOOL_USE_TARGET_RE.search(cmd)
    if not match:
        return None
    if match.group(1) is not None:
        return match.group(1).replace('\\"', '"')
    return match.group(2) if match.group(2) is not None else match.group(3)


def _inspect_harness_config(path: Path) -> dict[str, Any]:
    base: dict[str, Any] = {
        "config_path": str(path),
        "registered": False,
        "targets": [],
        "target": None,
        "target_exists": False,
        "ok": False,
    }
    if not path.exists():
        return base
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return base
    if not isinstance(data, dict) or not isinstance(data.get("hooks"), dict):
        return base
    cmds = [cmd for cmd in _extract_hook_commands(data["hooks"]) if _is_pre_tool_use_command(cmd)]
    if not cmds:
        return base
    cg_cmds = [cmd for cmd in cmds if "--harness" in cmd or "context-guard" in cmd]
    targets: list[str] = []
    for cmd in cg_cmds or cmds:
        target = _extract_pre_tool_use_target(cmd)
        if target and target not in targets:
            targets.append(target)
    target_exists = bool(targets) and all(Path(t).expanduser().is_file() for t in targets)
    return {
        "config_path": str(path),
        "registered": True,
        "targets": targets,
        "target": targets[0] if targets else None,
        "target_exists": target_exists,
        "ok": target_exists,
    }


def _resolve_harness_paths(
    claude_settings_path: Path | None,
    cursor_hooks_path: Path | None,
    codex_hooks_path: Path | None,
) -> tuple[tuple[str, Path], ...]:
    return (
        ("claude", claude_settings_path if claude_settings_path is not None else DEFAULT_CLAUDE_SETTINGS),
        ("cursor", cursor_hooks_path if cursor_hooks_path is not None else DEFAULT_CURSOR_HOOKS),
        ("codex", codex_hooks_path if codex_hooks_path is not None else DEFAULT_CODEX_HOOKS),
    )


def verify_harness_hooks(
    claude_settings_path: Path | None = None,
    cursor_hooks_path: Path | None = None,
    codex_hooks_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Verify registered hook configs and check on-disk existence of extracted `pre_tool_use.py` targets."""
    return {
        name: _inspect_harness_config(path)
        for name, path in _resolve_harness_paths(claude_settings_path, cursor_hooks_path, codex_hooks_path)
    }


def check_status(
    claude_settings_path: Path | None = None,
    cursor_hooks_path: Path | None = None,
    codex_hooks_path: Path | None = None,
) -> dict[str, bool]:
    """Return whether Context-Guard is installed in each harness config."""
    return {
        name: bool(_inspect_harness_config(path)["registered"])
        for name, path in _resolve_harness_paths(claude_settings_path, cursor_hooks_path, codex_hooks_path)
    }
