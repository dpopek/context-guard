"""Cycle-free harness registration status detector and matcher constants."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from spool.mcp_server import is_cursor_spool_mcp_configured

DEFAULT_CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"
DEFAULT_CURSOR_HOOKS = Path.home() / ".cursor" / "hooks.json"
DEFAULT_CODEX_HOOKS = Path.home() / ".codex" / "hooks.json"

CLAUDE_MATCHER = "Read|NotebookRead|Edit|MultiEdit|Write|NotebookEdit|Bash"
CLAUDE_POST_SYNC_MATCHER = "Read|NotebookRead|Edit|MultiEdit|Write|NotebookEdit"
CLAUDE_POST_ASYNC_MATCHER = "Bash"
CLAUDE_POST_SPOOL_MATCHER = "Bash|mcp__.*"
CLAUDE_POST_MATCHER = CLAUDE_POST_ASYNC_MATCHER
CURSOR_MATCHER = (
    "Shell|Read|Edit|Write|StrReplace|MultiStrReplace|EditFile|WriteFile|DeleteFile|"
    "read_file|edit_file|write_file|run_terminal_cmd"
)
CURSOR_POST_MATCHER = (
    "Shell|run_terminal_cmd|Read|read_file|Edit|Write|StrReplace|MultiStrReplace|"
    "EditFile|WriteFile|Delete|DeleteFile|edit_file|write_file"
)
CURSOR_POST_SPOOL_MATCHER = f"{CURSOR_POST_MATCHER}|MCP:.*|mcp__.*"
CODEX_MATCHER = "^(Bash|shell|exec_command|exec|apply_patch|Edit|Write|mcp__.*)$"
CODEX_POST_MATCHER = "^(Bash|shell|exec_command|exec|apply_patch|Edit|Write)$"
CG_HOOK_SCRIPTS = (
    "/hooks/pre_tool_use.py",
    "/hooks/pre_compact.py",
    "/hooks/post_tool_use.py",
    "/hooks/session_end.py",
    "\\hooks\\pre_tool_use.py",
    "\\hooks\\pre_compact.py",
    "\\hooks\\post_tool_use.py",
    "\\hooks\\session_end.py",
)


def claude_post_hook_groups(
    post_cmd: str,
    *,
    output_spool_mode: str = "off",
    event_name: str = "PostToolUse",
) -> list[dict[str, Any]]:
    """Return Claude PostToolUse/PostToolUseFailure sync file + Bash/MCP hook groups."""
    if output_spool_mode in ("active", "shadow") and event_name == "PostToolUse":
        tail = {"matcher": CLAUDE_POST_SPOOL_MATCHER, "hooks": [{"type": "command", "command": post_cmd, "timeout": 10}]}
    else:
        tail = {"matcher": CLAUDE_POST_ASYNC_MATCHER, "hooks": [{"type": "command", "command": post_cmd, "async": True}]}
    return [{"matcher": CLAUDE_POST_SYNC_MATCHER, "hooks": [{"type": "command", "command": post_cmd}]}, tail]


def cursor_post_matcher(output_spool_mode: str = "off") -> str:
    """Return Cursor postToolUse matcher for the configured `output_spool` mode."""
    return CURSOR_POST_SPOOL_MATCHER if output_spool_mode in ("active", "shadow") else CURSOR_POST_MATCHER


def is_cg_command(
    cmd: Any,
    managed_cmds: frozenset[str] = frozenset(),
    managed_frags: tuple[tuple[str, ...], ...] = (),
) -> bool:
    """True for a Context-Guard hook command or verified pack-managed installer hook."""
    if not isinstance(cmd, str):
        return False
    if cmd in managed_cmds:
        return True
    if any(script in cmd for script in CG_HOOK_SCRIPTS):
        return "--harness" in cmd or "context-guard" in cmd
    norm_cmd = cmd.replace("\\", "/")
    for frags in managed_frags:
        pos = 0
        matched = True
        for frag in frags:
            idx = norm_cmd.find(frag, pos)
            if idx < 0:
                matched = False
                break
            pos = idx + len(frag)
        if matched:
            return True
    return False


def without_cg_handlers(
    groups: list[Any],
    managed_cmds: frozenset[str] = frozenset(),
    managed_frags: tuple[tuple[str, ...], ...] = (),
) -> list[Any]:
    """Drop Context-Guard handlers from hook groups, keeping every other tool's handlers and groups."""
    kept: list[Any] = []
    for group in groups:
        if not isinstance(group, dict):
            kept.append(group)
            continue
        if is_cg_command(group.get("command"), managed_cmds, managed_frags):
            continue
        handlers = group.get("hooks")
        if isinstance(handlers, list):
            rest = [
                h for h in handlers
                if not (isinstance(h, dict) and is_cg_command(h.get("command"), managed_cmds, managed_frags))
            ]
            if len(rest) != len(handlers):
                if not rest:
                    continue
                group = {**group, "hooks": rest}
        kept.append(group)
    return kept


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


def _is_post_tool_use_command(cmd: Any) -> bool:
    return isinstance(cmd, str) and (("/hooks/post_tool_use.py" in cmd) or ("\\hooks\\post_tool_use.py" in cmd))


def _spool_hook_ok(harness: str, hooks_obj: dict[str, Any], mode: str) -> bool:
    if harness not in ("claude", "cursor"):
        return True
    spool_on = mode in ("active", "shadow")
    raw = hooks_obj.get("PostToolUse" if harness == "claude" else "postToolUse")
    if not isinstance(raw, list):
        return False
    if harness == "claude":
        exp, bad = (CLAUDE_POST_SPOOL_MATCHER, None) if spool_on else (CLAUDE_POST_ASYNC_MATCHER, CLAUDE_POST_SPOOL_MATCHER)
        cg: list[tuple[Any, dict[str, Any]]] = [
            (g.get("matcher"), h) for g in raw if isinstance(g, dict) if isinstance((hs := g.get("hooks")), list)
            for h in hs if isinstance(h, dict) and _is_post_tool_use_command(h.get("command"))
        ]
        return any(m == exp and (not spool_on or not h.get("async")) for m, h in cg) and not any(m == bad for m, _ in cg)
    exp, bad = cursor_post_matcher(mode), (None if spool_on else CURSOR_POST_SPOOL_MATCHER)
    cg_cu = [g.get("matcher") for g in raw if isinstance(g, dict) and _is_post_tool_use_command(g.get("command"))]
    return exp in cg_cu and bad not in cg_cu


def _inspect_harness_config(path: Path, *, harness: str = "", output_spool_mode: str = "off") -> dict[str, Any]:
    base: dict[str, Any] = {
        "config_path": str(path), "registered": False, "targets": [],
        "target": None, "target_exists": False, "ok": False, "spool_hook_ok": False,
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
        "config_path": str(path), "registered": True, "targets": targets,
        "target": targets[0] if targets else None, "target_exists": target_exists,
        "ok": target_exists, "spool_hook_ok": _spool_hook_ok(harness, data["hooks"], output_spool_mode),
    }


def _resolve_harness_paths(
    claude_settings_path: Path | None, cursor_hooks_path: Path | None, codex_hooks_path: Path | None
) -> tuple[tuple[str, Path], ...]:
    return (
        ("claude", claude_settings_path if claude_settings_path is not None else DEFAULT_CLAUDE_SETTINGS),
        ("cursor", cursor_hooks_path if cursor_hooks_path is not None else DEFAULT_CURSOR_HOOKS),
        ("codex", codex_hooks_path if codex_hooks_path is not None else DEFAULT_CODEX_HOOKS),
    )


def _inspect_cursor_mcp(mcp_path: Path) -> tuple[bool, bool]:
    if is_cursor_spool_mcp_configured(mcp_path):
        return True, False
    try:
        raw = json.loads(mcp_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, False
    srvs = raw.get("mcpServers") if isinstance(raw, Mapping) else None
    return False, isinstance(srvs, Mapping) and "context-guard-spool" in srvs


def verify_harness_hooks(
    claude_settings_path: Path | None = None, cursor_hooks_path: Path | None = None,
    codex_hooks_path: Path | None = None, *, output_spool_mode: str = "off",
    cursor_mcp_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Verify registered hook configs, Cursor MCP `--workspace` flag, and `pre_tool_use.py` targets."""
    paths = _resolve_harness_paths(claude_settings_path, cursor_hooks_path, codex_hooks_path)
    out = {name: _inspect_harness_config(p, harness=name, output_spool_mode=output_spool_mode) for name, p in paths}
    cu_hooks = paths[1][1]
    eff_mcp = cursor_mcp_path if cursor_mcp_path is not None else (
        (Path.home() / ".cursor" / "mcp.json") if cu_hooks == DEFAULT_CURSOR_HOOKS else (cu_hooks.parent / "mcp.json")
    )
    mcp_ok, mcp_stale = _inspect_cursor_mcp(eff_mcp)
    out["cursor"]["cursor_mcp_ok"] = mcp_ok
    out["cursor"]["cursor_mcp_stale"] = mcp_stale
    return out


def format_doctor_harness_row(name: str, installed: bool, detail_obj: Any) -> str:
    """Format one `--doctor` Markdown table row for Claude, Cursor, or Codex."""
    d = detail_obj if isinstance(detail_obj, Mapping) else {}
    if installed and d.get("target_exists") is False:
        status_lbl, detail_str = "WARN", f"registered, missing target ({d.get('target') or 'pre_tool_use.py'})"
    elif installed and d.get("spool_hook_ok") is False:
        status_lbl, detail_str = "WARN", "registered, spool post-hook mismatch (re-run install_harnesses.py)"
    elif name == "cursor" and d.get("cursor_mcp_stale") is True:
        status_lbl, detail_str = "WARN", "Cursor spool MCP missing --workspace (re-run install_harnesses.py)"
    else:
        status_lbl, detail_str = ("OK" if installed else "WARN"), ("registered" if installed else "not registered")
    return f"| Harness: `{name}` | `{status_lbl}` | `{detail_str}` |"


def check_status(
    claude_settings_path: Path | None = None, cursor_hooks_path: Path | None = None, codex_hooks_path: Path | None = None
) -> dict[str, bool]:
    """Return whether Context-Guard is installed in each harness config."""
    paths = _resolve_harness_paths(claude_settings_path, cursor_hooks_path, codex_hooks_path)
    return {name: bool(_inspect_harness_config(p, harness=name)["registered"]) for name, p in paths}


def native_fail_closed_hook_extras(
    runtime_cfg: Mapping[str, Any], *, claude_version: tuple[int, int, int] | None = None, probe_claude_fn: Any = None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Return `(claude_pre_extra, cursor_pre_extra)` when security policy enforcement is active."""
    packs = runtime_cfg.get("policy_packs")
    sec_active = bool(
        runtime_cfg.get("config_error")
        or runtime_cfg.get("legacy_security_keys")
        or (
            isinstance(packs, list)
            and any(
                isinstance(e, Mapping) and e.get("enabled", True) and str(e.get("kind") or "security") == "security"
                for e in packs
            )
        )
    )
    if not sec_active:
        return None, None
    cursor_extra: dict[str, Any] = {"failClosed": True, "timeout": 10}
    eff_ver = probe_claude_fn() if (claude_version is None and probe_claude_fn is not None) else claude_version
    claude_extra = {"onFailure": "block", "timeout": 15} if (eff_ver is not None and eff_ver >= (2, 1, 295)) else None
    return claude_extra, cursor_extra
