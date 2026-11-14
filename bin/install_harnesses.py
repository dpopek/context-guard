#!/usr/bin/env python3
"""Idempotent multi-harness installer/uninstaller for Context-Guard."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from bin import update_check  # noqa: E402
from bin.harness_status import (  # noqa: E402
    CLAUDE_MATCHER,
    CODEX_MATCHER,
    CURSOR_MATCHER,
    DEFAULT_CLAUDE_SETTINGS,
    DEFAULT_CODEX_HOOKS,
    DEFAULT_CURSOR_HOOKS,
    check_status as check_harness_status,
)
from bin.instruction_block import DEFAULT_SHIM_BIN_DIR, install_outline_pull, shim_installed, uninstall_outline_pull  # noqa: E402
from hooks.config import cached_raw_config_status  # noqa: E402
from hooks.state_store import resolve_plugin_root, warn  # noqa: E402

DEFAULT_PLUGIN_ROOT = resolve_plugin_root()

DEFAULT_CODEX_CONFIG = Path.home() / ".codex" / "config.toml"
DEFAULT_CURSOR_EXTENSIONS = Path.home() / ".cursor" / "extensions"
DEFAULT_ANTIGRAVITY_EXTENSIONS = Path.home() / ".antigravity" / "extensions"
DEFAULT_ANTIGRAVITY_IDE_EXTENSIONS = Path.home() / ".antigravity-ide" / "extensions"

EXTENSION_ID = "advox.context-guard-statusbar"
# PostToolUse shell-output measurement: shell tools only.
CLAUDE_POST_MATCHER = "Bash"
CODEX_POST_MATCHER = "^(Bash|shell|exec_command|exec)$"
CURSOR_POST_MATCHER = "Shell|run_terminal_cmd"

_CAMEL_TO_SNAKE_RE = re.compile(r"(?<!^)(?=[A-Z])")


def _event_to_snake(event_name: str) -> str:
    return _CAMEL_TO_SNAKE_RE.sub("_", event_name).lower()


def resolve_python_command(
    os_name: str = os.name,
    which_fn: Callable[[str], str | None] = shutil.which,
) -> str:
    """Resolve the portable Python launcher command across POSIX (`python3`/`python`) and Windows (`python`/`py -3`)."""
    if os_name == "nt":
        if which_fn("python"):
            return "python"
        if which_fn("py"):
            return "py -3"
        return "python3"
    if which_fn("python3"):
        return "python3"
    if which_fn("python"):
        return "python"
    return "python3"


def format_hook_script_path(path: Path) -> str:
    """Format a hook script path with forward slashes and double quotes when spaces are present."""
    posix_str = str(path).replace("\\", "/")
    return f'"{posix_str}"' if " " in posix_str else posix_str


def compute_codex_trusted_hash(
    event_name: str,
    matcher: str | None,
    command: str,
    timeout: int = 600,
    is_async: bool = False,
) -> str:
    """Return `sha256:<hex>` matching `codex-rs/config/src/fingerprint.rs` canonical JSON identity."""
    obj: dict[str, Any] = {
        "event_name": event_name,
        "hooks": [
            {
                "async": bool(is_async),
                "command": command,
                "timeout": int(timeout),
                "type": "command",
            }
        ],
    }
    if matcher is not None:
        obj["matcher"] = matcher
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


_CG_HOOK_SCRIPTS = (
    "/hooks/pre_tool_use.py",
    "/hooks/pre_compact.py",
    "/hooks/post_tool_use.py",
    "\\hooks\\pre_tool_use.py",
    "\\hooks\\pre_compact.py",
    "\\hooks\\post_tool_use.py",
)


_WS_STOP_SCRIPTS = (
    "/scripts/hooks/antigravity_stop_guard.py",
    "/scripts/hooks/claude_stop_guard.py",
    "\\scripts\\hooks\\antigravity_stop_guard.py",
    "\\scripts\\hooks\\claude_stop_guard.py",
)


def _is_cg_command(cmd: Any) -> bool:
    """True for a Context-Guard hook command or installer-managed workspace stop/baseline hook."""
    if not isinstance(cmd, str):
        return False
    if any(script in cmd for script in _CG_HOOK_SCRIPTS):
        return "--harness" in cmd or "context-guard" in cmd
    if any(script in cmd for script in _WS_STOP_SCRIPTS):
        return any(flag in cmd for flag in ("--capture-baseline", "--claude-hook", "--cursor-hook"))
    return False


def _without_cg_handlers(groups: list[Any]) -> list[Any]:
    """Drop Context-Guard handlers from hook groups, keeping every other tool's handlers and groups."""
    kept: list[Any] = []
    for group in groups:
        if not isinstance(group, dict):
            kept.append(group)
            continue
        if _is_cg_command(group.get("command")):
            continue
        handlers = group.get("hooks")
        if isinstance(handlers, list):
            rest = [h for h in handlers if not (isinstance(h, dict) and _is_cg_command(h.get("command")))]
            if len(rest) != len(handlers):
                if not rest:
                    continue
                group = {**group, "hooks": rest}
        kept.append(group)
    return kept


def _atomic_write_text(path: Path, content: str, create_backup: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        old_text = path.read_text(encoding="utf-8")
        if old_text == content:
            return
        if create_backup:
            bak_path = path.with_suffix(path.suffix + ".bak")
            if not bak_path.exists():
                shutil.copy2(path, bak_path)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp_path, str(path))
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _update_nested_hooks_json(
    cfg_path: Path,
    pre_cmd: str | None,
    pre_matcher: str | None,
    compact_cmd: str | None,
    dry_run: bool = False,
    statusline_cmd: str | None = None,
    manage_statusline: bool = False,
    post_cmd: str | None = None,
    post_events: tuple[str, ...] = (),
    post_matcher: str | None = None,
    post_handler_extra: dict[str, Any] | None = None,
    session_start_cmd: str | None = None,
    stop_cmd: str | None = None,
    stop_timeout: int | None = None,
) -> tuple[str, dict[str, Any]]:
    if not cfg_path.exists():
        return ("skipped (not found)", {})
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        warn(f"hooks config unreadable ({cfg_path}): {type(exc).__name__}: {exc}")
        return ("error (invalid json)", {})
    if not isinstance(data, dict):
        return ("skipped (invalid root)", {})
    hooks_root = data.setdefault("hooks", {})
    if not isinstance(hooks_root, dict):
        hooks_root = {}
        data["hooks"] = hooks_root

    for evt_key in ("PreToolUse", "PreCompact", "PostToolUse", "PostToolUseFailure", "SessionStart", "Stop"):
        existing = hooks_root.get(evt_key)
        if isinstance(existing, list):
            filtered = _without_cg_handlers(existing)
            if filtered:
                hooks_root[evt_key] = filtered
            else:
                hooks_root.pop(evt_key, None)

    if session_start_cmd is not None:
        hooks_root.setdefault("SessionStart", []).append(
            {"hooks": [{"type": "command", "command": session_start_cmd}]}
        )

    if pre_cmd is not None:
        pre_list = hooks_root.setdefault("PreToolUse", [])
        pre_entry: dict[str, Any] = {
            "matcher": pre_matcher,
            "hooks": [{"type": "command", "command": pre_cmd}],
        }
        pre_list.append(pre_entry)

    if compact_cmd is not None:
        compact_list = hooks_root.setdefault("PreCompact", [])
        compact_entry: dict[str, Any] = {
            "hooks": [{"type": "command", "command": compact_cmd}],
        }
        compact_list.append(compact_entry)

    if post_cmd is not None:
        for evt_key in post_events:
            hooks_root.setdefault(evt_key, []).append(
                {
                    "matcher": post_matcher,
                    "hooks": [{"type": "command", "command": post_cmd, **(post_handler_extra or {})}],
                }
            )

    if stop_cmd is not None:
        stop_entry: dict[str, Any] = {"type": "command", "command": stop_cmd}
        if stop_timeout is not None:
            stop_entry["timeout"] = stop_timeout
        hooks_root.setdefault("Stop", []).append({"hooks": [stop_entry]})

    if manage_statusline:
        if statusline_cmd is not None:
            cur_sl = data.get("statusLine")
            is_already_cg = isinstance(cur_sl, dict) and "cg_status.py" in str(
                cur_sl.get("command", "")
            )
            if cur_sl is not None and not is_already_cg:
                if "_context_guard_backup_statusLine" not in data:
                    data["_context_guard_backup_statusLine"] = cur_sl
            data["statusLine"] = {
                "type": "command",
                "command": statusline_cmd,
                "padding": 1,
            }
        else:
            if "_context_guard_backup_statusLine" in data:
                data["statusLine"] = data.pop("_context_guard_backup_statusLine")
            elif isinstance(data.get("statusLine"), dict) and "cg_status.py" in str(
                data["statusLine"].get("command", "")
            ):
                data.pop("statusLine", None)

    rendered = json.dumps(data, indent=2) + "\n"
    if not dry_run:
        _atomic_write_text(cfg_path, rendered)
    return ("updated", data)


def _update_cursor_hooks_json(
    cfg_path: Path,
    pre_cmd: str | None,
    compact_cmd: str | None,
    dry_run: bool = False,
    post_cmd: str | None = None,
    session_start_cmd: str | None = None,
    stop_cmd: str | None = None,
) -> str:
    if not cfg_path.exists():
        return "skipped (not found)"
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        warn(f"cursor hooks config unreadable ({cfg_path}): {type(exc).__name__}: {exc}")
        return "error (invalid json)"
    if not isinstance(data, dict):
        return "skipped (invalid root)"
    hooks_root = data.setdefault("hooks", {})
    if not isinstance(hooks_root, dict):
        hooks_root = {}
        data["hooks"] = hooks_root

    for evt_key in ("preToolUse", "preCompact", "postToolUse", "sessionStart", "stop"):
        existing = hooks_root.get(evt_key)
        if isinstance(existing, list):
            filtered = _without_cg_handlers(existing)
            if filtered:
                hooks_root[evt_key] = filtered
            else:
                hooks_root.pop(evt_key, None)

    if session_start_cmd is not None:
        hooks_root.setdefault("sessionStart", []).append({"command": session_start_cmd})

    if pre_cmd is not None:
        pre_list = hooks_root.setdefault("preToolUse", [])
        pre_list.append({"command": pre_cmd, "matcher": CURSOR_MATCHER})

    if compact_cmd is not None:
        compact_list = hooks_root.setdefault("preCompact", [])
        compact_list.append({"command": compact_cmd})

    if post_cmd is not None:
        hooks_root.setdefault("postToolUse", []).append(
            {"command": post_cmd, "matcher": CURSOR_POST_MATCHER}
        )

    if stop_cmd is not None:
        hooks_root.setdefault("stop", []).append({"command": stop_cmd})

    rendered = json.dumps(data, indent=2) + "\n"
    if not dry_run:
        _atomic_write_text(cfg_path, rendered)
    return "updated"


def sync_codex_config_toml(
    codex_hooks_path: Path,
    codex_config_path: Path,
    hooks_data: dict[str, Any],
    ensure_compact_limit: bool,
    dry_run: bool = False,
) -> str:
    if not codex_config_path.exists():
        return "skipped (not found)"
    raw_toml = codex_config_path.read_text(encoding="utf-8")

    # Strip existing [hooks.state."<codex_hooks_path>:..."] blocks (both raw and TOML backslash-escaped)
    raw_hooks_str = str(codex_hooks_path)
    toml_hooks_str = raw_hooks_str.replace("\\", "\\\\")
    candidates = {re.escape(raw_hooks_str), re.escape(toml_hooks_str)}
    cleaned = raw_toml
    for pat in candidates:
        block_re = re.compile(
            rf'(?m)^\n?\[hooks\.state\."{pat}:[^"]+"\]\n(?:(?!\[)[^\n]*(?:\n|$))*'
        )
        cleaned = block_re.sub("", cleaned)
    cleaned = cleaned.strip()
    cleaned = (cleaned + "\n") if cleaned else ""

    if ensure_compact_limit and "model_auto_compact_token_limit" not in cleaned:
        first_section_match = re.search(r"^\[", cleaned, flags=re.MULTILINE)
        limit_line = "model_auto_compact_token_limit = 250000\n"
        if first_section_match is not None:
            idx = first_section_match.start()
            prefix = cleaned[:idx]
            if prefix and not prefix.endswith("\n"):
                prefix += "\n"
            cleaned = prefix + limit_line + ("\n" if idx == 0 else "") + cleaned[idx:]
        else:
            cleaned = cleaned + limit_line

    # Generate fresh [hooks.state."<toml_hooks_str>:<snake_evt>:<g_idx>:<h_idx>"] blocks
    hooks_root = hooks_data.get("hooks") if isinstance(hooks_data, dict) else {}
    blocks: list[str] = []
    if isinstance(hooks_root, dict):
        for event_key, groups in hooks_root.items():
            if not isinstance(groups, list):
                continue
            snake_evt = _event_to_snake(str(event_key))
            for g_idx, grp in enumerate(groups):
                if not isinstance(grp, dict):
                    continue
                matcher = grp.get("matcher") if isinstance(grp.get("matcher"), str) else None
                h_list = grp.get("hooks")
                if not isinstance(h_list, list):
                    continue
                for h_idx, h_obj in enumerate(h_list):
                    if not isinstance(h_obj, dict):
                        continue
                    cmd = str(h_obj.get("command") or "")
                    if not cmd:
                        continue
                    timeout = int(h_obj.get("timeout") or 600)
                    is_async = bool(h_obj.get("async") or False)
                    thash = compute_codex_trusted_hash(
                        snake_evt, matcher, cmd, timeout=timeout, is_async=is_async
                    )
                    state_key = f"{toml_hooks_str}:{snake_evt}:{g_idx}:{h_idx}"
                    blocks.append(f'[hooks.state."{state_key}"]\ntrusted_hash = "{thash}"\n')

    final_toml = cleaned.rstrip() + "\n"
    if blocks:
        final_toml += "\n" + "\n".join(blocks)

    if not dry_run:
        _atomic_write_text(codex_config_path, final_toml)
    return "updated"


def install_ide_extension(
    plugin_root: Path,
    extensions_dir: Path,
    dry_run: bool = False,
) -> str:
    if not extensions_dir.exists():
        return "skipped (not found)"
    src_dir = plugin_root / "vscode-extension"
    if not (src_dir / "extension.js").is_file():
        src_dir = Path(__file__).resolve().parent.parent / "vscode-extension"
    if not (src_dir / "extension.js").is_file():
        return "skipped (missing template)"

    pkg_data = json.loads((src_dir / "package.json").read_text(encoding="utf-8"))
    version = str(pkg_data["version"])
    now_ms = int(time.time() * 1000)
    target_dir = extensions_dir / f"{EXTENSION_ID}-{version}"
    if not dry_run:
        for old_dir in extensions_dir.glob(f"{EXTENSION_ID}-*"):
            if old_dir.is_dir() and old_dir != target_dir:
                shutil.rmtree(old_dir, ignore_errors=True)
        target_dir.mkdir(parents=True, exist_ok=True)
        pkg_meta = pkg_data.get("__metadata")
        if not isinstance(pkg_meta, dict):
            pkg_meta = {}
        pkg_meta["installedTimestamp"] = now_ms
        pkg_meta.setdefault("targetPlatform", "universal")
        pkg_data["__metadata"] = pkg_meta
        _atomic_write_text(
            target_dir / "package.json",
            json.dumps(pkg_data, indent=2) + "\n",
            create_backup=False,
        )
        shutil.copy2(src_dir / "extension.js", target_dir / "extension.js")
        fallback_ext_dir = Path(__file__).resolve().parent.parent / "vscode-extension"
        js_names = sorted(
            {
                p.name
                for d in (src_dir, fallback_ext_dir)
                if d.is_dir()
                for p in d.glob("*.js")
                if p.name != "extension.js"
            }
        )
        for js_module in js_names:
            for candidate in (src_dir / js_module, fallback_ext_dir / js_module):
                if candidate.is_file():
                    shutil.copy2(candidate, target_dir / js_module)
                    break
        for icon_name in ("icon.svg", "icon.png"):
            for candidate in (src_dir / icon_name, fallback_ext_dir / icon_name):
                if candidate.is_file():
                    shutil.copy2(candidate, target_dir / icon_name)
                    break
        _atomic_write_text(
            target_dir / "plugin_root.json",
            json.dumps({"plugin_root": str(Path(plugin_root).resolve())}, indent=2) + "\n",
            create_backup=False,
        )
        for doc_name in ("README.md", "CHANGELOG.md"):
            for candidate in (
                src_dir / doc_name,
                plugin_root / doc_name,
                src_dir.parent / doc_name,
            ):
                if candidate.is_file():
                    shutil.copy2(candidate, target_dir / doc_name)
                    break

    ext_json = extensions_dir / "extensions.json"
    if ext_json.exists():
        try:
            raw_list = json.loads(ext_json.read_text(encoding="utf-8"))
            if isinstance(raw_list, list):
                filtered = [
                    item
                    for item in raw_list
                    if not (
                        isinstance(item, dict)
                        and isinstance(item.get("identifier"), dict)
                        and item["identifier"].get("id") == EXTENSION_ID
                    )
                ]
                filtered.append(
                    {
                        "identifier": {"id": EXTENSION_ID},
                        "version": version,
                        "location": {
                            "$mid": 1,
                            "fsPath": str(target_dir),
                            "external": f"file://{target_dir}",
                            "path": str(target_dir),
                            "scheme": "file",
                        },
                        "relativeLocation": target_dir.name,
                        "metadata": {
                            "isApplicationScoped": False,
                            "isMachineScoped": False,
                            "isBuiltin": False,
                            "installedTimestamp": now_ms,
                            "pinned": False,
                            "source": "vsix",
                            "targetPlatform": "universal",
                            "updated": True,
                            "private": False,
                            "isPreReleaseVersion": False,
                            "hasPreReleaseVersion": False,
                            "preRelease": False,
                        },
                    }
                )
                if not dry_run:
                    _atomic_write_text(ext_json, json.dumps(filtered, indent=2) + "\n")
        except Exception:
            return "error (extensions.json)"
    return "updated"


def _uninstall_ide_extension(
    extensions_dir: Path,
    dry_run: bool = False,
) -> str:
    if not extensions_dir.exists():
        return "skipped (not found)"
    if not dry_run:
        for old_dir in extensions_dir.glob(f"{EXTENSION_ID}-*"):
            if old_dir.is_dir():
                shutil.rmtree(old_dir, ignore_errors=True)

    ext_json = extensions_dir / "extensions.json"
    if ext_json.exists():
        try:
            raw_list = json.loads(ext_json.read_text(encoding="utf-8"))
            if isinstance(raw_list, list):
                filtered = [
                    item
                    for item in raw_list
                    if not (
                        isinstance(item, dict)
                        and isinstance(item.get("identifier"), dict)
                        and item["identifier"].get("id") == EXTENSION_ID
                    )
                ]
                if not dry_run:
                    _atomic_write_text(ext_json, json.dumps(filtered, indent=2) + "\n")
        except Exception:
            return "error (extensions.json)"
    return "updated"


def install_all(
    plugin_root: Path | None = None,
    claude_settings_path: Path = DEFAULT_CLAUDE_SETTINGS,
    cursor_hooks_path: Path = DEFAULT_CURSOR_HOOKS,
    codex_hooks_path: Path = DEFAULT_CODEX_HOOKS,
    codex_config_path: Path = DEFAULT_CODEX_CONFIG,
    cursor_extensions_dir: Path | None = None,
    antigravity_extensions_dir: Path | None = None,
    antigravity_ide_extensions_dir: Path | None = None,
    dry_run: bool = False,
    shim_bin_dir: Path | None = None,
    instruction_files: Sequence[Path] | None = None,
    workspace_root: Path | None = None,
) -> dict[str, str]:
    """Idempotently install Context-Guard hooks & status bars across Claude Code, Cursor, Antigravity, and Codex."""
    if plugin_root is None:
        plugin_root = DEFAULT_PLUGIN_ROOT
    if cursor_extensions_dir is None and claude_settings_path == DEFAULT_CLAUDE_SETTINGS:
        cursor_extensions_dir = DEFAULT_CURSOR_EXTENSIONS
    if antigravity_extensions_dir is None and claude_settings_path == DEFAULT_CLAUDE_SETTINGS:
        antigravity_extensions_dir = DEFAULT_ANTIGRAVITY_EXTENSIONS
    if antigravity_ide_extensions_dir is None and claude_settings_path == DEFAULT_CLAUDE_SETTINGS:
        antigravity_ide_extensions_dir = DEFAULT_ANTIGRAVITY_IDE_EXTENSIONS
    if workspace_root is None and (
        claude_settings_path == DEFAULT_CLAUDE_SETTINGS
        or bool(os.environ.get("CONTEXT_GUARD_CONFIG_PATH", "").strip())
    ):
        raw_cfg, _ = cached_raw_config_status()
        ws_val = raw_cfg.get("workspace_root") if isinstance(raw_cfg, dict) else None
        if isinstance(ws_val, str) and ws_val.strip():
            workspace_root = Path(ws_val.strip()).expanduser()

    py_cmd = resolve_python_command()
    pre_script = format_hook_script_path(Path(plugin_root) / "hooks" / "pre_tool_use.py")
    compact_script = format_hook_script_path(Path(plugin_root) / "hooks" / "pre_compact.py")
    status_script = format_hook_script_path(Path(plugin_root) / "bin" / "cg_status.py")
    post_script = format_hook_script_path(Path(plugin_root) / "hooks" / "post_tool_use.py")
    ws_start_cmd: str | None = None
    ws_claude_stop_cmd: str | None = None
    ws_cursor_stop_cmd: str | None = None
    if workspace_root is not None:
        ws_agy = Path(workspace_root) / "scripts" / "hooks" / "antigravity_stop_guard.py"
        ws_claude = Path(workspace_root) / "scripts" / "hooks" / "claude_stop_guard.py"
        if ws_agy.is_file() and ws_claude.is_file():
            ws_start_cmd = f"{py_cmd} {format_hook_script_path(ws_agy)} --capture-baseline"
            ws_claude_stop_cmd = f"{py_cmd} {format_hook_script_path(ws_claude)} --claude-hook"
            ws_cursor_stop_cmd = f"{py_cmd} {format_hook_script_path(ws_claude)} --cursor-hook"

    claude_status, _ = _update_nested_hooks_json(
        claude_settings_path,
        pre_cmd=f"{py_cmd} {pre_script} --harness claude",
        pre_matcher=CLAUDE_MATCHER,
        compact_cmd=f"{py_cmd} {compact_script} --harness claude",
        dry_run=dry_run,
        statusline_cmd=f"{py_cmd} {status_script} --claude-hud",
        manage_statusline=True,
        post_cmd=f"{py_cmd} {post_script} --harness claude",
        post_events=("PostToolUse", "PostToolUseFailure"),
        post_matcher=CLAUDE_POST_MATCHER,
        post_handler_extra={"async": True},
        session_start_cmd=ws_start_cmd,
        stop_cmd=ws_claude_stop_cmd,
        stop_timeout=30 if ws_claude_stop_cmd is not None else None,
    )
    cursor_status = _update_cursor_hooks_json(
        cursor_hooks_path,
        pre_cmd=f"{py_cmd} {pre_script} --harness cursor",
        compact_cmd=f"{py_cmd} {compact_script} --harness cursor",
        dry_run=dry_run,
        post_cmd=f"{py_cmd} {post_script} --harness cursor",
        session_start_cmd=ws_start_cmd,
        stop_cmd=ws_cursor_stop_cmd,
    )
    codex_status, codex_data = _update_nested_hooks_json(
        codex_hooks_path,
        pre_cmd=f"{py_cmd} {pre_script} --harness codex",
        pre_matcher=CODEX_MATCHER,
        compact_cmd=f"{py_cmd} {compact_script} --harness codex",
        dry_run=dry_run,
        post_cmd=f"{py_cmd} {post_script} --harness codex",
        post_events=("PostToolUse",),
        post_matcher=CODEX_POST_MATCHER,
        post_handler_extra={"timeout": 5},
        session_start_cmd=ws_start_cmd,
        stop_cmd=ws_claude_stop_cmd,
        stop_timeout=30 if ws_claude_stop_cmd is not None else None,
    )
    toml_status = sync_codex_config_toml(
        codex_hooks_path=codex_hooks_path,
        codex_config_path=codex_config_path,
        hooks_data=codex_data,
        ensure_compact_limit=True,
        dry_run=dry_run,
    )
    _skip = "skipped (not requested)"
    cursor_ext_status = install_ide_extension(plugin_root, cursor_extensions_dir, dry_run=dry_run) if cursor_extensions_dir is not None else _skip
    agy_ext_status = install_ide_extension(plugin_root, antigravity_extensions_dir, dry_run=dry_run) if antigravity_extensions_dir is not None else _skip
    agy_ide_ext_status = install_ide_extension(plugin_root, antigravity_ide_extensions_dir, dry_run=dry_run) if antigravity_ide_extensions_dir is not None else _skip
    return {
        "claude": claude_status,
        "cursor": cursor_status,
        "codex_hooks": codex_status,
        "codex_config": toml_status,
        "cursor_extension": cursor_ext_status,
        "antigravity_extension": agy_ext_status,
        "antigravity_ide_extension": agy_ide_ext_status,
        **install_outline_pull(
            plugin_root, claude_settings_path == DEFAULT_CLAUDE_SETTINGS, shim_bin_dir, instruction_files, dry_run
        ),
    }


def uninstall_all(
    claude_settings_path: Path = DEFAULT_CLAUDE_SETTINGS,
    cursor_hooks_path: Path = DEFAULT_CURSOR_HOOKS,
    codex_hooks_path: Path = DEFAULT_CODEX_HOOKS,
    codex_config_path: Path = DEFAULT_CODEX_CONFIG,
    cursor_extensions_dir: Path | None = None,
    antigravity_extensions_dir: Path | None = None,
    antigravity_ide_extensions_dir: Path | None = None,
    dry_run: bool = False,
    shim_bin_dir: Path | None = None,
    instruction_files: Sequence[Path] | None = None,
) -> dict[str, str]:
    """Remove Context-Guard hooks & status bars from Claude Code, Cursor, Antigravity, and OpenAI Codex."""
    if cursor_extensions_dir is None and claude_settings_path == DEFAULT_CLAUDE_SETTINGS:
        cursor_extensions_dir = DEFAULT_CURSOR_EXTENSIONS
    if antigravity_extensions_dir is None and claude_settings_path == DEFAULT_CLAUDE_SETTINGS:
        antigravity_extensions_dir = DEFAULT_ANTIGRAVITY_EXTENSIONS
    if antigravity_ide_extensions_dir is None and claude_settings_path == DEFAULT_CLAUDE_SETTINGS:
        antigravity_ide_extensions_dir = DEFAULT_ANTIGRAVITY_IDE_EXTENSIONS

    claude_status, _ = _update_nested_hooks_json(
        claude_settings_path,
        None,
        None,
        None,
        dry_run=dry_run,
        statusline_cmd=None,
        manage_statusline=True,
    )
    cursor_status = _update_cursor_hooks_json(
        cursor_hooks_path, None, None, dry_run=dry_run
    )
    codex_status, codex_data = _update_nested_hooks_json(
        codex_hooks_path, None, None, None, dry_run=dry_run
    )
    toml_status = sync_codex_config_toml(
        codex_hooks_path=codex_hooks_path,
        codex_config_path=codex_config_path,
        hooks_data=codex_data,
        ensure_compact_limit=False,
        dry_run=dry_run,
    )
    _skip = "skipped (not requested)"
    cursor_ext_status = _uninstall_ide_extension(cursor_extensions_dir, dry_run=dry_run) if cursor_extensions_dir is not None else _skip
    agy_ext_status = _uninstall_ide_extension(antigravity_extensions_dir, dry_run=dry_run) if antigravity_extensions_dir is not None else _skip
    agy_ide_ext_status = _uninstall_ide_extension(antigravity_ide_extensions_dir, dry_run=dry_run) if antigravity_ide_extensions_dir is not None else _skip
    return {
        "claude": claude_status,
        "cursor": cursor_status,
        "codex_hooks": codex_status,
        "codex_config": toml_status,
        "cursor_extension": cursor_ext_status,
        "antigravity_extension": agy_ext_status,
        "antigravity_ide_extension": agy_ide_ext_status,
        **uninstall_outline_pull(
            claude_settings_path == DEFAULT_CLAUDE_SETTINGS, shim_bin_dir, instruction_files, dry_run
        ),
    }


def check_status(
    claude_settings_path: Path | None = None,
    cursor_hooks_path: Path | None = None,
    codex_hooks_path: Path | None = None,
    shim_bin_dir: Path | None = None,
) -> dict[str, bool]:
    """Return whether Context-Guard is installed in each harness config, and the `cg-outline` shim."""
    status = check_harness_status(
        claude_settings_path=(
            claude_settings_path if claude_settings_path is not None else DEFAULT_CLAUDE_SETTINGS
        ),
        cursor_hooks_path=(
            cursor_hooks_path if cursor_hooks_path is not None else DEFAULT_CURSOR_HOOKS
        ),
        codex_hooks_path=(
            codex_hooks_path if codex_hooks_path is not None else DEFAULT_CODEX_HOOKS
        ),
    )
    status["outline_pull"] = shim_installed(shim_bin_dir or DEFAULT_SHIM_BIN_DIR)
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage Context-Guard multi-harness hooks.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--install", action="store_true", help="Install hooks across all harnesses")
    group.add_argument("--uninstall", action="store_true", help="Remove hooks across all harnesses")
    group.add_argument("--status", action="store_true", help="Check installation status")
    parser.add_argument("--dry-run", action="store_true", help="Do not write changes to disk")
    args = parser.parse_args(argv)

    if args.status:
        st = check_status()
        print(json.dumps(st, indent=2))
        return 0
    if args.install:
        res = install_all(dry_run=args.dry_run)
        if not args.dry_run:
            update_check.record_install(DEFAULT_PLUGIN_ROOT, datetime.now(timezone.utc))
        print(json.dumps(res, indent=2))
        return 0
    if args.uninstall:
        res = uninstall_all(dry_run=args.dry_run)
        if not args.dry_run:
            update_check.remove_install_record(DEFAULT_PLUGIN_ROOT)
        print(json.dumps(res, indent=2))
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
