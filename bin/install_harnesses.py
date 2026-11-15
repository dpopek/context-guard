#!/usr/bin/env python3
"""Idempotent multi-harness installer/uninstaller for Context-Guard."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePath
from typing import Any, Callable, Sequence
from urllib.parse import quote

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from bin import update_check  # noqa: E402
from bin.codex_toml import (  # noqa: E402
    compute_codex_trusted_hash as compute_codex_trusted_hash,
    sync_codex_config_toml as sync_codex_config_toml,
)
from bin.harness_status import (  # noqa: E402
    CLAUDE_MATCHER,
    CODEX_MATCHER,
    CURSOR_MATCHER,
    DEFAULT_CLAUDE_SETTINGS,
    DEFAULT_CODEX_HOOKS,
    DEFAULT_CURSOR_HOOKS,
    check_status as check_harness_status,
    merge_harness_matcher,
)
from bin.instruction_block import DEFAULT_INSTRUCTION_FILES, DEFAULT_SHIM_BIN_DIR, install_outline_pull, shim_installed, uninstall_outline_pull  # noqa: E402
from bin.migration_guard import RollbackJournal, StagedPackTransaction, preflight_migration_check  # noqa: E402
from hooks.config import cached_raw_config_status, clear_config_cache, load_runtime_config, resolve_user_config_path  # noqa: E402
from hooks.policy_engine import PolicyPackLoadError, load_verified_policy_pack  # noqa: E402
from hooks.state_store import resolve_plugin_root, warn  # noqa: E402
from policies.api import InstallerHookSpec  # noqa: E402

_INITIAL_PLUGIN_ROOT = resolve_plugin_root()
DEFAULT_PLUGIN_ROOT = _INITIAL_PLUGIN_ROOT


def _active_plugin_root(plugin_root: Path | None = None) -> Path:
    if plugin_root is not None:
        return Path(plugin_root)
    if DEFAULT_PLUGIN_ROOT != _INITIAL_PLUGIN_ROOT:
        return Path(DEFAULT_PLUGIN_ROOT)
    return resolve_plugin_root()


DEFAULT_CODEX_CONFIG = Path.home() / ".codex" / "config.toml"
DEFAULT_CURSOR_EXTENSIONS = Path.home() / ".cursor" / "extensions"
DEFAULT_ANTIGRAVITY_EXTENSIONS = Path.home() / ".antigravity" / "extensions"
DEFAULT_ANTIGRAVITY_IDE_EXTENSIONS = Path.home() / ".antigravity-ide" / "extensions"

EXTENSION_ID = "advox.context-guard-statusbar"
# PostToolUse shell-output measurement: shell tools only.
CLAUDE_POST_MATCHER = "Bash"
CODEX_POST_MATCHER = "^(Bash|shell|exec_command|exec)$"
CURSOR_POST_MATCHER = "Shell|run_terminal_cmd"

_SAFE_HOOK_PATH_RE = re.compile(r"[A-Za-z0-9_./:-]+")


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
    """Format a hook script path with forward slashes, double-quoting when special characters appear."""
    posix_str = str(path).replace("\\", "/")
    if _SAFE_HOOK_PATH_RE.fullmatch(posix_str):
        return posix_str
    escaped = posix_str.replace('"', '\\"')
    return f'"{escaped}"'


_CG_HOOK_SCRIPTS = (
    "/hooks/pre_tool_use.py",
    "/hooks/pre_compact.py",
    "/hooks/post_tool_use.py",
    "\\hooks\\pre_tool_use.py",
    "\\hooks\\pre_compact.py",
    "\\hooks\\post_tool_use.py",
)


def _expand_pack_command(template: str, py_cmd: str, raw_ws: str | None) -> str | None:
    cmd = template.replace("{python}", py_cmd)
    if "{workspace_root}" in cmd:
        if not raw_ws or not raw_ws.strip():
            return None
        ws_path = Path(raw_ws.strip()).expanduser()
        cmd = re.sub(
            r"\{workspace_root\}/([^\s]+)",
            lambda m: format_hook_script_path(ws_path / m.group(1)),
            cmd,
        )
        cmd = cmd.replace("{workspace_root}", format_hook_script_path(ws_path))
    return cmd


def _pack_command_fragments(template: str) -> tuple[str, ...]:
    parts = [p.strip() for p in re.split(r"\{python\}|\{workspace_root\}", template) if p.strip()]
    return tuple(parts)


def _collect_pack_contributions(
    py_cmd: str, workspace_root: Path | None = None
) -> tuple[
    dict[str, list[str]],
    dict[str, list[InstallerHookSpec]],
    frozenset[str],
    tuple[tuple[str, ...], ...],
    frozenset[str],
]:
    runtime_cfg = load_runtime_config()
    cfg_raw = runtime_cfg.get("config_path")
    cfg_path = Path(str(cfg_raw)) if isinstance(cfg_raw, str) and cfg_raw else resolve_user_config_path()
    matchers: dict[str, list[str]] = {}
    hooks_by_harness: dict[str, list[InstallerHookSpec]] = {}
    managed_cmds: set[str] = set()
    managed_frags: list[tuple[str, ...]] = []
    managed_events: set[str] = set()
    for entry in runtime_cfg.get("policy_packs") or ():
        if not isinstance(entry, dict) or not entry.get("enabled", True):
            continue
        try:
            manifest = load_verified_policy_pack(entry, config_path=cfg_path)
        except PolicyPackLoadError:
            continue
        for harness, pat in manifest.harness_matchers.items():
            if isinstance(pat, str) and pat.strip():
                matchers.setdefault(harness, []).append(pat.strip())
        raw_settings = entry.get("settings")
        settings: dict[str, Any] = raw_settings if isinstance(raw_settings, dict) else {}
        ws_val = workspace_root if workspace_root is not None else (settings.get("workspace_root") or runtime_cfg.get("workspace_root"))
        raw_ws = str(ws_val) if ws_val is not None else None
        for spec in manifest.installer_hooks:
            managed_events.add(spec.event_name)
            frags = _pack_command_fragments(spec.command)
            if frags:
                managed_frags.append(frags)
            expanded = _expand_pack_command(spec.command, py_cmd, raw_ws)
            if expanded is None:
                continue
            managed_cmds.add(expanded)
            hooks_by_harness.setdefault(spec.harness, []).append(
                InstallerHookSpec(
                    harness=spec.harness,
                    event_name=spec.event_name,
                    command=expanded,
                    timeout=spec.timeout,
                    matcher=spec.matcher,
                )
            )
    return matchers, hooks_by_harness, frozenset(managed_cmds), tuple(managed_frags), frozenset(managed_events)


def _is_cg_command(
    cmd: Any,
    managed_cmds: frozenset[str] = frozenset(),
    managed_frags: tuple[tuple[str, ...], ...] = (),
) -> bool:
    """True for a Context-Guard hook command or verified pack-managed installer hook."""
    if not isinstance(cmd, str):
        return False
    if cmd in managed_cmds:
        return True
    if any(script in cmd for script in _CG_HOOK_SCRIPTS):
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


def _without_cg_handlers(
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
        if _is_cg_command(group.get("command"), managed_cmds, managed_frags):
            continue
        handlers = group.get("hooks")
        if isinstance(handlers, list):
            rest = [
                h for h in handlers
                if not (isinstance(h, dict) and _is_cg_command(h.get("command"), managed_cmds, managed_frags))
            ]
            if len(rest) != len(handlers):
                if not rest:
                    continue
                group = {**group, "hooks": rest}
        kept.append(group)
    return kept


def _atomic_write_text(
    path: Path,
    content: str,
    create_backup: bool = True,
    journal: RollbackJournal | None = None,
) -> None:
    real_path = Path(os.path.realpath(str(path)))
    if journal is not None:
        journal.record_file_backup(real_path)
    real_path.parent.mkdir(parents=True, exist_ok=True)
    if real_path.exists():
        old_text = real_path.read_text(encoding="utf-8")
        if old_text == content:
            return
        if create_backup and journal is None:
            bak_path = path.with_suffix(path.suffix + ".bak")
            if not bak_path.exists():
                bak_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(real_path, bak_path)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{real_path.name}.", suffix=".tmp", dir=str(real_path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp_path, str(real_path))
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
    extra_hooks: Sequence[InstallerHookSpec] = (),
    managed_cmds: frozenset[str] = frozenset(),
    managed_frags: tuple[tuple[str, ...], ...] = (),
    managed_events: frozenset[str] = frozenset(),
    journal: RollbackJournal | None = None,
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

    events_to_clean = (
        "PreToolUse", "PreCompact", "PostToolUse", "PostToolUseFailure", "SessionStart", "Stop",
        *sorted(managed_events | {s.event_name for s in extra_hooks}),
    )
    for evt_key in dict.fromkeys(events_to_clean):
        existing = hooks_root.get(evt_key)
        if isinstance(existing, list):
            filtered = _without_cg_handlers(existing, managed_cmds, managed_frags)
            if filtered:
                hooks_root[evt_key] = filtered
            else:
                hooks_root.pop(evt_key, None)

    if pre_cmd is not None:
        hooks_root.setdefault("PreToolUse", []).append(
            {"matcher": pre_matcher, "hooks": [{"type": "command", "command": pre_cmd}]}
        )
    if compact_cmd is not None:
        hooks_root.setdefault("PreCompact", []).append(
            {"hooks": [{"type": "command", "command": compact_cmd}]}
        )
    if post_cmd is not None:
        for evt_key in post_events:
            hooks_root.setdefault(evt_key, []).append(
                {
                    "matcher": post_matcher,
                    "hooks": [{"type": "command", "command": post_cmd, **(post_handler_extra or {})}],
                }
            )
    for spec in extra_hooks:
        handler: dict[str, Any] = {"type": "command", "command": spec.command}
        if spec.timeout is not None:
            handler["timeout"] = spec.timeout
        group: dict[str, Any] = {"hooks": [handler]}
        if spec.matcher is not None:
            group["matcher"] = spec.matcher
        hooks_root.setdefault(spec.event_name, []).append(group)

    if manage_statusline:
        if statusline_cmd is not None:
            cur_sl = data.get("statusLine")
            is_already_cg = isinstance(cur_sl, dict) and "cg_status.py" in str(cur_sl.get("command", ""))
            if cur_sl is not None and not is_already_cg and "_context_guard_backup_statusLine" not in data:
                data["_context_guard_backup_statusLine"] = cur_sl
            data["statusLine"] = {"type": "command", "command": statusline_cmd, "padding": 1}
        elif "_context_guard_backup_statusLine" in data:
            data["statusLine"] = data.pop("_context_guard_backup_statusLine")
        elif isinstance(data.get("statusLine"), dict) and "cg_status.py" in str(data["statusLine"].get("command", "")):
            data.pop("statusLine", None)

    rendered = json.dumps(data, indent=2) + "\n"
    if not dry_run:
        _atomic_write_text(cfg_path, rendered, journal=journal)
    return ("updated", data)


def _update_cursor_hooks_json(
    cfg_path: Path,
    pre_cmd: str | None,
    compact_cmd: str | None,
    dry_run: bool = False,
    post_cmd: str | None = None,
    pre_matcher: str = CURSOR_MATCHER,
    extra_hooks: Sequence[InstallerHookSpec] = (),
    managed_cmds: frozenset[str] = frozenset(),
    managed_frags: tuple[tuple[str, ...], ...] = (),
    managed_events: frozenset[str] = frozenset(),
    journal: RollbackJournal | None = None,
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

    events_to_clean = (
        "preToolUse", "preCompact", "postToolUse", "sessionStart", "stop",
        *sorted(managed_events | {s.event_name for s in extra_hooks}),
    )
    for evt_key in dict.fromkeys(events_to_clean):
        existing = hooks_root.get(evt_key)
        if isinstance(existing, list):
            filtered = _without_cg_handlers(existing, managed_cmds, managed_frags)
            if filtered:
                hooks_root[evt_key] = filtered
            else:
                hooks_root.pop(evt_key, None)

    if pre_cmd is not None:
        hooks_root.setdefault("preToolUse", []).append({"command": pre_cmd, "matcher": pre_matcher})
    if compact_cmd is not None:
        hooks_root.setdefault("preCompact", []).append({"command": compact_cmd})
    if post_cmd is not None:
        hooks_root.setdefault("postToolUse", []).append({"command": post_cmd, "matcher": CURSOR_POST_MATCHER})
    for spec in extra_hooks:
        entry: dict[str, Any] = {"command": spec.command}
        if spec.matcher is not None:
            entry["matcher"] = spec.matcher
        if spec.timeout is not None:
            entry["timeout"] = spec.timeout
        hooks_root.setdefault(spec.event_name, []).append(entry)

    rendered = json.dumps(data, indent=2) + "\n"
    if not dry_run:
        _atomic_write_text(cfg_path, rendered, journal=journal)
    return "updated"


def build_vscode_file_uri_location(target_dir: Path | PurePath) -> dict[str, Any]:
    """Build a VS Code `extensions.json` location entry using RFC 8089 `file:///` URIs."""
    resolved = target_dir.resolve() if isinstance(target_dir, Path) else target_dir
    if isinstance(resolved, Path):
        external = resolved.as_uri()
    else:
        posix = resolved.as_posix()
        external = "file:" + quote(posix, safe="/:") if posix.startswith("//") else "file:///" + quote(posix.lstrip("/"), safe="/:")
    return {
        "$mid": 1,
        "fsPath": str(resolved),
        "external": external,
        "path": "/" + resolved.as_posix().lstrip("/"),
        "scheme": "file",
    }


def _update_extensions_json(
    extensions_dir: Path,
    new_entry: dict[str, Any] | None,
    dry_run: bool = False,
    journal: RollbackJournal | None = None,
) -> str:
    ext_json = extensions_dir / "extensions.json"
    if not ext_json.exists():
        return "updated"
    try:
        raw_list = json.loads(ext_json.read_text(encoding="utf-8"))
        if isinstance(raw_list, list):
            filtered = [
                item for item in raw_list
                if not (isinstance(item, dict) and isinstance(item.get("identifier"), dict) and item["identifier"].get("id") == EXTENSION_ID)
            ]
            if new_entry is not None:
                filtered.append(new_entry)
            if not dry_run:
                _atomic_write_text(ext_json, json.dumps(filtered, indent=2) + "\n", journal=journal)
    except Exception:
        return "error (extensions.json)"
    return "updated"


def install_ide_extension(
    plugin_root: Path,
    extensions_dir: Path,
    dry_run: bool = False,
    journal: RollbackJournal | None = None,
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
        dest_dir = (extensions_dir / f".staging-{EXTENSION_ID}-{os.getpid()}") if journal is not None else target_dir
        if journal is not None and dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)
        dest_dir.mkdir(parents=True, exist_ok=True)
        pkg_meta = pkg_data.get("__metadata")
        if not isinstance(pkg_meta, dict):
            pkg_meta = {}
        pkg_meta["installedTimestamp"] = now_ms
        pkg_meta.setdefault("targetPlatform", "universal")
        pkg_data["__metadata"] = pkg_meta
        _atomic_write_text(dest_dir / "package.json", json.dumps(pkg_data, indent=2) + "\n", create_backup=False)
        shutil.copy2(src_dir / "extension.js", dest_dir / "extension.js")
        fallback_ext_dir = Path(__file__).resolve().parent.parent / "vscode-extension"
        js_names = sorted({p.name for d in (src_dir, fallback_ext_dir) if d.is_dir() for p in d.glob("*.js") if p.name != "extension.js"})
        for asset_name in (*js_names, "icon.svg", "icon.png"):
            for candidate in (src_dir / asset_name, fallback_ext_dir / asset_name):
                if candidate.is_file():
                    shutil.copy2(candidate, dest_dir / asset_name)
                    break
        _atomic_write_text(dest_dir / "plugin_root.json", json.dumps({"plugin_root": str(Path(plugin_root).resolve())}, indent=2) + "\n", create_backup=False)
        for doc_name in ("README.md", "CHANGELOG.md"):
            for candidate in (src_dir / doc_name, plugin_root / doc_name, src_dir.parent / doc_name):
                if candidate.is_file():
                    shutil.copy2(candidate, dest_dir / doc_name)
                    break
        if journal is not None:
            journal.swap_directory(dest_dir, target_dir)
        for old_dir in extensions_dir.glob(f"{EXTENSION_ID}-*"):
            if old_dir.is_dir() and old_dir != target_dir:
                shutil.rmtree(old_dir, ignore_errors=True)

    entry = {
        "identifier": {"id": EXTENSION_ID},
        "version": version,
        "location": build_vscode_file_uri_location(target_dir),
        "relativeLocation": target_dir.name,
        "metadata": {
            "isApplicationScoped": False, "isMachineScoped": False, "isBuiltin": False,
            "installedTimestamp": now_ms, "pinned": False, "source": "vsix",
            "targetPlatform": "universal", "updated": True, "private": False,
            "isPreReleaseVersion": False, "hasPreReleaseVersion": False, "preRelease": False,
        },
    }
    return _update_extensions_json(extensions_dir, entry, dry_run=dry_run, journal=journal)


def _uninstall_ide_extension(extensions_dir: Path, dry_run: bool = False) -> str:
    if not extensions_dir.exists():
        return "skipped (not found)"
    if not dry_run:
        for old_dir in extensions_dir.glob(f"{EXTENSION_ID}-*"):
            if old_dir.is_dir():
                shutil.rmtree(old_dir, ignore_errors=True)
    return _update_extensions_json(extensions_dir, None, dry_run=dry_run)


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
    pack_source: Path | None = None,
) -> dict[str, str]:
    """Idempotently install Context-Guard hooks & status bars across Claude Code, Cursor, Antigravity, and Codex."""
    plugin_root = _active_plugin_root(plugin_root)
    use_defaults = claude_settings_path == DEFAULT_CLAUDE_SETTINGS
    if cursor_extensions_dir is None and use_defaults:
        cursor_extensions_dir = DEFAULT_CURSOR_EXTENSIONS
    if antigravity_extensions_dir is None and use_defaults:
        antigravity_extensions_dir = DEFAULT_ANTIGRAVITY_EXTENSIONS
    if antigravity_ide_extensions_dir is None and use_defaults:
        antigravity_ide_extensions_dir = DEFAULT_ANTIGRAVITY_IDE_EXTENSIONS

    journal: RollbackJournal | None = RollbackJournal() if pack_source is not None else None
    txn: StagedPackTransaction | None = (
        StagedPackTransaction(Path(pack_source), config_path=resolve_user_config_path(), journal=journal)
        if pack_source is not None
        else None
    )
    if txn is not None:
        txn.prepare()
        txn.validate()
        if dry_run:
            txn.rollback()
        else:
            txn.activate()
            clear_config_cache()

    try:
        py_cmd = resolve_python_command()
        pre_script = format_hook_script_path(Path(plugin_root) / "hooks" / "pre_tool_use.py")
        compact_script = format_hook_script_path(Path(plugin_root) / "hooks" / "pre_compact.py")
        status_script = format_hook_script_path(Path(plugin_root) / "bin" / "cg_status.py")
        post_script = format_hook_script_path(Path(plugin_root) / "hooks" / "post_tool_use.py")

        pack_matchers, pack_hooks, managed_cmds, managed_frags, managed_events = _collect_pack_contributions(
            py_cmd, workspace_root=workspace_root
        )
        claude_matcher = merge_harness_matcher(CLAUDE_MATCHER, pack_matchers.get("claude", ()))
        cursor_matcher = merge_harness_matcher(CURSOR_MATCHER, pack_matchers.get("cursor", ()))
        codex_matcher = merge_harness_matcher(CODEX_MATCHER, pack_matchers.get("codex", ()), regex_anchored=True)

        claude_status, _ = _update_nested_hooks_json(
            claude_settings_path,
            pre_cmd=f"{py_cmd} {pre_script} --harness claude",
            pre_matcher=claude_matcher,
            compact_cmd=f"{py_cmd} {compact_script} --harness claude",
            dry_run=dry_run,
            statusline_cmd=f"{py_cmd} {status_script} --claude-hud",
            manage_statusline=True,
            post_cmd=f"{py_cmd} {post_script} --harness claude",
            post_events=("PostToolUse", "PostToolUseFailure"),
            post_matcher=CLAUDE_POST_MATCHER,
            post_handler_extra={"async": True},
            extra_hooks=pack_hooks.get("claude", ()),
            managed_cmds=managed_cmds,
            managed_frags=managed_frags,
            managed_events=managed_events,
            journal=journal if not dry_run else None,
        )
        cursor_status = _update_cursor_hooks_json(
            cursor_hooks_path,
            pre_cmd=f"{py_cmd} {pre_script} --harness cursor",
            compact_cmd=f"{py_cmd} {compact_script} --harness cursor",
            dry_run=dry_run,
            post_cmd=f"{py_cmd} {post_script} --harness cursor",
            pre_matcher=cursor_matcher,
            extra_hooks=pack_hooks.get("cursor", ()),
            managed_cmds=managed_cmds,
            managed_frags=managed_frags,
            managed_events=managed_events,
            journal=journal if not dry_run else None,
        )
        codex_status, codex_data = _update_nested_hooks_json(
            codex_hooks_path,
            pre_cmd=f"{py_cmd} {pre_script} --harness codex",
            pre_matcher=codex_matcher,
            compact_cmd=f"{py_cmd} {compact_script} --harness codex",
            dry_run=dry_run,
            post_cmd=f"{py_cmd} {post_script} --harness codex",
            post_events=("PostToolUse",),
            post_matcher=CODEX_POST_MATCHER,
            post_handler_extra={"timeout": 5},
            extra_hooks=pack_hooks.get("codex", ()),
            managed_cmds=managed_cmds,
            managed_frags=managed_frags,
            managed_events=managed_events,
            journal=journal if not dry_run else None,
        )
        j_arg = journal if not dry_run else None

        def _toml_write(p: Path, c: str) -> None:
            _atomic_write_text(p, c, journal=j_arg)

        toml_status = sync_codex_config_toml(
            codex_hooks_path=codex_hooks_path,
            codex_config_path=codex_config_path,
            hooks_data=codex_data,
            ensure_compact_limit=True,
            dry_run=dry_run,
            atomic_writer=_toml_write,
        )
        _skip = "skipped (not requested)"
        cursor_ext_status = install_ide_extension(plugin_root, cursor_extensions_dir, dry_run=dry_run, journal=j_arg) if cursor_extensions_dir is not None else _skip
        agy_ext_status = install_ide_extension(plugin_root, antigravity_extensions_dir, dry_run=dry_run, journal=j_arg) if antigravity_extensions_dir is not None else _skip
        agy_ide_ext_status = install_ide_extension(plugin_root, antigravity_ide_extensions_dir, dry_run=dry_run, journal=j_arg) if antigravity_ide_extensions_dir is not None else _skip
        if j_arg is not None:
            eff_bin = shim_bin_dir or (DEFAULT_SHIM_BIN_DIR if use_defaults else None)
            if eff_bin is not None:
                j_arg.record_file_backup(eff_bin / "cg-outline")
            eff_inst = instruction_files if instruction_files is not None else (DEFAULT_INSTRUCTION_FILES if use_defaults else ())
            for inst_path in eff_inst:
                j_arg.record_file_backup(inst_path)
        res = {
            "claude": claude_status,
            "cursor": cursor_status,
            "codex_hooks": codex_status,
            "codex_config": toml_status,
            "cursor_extension": cursor_ext_status,
            "antigravity_extension": agy_ext_status,
            "antigravity_ide_extension": agy_ide_ext_status,
            **install_outline_pull(plugin_root, use_defaults, shim_bin_dir, instruction_files, dry_run),
        }
        if txn is not None and not dry_run:
            if any(str(v).startswith("error") for v in res.values()):
                txn.rollback()
                raise RuntimeError(f"harness installation error: {res}")
            txn.commit()
        return res
    except Exception:
        if txn is not None and not dry_run:
            txn.rollback()
        raise


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

    _, _, managed_cmds, managed_frags, managed_events = _collect_pack_contributions(resolve_python_command())

    claude_status, _ = _update_nested_hooks_json(
        claude_settings_path, None, None, None, dry_run=dry_run, statusline_cmd=None, manage_statusline=True,
        managed_cmds=managed_cmds, managed_frags=managed_frags, managed_events=managed_events,
    )
    cursor_status = _update_cursor_hooks_json(
        cursor_hooks_path, None, None, dry_run=dry_run,
        managed_cmds=managed_cmds, managed_frags=managed_frags, managed_events=managed_events,
    )
    codex_status, codex_data = _update_nested_hooks_json(
        codex_hooks_path, None, None, None, dry_run=dry_run,
        managed_cmds=managed_cmds, managed_frags=managed_frags, managed_events=managed_events,
    )
    toml_status = sync_codex_config_toml(
        codex_hooks_path=codex_hooks_path, codex_config_path=codex_config_path, hooks_data=codex_data,
        ensure_compact_limit=False, dry_run=dry_run, atomic_writer=_atomic_write_text,
    )
    _skip = "skipped (not requested)"
    cursor_ext_status = _uninstall_ide_extension(cursor_extensions_dir, dry_run=dry_run) if cursor_extensions_dir is not None else _skip
    agy_ext_status = _uninstall_ide_extension(antigravity_extensions_dir, dry_run=dry_run) if antigravity_extensions_dir is not None else _skip
    agy_ide_ext_status = _uninstall_ide_extension(antigravity_ide_extensions_dir, dry_run=dry_run) if antigravity_ide_extensions_dir is not None else _skip
    return {
        "claude": claude_status, "cursor": cursor_status, "codex_hooks": codex_status, "codex_config": toml_status,
        "cursor_extension": cursor_ext_status, "antigravity_extension": agy_ext_status, "antigravity_ide_extension": agy_ide_ext_status,
        **uninstall_outline_pull(claude_settings_path == DEFAULT_CLAUDE_SETTINGS, shim_bin_dir, instruction_files, dry_run),
    }


def check_status(
    claude_settings_path: Path | None = None,
    cursor_hooks_path: Path | None = None,
    codex_hooks_path: Path | None = None,
    shim_bin_dir: Path | None = None,
) -> dict[str, bool]:
    """Return whether Context-Guard is installed in each harness config, and the `cg-outline` shim."""
    status = check_harness_status(
        claude_settings_path=claude_settings_path if claude_settings_path is not None else DEFAULT_CLAUDE_SETTINGS,
        cursor_hooks_path=cursor_hooks_path if cursor_hooks_path is not None else DEFAULT_CURSOR_HOOKS,
        codex_hooks_path=codex_hooks_path if codex_hooks_path is not None else DEFAULT_CODEX_HOOKS,
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
    parser.add_argument("--pack-source", default=None, help="Install and activate a Policy API v1 pack directory")
    args = parser.parse_args(argv)

    if args.pack_source and not args.install:
        print("error: --pack-source requires --install", file=sys.stderr)
        return 2
    if args.status:
        print(json.dumps(check_status(), indent=2))
        return 0
    if args.install:
        if args.pack_source:
            try:
                res = install_all(dry_run=args.dry_run, pack_source=Path(args.pack_source))
            except Exception as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
        else:
            raw_cfg, cfg_err = cached_raw_config_status()
            if cfg_err is not None:
                print(f"error: {cfg_err}", file=sys.stderr)
                return 2
            errors, warnings = preflight_migration_check(raw_cfg if raw_cfg is not None else {})
            for w in warnings:
                print(f"warning: {w}", file=sys.stderr)
            if errors:
                for err in errors:
                    print(f"error: {err}", file=sys.stderr)
                return 2
            res = install_all(dry_run=args.dry_run)
        if not args.dry_run:
            update_check.record_install(_active_plugin_root(), datetime.now(timezone.utc))
        print(json.dumps(res, indent=2))
        return 0
    if args.uninstall:
        res = uninstall_all(dry_run=args.dry_run)
        if not args.dry_run:
            update_check.remove_install_record(_active_plugin_root())
        print(json.dumps(res, indent=2))
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
