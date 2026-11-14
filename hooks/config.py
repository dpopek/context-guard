"""Stat-keyed configuration loader and in-memory cache for `config.json`."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from hooks.state_store import warn

DEFAULT_USER_CONFIG_PATH = Path.home() / ".config" / "context-guard" / "config.json"
KNOWN_HARNESSES = ("antigravity", "claude", "cursor", "codex")


@dataclass(frozen=True)
class _CachedConfigEntry:
    stat_key: tuple[str, int, int]
    raw: dict[str, Any] | None
    error: str | None


_CONFIG_CACHE: dict[str, _CachedConfigEntry] = {}


def resolve_user_config_path(home: Path | None = None, env: Mapping[str, str] | None = None, os_name: str = os.name) -> Path:
    """Resolve per-user `config.json` across POSIX (`~/.config` / `$XDG_CONFIG_HOME`) and Windows (`%APPDATA%`)."""
    eff_home = home if home is not None else Path.home()
    eff_env = env if env is not None else os.environ
    primary = eff_home / ".config" / "context-guard" / "config.json"
    if primary.exists():
        return primary
    if (xdg_raw := str(eff_env.get("XDG_CONFIG_HOME") or "").strip()):
        xdg_candidate = Path(xdg_raw).expanduser() / "context-guard" / "config.json"
        if xdg_candidate.exists():
            return xdg_candidate
    if os_name == "nt" and (appdata_raw := str(eff_env.get("APPDATA") or "").strip()):
        win_candidate = Path(appdata_raw).expanduser() / "context-guard" / "config.json"
        if win_candidate.exists():
            return win_candidate
    return primary


def _resolve_effective_config_path(config_path: Path | None, default_path: Path | None) -> Path:
    if config_path is not None:
        return config_path
    if (env_override := os.environ.get("CONTEXT_GUARD_CONFIG_PATH", "").strip()):
        return Path(env_override).expanduser()
    if default_path is not None and default_path != DEFAULT_USER_CONFIG_PATH:
        return default_path
    return resolve_user_config_path()


def cached_raw_config_status(config_path: Path | None = None, *, default_path: Path | None = None) -> tuple[dict[str, Any] | None, str | None]:
    """Return `(raw_dict_copy, error_reason)` backed by `(realpath, st_mtime_ns, st_size)` cache.

    Missing files evict any stale entry for `realpath` and return `(None, None)` silently.
    Unreadable files (`PermissionError`, `IsADirectoryError`, `UnicodeDecodeError`) evict stale
    entries and return `(None, "cannot read config (<ExcType>)")` without caching transient I/O
    errors. Malformed or non-object JSON logs `warn` once per `(realpath, st_mtime_ns, st_size)`
    tuple and caches the error until the file changes on disk.
    """
    effective_path = _resolve_effective_config_path(config_path, default_path)
    try:
        st = os.stat(effective_path)
    except FileNotFoundError:
        if _CONFIG_CACHE:
            _CONFIG_CACHE.pop(os.path.realpath(effective_path), None)
        return None, None
    except OSError as exc:
        if _CONFIG_CACHE:
            _CONFIG_CACHE.pop(os.path.realpath(effective_path), None)
        return None, f"cannot read config ({type(exc).__name__})"

    realpath = os.path.realpath(effective_path)

    stat_key = (realpath, st.st_mtime_ns, st.st_size)
    cached = _CONFIG_CACHE.get(realpath)
    if cached is not None and cached.stat_key == stat_key:
        return (dict(cached.raw) if cached.raw is not None else None), cached.error

    try:
        raw_text = effective_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        _CONFIG_CACHE.pop(realpath, None)
        return None, None
    except (OSError, ValueError) as exc:
        _CONFIG_CACHE.pop(realpath, None)
        return None, f"cannot read config ({type(exc).__name__})"

    try:
        parsed = json.loads(raw_text)
    except (ValueError, TypeError):
        err = "invalid JSON syntax"
        warn(f"Invalid JSON syntax in {effective_path}")
        _CONFIG_CACHE[realpath] = _CachedConfigEntry(stat_key=stat_key, raw=None, error=err)
        return None, err

    if not isinstance(parsed, dict):
        err = f"config root must be a JSON object, got {type(parsed).__name__}"
        warn(f"Invalid config root in {effective_path}: {err}")
        _CONFIG_CACHE[realpath] = _CachedConfigEntry(stat_key=stat_key, raw=None, error=err)
        return None, err

    stored = dict(parsed)
    _CONFIG_CACHE[realpath] = _CachedConfigEntry(stat_key=stat_key, raw=stored, error=None)
    return dict(stored), None


def cached_raw_config(
    config_path: Path | None = None,
    *,
    default_path: Path | None = None,
) -> dict[str, Any] | None:
    """Return a shallow copy of the parsed `config.json` dict, or `None` if absent/invalid."""
    raw, _ = cached_raw_config_status(config_path, default_path=default_path)
    return raw


def clear_config_cache() -> None:
    """Clear the in-memory `config.json` stat cache."""
    _CONFIG_CACHE.clear()
