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
REQUIRED_CONFIG_KEYS: tuple[str, ...] = (
    "read_confirm_policy",
    "optimizers",
    "integrations",
    "regret_window_steps",
    "policy_packs",
    "model_labels",
)
READ_CONFIRM_POLICIES: frozenset[str] = frozenset({"strict", "bounded"})
OPTIMIZER_MODES: frozenset[str] = frozenset({"active", "shadow", "off"})
CLI_REWRITE_MODES: frozenset[str] = frozenset({"auto", "force", "off"})
INTEGRATION_MODES: frozenset[str] = frozenset({"active", "off"})
LEGACY_SECURITY_CONFIG_KEYS: tuple[str, ...] = (
    "restricted_bq_datasets",
    "allowed_bq_views_dataset",
    "enforce_governance_policy",
)


@dataclass(frozen=True)
class _CachedConfigEntry:
    stat_key: tuple[str, int, int]
    raw: dict[str, Any] | None
    error: str | None


_CONFIG_CACHE: dict[str, _CachedConfigEntry] = {}


def resolve_user_config_path(
    home: Path | None = None, env: Mapping[str, str] | None = None, os_name: str = os.name
) -> Path:
    """Resolve per-user `config.json` across POSIX (`~/.config` / `$XDG_CONFIG_HOME`) and Windows (`%APPDATA%` / `%LOCALAPPDATA%`)."""
    eff_home = home if home is not None else Path.home()
    eff_env = env if env is not None else os.environ
    primary = eff_home / ".config" / "context-guard" / "config.json"
    if primary.exists():
        return primary
    if (xdg_raw := str(eff_env.get("XDG_CONFIG_HOME") or "").strip()):
        xdg_candidate = Path(xdg_raw).expanduser() / "context-guard" / "config.json"
        if xdg_candidate.exists():
            return xdg_candidate
    if os_name == "nt":
        for var_name in ("APPDATA", "LOCALAPPDATA"):
            if (win_raw := str(eff_env.get(var_name) or "").strip()):
                win_candidate = Path(win_raw).expanduser() / "context-guard" / "config.json"
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


def default_runtime_config() -> dict[str, Any]:
    """Return clean default universal v4.4 runtime configuration."""
    return {
        "read_confirm_policy": "strict",
        "optimizers": {
            "range_trim": "active",
            "auto_outline": "active",
            "cli_rewrites": "auto",
            "output_spool": "off",
        },
        "integrations": {
            "atlassian_twg": "off",
        },
        "regret_window_steps": 2,
        "policy_packs": [],
        "model_labels": {},
        "repo_map_path": None,
        "workspace_root": None,
        "legacy_security_keys": (),
        "config_path": None,
        "config_error": None,
    }


def load_runtime_config(config_path: Path | None = None) -> dict[str, Any]:
    """Pure loader validating universal config.json schema without writing state or emitting warnings."""
    defaults = default_runtime_config()
    eff_path = _resolve_effective_config_path(config_path, DEFAULT_USER_CONFIG_PATH)
    raw, err = cached_raw_config_status(config_path, default_path=DEFAULT_USER_CONFIG_PATH)
    if err is not None:
        return {**defaults, "config_path": str(eff_path), "config_error": err}
    if raw is None:
        return {**defaults, "config_path": str(eff_path)}

    read_policy_raw = raw.get("read_confirm_policy", "strict")
    if not isinstance(read_policy_raw, str) or read_policy_raw not in READ_CONFIRM_POLICIES:
        return {**defaults, "config_path": str(eff_path), "config_error": "invalid 'read_confirm_policy'"}

    opt_out = dict(defaults["optimizers"])
    raw_opts = raw.get("optimizers")
    if raw_opts is not None:
        if not isinstance(raw_opts, dict):
            return {**defaults, "config_path": str(eff_path), "config_error": "invalid 'optimizers': expected object"}
        for key in ("range_trim", "auto_outline", "output_spool"):
            if key in raw_opts:
                val = raw_opts[key]
                if not isinstance(val, str) or val not in OPTIMIZER_MODES:
                    return {**defaults, "config_path": str(eff_path), "config_error": f"invalid 'optimizers.{key}'"}
                opt_out[key] = val
        if "cli_rewrites" in raw_opts:
            cval = raw_opts["cli_rewrites"]
            if not isinstance(cval, str) or cval not in CLI_REWRITE_MODES:
                return {**defaults, "config_path": str(eff_path), "config_error": "invalid 'optimizers.cli_rewrites'"}
            opt_out["cli_rewrites"] = cval

    int_out = dict(defaults["integrations"])
    raw_ints = raw.get("integrations")
    if raw_ints is not None:
        if not isinstance(raw_ints, dict):
            return {**defaults, "config_path": str(eff_path), "config_error": "invalid 'integrations': expected object"}
        if "atlassian_twg" in raw_ints:
            twg_val = raw_ints["atlassian_twg"]
            if not isinstance(twg_val, str) or twg_val not in INTEGRATION_MODES:
                return {**defaults, "config_path": str(eff_path), "config_error": "invalid 'integrations.atlassian_twg'"}
            int_out["atlassian_twg"] = twg_val

    regret_raw = raw.get("regret_window_steps", 2)
    if isinstance(regret_raw, bool) or not isinstance(regret_raw, int) or regret_raw < 1:
        return {**defaults, "config_path": str(eff_path), "config_error": "invalid 'regret_window_steps'"}

    raw_packs = raw.get("policy_packs", [])
    if not isinstance(raw_packs, list) or any(not isinstance(item, dict) for item in raw_packs):
        return {**defaults, "config_path": str(eff_path), "config_error": "invalid 'policy_packs': expected list"}

    raw_labels = raw.get("model_labels", {})
    if not isinstance(raw_labels, dict):
        return {**defaults, "config_path": str(eff_path), "config_error": "invalid 'model_labels': expected object"}
    model_labels = {
        h: v.strip()
        for h, v in raw_labels.items()
        if h in KNOWN_HARNESSES and isinstance(v, str) and v.strip()
    }

    legacy_keys = tuple(
        k
        for k in LEGACY_SECURITY_CONFIG_KEYS
        if raw.get(k) not in (None, False, "", [])
    )
    ws_raw = raw.get("workspace_root")
    workspace_root = str(Path(ws_raw).expanduser()) if isinstance(ws_raw, str) and ws_raw.strip() else None
    rm_raw = raw.get("repo_map_path")
    repo_map_path = str(Path(rm_raw).expanduser()) if isinstance(rm_raw, str) and rm_raw.strip() else None

    return {
        "read_confirm_policy": read_policy_raw,
        "optimizers": opt_out,
        "integrations": int_out,
        "regret_window_steps": regret_raw,
        "policy_packs": [dict(p) for p in raw_packs],
        "model_labels": model_labels,
        "repo_map_path": repo_map_path,
        "workspace_root": workspace_root,
        "legacy_security_keys": legacy_keys,
        "config_path": str(eff_path),
        "config_error": None,
    }
