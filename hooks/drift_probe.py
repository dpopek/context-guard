"""Native harness CLI version and fail-closed security configuration drift probes."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping

from core.platform_io import warn
from hooks.config import load_runtime_config

__all__ = ["inspect_native_security_drift", "probe_claude_cli_version"]

_CG_HOOK_TOKENS = ("pre_tool_use", "context-guard", "context_guard")
_CODEX_NOTICE = "Codex requires [features].hooks=true & trust_level for apply_patch hooks"


def _parse_json_object(path: Path) -> tuple[dict[str, Any], bool]:
    """Read a JSON object file; return `({}, False)` if missing or `({}, True)` with `warn()` on error."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}, False
    except (OSError, ValueError) as exc:
        warn(f"unable to read native hook config {path}: {type(exc).__name__}: {exc}")
        return {}, True
    try:
        parsed = json.loads(raw_text)
    except (ValueError, TypeError) as exc:
        warn(f"corrupt JSON in native hook config {path}: {exc}")
        return {}, True
    if not isinstance(parsed, dict):
        warn(f"invalid JSON root in native hook config {path}: expected object")
        return {}, True
    return parsed, False


def _extract_cg_hooks(data: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    hooks_map = data.get("hooks")
    raw = hooks_map.get(key) if isinstance(hooks_map, Mapping) else []
    if not isinstance(raw, list):
        return []
    subs: list[Mapping[str, Any]] = []
    for group in raw:
        if not isinstance(group, Mapping):
            continue
        nested = group.get("hooks")
        items = nested if isinstance(nested, list) else [group]
        subs.extend(item for item in items if isinstance(item, Mapping))
    return [entry for entry in subs if any(tok in str(entry.get("command") or "") for tok in _CG_HOOK_TOKENS)]


def probe_claude_cli_version(
    claude_bin: str = "claude",
    *,
    env: Mapping[str, str] | None = None,
    runner: Callable[..., Any] | None = None,
) -> tuple[int, int, int] | None:
    """Run `[claude_bin, '--version']` (timeout=2) and return `(major, minor, patch)` or None."""
    try:
        kw: dict[str, Any] = {"capture_output": True, "text": True, "timeout": 2, "check": False}
        if env is not None:
            kw["env"] = dict(env)
        proc = (runner or subprocess.run)([claude_bin, "--version"], **kw)
        out = f"{getattr(proc, 'stdout', '') or ''}\n{getattr(proc, 'stderr', '') or ''}"
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", out) if getattr(proc, "returncode", 0) == 0 else None
        return (int(match.group(1)), int(match.group(2)), int(match.group(3))) if match else None
    except (subprocess.SubprocessError, OSError, ValueError):
        return None


def inspect_native_security_drift(
    runtime_cfg: Mapping[str, Any] | None = None,
    *,
    claude_settings_path: Path | None = None,
    cursor_hooks_path: Path | None = None,
    codex_hooks_path: Path | None = None,
    codex_config_path: Path | None = None,
    claude_version: tuple[int, int, int] | None = None,
    probe_claude: bool = False,
) -> dict[str, Any]:
    """Inspect Claude, Cursor, and Codex native configs for fail-closed security drift."""
    cfg = runtime_cfg if runtime_cfg is not None else load_runtime_config()
    packs, home_dir = cfg.get("policy_packs"), Path.home()
    sec = bool(
        cfg.get("config_error")
        or cfg.get("legacy_security_keys")
        or (
            isinstance(packs, list)
            and any(
                isinstance(e, Mapping) and e.get("enabled", True) and str(e.get("kind") or "security") == "security"
                for e in packs
            )
        )
    )
    claude_p = claude_settings_path or (home_dir / ".claude" / "settings.json")
    cursor_p = cursor_hooks_path or (home_dir / ".cursor" / "hooks.json")
    codex_p = codex_hooks_path or (home_dir / ".codex" / "hooks.json")
    codex_toml_p = codex_config_path or (home_dir / ".codex" / "config.toml")

    c_data, c_corrupt = _parse_json_object(claude_p)
    cu_data, cu_corrupt = _parse_json_object(cursor_p)
    cx_data, cx_corrupt = _parse_json_object(codex_p)
    corrupt_configs = [str(p) for p, bad in ((claude_p, c_corrupt), (cursor_p, cu_corrupt), (codex_p, cx_corrupt)) if bad]

    c_h, cu_h, cx_h = _extract_cg_hooks(c_data, "PreToolUse"), _extract_cg_hooks(cu_data, "preToolUse"), _extract_cg_hooks(cx_data, "PreToolUse")
    c_fc = bool(c_h) and all(item.get("onFailure") == "block" for item in c_h)
    cu_fc = bool(cu_h) and all(item.get("failClosed") is True for item in cu_h)
    ver = probe_claude_cli_version() if (claude_version is None and probe_claude and sec) else claude_version

    try:
        toml = codex_toml_p.read_text(encoding="utf-8")
    except FileNotFoundError:
        toml = ""
    except (OSError, ValueError) as exc:
        warn(f"unable to read Codex config {codex_toml_p}: {type(exc).__name__}: {exc}")
        toml = ""
        corrupt_configs.append(str(codex_toml_p))

    has_drift = sec and (
        bool(corrupt_configs)
        or (bool(cu_h) and not cu_fc)
        or (bool(c_h) and ver is not None and ver >= (2, 1, 295) and not c_fc)
    )
    drift = ["NATIVE_FAIL_CLOSED_DRIFT"] if has_drift else []
    remediation: str | None = None
    if corrupt_configs and drift:
        remediation = "Fix corrupt harness config JSON and re-run install_harnesses.py for failClosed/onFailure=block."
    elif corrupt_configs:
        remediation = "Fix corrupt harness config JSON."
    elif drift:
        remediation = "Re-run install_harnesses.py for failClosed/onFailure=block."

    return {
        "security_active": sec,
        "ok": (not drift) and (not corrupt_configs),
        "drift_codes": drift,
        "corrupt_configs": corrupt_configs,
        "remediation": remediation,
        "claude": {
            "registered": bool(c_h),
            "on_failure_block": c_fc,
            "degraded_older_cli": bool(sec and c_h and ver is not None and ver < (2, 1, 295)),
            "version": ".".join(map(str, ver)) if ver is not None else None,
            "corrupt": c_corrupt,
        },
        "cursor": {"registered": bool(cu_h), "fail_closed": cu_fc, "corrupt": cu_corrupt},
        "codex": {
            "registered": bool(cx_h),
            "notices": [_CODEX_NOTICE] if sec else [],
            "has_trust_level": bool(re.search(r"^\s*trust_level\s*=", toml, re.M)),
            "features_hooks_enabled": bool(re.search(r"^\s*\[features\][^\[]*?^\s*hooks\s*=\s*true\b", toml, re.M | re.S)),
            "corrupt": cx_corrupt,
        },
    }
