"""Shared pytest fixtures."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Iterator

import pytest

from services import installer_service, status_service, token_usage, usage_report
from hooks import config as hooks_config, model_identity, outcomes, telemetry

_LIVE_OPERATOR_TARGETS = (
    Path.home() / ".config" / "context-guard" / "config.json",
    Path.home() / ".claude" / "settings.json",
    Path.home() / ".cursor" / "hooks.json",
    Path.home() / ".cursor" / "mcp.json",
    Path.home() / ".codex" / "hooks.json",
    Path.home() / ".codex" / "config.toml",
    Path.home() / ".gemini" / "settings.json",
)


def _snapshot_live_paths() -> dict[Path, tuple[int, int] | None]:
    snap: dict[Path, tuple[int, int] | None] = {}
    for target in _LIVE_OPERATOR_TARGETS:
        try:
            st = target.stat()
            snap[target] = (st.st_mtime_ns, st.st_size)
        except OSError:
            snap[target] = None
    return snap


@pytest.fixture(scope="session", autouse=True)
def _verify_live_operator_config_untouched() -> Iterator[None]:
    """Fail the test session if any test accidentally modified live user configuration files."""
    before = _snapshot_live_paths()
    yield
    after = _snapshot_live_paths()
    changed = [str(p) for p in _LIVE_OPERATOR_TARGETS if before.get(p) != after.get(p)]
    assert changed == [], f"Tests modified live operator configuration files: {changed}"


@pytest.fixture
def isolated_user_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect HOME, XDG, APPDATA, LOCALAPPDATA, and CONTEXT_GUARD_CONFIG_PATH into tmp_path."""
    home_dir = tmp_path / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home_dir / ".config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    cfg_path = home_dir / ".config" / "context-guard" / "config.json"
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    monkeypatch.setattr(hooks_config, "DEFAULT_USER_CONFIG_PATH", cfg_path)
    monkeypatch.setattr(installer_service, "DEFAULT_CURSOR_MCP_PATH", home_dir / ".cursor" / "mcp.json", raising=False)
    if "CONTEXT_GUARD_SPOOL_DIR" not in os.environ:
        monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(tmp_path / "default-telemetry" / "spool"))
    hooks_config.clear_config_cache()
    return home_dir


@pytest.fixture(autouse=True)
def _isolate_telemetry_ledgers(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep calls without an explicit path (including child subprocesses) away from live ~/.gemini and checkout ledgers."""
    isolated_home = tmp_path_factory.mktemp("isolated-home")
    monkeypatch.setenv("HOME", str(isolated_home))
    monkeypatch.setenv("USERPROFILE", str(isolated_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(isolated_home / ".config"))
    monkeypatch.setenv("APPDATA", str(isolated_home / "AppData" / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(isolated_home / "AppData" / "Local"))
    monkeypatch.setenv(
        "CONTEXT_GUARD_CONFIG_PATH",
        str(isolated_home / ".config" / "context-guard" / "config.json"),
    )
    monkeypatch.setenv(
        "CONTEXT_GUARD_HOME",
        str(isolated_home / ".gemini" / "config" / "plugins" / "context-guard"),
    )
    if "CONTEXT_GUARD_SPOOL_DIR" not in os.environ:
        monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(tmp_path / "default-telemetry" / "spool"))
    monkeypatch.setattr(hooks_config, "DEFAULT_USER_CONFIG_PATH", isolated_home / ".config" / "context-guard" / "config.json")
    monkeypatch.setattr(installer_service, "DEFAULT_CURSOR_MCP_PATH", isolated_home / ".cursor" / "mcp.json", raising=False)
    hooks_config.clear_config_cache()
    monkeypatch.setattr(telemetry, "DEFAULT_TELEMETRY_PATH", tmp_path / "default-telemetry" / "stats.json")
    monkeypatch.setattr(outcomes, "DEFAULT_OUTCOMES_PATH", tmp_path / "default-telemetry" / "outcomes.json")


@pytest.fixture(autouse=True)
def _isolate_model_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep model detection away from the developer's real ~/.codex and ~/.config/context-guard."""
    monkeypatch.setattr(model_identity, "CODEX_SESSIONS_DIR", tmp_path / "codex-sessions")
    monkeypatch.setattr(model_identity, "CODEX_CONFIG_PATH", tmp_path / "codex-config.toml")
    monkeypatch.setattr(model_identity, "GUARD_CONFIG_PATH", tmp_path / "guard-config.json")
    monkeypatch.setattr(model_identity, "ANTIGRAVITY_BRAIN_DIR", tmp_path / "antigravity-brain")


@pytest.fixture(autouse=True)
def _isolate_token_usage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep usage ingestion away from the real transcripts and the live token_usage.json."""
    monkeypatch.setattr(token_usage, "DEFAULT_USAGE_PATH", tmp_path / "default-telemetry" / "token_usage.json")
    monkeypatch.setattr(
        token_usage,
        "TRANSCRIPT_ROOTS",
        {name: tmp_path / "transcripts" / name for name in ("antigravity", "claude", "codex", "cursor")},
    )
    monkeypatch.setattr(usage_report, "PREAMBLE_HOME", tmp_path / "home")


@pytest.fixture(autouse=True)
def _isolate_update_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the HUD from reading the checkout's update.json or starting a real release check."""
    monkeypatch.setattr(status_service, "DEFAULT_UPDATE_PATH", tmp_path / "default-telemetry" / "update.json")
    monkeypatch.setattr(status_service, "spawn_update_check", lambda: None)


@pytest.fixture(autouse=True)
def _forbid_real_update_check(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail any test that starts update_check.py for real: it would ask the real origin and write the checkout."""
    leaked: list = []
    real_popen = subprocess.Popen

    class _GuardedPopen(real_popen):  # type: ignore[misc, valid-type]
        def __init__(self, args: Any, *rest: Any, **kwargs: Any) -> None:
            argv = [args] if isinstance(args, (str, bytes, Path)) else list(args)
            if any(str(part).endswith("update_check.py") for part in argv):
                leaked.append(argv)
                raise RuntimeError("real update check blocked by tests/conftest.py")
            super().__init__(args, *rest, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", _GuardedPopen)
    yield
    assert not leaked, f"a test started the real update check: {leaked}"
