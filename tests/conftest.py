"""Shared pytest fixtures."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Iterator

import pytest

from bin import cg_status, token_usage, usage_report
from hooks import model_identity, outcomes, telemetry


@pytest.fixture(autouse=True)
def _isolate_telemetry_ledgers(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep calls without an explicit path (including child subprocesses) away from live ~/.gemini and checkout ledgers."""
    isolated_home = tmp_path_factory.mktemp("isolated-home")
    monkeypatch.setenv("HOME", str(isolated_home))
    monkeypatch.setenv("USERPROFILE", str(isolated_home))
    monkeypatch.setenv(
        "CONTEXT_GUARD_HOME",
        str(isolated_home / ".gemini" / "config" / "plugins" / "context-guard"),
    )
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
    monkeypatch.setattr(cg_status, "DEFAULT_UPDATE_PATH", tmp_path / "default-telemetry" / "update.json")
    monkeypatch.setattr(cg_status, "spawn_update_check", lambda: None)


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
