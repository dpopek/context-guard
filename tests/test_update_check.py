"""Release check for team installs: version parsing, the state rule and the cached remote refresh."""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

fcntl: Any
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    from hooks import file_io as fcntl

from bin import update_check
from bin.update_check import (
    evaluate_update,
    is_update_stale,
    latest_tag,
    parse_version,
    record_install,
    refresh_update_state,
    remove_install_record,
)

NOW = datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
NOW_ISO = "2026-11-01T10:00:00Z"
LS_REMOTE = (
    "aaa\trefs/tags/v3.4.0\n"
    "bbb\trefs/tags/v3.99.0\n"
    "ccc\trefs/tags/v3.99.0^{}\n"
    "ddd\trefs/tags/v99.0.0-rc1\n"
    "eee\trefs/tags/release-4\n"
    "fff\trefs/tags/v3.6.2\n"
)


def _plugin(tmp_path: Path, version: str = "3.5.0", git: bool = True) -> Path:
    root = tmp_path / "context-guard"
    root.mkdir()
    (root / "plugin.json").write_text(json.dumps({"version": version}), encoding="utf-8")
    if git:
        (root / ".git").mkdir()
    return root


def _git_returning(stdout: str = "", returncode: int = 0, calls: list | None = None):
    def run(args: list) -> subprocess.CompletedProcess:
        if calls is not None:
            calls.append(args)
        return subprocess.CompletedProcess(args, returncode, stdout, "")

    return run


def _git_raising(exc: BaseException):
    def run(args: list) -> subprocess.CompletedProcess:
        raise exc

    return run


def _registered() -> bool:
    return True


def _never_registered() -> bool:
    return False


def _write_update(root: Path, **fields) -> None:
    (root / "telemetry").mkdir(exist_ok=True)
    (root / "telemetry" / "update.json").write_text(json.dumps(fields), encoding="utf-8")


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_parse_version_accepts_plain_and_v_prefixed_semver_only() -> None:
    assert parse_version("3.5.0") == (3, 5, 0)
    assert parse_version("v3.10.2") == (3, 10, 2)
    for bad in ("3.6", "v3.5.0-rc1", "release-4", "", None):
        assert parse_version(bad) is None


def test_latest_tag_picks_highest_semver_and_folds_peeled_lines() -> None:
    assert latest_tag(LS_REMOTE) == "3.99.0"
    assert latest_tag("a\trefs/tags/v0.9.0\nb\trefs/tags/v0.10.0\n") == "0.10.0"
    assert latest_tag("") is None
    assert latest_tag("x\trefs/tags/nightly\n") is None


@pytest.mark.parametrize(
    ("installed", "local", "latest", "ever_installed", "expected"),
    [
        ("3.5.0", "3.5.0", "3.99.0", True, "update_available"),
        ("3.4.0", "3.5.0", "3.99.0", True, "update_available"),
        ("3.5.0", "3.5.0", "3.5.0", True, "current"),
        ("3.5.0", "3.5.0", None, True, "current"),
        ("3.4.0", "3.5.0", None, True, "install_pending"),
        (None, "3.5.0", None, True, "install_pending"),
        (None, "3.5.0", None, False, "current"),
        ("3.5.0", None, "3.99.0", True, "current"),
    ],
)
def test_evaluate_update_first_match_wins(installed, local, latest, ever_installed, expected) -> None:
    assert evaluate_update(installed, local, latest, ever_installed) == expected


def test_is_update_stale_after_24_hours_or_without_a_stamp() -> None:
    assert is_update_stale(None, NOW)
    assert is_update_stale({}, NOW)
    assert is_update_stale({"checked_at": "garbage"}, NOW)
    assert is_update_stale({"checked_at": "2026-11-01T10:00:00"}, NOW)
    assert not is_update_stale({"checked_at": _iso(NOW - timedelta(hours=23))}, NOW)
    assert is_update_stale({"checked_at": _iso(NOW - timedelta(hours=24))}, NOW)


def test_refresh_runs_ls_remote_and_writes_update_json(tmp_path: Path) -> None:
    root = _plugin(tmp_path)
    calls: list = []
    state = refresh_update_state(root, NOW, _git_returning(LS_REMOTE, calls=calls), hooks_registered=_registered)
    assert calls == [["git", "-C", str(root), "ls-remote", "--tags", "origin"]]
    expected = {
        "checked_at": NOW_ISO,
        "installed": None,
        "local": "3.5.0",
        "latest": "3.99.0",
        "state": "update_available",
        "remote_error": None,
    }
    assert state == expected
    on_disk = json.loads((root / "telemetry" / "update.json").read_text(encoding="utf-8"))
    assert on_disk == expected
    assert list(on_disk) == list(expected)


def test_refresh_within_24_hours_skips_the_remote(tmp_path: Path) -> None:
    root = _plugin(tmp_path)
    _write_update(root, checked_at=_iso(NOW - timedelta(hours=1)), latest="3.99.0", remote_error=None)
    calls: list = []
    state = refresh_update_state(root, NOW, _git_returning(LS_REMOTE, calls=calls), hooks_registered=_registered)
    assert calls == []
    assert state["latest"] == "3.99.0"
    assert state["checked_at"] == _iso(NOW - timedelta(hours=1))


def test_force_ignores_the_cache(tmp_path: Path) -> None:
    root = _plugin(tmp_path)
    _write_update(root, checked_at=_iso(NOW - timedelta(hours=1)), latest="3.6.2", remote_error=None)
    calls: list = []
    state = refresh_update_state(
        root, NOW, _git_returning(LS_REMOTE, calls=calls), force=True, hooks_registered=_registered
    )
    assert len(calls) == 1
    assert state["latest"] == "3.99.0"


def test_no_git_checkout_skips_the_remote_and_marks_the_check(tmp_path: Path) -> None:
    root = _plugin(tmp_path, git=False)
    calls: list = []
    state = refresh_update_state(root, NOW, _git_returning(LS_REMOTE, calls=calls), hooks_registered=_never_registered)
    assert calls == []
    assert state["remote_error"] == "no git checkout"
    assert state["checked_at"] == NOW_ISO
    assert state["latest"] is None
    assert state["state"] == "current"


@pytest.mark.parametrize(
    ("run_git", "expected_error"),
    [
        (_git_returning("", returncode=128), "exit 128"),
        (_git_raising(subprocess.TimeoutExpired(["git"], 10)), "TimeoutExpired"),
        (_git_raising(FileNotFoundError("git")), "FileNotFoundError"),
    ],
)
def test_remote_failure_keeps_the_previous_latest(tmp_path: Path, run_git, expected_error) -> None:
    root = _plugin(tmp_path)
    _write_update(root, checked_at=_iso(NOW - timedelta(days=2)), latest="3.99.0", remote_error=None)
    state = refresh_update_state(root, NOW, run_git, hooks_registered=_registered)
    assert state["latest"] == "3.99.0"
    assert state["remote_error"] == expected_error
    assert state["checked_at"] == NOW_ISO


def test_successful_check_clears_a_previous_remote_error(tmp_path: Path) -> None:
    root = _plugin(tmp_path)
    _write_update(root, checked_at=_iso(NOW - timedelta(days=2)), latest=None, remote_error="exit 128")
    state = refresh_update_state(root, NOW, _git_returning(LS_REMOTE), hooks_registered=_registered)
    assert state["remote_error"] is None


def test_remote_false_leaves_the_check_fields_untouched(tmp_path: Path) -> None:
    root = _plugin(tmp_path)
    stamp = _iso(NOW - timedelta(days=3))
    _write_update(root, checked_at=stamp, latest="3.99.0", remote_error="exit 1")
    calls: list = []
    state = refresh_update_state(
        root, NOW, _git_returning(LS_REMOTE, calls=calls), remote=False, hooks_registered=_registered
    )
    assert calls == []
    assert state["checked_at"] == stamp
    assert state["remote_error"] == "exit 1"
    assert state["latest"] == "3.99.0"


def test_corrupt_update_and_install_files_are_treated_as_missing(tmp_path: Path) -> None:
    root = _plugin(tmp_path)
    (root / "telemetry").mkdir()
    (root / "telemetry" / "update.json").write_text("not json", encoding="utf-8")
    (root / "telemetry" / "install.json").write_text("[1, 2]", encoding="utf-8")
    state = refresh_update_state(root, NOW, _git_returning(LS_REMOTE), hooks_registered=_registered)
    assert state["installed"] is None
    assert state["latest"] == "3.99.0"
    assert json.loads((root / "telemetry" / "update.json").read_text(encoding="utf-8")) == state


def test_record_install_writes_the_record_and_clears_install_pending(tmp_path: Path) -> None:
    root = _plugin(tmp_path, git=False)
    before = refresh_update_state(root, NOW, _git_returning(""), hooks_registered=_registered)
    assert before["state"] == "install_pending"
    after = record_install(root, NOW)
    record = json.loads((root / "telemetry" / "install.json").read_text(encoding="utf-8"))
    assert record == {"version": "3.5.0", "installed_at": NOW_ISO}
    assert after["installed"] == "3.5.0"
    assert after["state"] == "current"


def test_remove_install_record_deletes_the_file_and_tolerates_absence(tmp_path: Path) -> None:
    root = _plugin(tmp_path, git=False)
    record_install(root, NOW)
    remove_install_record(root)
    assert not (root / "telemetry" / "install.json").exists()
    remove_install_record(root)


def test_run_git_never_waits_on_a_prompt(monkeypatch) -> None:
    seen: dict = {}

    def fake_run(args, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    monkeypatch.delenv("GCM_INTERACTIVE", raising=False)
    monkeypatch.setattr(update_check.subprocess, "run", fake_run)
    update_check.run_git(["git", "ls-remote"])
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert "BatchMode=yes" in seen["env"]["GIT_SSH_COMMAND"]
    assert seen["env"]["GCM_INTERACTIVE"] == "never"
    assert seen["timeout"] == 10


def test_cli_touches_the_lock_on_every_attempt(tmp_path: Path, monkeypatch, capsys) -> None:
    root = _plugin(tmp_path)
    (root / "telemetry").mkdir()
    lock_path = root / "telemetry" / "update.lock"
    lock_path.touch()
    old = time.time() - 2 * 3600
    os.utime(lock_path, (old, old))
    monkeypatch.setattr(update_check, "run_git", _git_returning(LS_REMOTE))
    monkeypatch.setattr(update_check, "hooks_registered", _registered)
    assert update_check.main(["--plugin-root", str(root)]) == 0
    assert time.time() - lock_path.stat().st_mtime < 60

    os.utime(lock_path, (old, old))
    with open(lock_path, "a", encoding="utf-8") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert update_check.main(["--plugin-root", str(root)]) == 0
    assert time.time() - lock_path.stat().st_mtime < 60
    capsys.readouterr()


def test_cli_prints_the_refreshed_state(tmp_path: Path, monkeypatch, capsys) -> None:
    root = _plugin(tmp_path)
    monkeypatch.setattr(update_check, "run_git", _git_returning(LS_REMOTE))
    monkeypatch.setattr(update_check, "hooks_registered", _registered)
    assert update_check.main(["--plugin-root", str(root), "--force"]) == 0
    assert json.loads(capsys.readouterr().out)["latest"] == "3.99.0"


def test_cli_exits_quietly_while_another_check_holds_the_lock(tmp_path: Path, monkeypatch, capsys) -> None:
    root = _plugin(tmp_path)
    (root / "telemetry").mkdir()
    calls: list = []
    monkeypatch.setattr(update_check, "run_git", _git_returning(LS_REMOTE, calls=calls))
    monkeypatch.setattr(update_check, "hooks_registered", _registered)
    with open(root / "telemetry" / "update.lock", "w", encoding="utf-8") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert update_check.main(["--plugin-root", str(root), "--force"]) == 0
    assert calls == []
    assert capsys.readouterr().out == ""


def test_refresh_update_state_rereads_install_record_after_slow_git_ls_remote(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    root = tmp_path / "plugin"
    (root / ".git").mkdir(parents=True)
    (root / "telemetry").mkdir(parents=True)
    (root / "plugin.json").write_text(json.dumps({"version": "9.5.0"}), encoding="utf-8")
    (root / "telemetry" / "install.json").write_text(
        json.dumps({"version": "9.4.0", "installed_at": "2026-11-01T00:00:00Z"}),
        encoding="utf-8",
    )
    lock_file = root / "telemetry" / "update.lock"
    lock_file.write_text("lock-sentinel\n", encoding="utf-8")

    now = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)

    def _slow_git_with_concurrent_install(args: list[str]) -> subprocess.CompletedProcess[str]:
        install_state = update_check.record_install(root, now)
        assert install_state["installed"] == "9.5.0"
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="abcdef1234567890\trefs/tags/v9.5.0\n",
            stderr="",
        )

    refreshed = update_check.refresh_update_state(
        root,
        now,
        run_git=_slow_git_with_concurrent_install,
        force=True,
        hooks_registered=lambda: True,
    )
    assert refreshed["installed"] == "9.5.0"
    assert refreshed["state"] == "current"

    persisted = json.loads((root / "telemetry" / "update.json").read_text(encoding="utf-8"))
    assert persisted["installed"] == "9.5.0"
    assert persisted["state"] == "current"

    monkeypatch.setattr(update_check, "run_git", _slow_git_with_concurrent_install)
    monkeypatch.setattr(update_check, "hooks_registered", lambda: True)
    assert update_check.main(["--plugin-root", str(root), "--force"]) == 0
    capsys.readouterr()
    assert lock_file.read_text(encoding="utf-8") == "lock-sentinel\n"


def test_python_modules_resolve_default_paths_from_plugin_root_and_env_override(
    tmp_path: Path, monkeypatch
) -> None:
    import sys
    from bin import install_harnesses
    from hooks import state_store

    repo_root = Path(__file__).resolve().parent.parent
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.delenv("CONTEXT_GUARD_HOME", raising=False)

    assert state_store.resolve_plugin_root() == repo_root.resolve()
    explicit_default = tmp_path / "explicit-default"
    assert state_store.resolve_plugin_root(explicit_default) == explicit_default.resolve()

    monkeypatch.setenv("CONTEXT_GUARD_HOME", "~/tilde-cg-home")
    assert (
        state_store.resolve_plugin_root(explicit_default)
        == (fake_home / "tilde-cg-home").resolve()
    )

    probe_script = (
        f"import json, sys; sys.path.insert(0, {str(repo_root)!r})\n"
        "from hooks import outcomes, telemetry\n"
        "from bin import cg_status, install_harnesses, token_usage, update_check\n"
        "print(json.dumps({\n"
        "  'telemetry': str(telemetry.DEFAULT_TELEMETRY_PATH),\n"
        "  'outcomes': str(outcomes.DEFAULT_OUTCOMES_PATH),\n"
        "  'token_usage': str(token_usage.DEFAULT_USAGE_PATH),\n"
        "  'cg_update': str(cg_status.DEFAULT_UPDATE_PATH),\n"
        "  'cg_update_script': str(cg_status.UPDATE_CHECK_SCRIPT),\n"
        "  'cg_version': cg_status.plugin_version(),\n"
        "  'update_root': str(update_check.ROOT),\n"
        "  'install_root': str(install_harnesses.DEFAULT_PLUGIN_ROOT),\n"
        "}))\n"
    )

    env_default = {k: v for k, v in os.environ.items() if k != "CONTEXT_GUARD_HOME"}
    env_default["HOME"] = str(fake_home)
    env_default["USERPROFILE"] = str(fake_home)
    proc_default = subprocess.run(
        [sys.executable, "-c", probe_script],
        env=env_default,
        capture_output=True,
        text=True,
        check=True,
    )
    data_default = json.loads(proc_default.stdout.strip())
    expected_default_tel = repo_root.resolve() / "telemetry"
    assert data_default["telemetry"] == str(expected_default_tel / "stats.json")
    assert data_default["outcomes"] == str(expected_default_tel / "outcomes.json")
    assert data_default["token_usage"] == str(expected_default_tel / "token_usage.json")
    assert data_default["cg_update"] == str(expected_default_tel / "update.json")
    assert data_default["cg_update_script"] == str((repo_root / "bin" / "update_check.py").resolve())
    assert data_default["update_root"] == str(repo_root.resolve())
    assert data_default["install_root"] == str(repo_root.resolve())

    custom_home = tmp_path / "custom-cg-home"
    env_override = {**env_default, "CONTEXT_GUARD_HOME": str(custom_home)}
    proc_override = subprocess.run(
        [sys.executable, "-c", probe_script],
        env=env_override,
        capture_output=True,
        text=True,
        check=True,
    )
    data_override = json.loads(proc_override.stdout.strip())
    expected_custom_tel = custom_home.resolve() / "telemetry"
    assert data_override["telemetry"] == str(expected_custom_tel / "stats.json")
    assert data_override["outcomes"] == str(expected_custom_tel / "outcomes.json")
    assert data_override["token_usage"] == str(expected_custom_tel / "token_usage.json")
    assert data_override["cg_update"] == str(expected_custom_tel / "update.json")
    assert data_override["cg_update_script"] == str((repo_root / "bin" / "update_check.py").resolve())
    assert data_override["cg_version"] == data_default["cg_version"]
    assert data_override["update_root"] == str(custom_home.resolve())
    assert data_override["install_root"] == str(custom_home.resolve())

    patched_root = tmp_path / "patched-install-root"
    patched_root.mkdir()
    claude_cfg = tmp_path / "claude-settings.json"
    claude_cfg.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(install_harnesses, "DEFAULT_PLUGIN_ROOT", patched_root)
    install_harnesses.install_all(
        claude_settings_path=claude_cfg,
        cursor_hooks_path=tmp_path / "cursor-hooks.json",
        codex_hooks_path=tmp_path / "codex-hooks.json",
        codex_config_path=tmp_path / "codex-config.toml",
    )
    written_claude_obj = json.loads(claude_cfg.read_text(encoding="utf-8"))
    assert str(patched_root) in json.dumps(written_claude_obj) or patched_root.name in json.dumps(written_claude_obj)


def test_update_check_single_flight_refresh_lock_and_js_backoff(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    plugin_root = tmp_path / "cg"
    telemetry_dir = plugin_root / "telemetry"
    telemetry_dir.mkdir(parents=True)
    refresh_lock_path = telemetry_dir / update_check.UPDATE_REFRESH_LOCK
    refresh_lock_path.write_text("", encoding="utf-8")

    with open(refresh_lock_path, "a+", encoding="utf-8") as held_lock:
        fcntl.flock(held_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            rc = update_check.main(["--plugin-root", str(plugin_root)])
            assert rc == 0
        finally:
            fcntl.flock(held_lock.fileno(), fcntl.LOCK_UN)

    assert not (telemetry_dir / update_check.UPDATE_RECORD).exists()

    lock_path = telemetry_dir / update_check.UPDATE_LOCK
    now_s = time.time()
    os.utime(lock_path, (now_s - 7200, now_s - 7200))
    proc = subprocess.run(
        [
            "node",
            "-e",
            "const Module = require('module'); const orig = Module._load; Module._load = (r,p,m) => r==='vscode'?{}:orig(r,p,m);"
            "const ext = require(process.argv[1]); console.log(JSON.stringify({staleLock: ext.isUpdateAttemptRecent(process.argv[2], Date.now())}));",
            str(repo_root / "vscode-extension" / "extension.js"),
            str(lock_path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(proc.stdout.strip())["staleLock"] is False

