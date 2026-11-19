"""Update notice in the status line, the Markdown report, the installer and the IDE extension."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from bin import cg_status, install_harnesses
from services import status_service
from services.status_service import load_update, render_claude_hud, render_update_line, render_update_suffix

# Captured at import, before tests/conftest.py swaps it for a no-op in every test.
REAL_SPAWN_UPDATE_CHECK = status_service.spawn_update_check

UPDATE_AVAILABLE = {
    "checked_at": "2026-11-01T10:00:00Z",
    "installed": "3.5.0",
    "local": "3.5.0",
    "latest": "3.99.0",
    "state": "update_available",
    "remote_error": None,
}
INSTALL_PENDING = {**UPDATE_AVAILABLE, "installed": "3.4.0", "latest": None, "state": "install_pending"}
CURRENT = {**UPDATE_AVAILABLE, "latest": "3.5.0", "state": "current"}


def _fresh(update: dict) -> dict:
    return {**update, "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def test_update_suffix_per_state() -> None:
    assert render_update_suffix(UPDATE_AVAILABLE) == " ⬆ 3.99.0"
    assert render_update_suffix(INSTALL_PENDING) == " ⬆ install"
    assert render_update_suffix(CURRENT) == ""
    assert render_update_suffix(None) == ""


def test_hud_appends_the_suffix_and_is_unchanged_without_an_update() -> None:
    stdin = {"model": {"display_name": "Claude Opus"}}
    stats = {"saved_tokens": 0}
    base = render_claude_hud(stdin, stats)
    assert render_claude_hud(stdin, stats, None) == base
    assert render_claude_hud(stdin, stats, CURRENT) == base
    assert render_claude_hud(stdin, stats, UPDATE_AVAILABLE) == base + " ⬆ 3.99.0"
    assert render_claude_hud(stdin, stats, INSTALL_PENDING) == base + " ⬆ install"


FORBIDDEN_GIT_WORDS = ("pull", "--force", "reset", "stash")


def test_update_line_names_the_commands() -> None:
    root = Path("/opt/cg")
    available = render_update_line(UPDATE_AVAILABLE, root)
    assert "3.99.0" in available
    assert (
        "`git -C /opt/cg fetch origin tag v3.99.0 --no-tags"
        " && git -C /opt/cg merge --ff-only v3.99.0"
        " && python3 /opt/cg/bin/install_harnesses.py --install`"
    ) in available
    pending = render_update_line(INSTALL_PENDING, root)
    assert "`python3 /opt/cg/bin/install_harnesses.py --install`" in pending
    for word in FORBIDDEN_GIT_WORDS:
        assert word not in available
        assert word not in pending
    assert "git" not in pending
    assert render_update_line(CURRENT, root) == ""
    assert render_update_line(None, root) == ""


def test_update_line_quotes_a_plugin_root_with_spaces() -> None:
    available = render_update_line(UPDATE_AVAILABLE, Path("/opt/my cg"))
    assert "git -C '/opt/my cg' fetch origin tag v3.99.0 --no-tags" in available
    assert "git -C '/opt/my cg' merge --ff-only v3.99.0" in available
    assert "python3 '/opt/my cg/bin/install_harnesses.py' --install" in available
    pending = render_update_line(INSTALL_PENDING, Path("/opt/my cg"))
    assert "python3 '/opt/my cg/bin/install_harnesses.py' --install" in pending


def test_load_update_returns_none_for_missing_or_unreadable_files(tmp_path: Path) -> None:
    path = tmp_path / "update.json"
    assert load_update(path) is None
    path.write_text("not json", encoding="utf-8")
    assert load_update(path) is None
    assert path.read_text(encoding="utf-8") == "not json"
    path.write_text("[1]", encoding="utf-8")
    assert load_update(path) is None
    path.write_text(json.dumps(UPDATE_AVAILABLE), encoding="utf-8")
    assert load_update(path) == UPDATE_AVAILABLE


def test_hud_starts_the_check_only_when_the_result_is_stale(tmp_path: Path, monkeypatch, capsys) -> None:
    spawns: list = []
    monkeypatch.setattr(status_service, "read_nonblocking_stdin_json", lambda: {})
    monkeypatch.setattr(status_service, "spawn_update_check", lambda: spawns.append(1))
    update_path = tmp_path / "update.json"
    argv = ["--claude-hud", "--stats-path", str(tmp_path / "stats.json"), "--update-path", str(update_path)]

    assert cg_status.main(argv) == 0
    assert spawns == [1]
    assert "⬆" not in capsys.readouterr().out

    update_path.write_text(json.dumps(_fresh(UPDATE_AVAILABLE)), encoding="utf-8")
    assert cg_status.main(argv) == 0
    assert spawns == [1]
    assert capsys.readouterr().out.rstrip("\n").endswith(" ⬆ 3.99.0")


def test_hud_backs_off_while_a_recent_attempt_left_a_fresh_lock(tmp_path: Path, monkeypatch, capsys) -> None:
    spawns: list = []
    monkeypatch.setattr(status_service, "read_nonblocking_stdin_json", lambda: {})
    monkeypatch.setattr(status_service, "spawn_update_check", lambda: spawns.append(1))
    update_path = tmp_path / "update.json"
    stale = {**UPDATE_AVAILABLE, "checked_at": "2020-01-01T00:00:00Z"}
    update_path.write_text(json.dumps(stale), encoding="utf-8")
    lock_path = tmp_path / "update.lock"
    argv = ["--claude-hud", "--stats-path", str(tmp_path / "stats.json"), "--update-path", str(update_path)]

    lock_path.touch()
    assert cg_status.main(argv) == 0
    assert spawns == []

    two_hours_ago = time.time() - 2 * 3600
    os.utime(lock_path, (two_hours_ago, two_hours_ago))
    assert cg_status.main(argv) == 0
    assert spawns == [1]

    lock_path.unlink()
    assert cg_status.main(argv) == 0
    assert spawns == [1, 1]
    capsys.readouterr()


def test_real_spawn_starts_update_check_detached(monkeypatch) -> None:
    seen: list = []

    def fake_popen(args, **kwargs):
        seen.append((args, kwargs))

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    REAL_SPAWN_UPDATE_CHECK()
    [(args, kwargs)] = seen
    assert args[-1].endswith("update_check.py")
    assert kwargs["start_new_session"] is True
    assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL


def test_markdown_and_json_include_the_update(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(status_service, "usage_lines", lambda stats, path, outcomes=None: [])
    monkeypatch.setattr(status_service, "usage_json", lambda stats, path, outcomes=None: {})
    update_path = tmp_path / "update.json"
    update_path.write_text(json.dumps(UPDATE_AVAILABLE), encoding="utf-8")
    common = ["--stats-path", str(tmp_path / "stats.json"), "--update-path", str(update_path)]

    assert cg_status.main(["--markdown", *common]) == 0
    markdown = capsys.readouterr().out
    assert "fetch origin tag v3.99.0 --no-tags" in markdown
    assert "merge --ff-only v3.99.0" in markdown
    assert "pull" not in markdown

    assert cg_status.main(["--json", *common]) == 0
    assert json.loads(capsys.readouterr().out)["update"] == UPDATE_AVAILABLE

    assert cg_status.main(["--short", *common]) == 0
    assert "⬆" not in capsys.readouterr().out


def test_installer_main_records_and_removes_the_install(tmp_path: Path, monkeypatch, capsys) -> None:
    root = tmp_path / "context-guard"
    root.mkdir()
    (root / "plugin.json").write_text(json.dumps({"version": "3.5.0"}), encoding="utf-8")
    monkeypatch.setattr(install_harnesses, "DEFAULT_PLUGIN_ROOT", root)
    monkeypatch.setattr(install_harnesses, "install_all", lambda dry_run=False: {})
    monkeypatch.setattr(install_harnesses, "uninstall_all", lambda dry_run=False: {})
    record = root / "telemetry" / "install.json"

    assert install_harnesses.main(["--install", "--dry-run"]) == 0
    assert not record.exists()

    assert install_harnesses.main(["--install"]) == 0
    assert json.loads(record.read_text(encoding="utf-8"))["version"] == "3.5.0"
    assert json.loads((root / "telemetry" / "update.json").read_text(encoding="utf-8"))["state"] == "current"

    assert install_harnesses.main(["--uninstall"]) == 0
    assert not record.exists()


EXT_DIR = Path(__file__).resolve().parent.parent / "vscode-extension"


def _node_eval(expression: str):
    script = (
        "const Module = require('module');"
        "const orig = Module._load;"
        "Module._load = (req, parent, isMain) => req === 'vscode' ? {} : orig(req, parent, isMain);"
        f"const ext = require({json.dumps(str(EXT_DIR / 'extension.js'))});"
        f"console.log(JSON.stringify({expression}));"
    )
    proc = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, encoding="utf-8", check=True
    )
    return json.loads(proc.stdout.strip())


def test_extension_badge_per_state() -> None:
    available = _node_eval(f"ext.updateBadge({json.dumps(UPDATE_AVAILABLE)})")
    assert available["prefix"] == "$(cloud-download) "
    assert "`3.5.0` → `3.99.0`" in available["tooltipLine"]
    assert "command:contextGuard.update" in available["tooltipLine"]
    pending = _node_eval(f"ext.updateBadge({json.dumps(INSTALL_PENDING)})")
    assert pending["prefix"] == "$(cloud-download) "
    assert "Run installer" in pending["tooltipLine"]
    assert _node_eval(f"ext.updateBadge({json.dumps(CURRENT)})") == {"prefix": "", "tooltipLine": ""}
    assert _node_eval("ext.updateBadge(null)") == {"prefix": "", "tooltipLine": ""}


def test_extension_notice_is_keyed_per_version() -> None:
    available = _node_eval(f"ext.updateNotice({json.dumps(UPDATE_AVAILABLE)})")
    assert available["key"] == "contextGuard.notified.update.3.99.0"
    assert available["button"] == "Update"
    pending = _node_eval(f"ext.updateNotice({json.dumps(INSTALL_PENDING)})")
    assert pending["key"] == "contextGuard.notified.install.3.5.0"
    assert pending["button"] == "Run installer"
    assert _node_eval(f"ext.updateNotice({json.dumps(CURRENT)})") is None
    assert _node_eval("ext.updateNotice(null)") is None


def test_extension_update_steps_fetch_the_tag_then_fast_forward_then_install() -> None:
    available = _node_eval("ext.updateSteps('update_available', '/opt/cg', '3.99.0')")
    assert available == [
        ["git", ["-C", "/opt/cg", "fetch", "origin", "tag", "v3.99.0", "--no-tags"]],
        ["git", ["-C", "/opt/cg", "merge", "--ff-only", "v3.99.0"]],
        ["python3", ["/opt/cg/bin/install_harnesses.py", "--install"]],
    ]
    pending = _node_eval("ext.updateSteps('install_pending', '/opt/cg', null)")
    assert pending == [["python3", ["/opt/cg/bin/install_harnesses.py", "--install"]]]
    for _, args in available + pending:
        for word in ("pull", "--force", "reset", "stash"):
            assert word not in args
    assert _node_eval("ext.updateSteps('update_available', '/opt/cg', null)") == []
    assert _node_eval("ext.updateSteps('current', '/opt/cg', '3.99.0')") == []


def test_extension_update_steps_never_prompt_for_credentials() -> None:
    env = _node_eval("ext.updateStepEnv({PATH: '/usr/bin', GIT_TERMINAL_PROMPT: '1'})")
    assert env == {
        "PATH": "/usr/bin",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_SSH_COMMAND": "ssh -o BatchMode=yes",
    }


def test_update_step_env_disables_git_prompts_and_ssh_batch_mode() -> None:
    default_env = _node_eval("ext.updateStepEnv(null)")
    assert default_env == {
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_SSH_COMMAND": "ssh -o BatchMode=yes",
    }
    custom_env = _node_eval("ext.updateStepEnv({GIT_SSH_COMMAND: 'ssh -i ~/.ssh/custom'})")
    assert custom_env == {
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_SSH_COMMAND": "ssh -i ~/.ssh/custom",
    }


def test_extension_tooltip_trusts_only_its_own_commands() -> None:
    ext_js = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(EXT_DIR.glob("*.js"))
    )
    assert "isTrusted = true" not in ext_js
    trusted = _node_eval("ext.TOOLTIP_COMMANDS")
    linked = sorted(set(re.findall(r"\(command:([\w.]+)\)", ext_js)))
    assert sorted(trusted) == linked == ["contextGuard.refresh", "contextGuard.showReport", "contextGuard.update"]
    assert "isTrusted = { enabledCommands: TOOLTIP_COMMANDS }" in ext_js


def test_extension_update_run_is_single_flight() -> None:
    ext_js = (EXT_DIR / "extension.js").read_text(encoding="utf-8")
    body = ext_js[ext_js.index("async function runUpdate()") : ext_js.index("function notifyUpdateOnce")]
    assert "if (updateInFlight)" in body
    assert "Context-Guard update is already running." in body
    assert "updateInFlight = true;" in body
    assert "finally" in body and "updateInFlight = false;" in body.split("finally", 1)[1]


def test_extension_staleness_and_stderr_tail() -> None:
    result = _node_eval(
        "{"
        " missing: ext.isUpdateStale(null, Date.parse('2026-11-01T20:00:00Z')),"
        " fresh: ext.isUpdateStale({checked_at: '2026-11-01T10:00:00Z'}, Date.parse('2026-11-01T20:00:00Z')),"
        " old: ext.isUpdateStale({checked_at: '2026-11-01T10:00:00Z'}, Date.parse('2026-11-02T10:00:00Z')),"
        " garbage: ext.isUpdateStale({checked_at: 'garbage'}, Date.parse('2026-11-01T20:00:00Z')),"
        " tail: ext.tailText('x'.repeat(600), 500),"
        " short: ext.tailText('  failed  ', 500)"
        "}"
    )
    assert result["missing"] is True
    assert result["fresh"] is False
    assert result["old"] is True
    assert result["garbage"] is True
    assert len(result["tail"]) == 501 and result["tail"].startswith("…")
    assert result["short"] == "failed"


def test_extension_contributes_the_update_command() -> None:
    manifest = json.loads((EXT_DIR / "package.json").read_text(encoding="utf-8"))
    commands = {entry["command"] for entry in manifest["contributes"]["commands"]}
    assert "contextGuard.update" in commands
    ext_js = (EXT_DIR / "extension.js").read_text(encoding="utf-8")
    assert 'registerCommand("contextGuard.update"' in ext_js
    assert "fs.watchFile(UPDATE_PATH" in ext_js
    assert "fs.unwatchFile(UPDATE_PATH" in ext_js
