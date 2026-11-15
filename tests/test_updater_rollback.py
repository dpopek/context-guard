"""Real git integration and mocked rollback tests for VS Code extension updater."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
UPDATER_JS = ROOT / "vscode-extension" / "updater.js"
EXTENSION_JS = ROOT / "vscode-extension" / "extension.js"


def _node_bin() -> str:
    found = shutil.which("node")
    assert found, "node binary is required for updater rollback tests"
    return found


def _git_bin() -> str:
    found = shutil.which("git")
    assert found, "git binary is required for updater rollback tests"
    return found


def _run_git(cwd: Path, *args: str) -> str:
    res = subprocess.run(
        [_git_bin(), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        timeout=20,
    )
    return res.stdout.strip()


def _run_node(script: str, *, env_extra: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ)
    env["CONTEXT_GUARD_UPDATER_JS"] = str(UPDATER_JS)
    env["CONTEXT_GUARD_EXTENSION_JS"] = str(EXTENSION_JS)
    if env_extra:
        env.update(env_extra)
    res = subprocess.run(
        [_node_bin(), "-e", script],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert res.returncode == 0, f"node failed rc={res.returncode}\nstdout={res.stdout}\nstderr={res.stderr}"
    parsed: dict[str, Any] = json.loads(res.stdout)
    return parsed


def _setup_git_repos(tmp_path: Path, *, fail_v2_installer: bool = False) -> tuple[Path, Path, str, str]:
    remote = tmp_path / "remote.git"
    subprocess.run([_git_bin(), "init", "--bare", str(remote)], check=True, capture_output=True, timeout=15)

    seed = tmp_path / "seed"
    seed.mkdir()
    _run_git(seed, "init")
    _run_git(seed, "config", "user.name", "Test Operator")
    _run_git(seed, "config", "user.email", "test@example.com")

    (seed / "bin").mkdir()
    installer_v1 = (
        "import pathlib, sys\n"
        "p = pathlib.Path(__file__).resolve().parents[1] / 'install_log.txt'\n"
        "p.write_text(' '.join(sys.argv[1:]), encoding='utf-8')\n"
    )
    (seed / "bin" / "install_harnesses.py").write_text(installer_v1, encoding="utf-8")
    (seed / "version.txt").write_text("v3.5.0\n", encoding="utf-8")
    _run_git(seed, "add", "bin/install_harnesses.py", "version.txt")
    _run_git(seed, "commit", "-m", "release v3.5.0")
    _run_git(seed, "tag", "v3.5.0")
    branch = _run_git(seed, "rev-parse", "--abbrev-ref", "HEAD")
    _run_git(seed, "push", str(remote), f"HEAD:{branch}", "--tags")
    sha_v1 = _run_git(seed, "rev-parse", "HEAD")

    clone = tmp_path / "plugin"
    subprocess.run([_git_bin(), "clone", str(remote), str(clone)], check=True, capture_output=True, timeout=15)
    _run_git(clone, "config", "user.name", "Test Operator")
    _run_git(clone, "config", "user.email", "test@example.com")

    if fail_v2_installer:
        installer_v2 = "import sys\nsys.stderr.write('simulated install failure\\n')\nsys.exit(2)\n"
        (seed / "bin" / "install_harnesses.py").write_text(installer_v2, encoding="utf-8")
    (seed / "version.txt").write_text("v3.99.0\n", encoding="utf-8")
    _run_git(seed, "add", "bin/install_harnesses.py", "version.txt")
    _run_git(seed, "commit", "-m", "release v3.99.0")
    _run_git(seed, "tag", "v3.99.0")
    _run_git(seed, "push", str(remote), f"HEAD:{branch}", "--tags")
    sha_v2 = _run_git(seed, "rev-parse", "HEAD")
    return clone, remote, sha_v1, sha_v2


def test_git_managed_update_clean_and_with_untracked_file(tmp_path: Path) -> None:
    """Real git repo fast-forwards to new tag while preserving untracked files."""
    clone, _remote, _sha_v1, sha_v2 = _setup_git_repos(tmp_path)
    (clone / "untracked_notes.txt").write_text("keep-untracked", encoding="utf-8")
    script = """
    const updater = require(process.env.CONTEXT_GUARD_UPDATER_JS);
    (async () => {
      const ok = await updater.executeManagedUpdate({
        state: "update_available",
        pluginRoot: process.env.TEST_PLUGIN_ROOT,
        latest: "3.99.0",
      });
      console.log(JSON.stringify({ ok }));
    })();
    """
    out = _run_node(script, env_extra={"TEST_PLUGIN_ROOT": str(clone)})
    assert out["ok"] is True
    assert _run_git(clone, "rev-parse", "HEAD") == sha_v2
    assert (clone / "version.txt").read_text(encoding="utf-8") == "v3.99.0\n"
    assert (clone / "untracked_notes.txt").read_text(encoding="utf-8") == "keep-untracked"
    assert (clone / "install_log.txt").read_text(encoding="utf-8") == "--install"


def test_git_managed_update_aborts_on_dirty_tracked_file_before_fetch(tmp_path: Path) -> None:
    """Dirty tracked file aborts BEFORE fetch, merge, or installer runs."""
    clone, _remote, sha_v1, _sha_v2 = _setup_git_repos(tmp_path)
    (clone / "version.txt").write_text("local-uncommitted-edit\n", encoding="utf-8")
    script = """
    const updater = require(process.env.CONTEXT_GUARD_UPDATER_JS);
    (async () => {
      try {
        await updater.executeManagedUpdate({
          state: "update_available",
          pluginRoot: process.env.TEST_PLUGIN_ROOT,
          latest: "3.99.0",
        });
        console.log(JSON.stringify({ threw: false }));
      } catch (err) {
        console.log(JSON.stringify({ threw: true, message: err.message }));
      }
    })();
    """
    out = _run_node(script, env_extra={"TEST_PLUGIN_ROOT": str(clone)})
    assert out["threw"] is True
    assert "uncommitted changes" in out["message"]
    assert _run_git(clone, "rev-parse", "HEAD") == sha_v1
    assert "v3.99.0" not in _run_git(clone, "tag")
    assert (clone / "version.txt").read_text(encoding="utf-8") == "local-uncommitted-edit\n"
    assert not (clone / "install_log.txt").exists()


def test_git_managed_update_install_failure_rolls_back_with_reset_keep(tmp_path: Path) -> None:
    """Installer failure after merge rolls HEAD back via git reset --keep and preserves untracked files."""
    clone, _remote, sha_v1, sha_v2 = _setup_git_repos(tmp_path, fail_v2_installer=True)
    assert sha_v1 != sha_v2
    (clone / "untracked_notes.txt").write_text("preserve-on-rollback", encoding="utf-8")
    script = """
    const updater = require(process.env.CONTEXT_GUARD_UPDATER_JS);
    (async () => {
      try {
        await updater.executeManagedUpdate({
          state: "update_available",
          pluginRoot: process.env.TEST_PLUGIN_ROOT,
          latest: "3.99.0",
        });
        console.log(JSON.stringify({ threw: false }));
      } catch (err) {
        console.log(JSON.stringify({ threw: true, message: err.message }));
      }
    })();
    """
    out = _run_node(script, env_extra={"TEST_PLUGIN_ROOT": str(clone)})
    assert out["threw"] is True
    assert "install_harnesses.py" in out["message"]
    assert _run_git(clone, "rev-parse", "HEAD") == sha_v1
    assert (clone / "version.txt").read_text(encoding="utf-8") == "v3.5.0\n"
    assert (clone / "untracked_notes.txt").read_text(encoding="utf-8") == "preserve-on-rollback"


def test_execute_managed_update_command_sequence_and_rollback_never_hard() -> None:
    """Mocked runCmd checks exact command ordering, reset --keep, never --hard, and preserved updateSteps."""
    script = """
    const updater = require(process.env.CONTEXT_GUARD_UPDATER_JS);
    (async () => {
      const root = "/tmp/cg-plugin";
      const okCalls = [];
      const okRes = await updater.executeManagedUpdate({
        state: "update_available",
        pluginRoot: root,
        latest: "3.99.0",
        runCmd: async (step) => {
          okCalls.push(step);
          if (step[0] === "git" && step[1].includes("status")) return "ok";
          if (step[0] === "git" && step[1].includes("rev-parse")) return "abc123\\n";
          return "";
        },
      });

      const rbCalls = [];
      let rbErr = "";
      try {
        await updater.executeManagedUpdate({
          state: "update_available",
          pluginRoot: root,
          latest: "3.99.0",
          runCmd: async (step) => {
            rbCalls.push(step);
            if (step[0] === "git" && step[1].includes("status")) return "";
            if (step[0] === "git" && step[1].includes("rev-parse")) return "deadbeef\\n";
            if (step[0] === "python3") throw new Error("install failed");
            return "";
          },
        });
      } catch (err) {
        rbErr = err.message;
      }

      const rbFailCalls = [];
      let rbCombinedErr = "";
      try {
        await updater.executeManagedUpdate({
          state: "update_available",
          pluginRoot: root,
          latest: "3.99.0",
          runCmd: async (step) => {
            rbFailCalls.push(step);
            if (step[0] === "git" && step[1].includes("rev-parse")) return "cafebabe";
            if (step[0] === "git" && step[1].includes("merge")) throw new Error("merge failed");
            if (step[0] === "git" && step[1].includes("reset")) throw new Error("reset refused");
            return "";
          },
        });
      } catch (err) {
        rbCombinedErr = err.message;
      }

      const pendCalls = [];
      const pendRes = await updater.executeManagedUpdate({
        state: "install_pending",
        pluginRoot: root,
        latest: null,
        runCmd: async (step) => { pendCalls.push(step); return ""; },
      });

      const upRes = await updater.executeManagedUpdate({
        state: "up_to_date",
        pluginRoot: root,
        latest: "3.99.0",
        runCmd: async () => { throw new Error("should not execute"); },
      });

      let semverErr = "";
      try {
        await updater.executeManagedUpdate({
          state: "update_available",
          pluginRoot: root,
          latest: "3.9.bad",
          runCmd: async () => { throw new Error("should not execute"); },
        });
      } catch (err) {
        semverErr = err.message;
      }

      const legacySteps = updater.updateSteps("update_available", root, "3.99.0");
      console.log(JSON.stringify({ okRes, okCalls, rbCalls, rbErr, rbCombinedErr, pendRes, pendCalls, upRes, semverErr, legacySteps }));
    })();
    """
    out = _run_node(script)
    assert out["okRes"] is True
    assert out["okCalls"] == [
        ["git", ["-C", "/tmp/cg-plugin", "status", "--porcelain", "--untracked-files=no"]],
        ["git", ["-C", "/tmp/cg-plugin", "rev-parse", "HEAD"]],
        ["git", ["-C", "/tmp/cg-plugin", "fetch", "origin", "tag", "v3.99.0", "--no-tags"]],
        ["git", ["-C", "/tmp/cg-plugin", "merge", "--ff-only", "v3.99.0"]],
        ["python3", ["/tmp/cg-plugin/bin/install_harnesses.py", "--install"]],
    ]
    assert out["rbErr"] == "install failed"
    assert out["rbCalls"][-1] == ["git", ["-C", "/tmp/cg-plugin", "reset", "--keep", "deadbeef"]]
    assert not any("--hard" in step[1] for step in out["rbCalls"])
    assert "merge failed" in out["rbCombinedErr"] and "reset refused" in out["rbCombinedErr"]
    assert out["pendRes"] is True
    assert out["pendCalls"] == [["python3", ["/tmp/cg-plugin/bin/install_harnesses.py", "--install"]]]
    assert out["upRes"] is False
    assert "Invalid update version" in out["semverErr"]
    assert len(out["legacySteps"]) == 3


def test_extension_run_update_triggers_rollback_on_install_error(tmp_path: Path) -> None:
    """extension.js runUpdate() delegates to executeManagedUpdate and reports error on rollback."""
    fake_root = tmp_path / "ext-plugin"
    (fake_root / "hooks").mkdir(parents=True)
    (fake_root / "telemetry").mkdir(parents=True)
    (fake_root / "plugin.json").write_text('{"version": "3.5.0"}', encoding="utf-8")
    (fake_root / "hooks" / "pre_tool_use.py").write_text("", encoding="utf-8")
    (fake_root / "telemetry" / "update.json").write_text('{"state":"update_available","latest":"3.99.0"}', encoding="utf-8")
    home_dir = tmp_path / "home"
    home_dir.mkdir(parents=True)

    script = """
    const Module = require("module");
    const commands = [];
    const errors = [];
    const handlers = {};
    const mockVscode = {
      StatusBarAlignment: { Right: 2 },
      ViewColumn: { One: 1 },
      ProgressLocation: { Notification: 15 },
      MarkdownString: class { constructor(v) { this.value = v || ""; } appendMarkdown(s) { this.value += s; } },
      window: {
        createStatusBarItem: () => ({ show() {}, dispose() {} }),
        registerWebviewViewProvider: () => ({ dispose() {} }),
        showInformationMessage: async () => undefined,
        showErrorMessage: async (msg) => { errors.push(msg); },
        withProgress: async (_o, fn) => fn(),
      },
      commands: {
        registerCommand: (id, cb) => { handlers[id] = cb; return { dispose() {} }; },
        executeCommand: () => {},
      },
      workspace: { getConfiguration: () => ({ get: () => false }) },
    };
    const mockChild = {
      execFile: (bin, args, _opts, cb) => {
        commands.push([bin, args]);
        if (bin === "git" && args.includes("status")) return cb(null, "", "");
        if (bin === "git" && args.includes("rev-parse")) return cb(null, "head111\\n", "");
        if (bin === "git" && (args.includes("fetch") || args.includes("merge") || args.includes("reset"))) return cb(null, "", "");
        if (args.includes("--install")) return cb(new Error("boom"), "", "install boom");
        return cb(null, "{}", "");
      },
      spawn: () => ({ unref() {}, on() {} }),
    };
    const origLoad = Module._load;
    Module._load = function (req, parent, isMain) {
      if (req === "vscode") return mockVscode;
      if (req === "child_process") return mockChild;
      return origLoad.apply(this, arguments);
    };
    process.env.HOME = process.env.TEST_HOME;
    process.env.CONTEXT_GUARD_HOME = process.env.TEST_ROOT;
    const ext = require(process.env.CONTEXT_GUARD_EXTENSION_JS);
    (async () => {
      try {
        ext.activate({
          subscriptions: [],
          globalState: { get: () => true, update: () => Promise.resolve() },
        });
        const res = await handlers["contextGuard.update"]();
        console.log(JSON.stringify({ res, commands, errors, hasExport: typeof ext.executeManagedUpdate === "function" }));
      } finally {
        ext.deactivate();
      }
    })();
    """
    out = _run_node(script, env_extra={"TEST_HOME": str(home_dir), "TEST_ROOT": str(fake_root)})
    assert out["hasExport"] is True
    assert out["res"] is False
    assert any("Context-Guard update stopped:" in e for e in out["errors"])
    assert any(cmd[0] == "git" and cmd[1][-3:] == ["reset", "--keep", "head111"] for cmd in out["commands"])
    assert not any(cmd[0] == "git" and "--hard" in cmd[1] for cmd in out["commands"])
