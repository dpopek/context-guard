"""Regression tests for standard install atomic rollback and safe RollbackJournal commit cleanup (P1-08)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
from typing import Any

import pytest

from bin import install_harnesses
from services import installer_service
from services.migration_guard import RollbackJournal

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def test_standard_install_rolls_back_all_harness_and_ide_changes_on_status_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Standard install_all (pack_source=None) rolls back harnesses, IDE swaps, shims, and instruction files on status error."""
    monkeypatch.setattr("services.instruction_block.IS_WINDOWS", False)
    claude_cfg = tmp_path / "claude" / "settings.json"
    cursor_cfg = tmp_path / "cursor" / "hooks.json"
    codex_cfg = tmp_path / "codex" / "hooks.json"
    codex_toml = tmp_path / "codex" / "config.toml"
    for p, txt in ((claude_cfg, '{"orig": 1}\n'), (cursor_cfg, "{corrupt-json"), (codex_cfg, "{}\n"), (codex_toml, 'model = "o3"\n')):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt, encoding="utf-8")

    ext_dir = tmp_path / "extensions"
    old_ext = ext_dir / "advox.context-guard-statusbar-4.3.0"
    old_ext.mkdir(parents=True)
    (old_ext / "extension.js").write_text("/* keep-me */\n", encoding="utf-8")
    ext_json_raw = json.dumps(
        [{"identifier": {"id": "advox.context-guard-statusbar"}, "version": "4.3.0", "relativeLocation": old_ext.name}],
        indent=2,
    ) + "\n"
    (ext_dir / "extensions.json").write_text(ext_json_raw, encoding="utf-8")

    bin_dir = tmp_path / "localbin"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.defpath}")
    inst_file = tmp_path / "claude" / "CLAUDE.md"
    inst_file.write_text("# Keep\n", encoding="utf-8")

    res = installer_service.install_all(
        plugin_root=PLUGIN_ROOT,
        claude_settings_path=claude_cfg,
        cursor_hooks_path=cursor_cfg,
        codex_hooks_path=codex_cfg,
        codex_config_path=codex_toml,
        cursor_extensions_dir=ext_dir,
        shim_bin_dir=bin_dir,
        instruction_files=(inst_file,),
    )
    assert res["cursor"] == "error (invalid json)"
    assert claude_cfg.read_text(encoding="utf-8") == '{"orig": 1}\n'
    assert codex_cfg.read_text(encoding="utf-8") == "{}\n"
    assert codex_toml.read_text(encoding="utf-8") == 'model = "o3"\n'
    assert inst_file.read_text(encoding="utf-8") == "# Keep\n"
    assert not (claude_cfg.with_suffix(".json.bak")).exists()
    assert not (bin_dir / "cg-outline").exists()
    assert (old_ext / "extension.js").read_text(encoding="utf-8") == "/* keep-me */\n"
    assert (ext_dir / "extensions.json").read_text(encoding="utf-8") == ext_json_raw
    assert list(ext_dir.glob(".rollback-*")) == []
    assert list(ext_dir.glob(".staging-*")) == []


def test_rollback_journal_commit_cleanup_oserror_does_not_trigger_destructive_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An OSError while deleting a backup during commit() must warn and preserve committed live targets."""
    live_a, src_a = tmp_path / "live_a", tmp_path / "src_a"
    live_b, src_b = tmp_path / "live_b", tmp_path / "src_b"
    for d, marker in ((live_a, "old-a"), (src_a, "new-a"), (live_b, "old-b"), (src_b, "new-b")):
        d.mkdir()
        (d / "marker.txt").write_text(marker, encoding="utf-8")

    real_rmtree = shutil.rmtree
    removals = 0

    def _fail_second_backup_cleanup(path: Any, *args: Any, **kwargs: Any) -> None:
        nonlocal removals
        p = Path(path)
        if ".rollback-bak-" in p.name:
            removals += 1
            if removals == 2:
                raise PermissionError(13, "locked backup dir")
        real_rmtree(path, *args, **kwargs)

    capsys.readouterr()
    with monkeypatch.context() as mp:
        mp.setattr(shutil, "rmtree", _fail_second_backup_cleanup)
        with RollbackJournal() as journal:
            journal.swap_directory(src_a, live_a)
            journal.swap_directory(src_b, live_b)
            journal.commit()
            # Subsequent rollback inside or outside context manager must be a no-op.
            journal.rollback()

    err = capsys.readouterr().err
    assert removals == 2
    assert (live_a / "marker.txt").read_text(encoding="utf-8") == "new-a"
    assert (live_b / "marker.txt").read_text(encoding="utf-8") == "new-b"
    assert "commit backup cleanup skipped" in err


def test_cli_install_harnesses_exits_nonzero_on_comma_delimited_instruction_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """CLI --install detects comma-delimited error suffixes such as 'created, error (...)' and exits 1."""
    monkeypatch.setattr(install_harnesses, "cached_raw_config_status", lambda: ({}, None))
    monkeypatch.setattr(install_harnesses, "preflight_migration_check", lambda *_a, **_kw: ([], []))
    monkeypatch.setattr(
        install_harnesses,
        "install_all",
        lambda **_kw: {"claude": "updated", "instruction_block": "created, error (UnicodeDecodeError)"},
    )
    recorded: list[Any] = []
    monkeypatch.setattr(install_harnesses.update_check, "record_install", lambda *a: recorded.append(a))

    rc = install_harnesses.main(["--install"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["instruction_block"] == "created, error (UnicodeDecodeError)"
    assert recorded == []
    assert installer_service.has_install_errors({"claude": "updated", "instruction_block": "created, error (UnicodeDecodeError)"}) is True
    assert installer_service.has_install_errors({"claude": "updated", "instruction_block": "created, unchanged"}) is False
