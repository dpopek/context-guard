"""The installer's outline-pull rule block and `cg-outline` shim: idempotent, owned, removable."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from bin.install_harnesses import check_status, install_all, uninstall_all
from bin.instruction_block import (
    BLOCK_BODY,
    BLOCK_END,
    BLOCK_START,
    SPOOL_SHIM_MARKER,
    SPOOL_SHIM_NAME,
    install_shim,
    remove_block,
    remove_shim,
    shim_installed,
    upsert_block,
)
from tests.helpers import write_python_module

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
USER_TEXT = "# My rules\n\nAlways answer in Polish.\n"
BLOCK = f"{BLOCK_START}\n{BLOCK_BODY}\n{BLOCK_END}\n"


def test_block_body_is_the_agreed_rule() -> None:
    assert BLOCK_BODY == (
        "Before reading a source file longer than ~400 lines, run `cg-outline <path>` "
        "(symbols with `L<start>-L<end>` ranges), then read only the ranges you need."
    )


def test_upsert_creates_a_missing_file(tmp_path: Path) -> None:
    target = tmp_path / "AGENTS.md"
    assert upsert_block(target) == "created"
    assert target.read_text(encoding="utf-8") == BLOCK


def test_upsert_keeps_user_text_and_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "GEMINI.md"
    target.write_text(USER_TEXT, encoding="utf-8")
    assert upsert_block(target) == "updated"
    assert target.read_text(encoding="utf-8") == USER_TEXT + "\n" + BLOCK
    assert upsert_block(target) == "unchanged"
    assert target.read_text(encoding="utf-8").count(BLOCK_START) == 1
    assert (tmp_path / "GEMINI.md.bak").read_text(encoding="utf-8") == USER_TEXT


def test_upsert_repairs_a_hand_edited_block_in_place(tmp_path: Path) -> None:
    target = tmp_path / "CLAUDE.md"
    tail = "\n## Later section\n"
    target.write_text(f"{USER_TEXT}\n{BLOCK_START}\nstale text\n{BLOCK_END}\n{tail}", encoding="utf-8")
    assert upsert_block(target) == "updated"
    assert target.read_text(encoding="utf-8") == USER_TEXT + "\n" + BLOCK + tail


def test_upsert_dry_run_writes_nothing(tmp_path: Path) -> None:
    target = tmp_path / "AGENTS.md"
    assert upsert_block(target, dry_run=True) == "created"
    assert not target.exists()


def test_remove_block_restores_the_original_bytes(tmp_path: Path) -> None:
    target = tmp_path / "GEMINI.md"
    target.write_text(USER_TEXT, encoding="utf-8")
    upsert_block(target)
    assert remove_block(target) is True
    assert target.read_text(encoding="utf-8") == USER_TEXT
    assert remove_block(target) is False


def test_remove_block_from_block_only_or_missing_file(tmp_path: Path) -> None:
    target = tmp_path / "AGENTS.md"
    upsert_block(target)
    assert remove_block(target) is True
    assert target.read_text(encoding="utf-8") == ""
    assert remove_block(tmp_path / "absent.md") is False


def test_unterminated_block_is_left_alone(tmp_path: Path) -> None:
    target = tmp_path / "CLAUDE.md"
    broken = f"{USER_TEXT}{BLOCK_START}\nno end marker\n"
    target.write_text(broken, encoding="utf-8")
    assert remove_block(target) is False
    assert upsert_block(target) == "skipped (unterminated block)"
    assert target.read_text(encoding="utf-8") == broken


def test_shim_runs_the_outline_cli(tmp_path: Path) -> None:
    import sys

    bin_dir = tmp_path / "bin"
    if os.name == "nt":
        assert install_shim(bin_dir, PLUGIN_ROOT) == "skipped (windows)"
        assert remove_shim(bin_dir) is False
        sample = write_python_module(tmp_path / "sample.py", funcs=30)
        proc = subprocess.run([sys.executable, str(PLUGIN_ROOT / "bin" / "outline.py"), str(sample)], capture_output=True, text=True, check=True)
        assert proc.stdout.startswith("# ") and "func_0" in proc.stdout
        return
    assert install_shim(bin_dir, PLUGIN_ROOT) == "created"
    assert install_shim(bin_dir, PLUGIN_ROOT) == "unchanged"
    shim = bin_dir / "cg-outline"
    assert os.access(shim, os.X_OK)
    sample = write_python_module(tmp_path / "sample.py", funcs=30)
    proc = subprocess.run([str(shim), str(sample)], capture_output=True, text=True, check=True)
    assert proc.stdout.startswith("# ")
    assert "func_0" in proc.stdout
    assert remove_shim(bin_dir) is True
    assert not shim.exists()
    assert remove_shim(bin_dir) is False


def test_shim_never_replaces_or_removes_a_foreign_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("bin.instruction_block.IS_WINDOWS", False)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    foreign = bin_dir / "cg-outline"
    foreign.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    assert install_shim(bin_dir, PLUGIN_ROOT) == "skipped (foreign file)"
    assert remove_shim(bin_dir) is False
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"


def _configs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    paths = tuple(tmp_path / name for name in ("settings.json", "cursor.json", "codex.json", "config.toml"))
    for path in paths[:3]:
        path.write_text("{}", encoding="utf-8")
    paths[3].write_text('model = "x"\n', encoding="utf-8")
    return paths  # type: ignore[return-value]


def test_install_all_skips_shim_and_blocks_unless_requested(tmp_path: Path) -> None:
    res = install_all(PLUGIN_ROOT, *_configs(tmp_path))
    assert res["cg_outline_shim"] == "skipped (not requested)"
    assert res["cg_spool_shim"] == "skipped (not requested)"
    assert res["instruction_block"] == "skipped (not requested)"


def test_install_and_uninstall_all_manage_shim_and_blocks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("bin.instruction_block.IS_WINDOWS", False)
    configs = _configs(tmp_path)
    bin_dir = tmp_path / "localbin"
    with_text = tmp_path / "gemini" / "GEMINI.md"
    with_text.parent.mkdir()
    with_text.write_text(USER_TEXT, encoding="utf-8")
    fresh = tmp_path / "codex" / "AGENTS.md"
    fresh.parent.mkdir()
    no_harness = tmp_path / "absent-harness" / "CLAUDE.md"
    files = (with_text, fresh, no_harness)

    monkeypatch.setenv("PATH", os.defpath)
    res = install_all(PLUGIN_ROOT, *configs, shim_bin_dir=bin_dir, instruction_files=files)
    assert res["cg_outline_shim"] == "created (not_on_path)"
    assert res["cg_spool_shim"] == "created (not_on_path)"
    assert res["instruction_block"] == "skipped (shim unavailable)"
    assert with_text.read_text(encoding="utf-8") == USER_TEXT and not fresh.exists()
    st = check_status(*configs[:3], shim_bin_dir=bin_dir)
    assert st["outline_pull"] is True and st["cg_spool_shim"] is True

    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.defpath}")
    res = install_all(PLUGIN_ROOT, *configs, shim_bin_dir=bin_dir, instruction_files=files)
    assert res["cg_outline_shim"] == "unchanged"
    assert res["cg_spool_shim"] == "unchanged"
    assert res["instruction_block"] == "updated, created, skipped (no harness directory)"
    assert not no_harness.parent.exists()
    again = install_all(PLUGIN_ROOT, *configs, shim_bin_dir=bin_dir, instruction_files=files)
    assert again["instruction_block"] == "unchanged, unchanged, skipped (no harness directory)"

    out = uninstall_all(*configs, shim_bin_dir=bin_dir, instruction_files=files)
    assert out["cg_outline_shim"] == "removed"
    assert out["cg_spool_shim"] == "removed"
    assert out["instruction_block"] == "removed, removed, absent"
    assert with_text.read_text(encoding="utf-8") == USER_TEXT
    assert fresh.read_text(encoding="utf-8") == ""
    st_after = check_status(*configs[:3], shim_bin_dir=bin_dir)
    assert st_after["outline_pull"] is False and st_after["cg_spool_shim"] is False


def test_install_all_dry_run_touches_nothing(tmp_path: Path) -> None:
    bin_dir = tmp_path / "localbin"
    target = tmp_path / "AGENTS.md"
    install_all(PLUGIN_ROOT, *_configs(tmp_path), shim_bin_dir=bin_dir, instruction_files=(target,), dry_run=True)
    assert not bin_dir.exists() and not target.exists()


def test_upsert_writes_through_a_symlink_and_keeps_the_link(tmp_path: Path) -> None:
    real = tmp_path / "CLAUDE.md"
    real.write_text(USER_TEXT, encoding="utf-8")
    link = tmp_path / "AGENTS.md"
    link.symlink_to(real)
    assert upsert_block(link) == "updated"
    assert link.is_symlink() and BLOCK_START in real.read_text(encoding="utf-8")
    assert upsert_block(real) == "unchanged"
    assert remove_block(link) is True
    assert link.is_symlink() and real.read_text(encoding="utf-8") == USER_TEXT


def test_crlf_user_text_stays_byte_identical(tmp_path: Path) -> None:
    target = tmp_path / "AGENTS.md"
    original = b"# Rules\r\n\r\nLine\r\n"
    target.write_bytes(original)
    assert upsert_block(target) == "updated"
    assert target.read_bytes().startswith(original)
    assert remove_block(target) is True
    assert target.read_bytes() == original
    hand_edited = original + f"\r\n{BLOCK_START}\r\nstale\r\n{BLOCK_END}\r\n\r\n## Tail\r\n".encode("utf-8")
    target.write_bytes(hand_edited)
    assert upsert_block(target) == "updated"
    assert "\n\n\n## Tail" not in target.read_text(encoding="utf-8")


def test_install_all_reports_instruction_and_shim_errors_instead_of_raising(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("bin.instruction_block.IS_WINDOWS", False)
    configs = _configs(tmp_path)
    bin_dir = tmp_path / "localbin"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.defpath}")
    binary = tmp_path / "AGENTS.md"
    binary.write_bytes(b"\xff\xfe not utf-8\n")
    good = tmp_path / "GEMINI.md"
    res = install_all(PLUGIN_ROOT, *configs, shim_bin_dir=bin_dir, instruction_files=(binary, good))
    assert res["instruction_block"] == "error (UnicodeDecodeError), created"
    assert binary.read_bytes() == b"\xff\xfe not utf-8\n"
    out = uninstall_all(*configs, shim_bin_dir=bin_dir, instruction_files=(binary, good))
    assert out["instruction_block"] == "error (UnicodeDecodeError), removed"

    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    res = install_all(PLUGIN_ROOT, *configs, shim_bin_dir=blocker, instruction_files=(good,))
    assert res["cg_outline_shim"].startswith("error (")
    assert res["cg_spool_shim"].startswith("error (")
    assert res["instruction_block"] == "skipped (shim unavailable)"


def test_cg_spool_shim_executes_cli_and_respects_foreign_files(tmp_path: Path, monkeypatch) -> None:
    import json
    import sys

    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(tmp_path / "spool"))
    bin_dir = tmp_path / "bin"
    if os.name == "nt":
        assert install_shim(bin_dir, PLUGIN_ROOT, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER, script_name="cg_spool.py") == "skipped (windows)"
        assert shim_installed(bin_dir, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER) is False
        assert remove_shim(bin_dir, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER) is False
        proc = subprocess.run([sys.executable, str(PLUGIN_ROOT / "bin" / "cg_spool.py"), "list", "--json"], capture_output=True, text=True, check=True)
        assert json.loads(proc.stdout)["ok"] is True
        return
    assert install_shim(bin_dir, PLUGIN_ROOT, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER, script_name="cg_spool.py") == "created"
    assert install_shim(bin_dir, PLUGIN_ROOT, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER, script_name="cg_spool.py") == "unchanged"
    assert shim_installed(bin_dir, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER) is True
    shim = bin_dir / SPOOL_SHIM_NAME
    assert os.access(shim, os.X_OK)
    proc = subprocess.run([str(shim), "list", "--json"], capture_output=True, text=True, check=True)
    assert json.loads(proc.stdout) == {"ok": True, "count": 0, "total_bytes": 0, "entries": []}
    assert remove_shim(bin_dir, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER) is True
    assert not shim.exists()
    assert remove_shim(bin_dir, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER) is False

    foreign = bin_dir / SPOOL_SHIM_NAME
    foreign.write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
    assert install_shim(bin_dir, PLUGIN_ROOT, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER, script_name="cg_spool.py") == "skipped (foreign file)"
    assert shim_installed(bin_dir, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER) is False
    assert remove_shim(bin_dir, shim_name=SPOOL_SHIM_NAME, marker=SPOOL_SHIM_MARKER) is False
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho custom\n"
