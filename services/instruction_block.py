"""Outline-pull discoverability: the `cg-outline` PATH shim and a marked rule block in instruction files.

Both are owned by markers: the installer never edits text outside its block and never replaces
or removes a `cg-outline` it did not write.
"""
from __future__ import annotations

import os
import shlex
import shutil
import sys
from pathlib import Path
from typing import Callable, Sequence

from core.platform_io import atomic_write_bytes

BLOCK_START = "<!-- context-guard:outline-pull:start -->"
BLOCK_END = "<!-- context-guard:outline-pull:end -->"
BLOCK_BODY = (
    "Before reading a source file longer than ~400 lines, run `cg-outline <path>` "
    "(symbols with `L<start>-L<end>` ranges), then read only the ranges you need."
)
_BLOCK = f"{BLOCK_START}\n{BLOCK_BODY}\n{BLOCK_END}\n"

SHIM_NAME = "cg-outline"
SHIM_MARKER = "# context-guard:cg-outline"
SPOOL_SHIM_NAME = "cg-spool"
SPOOL_SHIM_MARKER = "# context-guard:cg-spool"
CG_SHIM_NAME = "cg"
CG_SHIM_MARKER = "# context-guard:cg"
BUDGET_SHIM_NAME = "cg-budget"
BUDGET_SHIM_MARKER = "# context-guard:cg-budget"
EVAL_SHIM_NAME = "cg-eval"
EVAL_SHIM_MARKER = "# context-guard:cg-eval"
_EXTRA_SHIMS: tuple[tuple[str, str, str, str], ...] = (
    ("cg_spool_shim", SPOOL_SHIM_NAME, SPOOL_SHIM_MARKER, "cg_spool.py"),
    ("cg_shim", CG_SHIM_NAME, CG_SHIM_MARKER, "cg.py"),
    ("cg_budget_shim", BUDGET_SHIM_NAME, BUDGET_SHIM_MARKER, "cg_budget.py"),
    ("cg_eval_shim", EVAL_SHIM_NAME, EVAL_SHIM_MARKER, "cg_eval.py"),
)
IS_WINDOWS: bool = os.name == "nt"
DEFAULT_SHIM_BIN_DIR = Path.home() / ".local" / "bin"
DEFAULT_INSTRUCTION_FILES = (
    Path.home() / ".codex" / "AGENTS.md",
    Path.home() / ".gemini" / "GEMINI.md",
    Path.home() / ".claude" / "CLAUDE.md",
)


def _write(path: Path, content: str, mode: int | None = None) -> None:
    """Atomic replace; without `mode`, the first change to an existing file leaves a `.bak` beside it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_name(path.name + ".bak")
    if mode is None and path.exists() and not backup.exists():
        shutil.copy2(path, backup)
    eff_mode = mode if mode is not None else ((path.stat().st_mode & 0o777) if path.exists() else 0o644)
    atomic_write_bytes(path, content.encode("utf-8"), mode=eff_mode, prefix=f".{path.name}.")


def _read(path: Path) -> str:
    """File text with its line endings untouched, so text outside the block stays byte-identical."""
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def _resolved(path: Path) -> Path:
    """The file a symlinked instruction file points at: the link itself is never replaced."""
    return Path(os.path.realpath(str(path)))


def _block_span(text: str) -> tuple[int, int] | None:
    """`(start, end)` of the block including its trailing newline; `(start, -1)` when unterminated."""
    start = text.find(BLOCK_START)
    if start < 0:
        return None
    end = text.find(BLOCK_END, start)
    if end < 0:
        return start, -1
    end += len(BLOCK_END)
    if text[end : end + 2] == "\r\n":
        return start, end + 2
    return start, end + 1 if text[end : end + 1] == "\n" else end


def upsert_block(path: Path, dry_run: bool = False) -> str:
    """Ensure exactly one canonical block: `created`, `updated`, `unchanged` or a `skipped (...)` reason."""
    path = _resolved(path)
    existed = path.exists()
    text = _read(path) if existed else ""
    span = _block_span(text)
    if span is None:
        gap = "" if not text else ("\n" if text.endswith("\n") else "\n\n")
        new_text = text + gap + _BLOCK
    elif span[1] < 0:
        return "skipped (unterminated block)"
    else:
        new_text = text[: span[0]] + _BLOCK + text[span[1] :]
    if new_text == text:
        return "unchanged"
    if not dry_run:
        _write(path, new_text)
    return "updated" if existed else "created"


def remove_block(path: Path, dry_run: bool = False) -> bool:
    """Remove the block and the blank line that separated it; True when the file held one."""
    path = _resolved(path)
    if not path.exists():
        return False
    text = _read(path)
    span = _block_span(text)
    if span is None or span[1] < 0:
        return False
    head = text[: span[0]]
    if head.endswith("\n\n"):
        head = head[:-1]
    if not dry_run:
        _write(path, head + text[span[1] :])
    return True


def _shim_text(plugin_root: Path, script_name: str = "outline.py", marker: str = SHIM_MARKER) -> str:
    script = Path(plugin_root) / "bin" / script_name
    return (
        "#!/bin/sh\n"
        f"{marker} (managed by install_harnesses.py)\n"
        f'exec {shlex.quote(sys.executable)} {shlex.quote(str(script))} "$@"\n'
    )


def shim_installed(bin_dir: Path, shim_name: str = SHIM_NAME, marker: str = SHIM_MARKER) -> bool:
    """True when `bin_dir/<shim_name>` exists on POSIX and was written by this installer."""
    if IS_WINDOWS:
        return False
    shim = Path(bin_dir) / shim_name
    try:
        return shim.is_file() and marker in shim.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def on_path(bin_dir: Path) -> bool:
    """True when `bin_dir` is one of the `PATH` entries."""
    target = os.path.normcase(os.path.realpath(str(bin_dir)))
    entries = os.environ.get("PATH", "").split(os.pathsep)
    return any(entry and os.path.normcase(os.path.realpath(entry)) == target for entry in entries)


def install_shim(
    bin_dir: Path,
    plugin_root: Path,
    dry_run: bool = False,
    *,
    shim_name: str = SHIM_NAME,
    marker: str = SHIM_MARKER,
    script_name: str = "outline.py",
) -> str:
    """Write an executable POSIX shim: `created`, `updated`, `unchanged`, or `skipped (...)`."""
    if IS_WINDOWS:
        return "skipped (windows)"
    shim = Path(bin_dir) / shim_name
    existed = shim.exists() or shim.is_symlink()
    if existed and not shim_installed(bin_dir, shim_name=shim_name, marker=marker):
        return "skipped (foreign file)"
    content = _shim_text(plugin_root, script_name=script_name, marker=marker)
    if existed and shim.read_text(encoding="utf-8") == content and os.access(shim, os.X_OK):
        return "unchanged"
    if not dry_run:
        _write(shim, content, mode=0o755)
    return "updated" if existed else "created"


def remove_shim(
    bin_dir: Path, dry_run: bool = False, *, shim_name: str = SHIM_NAME, marker: str = SHIM_MARKER
) -> bool:
    """Remove the named shim if this installer wrote it; True when it did."""
    if not shim_installed(bin_dir, shim_name=shim_name, marker=marker):
        return False
    if not dry_run:
        (Path(bin_dir) / shim_name).unlink()
    return True


_NOT_REQUESTED = "skipped (not requested)"


def _guarded(step: Callable[[], str]) -> str:
    """Run one shim or instruction-file step; a failure becomes its status, never an installer crash."""
    try:
        return step()
    except (OSError, ValueError) as exc:
        return f"error ({type(exc).__name__})"


def _upsert_status(path: Path, dry_run: bool) -> str:
    if not path.parent.is_dir():
        return "skipped (no harness directory)"
    return _guarded(lambda: upsert_block(path, dry_run=dry_run))


def _install_one_shim(
    bin_dir: Path, plugin_root: Path, dry_run: bool, *, shim_name: str, marker: str, script_name: str
) -> tuple[str, bool]:
    status = _guarded(
        lambda: install_shim(
            bin_dir, plugin_root, dry_run=dry_run, shim_name=shim_name, marker=marker, script_name=script_name
        )
    )
    installed = not status.startswith(("skipped", "error"))
    usable = installed and on_path(bin_dir)
    return (f"{status} (not_on_path)" if installed and not usable else status), usable


def install_outline_pull(
    plugin_root: Path,
    use_defaults: bool,
    shim_bin_dir: Path | None,
    instruction_files: Sequence[Path] | None,
    dry_run: bool,
) -> dict[str, str]:
    """Install the shims and the rule block; real-home defaults only when `use_defaults` is set."""
    if use_defaults:
        shim_bin_dir = shim_bin_dir or DEFAULT_SHIM_BIN_DIR
        instruction_files = DEFAULT_INSTRUCTION_FILES if instruction_files is None else instruction_files
    shim_status, usable = _NOT_REQUESTED, False
    extra_statuses = {key: _NOT_REQUESTED for key, _, _, _ in _EXTRA_SHIMS}
    if shim_bin_dir is not None:
        bin_dir, root = shim_bin_dir, Path(plugin_root)
        shim_status, usable = _install_one_shim(
            bin_dir, root, dry_run, shim_name=SHIM_NAME, marker=SHIM_MARKER, script_name="outline.py"
        )
        for key, name, marker, script in _EXTRA_SHIMS:
            extra_statuses[key], _ = _install_one_shim(
                bin_dir, root, dry_run, shim_name=name, marker=marker, script_name=script
            )
    if not instruction_files:
        block_status = _NOT_REQUESTED
    elif not usable:
        block_status = "skipped (shim unavailable)"
    else:
        block_status = ", ".join(_upsert_status(path, dry_run) for path in instruction_files)
    return {"cg_outline_shim": shim_status, **extra_statuses, "instruction_block": block_status}


def _removal_status(removed: Callable[[], bool]) -> str:
    return _guarded(lambda: "removed" if removed() else "absent")


def uninstall_outline_pull(
    use_defaults: bool,
    shim_bin_dir: Path | None,
    instruction_files: Sequence[Path] | None,
    dry_run: bool,
) -> dict[str, str]:
    """Remove the shims and the rule blocks this installer wrote."""
    if use_defaults:
        shim_bin_dir = shim_bin_dir or DEFAULT_SHIM_BIN_DIR
        instruction_files = DEFAULT_INSTRUCTION_FILES if instruction_files is None else instruction_files
    shim_status = _NOT_REQUESTED
    extra_statuses = {key: _NOT_REQUESTED for key, _, _, _ in _EXTRA_SHIMS}
    if shim_bin_dir is not None:
        bin_dir = shim_bin_dir
        shim_status = _removal_status(lambda: remove_shim(bin_dir, dry_run=dry_run))
        for key, name, marker, _ in _EXTRA_SHIMS:
            extra_statuses[key] = _removal_status(
                lambda n=name, m=marker: remove_shim(bin_dir, dry_run=dry_run, shim_name=n, marker=m)  # type: ignore[misc]
            )
    blocks = [
        _removal_status(lambda p=path: remove_block(p, dry_run=dry_run))  # type: ignore[misc]
        for path in instruction_files or ()
    ]
    return {"cg_outline_shim": shim_status, **extra_statuses, "instruction_block": ", ".join(blocks) or _NOT_REQUESTED}
