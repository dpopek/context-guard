"""Cross-platform stdlib file locking, atomic JSON/byte I/O, diagnostics, and safe coercion."""

from __future__ import annotations

from datetime import datetime, timezone
import errno
import json
import math
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping
import uuid

_posix_fcntl: Any = None
try:
    import fcntl as _posix_fcntl
except ImportError:  # pragma: no cover - Windows
    pass

_win_msvcrt: Any = None
try:
    import msvcrt as _win_msvcrt
except ImportError:  # pragma: no cover - POSIX
    pass

LOCK_SH: int = int(getattr(_posix_fcntl, "LOCK_SH", 1))
LOCK_EX: int = int(getattr(_posix_fcntl, "LOCK_EX", 2))
LOCK_NB: int = int(getattr(_posix_fcntl, "LOCK_NB", 4))
LOCK_UN: int = int(getattr(_posix_fcntl, "LOCK_UN", 8))

_O_FLAGS = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)

__all__ = [
    "LOCK_EX",
    "LOCK_NB",
    "LOCK_SH",
    "LOCK_UN",
    "atomic_write_bytes",
    "check_unsafe_link",
    "coerce_float",
    "coerce_int",
    "flock",
    "now_iso",
    "read_json_object_or_quarantine",
    "read_plugin_version",
    "resolve_plugin_root",
    "safe_finite_int",
    "utc_now_iso_z",
    "warn",
    "write_json_atomic",
]


def flock(
    fd: int | Any,
    operation: int,
    *,
    posix_fcntl: Any = _posix_fcntl,
    win_msvcrt: Any = _win_msvcrt,
) -> None:
    """Cross-platform advisory file lock using fcntl.flock on POSIX and msvcrt.locking on Windows."""
    if posix_fcntl is not None:
        posix_fcntl.flock(fd, operation)
        return
    if win_msvcrt is None:
        return
    raw_fd = fd.fileno() if hasattr(fd, "fileno") else int(fd)
    try:
        os.lseek(raw_fd, 0, os.SEEK_SET)
    except OSError:
        pass
    if operation & LOCK_UN:
        try:
            win_msvcrt.locking(raw_fd, win_msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        return
    if not (operation & (LOCK_EX | LOCK_SH)):
        raise OSError(errno.EINVAL, f"unsupported flock operation: {operation}")
    non_blocking = bool(operation & LOCK_NB)
    if operation & LOCK_EX:
        mode = win_msvcrt.LK_NBLCK if non_blocking else win_msvcrt.LK_LOCK
    else:
        mode = (
            getattr(win_msvcrt, "LK_NBRLCK", win_msvcrt.LK_NBLCK)
            if non_blocking
            else getattr(win_msvcrt, "LK_RLCK", win_msvcrt.LK_LOCK)
        )
    try:
        win_msvcrt.locking(raw_fd, mode, 1)
    except OSError as exc:
        if non_blocking:
            raise BlockingIOError(str(exc)) from exc
        raise


def warn(message: object) -> None:
    """Emit an operator diagnostic to stderr safely without raising or leaving dirty stdio buffers."""
    try:
        text = f"context-guard: {message}\n"
    except Exception:
        text = "context-guard: <unprintable diagnostic>\n"
    try:
        if (stream := sys.stderr) is None:
            return
        if (raw := sys.__stderr__) is not None and stream is raw:
            os.write(raw.fileno(), text.encode("utf-8", errors="replace"))
        else:
            stream.write(text)
            stream.flush()
    except Exception:
        pass


def check_unsafe_link(path: Path) -> bool:
    """Return True if `path` is a symlink, Windows reparse point, or cannot be safely statted."""
    try:
        st = os.lstat(str(path))
        return stat.S_ISLNK(st.st_mode) or bool(
            getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    except OSError as exc:
        return not isinstance(exc, FileNotFoundError)


def atomic_write_bytes(
    target: Path,
    data: bytes,
    *,
    mode: int = 0o600,
    prefix: str = ".cg_tmp.",
) -> None:
    """Atomically write `data` to `target` using O_NOFOLLOW temp creation and os.replace."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.parent / f"{prefix}{target.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    try:
        with os.fdopen(
            os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_FLAGS, mode),
            "wb",
        ) as fh:
            fh.write(data)
        if os.name != "nt":
            os.chmod(str(tmp), mode)
        os.replace(str(tmp), str(target))
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def write_json_atomic(
    target: Path,
    payload: Mapping[str, Any],
    prefix: str = ".cg_json.",
    mode: int | None = None,
) -> None:
    """Serialize `payload` as indented UTF-8 JSON and atomically replace `target`."""
    encoded = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    atomic_write_bytes(target, encoded, mode=(0o600 if mode is None else mode), prefix=prefix)


def read_json_object_or_quarantine(target: Path) -> dict[str, Any] | None:
    """Load a JSON-object file; move corrupt or non-object files aside as `.corrupt-<stamp>`."""
    if not target.is_file():
        return None
    try:
        raw: Any = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except ValueError:
        raw = None
    if isinstance(raw, dict):
        return raw
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    quarantine = target.with_name(f"{target.name}.corrupt-{stamp}")
    try:
        os.replace(str(target), str(quarantine))
        warn(f"telemetry ledger {target} was not a JSON object; moved to {quarantine}")
    except OSError as exc:
        warn(f"telemetry ledger {target} was not a JSON object; quarantine failed: {exc}")
    return None


def resolve_plugin_root(default_root: Path | None = None) -> Path:
    """Resolve plugin root from `CONTEXT_GUARD_HOME`, explicit `default_root`, or checkout root."""
    if (env_home := os.environ.get("CONTEXT_GUARD_HOME", "").strip()):
        return Path(env_home).expanduser().resolve()
    if default_root is not None:
        return Path(default_root).expanduser().resolve()
    return Path(__file__).resolve().parent.parent


def read_plugin_version(
    plugin_root: Path | None = None,
    *,
    default: str = "unavailable",
) -> str:
    """Read `plugin.json['version']` safely, rejecting symlinks and Windows reparse points."""
    candidates: tuple[Path, ...]
    if plugin_root is not None:
        candidates = (Path(plugin_root).expanduser() / "plugin.json",)
    else:
        resolved = resolve_plugin_root()
        checkout_manifest = Path(__file__).resolve().parent.parent / "plugin.json"
        if resolved / "plugin.json" == checkout_manifest:
            candidates = (checkout_manifest,)
        else:
            candidates = (resolved / "plugin.json", checkout_manifest)
    for manifest in candidates:
        if check_unsafe_link(manifest) or not manifest.is_file():
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if isinstance(data, Mapping) and isinstance((raw_ver := data.get("version")), str):
            ver = raw_ver.strip()
            if ver:
                return ver
    return default


def now_iso() -> str:
    """Return current UTC ISO-8601 timestamp with second precision (`+00:00`)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def utc_now_iso_z() -> str:
    """Return current UTC ISO-8601 timestamp formatted with trailing `Z`."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def coerce_int(value: Any, default: int = 0) -> int:
    """Coerce ints, numeric strings, and finite floats to int; return `default` on bool/None/NaN/Inf."""
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else default
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return default
        try:
            return int(stripped)
        except ValueError:
            pass
    else:
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            pass
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return int(number) if math.isfinite(number) else default


def coerce_float(value: Any, default: float = 0.0) -> float:
    """Coerce numeric inputs to finite float; return `default` on bool, None, NaN, or Infinity."""
    if value is None or isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if math.isfinite(number) else default


def safe_finite_int(raw: Any, default: int = 0) -> int:
    """Coerce ints and finite floats to int without raising on bool, strings, NaN, or Infinity."""
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    return int(raw) if isinstance(raw, float) and math.isfinite(raw) else default
