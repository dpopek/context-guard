#!/usr/bin/env python3
"""Release check for team installs: installed vs checked-out vs newest tagged version, cached for 24 hours."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

fcntl: Any
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    from hooks import file_io as fcntl

from bin.harness_status import check_status  # noqa: E402
from hooks.state_store import resolve_plugin_root, warn  # noqa: E402
from hooks.telemetry import read_json_object_or_quarantine, write_json_atomic  # noqa: E402

ROOT = resolve_plugin_root()

CHECK_INTERVAL = timedelta(hours=24)
GIT_TIMEOUT_S = 10
NO_GIT_CHECKOUT = "no git checkout"
INSTALL_RECORD = "install.json"
UPDATE_RECORD = "update.json"
UPDATE_LOCK = "update.lock"
UPDATE_REFRESH_LOCK = "update_refresh.lock"

_HELD_UPDATE_LOCKS = threading.local()


def _held_lock_set() -> set[str]:
    held = getattr(_HELD_UPDATE_LOCKS, "paths", None)
    if held is None:
        held = set()
        _HELD_UPDATE_LOCKS.paths = held
    return held


@contextmanager
def update_lock(
    telemetry_dir: Path,
    *,
    non_blocking: bool = False,
    lock_name: str = UPDATE_LOCK,
) -> Iterator[bool]:
    """Acquire an exclusive flock on `telemetry_dir / lock_name` opened in `'a+'` mode (never `'w'`)."""
    try:
        telemetry_dir.mkdir(parents=True, exist_ok=True)
        lock_path = telemetry_dir / lock_name
        canon = os.path.realpath(lock_path)
    except OSError as exc:
        if not non_blocking:
            warn(f"update lock skipped: {type(exc).__name__}: {exc}")
        yield False
        return

    held = _held_lock_set()
    if canon in held:
        yield True
        return

    try:
        fh = open(lock_path, "a+", encoding="utf-8")
    except OSError as exc:
        if not non_blocking:
            warn(f"update lock skipped: {type(exc).__name__}: {exc}")
        yield False
        return

    flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if non_blocking else 0)
    try:
        fcntl.flock(fh.fileno(), flags)
    except BlockingIOError:
        fh.close()
        yield False
        return
    except OSError as exc:
        fh.close()
        if not non_blocking:
            warn(f"update lock skipped: {type(exc).__name__}: {exc}")
        yield False
        return

    held.add(canon)
    try:
        yield True
    finally:
        held.discard(canon)
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        fh.close()

_VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
_TAG_REF_RE = re.compile(r"refs/tags/(v\d+\.\d+\.\d+)(?:\^\{\})?")

Version = Tuple[int, int, int]
RunGit = Callable[[list], Any]


def parse_version(text: Optional[str]) -> Optional[Version]:
    """(major, minor, patch) for 'X.Y.Z' or 'vX.Y.Z'; None for anything else, pre-releases included."""
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.fullmatch(text.strip())
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def latest_tag(ls_remote_output: str) -> Optional[str]:
    """Highest 'vX.Y.Z' tag in `git ls-remote --tags` output as 'X.Y.Z'; a peeled '^{}' line counts once."""
    versions: set[Tuple[int, int, int]] = set()
    for line in ls_remote_output.splitlines():
        _, _, ref = line.partition("\t")
        match = _TAG_REF_RE.fullmatch(ref.strip())
        if match:
            parsed = parse_version(match[1])
            if parsed is not None:
                versions.add(parsed)
    if not versions:
        return None
    return ".".join(str(part) for part in max(versions))


def evaluate_update(
    installed: Optional[str], local: Optional[str], latest: Optional[str], ever_installed: bool
) -> str:
    """'update_available', 'install_pending' or 'current', first match wins."""
    local_v = parse_version(local)
    if local_v is None:
        return "current"
    latest_v = parse_version(latest)
    if latest_v is not None and latest_v > local_v:
        return "update_available"
    installed_v = parse_version(installed)
    if ever_installed and (installed_v is None or installed_v < local_v):
        return "install_pending"
    return "current"


def is_update_stale(update: Optional[Dict[str, Any]], now: datetime) -> bool:
    """True when `update` has no timezone-aware checked_at or it is at least 24 hours old."""
    stamp = update.get("checked_at") if isinstance(update, dict) else None
    if not isinstance(stamp, str):
        return True
    try:
        checked = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return True
    if checked.tzinfo is None:
        return True
    return now - checked >= CHECK_INTERVAL


def read_local_version(plugin_root: Path) -> Optional[str]:
    """`version` from the checked-out plugin.json, or None when it cannot be read."""
    try:
        version = json.loads((plugin_root / "plugin.json").read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError, AttributeError):
        return None
    return version if isinstance(version, str) else None


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text_field(record: Dict[str, Any], key: str) -> Optional[str]:
    value = record.get(key)
    return value if isinstance(value, str) else None


def run_git(args: list) -> subprocess.CompletedProcess:
    """Run git without ever waiting on a person: no credential, GCM or ssh passphrase prompt, 10 s cap."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    env.setdefault("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
    env.setdefault("GCM_INTERACTIVE", "never")
    return subprocess.run(args, capture_output=True, text=True, timeout=GIT_TIMEOUT_S, env=env, check=False)


def hooks_registered() -> bool:
    """Whether a harness config already carries the hook: an install that predates install.json."""
    try:
        return any(check_status().values())
    except (OSError, ValueError):
        return False


def _resolve_run_git(explicit: Optional[RunGit]) -> RunGit:
    return explicit if explicit is not None else run_git


def _resolve_hooks_registered(explicit: Optional[Callable[[], bool]]) -> Callable[[], bool]:
    return explicit if explicit is not None else hooks_registered


def _ls_remote_latest(plugin_root: Path, run_git: RunGit, previous: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """(latest, remote_error); a failed call keeps `previous` and names the failure."""
    try:
        proc = run_git(["git", "-C", str(plugin_root), "ls-remote", "--tags", "origin"])
    except (OSError, subprocess.SubprocessError) as exc:
        return previous, type(exc).__name__
    if proc.returncode != 0:
        return previous, f"exit {proc.returncode}"
    return latest_tag(proc.stdout or ""), None


def refresh_update_state(
    plugin_root: Path,
    now: datetime,
    run_git: Optional[RunGit] = None,
    *,
    force: bool = False,
    remote: bool = True,
    hooks_registered: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Recompute and write telemetry/update.json; the remote is asked at most once per 24 hours."""
    effective_run_git = _resolve_run_git(run_git)
    effective_hooks_registered = _resolve_hooks_registered(hooks_registered)
    telemetry_dir = plugin_root / "telemetry"
    update_path = telemetry_dir / UPDATE_RECORD
    with update_lock(telemetry_dir, non_blocking=False):
        try:
            previous = read_json_object_or_quarantine(update_path) or {}
        except OSError:
            previous = {}

    did_remote = False
    fetched_latest: Optional[str] = None
    fetched_error: Optional[str] = None
    if remote and (force or is_update_stale(previous, now)):
        did_remote = True
        prev_latest = _text_field(previous, "latest")
        if (plugin_root / ".git").exists():
            fetched_latest, fetched_error = _ls_remote_latest(plugin_root, effective_run_git, prev_latest)
        else:
            fetched_latest = prev_latest
            fetched_error = NO_GIT_CHECKOUT

    with update_lock(telemetry_dir, non_blocking=False):
        try:
            current_prev = read_json_object_or_quarantine(update_path) or {}
        except OSError:
            current_prev = {}
        try:
            install = read_json_object_or_quarantine(telemetry_dir / INSTALL_RECORD) or {}
        except OSError:
            install = {}
        installed = _text_field(install, "version")
        if did_remote:
            checked_at: Optional[str] = _iso(now)
            latest = (
                fetched_latest
                if fetched_error is None or fetched_latest is not None
                else _text_field(current_prev, "latest")
            )
            remote_error = fetched_error
        else:
            checked_at = _text_field(current_prev, "checked_at")
            latest = _text_field(current_prev, "latest")
            remote_error = _text_field(current_prev, "remote_error")
        local = read_local_version(plugin_root)
        ever_installed = installed is not None or effective_hooks_registered()
        state = {
            "checked_at": checked_at,
            "installed": installed,
            "local": local,
            "latest": latest,
            "state": evaluate_update(installed, local, latest, ever_installed),
            "remote_error": remote_error,
        }
        try:
            telemetry_dir.mkdir(parents=True, exist_ok=True)
            write_json_atomic(update_path, state, ".update-")
        except OSError as exc:
            warn(f"update state save skipped: {type(exc).__name__}: {exc}")
    return state


def record_install(plugin_root: Path, now: datetime) -> Dict[str, Any]:
    """Write telemetry/install.json for the checked-out version, then refresh update.json without the network."""
    telemetry_dir = plugin_root / "telemetry"
    local_ver = read_local_version(plugin_root)
    record = {"version": local_ver, "installed_at": _iso(now)}
    with update_lock(telemetry_dir, non_blocking=False):
        wrote_install = False
        try:
            telemetry_dir.mkdir(parents=True, exist_ok=True)
            write_json_atomic(telemetry_dir / INSTALL_RECORD, record, ".install-")
            wrote_install = True
        except OSError as exc:
            warn(f"install record save skipped: {type(exc).__name__}: {exc}")
        state = refresh_update_state(plugin_root, now, remote=False)
        if not wrote_install:
            ever_installed = local_ver is not None or _resolve_hooks_registered(None)()
            state = {
                **state,
                "installed": local_ver,
                "state": evaluate_update(local_ver, state.get("local"), state.get("latest"), ever_installed),
            }
        return state


def remove_install_record(plugin_root: Path) -> None:
    telemetry_dir = plugin_root / "telemetry"
    with update_lock(telemetry_dir, non_blocking=False):
        try:
            (telemetry_dir / INSTALL_RECORD).unlink(missing_ok=True)
        except OSError as exc:
            warn(f"install record removal skipped: {type(exc).__name__}: {exc}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check for a newer Context-Guard release tag.")
    parser.add_argument("--force", action="store_true", help="Ignore the 24-hour cache")
    parser.add_argument("--plugin-root", type=Path, default=resolve_plugin_root(), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    telemetry_dir = args.plugin_root / "telemetry"
    lock_path = telemetry_dir / UPDATE_LOCK
    # Every attempt stamps update.lock in non-truncating mode so HUD backoff sees recent attempts.
    try:
        telemetry_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "a+", encoding="utf-8"):
            os.utime(lock_path, None)
    except OSError:
        return 0
    with update_lock(telemetry_dir, non_blocking=True) as can_proceed:
        if not can_proceed:
            return 0
    with update_lock(telemetry_dir, non_blocking=True, lock_name=UPDATE_REFRESH_LOCK) as acquired:
        if not acquired:
            return 0
        state = refresh_update_state(
            args.plugin_root,
            datetime.now(timezone.utc),
            force=args.force,
        )
    print(json.dumps(state, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
