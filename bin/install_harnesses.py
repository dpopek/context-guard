#!/usr/bin/env python3
"""CLI entrypoint for Context-Guard multi-harness installer and uninstaller."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from bin import update_check  # noqa: E402
from core.platform_io import resolve_plugin_root  # noqa: E402
from hooks.config import cached_raw_config_status  # noqa: E402
from services.installer_service import CLAUDE_MATCHER, check_status, install_all, uninstall_all  # noqa: E402
from services.migration_guard import preflight_migration_check, resolve_effective_config_path  # noqa: E402

__all__ = ["CLAUDE_MATCHER", "DEFAULT_PLUGIN_ROOT", "check_status", "install_all", "main", "uninstall_all"]

_INITIAL_PLUGIN_ROOT = resolve_plugin_root()
DEFAULT_PLUGIN_ROOT = _INITIAL_PLUGIN_ROOT


def _active_plugin_root() -> Path:
    if DEFAULT_PLUGIN_ROOT != _INITIAL_PLUGIN_ROOT:
        return Path(DEFAULT_PLUGIN_ROOT)
    return resolve_plugin_root()


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `--install`, `--uninstall`, and `--status`."""
    parser = argparse.ArgumentParser(description="Manage Context-Guard multi-harness hooks.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--install", action="store_true", help="Install hooks across all harnesses")
    group.add_argument("--uninstall", action="store_true", help="Remove hooks across all harnesses")
    group.add_argument("--status", action="store_true", help="Check installation status")
    parser.add_argument("--dry-run", action="store_true", help="Do not write changes to disk")
    parser.add_argument("--pack-source", default=None, help="Install and activate a Policy API v1 pack directory")
    args = parser.parse_args(argv)

    if args.pack_source and not args.install:
        print("error: --pack-source requires --install", file=sys.stderr)
        return 2
    if args.status:
        print(json.dumps(check_status(), indent=2))
        return 0
    if args.install:
        if args.pack_source:
            try:
                res = install_all(dry_run=args.dry_run, pack_source=Path(args.pack_source))
            except Exception as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
        else:
            raw_cfg, cfg_err = cached_raw_config_status()
            if cfg_err is not None:
                print(f"error: {cfg_err}", file=sys.stderr)
                return 2
            errors, warnings = preflight_migration_check(
                raw_cfg if raw_cfg is not None else {}, config_path=resolve_effective_config_path()
            )
            for w in warnings:
                print(f"warning: {w}", file=sys.stderr)
            if errors:
                for err in errors:
                    print(f"error: {err}", file=sys.stderr)
                return 2
            try:
                res = install_all(dry_run=args.dry_run)
            except Exception as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
        has_error = any(str(v).startswith("error") for v in res.values())
        if not args.dry_run and not has_error:
            update_check.record_install(_active_plugin_root(), datetime.now(timezone.utc))
        print(json.dumps(res, indent=2))
        return 1 if has_error else 0
    if args.uninstall:
        try:
            res = uninstall_all(dry_run=args.dry_run)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        has_error = any(str(v).startswith("error") for v in res.values())
        if not args.dry_run and not has_error:
            update_check.remove_install_record(_active_plugin_root())
        print(json.dumps(res, indent=2))
        return 1 if has_error else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
