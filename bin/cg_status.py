#!/usr/bin/env python3
"""CLI entrypoint for Context-Guard status line, telemetry, outcomes, doctor, and usage reports."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from bin.update_check import is_update_stale  # noqa: E402
from core.platform_io import warn  # noqa: E402
from hooks.outcomes import load_outcomes  # noqa: E402
from hooks.telemetry import load_telemetry_stats  # noqa: E402
from services import replay_benchmark, status_service, token_usage  # noqa: E402
from services.outcomes_report import render_outcomes_report  # noqa: E402
from spool.store import inspect_spool_health  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Format Context-Guard token telemetry.")
    parser.add_argument("--stats-path", type=Path, default=None, help="Path to telemetry stats.json")
    parser.add_argument("--outcomes-path", type=Path, default=None, help="Path to intervention outcomes ledger")
    parser.add_argument("--usage-path", type=Path, default=None, help="Path to token usage ledger")
    parser.add_argument("--update-path", type=Path, default=None, help="Path to update.json")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--short", action="store_true", help="Single-line status string")
    group.add_argument("--claude-hud", action="store_true", help="Claude Code statusLine HUD")
    group.add_argument("--markdown", action="store_true", help="Full Markdown report")
    group.add_argument("--json", action="store_true", help="Raw JSON stats")
    group.add_argument("--public-json", action="store_true", help="Scrubbed public JSON telemetry bundle")
    group.add_argument("--outcomes", action="store_true", help="Markdown report of outcomes per harness x model")
    group.add_argument("--usage", action="store_true", help="Markdown report of real token usage and preamble")
    group.add_argument("--doctor", action="store_true", help="Environment and harness self-diagnostics report")
    group.add_argument("--replay", action="store_true", help="Run isolated deterministic multi-harness replay")
    group.add_argument("--benchmark", action="store_true", help="Run isolated deterministic latency/savings benchmark")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `cg_status.py` / `cg status`."""
    args = _build_parser().parse_args(argv)
    eff_update_path = args.update_path if args.update_path is not None else status_service.DEFAULT_UPDATE_PATH

    try:
        if not (args.doctor or args.replay or args.benchmark):
            uses_default = (
                (args.outcomes_path is None) if args.outcomes else (args.stats_path is None and args.usage_path is None)
            )
            if uses_default and (cw := status_service.detect_checkout_telemetry_mismatch()):
                warn(cw)
        if args.doctor:
            doc = status_service.run_doctor()
            print(status_service.render_doctor_report(doc), end="")
            return 0 if doc.get("ok") else 1
        if args.replay:
            rep = replay_benchmark.run_deterministic_replay()
            print(replay_benchmark.render_replay_report(rep), end="")
            return 0 if rep.get("ok") else 1
        if args.benchmark:
            bench = replay_benchmark.run_deterministic_benchmark()
            print(replay_benchmark.render_benchmark_report(bench), end="")
            return 0 if bench.get("ok") else 1
        if args.outcomes:
            u_path = args.usage_path or (token_usage.DEFAULT_USAGE_PATH if args.outcomes_path is None else None)
            u_state = token_usage.restore_usage_state(u_path) if u_path and u_path.is_file() else None
            rcpt_sum = inspect_spool_health()["receipts"] if args.outcomes_path is None else None
            print(render_outcomes_report(load_outcomes(args.outcomes_path), u_state, receipt_summary=rcpt_sum), end="")
            return 0
        stats = load_telemetry_stats(args.stats_path)
        if args.claude_hud:
            stdin_data = status_service.read_nonblocking_stdin_json()
            update = status_service.load_update(eff_update_path)
            if is_update_stale(update, datetime.now(timezone.utc)) and not status_service.update_attempt_is_recent(
                eff_update_path, time.time()
            ):
                status_service.spawn_update_check()
            print(status_service.render_claude_hud(stdin_data, stats, update))
            return 0
        if args.usage:
            print("\n".join(status_service.usage_lines(stats, args.usage_path, args.outcomes_path)).lstrip("\n"))
            return 0
        if args.markdown:
            report = (
                status_service.render_markdown_report(stats)
                + "\n".join(status_service.usage_lines(stats, args.usage_path, args.outcomes_path))
                + "\n"
            )
            update_line = status_service.render_update_line(
                status_service.load_update(eff_update_path), status_service.ROOT
            )
            print(report + (f"\n{update_line}\n" if update_line else ""), end="")
            return 0
        if args.public_json:
            rcpt_sum = inspect_spool_health()["receipts"] if args.outcomes_path is None else None
            bundle = replay_benchmark.build_public_json_bundle(
                stats,
                status_service.usage_json(stats, args.usage_path, args.outcomes_path),
                load_outcomes(args.outcomes_path),
                status_service.load_update(eff_update_path),
                receipt_summary=rcpt_sum,
            )
            print(json.dumps(bundle, indent=2))
            return 0
        if args.json:
            payload = {
                **stats,
                "token_usage": status_service.usage_json(stats, args.usage_path, args.outcomes_path),
                "update": status_service.load_update(eff_update_path),
            }
            print(json.dumps(payload, indent=2))
            return 0
        print(status_service.render_short_status(stats))
        return 0
    except Exception as exc:
        warn(f"status line failed: {type(exc).__name__}: {exc}")
        if getattr(args, "json", False) or getattr(args, "public_json", False):
            print(json.dumps({"error": type(exc).__name__}))
        else:
            print("CG: n/a")
        return 0 if getattr(args, "claude_hud", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
