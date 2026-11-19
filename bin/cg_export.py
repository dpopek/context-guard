#!/usr/bin/env python3
"""Off-hot-path 100% stdlib OTLP/JSON telemetry exporter CLI (`cg export --otel`)."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys
from typing import Any

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from services.export_service import (  # noqa: E402
    build_otel_export_bundle,
    export_otel_to_file,
    post_otel_http,
    render_bundle_bytes,
    validate_endpoint_url,
)

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cg-export", description="Off-hot-path OTLP/JSON telemetry exporter.")
    p.add_argument("--otel", action="store_true", help="Export scrubbed OTLP/JSON spans and logs.")
    p.add_argument("--receipts-path", type=Path, default=None, help="Override receipts.jsonl path.")
    p.add_argument("--ledger-path", type=Path, default=None, help="Optional evidence_events.json path.")
    p.add_argument("--outcomes-path", type=Path, default=None, help="Optional outcomes.json path.")
    p.add_argument("--window-seconds", type=float, default=None, help="Trailing export window in seconds.")
    p.add_argument("--output", type=Path, default=None, help="Atomically write payload to path.")
    p.add_argument("--ndjson", action="store_true", help="Emit one scrubbed event JSON object per line.")
    p.add_argument("--endpoint", type=str, default=None, help="Opt-in HTTP/HTTPS OTLP endpoint URL.")
    p.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds (0.5..30.0).")
    p.add_argument("--service-name", type=str, default="context-guard", help="OTel service.name attribute.")
    p.add_argument("--json", action="store_true", help="Emit structured JSON output.")
    return p


def _cli_err(code: str, detail: str | None = None, exit_code: int = 2) -> int:
    print(json.dumps({"ok": False, "error": code, **({"detail": detail} if detail else {})}))
    return exit_code


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `cg export --otel`."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        ns = _build_parser().parse_args(raw_argv[1:] if raw_argv and raw_argv[0] == "export" else raw_argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else _cli_err("invalid_arguments")
    if not ns.otel:
        return _cli_err("invalid_arguments", "--otel flag is required")
    if ns.window_seconds is not None and (not math.isfinite(float(ns.window_seconds)) or float(ns.window_seconds) < 0.0):
        return _cli_err("invalid_arguments", "--window-seconds must be >= 0")
    if ns.endpoint is not None and (ep_err := validate_endpoint_url(str(ns.endpoint))) is not None:
        return _cli_err(ep_err, "Endpoint must use http:// or https://")

    bundle = build_otel_export_bundle(
        receipts_path=ns.receipts_path,
        ledger_path=ns.ledger_path,
        outcomes_path=ns.outcomes_path,
        window_seconds=ns.window_seconds,
        service_name=str(ns.service_name),
    )
    if not bundle.get("ok"):
        print(json.dumps(bundle))
        return 1
    status_summary: dict[str, Any] = {"ok": True, "exported_events": bundle["exported_events"]}
    if ns.output is not None:
        file_res = export_otel_to_file(bundle, Path(ns.output), ndjson=bool(ns.ndjson))
        if not file_res.get("ok"):
            print(json.dumps(file_res))
            return 1
        status_summary["file"] = file_res
    if ns.endpoint is not None:
        http_res = post_otel_http(bundle, str(ns.endpoint), timeout_seconds=float(ns.timeout))
        if not http_res.get("ok"):
            print(json.dumps(http_res))
            return 2 if http_res.get("error") == "invalid_endpoint_scheme" else 1
        status_summary["http"] = http_res
    if ns.output is None and ns.endpoint is None:
        sys.stdout.write(render_bundle_bytes(bundle, ndjson=bool(ns.ndjson)).decode("utf-8"))
        return 0
    print(json.dumps(status_summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
