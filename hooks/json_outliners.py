"""Specialized JSON and JSONL outliners for MCP step outputs and transcripts."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from hooks.outline import MAX_OUTLINE_FILE_BYTES, OUTLINE_EXTENSIONS, extract_outline_symbols


@dataclass(frozen=True)
class PendingUnwrapWrite:
    """Deferred atomic file write for an unwrapped artifact payload."""

    target_path: Path
    content: str


@dataclass(frozen=True)
class PreparedOutline:
    """In-memory outline result prepared without touching disk for unwrapped artifacts."""

    total_lines: int
    outline_text: str
    unwrapped_target: Path | None = None
    pending_write: PendingUnwrapWrite | None = None

AUTO_OUTLINE_LINE_THRESHOLD = 150
MCP_OUTPUT_OUTLINE_MIN_BYTES = 16 * 1024  # 16 KB minimum before inspecting MCP output.txt
ANTIGRAVITY_FULL_TRANSCRIPT_NAME = "transcript_full.jsonl"
TRANSCRIPT_FILENAMES = frozenset({"transcript.jsonl", ANTIGRAVITY_FULL_TRANSCRIPT_NAME})
ANTIGRAVITY_FULL_TRANSCRIPT_GLOB = f"*/.system_generated/logs/{ANTIGRAVITY_FULL_TRANSCRIPT_NAME}"
MAX_FORMAT_JSON_BYTES = 512 * 1024  # 512 KB cap for pretty-printing 1-line JSON to disk
NON_SYMBOL_OUTLINE_PREFIXES = ("# [WARN:", "# [INFO:", "imports:", "package ")


class SpecialReadTarget(NamedTuple):
    """Normalized classification of MCP step outputs, optional integration spills, and transcript logs."""

    basename: str
    is_mcp_step_output: bool
    is_twg_stdout: bool
    is_transcript_log: bool


def classify_special_read_target(canon: str) -> SpecialReadTarget:
    """Classify a canonical path across POSIX and Windows path separators."""
    norm_path = canon.replace("\\", "/")
    basename = norm_path.rsplit("/", 1)[-1]
    return SpecialReadTarget(
        basename=basename,
        is_mcp_step_output=basename == "output.txt" and "/.system_generated/steps/" in norm_path,
        is_twg_stdout=basename in ("stdout.json", "stdout.compact.json") and "/twg/" in norm_path,
        is_transcript_log=basename in TRANSCRIPT_FILENAMES and "/.system_generated/logs/" in norm_path,
    )


def _write_text_atomic(target_path: Path, text: str) -> str | None:
    """Atomically write text to target_path and return its canonical realpath."""
    tmp_name: str | None = None
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(target_path.parent),
            prefix=f".{target_path.name}.", suffix=".tmp", delete=False,
        ) as tmp_fh:
            tmp_name = tmp_fh.name
            tmp_fh.write(text)
            tmp_fh.flush()
        os.replace(tmp_name, target_path)
        return os.path.realpath(str(target_path))
    except OSError:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        return None


def materialize_unwrap_write(pending: PendingUnwrapWrite | None) -> str | None:
    """Atomically persist a deferred unwrap payload to disk and return its canonical path."""
    if pending is None:
        return None
    return _write_text_atomic(pending.target_path, pending.content)


def finalize_outline_text(prepared: PreparedOutline, actual_unwrapped: str | None) -> str:
    """Reconcile the planned unwrapped path in `prepared.outline_text` with `actual_unwrapped`."""
    if prepared.unwrapped_target is None:
        return prepared.outline_text
    planned_canon = os.path.realpath(str(prepared.unwrapped_target))
    planned_token = f", unwrapped at {planned_canon}"
    if actual_unwrapped:
        return prepared.outline_text.replace(planned_token, f", unwrapped at {actual_unwrapped}")
    return prepared.outline_text.replace(planned_token, "")


def _unwrapped_suffix(target_path: Path | None) -> str:
    return f", unwrapped at {os.path.realpath(str(target_path))}" if target_path is not None else ""


def _json_samples(items: list[Any], label: str) -> list[str]:
    return [f"  {label}[{i}]: {json.dumps(it, ensure_ascii=False)[:240]}" for i, it in enumerate(items[:3])]


def prepare_mcp_step_outline(file_path: Path, st_size: int) -> PreparedOutline | None:
    """Prepare an outline and optional deferred unwrap write for an MCP step output.txt without writing to disk."""
    if st_size < MCP_OUTPUT_OUTLINE_MIN_BYTES or st_size > MAX_OUTLINE_FILE_BYTES:
        return None
    try:
        raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw_text)
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, (dict, list)):
        return None

    if isinstance(data, dict):
        content = data.get("content")
        raw_name = data.get("file_path") or data.get("file_name")
        if isinstance(content, str) and isinstance(raw_name, str) and raw_name.strip():
            safe_name = re.split(r"[/\\]", raw_name.strip())[-1]
            if safe_name and safe_name not in (".", "..", "output.txt"):
                inner_ext = Path(safe_name).suffix.lower()
                lines = content.splitlines()
                total_lines = len(lines)
                if total_lines > AUTO_OUTLINE_LINE_THRESHOLD or len(content) >= MCP_OUTPUT_OUTLINE_MIN_BYTES:
                    target_path = file_path.parent / safe_name
                    pending = PendingUnwrapWrite(target_path=target_path, content=content)
                    planned_canon = os.path.realpath(str(target_path))
                    header = f"# {raw_name.strip()} ({total_lines} LOC, unwrapped at {planned_canon})"
                    if inner_ext in OUTLINE_EXTENSIONS:
                        symbols = extract_outline_symbols(content, inner_ext)
                        if any(not s.lstrip().startswith(NON_SYMBOL_OUTLINE_PREFIXES) for s in symbols):
                            return PreparedOutline(total_lines, f"{header}\n" + "\n".join(symbols), target_path, pending)
                    preview = [f"  L{idx + 1}: {line[:200]}" for idx, line in enumerate(lines[:15])]
                    outline_text = header + "\npreview (first 15 lines):\n" + "\n".join(preview)
                    return PreparedOutline(total_lines, outline_text, target_path, pending)

        rows = data.get("rows")
        if isinstance(rows, list) and len(rows) > 20:
            target_bq: Path | None = None
            pending_bq: PendingUnwrapWrite | None = None
            if st_size <= MAX_FORMAT_JSON_BYTES and len(raw_text.splitlines()) <= 5:
                target_bq = file_path.parent / "output_formatted.json"
                pending_bq = PendingUnwrapWrite(target_bq, json.dumps(data, indent=2, ensure_ascii=False))
            schema_fields: list[str] = []
            schema_obj = data.get("schema")
            if isinstance(schema_obj, dict) and isinstance(schema_obj.get("fields"), list):
                schema_fields = [
                    f"{f['name']}: {f.get('type') or 'ANY'}"
                    for f in schema_obj["fields"]
                    if isinstance(f, dict) and f.get("name")
                ]
            if not schema_fields and isinstance(rows[0], dict):
                schema_fields = [f"{k}: ANY" for k in rows[0]]
            summary_lines = [
                f"# BigQuery/Tabular JSON result ({len(rows)} rows){_unwrapped_suffix(target_bq)} [{st_size} bytes]",
                f"columns: {', '.join(schema_fields)}" if schema_fields else "columns: (untyped)",
                "sample_rows (first 3):",
                *_json_samples(rows, "row"),
            ]
            return PreparedOutline(len(rows), "\n".join(summary_lines), target_bq, pending_bq)

    items_list: list[Any] | None = data if isinstance(data, list) and len(data) > 5 else None
    if items_list is None and isinstance(data, dict):
        items_list = next(
            (v for k in ("items", "results", "values") for v in (data.get(k),) if isinstance(v, list) and len(v) > 5),
            None,
        )

    if items_list is not None:
        target_list: Path | None = None
        pending_list: PendingUnwrapWrite | None = None
        formatted_line_count = max(len(items_list), AUTO_OUTLINE_LINE_THRESHOLD + 1)
        if st_size <= MAX_FORMAT_JSON_BYTES:
            formatted_json = json.dumps(data, indent=2, ensure_ascii=False)
            formatted_line_count = max(len(formatted_json.splitlines()), AUTO_OUTLINE_LINE_THRESHOLD + 1)
            target_list = file_path.parent / "output_formatted.json"
            pending_list = PendingUnwrapWrite(target_list, formatted_json)
        first_keys = [str(k) for k in list(items_list[0].keys())[:10]] if isinstance(items_list[0], dict) else []
        summary_lines = [
            f"# MCP JSON collection ({len(items_list)} items{_unwrapped_suffix(target_list)}) [{st_size} bytes]",
            f"item_keys: {', '.join(first_keys)}" if first_keys else "item_keys: (non-dict)",
            "sample_items (first 3):",
            *_json_samples(items_list, "item"),
        ]
        return PreparedOutline(formatted_line_count, "\n".join(summary_lines), target_list, pending_list)

    return None


def unwrap_and_outline_mcp_output(file_path: Path, st_size: int) -> tuple[int, str, str | None] | None:
    """Outline a large MCP step output.txt; writes the unwrapped inner file next to it."""
    prepared = prepare_mcp_step_outline(file_path, st_size)
    if prepared is None:
        return None
    unwrapped_canon = materialize_unwrap_write(prepared.pending_write)
    return (prepared.total_lines, finalize_outline_text(prepared, unwrapped_canon), unwrapped_canon)


def unwrap_and_outline_mcp_step_output(file_path: Path, st_size: int) -> tuple[int, str, str | None] | None:
    """Backwards-compatible alias for `unwrap_and_outline_mcp_output`."""
    return unwrap_and_outline_mcp_output(file_path, st_size)


def _format_transcript_jsonl_line(line_no: int, raw_bytes: bytes) -> str:
    try:
        loaded = json.loads(raw_bytes.decode("utf-8", errors="replace"))
    except (ValueError, TypeError):
        loaded = {}
    entry: dict[str, Any] = loaded if isinstance(loaded, dict) else {}
    tcalls = entry.get("tool_calls")
    t_names = [str(tc.get("name") or "?") for tc in tcalls if isinstance(tc, dict)] if isinstance(tcalls, list) else []
    tools_str = f" tools=[{','.join(t_names)}]" if t_names else ""
    trunc = entry.get("truncated_fields")
    trunc_str = f" truncated={trunc}" if isinstance(trunc, list) and trunc else ""
    return (
        f"  L{line_no}: step_index={entry.get('step_index', '?')} type={entry.get('type', 'UNKNOWN')}"
        f" source={entry.get('source', 'UNKNOWN')}{tools_str} len={len(raw_bytes)}B{trunc_str}"
    )


def build_transcript_jsonl_outline(
    file_path: Path, st_size: int, max_hash_bytes: int = 10 * 1024 * 1024, start_line: int = 1, end_line: int = -1
) -> tuple[int, str, str | None] | None:
    """Build a streaming step index outline for large transcript.jsonl / transcript_full.jsonl files."""
    if st_size < MCP_OUTPUT_OUTLINE_MIN_BYTES or st_size > max_hash_bytes:
        return None
    first_items: list[tuple[int, bytes]] = []
    span_items: list[tuple[int, bytes]] = []
    last_items: deque[tuple[int, bytes]] = deque(maxlen=15)
    collect_span = start_line > 1 or end_line != -1
    span_end = min(end_line, start_line + 79) if end_line != -1 else (start_line + 79)
    total_lines = 0
    try:
        with open(file_path, "rb") as fh:
            for raw_line in fh:
                total_lines += 1
                if len(first_items) < 3:
                    first_items.append((total_lines, raw_line))
                if collect_span and start_line <= total_lines <= span_end:
                    span_items.append((total_lines, raw_line))
                last_items.append((total_lines, raw_line))
    except OSError:
        return None
    if total_lines == 0:
        return None

    combined_map = dict([*first_items, *span_items, *last_items])
    summary_lines = [f"# {file_path.name} ({total_lines} JSONL lines, {st_size} bytes)"]
    prev_lno = 0
    for lno in sorted(combined_map):
        if prev_lno > 0 and lno > prev_lno + 1:
            summary_lines.append("  ...")
        summary_lines.append(_format_transcript_jsonl_line(lno, combined_map[lno]))
        prev_lno = lno
    return (total_lines, "\n".join(summary_lines), None)

