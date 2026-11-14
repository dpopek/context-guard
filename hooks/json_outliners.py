"""Specialized JSON and JSONL outliners for MCP step outputs, TWG CLI spills, and transcripts."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from hooks.outline import (
    MAX_OUTLINE_FILE_BYTES,
    OUTLINE_EXTENSIONS,
    extract_outline_symbols,
)


@dataclass(frozen=True)
class PendingUnwrapWrite:
    """Deferred atomic file write for an unwrapped MCP or TWG payload."""

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
TWG_STDOUT_OUTLINE_MIN_BYTES = 6 * 1024  # 6 KB minimum before outlining TWG stdout*.json
TWG_STDOUT_FILENAMES = frozenset({"stdout.json", "stdout.compact.json"})
ANTIGRAVITY_FULL_TRANSCRIPT_NAME = "transcript_full.jsonl"
TRANSCRIPT_FILENAMES = frozenset({"transcript.jsonl", ANTIGRAVITY_FULL_TRANSCRIPT_NAME})
ANTIGRAVITY_FULL_TRANSCRIPT_GLOB = f"*/.system_generated/logs/{ANTIGRAVITY_FULL_TRANSCRIPT_NAME}"
MAX_FORMAT_JSON_BYTES = 512 * 1024  # 512 KB cap for pretty-printing 1-line JSON to disk
NON_SYMBOL_OUTLINE_PREFIXES = ("# [WARN:", "# [INFO:", "imports:", "package ")


class SpecialReadTarget(NamedTuple):
    """Normalized classification of MCP step outputs, TWG spills, and transcript logs."""

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
        is_twg_stdout=basename in TWG_STDOUT_FILENAMES and "/twg/" in norm_path,
        is_transcript_log=(
            basename in TRANSCRIPT_FILENAMES and "/.system_generated/logs/" in norm_path
        ),
    )


def _write_text_atomic(target_path: Path, text: str) -> str | None:
    """Atomically write text to target_path and return its canonical realpath."""
    tmp_name: str | None = None
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(target_path.parent),
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            delete=False,
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
            safe_name = os.path.basename(raw_name.strip())
            if safe_name and safe_name not in (".", "..", "output.txt"):
                inner_ext = Path(safe_name).suffix.lower()
                lines = content.splitlines()
                total_lines = len(lines)
                if (
                    total_lines > AUTO_OUTLINE_LINE_THRESHOLD
                    or len(content) >= MCP_OUTPUT_OUTLINE_MIN_BYTES
                ):
                    target_path = file_path.parent / safe_name
                    pending = PendingUnwrapWrite(target_path=target_path, content=content)
                    planned_canon = os.path.realpath(str(target_path))
                    header = (
                        f"# {raw_name.strip()} ({total_lines} LOC, unwrapped at {planned_canon})"
                    )
                    if inner_ext in OUTLINE_EXTENSIONS:
                        symbols = extract_outline_symbols(content, inner_ext)
                        has_real_symbols = any(
                            not s.lstrip().startswith(NON_SYMBOL_OUTLINE_PREFIXES)
                            for s in symbols
                        )
                        if has_real_symbols:
                            outline_text = header + "\n" + "\n".join(symbols)
                            return PreparedOutline(
                                total_lines=total_lines,
                                outline_text=outline_text,
                                unwrapped_target=target_path,
                                pending_write=pending,
                            )
                    preview_lines = [
                        f"  L{idx + 1}: {line[:200]}" for idx, line in enumerate(lines[:15])
                    ]
                    outline_text = (
                        header + "\npreview (first 15 lines):\n" + "\n".join(preview_lines)
                    )
                    return PreparedOutline(
                        total_lines=total_lines,
                        outline_text=outline_text,
                        unwrapped_target=target_path,
                        pending_write=pending,
                    )

        rows = data.get("rows")
        if isinstance(rows, list) and len(rows) > 20:
            target_bq: Path | None = None
            pending_bq: PendingUnwrapWrite | None = None
            if st_size <= MAX_FORMAT_JSON_BYTES and len(raw_text.splitlines()) <= 5:
                formatted_bq = json.dumps(data, indent=2, ensure_ascii=False)
                target_bq = file_path.parent / "output_formatted.json"
                pending_bq = PendingUnwrapWrite(target_path=target_bq, content=formatted_bq)
            schema_fields: list[str] = []
            schema_obj = data.get("schema")
            if isinstance(schema_obj, dict) and isinstance(schema_obj.get("fields"), list):
                for field in schema_obj["fields"]:
                    if isinstance(field, dict) and field.get("name"):
                        f_type = field.get("type") or "ANY"
                        schema_fields.append(f"{field['name']}: {f_type}")
            if not schema_fields and isinstance(rows[0], dict):
                schema_fields = [f"{k}: ANY" for k in rows[0]]
            sample_lines = [
                f"  row[{idx}]: {json.dumps(row, ensure_ascii=False)[:240]}"
                for idx, row in enumerate(rows[:3])
            ]
            planned_bq = os.path.realpath(str(target_bq)) if target_bq is not None else None
            loc_suffix = f", unwrapped at {planned_bq}" if planned_bq else ""
            summary_lines = [
                f"# BigQuery/Tabular JSON result ({len(rows)} rows){loc_suffix} [{st_size} bytes]",
                f"columns: {', '.join(schema_fields)}" if schema_fields else "columns: (untyped)",
                "sample_rows (first 3):",
                *sample_lines,
            ]
            return PreparedOutline(
                total_lines=len(rows),
                outline_text="\n".join(summary_lines),
                unwrapped_target=target_bq,
                pending_write=pending_bq,
            )

    items_list: list[Any] | None = None
    if isinstance(data, list) and len(data) > 5:
        items_list = data
    elif isinstance(data, dict) and isinstance(data.get("items"), list) and len(data["items"]) > 5:
        items_list = data["items"]

    if items_list is not None:
        target_list: Path | None = None
        pending_list: PendingUnwrapWrite | None = None
        formatted_line_count = max(len(items_list), AUTO_OUTLINE_LINE_THRESHOLD + 1)
        if st_size <= MAX_FORMAT_JSON_BYTES:
            formatted_json = json.dumps(data, indent=2, ensure_ascii=False)
            formatted_line_count = max(
                len(formatted_json.splitlines()), AUTO_OUTLINE_LINE_THRESHOLD + 1
            )
            target_list = file_path.parent / "output_formatted.json"
            pending_list = PendingUnwrapWrite(target_path=target_list, content=formatted_json)
        first_keys = (
            [str(k) for k in list(items_list[0].keys())[:10]]
            if isinstance(items_list[0], dict)
            else []
        )
        planned_list = os.path.realpath(str(target_list)) if target_list is not None else None
        loc_suffix = f", unwrapped at {planned_list}" if planned_list else ""
        header = f"# MCP JSON collection ({len(items_list)} items{loc_suffix}) [{st_size} bytes]"
        keys_line = f"item_keys: {', '.join(first_keys)}" if first_keys else "item_keys: (non-dict)"
        sample_lines = [
            f"  item[{idx}]: {json.dumps(item, ensure_ascii=False)[:240]}"
            for idx, item in enumerate(items_list[:3])
        ]
        summary_lines = [
            header,
            keys_line,
            "sample_items (first 3):",
            *sample_lines,
        ]
        return PreparedOutline(
            total_lines=formatted_line_count,
            outline_text="\n".join(summary_lines),
            unwrapped_target=target_list,
            pending_write=pending_list,
        )

    return None


def unwrap_and_outline_mcp_output(
    file_path: Path, st_size: int
) -> tuple[int, str, str | None] | None:
    """Outline a large MCP step output.txt; writes the unwrapped inner file next to it."""
    prepared = prepare_mcp_step_outline(file_path, st_size)
    if prepared is None:
        return None
    unwrapped_canon = materialize_unwrap_write(prepared.pending_write)
    outline_text = finalize_outline_text(prepared, unwrapped_canon)
    return (prepared.total_lines, outline_text, unwrapped_canon)


def unwrap_and_outline_mcp_step_output(
    file_path: Path, st_size: int
) -> tuple[int, str, str | None] | None:
    """Backwards-compatible alias for `unwrap_and_outline_mcp_output`."""
    return unwrap_and_outline_mcp_output(file_path, st_size)


def _format_transcript_jsonl_line(line_no: int, raw_bytes: bytes) -> str:
    try:
        entry = json.loads(raw_bytes.decode("utf-8", errors="replace"))
    except (ValueError, TypeError):
        entry = {}
    if not isinstance(entry, dict):
        entry = {}
    idx = entry.get("step_index", "?")
    etype = entry.get("type", "UNKNOWN")
    esource = entry.get("source", "UNKNOWN")
    tcalls = entry.get("tool_calls")
    tools_str = ""
    if isinstance(tcalls, list) and tcalls:
        t_names = [str(tc.get("name") or "?") for tc in tcalls if isinstance(tc, dict)]
        if t_names:
            tools_str = f" tools=[{','.join(t_names)}]"
    trunc = entry.get("truncated_fields")
    trunc_str = f" truncated={trunc}" if isinstance(trunc, list) and trunc else ""
    return f"  L{line_no}: step_index={idx} type={etype} source={esource}{tools_str} len={len(raw_bytes)}B{trunc_str}"


def build_transcript_jsonl_outline(
    file_path: Path,
    st_size: int,
    max_hash_bytes: int = 10 * 1024 * 1024,
    start_line: int = 1,
    end_line: int = -1,
) -> tuple[int, str, str | None] | None:
    """Build a streaming step index outline for large transcript.jsonl / transcript_full.jsonl files."""
    if st_size < MCP_OUTPUT_OUTLINE_MIN_BYTES or st_size > max_hash_bytes:
        return None
    first_items: list[tuple[int, bytes]] = []
    span_items: list[tuple[int, bytes]] = []
    last_items: deque[tuple[int, bytes]] = deque(maxlen=15)
    collect_span = start_line > 1 or end_line != -1
    span_end = (
        min(end_line, start_line + 79) if end_line != -1 else (start_line + 79)
    )
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

    combined_map: dict[int, bytes] = {}
    for lno, raw_b in first_items:
        combined_map[lno] = raw_b
    for lno, raw_b in span_items:
        combined_map[lno] = raw_b
    for lno, raw_b in last_items:
        combined_map[lno] = raw_b

    summary_lines = [f"# {file_path.name} ({total_lines} JSONL lines, {st_size} bytes)"]
    prev_lno = 0
    for lno in sorted(combined_map):
        if prev_lno > 0 and lno > prev_lno + 1:
            summary_lines.append("  ...")
        summary_lines.append(_format_transcript_jsonl_line(lno, combined_map[lno]))
        prev_lno = lno
    return (total_lines, "\n".join(summary_lines), None)


def _extract_adf_text(node: Any) -> str:
    """Recursively extract plain text from an Atlassian Document Format (ADF) node or string."""
    if node is None:
        return ""
    if isinstance(node, str):
        return node.strip()
    if isinstance(node, list):
        parts = [_extract_adf_text(child) for child in node]
        return "".join(p for p in parts if p)
    if isinstance(node, dict):
        ntype = str(node.get("type") or "")
        if ntype == "text":
            return str(node.get("text") or "")
        if ntype == "hardBreak":
            return "\n"
        children = node.get("content")
        inner = _extract_adf_text(children) if isinstance(children, list) else ""
        if ntype in ("paragraph", "heading", "listItem", "codeBlock", "blockquote"):
            return inner + "\n" if inner else ""
        return inner
    return ""


def _safe_nested_name(obj: Any, key: str = "name") -> str:
    if isinstance(obj, dict):
        val = obj.get(key) or obj.get("displayName") or obj.get("value")
        return str(val) if val is not None else "-"
    return str(obj) if obj is not None else "-"


def _format_twg_workitem(item: dict[str, Any]) -> list[str]:
    raw_fields = item.get("fields")
    fields = raw_fields if isinstance(raw_fields, dict) else item
    key = str(item.get("key") or fields.get("key") or "?")
    summary = str(fields.get("summary") or "")
    status = _safe_nested_name(fields.get("status"))
    itype = _safe_nested_name(fields.get("issuetype"))
    prio = _safe_nested_name(fields.get("priority"))
    assignee = _safe_nested_name(fields.get("assignee"), "displayName")
    reporter = _safe_nested_name(fields.get("reporter"), "displayName")
    labels = fields.get("labels")
    labels_str = ", ".join(str(x) for x in labels) if isinstance(labels, list) and labels else "-"

    out = [
        f"## {key}: {summary}",
        f"  status: {status} | type: {itype} | priority: {prio}",
        f"  assignee: {assignee} | reporter: {reporter} | labels: {labels_str}",
    ]
    desc_text = _extract_adf_text(fields.get("description")).strip()
    if desc_text:
        out.append("  description:")
        for dline in desc_text[:1200].splitlines()[:20]:
            out.append(f"    {dline}")
    comment_container = fields.get("comment")
    comments = (
        comment_container.get("comments")
        if isinstance(comment_container, dict)
        and isinstance(comment_container.get("comments"), list)
        else []
    )
    if comments:
        out.append(f"  comments ({len(comments)} total, showing last {min(5, len(comments))}):")
        for c in comments[-5:]:
            if not isinstance(c, dict):
                continue
            author = _safe_nested_name(c.get("author"), "displayName")
            created = str(c.get("created") or "")[:19]
            cbody = _extract_adf_text(c.get("body")).strip().replace("\n", " ")[:400]
            out.append(f"    - [{created}] {author}: {cbody}")
    return out


def prepare_twg_stdout_outline(
    file_path: Path, st_size: int, cache_dir: Path | None = None
) -> PreparedOutline | None:
    """Prepare structured summary (or inline payload if <6 KB without disk writes) for TWG CLI stdout*.json files."""
    if st_size <= 0 or st_size > MAX_OUTLINE_FILE_BYTES:
        return None
    try:
        raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        data_obj = json.loads(raw_text)
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data_obj, dict):
        return None

    lines = raw_text.splitlines()
    total_lines = len(lines)
    formatted_text = raw_text
    sibling_pretty = file_path.parent / "stdout.json"
    if file_path.name == "stdout.compact.json" and sibling_pretty.is_file():
        try:
            formatted_text = sibling_pretty.read_text(encoding="utf-8", errors="replace")
            lines = formatted_text.splitlines()
            total_lines = len(lines)
        except OSError:
            if st_size <= MAX_FORMAT_JSON_BYTES:
                formatted_text = json.dumps(data_obj, indent=2, ensure_ascii=False)
                lines = formatted_text.splitlines()
                total_lines = len(lines)
    elif total_lines <= 5 and st_size <= MAX_FORMAT_JSON_BYTES:
        formatted_text = json.dumps(data_obj, indent=2, ensure_ascii=False)
        lines = formatted_text.splitlines()
        total_lines = len(lines)

    command = str(data_obj.get("command") or "twg")
    if st_size < TWG_STDOUT_OUTLINE_MIN_BYTES:
        inline_text = (
            f"# TWG CLI output ({command}, {total_lines} lines, {st_size} bytes — full payload inline)\n"
            f"```json\n{formatted_text.strip()}\n```"
        )
        return PreparedOutline(
            total_lines=total_lines,
            outline_text=inline_text,
            unwrapped_target=None,
            pending_write=None,
        )

    target_path: Path | None = None
    pending: PendingUnwrapWrite | None = None
    if cache_dir is not None:
        run_tag = re.sub(
            r"[^A-Za-z0-9._-]",
            "_",
            f"{file_path.parent.parent.name}_{file_path.parent.name}",
        )
        target_path = cache_dir / f"{run_tag}_stdout_formatted.json"
        pending = PendingUnwrapWrite(target_path=target_path, content=formatted_text)
    elif total_lines != len(raw_text.splitlines()):
        target_path = file_path.parent / "stdout_formatted.json"
        pending = PendingUnwrapWrite(target_path=target_path, content=formatted_text)

    payload = data_obj.get("data")
    header = f"# TWG CLI output ({command}, {total_lines} lines, {st_size} bytes)"
    if target_path is not None:
        planned_canon = os.path.realpath(str(target_path))
        header = (
            f"# TWG CLI output ({command}, {total_lines} lines, {st_size} bytes, "
            f"unwrapped at {planned_canon})"
        )
    summary_lines = [header]

    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        for item in payload[:5]:
            if isinstance(item, dict):
                summary_lines.extend(_format_twg_workitem(item))
        return PreparedOutline(
            total_lines=total_lines,
            outline_text="\n".join(summary_lines),
            unwrapped_target=target_path,
            pending_write=pending,
        )

    if isinstance(payload, dict):
        if "key" in payload and ("summary" in payload or "fields" in payload):
            summary_lines.extend(_format_twg_workitem(payload))
            return PreparedOutline(
                total_lines=total_lines,
                outline_text="\n".join(summary_lines),
                unwrapped_target=target_path,
                pending_write=pending,
            )

        issues = payload.get("issues")
        if isinstance(issues, list) and issues:
            summary_lines.append(f"issues ({len(issues)} returned):")
            for issue in issues[:25]:
                if not isinstance(issue, dict):
                    continue
                raw_ifields = issue.get("fields")
                ifields = raw_ifields if isinstance(raw_ifields, dict) else issue
                ikey = str(issue.get("key") or ifields.get("key") or "?")
                isum = str(ifields.get("summary") or "")
                istat = _safe_nested_name(ifields.get("status"))
                iprio = _safe_nested_name(ifields.get("priority"))
                iass = _safe_nested_name(ifields.get("assignee"), "displayName")
                summary_lines.append(
                    f"  - {ikey} [{istat}] (priority={iprio}, assignee={iass}): {isum}"
                )
            return PreparedOutline(
                total_lines=total_lines,
                outline_text="\n".join(summary_lines),
                unwrapped_target=target_path,
                pending_write=pending,
            )

        fields_meta = payload.get("fields")
        if isinstance(fields_meta, (list, dict)) and fields_meta:
            field_items = (
                fields_meta
                if isinstance(fields_meta, list)
                else [
                    v if isinstance(v, dict) else {"fieldId": k, "name": str(v)}
                    for k, v in fields_meta.items()
                ]
            )
            dict_fields = [f for f in field_items if isinstance(f, dict)]
            req_fields = [f for f in dict_fields if bool(f.get("required"))]
            opt_fields = [f for f in dict_fields if not bool(f.get("required"))][:25]
            summary_lines.append(f"fields ({len(dict_fields)} total):")
            for fitem in req_fields + opt_fields:
                fid = str(fitem.get("fieldId") or fitem.get("key") or fitem.get("id") or "?")
                fname = str(fitem.get("name") or "")
                freq = bool(fitem.get("required"))
                fschema = fitem.get("schema")
                ftype = _safe_nested_name(fschema, "type") if isinstance(fschema, dict) else "-"
                summary_lines.append(f"  - {fid} ({fname}): required={freq}, type={ftype}")
            return PreparedOutline(
                total_lines=total_lines,
                outline_text="\n".join(summary_lines),
                unwrapped_target=target_path,
                pending_write=pending,
            )

    preview = [f"  L{idx + 1}: {line[:200]}" for idx, line in enumerate(lines[:15])]
    summary_lines.append("preview (first 15 lines):")
    summary_lines.extend(preview)
    return PreparedOutline(
        total_lines=total_lines,
        outline_text="\n".join(summary_lines),
        unwrapped_target=target_path,
        pending_write=pending,
    )


def unwrap_and_outline_twg_stdout(
    file_path: Path, st_size: int, cache_dir: Path | None = None
) -> tuple[int, str, str | None] | None:
    """Build structured summary (or full inline payload if <6 KB) for TWG CLI stdout*.json files."""
    prepared = prepare_twg_stdout_outline(file_path, st_size, cache_dir=cache_dir)
    if prepared is None:
        return None
    unwrapped_canon = materialize_unwrap_write(prepared.pending_write)
    outline_text = finalize_outline_text(prepared, unwrapped_canon)
    return (prepared.total_lines, outline_text, unwrapped_canon)
