"""Opt-in Atlassian Teamwork Graph CLI (`twg`) and generic Atlassian ADF helpers."""

from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

from core.contracts import (
    MAX_FORMAT_JSON_BYTES,
    MAX_OUTLINE_FILE_BYTES,
    PendingUnwrapWrite,
    PreparedOutline,
    finalize_outline_text,
    materialize_unwrap_write,
)

TWG_STDOUT_OUTLINE_MIN_BYTES = 6 * 1024  # 6 KB minimum before outlining TWG stdout*.json
TWG_STDOUT_FILENAMES = frozenset({"stdout.json", "stdout.compact.json"})

_LEADING_CD_PREFIX_RE = re.compile(
    r"^(\s*cd\s+(?:\"[^\"]+\"|'[^']+'|[^;&|<>`\n]+?)\s*(?:&&|;)\s*)(.+)$",
    re.DOTALL,
)
_SHELL_CHAIN_OPERATORS = (";", "&&", "||", "|", "\n", "`", "$(")
_SHELL_REDIRECTION_OPERATORS = (">", "<")
_RELATIVE_FILE_ARG_RE = re.compile(r"^@?(?!/)(?:[\w.-]+/)*[\w.-]+\.[A-Za-z0-9]{1,5}$")
_TWG_NONCANONICAL_RE = re.compile(
    r"^\s*(?:TWG_AGENT_DEFAULTS=\S+\s+)*(?:(?:~|/Users/[^/\s]+|/home/[^/\s]+)/\.local/bin/)?twg(\s+.*)?$",
    re.DOTALL,
)


def extract_adf_plain_text(node: Any) -> str:
    """Recursively extract plain text from an Atlassian Document Format (ADF) node or string."""
    if node is None:
        return ""
    if isinstance(node, str):
        return node.strip()
    if isinstance(node, list):
        parts = [extract_adf_plain_text(child) for child in node]
        return "".join(p for p in parts if p)
    if isinstance(node, dict):
        ntype = str(node.get("type") or "")
        if ntype == "text":
            return str(node.get("text") or "")
        if ntype == "hardBreak":
            return "\n"
        children = node.get("content")
        inner = extract_adf_plain_text(children) if isinstance(children, list) else ""
        if ntype in ("paragraph", "heading", "listItem", "codeBlock", "blockquote"):
            return inner + "\n" if inner else ""
        return inner
    return ""


def _safe_nested_name(obj: Any, key: str = "name") -> str:
    if isinstance(obj, dict):
        val = obj.get(key) or obj.get("displayName") or obj.get("value")
        return str(val) if val is not None else "-"
    return str(obj) if obj is not None else "-"


def _twg_fields(obj: dict[str, Any]) -> dict[str, Any]:
    raw = obj.get("fields")
    return raw if isinstance(raw, dict) else obj


def _unwrapped_suffix(target_path: Path | None) -> str:
    return f", unwrapped at {os.path.realpath(str(target_path))}" if target_path is not None else ""


def _format_twg_workitem(item: dict[str, Any]) -> list[str]:
    fields = _twg_fields(item)
    key = str(item.get("key") or fields.get("key") or "?")
    labels = fields.get("labels")
    labels_str = ", ".join(str(x) for x in labels) if isinstance(labels, list) and labels else "-"
    out = [
        f"## {key}: {fields.get('summary') or ''}",
        f"  status: {_safe_nested_name(fields.get('status'))} | type: {_safe_nested_name(fields.get('issuetype'))} | priority: {_safe_nested_name(fields.get('priority'))}",
        f"  assignee: {_safe_nested_name(fields.get('assignee'), 'displayName')} | reporter: {_safe_nested_name(fields.get('reporter'), 'displayName')} | labels: {labels_str}",
    ]
    desc_text = extract_adf_plain_text(fields.get("description")).strip()
    if desc_text:
        out.extend(["  description:", *(f"    {dline}" for dline in desc_text[:1200].splitlines()[:20])])
    cc = fields.get("comment")
    comments = cc.get("comments") if isinstance(cc, dict) and isinstance(cc.get("comments"), list) else []
    if comments:
        out.append(f"  comments ({len(comments)} total, showing last {min(5, len(comments))}):")
        for comment in comments[-5:]:
            if isinstance(comment, dict):
                author = _safe_nested_name(comment.get("author"), "displayName")
                created = str(comment.get("created") or "")[:19]
                cbody = extract_adf_plain_text(comment.get("body")).strip().replace("\n", " ")[:400]
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

    formatted_text = raw_text
    sibling_pretty = file_path.parent / "stdout.json"
    if file_path.name == "stdout.compact.json" and sibling_pretty.is_file():
        try:
            formatted_text = sibling_pretty.read_text(encoding="utf-8", errors="replace")
        except OSError:
            if st_size <= MAX_FORMAT_JSON_BYTES:
                formatted_text = json.dumps(data_obj, indent=2, ensure_ascii=False)
    elif len(raw_text.splitlines()) <= 5 and st_size <= MAX_FORMAT_JSON_BYTES:
        formatted_text = json.dumps(data_obj, indent=2, ensure_ascii=False)

    lines = formatted_text.splitlines()
    total_lines = len(lines)
    command = str(data_obj.get("command") or "twg")
    if st_size < TWG_STDOUT_OUTLINE_MIN_BYTES:
        inline = f"# TWG CLI output ({command}, {total_lines} lines, {st_size} bytes — full payload inline)\n```json\n{formatted_text.strip()}\n```"
        return PreparedOutline(total_lines, inline)

    target_path: Path | None = None
    pending: PendingUnwrapWrite | None = None
    if cache_dir is not None:
        run_tag = re.sub(r"[^A-Za-z0-9._-]", "_", f"{file_path.parent.parent.name}_{file_path.parent.name}")
        target_path = cache_dir / f"{run_tag}_stdout_formatted.json"
        pending = PendingUnwrapWrite(target_path, formatted_text)
    elif total_lines != len(raw_text.splitlines()):
        target_path = file_path.parent / "stdout_formatted.json"
        pending = PendingUnwrapWrite(target_path, formatted_text)

    payload = data_obj.get("data")
    summary_lines = [f"# TWG CLI output ({command}, {total_lines} lines, {st_size} bytes{_unwrapped_suffix(target_path)})"]

    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        for item in payload[:5]:
            if isinstance(item, dict):
                summary_lines.extend(_format_twg_workitem(item))
        return PreparedOutline(total_lines, "\n".join(summary_lines), target_path, pending)

    if isinstance(payload, dict):
        if "key" in payload and ("summary" in payload or "fields" in payload):
            summary_lines.extend(_format_twg_workitem(payload))
            return PreparedOutline(total_lines, "\n".join(summary_lines), target_path, pending)

        issues = payload.get("issues")
        if isinstance(issues, list) and issues:
            summary_lines.append(f"issues ({len(issues)} returned):")
            for issue in issues[:25]:
                if not isinstance(issue, dict):
                    continue
                ifields = _twg_fields(issue)
                ikey = str(issue.get("key") or ifields.get("key") or "?")
                isum = str(ifields.get("summary") or "")
                istat = _safe_nested_name(ifields.get("status"))
                iprio = _safe_nested_name(ifields.get("priority"))
                iass = _safe_nested_name(ifields.get("assignee"), "displayName")
                summary_lines.append(f"  - {ikey} [{istat}] (priority={iprio}, assignee={iass}): {isum}")
            return PreparedOutline(total_lines, "\n".join(summary_lines), target_path, pending)

        fields_meta = payload.get("fields")
        if isinstance(fields_meta, (list, dict)) and fields_meta:
            field_items = (
                fields_meta if isinstance(fields_meta, list)
                else [v if isinstance(v, dict) else {"fieldId": k, "name": str(v)} for k, v in fields_meta.items()]
            )
            dict_fields = [f for f in field_items if isinstance(f, dict)]
            req_fields = [f for f in dict_fields if bool(f.get("required"))]
            opt_fields = [f for f in dict_fields if not bool(f.get("required"))][:25]
            summary_lines.append(f"fields ({len(dict_fields)} total):")
            for fitem in req_fields + opt_fields:
                fid = str(fitem.get("fieldId") or fitem.get("key") or fitem.get("id") or "?")
                fname, freq = str(fitem.get("name") or ""), bool(fitem.get("required"))
                fschema = fitem.get("schema")
                ftype = _safe_nested_name(fschema, "type") if isinstance(fschema, dict) else "-"
                summary_lines.append(f"  - {fid} ({fname}): required={freq}, type={ftype}")
            return PreparedOutline(total_lines, "\n".join(summary_lines), target_path, pending)

    summary_lines.append("preview (first 15 lines):")
    summary_lines.extend(f"  L{idx + 1}: {line[:200]}" for idx, line in enumerate(lines[:15]))
    return PreparedOutline(total_lines, "\n".join(summary_lines), target_path, pending)


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


def _unquoted_text(text: str) -> str:
    out: list[str] = []
    quote, escaped = "", False
    for ch in text:
        if escaped:
            escaped = False
        elif ch == "\\" and quote != "'":
            escaped = True
        elif quote:
            quote = "" if ch == quote else quote
        elif ch in ("'", '"'):
            quote = ch
        else:
            out.append(ch)
    return "".join(out)


def _twg_has_relative_file_arg(args_str: str) -> bool:
    try:
        tokens = shlex.split(args_str)
    except ValueError:
        return True
    return any(not tok.startswith("-") and _RELATIVE_FILE_ARG_RE.match(tok) for tok in tokens)


def rewrite_twg_cli_command(command_line: str) -> str | None:
    """Canonicalize single-statement `twg` invocations when Atlassian TWG integration is active."""
    trimmed = command_line.strip()
    cd_match = _LEADING_CD_PREFIX_RE.match(trimmed)
    cd_prefix, remainder = (cd_match.group(1), cd_match.group(2)) if cd_match else ("", trimmed)
    stripped = remainder.strip()
    if any(op in _unquoted_text(stripped) for op in (*_SHELL_CHAIN_OPERATORS, "&", *_SHELL_REDIRECTION_OPERATORS)):
        return None
    twg_match = _TWG_NONCANONICAL_RE.match(stripped)
    if twg_match and "$(" not in stripped and (cd_prefix or (not stripped.startswith("twg ") and stripped != "twg")):
        suffix = twg_match.group(1) or ""
        return None if (cd_prefix and _twg_has_relative_file_arg(suffix)) else f"twg{suffix}"
    return None


__all__ = [
    "TWG_STDOUT_FILENAMES",
    "TWG_STDOUT_OUTLINE_MIN_BYTES",
    "extract_adf_plain_text",
    "prepare_twg_stdout_outline",
    "rewrite_twg_cli_command",
    "unwrap_and_outline_twg_stdout",
]
