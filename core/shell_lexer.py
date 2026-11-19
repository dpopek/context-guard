"""Canonical Layer 0 shell command preparation, segmentation, tokenization, and wrapper stripping."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
import os
import re
import shlex
from typing import Literal, overload

_LEADING_CD_PREFIX_RE = re.compile(
    r"^(\s*cd\s+(?:\"[^\"]+\"|'[^']+'|[^;&|<>`\n]+?)\s*(?:&&|;)\s*)(.+)$",
    re.DOTALL,
)
_SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||;|\|")
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_DURATION_RE = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")

DEFAULT_EXEC_WRAPPERS: frozenset[str] = frozenset(
    ("env", "command", "exec", "nohup", "time", "builtin")
)
SHELL_FAMILY_WRAPPERS: frozenset[str] = DEFAULT_EXEC_WRAPPERS | frozenset(
    ("sudo", "nice", "taskpolicy", "timeout", "npx")
)
_WRAPPERS_WITH_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "env": frozenset(("-u", "--unset", "-C", "--chdir", "-S", "--split-string")),
    "nice": frozenset(("-n", "--adjustment")),
    "taskpolicy": frozenset(("-c", "-d")),
    "sudo": frozenset(("-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U")),
    "timeout": frozenset(("-k", "--kill-after", "-s", "--signal")),
    "npx": frozenset(("-p", "--package", "-c", "--call")),
}

__all__ = [
    "DEFAULT_EXEC_WRAPPERS",
    "SHELL_FAMILY_WRAPPERS",
    "first_pipeline_segment",
    "first_segment_tokens",
    "first_statement",
    "iter_unquoted",
    "normalize_cmd_basename",
    "prepare_shell_lines",
    "split_leading_cd_prefix",
    "split_pipeline",
    "split_shell_segments",
    "split_unquoted_segments",
    "strip_command_wrappers",
    "tokenize_shell_segment",
    "unquoted_text",
]


def normalize_cmd_basename(token: str) -> str:
    """Return lowercase command basename with path prefixes and Windows suffixes stripped."""
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for ext in (".exe", ".cmd", ".bat"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


def split_leading_cd_prefix(command: str) -> tuple[str, str]:
    """Split a leading `cd <dir> && ...` or `cd <dir>; ...` prefix from the remainder."""
    match = _LEADING_CD_PREFIX_RE.match(command)
    return (match.group(1), match.group(2)) if match else ("", command)


def iter_unquoted(text: str) -> Iterator[tuple[int, str]]:
    """Yield `(index, char)` for characters outside single/double quotes and backslash escapes."""
    quote, escaped = "", False
    for idx, ch in enumerate(text):
        if escaped:
            escaped = False
        elif ch == "\\" and quote != "'":
            escaped = True
        elif quote:
            quote = "" if ch == quote else quote
        elif ch in ("'", '"'):
            quote = ch
        else:
            yield idx, ch


def unquoted_text(text: str) -> str:
    """Return characters in `text` that appear outside quotes and backslash escapes."""
    return "".join(ch for _, ch in iter_unquoted(text))


def first_statement(text: str) -> str:
    """Extract the first shell statement ending at `;`, newline, `||`, `&&`, or background `&`."""
    n = len(text)
    for idx, ch in iter_unquoted(text):
        if ch in (";", "\n") or (ch == "|" and idx + 1 < n and text[idx + 1] == "|"):
            return text[:idx]
        if ch == "&":
            prev = text[idx - 1] if idx > 0 else ""
            nxt = text[idx + 1] if idx + 1 < n else ""
            if nxt == "&" or (prev not in (">", "<", "|") and nxt != ">"):
                return text[:idx]
    return text


def split_pipeline(statement: str) -> list[str]:
    """Split one shell statement at unquoted `|` / `|&` pipeline operators."""
    parts: list[str] = []
    start = 0
    for idx, ch in iter_unquoted(statement):
        if ch == "|":
            parts.append(statement[start:idx])
            start = idx + (2 if idx + 1 < len(statement) and statement[idx + 1] == "&" else 1)
    parts.append(statement[start:])
    return parts


def first_pipeline_segment(text: str) -> str:
    """Return the first pipeline segment of the first statement in `text`."""
    return split_pipeline(first_statement(text))[0]


def prepare_shell_lines(command: str) -> str:
    """Turn unquoted newlines into `;` and drop whole-line `#` comments; raise ValueError on open quote."""
    out: list[str] = []
    quote = ""
    line_start = True
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                i += 1
                out.append(command[i])
            elif ch == quote:
                quote = ""
        elif ch == "\\" and i + 1 < n:
            out.append(ch + command[i + 1])
            i += 1
            line_start = False
        elif ch == "\n":
            out.append(" ; ")
            line_start = True
        elif ch == "#" and line_start:
            end = command.find("\n", i)
            i = n if end == -1 else end - 1
        else:
            if ch in "'\"":
                quote = ch
            if not ch.isspace():
                line_start = False
            out.append(ch)
        i += 1
    if quote:
        raise ValueError("unbalanced quote")
    return "".join(out)


def split_unquoted_segments(prepared: str) -> list[str]:
    """Split a quote-balanced shell string at unquoted `;`, `|`, `&&`, and `||`."""
    segments: list[str] = []
    cur: list[str] = []
    quote = ""
    i = 0
    n = len(prepared)
    while i < n:
        ch = prepared[i]
        if quote == "'":
            cur.append(ch)
            if ch == "'":
                quote = ""
        elif quote == '"':
            if ch == "\\" and i + 1 < n:
                cur.append(ch + prepared[i + 1])
                i += 2
                continue
            cur.append(ch)
            if ch == '"':
                quote = ""
        elif ch == "\\" and i + 1 < n:
            cur.append(ch + prepared[i + 1])
            i += 2
            continue
        elif ch in ("'", '"'):
            quote = ch
            cur.append(ch)
        elif prepared[i : i + 2] in ("&&", "||"):
            segments.append("".join(cur))
            cur = []
            i += 2
            continue
        elif ch in (";", "|"):
            segments.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    segments.append("".join(cur))
    return [seg.strip() for seg in segments if seg.strip()]


def split_shell_segments(command: str, *, include_subshells: bool = False) -> list[str]:
    """Split `command` into non-empty stripped segments across chains, pipes, and optionally subshells."""
    if include_subshells:
        segs: list[str] = []
        start = 0
        for idx, ch in iter_unquoted(command):
            if ch in ";\n|&()":
                if (seg := command[start:idx].strip()):
                    segs.append(seg)
                start = idx + 1
        if (tail := command[start:].strip()):
            segs.append(tail)
        return segs
    try:
        return split_unquoted_segments(prepare_shell_lines(command))
    except ValueError:
        return [seg.strip() for seg in _SEGMENT_SPLIT_RE.split(command) if seg.strip()]


def _escape_windows_backslashes(text: str, eff_os: str) -> str:
    out: list[str] = []
    has_drive, tok_len, quote, i, n = False, 0, "", 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                i += 1
                out.append(text[i])
            elif ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
            out.append(ch)
        elif ch.isspace() or ch in "|&;()<>=":
            has_drive, tok_len = False, 0
            out.append(ch)
        elif ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "\\":
                out.append("\\\\\\\\" if eff_os == "nt" and tok_len == 0 else "\\\\")
            elif (has_drive or eff_os == "nt") and not nxt.isspace() and nxt not in "\"'|&;<>()$`":
                out.append("\\\\" + nxt)
            else:
                out.append("\\" + nxt)
            tok_len += 1
            i += 1
        else:
            if out and tok_len == 1 and ch == ":" and out[-1].isalpha():
                has_drive = True
            tok_len += 1
            out.append(ch)
        i += 1
    return "".join(out)


@overload
def tokenize_shell_segment(
    segment: str, *, fallback_split: Literal[True], os_name: str | None = None
) -> list[str]: ...


@overload
def tokenize_shell_segment(
    segment: str, *, fallback_split: Literal[False] = False, os_name: str | None = None
) -> list[str] | None: ...


@overload
def tokenize_shell_segment(
    segment: str, *, fallback_split: bool, os_name: str | None = None
) -> list[str] | None: ...


def tokenize_shell_segment(
    segment: str,
    *,
    fallback_split: bool = False,
    os_name: str | None = None,
) -> list[str] | None:
    """Tokenize one shell segment with Windows backslash tolerance; fallback or None on open quote."""
    eff_os = os.name if os_name is None else os_name
    prepared = _escape_windows_backslashes(segment, eff_os) if "\\" in segment else segment
    try:
        return shlex.split(prepared)
    except ValueError:
        return segment.split() if fallback_split else None


def strip_command_wrappers(
    tokens: Sequence[str],
    *,
    wrappers: frozenset[str] = DEFAULT_EXEC_WRAPPERS,
) -> list[str]:
    """Strip leading env assignments and execution wrappers (`env`, `nice`, `taskpolicy`, etc.)."""
    toks = list(tokens)
    i, n = 0, len(toks)
    while i < n:
        tok = toks[i]
        if _ASSIGNMENT_RE.match(tok):
            i += 1
            continue
        base = normalize_cmd_basename(tok)
        if base in wrappers:
            if base == "command" and i + 1 < n and toks[i + 1] in ("-v", "-V"):
                break
            val_flags = _WRAPPERS_WITH_VALUE_FLAGS.get(base, frozenset())
            i += 1
            while i < n and toks[i].startswith("-") and toks[i] != "--":
                flag = toks[i]
                i += 2 if flag in val_flags and i + 1 < n else 1
            if i < n and toks[i] == "--":
                i += 1
            if base == "timeout" and i < n and _DURATION_RE.match(toks[i]):
                i += 1
            continue
        break
    return toks[i:]


def first_segment_tokens(command: str, *, os_name: str | None = None) -> list[str]:
    """Tokenize the first meaningful segment of `command`, skipping a leading `cd` segment."""
    segments = [
        toks
        for seg in split_shell_segments(command)
        if (toks := tokenize_shell_segment(seg, fallback_split=True, os_name=os_name))
    ]
    if len(segments) > 1 and segments[0][:1] == ["cd"]:
        return segments[1]
    return segments[0] if segments else []
