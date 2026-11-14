"""Shell command families and output size measurement for the PostToolUse hook; pure functions, no I/O."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from hooks.file_io import normalize_cmd_basename

SIM_THRESHOLD_CHARS = 8000
SIM_HEAD_LINES = 60
SIM_TAIL_LINES = 40
SIM_MARKER = "[... output trimmed by Context-Guard ...]"
# Claude Code moves Bash output at or above this size to a file and shows the agent a short preview.
CLAUDE_INLINE_CAP_CHARS = 30000
# The preview the agent sees for a spilled output: about 2,000 chars, 4 chars per token.
SPILL_PREVIEW_TOKENS = 500
BUCKETS = ("<1k", "1-5k", "5-20k", "20-30k", ">=30k")
_BUCKET_UPPER_BOUNDS = (
    (1000, "<1k"),
    (5000, "1-5k"),
    (20000, "5-20k"),
    (CLAUDE_INLINE_CAP_CHARS, "20-30k"),
)

_SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||;|\|")
_OPERATOR_CHARS = frozenset("&|;")
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PYTHON_RE = re.compile(r"^python(\d+(\.\d+)*)?$")
_WRAPPERS = frozenset(
    ("sudo", "env", "time", "nice", "taskpolicy", "timeout", "command", "nohup", "exec", "npx")
)
_SHELLS = frozenset(("bash", "sh", "zsh"))
_GIT_OPTIONS_WITH_VALUE = frozenset(("-C", "-c", "--git-dir", "--work-tree"))
_JS_PACKAGE_MANAGERS = frozenset(("npm", "pnpm", "yarn"))
_RUN_WRAPPERS = frozenset(("uv", "poetry"))
_PYTHON_OPTIONS_WITH_VALUE = frozenset(("-X", "-W"))
_SINGLE_FAMILY = {
    "grep": "search",
    "rg": "search",
    "ag": "search",
    "ls": "list",
    "find": "list",
    "fd": "list",
    "tree": "list",
    "du": "list",
    "cat": "read",
    "head": "read",
    "tail": "read",
    "less": "read",
    "bat": "read",
    "wc": "read",
    "pytest": "test",
    "jest": "test",
    "vitest": "test",
    "make": "build",
    "tsc": "build",
    "kubectl": "container",
}


@dataclass(frozen=True)
class Measurement:
    """Size of one shell output, what of it reaches the agent's context, and what head+tail would save.

    `tokens` is the full size; `context_tokens` is what the agent sees (only a preview when spilled).
    """

    chars: int
    tokens: int
    context_tokens: int
    bucket: str
    spilled: bool
    sim_hit: bool
    sim_saved_tokens: int


def _tokens(segment: str) -> list[str]:
    if "\\" in segment:
        out: list[str] = []
        i, q, n = 0, "", len(segment)
        while i < n:
            ch = segment[i]
            if q:
                if q == '"' and ch == "\\" and i + 1 < n:
                    nxt = segment[i + 1]
                    out.append("\\\\" + nxt if nxt not in '"\\$`\n' else ch + nxt)
                    i += 2
                    continue
                if ch == q:
                    q = ""
                out.append(ch)
            elif ch in ('"', "'"):
                q = ch
                out.append(ch)
            elif ch == "\\" and i + 1 < n and segment[i + 1] not in " \t\n'\"|&;()$`<>":
                out.append("\\\\")
            elif ch == "\\" and i + 1 < n:
                out.append(ch + segment[i + 1])
                i += 2
                continue
            else:
                out.append(ch)
            i += 1
        segment = "".join(out)
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _prepare_lines(command: str) -> str:
    """Turn unquoted newlines into `;` and drop whole-line comments; raises ValueError on open quotes."""
    out: list[str] = []
    quote = ""
    line_start = True
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(command):
                i += 1
                out.append(command[i])
            elif ch == quote:
                quote = ""
        elif ch == "\\" and i + 1 < len(command):
            out.append(ch + command[i + 1])
            i += 1
            line_start = False
        elif ch == "\n":
            out.append(" ; ")
            line_start = True
        elif ch == "#" and line_start:
            end = command.find("\n", i)
            i = len(command) if end == -1 else end - 1
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


def _split_unquoted_segments(prepared: str) -> list[str]:
    """Split `prepared` at unquoted `;`, `|`, `&&`, and `||`."""
    segments: list[str] = []
    cur: list[str] = []
    quote = ""
    i = 0
    while i < len(prepared):
        ch = prepared[i]
        if quote == "'":
            cur.append(ch)
            if ch == "'":
                quote = ""
        elif quote == '"':
            if ch == "\\" and i + 1 < len(prepared):
                cur.append(ch + prepared[i + 1])
                i += 2
                continue
            cur.append(ch)
            if ch == '"':
                quote = ""
        elif ch == "\\" and i + 1 < len(prepared):
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


def _first_segment_tokens(command: str) -> list[str]:
    """Tokens of the first meaningful segment, cutting at `&&`, `||`, `|` and `;` outside quotes.

    A leading `cd` segment is skipped. An unbalanced quote falls back to a plain regex split.
    """
    try:
        raw_segments = _split_unquoted_segments(_prepare_lines(command))
        segments = [toks for seg in raw_segments if (toks := _tokens(seg))]
    except ValueError:
        parts = [s.strip() for s in _SEGMENT_SPLIT_RE.split(command) if s.strip()]
        segments = [_tokens(part) for part in parts]
    if len(segments) > 1 and segments[0][:1] == ["cd"]:
        return segments[1]
    return segments[0] if segments else []


def _git_subcommand(args: list[str]) -> str:
    i = 0
    while i < len(args):
        if args[i] in _GIT_OPTIONS_WITH_VALUE:
            i += 2
        elif args[i].startswith("-"):
            i += 1
        else:
            return args[i]
    return ""


def _python_family(args: list[str]) -> str:
    """Family of a python invocation: skip interpreter options, then look at `-m <module>`."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-m":
        i += 2 if args[i] in _PYTHON_OPTIONS_WITH_VALUE else 1
    if args[i : i + 2] == ["-m", "pytest"]:
        return "test"
    return "build" if args[i : i + 3] == ["-m", "pip", "install"] else "other"


def _family_of_tool(name: str, args: list[str]) -> str | None:
    """Family for a tool and the tokens after it; None when the tool is unknown."""
    if name == "git":
        sub = _git_subcommand(args)
        if sub in ("log", "show", "reflog"):
            return "git_log"
        if sub == "diff":
            return "git_diff"
        return "search" if sub == "grep" else "git_other"
    if name in _SINGLE_FAMILY:
        return _SINGLE_FAMILY[name]
    if name in _SHELLS and len(args) >= 2 and args[0].startswith("-") and "c" in args[0]:
        return classify_family(args[1])
    if _PYTHON_RE.match(name):
        return _python_family(args)
    if name in _RUN_WRAPPERS:
        # `uv run <cmd>` and `poetry run <cmd>` classify as <cmd>; anything else (`uv pip install`) is other.
        words = [a for a in args if not a.startswith("-")]
        if words[:1] == ["run"]:
            rest = args[args.index("run") + 1 :]
            return _classify_tokens(rest)
        return "other"
    words = [a for a in args if not a.startswith("-")]
    sub = words[0] if words else ""
    arg = words[1] if len(words) > 1 else ""
    if name in _JS_PACKAGE_MANAGERS:
        if sub == "test" or (sub == "run" and arg.startswith("test")):
            return "test"
        if sub in ("install", "ci") or (sub == "run" and arg == "build"):
            return "build"
        return "other"
    if name in ("pip", "pip3"):
        return "build" if sub == "install" else "other"
    if name == "cargo":
        return {"test": "test", "build": "build"}.get(sub, "other")
    if name == "go":
        return "test" if sub == "test" else "other"
    if name == "docker":
        return "build" if sub == "build" else "container"
    return None


def _classify_tokens(tokens: list[str]) -> str:
    in_wrapper = False
    for i, token in enumerate(tokens):
        if _ASSIGNMENT_RE.match(token) or token.startswith("-"):
            continue
        name = normalize_cmd_basename(token)
        if name in _WRAPPERS:
            in_wrapper = True
            continue
        family = _family_of_tool(name, tokens[i + 1 :])
        if family is not None:
            return family
        if not in_wrapper:
            return "other"
    return "other"


def classify_family(command: str) -> str:
    """Command family of the first segment of a shell command line; `other` when unknown.

    Assignments and flags are skipped. After a wrapper (`nice`, `taskpolicy`, `env`, ...) unknown
    tokens are the wrapper's own arguments and are skipped too; outside a wrapper the first unknown
    tool decides `other`.
    """
    return _classify_tokens(_first_segment_tokens(command or ""))


def _bucket(chars: int) -> str:
    for upper, label in _BUCKET_UPPER_BOUNDS:
        if chars < upper:
            return label
    return BUCKETS[-1]


def _token_estimate(text: str) -> int:
    return len(text.encode("utf-8", errors="ignore")) // 4


def _line_count(text: str) -> int:
    return text.count("\n") + (1 if text and not text.endswith("\n") else 0)


def _head_end(text: str, lines: int) -> int:
    """Index just past the first `lines` lines."""
    pos = 0
    for _ in range(lines):
        nxt = text.find("\n", pos)
        if nxt == -1:
            return len(text)
        pos = nxt + 1
    return pos


def _tail_start(text: str, lines: int) -> int:
    """Index where the last `lines` lines begin."""
    pos = len(text) - 1 if text.endswith("\n") else len(text)
    for _ in range(lines):
        prev = text.rfind("\n", 0, pos)
        if prev == -1:
            return 0
        pos = prev
    return pos + 1


def measure(output: str, harness: str) -> Measurement:
    """Measure one shell output and simulate the head+tail rule on it.

    A Claude Code output at or above the inline cap is `spilled`: the agent already sees only a
    preview, so it never counts as a simulated hit.
    """
    chars = len(output)
    tokens = _token_estimate(output)
    spilled = harness == "claude" and chars >= CLAUDE_INLINE_CAP_CHARS
    sim_hit = (
        not spilled
        and chars > SIM_THRESHOLD_CHARS
        and _line_count(output) > SIM_HEAD_LINES + SIM_TAIL_LINES
    )
    saved = 0
    if sim_hit:
        kept = (
            output[: _head_end(output, SIM_HEAD_LINES)]
            + SIM_MARKER
            + "\n"
            + output[_tail_start(output, SIM_TAIL_LINES) :]
        )
        saved = max(0, tokens - _token_estimate(kept))
    context_tokens = min(tokens, SPILL_PREVIEW_TOKENS) if spilled else tokens
    return Measurement(chars, tokens, context_tokens, _bucket(chars), spilled, sim_hit, saved)
