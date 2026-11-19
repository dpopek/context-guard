"""Shell command families and output size measurement for the PostToolUse hook; pure functions, no I/O."""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.shell_lexer import (
    SHELL_FAMILY_WRAPPERS, first_segment_tokens, normalize_cmd_basename, strip_command_wrappers,
)

SIM_THRESHOLD_CHARS = 8000
SIM_HEAD_LINES = 60
SIM_TAIL_LINES = 40
SIM_MARKER = "[... output trimmed by Context-Guard ...]"
# Claude Code moves Bash output at or above this size to a file and shows the agent a short preview.
CLAUDE_INLINE_CAP_CHARS = 30000
# The preview the agent sees for a spilled output: about 2,000 chars, 4 chars per token.
SPILL_PREVIEW_TOKENS = 500
BUCKETS = ("<1k", "1-5k", "5-20k", "20-30k", ">=30k")
_BUCKET_UPPER_BOUNDS = ((1000, "<1k"), (5000, "1-5k"), (20000, "5-20k"), (CLAUDE_INLINE_CAP_CHARS, "20-30k"))

_PYTHON_RE = re.compile(r"^python(\d+(\.\d+)*)?$")
_SHELLS = frozenset(("bash", "sh", "zsh"))
_GIT_OPTIONS_WITH_VALUE = frozenset(("-C", "-c", "--git-dir", "--work-tree"))
_JS_PACKAGE_MANAGERS = frozenset(("npm", "pnpm", "yarn"))
_RUN_WRAPPERS = frozenset(("uv", "poetry"))
_PYTHON_OPTIONS_WITH_VALUE = frozenset(("-X", "-W"))
_SINGLE_FAMILY = {
    "grep": "search", "rg": "search", "ag": "search",
    "ls": "list", "find": "list", "fd": "list", "tree": "list", "du": "list",
    "cat": "read", "head": "read", "tail": "read", "less": "read", "bat": "read", "wc": "read",
    "pytest": "test", "jest": "test", "vitest": "test",
    "make": "build", "tsc": "build", "kubectl": "container",
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
        words = [a for a in args if not a.startswith("-")]
        return _classify_tokens(args[args.index("run") + 1 :]) if words[:1] == ["run"] else "other"
    words = [a for a in args if not a.startswith("-")]
    sub, arg = (words[0] if words else ""), (words[1] if len(words) > 1 else "")
    if name in _JS_PACKAGE_MANAGERS:
        if sub == "test" or (sub == "run" and arg.startswith("test")):
            return "test"
        return "build" if sub in ("install", "ci") or (sub == "run" and arg == "build") else "other"
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
    stripped = strip_command_wrappers(tokens, wrappers=SHELL_FAMILY_WRAPPERS)
    for i, token in enumerate(stripped):
        if token.startswith("-"):
            continue
        family = _family_of_tool(normalize_cmd_basename(token), stripped[i + 1 :])
        return family if family is not None else "other"
    return "other"


def classify_family(command: str) -> str:
    """Command family of the first segment of a shell command line; `other` when unknown."""
    return _classify_tokens(first_segment_tokens(command or ""))


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
    pos = 0
    for _ in range(lines):
        if (nxt := text.find("\n", pos)) == -1:
            return len(text)
        pos = nxt + 1
    return pos


def _tail_start(text: str, lines: int) -> int:
    pos = len(text) - 1 if text.endswith("\n") else len(text)
    for _ in range(lines):
        if (prev := text.rfind("\n", 0, pos)) == -1:
            return 0
        pos = prev
    return pos + 1


def measure(output: str, harness: str) -> Measurement:
    """Measure one shell output and simulate the head+tail rule on it."""
    chars, tokens = len(output), _token_estimate(output)
    spilled = harness == "claude" and chars >= CLAUDE_INLINE_CAP_CHARS
    sim_hit = not spilled and chars > SIM_THRESHOLD_CHARS and _line_count(output) > SIM_HEAD_LINES + SIM_TAIL_LINES
    saved = 0
    if sim_hit:
        kept = output[: _head_end(output, SIM_HEAD_LINES)] + SIM_MARKER + "\n" + output[_tail_start(output, SIM_TAIL_LINES) :]
        saved = max(0, tokens - _token_estimate(kept))
    context_tokens = min(tokens, SPILL_PREVIEW_TOKENS) if spilled else tokens
    return Measurement(chars, tokens, context_tokens, _bucket(chars), spilled, sim_hit, saved)
