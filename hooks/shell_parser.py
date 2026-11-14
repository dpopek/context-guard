"""Quiet CLI flag rewriter and outline/read target parser for shell PreToolUse."""

from __future__ import annotations

import os
import re
import shlex
from typing import Iterator

_LEADING_CD_PREFIX_RE = re.compile(r"^(\s*cd\s+(?:\"[^\"]+\"|'[^']+'|[^;&|<>`\n]+?)\s*(?:&&|;)\s*)(.+)$", re.DOTALL)
_SHELL_CHAIN_OPERATORS = (";", "&&", "||", "|", "\n", "`", "$(")
_SHELL_REDIRECTION_OPERATORS = (">", "<")
_SKIP_REDIR_TOKENS = frozenset({">", ">>", "1>", "1>>", "2>", "2>>", "&>", "&>>", "<", "<<", "<<-", "<<<", "0<", "0<<", "0<<<"})
_SED_CLAUSE_LINE_RE = re.compile(r"^(\d+|\$)\s*p$")
_SED_CLAUSE_RANGE_RE = re.compile(r"^(\d+)\s*,\s*(\d+)\s*p$")
_SED_CLAUSE_PLUS_RE = re.compile(r"^(\d+)\s*,\s*\+\s*(\d+)\s*p$")
_SED_CLAUSE_EOF_RE = re.compile(r"^(\d+)\s*,\s*\$\s*p$")
_SED_CLAUSE_QUIT_RE = re.compile(r"^\d+\s*q$")
_SHELL_OUTLINE_CMD_RE = re.compile(
    r"^\s*(?:(?:[\w./:\\-]+[\\/])?python3?(?:\.\d+)?\s+(?:-[a-zA-Z0-9]+\s+)*)?(?:[~$\w./:\\-]+[\\/])?(?:outline\.py|cg-outline)\s+\S+"
)
_PYTEST_SINGLE_CMD_RE = re.compile(
    r"^\s*(?:(?:poetry|uv|pipenv|pdm)\s+run\s+)?(?:(?:[\w./-]+/)?pytest|(?:[\w./-]+/)?python3?(?:\.\d+)?\s+-m\s+pytest)(?:\s+.*)?$"
)
_PYTEST_SHORT_VERBOSITY_RE = re.compile(r"-[a-zA-Z]*[qv][a-zA-Z]*")
_CARGO_TEST_SINGLE_CMD_RE = re.compile(r"^\s*cargo\s+test(?:\s+.*)?$")
_CARGO_TEST_EXISTING_FLAGS_RE = re.compile(r"(?:^|\s)(?:-q|--quiet|--nocapture)(?:\s|$)")
_VITEST_SINGLE_CMD_RE = re.compile(r"^\s*(?:(?:npx|pnpm|yarn)\s+)?(?:[\w./-]+/)?vitest(?:\s+run)?(?:\s+.*)?$")
_VITEST_EXISTING_FLAGS_RE = re.compile(r"(?:^|\s)(?:--silent|--reporter)(?:\s|$|=)")
_GREP_EXCLUDED_DIRS = frozenset({".git", ".mypy_cache", ".pytest_cache", "__pycache__", "node_modules", "venv", ".venv", ".ruff_cache"})
_RELATIVE_FILE_ARG_RE = re.compile(r"^@?(?!/)(?:[\w.-]+/)*[\w.-]+\.[A-Za-z0-9]{1,5}$")
_GIT_STATUS_BARE_RE = re.compile(r"^\s*git\s+status\s*$")
_GREP_CACHE_EXCLUDE_FLAGS = (
    "-I --exclude-dir=.git --exclude-dir=.mypy_cache --exclude-dir=.pytest_cache "
    "--exclude-dir=__pycache__ --exclude-dir=node_modules --exclude-dir=venv --exclude-dir=.venv --exclude-dir=.ruff_cache"
)
_GREP_FILE_EXCLUDE_FLAGS = (
    "'--exclude=*.min.js' '--exclude=*.min.css' '--exclude=*.map' "
    "'--exclude=package-lock.json' '--exclude=pnpm-lock.yaml' '--exclude=yarn.lock'"
)
_GREP_EXCLUDED_BASENAMES = frozenset({"package-lock.json", "pnpm-lock.yaml", "yarn.lock"})
_GREP_EXCLUDED_SUFFIXES = (".min.js", ".min.css", ".map")
_GREP_BIN_RE = re.compile(r"^((?:[\w./-]+/)?grep)\s+(.+)$", re.DOTALL)
_GREP_RECURSIVE_FLAG_RE = re.compile(r"(?:^|\s)(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)(?:\s|$)")
_QUOTED_STRING_RE = re.compile(r"""(?:"(?:\\.|[^"\\])*"|'[^']*')""")
_TWG_NONCANONICAL_RE = re.compile(
    r"^\s*(?:TWG_AGENT_DEFAULTS=\S+\s+)*(?:~|/Users/[^/\s]+|/home/[^/\s]+)?(?:/\.local/bin/)?twg(\s+.*)?$", re.DOTALL
)
_SHELL_READER_BINS = frozenset({"cat", "head", "tail", "sed", "awk", "less", "bat", "nl"})
_UNBOUNDED_SHELL_DUMP_BINS = frozenset({"cat", "less", "bat", "nl"})


def split_leading_cd_prefix(command: str) -> tuple[str, str]:
    """Split a leading `cd <dir> && ...` or `cd <dir>; ...` prefix from the remainder."""
    match = _LEADING_CD_PREFIX_RE.match(command)
    return (match.group(1), match.group(2)) if match else ("", command)


def _split_tokens(text: str) -> list[str] | None:
    try:
        return shlex.split(text)
    except ValueError:
        return None


def _effective_cwd(cd_prefix: str, cwd: str | None) -> str | None:
    if not cd_prefix:
        return cwd
    head = cd_prefix.rstrip()
    head = head[:-2].strip() if head.endswith("&&") else (head[:-1].strip() if head.endswith(";") else head)
    tokens = _split_tokens(head)
    raw_dir = next((t for t in tokens[1:] if not t.startswith("-")), "") if tokens and tokens[0] == "cd" else ""
    if not raw_dir:
        return cwd
    target_dir = os.path.expanduser(raw_dir)
    return target_dir if (os.path.isabs(target_dir) or not cwd) else os.path.join(cwd, target_dir)


def _iter_unquoted(text: str) -> Iterator[tuple[int, str]]:
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


def _first_statement(text: str) -> str:
    n = len(text)
    for idx, ch in _iter_unquoted(text):
        if ch in (";", "\n") or (ch == "|" and idx + 1 < n and text[idx + 1] == "|"):
            return text[:idx]
        if ch == "&":
            prev = text[idx - 1] if idx > 0 else ""
            nxt = text[idx + 1] if idx + 1 < n else ""
            if nxt == "&" or (prev not in (">", "<", "|") and nxt != ">"):
                return text[:idx]
    return text


def _split_pipeline(statement: str) -> list[str]:
    parts: list[str] = []
    start = 0
    for idx, ch in _iter_unquoted(statement):
        if ch == "|":
            parts.append(statement[start:idx])
            start = idx + (2 if idx + 1 < len(statement) and statement[idx + 1] == "&" else 1)
    parts.append(statement[start:])
    return parts


def _first_pipeline_segment(text: str) -> str:
    return _split_pipeline(_first_statement(text))[0]


def _resolve_shell_targets(tokens: list[str], eff_cwd: str | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
        elif tok in _SKIP_REDIR_TOKENS:
            skip_next = True
        elif tok and not tok.startswith(("-", ">", "1>", "2>", "&>", "<", "0<")) and "\x00" not in tok:
            expanded = os.path.expanduser(tok)
            try:
                canon = os.path.realpath(expanded if (os.path.isabs(expanded) or not eff_cwd) else os.path.join(eff_cwd, expanded))
                if canon not in seen and os.path.isfile(canon):
                    seen.add(canon)
                    out.append(canon)
            except (OSError, ValueError):
                pass
    return out


def _is_sed_in_place(args: list[str]) -> bool:
    expect_arg = False
    for tok in args:
        if expect_arg:
            expect_arg = False
        elif tok == "--":
            break
        elif tok == "--in-place" or tok.startswith("--in-place="):
            return True
        elif tok in ("-e", "-f", "--expression", "--file"):
            expect_arg = True
        elif tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            for ch in tok[1:]:
                if ch in ("e", "f"):
                    break
                if ch in ("i", "I"):
                    return True
    return False


def is_outline_pull(command_line: str) -> bool:
    """Return True iff single command asks the outline CLI (`cg-outline` / `outline.py`) for a file skeleton."""
    _, remainder = split_leading_cd_prefix(command_line)
    if any(op in _QUOTED_STRING_RE.sub(" ", remainder) for op in _SHELL_CHAIN_OPERATORS + _SHELL_REDIRECTION_OPERATORS):
        return False
    return bool(_SHELL_OUTLINE_CMD_RE.match(remainder.strip()))


def extract_outline_pull_targets(command_line: str, cwd: str | None = None) -> list[str]:
    """Return canonical existing file targets for an outline-pull shell command."""
    if not is_outline_pull(command_line):
        return []
    cd_prefix, remainder = split_leading_cd_prefix(command_line)
    tokens = _split_tokens(remainder)
    if not tokens:
        return []
    idx = next((i for i, t in enumerate(tokens) if t.replace("\\", "/").rsplit("/", 1)[-1] in ("outline.py", "cg-outline")), -1)
    return _resolve_shell_targets(tokens[idx + 1 :], _effective_cwd(cd_prefix, cwd)) if idx >= 0 else []


def is_unbounded_shell_dump(command_line: str) -> bool:
    """Return True iff the first pipeline segment invokes an unbounded shell file dumper."""
    tokens = _split_tokens(_first_pipeline_segment(split_leading_cd_prefix(command_line)[1]))
    return bool(tokens and tokens[0].replace("\\", "/").rsplit("/", 1)[-1] in _UNBOUNDED_SHELL_DUMP_BINS)


def extract_shell_read_targets(command_line: str, cwd: str | None = None) -> list[str]:
    """Return deduplicated existing file targets read by the first pipeline segment."""
    cd_prefix, remainder = split_leading_cd_prefix(command_line)
    tokens = _split_tokens(_first_pipeline_segment(remainder))
    if not tokens:
        return []
    bin_name = tokens[0].replace("\\", "/").rsplit("/", 1)[-1]
    if bin_name not in _SHELL_READER_BINS or (bin_name == "sed" and _is_sed_in_place(tokens[1:])):
        return []
    return _resolve_shell_targets(tokens[1:], _effective_cwd(cd_prefix, cwd))


def _parse_ht_spec(cmd: str, spec: str, is_bytes: bool, total_lines: int | None) -> int | None:
    if not spec:
        return None
    if is_bytes:
        if (cmd == "tail" and spec[0] == "+") or (cmd == "head" and spec[0] == "-"):
            return None
        raw = spec[1:] if spec[0] in "+-" else spec
        return max(1, (int(raw) + 39) // 40) if raw.isdigit() and int(raw) > 0 else None
    if spec[0] == "+" and spec[1:].isdigit():
        val = int(spec[1:])
        if cmd == "head":
            return val if val > 0 else None
        return max(1, total_lines - val + 1) if val >= 2 and total_lines and total_lines > 0 else None
    raw = spec[1:] if (spec[0] == "-" and cmd != "head") else ("" if spec[0] in "+-" else spec)
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def _head_tail_bound(cmd: str, args: list[str], total_lines: int | None) -> int | None:
    bound: int | None = 10
    pending: str | None = None
    for tok in args:
        if pending is not None:
            if (bound := _parse_ht_spec(cmd, tok, pending == "c", total_lines)) is None:
                return None
            pending = None
        elif tok == "--":
            break
        elif cmd == "tail" and (tok in ("--follow", "--retry") or tok.startswith("--follow=")):
            return None
        elif tok in ("--lines", "--bytes"):
            pending = "c" if tok == "--bytes" else "n"
        elif tok.startswith(("--lines=", "--bytes=")):
            if (bound := _parse_ht_spec(cmd, tok.split("=", 1)[1], tok.startswith("--bytes="), total_lines)) is None:
                return None
        elif tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            if tok[1:].isdigit():
                if (bound := _parse_ht_spec(cmd, tok[1:], False, total_lines)) is None:
                    return None
                continue
            for j, ch in enumerate(tok[1:]):
                if (cmd == "tail" and ch in ("f", "F")) or ch not in ("n", "c", "q", "v", "z"):
                    return None
                if ch in ("n", "c"):
                    if (rest := tok[j + 2 :]):
                        if (bound := _parse_ht_spec(cmd, rest, ch == "c", total_lines)) is None:
                            return None
                    else:
                        pending = ch
                    break
    return None if pending is not None else bound


def _sed_bound(args: list[str], total_lines: int | None) -> int | None:
    quiet, explicit_expr, expect_expr, end_opts = False, False, False, False
    scripts, positionals = [], []
    for tok in args:
        if expect_expr:
            scripts.append(tok)
            expect_expr = False
        elif not end_opts and tok == "--":
            end_opts = True
        elif not end_opts and tok in ("--quiet", "--silent"):
            quiet = True
        elif not end_opts and (tok in ("--in-place", "-i", "-I", "-f", "--file") or tok.startswith(("--in-place=", "--file="))):
            return None
        elif not end_opts and tok in ("-e", "--expression"):
            explicit_expr = expect_expr = True
        elif not end_opts and tok.startswith("--expression="):
            explicit_expr = True
            scripts.append(tok.split("=", 1)[1])
        elif not end_opts and tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            for j, ch in enumerate(tok[1:]):
                if ch not in ("n", "e", "E", "r", "u", "z"):
                    return None
                if ch == "n":
                    quiet = True
                elif ch == "e":
                    explicit_expr = True
                    if (rest := tok[j + 2 :]):
                        scripts.append(rest)
                    else:
                        expect_expr = True
                    break
        elif not tok.startswith("-") or end_opts or tok == "-":
            positionals.append(tok)
        else:
            return None
    if expect_expr or not quiet or (not explicit_expr and not positionals):
        return None
    if not explicit_expr:
        scripts.append(positionals[0])
    total = 0
    for part in scripts:
        for raw_c in re.split(r"[;\n]", part):
            c = raw_c.strip()
            if not c or _SED_CLAUSE_QUIT_RE.fullmatch(c):
                continue
            if (m := _SED_CLAUSE_LINE_RE.fullmatch(c)) and m.group(1) != "0":
                total += 1
            elif (m := _SED_CLAUSE_RANGE_RE.fullmatch(c)) and 1 <= int(m.group(1)) <= int(m.group(2)):
                total += int(m.group(2)) - int(m.group(1)) + 1
            elif (m := _SED_CLAUSE_PLUS_RE.fullmatch(c)) and int(m.group(1)) >= 1:
                total += int(m.group(2)) + 1
            elif (m := _SED_CLAUSE_EOF_RE.fullmatch(c)) and int(m.group(1)) >= 2 and total_lines and total_lines > 0:
                total += max(1, total_lines - int(m.group(1)) + 1)
            else:
                return None
    return total if total > 0 else None


def is_bounded_shell_read(command_line: str, total_lines: int | None = None, max_lines: int = 250) -> bool:
    """Return True iff the first shell statement stays within `max_lines` of bounded output."""
    bound: int | None = None
    upstream_is_raw = True
    for seg in _split_pipeline(_first_statement(split_leading_cd_prefix(command_line)[1])):
        tokens = _split_tokens(seg)
        if not tokens:
            return False
        cmd = tokens[0].replace("\\", "/").rsplit("/", 1)[-1]
        if cmd in ("cat", "nl", "bat"):
            continue
        eff_total = total_lines if upstream_is_raw else bound
        stage = _head_tail_bound(cmd, tokens[1:], eff_total) if cmd in ("head", "tail") else (_sed_bound(tokens[1:], eff_total) if cmd == "sed" else None)
        upstream_is_raw = False
        if cmd not in ("head", "tail", "sed"):
            bound = None
        elif stage is not None:
            bound = stage if bound is None else min(bound, stage)
    return bound is not None and 0 < bound <= max_lines


def _pytest_has_verbosity_flags(command: str) -> bool:
    tokens = _split_tokens(command)
    return True if tokens is None else any(
        t in ("--quiet", "--verbose") or t.startswith(("--tb", "--verbosity")) or bool(_PYTEST_SHORT_VERBOSITY_RE.fullmatch(t))
        for t in tokens
    )


def _grep_should_inject_file_excludes(args_str: str) -> bool:
    tokens = _split_tokens(args_str)
    if tokens is None:
        return False
    after_dd = False
    for tok in tokens:
        if tok == "--":
            after_dd = True
            continue
        if not after_dd and tok.startswith(("--exclude", "--include")):
            return False
        base = os.path.basename(tok).lower()
        if base in _GREP_EXCLUDED_BASENAMES or base.endswith(_GREP_EXCLUDED_SUFFIXES):
            return False
    return True


def _grep_targets_excluded_dir(args_str: str) -> bool:
    tokens = _split_tokens(args_str)
    return True if tokens is None else any(_GREP_EXCLUDED_DIRS.intersection(t.split("/")) for t in [t for t in tokens if not t.startswith("-")][1:])


def _twg_has_relative_file_arg(args_str: str) -> bool:
    tokens = _split_tokens(args_str)
    return True if tokens is None else any(not t.startswith("-") and _RELATIVE_FILE_ARG_RE.match(t) for t in tokens)


def _has_double_dash_or_bad_quotes(command: str) -> bool:
    tokens = _split_tokens(command)
    return tokens is None or "--" in tokens


def rewrite_quiet_cli_flags(command_line: str) -> str | None:
    """Append output-trimming flags to single-statement test runners, bare git status, or recursive grep."""
    cd_prefix, remainder = split_leading_cd_prefix(command_line.strip())
    stripped = remainder.strip()
    if any(op in _QUOTED_STRING_RE.sub(" ", stripped) for op in (*_SHELL_CHAIN_OPERATORS, "&", *_SHELL_REDIRECTION_OPERATORS)):
        return None
    twg_match = _TWG_NONCANONICAL_RE.match(stripped)
    if twg_match and "$(" not in stripped and (cd_prefix or (not stripped.startswith("twg ") and stripped != "twg")):
        suffix = twg_match.group(1) or ""
        return None if (cd_prefix and _twg_has_relative_file_arg(suffix)) else f"twg{suffix}"
    if any(op in stripped for op in ("\n", "`", "$(")):
        return None
    grep_match = _GREP_BIN_RE.match(stripped)
    if grep_match:
        raw_args = grep_match.group(2)
        unquoted_args = f" {_QUOTED_STRING_RE.sub(' ', raw_args)} "
        if _GREP_RECURSIVE_FLAG_RE.search(unquoted_args) and "--exclude-dir" not in unquoted_args and not _grep_targets_excluded_dir(raw_args):
            extra = f" {_GREP_FILE_EXCLUDE_FLAGS}" if _grep_should_inject_file_excludes(raw_args) else ""
            return f"{cd_prefix}{grep_match.group(1)} {_GREP_CACHE_EXCLUDE_FLAGS}{extra} {raw_args}"
    if _GIT_STATUS_BARE_RE.match(stripped):
        return f"{cd_prefix}git status -sb"
    if _PYTEST_SINGLE_CMD_RE.match(stripped) and not _pytest_has_verbosity_flags(stripped) and not _has_double_dash_or_bad_quotes(stripped):
        return f"{cd_prefix}{stripped} -q --tb=short --no-header"
    if _CARGO_TEST_SINGLE_CMD_RE.match(stripped) and not _CARGO_TEST_EXISTING_FLAGS_RE.search(stripped) and not _has_double_dash_or_bad_quotes(stripped):
        return f"{cd_prefix}{stripped} -q"
    if _VITEST_SINGLE_CMD_RE.match(stripped) and not _VITEST_EXISTING_FLAGS_RE.search(stripped) and not _has_double_dash_or_bad_quotes(stripped):
        return f"{cd_prefix}{stripped} --reporter=dot"
    return None


__all__ = [
    "extract_outline_pull_targets", "extract_shell_read_targets", "is_bounded_shell_read",
    "is_outline_pull", "is_unbounded_shell_dump", "rewrite_quiet_cli_flags", "split_leading_cd_prefix",
]
