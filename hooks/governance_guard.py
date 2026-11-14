"""Multi-harness governance path guard, shell bypass detector, BigQuery CLI/SDK gate, and mutated-repo tracker."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hooks.file_io import normalize_cmd_basename
from hooks.harness_adapter import NormalizedToolCall
from hooks.local_repo_guard import is_bigquery_sql_tool_call, strip_sql_comments
from hooks.state_store import MUTATED_REPOS_SCHEMA, STATE_FILENAME, locked_state

_GIT_UNSAFE_CONFIG_PREFIXES = (
    "alias.",
    "core.fsmonitor",
    "core.sshcommand",
    "core.hookspath",
    "core.editor",
    "core.pager",
    "pager.",
    "diff.external",
    "filter.",
    "credential.",
)


def is_safe_git_config_kv(cfg_kv: str) -> bool:
    """Reject `git -c <key>=<val>` pairs that can execute external commands or rewrite subcommands."""
    lower_kv = cfg_kv.strip().lower()
    if not lower_kv or "!" in lower_kv:
        return False
    return not lower_kv.startswith(_GIT_UNSAFE_CONFIG_PREFIXES)

__all__ = ["PROTECTED_GOVERNANCE_SUFFIXES", "STATIC_GOVERNANCE_INTERNAL_DENY_REASON", "check_shell_bigquery_raw", "check_shell_bypass_vectors", "check_shell_protected_writes", "evaluate_governance_and_shell_guards", "is_protected_governance_path", "is_readonly_shell_command", "payload_may_require_fail_closed_guard", "record_mutated_repos_in_state"]
STATIC_GOVERNANCE_INTERNAL_DENY_REASON = "CONTEXT-GUARD GOVERNANCE GUARD INTERNAL ERROR (fail-closed): Unable to verify governance/BigQuery isolation; tool call blocked."
PROTECTED_GOVERNANCE_SUFFIXES: tuple[tuple[str, str], ...] = (("/scripts/audit/", "audit_guard"), ("/scripts/ci/verify_agent_state.py", "verification_token"), ("/scripts/ci/run-quality-suite.sh", "audit_guard"), ("/scripts/hooks/", "git_hooks"), ("/scripts/claude_hooks/", "harness_config"), ("/tests/baselines/", "audit_guard"), ("/.githooks/", "git_hooks"), ("/.husky/", "git_hooks"), ("/.claude/settings.json", "harness_config"), ("/.claude/settings.local.json", "harness_config"), ("/.claude/hooks.json", "harness_config"), ("/.claude/hooks/", "harness_config"), ("/.codex/hooks.json", "harness_config"), ("/.codex/config.toml", "harness_config"), ("/.codex/hooks/", "harness_config"), ("/.codex/rules/", "harness_config"), ("/.cursor/hooks.json", "harness_config"), ("/.cursor/hooks/", "harness_config"), ("/.agents/hooks.json", "harness_config"), ("/.agents/hooks/", "harness_config"))
_GUARD_REPO_SCOPED_SUFFIXES = frozenset({"/scripts/audit/", "/scripts/ci/run-quality-suite.sh", "/scripts/hooks/", "/tests/baselines/"})
_GUARD_CORE_MARKERS = ("scripts/audit/guard_manifest.json", "guard_manifest.json", "audit_guard_config.json", "scripts/ci/verify_agent_state.py", "scripts/hooks/antigravity_stop_guard.py", "tests/baselines/refactoring_slop.json", "tests/baselines/ai_slop_baseline.json")
_PROTECTED_BASENAMES = {"guard_manifest.json": "audit_guard", "audit_guard_config.json": "audit_guard", ".agent-verification-token.json": "verification_token", ".agent-failure-streak.json": "verification_token"}
_PROTECTED_HOME_REL_PREFIXES: tuple[tuple[str, str], ...] = ((".git-hooks/", "git_hooks"), (".cursor/hooks.json", "harness_config"), (".codex/hooks.json", "harness_config"), (".codex/config.toml", "harness_config"), (".codex/hooks/", "harness_config"), (".codex/rules/", "harness_config"), (".claude/settings.json", "harness_config"), (".claude/settings.local.json", "harness_config"), (".gemini/settings.json", "harness_config"), (".gemini/config/", "context_guard_config"), (".config/context-guard/", "context_guard_config"))
_APPLY_PATCH_MOVE_RE = re.compile(r"^\*\*\*\s+Move to:\s+(.+?)\s*$", re.MULTILINE)
_ENV_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_CLI_LONG_FLAG_RE = re.compile(r"^--[A-Za-z0-9][\w-]*(?:=.*)?$", re.DOTALL)
_SED_INPLACE_RE = re.compile(r"^(?:--in-place(?:=.*)?|-[Enrsuz0-9]*i.*)$")
_SED_SUBST_WRITE_RE = re.compile(r"s([^\w\s])(?:\\.|(?!\1)[^\\])*\1(?:\\.|(?!\1)[^\\])*\1[gipmI0-9]*[wWeE]", re.DOTALL)
_EMBEDDED_SLASH_PATH_RE = re.compile(r"[~A-Za-z0-9_./-]+/[A-Za-z0-9_./-]*")
_INLINE_INTERP_RE = re.compile(r"(?:^|[\s;|&(])(?:[\w./-]+/)?(?:python3?(?:\.\d+)?|node|ruby|perl|sh|bash|zsh|dash|ksh)\b(?:[^\n]*?\s-[a-zA-Z]*[ce]\b|[^\n]*?<<-?\s*['\"\\]?[A-Za-z_]\w*)", re.DOTALL)
_INLINE_SHELL_EXEC_RE = re.compile(r"(?:^|[\s;|&(])(?:[\w./-]+/)?(?:sh|bash|zsh|dash|ksh)\b(?:[^\n]*?\s-[a-zA-Z]*c\b|[^\n]*?<<-?\s*['\"\\]?[A-Za-z_]\w*)", re.DOTALL)
_SCRIPT_SHELL_REDIR_RE = re.compile(r"(?:^|[\s;|&()])\d*>>?(?![=>])")
_SCRIPT_OPEN_WRITE_RE = re.compile(r"""\bopen\s*\([^;\n]*?(?:,\s*|\bmode\s*=\s*)['"][rwa+btU]*[wa+][rwa+btU]*['"]""")
_SCRIPT_WRITE_INDICATORS = (".write(", ".writelines(", "write_text", "write_bytes", "writeFileSync", "writeFile", "os.unlink(", ".unlink(", "os.remove(", "os.rename(", ".rename(", "os.replace(", "shutil.", "os.system", "subprocess", "sed -i", "tee ")
_SCRIPT_PROTECTED_SUBSTRINGS = ("guard_manifest.json", "audit_guard_config.json", ".agent-verification-token.json", ".agent-failure-streak.json", ".githooks", ".husky", ".git-hooks", ".claude/settings.json", ".claude/settings.local.json", ".claude/hooks", ".cursor/hooks.json", ".cursor/hooks", ".agents/hooks.json", ".agents/hooks", ".codex/hooks.json", ".codex/config.toml", ".codex/hooks", ".codex/rules", ".gemini/settings.json", ".gemini/config", "context-guard/config.json", "verify_agent_state.py", "scripts/claude_hooks")
_SCRIPT_QUOTED_LIT_RE = re.compile(r"""['"]([^'"\n]{3,240})['"]""")
_SHELL_VAR_REF_RE = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
_LEADING_UNSET_VAR_RE = re.compile(r"^\$(?:\{[A-Za-z_]\w*\}|[A-Za-z_]\w*)(?:/|$)")
_HEREDOC_EXEC_HEADER_RE = re.compile(r"(?:^|[;|&(`])\s*(?:[A-Za-z_]\w*=\S*\s+|(?:env|sudo|command|nohup|exec|builtin)\s+)*(?:[\w./-]+/)?(?:sh|bash|zsh|dash|ksh|python3?(?:\.\d+)?|node|ruby|perl|php|bq|eval|source)\b")
_BQ_PY_SDK_MARKERS = ("bigquery.client", "from google.cloud import bigquery", "google.cloud.bigquery", "read_gbq", "pandas_gbq", "to_gbq", "bigframes")
_BQ_SUBCOMMANDS = frozenset("query head mk update cp extract load insert rm".split())
_TRUTHY_FORBIDDEN_ENV = frozenset("HUSKY_SKIP_HOOKS PRE_COMMIT_ALLOW_NO_CONFIG ALLOW_ASSERTION_REDUCTION ALLOW_TEST_DELETION ALLOW_CUSTOM_VERIFY_CMD SKIP_AGENT_GUARD".split())
_GIT_VALUE_FLAGS = frozenset("-m --message -F --file -C -c --reuse-message --reedit-message --fixup --squash --author --date --cleanup --trailer --pathspec-from-file --strategy -X --strategy-option --onto".split())
_WRITE_REDIRECT_OPS = frozenset("> >> >| &> >& 1> 2> 1>> 2>>".split())
_ALL_REDIRECT_OPS = _WRITE_REDIRECT_OPS | frozenset("< << <<- <> 2>&1 1>&2".split())
_READONLY_SIMPLE_BINS = frozenset("ls pwd wc which type whoami id uname date printenv true false basename dirname realpath readlink echo printf grep rg egrep fgrep head tail cat nl less more stat file du df cut tr".split())
_READONLY_GIT_SUBCMDS = frozenset("status diff log show rev-parse ls-files ls-tree cat-file grep blame shortlog describe".split())
_FIND_WRITE_FLAGS = frozenset("-delete -exec -execdir -ok -okdir -fprint -fprint0 -fls -fprintf".split())
_NON_REPO_TOP_DIRS = frozenset("docs scripts repos .git .agents .claude .codex .cursor .gemini .worktrees".split())
_MUTATING_FILE_BINS = frozenset("tee cp mv rm unlink chmod chown install ln touch truncate".split())
_SHELL_PREFIX_WRAPPERS = frozenset("{ } ! sudo command nohup time timeout nice env builtin exec".split())
_MUTATING_TOOL_NAMES = frozenset("edit multiedit multi_edit write notebookedit strreplace multistrreplace editfile writefile deletefile delete delete_file create_file edit_file write_file replace_file_content multi_replace_file_content write_to_file apply_patch".split())
_SHELL_TOK_RE = re.compile(r"(?P<ws>[ \t\r]+)|(?P<sep>\n|;|&&|\|\||[()]|\|(?!\|)|(?<![><|])&(?!>))|(?P<redir>(?<![^\s;|&><()])(?:1>&2|2>&1|[12]>>|[12]>)|<<-|>>|>\||&>|>&|<<|<>|>|<)|'(?P<sq>[^']*)'?|\"(?P<dq>(?:\\.|[^\"\\])*)\"?|\\(?P<esc>.)|(?P<raw>[^\s'\"\\;|&><()]+)", re.DOTALL)

@dataclass(frozen=True)
class _ShellSegment:
    cd_target: str | None
    env_pairs: tuple[tuple[str, str], ...]
    words: tuple[str, ...]
    redirects: tuple[tuple[str, str], ...]
    is_export: bool = False

def _is_unguarded_git_repo_dir(repo_dir: Path, ws_root: Path | None) -> bool:
    try:
        cur = repo_dir.expanduser().resolve()
        ws_res = ws_root.expanduser().resolve() if ws_root is not None else None
    except OSError:
        return False
    if ws_res is not None and os.path.normcase(str(cur)) == os.path.normcase(str(ws_res)):
        return False
    git_root: Path | None = None
    while cur != cur.parent and (ws_res is None or os.path.normcase(str(cur)) != os.path.normcase(str(ws_res))):
        if (cur / ".git").exists():
            git_root = cur
            break
        cur = cur.parent
    return git_root is not None and not any((git_root / m).exists() for m in _GUARD_CORE_MARKERS)


def _match_posix_candidate(posix_path: str, home_posix: str, fallback_base: Path | None, ws_root: Path | None) -> str | None:
    if not (norm := posix_path.replace("\\", "/").strip()):
        return None
    if (base := norm.rstrip("/").rsplit("/", 1)[-1]) in _PROTECTED_BASENAMES:
        return _PROTECTED_BASENAMES[base]
    for rel_prefix, cat in _PROTECTED_HOME_REL_PREFIXES:
        clean_p = rel_prefix.rstrip("/")
        if any(norm == f"{pfx}{clean_p}" or norm.startswith(f"{pfx}{clean_p}/") for pfx in ("~/", f"{home_posix}/")) or (
            rel_prefix == ".config/context-guard/" and ("/.config/context-guard/" in f"{norm}/" or "/context-guard/config.json" in norm)
        ):
            return cat
    anchored_dir, anchored_file = f"/{norm.strip('/')}/", f"/{norm.strip('/')}"
    is_abs_like = norm.startswith(("/", "~")) or (len(norm) >= 3 and norm[0].isalpha() and norm[1:3] == ":/")
    for sfx, cat in PROTECTED_GOVERNANCE_SUFFIXES:
        matched = (sfx in anchored_dir) if sfx.endswith("/") else anchored_file.endswith(sfx)
        if not matched:
            continue
        if sfx in _GUARD_REPO_SCOPED_SUFFIXES:
            pos = anchored_dir.rfind(sfx) if sfx.endswith("/") else (len(anchored_file) - len(sfx))
            prefix_str = anchored_dir[:pos] if sfx.endswith("/") else anchored_file[:pos]
            if len(prefix_str) >= 3 and prefix_str[0] == "/" and prefix_str[1].isalpha() and prefix_str[2] == ":":
                prefix_str = prefix_str[1:]
            repo_dir = Path(prefix_str) if (is_abs_like and prefix_str) else fallback_base
            if repo_dir is not None and _is_unguarded_git_repo_dir(repo_dir, ws_root):
                continue
        return cat
    return None


def is_protected_governance_path(raw_path: str, cwd: str | None = None, workspace_root: Path | None = None) -> str | None:
    """Return short governance category label if `raw_path` (or its resolved symlink target) is protected."""
    if not (cleaned := raw_path.strip()) or cleaned in ("/dev/null", "NUL", "-"):
        return None
    home_posix = Path.home().as_posix().rstrip("/")
    expanded = os.path.expanduser(f"{home_posix}/{cleaned[6:]}" if cleaned.startswith("$HOME/") else cleaned)
    candidates = [cleaned.replace("\\", "/"), expanded.replace("\\", "/"), os.path.normpath(expanded).replace("\\", "/")]
    exp_path = Path(expanded)
    rel_base = Path(cwd).expanduser() if cwd else (workspace_root.expanduser() if workspace_root is not None else None)
    path_objs = [exp_path] if exp_path.is_absolute() else ([rel_base / exp_path] if rel_base is not None else [])
    for pobj in path_objs:
        candidates.append(os.path.normpath(str(pobj)).replace("\\", "/"))
        try:
            candidates.append(os.path.realpath(str(pobj)).replace("\\", "/"))
        except OSError:
            pass
    if (env_cfg := os.environ.get("CONTEXT_GUARD_CONFIG_PATH", "").strip()):
        env_norms = {os.path.normcase(os.path.normpath(os.path.expanduser(env_cfg))).replace("\\", "/"), os.path.normcase(os.path.realpath(os.path.expanduser(env_cfg))).replace("\\", "/")}
        if any(os.path.normcase(c).replace("\\", "/") in env_norms for c in candidates):
            return "context_guard_config"
    return next((hit for cand in candidates for hit in (_match_posix_candidate(cand, home_posix, rel_base, workspace_root),) if hit), None)

def _find_subshell_end(s: str, j: int) -> int:
    depth, q, n = 1, "", len(s)
    while j < n and depth > 0:
        c = s[j]
        if q:
            j += 1 if (q == '"' and c == "\\" and j + 1 < n) else 0
            q = "" if c == q else q
        elif c == "\\" and j + 1 < n:
            j += 1
        elif c in ("'", '"'):
            q = c
        elif c in ("(", ")"):
            depth += 1 if c == "(" else -1
        j += 1
    return j

def _mask_subshells(command: str) -> tuple[str, list[str], bool]:
    out, subs, in_s, in_d, has_sub, i, n = [], [], False, False, False, 0, len(command)
    while i < n:
        ch = command[i]
        if in_s or (ch == "'" and not in_d):
            in_s, i = ((ch != "'") if in_s else True), i + 1
            out.append(ch)
        elif ch == '"':
            in_d, i = not in_d, i + 1
            out.append(ch)
        elif ch == "\\" and i + 1 < n and (not in_d or command[i + 1] in ('"', "\\", "$", "`")):
            out.append(command[i : i + 2])
            i += 2
        elif ch == "$" and i + 1 < n and command[i + 1] == "(":
            has_sub, j = True, _find_subshell_end(command, i + 2)
            if (inner := command[i + 2 : (j - 1 if j <= n and j > i + 2 and command[j - 1] == ")" else j)].strip()):
                subs.append(inner)
            out.append("__CG_SUB__")
            i = j
        elif ch == "`":
            has_sub, j = True, i + 1
            while j < n and command[j] != "`":
                j += 2 if (command[j] == "\\" and j + 1 < n) else 1
            if (inner := command[i + 1 : j].strip()):
                subs.append(inner)
            out.append("__CG_SUB__")
            i = min(n, j + 1)
        else:
            out.append(ch)
            i += 1
    return "".join(out), subs, has_sub

def _parse_shell_segments(command: str, include_subshells: bool = True) -> tuple[list[_ShellSegment], bool]:
    masked, subs, has_sub = _mask_subshells(command)
    raw_segs: list[list[tuple[str, bool]]] = []
    cur_seg: list[tuple[str, bool]] = []
    cur_w: list[str] = []
    was_q = False

    def _flush(split_seg: bool = False) -> None:
        nonlocal cur_seg, cur_w, was_q
        if cur_w or was_q:
            cur_seg.append(("".join(cur_w), was_q))
            cur_w, was_q = [], False
        if split_seg and cur_seg:
            raw_segs.append(cur_seg)
            cur_seg = []

    for m in _SHELL_TOK_RE.finditer(masked):
        k = m.lastgroup
        if k in ("ws", "sep"):
            _flush(split_seg=(k == "sep"))
        elif k == "redir":
            _flush()
            cur_seg.append((m.group("redir"), False))
        elif k:
            if k == "dq":
                cur_w.append(re.sub(r'\\(["\\$`])', r"\1", m.group("dq")))
            elif k == "esc":
                esc_ch, prefix = m.group("esc"), "".join(cur_w)
                keep_bs = (len(prefix) >= 2 and prefix[0].isalpha() and prefix[1] == ":") or (os.name == "nt" and (esc_ch.isalnum() or esc_ch in "_.-~"))
                cur_w.append(f"\\{esc_ch}" if keep_bs else esc_ch)
            else:
                cur_w.append(m.group(k))
            was_q = was_q or (k != "raw")
    _flush(split_seg=True)
    parsed: list[_ShellSegment] = []
    for seg in raw_segs:
        redirects, words, i = [], [], 0
        while i < len(seg):
            tok, q = seg[i]
            if not q and tok in _ALL_REDIRECT_OPS:
                redirects.append((tok, "" if tok in ("2>&1", "1>&2") else (seg[i + 1][0] if i + 1 < len(seg) else "")))
                i += 1 if tok in ("2>&1", "1>&2") else 2
            else:
                words.append(tok)
                i += 1
        env_pairs, is_export, idx = [], False, 0
        while idx < len(words):
            w = words[idx]
            w_base = w if "=" in w else normalize_cmd_basename(w)
            if w_base in ("env", "export"):
                is_export, idx = (w_base == "export"), idx + 1
                while idx < len(words) and ((m_e := _ENV_ASSIGN_RE.match(words[idx])) is not None or (w_base == "env" and words[idx].startswith("-"))):
                    if m_e is not None:
                        env_pairs.append((m_e.group(1), m_e.group(2)))
                    idx += 1
                idx = len(words) if is_export else idx
            elif w_base in _SHELL_PREFIX_WRAPPERS:
                idx += 1
                if w_base == "timeout":
                    while idx < len(words) and words[idx].startswith("-"):
                        idx += 2 if words[idx] in ("-k", "-s", "--kill-after", "--signal") and idx + 1 < len(words) else 1
                    if idx < len(words) and re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", words[idx]):
                        idx += 1
                elif w_base == "nice":
                    while idx < len(words) and words[idx].startswith("-"):
                        idx += 2 if words[idx] in ("-n", "--adjustment") and idx + 1 < len(words) else 1
            elif (m_l := _ENV_ASSIGN_RE.match(w)) is not None:
                env_pairs.append((m_l.group(1), m_l.group(2)))
                idx += 1
            else:
                break
        rem = words[idx:]
        while rem and rem[-1] == "}":
            rem.pop()
        if rem or env_pairs or redirects or is_export:
            c_args = [a for a in rem[1:] if a not in ("-L", "-P", "--")] if (rem and rem[0] == "cd" and not redirects) else []
            cd_target = c_args[0] if (len(c_args) == 1 and c_args[0] != "-" and "$" not in c_args[0]) else None
            parsed.append(_ShellSegment(cd_target, tuple(env_pairs), tuple(rem), tuple(redirects), is_export))
    for sub in (subs if include_subshells else ()):
        parsed.extend(_parse_shell_segments(sub, include_subshells=True)[0])
    return parsed, has_sub

def _parse_git_head(args: tuple[str, ...]) -> tuple[str | None, tuple[str, ...], str | None, bool, bool]:
    idx, dash_c_dir, hookspath, safe_cfg = 0, None, False, True
    while idx < len(args):
        tok = args[idx]
        if tok == "-c" or (tok.startswith("-c") and len(tok) > 2):
            kv = (args[idx + 1] if idx + 1 < len(args) else "") if tok == "-c" else tok[2:]
            hookspath = hookspath or kv.strip().lower().startswith("core.hookspath")
            safe_cfg, idx = safe_cfg and bool((idx + 1 < len(args) or tok != "-c") and is_safe_git_config_kv(kv)), idx + (2 if tok == "-c" else 1)
        elif tok == "-C":
            dash_c_dir = args[idx + 1] if idx + 1 < len(args) else dash_c_dir
            safe_cfg, idx = safe_cfg and (idx + 1 < len(args)), idx + 2
        elif tok in ("--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"):
            hookspath = hookspath or (tok == "--config-env" and idx + 1 < len(args) and "core.hookspath" in args[idx + 1].lower())
            safe_cfg, idx = safe_cfg and (idx + 1 < len(args)), idx + 2
        elif tok.startswith("-"):
            hookspath, idx = hookspath or ("core.hookspath" in tok.lower()), idx + 1
        else:
            return tok, args[idx + 1 :], dash_c_dir, hookspath, safe_cfg
    return None, (), dash_c_dir, hookspath, safe_cfg

def _check_git_bypass(tokens: tuple[str, ...]) -> str | None:
    subcmd, rest, _, hookspath, _ = _parse_git_head(tokens[1:])
    if hookspath:
        return "CONTEXT-GUARD GOVERNANCE BLOCK: Overriding `core.hooksPath` via `git` is forbidden."
    if subcmd == "config" and not any(t in ("--get", "--get-all", "--get-regexp", "--list", "-l") for t in rest) and any(
        t.lower() == "core.hookspath" or t.lower().startswith("core.hookspath=") for t in rest
    ):
        return "CONTEXT-GUARD GOVERNANCE BLOCK: Mutating `git config core.hooksPath` is forbidden."
    if subcmd == "add":
        pre_dd = rest[: rest.index("--")] if "--" in rest else rest
        if any(t in ("-A", "--all", "--no-ignore-removal") or (t.startswith("-") and not t.startswith("--") and "A" in t[1:]) for t in pre_dd):
            return "CONTEXT-GUARD GOVERNANCE BLOCK: Mass staging (`git add -A` / `--all`) is forbidden; stage explicit file paths."
        if any(t in (".", "./") or os.path.normpath(t) == "." for t in rest if t != "--"):
            return "CONTEXT-GUARD GOVERNANCE BLOCK: `git add .` is forbidden; stage explicit file paths."
    elif subcmd in ("commit", "push", "merge", "cherry-pick", "rebase", "am"):
        j = 0
        while j < len(rest) and rest[j] != "--":
            t = rest[j]
            if t in ("--no-verify", "--reset-circuit-breaker"):
                return f"CONTEXT-GUARD GOVERNANCE BLOCK: `git {subcmd} {t}` hook bypass is forbidden."
            if t in _GIT_VALUE_FLAGS:
                j += 2
            elif t.startswith("-") and not t.startswith("--") and len(t) >= 2:
                chars, skip_next = t[1:], False
                for pos, ch in enumerate(chars):
                    if ch == "n" and subcmd in ("commit", "push"):
                        return f"CONTEXT-GUARD GOVERNANCE BLOCK: `git {subcmd} -{chars}` (`--no-verify`) is forbidden."
                    if ch in ("m", "F", "C", "c", "X"):
                        skip_next = pos == len(chars) - 1
                        break
                j += 2 if skip_next else 1
            else:
                j += 1
    return None

_HEREDOC_START_RE = re.compile(r"<<-?\s*(?:(['\"])([A-Za-z_]\w*)\1|\\?([A-Za-z_]\w*))")


def _strip_heredoc_bodies(cmd: str, *, keep_exec_bodies: bool = False) -> str:
    out: list[str] = []
    end_marker: str | None = None
    allow_tabs = False
    for line in cmd.splitlines():
        if end_marker is not None:
            if (line.lstrip("\t") if allow_tabs else line).strip() == end_marker:
                end_marker = None
            continue
        out.append(line)
        if (m := _HEREDOC_START_RE.search(line)) and not (keep_exec_bodies and _HEREDOC_EXEC_HEADER_RE.search(line)):
            end_marker = m.group(2) or m.group(3)
            allow_tabs = line[m.start() : m.end()].startswith("<<-")
    return "\n".join(out)


def _expand_shell_vars(raw: str, env_map: dict[str, str]) -> str:
    return _SHELL_VAR_REF_RE.sub(lambda m: env_map.get(m.group(1) or m.group(2) or "", m.group(0)), raw) if "$" in raw and env_map else raw


def _check_shell_write_target(raw_target: str, eff_cwd: str | None, ws_root: Path | None, env_map: dict[str, str]) -> str | None:
    expanded = _expand_shell_vars(raw_target, env_map)
    if not expanded.startswith("$HOME/") and (m_var := _LEADING_UNSET_VAR_RE.match(expanded)) is not None:
        tail = expanded[m_var.end() :]
        return is_protected_governance_path(tail, cwd=None, workspace_root=None) if tail else None
    return is_protected_governance_path(expanded, cwd=eff_cwd, workspace_root=ws_root)


def _cp_dest_operands(args: tuple[str, ...]) -> list[str]:
    targets, non_flags, idx = [], [], 0
    while idx < len(args):
        a = args[idx]
        if a in ("-t", "--target-directory") and idx + 1 < len(args):
            targets.append(args[idx + 1])
            idx += 2
        elif a.startswith("--target-directory="):
            targets.append(a.split("=", 1)[1])
            idx += 1
        elif a.startswith("-t") and not a.startswith("--") and len(a) > 2:
            targets.append(a[2:])
            idx += 1
        else:
            if not a.startswith("-"):
                non_flags.append(a)
            idx += 1
    return targets or ([non_flags[-1]] if len(non_flags) >= 2 else non_flags)


def check_shell_bypass_vectors(command: str) -> str | None:
    """Return block reason if `command` contains git hook bypasses, forbidden env vars, mass staging, or circuit-breaker resets."""
    stripped_cmd = _strip_heredoc_bodies(command, keep_exec_bodies=True) if command and command.strip() else ""
    for seg in (_parse_shell_segments(stripped_cmd)[0] if stripped_cmd else ()):
        cmd_bin = "export" if seg.is_export else (normalize_cmd_basename(seg.words[0]) if seg.words else "")
        for key, val in seg.env_pairs:
            v_low = val.strip().lower()
            if (key == "HUSKY" and v_low == "0") or (key in _TRUTHY_FORBIDDEN_ENV and v_low not in ("", "0", "false", "no")) or (key == "SKIP" and v_low and cmd_bin in ("git", "pre-commit", "export", "")):
                return f"CONTEXT-GUARD GOVERNANCE BLOCK: Hook/guard bypass via `{key}={val}` is forbidden."
            if ((key == "GIT_CONFIG_PARAMETERS" or key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))) and "core.hookspath" in v_low) or (
                key == "GIT_CONFIG_COUNT" and v_low not in ("", "0") and not any(k.startswith("GIT_CONFIG_KEY_") for k, _ in seg.env_pairs)
            ):
                return f"CONTEXT-GUARD GOVERNANCE BLOCK: Overriding `core.hooksPath` via `{key}` is forbidden."
        if cmd_bin == "git":
            if (git_hit := _check_git_bypass(seg.words)) is not None:
                return git_hit
        elif seg.words:
            for pos, tok in enumerate(seg.words[1:], start=1):
                if tok == "--reset-circuit-breaker" or tok.startswith("--reset-circuit-breaker="):
                    return "CONTEXT-GUARD GOVERNANCE BLOCK: `--reset-circuit-breaker` is reserved for human operators."
                if tok == "--capture-baseline" or tok.startswith("--capture-baseline="):
                    return "CONTEXT-GUARD GOVERNANCE BLOCK: `--capture-baseline` is reserved for SessionStart hooks (`stop_guard_baseline_tamper`)."
                if cmd_bin in ("python", "python3") and tok == "-c" and pos + 1 < len(seg.words) and "--capture-baseline" in seg.words[pos + 1]:
                    return "CONTEXT-GUARD GOVERNANCE BLOCK: `--capture-baseline` is reserved for SessionStart hooks (`stop_guard_baseline_tamper`)."
                if cmd_bin in ("sh", "bash", "zsh", "dash", "ksh") and tok.startswith("-") and not tok.startswith("--") and "c" in tok[1:] and pos + 1 < len(seg.words) and (sub_hit := check_shell_bypass_vectors(seg.words[pos + 1])) is not None:
                    return sub_hit
    return None

def _advance_cwd(cur_cwd: str | None, cd_target: str | None) -> str | None:
    exp = os.path.expanduser(cd_target) if cd_target else ""
    return cur_cwd if not exp else (exp if os.path.isabs(exp) else (str(Path(cur_cwd) / exp) if cur_cwd else exp))

def check_shell_protected_writes(command: str, cwd: str | None = None, workspace_root: Path | None = None, _depth: int = 0) -> str | None:
    """Return block reason if `command` mutates a protected governance path via redirection, CLI tools, or inline scripts."""
    if _depth > 8:
        return "CONTEXT-GUARD GOVERNANCE BLOCK: Nested shell depth limit exceeded."
    if not command or not command.strip():
        return None
    stripped_cmd = _strip_heredoc_bodies(command, keep_exec_bodies=True)
    eff_cwd: str | None = cwd
    shell_vars: dict[str, str] = {}
    heredoc_tail = stripped_cmd.split("\n", 1)[1] if "\n" in stripped_cmd else ""
    for seg in _parse_shell_segments(stripped_cmd)[0]:
        eff_vars = {**shell_vars, **{k: _expand_shell_vars(v, shell_vars) for k, v in seg.env_pairs}}
        if not seg.words and seg.env_pairs:
            shell_vars.update(eff_vars)
        if seg.cd_target is not None or (seg.words and seg.words[0] == "cd" and not seg.redirects):
            c_args = [a for a in seg.words[1:] if a not in ("-L", "-P", "--")] if seg.words else []
            cd_dest = seg.cd_target or (_expand_shell_vars(c_args[0], eff_vars) if len(c_args) == 1 and c_args[0] != "-" else None)
            if cd_dest and "$" not in cd_dest:
                eff_cwd = _advance_cwd(eff_cwd, cd_dest)
            continue
        for op, target in seg.redirects:
            if op in _WRITE_REDIRECT_OPS and target and not target.startswith("&") and (cat := _check_shell_write_target(target, eff_cwd, workspace_root, eff_vars)) is not None:
                return f"CONTEXT-GUARD GOVERNANCE BLOCK: Shell redirection targeting protected path `{target}` (`{cat}`) is forbidden."
        if not seg.words:
            continue
        cmd_bin, args = normalize_cmd_basename(seg.words[0]), seg.words[1:]
        seg_head = " ".join((cmd_bin, *args, *(f"{op} {tgt}" for op, tgt in seg.redirects)))
        if _INLINE_INTERP_RE.search(seg_head):
            has_hd = any(op in ("<<", "<<-") for op, _ in seg.redirects)
            seg_text = f"{seg_head}\n{heredoc_tail}" if (has_hd and heredoc_tail) else seg_head
            has_inline_write = (
                any(ind in seg_text for ind in _SCRIPT_WRITE_INDICATORS)
                or _SCRIPT_OPEN_WRITE_RE.search(seg_text) is not None
                or (_INLINE_SHELL_EXEC_RE.search(seg_text) is not None and _SCRIPT_SHELL_REDIR_RE.search(seg_text) is not None)
            )
            if has_inline_write:
                inline_cands = [m.group(1) for m in _SCRIPT_QUOTED_LIT_RE.finditer(seg_text)] + [
                    m.group(0) for m in _EMBEDDED_SLASH_PATH_RE.finditer(seg_text)
                ]
                if any(sub in seg_text for sub in _SCRIPT_PROTECTED_SUBSTRINGS) or any(
                    _check_shell_write_target(cand, eff_cwd, workspace_root, eff_vars) is not None for cand in inline_cands
                ):
                    return "CONTEXT-GUARD GOVERNANCE BLOCK: Inline script/heredoc write targeting a protected governance path is forbidden."
        if cmd_bin in ("sh", "bash", "zsh", "dash", "ksh"):
            for pos, a in enumerate(args):
                if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and pos + 1 < len(args) and (sub := check_shell_protected_writes(args[pos + 1], cwd=eff_cwd, workspace_root=workspace_root, _depth=_depth + 1)) is not None:
                    return sub
        operands, check_cwd = [], eff_cwd
        if cmd_bin in ("cp", "install"):
            operands = _cp_dest_operands(args)
        elif (cmd_bin in ("sed", "gsed") and any(_SED_INPLACE_RE.match(a) for a in args)) or (
            cmd_bin in ("perl", "ruby") and any(a.startswith("-") and not a.startswith("--") and "i" in a[1:] for a in args)
        ) or cmd_bin in _MUTATING_FILE_BINS:
            operands = [a for a in args if not a.startswith("-")]
        elif cmd_bin == "dd":
            operands = [a[3:] for a in args if a.startswith("of=")]
        elif cmd_bin == "git":
            subcmd, rest, dash_c, _, _ = _parse_git_head(args)
            check_cwd = _advance_cwd(check_cwd, _expand_shell_vars(dash_c, eff_vars) if dash_c else None)
            operands = [a for a in rest if a != "--" and not a.startswith("-")] if subcmd in ("checkout", "restore", "rm", "mv", "clean", "apply") else []
        for op_path in operands:
            if (cat := _check_shell_write_target(op_path, check_cwd, workspace_root, eff_vars)) is not None:
                return f"CONTEXT-GUARD GOVERNANCE BLOCK: `{cmd_bin}` targeting protected governance path `{op_path}` (`{cat}`) is forbidden."
    return None

def check_shell_bigquery_raw(command: str, cfg: dict[str, Any], _depth: int = 0) -> str | None:
    """Block `bq` CLI and Python BigQuery SDK queries against restricted raw datasets."""
    if _depth > 8:
        return "CONTEXT-GUARD BIGQUERY AI-VIEWS BLOCK: Nested shell depth limit exceeded."
    segments = _parse_shell_segments(command)[0] if command and command.strip() else []
    for seg in segments:
        if seg.words and normalize_cmd_basename(seg.words[0]) in ("sh", "bash", "zsh", "dash", "ksh"):
            for pos, tok in enumerate(seg.words[1:], start=1):
                if tok.startswith("-") and not tok.startswith("--") and "c" in tok[1:] and pos + 1 < len(seg.words):
                    if (sub_hit := check_shell_bigquery_raw(seg.words[pos + 1], cfg, _depth=_depth + 1)) is not None:
                        return sub_hit
    bq_segs = [seg for seg in segments if seg.words and normalize_cmd_basename(seg.words[0]) == "bq" and any(t in _BQ_SUBCOMMANDS for t in seg.words[1:])]
    if not bq_segs and not (command and any(marker in command.lower() for marker in _BQ_PY_SDK_MARKERS)):
        return None
    if isinstance(cfg.get("config_error"), str) and cfg["config_error"]:
        return f"CONTEXT-GUARD BIGQUERY CONFIG ERROR (fail-closed): {cfg['config_error']}"
    if cfg.get("allow_bq_raw_ddl_maintenance") is True or not (restricted := tuple(cfg.get("restricted_bq_datasets") or ())):
        return None
    restricted_low = {ds.lower() for ds in restricted}
    ds_flags = [
        w.split("=", 1)[1] if w.startswith(("--dataset_id=", "-d=")) else (seg.words[idx + 1] if w in ("--dataset_id", "-d") and idx + 1 < len(seg.words) else w[2:])
        for seg in bq_segs for idx, w in enumerate(seg.words[1:], start=1)
        if w.startswith(("--dataset_id=", "-d=")) or (w in ("--dataset_id", "-d") and idx + 1 < len(seg.words)) or (w.startswith("-d") and len(w) > 2 and not w.startswith("--"))
    ]
    flag_hit = any(dv.strip("`\"'").rsplit(":", 1)[-1].rsplit(".", 1)[-1].lower() in restricted_low for dv in ds_flags)
    joined = "|".join(re.escape(ds) for ds in restricted)
    forbidden_re = re.compile(rf"(?:^|[\s:`\"'(.])(?:{joined})\s*[`\"']?\s*\.|:[`\"']?(?:{joined})\b|\bSCHEMA\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?[`\"'\w.:-]*\b(?:{joined})\b", re.IGNORECASE)
    sql_chunks = [strip_sql_comments(w) for seg in segments for w in seg.words[1:] if not _CLI_LONG_FLAG_RE.match(w)] + ([strip_sql_comments(command.split("\n", 1)[1])] if "\n" in command else [])
    if not flag_hit and not any(forbidden_re.search(chunk) for chunk in sql_chunks):
        return None
    ds_label, hint = ", ".join(f"`{ds}`" for ds in restricted), cfg.get("allowed_bq_views_hint") or "authorized views"
    return f'CONTEXT-GUARD BIGQUERY AI-VIEWS BLOCK: Shell/SDK query to {ds_label} is blocked by Zero-Trust data isolation rules. Query `{hint}` instead. Operator DDL maintenance requires `"allow_bq_raw_ddl_maintenance": true` in `config.json`.'

def evaluate_governance_and_shell_guards(norm: NormalizedToolCall, cfg: dict[str, Any]) -> dict[str, Any] | None:
    """Evaluate opt-in governance policy (`enforce_governance_policy`) and BigQuery CLI/SDK guards."""
    ws_root = cfg.get("workspace_root") if isinstance(cfg.get("workspace_root"), Path) else None
    cfg_err = cfg.get("config_error")
    has_cfg_err = isinstance(cfg_err, str) and bool(cfg_err)
    err_dec = {"decision": "deny", "reason": f"CONTEXT-GUARD GOVERNANCE CONFIG ERROR (fail-closed): {cfg_err}"} if has_cfg_err else None
    enforce_gov = has_cfg_err or (cfg.get("enforce_governance_policy") is True)
    if enforce_gov:
        targets: list[str] = list(norm.mutated_paths)
        if norm.canonical_tool in ("edit_file", "write_file"):
            targets.extend(val.strip() for k in ("Path", "TargetFile", "AbsolutePath") for val in (norm.canonical_args.get(k),) if isinstance(val, str) and val.strip() and val.strip() not in targets)
        if norm.original_tool_name == "apply_patch":
            targets.extend(m.group(1).strip() for m in _APPLY_PATCH_MOVE_RE.finditer(str(norm.original_tool_input.get("patch") or norm.original_tool_input.get("input") or "")))
        for target in targets:
            if (cat := is_protected_governance_path(target, cwd=norm.cwd, workspace_root=ws_root)) is not None and (has_cfg_err or not cfg.get("allow_governance_mutations", False)):
                return err_dec or {"decision": "deny", "reason": f"CONTEXT-GUARD GOVERNANCE BLOCK: Direct modification of protected `{cat}` asset `{target}` is forbidden."}
    if norm.canonical_tool == "run_command":
        cmd = str(norm.canonical_args.get("CommandLine") or "")
        if enforce_gov:
            if (bypass_reason := check_shell_bypass_vectors(cmd)) is not None:
                return err_dec or {"decision": "deny", "reason": bypass_reason}
            if (write_reason := check_shell_protected_writes(cmd, cwd=norm.cwd, workspace_root=ws_root)) is not None and (has_cfg_err or not cfg.get("allow_governance_mutations", False)):
                return err_dec or {"decision": "deny", "reason": write_reason}
        if (bq_reason := check_shell_bigquery_raw(cmd, cfg)) is not None:
            return {"decision": "deny", "reason": bq_reason}
    return None

def payload_may_require_fail_closed_guard(norm: NormalizedToolCall) -> bool:
    """Return True for any mutating file/patch call, MCP BigQuery/SQL call, or non-empty shell command."""
    ctool, otool = norm.canonical_tool.lower(), norm.original_tool_name.lower()
    if norm.mutated_paths or ctool in _MUTATING_TOOL_NAMES or otool in _MUTATING_TOOL_NAMES or is_bigquery_sql_tool_call(norm.canonical_tool, norm.canonical_args) or any(k in ctool or k in otool for k in ("bigquery", "execute_sql")):
        return True
    cmd = str(norm.canonical_args.get("CommandLine") or norm.original_tool_input.get("command") or norm.original_tool_input.get("cmd") or "").strip()
    return bool(cmd) and (norm.canonical_tool == "run_command" or otool in ("bash", "shell", "exec", "exec_command", "shell_command", "run_command", "run_terminal_cmd"))

def _is_readonly_git_segment(args: tuple[str, ...]) -> bool:
    subcmd, rest, _, hookspath, safe_cfg = _parse_git_head(args)
    bad_git_flag = any(
        tok in ("-o", "--output", "--ext-diff", "--exec-path")
        or tok.startswith(("--output=", "--ext-diff=", "--exec-path="))
        or (tok.startswith("-o") and not tok.startswith("--"))
        for tok in args
    )
    if bad_git_flag or not safe_cfg or hookspath or subcmd is None:
        return False
    if subcmd in _READONLY_GIT_SUBCMDS:
        return True
    if subcmd == "branch":
        return all(t in ("--show-current", "-a", "--all", "-r", "--remotes", "-l", "--list", "-v", "-vv") for t in rest)
    return (all(t in ("-v", "--verbose") for t in rest) if subcmd == "remote" else False) or (
        subcmd == "config" and any(t in ("--get", "--get-all", "--get-regexp", "--list", "-l") for t in rest) and not any(t in ("--unset", "--unset-all", "--add", "--replace-all", "-e", "--edit") for t in rest)
    )

def _is_readonly_sed_args(args: tuple[str, ...]) -> bool:
    has_quiet = any(a in ("-n", "--quiet", "--silent") or (a.startswith("-") and not a.startswith("--") and "n" in a[1:]) for a in args)
    if not has_quiet or any(_SED_INPLACE_RE.match(a) or a in ("-f", "--file") or a.startswith(("-f", "--file=")) for a in args):
        return False
    scripts: list[str] = []
    idx = 0
    while idx < len(args):
        a = args[idx]
        if a in ("-e", "--expression") and idx + 1 < len(args):
            scripts.append(args[idx + 1])
            idx += 2
        elif a.startswith("--expression="):
            scripts.append(a.split("=", 1)[1])
            idx += 1
        elif a.startswith("-e") and not a.startswith("--") and len(a) > 2:
            scripts.append(a[2:])
            idx += 1
        else:
            idx += 1
    if not scripts:
        scripts = [next((a for a in args if not a.startswith("-")), "")]
    for scr in scripts:
        if _SED_SUBST_WRITE_RE.search(scr):
            return False
        stripped = re.sub(r"/(\\.|[^/\\])*/", "//", re.sub(r"s([^\w\s])(?:\\.|(?!\1)[^\\])*\1(?:\\.|(?!\1)[^\\])*\1[gipmI0-9]*", "", scr, flags=re.DOTALL))
        if re.search(r"[wWeE]", stripped):
            return False
    return True

def is_readonly_shell_command(command: str) -> bool:
    """Return True only when every statement and pipeline segment in `command` is strictly read-only."""
    segments, has_sub = _parse_shell_segments(command, include_subshells=False) if command and command.strip() else ([], True)
    if has_sub or not segments:
        return False
    for seg in segments:
        if any(op in ("<<", "<<-", "<>") or (op in _WRITE_REDIRECT_OPS and target != "/dev/null") for op, target in seg.redirects):
            return False
        if seg.cd_target is not None:
            continue
        if not seg.words:
            return False
        cmd_bin, args = normalize_cmd_basename(seg.words[0]), seg.words[1:]
        uniq_ok = cmd_bin == "uniq" and sum(1 for a in args if a != "--" and (not a.startswith("-") or a == "-")) <= 1
        if not ((_is_readonly_git_segment(args) if cmd_bin == "git" else False) or uniq_ok or (cmd_bin in _READONLY_SIMPLE_BINS and not (cmd_bin == "rg" and any(a == "--pre" or a.startswith("--pre=") for a in args))) or (cmd_bin == "sort" and not any(a in ("-o", "--output") or a.startswith(("-o", "--output=")) for a in args)) or (cmd_bin in ("sed", "gsed") and _is_readonly_sed_args(args)) or (cmd_bin == "find" and not any(a in _FIND_WRITE_FLAGS or a.startswith(("-fprint", "-fls")) for a in args))):
            return False
    return True

def _map_path_to_repo(cand_str: str, base_dir: Path, ws_root: Path) -> str | None:
    if not (cleaned := cand_str.strip()) or cleaned.startswith("-") or "://" in cleaned:
        return None
    exp = Path(os.path.expanduser(cleaned))
    try:
        resolved = (exp if exp.is_absolute() else (base_dir / exp)).resolve()
        rel = resolved.relative_to(ws_root)
    except (OSError, ValueError):
        return None
    if not rel.parts or rel.parts[0] in _NON_REPO_TOP_DIRS:
        return None
    for idx, seg in enumerate(rel.parts):
        if seg == ".worktrees" and idx + 1 < len(rel.parts):
            return Path(*rel.parts[: idx + 2]).as_posix()
        if seg in (".claude", ".codex", ".cursor", ".git") and idx + 2 < len(rel.parts) and rel.parts[idx + 1] == "worktrees":
            return Path(*rel.parts[: idx + 3]).as_posix()
    cur = resolved if resolved.is_dir() else resolved.parent
    while cur != ws_root and ws_root in cur.parents:
        if cur.name != ".git" and (cur / ".git").exists():
            return cur.relative_to(ws_root).as_posix()
        cur = cur.parent
    return None

def _scrub_legacy_mutated_repos(state_dir_path: Path) -> None:
    sf = state_dir_path / STATE_FILENAME
    try:
        if sf.is_file() and '"mutated_repos"' in (raw := sf.read_text(encoding="utf-8")) and '"mutated_repos_schema"' not in raw:
            with locked_state(state_dir_path, create=False):
                pass
    except OSError:
        pass

def record_mutated_repos_in_state(state_dir_path: Path, norm: NormalizedToolCall, workspace_root: Path | None) -> None:
    """Record resolved workspace-relative repository names mutated by structured file-write tools."""
    _scrub_legacy_mutated_repos(state_dir_path)
    if not norm.mutated_paths and norm.canonical_tool not in ("edit_file", "write_file"):
        return
    env_ws = os.environ.get("CONTEXT_GUARD_WORKSPACE_ROOT", "").strip()
    raw_ws = workspace_root or (Path(env_ws) if env_ws else None)
    if raw_ws is None:
        return
    ws_root = raw_ws.expanduser().resolve()
    base_dir = Path(norm.cwd).expanduser().resolve() if norm.cwd else ws_root
    p_arg = norm.canonical_args.get("Path")
    raw_paths = list(norm.mutated_paths) or ([p_arg.strip()] if isinstance(p_arg, str) and p_arg.strip() else [])
    if not (discovered := {r for raw_c in raw_paths for r in (_map_path_to_repo(raw_c, base_dir, ws_root),) if r}):
        return
    with locked_state(state_dir_path) as txn:
        prev = txn.state.get("mutated_repos")
        merged = sorted((set(prev) if isinstance(prev, list) else set()) | discovered)
        if prev != merged or txn.state.get("mutated_repos_schema") != MUTATED_REPOS_SCHEMA:
            txn.state["mutated_repos"] = merged
            txn.state["mutated_repos_schema"] = MUTATED_REPOS_SCHEMA
            txn.dirty = True
