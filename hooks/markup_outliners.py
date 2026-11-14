#!/usr/bin/env python3
"""Zero-dependency structural outliners for Markdown, Diff, HTML/Hyvä/Vue, XML, JSON/YAML, and Logs."""

from __future__ import annotations

import re

_RUST_CHAR_RE = re.compile(r"'(?:\\.[^']*|[^'\\])'")  # char literal; a bare `'a` is a lifetime


def find_block_end(
    lines: list[str],
    start_idx: int,
    max_idx: int | None = None,
    *,
    allow_hash_comment: bool = False,
    track_brackets: bool = False,
    rust_lifetimes: bool = False,
) -> int:
    """Find 1-based closing line of a block starting at 0-based `start_idx`, ignoring strings and comments."""
    limit = len(lines) if max_idx is None else min(len(lines), max_idx + 1)
    depth = 0
    paren_depth = 0
    found_open = False
    in_quote: str | None = None
    escaped = False
    in_block_comment = False

    for idx in range(start_idx, limit):
        line = lines[idx]
        col = 0
        line_len = len(line)
        while col < line_len:
            ch = line[col]
            if in_block_comment:
                if line[col : col + 2] == "*/":
                    in_block_comment = False
                    col += 2
                else:
                    col += 1
                continue

            if in_quote is not None:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == in_quote:
                    in_quote = None
                col += 1
                continue

            two_chars = line[col : col + 2]
            if two_chars == "//":
                break
            if two_chars == "/*":
                in_block_comment = True
                col += 2
                continue
            if allow_hash_comment and ch == "#":
                break
            if rust_lifetimes and ch == "'":
                m_char = _RUST_CHAR_RE.match(line, col)
                col = m_char.end() if m_char else col + 1
                continue
            if ch in ("'", '"', "`"):
                in_quote = ch
                col += 1
                continue

            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)
            elif ch == "{" or (track_brackets and ch == "["):
                depth += 1
                found_open = True
            elif ch == "}" or (track_brackets and ch == "]"):
                depth -= 1
                if found_open and depth <= 0:
                    return idx + 1
            elif not track_brackets and ch == ";" and not found_open and paren_depth == 0:
                return idx + 1

            col += 1

    return start_idx + 1


_find_brace_block_end = find_block_end


def outline_markdown(source: str) -> list[str]:
    """Extract ATX Markdown headings (`#` .. `######`) with section line spans, ignoring code fences."""
    lines = source.splitlines()
    total = len(lines)
    if total == 0:
        return []

    fence_re = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
    heading_re = re.compile(r"^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
    table_delim_re = re.compile(r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?\s*$")

    headings: list[tuple[int, int, str]] = []
    in_fence_char: str | None = None
    in_fence_len = 0

    for idx, line in enumerate(lines):
        m_fence = fence_re.match(line)
        if m_fence:
            marker = m_fence.group(1)
            rest = m_fence.group(2)
            ch = marker[0]
            if in_fence_char is None:
                in_fence_char = ch
                in_fence_len = len(marker)
            elif ch == in_fence_char and len(marker) >= in_fence_len and not rest.strip():
                in_fence_char = None
                in_fence_len = 0
            continue

        if in_fence_char is not None:
            continue

        m_head = heading_re.match(line)
        if m_head:
            level = len(m_head.group(1))
            title = m_head.group(2).strip()
            headings.append((idx + 1, level, title))

    out: list[str] = []
    for i, (start_line, level, title) in enumerate(headings):
        end_line = total
        for next_start, next_level, _ in headings[i + 1 :]:
            if next_level <= level:
                end_line = next_start - 1
                break
        direct_end = (headings[i + 1][0] - 1) if (i + 1 < len(headings)) else total
        has_table = False
        code_blocks = 0
        b_char: str | None = None
        b_len = 0
        for b_line in lines[start_line:direct_end]:
            m_bf = fence_re.match(b_line)
            if m_bf:
                marker = m_bf.group(1)
                rest = m_bf.group(2)
                ch = marker[0]
                if b_char is None:
                    b_char = ch
                    b_len = len(marker)
                    code_blocks += 1
                elif ch == b_char and len(marker) >= b_len and not rest.strip():
                    b_char = None
                    b_len = 0
                continue
            if b_char is None and not has_table and table_delim_re.match(b_line):
                has_table = True
        badges: list[str] = []
        if has_table:
            badges.append("table")
        if code_blocks == 1:
            badges.append("1 code block")
        elif code_blocks > 1:
            badges.append(f"{code_blocks} code blocks")
        badge_str = f" [{', '.join(badges)}]" if badges else ""
        out.append(f"{'#' * level} {title}{badge_str}: L{start_line}-L{end_line}")
    return out


def outline_diff(source: str) -> list[str]:
    """Extract unified diff file spans and `@@ ... @@` hunk headers."""
    lines = source.splitlines()
    total = len(lines)
    if total == 0:
        return []

    diff_git_re = re.compile(r"^diff --git\s+\S+\s+(\S+)")
    plus_file_re = re.compile(r"^\+\+\+\s+(\S+)")
    hunk_re = re.compile(r"^(@@\s+-[0-9,]+\s+\+[0-9,]+\s+@@.*)$")

    file_entries: list[tuple[int, str, list[tuple[int, str]]]] = []
    current_start: int | None = None
    current_path: str | None = None
    current_hunks: list[tuple[int, str]] = []

    for idx, line in enumerate(lines):
        lineno = idx + 1
        m_git = diff_git_re.match(line)
        if m_git:
            if current_start is not None and current_path is not None:
                file_entries.append((current_start, current_path, current_hunks))
            current_start = lineno
            current_path = m_git.group(1)
            current_hunks = []
            continue

        m_plus = plus_file_re.match(line)
        if m_plus and current_start is None:
            current_start = lineno
            current_path = m_plus.group(1)
            current_hunks = []
            continue

        m_hunk = hunk_re.match(line)
        if m_hunk:
            current_hunks.append((lineno, m_hunk.group(1).strip()))

    if current_start is not None and current_path is not None:
        file_entries.append((current_start, current_path, current_hunks))

    out: list[str] = []
    for i, (start_line, path_label, hunks) in enumerate(file_entries):
        end_line = file_entries[i + 1][0] - 1 if i + 1 < len(file_entries) else total
        out.append(f"file {path_label}: L{start_line}-L{end_line}")
        for hunk_lineno, hunk_text in hunks:
            out.append(f"  {hunk_text.rstrip(':')}: L{hunk_lineno}")
    return out


def _find_closing_tag_line(lines: list[str], start_idx: int, tag: str) -> int:
    """Find the 1-based line number of the matching `</tag>` for an opening `<tag>` at `start_idx`."""
    open_re = re.compile(rf"<{re.escape(tag)}\b[^>]*>", re.IGNORECASE)
    close_re = re.compile(rf"</{re.escape(tag)}\s*>", re.IGNORECASE)
    self_close_re = re.compile(rf"<{re.escape(tag)}\b[^>]*/\s*>", re.IGNORECASE)

    depth = 0
    for idx in range(start_idx, len(lines)):
        line = lines[idx]
        opens = len(open_re.findall(line)) - len(self_close_re.findall(line))
        closes = len(close_re.findall(line))
        depth += opens - closes
        if idx == start_idx and depth <= 0:
            return idx + 1
        if idx > start_idx and depth <= 0:
            return idx + 1
    return start_idx + 1


def _outline_script_body(lines: list[str], start_idx: int, end_idx: int) -> list[str]:
    """Extract JS/TS functions and arrow functions inside `<script>` spans (`start_idx`..`end_idx`)."""
    out: list[str] = []
    fn_re = re.compile(
        r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*(\([^)]*\)(?:\s*:\s*[^{]+)?)\s*\{"
    )
    arrow_re = re.compile(
        r"^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
    )
    for idx in range(start_idx, min(len(lines), end_idx + 1)):
        line = lines[idx]
        lineno = idx + 1
        m_fn = fn_re.match(line)
        if m_fn:
            name = m_fn.group(1)
            sig_rest = m_fn.group(2).strip()
            end_line = find_block_end(lines, idx, end_idx)
            out.append(f"  function {name}{sig_rest}: L{lineno}-L{end_line}")
            continue
        m_arrow = arrow_re.match(line)
        if m_arrow:
            name = m_arrow.group(1)
            end_line = find_block_end(lines, idx, end_idx)
            out.append(f"  const {name} =>: L{lineno}-L{end_line}")
    return out


def outline_template_markup(source: str, ext: str) -> list[str]:
    """Extract structural sections from `.phtml` (Magento/Hyvä) and `.vue` SFC templates."""
    lines = source.splitlines()
    out: list[str] = []
    ext_low = ext.lower()

    var_re = re.compile(r"@var\s+([^\*\r\n]+)")
    tag_open_re = re.compile(
        r"^\s*<(template|script|style|section|form|div|header|footer|main|nav|aside)\b([^>]*)>",
        re.IGNORECASE,
    )
    attr_id_re = re.compile(r'\bid="([^"]+)"')
    attr_xdata_re = re.compile(r'\bx-data="([^"]*)"')
    attr_xfor_re = re.compile(r'\bx-for="([^"]*)"')
    attr_xif_re = re.compile(r'\bx-if="([^"]*)"')

    for idx, line in enumerate(lines):
        lineno = idx + 1
        m_var = var_re.search(line)
        if m_var:
            out.append(f"@var {m_var.group(1).strip()}: L{lineno}")
            continue

        m_tag = tag_open_re.match(line)
        if not m_tag:
            continue

        tag = m_tag.group(1).lower()
        attrs_raw = m_tag.group(2)
        is_self_closing = attrs_raw.rstrip().endswith("/")

        if ext_low == ".vue" and tag not in ("template", "script", "style"):
            continue

        m_id = attr_id_re.search(attrs_raw)
        m_xdata = attr_xdata_re.search(attrs_raw)
        m_xfor = attr_xfor_re.search(attrs_raw)
        m_xif = attr_xif_re.search(attrs_raw)

        if ext_low == ".phtml" and tag == "div" and not (m_id or m_xdata):
            continue

        end_line = lineno if is_self_closing else _find_closing_tag_line(lines, idx, tag)

        if tag in ("script", "style") and attrs_raw.strip():
            clean_attrs = " ".join(attrs_raw.strip().rstrip("/").split())
            label = f"<{tag} {clean_attrs}>" if clean_attrs else f"<{tag}>"
        else:
            id_suffix = f"#{m_id.group(1)}" if m_id else ""
            extra_parts: list[str] = []
            if m_xdata:
                extra_parts.append(f'x-data="{m_xdata.group(1)}"')
            if m_xfor:
                extra_parts.append(f'x-for="{m_xfor.group(1)}"')
            if m_xif:
                extra_parts.append(f'x-if="{m_xif.group(1)}"')
            extra_str = (" " + " ".join(extra_parts)) if extra_parts else ""
            label = f"<{tag}{id_suffix}{extra_str}>"

        out.append(f"{label}: L{lineno}-L{end_line}")
        if tag == "script" and end_line > lineno:
            out.extend(_outline_script_body(lines, idx + 1, end_line - 1))

    return out


def outline_xml(source: str) -> list[str]:
    """Extract structural layout/DI/config nodes and line spans from XML files."""
    lines = source.splitlines()
    out: list[str] = []
    xml_tags = (
        "page|layout|config|body|head|referenceContainer|container|"
        "referenceBlock|block|type|virtualType|plugin|preference|"
        "route|event|observer|acl|menu|system|section|group|field|"
        "modules|global|frontend|adminhtml|default|crontab|jobs|"
        "models|blocks|helpers|resources|events|observers|routers|translate|rewrite"
    )
    tag_re = re.compile(rf"^(\s*)<({xml_tags})\b([^>]*)>")
    attr_re = re.compile(r'\b(name|id|for|type|class|template)="([^"]+)"')

    for idx, line in enumerate(lines):
        lineno = idx + 1
        m = tag_re.match(line)
        if not m:
            continue
        indent_spaces = len(m.group(1).expandtabs(4))
        indent_prefix = "  " * min(indent_spaces // 4, 4)
        tag = m.group(2)
        attrs_raw = m.group(3)
        is_self_closing = attrs_raw.rstrip().endswith("/") or f"</{tag}>" in line

        attrs_found = dict(attr_re.findall(attrs_raw))
        ordered_attrs: list[str] = []
        for key in ("name", "id", "for", "type", "class", "template"):
            if key in attrs_found:
                ordered_attrs.append(f'{key}="{attrs_found[key]}"')
        attr_str = (" " + " ".join(ordered_attrs)) if ordered_attrs else ""

        if is_self_closing:
            out.append(f"{indent_prefix}<{tag}{attr_str}/>: L{lineno}")
        else:
            end_line = _find_closing_tag_line(lines, idx, tag)
            out.append(f"{indent_prefix}<{tag}{attr_str}>: L{lineno}-L{end_line}")

    return out


def outline_json_or_yaml(source: str, ext: str) -> list[str]:
    """Extract top-level keys and line spans from `.json`, `.yaml`, and `.yml` files."""
    lines = source.splitlines()
    total = len(lines)
    if total == 0:
        return []

    ext_low = ext.lower()
    out: list[str] = []

    if ext_low == ".json":
        key_re = re.compile(r'^( {2,4})"([^"]+)"\s*:\s*(.*)$')
        for idx, line in enumerate(lines):
            lineno = idx + 1
            m = key_re.match(line)
            if not m:
                continue
            indent = m.group(1)
            if indent != "  " and any(l.startswith('  "') for l in lines[:20]):
                continue
            key = m.group(2)
            rest = m.group(3).strip()
            if rest.startswith(("{", "[")) and not (rest.endswith(("}", "},", "]", "],"))):
                end_line = find_block_end(lines, idx, track_brackets=True)
            else:
                end_line = lineno
            out.append(f'"{key}": L{lineno}-L{end_line}')
        return out

    yaml_key_re = re.compile(r"^([A-Za-z0-9_.-]+)\s*:(?:\s+.*)?$")
    top_keys: list[tuple[int, str]] = []
    for idx, line in enumerate(lines):
        if line.startswith(("#", "---", "...")):
            continue
        m = yaml_key_re.match(line)
        if m:
            top_keys.append((idx + 1, m.group(1)))

    for i, (start_line, key) in enumerate(top_keys):
        next_start = top_keys[i + 1][0] if i + 1 < len(top_keys) else total + 1
        end_line = next_start - 1
        while end_line > start_line and not lines[end_line - 1].strip():
            end_line -= 1
        out.append(f"{key}: L{start_line}-L{end_line}")
    return out


def outline_task_output(source: str) -> list[str]:
    """Extract banners, test failures, tracebacks, and exceptions from `.output` / `.log` files."""
    lines = source.splitlines()
    out: list[str] = []
    banner_re = re.compile(r"^={3,}\s+.+\s+={3,}$")
    fail_re = re.compile(r"\b(FAILED|ERROR)\b")
    tb_re = re.compile(r"^Traceback \(most recent call last\):")
    exc_re = re.compile(r"^[A-Za-z0-9_.]*(?:Error|Exception|Failure):\s+.+$")

    for idx, line in enumerate(lines):
        lineno = idx + 1
        stripped = line.strip()
        if not stripped:
            continue
        if any((banner_re.match(stripped), tb_re.match(stripped), exc_re.match(stripped), fail_re.search(stripped))):
            out.append(f"{stripped}: L{lineno}")
    return out


def outline_css(source: str) -> list[str]:
    """Extract `@media`/`@keyframes`/`@layer` blocks and top-level rule spans from CSS/SCSS (max 120)."""
    lines = source.splitlines()
    out: list[str] = []
    rule_re = re.compile(r"^(\s*)(@[A-Za-z_-]+[^{;]*|[.#A-Za-z_:][^{;]*)\{")
    for idx, line in enumerate(lines):
        if len(out) >= 120:
            break
        m = rule_re.match(line)
        if not m:
            continue
        indent = "  " if m.group(1) else ""
        selector = " ".join(m.group(2).strip().split())
        if len(selector) > 80:
            selector = selector[:77] + "..."
        end_line = find_block_end(lines, idx)
        out.append(f"{indent}{selector}: L{idx + 1}-L{end_line}")
    return out


def outline_toml(source: str) -> list[str]:
    """Extract `[table]` and `[[array_of_tables]]` spans from TOML, ignoring multiline strings."""
    lines = source.splitlines()
    total = len(lines)
    if total == 0:
        return []
    header_re = re.compile(r"^\s*(\[\[?[A-Za-z0-9_.\"-]+\]?\])\s*(?:#.*)?$")
    headers: list[tuple[int, str]] = []
    in_multiline: str | None = None
    for idx, line in enumerate(lines):
        if in_multiline is not None:
            if in_multiline in line:
                in_multiline = None
            continue
        m = header_re.match(line)
        if m:
            headers.append((idx + 1, m.group(1)))
        for delim in ('"""', "'''"):
            if line.count(delim) % 2 == 1:
                in_multiline = delim
                break
    out: list[str] = []
    for i, (start_line, name) in enumerate(headers):
        next_start = headers[i + 1][0] if i + 1 < len(headers) else total + 1
        end_line = next_start - 1
        while end_line > start_line and not lines[end_line - 1].strip():
            end_line -= 1
        out.append(f"{name}: L{start_line}-L{end_line}")
    return out


_HEREDOC_TAG_RE = re.compile(r"['\"]([A-Za-z_]\w*)['\"]")


def _strip_shell_non_heredoc(line: str) -> str:
    """Strip quotes, `<<<` here-strings, comments, and `(( ... ))` arithmetic, keeping `<<` delimiters."""
    out: list[str] = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            i += 2
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            break
        elif line[i : i + 2] == "((":
            depth, j = 2, i + 2
            while j < n and depth > 0:
                if line[j] == "\\" and j + 1 < n:
                    j += 2
                else:
                    depth += 1 if line[j] == "(" else (-1 if line[j] == ")" else 0)
                    j += 1
            out.append(" ")
            i = j
        elif line[i : i + 3] == "<<<":
            out.append("   ")
            i += 3
        elif line[i : i + 2] == "<<":
            j = i + 2 + (1 if i + 2 < n and line[i + 2] == "-" else 0)
            while j < n and line[j].isspace():
                j += 1
            end_q = line.find(line[j], j + 1) if j < n and line[j] in ("'", '"') else -1
            if end_q != -1 and _HEREDOC_TAG_RE.fullmatch(line[j : end_q + 1]):
                out.append(line[i : end_q + 1])
                i = end_q + 1
            else:
                out.append("<<")
                i += 2
        elif ch in ("'", '"'):
            j = i + 1
            while j < n and line[j] != ch:
                j += 2 if ch == '"' and line[j] == "\\" and j + 1 < n else 1
            out.append(" ")
            i = (j + 1) if j < n else n
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def outline_shell(source: str) -> list[str]:
    """Extract shell function spans from `.sh`/`.bash`/`.zsh`, ignoring heredoc bodies."""
    lines = source.splitlines()
    out: list[str] = []
    heredoc_re = re.compile(r"<<-?\s*['\"]?([A-Za-z_]\w*)['\"]?")
    fn_re = re.compile(
        r"^\s*(?:function\s+([A-Za-z_][\w-]*)\s*(?:\(\s*\))?|([A-Za-z_][\w-]*)\s*\(\s*\))\s*\{?"
    )
    reserved = {"if", "for", "while", "until", "case", "select"}
    heredoc_eof: str | None = None
    for idx, line in enumerate(lines):
        if heredoc_eof is not None:
            if line.strip() == heredoc_eof:
                heredoc_eof = None
            continue
        stripped = line.lstrip()
        if not stripped.startswith("#"):
            m_hd = heredoc_re.search(_strip_shell_non_heredoc(line))
            if m_hd:
                heredoc_eof = m_hd.group(1)
                continue
        m_fn = fn_re.match(line)
        if m_fn:
            name = m_fn.group(1) or m_fn.group(2)
            if name and name not in reserved:
                end_line = find_block_end(lines, idx, allow_hash_comment=True)
                out.append(f"function {name}(): L{idx + 1}-L{end_line}")
    return out
