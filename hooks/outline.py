"""Multi-language structural AST/symbol outline library (Search -> Outline -> Target); CLI in bin/outline.py."""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

from hooks.markup_outliners import (
    find_block_end, outline_css, outline_diff, outline_json_or_yaml, outline_markdown,
    outline_shell, outline_task_output, outline_template_markup, outline_toml, outline_xml,
)

MAX_OUTLINE_FILE_BYTES = 2 * 1024 * 1024  # 2 MB cap to prevent CPU spikes on minified bundles

OUTLINE_EXTENSIONS: tuple[str, ...] = (
    ".py", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".php", ".phtml",
    ".vue", ".html", ".htm", ".xml", ".md", ".mdx", ".diff", ".patch", ".json", ".yaml", ".yml",
    ".toml", ".css", ".scss", ".sh", ".bash", ".zsh", ".output", ".go", ".rs", ".sql", ".sqlx",
)

_TS_LANG_MAP: dict[str, str] = {
    ".ts": "typescript", ".tsx": "tsx", ".mts": "typescript", ".cts": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".php": "php", ".go": "go", ".rs": "rust",
}


def _unparse_expr(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except (ValueError, TypeError, RecursionError):
        return "..."


def _format_py_args(args: ast.arguments) -> str:
    parts: list[str] = []
    all_pos = list(getattr(args, "posonlyargs", [])) + list(args.args)
    for arg in all_pos:
        ann = f": {_unparse_expr(arg.annotation)}" if arg.annotation else ""
        parts.append(f"{arg.arg}{ann}")
    if args.vararg:
        ann = f": {_unparse_expr(args.vararg.annotation)}" if args.vararg.annotation else ""
        parts.append(f"*{args.vararg.arg}{ann}")
    for kwarg in args.kwonlyargs:
        ann = f": {_unparse_expr(kwarg.annotation)}" if kwarg.annotation else ""
        parts.append(f"{kwarg.arg}{ann}")
    if args.kwarg:
        ann = f": {_unparse_expr(args.kwarg.annotation)}" if args.kwarg.annotation else ""
        parts.append(f"**{args.kwarg.arg}{ann}")
    return ", ".join(parts)


def _node_start_line(node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    dec_lines = [
        int(d.lineno)
        for d in getattr(node, "decorator_list", [])
        if hasattr(d, "lineno") and isinstance(d.lineno, int)
    ]
    return min([node.lineno, *dec_lines])


def _format_py_decorators(node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    decs = getattr(node, "decorator_list", [])
    if not decs:
        return ""
    formatted = [f"@{_unparse_expr(d)}" for d in decs if _unparse_expr(d)]
    return (" ".join(formatted) + " ") if formatted else ""


def _first_doc_summary(node: ast.AST, include_doc: bool) -> str:
    if not include_doc:
        return ""
    doc = ast.get_docstring(node)  # type: ignore[arg-type]
    if not doc:
        return ""
    first = " ".join(doc.strip().splitlines()[0].split())
    if not first:
        return ""
    if len(first) > 60:
        first = first[:57] + "..."
    return f"  # {first}"


def _format_py_func(
    node: ast.FunctionDef | ast.AsyncFunctionDef, indent: str = "", include_doc: bool = True
) -> str:
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    sig = _format_py_args(node.args)
    if len(sig) > 90:
        sig = sig[:87] + "..."
    ret = f" -> {_unparse_expr(node.returns)}" if node.returns else ""
    start_line = _node_start_line(node)
    end_line = getattr(node, "end_lineno", None) or node.lineno
    dec_prefix = _format_py_decorators(node)
    doc_suffix = _first_doc_summary(node, include_doc)
    return f"{indent}{dec_prefix}{prefix} {node.name}({sig}){ret}: L{start_line}-L{end_line}{doc_suffix}"


def _outline_python_regex_fallback(source: str, err: SyntaxError) -> list[str]:
    err_line = err.lineno or "?"
    out = [f"# [WARN: AST SyntaxError on line {err_line}, using regex fallback]"]
    pat = re.compile(r"^(\s*)(?:(async\s+def|def|class)\s+([A-Za-z_]\w*).*?:)")
    for idx, line in enumerate(source.splitlines(), start=1):
        m = pat.match(line)
        if m:
            indent = "  " if len(m.group(1)) > 0 else ""
            out.append(f"{indent}{line.strip()} L{idx}")
    return out


def outline_python(source: str) -> list[str]:
    """Extract structural outline from Python source using stdlib ast."""
    try:
        tree = ast.parse(source)
    except SyntaxError as err:
        return _outline_python_regex_fallback(source, err)

    out: list[str] = []
    import_lines: list[int] = []

    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_lines.append(node.lineno)
            end_l = getattr(node, "end_lineno", None)
            if end_l:
                import_lines.append(end_l)

    if import_lines:
        out.append(f"imports: L{min(import_lines)}-L{max(import_lines)}")

    total_nodes = sum(
        1 + sum(1 for c in n.body if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)))
        if isinstance(n, ast.ClassDef)
        else (1 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) else 0)
        for n in tree.body
    )
    include_doc = total_nodes <= 80

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            bases = ", ".join(_unparse_expr(b) for b in node.bases if _unparse_expr(b))
            base_str = f"({bases})" if bases else ""
            start_line = _node_start_line(node)
            end_line = getattr(node, "end_lineno", None) or node.lineno
            dec_prefix = _format_py_decorators(node)
            doc_suffix = _first_doc_summary(node, include_doc)
            out.append(
                f"{dec_prefix}class {node.name}{base_str}: L{start_line}-L{end_line}{doc_suffix}"
            )
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.append(_format_py_func(child, indent="  ", include_doc=include_doc))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(_format_py_func(node, indent="", include_doc=include_doc))

    return out


_find_block_end = find_block_end


def _find_closing_paren_idx(
    lines: list[str],
    start_idx: int,
    open_paren_col: int,
    max_Lookahead: int = 25,
) -> tuple[int, str] | None:
    """Return (0-based line_idx, remainder_after_close_paren) when balanced `)` is found."""
    paren_depth = 0
    in_quote: str | None = None
    escaped = False
    limit = min(len(lines), start_idx + max_Lookahead)
    for scan_idx in range(start_idx, limit):
        line = lines[scan_idx]
        col_start = open_paren_col if scan_idx == start_idx else 0
        for col_idx in range(col_start, len(line)):
            ch = line[col_idx]
            if escaped:
                escaped = False
                continue
            if in_quote is not None:
                if ch == "\\":
                    escaped = True
                elif ch == in_quote:
                    in_quote = None
                continue
            if ch in ("'", '"', "`"):
                in_quote = ch
            elif ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    return (scan_idx, line[col_idx + 1 :])
    return None


def _find_multiline_arrow_end_idx(lines: list[str], start_idx: int, open_paren_col: int) -> int | None:
    """Return 0-based line index of `=>` if multiline parameter list starting at (start_idx, open_paren_col) is followed by `=>`."""
    res = _find_closing_paren_idx(lines, start_idx, open_paren_col, max_Lookahead=15)
    if res is None:
        return None
    scan_idx, remainder = res
    if re.match(r"^\s*(?::.+)?=>", remainder):
        return scan_idx
    return None


def _find_ts_method_end(lines: list[str], start_idx: int, open_paren_col: int) -> int | None:
    """Return 1-based end line of a method whose parameter list opens at the given column; None when no body follows."""
    res = _find_closing_paren_idx(lines, start_idx, open_paren_col, max_Lookahead=40)
    if res is None:
        return None
    close_idx, remainder = res
    if re.match(r"^\s*(?::.*)?\{\s*(?://.*)?$", remainder):
        # Body opens with the last `{` of the line: braces in parameter and return types are not the body.
        return _find_block_end(["{"] + lines[close_idx + 1 :], 0) + close_idx
    if re.match(r"^\s*(?::\s*[^{;]+)?\{", remainder):
        return _find_block_end(lines, close_idx)
    return None


def outline_ts_js(source: str) -> list[str]:
    """Extract declarations and line spans from TypeScript / JavaScript source."""
    lines = source.splitlines()
    out: list[str] = []

    top_decl_re = re.compile(
        r"^\s*(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?"
        r"(interface|type|class|function|enum)\s+([A-Za-z_$][\w$]*)"
    )
    arrow_re = re.compile(
        r"^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
    )
    multiline_arrow_start_re = re.compile(
        r"^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?\("
    )
    method_start_re = re.compile(
        r"^[ \t]{2,8}(?:(?:public|protected|private|static|readonly|async|override|get|set)\s+)*"
        r"([A-Za-z_$][\w$]*)\s*(?:<[^(]*>)?\s*\("
    )
    reserved_keywords = {"if", "for", "while", "switch", "catch", "return", "function", "constructor"}

    for idx, line in enumerate(lines):
        lineno = idx + 1
        m_top = top_decl_re.match(line)
        if m_top:
            kind, name = m_top.group(1), m_top.group(2)
            end_line = _find_block_end(lines, idx)
            if kind == "type":
                last = nxt = idx
                while (nxt := nxt + 1) < len(lines):
                    member = lines[nxt].lstrip()
                    if member.startswith("//"):
                        continue
                    if not (member.startswith(("|", "&")) or lines[last].split("//")[0].rstrip().endswith(("=", "|", "&"))):
                        break
                    last = nxt
                span = "".join(lines[idx : last + 1])
                if span.count("{") <= span.count("}"):
                    end_line = last + 1
            out.append(f"{kind} {name}: L{lineno}-L{end_line}")
            continue

        m_arrow = arrow_re.match(line)
        if m_arrow:
            name = m_arrow.group(1)
            end_line = _find_block_end(lines, idx)
            out.append(f"const {name} =>: L{lineno}-L{end_line}")
            continue

        m_multi_arrow = multiline_arrow_start_re.match(line)
        if m_multi_arrow:
            arrow_line_idx = _find_multiline_arrow_end_idx(lines, idx, m_multi_arrow.end() - 1)
            if arrow_line_idx is not None:
                name = m_multi_arrow.group(1)
                end_line = _find_block_end(lines, arrow_line_idx)
                out.append(f"const {name} =>: L{lineno}-L{end_line}")
                continue

        m_method = method_start_re.match(line)
        if m_method:
            name = m_method.group(1)
            if name not in reserved_keywords or name == "constructor":
                method_end = _find_ts_method_end(lines, idx, m_method.end() - 1)
                if method_end is not None:
                    out.append(f"  method {name}: L{lineno}-L{method_end}")

    return out


def outline_php(source: str) -> list[str]:
    """Extract namespace, class/interface/trait, and method spans from PHP source."""
    lines = source.splitlines()
    out: list[str] = []

    ns_re = re.compile(r"^\s*namespace\s+([A-Za-z0-9_\\]+)\s*;")
    class_re = re.compile(
        r"^\s*(?:(?:abstract|final|readonly)\s+)*(class|interface|trait|enum)\s+([A-Za-z_]\w*)"
    )
    func_re = re.compile(
        r"^\s*((?:(?:abstract|final|public|protected|private|static)\s+)*)function\s+([A-Za-z_]\w*)\s*\("
    )

    for idx, line in enumerate(lines):
        lineno = idx + 1
        m_ns = ns_re.match(line)
        if m_ns:
            out.append(f"namespace {m_ns.group(1)}: L{lineno}")
            continue

        m_cls = class_re.match(line)
        if m_cls:
            kind, name = m_cls.group(1), m_cls.group(2)
            end_line = _find_block_end(lines, idx, allow_hash_comment=True)
            out.append(f"{kind} {name}: L{lineno}-L{end_line}")
            continue

        m_fn = func_re.match(line)
        if m_fn:
            mods = m_fn.group(1).split()
            vis = next((w for w in mods if w in ("public", "protected", "private")), "public")
            stat = " static" if "static" in mods else ""
            name = m_fn.group(2)
            end_line = _find_block_end(lines, idx, allow_hash_comment=True)
            indent = "  " if line.startswith((" ", "\t")) else ""
            out.append(f"{indent}{vis}{stat} function {name}: L{lineno}-L{end_line}")

    return out


def outline_go(source: str) -> list[str]:
    """Extract package, struct/interface types, functions, and receiver methods from Go source."""
    lines = source.splitlines()
    out: list[str] = []

    pkg_re = re.compile(r"^\s*package\s+([A-Za-z_]\w*)\b")
    type_re = re.compile(r"^\s*type\s+([A-Za-z_]\w*)(?:\[[^\]]*\])?\s+(?:=\s*)?(?:(struct|interface)\b)?")
    func_re = re.compile(r"^\s*func\s+(?:\(([^)]+)\)\s+)?([A-Za-z_]\w*)\s*\(")

    for idx, line in enumerate(lines):
        lineno = idx + 1
        m_pkg = pkg_re.match(line)
        if m_pkg:
            out.append(f"package {m_pkg.group(1)}: L{lineno}")
            continue

        m_type = type_re.match(line)
        if m_type:
            name, kind = m_type.group(1), m_type.group(2)
            if kind:
                out.append(f"type {name} {kind}: L{lineno}-L{_find_block_end(lines, idx)}")
            else:
                out.append(f"type {name}: L{lineno}-L{lineno}")
            continue

        m_fn = func_re.match(line)
        if m_fn:
            recv, name = m_fn.group(1), m_fn.group(2)
            end_line = _find_block_end(lines, idx)
            if recv:
                out.append(f"func ({recv.strip()}) {name}: L{lineno}-L{end_line}")
            else:
                out.append(f"func {name}: L{lineno}-L{end_line}")

    return out


def outline_rust(source: str) -> list[str]:
    """Extract structs, enums, traits, impl blocks, and functions from Rust source."""
    lines = source.splitlines()
    out: list[str] = []

    item_re = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(struct|enum|trait|mod)\s+([A-Za-z_]\w*)\b")
    impl_re = re.compile(r"^\s*impl(?:<[^>]*>)?\s+([^{]+?)\s*\{")
    fn_re = re.compile(
        r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)\s*[<(]"
    )

    for idx, line in enumerate(lines):
        lineno = idx + 1
        m_item = item_re.match(line)
        if m_item:
            kind, name = m_item.group(1), m_item.group(2)
            end_line = _find_block_end(lines, idx, rust_lifetimes=True)
            out.append(f"{kind} {name}: L{lineno}-L{end_line}")
            continue

        m_impl = impl_re.match(line)
        if m_impl:
            target = " ".join(m_impl.group(1).split())
            end_line = _find_block_end(lines, idx, rust_lifetimes=True)
            out.append(f"impl {target}: L{lineno}-L{end_line}")
            continue

        m_fn = fn_re.match(line)
        if m_fn:
            indent = "  " if len(m_fn.group(1)) > 0 else ""
            name = m_fn.group(2)
            end_line = _find_block_end(lines, idx, rust_lifetimes=True)
            out.append(f"{indent}fn {name}: L{lineno}-L{end_line}")

    return out


def _find_sql_statement_end(lines: list[str], start_idx: int) -> int:
    """Find 1-based line ending a SQL statement with `;` outside quotes, or EOF."""
    in_quote: str | None = None
    for idx in range(start_idx, len(lines)):
        line = lines[idx]
        for col, ch in enumerate(line):
            if in_quote is not None:
                if ch == in_quote:
                    in_quote = None
                continue
            if line[col : col + 2] == "--":
                break
            if ch in ("'", '"', "`"):
                in_quote = ch
            elif ch == ";":
                return idx + 1
    return len(lines)


def outline_sql(source: str) -> list[str]:
    """Extract Dataform config blocks, CREATE DDL statements, and CTEs from SQL/SQLX source."""
    lines = source.splitlines()
    out: list[str] = []

    config_re = re.compile(r"^\s*config\s*\{")
    create_re = re.compile(
        r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMP(?:ORARY)?\s+)?"
        r"(MATERIALIZED\s+VIEW|TABLE|VIEW|FUNCTION|PROCEDURE)\s+"
        r"(?:IF\s+NOT\s+EXISTS\s+)?([`\"\w.]+)",
        re.IGNORECASE,
    )
    cte_re = re.compile(r"^\s*(?:WITH(?:\s+RECURSIVE)?|,)\s*([A-Za-z_]\w*)\s+AS\s*\(", re.IGNORECASE)

    for idx, line in enumerate(lines):
        lineno = idx + 1
        if config_re.match(line):
            end_line = _find_block_end(lines, idx)
            out.append(f"config: L{lineno}-L{end_line}")
            continue

        m_cr = create_re.match(line)
        if m_cr:
            kind = " ".join(m_cr.group(1).upper().split())
            name = m_cr.group(2)
            end_line = _find_sql_statement_end(lines, idx)
            out.append(f"CREATE {kind} {name}: L{lineno}-L{end_line}")
            continue

        m_cte = cte_re.match(line)
        if m_cte:
            name = m_cte.group(1)
            closed = _find_closing_paren_idx(lines, idx, m_cte.end() - 1, max_Lookahead=200)
            end_line = (closed[0] + 1) if closed is not None else lineno
            out.append(f"CTE {name}: L{lineno}-L{end_line}")

    return out


def _extract_ts_node_name(node: object, raw_bytes: bytes, field: str = "name") -> str:
    """Extract identifier string from a Tree-sitter node's `field` (default `name`)."""
    child_fn = getattr(node, "child_by_field_name", None)
    if not callable(child_fn):
        return ""
    name_node = child_fn(field)
    if name_node is None:
        return ""
    text_attr = getattr(name_node, "text", None)
    if isinstance(text_attr, bytes):
        return text_attr.decode("utf-8", errors="replace")
    start_b = getattr(name_node, "start_byte", None)
    end_b = getattr(name_node, "end_byte", None)
    if isinstance(start_b, int) and isinstance(end_b, int):
        return raw_bytes[start_b:end_b].decode("utf-8", errors="replace")
    return ""


def try_outline_tree_sitter(source: str, ext: str) -> list[str] | None:
    """Attempt structural outline extraction via optional tree_sitter_language_pack; return None on fallback."""
    lang = _TS_LANG_MAP.get(ext)
    if not lang:
        return None
    try:
        import tree_sitter_language_pack as ts_pack  # type: ignore[import-not-found]

        get_parser = getattr(ts_pack, "get_parser", None)
        if not callable(get_parser):
            return None
        parser = get_parser(lang)
        raw_bytes = source.encode("utf-8", errors="replace")
        tree = parser.parse(raw_bytes)
        root = getattr(tree, "root_node", None)
        if root is None:
            return None

        out: list[str] = []

        def _visit(node: object, depth: int = 0) -> None:
            if depth > 6:
                return
            ntype = str(getattr(node, "type", ""))
            sp = getattr(node, "start_point", (0, 0))
            ep = getattr(node, "end_point", (0, 0))
            start_line = int(sp[0]) + 1
            end_line = int(ep[0]) + 1
            name = _extract_ts_node_name(node, raw_bytes)
            children = getattr(node, "named_children", None)
            if children is None:
                children = getattr(node, "children", [])

            if ntype in ("class_declaration", "abstract_class_declaration", "class_specifier") and name:
                out.append(f"class {name}: L{start_line}-L{end_line}")
            elif ntype == "interface_declaration" and name:
                out.append(f"interface {name}: L{start_line}-L{end_line}")
            elif ntype == "type_alias_declaration" and name:
                out.append(f"type {name}: L{start_line}-L{end_line}")
            elif ntype in ("enum_declaration", "enum_item") and name:
                out.append(f"enum {name}: L{start_line}-L{end_line}")
            elif ntype == "struct_item" and name:
                out.append(f"struct {name}: L{start_line}-L{end_line}")
            elif ntype in ("trait_item", "trait_declaration") and name:
                out.append(f"trait {name}: L{start_line}-L{end_line}")
            elif ntype in ("type_spec", "type_alias") and name:
                spec_fn = getattr(node, "child_by_field_name", None)
                spec_type = str(getattr(spec_fn("type") if callable(spec_fn) else None, "type", ""))
                suffix = {"struct_type": " struct", "interface_type": " interface"}.get(spec_type, "")
                out.append(f"type {name}{suffix}: L{start_line}-L{end_line}")
            elif ntype == "impl_item":
                type_name = _extract_ts_node_name(node, raw_bytes, "type") or name or "block"
                trait_name = _extract_ts_node_name(node, raw_bytes, "trait")
                if trait_name:
                    out.append(f"impl {trait_name} for {type_name}: L{start_line}-L{end_line}")
                else:
                    out.append(f"impl {type_name}: L{start_line}-L{end_line}")
            elif ntype in ("function_declaration", "function_definition") and name:
                prefix = "func" if ext == ".go" else "function"
                out.append(f"{prefix} {name}: L{start_line}-L{end_line}")
            elif ntype == "function_item" and name:
                indent = "  " if depth > 1 else ""
                out.append(f"{indent}fn {name}: L{start_line}-L{end_line}")
            elif ntype in ("method_definition", "method_declaration") and name:
                out.append(f"  method {name}: L{start_line}-L{end_line}")
            elif ntype == "variable_declarator" and name:
                child_fn = getattr(node, "child_by_field_name", None)
                val_node = child_fn("value") if callable(child_fn) else None
                val_types = {
                    str(getattr(c, "type", ""))
                    for c in ([val_node] if val_node is not None else []) + list(children or [])
                }
                if val_types & {"arrow_function", "function_expression", "function"}:
                    out.append(f"const {name} =>: L{start_line}-L{end_line}")

            for child in children or []:
                _visit(child, depth + 1)

        _visit(root, 0)
        return out if out else None
    except (ImportError, OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError):
        return None


def extract_outline_symbols(source: str, ext: str) -> list[str]:
    """Unified dispatcher returning symbol lines for a given file extension."""
    ext_low = ext.lower()
    if ext_low == ".py":
        return outline_python(source)
    if ext_low in (".md", ".mdx"):
        return outline_markdown(source)
    if ext_low in (".diff", ".patch"):
        return outline_diff(source)
    if ext_low == ".xml":
        return outline_xml(source)
    if ext_low in (".vue", ".html", ".htm"):
        return outline_template_markup(source, ext_low)
    if ext_low in (".css", ".scss"):
        return outline_css(source)
    if ext_low == ".toml":
        return outline_toml(source)
    if ext_low in (".sh", ".bash", ".zsh"):
        return outline_shell(source)
    if ext_low == ".phtml":
        php_res = outline_php(source)
        tmpl_res = outline_template_markup(source, ext_low)
        has_cls = any(re.match(r"^(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+", s) for s in php_res)
        return (php_res + tmpl_res) if has_cls else tmpl_res
    if ext_low in (".json", ".yaml", ".yml"):
        return outline_json_or_yaml(source, ext_low)
    if ext_low == ".output":
        return outline_task_output(source)

    ts_symbols = try_outline_tree_sitter(source, ext_low)
    if ts_symbols is not None:
        return ts_symbols

    if ext_low in (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"):
        return outline_ts_js(source)
    if ext_low == ".php":
        return outline_php(source)
    if ext_low == ".go":
        return outline_go(source)
    if ext_low == ".rs":
        return outline_rust(source)
    if ext_low in (".sql", ".sqlx"):
        return outline_sql(source)
    return ["# [INFO: Unsupported extension for structural outline; use grep_search]"]


def generate_outline(path: str) -> str:
    """Generate formatted structural outline for file at path."""
    file_path = Path(path)
    st = file_path.stat()
    if st.st_size > MAX_OUTLINE_FILE_BYTES:
        return (
            f"# {path} ({st.st_size} bytes)\n"
            f"# [WARN: File exceeds {MAX_OUTLINE_FILE_BYTES} bytes limit; skipping AST outline]"
        )

    source = file_path.read_text(encoding="utf-8", errors="replace")
    total_lines = len(source.splitlines())
    ext = file_path.suffix.lower()
    symbols = extract_outline_symbols(source, ext)

    header = f"# {path} ({total_lines} LOC)"
    if not symbols:
        return f"{header}\n# [No top-level symbols detected]"
    return header + "\n" + "\n".join(symbols)


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        sys.stderr.write("Usage: outline.py <file1> [<file2> ...]\n")
        return 1

    exit_code = 0
    outputs: list[str] = []
    for raw_path in args:
        if not os.path.isfile(raw_path):
            sys.stderr.write(f"# ERROR: File not found: {raw_path}\n")
            exit_code = 1
            continue
        outputs.append(generate_outline(raw_path))

    if outputs:
        sys.stdout.write("\n\n".join(outputs) + "\n")
    return exit_code
