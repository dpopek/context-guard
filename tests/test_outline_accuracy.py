from __future__ import annotations

import pytest

from hooks.outline import (
    outline_go,
    outline_php,
    outline_rust,
    outline_ts_js,
    try_outline_tree_sitter,
)


def test_ts_accessors_are_listed_as_methods() -> None:
    src = (
        "export class JoinAttribute {\n"
        "    get isMany(): boolean {\n"
        "        return true\n"
        "    }\n"
        "\n"
        "    set value(v: string) {\n"
        "        this.v = v\n"
        "    }\n"
        "\n"
        "    get(key: string): string {\n"
        "        return key\n"
        "    }\n"
        "}\n"
    )
    res = outline_ts_js(src)
    assert "  method isMany: L2-L4" in res
    assert "  method value: L6-L8" in res
    assert "  method get: L10-L12" in res


def test_ts_ambient_declarations_are_listed() -> None:
    src = (
        "export declare class Binary {\n"
        "    x: number;\n"
        "}\n"
        "export declare interface BinaryExtended {\n"
        "    a: string;\n"
        "}\n"
        "export declare abstract class BSONValue {\n"
        "}\n"
        "declare type BinarySequence = Uint8Array;\n"
    )
    res = outline_ts_js(src)
    assert "class Binary: L1-L3" in res
    assert "interface BinaryExtended: L4-L6" in res
    assert "class BSONValue: L7-L8" in res
    assert "type BinarySequence: L9-L9" in res


def test_ts_multiline_type_alias_span_covers_all_members() -> None:
    src = (
        "export type Primary =\n"
        '    | "int"\n'
        '    | "bigint"\n'
        "\n"
        "export type Shape = {\n"
        "    a: string\n"
        "}\n"
        'export type Short = "x" | "y"\n'
        "export function after() {\n"
        "    return 1\n"
        "}\n"
    )
    res = outline_ts_js(src)
    assert "type Primary: L1-L3" in res
    assert "type Shape: L5-L7" in res
    assert "type Short: L8-L8" in res
    assert "function after: L9-L11" in res


def test_rust_lifetimes_do_not_break_block_ends() -> None:
    src = (
        "impl Stream {\n"
        "    fn as_fd(&self) -> BorrowedFd<'_> {\n"
        "        self.fd()\n"
        "    }\n"
        "\n"
        "    fn brace<'a>(&'a self) -> char {\n"
        "        '{'\n"
        "    }\n"
        "}\n"
        "pub struct Wrapper<'a> {\n"
        "    inner: &'a str,\n"
        "}\n"
    )
    res = outline_rust(src)
    assert "impl Stream: L1-L9" in res
    assert "  fn as_fd: L2-L4" in res
    assert "  fn brace: L6-L8" in res
    assert "struct Wrapper: L10-L12" in res


GO_SRC = (
    "package navigation\n"
    "\n"
    "type Menu []*MenuEntry\n"
    "\n"
    "type Menus map[string]Menu\n"
    "\n"
    "type menuEntryBy func(m1, m2 *MenuEntry) bool\n"
    "\n"
    "type MenuEntry struct {\n"
    "\tName string\n"
    "}\n"
    "\n"
    "func (m Menu) Add(me *MenuEntry) Menu {\n"
    "\treturn m\n"
    "}\n"
)


def test_go_named_types_without_body_are_listed() -> None:
    res = outline_go(GO_SRC)
    assert "type Menu: L3-L3" in res
    assert "type Menus: L5-L5" in res
    assert "type menuEntryBy: L7-L7" in res
    assert "type MenuEntry struct: L9-L11" in res
    assert "func (m Menu) Add: L13-L15" in res


def test_php_enum_and_bodiless_methods_are_listed() -> None:
    src = (
        "<?php\n"
        "enum Digit: int\n"
        "{\n"
        "    case One = 1;\n"
        "}\n"
        "abstract class Factory\n"
        "{\n"
        "    abstract public function definition();\n"
        "    final protected static function make(): static\n"
        "    {\n"
        "    }\n"
        "}\n"
    )
    res = outline_php(src)
    assert "enum Digit: L2-L5" in res
    assert "  public function definition: L8-L8" in res
    assert "  protected static function make: L9-L11" in res


def test_tree_sitter_go_type_declarations_are_listed() -> None:
    pytest.importorskip("tree_sitter_language_pack")
    res = try_outline_tree_sitter(GO_SRC, ".go")
    assert res is not None
    assert "type Menu: L3-L3" in res
    assert "type menuEntryBy: L7-L7" in res
    assert "type MenuEntry struct: L9-L11" in res


def test_tree_sitter_php_trait_has_its_own_range_line() -> None:
    pytest.importorskip("tree_sitter_language_pack")
    src = "<?php\ntrait HasEvents\n{\n    public function boot() {}\n}\n"
    res = try_outline_tree_sitter(src, ".php")
    assert res is not None
    assert "trait HasEvents: L2-L5" in res


def test_ts_generic_methods_are_listed() -> None:
    src = (
        "export class Utils {\n"
        "    static isFindOneOptions<Entity = any>(\n"
        "        obj: any,\n"
        "    ): obj is FindOneOptions<Entity> {\n"
        "        return true\n"
        "    }\n"
        "\n"
        "    protected filterByTarget<T extends { target: Function | string }>(array: T[]): T[] {\n"
        "        return array\n"
        "    }\n"
        "}\n"
    )
    res = outline_ts_js(src)
    assert "  method isFindOneOptions: L2-L6" in res
    assert "  method filterByTarget: L8-L10" in res


def test_ts_method_span_ignores_braces_in_parameter_and_return_types() -> None:
    src = (
        "export class Driver {\n"
        "    parseTableName(\n"
        "        target: string,\n"
        "    ): { database?: string; tableName: string } {\n"
        "        const name = target\n"
        "        return { tableName: name }\n"
        "    }\n"
        "\n"
        "    normalizeType(column: {\n"
        "        type: string\n"
        "    }): string {\n"
        "        if (column.type) {\n"
        '            return "int"\n'
        "        }\n"
        '        return "varchar"\n'
        "    }\n"
        "\n"
        "    short(): number { return 1 }\n"
        "}\n"
    )
    res = outline_ts_js(src)
    assert "  method parseTableName: L2-L7" in res
    assert "  method normalizeType: L9-L16" in res
    assert "  method short: L18-L18" in res


def test_ts_type_alias_span_skips_comment_lines_between_members() -> None:
    src = (
        "export type Simple =\n"
        '    | "simple-array" // mapped to string\n'
        '    // | "string"\n'
        '    | "simple-json"\n'
        "// trailing note\n"
        "export const after = 1\n"
    )
    assert "type Simple: L1-L4" in outline_ts_js(src)


def test_tree_sitter_ts_abstract_class_is_listed() -> None:
    pytest.importorskip("tree_sitter_language_pack")
    res = try_outline_tree_sitter("export abstract class BSONValue {\n    abstract get kind(): string\n}\n", ".ts")
    assert res is not None
    assert "class BSONValue: L1-L3" in res


def test_outline_shell_ignores_arithmetic_shift_herestrings_and_quotes() -> None:
    from hooks.markup_outliners import outline_shell

    src = (
        "#!/usr/bin/env bash\n"
        "calc_mask() {\n"
        "  (( mask = 1 << bits ))\n"
        "  val=$(( shifted << 2 ))\n"
        "  echo \"cat << FAKE_EOF\"\n"
        "  printf '%s' '<< SINGLE_FAKE'\n"
        "  cat <<< \"here string\"\n"
        "}\n"
        "real_after() {\n"
        "  cat << 'EOF'\n"
        "inside_heredoc() {\n"
        "  echo skipped\n"
        "}\n"
        "EOF\n"
        "  echo done\n"
        "}\n"
        "final_fn() {\n"
        "  return 0\n"
        "}\n"
    )
    symbols = outline_shell(src)
    joined = "\n".join(symbols)
    assert "function calc_mask(): L2-L8" in joined
    assert "function real_after(): L9-L16" in joined
    assert "function final_fn(): L17-L19" in joined
    assert "inside_heredoc" not in joined
