from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from hooks.outline import (
    OUTLINE_EXTENSIONS,
    extract_outline_symbols,
    generate_outline,
    outline_go,
    outline_php,
    outline_python,
    outline_rust,
    outline_sql,
    outline_ts_js,
    try_outline_tree_sitter,
)


def test_outline_python_classes_and_functions() -> None:
    src = (
        "import os\n"
        "import sys\n\n"
        "class SampleService(BaseService):\n"
        "    def __init__(self, db: str) -> None:\n"
        "        self.db = db\n\n"
        "    async def fetch_items(self, limit: int = 10) -> list[str]:\n"
        "        return []\n\n"
        "def helper_func(x: int) -> int:\n"
        "    return x + 1\n"
    )
    joined = "\n".join(outline_python(src))
    assert "class SampleService(BaseService): L4-L9" in joined
    assert "def __init__(self, db: str) -> None: L5-L6" in joined
    assert "async def fetch_items(self, limit: int) -> list[str]: L8-L9" in joined
    assert "def helper_func(x: int) -> int: L11-L12" in joined


def test_outline_python_syntax_error_fallback() -> None:
    broken_src = "class BrokenClass:\n    def valid_sig(self):\n        if :\n"
    joined = "\n".join(outline_python(broken_src))
    assert "WARN: AST SyntaxError" in joined
    assert "class BrokenClass" in joined


def test_outline_typescript_declarations() -> None:
    ts_src = (
        "export interface OrderDto {\n"
        "  id: string;\n"
        "}\n\n"
        "export class OrderClient {\n"
        "  async getOrder(id: string): Promise<OrderDto> {\n"
        "    return { id };\n"
        "  }\n"
        "}\n\n"
        "export function formatOrder(o: OrderDto): string {\n"
        "  return o.id;\n"
        "}\n"
    )
    joined = "\n".join(outline_ts_js(ts_src))
    assert "interface OrderDto: L1-L3" in joined
    assert "class OrderClient: L5-L9" in joined
    assert "function formatOrder: L11-L13" in joined


def test_outline_php_magento_class() -> None:
    php_src = (
        "<?php\n"
        "namespace Acme\\Catalog\\Model;\n\n"
        "class ProductSync\n"
        "{\n"
        "    public function execute(array $ids): bool\n"
        "    {\n"
        "        return true;\n"
        "    }\n"
        "}\n"
    )
    joined = "\n".join(outline_php(php_src))
    assert "namespace Acme\\Catalog\\Model: L2" in joined
    assert "class ProductSync: L4-L10" in joined
    assert "public function execute: L6-L9" in joined


def test_cli_missing_file_returns_nonzero() -> None:
    script = Path(__file__).resolve().parent.parent / "bin" / "outline.py"
    proc = subprocess.run(
        [sys.executable, str(script), "/nonexistent/path/does_not_exist.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1


def test_generate_outline_oversized_file_guard(tmp_path: Path) -> None:
    big = tmp_path / "oversized.py"
    big.write_text("x = 1\n" * (400 * 1024), encoding="utf-8")
    out = generate_outline(str(big))
    assert "WARN: File exceeds" in out


def test_outline_python_decorators_included_in_signature_and_start_line() -> None:
    src = (
        "from dataclasses import dataclass\n\n"
        "@dataclass\n"
        "class OrderItem:\n"
        "    sku: str\n\n"
        "@router.post('/orders')\n"
        "@authenticated\n"
        "async def create_order(item: OrderItem) -> dict:\n"
        "    return {}\n"
    )
    joined = "\n".join(outline_python(src))
    assert "@dataclass class OrderItem: L3-L5" in joined
    assert (
        "@router.post('/orders') @authenticated async def create_order(item: OrderItem) -> dict: L7-L10"
        in joined
    )


def test_outline_typescript_multiline_arrow_component_and_non_arrow_parens() -> None:
    ts_src = (
        "export const OrderTable = ({\n"
        "  orders,\n"
        "  onSelect,\n"
        "}: OrderTableProps): JSX.Element => {\n"
        "  return <div />;\n"
        "};\n\n"
        "const groupedExpr = (\n"
        "  1 + 2\n"
        ");\n"
    )
    joined = "\n".join(outline_ts_js(ts_src))
    assert "const OrderTable =>: L1-L6" in joined
    assert "groupedExpr" not in joined


def test_outline_typescript_multiline_arrow_with_string_parens_and_fn_return_type() -> None:
    ts_src = (
        "export const useFormatter = (\n"
        "  fallback = ')',\n"
        "): ((val: string) => string) => {\n"
        "  return (val: string) => val || fallback;\n"
        "};\n"
    )
    joined = "\n".join(outline_ts_js(ts_src))
    assert "const useFormatter =>: L1-L5" in joined


def test_find_block_end_ignores_braces_in_strings_and_comments() -> None:
    ts_src = (
        "export function parseTemplate(input: string): string {\n"
        "  const closingBrace = '}';\n"
        "  const tpl = `nested } ${input}`;\n"
        "  // single line comment with } }\n"
        "  /* multi-line comment\n"
        "     with closing braces } } */\n"
        "  return tpl + closingBrace;\n"
        "}\n"
    )
    joined = "\n".join(outline_ts_js(ts_src))
    assert "function parseTemplate: L1-L8" in joined


def test_outline_ts_multiline_class_methods() -> None:
    ts_src = (
        "export class PaymentGateway {\n"
        "  public async chargeCustomer(\n"
        "    customerId: string,\n"
        "    amountCents: number,\n"
        "    options = { currency: 'PLN' }\n"
        "  ): Promise<boolean> {\n"
        "    return amountCents > 0;\n"
        "  }\n"
        "}\n"
    )
    joined = "\n".join(outline_ts_js(ts_src))
    assert "class PaymentGateway: L1-L9" in joined
    assert "  method chargeCustomer: L2-L8" in joined


def test_outline_go_extracts_package_types_and_funcs() -> None:
    go_src = (
        "package billing\n\n"
        "type Invoice struct {\n"
        "    ID string\n"
        "}\n\n"
        "type Biller interface {\n"
        "    Bill(inv Invoice) error\n"
        "}\n\n"
        "func NewInvoice(id string) Invoice {\n"
        "    return Invoice{ID: id}\n"
        "}\n\n"
        "func (s *Service) Process(inv Invoice) error {\n"
        "    return nil\n"
        "}\n"
    )
    joined = "\n".join(outline_go(go_src))
    assert "package billing: L1" in joined
    assert "type Invoice struct: L3-L5" in joined
    assert "type Biller interface: L7-L9" in joined
    assert "func NewInvoice: L11-L13" in joined
    assert "func (s *Service) Process: L15-L17" in joined


def test_outline_rust_extracts_structs_impls_and_fns() -> None:
    rs_src = (
        "pub struct TokenCache {\n"
        "    cap: usize,\n"
        "}\n\n"
        "impl TokenCache {\n"
        "    pub fn new(cap: usize) -> Self {\n"
        "        Self { cap }\n"
        "    }\n"
        "}\n\n"
        "pub async fn run_worker() -> Result<(), String> {\n"
        "    Ok(())\n"
        "}\n"
    )
    joined = "\n".join(outline_rust(rs_src))
    assert "struct TokenCache: L1-L3" in joined
    assert "impl TokenCache: L5-L9" in joined
    assert "  fn new: L6-L8" in joined
    assert "fn run_worker: L11-L13" in joined


def test_outline_sql_extracts_dataform_config_ctes_and_ddl() -> None:
    sql_src = (
        "config {\n"
        "  type: 'table',\n"
        "  schema: 'analytics'\n"
        "}\n\n"
        "CREATE OR REPLACE TABLE `proj.analytics.daily_orders` AS\n"
        "WITH raw_orders AS (\n"
        "  SELECT id, amount FROM `proj.raw.orders`\n"
        ")\n"
        "SELECT * FROM raw_orders;\n"
    )
    joined = "\n".join(outline_sql(sql_src))
    assert "config: L1-L4" in joined
    assert "CREATE TABLE `proj.analytics.daily_orders`: L6-L10" in joined
    assert "CTE raw_orders: L7-L9" in joined


class FakeTSNode:
    def __init__(
        self,
        node_type: str,
        start_row: int,
        end_row: int,
        name: str = "",
        fields: dict[str, FakeTSNode] | None = None,
        children: list[FakeTSNode] | None = None,
        text: str = "",
    ) -> None:
        self.type = node_type
        self.start_point = (start_row, 0)
        self.end_point = (end_row, 0)
        self._fields = dict(fields or {})
        if name and "name" not in self._fields:
            self._fields["name"] = FakeTSNode("identifier", start_row, start_row, text=name)
        self.children = children or []
        self.named_children = self.children
        raw = text.encode("utf-8") if text else None
        self.text = raw
        self.start_byte = 0
        self.end_byte = len(raw) if raw else 0

    def child_by_field_name(self, field: str) -> FakeTSNode | None:
        return self._fields.get(field)


def test_tree_sitter_optional_backend_and_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeParser:
        def parse(self, _raw: bytes) -> Any:
            method_node = FakeTSNode("method_definition", 1, 3, name="compute")
            cbody_node = FakeTSNode("class_body", 0, 4, children=[method_node])
            cls_node = FakeTSNode("class_declaration", 0, 4, name="Engine", children=[cbody_node])
            exp_node = FakeTSNode("export_statement", 0, 4, children=[cls_node])
            root = FakeTSNode("program", 0, 4, children=[exp_node])
            return type("FakeTree", (), {"root_node": root})()

    fake_mod = type("FakeTSPack", (), {"get_parser": staticmethod(lambda _lang: FakeParser())})
    monkeypatch.setitem(sys.modules, "tree_sitter_language_pack", fake_mod)
    ts_res = try_outline_tree_sitter("class Engine {\n  compute() {\n  }\n}\n", ".ts")
    assert ts_res is not None
    joined = "\n".join(ts_res)
    assert "class Engine: L1-L5" in joined
    assert "  method compute: L2-L4" in joined

    monkeypatch.setitem(sys.modules, "tree_sitter_language_pack", None)
    fallback_res = extract_outline_symbols("export function hello(): void {\n}\n", ".ts")
    assert "function hello: L1-L2" in "\n".join(fallback_res)


def test_outline_markdown_headings_with_line_spans_ignoring_code_fences() -> None:
    md = (
        "# Architecture Guide\n"
        "Intro paragraph.\n"
        "## 1. Overview\n"
        "Details here.\n"
        "```bash\n"
        "# This shell comment inside a code fence must NOT be treated as a heading\n"
        "pytest -q\n"
        "```\n"
        "### 1.1 Sub-section\n"
        "More details.\n"
        "## 2. Deployment\n"
        "Final notes.\n"
    )
    out = "\n".join(extract_outline_symbols(md, ".md"))
    assert "# Architecture Guide: L1-L12" in out
    assert "## 1. Overview [1 code block]: L3-L10" in out
    assert "### 1.1 Sub-section: L9-L10" in out
    assert "## 2. Deployment: L11-L12" in out
    assert "shell comment" not in out


def test_outline_diff_files_and_hunks() -> None:
    diff_src = (
        "diff --git a/src/app.py b/src/app.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,4 +10,5 @@ def run():\n"
        "     x = 1\n"
        "+    y = 2\n"
        "diff --git a/src/utils.py b/src/utils.py\n"
        "--- a/src/utils.py\n"
        "+++ b/src/utils.py\n"
        "@@ -1,2 +1,3 @@\n"
        "+import os\n"
    )
    out = "\n".join(extract_outline_symbols(diff_src, ".diff"))
    assert "file b/src/app.py: L1-L7" in out
    assert "@@ -10,4 +10,5 @@ def run(): L5" in out
    assert "file b/src/utils.py: L8-L12" in out


def test_outline_phtml_hyva_template_without_php_classes() -> None:
    phtml = (
        "<?php\n"
        "/** @var \\Magento\\Framework\\View\\Element\\Template $block */\n"
        "/** @var \\Hyva\\Theme\\Model\\ViewModelRegistry $viewModels */\n"
        "?>\n"
        '<section id="checkout-shipping" x-data="initShippingMethod()">\n'
        '  <div class="container">\n'
        '    <template x-for="rate in rates">\n'
        '      <span x-text="rate.title"></span>\n'
        "    </template>\n"
        "  </div>\n"
        "</section>\n"
        "<script>\n"
        "function initShippingMethod() {\n"
        "    return { rates: [] };\n"
        "}\n"
        "</script>\n"
    )
    out = "\n".join(extract_outline_symbols(phtml, ".phtml"))
    assert "@var \\Magento\\Framework\\View\\Element\\Template $block: L2" in out
    assert '<section#checkout-shipping x-data="initShippingMethod()">: L5-L11' in out
    assert "<script>: L12-L16" in out
    assert "function initShippingMethod(): L13-L15" in out


def test_outline_vue_sfc_blocks() -> None:
    vue = (
        "<template>\n"
        '  <div class="card">Hello</div>\n'
        "</template>\n"
        '<script setup lang="ts">\n'
        "export function formatCard(title: string): string {\n"
        "  return title.trim();\n"
        "}\n"
        "</script>\n"
        "<style scoped>\n"
        ".card { color: red; }\n"
        "</style>\n"
    )
    out = "\n".join(extract_outline_symbols(vue, ".vue"))
    assert "<template>: L1-L3" in out
    assert '<script setup lang="ts">: L4-L8' in out
    assert "function formatCard(title: string): string: L5-L7" in out
    assert "<style scoped>: L9-L11" in out


def test_outline_xml_layout_and_di() -> None:
    xml_src = (
        '<?xml version="1.0"?>\n'
        '<page xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
        "    <body>\n"
        '        <referenceContainer name="content">\n'
        '            <block class="Vendor\\Module\\Block\\Info" name="vendor.info" template="Vendor_Module::info.phtml"/>\n'
        "        </referenceContainer>\n"
        "    </body>\n"
        "</page>\n"
    )
    out = "\n".join(extract_outline_symbols(xml_src, ".xml"))
    assert "<page>: L2-L8" in out
    assert '<referenceContainer name="content">: L4-L6' in out
    assert '<block name="vendor.info"' in out


def test_outline_xml_magento1_config() -> None:
    m1_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<config>\n"
        "    <modules>\n"
        "        <Vendor_Bridge><version>1.0.0</version></Vendor_Bridge>\n"
        "    </modules>\n"
        "    <global>\n"
        "        <models>\n"
        "            <bridge><class>Vendor_Bridge_Model</class></bridge>\n"
        "        </models>\n"
        "        <blocks>\n"
        "            <bridge><class>Vendor_Bridge_Block</class></bridge>\n"
        "        </blocks>\n"
        "        <helpers>\n"
        "            <bridge><class>Vendor_Bridge_Helper</class></bridge>\n"
        "        </helpers>\n"
        "        <resources>\n"
        "            <bridge_setup><setup><module>Vendor_Bridge</module></setup></bridge_setup>\n"
        "        </resources>\n"
        "        <events>\n"
        "            <sales_order_save_after>\n"
        "                <observers>\n"
        "                    <push_order><class>bridge/observer</class></push_order>\n"
        "                </observers>\n"
        "            </sales_order_save_after>\n"
        "        </events>\n"
        "    </global>\n"
        "    <frontend>\n"
        "        <routers><bridge><use>standard</use></bridge></routers>\n"
        "    </frontend>\n"
        "    <adminhtml>\n"
        "        <translate><modules><Vendor_Bridge/></modules></translate>\n"
        "    </adminhtml>\n"
        "    <crontab>\n"
        "        <jobs><bridge_sync><schedule/></bridge_sync></jobs>\n"
        "    </crontab>\n"
        "</config>\n"
    )
    out = "\n".join(extract_outline_symbols(m1_xml, ".xml"))
    assert "<config>: L2-L36" in out
    assert "<modules>: L3-L5" in out
    assert "<global>: L6-L26" in out
    assert "<models>: L7-L9" in out
    assert "<blocks>: L10-L12" in out
    assert "<helpers>: L13-L15" in out
    assert "<resources>: L16-L18" in out
    assert "<events>: L19-L25" in out
    assert "<frontend>: L27-L29" in out
    assert "<adminhtml>: L30-L32" in out
    assert "<crontab>: L33-L35" in out


def test_outline_json_and_yaml_top_level_keys() -> None:
    json_src = (
        "{\n"
        '  "name": "pkg",\n'
        '  "scripts": {\n'
        '    "test": "vitest"\n'
        "  },\n"
        '  "dependencies": {\n'
        '    "vue": "^3.0.0"\n'
        "  }\n"
        "}\n"
    )
    out_json = "\n".join(extract_outline_symbols(json_src, ".json"))
    assert '"name": L2-L2' in out_json
    assert '"scripts": L3-L5' in out_json
    assert '"dependencies": L6-L8' in out_json

    yaml_src = (
        "services:\n"
        "  web:\n"
        "    image: nginx:alpine\n"
        "volumes:\n"
        "  data:\n"
        "    driver: local\n"
    )
    out_yaml = "\n".join(extract_outline_symbols(yaml_src, ".yml"))
    assert "services: L1-L3" in out_yaml
    assert "volumes: L4-L6" in out_yaml


def test_outline_task_output_log_sections() -> None:
    log_src = (
        "=== Running test suite ===\n"
        "collecting ... collected 12 items\n"
        "tests/test_app.py::test_login FAILED\n"
        "Traceback (most recent call last):\n"
        '  File "tests/test_app.py", line 14, in test_login\n'
        "AssertionError: invalid token\n"
        "=== 1 failed, 11 passed in 0.42s ===\n"
    )
    out_log = "\n".join(extract_outline_symbols(log_src, ".output"))
    assert "=== Running test suite ===: L1" in out_log
    assert "tests/test_app.py::test_login FAILED: L3" in out_log
    assert "AssertionError: invalid token: L6" in out_log


def test_mts_and_cts_outlined_via_ts_parser(tmp_path: Path) -> None:
    assert ".mts" in OUTLINE_EXTENSIONS
    assert ".cts" in OUTLINE_EXTENSIONS
    body = (
        "export class Greeter {\n"
        + "".join(f"  step{i}(): number {{ return {i}; }}\n" for i in range(90))
        + "}\n"
        + "export function computeTotal(items: number[]): number {\n"
        + "".join(f"  const v{i} = items.length + {i};\n" for i in range(95))
        + "  return v0;\n"
        + "}\n"
    )
    for ext in (".mts", ".cts"):
        mod_path = tmp_path / f"sample_mod{ext}"
        mod_path.write_text(body, encoding="utf-8")
        out = generate_outline(str(mod_path))
        assert "Greeter" in out
        assert "computeTotal" in out
        assert re.search(r"L\d+-L\d+", out)


def test_block_scanner_handles_ts_private_fields_and_vue_array_signatures() -> None:
    ts_src = (
        "export class Worker {\n"
        "  #ready = true;\n"
        "  run(items: string[] = []): boolean {\n"
        "    if (this.#ready) {\n"
        "      return items.length > 0;\n"
        "    }\n"
        "    return false;\n"
        "  }\n"
        "}\n"
    )
    ts_out = "\n".join(outline_ts_js(ts_src))
    assert "class Worker: L1-L9" in ts_out
    assert "  method run: L3-L8" in ts_out

    vue_src = (
        '<script setup lang="ts">\n'
        "export function loadItems(ids: string[] = []): number {\n"
        "  // comment with } }\n"
        "  return ids.length;\n"
        "}\n"
        "const filterRows = (rows: number[] = []) => {\n"
        "  return rows;\n"
        "};\n"
        "</script>\n"
    )
    vue_out = "\n".join(extract_outline_symbols(vue_src, ".vue"))
    assert "  function loadItems(ids: string[] = []): number: L2-L5" in vue_out
    assert "  const filterRows =>: L6-L8" in vue_out


def test_tree_sitter_extracts_exported_class_methods_arrow_fns_and_rust_impl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _id(text: str, row: int = 0) -> FakeTSNode:
        return FakeTSNode("identifier", row, row, text=text)

    method = FakeTSNode("method_definition", 1, 3, name="charge")
    cbody = FakeTSNode("class_body", 0, 4, children=[method])
    cls_decl = FakeTSNode("class_declaration", 0, 4, name="Gateway", children=[cbody])
    exp_cls = FakeTSNode("export_statement", 0, 4, children=[cls_decl])

    arrow = FakeTSNode("arrow_function", 6, 8)
    var_decl = FakeTSNode(
        "variable_declarator",
        6,
        8,
        name="useAuth",
        fields={"value": arrow},
        children=[arrow],
    )
    lex_decl = FakeTSNode("lexical_declaration", 6, 8, children=[var_decl])
    exp_fn = FakeTSNode("export_statement", 6, 8, children=[lex_decl])
    ts_root = FakeTSNode("program", 0, 8, children=[exp_cls, exp_fn])

    fn_fmt = FakeTSNode("function_item", 1, 3, name="fmt")
    impl_node = FakeTSNode(
        "impl_item",
        0,
        4,
        fields={"trait": _id("Display", 0), "type": _id("TokenCache", 0)},
        children=[fn_fmt],
    )
    rs_root = FakeTSNode("source_file", 0, 4, children=[impl_node])

    class FakeParser:
        def __init__(self, lang: str) -> None:
            self.lang = lang

        def parse(self, _raw: bytes) -> Any:
            root = ts_root if self.lang == "typescript" else rs_root
            return type("FakeTree", (), {"root_node": root})()

    fake_mod = type("FakeTSPack", (), {"get_parser": staticmethod(lambda lang: FakeParser(lang))})
    monkeypatch.setitem(sys.modules, "tree_sitter_language_pack", fake_mod)

    ts_res = try_outline_tree_sitter(
        "export class Gateway {}\nexport const useAuth = () => {}\n", ".ts"
    )
    assert ts_res == [
        "class Gateway: L1-L5",
        "  method charge: L2-L4",
        "const useAuth =>: L7-L9",
    ]
    rs_res = try_outline_tree_sitter("impl Display for TokenCache {\n  fn fmt() {}\n}\n", ".rs")
    assert rs_res == [
        "impl Display for TokenCache: L1-L5",
        "  fn fmt: L2-L4",
    ]


def test_real_tree_sitter_language_pack_integration_when_installed() -> None:
    import importlib.util

    ts_res = try_outline_tree_sitter(
        "export class Gateway {\n  charge(): number {\n    return 1;\n  }\n}\n",
        ".ts",
    )
    if importlib.util.find_spec("tree_sitter_language_pack") is None:
        assert ts_res is None
    else:
        assert ts_res is not None
        joined = "\n".join(ts_res)
        assert "class Gateway: L1-L5" in joined
        assert "  method charge: L2-L4" in joined


def test_classify_special_read_target_handles_posix_and_windows_paths() -> None:
    from hooks.json_outliners import (
        ANTIGRAVITY_FULL_TRANSCRIPT_GLOB,
        ANTIGRAVITY_FULL_TRANSCRIPT_NAME,
        TRANSCRIPT_FILENAMES,
        classify_special_read_target,
    )

    mcp_win = r"C:\Users\alice\.gemini\antigravity\brain\123\.system_generated\steps\42\output.txt"
    t_mcp = classify_special_read_target(mcp_win)
    assert t_mcp.basename == "output.txt"
    assert t_mcp.is_mcp_step_output is True
    assert t_mcp.is_twg_stdout is False
    assert t_mcp.is_transcript_log is False

    twg_path = "/tmp/twg/call-99/stdout.compact.json"
    t_twg = classify_special_read_target(twg_path)
    assert t_twg.is_twg_stdout is True
    assert t_twg.is_mcp_step_output is False

    tr_win = r"C:\Users\alice\.gemini\antigravity\brain\123\.system_generated\logs\transcript_full.jsonl"
    t_tr = classify_special_read_target(tr_win)
    assert t_tr.is_transcript_log is True
    assert ANTIGRAVITY_FULL_TRANSCRIPT_NAME == "transcript_full.jsonl"
    assert "transcript_full.jsonl" in TRANSCRIPT_FILENAMES
    assert ANTIGRAVITY_FULL_TRANSCRIPT_GLOB.endswith("transcript_full.jsonl")


def test_read_planner_stays_under_800_loc() -> None:
    from hooks import read_planner

    assert read_planner.covering_read_step([[1, 50, 2, 2]], 10, 30) == 2
    assert read_planner.trim_partially_covered_range([[1, 20, 1, 2]], 15, 40) == (21, 40)
    planner_loc = len(Path(read_planner.__file__).read_text(encoding="utf-8").splitlines())
    assert planner_loc <= 800



