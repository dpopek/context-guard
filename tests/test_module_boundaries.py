"""Modules in hooks/ and bin/ talk to each other through public names only."""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path

from hooks.local_repo_guard import GENERIC_REPO_BASENAMES

ROOT = Path(__file__).resolve().parent.parent


def _private_cross_imports_in_source(
    rel: str, src: str, prod_modules: set[str]
) -> list[str]:
    offenders: list[str] = []
    tree = ast.parse(src, filename=rel)
    pkg = rel.split("/")[0]
    module_aliases: set[str] = set()
    pkg_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in ("hooks", "bin"):
                    if alias.asname:
                        module_aliases.add(alias.asname)
                    elif "." not in alias.name:
                        pkg_aliases.add(alias.name)
                    else:
                        pkg_aliases.add(top)
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                base = (
                    f"{pkg}.{node.module}"
                    if node.level == 1 and node.module
                    else (pkg if node.level == 1 else (node.module or ""))
                )
            else:
                base = node.module or ""
            if base.split(".")[0] not in ("hooks", "bin"):
                continue
            for alias in node.names:
                if alias.name.startswith("_") or (alias.asname or "").startswith("_"):
                    offenders.append(f"{rel}:{node.lineno} {alias.name}")
                elif base in ("hooks", "bin") and alias.name in prod_modules:
                    module_aliases.add(alias.asname or alias.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr.startswith("_") and not node.attr.startswith("__"):
            val = node.value
            if isinstance(val, ast.Name) and val.id in module_aliases:
                offenders.append(f"{rel}:{node.lineno} {val.id}.{node.attr}")
            elif (
                isinstance(val, ast.Attribute)
                and isinstance(val.value, ast.Name)
                and val.value.id in pkg_aliases
                and val.attr in prod_modules
            ):
                offenders.append(f"{rel}:{node.lineno} {val.value.id}.{val.attr}.{node.attr}")
    return offenders


def _private_cross_imports() -> list[str]:
    prod_modules = {p.stem for folder in ("hooks", "bin") for p in (ROOT / folder).glob("*.py")} | {
        "hooks",
        "bin",
    }
    offenders: list[str] = []
    for path in sorted([*ROOT.glob("hooks/*.py"), *ROOT.glob("bin/*.py")]):
        rel = path.relative_to(ROOT).as_posix()
        offenders.extend(_private_cross_imports_in_source(rel, path.read_text(encoding="utf-8"), prod_modules))
    return offenders


def test_no_private_names_cross_module_boundaries() -> None:
    assert _private_cross_imports() == []
    sample = "from hooks import file_io\nimport hooks.config\nfile_io._priv()\nhooks.config._priv()\n"
    assert _private_cross_imports_in_source("bin/demo.py", sample, {"file_io", "config", "hooks", "bin"}) == [
        "bin/demo.py:3 file_io._priv",
        "bin/demo.py:4 hooks.config._priv",
    ]


def test_one_operator_diagnostic() -> None:
    from hooks import outcomes, pre_compact, pre_invocation, pre_tool_use, state_store, telemetry

    assert (
        telemetry.warn
        is outcomes.warn
        is pre_tool_use.warn
        is pre_compact.warn
        is pre_invocation.warn
        is state_store.warn
    )


def test_pre_invocation_does_not_import_pre_tool_use() -> None:
    path = ROOT / "hooks" / "pre_invocation.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "hooks.pre_tool_use":
                offenders.append(f"pre_invocation.py:{node.lineno} from hooks.pre_tool_use")
            elif node.module == "hooks" and any(a.name == "pre_tool_use" for a in node.names):
                offenders.append(f"pre_invocation.py:{node.lineno} from hooks import pre_tool_use")
        elif isinstance(node, ast.Import):
            if any(a.name == "hooks.pre_tool_use" for a in node.names):
                offenders.append(f"pre_invocation.py:{node.lineno} import hooks.pre_tool_use")
    assert offenders == []


def _build_package_import_graph() -> dict[str, set[str]]:
    mod_paths: dict[str, Path] = {}
    for path in sorted([*ROOT.glob("hooks/*.py"), *ROOT.glob("bin/*.py")]):
        pkg = path.parent.name
        mod_name = pkg if path.stem == "__init__" else f"{pkg}.{path.stem}"
        mod_paths[mod_name] = path

    graph: dict[str, set[str]] = {mod_name: set() for mod_name in mod_paths}
    for mod_name, path in mod_paths.items():
        pkg = path.parent.name
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    raw = alias.name
                    if raw in mod_paths:
                        graph[mod_name].add(raw)
                    elif raw.split(".")[0] in ("hooks", "bin"):
                        cand = ".".join(raw.split(".")[:2])
                        if cand in mod_paths:
                            graph[mod_name].add(cand)
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    if node.level == 1:
                        base = f"{pkg}.{node.module}" if node.module else pkg
                    else:
                        base = node.module or ""
                else:
                    base = node.module or ""

                if base in ("hooks", "bin"):
                    for alias in node.names:
                        cand = f"{base}.{alias.name}"
                        if cand in mod_paths:
                            graph[mod_name].add(cand)
                        elif base in mod_paths:
                            graph[mod_name].add(base)
                elif base.startswith(("hooks.", "bin.")):
                    cand = ".".join(base.split(".")[:2])
                    if cand in mod_paths:
                        graph[mod_name].add(cand)
    return graph


def _tarjan_cyclic_sccs(graph: dict[str, set[str]]) -> list[list[str]]:
    index_counter = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    cyclic_sccs: list[list[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index_counter
        indices[node] = index_counter
        lowlink[node] = index_counter
        index_counter += 1
        stack.append(node)
        on_stack.add(node)

        for succ in sorted(graph.get(node, ())):
            if succ not in indices:
                strongconnect(succ)
                lowlink[node] = min(lowlink[node], lowlink[succ])
            elif succ in on_stack:
                lowlink[node] = min(lowlink[node], indices[succ])

        if lowlink[node] == indices[node]:
            scc: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                scc.append(member)
                if member == node:
                    break
            scc.sort()
            if len(scc) > 1 or (len(scc) == 1 and scc[0] in graph.get(scc[0], ())):
                cyclic_sccs.append(scc)

    for vertex in sorted(graph):
        if vertex not in indices:
            strongconnect(vertex)

    return cyclic_sccs


def test_zero_import_cycles_across_hooks_and_bin() -> None:
    graph = _build_package_import_graph()
    cycles = _tarjan_cyclic_sccs(graph)
    assert cycles == [], f"Cyclic module import components detected: {cycles}"
    assert "hooks.harness_adapter" not in graph.get("hooks.outcomes", set()), (
        "hooks.outcomes must not import hooks.harness_adapter"
    )
    assert "hooks.pre_tool_use" not in graph.get("hooks.read_planner", set())


def test_hooks_total_loc_ceiling() -> None:
    """Keep slimmed runtime hooks/* well below the 6,800 LOC total ceiling."""
    total_loc = sum(
        len(path.read_text(encoding="utf-8").splitlines())
        for path in (ROOT / "hooks").glob("*.py")
    )
    assert total_loc < 6800, f"hooks/*.py total LOC is {total_loc} (must be < 6800)"


MAX_PROD_FILE_LOC = 800
MAX_JS_FILE_LOC = 500


def test_production_module_loc_ceilings() -> None:
    """Every production Python module in hooks/*.py and bin/*.py must stay <= 800 LOC."""
    violations: list[str] = []
    for folder in ("hooks", "bin"):
        for path in sorted((ROOT / folder).glob("*.py")):
            loc = len(path.read_text(encoding="utf-8").splitlines())
            if loc > MAX_PROD_FILE_LOC:
                violations.append(
                    f"{path.relative_to(ROOT)}: {loc} LOC exceeds {MAX_PROD_FILE_LOC} LOC ceiling"
                )
    assert violations == [], f"Production module LOC ceiling violations: {violations}"


def test_vscode_extension_js_loc_ceilings() -> None:
    """Extension entrypoint and extracted JS modules must exist and stay <= 500 LOC each."""
    ext_dir = ROOT / "vscode-extension"
    for required in ("extension.js", "view_model.js", "updater.js", "renderers.js"):
        assert (ext_dir / required).is_file(), f"Missing modular extension file: {required}"
    violations: list[str] = []
    for path in sorted(ext_dir.glob("*.js")):
        loc = len(path.read_text(encoding="utf-8").splitlines())
        if loc > MAX_JS_FILE_LOC:
            violations.append(f"{path.relative_to(ROOT)}: {loc} LOC exceeds {MAX_JS_FILE_LOC} LOC ceiling")
    assert violations == [], f"VS Code extension JS LOC violations: {violations}"


_ALLOWED_TEST_USERS = frozenset({"dev", "x", "u", "user", "example", "alice", "bob", "jan"})
_GENERIC_CI_USERS = frozenset(
    {"runner", "ubuntu", "root", "vscode", "codespace", "docker", "builder", "dev", "user", "test", "admin"}
)
_USER_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/([A-Za-z0-9._-]+)")
_WIN_USER_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z]:(?:[/\\]|\\\\)Users(?:[/\\]|\\\\)([A-Za-z0-9._-]+)",
    re.IGNORECASE,
)
_GCP_PROJECT_PROD_RE = re.compile(
    r"\b[a-z][a-z0-9]+-[a-z][a-z0-9]+-\d{5,}(?:-[a-z0-9]+)?\b", re.IGNORECASE
)
_GCP_PROJECT_TEST_RE = re.compile(
    r"\b(?!(?:acme|example)-)[a-z][a-z0-9]+-[a-z][a-z0-9]+-\d{5,}(?:-[a-z0-9]+)?\b",
    re.IGNORECASE,
)
_LOCAL_EMAIL_RE = re.compile(r"@[A-Za-z0-9._-]+\.local\b", re.IGNORECASE)
_ATLASSIAN_RE = re.compile(r"\b(?!example\.)[a-z0-9-]+\.atlassian\.net\b", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9_]+(?:-[a-z0-9_]+)*")
_SKIP_DYNAMIC_TERMS = GENERIC_REPO_BASENAMES | {
    "magento",
    "context-guard",
    "advox",
    "dpopek",
    "python",
    "docs",
    "integration",
    "deployment",
    "misc",
    "core",
    "devops",
    "modules",
    "services",
    "mobile",
}


def _load_operator_private_terms() -> frozenset[str]:
    terms: set[str] = set()
    home = Path.home()
    me = home.name.lower()
    if len(me) >= 3 and me not in _GENERIC_CI_USERS:
        terms.add(me)
    cfg_path = home / ".config" / "context-guard" / "config.json"
    if not cfg_path.is_file():
        return frozenset(terms)
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset(terms)
    for ds in cfg.get("restricted_bq_datasets") or []:
        if isinstance(ds, str) and len(ds) >= 4:
            terms.add(ds.lower())
    hint = str(cfg.get("allowed_bq_views_hint") or "")
    for m in re.finditer(r"[a-z][a-z0-9]+-[a-z][a-z0-9]+(?:-\d{4,})?", hint.lower()):
        proj = m.group(0)
        terms.add(proj)
        parts = proj.split("-")
        if len(parts) >= 2:
            terms.add(f"{parts[0]}-{parts[1]}")
    rm_raw = cfg.get("repo_map_path")
    if isinstance(rm_raw, str) and Path(rm_raw).is_file():
        try:
            rm = json.loads(Path(rm_raw).read_text(encoding="utf-8"))
            for entry in rm.get("repositories") or []:
                name = str(entry.get("name") or "").lower()
                if len(name) >= 4 and name not in _SKIP_DYNAMIC_TERMS:
                    terms.add(name)
                slug = str(entry.get("remote_slug") or entry.get("gitlab_path") or "").lower()
                for part in slug.split("/"):
                    if len(part) >= 4 and part not in _SKIP_DYNAMIC_TERMS:
                        terms.add(part)
        except (OSError, ValueError):
            pass
    return frozenset(terms)


def _find_privacy_leak(
    content: str, *, allow_test_fixtures: bool, dynamic_terms: frozenset[str]
) -> str | None:
    for rx in (_USER_PATH_RE, _WIN_USER_PATH_RE):
        for m in rx.finditer(content):
            uname = m.group(1)
            if not allow_test_fixtures or uname.lower() not in _ALLOWED_TEST_USERS:
                return m.group(0)
    gcp_re = _GCP_PROJECT_TEST_RE if allow_test_fixtures else _GCP_PROJECT_PROD_RE
    for rx in (gcp_re, _LOCAL_EMAIL_RE, _ATLASSIAN_RE):
        hit = rx.search(content)
        if hit:
            return hit.group(0)
    if dynamic_terms:
        for m in _TOKEN_RE.finditer(content.lower()):
            seg = m.group(0)
            cands = {seg}
            if "-" in seg:
                parts = seg.split("-")
                cands.update(f"{parts[i]}-{parts[i + 1]}" for i in range(len(parts) - 1))
                cands.update(
                    f"{parts[i]}-{parts[i + 1]}-{parts[i + 2]}" for i in range(len(parts) - 2)
                )
            for cand in cands:
                if cand in dynamic_terms:
                    return cand
    return None


def _iter_project_svg_files(root: Path) -> list[Path]:
    svg_files = sorted(p for p in root.glob("*.svg") if p.is_file())
    skip_dirs = frozenset({"venv", ".venv", "node_modules", "__pycache__"})
    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name.startswith(".") or child.name in skip_dirs:
            continue
        for dirpath, dirnames, filenames in os.walk(child):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in skip_dirs)
            for fname in sorted(filenames):
                if fname.endswith(".svg"):
                    svg_files.append(Path(dirpath) / fname)
    return svg_files


def test_outline_loc_ceiling_and_zero_hardcoded_user_paths() -> None:
    outline_py = ROOT / "hooks" / "outline.py"
    loc = len(outline_py.read_text(encoding="utf-8").splitlines())
    assert loc < 680, f"hooks/outline.py has {loc} LOC (must be < 680)"

    assert not (ROOT / "docs").exists(), (
        "Internal planning docs/ folder must not exist inside the distributable plugin directory"
    )
    assert _find_privacy_leak(
        "/Users/" + "jdoe_real/repo", allow_test_fixtures=True, dynamic_terms=frozenset()
    )
    assert _find_privacy_leak(
        "C:\\Users\\" + "jdoe_real\\repo", allow_test_fixtures=True, dynamic_terms=frozenset()
    )
    assert _find_privacy_leak(
        "c:/users/" + "jdoe_real/repo", allow_test_fixtures=True, dynamic_terms=frozenset()
    )
    assert _find_privacy_leak(r"c:\users\alice\repo", allow_test_fixtures=False, dynamic_terms=frozenset())
    assert _find_privacy_leak(r"c:\users\alice\repo", allow_test_fixtures=True, dynamic_terms=frozenset()) is None
    assert _find_privacy_leak("/Users/dev/repo", allow_test_fixtures=False, dynamic_terms=frozenset())
    assert _find_privacy_leak("/Users/dev/repo", allow_test_fixtures=True, dynamic_terms=frozenset()) is None
    assert _find_privacy_leak(
        "SELECT * FROM corp-" + "data-987654:ds.tbl",
        allow_test_fixtures=True,
        dynamic_terms=frozenset(),
    )
    assert _find_privacy_leak("u@host." + "local", allow_test_fixtures=False, dynamic_terms=frozenset())
    assert _find_privacy_leak(
        "mycorp." + "atlassian.net", allow_test_fixtures=False, dynamic_terms=frozenset()
    )
    assert _find_privacy_leak(
        "repo secret-client-repo", allow_test_fixtures=True, dynamic_terms=frozenset({"secret-client-repo"})
    )

    dynamic_terms = _load_operator_private_terms()
    for folder in ("bin", "hooks", "rules", "skills", "tests", "vscode-extension"):
        is_tests = folder == "tests"
        for src_file in sorted((ROOT / folder).rglob("*")):
            if not src_file.is_file() or src_file.suffix not in (".py", ".md", ".json", ".js"):
                continue
            content = src_file.read_text(encoding="utf-8")
            leak = _find_privacy_leak(content, allow_test_fixtures=is_tests, dynamic_terms=dynamic_terms)
            assert leak is None, (
                f"Forbidden personal/company token '{leak}' found in {src_file.relative_to(ROOT)}"
            )
    extra_prod_files = [
        *(ROOT / rel for rel in ("README.md", "AGENTS.md", "CHANGELOG.md", "plugin.json", "hooks.json", "LICENSE", "pyproject.toml")),
        *(p for p in sorted((ROOT / ".githooks").glob("*")) if p.is_file()),
        *sorted((ROOT / ".github" / "workflows").glob("*.yml")),
        *_iter_project_svg_files(ROOT),
    ]
    for doc_path in extra_prod_files:
        if doc_path.is_file():
            doc_leak = _find_privacy_leak(
                doc_path.read_text(encoding="utf-8"),
                allow_test_fixtures=False,
                dynamic_terms=dynamic_terms,
            )
            assert doc_leak is None, f"Forbidden personal/company token '{doc_leak}' found in {doc_path.relative_to(ROOT)}"



MAX_TEST_FILE_LOC = 800
FORBIDDEN_WAVE_TEST_NAMES = {
    "test_horizon1_remediation.py",
    "test_horizon2_domain_cohesion.py",
    "test_horizon3_architecture_concurrency.py",
    "test_extension_audit_remediation.py",
    "test_audit3_remediation.py",
    "test_telemetry_isolation_p0.py",
}


def test_test_module_loc_ceilings() -> None:
    """Every test file in tests/*.py must stay <= 800 LOC and avoid chronological wave names."""
    violations: list[str] = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        if path.name in FORBIDDEN_WAVE_TEST_NAMES or re.match(
            r"test_(horizon\d+|.*audit\d*|.*_p\d+)\.py$", path.name
        ):
            violations.append(f"{path.name}: chronological audit-wave filename is forbidden")
        loc = len(path.read_text(encoding="utf-8").splitlines())
        if loc > MAX_TEST_FILE_LOC:
            violations.append(f"{path.name}: {loc} LOC exceeds {MAX_TEST_FILE_LOC} LOC ceiling")
    assert violations == [], f"Test suite topology violations: {violations}"


def test_no_unittest_testcase_in_test_suite() -> None:
    """All tests must use plain pytest functions and fixtures rather than unittest.TestCase."""
    violations: list[str] = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "unittest" or alias.name.startswith("unittest."):
                        violations.append(f"{path.name}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("unittest"):
                violations.append(f"{path.name}:{node.lineno} imports from {node.module}")
            elif isinstance(node, ast.ClassDef):
                for base in node.bases:
                    if "TestCase" in ast.unparse(base):
                        violations.append(f"{path.name}:{node.lineno} subclasses {ast.unparse(base)}")
    assert violations == [], f"Legacy unittest usage detected: {violations}"


def test_tests_do_not_access_private_production_symbols() -> None:
    """Tests must only import, call, or monkeypatch public symbols on hooks.* and bin.* modules."""
    prod_modules = {p.stem for folder in ("hooks", "bin") for p in (ROOT / folder).glob("*.py")} | {
        "hooks",
        "bin",
    }
    violations: list[str] = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module_aliases: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in ("hooks", "bin"):
                        module_aliases.add(alias.asname or alias.name.split(".")[-1])
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = mod.split(".")[0]
                if top in ("hooks", "bin"):
                    for alias in node.names:
                        if alias.name.startswith("_") and not alias.name.startswith("__"):
                            violations.append(
                                f"{path.name}:{node.lineno} imports private {mod}.{alias.name}"
                            )
                        elif alias.name in prod_modules:
                            module_aliases.add(alias.asname or alias.name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if (
                    node.value.id in module_aliases
                    and node.attr.startswith("_")
                    and not node.attr.startswith("__")
                ):
                    violations.append(
                        f"{path.name}:{node.lineno} accesses private {node.value.id}.{node.attr}"
                    )
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "setattr":
                    if len(node.args) >= 2 and isinstance(node.args[0], ast.Name):
                        target_mod = node.args[0].id
                        attr_node = node.args[1]
                        if (
                            target_mod in module_aliases
                            and isinstance(attr_node, ast.Constant)
                            and isinstance(attr_node.value, str)
                            and attr_node.value.startswith("_")
                        ):
                            violations.append(
                                f"{path.name}:{node.lineno} monkeypatches private {target_mod}.{attr_node.value}"
                            )
    assert violations == [], f"Private production symbol access in tests: {violations}"


def test_every_test_function_has_assertions() -> None:
    """Every test_* function in tests/*.py must execute at least one assert, pytest.raises, or helper assertion."""
    assertion_helpers = {
        "assert_all_protected",
        "assert_protected",
        "assert_unprotected",
        "check_case",
    }
    violations: list[str] = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
                continue
            has_assert = False
            for child in ast.walk(node):
                if isinstance(child, ast.Assert):
                    has_assert = True
                    break
                if isinstance(child, ast.Call):
                    func_str = ast.unparse(child.func)
                    if (
                        func_str in ("pytest.raises", "pytest.fail", "pytest.warns")
                        or func_str.startswith("assert_")
                        or func_str in assertion_helpers
                    ):
                        has_assert = True
                        break
            if not has_assert:
                violations.append(f"{path.name}:{node.lineno} {node.name} has zero assertions")
    assert violations == [], f"Unasserted test functions detected: {violations}"


def test_every_python_module_enables_future_annotations() -> None:
    """Every non-__init__.py module in hooks/, bin/, and tests/ must enable PEP 563 future annotations for Python 3.9+ cross-OS compatibility."""
    violations: list[str] = []
    for folder in ("hooks", "bin", "tests"):
        for path in sorted((ROOT / folder).glob("*.py")):
            if path.name == "__init__.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            has_future = any(
                isinstance(node, ast.ImportFrom)
                and node.module == "__future__"
                and any(alias.name == "annotations" for alias in node.names)
                for node in tree.body
            )
            if not has_future:
                violations.append(str(path.relative_to(ROOT)))
    assert violations == [], f"Missing 'from __future__ import annotations': {violations}"


UNIX_ONLY_STDLIB_MODULES = frozenset({"fcntl", "pwd", "grp", "termios", "resource", "pty"})


def test_no_unguarded_unix_only_imports() -> None:
    """Top-level imports of Unix-only stdlib modules must be guarded by try/except ImportError so Windows works."""
    violations: list[str] = []
    for folder in ("hooks", "bin", "tests"):
        for path in sorted((ROOT / folder).glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for stmt in tree.body:
                if isinstance(stmt, ast.Import):
                    for alias in stmt.names:
                        if alias.name.split(".")[0] in UNIX_ONLY_STDLIB_MODULES:
                            violations.append(
                                f"{path.relative_to(ROOT)}:{stmt.lineno} unguarded 'import {alias.name}'"
                            )
                elif isinstance(stmt, ast.ImportFrom):
                    mod = (stmt.module or "").split(".")[0]
                    if mod in UNIX_ONLY_STDLIB_MODULES:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{stmt.lineno} unguarded 'from {stmt.module} import ...'"
                        )
    assert violations == [], f"Unguarded Unix-only imports break Windows compatibility: {violations}"


def test_python39_runtime_ast_compatibility_and_no_bare_except() -> None:
    """Enforce Python 3.9 runtime compatibility (no match/case, no isinstance(x, A | B)) and no bare except:."""
    violations: list[str] = []
    match_cls = getattr(ast, "Match", None)
    for folder in ("hooks", "bin", "tests"):
        for path in sorted((ROOT / folder).glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            rel = path.relative_to(ROOT)
            for node in ast.walk(tree):
                if match_cls is not None and isinstance(node, match_cls):
                    violations.append(f"{rel}:{node.lineno} match/case requires Python 3.10+")
                elif isinstance(node, ast.ExceptHandler) and node.type is None:
                    violations.append(f"{rel}:{node.lineno} bare 'except:' is forbidden")
                elif (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in ("isinstance", "issubclass")
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.BinOp)
                    and isinstance(node.args[1].op, ast.BitOr)
                ):
                    violations.append(
                        f"{rel}:{node.lineno} {node.func.id}(..., A | B) fails at runtime on Python 3.9; use a tuple (A, B)"
                    )
    assert violations == [], f"Python 3.9 runtime / bare-except violations: {violations}"
