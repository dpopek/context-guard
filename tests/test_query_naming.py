"""Functions named like queries do not write state; core/, hooks/, policies/, integrations/, spool/, services/, evidence/ never import bin/."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path
from typing import Iterator

from hooks import model_identity, pre_tool_use

ROOT = Path(__file__).resolve().parent.parent

QUERY_PREFIXES = tuple(
    lead + stem
    for stem in (
        "get_", "compute_", "check_", "validate_", "is_", "has_", "find_",
        "load_", "resolve_", "read_", "detect_", "classify_", "evaluate_",
    )
    for lead in ("", "_")
)
FORBIDDEN_CALLS = frozenset({"locked_state", "warn"})
FORBIDDEN_CALL_PREFIXES = ("save", "record_", "_record_", "_commit_", "write_")
SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)

ALLOWED_QUERY_MUTATORS = {
    "core/platform_io.py::read_json_object_or_quarantine": (
        "the quarantine side effect is in the name"
    ),
}


def _called_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return ""


def _root_name(target: ast.expr) -> str:
    while isinstance(target, (ast.Subscript, ast.Attribute)):
        target = target.value
    return target.id if isinstance(target, ast.Name) else ""


def _own_nodes(func: ast.AST) -> Iterator[ast.AST]:
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        if isinstance(node, SCOPES):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _function_violations(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = func.args
    params = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    found: list[tuple[int, str]] = []
    for node in _own_nodes(func):
        if isinstance(node, ast.Call):
            name = _called_name(node)
            if name in FORBIDDEN_CALLS or name.startswith(FORBIDDEN_CALL_PREFIXES):
                found.append((node.lineno, f"calls {name}()"))
        elif isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                root = _root_name(target)
                if isinstance(target, (ast.Subscript, ast.Attribute)) and root in params:
                    found.append((node.lineno, f"assigns into parameter {root}"))
    return [f"{line} {reason}" for line, reason in sorted(found)]


def query_violations(source: str, label: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(QUERY_PREFIXES):
            violations = _function_violations(node)
            if violations:
                result[f"{label}::{node.name}"] = violations
    return result


def allow_list_problems(
    found: dict[str, list[str]], allowed: dict[str, str]
) -> tuple[list[str], list[str]]:
    unexpected = [f"{key}: {'; '.join(found[key])}" for key in sorted(found) if key not in allowed]
    stale = sorted(key for key in allowed if key not in found)
    return unexpected, stale


def bin_imports(source: str, label: str) -> list[str]:
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            modules = [node.module or ""]
        else:
            continue
        for module in modules:
            if module.split(".")[0] == "bin":
                offenders.append(f"{label}:{node.lineno} {module}")
    return sorted(offenders, key=lambda entry: int(entry.split(":")[1].split()[0]))


def _sources(*patterns: str) -> Iterator[tuple[str, str]]:
    for path in sorted(p for pattern in patterns for p in ROOT.glob(pattern)):
        yield path.relative_to(ROOT).as_posix(), path.read_text(encoding="utf-8")


def test_state_writing_functions_carry_command_names() -> None:
    from hooks import outcomes, read_planner

    renamed = {
        model_identity: ("resolve_model", "memoize_model"),
    }
    for module, (old, new) in renamed.items():
        assert callable(getattr(module, new)), f"{module.__name__}.{new} missing"
        assert not hasattr(module, old), f"{module.__name__}.{old} still present"
    assert callable(read_planner.handle_file_read_verdict)
    assert callable(outcomes.record_direct_outcome)


def test_query_named_functions_do_not_write_state() -> None:
    found: dict[str, list[str]] = {}
    for label, source in _sources(
        "core/*.py", "hooks/*.py", "services/*.py", "bin/*.py", "policies/*.py", "integrations/*.py", "spool/*.py"
    ):
        found.update(query_violations(source, label))
    unexpected, stale = allow_list_problems(found, ALLOWED_QUERY_MUTATORS)
    assert unexpected == [], "query-named functions that write state (rename them):\n" + "\n".join(unexpected)
    assert stale == [], "remove stale ALLOWED_QUERY_MUTATORS entries:\n" + "\n".join(stale)


def test_hooks_never_import_bin() -> None:
    offenders = [
        entry
        for label, source in _sources(
            "core/*.py", "hooks/*.py", "policies/*.py", "integrations/*.py", "spool/*.py", "services/*.py", "evidence/*.py"
        )
        for entry in bin_imports(source, label)
    ]
    assert offenders == [], (
        "core/, hooks/, policies/, integrations/, spool/, services/, evidence/ must not import bin/:\n"
        + "\n".join(offenders)
    )


def _violations_of(source: str) -> dict[str, list[str]]:
    return query_violations(textwrap.dedent(source), "hooks/sample.py")


def test_query_function_calling_locked_state_is_flagged() -> None:
    found = _violations_of(
        """
        def evaluate_x(path):
            with locked_state(path) as txn:
                return txn.state
        """
    )
    assert found == {"hooks/sample.py::evaluate_x": ["3 calls locked_state()"]}


def test_query_function_calling_a_recorder_is_flagged() -> None:
    found = _violations_of(
        """
        def _get_y(payload):
            telemetry.record_event(payload)
            return 1
        """
    )
    assert found == {"hooks/sample.py::_get_y": ["3 calls record_event()"]}


def test_query_function_assigning_into_a_parameter_is_flagged() -> None:
    found = _violations_of(
        """
        def resolve_z(state):
            state["k"] = 1
            state.counter += 1
            return state["k"]
        """
    )
    assert found == {
        "hooks/sample.py::resolve_z": [
            "3 assigns into parameter state",
            "4 assigns into parameter state",
        ]
    }


def test_nested_functions_are_their_own_scope() -> None:
    found = _violations_of(
        """
        def get_outer():
            def helper():
                locked_state("p")
            return helper

        def build():
            def _load_inner(state):
                state["k"] = 1
            return _load_inner
        """
    )
    assert found == {"hooks/sample.py::_load_inner": ["9 assigns into parameter state"]}


def test_pure_query_with_local_building_passes() -> None:
    found = _violations_of(
        """
        def find_items(text, items):
            out = []
            out.append(text.replace("a", "b"))
            seen = {}
            seen["k"] = items
            seen.update({"j": 1})
            return out, seen
        """
    )
    assert found == {}


def test_command_named_function_is_not_checked() -> None:
    found = _violations_of(
        """
        def gate_x(path):
            with locked_state(path):
                warn("x")
        """
    )
    assert found == {}


def test_stale_and_unexpected_entries_are_reported() -> None:
    found = {"hooks/a.py::get_a": ["3 calls warn()"], "hooks/b.py::get_b": ["4 calls save()"]}
    allowed = {"hooks/a.py::get_a": "reason", "hooks/c.py::get_c": "reason"}
    unexpected, stale = allow_list_problems(found, allowed)
    assert unexpected == ["hooks/b.py::get_b: 4 calls save()"]
    assert stale == ["hooks/c.py::get_c"]


def test_bin_import_forms_are_detected() -> None:
    source = textwrap.dedent(
        """
        import bin
        import bin.cg_status as status
        from bin import outline
        from bin.cg_status import main
        from hooks import telemetry
        import binascii
        """
    )
    assert bin_imports(source, "hooks/sample.py") == [
        "hooks/sample.py:2 bin",
        "hooks/sample.py:3 bin.cg_status",
        "hooks/sample.py:4 bin",
        "hooks/sample.py:5 bin.cg_status",
    ]
