"""Regression guards ensuring runtime compatibility with macOS /usr/bin/python3 (3.9+)."""

from __future__ import annotations

import ast
from datetime import datetime, timezone
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SYSTEM_PYTHON3 = Path("/usr/bin/python3")


def _has_future_annotations(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            if any(alias.name == "annotations" for alias in node.names):
                return True
    return False


def _contains_bitor(node: ast.AST | None) -> bool:
    if node is None:
        return False
    return any(
        isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr)
        for sub in ast.walk(node)
    )


def _iter_annotation_nodes(tree: ast.Module) -> list[ast.AST]:
    nodes: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.returns is not None:
                nodes.append(node.returns)
            all_args = (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            )
            if node.args.vararg is not None:
                all_args.append(node.args.vararg)
            if node.args.kwarg is not None:
                all_args.append(node.args.kwarg)
            for arg in all_args:
                if arg.annotation is not None:
                    nodes.append(arg.annotation)
        elif isinstance(node, ast.AnnAssign) and node.annotation is not None:
            nodes.append(node.annotation)
    return nodes


def test_ast_no_python310_only_runtime_constructs() -> None:
    """Reject dataclass(slots=/kw_only=), match/case, zip(strict=), and runtime PEP 604 unions."""
    offenders: list[str] = []
    match_cls = getattr(ast, "Match", None)

    for path in sorted([
        *ROOT.glob("hooks/*.py"),
        *ROOT.glob("bin/*.py"),
        *ROOT.glob("policies/*.py"),
        *ROOT.glob("integrations/*.py"),
        *ROOT.glob("spool/*.py"),
        *ROOT.glob("tests/*.py"),
    ]):
        rel = path.relative_to(ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        has_future = _has_future_annotations(tree)

        if path.name != "__init__.py" and not has_future:
            offenders.append(f"{rel}:1 missing 'from __future__ import annotations'")
        if not has_future:
            for ann in _iter_annotation_nodes(tree):
                if _contains_bitor(ann):
                    offenders.append(
                        f"{rel}:{getattr(ann, 'lineno', 1)} PEP 604 '|' annotation without future annotations"
                    )

        for node in ast.walk(tree):
            if match_cls is not None and isinstance(node, match_cls):
                offenders.append(f"{rel}:{node.lineno} structural pattern matching (Python 3.10+)")

            if isinstance(node, ast.Call):
                func = node.func
                func_name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr
                    if isinstance(func, ast.Attribute)
                    else ""
                )
                if func_name == "dataclass":
                    for kw in node.keywords:
                        if kw.arg in ("slots", "kw_only"):
                            offenders.append(
                                f"{rel}:{node.lineno} @dataclass({kw.arg}=...) requires Python 3.10+"
                            )
                elif func_name == "zip":
                    for kw in node.keywords:
                        if kw.arg == "strict":
                            offenders.append(
                                f"{rel}:{node.lineno} zip(strict=...) requires Python 3.10+"
                            )
                elif func_name in ("isinstance", "issubclass") and len(node.args) >= 2:
                    if _contains_bitor(node.args[1]):
                        offenders.append(
                            f"{rel}:{node.lineno} {func_name}(..., A | B) requires Python 3.10+"
                        )

    assert offenders == []


def _runtime_python() -> str:
    if SYSTEM_PYTHON3.is_file() and os.access(SYSTEM_PYTHON3, os.X_OK):
        return str(SYSTEM_PYTHON3)
    return sys.executable


def test_system_python3_imports_all_hooks_and_bin_modules(tmp_path: Path) -> None:
    """Every module in hooks/ and bin/ must import cleanly under /usr/bin/python3 (3.9.6 on macOS)."""
    py = _runtime_python()
    modules = sorted(
        f"{p.parent.name}.{p.stem}"
        for p in [
            *ROOT.glob("hooks/*.py"),
            *ROOT.glob("bin/*.py"),
            *ROOT.glob("policies/*.py"),
            *ROOT.glob("integrations/*.py"),
            *ROOT.glob("spool/*.py"),
        ]
        if p.stem != "__init__"
    )
    script = (
        "import importlib, sys; "
        f"sys.path.insert(0, {str(ROOT)!r}); "
        f"[importlib.import_module(m) for m in {modules!r}]; "
        "print('IMPORT_OK')"
    )
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "CONTEXT_GUARD_HOME": str(tmp_path / "cg_home"),
        "CONTEXT_GUARD_CONFIG_PATH": str(tmp_path / "missing_config.json"),
    }
    proc = subprocess.run(
        [py, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    assert proc.returncode == 0, f"{py} import failed:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    assert "IMPORT_OK" in proc.stdout


@pytest.mark.parametrize(
    ("rel_script", "extra_args", "stdin_obj", "expect_json"),
    [
        (
            "hooks/pre_tool_use.py",
            [],
            {
                "conversation_id": "py39-smoke",
                "tool_name": "run_command",
                "tool_input": {"CommandLine": "git status"},
            },
            True,
        ),
        (
            "hooks/pre_invocation.py",
            [],
            {"conversation_id": "py39-smoke", "initialNumSteps": 1},
            True,
        ),
        (
            "hooks/pre_compact.py",
            ["--harness", "claude"],
            {"session_id": "py39-smoke"},
            True,
        ),
        (
            "hooks/post_tool_use.py",
            ["--harness", "claude"],
            {
                "session_id": "py39-smoke",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "tool_response": {"stdout": "ok\n", "stderr": ""},
            },
            True,
        ),
        ("bin/cg_status.py", ["--short"], None, False),
        ("bin/cg_status.py", ["--replay"], None, False),
        ("bin/cg_status.py", ["--benchmark"], None, False),
        ("bin/cg_status.py", ["--public-json"], None, False),
        ("bin/install_harnesses.py", ["--status"], None, False),
        ("bin/cg_spool.py", ["list", "--json"], None, True),
    ],
)
def test_system_python3_executes_hook_and_cli_entrypoints(
    tmp_path: Path,
    rel_script: str,
    extra_args: list[str],
    stdin_obj: dict[str, object] | None,
    expect_json: bool,
) -> None:
    """All hook entrypoints and status CLIs must exit 0 under /usr/bin/python3."""
    py = _runtime_python()
    cg_home = tmp_path / "cg_home"
    telemetry_dir = cg_home / "telemetry"
    telemetry_dir.mkdir(parents=True, exist_ok=True)
    # Pre-seed fresh update.json so cg_status.py does not spawn background update_check.py.
    (telemetry_dir / "update.json").write_text(
        json.dumps(
            {
                "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "state": "current",
            }
        ),
        encoding="utf-8",
    )
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "CONTEXT_GUARD_HOME": str(cg_home),
        "CONTEXT_GUARD_STATE_DIR": str(state_dir),
        "CONTEXT_GUARD_SPOOL_DIR": str(telemetry_dir / "spool"),
        "CONTEXT_GUARD_CONFIG_PATH": str(tmp_path / "missing_config.json"),
    }
    stdin_text = json.dumps(stdin_obj) if stdin_obj is not None else ""
    proc = subprocess.run(
        [py, str(ROOT / rel_script), *extra_args],
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    assert proc.returncode == 0, (
        f"{py} {rel_script} exited {proc.returncode}:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    )
    if expect_json:
        parsed = json.loads(proc.stdout)
        assert isinstance(parsed, dict)
        if rel_script == "bin/cg_spool.py":
            assert parsed.get("ok") is True


def test_system_python3_executes_mcp_auto_outline_and_silent_range_trim(tmp_path: Path) -> None:
    """Exercise read_planner + json_outliners + telemetry + outcomes under /usr/bin/python3."""
    py = _runtime_python()
    cg_home = tmp_path / "cg_home"
    cg_home.mkdir(parents=True, exist_ok=True)
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    sample = tmp_path / "big_module.py"
    sample.write_text(
        "\n".join(f"line_{i} = {i}" for i in range(1, 201)),
        encoding="utf-8",
    )
    mcp_dir = tmp_path / ".system_generated" / "steps" / "42"
    mcp_dir.mkdir(parents=True, exist_ok=True)
    mcp_out = mcp_dir / "output.txt"
    mcp_out.write_text(
        json.dumps(
            {
                "file_name": "rep.py",
                "file_path": "pkg/rep.py",
                "content": "\n".join(f"def fn_{i}() -> int:\n    return {i}\n" for i in range(90)),
            }
        )
        + (" " * 16_000),
        encoding="utf-8",
    )

    cfg_path = cg_home / "config.json"
    cfg_path.write_text(json.dumps({"read_confirm_policy": "bounded"}), encoding="utf-8")
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "CONTEXT_GUARD_HOME": str(cg_home),
        "CONTEXT_GUARD_STATE_DIR": str(state_dir),
        "CONTEXT_GUARD_CONFIG_PATH": str(cfg_path),
    }

    def _run_hook(rel_script: str, payload: dict[str, object], *extra_args: str) -> dict[str, object]:
        proc = subprocess.run(
            [py, str(ROOT / rel_script), *extra_args],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)

    # 1. Overlapping read_file gets silently trimmed to unread tail (StartLine=101)
    p1: dict[str, object] = {
        "conversationId": "py39-read-smoke",
        "stepIdx": 1,
        "toolCall": {
            "id": "py39-r1",
            "name": "read_file",
            "args": {"Path": str(sample), "StartLine": 1, "EndLine": 100},
        },
    }
    r1 = _run_hook("hooks/pre_tool_use.py", p1)
    assert r1.get("decision") == "allow"
    _run_hook("hooks/post_tool_use.py", p1, "--harness", "antigravity")
    p2: dict[str, object] = {
        "conversationId": "py39-read-smoke",
        "stepIdx": 2,
        "toolCall": {
            "id": "py39-r2",
            "name": "read_file",
            "args": {"Path": str(sample), "StartLine": 50, "EndLine": 150},
        },
    }
    r2 = _run_hook("hooks/pre_tool_use.py", p2)
    assert r2.get("decision") == "allow"
    assert r2.get("overwrite") == {"StartLine": 101, "EndLine": 150}
    _run_hook("hooks/post_tool_use.py", p2, "--harness", "antigravity")

    # 2. Large MCP steps/<N>/output.txt artifact is auto-outlined and denied on first touch
    r_mcp = _run_hook(
        "hooks/pre_tool_use.py",
        {
            "conversationId": "py39-read-smoke",
            "stepIdx": 3,
            "toolCall": {"name": "read_file", "args": {"Path": str(mcp_out)}},
        },
    )
    assert r_mcp.get("decision") == "deny"
    assert "AUTO-OUTLINE" in str(r_mcp.get("reason", ""))
