"""Tests for quiet CLI flag rewrites, outline-pull command detection, and latency invariants."""

from __future__ import annotations

import ntpath
import os
import random
import statistics
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from hooks import pre_tool_use as ptu, shell_parser
from hooks.shell_output import classify_family
from hooks.shell_parser import (
    extract_outline_pull_targets,
    extract_shell_read_targets,
    is_bounded_shell_read,
    is_outline_pull,
    is_unbounded_shell_dump,
    rewrite_quiet_cli_flags,
    split_leading_cd_prefix,
)
from hooks.telemetry import load_telemetry_stats
from integrations.atlassian_twg import rewrite_twg_cli_command
from tests.helpers import read_outcomes_ledger, write_python_module


def test_split_leading_cd_prefix() -> None:
    assert split_leading_cd_prefix("cd repo && pytest tests/") == ("cd repo && ", "pytest tests/")
    assert split_leading_cd_prefix("cd '/tmp/my repo'; git status") == ("cd '/tmp/my repo'; ", "git status")
    assert split_leading_cd_prefix("pytest tests/") == ("", "pytest tests/")


def test_is_outline_pull_matches_bare_commands_and_rejects_compound_chains(
    tmp_path: Path,
) -> None:
    assert is_outline_pull("cg-outline src/app.py") is True
    assert is_outline_pull("cd repo && cg-outline src/app.py") is True
    assert is_outline_pull("python3 ~/.gemini/config/plugins/context-guard/hooks/outline.py src/app.py") is True
    assert is_outline_pull("/opt/plugins/context-guard/hooks/outline.py src/app.py") is True

    assert is_outline_pull("cg-outline src/app.py && cat src/app.py") is False
    assert is_outline_pull("cg-outline src/app.py; ls") is False
    assert is_outline_pull("cg-outline src/app.py | head -n 5") is False
    assert is_outline_pull("cg-outline src/app.py > out.txt") is False
    assert is_outline_pull("cat src/app.py") is False

    state_dir = tmp_path / "state"
    res = ptu.evaluate_hook(
        {
            "conversationId": "c-pull",
            "stepIdx": 1,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "cg-outline src/app.py"}},
        },
        state_dir=str(state_dir),
    )
    assert res == {"decision": "allow"}
    stats = load_telemetry_stats(state_dir / "telemetry_stats.json")
    assert stats["events"]["outline_pulls"] == 1
    assert read_outcomes_ledger(state_dir)["by_key"]["antigravity|unknown|outline_pull"]["applied"] == 1


def test_extract_outline_pull_targets_resolves_cwd_dedups_and_handles_bad_quotes(tmp_path: Path) -> None:
    sub = tmp_path / "repo"
    sub.mkdir()
    a_py = sub / "a.py"
    b_py = sub / "b.py"
    a_py.write_text("x = 1\n", encoding="utf-8")
    b_py.write_text("y = 2\n", encoding="utf-8")

    assert extract_outline_pull_targets(f"cg-outline {a_py}") == [os.path.realpath(a_py)]
    assert extract_outline_pull_targets(f"cd repo && cg-outline -v a.py b.py a.py missing.py", cwd=str(tmp_path)) == [
        os.path.realpath(a_py),
        os.path.realpath(b_py),
    ]
    assert extract_outline_pull_targets(
        f"python3 ~/.gemini/config/plugins/context-guard/hooks/outline.py {a_py}"
    ) == [os.path.realpath(a_py)]
    assert extract_outline_pull_targets(f"cg-outline {a_py} && cat {a_py}") == []
    assert extract_outline_pull_targets('cg-outline "unterminated') == []


def test_extract_shell_read_targets_and_unbounded_dump_detection(tmp_path: Path) -> None:
    sub = tmp_path / "pkg"
    sub.mkdir()
    a_py = sub / "a.py"
    b_py = sub / "b.py"
    a_py.write_text("a = 1\n", encoding="utf-8")
    b_py.write_text("b = 2\n", encoding="utf-8")

    assert is_unbounded_shell_dump(f"cat {a_py}") is True
    assert is_unbounded_shell_dump(f"/bin/cat {a_py} | head -n 5") is True
    assert is_unbounded_shell_dump(f"cd pkg && nl a.py") is True
    assert is_unbounded_shell_dump(f"less {a_py}") is True
    assert is_unbounded_shell_dump(f"bat {a_py}") is True
    assert is_unbounded_shell_dump(f"head -n 20 {a_py}") is False
    assert is_unbounded_shell_dump(f"sed -n '1,40p' {a_py}") is False
    assert is_unbounded_shell_dump("pytest tests/") is False
    assert is_unbounded_shell_dump('cat "unterminated') is False

    assert extract_shell_read_targets(f"cd pkg && cat a.py a.py missing.py | grep {b_py}", cwd=str(tmp_path)) == [
        os.path.realpath(a_py)
    ]
    assert extract_shell_read_targets(f"sed -n '1,20p' {a_py} {b_py}") == [
        os.path.realpath(a_py),
        os.path.realpath(b_py),
    ]
    assert extract_shell_read_targets(f"awk '{{print $1}}' {a_py}") == [os.path.realpath(a_py)]
    assert extract_shell_read_targets(f"pytest {a_py}") == []
    assert extract_shell_read_targets('cat "unterminated') == []

    space_py = sub / "a b.py"
    space_py.write_text("s = 1\n", encoding="utf-8")
    assert is_unbounded_shell_dump(f'cat "{space_py}"') is True
    assert extract_shell_read_targets(f'cat "{space_py}"') == [os.path.realpath(space_py)]

    if os.name != "nt":
        pipe_py = sub / "a|b.py"
        pipe_py.write_text("p = 1\n", encoding="utf-8")
        assert is_unbounded_shell_dump(f'cat "{pipe_py}"') is True
        assert extract_shell_read_targets(f'cat "{pipe_py}"') == [os.path.realpath(pipe_py)]
    assert extract_shell_read_targets(f"awk -F'|' '{{print $1}}' {a_py}") == [os.path.realpath(a_py)]
    assert extract_shell_read_targets(f"sed -n '/a|b/p' {a_py}") == [os.path.realpath(a_py)]
    assert extract_shell_read_targets(f"cat {a_py} > {b_py}") == [os.path.realpath(a_py)]
    assert extract_shell_read_targets(f"cat {a_py} >>{b_py} 2> {b_py}") == [os.path.realpath(a_py)]
    assert extract_shell_read_targets("cat a\x00b.py") == []


def test_shell_output_empty_and_pipe_quotes_and_python_inline_write() -> None:
    assert classify_family("") == "other"
    assert classify_family("   ") == "other"
    assert classify_family("grep -E 'foo|bar' src/app.py") == "search"
    assert rewrite_quiet_cli_flags("python3 -c \"open('foo.py', 'w').write('x')\"") is None


def test_pytest_quiet_flags_rewrite(tmp_path: Path) -> None:
    assert (
        rewrite_quiet_cli_flags("venv/bin/pytest tests/unit")
        == "venv/bin/pytest tests/unit -q --tb=short --no-header"
    )
    assert (
        rewrite_quiet_cli_flags("python3 -m pytest tests/")
        == "python3 -m pytest tests/ -q --tb=short --no-header"
    )
    res = ptu.evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 6,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "venv/bin/pytest tests/unit"}},
        },
        state_dir=str(tmp_path / "state"),
    )
    assert res == {
        "decision": "allow",
        "overwrite": {"CommandLine": "venv/bin/pytest tests/unit -q --tb=short --no-header"},
    }


def test_pytest_with_existing_flags_not_rewritten() -> None:
    assert rewrite_quiet_cli_flags("venv/bin/pytest -v tests/unit") is None
    assert rewrite_quiet_cli_flags("cd analytics-engine && venv/bin/pytest tests/ && echo done") is None


def test_pytest_verbosity_flags_detected_after_tokenization() -> None:
    for cmd in (
        "venv/bin/pytest tests/unit --tb=long",
        "pytest --tb long tests/",
        "pytest -vv tests/",
        "python3 -m pytest -qq",
        "pytest -xvs tests/test_a.py",
        "pytest --verbosity=2 tests/",
    ):
        assert rewrite_quiet_cli_flags(cmd) is None, cmd
    assert (
        rewrite_quiet_cli_flags("pytest -x -k 'not slow' tests/")
        == "pytest -x -k 'not slow' tests/ -q --tb=short --no-header"
    )


def test_cd_prefix_and_npm_test_safety_in_rewrite_quiet_cli_flags() -> None:
    assert (
        rewrite_quiet_cli_flags("cd analytics-engine && venv/bin/pytest tests/")
        == "cd analytics-engine && venv/bin/pytest tests/ -q --tb=short --no-header"
    )
    assert (
        rewrite_quiet_cli_flags("cd /Users/dev/workspace/support-bot && git status")
        == "cd /Users/dev/workspace/support-bot && git status -sb"
    )
    assert rewrite_quiet_cli_flags('cd "/Users/dev/my repo" && npx jest test/flusher.test.js') is None
    assert (
        rewrite_quiet_cli_flags('cd "/Users/dev/my repo" && npx vitest run')
        == 'cd "/Users/dev/my repo" && npx vitest run --reporter=dot'
    )
    assert rewrite_quiet_cli_flags("cd /Users/dev/workspace/support-bot && npm test") is None
    assert rewrite_quiet_cli_flags("cd /Users/dev/workspace/support-bot && pnpm test") is None
    assert rewrite_quiet_cli_flags("cd /Users/dev/workspace/support-bot && npm test -- --watch") is None
    assert rewrite_quiet_cli_flags("cd repo && npx jest test/a.test.js && npm run lint") is None


def test_git_status_rewrite() -> None:
    assert rewrite_quiet_cli_flags("git status") == "git status -sb"
    assert rewrite_quiet_cli_flags("git status --porcelain") is None
    assert rewrite_quiet_cli_flags("git diff HEAD~1") is None


def test_rewrite_quiet_cli_flags_for_cargo_jest_and_vitest() -> None:
    assert rewrite_quiet_cli_flags("cargo test --lib") == "cargo test --lib -q"
    assert rewrite_quiet_cli_flags("cargo test -q") is None
    assert rewrite_quiet_cli_flags("cargo test -- --nocapture") is None
    assert rewrite_quiet_cli_flags("npx jest src/order.test.ts") is None
    assert rewrite_quiet_cli_flags("npx jest --silent") is None
    assert rewrite_quiet_cli_flags("npx vitest run") == "npx vitest run --reporter=dot"
    assert rewrite_quiet_cli_flags("npx vitest run --reporter=dot") is None


def test_twg_canonicalization_and_redirection_guard_in_rewrite_cli(tmp_path: Path, isolated_user_env: Path) -> None:
    _ = isolated_user_env
    assert (
        rewrite_quiet_cli_flags(
            'TWG_AGENT_DEFAULTS=1 ~/.local/bin/twg jira workitem search --jql "project = CORE"'
        )
        is None
    )
    assert (
        rewrite_quiet_cli_flags(
            'TWG_AGENT_DEFAULTS=1 ~/.local/bin/twg jira workitem search --jql "project = CORE"',
            enable_atlassian_twg=True,
        )
        == 'twg jira workitem search --jql "project = CORE"'
    )
    assert (
        rewrite_twg_cli_command(
            "/Users/dev/.local/bin/twg jira workitem get PROJ-2780 --output json"
        )
        == "twg jira workitem get PROJ-2780 --output json"
    )
    assert rewrite_quiet_cli_flags("~/.local/bin/twg jira --help", enable_atlassian_twg=True) == "twg jira --help"
    assert (
        rewrite_quiet_cli_flags(
            "cd /Users/dev/workspace && twg jira workitem get PROJ-2780 --output json",
            enable_atlassian_twg=True,
        )
        == "twg jira workitem get PROJ-2780 --output json"
    )
    assert rewrite_quiet_cli_flags("twg jira workitem get PROJ-2780 --output json", enable_atlassian_twg=True) is None
    assert ptu.evaluate_hook(
        {
            "conversationId": "c-twg-off",
            "stepIdx": 1,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "~/.local/bin/twg jira --help"}},
        },
        state_dir=str(tmp_path / "state"),
    ) == {"decision": "allow"}
    assert rewrite_quiet_cli_flags("venv/bin/pytest tests/unit > /tmp/pytest.log") is None
    assert rewrite_quiet_cli_flags("npx jest test/a.test.js > /tmp/jest.log") is None


def test_recursive_grep_injects_cache_exclude_dirs() -> None:
    rewritten = rewrite_quiet_cli_flags(
        'grep -rn -m 40 -E "transaction_type|delisted" /Users/dev/workspace/analytics-engine/src'
    )
    assert rewritten is not None
    assert rewritten.startswith("grep -I --exclude-dir=.git --exclude-dir=.mypy_cache ")
    assert "--exclude-dir=.pytest_cache" in rewritten
    assert "--exclude-dir=node_modules" in rewritten
    assert "--exclude-dir=venv" in rewritten
    assert rewritten.endswith(
        '-rn -m 40 -E "transaction_type|delisted" /Users/dev/workspace/analytics-engine/src'
    )

    rewritten_cd = rewrite_quiet_cli_flags('cd /tmp/repo && grep -r "foo" src/')
    assert rewritten_cd is not None
    assert rewritten_cd.startswith("cd /tmp/repo && grep -I --exclude-dir=.git ")

    assert rewrite_quiet_cli_flags('grep -n "foo" src/main.py') is None
    assert rewrite_quiet_cli_flags('grep -n "-rn" src/main.py') is None
    assert rewrite_quiet_cli_flags("grep -n '-r' src/main.py") is None
    assert rewrite_quiet_cli_flags('grep --exclude-dir=.git -rn "foo" src/') is None


def test_rewrite_quiet_cli_flags_for_wrapped_runners() -> None:
    assert (
        rewrite_quiet_cli_flags("python3 -m pytest tests/")
        == "python3 -m pytest tests/ -q --tb=short --no-header"
    )
    assert (
        rewrite_quiet_cli_flags(".venv/bin/pytest tests/unit")
        == ".venv/bin/pytest tests/unit -q --tb=short --no-header"
    )
    assert (
        rewrite_quiet_cli_flags("poetry run pytest")
        == "poetry run pytest -q --tb=short --no-header"
    )
    assert (
        rewrite_quiet_cli_flags("uv run pytest tests/")
        == "uv run pytest tests/ -q --tb=short --no-header"
    )
    assert rewrite_quiet_cli_flags("pnpm test") is None
    assert rewrite_quiet_cli_flags("yarn test") is None


def test_generative_shell_parser_fuzzer_invariants() -> None:
    """Seeded property fuzzer: never raises on malformed shell strings."""
    rng = random.Random(2026)
    verbs = ["cg-outline", "head -n 20", "pytest", "grep -rn foo", "git status"]
    paths = [
        "src/app.py",
        "src/[unclosed.py",
        '"path with spaces/mod.ts"',
        "'unterminated_quote/mod.py",
    ]
    connectors = [" && ", " ; ", " | ", " || ", "\n"]
    mutations = [" > /tmp/out.py", " >> /tmp/out.py", " | tee /tmp/out.py"]

    for _ in range(250):
        parts = [f"{rng.choice(verbs)} {rng.choice(paths)}" for _ in range(rng.randint(1, 3))]
        cmd = rng.choice(connectors).join(parts)
        if rng.random() < 0.4:
            cmd = f"{cmd}{rng.choice(mutations)}"
        pull = is_outline_pull(cmd)
        rewritten = rewrite_quiet_cli_flags(cmd)
        assert isinstance(pull, bool)
        assert rewritten is None or isinstance(rewritten, str)


def test_shell_parser_and_read_planner_hot_path_latency_budget(tmp_path: Path) -> None:
    """Hot-path rewrite_quiet_cli_flags + evaluate_hook median latency must stay below budget."""
    target = write_python_module(tmp_path / "hot.py", funcs=60)
    state_dir = str(tmp_path / "state")
    payload = {
        "conversationId": "perf-session",
        "stepIdx": 1,
        "toolCall": {"name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 40}},
    }
    ptu.evaluate_hook(payload, state_dir=state_dir)

    durations_ms: list[float] = []
    for step in range(2, 62):
        t0 = time.perf_counter()
        rewrite_quiet_cli_flags("pytest tests/")
        payload["stepIdx"] = step
        ptu.evaluate_hook(payload, state_dir=state_dir)
        durations_ms.append((time.perf_counter() - t0) * 1000.0)

    median_ms = statistics.median(durations_ms)
    if os.name == "nt":
        budget_ms = 25.0
    elif sys.platform == "darwin" and os.environ.get("CI"):
        budget_ms = 35.0
    else:
        budget_ms = 10.0
    assert median_ms < budget_ms, f"Hot-path median latency {median_ms:.2f} ms exceeded {budget_ms} ms budget"
    assert len(Path(shell_parser.__file__).read_text(encoding="utf-8").splitlines()) <= 800


def test_windows_backslash_paths_in_shell_commands(monkeypatch) -> None:
    win_mod = r"C:\Users\alice\AppData\Local\Temp\mod.py"
    win_root = r"C:\Users\alice\Temp"
    win_a = rf"{win_root}\a.py"
    win_pkg_a = rf"{win_root}\pkg\a.py"
    win_other = rf"{win_root}\other.py"
    win_pipe = rf"{win_root}\a|b.py"

    assert is_outline_pull(rf"cg-outline {win_mod}") is True
    assert is_outline_pull(rf"cg-outline.cmd {win_mod}") is True
    assert is_outline_pull(rf"C:\Python313\python.exe C:\Users\alice\hooks\outline.py {win_mod}") is True
    assert is_unbounded_shell_dump(rf"cat {win_mod}") is True
    assert is_unbounded_shell_dump(rf"CAT.EXE {win_mod}") is True
    assert is_bounded_shell_read(rf"sed -n '1,40p' {win_mod}") is True
    assert is_bounded_shell_read(rf"head.exe -n 20 {win_mod}") is True

    existing_win_paths = {win_a, win_pkg_a, win_other, win_pipe}
    fake_nt_os = SimpleNamespace(
        name="nt",
        path=SimpleNamespace(
            expanduser=ntpath.expanduser,
            isabs=ntpath.isabs,
            join=ntpath.join,
            realpath=ntpath.normpath,
            isfile=lambda p: p in existing_win_paths,
            basename=ntpath.basename,
        ),
    )
    monkeypatch.setattr(shell_parser, "os", fake_nt_os)

    assert extract_outline_pull_targets(rf"cg-outline.cmd {win_a}", cwd=win_root) == [win_a]
    assert extract_shell_read_targets(rf"cat {win_a}") == [win_a]
    assert extract_shell_read_targets(rf"CAT.EXE {win_a}") == [win_a]
    assert extract_shell_read_targets(f'cat "{win_pipe}"') == [win_pipe]
    assert extract_shell_read_targets(rf"cd {win_root} && cat pkg\a.py") == [win_pkg_a]
    assert extract_shell_read_targets(rf"cat {win_a} < {win_other}") == [win_a]
    assert extract_shell_read_targets(rf"cat <{win_other}") == []
    assert extract_shell_read_targets(rf"sed -e 's/i/x/' {win_a}") == [win_a]
    assert extract_shell_read_targets(rf"sed -i.bak 's/i/x/' {win_a}") == []
