"""Tests for EOF canonicalization, instruction-file bypass, Antigravity mutations, Phase B GitLab gate, and CLI rewrites."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from hooks.local_repo_guard import load_guard_config
from hooks.markup_outliners import outline_css, outline_shell, outline_toml
from hooks.outline import OUTLINE_EXTENSIONS, extract_outline_symbols
from hooks.pre_tool_use import evaluate_hook, handle_gitlab_mandatory_gate
from hooks.read_planner import (
    covering_read_step,
    normalize_effective_bounds,
    normalize_recorded_ranges,
    trim_partially_covered_range,
)
from hooks.shell_parser import rewrite_quiet_cli_flags
from hooks.telemetry import load_telemetry_stats


def _load_ledger(state_dir: str | Path) -> dict[str, Any]:
    return json.loads((Path(state_dir) / ".context_guard_state.json").read_text(encoding="utf-8"))


def test_instruction_files_and_large_markdown_allowed_cleanly_and_partial_trims(
    tmp_path: Path,
) -> None:
    skill = tmp_path / "skills" / "demo" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(
        "".join(f"## Section {i}\nBody {i}\n" for i in range(142)) + "End\n",
        encoding="utf-8",
    )  # 285 LOC
    sd = str(tmp_path / "state")
    canon = os.path.realpath(str(skill))

    # Full read (1..-1) allowed cleanly and recorded as [1, 285, 1]
    r1 = evaluate_hook(
        {"conversationId": "c1", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(skill)}}},
        state_dir=sd,
    )
    assert r1 == {"decision": "allow"}
    ledger = _load_ledger(sd)
    assert ledger["files"][canon]["reads"] == [[1, 285, 1]]
    stats = load_telemetry_stats(Path(sd) / "telemetry_stats.json")
    assert stats["events"]["allowed_reads"] == 1

    # Partial read 1..50 followed by full read 1..-1 trims silently to 51..285
    agents_md = tmp_path / "AGENTS.md"
    agents_md.write_text(
        "".join(f"## Rule {i}\nText {i}\n" for i in range(142)) + "Tail\n",
        encoding="utf-8",
    )  # 285 LOC
    assert evaluate_hook(
        {
            "conversationId": "c2",
            "stepIdx": 1,
            "toolCall": {"name": "read_file", "args": {"Path": str(agents_md), "StartLine": 1, "EndLine": 50}},
        },
        state_dir=sd,
    ) == {"decision": "allow"}
    r_trim = evaluate_hook(
        {"conversationId": "c2", "stepIdx": 2, "toolCall": {"name": "read_file", "args": {"Path": str(agents_md)}}},
        state_dir=sd,
    )
    assert r_trim == {"decision": "allow", "overwrite": {"StartLine": 51, "EndLine": 285}}
    canon_agents = os.path.realpath(str(agents_md))
    assert _load_ledger(sd)["files"][canon_agents]["reads"] == [[1, 50, 1], [51, 285, 2]]

    # 401-LOC CLAUDE.md also allowed directly in v4 without blocking
    claude_big = tmp_path / "CLAUDE.md"
    claude_big.write_text(
        "".join(f"## Heading {i}\nBody {i}\n" for i in range(200)) + "Extra\n",
        encoding="utf-8",
    )  # 401 LOC
    r_big = evaluate_hook(
        {"conversationId": "c3", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(claude_big)}}},
        state_dir=str(tmp_path / "state_big"),
    )
    assert r_big == {"decision": "allow"}


def test_legacy_minus_one_interval_normalized_before_merge_intervals() -> None:
    assert normalize_recorded_ranges([[1, 100, 1], [101, -1, 2]], 285) == [
        [1, 100, 1],
        [101, 285, 2],
    ]
    assert covering_read_step([[1, 100, 1], [101, -1, 2]], 1, 285, target_lines=285) == 2
    assert covering_read_step([[1, 285, 1]], 1, -1, target_lines=285) == 1
    assert trim_partially_covered_range([[1, 50, 1]], 1, -1, target_lines=285) == (51, 285)
    assert normalize_effective_bounds(0, 10, 285) is None
    assert normalize_effective_bounds(1, -5, 285) is None
    assert normalize_effective_bounds(300, 350, 285) is None
    assert covering_read_step([[1, 285, 1]], 0, 10, target_lines=285) is None
    assert covering_read_step([[1, 285, 1]], 1, -5, target_lines=285) is None


def test_antigravity_mutation_tools_and_claude_bash_no_rewrite(tmp_path: Path) -> None:
    f = tmp_path / "mod.py"
    f.write_text("x = 1\ny = 2\n", encoding="utf-8")
    canon = os.path.realpath(str(f))
    sd = str(tmp_path / "state")
    assert (
        evaluate_hook(
            {"conversationId": "ag1", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(f), "StartLine": 1, "EndLine": 1}}},
            state_dir=sd,
        )
        == {"decision": "allow"}
    )
    # Partial overlap before mutation trims silently to line 2
    assert (
        evaluate_hook(
            {"conversationId": "ag1", "stepIdx": 2, "toolCall": {"name": "read_file", "args": {"Path": str(f)}}},
            state_dir=sd,
        )
        == {"decision": "allow", "overwrite": {"StartLine": 2, "EndLine": 2}}
    )
    for idx, mut_tool in enumerate(
        ("replace_file_content", "multi_replace_file_content", "write_to_file"), start=3
    ):
        assert (
            evaluate_hook(
                {
                    "conversationId": "ag1",
                    "stepIdx": idx * 2,
                    "toolCall": {"name": mut_tool, "args": {"TargetFile": str(f)}},
                },
                state_dir=sd,
            )
            == {"decision": "allow"}
        )
        assert canon not in _load_ledger(sd).get("files", {})
        assert (
            evaluate_hook(
                {
                    "conversationId": "ag1",
                    "stepIdx": idx * 2 + 1,
                    "toolCall": {"name": "read_file", "args": {"Path": str(f)}},
                },
                state_dir=sd,
            )
            == {"decision": "allow"}
        )

    # Claude Bash is not rewritten (preserves native permissions/headless), Antigravity run_command IS rewritten
    assert (
        evaluate_hook(
            {"session_id": "cl1", "tool_name": "Bash", "tool_input": {"command": "pytest tests/"}},
            state_dir=sd,
            cli_harness="claude",
        )
        == {}
    )
    ag_cmd = evaluate_hook(
        {
            "conversationId": "ag1",
            "stepIdx": 20,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest tests/"}},
        },
        state_dir=sd,
    )
    assert ag_cmd["overwrite"]["CommandLine"] == "pytest tests/ -q --tb=short --no-header"


def test_cli_grep_single_quoted_exclusions_and_double_dash_runner_guard() -> None:
    rewritten = rewrite_quiet_cli_flags("grep -rn pattern src/")
    assert rewritten is not None
    assert "'--exclude=*.min.js'" in rewritten
    assert "'--exclude=*.min.css'" in rewritten
    assert "'--exclude=*.map'" in rewritten
    assert "'--exclude=package-lock.json'" in rewritten
    assert rewrite_quiet_cli_flags(rewritten) is None

    # Explicit --include, --exclude, or lockfile target skips file exclusions
    inc_rewritten = rewrite_quiet_cli_flags("grep -rn --include='*.min.js' pat src/")
    assert inc_rewritten is not None and "'--exclude=*.min.js'" not in inc_rewritten
    lock_rewritten = rewrite_quiet_cli_flags("grep -rn lodash package-lock.json")
    assert lock_rewritten is not None and "'--exclude=package-lock.json'" not in lock_rewritten

    # "--" separator prevents appending runner flags
    assert rewrite_quiet_cli_flags("pytest tests/ -- --custom-arg") is None
    assert rewrite_quiet_cli_flags("npx jest -- --watch") is None
    assert rewrite_quiet_cli_flags("npx vitest run -- --reporter=dot") is None
    assert rewrite_quiet_cli_flags("pnpm test -- --bail") is None


def test_phase_b_gitlab_gate_and_legacy_config_tolerance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 1. Legacy optimizer keys in config.json keep config_error=None
    cfg_path = tmp_path / "legacy_opt.json"
    cfg_path.write_text(json.dumps({"instruction_file_bypass_lines": "bad", "enforcement": {"outline": "block"}}), encoding="utf-8")
    cfg = load_guard_config(cfg_path)
    assert cfg["config_error"] is None

    # 2. Malformed JSON sets config_error -> Phase B GitLab fails CLOSED (deny)
    broken_cfg = tmp_path / "broken.json"
    broken_cfg.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(broken_cfg))
    sd = str(tmp_path / "state")
    gl_payload = {
        "conversationId": "gl1",
        "stepIdx": 1,
        "toolCall": {
            "name": "call_mcp_tool",
            "args": {"ServerName": "gitlab", "ToolName": "get_project", "Arguments": {"project_id": "x"}},
        },
    }
    res_closed = evaluate_hook(gl_payload, state_dir=sd)
    assert res_closed["decision"] == "deny"
    assert "GITLAB CONFIG ERROR (fail-closed)" in res_closed["reason"]

    # 3. Valid config (config_error=None) + unexpected runtime exception in Phase B fails OPEN with stderr warning
    valid_cfg = tmp_path / "valid.json"
    valid_cfg.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(valid_cfg))
    from hooks import pre_tool_use as ptu

    def _boom(*_a: Any, **_kw: Any) -> dict[str, Any]:
        raise RuntimeError("simulated disk error")

    monkeypatch.setattr(ptu, "gate_gitlab_local_first", _boom)
    res_open = evaluate_hook(gl_payload, state_dir=sd)
    assert res_open == {"decision": "allow"}
    assert "simulated disk error" in capsys.readouterr().err
    assert callable(handle_gitlab_mandatory_gate)


def test_python_markdown_and_new_format_outliners() -> None:
    for ext in (".html", ".htm", ".css", ".scss", ".toml", ".sh", ".bash", ".zsh"):
        assert ext in OUTLINE_EXTENSIONS

    py_src = (
        "def long_fn("
        + ", ".join(f"param_{i}: dict[str, list[int]]" for i in range(6))
        + ") -> bool:\n"
        + '    """Check whether long parameters truncate inside parens.\n    More details.\n    """\n'
        + "    return True\n"
    )
    py_out = extract_outline_symbols(py_src, ".py")
    assert any(
        "...) -> bool: L1-L5  # Check whether long parameters truncate inside parens." in line
        for line in py_out
    )

    # >80 symbols omits docstring summaries to bound outline size
    many_py = "".join(f'def fn_{i}() -> int:\n    """Doc {i}."""\n    return {i}\n' for i in range(85))
    many_out = extract_outline_symbols(many_py, ".py")
    assert len(many_out) == 85
    assert all("# Doc" not in line for line in many_out)

    md_src = (
        "# Title\n\n"
        "| A | B |\n"
        "| :--- | ---: |\n"
        "| 1 | 2 |\n\n"
        "```python\n"
        "# not a heading\n"
        "```\n\n"
        "## Child\n"
        "Just text\n"
    )
    md_out = extract_outline_symbols(md_src, ".md")
    assert md_out[0] == "# Title [table, 1 code block]: L1-L12"
    assert md_out[1] == "## Child: L11-L12"

    html_src = '<header id="top">\n  <nav id="main-nav"></nav>\n</header>\n<main id="app">\n</main>\n'
    html_out = extract_outline_symbols(html_src, ".html")
    assert "<header#top>: L1-L3" in html_out
    assert "<main#app>: L4-L5" in html_out

    css_src = "@media (min-width: 768px) {\n  .card {\n    color: red;\n  }\n}\n"
    css_out = outline_css(css_src)
    assert "@media (min-width: 768px): L1-L5" in css_out

    toml_src = '[project]\nname = "cg"\ndesc = """\n[not_a_table]\n"""\n\n[[ADAPTERS]]\nid = 1\n'
    assert outline_toml(toml_src) == ["[project]: L1-L5", "[[ADAPTERS]]: L7-L8"]
    assert extract_outline_symbols(toml_src, ".toml") == ["[project]: L1-L5", "[[ADAPTERS]]: L7-L8"]

    sh_src = (
        "#!/usr/bin/env bash\n"
        "cat << 'EOF'\n"
        "fake_fn() {\n"
        "  echo no\n"
        "}\n"
        "EOF\n"
        "real_fn() {\n"
        "  echo yes\n"
        "}\n"
    )
    assert outline_shell(sh_src) == ["function real_fn(): L7-L9"]
    assert extract_outline_symbols(sh_src, ".sh") == ["function real_fn(): L7-L9"]

