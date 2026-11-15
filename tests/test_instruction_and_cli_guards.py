"""Tests for EOF canonicalization, instruction-file bypass, Antigravity mutations, Policy API v1 fail-closed gate, and CLI rewrites."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from hooks.config import clear_config_cache, load_runtime_config
from hooks.markup_outliners import outline_css, outline_shell, outline_toml
from hooks.outline import OUTLINE_EXTENSIONS, extract_outline_symbols
from hooks.pre_tool_use import evaluate_hook
from hooks.read_planner import (
    covering_read_step,
    normalize_effective_bounds,
    normalize_recorded_ranges,
    trim_partially_covered_range,
)
from hooks.shell_parser import rewrite_quiet_cli_flags
from hooks.telemetry import load_telemetry_stats
from tests.helpers import ag_read


def _load_ledger(state_dir: str | Path) -> dict[str, Any]:
    return json.loads((Path(state_dir) / ".context_guard_state.json").read_text(encoding="utf-8"))


def _set_bounded_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "cg_cfg.json"
    cfg.write_text(json.dumps({"read_confirm_policy": "bounded"}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg))
    clear_config_cache()


def test_instruction_files_and_large_markdown_allowed_cleanly_and_partial_trims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_bounded_policy(tmp_path, monkeypatch)
    try:
        skill = tmp_path / "skills" / "demo" / "SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text(
            "".join(f"## Section {i}\nBody {i}\n" for i in range(142)) + "End\n",
            encoding="utf-8",
        )  # 285 LOC
        sd = str(tmp_path / "state")
        canon = os.path.realpath(str(skill))

        # Full read (1..-1) allowed cleanly and recorded as [1, 285, 1, 1] after PostToolUse
        r1 = ag_read(skill, sd, step_idx=1, conv_id="c1", confirm=True)
        assert r1 == {"decision": "allow"}
        ledger = _load_ledger(sd)
        assert ledger["files"][canon]["reads"] == [[1, 285, 1, 1]]
        stats = load_telemetry_stats(Path(sd) / "telemetry_stats.json")
        assert stats["events"]["allowed_reads"] == 1

        # Partial read 1..50 followed by full read 1..-1 trims silently to 51..285
        agents_md = tmp_path / "AGENTS.md"
        agents_md.write_text(
            "".join(f"## Rule {i}\nText {i}\n" for i in range(142)) + "Tail\n",
            encoding="utf-8",
        )  # 285 LOC
        assert ag_read(agents_md, sd, start_line=1, end_line=50, step_idx=1, conv_id="c2", confirm=True) == {"decision": "allow"}
        r_trim = ag_read(agents_md, sd, step_idx=2, conv_id="c2", confirm=True)
        assert r_trim == {"decision": "allow", "overwrite": {"StartLine": 51, "EndLine": 285}}
        canon_agents = os.path.realpath(str(agents_md))
        assert _load_ledger(sd)["files"][canon_agents]["reads"] == [[1, 285, 2, 1]]

        # 401-LOC CLAUDE.md also allowed directly in v4 without blocking
        claude_big = tmp_path / "CLAUDE.md"
        claude_big.write_text(
            "".join(f"## Heading {i}\nBody {i}\n" for i in range(200)) + "Extra\n",
            encoding="utf-8",
        )  # 401 LOC
        r_big = ag_read(claude_big, tmp_path / "state_big", step_idx=1, conv_id="c3", confirm=True)
        assert r_big == {"decision": "allow"}
    finally:
        clear_config_cache()


def test_legacy_minus_one_interval_normalized_before_merge_intervals() -> None:
    assert normalize_recorded_ranges([[1, 100, 1, 2], [101, -1, 2, 2]], 285) == [
        [1, 100, 1, 2],
        [101, 285, 2, 2],
    ]
    assert covering_read_step([[1, 100, 1, 2], [101, -1, 2, 2]], 1, 285, target_lines=285) == 2
    assert covering_read_step([[1, 285, 1, 2]], 1, -1, target_lines=285) == 1
    assert trim_partially_covered_range([[1, 50, 1, 2]], 1, -1, target_lines=285) == (51, 285)
    assert normalize_effective_bounds(0, 10, 285) is None
    assert normalize_effective_bounds(1, -5, 285) is None
    assert normalize_effective_bounds(300, 350, 285) is None
    assert covering_read_step([[1, 285, 1, 2]], 0, 10, target_lines=285) is None
    assert covering_read_step([[1, 285, 1, 2]], 1, -5, target_lines=285) is None


def test_antigravity_mutation_tools_and_claude_bash_no_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_bounded_policy(tmp_path, monkeypatch)
    try:
        f = tmp_path / "mod.py"
        f.write_text("x = 1\ny = 2\n", encoding="utf-8")
        canon = os.path.realpath(str(f))
        sd = str(tmp_path / "state")
        assert ag_read(f, sd, start_line=1, end_line=1, step_idx=1, conv_id="ag1", confirm=True) == {"decision": "allow"}
        # Partial overlap before mutation trims silently to line 2
        assert ag_read(f, sd, step_idx=2, conv_id="ag1", confirm=True) == {
            "decision": "allow",
            "overwrite": {"StartLine": 2, "EndLine": 2},
        }
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
            assert ag_read(f, sd, step_idx=idx * 2 + 1, conv_id="ag1", confirm=True) == {"decision": "allow"}

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
    finally:
        clear_config_cache()


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


def test_policy_api_v1_gate_and_legacy_config_tolerance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 1. Legacy optimizer keys in config.json keep config_error=None
    cfg_path = tmp_path / "legacy_opt.json"
    cfg_path.write_text(json.dumps({"instruction_file_bypass_lines": "bad", "enforcement": {"outline": "block"}}), encoding="utf-8")
    cfg = load_runtime_config(cfg_path)
    assert cfg["config_error"] is None

    # 2. Malformed JSON sets config_error -> scoped tool call fails CLOSED (deny)
    broken_cfg = tmp_path / "broken.json"
    broken_cfg.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(broken_cfg))
    clear_config_cache()
    sd = str(tmp_path / "state")
    mcp_payload = {
        "conversationId": "pol1",
        "stepIdx": 1,
        "toolCall": {
            "name": "call_mcp_tool",
            "args": {"ServerName": "example-mcp", "ToolName": "get_item", "Arguments": {"id": "x"}},
        },
    }
    res_closed = evaluate_hook(mcp_payload, state_dir=sd)
    assert res_closed["decision"] == "deny"
    assert "CONFIG ERROR (fail-closed)" in res_closed["reason"]

    # 3. Valid config + optimization pack exception fails OPEN with stderr warning; security pack exception fails CLOSED
    pack_dir = tmp_path / "policies" / "crashing-opt"
    pack_dir.mkdir(parents=True)
    pack_src = (
        "from __future__ import annotations\n"
        "from policies.api import POLICY_API_VERSION, PolicyPackManifest\n"
        "def _boom(ctx):\n"
        "    raise RuntimeError('simulated opt crash')\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        "    pack_id='crashing-opt', api_version=POLICY_API_VERSION,\n"
        "    kind='optimization', covered_domains=('synthetic-opt',), evaluate=_boom,\n"
        ")\n"
    ).encode("utf-8")
    pack_file = pack_dir / "pack.py"
    pack_file.write_bytes(pack_src)
    file_sha = hashlib.sha256(pack_src).hexdigest()
    tree_sha = hashlib.sha256(f"pack.py:{file_sha}\n".encode("utf-8")).hexdigest()
    valid_cfg = tmp_path / "valid.json"
    valid_cfg.write_text(
        json.dumps({
            "policy_packs": [{
                "id": "crashing-opt",
                "path": str(pack_file),
                "enabled": True,
                "kind": "optimization",
                "file_hashes": {"pack.py": file_sha},
                "tree_sha256": tree_sha,
            }]
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(valid_cfg))
    clear_config_cache()
    res_open = evaluate_hook(mcp_payload, state_dir=sd)
    assert res_open == {"decision": "allow"}
    assert "crashing-opt" in capsys.readouterr().err


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

