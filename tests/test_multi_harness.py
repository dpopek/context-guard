"""Unit and integration tests for Context-Guard Multi-Harness support."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from hooks import config as guard_config
from hooks.harness_adapter import (
    NormalizedToolCall,
    detect_harness,
    extract_apply_patch_paths,
    format_pre_tool_output,
    normalize_pre_tool_payload,
)


def test_detect_harness_variants() -> None:
    assert detect_harness({"toolCall": {"name": "read_file", "args": {}}}) == "antigravity"
    assert detect_harness({"tool_name": "Read", "tool_input": {}}, cli_harness="claude") == "claude"
    assert detect_harness({"tool_name": "Read", "tool_input": {}}, env={"CURSOR_TRACE_ID": "1"}) == "cursor"
    assert (
        detect_harness(
            {
                "tool_name": "Bash",
                "tool_input": {},
                "transcript_path": "/Users/u/.codex/sessions/a.jsonl",
            }
        )
        == "codex"
    )


def test_detect_harness_prefers_payload_signals_and_ignores_env_order() -> None:
    claude_env = {"CLAUDE_CODE_ENTRYPOINT": "cli", "CLAUDECODE": "1"}
    codex_transcript = {
        "tool_name": "Bash",
        "tool_input": {},
        "transcript_path": "/Users/u/.codex/sessions/a.jsonl",
    }
    # A harness launched from a Claude Code shell inherits CLAUDE_*; the payload names the caller.
    assert detect_harness(codex_transcript, env=claude_env) == "codex"
    assert detect_harness({"tool_name": "Read", "cursor_version": "2.0"}, env=claude_env) == "cursor"

    # Codex run inside a Claude Code shell: both prefixes present, either order.
    both = [("CLAUDE_CODE_ENTRYPOINT", "cli"), ("CODEX_SANDBOX", "seatbelt")]
    assert detect_harness({"tool_name": "Bash"}, env=dict(both)) == "codex"
    assert detect_harness({"tool_name": "Bash"}, env=dict(reversed(both))) == "codex"

    # CURSOR_* comes from every Cursor integrated terminal, so a CLI agent there keeps its own name.
    ide = [("CURSOR_TRACE_ID", "1"), ("CLAUDE_CODE_ENTRYPOINT", "cli")]
    assert detect_harness({"tool_name": "Read"}, env=dict(ide)) == "claude"
    assert detect_harness({"tool_name": "Read"}, env=dict(reversed(ide))) == "claude"

def test_normalize_and_format_claude_read_offset_limit() -> None:
    payload = {
        "session_id": "sess-1",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/app.py", "offset": 10, "limit": 20},
    }
    norm = normalize_pre_tool_payload(payload, cli_harness="claude")
    assert norm.canonical_tool == "read_file"
    assert norm.canonical_args == {"Path": "/tmp/app.py", "StartLine": 10, "EndLine": 29}

    # Unmodified allow must return empty dict {} so native permissions are untouched
    assert format_pre_tool_output({"decision": "allow"}, norm) == {}

    # Trimmed range overwrite converts back to offset/limit
    trimmed_out = format_pre_tool_output(
        {"decision": "allow", "overwrite": {"StartLine": 15, "EndLine": 29}}, norm
    )
    assert trimmed_out == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": {"file_path": "/tmp/app.py", "offset": 15, "limit": 15},
        }
    }


def test_extract_apply_patch_paths(tmp_path: Path) -> None:
    patch_text = "*** Begin Patch\n*** Update File: src/a.py\n@@\n*** Add File: src/b.py\n*** End Patch"
    paths = extract_apply_patch_paths({"patch": patch_text}, cwd=str(tmp_path))
    assert paths == [str(tmp_path / "src/a.py"), str(tmp_path / "src/b.py")]


from hooks.pre_compact import handle_pre_compact
from hooks.pre_tool_use import evaluate_hook


def _configure_synthetic_mcp_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_config.clear_config_cache()
    pack_dir = tmp_path / "policies" / "acme_mcp"
    pack_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(pack_dir.parent, 0o700)
    os.chmod(pack_dir, 0o700)
    pack_src = (
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n\n"
        "def evaluate(ctx):\n"
        "    if ctx.canonical_tool == 'call_mcp_tool' or ctx.original_tool_name.lower().startswith(('mcp_', 'mcp:')):\n"
        "        sql = str(ctx.canonical_args.get('query') or ctx.canonical_args.get('Arguments', {}).get('query') or '')\n"
        "        if 'raw_warehouse' in sql or not sql:\n"
        "            return PolicyDecision(decision='deny', reason='Blocked by acme-mcp-sec: use safe views')\n"
        "    return None\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        "    pack_id='acme-mcp-sec', api_version=POLICY_API_VERSION,\n"
        "    kind='security', covered_domains=('synthetic-mcp',), evaluate=evaluate,\n"
        ")\n"
    ).encode("utf-8")
    pack_file = pack_dir / "pack.py"
    pack_file.write_bytes(pack_src)
    os.chmod(pack_file, 0o600)
    fsha = hashlib.sha256(pack_src).hexdigest()
    tsha = hashlib.sha256(f"pack.py:{fsha}\n".encode("utf-8")).hexdigest()
    entry = {
        "id": "acme-mcp-sec",
        "path": str(pack_file),
        "enabled": True,
        "kind": "security",
        "scopes": ["mcp_call"],
        "fallback_matchers": {"mcp_tool_regex": r"^mcp__?acme_db(?:__|$)"},
        "file_hashes": {"pack.py": fsha},
        "tree_sha256": tsha,
        "settings": {},
    }
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"policy_packs": [entry]}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg))
    guard_config.clear_config_cache()


def test_double_underscore_and_colon_mcp_routing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    norm_u = normalize_pre_tool_payload(
        {"tool_name": "mcp__acme_db__execute_sql_readonly", "tool_input": {"query": "SELECT 1"}},
        cli_harness="claude",
    )
    assert norm_u.original_tool_name == "mcp__acme_db__execute_sql_readonly"
    norm_c = normalize_pre_tool_payload(
        {"tool_name": "MCP:acme_db:execute_sql_readonly", "tool_input": {"query": "SELECT 1"}},
        cli_harness="cursor",
    )
    assert norm_c.original_tool_name == "MCP:acme_db:execute_sql_readonly"

    _configure_synthetic_mcp_pack(tmp_path, monkeypatch)
    state_dir = str(tmp_path / "mcp_state")
    for tname in ("mcp__acme_db__execute_sql_readonly", "MCP:acme_db:execute_sql_readonly"):
        res = evaluate_hook(
            {"session_id": "s-mcp", "tool_name": tname, "tool_input": {"query": "SELECT * FROM raw_warehouse.orders"}},
            state_dir=state_dir,
            cli_harness="claude",
        )
        assert res["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_read_allows_normal_file_trims_overlap_and_outlines_mcp_output(tmp_path: Path) -> None:
    big_py = tmp_path / "service.py"
    lines = [f"def fn_{i}():\n    return {i}\n" for i in range(90)]
    big_py.write_text("".join(lines), encoding="utf-8")
    state_dir = str(tmp_path / "state")

    from tests.helpers import claude_read

    # 1. Targeted Read offset=1, limit=30 -> allow ({}) & confirmed via PostToolBatch
    res1 = claude_read(big_py, state_dir, offset=1, limit=30, session_id="s1", confirm=True)
    assert res1 == {}

    # 2. Overlapping Read offset=20, limit=30 (lines 20..49) -> silent range_trim to offset=31, limit=19
    res2 = claude_read(big_py, state_dir, offset=20, limit=30, session_id="s1", confirm=False)
    assert res2["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert res2["hookSpecificOutput"]["updatedInput"] == {
        "file_path": str(big_py),
        "offset": 31,
        "limit": 19,
    }

    # 3. MCP step output >= 16 KB triggers AUTO-OUTLINE deny in hookSpecificOutput, retry allows
    mcp_dir = tmp_path / ".system_generated" / "steps" / "1"
    mcp_dir.mkdir(parents=True)
    mcp_out = mcp_dir / "output.txt"
    mcp_out.write_text(
        json.dumps({"file_name": "big.py", "content": "".join(lines)}),
        encoding="utf-8",
    )
    # Write > 16 KB
    mcp_out.write_text(
        json.dumps({"file_name": "big.py", "content": "\n".join(f"v_{i} = {i}" for i in range(1500))}),
        encoding="utf-8",
    )
    res_mcp1 = evaluate_hook(
        {"session_id": "s1", "tool_name": "Read", "tool_input": {"file_path": str(mcp_out)}},
        state_dir=state_dir,
        cli_harness="claude",
    )
    assert res_mcp1["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "CONTEXT-GUARD AUTO-OUTLINE" in res_mcp1["hookSpecificOutput"]["permissionDecisionReason"]
    res_mcp2 = evaluate_hook(
        {"session_id": "s1", "tool_name": "Read", "tool_input": {"file_path": str(mcp_out)}},
        state_dir=state_dir,
        cli_harness="claude",
    )
    assert res_mcp2 == {}


def test_claude_edit_invalidates_read_cache(tmp_path: Path) -> None:
    f = tmp_path / "app.py"
    f.write_text("\n".join(f"x_{i} = {i}" for i in range(60)) + "\n", encoding="utf-8")
    state_dir = str(tmp_path / "edit_state")

    assert (
        evaluate_hook(
            {"session_id": "s2", "tool_name": "Read", "tool_input": {"file_path": str(f), "offset": 1, "limit": 30}},
            state_dir=state_dir,
            cli_harness="claude",
        )
        == {}
    )
    assert (
        evaluate_hook(
            {"session_id": "s2", "tool_name": "Edit", "tool_input": {"file_path": str(f)}},
            state_dir=state_dir,
            cli_harness="claude",
        )
        == {}
    )
    # Because Edit invalidated cache, overlapping read [20, 49] is NOT trimmed
    assert (
        evaluate_hook(
            {"session_id": "s2", "tool_name": "Read", "tool_input": {"file_path": str(f), "offset": 20, "limit": 30}},
            state_dir=state_dir,
            cli_harness="claude",
        )
        == {}
    )


def test_pre_compact_clears_session_file_cache(tmp_path: Path) -> None:
    from tests.helpers import claude_read

    f = tmp_path / "small.py"
    f.write_text("\n".join(f"a_{i} = {i}" for i in range(60)) + "\n", encoding="utf-8")
    state_dir = str(tmp_path / "compact_state")

    claude_read(f, state_dir, offset=1, limit=30, session_id="c1", confirm=True)
    overlapping = claude_read(f, state_dir, offset=20, limit=30, session_id="c1", confirm=False)
    assert overlapping["hookSpecificOutput"]["updatedInput"]["offset"] == 31

    # Trigger PreCompact -> clears cache
    assert handle_pre_compact({"session_id": "c1"}, state_dir=state_dir) == {}

    # After compact: overlapping read [20, 49] is no longer trimmed
    allowed = claude_read(f, state_dir, offset=20, limit=30, session_id="c1", confirm=False)
    assert allowed == {}


from bin.install_harnesses import (
    CODEX_POST_MATCHER,
    CURSOR_POST_MATCHER,
    compute_codex_trusted_hash,
    install_all,
    uninstall_all,
)


def test_codex_trusted_hash_matches_upstream_formula() -> None:
    cmd1 = '[ -n "$SUPERSET_HOME_DIR" ] && [ -x "$SUPERSET_HOME_DIR/hooks/notify.sh" ] && SUPERSET_HOOK_HARNESS=codex "$SUPERSET_HOME_DIR/hooks/notify.sh" || true'
    assert (
        compute_codex_trusted_hash("pre_tool_use", "^request_user_input$", cmd1)
        == "sha256:89353540103d18934f6410dcd87e6005696acbe38f5342ea043a8a1e5dcb2483"
    )
    assert (
        compute_codex_trusted_hash("user_prompt_submit", None, cmd1)
        == "sha256:ff4c98b3095aaba47057475efe3594fd7b03851788941df8ff5f3e2e2c321c19"
    )


def test_installer_idempotency_and_uninstall(tmp_path: Path) -> None:
    claude_cfg = tmp_path / "settings.json"
    cursor_cfg = tmp_path / "cursor_hooks.json"
    codex_cfg = tmp_path / "codex_hooks.json"
    codex_toml = tmp_path / "config.toml"

    claude_cfg.write_text(
        '{"model": "opus", "hooks": {"PreToolUse": [{"matcher": "Artifact", "hooks": [{"type": "command", "command": "superset.sh"}]}]}}',
        encoding="utf-8",
    )
    cursor_cfg.write_text(
        '{"version": 1, "hooks": {"sessionStart": [{"command": "superset"}]}}',
        encoding="utf-8",
    )
    codex_cfg.write_text(
        '{"hooks": {"PreToolUse": [{"matcher": "^request_user_input$", "hooks": [{"type": "command", "command": "superset"}]}]}}',
        encoding="utf-8",
    )
    codex_toml.write_text('model = "gpt-6.1-sol"\n', encoding="utf-8")

    plugin_root = Path(__file__).resolve().parent.parent
    install_all(plugin_root, claude_cfg, cursor_cfg, codex_cfg, codex_toml)
    first_claude = claude_cfg.read_text(encoding="utf-8")
    first_cursor = cursor_cfg.read_text(encoding="utf-8")
    first_toml = codex_toml.read_text(encoding="utf-8")

    # Second run must be 100% idempotent
    install_all(plugin_root, claude_cfg, cursor_cfg, codex_cfg, codex_toml)
    assert claude_cfg.read_text(encoding="utf-8") == first_claude
    assert cursor_cfg.read_text(encoding="utf-8") == first_cursor
    assert codex_toml.read_text(encoding="utf-8") == first_toml
    assert 'trusted_hash = "sha256:' in first_toml
    assert "preCompact" in first_cursor

    # Uninstall removes only context-guard entries and preserves Superset hooks
    uninstall_all(claude_cfg, cursor_cfg, codex_cfg, codex_toml)
    assert "context-guard" not in claude_cfg.read_text(encoding="utf-8")
    assert "superset.sh" in claude_cfg.read_text(encoding="utf-8")
    assert "context-guard" not in cursor_cfg.read_text(encoding="utf-8")
    assert "context-guard" not in codex_cfg.read_text(encoding="utf-8")


def test_installer_registers_shell_output_hooks(tmp_path: Path) -> None:
    from bin.install_harnesses import format_hook_script_path, resolve_python_command

    claude_cfg = tmp_path / "claude.json"
    cursor_cfg = tmp_path / "cursor_hooks.json"
    codex_cfg = tmp_path / "codex_hooks.json"
    codex_toml = tmp_path / "config.toml"
    for cfg in (claude_cfg, cursor_cfg, codex_cfg):
        cfg.write_text("{}", encoding="utf-8")
    codex_toml.write_text('model = "gpt-6.1-sol"\n', encoding="utf-8")
    plugin_root = Path(__file__).resolve().parent.parent
    py_cmd = resolve_python_command()
    post_script = format_hook_script_path(plugin_root / "hooks" / "post_tool_use.py")
    session_end_script = format_hook_script_path(plugin_root / "hooks" / "session_end.py")

    install_all(plugin_root, claude_cfg, cursor_cfg, codex_cfg, codex_toml, dry_run=True)
    assert claude_cfg.read_text(encoding="utf-8") == "{}"

    install_all(plugin_root, claude_cfg, cursor_cfg, codex_cfg, codex_toml)

    claude = json.loads(claude_cfg.read_text(encoding="utf-8"))
    for event in ("PostToolUse", "PostToolUseFailure"):
        assert claude["hooks"][event] == [
            {
                "matcher": "Read|NotebookRead|Edit|MultiEdit|Write|NotebookEdit",
                "hooks": [{"type": "command", "command": f"{py_cmd} {post_script} --harness claude"}],
            },
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": f"{py_cmd} {post_script} --harness claude", "async": True}],
            },
        ]
    assert claude["hooks"]["PostToolBatch"] == [
        {"hooks": [{"type": "command", "command": f"{py_cmd} {post_script} --harness claude --event PostToolBatch"}]}
    ]
    assert claude["hooks"]["SessionEnd"] == [
        {"hooks": [{"type": "command", "command": f"{py_cmd} {session_end_script} --harness claude"}]}
    ]

    codex = json.loads(codex_cfg.read_text(encoding="utf-8"))
    codex_cmd = f"{py_cmd} {post_script} --harness codex"
    assert codex["hooks"]["PostToolUse"] == [
        {
            "matcher": CODEX_POST_MATCHER,
            "hooks": [{"type": "command", "command": codex_cmd, "timeout": 5}],
        }
    ]
    expected_hash = compute_codex_trusted_hash("post_tool_use", CODEX_POST_MATCHER, codex_cmd, timeout=5)
    assert f'trusted_hash = "{expected_hash}"' in codex_toml.read_text(encoding="utf-8")

    cursor = json.loads(cursor_cfg.read_text(encoding="utf-8"))
    assert cursor["hooks"]["postToolUse"] == [
        {"command": f"{py_cmd} {post_script} --harness cursor", "matcher": CURSOR_POST_MATCHER}
    ]

    uninstall_all(claude_cfg, cursor_cfg, codex_cfg, codex_toml)
    for cfg in (claude_cfg, cursor_cfg, codex_cfg, codex_toml):
        assert "post_tool_use" not in cfg.read_text(encoding="utf-8")
        assert "session_end" not in cfg.read_text(encoding="utf-8")


def test_evaluate_hook_env_detection_and_pack_matchers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import re
    from bin.harness_status import merge_harness_matcher
    from bin.install_harnesses import CLAUDE_MATCHER, CODEX_MATCHER, CURSOR_MATCHER

    assert re.search(CLAUDE_MATCHER, "Bash") and re.search(CURSOR_MATCHER, "Shell")
    assert re.search(CODEX_MATCHER, "mcp__acme_db__execute_sql_readonly")
    for base, anchored in ((CLAUDE_MATCHER, False), (CURSOR_MATCHER, False), (CODEX_MATCHER, True)):
        merged = merge_harness_matcher(base, ("mcp__acme_db__.*",), regex_anchored=anchored)
        assert re.search(merged, "mcp__acme_db__execute_sql_readonly")

    _configure_synthetic_mcp_pack(tmp_path, monkeypatch)
    monkeypatch.setenv("CODEX_SANDBOX", "seatbelt")
    res1 = evaluate_hook(
        {
            "session_id": "cx-env",
            "tool_name": "mcp__acme_db__execute_sql_readonly",
            "tool_input": {},
        },
        state_dir=str(tmp_path / "env_state"),
    )
    assert res1["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_normal_source_file_reads_are_always_allowed_across_harnesses(tmp_path: Path) -> None:
    """Normal source files never trigger AUTO-OUTLINE blocking."""
    big_py = tmp_path / "chunked_target.py"
    lines = [f"def handler_{i}(x: int) -> int:\n    return x + {i}\n\n" for i in range(100)]
    big_py.write_text("".join(lines), encoding="utf-8")
    state_dir = str(tmp_path / "state_chunk")

    assert (
        evaluate_hook(
            {"session_id": "s-chunk", "tool_name": "Read", "tool_input": {"file_path": str(big_py)}},
            state_dir=state_dir,
            cli_harness="claude",
        )
        == {}
    )
    assert (
        evaluate_hook(
            {"conversationId": "ag-chunk", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(big_py)}}},
            state_dir=state_dir,
            cli_harness="antigravity",
        )
        == {"decision": "allow"}
    )


def test_matchers_include_codex_exec_and_cursor_snake_case_and_clean_stale_extension_dir(tmp_path: Path) -> None:
    import re
    from bin.install_harnesses import CODEX_MATCHER, CURSOR_MATCHER, EXTENSION_ID, install_all

    assert re.search(CODEX_MATCHER, "exec")
    assert re.search(CODEX_MATCHER, "exec_command")
    assert re.search(CURSOR_MATCHER, "read_file")
    assert re.search(CURSOR_MATCHER, "run_terminal_cmd")

    ext_dir = tmp_path / "ext"
    stale = ext_dir / f"{EXTENSION_ID}-0.0.1"
    stale.mkdir(parents=True)
    (stale / "extension.js").write_text("// old", encoding="utf-8")
    (ext_dir / "extensions.json").write_text("[]", encoding="utf-8")

    plugin_root = Path(__file__).resolve().parent.parent
    version = json.loads((plugin_root / "vscode-extension" / "package.json").read_text(encoding="utf-8"))["version"]
    install_all(
        plugin_root,
        tmp_path / "claude.json",
        tmp_path / "cursor.json",
        tmp_path / "codex.json",
        tmp_path / "config.toml",
        cursor_extensions_dir=ext_dir,
        antigravity_extensions_dir=ext_dir,
        antigravity_ide_extensions_dir=ext_dir,
    )
    assert not stale.exists()
    installed = ext_dir / f"{EXTENSION_ID}-{version}"
    assert (installed / "extension.js").is_file()
    entries = json.loads((ext_dir / "extensions.json").read_text(encoding="utf-8"))
    assert [(e["version"], e["relativeLocation"]) for e in entries] == [(version, installed.name)]





def test_cursor_str_replace_invalidates_read_cache(tmp_path: Path) -> None:
    """Verify Cursor `StrReplace` invalidates cached reads so subsequent overlapping reads are not trimmed."""
    src = tmp_path / "service.py"
    src.write_text("".join(f"def fn_{i}():\n    return {i}\n" for i in range(60)), encoding="utf-8")
    state_dir = str(tmp_path / "cursor_edit_unlock")

    assert (
        evaluate_hook(
            {"session_id": "cc-1", "tool_name": "Read", "tool_input": {"file_path": str(src), "offset": 1, "limit": 40}},
            state_dir=state_dir,
            cli_harness="cursor",
        )
        == {}
    )
    r_mut = evaluate_hook(
        {
            "session_id": "cc-1",
            "tool_name": "StrReplace",
            "tool_input": {"relative_workspace_path": "service.py"},
            "cwd": str(tmp_path),
        },
        state_dir=state_dir,
        cli_harness="cursor",
    )
    assert r_mut == {}
    r_after_mut = evaluate_hook(
        {"session_id": "cc-1", "tool_name": "Read", "tool_input": {"file_path": str(src), "offset": 20, "limit": 40}},
        state_dir=state_dir,
        cli_harness="cursor",
    )
    assert r_after_mut == {}



def test_notebook_read_cell_id_does_not_false_block_distinct_cells_and_maps_notebook_path(
    tmp_path: Path,
) -> None:
    nb = tmp_path / "analysis.ipynb"
    nb.write_text(json.dumps({"cells": [{"id": "cell-1"}, {"id": "cell-2"}]}), encoding="utf-8")
    sd = str(tmp_path / "state")

    r1 = evaluate_hook(
        {
            "session_id": "s-nb",
            "tool_name": "NotebookRead",
            "tool_input": {"notebook_path": str(nb), "cell_id": "cell-1"},
        },
        state_dir=sd,
        cli_harness="claude",
    )
    assert r1 == {}

    r2 = evaluate_hook(
        {
            "session_id": "s-nb",
            "tool_name": "NotebookRead",
            "tool_input": {"notebook_path": str(nb), "cell_id": "cell-2"},
        },
        state_dir=sd,
        cli_harness="claude",
    )
    assert r2 == {}

    norm_nb = normalize_pre_tool_payload(
        {"session_id": "s-nb", "tool_name": "NotebookRead", "tool_input": {"notebook_path": str(nb)}},
        cli_harness="claude",
    )
    formatted = format_pre_tool_output(
        {
            "decision": "allow",
            "overwrite": {"Path": "/tmp/redirected.ipynb", "StartLine": 10, "EndLine": 30},
        },
        norm_nb,
    )
    updated = formatted["hookSpecificOutput"]["updatedInput"]
    assert updated["notebook_path"] == "/tmp/redirected.ipynb"
    assert "file_path" not in updated
    assert "offset" not in updated
    assert "limit" not in updated


def test_antigravity_normalize_extracts_cwd_and_resolves_relative_paths_only_in_canonical(
    tmp_path: Path,
) -> None:
    payload_edit = {
        "conversationId": "c-ag-cwd",
        "stepIdx": 3,
        "cwd": str(tmp_path),
        "toolCall": {
            "name": "replace_file_content",
            "args": {"TargetFile": "pkg/mod.py", "StartLine": 1, "EndLine": 10},
        },
    }
    norm_edit = normalize_pre_tool_payload(payload_edit)
    expected_edit = str(tmp_path / "pkg/mod.py")
    assert norm_edit.cwd == str(tmp_path)
    assert norm_edit.canonical_args["TargetFile"] == expected_edit
    assert norm_edit.mutated_paths == (expected_edit,)
    assert norm_edit.original_tool_input["TargetFile"] == "pkg/mod.py"

    payload_write = {
        "conversationId": "c-ag-cwd",
        "stepIdx": 4,
        "cwd": str(tmp_path),
        "toolCall": {"name": "write_to_file", "args": {"AbsolutePath": "sub/out.py"}},
    }
    norm_write = normalize_pre_tool_payload(payload_write)
    assert norm_write.canonical_args["AbsolutePath"] == str(tmp_path / "sub/out.py")
    assert norm_write.mutated_paths == (str(tmp_path / "sub/out.py"),)
    assert norm_write.original_tool_input["AbsolutePath"] == "sub/out.py"

    payload_read = {
        "conversationId": "c-ag-cwd",
        "stepIdx": 5,
        "cwd": str(tmp_path),
        "toolCall": {"name": "read_file", "args": {"Path": "rel.py"}},
    }
    norm_read = normalize_pre_tool_payload(payload_read)
    assert norm_read.canonical_args["Path"] == str(tmp_path / "rel.py")
    assert norm_read.original_tool_input["Path"] == "rel.py"

    norm_blank = normalize_pre_tool_payload(
        {
            "conversationId": "c-ag-cwd",
            "stepIdx": 6,
            "cwd": "   ",
            "toolCall": {"name": "read_file", "args": {"Path": "rel.py"}},
        }
    )
    assert norm_blank.cwd is None
    assert norm_blank.canonical_args["Path"] == "rel.py"


def test_format_pre_tool_output_detects_path_key_and_respects_original_line_bounds() -> None:
    norm_path_key = normalize_pre_tool_payload(
        {"tool_name": "read_file", "tool_input": {"path": "/tmp/a.py"}, "session_id": "s1"}
    )
    fmt_path = format_pre_tool_output(
        {"decision": "allow", "overwrite": {"Path": "/tmp/b.py", "StartLine": 10, "EndLine": 30}},
        norm_path_key,
    )
    upd_path = fmt_path["hookSpecificOutput"]["updatedInput"]
    assert upd_path == {"path": "/tmp/b.py", "offset": 10, "limit": 21}
    assert "file_path" not in upd_path

    norm_orig_bounds = normalize_pre_tool_payload(
        {
            "tool_name": "read_file",
            "tool_input": {"file_path": "/tmp/a.py", "StartLine": 1, "EndLine": 50},
            "session_id": "s2",
        }
    )
    fmt_bounds = format_pre_tool_output(
        {"decision": "allow", "overwrite": {"Path": "/tmp/a.py", "StartLine": 25, "EndLine": 50}},
        norm_orig_bounds,
    )
    upd_bounds = fmt_bounds["hookSpecificOutput"]["updatedInput"]
    assert upd_bounds["file_path"] == "/tmp/a.py"
    assert upd_bounds["StartLine"] == 25
    assert upd_bounds["EndLine"] == 50
    assert "offset" not in upd_bounds
    assert "limit" not in upd_bounds

    norm_end_only = normalize_pre_tool_payload(
        {"tool_name": "view_file", "tool_input": {"path": "/tmp/a.py", "EndLine": 40}, "session_id": "s3"}
    )
    fmt_end = format_pre_tool_output(
        {"decision": "allow", "overwrite": {"StartLine": 15, "EndLine": 40}},
        norm_end_only,
    )
    upd_end = fmt_end["hookSpecificOutput"]["updatedInput"]
    assert upd_end["StartLine"] == 15
    assert upd_end["EndLine"] == 40
    assert "offset" not in upd_end
    assert "limit" not in upd_end


def test_non_antigravity_format_preserves_capital_path_key() -> None:
    from hooks.harness_adapter import format_pre_tool_output, normalize_pre_tool_payload

    norm = normalize_pre_tool_payload(
        {"tool_name": "read_file", "tool_input": {"Path": "/old.py", "StartLine": 1, "EndLine": 50}, "session_id": "s4"}
    )
    fmt = format_pre_tool_output({"decision": "allow", "overwrite": {"Path": "/new.py"}}, norm)
    assert fmt["hookSpecificOutput"]["updatedInput"] == {"Path": "/new.py", "StartLine": 1, "EndLine": 50}


def test_installer_output_spool_hooks_mcp_verify_and_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from bin.harness_status import (
        CLAUDE_POST_SPOOL_MATCHER, CLAUDE_POST_SYNC_MATCHER, CURSOR_POST_SPOOL_MATCHER,
        verify_harness_hooks, without_cg_handlers,
    )
    from bin.install_harnesses import check_status as install_check_status

    plugin_root = Path(__file__).resolve().parent.parent
    cfg_path = tmp_path / "cfg" / "config.json"
    cfg_path.parent.mkdir(parents=True)
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "active"}, "integrations": {"cursor_spool_mcp": "active"}}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    guard_config.clear_config_cache()
    monkeypatch.setattr("bin.instruction_block.IS_WINDOWS", False)

    claude_cfg = tmp_path / "claude" / "settings.json"
    cursor_dir = tmp_path / "cursor"
    cursor_cfg, cursor_mcp = cursor_dir / "hooks.json", cursor_dir / "mcp.json"
    codex_cfg, codex_toml, bin_dir = tmp_path / "codex" / "hooks.json", tmp_path / "codex" / "config.toml", tmp_path / "bin"
    for p, txt in ((claude_cfg, "{}"), (cursor_cfg, "{}"), (codex_cfg, "{}"), (codex_toml, 'model = "x"\n')):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt, encoding="utf-8")

    dry = install_all(plugin_root, claude_cfg, cursor_cfg, codex_cfg, codex_toml, dry_run=True, shim_bin_dir=bin_dir)
    assert dry["cursor_spool_mcp"] == "created" and not cursor_mcp.exists()

    res = install_all(plugin_root, claude_cfg, cursor_cfg, codex_cfg, codex_toml, shim_bin_dir=bin_dir)
    assert res["cursor_spool_mcp"] == "created"
    cl_hooks = json.loads(claude_cfg.read_text(encoding="utf-8"))["hooks"]
    assert [g["matcher"] for g in cl_hooks["PostToolUse"]] == [CLAUDE_POST_SYNC_MATCHER, CLAUDE_POST_SPOOL_MATCHER]
    assert cl_hooks["PostToolUse"][1]["hooks"][0]["timeout"] == 10
    assert "async" not in cl_hooks["PostToolUse"][1]["hooks"][0]
    assert cl_hooks["PostToolUseFailure"][1]["matcher"] == "Bash"
    assert cl_hooks["PostToolUseFailure"][1]["hooks"][0]["async"] is True
    assert "timeout" not in cl_hooks["PostToolUseFailure"][1]["hooks"][0]
    cu_hooks = json.loads(cursor_cfg.read_text(encoding="utf-8"))["hooks"]
    assert cu_hooks["postToolUse"][0]["matcher"] == CURSOR_POST_SPOOL_MATCHER
    mcp_data = json.loads(cursor_mcp.read_text(encoding="utf-8"))
    assert mcp_data["mcpServers"]["context-guard-spool"]["args"][0].endswith("cg_spool.py")

    vh_on = verify_harness_hooks(claude_cfg, cursor_cfg, codex_cfg, output_spool_mode="active")
    vh_off = verify_harness_hooks(claude_cfg, cursor_cfg, codex_cfg, output_spool_mode="off")
    assert vh_on["claude"]["spool_hook_ok"] is True and vh_on["cursor"]["spool_hook_ok"] is True
    assert vh_off["claude"]["spool_hook_ok"] is False and vh_off["cursor"]["spool_hook_ok"] is False
    st = install_check_status(claude_cfg, cursor_cfg, codex_cfg, shim_bin_dir=bin_dir, cursor_mcp_path=cursor_mcp)
    assert st["claude"] and st["cursor"] and st["cg_spool_shim"] and st["cursor_spool_mcp"]

    assert without_cg_handlers(cl_hooks["PostToolUse"]) == []
    assert without_cg_handlers(cu_hooks["postToolUse"]) == []

    # shadow hooks keep spool matchers, while mcp=off removes cursor_spool_mcp
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "shadow"}, "integrations": {"cursor_spool_mcp": "off"}}), encoding="utf-8")
    guard_config.clear_config_cache()
    res_sh = install_all(plugin_root, claude_cfg, cursor_cfg, codex_cfg, codex_toml, shim_bin_dir=bin_dir, cursor_mcp_path=cursor_mcp)
    assert res_sh["cursor_spool_mcp"] == "removed"
    assert install_check_status(claude_cfg, cursor_cfg, codex_cfg, shim_bin_dir=bin_dir, cursor_mcp_path=cursor_mcp)["cursor_spool_mcp"] is False

    # Malformed mcp.json returns an error status instead of raising
    cursor_mcp.write_text("{corrupt", encoding="utf-8")
    res_err = install_all(plugin_root, claude_cfg, cursor_cfg, codex_cfg, codex_toml, shim_bin_dir=bin_dir, cursor_mcp_path=cursor_mcp)
    assert res_err["cursor_spool_mcp"].startswith("error (")
    cursor_mcp.write_text(json.dumps({"mcpServers": {"context-guard-spool": {"command": "x"}}}), encoding="utf-8")
    out = uninstall_all(claude_cfg, cursor_cfg, codex_cfg, codex_toml, shim_bin_dir=bin_dir, cursor_mcp_path=cursor_mcp)
    assert out["cursor_spool_mcp"] == "removed"


def test_installer_rollback_restores_cg_spool_and_cursor_mcp(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin_root = Path(__file__).resolve().parent.parent
    monkeypatch.setattr("bin.instruction_block.IS_WINDOWS", False)
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "active"}, "integrations": {"cursor_spool_mcp": "active"}}), encoding="utf-8")
    guard_config.clear_config_cache()

    pack_src = tmp_path / "pack_src"
    pack_src.mkdir()
    (pack_src / "pack.py").write_text(
        "from policies.api import ALL_SECURITY_SCOPES, PolicyDecision, PolicyPackManifest\n"
        "PACK_MANIFEST = PolicyPackManifest(pack_id='sec-rb', api_version=1, kind='security', "
        "covered_domains=('governance_guard', 'local_repo_guard', 'bigquery_guard'), "
        "evaluate=lambda _c: PolicyDecision(decision='allow'), inspect_config=lambda _s: [])\n",
        encoding="utf-8",
    )
    claude_cfg, cursor_cfg = tmp_path / "claude" / "settings.json", tmp_path / "cursor" / "hooks.json"
    codex_cfg, codex_toml = tmp_path / "codex" / "hooks.json", tmp_path / "codex" / "config.toml"
    cursor_mcp, bin_dir, bad_inst = tmp_path / "cursor" / "mcp.json", tmp_path / "bin", tmp_path / "AGENTS.md"
    for p, txt in ((claude_cfg, "{}\n"), (cursor_cfg, "{}\n"), (codex_cfg, "{}\n"), (codex_toml, "")):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt, encoding="utf-8")
    orig_mcp = json.dumps({"mcpServers": {"other": {"command": "echo"}}}, indent=2) + "\n"
    cursor_mcp.write_text(orig_mcp, encoding="utf-8")
    bad_inst.write_bytes(b"\xff\xfe invalid utf8\n")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.defpath}")

    with pytest.raises(RuntimeError, match="harness installation error"):
        install_all(
            plugin_root, claude_cfg, cursor_cfg, codex_cfg, codex_toml,
            shim_bin_dir=bin_dir, instruction_files=(bad_inst,), pack_source=pack_src, cursor_mcp_path=cursor_mcp,
        )
    assert cursor_mcp.read_text(encoding="utf-8") == orig_mcp
    assert not (bin_dir / "cg-spool").exists()
    assert not (bin_dir / "cg-outline").exists()
