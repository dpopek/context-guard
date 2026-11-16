"""Tests for cross-harness preamble & MCP budget advisor engine and `cg_budget.py` CLI."""

from __future__ import annotations

import ast
import json
import socket
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from bin import budget_advisor, cg_budget, mcp_inventory, token_usage, usage_report

REPO_ROOT = Path(__file__).resolve().parent.parent


def _snapshot_tree(root: Path) -> list[tuple[str, int, int]]:
    if not root.exists():
        return []
    return [
        (p.relative_to(root).as_posix(), st.st_size, st.st_mtime_ns)
        for p in sorted(root.rglob("*"))
        if p.is_file() and (st := p.stat())
    ]


def _manifest_version() -> str:
    return str(json.loads((REPO_ROOT / "plugin.json").read_text(encoding="utf-8"))["version"])


def test_collect_preamble_budget_handles_all_four_harnesses_and_cursor_cache_unavailable(tmp_path: Path) -> None:
    home = tmp_path / "Users" / "alice"
    ws = home / "projects" / "app"
    home.mkdir(parents=True)
    ws.mkdir(parents=True)

    # Claude: global + @import, workspace, >200-line MEMORY.md, skills
    (home / ".claude" / "skills" / "dup-skill").mkdir(parents=True)
    (home / ".claude" / "skills" / "dup-skill" / "SKILL.md").write_text("---\nname: dup-skill\ndescription: Claude copy\n---\n", encoding="utf-8")
    (home / ".claude" / "CLAUDE.md").write_text("Global rule\n@shared.md\n", encoding="utf-8")
    (home / ".claude" / "shared.md").write_text("Shared imported guidance\n", encoding="utf-8")
    large_ws_claude = "# Workspace\n" + ("Keep patches minimal.\n" * 900)
    assert len(large_ws_claude.encode("utf-8")) > budget_advisor.LARGE_INSTRUCTION_FILE_BYTES
    (ws / "CLAUDE.md").write_text(large_ws_claude, encoding="utf-8")

    mem_path = usage_report.memory_index_path(home, ws)
    mem_path.parent.mkdir(parents=True)
    mem_lines = [f"- line {i}: remembered fact" for i in range(1, 231)]
    mem_path.write_text("\n".join(mem_lines) + "\n", encoding="utf-8")

    # Antigravity: GEMINI.md, plugin rules, workspace AGENTS.md, duplicate skills
    (home / ".gemini" / "config" / "plugins" / "p1" / "rules").mkdir(parents=True)
    (home / ".gemini" / "GEMINI.md").write_text("Global Antigravity\n", encoding="utf-8")
    (home / ".gemini" / "config" / "plugins" / "p1" / "rules" / "r1.md").write_text("Plugin rule\n", encoding="utf-8")
    (ws / ".agents" / "skills" / "ws-skill").mkdir(parents=True)
    (ws / ".agents" / "skills" / "ws-skill" / "SKILL.md").write_text("---\nname: ws-skill\ndescription: Workspace skill\n---\n", encoding="utf-8")
    (ws / "AGENTS.md").write_text("Workspace AGENTS\n", encoding="utf-8")
    (ws / ".agents" / "AGENTS.md").write_text("Dot agents rules\n", encoding="utf-8")
    for sdir in (
        home / ".gemini" / "config" / "skills" / "dup-ag",
        home / ".gemini" / "config" / "plugins" / "p1" / "skills" / "dup-ag",
    ):
        sdir.mkdir(parents=True)
        (sdir / "SKILL.md").write_text("---\nname: dup-ag\ndescription: Duplicate skill\n---\n", encoding="utf-8")

    # Codex & Cursor static files
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "AGENTS.md").write_text("Codex user rules\n", encoding="utf-8")
    (ws / ".cursor" / "rules").mkdir(parents=True)
    (ws / ".cursorrules").write_text("Legacy cursor rules\n", encoding="utf-8")
    (ws / ".cursor" / "rules" / "style.mdc").write_text("Cursor mdc rule\n", encoding="utf-8")

    usage_state: dict[str, Any] = {
        "totals": {
            "antigravity|gemini-3-pro": {"input": 200, "cache_read": 800, "cache_write": 0, "events": 2, "total_only": 0},
            "claude|claude-sonnet-4-6": {"input": 100, "cache_read": 900, "cache_write": 0, "events": 2, "total_only": 0},
            "codex|gpt-5": {"input": 1000, "cache_read": 0, "cache_write": 0, "events": 2, "total_only": 2},
        },
        "preamble": {"antigravity": [12_000, 14_000]},
        "preamble_parts": [{"measured": 10_000, "components": {"system_prompt": {"core": 5000}}}],
        "codex_preamble_parts": [{"measured": 6000, "cohort": "codex (cli)", "components": {"instructions": {"agents_md": 500}}}],
        "cursor_estimates": {"c1.json": {"inode": 1, "size": 400, "tokens": 2500, "day": "2026-11-16"}},
    }

    pre = budget_advisor.collect_preamble_budget(home, ws, usage_state)
    assert pre["harnesses_scanned"] == ["antigravity", "claude", "codex", "cursor"]
    serialized = json.dumps(pre)
    assert "/Users/alice" not in serialized

    mem_rec = next(f for f in pre["static_files"] if f["component"] == "memory_index")
    expected_mem_tokens = len("\n".join(mem_lines[:usage_report.MEMORY_LOAD_LINES]).encode("utf-8")) // 4
    assert mem_rec["lines"] == 230
    assert mem_rec["estimated_tokens"] == expected_mem_tokens
    assert pre["by_harness"]["claude"]["memory_lines"] == 230
    assert pre["by_harness"]["cursor"]["static_bytes"] > 0

    sess = pre["session_summaries"]
    assert sess["antigravity"]["evidence"] == "measured"
    assert sess["antigravity"]["cache_read_share_pct"] == 80.0 and sess["antigravity"]["cache_evidence"] == "measured"
    assert sess["claude (cli)"]["evidence"] == "measured"
    assert sess["claude (cli)"]["cache_read_share_pct"] == 90.0
    assert sess["claude (desktop)"]["sessions"] == 0 and sess["claude (desktop)"]["median"] is None
    assert sess["claude (desktop)"]["evidence"] == "unavailable" and sess["claude (desktop)"]["cache_read_share_pct"] is None
    assert sess["codex (cli)"]["evidence"] == "measured" and sess["codex (cli)"]["cache_read_share_pct"] is None
    assert sess["codex (cli)"]["cache_evidence"] == "unavailable"
    assert sess["cursor"]["sessions"] == 1 and sess["cursor"]["median"] == 2500
    assert sess["cursor"]["evidence"] == "estimated"
    assert sess["cursor"]["cache_read_share_pct"] is None and sess["cursor"]["cache_evidence"] == "unavailable"

    assert any(d["name"] == "dup-ag" and d["count"] == 2 for d in pre["duplicate_skills"])
    assert any("MEMORY.md" in w for w in pre["warnings"])
    assert any("Large instruction file" in w for w in pre["warnings"])

    empty_pre = budget_advisor.collect_preamble_budget(home, ws, None, harnesses=["cursor", "codex"])
    assert empty_pre["harnesses_scanned"] == ["codex", "cursor"]
    for h in ("codex", "cursor"):
        row = empty_pre["session_summaries"][h]
        assert row["sessions"] == 0 and row["median"] is None and row["recent_median"] is None
        assert row["p90"] is None and row["last"] is None and row["evidence"] == "unavailable"


def test_recommendations_avoid_false_unused_alerts_when_telemetry_unavailable(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"jira": {"command": "npx", "args": ["jira"]}}}), encoding="utf-8")
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text('[mcp_servers.cx-srv]\ncommand = "node"\nargs = ["srv.js"]\n', encoding="utf-8")

    pre = budget_advisor.collect_preamble_budget(home, ws, None)
    mcp_none = mcp_inventory.collect_mcp_inventory(home, ws, None)

    for u_state in (
        None,
        token_usage.empty_usage_state(),
        {
            "totals": {"codex|gpt-5": {"input": 100, "output": 10, "cache_read": 0, "cache_write": 0, "events": 1}},
            "preamble_parts": [{"measured": 9000, "components": {"deferred_tools": {"mcp:jira": 900}}}],
            "component_use": {},
            "component_use_since": "2026-10-01",
        },
        {
            "totals": {"claude|sonnet": {"input": 100, "output": 10, "cache_read": 0, "cache_write": 0, "events": 1}},
            "preamble_parts": [{"measured": 9000, "components": {"deferred_tools": {"mcp:jira": 900, "mcp:used": 600}}}],
            "component_use": {"2026-11-15": {"mcp:used": 3}},
            "component_use_since": "2026-11-10",
        },
    ):
        mcp_curr = mcp_inventory.collect_mcp_inventory(home, ws, u_state) if u_state else mcp_none
        recs = budget_advisor.build_budget_recommendations(pre, mcp_curr, u_state, today=date(2026, 11, 16))
        assert all(it["kind"] != "unused_mcp_or_plugin_30d" for it in recs["items"])

    # Now with >=30 days tracked component_use and measured unused Claude server + plugin, Codex stays exempt
    ready_state: dict[str, Any] = {
        "totals": {"claude|sonnet": {"input": 100, "output": 10, "cache_read": 0, "cache_write": 0, "events": 1}},
        "preamble_parts": [
            {"measured": 9000, "components": {"deferred_tools": {"mcp:jira": 900, "mcp:used": 600}, "skills": {"stale-plug": 750}}},
        ],
        "component_use": {"2026-11-15": {"mcp:used": 5}},
        "component_use_since": "2026-10-01",
        "updated_at": "2026-11-16T10:00:00Z",
    }
    mcp_ready = mcp_inventory.collect_mcp_inventory(home, ws, ready_state)
    # Also simulate a probed Codex server with calls_30d == 0 and a probed Claude server not in preamble_parts
    mcp_ready["servers"].append({
        "name": "probed-cl", "normalized_key": "mcp:probed-cl", "harness": "claude", "scope": "user",
        "source": "~/.claude.json", "transport": "stdio", "enabled": True, "schema_status": "probed",
        "estimated_tokens": 600, "calls_30d": 0, "calls_evidence": "measured",
    })
    for srv in mcp_ready["servers"]:
        if srv["harness"] == "codex":
            srv["estimated_tokens"] = 800
    recs_ready = budget_advisor.build_budget_recommendations(pre, mcp_ready, ready_state, today=date(2026, 11, 16))
    unused_targets = {it["target"] for it in recs_ready["items"] if it["kind"] == "unused_mcp_or_plugin_30d"}
    assert unused_targets == {"mcp:jira", "stale-plug", "probed-cl"}


def test_recommendations_and_profiles_never_auto_mutate_or_guarantee_savings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()

    # Create conditions for duplicate_mcp_server, mcp_tool_overlap, duplicate_skills, memory_index_truncation,
    # large_instruction_file, unobserved_mcp_schemas, and unused_mcp_or_plugin_30d.
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"gh": {"command": "npx"}, "unobs": {"command": "npx"}}}), encoding="utf-8")
    (ws / ".mcp.json").write_text(json.dumps({"mcpServers": {"gh": {"command": "npx"}}}), encoding="utf-8")
    ag_dir = home / ".gemini" / "antigravity"
    ag_dir.mkdir(parents=True)
    (ag_dir / "mcp_config.json").write_text(json.dumps({"mcpServers": {"fs": {"command": "npx"}}}), encoding="utf-8")
    (ag_dir / "mcp" / "fs").mkdir(parents=True)
    (ag_dir / "mcp" / "fs" / "read_file.json").write_text("{}", encoding="utf-8")
    (ws / ".cursor").mkdir()
    (ws / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"context-guard-spool": {"command": "python3", "args": ["cg_spool.py"]}}}),
        encoding="utf-8",
    )

    (ws / "CLAUDE.md").write_text("X" * (budget_advisor.LARGE_INSTRUCTION_FILE_BYTES + 2048), encoding="utf-8")
    mem_path = usage_report.memory_index_path(home, ws)
    mem_path.parent.mkdir(parents=True)
    mem_path.write_text("\n".join(f"item {i}" for i in range(175)) + "\n", encoding="utf-8")
    for sdir in (
        home / ".gemini" / "config" / "skills" / "dup",
        home / ".gemini" / "config" / "plugins" / "p1" / "skills" / "dup",
    ):
        sdir.mkdir(parents=True)
        (sdir / "SKILL.md").write_text("---\nname: dup\ndescription: d\n---\n", encoding="utf-8")

    # Ensure isolated run_budget_audit(home=...) NEVER reads DEFAULT_USAGE_PATH
    poisoned_usage = tmp_path / "poisoned_operator_usage.json"
    poisoned_state = token_usage.empty_usage_state()
    poisoned_state["totals"] = {"claude|sonnet": {"input": 500, "output": 20, "cache_read": 0, "cache_write": 0, "events": 1}}
    poisoned_state["preamble_parts"] = [{"measured": 9000, "components": {"skills": {"poisoned-plugin": 1200}}}]
    poisoned_state["component_use"] = {"2026-11-15": {"mcp:other": 1}}
    poisoned_state["component_use_since"] = "2026-10-01"
    poisoned_state["updated_at"] = "2026-11-16T10:00:00Z"
    poisoned_usage.write_text(json.dumps(poisoned_state), encoding="utf-8")
    monkeypatch.setattr(token_usage, "DEFAULT_USAGE_PATH", poisoned_usage)

    isolated_report = budget_advisor.run_budget_audit(home=home, workspace_root=ws)
    assert isolated_report["plugin_version"] == _manifest_version()
    assert isolated_report["read_only"] is True and isolated_report["auto_mutated_configs"] is False
    assert isolated_report["preamble"]["session_summaries"]["claude"]["sessions"] == 0
    assert all(it["target"] != "poisoned-plugin" for it in isolated_report["recommendations"]["items"])
    assert all(it["kind"] != "unused_mcp_or_plugin_30d" for it in isolated_report["recommendations"]["items"])

    # Now run with explicit usage_path so all 7 kinds fire and verify ordering + non-mutation flags
    full_report = budget_advisor.run_budget_audit(home=home, workspace_root=ws, usage_path=poisoned_usage)
    recs = full_report["recommendations"]
    assert recs["auto_applied"] is False and recs["guaranteed_savings"] is False

    kinds_seen = {it["kind"] for it in recs["items"]}
    assert kinds_seen == {
        "unused_mcp_or_plugin_30d",
        "duplicate_mcp_server",
        "mcp_tool_overlap",
        "duplicate_skills",
        "memory_index_truncation",
        "large_instruction_file",
        "unobserved_mcp_schemas",
    }

    sev_rank = {"high": 0, "medium": 1, "low": 2}
    sort_keys = [
        (sev_rank[it["severity"]], -(it["estimated_tokens_delta"] if isinstance(it["estimated_tokens_delta"], int) else -1))
        for it in recs["items"]
    ]
    assert sort_keys == sorted(sort_keys)
    for it in recs["items"]:
        assert it["auto_applied"] is False and it["guaranteed_savings"] is False
        assert "cache" in it["cache_caveat"].lower() and "session" in it["cache_caveat"].lower()

    profiles = {p["name"]: p for p in recs["session_profiles"]}
    assert set(profiles) == {"minimal-core", "full-integrations"}
    assert "cursor:context-guard-spool" in profiles["minimal-core"]["keep_servers"]
    assert profiles["full-integrations"]["disable_candidates"] == []
    for prof in profiles.values():
        assert prof["auto_applied"] is False and prof["guaranteed_savings"] is False
        assert "cache" in prof["cache_caveat"].lower()


def test_cli_budget_markdown_json_and_probe_validation_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()

    def _forbid_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Validation failures must exit before spawning any subprocess")

    monkeypatch.setattr(subprocess, "Popen", _forbid_spawn)
    assert cg_budget.main(["--preamble", "--probe"]) == 2
    assert "cannot be used with --preamble" in capsys.readouterr().err

    assert cg_budget.main(["budget", "--preamble", "--probe", "--json"]) == 2
    err_json = json.loads(capsys.readouterr().out)
    assert err_json["ok"] is False and err_json["error"] == "invalid_arguments"

    assert cg_budget.main(["--mcp", "--probe", "--probe-timeout", "0.1"]) == 2
    capsys.readouterr()
    assert cg_budget.main(["--mcp", "--probe", "--probe-timeout", "30.1", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_arguments"
    assert cg_budget.main(["--bogus-flag", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "invalid_arguments"
    with pytest.raises(ValueError):
        budget_advisor.run_budget_audit(home=home, workspace_root=ws, probe=True, probe_timeout_s=0.1)
    monkeypatch.undo()

    # Populate passive configs + local stdio server script
    probe_srv = ws / "ndjson_srv.py"
    probe_srv.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    if msg.get('method') == 'initialize':\n"
        "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'protocolVersion': '2024-11-05'}}) + '\\n')\n"
        "    elif msg.get('method') == 'tools/list':\n"
        "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'tools': [{'name': 'ping'}]}}) + '\\n')\n"
        "    sys.stdout.flush()\n",
        encoding="utf-8",
    )
    (home / ".claude.json").write_text(
        json.dumps({"mcpServers": {"local-echo": {"command": sys.executable, "args": ["${workspaceFolder}/ndjson_srv.py"]}}}),
        encoding="utf-8",
    )
    (ws / "CLAUDE.md").write_text("Project instructions\n", encoding="utf-8")

    # Passive --json with leading "budget"
    assert cg_budget.main(["budget", "--preamble", "--mcp", "--recommendations", "--home", str(home), "--workspace", str(ws), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "passive" and payload["read_only"] is True and payload["auto_mutated_configs"] is False
    assert set(payload["requested_sections"]) == {"preamble", "mcp", "recommendations"}

    # Passive default Markdown
    assert cg_budget.main(["--home", str(home), "--workspace", str(ws), "--markdown"]) == 0
    md_passive = capsys.readouterr().out
    assert "[measured]" in md_passive and "[estimated]" in md_passive and "unavailable" in md_passive
    assert "No config auto-mutation" in md_passive and "No guaranteed billing savings" in md_passive
    assert "> [!WARNING]" not in md_passive

    # Subset --preamble only and --harness / --usage-path filtering
    usage_file = tmp_path / "custom_usage.json"
    usage_file.write_text(json.dumps(token_usage.empty_usage_state()), encoding="utf-8")
    assert cg_budget.main(["--preamble", "--harness", "claude", "--home", str(home), "--workspace", str(ws), "--usage-path", str(usage_file), "--json"]) == 0
    pre_only = json.loads(capsys.readouterr().out)
    assert pre_only["harnesses_scanned"] == ["claude"]
    assert "preamble" in pre_only and "mcp" not in pre_only and "recommendations" not in pre_only

    # Active --probe --mcp --markdown renders warning banner and measures probed server
    assert cg_budget.main(["--mcp", "--probe", "--probe-timeout", "2.0", "--home", str(home), "--workspace", str(ws), "--markdown"]) == 0
    md_probe = capsys.readouterr().out
    assert "> [!WARNING]" in md_probe
    assert "`local-echo`" in md_probe and "1 [measured]" in md_probe and "[estimated]" in md_probe


def test_cli_passive_default_audit_touches_zero_files_and_spawns_zero_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()
    (ws / "AGENTS.md").write_text("Workspace rules\n", encoding="utf-8")
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"context-guard-spool": {"command": "python3", "args": ["cg_spool.py"]}}}),
        encoding="utf-8",
    )

    before = _snapshot_tree(tmp_path)

    def _forbid(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Passive budget CLI must never spawn subprocesses or open sockets")

    monkeypatch.setattr(subprocess, "Popen", _forbid)
    monkeypatch.setattr(subprocess, "run", _forbid)
    monkeypatch.setattr(socket, "socket", _forbid)
    monkeypatch.chdir(ws)

    assert cg_budget.main(["--home", str(home), "--json"]) == 0
    out_data = json.loads(capsys.readouterr().out)
    assert any(f["path"] == "<workspace>/AGENTS.md" for f in out_data["preamble"]["static_files"])
    assert cg_budget.main(["--home", str(home)]) == 0
    assert "Context-Guard Preamble & MCP Budget Advisor" in capsys.readouterr().out
    assert _snapshot_tree(tmp_path) == before

    # Zero os.getcwd() inside library bin/budget_advisor.py
    tree = ast.parse((REPO_ROOT / "bin" / "budget_advisor.py").read_text(encoding="utf-8"))
    cwd_calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr == "getcwd" and isinstance(n.value, ast.Name) and n.value.id == "os"
    ]
    assert cwd_calls == []
