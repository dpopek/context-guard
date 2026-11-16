"""Tests for passive MCP inventory, Codex TOML parser, read-only usage snapshots, and opt-in stdio probing."""

from __future__ import annotations

import ast
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from bin import mcp_inventory, token_usage
from bin.codex_toml import parse_codex_mcp_servers
from bin.preamble_attribution import CODEX_TOOL_BYTES_PER_TOKEN
from spool.mcp_server import SPOOL_MCP_TOOL_SCHEMAS

REPO_ROOT = Path(__file__).resolve().parent.parent


def _snapshot_tree(root: Path) -> list[tuple[str, int, int]]:
    snap: list[tuple[str, int, int]] = []
    if not root.exists():
        return snap
    for p in sorted(root.rglob("*")):
        if p.is_file():
            st = p.stat()
            snap.append((p.relative_to(root).as_posix(), st.st_size, st.st_mtime_ns))
    return snap


def _write_probe_script(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def test_passive_inventory_has_zero_subprocess_network_or_disk_side_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "alice_home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()

    (home / ".gemini" / "antigravity" / "mcp" / "github").mkdir(parents=True)
    (home / ".gemini" / "antigravity" / "mcp" / "github" / "get_issue.json").write_text('{"name":"get_issue"}', encoding="utf-8")
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs"]}}}), encoding="utf-8")
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"context-guard-spool": {"command": "python3", "args": ["cg_spool.py"]}}}), encoding="utf-8")
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text('[mcp_servers.docs]\nurl = "https://docs.example.com/mcp"\n', encoding="utf-8")

    # Seed corrupt token_usage.json, valid usage snapshot, and a Claude transcript: read_usage_snapshot MUST NOT quarantine or lock!
    usage_path = home / ".gemini" / "telemetry" / "token_usage.json"
    usage_path.parent.mkdir(parents=True, exist_ok=True)
    usage_path.write_text("{corrupt-json", encoding="utf-8")
    valid_usage = home / ".gemini" / "telemetry" / "valid_usage.json"
    seed_state = token_usage.empty_usage_state()
    seed_state["totals"] = {"codex|gpt-5": {"input": 50, "output": 5, "cache_read": 0, "cache_write": 0, "events": 1, "total_only": 0}}
    valid_usage.write_text(json.dumps(seed_state), encoding="utf-8")
    claude_proj = home / ".claude" / "projects" / "proj-a"
    claude_proj.mkdir(parents=True)
    (claude_proj / "sess1.jsonl").write_text(
        json.dumps({"type": "assistant", "timestamp": "2026-11-16T10:00:00Z", "message": {"id": "m1", "model": "claude-sonnet-4-6", "usage": {"input_tokens": 200, "output_tokens": 10}, "content": [{"type": "tool_use", "name": "mcp__fs__read_file", "input": {}}]}}) + "\n",
        encoding="utf-8",
    )

    before = _snapshot_tree(tmp_path)

    def _forbid(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Passive discovery must never launch subprocesses or open sockets")

    monkeypatch.setattr(subprocess, "Popen", _forbid)
    monkeypatch.setattr(subprocess, "run", _forbid)
    monkeypatch.setattr(socket, "socket", _forbid)

    roots = token_usage.transcript_roots_for_home(home)
    assert set(roots) == {"antigravity", "claude", "codex", "cursor"}
    snapshot = token_usage.read_usage_snapshot(usage_path, roots=roots)
    assert snapshot["totals"]
    assert snapshot["component_use_since"] is not None
    assert not usage_path.with_suffix(".lock").exists()

    merged_snap = token_usage.read_usage_snapshot(valid_usage, roots=roots)
    assert "codex|gpt-5" in merged_snap["totals"] and "claude|claude-sonnet-4-6" in merged_snap["totals"]

    servers, issues = mcp_inventory.discover_passive_mcp_configs(home, ws)
    inv = mcp_inventory.collect_mcp_inventory(home, ws, snapshot, probe=False)

    assert _snapshot_tree(tmp_path) == before
    assert issues == []
    assert len(servers) == 4
    assert inv["mode"] == "passive"
    assert inv["probe_warning"] is None
    assert all(s["probe_status"] == "not_probed" for s in inv["servers"])

    # Enforce zero os.getcwd() inside bin/mcp_inventory.py
    inv_src = (REPO_ROOT / "bin" / "mcp_inventory.py").read_text(encoding="utf-8")
    tree = ast.parse(inv_src)
    cwd_calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr == "getcwd" and isinstance(n.value, ast.Name) and n.value.id == "os"
    ]
    assert cwd_calls == []


def test_discovers_all_four_harnesses_and_respects_disabled_flags(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ws = tmp_path / "repo"
    home.mkdir()
    ws.mkdir()

    # Antigravity: primary + malformed fallback + disabled entry
    ag_dir = home / ".gemini" / "antigravity"
    ag_dir.mkdir(parents=True)
    (ag_dir / "mcp_config.json").write_text(
        json.dumps({"mcpServers": {"ag-http": {"serverUrl": "https://ag.example.com/mcp"}, "ag-off": {"command": "node", "disabled": True}}}),
        encoding="utf-8",
    )
    (home / ".gemini" / "config").mkdir(parents=True)
    (home / ".gemini" / "config" / "mcp_config.json").write_text("{bad json", encoding="utf-8")

    # Claude: user, workspace via projects[ws], settings.json, and .mcp.json with disabledMcpjsonServers
    (home / ".claude").mkdir()
    (home / ".claude.json").write_text(
        json.dumps({
            "mcpServers": {"cl-user": {"command": "npx", "args": ["srv"]}},
            "projects": {
                str(ws): {
                    "mcpServers": {"cl-proj": {"type": "http", "url": "https://cl.example.com"}},
                    "disabledMcpjsonServers": ["cl-ws-disabled"],
                }
            },
        }),
        encoding="utf-8",
    )
    (home / ".claude" / "settings.json").write_text(json.dumps({"mcpServers": {"cl-set": {"command": "uvx", "args": ["tool"]}}}), encoding="utf-8")
    (ws / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"cl-ws-on": {"command": "python3", "args": ["m.py"]}, "cl-ws-disabled": {"command": "python3", "args": ["d.py"]}}}),
        encoding="utf-8",
    )

    # Cursor: user + workspace
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"cur-user": {"url": "https://cur.example.com"}}}), encoding="utf-8")
    (ws / ".cursor").mkdir()
    (ws / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"cur-off": {"command": "node", "disabled": True}}}), encoding="utf-8")

    # Codex: CRLF, multiline args, quoted names, inline # comments, unrelated tables, malformed recovery
    (home / ".codex").mkdir()
    toml_user = (
        '[features]\r\nshell_snapshot = true\r\n\r\n'
        '[mcp_servers."cx.quoted"]\r\n'
        'command = "uvx"\r\n'
        'args = [\r\n  "--flag#keep", # comment\r\n  123,\r\n  """multi\r\nline""",\r\n]\r\n'
        'enabled = false # disabled here\r\n\r\n'
        '[mcp_servers."cx.quoted".env]\r\nAPI_KEY = "top-secret"\r\n\r\n'
        '[mcp_servers."cx.quoted".other]\r\nenabled = true\r\ncommand = "ignored"\r\n\r\n'
        '[mcp_servers.broken]\r\ncommand = "unterminated\r\nurl = "https://cx.example.com/sse"\r\n'
    )
    (home / ".codex" / "config.toml").write_bytes(toml_user.encode("utf-8"))
    (ws / ".codex").mkdir()
    (ws / ".codex" / "config.toml").write_text('[mcp_servers.cx-ws]\ncommand = "node"\nargs = [\'a\', \'b\']\n', encoding="utf-8")

    parsed = parse_codex_mcp_servers(toml_user)
    assert [p["name"] for p in parsed] == ["cx.quoted", "broken"]
    assert parsed[0]["enabled"] is False
    assert parsed[0]["command"] == "uvx"
    assert parsed[0]["args"] == ["--flag#keep", "multi\nline"]
    assert parsed[0]["env"] == {"API_KEY": "top-secret"}
    assert parsed[1]["command"] is None and parsed[1]["url"] == "https://cx.example.com/sse"

    inv = mcp_inventory.collect_mcp_inventory(home, ws)
    by_name = {(s["harness"], s["name"]): s for s in inv["servers"]}
    assert len(inv["config_issues"]) == 1
    assert inv["config_issues"][0]["harness"] == "antigravity"
    assert by_name[("antigravity", "ag-http")]["transport"] == "http"
    assert by_name[("antigravity", "ag-off")]["enabled"] is False
    assert by_name[("claude", "cl-user")]["scope"] == "user"
    assert by_name[("claude", "cl-proj")]["transport"] == "http"
    assert by_name[("claude", "cl-set")]["scope"] == "user"
    assert by_name[("claude", "cl-ws-on")]["enabled"] is True
    assert by_name[("claude", "cl-ws-disabled")]["enabled"] is False
    assert by_name[("cursor", "cur-off")]["enabled"] is False
    assert by_name[("codex", "cx.quoted")]["enabled"] is False
    assert by_name[("codex", "cx-ws")]["scope"] == "workspace"

    subset = mcp_inventory.collect_mcp_inventory(home, ws, harnesses=["claude", "cursor"])
    assert subset["harnesses_scanned"] == ["claude", "cursor"]
    assert {s["harness"] for s in subset["servers"]} == {"claude", "cursor"}


def test_antigravity_cached_and_cursor_bundled_spool_schemas_measure_accurately(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()

    # Antigravity configured + cached dir, plus cache-only dir
    (home / ".gemini" / "antigravity").mkdir(parents=True)
    (home / ".gemini" / "antigravity" / "mcp_config.json").write_text(
        json.dumps({"mcpServers": {"pg": {"command": "npx", "args": ["pg-mcp"]}}}), encoding="utf-8"
    )
    pg_cache = home / ".gemini" / "antigravity" / "mcp" / "pg"
    pg_cache.mkdir(parents=True)
    (pg_cache / "run_query.json").write_text('{"name":"run_query","description":"x"}', encoding="utf-8")
    (pg_cache / "list_tables.json").write_text('{"name":"list_tables"}', encoding="utf-8")
    (pg_cache / "instructions.md").write_text("Use parameterized SQL.\n", encoding="utf-8")

    ide_cache = home / ".gemini" / "antigravity" / "mcp" / "ide-tool"
    ide_cache.mkdir(parents=True)
    (ide_cache / "ping.json").write_text('{"name":"ping"}', encoding="utf-8")

    # Cursor bundled context-guard-spool (both by server name and by cg_spool.py command/arg)
    (ws / ".cursor").mkdir()
    (ws / ".cursor" / "mcp.json").write_text(
        json.dumps({
            "mcpServers": {
                "context-guard-spool": {"command": "python3", "args": ["/opt/cg/bin/cg_spool.py", "mcp", "--workspace", "${workspaceFolder}"]},
                "custom-spool-alias": {"command": "python3", "args": ["/opt/cg/bin/cg_spool.py", "mcp"]},
            }
        }),
        encoding="utf-8",
    )

    inv = mcp_inventory.collect_mcp_inventory(home, ws)
    by_name = {(s["harness"], s["name"]): s for s in inv["servers"]}

    pg = by_name[("antigravity", "pg")]
    expected_lazy = len(b"# pg\nLazy:\nlist_tables\nrun_query\n")
    expected_bytes = (pg_cache / "list_tables.json").stat().st_size + (pg_cache / "run_query.json").stat().st_size + (pg_cache / "instructions.md").stat().st_size
    assert pg["schema_status"] == "cached"
    assert pg["tool_names"] == ["list_tables", "run_query"]
    assert pg["tool_count"] == 2 and pg["tool_count_evidence"] == "measured"
    assert pg["lazy_listing_bytes"] == expected_lazy
    assert pg["lazy_listing_tokens"] == expected_lazy // 4
    assert pg["schema_bytes"] == expected_bytes and pg["schema_bytes_evidence"] == "measured"
    assert pg["estimated_tokens"] == expected_bytes // 4 and pg["token_evidence"] == "estimated"

    ide = by_name[("antigravity", "ide-tool")]
    assert ide["transport"] == "ide_managed"
    assert ide["source"] == "~/.gemini/antigravity/mcp/ide-tool"
    assert ide["schema_status"] == "cached" and ide["tool_count"] == 1

    expected_spool_bytes = len(json.dumps(SPOOL_MCP_TOOL_SCHEMAS, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    for alias in ("context-guard-spool", "custom-spool-alias"):
        sp = by_name[("cursor", alias)]
        assert sp["schema_status"] == "bundled"
        assert sp["tool_count"] == 3 and sp["tool_count_evidence"] == "measured"
        assert sp["tool_names"] == ["cg_spool_slice", "cg_spool_grep", "cg_spool_list"]
        assert sp["schema_bytes"] == expected_spool_bytes
        assert sp["estimated_tokens"] == expected_spool_bytes // 4

    assert inv["summary"]["completeness"] == "complete"
    assert inv["summary"]["known_tools_evidence"] == "measured"


def test_missing_schemas_and_empty_telemetry_report_unavailable_never_zero(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()

    # Empty inventory first
    empty_inv = mcp_inventory.collect_mcp_inventory(home, ws, None)
    assert empty_inv["summary"]["completeness"] == "empty"
    assert empty_inv["summary"]["known_tools_total"] is None
    assert empty_inv["summary"]["known_tools_evidence"] == "unavailable"
    assert empty_inv["summary"]["estimated_schema_tokens_total"] is None

    # Configured servers without schema caches + empty usage_state -> unavailable, never 0!
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"jira": {"command": "npx", "args": ["jira"]}}}), encoding="utf-8")
    empty_snap = token_usage.read_usage_snapshot(None, roots=token_usage.transcript_roots_for_home(home))
    assert empty_snap["component_use_since"] is None
    inv_no_tel = mcp_inventory.collect_mcp_inventory(home, ws, empty_snap)
    jira = inv_no_tel["servers"][0]
    assert jira["schema_status"] == "unavailable"
    assert jira["tool_count"] is None and jira["tool_count_evidence"] == "unavailable"
    assert jira["schema_bytes"] is None and jira["schema_bytes_evidence"] == "unavailable"
    assert jira["estimated_tokens"] is None and jira["token_evidence"] == "unavailable"
    assert jira["calls_30d"] is None and jira["calls_evidence"] == "unavailable"
    assert inv_no_tel["summary"]["completeness"] == "partial"
    assert inv_no_tel["summary"]["known_tools_total"] is None
    assert inv_no_tel["summary"]["known_tools_evidence"] == "unavailable"

    # Now provide usage history with 0 calls for jira, plus preamble_parts + synthetic mcp:ccd_slack + Cursor bundled
    (ws / ".cursor").mkdir()
    (ws / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"context-guard-spool": {"command": "python3", "args": ["cg_spool.py"]}}}), encoding="utf-8")
    usage_state = {
        "totals": {"claude|claude-sonnet-4-6": {"input": 1000, "output": 50, "cache_read": 0, "cache_write": 0, "events": 1, "total_only": 0}},
        "component_use": {"2026-11-15": {"mcp:ccd_slack": 4}, "2026-11-16": {"mcp:ccd_slack": 2}},
        "preamble_parts": [
            {"measured": 8000, "components": {"deferred_tools": {"mcp:jira": 200, "mcp:ccd_slack": 300}, "mcp_instructions": {"mcp:jira": 50}}},
            {"measured": 8200, "components": {"deferred_tools": {"mcp:jira": 220, "mcp:ccd_slack": 500}, "mcp_instructions": {"mcp:jira": 70}}},
        ],
        "codex_preamble_parts": [
            {"measured": 4000, "cohort": "codex (cli)", "components": {"deferred_tools": {"mcp:cx_app": 150}}},
        ],
    }
    inv_hist = mcp_inventory.collect_mcp_inventory(home, ws, usage_state)
    by_key = {(s["harness"], s["normalized_key"]): s for s in inv_hist["servers"]}

    jira_h = by_key[("claude", "mcp:jira")]
    assert jira_h["calls_30d"] == 0 and jira_h["calls_evidence"] == "measured"
    assert jira_h["schema_status"] == "transcript_only"
    assert jira_h["tool_count"] is None and jira_h["schema_bytes"] is None
    assert jira_h["transcript_preamble_tokens"] == 270 and jira_h["transcript_tokens_evidence"] == "measured"

    ccd = by_key[("claude", "mcp:ccd_slack")]
    assert ccd["scope"] == "ide_managed" and ccd["source"] == "transcript_ledger" and ccd["transport"] == "ide_managed"
    assert ccd["calls_30d"] == 6 and ccd["transcript_preamble_tokens"] == 400

    cx_syn = by_key[("codex", "mcp:cx_app")]
    assert cx_syn["schema_status"] == "transcript_only" and cx_syn["transcript_preamble_tokens"] == 150

    assert inv_hist["summary"]["completeness"] == "partial"
    assert inv_hist["summary"]["known_tools_total"] == 3
    assert inv_hist["summary"]["known_tools_evidence"] == "partial"
    assert inv_hist["summary"]["estimated_schema_tokens_evidence"] == "partial"


def test_redacts_env_secrets_url_tokens_and_home_paths(tmp_path: Path) -> None:
    alice_home = tmp_path / "Users" / "alice"
    ws = alice_home / "projects" / "app"
    alice_home.mkdir(parents=True)
    ws.mkdir(parents=True)

    (alice_home / ".claude.json").write_text(
        json.dumps({
            "mcpServers": {
                "secret-stdio": {
                    "command": "/Users/alice/bin/my-secret-tool",
                    "args": ["--bearer", "arg-bearer-secret-111", "/Users/alice/private/key.pem"],
                    "cwd": "/Users/alice/projects/app",
                    "env": {"OPENAI_API_KEY": "sk-openai-secret-222", "GITLAB_TOKEN": "glpat-secret-333"},
                },
                "secret-http": {
                    "type": "http",
                    "url": "https://api.example.com/mcp?token=url-secret-444",
                    "headers": {"Authorization": "Basic YWxpY2U6c2VjcmV0NTU1"},
                },
            }
        }),
        encoding="utf-8",
    )
    (alice_home / ".cursor").mkdir()
    (alice_home / ".cursor" / "mcp.json").write_text("{broken json", encoding="utf-8")
    (alice_home / ".codex").mkdir()
    (alice_home / ".codex" / "config.toml").write_text(
        '[mcp_servers.win-srv]\ncommand = "C:\\\\Users\\\\alice\\\\tools\\\\win-mcp.exe"\n'
        'args = ["--token=codex-arg-secret-666"]\n\n[mcp_servers.win-srv.env]\nOPENAI_API_KEY = "sk-codex-secret-777"\n',
        encoding="utf-8",
    )

    assert mcp_inventory.format_display_path(ws / ".mcp.json", alice_home, ws) == "<workspace>/.mcp.json"
    assert mcp_inventory.format_display_path(alice_home / ".claude.json", alice_home, ws) == "~/.claude.json"
    assert mcp_inventory.format_display_path(Path("C:\\Users\\alice\\.cursor\\mcp.json"), alice_home, ws) == "~/.cursor/mcp.json"

    inv = mcp_inventory.collect_mcp_inventory(alice_home, ws)
    serialized = json.dumps(inv)
    for forbidden in (
        "OPENAI_API_KEY", "GITLAB_TOKEN", "sk-openai-secret-222", "glpat-secret-333",
        "url-secret-444", "YWxpY2U6c2VjcmV0NTU1", "arg-bearer-secret-111",
        "codex-arg-secret-666", "sk-codex-secret-777", "/Users/alice", "C:\\Users\\alice",
    ):
        assert forbidden not in serialized

    by_name = {s["name"]: s for s in inv["servers"]}
    assert by_name["secret-stdio"]["command_basename"] == "my-secret-tool"
    assert by_name["win-srv"]["command_basename"] == "win-mcp.exe"
    assert inv["config_issues"][0]["path"] == "~/.cursor/mcp.json"


def test_detects_duplicate_servers_tool_names_and_native_overlaps(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()

    # Antigravity caches two active servers + one disabled server
    ag_dir = home / ".gemini" / "antigravity"
    ag_dir.mkdir(parents=True)
    (ag_dir / "mcp_config.json").write_text(
        json.dumps({"mcpServers": {"fs": {"command": "npx"}, "gitx": {"command": "npx"}, "off-srv": {"command": "npx", "disabled": True}}}),
        encoding="utf-8",
    )
    for srv_name, tools in (
        ("fs", ["read_file", "write_file", "grep_search", "shared_tool"]),
        ("gitx", ["git_status", "bash", "shared_tool"]),
        ("off-srv", ["read_file", "shared_tool"]),
    ):
        cdir = ag_dir / "mcp" / srv_name
        cdir.mkdir(parents=True)
        for t in tools:
            (cdir / f"{t}.json").write_text("{}", encoding="utf-8")

    # Claude defines `gh` in BOTH user (~/.claude.json) and workspace (.mcp.json)
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"gh": {"command": "npx"}}}), encoding="utf-8")
    (ws / ".mcp.json").write_text(json.dumps({"mcpServers": {"gh": {"command": "npx"}}}), encoding="utf-8")

    inv = mcp_inventory.collect_mcp_inventory(home, ws)
    overlaps = inv["overlaps"]
    kinds = {(o["kind"], o.get("category") or o.get("tool_name") or o.get("normalized_key")): o for o in overlaps}

    assert ("duplicate_server_definition", "mcp:gh") in kinds
    assert ("duplicate_tool_name", "shared_tool") in kinds
    assert kinds[("duplicate_tool_name", "shared_tool")]["servers"] == ["fs", "gitx"]
    assert ("native_tool_overlap", "file_read") in kinds
    assert ("native_tool_overlap", "file_write") in kinds
    assert ("native_tool_overlap", "filesystem_list") in kinds
    assert ("native_tool_overlap", "git_cli") in kinds
    assert ("native_tool_overlap", "shell_exec") in kinds
    assert all("off-srv" not in json.dumps(o) for o in overlaps)


def test_probe_ndjson_and_content_length_servers_and_enforces_timeout_and_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ndjson_srv = tmp_path / "ndjson_srv.py"
    _write_probe_script(
        ndjson_srv,
        "import json, sys\n"
        "tools = [{'name': 'alpha', 'inputSchema': {'type': 'object'}}, {'name': 'beta', 'inputSchema': {'type': 'object'}}]\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    if msg.get('method') == 'initialize':\n"
        "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'protocolVersion': '2024-11-05'}}) + '\\n')\n"
        "        sys.stdout.flush()\n"
        "    elif msg.get('method') == 'tools/list':\n"
        "        sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'tools': tools}}) + '\\n')\n"
        "        sys.stdout.flush()\n",
    )

    lsp_srv = tmp_path / "lsp_srv.py"
    _write_probe_script(
        lsp_srv,
        "import json, sys\n"
        "def send(obj):\n"
        "    raw = json.dumps(obj, separators=(',', ':')).encode('utf-8')\n"
        "    sys.stdout.buffer.write(f'Content-Type: application/vscode-jsonrpc\\r\\nContent-Length: {len(raw)}\\r\\n\\r\\n'.encode('ascii') + raw)\n"
        "    sys.stdout.buffer.flush()\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    if msg.get('method') == 'initialize':\n"
        "        send({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'protocolVersion': '2024-11-05'}})\n"
        "    elif msg.get('method') == 'tools/list':\n"
        "        send({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'tools': [{'name': 'gamma'}]}})\n",
    )

    hang_srv = tmp_path / "hang_srv.py"
    _write_probe_script(hang_srv, "import time\ntime.sleep(10)\n")
    bad_srv = tmp_path / "bad_srv.py"
    _write_probe_script(bad_srv, "import sys\nsys.stdout.write('not-json\\n')\nsys.stdout.flush()\n")
    noisy_srv = tmp_path / "noisy_srv.py"
    _write_probe_script(noisy_srv, "import sys\nsys.stdout.write('{' + ('x' * 1024) + '\\n')\nsys.stdout.flush()\n")

    r_ndjson = mcp_inventory.probe_stdio_mcp_server(sys.executable, [str(ndjson_srv)], timeout_s=2.0)
    r_lsp = mcp_inventory.probe_stdio_mcp_server(sys.executable, [str(lsp_srv)], timeout_s=2.0)
    r_hang = mcp_inventory.probe_stdio_mcp_server(sys.executable, [str(hang_srv)], timeout_s=0.2)
    r_enoent = mcp_inventory.probe_stdio_mcp_server("nonexistent_cmd_404_xyz")
    r_bad = mcp_inventory.probe_stdio_mcp_server(sys.executable, [str(bad_srv)], timeout_s=1.0)
    r_noisy = mcp_inventory.probe_stdio_mcp_server(sys.executable, [str(noisy_srv)], timeout_s=1.0, max_stdout_bytes=256)

    assert r_ndjson["probe_status"] == "ok" and r_ndjson["tool_names"] == ["alpha", "beta"] and r_ndjson["tool_count"] == 2
    assert r_lsp["probe_status"] == "ok" and r_lsp["tool_names"] == ["gamma"] and r_lsp["tool_count"] == 1
    assert r_hang["probe_status"] == "timeout" and r_hang["probe_duration_ms"] < 4000.0
    assert r_enoent["probe_status"] == "spawn_error"
    assert r_bad["probe_status"] == "protocol_error"
    assert r_noisy["probe_status"] == "output_exceeded"

    # End-to-end collect_mcp_inventory(..., probe=True): remote skip, missing workspace skip, resolved workspace, Codex / 5
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()
    (ws / "local_ndjson.py").write_text(ndjson_srv.read_text(encoding="utf-8"), encoding="utf-8")
    (home / ".claude.json").write_text(
        json.dumps({
            "mcpServers": {
                "remote": {"type": "http", "url": "https://r.example.com"},
                "needs-ws": {"command": sys.executable, "args": ["${workspaceFolder}/local_ndjson.py"]},
            }
        }),
        encoding="utf-8",
    )
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text(
        f'[mcp_servers.cx-ndjson]\ncommand = "{sys.executable.replace(chr(92), "/")}"\nargs = ["{str(ndjson_srv).replace(chr(92), "/")}"]\n',
        encoding="utf-8",
    )

    inv_no_ws = mcp_inventory.collect_mcp_inventory(home, None, probe=True, probe_timeout_s=2.0)
    assert inv_no_ws["mode"] == "probe" and inv_no_ws["probe_warning"] == mcp_inventory.PROBE_SIDE_EFFECT_WARNING
    by_no_ws = {s["name"]: s for s in inv_no_ws["servers"]}
    assert by_no_ws["remote"]["probe_status"] == "skipped_remote_transport"
    assert by_no_ws["needs-ws"]["probe_status"] == "skipped_missing_workspace"
    cx_res = by_no_ws["cx-ndjson"]
    assert cx_res["probe_status"] == "ok" and cx_res["schema_status"] == "probed"
    assert cx_res["estimated_tokens"] == cx_res["schema_bytes"] // CODEX_TOOL_BYTES_PER_TOKEN

    inv_with_ws = mcp_inventory.collect_mcp_inventory(home, ws, probe=True, probe_servers=["needs-ws"], probe_timeout_s=2.0)
    by_ws = {s["name"]: s for s in inv_with_ws["servers"]}
    assert by_ws["needs-ws"]["probe_status"] == "ok" and by_ws["needs-ws"]["estimated_tokens"] == by_ws["needs-ws"]["schema_bytes"] // 4
    assert by_ws["cx-ndjson"]["probe_status"] == "not_probed"

    # MAX_PROBE_SERVERS cap enforcement
    many_srvs = {f"s{i:02d}": {"command": "echo", "args": [str(i)]} for i in range(mcp_inventory.MAX_PROBE_SERVERS + 2)}
    (home / ".claude.json").write_text(json.dumps({"mcpServers": many_srvs}), encoding="utf-8")
    (home / ".codex" / "config.toml").unlink()
    monkeypatch.setattr(
        mcp_inventory,
        "probe_stdio_mcp_server",
        lambda *a, **kw: {"probe_status": "ok", "tool_names": ["t"], "tool_count": 1, "schema_bytes": 40, "estimated_tokens": 10, "probe_duration_ms": 1.0, "probe_error": None},
    )
    inv_cap = mcp_inventory.collect_mcp_inventory(home, ws, probe=True)
    assert inv_cap["summary"]["probed_ok"] == mcp_inventory.MAX_PROBE_SERVERS
    assert sum(1 for s in inv_cap["servers"] if s["probe_status"] == "skipped_probe_limit") == 2
