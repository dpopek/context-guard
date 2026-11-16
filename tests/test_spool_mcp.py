from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

import pytest

from bin.migration_guard import RollbackJournal
from spool.mcp_server import is_cursor_spool_mcp_configured, serve_stdio, sync_cursor_spool_mcp
from spool.store import spool_tool_output

REPO_ROOT = Path(__file__).resolve().parent.parent


def encode_lsp(payload: Any) -> bytes:
    """Encode a JSON value as an LSP Content-Length frame."""
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def parse_lsp_stream(raw: bytes) -> list[dict[str, Any]]:
    """Decode all LSP Content-Length frames from a byte buffer."""
    frames: list[dict[str, Any]] = []
    pos = 0
    while pos < len(raw):
        sep = raw.find(b"\r\n\r\n", pos)
        assert sep != -1, f"Missing LSP header terminator at offset {pos}"
        hdr = raw[pos:sep].decode("ascii")
        assert hdr.lower().startswith("content-length:")
        length = int(hdr.split(":", 1)[1].strip())
        start = sep + 4
        end = start + length
        assert end <= len(raw)
        frames.append(json.loads(raw[start:end].decode("utf-8")))
        pos = end
    return frames


def seed_sample_spool(spool_dir: Path, workspace_root: Path | None = None) -> str:
    """Create a deterministic spooled output entry and return its spool_id."""
    lines = [f"entry-{i:04d} " + ("d" * 70) for i in range(1, 221)]
    lines[119] = "entry-0120 ALERT_TOKEN " + ("d" * 60)
    res = spool_tool_output(
        "\n".join(lines) + "\n",
        session_id="mcp-sess",
        call_id="mcp-c1",
        harness="cursor",
        tool_name="MCP:demo:logs",
        workspace_root=workspace_root or REPO_ROOT,
        spool_dir=spool_dir,
        now_ts=1_700_000_500.0,
    )
    assert res is not None
    return res[0].spool_id


def test_mcp_server_ndjson_initialize_ping_list_call_and_errors(tmp_path: Path) -> None:
    """Verify NDJSON initialize version lookup, ping, tools/list, tools/call, and JSON-RPC errors."""
    spool_dir = tmp_path / "spool"
    sid = seed_sample_spool(spool_dir)
    expected_version = json.loads((REPO_ROOT / "plugin.json").read_text(encoding="utf-8"))["version"]

    requests: list[bytes] = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}).encode("utf-8"),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode("utf-8"),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).encode("utf-8"),
        json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {"session_id": "mcp-sess"}}}).encode("utf-8"),
        json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid, "start_line": 119, "limit": 3}}}).encode("utf-8"),
        json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "cg_spool_grep", "arguments": {"spool_id": sid, "pattern": "ALERT_TOKEN"}}}).encode("utf-8"),
        b"{not valid json",
        b"[1, 2, 3]",
        json.dumps({"jsonrpc": "2.0", "id": 7, "method": "unknown/method"}).encode("utf-8"),
        json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "unknown_tool", "arguments": {}}}).encode("utf-8"),
        json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid, "limit": True}}}).encode("utf-8"),
        json.dumps({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "cg_spool_grep", "arguments": {"spool_id": sid, "pattern": "[unclosed"}}}).encode("utf-8"),
    ]
    in_buf = io.BytesIO(b"\n".join(requests) + b"\n")
    out_buf = io.BytesIO()

    rc = serve_stdio(spool_dir=spool_dir, stdin=in_buf, stdout=out_buf, plugin_root=REPO_ROOT, workspace_root=REPO_ROOT)
    assert rc == 0
    replies = [json.loads(line.decode("utf-8")) for line in out_buf.getvalue().splitlines() if line.strip()]
    assert len(replies) == 12

    init_res = replies[0]["result"]
    assert init_res["serverInfo"]["name"] == "context-guard-spool"
    assert init_res["serverInfo"]["version"] == expected_version
    assert replies[1]["result"] == {}
    tool_names = [t["name"] for t in replies[2]["result"]["tools"]]
    assert tool_names == ["cg_spool_slice", "cg_spool_grep", "cg_spool_list"]

    list_body = json.loads(replies[3]["result"]["content"][0]["text"])
    assert replies[3]["result"]["isError"] is False
    assert list_body["count"] == 1 and list_body["entries"][0]["spool_id"] == sid

    slice_body = json.loads(replies[4]["result"]["content"][0]["text"])
    assert replies[4]["result"]["isError"] is False
    assert "ALERT_TOKEN" in slice_body["content"]

    grep_body = json.loads(replies[5]["result"]["content"][0]["text"])
    assert grep_body["match_count"] == 1 and grep_body["matches"][0]["line"] == 120

    assert replies[6]["error"]["code"] == -32700
    assert replies[7]["error"]["code"] == -32600
    assert replies[8]["error"]["code"] == -32601
    assert replies[9]["error"]["code"] == -32601
    assert replies[10]["error"]["code"] == -32602
    assert replies[11]["result"]["isError"] is True
    assert "invalid_regex" in json.loads(replies[11]["result"]["content"][0]["text"])["error"]

    # Confirm dynamic plugin.json version override on a custom plugin_root.
    alt_root = tmp_path / "alt_plugin"
    alt_root.mkdir()
    (alt_root / "plugin.json").write_text(json.dumps({"version": "9.8.7"}), encoding="utf-8")
    alt_out = io.BytesIO()
    assert serve_stdio(
        spool_dir=spool_dir,
        stdin=io.BytesIO(json.dumps({"jsonrpc": "2.0", "id": 99, "method": "initialize"}).encode("utf-8") + b"\n"),
        stdout=alt_out,
        plugin_root=alt_root,
        workspace_root=REPO_ROOT,
    ) == 0
    assert json.loads(alt_out.getvalue().decode("utf-8"))["result"]["serverInfo"]["version"] == "9.8.7"


def test_mcp_server_content_length_framing_matches_input_mode_and_notifications(tmp_path: Path) -> None:
    """Reply strictly in LSP Content-Length framing and emit zero bytes for notifications."""
    spool_dir = tmp_path / "spool"
    seed_sample_spool(spool_dir)

    raw_in = b"".join(
        [
            encode_lsp({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            encode_lsp({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            encode_lsp({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            encode_lsp({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {}}}),
            b"Content-Length: notanumber\r\n\r\n",
        ]
    )
    out_buf = io.BytesIO()
    rc = serve_stdio(spool_dir=spool_dir, stdin=io.BytesIO(raw_in), stdout=out_buf, plugin_root=REPO_ROOT, workspace_root=REPO_ROOT)
    assert rc == 0

    frames = parse_lsp_stream(out_buf.getvalue())
    assert [f.get("id") for f in frames] == [1, 2, 3, None]
    assert frames[0]["result"]["serverInfo"]["name"] == "context-guard-spool"
    assert len(frames[1]["result"]["tools"]) == 3
    assert json.loads(frames[2]["result"]["content"][0]["text"])["count"] == 1
    assert frames[3]["error"]["code"] == -32700


def test_mcp_server_subprocess_eof_and_tool_execution_errors(tmp_path: Path) -> None:
    """Spawn bin/cg_spool.py mcp over stdio, exercise tool errors, and exit 0 on EOF."""
    spool_dir = tmp_path / "spool"
    sid = seed_sample_spool(spool_dir)

    payload = b"\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode("utf-8"),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": "sp_000000000000"}}}).encode("utf-8"),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cg_spool_grep", "arguments": {"spool_id": sid, "pattern": "("}}}).encode("utf-8"),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {}}}).encode("utf-8"),
        ]
    ) + b"\n"

    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "bin" / "cg_spool.py"), "mcp", "--spool-dir", str(spool_dir), "--workspace", str(REPO_ROOT)],
        cwd=str(REPO_ROOT),
        input=payload,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stderr == b""
    lines = [json.loads(line.decode("utf-8")) for line in proc.stdout.splitlines() if line.strip()]
    assert [row["id"] for row in lines] == [1, 2, 3, 4]
    assert lines[1]["result"]["isError"] is True
    assert json.loads(lines[1]["result"]["content"][0]["text"])["error"] == "spool_not_found"
    assert lines[2]["result"]["isError"] is True
    assert "invalid_regex" in json.loads(lines[2]["result"]["content"][0]["text"])["error"]
    assert lines[3]["result"]["isError"] is False


def test_sync_cursor_spool_mcp_preserves_foreign_servers_and_never_creates_empty_file(tmp_path: Path) -> None:
    """Sync context-guard-spool safely without clobbering foreign servers or creating empty files."""
    mcp_path = tmp_path / ".cursor" / "mcp.json"

    assert sync_cursor_spool_mcp(mcp_path, REPO_ROOT, enabled=False) == "absent"
    assert not mcp_path.exists()

    assert sync_cursor_spool_mcp(mcp_path, REPO_ROOT, enabled=True, dry_run=True) == "created"
    assert not mcp_path.exists()

    assert sync_cursor_spool_mcp(mcp_path, REPO_ROOT, enabled=True, py_executable="/opt/py/bin/python3") == "created"
    assert mcp_path.exists()
    if os.name != "nt":
        assert stat.S_IMODE(mcp_path.stat().st_mode) == 0o600
    assert sync_cursor_spool_mcp(mcp_path, REPO_ROOT, enabled=True, py_executable="/opt/py/bin/python3") == "unchanged"

    # Populate foreign server + top-level keys, ensure non-destructive update and removal.
    seed_cfg = {
        "mcpServers": {"foreign-srv": {"command": "node", "args": ["index.js"]}},
        "customSetting": {"keep": True},
    }
    mcp_path.write_text(json.dumps(seed_cfg, indent=2), encoding="utf-8")

    assert sync_cursor_spool_mcp(mcp_path, REPO_ROOT, enabled=True, py_executable="python3") == "updated"
    updated = json.loads(mcp_path.read_text(encoding="utf-8"))
    assert updated["customSetting"] == {"keep": True}
    assert updated["mcpServers"]["foreign-srv"] == {"command": "node", "args": ["index.js"]}
    assert updated["mcpServers"]["context-guard-spool"] == {
        "command": "python3",
        "args": [str((REPO_ROOT / "bin" / "cg_spool.py").resolve()), "mcp", "--workspace", "${workspaceFolder}"],
    }
    assert is_cursor_spool_mcp_configured(mcp_path) is True

    assert sync_cursor_spool_mcp(mcp_path, REPO_ROOT, enabled=False) == "removed"
    assert is_cursor_spool_mcp_configured(mcp_path) is False
    after_remove = json.loads(mcp_path.read_text(encoding="utf-8"))
    assert "context-guard-spool" not in after_remove["mcpServers"]
    assert after_remove["mcpServers"]["foreign-srv"] == {"command": "node", "args": ["index.js"]}
    assert after_remove["customSetting"] == {"keep": True}
    assert sync_cursor_spool_mcp(mcp_path, REPO_ROOT, enabled=False) == "unchanged"

    bad_path = tmp_path / "bad.json"
    bad_path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        sync_cursor_spool_mcp(bad_path, REPO_ROOT, enabled=True)

    if os.name != "nt":
        link_path = tmp_path / "link_mcp.json"
        link_path.symlink_to(mcp_path)
        with pytest.raises(OSError):
            sync_cursor_spool_mcp(link_path, REPO_ROOT, enabled=True)


def test_sync_cursor_spool_mcp_rollback_journal_restores_on_exception(tmp_path: Path) -> None:
    """Restore existing mcp.json and remove newly created mcp.json when RollbackJournal aborts."""
    existing = tmp_path / "existing_mcp.json"
    initial_text = json.dumps({"mcpServers": {"foreign": {"command": "echo"}}}, indent=2) + "\n"
    existing.write_text(initial_text, encoding="utf-8")

    with pytest.raises(RuntimeError):
        with RollbackJournal() as journal:
            status = sync_cursor_spool_mcp(existing, REPO_ROOT, enabled=True, journal=journal)
            assert status == "updated"
            assert "context-guard-spool" in json.loads(existing.read_text(encoding="utf-8"))["mcpServers"]
            raise RuntimeError("abort install")

    assert existing.read_text(encoding="utf-8") == initial_text

    fresh = tmp_path / "fresh_mcp.json"
    with pytest.raises(RuntimeError):
        with RollbackJournal() as journal:
            status = sync_cursor_spool_mcp(fresh, REPO_ROOT, enabled=True, journal=journal)
            assert status == "created"
            assert fresh.exists()
            raise RuntimeError("abort fresh install")

    assert not fresh.exists()
