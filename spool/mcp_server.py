"""Dual-framed JSON-RPC 2.0 stdio MCP server and Cursor `.cursor/mcp.json` synchronizer."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, BinaryIO, Mapping

from hooks import state_store
from spool.store import grep_spool, list_spools, resolve_spool_dir, slice_spool

_SERVER_NAME = "context-guard-spool"
_DEFAULT_PROTOCOL_VERSION = "2024-11-05"

_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "cg_spool_slice",
        "description": "Read a bounded line slice from a Context-Guard spooled tool output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "spool_id": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1, "default": 1},
                "limit": {"type": "integer", "minimum": 1, "default": 120}, "end_line": {"type": "integer", "minimum": 1},
            },
            "required": ["spool_id"], "additionalProperties": False,
        },
    },
    {
        "name": "cg_spool_grep",
        "description": "Search a Context-Guard spooled tool output with a regular expression.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "spool_id": {"type": "string"}, "pattern": {"type": "string"},
                "ignore_case": {"type": "boolean", "default": False},
                "max_matches": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
                "context_lines": {"type": "integer", "minimum": 0, "maximum": 10, "default": 0},
            },
            "required": ["spool_id", "pattern"], "additionalProperties": False,
        },
    },
    {
        "name": "cg_spool_list",
        "description": "List available spooled tool outputs newest-first.",
        "inputSchema": {
            "type": "object", "properties": {"session_id": {"type": "string"}},
            "required": [], "additionalProperties": False,
        },
    },
]

def _load_plugin_version(plugin_root: Path | None = None) -> str:
    root = Path(plugin_root) if plugin_root is not None else state_store.resolve_plugin_root()
    try:
        data = json.loads((root / "plugin.json").read_text(encoding="utf-8"))
        if isinstance(data, Mapping) and isinstance(data.get("version"), str) and data["version"].strip():
            return data["version"].strip()
    except (OSError, ValueError, TypeError):
        pass
    return "0.0.0"

def _read_exact(stream: BinaryIO, count: int) -> bytes:
    chunks, remaining = [], count
    while remaining > 0 and (chunk := stream.read(remaining)):
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def _read_frame(stream: BinaryIO) -> tuple[str, bytes | None, bool]:
    while True:
        if not (raw_line := stream.readline()):
            return "ndjson", None, False
        if raw_line.strip():
            break
    if raw_line.lower().startswith((b"content-length:", b"content-type:")):
        headers = [raw_line]
        while (hdr_line := stream.readline()) and hdr_line not in (b"\r\n", b"\n"):
            headers.append(hdr_line)
        content_len: int | None = None
        for hdr in headers:
            text = hdr.decode("ascii", errors="replace").strip()
            if text.lower().startswith("content-length:") and (rv := text.split(":", 1)[1].strip()).isdigit():
                content_len = int(rv)
        if content_len is None or content_len < 0:
            return "lsp", b"", True
        body = _read_exact(stream, content_len)
        return ("lsp", b"", True) if len(body) < content_len else ("lsp", body, False)
    return "ndjson", raw_line.strip(), False

def _write_frame(stream: BinaryIO, framing: str, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    stream.write((f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw) if framing == "lsp" else (raw + b"\n"))
    stream.flush()

def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

def _is_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)

def _dispatch_tool_call(req_id: Any, params: Any, eff_dir: Path | None) -> dict[str, Any]:
    if not isinstance(params, Mapping) or not isinstance((name := params.get("name")), str):
        return _rpc_error(req_id, -32602, "Invalid params: expected tool 'name'")
    raw_args = params.get("arguments")
    if raw_args is None:
        args: Mapping[str, Any] = {}
    elif isinstance(raw_args, Mapping):
        args = raw_args
    else:
        return _rpc_error(req_id, -32602, "Invalid params: 'arguments' must be an object")

    if name == "cg_spool_slice":
        sid, sl, lim, el = args.get("spool_id"), args.get("start_line", 1), args.get("limit", 120), args.get("end_line")
        if not isinstance(sid, str) or not sid.strip() or not _is_int(sl) or not _is_int(lim) or (el is not None and not _is_int(el)):
            return _rpc_error(req_id, -32602, "Invalid params: cg_spool_slice requires valid 'spool_id' and integer bounds")
        res = slice_spool(sid.strip(), start_line=int(sl), limit=int(lim), end_line=el, spool_dir=eff_dir)
    elif name == "cg_spool_grep":
        sid, pat, ic, mm, ctx = args.get("spool_id"), args.get("pattern"), args.get("ignore_case", False), args.get("max_matches", 50), args.get("context_lines", 0)
        if not isinstance(sid, str) or not sid.strip() or not isinstance(pat, str) or not isinstance(ic, bool) or not _is_int(mm) or not _is_int(ctx):
            return _rpc_error(req_id, -32602, "Invalid params: cg_spool_grep requires valid 'spool_id', 'pattern', and options")
        res = grep_spool(sid.strip(), pat, ignore_case=ic, max_matches=int(mm), context_lines=int(ctx), spool_dir=eff_dir)
    elif name == "cg_spool_list":
        sess = args.get("session_id")
        if sess is not None and not isinstance(sess, str):
            return _rpc_error(req_id, -32602, "Invalid params: 'session_id' must be a string")
        res = list_spools(session_id=sess, spool_dir=eff_dir)
    else:
        return _rpc_error(req_id, -32601, f"Unknown tool: {name}")
    return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(res)}], "isError": not bool(res.get("ok"))}}

def _handle_rpc_message(msg: Mapping[str, Any], eff_dir: Path | None, version: str) -> dict[str, Any] | None:
    if "id" not in msg:
        return None
    req_id, method, params = msg["id"], msg.get("method"), msg.get("params")
    if not isinstance(method, str):
        return _rpc_error(req_id, -32600, "Invalid Request")
    if method == "initialize":
        proto = str(params["protocolVersion"]) if isinstance(params, Mapping) and isinstance(params.get("protocolVersion"), str) and params["protocolVersion"] else _DEFAULT_PROTOCOL_VERSION
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": proto, "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": _SERVER_NAME, "version": version},
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": _TOOL_SCHEMAS}}
    if method == "tools/call":
        return _dispatch_tool_call(req_id, params, eff_dir)
    return _rpc_error(req_id, -32601, f"Method not found: {method}")

def serve_stdio(
    *, spool_dir: Path | None = None, stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None, plugin_root: Path | None = None,
) -> int:
    """Serve JSON-RPC 2.0 MCP spool tools over stdio supporting NDJSON and LSP Content-Length."""
    in_stream: BinaryIO = stdin if stdin is not None else sys.stdin.buffer
    out_stream: BinaryIO = stdout if stdout is not None else sys.stdout.buffer
    eff_dir, version = (spool_dir if spool_dir is not None else resolve_spool_dir()), _load_plugin_version(plugin_root)
    while True:
        framing, body, header_err = _read_frame(in_stream)
        if body is None:
            return 0
        if header_err:
            _write_frame(out_stream, framing, _rpc_error(None, -32700, "Parse error"))
            continue
        try:
            msg = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            _write_frame(out_stream, framing, _rpc_error(None, -32700, "Parse error"))
            continue
        if not isinstance(msg, Mapping):
            _write_frame(out_stream, framing, _rpc_error(None, -32600, "Invalid Request"))
            continue
        if (reply := _handle_rpc_message(msg, eff_dir, version)) is not None:
            _write_frame(out_stream, framing, reply)

def _is_unsafe_link(path: Path) -> bool:
    try:
        st = os.lstat(str(path))
        return stat.S_ISLNK(st.st_mode) or bool(
            getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    except FileNotFoundError:
        return False
    except OSError:
        return True

def _write_json_atomic(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        if os.name != "nt":
            os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(path))
    except OSError:
        Path(tmp_path).unlink(missing_ok=True)
        raise

def sync_cursor_spool_mcp(
    mcp_path: Path, plugin_root: Path, *, enabled: bool,
    py_executable: str | None = None, dry_run: bool = False, journal: Any = None,
) -> str:
    """Non-destructively sync `context-guard-spool` in Cursor `mcp.json`."""
    target = Path(mcp_path).expanduser()
    if _is_unsafe_link(target):
        raise OSError(f"Refusing symlink/reparse point: {target}")
    desired = {
        "command": py_executable or sys.executable or "python3",
        "args": [str((Path(plugin_root) / "bin" / "cg_spool.py").resolve()), "mcp"],
    }
    if not target.exists():
        if not enabled:
            return "absent"
        if not dry_run:
            if journal is not None:
                journal.record_file_backup(target)
            _write_json_atomic(target, {"mcpServers": {_SERVER_NAME: desired}})
        return "created"
    raw = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Expected JSON object in {target}")
    servers = raw.get("mcpServers")
    if not enabled:
        if not isinstance(servers, Mapping) or _SERVER_NAME not in servers:
            return "unchanged"
        if not dry_run:
            if journal is not None:
                journal.record_file_backup(target)
            _write_json_atomic(target, {**raw, "mcpServers": {k: v for k, v in servers.items() if k != _SERVER_NAME}})
        return "removed"
    if servers is not None and not isinstance(servers, Mapping):
        raise ValueError(f"Expected 'mcpServers' object in {target}")
    servers_map = dict(servers) if isinstance(servers, Mapping) else {}
    if servers_map.get(_SERVER_NAME) == desired:
        return "unchanged"
    servers_map[_SERVER_NAME] = desired
    if not dry_run:
        if journal is not None:
            journal.record_file_backup(target)
        _write_json_atomic(target, {**raw, "mcpServers": servers_map})
    return "updated"
