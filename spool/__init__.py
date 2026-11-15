"""Context-Guard reversible output spooling package and stdio MCP recovery server."""

from __future__ import annotations

from spool.mcp_server import serve_stdio, sync_cursor_spool_mcp
from spool.store import (
    build_post_tool_spool_response,
    classify_pre_tool_spool_followup,
    compute_command_signature,
    gc_spools,
    grep_spool,
    inspect_spool_health,
    is_verbose_override_command,
    list_spools,
    resolve_spool_dir,
    slice_spool,
    spool_tool_output,
)

__all__ = [
    "build_post_tool_spool_response",
    "classify_pre_tool_spool_followup",
    "compute_command_signature",
    "gc_spools",
    "grep_spool",
    "inspect_spool_health",
    "is_verbose_override_command",
    "list_spools",
    "resolve_spool_dir",
    "serve_stdio",
    "slice_spool",
    "spool_tool_output",
    "sync_cursor_spool_mcp",
]
