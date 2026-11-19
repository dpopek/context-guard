"""Cursor MCP JSON decoding, passthrough safety guards, and object wire-output spool tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.contracts import SpoolDecision
from hooks import config
from hooks.harness_adapter import format_post_tool_spool_response
from hooks.post_tool_use import handle_post_tool_use
from spool.classifier import (
    extract_tool_payload_text,
    format_spooled_tool_output,
    prepare_post_tool_spool_candidate,
)
from spool.store import slice_spool, spool_post_tool_output


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    (repo / ".git").mkdir(parents=True, exist_ok=True)
    return repo


def _make_lines(count: int, *, prefix: str = "row", width: int = 84) -> str:
    pad = "x" * max(1, width - len(prefix) - 8)
    return "\n".join(f"{prefix}-{idx:04d} {pad}" for idx in range(1, count + 1)) + "\n"


def _run_cursor_spool(
    payload: dict[str, Any], *, spool_dir: Path, call_id: str = "c1", now_ts: float = 1_000.0
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    decision, meta = spool_post_tool_output(
        "cursor",
        payload,
        mode="active",
        session_id="cur-mcp-sess",
        call_id=call_id,
        spool_dir=spool_dir,
        now_ts=now_ts,
    )
    return format_post_tool_spool_response("cursor", decision), meta


def test_cursor_mcp_json_stringified_call_tool_result_spools_and_recovers(tmp_path: Path) -> None:
    """Decode JSON-stringified MCP CallToolResult, omit stale structuredContent, and recover via slice."""
    repo = _repo(tmp_path, "call_res")
    spool_dir = tmp_path / "spool"
    big = _make_lines(220, prefix="mcp")
    raw_json = json.dumps(
        {
            "content": [{"type": "text", "text": big}],
            "isError": False,
            "structuredContent": {"rows": 999},
        }
    )

    resp, meta = _run_cursor_spool(
        {
            "tool_name": "MCP:analytics:query",
            "tool_input": {"sql": "select * from events"},
            "tool_output": raw_json,
            "cwd": str(repo),
        },
        spool_dir=spool_dir,
        call_id="c-calltool",
    )

    assert meta is not None
    out = resp["updated_mcp_tool_output"]
    assert isinstance(out, dict)
    assert out["isError"] is False
    assert "structuredContent" not in out
    assert isinstance(out["content"], list) and len(out["content"]) == 1
    block = out["content"][0]
    assert block["type"] == "text"
    assert block["text"].startswith("[CONTEXT-GUARD OUTPUT SPOOL:")
    assert meta["spool_id"] in block["text"]

    recovered = slice_spool(
        meta["spool_id"],
        start_line=1,
        limit=250,
        workspace_root=repo,
        spool_dir=spool_dir,
        now_ts=1_005.0,
    )
    assert recovered["ok"] is True
    assert recovered["content"] + "\n" == big


def test_cursor_mcp_json_dict_and_plain_string_shapes(tmp_path: Path) -> None:
    """Preserve dict scalar fields on JSON-stringified dicts and wrap plain strings as MCP content."""
    repo = _repo(tmp_path, "shapes")
    spool_dir = tmp_path / "spool"
    big = _make_lines(220, prefix="shape")

    dict_json = json.dumps({"text": big, "meta": "keep"})
    resp_dict, meta_dict = _run_cursor_spool(
        {"tool_name": "MCP:srv:get", "tool_input": {"id": 1}, "tool_output": dict_json, "cwd": str(repo)},
        spool_dir=spool_dir,
        call_id="c-dict-json",
        now_ts=1_001.0,
    )
    assert meta_dict is not None
    out_dict = resp_dict["updated_mcp_tool_output"]
    assert isinstance(out_dict, dict)
    assert out_dict["meta"] == "keep"
    assert out_dict["text"].startswith("[CONTEXT-GUARD OUTPUT SPOOL:")
    assert meta_dict["spool_id"] in out_dict["text"]

    resp_plain, meta_plain = _run_cursor_spool(
        {"tool_name": "MCP:srv:raw", "tool_input": {"id": 2}, "tool_output": big, "cwd": str(repo)},
        spool_dir=spool_dir,
        call_id="c-plain-str",
        now_ts=1_002.0,
    )
    assert meta_plain is not None
    out_plain = resp_plain["updated_mcp_tool_output"]
    assert isinstance(out_plain, dict)
    assert out_plain["content"][0]["type"] == "text"
    assert out_plain["content"][0]["text"].startswith("[CONTEXT-GUARD OUTPUT SPOOL:")
    assert meta_plain["spool_id"] in out_plain["content"][0]["text"]

    blocks_json = json.dumps([{"type": "text", "text": big}])
    resp_blocks, meta_blocks = _run_cursor_spool(
        {"tool_name": "mcp__srv__list", "tool_input": {"id": 3}, "tool_output": blocks_json, "cwd": str(repo)},
        spool_dir=spool_dir,
        call_id="c-blocks-json",
        now_ts=1_003.0,
    )
    assert meta_blocks is not None
    out_blocks = resp_blocks["updated_mcp_tool_output"]
    assert isinstance(out_blocks, dict)
    assert out_blocks["content"][0]["text"].startswith("[CONTEXT-GUARD OUTPUT SPOOL:")

    bad_json_str = "{not-valid-json\n" + big
    resp_bad, meta_bad = _run_cursor_spool(
        {"tool_name": "MCP:srv:badjson", "tool_input": {"id": 4}, "tool_output": bad_json_str, "cwd": str(repo)},
        spool_dir=spool_dir,
        call_id="c-bad-json",
        now_ts=1_004.0,
    )
    assert meta_bad is not None
    assert resp_bad["updated_mcp_tool_output"]["content"][0]["text"].startswith("[CONTEXT-GUARD OUTPUT SPOOL:")


def test_cursor_mcp_skips_errors_redacted_truncated_unavailable_and_multimodal(tmp_path: Path) -> None:
    """Pass through redacted, error, truncated, unavailable, and mixed multimodal Cursor MCP outputs."""
    repo = _repo(tmp_path, "passthrough")
    spool_dir = tmp_path / "spool"
    big = _make_lines(220, prefix="skip")

    cases: list[dict[str, Any]] = [
        {"tool_name": "MCP:srv:a", "tool_input": {}, "tool_output": json.dumps({"redacted": True}), "cwd": str(repo)},
        {"tool_name": "MCP:srv:b", "tool_input": {}, "tool_output": json.dumps({"redacted": True, "text": big}), "cwd": str(repo)},
        {"tool_name": "MCP:srv:c", "tool_input": {}, "tool_output": json.dumps({"unavailable": True, "text": big}), "cwd": str(repo)},
        {
            "tool_name": "MCP:srv:d",
            "tool_input": {},
            "tool_output": json.dumps({"isError": True, "content": [{"type": "text", "text": big}]}),
            "cwd": str(repo),
        },
        {
            "tool_name": "MCP:srv:e",
            "tool_input": {},
            "tool_output": json.dumps({"truncated": True, "content": [{"type": "text", "text": big}]}),
            "cwd": str(repo),
        },
        {
            "tool_name": "MCP:srv:f",
            "tool_input": {},
            "tool_output": json.dumps({"is_truncated": True, "text": big}),
            "cwd": str(repo),
        },
        {"tool_name": "MCP:srv:g", "tool_input": {}, "truncated": True, "tool_output": {"text": big}, "cwd": str(repo)},
        {"tool_name": "MCP:srv:h", "tool_input": {}, "is_truncated": True, "tool_output": big, "cwd": str(repo)},
        {
            "tool_name": "MCP:srv:i",
            "tool_input": {},
            "tool_output": {"content": [{"type": "text", "text": big}, {"type": "image", "data": "abc"}]},
            "cwd": str(repo),
        },
        {
            "tool_name": "MCP:srv:j",
            "tool_input": {},
            "tool_output": json.dumps({"content": [{"type": "text", "text": big}, {"type": "resource", "uri": "file:///a"}]}),
            "cwd": str(repo),
        },
        {"tool_name": "MCP:srv:k", "tool_input": {}, "tool_output": {"content": []}, "cwd": str(repo)},
        {
            "tool_name": "MCP:srv:l",
            "tool_input": {},
            "tool_output": {"content": [{"type": "image", "data": "abc"}], "text": big},
            "cwd": str(repo),
        },
    ]

    for idx, payload in enumerate(cases):
        resp, meta = _run_cursor_spool(payload, spool_dir=spool_dir, call_id=f"c-skip-{idx}")
        assert resp == {} and meta is None
    assert not spool_dir.exists()


def test_cursor_extract_format_helpers_and_claude_truncation_parity(tmp_path: Path) -> None:
    """Decode Cursor JSON across shell/MCP, format shapes cleanly, and keep Claude truncation spooling."""
    big = _make_lines(220, prefix="helper")
    assert extract_tool_payload_text("cursor", json.dumps({"stdout": big, "exitCode": 0}), False) == (big, "stdout")
    assert extract_tool_payload_text("cursor", json.dumps({"content": [{"type": "text", "text": big}]}), True) == (
        big,
        "mcp_content",
    )

    mcp_out = format_spooled_tool_output(
        "cursor", "mcp_content", {"content": [{"type": "text", "text": "x"}], "isError": False, "structuredContent": {"k": 1}}, "sum"
    )
    assert mcp_out == {"isError": False, "content": [{"type": "text", "text": "sum"}]}
    assert format_spooled_tool_output("cursor", "output", {"output": "x", "extra": 2}, "sum") == {
        "output": "sum",
        "extra": 2,
    }
    assert format_spooled_tool_output("cursor", "str", "x", "sum") == {"content": [{"type": "text", "text": "sum"}]}
    assert format_spooled_tool_output("claude", "blocks", [{"type": "text", "text": "x"}], "sum") == [
        {"type": "text", "text": "sum"}
    ]

    assert format_post_tool_spool_response("cursor", SpoolDecision("cursor", "sum", "str", {})) == {
        "updated_mcp_tool_output": {"content": [{"type": "text", "text": "sum"}]}
    }
    assert format_post_tool_spool_response("cursor", SpoolDecision("cursor", {"text": "sum"}, "text", {})) == {
        "updated_mcp_tool_output": {"text": "sum"}
    }
    assert format_post_tool_spool_response("cursor", SpoolDecision("cursor", [{"type": "text", "text": "sum"}], "blocks", {})) == {}

    claude_cand = prepare_post_tool_spool_candidate(
        "claude", {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "truncated": True, "tool_response": big}
    )
    assert claude_cand is not None and claude_cand[7] is True
    repo = _repo(tmp_path, "claude_trunc")
    dec_cl, meta_cl = spool_post_tool_output(
        "claude",
        {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "truncated": True, "tool_response": big, "cwd": str(repo)},
        mode="active",
        session_id="cl-trunc",
        call_id="c-cl-t",
        spool_dir=tmp_path / "spool_cl",
    )
    assert dec_cl is not None and meta_cl is not None and isinstance(dec_cl.updated_output, str)


def test_end_to_end_handle_post_tool_use_cursor_mcp_json_spool_and_slice(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify handle_post_tool_use('cursor', ...) spools JSON MCP output and slice_spool recovers it."""
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "active"}}), encoding="utf-8")
    config.clear_config_cache()

    spool_dir = tmp_path / "e2e_spool"
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))
    repo = _repo(tmp_path, "e2e_repo")
    state_dir = tmp_path / "state"
    big = _make_lines(220, prefix="e2e")

    res = handle_post_tool_use(
        "cursor",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "cur-e2e",
            "call_id": "call-e2e-1",
            "tool_name": "MCP:analytics:query",
            "tool_input": {"sql": "select 1"},
            "tool_output": json.dumps(
                {
                    "content": [{"type": "text", "text": big}],
                    "isError": False,
                    "structuredContent": {"count": 220},
                }
            ),
            "cwd": str(repo),
        },
        state_dir=str(state_dir),
    )

    out = res["updated_mcp_tool_output"]
    assert isinstance(out, dict)
    assert out["isError"] is False
    assert "structuredContent" not in out
    summary_text = out["content"][0]["text"]
    assert summary_text.startswith("[CONTEXT-GUARD OUTPUT SPOOL:")
    sid = next(tok for tok in summary_text.split() if tok.startswith("sp_"))

    sliced = slice_spool(sid, start_line=1, limit=250, workspace_root=repo, spool_dir=spool_dir)
    assert sliced["ok"] is True
    assert sliced["content"] + "\n" == big

    err_res = handle_post_tool_use(
        "cursor",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "cur-e2e",
            "call_id": "call-e2e-err",
            "tool_name": "MCP:analytics:query",
            "tool_input": {"sql": "bad"},
            "tool_output": json.dumps({"isError": True, "content": [{"type": "text", "text": big}]}),
            "cwd": str(repo),
        },
        state_dir=str(state_dir),
    )
    assert err_res == {}
