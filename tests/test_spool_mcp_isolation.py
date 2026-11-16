"""Tests for spool workspace identity resolution, isolation config, and domain separation."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
from typing import Any

import pytest

from spool.mcp_server import is_cursor_spool_mcp_configured, serve_stdio, sync_cursor_spool_mcp
from spool.receipts import (
    compute_scope_key,
    compute_scoped_spool_id,
    read_spool_isolation_config,
    resolve_workspace_identity,
    same_workspace_dir,
)
from spool.store import spool_tool_output


def test_resolve_workspace_identity_git_root_worktree_home_anchor_template_and_multi_root(
    tmp_path: Path,
) -> None:
    """Resolve .git dirs/worktree files to canonical root and reject anchors, home, templates, or multi-roots."""
    repo = tmp_path / "repo_alpha"
    sub = repo / "src" / "pkg"
    sub.mkdir(parents=True)
    (repo / ".git").mkdir()

    ws_id_root, canon_root, err_root = resolve_workspace_identity(repo)
    ws_id_sub, canon_sub, err_sub = resolve_workspace_identity(sub)
    assert err_root is None and err_sub is None
    expected_canon = os.path.realpath(str(repo))
    expected_id = "ws_" + hashlib.sha256(
        f"cg-ws-v1:{os.path.normcase(expected_canon)}".encode("utf-8")
    ).hexdigest()[:16]
    assert canon_root == expected_canon
    assert canon_sub == expected_canon
    assert ws_id_root == expected_id
    assert ws_id_sub == expected_id
    assert re.fullmatch(r"^ws_[0-9a-f]{16}$", ws_id_root)

    # .git worktree file (not a directory) also marks a workspace root
    wt_root = tmp_path / "wt_beta"
    wt_sub = wt_root / "nested"
    wt_sub.mkdir(parents=True)
    (wt_root / ".git").write_text("gitdir: ../repo_alpha/.git/worktrees/wt_beta\n", encoding="utf-8")
    wt_id, wt_canon, wt_err = resolve_workspace_identity(wt_sub)
    assert wt_err is None
    assert wt_canon == os.path.realpath(str(wt_root))
    assert wt_id != ws_id_root

    # Non-marker directory falls back to realpath(dir)
    plain = tmp_path / "plain_dir"
    plain.mkdir()
    plain_id, plain_canon, plain_err = resolve_workspace_identity(plain)
    assert plain_err is None
    assert plain_canon == os.path.realpath(str(plain))
    assert re.fullmatch(r"^ws_[0-9a-f]{16}$", plain_id)

    # file:// URI decoding (including %20 space)
    spaced = tmp_path / "my project"
    spaced.mkdir()
    uri = spaced.as_uri()
    uri_id, uri_canon, uri_err = resolve_workspace_identity(uri)
    assert uri_err is None
    assert uri_canon == os.path.realpath(str(spaced))
    assert re.fullmatch(r"^ws_[0-9a-f]{16}$", uri_id)

    # Invalid / unresolved inputs fail closed
    anchor = Path(os.path.realpath(str(tmp_path))).anchor
    for bad in ("", "   ", "${workspaceFolder}", "relative/path", anchor, str(Path.home()), str(tmp_path / "missing")):
        bid, bcanon, berr = resolve_workspace_identity(bad)
        assert (bid, bcanon, berr) == ("", "", "workspace_unresolved")

    # Multi-root without narrowing cwd -> workspace_ambiguous; cwd inside one root narrows cleanly
    amb_id, amb_canon, amb_err = resolve_workspace_identity(
        None, workspace_roots=[repo.as_uri(), wt_root.as_uri()]
    )
    assert (amb_id, amb_canon, amb_err) == ("", "", "workspace_ambiguous")

    nar_id, nar_canon, nar_err = resolve_workspace_identity(
        sub, workspace_roots=[repo.as_uri(), wt_root.as_uri()]
    )
    assert nar_err is None
    assert nar_canon == expected_canon
    assert nar_id == expected_id


def test_read_spool_isolation_config_defaults_and_rejects_invalid_values(tmp_path: Path) -> None:
    """Default to workspace, accept session/global, reject invalid spool shapes, fail open on bad JSON."""
    assert read_spool_isolation_config(tmp_path / "absent.json") == ("workspace", None)

    for mode in ("workspace", "session", "global"):
        cfg = tmp_path / f"{mode}.json"
        cfg.write_text(f'{{"spool": {{"isolation": "{mode}"}}}}', encoding="utf-8")
        assert read_spool_isolation_config(cfg) == (mode, None)

    no_spool = tmp_path / "no_spool.json"
    no_spool.write_text('{"read_confirm_policy": "strict"}', encoding="utf-8")
    assert read_spool_isolation_config(no_spool) == ("workspace", None)

    bad_shape = tmp_path / "bad_shape.json"
    bad_shape.write_text('{"spool": "bad"}', encoding="utf-8")
    assert read_spool_isolation_config(bad_shape) == ("", "invalid_spool_config")

    bad_mode = tmp_path / "bad_mode.json"
    bad_mode.write_text('{"spool": {"isolation": "tenant"}}', encoding="utf-8")
    assert read_spool_isolation_config(bad_mode) == ("", "invalid_spool_config")

    corrupt_json = tmp_path / "corrupt.json"
    corrupt_json.write_text("{not valid json", encoding="utf-8")
    assert read_spool_isolation_config(corrupt_json) == ("workspace", None)


def test_compute_scoped_spool_id_separates_domains() -> None:
    """Produce valid sp_<12hex> IDs isolated across workspace, session, and global domains."""
    sha = "a" * 64
    k_a, e_a = compute_scope_key("workspace", workspace_id="ws_1111111111111111")
    k_b, e_b = compute_scope_key("workspace", workspace_id="ws_2222222222222222")
    k_s, e_s = compute_scope_key("session", session_id="sess-1")
    k_g, e_g = compute_scope_key("global")
    assert (e_a, e_b, e_s, e_g) == (None, None, None, None)

    ids = [
        compute_scoped_spool_id(k_a, sha),
        compute_scoped_spool_id(k_b, sha),
        compute_scoped_spool_id(k_s, sha),
        compute_scoped_spool_id(k_g, sha),
    ]
    assert all(re.fullmatch(r"^sp_[0-9a-f]{12}$", sid) for sid in ids)
    assert len(set(ids)) == 4
    assert compute_scope_key("workspace", workspace_id="") == ("", "workspace_unresolved")
    assert compute_scope_key("session", session_id="") == ("", "session_unresolved")


def _big_spool_text(tag: str) -> str:
    return "\n".join(f"{tag}-{i:04d} " + ("x" * 64) for i in range(1, 221)) + "\n"


def _rpc_ndjson(reqs: list[dict[str, Any]], **serve_kw: Any) -> list[dict[str, Any]]:
    in_buf = io.BytesIO(b"\n".join(json.dumps(r).encode("utf-8") for r in reqs) + b"\n")
    out_buf = io.BytesIO()
    assert serve_stdio(stdin=in_buf, stdout=out_buf, **serve_kw) == 0
    return [json.loads(ln.decode("utf-8")) for ln in out_buf.getvalue().splitlines() if ln.strip()]


def test_workspace_isolation_blocks_cross_project_slice_grep_and_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Block cross-workspace slice/grep/list, ignore workspace* args, and forbid os.getcwd inside serve_stdio."""
    proj_a, proj_b = tmp_path / "proj_a", tmp_path / "proj_b"
    (proj_a / ".git").mkdir(parents=True)
    (proj_b / ".git").mkdir(parents=True)
    spool_dir = tmp_path / "spool"

    res_a = spool_tool_output(
        _big_spool_text("ALPHA"), session_id="s-a", call_id="c-a", harness="cursor",
        tool_name="MCP:a:run", workspace_root=proj_a, spool_dir=spool_dir, now_ts=1_700_000_000.0,
    )
    assert res_a is not None
    sid_a = res_a[0].spool_id

    def _forbid_cwd() -> str:
        raise AssertionError("serve_stdio must never call os.getcwd")

    with monkeypatch.context() as mp:
        mp.setattr(os, "getcwd", _forbid_cwd)
        replies = _rpc_ndjson(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {"workspace_root": str(proj_a)}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_a, "workspace_root": str(proj_a), "workspace_id": "ws_0000000000000000"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cg_spool_grep", "arguments": {"spool_id": sid_a, "pattern": "ALPHA", "workspace": str(proj_a)}}},
            ],
            spool_dir=spool_dir,
            workspace_root=proj_b,
            isolation="workspace",
        )
        ok_replies = _rpc_ndjson(
            [{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_a, "limit": 2}}}],
            spool_dir=spool_dir,
            workspace_root=proj_a,
            isolation="workspace",
        )
    assert ok_replies[0]["result"]["isError"] is False
    assert [r["id"] for r in replies] == [1, 2, 3, 4]
    list_res = json.loads(replies[1]["result"]["content"][0]["text"])
    assert replies[1]["result"]["isError"] is False and list_res["count"] == 0
    for idx in (2, 3):
        assert replies[idx]["result"]["isError"] is True
        assert json.loads(replies[idx]["result"]["content"][0]["text"])["error"] == "workspace_mismatch"


def test_mcp_multi_root_roots_list_returns_workspace_ambiguous_and_single_root_succeeds(
    tmp_path: Path,
) -> None:
    """Exercise interactive roots/list handshake, FIFO replay during WaitingRootsResp, ambiguous & single roots."""
    repo_a, repo_b = tmp_path / "repo_a", tmp_path / "repo_b"
    (repo_a / ".git").mkdir(parents=True)
    (repo_b / ".git").mkdir(parents=True)
    spool_dir = tmp_path / "spool"
    res_a = spool_tool_output(
        _big_spool_text("ROOTA"), session_id="s-r", call_id="c-r", harness="cursor",
        tool_name="MCP:r:run", workspace_root=repo_a, spool_dir=spool_dir, now_ts=1_700_000_010.0,
    )
    assert res_a is not None
    sid_a = res_a[0].spool_id

    c2s_r, c2s_w = os.pipe()
    s2c_r, s2c_w = os.pipe()
    in_fh, out_fh = os.fdopen(c2s_r, "rb"), os.fdopen(s2c_w, "wb")
    client_w, client_r = os.fdopen(c2s_w, "wb"), os.fdopen(s2c_r, "rb")
    t = threading.Thread(
        target=lambda: serve_stdio(spool_dir=spool_dir, stdin=in_fh, stdout=out_fh, isolation="workspace"),
        daemon=True,
    )
    t.start()

    def _send(obj: dict[str, Any]) -> None:
        client_w.write((json.dumps(obj) + "\n").encode("utf-8"))
        client_w.flush()

    def _recv() -> dict[str, Any]:
        return json.loads(client_r.readline().decode("utf-8"))

    _send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {"roots": {"listChanged": True}}}})
    assert _recv()["id"] == 1
    _send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {}}})
    req_roots = _recv()
    assert req_roots["method"] == "roots/list" and str(req_roots["id"]).startswith("cg-roots-")
    # Interleave ping & second tools/call while WaitingRootsResp awaits roots/list response
    _send({"jsonrpc": "2.0", "id": 3, "method": "ping"})
    _send({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_a}}})
    _send({"jsonrpc": "2.0", "id": req_roots["id"], "result": {"roots": [{"uri": repo_a.as_uri()}, {"uri": repo_b.as_uri()}]}})
    replayed = [_recv(), _recv(), _recv()]
    assert [r["id"] for r in replayed] == [2, 3, 4]
    assert replayed[0]["result"]["isError"] is True
    assert json.loads(replayed[0]["result"]["content"][0]["text"])["error"] == "workspace_ambiguous"
    assert replayed[1]["result"] == {}
    assert json.loads(replayed[2]["result"]["content"][0]["text"])["error"] == "workspace_ambiguous"

    # Invalidate cached roots and answer with a single root -> slice succeeds
    _send({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"})
    _send({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_a, "limit": 2}}})
    req_roots_2 = _recv()
    assert req_roots_2["method"] == "roots/list"
    _send({"jsonrpc": "2.0", "id": req_roots_2["id"], "result": {"roots": [{"uri": repo_a.as_uri()}]}})
    ok_reply = _recv()
    assert ok_reply["id"] == 5 and ok_reply["result"]["isError"] is False
    assert "ROOTA-0001" in json.loads(ok_reply["result"]["content"][0]["text"])["content"]
    client_w.close()
    t.join(timeout=5)
    for fh in (client_r, in_fh, out_fh):
        fh.close()
    assert not t.is_alive()


def test_mcp_missing_workspace_or_literal_template_fails_closed_without_global_fallback(
    tmp_path: Path,
) -> None:
    """Missing --workspace, literal ${workspaceFolder}, and unanswerable roots/list fail closed as workspace_unresolved."""
    repo = tmp_path / "repo_u"
    (repo / ".git").mkdir(parents=True)
    spool_dir = tmp_path / "spool"
    res = spool_tool_output(
        _big_spool_text("UNRES"), session_id="s-u", call_id="c-u", harness="cursor",
        tool_name="MCP:u:run", workspace_root=repo, spool_dir=spool_dir, now_ts=1_700_000_020.0,
    )
    assert res is not None
    sid = res[0].spool_id

    for ws in (None, "${workspaceFolder}"):
        replies = _rpc_ndjson(
            [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid}}}],
            spool_dir=spool_dir, workspace_root=ws, isolation="workspace",
        )
        assert replies[0]["result"]["isError"] is True
        assert json.loads(replies[0]["result"]["content"][0]["text"])["error"] == "workspace_unresolved"

    # Client advertises capabilities.roots but sends EOF before answering roots/list -> no fallback to --workspace
    eof_replies = _rpc_ndjson(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {"roots": {}}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {}}},
        ],
        spool_dir=spool_dir, workspace_root=repo, isolation="workspace",
    )
    tool_rep = next(r for r in eof_replies if r.get("id") == 2)
    assert tool_rep["result"]["isError"] is True
    assert json.loads(tool_rep["result"]["content"][0]["text"])["error"] == "workspace_unresolved"


def test_session_and_global_isolation_modes_and_roots_list_changed_invalidation(
    tmp_path: Path,
) -> None:
    """Enforce session isolation, ignore spoofed session_id in list, permit global mode, and validate Cursor mcp.json."""
    repo = tmp_path / "repo_sg"
    (repo / ".git").mkdir(parents=True)
    spool_dir = tmp_path / "spool"

    res_s1 = spool_tool_output(
        _big_spool_text("S1"), session_id="sess-1", call_id="c1", harness="cursor",
        tool_name="MCP:sg:run", workspace_root=repo, isolation="session", spool_dir=spool_dir, now_ts=1_700_000_030.0,
    )
    res_g = spool_tool_output(
        _big_spool_text("GLOB"), session_id="sess-g", call_id="c2", harness="cursor",
        tool_name="MCP:sg:run", workspace_root=repo, isolation="global", spool_dir=spool_dir, now_ts=1_700_000_031.0,
    )
    assert res_s1 is not None and res_g is not None
    sid_1, sid_g = res_s1[0].spool_id, res_g[0].spool_id

    # In session mode, sess-2 cannot read sess-1 spool and spoofed session_id="sess-1" in list args is ignored
    s2_replies = _rpc_ndjson(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {"session_id": "sess-1"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_1}}},
        ],
        spool_dir=spool_dir, workspace_root=repo, session_id="sess-2", isolation="session",
    )
    assert json.loads(s2_replies[0]["result"]["content"][0]["text"])["count"] == 0
    assert s2_replies[1]["result"]["isError"] is True
    assert json.loads(s2_replies[1]["result"]["content"][0]["text"])["error"] == "session_mismatch"

    # Global mode shares access without workspace_root
    g_replies = _rpc_ndjson(
        [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_g, "limit": 2}}}],
        spool_dir=spool_dir, isolation="global",
    )
    assert g_replies[0]["result"]["isError"] is False
    assert "GLOB-0001" in json.loads(g_replies[0]["result"]["content"][0]["text"])["content"]

    mcp_path = tmp_path / "cursor" / "mcp.json"
    mcp_path.parent.mkdir(parents=True)
    mcp_path.write_text(json.dumps({"mcpServers": {"context-guard-spool": {"command": "python3", "args": ["bin/cg_spool.py", "mcp"]}}}), encoding="utf-8")
    assert is_cursor_spool_mcp_configured(mcp_path) is False
    sync_cursor_spool_mcp(mcp_path, Path(__file__).resolve().parent.parent, enabled=True, py_executable="python3")
    assert is_cursor_spool_mcp_configured(mcp_path) is True

    # CLI --workspace, --session, and on_reliability_failure integration + mcp zero-getcwd guarantee
    from bin import cg_spool
    from hooks import telemetry

    (other_repo := tmp_path / "other_cli_repo").mkdir()
    (other_repo / ".git").mkdir()
    assert cg_spool.main(["slice", sid_1, "--workspace", str(other_repo), "--session", "sess-1", "--spool-dir", str(spool_dir), "--json"]) == 1
    assert cg_spool.main(["list", "--workspace", str(repo), "--session", "sess-1", "--spool-dir", str(spool_dir), "--json"]) == 0
    (spool_dir / f"{sid_1}.txt").write_bytes(b"\xff\xfe\x80")
    assert cg_spool.main(["slice", sid_1, "--workspace", str(repo), "--session", "sess-1", "--spool-dir", str(spool_dir), "--json"]) == 1
    assert telemetry.load_telemetry_stats()["events"]["reliability_failures"] == 1


def _forbid_os_getcwd() -> str:
    raise AssertionError("serve_stdio must never call os.getcwd")


def _make_dir_symlink(link_path: Path, target_dir: Path) -> None:
    try:
        link_path.symlink_to(target_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


def test_symlinked_and_case_variant_workspace_parity_across_hook_and_mcp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify symlinked and case-variant workspaces match via os.path.samefile across hook writes and MCP reads."""
    real_proj = tmp_path / "ProjAlpha"
    (real_proj / ".git").mkdir(parents=True)
    other_proj = tmp_path / "ProjBeta"
    (other_proj / ".git").mkdir(parents=True)
    symlink_proj = tmp_path / "proj_alpha_link"
    _make_dir_symlink(symlink_proj, real_proj)
    (symlink_proj / "nested").mkdir()
    assert same_workspace_dir(real_proj, symlink_proj) is True
    assert os.path.samefile(str(real_proj), str(symlink_proj))

    spool_dir = tmp_path / "spool"
    res_real = spool_tool_output(
        _big_spool_text("SYMLINK_REAL"), session_id="s-sym", call_id="c-sym-1", harness="claude",
        tool_name="Bash", workspace_root=real_proj, isolation="workspace", spool_dir=spool_dir, now_ts=1_700_000_100.0,
    )
    res_sym = spool_tool_output(
        _big_spool_text("SYMLINK_ALIAS"), session_id="s-sym", call_id="c-sym-2", harness="cursor",
        tool_name="MCP:sym:run", workspace_root=symlink_proj / "nested", isolation="workspace",
        spool_dir=spool_dir, now_ts=1_700_000_101.0,
    )
    assert res_real is not None and res_sym is not None
    sid_real, sid_sym = res_real[0].spool_id, res_sym[0].spool_id

    with monkeypatch.context() as mp:
        mp.setattr(os, "getcwd", _forbid_os_getcwd)
        sym_replies = _rpc_ndjson(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_real, "limit": 2}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cg_spool_grep", "arguments": {"spool_id": sid_real, "pattern": "SYMLINK_REAL-0001"}}},
            ],
            spool_dir=spool_dir, workspace_root=symlink_proj, isolation="workspace",
        )
        real_replies = _rpc_ndjson(
            [{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_sym, "limit": 2}}}],
            spool_dir=spool_dir, workspace_root=real_proj, isolation="workspace",
        )
        other_replies = _rpc_ndjson(
            [{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_real}}}],
            spool_dir=spool_dir, workspace_root=other_proj, isolation="workspace",
        )
        case_alias = tmp_path / "projalpha"
        case_replies = (
            _rpc_ndjson(
                [{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_real, "limit": 1}}}],
                spool_dir=spool_dir, workspace_root=case_alias, isolation="workspace",
            )
            if case_alias.exists() and same_workspace_dir(real_proj, case_alias)
            else None
        )

    assert sym_replies[0]["result"]["isError"] is False
    assert json.loads(sym_replies[0]["result"]["content"][0]["text"])["count"] == 2
    assert sym_replies[1]["result"]["isError"] is False
    assert "SYMLINK_REAL-0001" in json.loads(sym_replies[1]["result"]["content"][0]["text"])["content"]
    assert sym_replies[2]["result"]["isError"] is False
    assert json.loads(sym_replies[2]["result"]["content"][0]["text"])["match_count"] == 1
    assert real_replies[0]["result"]["isError"] is False
    assert "SYMLINK_ALIAS-0001" in json.loads(real_replies[0]["result"]["content"][0]["text"])["content"]
    assert other_replies[0]["result"]["isError"] is True
    assert json.loads(other_replies[0]["result"]["content"][0]["text"])["error"] == "workspace_mismatch"
    if case_replies is not None:
        assert case_replies[0]["result"]["isError"] is False
        assert "SYMLINK_REAL-0001" in json.loads(case_replies[0]["result"]["content"][0]["text"])["content"]


def test_mcp_roots_list_deduplicates_symlink_and_alias_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deduplicate symlink and alias workspace roots in MCP roots/list instead of failing workspace_ambiguous."""
    real_proj = tmp_path / "DedupRepo"
    (real_proj / ".git").mkdir(parents=True)
    other_proj = tmp_path / "DistinctRepo"
    (other_proj / ".git").mkdir(parents=True)
    symlink_proj = tmp_path / "dedup_repo_link"
    _make_dir_symlink(symlink_proj, real_proj)

    spool_dir = tmp_path / "spool"
    res = spool_tool_output(
        _big_spool_text("DEDUP_ROOT"), session_id="s-dd", call_id="c-dd", harness="cursor",
        tool_name="MCP:dd:run", workspace_root=real_proj, isolation="workspace", spool_dir=spool_dir, now_ts=1_700_000_200.0,
    )
    assert res is not None
    sid = res[0].spool_id

    dup_roots = [{"uri": real_proj.as_uri()}, {"uri": symlink_proj.as_uri()}]
    case_alias = tmp_path / "deduprepo"
    if case_alias.exists() and same_workspace_dir(real_proj, case_alias):
        dup_roots.append({"uri": case_alias.as_uri()})

    c2s_r, c2s_w = os.pipe()
    s2c_r, s2c_w = os.pipe()
    in_fh, out_fh = os.fdopen(c2s_r, "rb"), os.fdopen(s2c_w, "wb")
    client_w, client_r = os.fdopen(c2s_w, "wb"), os.fdopen(s2c_r, "rb")
    t = threading.Thread(
        target=lambda: serve_stdio(spool_dir=spool_dir, stdin=in_fh, stdout=out_fh, isolation="workspace"),
        daemon=True,
    )

    def _send(obj: dict[str, Any]) -> None:
        client_w.write((json.dumps(obj) + "\n").encode("utf-8"))
        client_w.flush()

    def _recv() -> dict[str, Any]:
        return json.loads(client_r.readline().decode("utf-8"))

    with monkeypatch.context() as mp:
        mp.setattr(os, "getcwd", _forbid_os_getcwd)
        t.start()
        _send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {"roots": {"listChanged": True}}}})
        assert _recv()["id"] == 1
        _send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {}}})
        req_roots = _recv()
        assert req_roots["method"] == "roots/list"
        _send({"jsonrpc": "2.0", "id": req_roots["id"], "result": {"roots": dup_roots}})
        list_rep = _recv()
        assert list_rep["id"] == 2 and list_rep["result"]["isError"] is False
        assert json.loads(list_rep["result"]["content"][0]["text"])["count"] == 1

        _send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid, "limit": 2}}})
        slice_rep = _recv()
        assert slice_rep["id"] == 3 and slice_rep["result"]["isError"] is False
        assert "DEDUP_ROOT-0001" in json.loads(slice_rep["result"]["content"][0]["text"])["content"]

        # Adding a genuinely distinct second workspace triggers workspace_ambiguous
        _send({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"})
        _send({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid}}})
        req_roots_2 = _recv()
        _send({"jsonrpc": "2.0", "id": req_roots_2["id"], "result": {"roots": [*dup_roots, {"uri": other_proj.as_uri()}]}})
        amb_rep = _recv()
        assert amb_rep["id"] == 4 and amb_rep["result"]["isError"] is True
        assert json.loads(amb_rep["result"]["content"][0]["text"])["error"] == "workspace_ambiguous"
        client_w.close()
        t.join(timeout=5)

    for fh in (client_r, in_fh, out_fh):
        fh.close()
    assert not t.is_alive()


def test_deleted_or_moved_workspace_fails_closed_without_global_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject deleted or moved workspace roots as workspace_unresolved/mismatch with zero global fallback."""
    ephemeral_proj = tmp_path / "EphemeralRepo"
    (ephemeral_proj / ".git").mkdir(parents=True)
    movable_proj = tmp_path / "MovableRepo"
    (movable_proj / ".git").mkdir(parents=True)
    spool_dir = tmp_path / "spool"

    res_del = spool_tool_output(
        _big_spool_text("DELETED_WS"), session_id="s-del", call_id="c-del", harness="cursor",
        tool_name="MCP:del:run", workspace_root=ephemeral_proj, isolation="workspace", spool_dir=spool_dir, now_ts=1_700_000_300.0,
    )
    res_mov = spool_tool_output(
        _big_spool_text("MOVED_WS"), session_id="s-mov", call_id="c-mov", harness="cursor",
        tool_name="MCP:mov:run", workspace_root=movable_proj, isolation="workspace", spool_dir=spool_dir, now_ts=1_700_000_301.0,
    )
    res_glob = spool_tool_output(
        _big_spool_text("GLOBAL_DECOY"), session_id="s-gl", call_id="c-gl", harness="cursor",
        tool_name="MCP:gl:run", isolation="global", spool_dir=spool_dir, now_ts=1_700_000_302.0,
    )
    assert res_del is not None and res_mov is not None and res_glob is not None
    sid_del, sid_mov, sid_glob = res_del[0].spool_id, res_mov[0].spool_id, res_glob[0].spool_id

    shutil.rmtree(ephemeral_proj)
    moved_proj = tmp_path / "MovedRepo"
    movable_proj.rename(moved_proj)

    with monkeypatch.context() as mp:
        mp.setattr(os, "getcwd", _forbid_os_getcwd)
        del_replies = _rpc_ndjson(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_del}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cg_spool_grep", "arguments": {"spool_id": sid_del, "pattern": "DELETED_WS"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_glob}}},
            ],
            spool_dir=spool_dir, workspace_root=ephemeral_proj, isolation="workspace",
        )
        old_mov_replies = _rpc_ndjson(
            [{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_mov}}}],
            spool_dir=spool_dir, workspace_root=movable_proj, isolation="workspace",
        )
        new_mov_replies = _rpc_ndjson(
            [
                {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "cg_spool_list", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_mov}}},
                {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "cg_spool_grep", "arguments": {"spool_id": sid_mov, "pattern": "MOVED_WS"}}},
                {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_glob}}},
            ],
            spool_dir=spool_dir, workspace_root=moved_proj, isolation="workspace",
        )

    for rep in del_replies:
        assert rep["result"]["isError"] is True
        assert json.loads(rep["result"]["content"][0]["text"])["error"] == "workspace_unresolved"
    assert old_mov_replies[0]["result"]["isError"] is True
    assert json.loads(old_mov_replies[0]["result"]["content"][0]["text"])["error"] == "workspace_unresolved"
    assert new_mov_replies[0]["result"]["isError"] is False
    assert json.loads(new_mov_replies[0]["result"]["content"][0]["text"])["count"] == 0
    for idx in (1, 2, 3):
        assert new_mov_replies[idx]["result"]["isError"] is True
        assert json.loads(new_mov_replies[idx]["result"]["content"][0]["text"])["error"] == "workspace_mismatch"


def test_cli_and_mcp_workspace_root_alias_and_startup_env_pinning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify --workspace-root across CLI/MCP/Cursor config and startup CONTEXT_GUARD_WORKSPACE_ROOT pinning."""
    from bin import cg_spool

    repo_root = Path(__file__).resolve().parent.parent
    proj_a, proj_b = tmp_path / "CliProjA", tmp_path / "CliProjB"
    (proj_a / ".git").mkdir(parents=True)
    (proj_b / ".git").mkdir(parents=True)
    spool_dir = tmp_path / "spool"

    res_a = spool_tool_output(
        _big_spool_text("WSROOT"), session_id="s-wr", call_id="c-wr", harness="claude",
        tool_name="Bash", workspace_root=proj_a, isolation="workspace", spool_dir=spool_dir, now_ts=1_700_000_400.0,
    )
    assert res_a is not None
    sid_a = res_a[0].spool_id

    # Cursor mcp.json validation accepts --workspace and --workspace-root with non-empty value
    mcp_cfg = tmp_path / "mcp.json"
    for valid_args in (
        ["bin/cg_spool.py", "mcp", "--workspace", "${workspaceFolder}"],
        ["bin/cg_spool.py", "mcp", "--workspace-root", "${workspaceFolder}"],
    ):
        mcp_cfg.write_text(json.dumps({"mcpServers": {"context-guard-spool": {"command": "python3", "args": valid_args}}}), encoding="utf-8")
        assert is_cursor_spool_mcp_configured(mcp_cfg) is True
    for bad_args in (
        ["bin/cg_spool.py", "--workspace-root", "${workspaceFolder}"],
        ["bin/cg_spool.py", "mcp", "--workspace-root"],
        ["bin/cg_spool.py", "mcp", "--workspace-root", "   "],
        ["bin/cg_spool.py", "mcp", "--workspace", "${workspaceFolder}", "--workspace-root", ""],
    ):
        mcp_cfg.write_text(json.dumps({"mcpServers": {"context-guard-spool": {"command": "python3", "args": bad_args}}}), encoding="utf-8")
        assert is_cursor_spool_mcp_configured(mcp_cfg) is False

    cfg_absent = tmp_path / "absent_config.json"
    with monkeypatch.context() as mp:
        mp.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_absent))
        capsys.readouterr()
        assert cg_spool.main(["list", "--workspace-root", str(proj_a), "--spool-dir", str(spool_dir), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["count"] == 1
        assert cg_spool.main(["slice", sid_a, "--workspace-root", str(proj_a), "--limit", "2", "--spool-dir", str(spool_dir), "--json"]) == 0
        assert "WSROOT-0001" in json.loads(capsys.readouterr().out)["content"]
        assert cg_spool.main(["grep", sid_a, "WSROOT-0001", "--workspace-root", str(proj_a), "--spool-dir", str(spool_dir), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["match_count"] == 1
        assert cg_spool.main(["slice", sid_a, "--workspace-root", str(proj_b), "--spool-dir", str(spool_dir), "--json"]) == 1
        assert json.loads(capsys.readouterr().out)["error"] == "workspace_mismatch"
        assert cg_spool.main(["gc", "--workspace-root", str(proj_a), "--spool-dir", str(spool_dir), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True

        # Subprocess CLI `mcp --workspace-root`
        proc_in = b"\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode("utf-8"),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_a, "limit": 2}}}).encode("utf-8"),
        ]) + b"\n"
        proc = subprocess.run(
            [sys.executable, str(repo_root / "bin" / "cg_spool.py"), "mcp", "--spool-dir", str(spool_dir), "--workspace-root", str(proj_a)],
            cwd=str(repo_root), input=proc_in, capture_output=True, check=False,
        )
        assert proc.returncode == 0 and proc.stderr == b""
        proc_replies = [json.loads(ln.decode("utf-8")) for ln in proc.stdout.splitlines() if ln.strip()]
        assert proc_replies[1]["result"]["isError"] is False
        assert "WSROOT-0001" in json.loads(proc_replies[1]["result"]["content"][0]["text"])["content"]

        # Startup pinning of CONTEXT_GUARD_WORKSPACE_ROOT (immutable mid-session, zero os.getcwd)
        c2s_r, c2s_w = os.pipe()
        s2c_r, s2c_w = os.pipe()
        in_fh, out_fh = os.fdopen(c2s_r, "rb"), os.fdopen(s2c_w, "wb")
        client_w, client_r = os.fdopen(c2s_w, "wb"), os.fdopen(s2c_r, "rb")
        mp.setattr(os, "getcwd", _forbid_os_getcwd)
        mp.setenv("CONTEXT_GUARD_WORKSPACE_ROOT", str(proj_a))
        t = threading.Thread(
            target=lambda: serve_stdio(spool_dir=spool_dir, stdin=in_fh, stdout=out_fh, isolation="workspace"),
            daemon=True,
        )
        t.start()
        client_w.write((json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n").encode("utf-8"))
        client_w.flush()
        assert json.loads(client_r.readline().decode("utf-8"))["id"] == 1
        mp.setenv("CONTEXT_GUARD_WORKSPACE_ROOT", str(proj_b))
        client_w.write((json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cg_spool_slice", "arguments": {"spool_id": sid_a, "limit": 1}}}) + "\n").encode("utf-8"))
        client_w.flush()
        pinned_rep = json.loads(client_r.readline().decode("utf-8"))
        client_w.close()
        t.join(timeout=5)
        for fh in (client_r, in_fh, out_fh):
            fh.close()
        assert not t.is_alive()
        assert pinned_rep["result"]["isError"] is False
        assert "WSROOT-0001" in json.loads(pinned_rep["result"]["content"][0]["text"])["content"]
