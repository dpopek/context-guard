"""Transactional, TOCTOU, policy-reconciliation, and harness-capability tests for read planning and hooks."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from core.contracts import PendingRead, PlannerMeta, SpoolDecision
from hooks import (
    config,
    file_io,
    harness_adapter,
    outcomes,
    policy_engine,
    post_tool_use,
    pre_tool_use,
    read_planner,
    state_store,
)
from hooks.harness_adapter import NormalizedToolCall


def _tree_sha(file_hashes: dict[str, str]) -> str:
    manifest = "".join(f"{k}:{file_hashes[k]}\n" for k in sorted(file_hashes))
    return hashlib.sha256(manifest.encode("utf-8")).hexdigest()


def _write_pack(
    policies_dir: Path,
    pack_id: str,
    pack_src: str,
    *,
    kind: str = "security",
    scopes: list[str] | None = None,
    fallback_matchers: dict[str, Any] | None = None,
) -> tuple[Path, dict[str, Any]]:
    policies_dir.mkdir(parents=True, exist_ok=True)
    pack_dir = policies_dir / pack_id
    pack_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(policies_dir, 0o700)
        os.chmod(pack_dir, 0o700)
    hashes: dict[str, str] = {}
    for name, src in (("__init__.py", '"""Test pack."""\n'), ("pack.py", pack_src)):
        raw = src.encode("utf-8")
        fp = pack_dir / name
        fp.write_bytes(raw)
        if os.name != "nt":
            os.chmod(fp, 0o600)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    entry: dict[str, Any] = {
        "id": pack_id,
        "path": str(pack_dir / "pack.py"),
        "enabled": True,
        "kind": kind,
        "scopes": scopes or ["file_mutation", "shell_command"],
        "fallback_matchers": fallback_matchers or {"protected_path_prefixes": [".githooks/"], "shell_commands": ["forbidden_cmd"]},
        "file_hashes": hashes,
        "tree_sha256": _tree_sha(hashes),
        "settings": {},
    }
    return pack_dir, entry


def _write_cfg(env_root: Path, cfg_obj: dict[str, Any]) -> Path:
    cfg_path = env_root / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg_obj), encoding="utf-8")
    config.clear_config_cache()
    return cfg_path


def test_readonly_state_dir_does_not_fail_closed_deny_reads(
    tmp_path: Path, isolated_user_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    sec_src = (
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n"
        "def evaluate(ctx):\n"
        "    if ctx.canonical_tool == 'edit_file' and '.githooks/' in str(ctx.canonical_args.get('Path', '')):\n"
        "        return PolicyDecision(decision='deny', reason='SEC_BLOCKED')\n"
        "    return None\n"
        "PACK_MANIFEST = PolicyPackManifest(pack_id='ro-sec', api_version=POLICY_API_VERSION, "
        "kind='security', covered_domains=('gov',), evaluate=evaluate)\n"
    )
    _, sec_entry = _write_pack(isolated_user_env / ".config" / "context-guard" / "policies", "ro-sec", sec_src)
    _write_cfg(isolated_user_env, {"read_confirm_policy": "bounded", "policy_packs": [sec_entry]})
    target = tmp_path / "sample.py"
    target.write_text("\n".join(f"x_{i} = {i}" for i in range(1, 50)) + "\n", encoding="utf-8")
    ro_state = tmp_path / "ro_state"
    ro_state.mkdir()
    try:
        if os.name != "nt" and getattr(os, "geteuid", lambda: 1)() != 0:
            os.chmod(ro_state, 0o555)
            cl_ro = pre_tool_use.evaluate_hook(
                {"session_id": "s-ro", "tool_name": "Read", "tool_input": {"file_path": str(target), "offset": 1, "limit": 20}},
                state_dir=str(ro_state), cli_harness="claude",
            )
            assert cl_ro == {}
            assert pre_tool_use.evaluate_hook(
                {"conversationId": "s-ro", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 20}}},
                state_dir=str(ro_state),
            ) == {"decision": "allow"}
            assert "commit_planned_file_read fallback" in capsys.readouterr().err

        # Even if plan_file_read_verdict itself hits OSError with active security, reads MUST fail-open (never deny)
        monkeypatch.setattr(pre_tool_use, "plan_file_read_verdict", lambda *a, **kw: (_ for _ in ()).throw(PermissionError("ro dir")))
        res_plan_err = pre_tool_use.evaluate_hook(
            {"session_id": "s-ro2", "tool_name": "Read", "tool_input": {"file_path": str(target), "offset": 1, "limit": 20}},
            state_dir=str(tmp_path / "rw_state"), cli_harness="claude",
        )
        assert res_plan_err == {}
        assert "plan_file_read_verdict fallback" in capsys.readouterr().err

        # Security policy internal errors STILL fail-closed deny
        monkeypatch.setattr(pre_tool_use, "apply_policy_packs_with_records", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("sec boom")))
        res_sec_err = pre_tool_use.evaluate_hook(
            {"session_id": "s-ro2", "tool_name": "Edit", "tool_input": {"file_path": str(target)}},
            state_dir=str(tmp_path / "rw_state"), cli_harness="claude",
        )
        assert res_sec_err["hookSpecificOutput"]["permissionDecision"] == "deny"
    finally:
        if os.name != "nt":
            os.chmod(ro_state, 0o755)
        config.clear_config_cache()


def test_commit_planned_file_read_falls_back_when_state_persistence_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    # Pure decide_file_read performs ZERO disk I/O and ZERO time.time() calls
    in_state: dict[str, Any] = {
        "max_tool_step_idx": 5,
        "files": {"/virtual/mod.py": {"sha256": "abc123", "reads": [[1, 20, 1, 2], [81, 100, 2, 2], [1, 10, 5, 2]]}},
    }
    with monkeypatch.context() as mp:
        mp.setattr(time, "time", lambda: (_ for _ in ()).throw(AssertionError("clock access")))
        mp.setattr(file_io, "compute_file_sha256", lambda _p: (_ for _ in ()).throw(AssertionError("sha disk access")))
        mp.setattr(file_io, "count_file_lines_streaming", lambda _p: (_ for _ in ()).throw(AssertionError("line count access")))
        pure_plan = read_planner.decide_file_read(
            raw_path="/virtual/mod.py", canon="/virtual/mod.py", sha256="abc123", target_lines=120, state=in_state,
            start_line=1, end_line=100, byte_offset=0, step_idx=3, can_trim=True, min_tier=2, now_ts=1234.5,
        )
    assert in_state["files"]["/virtual/mod.py"]["reads"][-1] == [1, 10, 5, 2]
    assert isinstance(pure_plan.meta, PlannerMeta) and isinstance(pure_plan.meta.pending_read, PendingRead)
    assert pure_plan.outcome.decision == {"decision": "allow", "overwrite": {"StartLine": 21, "EndLine": 80}}
    assert pure_plan.meta.pending_read.trimmed_spans == ((1, 20), (81, 100))

    target = tmp_path / "pers_fail.py"
    target.write_text("\n".join(f"x_{i} = {i}" for i in range(1, 120)) + "\n", encoding="utf-8")
    sdir = tmp_path / "state"
    assert read_planner.handle_file_read_verdict(sdir, str(target), 1, 50, 0, 1, min_tier=1, call_id="c1").decision == {"decision": "allow"}
    post_tool_use.handle_post_tool_use("antigravity", {"conversationId": "s", "stepIdx": 1, "toolCall": {"id": "c1", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 50}}}, state_dir=str(sdir))

    snap_copy = state_store.read_state_snapshot(sdir)

    @contextmanager
    def _unsavable_locked(_path: Path) -> Iterator[Any]:
        yield type("_FakeTxn", (), {"state": snap_copy, "dirty": False, "save": lambda self: False})()

    planned_trim = read_planner.plan_file_read_verdict(sdir, str(target), 1, 100, 0, 2, min_tier=1, locked_state_fn=_unsavable_locked)
    assert planned_trim.outcome.decision.get("overwrite") == {"StartLine": 51, "EndLine": 100}
    res_save_false = read_planner.commit_planned_file_read(planned_trim)
    assert res_save_false.decision == {"decision": "allow"}
    assert res_save_false.followup_resolution is None
    assert "failed to persist session state" in capsys.readouterr().err

    # Also fail-open without overwrite or followup_resolution on ENOSPC during locked_state.__exit__
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda s, d: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full")) if str(sdir) in os.fspath(d) else real_replace(s, d))
    planned_enospc = read_planner.plan_file_read_verdict(sdir, str(target), 1, 100, 0, 2, min_tier=1)
    planned_enospc = planned_enospc._replace(outcome=planned_enospc.outcome._replace(followup_resolution=("outline", "targeted_followup")))
    res_enospc = read_planner.commit_planned_file_read(planned_enospc)
    assert res_enospc.decision == {"decision": "allow"} and res_enospc.followup_resolution is None
    err_enospc = capsys.readouterr().err
    assert "failed to persist session state" in err_enospc and "state not saved" in err_enospc


def test_commit_planned_file_read_strips_dangling_redirect_when_unwrap_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    mcp_dir = tmp_path / ".system_generated" / "steps" / "55"
    mcp_dir.mkdir(parents=True)
    mcp_file = mcp_dir / "output.txt"
    inner_py = mcp_dir / "inner_unwrap.py"
    code = "\n".join(f"def fn_{i}() -> int:\n    return {i}" for i in range(120))
    mcp_file.write_text(json.dumps({"file_name": "inner_unwrap.py", "content": code}) + (" " * 17000), encoding="utf-8")
    sdir = tmp_path / "state"
    canon = os.path.realpath(str(mcp_file))

    # Case 1: outline commit with failing unwrap_writer strips ', unwrapped at ...' from reason
    pl_ol = read_planner.plan_file_read_verdict(sdir, str(mcp_file), 1, -1, 0, 1, unwrap_writer=lambda _pw: None)
    assert ", unwrapped at " in pl_ol.outcome.decision["reason"]
    res_ol = read_planner.commit_planned_file_read(pl_ol)
    assert res_ol.decision["decision"] == "deny" and ", unwrapped at " not in res_ol.decision["reason"]
    saved_ol = json.loads(state_store.state_file_in(sdir).read_text(encoding="utf-8"))
    assert "unwrapped_path" not in saved_ol["files"][canon]

    # Case 2: targeted read commit with failing unwrap_writer strips dangling Path overwrite & redirect_path
    pl_rd = read_planner.plan_file_read_verdict(sdir, str(mcp_file), 1, 30, 0, 2, call_id="c-unwrap-fail", unwrap_writer=lambda _pw: None)
    assert pl_rd.outcome.decision.get("overwrite", {}).get("Path") == os.path.realpath(str(inner_py))
    res_rd = read_planner.commit_planned_file_read(pl_rd)
    assert res_rd.decision == {"decision": "allow"} and not inner_py.exists()
    saved_rd = json.loads(state_store.state_file_in(sdir).read_text(encoding="utf-8"))
    rec = saved_rd["files"][canon]["pending_reads"]["c-unwrap-fail"]
    assert rec["redirect_path"] is None and rec["is_redirect"] is False
    assert "stripping dangling redirect" in capsys.readouterr().err


def test_commit_planned_file_read_aborts_stale_trim_on_concurrent_mutation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "concurrent.py"
    target.write_text("\n".join(f"line_{i} = {i}" for i in range(1, 150)) + "\n", encoding="utf-8")
    canon = os.path.realpath(str(target))
    sdir = tmp_path / "state"

    assert read_planner.handle_file_read_verdict(sdir, str(target), 1, 50, 0, 1, min_tier=1, call_id="c1").decision == {"decision": "allow"}
    post_tool_use.handle_post_tool_use("antigravity", {"conversationId": "s", "stepIdx": 1, "toolCall": {"id": "c1", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 50}}}, state_dir=str(sdir))

    # Scenario A: concurrent read mutation changes reads in ledger between plan and commit
    planned_a = read_planner.plan_file_read_verdict(sdir, str(target), 1, 100, 0, 2, min_tier=1, call_id="c2")
    assert planned_a.outcome.decision == {"decision": "allow", "overwrite": {"StartLine": 51, "EndLine": 100}}
    with state_store.locked_state(sdir) as txn:
        txn.state["files"][canon]["reads"].append([51, 100, 1, 2])
        txn.dirty = True
    res_a = read_planner.commit_planned_file_read(planned_a)
    assert res_a.decision == {"decision": "allow"} and res_a.intervention is None
    assert "c2" not in (json.loads(state_store.state_file_in(sdir).read_text(encoding="utf-8"))["files"][canon].get("pending_reads") or {})
    assert "aborted stale plan" in capsys.readouterr().err

    # Scenario B: concurrent file modification changes sha256 between plan and commit
    planned_b = read_planner.plan_file_read_verdict(sdir, str(target), 1, 120, 0, 3, min_tier=1, call_id="c3")
    assert "overwrite" in planned_b.outcome.decision
    target.write_text("\n".join(f"mutated_{i} = {i}" for i in range(1, 150)) + "\n", encoding="utf-8")
    res_b = read_planner.commit_planned_file_read(planned_b)
    assert res_b.decision == {"decision": "allow"} and res_b.intervention is None
    assert "aborted stale plan" in capsys.readouterr().err


def test_pre_tool_use_merges_pack_overwrite_on_read_file_and_skips_followup_on_discard(
    tmp_path: Path, isolated_user_env: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "big_src.py"
    safe_copy = tmp_path / "safe_copy.py"
    src_text = "\n".join(f"v_{i} = {i}" for i in range(1, 150)) + "\n"
    target.write_text(src_text, encoding="utf-8")
    safe_copy.write_text(src_text, encoding="utf-8")
    opt_src = (
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n"
        "def evaluate(ctx):\n"
        "    if ctx.canonical_tool == 'read_file' and 'big_src.py' in str(ctx.canonical_args.get('Path', '')):\n"
        f"        return PolicyDecision(decision='allow', overwrite={{'Path': {str(safe_copy)!r}}})\n"
        "    return None\n"
        "PACK_MANIFEST = PolicyPackManifest(pack_id='read-opt', api_version=POLICY_API_VERSION, "
        "kind='optimization', covered_domains=('opt',), evaluate=evaluate)\n"
    )
    _, opt_entry = _write_pack(isolated_user_env / ".config" / "context-guard" / "policies", "read-opt", opt_src, kind="optimization", scopes=[])
    _write_cfg(isolated_user_env, {"read_confirm_policy": "bounded", "optimizers": {"range_trim": "active"}, "policy_packs": [opt_entry]})
    sdir = tmp_path / "state"
    safe_canon = os.path.realpath(str(safe_copy))

    try:
        # 1) Untrimmed read STILL retains Pass-1 pack_ow Path rewrite
        r1 = pre_tool_use.evaluate_hook(
            {"conversationId": "s-merge", "stepIdx": 1, "toolCall": {"id": "m1", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 50}}},
            state_dir=str(sdir),
        )
        assert r1 == {"decision": "allow", "overwrite": {"Path": str(safe_copy)}}
        post_tool_use.handle_post_tool_use("antigravity", {"conversationId": "s-merge", "stepIdx": 1, "toolCall": {"id": "m1", "name": "read_file", "args": {"Path": str(safe_copy), "StartLine": 1, "EndLine": 50}}}, state_dir=str(sdir))

        # 2) Range-trimmed read merges Pass-1 pack_ow AND planner StartLine/EndLine overwrite
        r2 = pre_tool_use.evaluate_hook(
            {"conversationId": "s-merge", "stepIdx": 2, "toolCall": {"id": "m2", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 100}}},
            state_dir=str(sdir),
        )
        assert r2 == {"decision": "allow", "overwrite": {"Path": str(safe_copy), "StartLine": 51, "EndLine": 100}}

        # 3) Pass-2 discard keeps followup_resolution=None and leaves pending_followup_kind intact
        mcp_dir = tmp_path / ".system_generated" / "steps" / "77"
        mcp_dir.mkdir(parents=True)
        mcp_file = mcp_dir / "output.txt"
        mcp_file.write_text(json.dumps({"file_name": "secret_inner.py", "content": "\n".join(f"d_{i} = {i}" for i in range(200))}) + (" " * 17000), encoding="utf-8")
        mcp_canon = os.path.realpath(str(mcp_file))
        with state_store.locked_state(sdir) as txn:
            txn.state["files"][mcp_canon] = {
                "sha256": file_io.compute_file_sha256(mcp_canon),
                "reads": [],
                "outlined": True,
                "pending_followup_kind": "outline",
            }
            txn.dirty = True
        outcomes.open_outcome_window("antigravity", "unknown", "outline", "s-merge", mcp_canon, 1, regret_window_steps=8, ledger_path=sdir / "outcomes.json")
        monkeypatch.setattr(
            pre_tool_use, "verify_security_policies_post_transform",
            lambda call, cfg, **kw: {"decision": "deny", "reason": "blocked unwrapped"} if "secret_inner.py" in str(call.canonical_args.get("Path") or "") else None,
        )
        r_disc = pre_tool_use.evaluate_hook(
            {"conversationId": "s-merge", "stepIdx": 3, "toolCall": {"id": "m3", "name": "read_file", "args": {"Path": str(mcp_file), "StartLine": 1, "EndLine": 30}}},
            state_dir=str(sdir),
        )
        assert r_disc == {"decision": "allow"}
        st_after = json.loads(state_store.state_file_in(sdir).read_text(encoding="utf-8"))
        assert st_after["files"][mcp_canon]["pending_followup_kind"] == "outline"
        assert len(outcomes.load_outcomes(sdir / "outcomes.json")["open_windows"]) == 1
        assert outcomes.load_outcomes(sdir / "outcomes.json")["by_key"].get("antigravity|unknown|outline", {}).get("recovery", {}).get("targeted", 0) == 0
        assert safe_canon in st_after["files"]
    finally:
        config.clear_config_cache()


def test_post_tool_use_unified_caps_cursor_empty_text_synthetic_redirect_and_batch(
    tmp_path: Path, isolated_user_env: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_cfg(isolated_user_env, {"read_confirm_policy": "bounded", "optimizers": {"range_trim": "active", "auto_outline": "off"}})
    sdir = tmp_path / "state"
    # 1) Unified caps: Antigravity 42,000 B (<= 46,080) -> tier 1; Cursor 70,000 B (<= 80,000) -> tier 2
    ag_42k = tmp_path / "ag_42k.py"
    ag_42k.write_text(("x = '" + ("a" * 98) + "'\n") * 400, encoding="utf-8")
    assert 40_000 < ag_42k.stat().st_size <= 46_080
    assert pre_tool_use.evaluate_hook({"conversationId": "s-caps", "stepIdx": 1, "toolCall": {"id": "ag-42k", "name": "read_file", "args": {"Path": str(ag_42k), "StartLine": 1, "EndLine": 400}}}, state_dir=str(sdir)) == {"decision": "allow"}
    post_tool_use.handle_post_tool_use("antigravity", {"conversationId": "s-caps", "stepIdx": 1, "toolCall": {"id": "ag-42k", "name": "read_file", "args": {"Path": str(ag_42k), "StartLine": 1, "EndLine": 400}}}, state_dir=str(sdir))
    assert state_store.read_state_snapshot(sdir)["files"][os.path.realpath(str(ag_42k))]["reads"] == [[1, 400, 1, 1]]

    cur_70k = tmp_path / "cur_70k.py"
    cur_lines = [("y = '" + ("b" * 70) + "'\n") for _ in range(900)]
    cur_text = "".join(cur_lines)
    cur_70k.write_text(cur_text, encoding="utf-8")
    assert 60_000 < cur_70k.stat().st_size <= 80_000
    pre_tool_use.evaluate_hook({"session_id": "s-cur", "call_id": "cur-70k", "tool_name": "Read", "tool_input": {"file_path": str(cur_70k), "offset": 1, "limit": 900}}, state_dir=str(sdir), cli_harness="cursor")
    post_tool_use.handle_post_tool_use("cursor", {"session_id": "s-cur", "call_id": "cur-70k", "tool_name": "Read", "tool_input": {"file_path": str(cur_70k), "offset": 1, "limit": 900}, "tool_output": cur_text}, state_dir=str(sdir))
    assert state_store.read_state_snapshot(sdir)["files"][os.path.realpath(str(cur_70k))]["reads"] == [[1, 900, 1, 2]]

    # 2) Cursor empty text/content dicts MUST drop to tier=0 (neither provisional nor tier=1)
    small = tmp_path / "cur_empty.py"
    small.write_text("\n".join(f"z_{i} = {i}" for i in range(1, 30)) + "\n", encoding="utf-8")
    for idx, empty_out in enumerate(({"text": ""}, {"content": ""})):
        cid = f"cur-empty-{idx}"
        pre_tool_use.evaluate_hook({"session_id": "s-cur", "call_id": cid, "tool_name": "Read", "tool_input": {"file_path": str(small), "offset": 1, "limit": 10}}, state_dir=str(sdir), cli_harness="cursor")
        post_tool_use.handle_post_tool_use("cursor", {"session_id": "s-cur", "call_id": cid, "tool_name": "Read", "tool_input": {"file_path": str(small), "offset": 1, "limit": 10}, "tool_output": empty_out}, state_dir=str(sdir))
    assert state_store.read_state_snapshot(sdir)["files"][os.path.realpath(str(small))]["reads"] == []

    # 3) Synthetic call_id + redirected MCP path matches pending entry via redirect_path in _locate_pending_entry
    _write_cfg(isolated_user_env, {"read_confirm_policy": "bounded", "optimizers": {"range_trim": "active", "auto_outline": "active"}})
    mcp_dir = tmp_path / ".system_generated" / "steps" / "88"
    mcp_dir.mkdir(parents=True)
    mcp_file = mcp_dir / "output.txt"
    unwrapped = mcp_dir / "redir_target.py"
    mcp_file.write_text(json.dumps({"file_name": "redir_target.py", "content": "\n".join(f"u_{i} = {i}" for i in range(400))}) + (" " * 17000), encoding="utf-8")
    read_planner.handle_file_read_verdict(sdir, str(mcp_file), 1, 20, 0, 1, allow_auto_outline=False, call_id="", synthetic_id=True)
    assert unwrapped.is_file()
    mcp_canon = os.path.realpath(str(mcp_file))
    assert "pending_reads" in state_store.read_state_snapshot(sdir)["files"][mcp_canon]
    post_tool_use.handle_post_tool_use("antigravity", {"conversationId": "s-synth", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(unwrapped), "StartLine": 1, "EndLine": 20}}}, state_dir=str(sdir))
    assert "pending_reads" not in state_store.read_state_snapshot(sdir)["files"][mcp_canon]

    # 4) PostToolBatch with DeleteFile invalidates cache, reconciles mutation windows, and runs on_tool_completed
    seen_hooks: list[tuple[str, str]] = []
    hook_src = (
        "from policies.api import POLICY_API_VERSION, PolicyPackManifest\n"
        f"OUT_LOG = {str(tmp_path / 'hook_events.jsonl')!r}\n"
        "def on_done(pctx):\n"
        "    import json\n"
        "    with open(OUT_LOG, 'a', encoding='utf-8') as fh:\n"
        "        fh.write(json.dumps([pctx.canonical_tool, list(pctx.mutated_paths)]) + '\\n')\n"
        "PACK_MANIFEST = PolicyPackManifest(pack_id='batch-obs', api_version=POLICY_API_VERSION, "
        "kind='optimization', covered_domains=('obs',), evaluate=lambda _c: None, on_tool_completed=on_done)\n"
    )
    _, hook_entry = _write_pack(isolated_user_env / ".config" / "context-guard" / "policies", "batch-obs", hook_src, kind="optimization", scopes=[])
    _write_cfg(isolated_user_env, {"read_confirm_policy": "bounded", "optimizers": {"range_trim": "active"}, "policy_packs": [hook_entry]})
    outcomes.open_outcome_window("claude", "claude-sonnet-4-6", "range_trim", "s-batch", os.path.realpath(str(cur_70k)), 1, regret_window_steps=8, ledger_path=sdir / "outcomes.json")
    post_tool_use.handle_post_tool_use(
        "claude",
        {"session_id": "s-batch", "tool_calls": [{"tool_name": "DeleteFile", "tool_input": {"file_path": str(cur_70k)}}]},
        state_dir=str(sdir), event_name="PostToolBatch",
    )
    cur_canon = os.path.realpath(str(cur_70k))
    assert cur_canon not in state_store.read_state_snapshot(sdir)["files"]
    assert outcomes.load_outcomes(sdir / "outcomes.json")["open_windows"] == {}
    seen_hooks.extend(tuple(json.loads(ln)) for ln in (tmp_path / "hook_events.jsonl").read_text(encoding="utf-8").splitlines())
    assert ["delete_file", [str(cur_70k)]] in [[t, p] for t, p in seen_hooks]

    # 5) handle_post_tool_use passes state_dir=None to governor and formats SpoolDecision via harness_adapter
    gov_dirs: list[Any] = []

    def _cap_gov(c: Any, h: str, **kw: Any) -> Any:
        gov_dirs.append(kw.get("state_dir"))
        return c

    monkeypatch.setattr(post_tool_use, "apply_runtime_governor", _cap_gov)
    monkeypatch.setattr(post_tool_use.spool_store, "spool_post_tool_output", lambda *a, **kw: (SpoolDecision("claude", {"summary": "spooled"}, "text", {}), None))
    _write_cfg(isolated_user_env, {"optimizers": {"output_spool": "active"}})
    sp_res = post_tool_use.handle_post_tool_use("claude", {"session_id": "s-sp", "tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": {"output": "ok"}}, state_dir=None)
    assert gov_dirs == [None]
    assert sp_res == {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": {"summary": "spooled"}}}
    config.clear_config_cache()


def test_policy_engine_with_overwrite_preserves_all_fields_and_fallback_canonicalizes_symlinks(
    tmp_path: Path, isolated_user_env: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    norm = NormalizedToolCall(
        harness="claude", canonical_tool="edit_file", canonical_args={"Path": str(tmp_path / "old.py")},
        original_tool_name="Edit", original_tool_input={"file_path": str(tmp_path / "old.py")},
        session_id="s1", step_idx=1, cwd=str(tmp_path), artifact_dir=None,
        mutated_paths=(str(tmp_path / "old.py"),), call_id="", has_synthetic_call_id=True,
        workspace_roots=(str(tmp_path), "/ws/two"),
    )
    updated = policy_engine.apply_overwrite_to_call(norm, {"file_path": "sub/new.py"})
    assert updated.has_synthetic_call_id is True
    assert updated.workspace_roots == (str(tmp_path), "/ws/two")
    assert updated.canonical_args["Path"] == str(tmp_path / "sub/new.py")
    assert updated.mutated_paths == (str(tmp_path / "sub/new.py"),)

    # Scoped fallback must resolve `../` and symlinks to protected prefixes
    prot_dir = tmp_path / "protected"
    prot_dir.mkdir()
    secret = prot_dir / "secret.txt"
    secret.write_text("top-secret", encoding="utf-8")
    alias = tmp_path / "alias_dir"
    if os.name != "nt":
        alias.symlink_to(prot_dir)

    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    _, sec_entry = _write_pack(
        policies_dir, "fb-sec", "PACK_MANIFEST = None\n",
        scopes=["file_mutation"], fallback_matchers={"protected_path_prefixes": [str(prot_dir) + "/"]},
    )
    (policies_dir / "fb-sec" / "pack.py").write_text("# tampered\n", encoding="utf-8")
    cfg: dict[str, Any] = {"policy_packs": [sec_entry]}
    trav_norm = NormalizedToolCall(
        harness="claude", canonical_tool="edit_file", canonical_args={"Path": "sub/../protected/secret.txt"},
        original_tool_name="Edit", original_tool_input={"file_path": "sub/../protected/secret.txt"},
        session_id="s1", step_idx=1, cwd=str(tmp_path), artifact_dir=None, mutated_paths=("sub/../protected/secret.txt",),
    )
    trav_dec = policy_engine.apply_policy_packs(trav_norm, cfg)
    assert trav_dec is not None and trav_dec["decision"] == "deny"
    if os.name != "nt":
        sym_del = NormalizedToolCall(
            harness="claude", canonical_tool="delete_file", canonical_args={"Path": str(alias / "secret.txt")},
            original_tool_name="DeleteFile", original_tool_input={"file_path": str(alias / "secret.txt")},
            session_id="s1", step_idx=1, cwd=str(tmp_path), artifact_dir=None, mutated_paths=(str(alias / "secret.txt"),),
        )
        assert policy_engine.infer_tool_scopes(sym_del) == ("file_mutation",)
        sym_dec = policy_engine.apply_policy_packs(sym_del, cfg)
        assert sym_dec is not None and sym_dec["decision"] == "deny"
        # Pass-2 security error MUST deny even with fallback_norm present
        act, _ = policy_engine.reconcile_post_transform(sym_del, cfg, fallback_norm=norm)
        assert act == "deny"

    # Namespace collision check inside post-tool hooks and session transitions
    hook_calls: list[str] = []
    p_src = (
        "from policies.api import POLICY_API_VERSION, PolicyPackManifest\n"
        f"LOG = {str(tmp_path / 'ns_log.txt')!r}\n"
        "def _cb(*_a):\n"
        "    with open(LOG, 'a', encoding='utf-8') as f: f.write('called\\n')\n"
        "PACK_MANIFEST = PolicyPackManifest(pack_id='dup-a', api_version=POLICY_API_VERSION, "
        "kind='optimization', covered_domains=(), evaluate=lambda _c: None, on_session_transition=_cb)\n"
    )
    _, e1 = _write_pack(policies_dir, "dup-a", p_src, kind="optimization", scopes=[])
    _, e2 = _write_pack(policies_dir, "dup_a", p_src.replace("dup-a", "dup_a"), kind="optimization", scopes=[])
    policy_engine.notify_session_transition("session_end", {}, {"policy_packs": [e1, e2]})
    assert not (tmp_path / "ns_log.txt").exists() and hook_calls == []


def test_harness_adapter_delete_file_and_notebook_read_cell_id() -> None:
    for payload, h in (
        ({"session_id": "s", "tool_name": "Delete", "tool_input": {"file_path": "a.py"}}, "claude"),
        ({"session_id": "s", "tool_name": "DeleteFile", "tool_input": {"path": "a.py"}}, "cursor"),
        ({"conversationId": "s", "stepIdx": 1, "toolCall": {"name": "delete_file", "args": {"Path": "a.py"}}}, "antigravity"),
    ):
        del_norm = harness_adapter.normalize_pre_tool_payload(payload, cli_harness=h)
        assert del_norm.canonical_tool == "delete_file"
        assert del_norm.mutated_paths == ("a.py",)
        assert policy_engine.infer_tool_scopes(del_norm) == ("file_mutation",)

    nb_norm = harness_adapter.normalize_pre_tool_payload(
        {"session_id": "s", "tool_name": "NotebookRead", "tool_input": {"notebook_path": "/repo/nb.ipynb", "cell_id": "cell-7"}},
        cli_harness="claude",
    )
    assert nb_norm.canonical_tool == "NotebookRead"
    assert nb_norm.canonical_args == {"Path": "/repo/nb.ipynb", "cell_id": "cell-7"}
    nb_out = harness_adapter.format_pre_tool_output(
        {"decision": "allow", "overwrite": {"Path": "/safe/nb.ipynb"}}, nb_norm,
    )
    assert nb_out["hookSpecificOutput"]["updatedInput"] == {"notebook_path": "/safe/nb.ipynb", "cell_id": "cell-7"}

    # Non-finite floats in overwrite fall back safely via core.platform_io.safe_finite_int
    rd_norm = harness_adapter.normalize_pre_tool_payload(
        {"session_id": "s", "tool_name": "Read", "tool_input": {"file_path": "/repo/a.py", "offset": 1, "limit": 50}},
        cli_harness="claude",
    )
    rd_out = harness_adapter.format_pre_tool_output(
        {"decision": "allow", "overwrite": {"StartLine": float("nan"), "EndLine": float("inf")}}, rd_norm,
    )
    assert rd_out["hookSpecificOutput"]["updatedInput"] == {"file_path": "/repo/a.py", "offset": 1, "limit": 50}
    assert harness_adapter.format_post_tool_spool_response("claude", SpoolDecision("claude", {"k": 1}, "text", {})) == {
        "hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": {"k": 1}}
    }
    assert harness_adapter.format_post_tool_spool_response("cursor", SpoolDecision("cursor", "sp", "text", {})) == {
        "updated_mcp_tool_output": {"content": [{"type": "text", "text": "sp"}]}
    }
    assert harness_adapter.format_post_tool_spool_response("cursor", SpoolDecision("cursor", {"text": "sp"}, "text", {})) == {
        "updated_mcp_tool_output": {"text": "sp"}
    }
    assert harness_adapter.format_post_tool_spool_response("claude", None) == {}


def test_commit_planned_file_read_avoids_in_lock_hashing_and_plain_rehash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdir = tmp_path / "state"
    target = tmp_path / "ledger_perf.py"
    target.write_text("\n".join(f"val_{i} = {i}" for i in range(1, 140)) + "\n", encoding="utf-8")

    lock_held = [False]
    hash_calls: list[tuple[str, str, bool]] = []
    real_compute = file_io.compute_file_sha256
    real_stat_sha = file_io.stat_and_compute_file_sha256

    def _spy_compute(path: str) -> str | None:
        hash_calls.append(("compute", os.path.realpath(path), lock_held[0]))
        return real_compute(path)

    def _spy_stat_sha(path: str) -> tuple[str | None, file_io.FileStatIdentity | None]:
        hash_calls.append(("stat_sha", os.path.realpath(path), lock_held[0]))
        return real_stat_sha(path)

    @contextmanager
    def _tracking_lock(p: Path) -> Iterator[Any]:
        with state_store.locked_state(p) as txn:
            lock_held[0] = True
            try:
                yield txn
            finally:
                lock_held[0] = False

    monkeypatch.setattr(file_io, "compute_file_sha256", _spy_compute)
    monkeypatch.setattr(file_io, "stat_and_compute_file_sha256", _spy_stat_sha)

    # 1) Plain untrimmed read hashes once in plan and 0 times in commit
    hash_calls.clear()
    pl_plain = read_planner.plan_file_read_verdict(
        sdir, str(target), 1, 40, 0, 1, min_tier=1, call_id="c1", locked_state_fn=_tracking_lock,
    )
    assert len(hash_calls) == 1 and hash_calls[0][2] is False
    hash_calls.clear()
    res_plain = read_planner.commit_planned_file_read(pl_plain)
    assert res_plain.decision == {"decision": "allow"}
    assert hash_calls == []
    post_tool_use.handle_post_tool_use(
        "antigravity",
        {"conversationId": "s-lock", "stepIdx": 1, "toolCall": {"id": "c1", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 40}}},
        state_dir=str(sdir),
    )

    # 2) Trimmed read hashes pre-lock in commit, 0 times inside lock
    hash_calls.clear()
    pl_trim = read_planner.plan_file_read_verdict(
        sdir, str(target), 1, 80, 0, 2, min_tier=1, call_id="c2", locked_state_fn=_tracking_lock,
    )
    assert pl_trim.outcome.decision == {"decision": "allow", "overwrite": {"StartLine": 41, "EndLine": 80}}
    res_trim = read_planner.commit_planned_file_read(pl_trim)
    assert res_trim.decision == {"decision": "allow", "overwrite": {"StartLine": 41, "EndLine": 80}}
    assert [c for c in hash_calls if c[2]] == [] and len(hash_calls) == 2

    # 3) Redirected read against existing unwrapped artifact performs 0 hashes inside lock
    mcp_dir = tmp_path / ".system_generated" / "steps" / "91"
    mcp_dir.mkdir(parents=True)
    mcp_file = mcp_dir / "output.txt"
    inner_py = mcp_dir / "inner_redir.py"
    code = "\n".join(f"def f_{i}() -> int:\n    return {i}" for i in range(150))
    mcp_file.write_text(json.dumps({"file_name": "inner_redir.py", "content": code}) + (" " * 17000), encoding="utf-8")
    assert read_planner.handle_file_read_verdict(sdir, str(mcp_file), 1, -1, 0, 3, call_id="c-ol").decision["decision"] == "deny"
    assert inner_py.is_file()

    hash_calls.clear()
    pl_redir = read_planner.plan_file_read_verdict(
        sdir, str(mcp_file), 1, 30, 0, 4, call_id="c3", locked_state_fn=_tracking_lock,
    )
    assert pl_redir.outcome.decision.get("overwrite", {}).get("Path") == os.path.realpath(str(inner_py))
    res_redir = read_planner.commit_planned_file_read(pl_redir)
    assert res_redir.decision.get("overwrite", {}).get("Path") == os.path.realpath(str(inner_py))
    assert [c for c in hash_calls if c[2]] == []


def test_commit_planned_file_read_catches_race_in_lock_and_same_stat_trim_mutation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    sdir = tmp_path / "state"
    target = tmp_path / "stale_race.py"
    original = "\n".join(f"aa_{i:03d} = {i:04d}" for i in range(1, 130)) + "\n"
    target.write_text(original, encoding="utf-8")
    canon = os.path.realpath(str(target))

    assert read_planner.handle_file_read_verdict(sdir, str(target), 1, 40, 0, 1, min_tier=1, call_id="c1").decision == {"decision": "allow"}
    post_tool_use.handle_post_tool_use(
        "antigravity",
        {"conversationId": "s-race", "stepIdx": 1, "toolCall": {"id": "c1", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 40}}},
        state_dir=str(sdir),
    )

    # 1) Same-size, preserved-mtime_ns mutation between plan and commit on a trimmed plan
    st_before = os.stat(target)
    pl_same = read_planner.plan_file_read_verdict(sdir, str(target), 1, 90, 0, 2, min_tier=1, call_id="c-same")
    assert pl_same.outcome.decision == {"decision": "allow", "overwrite": {"StartLine": 41, "EndLine": 90}}
    mutated_same = original.replace("aa_", "bb_")
    assert len(mutated_same.encode("utf-8")) == len(original.encode("utf-8"))
    target.write_text(mutated_same, encoding="utf-8")
    os.utime(target, ns=(st_before.st_atime_ns, st_before.st_mtime_ns))
    assert pl_same.meta is not None and file_io.stat_file_identity(str(target)) == pl_same.meta.target_stat
    res_same = read_planner.commit_planned_file_read(pl_same)
    assert res_same.decision == {"decision": "allow"} and res_same.intervention is None
    assert "aborted stale plan" in capsys.readouterr().err
    saved = json.loads(state_store.state_file_in(sdir).read_text(encoding="utf-8"))
    assert "c-same" not in (saved["files"][canon].get("pending_reads") or {})

    # 2) Concurrent mutation right before lock entry caught inside lock by stat_file_identity
    assert read_planner.handle_file_read_verdict(sdir, str(target), 1, 40, 0, 3, min_tier=1, call_id="c2").decision == {"decision": "allow"}
    post_tool_use.handle_post_tool_use(
        "antigravity",
        {"conversationId": "s-race", "stepIdx": 3, "toolCall": {"id": "c2", "name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 40}}},
        state_dir=str(sdir),
    )

    @contextmanager
    def _mutating_before_lock_body(p: Path) -> Iterator[Any]:
        target.write_text(mutated_same + "extra_race_line = 999\n", encoding="utf-8")
        with state_store.locked_state(p) as txn:
            yield txn

    pl_race = read_planner.plan_file_read_verdict(sdir, str(target), 1, 80, 0, 4, min_tier=1, call_id="c-race")
    assert pl_race.outcome.decision == {"decision": "allow", "overwrite": {"StartLine": 41, "EndLine": 80}}
    pl_race = pl_race._replace(locked_state_fn=_mutating_before_lock_body)
    res_race = read_planner.commit_planned_file_read(pl_race)
    assert res_race.decision == {"decision": "allow"} and res_race.intervention is None
    assert "aborted stale plan" in capsys.readouterr().err
    saved_after = json.loads(state_store.state_file_in(sdir).read_text(encoding="utf-8"))
    assert "c-race" not in (saved_after["files"][canon].get("pending_reads") or {})
