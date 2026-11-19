"""Operational hardening and safe-migration contract tests across Context-Guard stores and hooks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

import pytest

from services.migration_guard import RollbackJournal, StagedPackTransaction, preflight_migration_check
from evidence import ledger as evidence_ledger
from hooks import config, outcomes, policy_engine, post_tool_use, pre_tool_use, state_store
from hooks.policy_engine import PolicyPackLoadError
from policies import governor
from policies.api import ADAPTER_CONTRACT_VERSION, GOVERNOR_SCHEMA_VERSION, HARD_INTEGRITY_FAILURE_REASONS
from spool import receipts as spool_receipts, store as spool_store


def _make_workspace(base: Path, name: str = "ws") -> Path:
    ws = base / name
    (ws / ".git").mkdir(parents=True, exist_ok=True)
    return ws


def _make_spool_text(tag: str, lines: int = 240) -> str:
    return "\n".join(f"{tag}-line-{i:04d}: " + ("x" * 72) for i in range(lines))


def _pack_source_text(pack_id: str, blocked_token: str, *, api_version: int = 1) -> str:
    return (
        "from __future__ import annotations\n"
        "from policies.api import ALL_SECURITY_SCOPES, PolicyDecision, PolicyPackManifest\n\n"
        "def evaluate(ctx):\n"
        "    cmd = str(ctx.canonical_args.get('CommandLine') or ctx.canonical_args.get('command') or '')\n"
        f"    if {blocked_token!r} in cmd:\n"
        f"        return PolicyDecision(decision='deny', reason='blocked by {pack_id}')\n"
        "    return None\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        f"    pack_id={pack_id!r}, api_version={api_version}, kind='security',\n"
        "    covered_domains=ALL_SECURITY_SCOPES, evaluate=evaluate, harness_matchers={},\n"
        ")\n"
    )


def _write_verified_pack_entry(env_root: Path, pack_id: str, blocked_token: str) -> dict[str, Any]:
    pack_dir = env_root / "policies" / pack_id
    pack_dir.mkdir(parents=True, exist_ok=True)
    raw = _pack_source_text(pack_id, blocked_token).encode("utf-8")
    entry_file = pack_dir / "pack.py"
    entry_file.write_bytes(raw)
    fh = hashlib.sha256(raw).hexdigest()
    tree_sha = hashlib.sha256(f"pack.py:{fh}\n".encode("utf-8")).hexdigest()
    return {
        "id": pack_id, "path": str(entry_file), "enabled": True, "kind": "security",
        "scopes": ["file_mutation", "shell_command", "mcp_call"],
        "file_hashes": {"pack.py": fh}, "tree_sha256": tree_sha,
    }


def _find_leaked_temps(directory: Path) -> list[str]:
    if not directory.is_dir():
        return []
    return sorted(
        p.name for p in directory.rglob("*")
        if p.name.endswith((".tmp", ".spool")) or p.name.startswith((".tmp.", ".cg_state.", ".outcomes."))
    )


def _isolate_env(monkeypatch: pytest.MonkeyPatch, root: Path, cfg_payload: dict[str, Any]) -> dict[str, Path]:
    home_d, cg_d, spool_d, state_d = root / "home", root / "cg_home", root / "spool", root / "state"
    for d in (home_d, root / "xdg", root / "appdata", root / "localappdata", cg_d, spool_d, state_d):
        d.mkdir(parents=True, exist_ok=True)
    cfg_path = root / "config.json"
    cfg_path.write_text(json.dumps(cfg_payload, indent=2), encoding="utf-8")
    for env_k, env_v in (
        ("HOME", home_d), ("USERPROFILE", home_d), ("XDG_CONFIG_HOME", root / "xdg"),
        ("APPDATA", root / "appdata"), ("LOCALAPPDATA", root / "localappdata"),
        ("CONTEXT_GUARD_HOME", cg_d), ("CONTEXT_GUARD_CONFIG_PATH", cfg_path), ("CONTEXT_GUARD_SPOOL_DIR", spool_d),
    ):
        monkeypatch.setenv(env_k, str(env_v))
    config.clear_config_cache()
    policy_engine.clear_pack_cache()
    return {"cfg_path": cfg_path, "spool_dir": spool_d, "state_dir": state_d}


def test_hardening_harness_upgrade_invalidates_attestations_without_lowering_security(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_root = tmp_path / "env"
    pack_entry = _write_verified_pack_entry(env_root, "upgrade_sec", "forbidden_upgrade_op")
    base_opts = {
        "range_trim": "active", "auto_outline": "active", "cli_rewrites": "auto",
        "output_spool": "active", "dynamic_tool_mutation": "active",
    }
    cfg_v1: dict[str, Any] = {
        "read_confirm_policy": "strict",
        "optimizers": dict(base_opts),
        "governor": {
            "harness_build_id": "claude_cli_100",
            "adapter_version": ADAPTER_CONTRACT_VERSION,
            "require_runtime_verified": True,
        },
        "policy_packs": [pack_entry],
    }
    paths = _isolate_env(monkeypatch, env_root, cfg_v1)
    gov_dir = paths["state_dir"]

    for cap_id in governor.GOVERNED_CAPABILITIES:
        att = governor.attest_capability(
            "claude", cap_id, verification_evidence=f"probe:{cap_id}:ok",
            harness_build_id="claude_cli_100", runtime_cfg=cfg_v1, state_dir=gov_dir,
        )
        assert att["runtime_verified"] is True

    before = governor.evaluate_governor("claude", runtime_cfg=cfg_v1, state_dir=gov_dir)
    assert before["schema_version"] == GOVERNOR_SCHEMA_VERSION
    assert before["security_enforcement_lowered"] is False
    assert before["decisions"]["output_spool"]["selected_mode"] == "active"
    assert before["decisions"]["dynamic_tool_mutation"]["selected_mode"] == "active"

    cfg_v2 = {
        **cfg_v1,
        "governor": {
            "harness_build_id": "claude_cli_200",
            "adapter_version": ADAPTER_CONTRACT_VERSION,
            "require_runtime_verified": True,
        },
    }
    after_build = governor.evaluate_governor("claude", runtime_cfg=cfg_v2, state_dir=gov_dir)
    assert after_build["security_enforcement_lowered"] is False
    assert after_build["capabilities"]["output_replacement"]["runtime_verified"] is False
    assert after_build["capabilities"]["output_replacement"]["invalidated_reason"] == "build_changed"
    assert after_build["decisions"]["output_spool"]["downgraded"] is True
    assert after_build["decisions"]["output_spool"]["selected_mode"] in ("shadow", "passthrough")
    assert after_build["decisions"]["dynamic_tool_mutation"]["downgraded"] is True

    after_adapter = governor.evaluate_governor(
        "claude", runtime_cfg=cfg_v1, state_dir=gov_dir, adapter_version="harness_adapter_v2",
    )
    assert after_adapter["capabilities"]["pre_tool_interception"]["invalidated_reason"] == "adapter_changed"
    after_fp = governor.evaluate_governor("claude", runtime_cfg={**cfg_v1, "read_confirm_policy": "bounded"}, state_dir=gov_dir)
    assert after_fp["capabilities"]["pre_tool_interception"]["invalidated_reason"] == "config_fingerprint_changed"

    assert "integrity_mismatch" in HARD_INTEGRITY_FAILURE_REASONS
    brk = governor.record_governor_signal("output_spool", "integrity_mismatch", state_dir=gov_dir)
    assert brk["tripped"] is True and brk["state"] == "open"
    denied_reset = governor.reset_circuit_breaker("output_spool", state_dir=gov_dir)
    assert denied_reset["ok"] is False
    assert denied_reset["error"] == "hysteresis_requires_verification_or_operator_reset"

    paths["cfg_path"].write_text(json.dumps(cfg_v2, indent=2), encoding="utf-8")
    config.clear_config_cache()
    policy_engine.clear_pack_cache()
    loaded_v2 = config.load_runtime_config(paths["cfg_path"])
    assert loaded_v2.get("governor", {}).get("harness_build_id") == "claude_cli_200"
    assert loaded_v2.get("governor", {}).get("require_runtime_verified") is True
    assert loaded_v2["optimizers"].get("dynamic_tool_mutation") == "active"
    ws = _make_workspace(tmp_path, "ws_upgrade")
    bad_res = pre_tool_use.evaluate_hook(
        {"tool_name": "Bash", "tool_input": {"command": "echo forbidden_upgrade_op"}, "session_id": "s_upg", "cwd": str(ws)},
        state_dir=str(gov_dir), cli_harness="claude",
    )
    assert bad_res["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "blocked by upgrade_sec" in bad_res["hookSpecificOutput"]["permissionDecisionReason"]
    safe_res = pre_tool_use.evaluate_hook(
        {"tool_name": "Bash", "tool_input": {"command": "git status"}, "session_id": "s_upg", "cwd": str(ws)},
        state_dir=str(gov_dir), cli_harness="claude",
    )
    assert safe_res.get("hookSpecificOutput", {}).get("permissionDecision") != "deny"

    ok_reset = governor.reset_circuit_breaker(
        "output_spool", state_dir=gov_dir, verification_passed=True, verification_evidence="replay:clean",
    )
    assert ok_reset["ok"] is True and ok_reset["breaker"]["tripped"] is False
    post_res = post_tool_use.handle_post_tool_use(
        "claude",
        {
            "hook_event_name": "PostToolUse", "tool_name": "Bash",
            "tool_input": {"command": "pytest"}, "tool_response": {"stdout": _make_spool_text("post_upg")},
            "session_id": "s_upg", "cwd": str(ws), "claude_version": "claude_cli_200",
        },
        state_dir=str(gov_dir),
    )
    assert post_res == {}


def test_hardening_resumed_session_reconciles_evicting_tombstones_and_dedups_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg: dict[str, Any] = {
        "read_confirm_policy": "bounded",
        "optimizers": {"range_trim": "active", "auto_outline": "active", "output_spool": "active", "cli_rewrites": "auto"},
        "policy_packs": [],
    }
    paths = _isolate_env(monkeypatch, tmp_path / "resume_env", cfg)
    ws = _make_workspace(tmp_path, "ws_resume")
    large_py = ws / "service.py"
    large_py.write_text("\n".join(f"def handler_{i:03d}(val: int) -> int:\n    return val + {i}" for i in range(130)) + "\n", encoding="utf-8")
    file_lines = large_py.read_text(encoding="utf-8").splitlines()
    sdir = paths["state_dir"]

    p1 = {
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(large_py), "StartLine": 1, "EndLine": 100}, "id": "res_1"},
        "conversationId": "conv_resume",
    }
    pre_tool_use.evaluate_hook(p1, state_dir=str(sdir), cli_harness="antigravity")
    post_tool_use.handle_post_tool_use("antigravity", {**p1, "toolResponse": "\n".join(file_lines[:100])}, state_dir=str(sdir))
    assert state_store.read_state_snapshot(sdir)["read_ledger_schema"] == 2

    config.clear_config_cache()
    p2 = {
        "toolCall": {"name": "view_file", "args": {"AbsolutePath": str(large_py), "StartLine": 1, "EndLine": 180}, "id": "res_2"},
        "conversationId": "conv_resume",
    }
    resumed_dec = pre_tool_use.evaluate_hook(p2, state_dir=str(sdir), cli_harness="antigravity")
    assert resumed_dec.get("overwrite", {}).get("StartLine") == 101

    spool_dir = paths["spool_dir"]
    rcpt_path = spool_receipts.receipts_path_for(spool_dir)
    created = spool_store.spool_tool_output(
        _make_spool_text("evict_crash"), session_id="sess_res", call_id="call_ev_1",
        harness="claude", tool_name="Bash", workspace_root=ws, spool_dir=spool_dir, now_ts=1000.0,
    )
    assert created is not None
    sid_1 = created[0].spool_id
    blob_1 = spool_dir / f"{sid_1}.txt"
    assert blob_1.is_file()

    idx_path = spool_dir / "spool_index.json"
    idx_doc = json.loads(idx_path.read_text(encoding="utf-8"))
    ent_1 = idx_doc["entries"].pop(sid_1)
    idx_doc.setdefault("tombstones", {})[sid_1] = {
        "spool_id": sid_1, "state": "evicting", "reason": "ttl_expired", "evicted_at": 2000.0,
        "workspace_id": ent_1["workspace_id"], "session_id": ent_1["session_id"],
        "total_bytes": ent_1["total_bytes"], "canon_root": ent_1.get("canon_root", ""),
    }
    idx_path.write_text(json.dumps(idx_doc), encoding="utf-8")

    mid_slice = spool_store.slice_spool(sid_1, start_line=1, limit=20, workspace_root=ws, spool_dir=spool_dir)
    assert mid_slice["ok"] is False and mid_slice["error"] == "spool_evicted" and mid_slice["eviction_reason"] == "ttl_expired"

    reconciled = spool_store.gc_spools(spool_dir=spool_dir, now_ts=2010.0)
    assert reconciled["ok"] is True and reconciled["removed_count"] == 1
    assert not blob_1.exists()
    assert json.loads(idx_path.read_text(encoding="utf-8"))["tombstones"][sid_1]["state"] == "evicted"

    created_2 = spool_store.spool_tool_output(
        _make_spool_text("dedup_check"), session_id="sess_res", call_id="call_dd_2",
        harness="claude", tool_name="Bash", workspace_root=ws, spool_dir=spool_dir, now_ts=2020.0,
    )
    assert created_2 is not None
    contract_2, summary_2 = created_2
    dup_rcpt = spool_receipts.find_created_receipt(contract_2.spool_id, session_id="sess_res", call_id="call_dd_2", receipts_path=rcpt_path)
    assert dup_rcpt is not None
    before_cnt = spool_receipts.summarize_receipts(rcpt_path)["receipt_count"]
    assert spool_receipts.append_receipt(dup_rcpt, receipts_path=rcpt_path) is True
    assert spool_receipts.summarize_receipts(rcpt_path)["receipt_count"] == before_cnt

    batch_pl = {"tool_calls": [{"tool_use_id": "call_dd_2", "tool_response": summary_2}]}
    assert spool_receipts.persist_spool_delivery_verification(
        batch_pl, harness="claude", session_id="sess_res", workspace_root=ws, spool_dir=spool_dir, receipts_path=rcpt_path,
    ) == 1
    assert spool_receipts.persist_spool_delivery_verification(
        batch_pl, harness="claude", session_id="sess_res", workspace_root=ws, spool_dir=spool_dir, receipts_path=rcpt_path,
    ) == 0

    ev_ledger = tmp_path / "evidence_events.json"
    ing_1 = evidence_ledger.ingest_context_receipts(ev_ledger, rcpt_path)
    ing_2 = evidence_ledger.ingest_context_receipts(ev_ledger, rcpt_path)
    assert ing_1["ok"] is True and ing_1["appended_count"] >= 2
    assert ing_2["ok"] is True and ing_2["appended_count"] == 0 and ing_2["duplicate_count"] == ing_1["appended_count"]


def test_hardening_retention_boundaries_ttl_entries_bytes_tombstones_and_receipt_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_env(monkeypatch, tmp_path / "ret_env", {"optimizers": {"output_spool": "active"}, "policy_packs": []})
    ws = _make_workspace(tmp_path, "ws_ret")

    d_ttl = tmp_path / "spool_ttl"
    c_ttl = spool_store.spool_tool_output(
        _make_spool_text("ttl_item"), session_id="s_ret", call_id="c_ttl",
        harness="claude", tool_name="Bash", workspace_root=ws, spool_dir=d_ttl, now_ts=1000.0,
    )
    assert c_ttl is not None
    at_boundary = spool_store.gc_spools(max_age_seconds=100.0, spool_dir=d_ttl, now_ts=1100.0)
    assert at_boundary["removed_count"] == 0 and at_boundary["remaining_count"] == 1
    past_boundary = spool_store.gc_spools(max_age_seconds=100.0, spool_dir=d_ttl, now_ts=1100.01)
    assert past_boundary["removed_count"] == 1 and past_boundary["remaining_count"] == 0
    ttl_tomb = json.loads((d_ttl / "spool_index.json").read_text(encoding="utf-8"))["tombstones"][c_ttl[0].spool_id]
    assert ttl_tomb["reason"] == "ttl_expired" and ttl_tomb["state"] == "evicted"

    spool_store.gc_spools(spool_dir=d_ttl, now_ts=1100.01 + spool_store.SPOOL_TOMBSTONE_MAX_AGE_SECONDS + 5.0)
    assert json.loads((d_ttl / "spool_index.json").read_text(encoding="utf-8"))["tombstones"] == {}

    d_ent = tmp_path / "spool_entries"
    sids_ent: list[str] = []
    for i in range(4):
        sp = spool_store.spool_tool_output(
            _make_spool_text(f"ent_{i}"), session_id="s_ret", call_id=f"c_ent_{i}",
            harness="claude", tool_name="Bash", workspace_root=ws, spool_dir=d_ent, now_ts=100.0 + i * 10.0,
        )
        assert sp is not None
        sids_ent.append(sp[0].spool_id)
    assert spool_store.slice_spool(sids_ent[0], start_line=1, limit=5, workspace_root=ws, spool_dir=d_ent, now_ts=200.0)["ok"] is True
    gc_ent = spool_store.gc_spools(max_entries=2, spool_dir=d_ent, now_ts=250.0)
    assert gc_ent["removed_count"] == 2 and gc_ent["remaining_count"] == 2
    idx_ent = json.loads((d_ent / "spool_index.json").read_text(encoding="utf-8"))
    assert set(idx_ent["entries"]) == {sids_ent[0], sids_ent[3]}
    for evicted_sid in (sids_ent[1], sids_ent[2]):
        assert idx_ent["tombstones"][evicted_sid]["reason"] == "max_entries_lru"

    d_bytes = tmp_path / "spool_bytes"
    sids_b, sizes_b = [], []
    for i in range(3):
        sp_b = spool_store.spool_tool_output(
            _make_spool_text(f"bytes_{i}"), session_id="s_ret", call_id=f"c_b_{i}",
            harness="claude", tool_name="Bash", workspace_root=ws, spool_dir=d_bytes, now_ts=10.0 + i,
        )
        assert sp_b is not None
        sids_b.append(sp_b[0].spool_id)
        sizes_b.append(sp_b[0].total_bytes)
    cap_two = sizes_b[1] + sizes_b[2] + 64
    gc_b = spool_store.gc_spools(max_entries=64, max_total_bytes=cap_two, spool_dir=d_bytes, now_ts=50.0)
    assert gc_b["removed_count"] == 1 and gc_b["remaining_count"] == 2
    idx_b = json.loads((d_bytes / "spool_index.json").read_text(encoding="utf-8"))
    assert idx_b["tombstones"][sids_b[0]]["reason"] == "max_bytes_lru"

    for extra_i in range(spool_store.SPOOL_MAX_TOMBSTONES + 5):
        fake_sid = f"sp_{extra_i:012x}"
        idx_b["tombstones"][fake_sid] = {
            "spool_id": fake_sid, "state": "evicted", "reason": "ttl_expired",
            "evicted_at": 60.0 + extra_i, "workspace_id": "ws_0123456789abcdef",
            "session_id": "s_ret", "total_bytes": 100,
        }
    (d_bytes / "spool_index.json").write_text(json.dumps(idx_b), encoding="utf-8")
    spool_store.gc_spools(max_entries=64, max_total_bytes=cap_two, spool_dir=d_bytes, now_ts=300.0)
    assert len(json.loads((d_bytes / "spool_index.json").read_text(encoding="utf-8"))["tombstones"]) == spool_store.SPOOL_MAX_TOMBSTONES

    rcpt_dir = tmp_path / "spool_rot"
    rcpt_dir.mkdir(parents=True, exist_ok=True)
    rcpt_path = rcpt_dir / "receipts.jsonl"
    assert spool_receipts.RECEIPTS_MAX_BYTES == 512 * 1024 and spool_receipts.RECEIPTS_KEEP_ROWS == 256
    pad = "p" * 1850
    seed_lines = [
        json.dumps(
            dict(spool_receipts.build_receipt(
                event_type="spool_recovery", harness="cli", session_id="s_rot",
                workspace_id="ws_0123456789abcdef", turn_key="", call_id=f"c_{i}",
                spool_id="sp_0123456789ab", line_span=(1, 10), byte_span=(0, 100),
                delivery_evidence="unverified", spool_id_referenced=True, event_id=f"ev_{i:016x}", reason=pad,
            )),
            separators=(",", ":"), sort_keys=True,
        ) + "\n"
        for i in range(299)
    ]
    rcpt_path.write_text("".join(seed_lines), encoding="utf-8")
    assert rcpt_path.stat().st_size > spool_receipts.RECEIPTS_MAX_BYTES
    last_rcpt = spool_receipts.build_receipt(
        event_type="spool_recovery", harness="cli", session_id="s_rot",
        workspace_id="ws_0123456789abcdef", turn_key="", call_id="c_299",
        spool_id="sp_0123456789ab", line_span=(1, 10), byte_span=(0, 100),
        delivery_evidence="unverified", spool_id_referenced=True, event_id=f"ev_{299:016x}", reason=pad,
    )
    assert spool_receipts.append_receipt(last_rcpt, receipts_path=rcpt_path) is True
    kept_objs = [json.loads(ln) for ln in rcpt_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert kept_objs[0]["_meta"] == "receipts_rotation"
    assert kept_objs[0]["dropped_rows"] == 44 and kept_objs[0]["retained_rows"] == spool_receipts.RECEIPTS_KEEP_ROWS
    kept_rows = [obj for obj in kept_objs if obj.get("_meta") != "receipts_rotation"]
    assert len(kept_rows) == spool_receipts.RECEIPTS_KEEP_ROWS
    assert len(spool_receipts.load_receipt_rows(rcpt_path)) == spool_receipts.RECEIPTS_KEEP_ROWS
    kept_ids = [obj["event_id"] for obj in kept_rows]
    assert f"ev_{299:016x}" in kept_ids and f"ev_{0:016x}" not in kept_ids
    assert _find_leaked_temps(rcpt_dir) == []


def test_hardening_disk_full_enospc_and_corrupt_files_fail_safe_without_temp_leaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_root = tmp_path / "enospc_env"
    pack_entry = _write_verified_pack_entry(env_root, "enospc_sec", "forbidden_enospc_cmd")
    cfg: dict[str, Any] = {
        "read_confirm_policy": "bounded",
        "optimizers": {"range_trim": "active", "auto_outline": "active", "output_spool": "active", "cli_rewrites": "auto"},
        "policy_packs": [pack_entry],
    }
    paths = _isolate_env(monkeypatch, env_root, cfg)
    ws = _make_workspace(tmp_path, "ws_enospc")
    sample_py = ws / "mod.py"
    sample_py.write_text("\n".join(f"X_{i} = {i}" for i in range(60)) + "\n", encoding="utf-8")
    sdir, spool_dir = paths["state_dir"], paths["spool_dir"]
    real_replace = os.replace

    def _enospc_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        dst_s = os.fspath(dst)
        if dst_s.startswith(str(sdir)) or dst_s.startswith(str(spool_dir)):
            raise OSError(errno.ENOSPC, "No space left on device")
        real_replace(src, dst)

    with monkeypatch.context() as mp:
        mp.setattr(os, "replace", _enospc_replace)
        with pytest.raises(state_store.StatePersistenceError):
            with state_store.locked_state(sdir) as txn:
                txn.state["auto_step_seq"], txn.dirty = 7, True
        assert spool_store.spool_tool_output(
            _make_spool_text("enospc_blob"), session_id="s_full", call_id="c_full",
            harness="claude", tool_name="Bash", workspace_root=ws, spool_dir=spool_dir,
        ) is None
        allow_res = pre_tool_use.evaluate_hook(
            {"tool_name": "Read", "tool_input": {"file_path": str(sample_py), "offset": 1, "limit": 30}, "session_id": "s_full", "cwd": str(ws)},
            state_dir=str(sdir), cli_harness="claude",
        )
        assert allow_res.get("hookSpecificOutput", {}).get("permissionDecision") != "deny"
        deny_res = pre_tool_use.evaluate_hook(
            {"tool_name": "Bash", "tool_input": {"command": "echo forbidden_enospc_cmd"}, "session_id": "s_full", "cwd": str(ws)},
            state_dir=str(sdir), cli_harness="claude",
        )
        assert deny_res["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "blocked by enospc_sec" in deny_res["hookSpecificOutput"]["permissionDecisionReason"]
        assert post_tool_use.handle_post_tool_use(
            "claude",
            {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": {"stdout": _make_spool_text("post_enospc")}, "session_id": "s_full", "cwd": str(ws)},
            state_dir=str(sdir),
        ) == {}

    assert _find_leaked_temps(sdir) == [] and _find_leaked_temps(spool_dir) == []

    corrupt_sdir = tmp_path / "corrupt_state"
    corrupt_sdir.mkdir(parents=True)
    (corrupt_sdir / ".context_guard_state.json").write_text("{broken_state_json", encoding="utf-8")
    with state_store.locked_state(corrupt_sdir) as txn:
        assert txn.state["read_ledger_schema"] == 2
        txn.state["auto_step_seq"], txn.dirty = 3, True
    assert (corrupt_sdir / ".context_guard_state.json.corrupt").is_file()

    corrupt_spool = tmp_path / "corrupt_spool"
    corrupt_spool.mkdir(parents=True)
    (corrupt_spool / "spool_index.json").write_text("{not_valid_spool_index", encoding="utf-8")
    assert spool_store.spool_tool_output(
        _make_spool_text("after_corrupt_idx"), session_id="s_cor", call_id="c_cor",
        harness="claude", tool_name="Bash", workspace_root=ws, spool_dir=corrupt_spool,
    ) is not None
    assert any(p.name.startswith(".spool_index.corrupt.") for p in corrupt_spool.iterdir())

    corrupt_out = corrupt_sdir / "outcomes.json"
    corrupt_out.write_text("{corrupt_outcomes", encoding="utf-8")
    assert outcomes.load_outcomes(corrupt_out)["schema_version"] == 4
    outcomes.record_direct_outcome("claude", "sonnet", "outline", "applied", ledger_path=corrupt_out, session_id="s_c", step_idx=1, call_id="c_1")
    assert any(p.name.startswith("outcomes.json.corrupt") for p in corrupt_sdir.iterdir())
    assert json.loads(corrupt_out.read_text(encoding="utf-8"))["schema_version"] == 4

    corrupt_gov = tmp_path / "corrupt_gov"
    corrupt_gov.mkdir(parents=True)
    (corrupt_gov / "governor_state.json").write_text("{corrupt_governor", encoding="utf-8")
    assert governor.is_optimizer_tripped("output_spool", state_dir=corrupt_gov) is True
    gov_eval = governor.evaluate_governor("claude", runtime_cfg=cfg, state_dir=corrupt_gov)
    assert gov_eval["security_enforcement_lowered"] is False
    assert gov_eval["decisions"]["output_spool"]["selected_mode"] == "passthrough"


def test_hardening_permission_errors_and_unsafe_symlinks_handled_gracefully(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_root = tmp_path / "perm_env"
    pack_entry = _write_verified_pack_entry(env_root, "perm_sec", "forbidden_perm_cmd")
    cfg: dict[str, Any] = {
        "read_confirm_policy": "strict",
        "optimizers": {"range_trim": "active", "output_spool": "active", "cli_rewrites": "auto"},
        "policy_packs": [pack_entry],
    }
    _isolate_env(monkeypatch, env_root, cfg)
    ws = _make_workspace(tmp_path, "ws_perm")
    denied_root = tmp_path / "denied_area"
    denied_spool, denied_state = denied_root / "spool", denied_root / "state"
    denied_spool.mkdir(parents=True)
    denied_state.mkdir(parents=True)

    real_open, real_mkstemp = os.open, tempfile.mkstemp

    def _eacces_open(path: str | os.PathLike[str], flags: int, mode: int = 0o777, **kw: Any) -> int:
        if os.fspath(path).startswith(str(denied_root)):
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real_open(path, flags, mode, **kw)

    def _eacces_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        if str(kwargs.get("dir") or "").startswith(str(denied_root)):
            raise PermissionError(errno.EACCES, "Permission denied", str(kwargs.get("dir")))
        return real_mkstemp(*args, **kwargs)

    sample_rcpt = spool_receipts.build_receipt(
        event_type="spool_created", harness="claude", session_id="s_p",
        workspace_id="ws_0123456789abcdef", turn_key="", call_id="c_p",
        spool_id="sp_0123456789ab", line_span=(0, 10), byte_span=(0, 100),
        delivery_evidence="replacement_emitted", spool_id_referenced=False,
    )

    with monkeypatch.context() as mp:
        mp.setattr(os, "open", _eacces_open)
        mp.setattr(tempfile, "mkstemp", _eacces_mkstemp)
        assert spool_store.spool_tool_output(
            _make_spool_text("eacces_blob"), session_id="s_p", call_id="c_p",
            harness="claude", tool_name="Bash", workspace_root=ws, spool_dir=denied_spool,
        ) is None
        assert spool_receipts.append_receipt(sample_rcpt, receipts_path=denied_spool / "receipts.jsonl") is False
        ok_hook = pre_tool_use.evaluate_hook(
            {"tool_name": "Bash", "tool_input": {"command": "git status"}, "session_id": "s_p", "cwd": str(ws)},
            state_dir=str(denied_state), cli_harness="claude",
        )
        assert ok_hook.get("hookSpecificOutput", {}).get("permissionDecision") != "deny"
        sec_hook = pre_tool_use.evaluate_hook(
            {"tool_name": "Bash", "tool_input": {"command": "echo forbidden_perm_cmd"}, "session_id": "s_p", "cwd": str(ws)},
            state_dir=str(denied_state), cli_harness="claude",
        )
        assert sec_hook["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "blocked by perm_sec" in sec_hook["hookSpecificOutput"]["permissionDecisionReason"]
        assert post_tool_use.handle_post_tool_use(
            "claude", {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"stdout": "ok"}, "session_id": "s_p", "cwd": str(ws)},
            state_dir=str(denied_state),
        ) == {}

    secret_file = tmp_path / "outside_secret.txt"
    secret_file.write_text("DO_NOT_OVERWRITE_SECRET\n", encoding="utf-8")
    sym_dir = tmp_path / "symlink_area"
    sym_dir.mkdir(parents=True)
    sym_rcpt, sym_idx = sym_dir / "receipts.jsonl", sym_dir / "spool_index.json"
    sym_ledger, sym_gov = sym_dir / "evidence_events.json", sym_dir / "governor_state.json"

    symlink_supported = True
    try:
        for link_p in (sym_rcpt, sym_idx, sym_ledger, sym_gov):
            link_p.symlink_to(secret_file)
    except (OSError, NotImplementedError):
        symlink_supported = False

    if symlink_supported:
        assert spool_receipts.check_unsafe_link(sym_rcpt) is True
        assert spool_receipts.append_receipt(sample_rcpt, receipts_path=sym_rcpt) is False
        assert spool_store.list_spools(workspace_root=ws, spool_dir=sym_dir) == {"ok": False, "error": "unsafe_path"}
        assert spool_store.slice_spool("sp_0123456789ab", workspace_root=ws, spool_dir=sym_dir)["error"] == "unsafe_path"
        assert spool_store.gc_spools(spool_dir=sym_dir) == {"ok": False, "error": "unsafe_path"}
        assert evidence_ledger.append_durable_events(sym_ledger, [sample_rcpt])["error"] == "unsafe_path"
        assert evidence_ledger.derive_outcomes_from_ledger(sym_ledger)["error"] == "unsafe_path"
        assert governor.is_optimizer_tripped("output_spool", state_dir=sym_dir) is True
        assert governor.attest_capability("claude", "output_replacement", verification_evidence="probe:ok", state_dir=sym_dir)["invalidated_reason"] == "unsafe_path"
        assert secret_file.read_text(encoding="utf-8") == "DO_NOT_OVERWRITE_SECRET\n"
    else:
        real_lstat = os.lstat

        def _fake_symlink_lstat(p: str | os.PathLike[str]) -> os.stat_result:
            st_res = real_lstat(secret_file)
            if os.fspath(p) in {str(sym_rcpt), str(sym_idx), str(sym_ledger), str(sym_gov)}:
                vals = list(st_res)
                vals[0] = stat.S_IFLNK | 0o777
                return os.stat_result(vals)
            return real_lstat(p)

        with monkeypatch.context() as mp:
            mp.setattr(os, "lstat", _fake_symlink_lstat)
            assert spool_receipts.check_unsafe_link(sym_rcpt) is True
            assert spool_receipts.append_receipt(sample_rcpt, receipts_path=sym_rcpt) is False
            assert evidence_ledger.append_durable_events(sym_ledger, [sample_rcpt])["error"] == "unsafe_path"


def test_hardening_concurrent_writers_and_readers_preserve_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_env(monkeypatch, tmp_path / "conc_env", {"optimizers": {"output_spool": "active"}, "policy_packs": []})
    ws = _make_workspace(tmp_path, "ws_conc")
    state_dir, spool_dir = tmp_path / "conc_state", tmp_path / "conc_spool"
    outcomes_path, ledger_path = tmp_path / "conc_outcomes.json", tmp_path / "conc_evidence.json"
    num_workers, loops_per_worker = 4, 4

    def _state_worker(w_id: int) -> list[int]:
        seen_schemas: list[int] = []
        for k in range(loops_per_worker):
            with state_store.locked_state(state_dir) as txn:
                txn.state["auto_step_seq"] = int(txn.state.get("auto_step_seq") or 0) + 1
                f_ent = txn.state.setdefault("files", {}).setdefault(f"mod_{w_id}.py", {"sha256": f"h{w_id}", "reads": []})
                f_ent["reads"] = state_store.merge_intervals([*list(f_ent.get("reads") or []), [1 + k * 10, 10 + k * 10, k + 1, 2]])
                txn.dirty = True
            seen_schemas.append(int(state_store.read_state_snapshot(state_dir)["read_ledger_schema"]))
        return seen_schemas

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        results = [f.result() for f in [pool.submit(_state_worker, w) for w in range(num_workers)]]

    assert all(s == 2 for sub in results for s in sub)
    final_snap = state_store.read_state_snapshot(state_dir)
    assert final_snap["auto_step_seq"] == num_workers * loops_per_worker
    for w_id in range(num_workers):
        assert final_snap["files"][f"mod_{w_id}.py"]["reads"] == [[1, 40, 4, 2]]
    assert _find_leaked_temps(state_dir) == []

    def _spool_and_ledger_worker(idx: int) -> str:
        sp = spool_store.spool_tool_output(
            _make_spool_text(f"conc_worker_{idx}"), session_id=f"sess_c_{idx}", call_id=f"call_c_{idx}",
            harness="claude", tool_name="Bash", workspace_root=ws, spool_dir=spool_dir, now_ts=500.0 + idx,
        )
        assert sp is not None
        sid = sp[0].spool_id
        sl = spool_store.slice_spool(sid, start_line=1, limit=15, workspace_root=ws, spool_dir=spool_dir)
        assert sl["ok"] is True and f"conc_worker_{idx}-line-0000" in sl["content"]
        assert spool_store.list_spools(workspace_root=ws, spool_dir=spool_dir)["ok"] is True
        outcomes.record_direct_outcome(
            "claude", "sonnet", "output_spool", "applied", ledger_path=outcomes_path,
            session_id=f"sess_c_{idx}", step_idx=idx + 1, call_id=f"call_c_{idx}",
        )
        rcpt = spool_receipts.find_created_receipt(sid, receipts_path=spool_receipts.receipts_path_for(spool_dir))
        assert rcpt is not None
        assert evidence_ledger.append_durable_events(ledger_path, [rcpt])["ok"] is True
        return sid

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        sids = [f.result() for f in [pool.submit(_spool_and_ledger_worker, i) for i in range(6)]]

    assert len(set(sids)) == 6
    assert spool_store.list_spools(workspace_root=ws, spool_dir=spool_dir)["count"] == 6
    assert spool_store.inspect_spool_health(spool_dir)["reliability_failures"] == 0
    assert outcomes.load_outcomes(outcomes_path)["by_key"]["claude|sonnet|output_spool"]["total"] == 6
    assert evidence_ledger.derive_outcomes_from_ledger(ledger_path)["event_count"] == 6
    assert _find_leaked_temps(spool_dir) == []


def test_hardening_safe_migrations_rollback_journal_and_schema_invariants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "mig_cfg"
    cfg_dir.mkdir(parents=True)
    cfg_path = cfg_dir / "config.json"

    v1_src, bad_src, v2_src = tmp_path / "src_v1", tmp_path / "src_bad", tmp_path / "src_v2"
    for d in (v1_src, bad_src, v2_src):
        d.mkdir()
    (v1_src / "pack.py").write_text(_pack_source_text("mig_guard", "v1_forbidden"), encoding="utf-8")
    (bad_src / "pack.py").write_text(_pack_source_text("mig_guard", "bad_api", api_version=99), encoding="utf-8")
    (v2_src / "pack.py").write_text(_pack_source_text("mig_guard", "v2_forbidden"), encoding="utf-8")

    tx1 = StagedPackTransaction(v1_src, config_path=cfg_path, journal=RollbackJournal())
    tx1.prepare()
    tx1.validate()
    activated_v1 = tx1.activate()
    tx1.commit()
    assert preflight_migration_check(activated_v1, cfg_path, extra_trusted_roots=(cfg_dir / "policies",)) == ([], [])
    live_pack = cfg_dir / "policies" / "mig_guard" / "pack.py"
    v1_pack_bytes, v1_cfg_bytes = live_pack.read_bytes(), cfg_path.read_bytes()

    tx_bad = StagedPackTransaction(bad_src, config_path=cfg_path)
    tx_bad.prepare()
    with pytest.raises(PolicyPackLoadError):
        tx_bad.validate()
    assert [p.name for p in (cfg_dir / "policies").iterdir() if p.name.startswith(".staging-")] == []
    assert live_pack.read_bytes() == v1_pack_bytes and cfg_path.read_bytes() == v1_cfg_bytes

    real_replace = os.replace

    def _fail_cfg_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        if os.path.abspath(os.fspath(dst)) == os.path.abspath(str(cfg_path)):
            raise OSError(errno.ENOSPC, "Simulated disk full on config activation")
        real_replace(src, dst)

    tx_io = StagedPackTransaction(v2_src, config_path=cfg_path)
    tx_io.prepare()
    tx_io.validate()
    with monkeypatch.context() as mp:
        mp.setattr(os, "replace", _fail_cfg_replace)
        with pytest.raises(OSError):
            tx_io.activate()

    assert live_pack.read_bytes() == v1_pack_bytes and cfg_path.read_bytes() == v1_cfg_bytes
    assert [p.name for p in (cfg_dir / "policies").iterdir() if p.name.startswith((".staging-", ".backup-"))] == []

    out_v3_path = tmp_path / "outcomes_v3.json"
    out_v3_path.write_text(
        json.dumps({
            "schema_version": 3, "updated_at": "2026-10-01T00:00:00Z",
            "by_key": {"claude|sonnet|outline": {"total": 10, "applied": 10, "targeted_followup": 3, "full_bypass": 1, "shell_bypass": 1}},
        }),
        encoding="utf-8",
    )
    loaded_v4 = outcomes.load_outcomes(out_v3_path)
    assert loaded_v4["schema_version"] == 4
    row_v3 = loaded_v4["by_key"]["claude|sonnet|outline"]
    assert row_v3["legacy_v3"] is True
    assert row_v3["recovery"] == {"none": 0, "targeted": 3, "full": 2, "pending_or_unknown": 0}
    assert row_v3["regret"] == {"none": 0, "suspected": 2, "confirmed": 0, "unknown": 3}
    rates = outcomes.compute_regret_rates(row_v3)
    assert rates["resolved"] == 2 and rates["confirmed_regret_rate"] == 0.0 and rates["suspected_regret_rate"] == 1.0

    outcomes.record_direct_outcome(
        "claude", "sonnet", "output_spool", "applied", ledger_path=out_v3_path,
        session_id="s_mig", step_idx=1, call_id="c_mig_1",
    )
    persisted_v4 = json.loads(out_v3_path.read_text(encoding="utf-8"))
    assert persisted_v4["schema_version"] == 4
    assert persisted_v4["by_key"]["claude|sonnet|outline"]["total"] == 10
    assert persisted_v4["by_key"]["claude|sonnet|output_spool"]["total"] == 1

    ev_ledger = tmp_path / "mig_evidence.json"
    ing = evidence_ledger.ingest_context_receipts(ev_ledger, tmp_path / "absent_receipts.jsonl", outcomes_path=out_v3_path)
    assert ing["ok"] is True and ing["has_migrated_baseline"] is True
    assert evidence_ledger.derive_outcomes_from_ledger(ev_ledger)["migrated_outcomes_baseline"] is not None

    legacy_sdir = tmp_path / "legacy_ledger_v1"
    legacy_sdir.mkdir(parents=True)
    legacy_sf = legacy_sdir / ".context_guard_state.json"
    legacy_sf.write_text(
        json.dumps({
            "read_ledger_schema": 1, "mutated_repos_schema": 1, "mutated_repos": ["/tmp/old_repo"],
            "files": {
                "/tmp/mod.py": {
                    "sha256": "abc123", "reads": [[1, 100, 1]],
                    "pending_reads": {"old_c": {"step": 1}}, "completed_read_ids": {"done_c": 1},
                    "outlined": True, "outlined_step": 2,
                }
            },
        }),
        encoding="utf-8",
    )
    snap_ro = state_store.read_state_snapshot(legacy_sdir)
    assert snap_ro["read_ledger_schema"] == 2 and snap_ro["files"]["/tmp/mod.py"]["reads"] == []
    assert "pending_reads" not in snap_ro["files"]["/tmp/mod.py"]
    assert json.loads(legacy_sf.read_text(encoding="utf-8"))["read_ledger_schema"] == 1

    with state_store.locked_state(legacy_sdir) as txn:
        assert txn.state["read_ledger_schema"] == 2 and "mutated_repos" not in txn.state
        assert txn.state["mutated_repos_schema"] == 2
    upgraded_disk = json.loads(legacy_sf.read_text(encoding="utf-8"))
    assert upgraded_disk["read_ledger_schema"] == 2
    assert upgraded_disk["files"]["/tmp/mod.py"]["reads"] == [] and upgraded_disk["files"]["/tmp/mod.py"]["outlined"] is True
