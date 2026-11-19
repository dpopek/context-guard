"""Read Ledger v2, 3-tier confirmation, Claude PostToolBatch, and provisional isolation tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from hooks import config as guard_config, post_tool_use, pre_tool_use, read_planner, state_store
from hooks.harness_adapter import extract_apply_patch_paths, probe_runtime_capabilities
from hooks.outcomes import ledger_path_for
from hooks.state_store import READ_LEDGER_SCHEMA, locked_state, merge_intervals, state_file_in
from tests.harness_payload_fixtures import (
    ag_post_read_payload,
    ag_pre_read_payload,
    claude_batch_read_item,
    claude_post_batch_payload,
    claude_post_failure_payload,
    claude_post_read_payload,
    claude_pre_read_payload,
    cursor_post_read_payload,
    cursor_pre_read_payload,
    format_claude_read_gutter,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_numbered_file(path: Path, count: int = 40, prefix: str = "line") -> tuple[Path, list[str]]:
    lines = [f"{prefix}_{i:03d} = {i}" for i in range(1, count + 1)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path, lines


def _set_read_confirm_policy(home_dir: Path, policy: str, extra: dict[str, Any] | None = None) -> None:
    cfg: dict[str, Any] = {"read_confirm_policy": policy}
    if extra:
        cfg.update(extra)
    cfg_path = home_dir / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    guard_config.clear_config_cache()


def _load_state(state_dir: Path) -> dict[str, Any]:
    return json.loads(state_file_in(state_dir).read_text(encoding="utf-8"))


def _load_stats(stats_path: Path) -> dict[str, Any]:
    return json.loads(stats_path.read_text(encoding="utf-8"))


def _load_outcomes(state_dir: Path) -> dict[str, Any]:
    lp = ledger_path_for(str(state_dir))
    assert lp is not None and lp.is_file()
    return json.loads(lp.read_text(encoding="utf-8"))


def test_schema_v2_downgrade_defense_same_tier_merge_and_pre_merge_min_tier_filtering() -> None:
    assert READ_LEDGER_SCHEMA == 2
    assert merge_intervals([[1, 20, 1], [1, 10, 1, True], [1, 10, 1, 0], [1, 10, 1, 3]]) == []

    # Same-tier adjacent ranges coalesce; cross-tier ranges remain isolated.
    merged = merge_intervals([[1, 20, 1, 2], [21, 30, 2, 2], [25, 45, 3, 1], [46, 60, 4, 1]])
    assert merged == [[1, 30, 2, 2], [25, 60, 4, 1]]

    reads = [[1, 20, 1, 2], [21, 40, 2, 1]]
    assert read_planner.covering_read_step(reads, 5, 18, target_lines=60, min_tier=2) == 1
    assert read_planner.covering_read_step(reads, 15, 35, target_lines=60, min_tier=2) is None
    assert read_planner.covering_read_step(reads, 15, 35, target_lines=60, min_tier=1) is not None

    # strict (min_tier=2) trims only against [1, 20], NOT [21, 40].
    assert read_planner.trim_partially_covered_range(reads, 10, 50, target_lines=60, min_tier=2) == (21, 50)
    # bounded (min_tier=1) uses both intervals while never downgrading tier=2 in reads.
    assert read_planner.trim_partially_covered_range(reads, 10, 50, target_lines=60, min_tier=1) == (41, 50)


def test_normalize_read_body_fingerprint_handles_crlf_and_uniform_gutters() -> None:
    fn = read_planner.normalize_read_body_fingerprint
    plain = "alpha\nbeta\ngamma"
    crlf = "alpha\r\nbeta\rgamma"
    gutter_arrow = format_claude_read_gutter(["alpha", "beta", "gamma"], start_line=1, sep="→")
    gutter_tab = format_claude_read_gutter(["alpha", "beta", "gamma"], start_line=10, sep="\t")
    assert fn(crlf) == fn(plain)
    assert fn(gutter_arrow) == fn(plain)
    assert fn(gutter_tab) == fn(plain)
    # Non-uniform gutter (line without gutter prefix) must NOT strip prefix.
    mixed = "     1→alpha\nbeta"
    assert fn(mixed) != fn(plain)


def test_plan_file_read_verdict_is_pure_and_pass2_block_writes_no_unwrap_or_pending(
    tmp_path: Path, isolated_user_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    step_dir = tmp_path / ".system_generated" / "steps" / "77"
    step_dir.mkdir(parents=True)
    mcp_file = step_dir / "output.txt"
    inner_py = step_dir / "secret_target.py"
    code = "\n".join(f"def fn_{i}():\n    return {i}" for i in range(100))
    mcp_file.write_text(json.dumps({"file_name": "secret_target.py", "content": code}) + (" " * 17000), encoding="utf-8")

    state_dir = tmp_path / "state"
    planned = read_planner.plan_file_read_verdict(state_dir, str(mcp_file), 1, 20, 0, 1, allow_auto_outline=False, call_id="c1")
    assert planned.outcome.decision.get("overwrite", {}).get("Path") == os.path.realpath(str(inner_py))
    assert not inner_py.exists()
    assert not state_file_in(state_dir).exists()

    # Pass-2 rejecting the rewritten target cancels commit cleanly (zero unwrap file & zero pending_reads).
    # Pre-mark outlined so evaluate_hook plans Path redirect instead of outline-deny.
    with locked_state(state_dir) as txn:
        txn.state["files"][os.path.realpath(str(mcp_file))] = {"sha256": pre_tool_use.compute_file_sha256(str(mcp_file)), "reads": [], "outlined": True}
        txn.dirty = True
    monkeypatch.setattr(
        pre_tool_use,
        "verify_security_policies_post_transform",
        lambda call, cfg, **kw: {"decision": "deny", "reason": "blocked target"}
        if "secret_target.py" in str(call.canonical_args.get("Path") or "")
        else None,
    )
    res = pre_tool_use.evaluate_hook(
        ag_pre_read_payload(mcp_file, start_line=1, end_line=20, step_idx=1, call_id="c1"),
        state_dir=str(state_dir),
    )
    assert res == {"decision": "allow"}
    assert not inner_py.exists()
    assert "pending_reads" not in _load_state(state_dir)["files"].get(os.path.realpath(str(mcp_file)), {})


def test_claude_post_tool_use_succeeds_but_post_tool_batch_truncated_or_modified_blocks_tier2_and_evicts_tier1(
    tmp_path: Path, isolated_user_env: Path
) -> None:
    _set_read_confirm_policy(isolated_user_env, "bounded")
    f, lines = _write_numbered_file(tmp_path / "mod.py", 30)
    canon = os.path.realpath(str(f))
    state_dir = tmp_path / "state"
    stats_path = state_dir / "telemetry_stats.json"

    pre_res = pre_tool_use.evaluate_hook(
        claude_pre_read_payload(f, offset=1, limit=15, tool_use_id="toolu_evict_1"),
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert pre_res == {}
    st_pre = _load_state(state_dir)
    assert st_pre["read_ledger_schema"] == 2
    assert st_pre["files"][canon]["reads"] == []
    assert "toolu_evict_1" in st_pre["files"][canon]["pending_reads"]

    # PostToolUse alone stays provisional inside pending_reads (NEVER appended to active reads).
    post_tool_use.handle_post_tool_use(
        "claude",
        claude_post_read_payload(f, tool_use_id="toolu_evict_1", start_line=1, num_lines=15, total_lines=30),
        stats_path=stats_path,
        state_dir=state_dir,
    )
    st_mid = _load_state(state_dir)
    assert st_mid["files"][canon]["reads"] == []
    assert st_mid["files"][canon]["pending_reads"]["toolu_evict_1"]["post_stage"] == "tool_executed"
    assert st_mid["files"][canon]["pending_reads"]["toolu_evict_1"]["provisional_tier"] == 1
    assert st_mid["files"][canon]["pending_reads"]["toolu_evict_1"]["credited"] is False

    # Even under "bounded", overlapping PreToolUse MUST NOT trim against unconfirmed provisional tier=1!
    overlap_pre = pre_tool_use.evaluate_hook(
        claude_pre_read_payload(f, offset=5, limit=15, tool_use_id="toolu_evict_overlap"),
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert overlap_pre == {}

    # Terminal PostToolBatch arrives truncated -> evicts provisional tier=1 & records tier=0 with zero credit.
    batch_payload = claude_post_batch_payload(
        [
            claude_batch_read_item(
                f,
                tool_use_id="toolu_evict_1",
                response=format_claude_read_gutter(lines[:10], start_line=1),
                start_line=1,
                limit=15,
                truncated=True,
            )
        ]
    )
    post_tool_use.handle_post_tool_use(
        "claude",
        batch_payload,
        stats_path=stats_path,
        state_dir=state_dir,
        event_name="PostToolBatch",
    )
    st_end = _load_state(state_dir)
    assert st_end["files"][canon]["reads"] == []
    assert "toolu_evict_1" not in st_end["files"][canon]["pending_reads"]
    assert st_end["files"][canon]["completed_read_ids"]["toolu_evict_1"] == {"tier": 0, "credited": False}
    lp = ledger_path_for(str(state_dir))
    if lp is not None and lp.is_file():
        by_key = json.loads(lp.read_text(encoding="utf-8")).get("by_key", {})
        assert not any(k.endswith("|range_trim") for k in by_key)


def test_claude_post_tool_use_and_post_tool_batch_same_call_id_are_idempotent_single_credit(
    tmp_path: Path, isolated_user_env: Path
) -> None:
    f, lines = _write_numbered_file(tmp_path / "svc.py", 40)
    canon = os.path.realpath(str(f))
    state_dir = tmp_path / "state"
    stats_path = state_dir / "telemetry_stats.json"

    # Read 1: 1..20 confirmed via PostToolBatch -> tier=2 in reads.
    pre_tool_use.evaluate_hook(
        claude_pre_read_payload(f, offset=1, limit=20, tool_use_id="toolu_1"),
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    post_tool_use.handle_post_tool_use(
        "claude",
        claude_post_batch_payload(
            [
                claude_batch_read_item(
                    f,
                    tool_use_id="toolu_1",
                    response=format_claude_read_gutter(lines[:20], start_line=1),
                    start_line=1,
                    limit=20,
                )
            ]
        ),
        state_dir=state_dir,
        event_name="PostToolBatch",
    )
    assert _load_state(state_dir)["files"][canon]["reads"] == [[1, 20, 1, 2]]

    # Read 2: 10..30 overlaps 1..20 -> PreToolUse silently trims to 21..30 (NO stats/outcomes credit yet!).
    trim_res = pre_tool_use.evaluate_hook(
        claude_pre_read_payload(f, offset=10, limit=21, tool_use_id="toolu_2"),
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    updated_in = trim_res["hookSpecificOutput"]["updatedInput"]
    assert updated_in["offset"] == 21
    assert updated_in["limit"] == 10
    lp = ledger_path_for(str(state_dir))
    assert lp is None or not lp.is_file()
    assert _load_stats(stats_path).get("events", {}).get("ranges_trimmed", 0) == 0

    # First PostToolUse on toolu_2: provisional only, zero credit.
    post_tool_use.handle_post_tool_use(
        "claude",
        claude_post_read_payload(f, tool_use_id="toolu_2", start_line=21, num_lines=10, total_lines=40),
        stats_path=stats_path,
        state_dir=state_dir,
        event_name="PostToolUse",
    )
    assert _load_stats(stats_path).get("events", {}).get("ranges_trimmed", 0) == 0
    assert lp is None or not lp.is_file()

    # Terminal PostToolBatch confirms toolu_2 body -> promotes tier=2 and credits ONCE.
    batch_ok = claude_post_batch_payload(
        [
            claude_batch_read_item(
                f,
                tool_use_id="toolu_2",
                response=format_claude_read_gutter(lines[20:30], start_line=21),
                start_line=21,
                limit=10,
            )
        ]
    )
    post_tool_use.handle_post_tool_use("claude", batch_ok, stats_path=stats_path, state_dir=state_dir, event_name="PostToolBatch")
    # Replay PostToolBatch AND out-of-order late PostToolUse for same call_id -> strict no-op.
    post_tool_use.handle_post_tool_use("claude", batch_ok, stats_path=stats_path, state_dir=state_dir, event_name="PostToolBatch")
    post_tool_use.handle_post_tool_use(
        "claude",
        claude_post_read_payload(f, tool_use_id="toolu_2", start_line=21, num_lines=10, total_lines=40),
        stats_path=stats_path,
        state_dir=state_dir,
        event_name="PostToolUse",
    )

    assert _load_stats(stats_path)["events"]["ranges_trimmed"] == 1
    out_data = _load_outcomes(state_dir)
    assert out_data["by_key"]["claude|unknown|range_trim"]["applied"] == 1
    assert _load_state(state_dir)["files"][canon]["reads"] == [[1, 30, 2, 2]]
    assert _load_state(state_dir)["files"][canon]["completed_read_ids"]["toolu_2"] == {"tier": 2, "credited": True}


def test_same_line_count_different_body_fingerprint_rejected_from_content_verified(
    tmp_path: Path, isolated_user_env: Path
) -> None:
    f, lines = _write_numbered_file(tmp_path / "fp.py", 20)
    canon = os.path.realpath(str(f))
    state_dir = tmp_path / "state"

    pre_tool_use.evaluate_hook(
        claude_pre_read_payload(f, offset=1, limit=10, tool_use_id="toolu_fp"),
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    tampered = list(lines[:10])
    tampered[4] = "line_005 = 999999"  # Same line count (10), different content!
    post_tool_use.handle_post_tool_use(
        "claude",
        claude_post_batch_payload(
            [
                claude_batch_read_item(
                    f,
                    tool_use_id="toolu_fp",
                    response=format_claude_read_gutter(tampered, start_line=1),
                    start_line=1,
                    limit=10,
                )
            ]
        ),
        state_dir=state_dir,
        event_name="PostToolBatch",
    )
    assert _load_state(state_dir)["files"][canon]["reads"] == []
    assert _load_state(state_dir)["files"][canon]["completed_read_ids"]["toolu_fp"] == {"tier": 0, "credited": False}

    # Cursor same line count / different body -> rejected from tier=2 even with matching disk sha256!
    cur_state = tmp_path / "cur_state"
    pre_tool_use.evaluate_hook(
        cursor_pre_read_payload(f, offset=1, limit=10, call_id="cur_fp"),
        state_dir=str(cur_state),
        cli_harness="cursor",
    )
    post_tool_use.handle_post_tool_use(
        "cursor",
        cursor_post_read_payload(f, call_id="cur_fp", tool_output="\n".join(tampered), offset=1, limit=10),
        state_dir=str(cur_state),
    )
    assert _load_state(cur_state)["files"][canon]["reads"] == []


def test_claude_batch_text_blocks_and_failure_event_handling(
    tmp_path: Path, isolated_user_env: Path
) -> None:
    f, lines = _write_numbered_file(tmp_path / "blk.py", 20)
    canon = os.path.realpath(str(f))
    state_dir = tmp_path / "state"

    pre_tool_use.evaluate_hook(
        claude_pre_read_payload(f, offset=1, limit=10, tool_use_id="toolu_blk"),
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    post_tool_use.handle_post_tool_use(
        "claude",
        claude_post_batch_payload(
            [
                claude_batch_read_item(
                    f,
                    tool_use_id="toolu_blk",
                    response=[{"type": "text", "text": format_claude_read_gutter(lines[:10], start_line=1)}],
                    start_line=1,
                    limit=10,
                )
            ]
        ),
        state_dir=str(state_dir),
        event_name="PostToolBatch",
    )
    assert _load_state(state_dir)["files"][canon]["reads"] == [[1, 10, 1, 2]]

    pre_tool_use.evaluate_hook(
        claude_pre_read_payload(f, offset=11, limit=10, tool_use_id="toolu_fail"),
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    post_tool_use.handle_post_tool_use(
        "claude",
        claude_post_failure_payload(f, tool_use_id="toolu_fail"),
        state_dir=str(state_dir),
        event_name="PostToolUseFailure",
    )
    st = _load_state(state_dir)
    assert "toolu_fail" not in st["files"][canon].get("pending_reads", {})
    assert st["files"][canon]["completed_read_ids"]["toolu_fail"] == {"tier": 0, "credited": False}
    assert st["files"][canon]["reads"] == [[1, 10, 1, 2]]


def test_cursor_tiers_antigravity_bounded_policy_and_codex_patch_paths(
    tmp_path: Path, isolated_user_env: Path
) -> None:
    f, lines = _write_numbered_file(tmp_path / "cur.py", 30)
    canon = os.path.realpath(str(f))
    cur_state = tmp_path / "cur_state"

    # Cursor tier=1 metadata-only when redacted=False and empty string absent vs explicit metadata dict.
    pre_tool_use.evaluate_hook(
        cursor_pre_read_payload(f, offset=1, limit=10, call_id="cur_meta"),
        state_dir=str(cur_state),
        cli_harness="cursor",
    )
    post_tool_use.handle_post_tool_use(
        "cursor",
        cursor_post_read_payload(f, call_id="cur_meta", tool_output={"lines": 10, "startLine": 1}, offset=1, limit=10),
        state_dir=str(cur_state),
    )
    assert _load_state(cur_state)["files"][canon]["reads"] == [[1, 10, 1, 1]]
    # Under default strict policy, tier=1 does NOT trigger range_trim.
    res_strict = pre_tool_use.evaluate_hook(
        cursor_pre_read_payload(f, offset=5, limit=15, call_id="cur_ov"),
        state_dir=str(cur_state),
        cli_harness="cursor",
    )
    assert res_strict == {}

    # Cursor redacted output -> tier=0.
    pre_tool_use.evaluate_hook(
        cursor_pre_read_payload(f, offset=11, limit=10, call_id="cur_redacted"),
        state_dir=str(cur_state),
        cli_harness="cursor",
    )
    post_tool_use.handle_post_tool_use(
        "cursor",
        cursor_post_read_payload(f, call_id="cur_redacted", tool_output="[REDACTED]", offset=11, limit=10),
        state_dir=str(cur_state),
    )
    assert _load_state(cur_state)["files"][canon]["reads"] == [[1, 10, 1, 1]]

    # Antigravity strict (default): real toolCall.id gives tier=1, zero trimming!
    ag_state = tmp_path / "ag_state"
    pre_tool_use.evaluate_hook(ag_pre_read_payload(f, start_line=1, end_line=15, step_idx=1, call_id="ag1"), state_dir=str(ag_state))
    post_tool_use.handle_post_tool_use("antigravity", ag_post_read_payload(f, call_id="ag1", step_idx=1, start_line=1, end_line=15), state_dir=str(ag_state))
    assert _load_state(ag_state)["files"][canon]["reads"] == [[1, 15, 1, 1]]
    assert pre_tool_use.evaluate_hook(ag_pre_read_payload(f, start_line=5, end_line=25, step_idx=2, call_id="ag2"), state_dir=str(ag_state)) == {"decision": "allow"}

    # Antigravity missing toolCall.id (synthetic) -> tier=0 even under bounded!
    _set_read_confirm_policy(isolated_user_env, "bounded")
    ag_synth = tmp_path / "ag_synth"
    pre_tool_use.evaluate_hook(ag_pre_read_payload(f, start_line=1, end_line=15, step_idx=1, call_id=None), state_dir=str(ag_synth))
    post_tool_use.handle_post_tool_use("antigravity", ag_post_read_payload(f, call_id=None, step_idx=1, start_line=1, end_line=15), state_dir=str(ag_synth))
    assert _load_state(ag_synth)["files"][canon]["reads"] == []

    # Antigravity real id under bounded -> tier=1 unlocks trimming!
    res_bounded = pre_tool_use.evaluate_hook(
        ag_pre_read_payload(f, start_line=5, end_line=25, step_idx=2, call_id="ag_b2"),
        state_dir=str(ag_state),
    )
    assert res_bounded["overwrite"] == {"StartLine": 16, "EndLine": 25}

    # Codex Move to extraction + runtime capabilities probe.
    patch_text = "*** Begin Patch\n*** Update File: a.py\n*** Move to: b/c.py\n@@\n+x\n*** End Patch"
    assert extract_apply_patch_paths(patch_text) == ["a.py", "b/c.py"]
    caps = probe_runtime_capabilities("claude", version="2.1.295")
    assert caps.native_fail_closed_supported is True
    assert caps.content_verified_reads_supported is True


def test_optimizers_range_trim_off_fifo_128_and_session_end_cleanup(
    tmp_path: Path, isolated_user_env: Path
) -> None:
    _set_read_confirm_policy(isolated_user_env, "strict", {"optimizers": {"range_trim": "off"}})
    f, lines = _write_numbered_file(tmp_path / "opt.py", 30)
    canon = os.path.realpath(str(f))
    state_dir = tmp_path / "state"

    pre_tool_use.evaluate_hook(claude_pre_read_payload(f, offset=1, limit=15, tool_use_id="c1"), state_dir=str(state_dir), cli_harness="claude")
    post_tool_use.handle_post_tool_use(
        "claude",
        claude_post_batch_payload([claude_batch_read_item(f, tool_use_id="c1", response=format_claude_read_gutter(lines[:15]), start_line=1, limit=15)]),
        state_dir=str(state_dir),
        event_name="PostToolBatch",
    )
    assert _load_state(state_dir)["files"][canon]["reads"] == [[1, 15, 1, 2]]
    assert pre_tool_use.evaluate_hook(claude_pre_read_payload(f, offset=5, limit=20, tool_use_id="c2"), state_dir=str(state_dir), cli_harness="claude") == {}

    # FIFO cap <= 128 on completed_read_ids & SessionEnd clears transient pending_reads.
    with locked_state(state_dir) as txn:
        txn.state["files"][canon]["completed_read_ids"] = {f"old_{i}": {"tier": 2, "credited": False} for i in range(135)}
        txn.dirty = True
    pre_tool_use.evaluate_hook(claude_pre_read_payload(f, offset=16, limit=5, tool_use_id="c3"), state_dir=str(state_dir), cli_harness="claude")
    assert "c3" in _load_state(state_dir)["files"][canon]["pending_reads"]

    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "hooks" / "session_end.py"), "--state-dir", str(state_dir)],
        input=json.dumps({"session_id": "s1"}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {}
    assert _load_state(state_dir)["files"][canon].get("pending_reads", {}) == {}
