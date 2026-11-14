"""Session lifecycle, compaction boundary, rewind pruning, and state dir resolution tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hooks import outcomes, pre_compact, pre_invocation, state_store
from hooks.pre_invocation import handle_pre_invocation
from hooks.session_lifecycle import apply_compaction_boundary, prune_state_on_rewind
from hooks.state_store import state_file_in


def test_resolve_state_dir_isolates_agent_id_while_preserving_direct_artifact_dir(
    tmp_path: Path,
) -> None:
    resolved_session = state_store.resolve_state_dir(
        {"session_id": "sess-parent", "agent_id": "sub-worker-1"},
        None,
    )
    assert resolved_session.parent.name == "subagents"
    assert resolved_session.name.startswith("sub-worker-1-")

    resolved_explicit = state_store.resolve_state_dir(
        {"artifactDirectoryPath": "/tmp/art-parent", "agent_id": "sub-worker-1"},
        str(tmp_path),
    )
    assert resolved_explicit.parent == tmp_path / "subagents"
    assert resolved_explicit.name.startswith("sub-worker-1-")

    assert (
        state_store.resolve_state_dir(
            {"artifactDirectoryPath": "/tmp/art-parent", "agent_id": "sub-worker-1"}, None
        )
        == Path("/tmp/art-parent")
    )


def test_corrupt_session_state_quarantined_with_warn_and_hooks_log_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sd = tmp_path / "corrupt_sd"
    sd.mkdir(parents=True)
    sf = sd / state_store.STATE_FILENAME
    sf.write_text("{broken json", encoding="utf-8")

    with state_store.locked_state(sd) as txn:
        assert txn.state == {"files": {}}

    err_state = capsys.readouterr().err
    assert "corrupt" in err_state.lower()
    assert (sd / f"{state_store.STATE_FILENAME}.corrupt").is_file()

    def raise_oserror(*_a: object, **_kw: object) -> object:
        raise OSError("simulated lock failure")

    sd_pc = tmp_path / "pc_sd"
    sd_pc.mkdir(parents=True)
    (sd_pc / state_store.STATE_FILENAME).write_text('{"files": {}}', encoding="utf-8")
    monkeypatch.setattr(pre_compact, "locked_state", raise_oserror)
    assert pre_compact.handle_pre_compact({"session_id": "s1"}, state_dir=str(sd_pc)) == {}
    assert "simulated lock failure" in capsys.readouterr().err

    monkeypatch.setattr(pre_invocation, "locked_state", raise_oserror)
    assert (
        pre_invocation.handle_pre_invocation(
            {"conversationId": "c1", "initialNumSteps": 5}, state_dir=str(sd_pc)
        )
        == {}
    )
    assert "simulated lock failure" in capsys.readouterr().err


def test_checkpoint_prunes_pre_checkpoint_files_and_preserves_newer_ones(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    transcript = tmp_path / "transcript.jsonl"

    state: dict[str, Any] = {
        "files": {
            "/tmp/pre_cp.py": {"sha256": "aaa", "reads": [[1, 40, 120]]},
            "/tmp/post_cp.py": {"sha256": "bbb", "reads": [[1, 40, 262]]},
        },
        "gitlab_fallback_allowed": ["group/repo-a"],
        "bq_raw_fallback_allowed": ["proj.dataset.tbl"],
    }

    sf = state_file_in(state_dir)
    sf.write_text(json.dumps(state), encoding="utf-8")

    lines = [
        json.dumps({"step_index": 120, "type": "GENERIC", "content": "pre-checkpoint work"}),
        json.dumps(
            {
                "step_index": 258,
                "source": "SYSTEM",
                "type": "CHECKPOINT",
                "content": "# Resuming after checkpoint",
            }
        ),
        json.dumps({"step_index": 262, "type": "USER_INPUT", "content": "post-checkpoint prompt"}),
    ]
    transcript.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = handle_pre_invocation(
        {
            "conversationId": "conv-def05-cp",
            "initialNumSteps": 263,
            "transcriptPath": str(transcript),
        },
        state_dir=str(state_dir),
    )
    assert res == {}

    updated = json.loads(sf.read_text(encoding="utf-8"))
    assert updated["last_checkpoint_step"] == 258
    assert "gitlab_fallback_allowed" not in updated
    assert "bq_raw_fallback_allowed" not in updated
    assert "/tmp/pre_cp.py" not in updated["files"]
    assert "/tmp/post_cp.py" in updated["files"]

    apply_compaction_boundary(updated, checkpoint_step=None)
    assert updated["files"] == {}


def test_rewind_never_raises_max_tool_step_idx_upwards(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True)
    transcript = tmp_path / "transcript.jsonl"

    sf = state_file_in(state_dir)
    sf.write_text(
        json.dumps(
            {
                "files": {
                    "/tmp/keep.py": {"sha256": "k", "reads": [[1, 10, 2]]},
                    "/tmp/drop.py": {"sha256": "d", "reads": [[1, 10, 12]]},
                },
                "max_inv_steps": 30,
                "max_tool_step_idx": 4,
                "max_step_idx": 4,
            }
        ),
        encoding="utf-8",
    )
    transcript.write_text(
        json.dumps({"step_index": 9, "type": "USER_INPUT", "content": "rewound"}) + "\n",
        encoding="utf-8",
    )

    res = handle_pre_invocation(
        {
            "conversationId": "conv-def05-rw",
            "initialNumSteps": 10,
            "transcriptPath": str(transcript),
        },
        state_dir=str(state_dir),
    )
    assert res == {}

    updated = json.loads(sf.read_text(encoding="utf-8"))
    assert updated["max_inv_steps"] == 10
    assert updated["max_tool_step_idx"] == 4
    assert updated["max_step_idx"] == 4
    assert "/tmp/keep.py" in updated["files"]
    assert "/tmp/drop.py" not in updated["files"]

    raw_state: dict[str, Any] = {
        "max_inv_steps": 30,
        "max_tool_step_idx": 4,
        "max_step_idx": 4,
    }
    assert prune_state_on_rewind(raw_state, 3, inclusive=True) is True
    assert raw_state["max_tool_step_idx"] == 3
    assert raw_state["max_step_idx"] == 3


def test_inspect_transcript_checkpoint_merges_full_subagent_and_skips_self_rescan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compact_p = tmp_path / "transcript.jsonl"
    full_p = tmp_path / "transcript_full.jsonl"
    compact_p.write_text(
        json.dumps(
            {
                "step_index": 0,
                "type": "USER_INPUT",
                "content": "truncated...",
                "truncated_fields": ["content"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    full_p.write_text(
        json.dumps(
            {
                "step_index": 0,
                "type": "USER_INPUT",
                "content": "<SYSTEM_MESSAGE>Subagent</SYSTEM_MESSAGE>\nYou have been spawned as a subagent.",
            }
        )
        + "\n"
        + json.dumps({"step_index": 15, "type": "CHECKPOINT", "content": "checkpoint"})
        + "\n",
        encoding="utf-8",
    )
    scan = pre_invocation.inspect_transcript_checkpoint(str(compact_p), None)
    assert scan.last_cp_step == 15
    assert scan.cursor is not None
    assert scan.cursor["is_subagent"] is True

    calls = 0
    orig_scan = pre_invocation.scan_jsonl_incremental

    def counting_scan(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        return orig_scan(*args, **kwargs)

    monkeypatch.setattr(pre_invocation, "scan_jsonl_incremental", counting_scan)
    pre_invocation.inspect_transcript_checkpoint(str(full_p), None)
    assert calls == 1


def test_rewind_in_pre_tool_use_prunes_future_reads_and_outlines(tmp_path: Path) -> None:
    from hooks.pre_tool_use import evaluate_hook

    sample_file = tmp_path / "sample.py"
    sample_file.write_text("\n".join(f"line {i}" for i in range(1, 201)), encoding="utf-8")
    state_dir = str(tmp_path / "state")
    mcp_dir = tmp_path / ".system_generated" / "steps" / "12"
    mcp_dir.mkdir(parents=True)
    large_mcp = mcp_dir / "output.txt"
    large_mcp.write_text(
        json.dumps(
            {
                "file_name": "rewound_service.py",
                "file_path": "pkg/rewound_service.py",
                "content": "\n".join(f"def fn_{i}() -> int:\n    return {i}\n" for i in range(90)),
            }
        )
        + (" " * 16_000),
        encoding="utf-8",
    )

    evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 10,
            "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 1, "EndLine": 50}},
        },
        state_dir=state_dir,
    )
    res_outline = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 12,
            "toolCall": {"name": "read_file", "args": {"Path": str(large_mcp)}},
        },
        state_dir=state_dir,
    )
    assert res_outline["decision"] == "deny"
    assert "CONTEXT-GUARD AUTO-OUTLINE" in res_outline["reason"]

    # Rewinding to step 2 prunes step 10's read so 1..80 is NOT trimmed, and prunes step 12's MCP outline.
    res_after_rewind = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 2,
            "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 1, "EndLine": 80}},
        },
        state_dir=state_dir,
    )
    assert res_after_rewind == {"decision": "allow"}

    res_reoutline = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 3,
            "toolCall": {"name": "read_file", "args": {"Path": str(large_mcp)}},
        },
        state_dir=state_dir,
    )
    assert res_reoutline["decision"] == "deny"
    assert "CONTEXT-GUARD AUTO-OUTLINE" in res_reoutline["reason"]


def test_parallel_reads_in_same_step_do_not_trigger_rewind_prune(tmp_path: Path) -> None:
    from hooks.pre_tool_use import evaluate_hook

    sample_file = tmp_path / "sample.py"
    sample_file.write_text("\n".join(f"line {i}" for i in range(1, 201)), encoding="utf-8")
    state_dir = str(tmp_path / "state")
    evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 5,
            "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 1, "EndLine": 40}},
        },
        state_dir=state_dir,
    )
    res_trim_same_step = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 5,
            "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 20, "EndLine": 60}},
        },
        state_dir=state_dir,
    )
    assert res_trim_same_step == {"decision": "allow", "overwrite": {"StartLine": 41, "EndLine": 60}}


def test_prune_on_tool_rewind_keeps_invocation_high_water_mark() -> None:
    state = {
        "files": {"/x.py": {"sha256": "a", "reads": [[1, -1, 12]]}},
        "max_inv_steps": 25,
        "max_tool_step_idx": 12,
        "max_step_idx": 12,
    }
    assert prune_state_on_rewind(state, 3, inclusive=True) is True
    assert state["max_inv_steps"] == 25
    assert state["max_tool_step_idx"] == 3
    assert state["max_step_idx"] == 3
    assert state["files"] == {}


def test_rewind_deletes_entry_with_malformed_reads() -> None:
    state = {
        "files": {
            "/bad": {"sha256": "a", "reads": "oops", "outlined": True, "outlined_step": 1},
            "/missing": {"sha256": "c", "outlined": True, "outlined_step": 1},
            "/ok": {"sha256": "b", "reads": [[1, 5, 1]]},
        }
    }
    assert prune_state_on_rewind(state, 3, inclusive=True) is True
    assert state["files"] == {"/ok": {"sha256": "b", "reads": [[1, 5, 1]]}}


def test_auto_outline_large_transcript_jsonl_and_targeted_read(tmp_path: Path) -> None:
    from hooks.pre_tool_use import evaluate_hook

    state_dir = str(tmp_path / "state")
    logs_dir = tmp_path / "state" / ".system_generated" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    transcript_file = logs_dir / "transcript.jsonl"
    lines = [
        json.dumps(
            {
                "step_index": idx,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "content": f"Step {idx} response payload " + ("x" * 500),
                "truncated_fields": ["content"] if idx == 44 else [],
            }
        )
        for idx in range(45)
    ]
    transcript_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert transcript_file.stat().st_size >= 16 * 1024

    res_first = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 10,
            "toolCall": {"name": "read_file", "args": {"Path": str(transcript_file)}},
        },
        state_dir=state_dir,
    )
    assert res_first["decision"] == "deny"
    assert "CONTEXT-GUARD AUTO-OUTLINE" in res_first["reason"]
    assert "transcript.jsonl (45 JSONL lines" in res_first["reason"]
    assert "L45: step_index=44 type=PLANNER_RESPONSE" in res_first["reason"]
    assert "truncated=['content']" in res_first["reason"]

    res_targeted = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 11,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(transcript_file), "StartLine": 44, "EndLine": 45},
            },
        },
        state_dir=state_dir,
    )
    assert res_targeted["decision"] == "allow"


def test_transcript_jsonl_outline_after_narrow_read_includes_requested_span_and_tools(
    tmp_path: Path,
) -> None:
    from hooks.pre_tool_use import evaluate_hook

    state_dir = str(tmp_path / "state")
    logs_dir = tmp_path / "state" / ".system_generated" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    transcript_file = logs_dir / "transcript.jsonl"
    lines = [
        json.dumps(
            {
                "step_index": idx,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "tool_calls": [{"name": "read_file"}] if idx == 20 else [],
                "content": f"Step {idx} payload " + ("y" * 400),
            }
        )
        for idx in range(60)
    ]
    transcript_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res_narrow = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 40,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(transcript_file), "StartLine": 55, "EndLine": 60},
            },
        },
        state_dir=state_dir,
    )
    assert res_narrow["decision"] == "allow"

    res_wide = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 41,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(transcript_file), "StartLine": 10, "EndLine": 34},
            },
        },
        state_dir=state_dir,
    )
    assert res_wide["decision"] == "deny"
    assert "CONTEXT-GUARD AUTO-OUTLINE" in res_wide["reason"]
    assert "L21: step_index=20 type=PLANNER_RESPONSE source=MODEL tools=[read_file]" in res_wide["reason"]


def test_prune_state_on_rewind_clears_transcript_cursor_on_partial_rewind() -> None:
    state_gt: dict[str, Any] = {
        "last_checkpoint_step": 10,
        "transcript_cursor": {"offset": 500, "last_cp_step": 10},
        "files": {},
    }
    assert prune_state_on_rewind(state_gt, current_step=5, inclusive=True) is True
    assert "transcript_cursor" not in state_gt
    assert state_gt["last_checkpoint_step"] == 0

    state_eq: dict[str, Any] = {
        "last_checkpoint_step": 5,
        "transcript_cursor": {"offset": 500, "last_cp_step": 5},
        "files": {},
    }
    assert prune_state_on_rewind(state_eq, current_step=5, inclusive=True) is True
    assert "transcript_cursor" not in state_eq
    assert state_eq["last_checkpoint_step"] == 0

    state_lt: dict[str, Any] = {
        "last_checkpoint_step": 3,
        "transcript_cursor": {"offset": 500, "last_cp_step": 3},
        "files": {},
    }
    assert prune_state_on_rewind(state_lt, current_step=5, inclusive=True) is False
    assert "transcript_cursor" in state_lt
    assert state_lt["last_checkpoint_step"] == 3
