"""Core unit and integration tests for hooks.pre_tool_use read planner, trims, outlines, and rewind."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from hooks.config import clear_config_cache
from hooks.outline import extract_outline_symbols
from hooks.post_tool_use import handle_post_tool_use
from hooks.pre_tool_use import evaluate_hook, main
from hooks.read_planner import covering_read_step, handle_file_read_verdict
from hooks.session_lifecycle import prune_state_on_rewind
from tests.helpers import ag_read, claude_read, read_session_state


def _make_sample(tmp_path: Path, count: int = 200) -> tuple[Path, str]:
    sample = tmp_path / "sample.py"
    sample.write_text("\n".join(f"line {i}" for i in range(1, count + 1)) + "\n", encoding="utf-8")
    return sample, str(tmp_path / "state")


def test_first_read_allowed_and_recorded(tmp_path: Path) -> None:
    sample_file, state_dir = _make_sample(tmp_path)
    payload = {
        "conversationId": "conv-1",
        "stepIdx": 10,
        "toolCall": {"id": "ag-1", "name": "read_file", "args": {"Path": str(sample_file)}},
    }
    res = evaluate_hook(payload, state_dir=state_dir)
    assert res == {"decision": "allow"}

    pre_state = read_session_state(state_dir)
    canon_path = os.path.realpath(str(sample_file))
    assert canon_path in pre_state["files"]
    assert pre_state["files"][canon_path]["reads"] == []
    assert "ag-1" in pre_state["files"][canon_path]["pending_reads"]

    handle_post_tool_use("antigravity", payload, state_dir=state_dir, event_name="PostToolUse")
    state = read_session_state(state_dir)
    assert state["files"][canon_path]["reads"] == [[1, 200, 10, 1]]


def test_repeat_normal_file_read_is_allowed_in_v4(tmp_path: Path) -> None:
    sample_file, state_dir = _make_sample(tmp_path)
    p1 = {
        "conversationId": "conv-1",
        "stepIdx": 10,
        "toolCall": {"name": "read_file", "args": {"Path": str(sample_file)}},
    }
    p2 = {
        "conversationId": "conv-1",
        "stepIdx": 15,
        "toolCall": {"name": "read_file", "args": {"Path": str(sample_file)}},
    }
    assert evaluate_hook(p1, state_dir=state_dir) == {"decision": "allow"}
    assert evaluate_hook(p2, state_dir=state_dir) == {"decision": "allow"}


def test_disjoint_range_reads_allowed(tmp_path: Path) -> None:
    sample_file, state_dir = _make_sample(tmp_path)
    r1 = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 1,
            "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 1, "EndLine": 30}},
        },
        state_dir=state_dir,
    )
    r2 = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 2,
            "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 50, "EndLine": 80}},
        },
        state_dir=state_dir,
    )
    assert r1 == {"decision": "allow"}
    assert r2 == {"decision": "allow"}


def _enable_bounded_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "cg_cfg.json"
    cfg.write_text(json.dumps({"read_confirm_policy": "bounded"}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg))
    clear_config_cache()


def test_partial_overlap_reads_rewritten_via_silent_range_trim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_bounded_policy(tmp_path, monkeypatch)
    try:
        sample_file, state_dir = _make_sample(tmp_path)
        canon = os.path.realpath(str(sample_file))

        assert ag_read(sample_file, state_dir, start_line=1, end_line=50, step_idx=1, confirm=True) == {"decision": "allow"}
        res_leading = ag_read(sample_file, state_dir, start_line=30, end_line=80, step_idx=2, confirm=True)
        assert res_leading == {"decision": "allow", "overwrite": {"StartLine": 51, "EndLine": 80}}

        assert ag_read(sample_file, state_dir, start_line=120, end_line=150, step_idx=3, confirm=True) == {"decision": "allow"}
        res_trailing = ag_read(sample_file, state_dir, start_line=100, end_line=130, step_idx=4, confirm=True)
        assert res_trailing == {"decision": "allow", "overwrite": {"StartLine": 100, "EndLine": 119}}

        state = read_session_state(state_dir)
        assert covering_read_step(state["files"][canon]["reads"], 1, 80, target_lines=200, min_tier=1) is not None
        assert covering_read_step(state["files"][canon]["reads"], 100, 150, target_lines=200, min_tier=1) is not None
    finally:
        clear_config_cache()


def test_contiguous_reads_merged_and_trim_spanning_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_bounded_policy(tmp_path, monkeypatch)
    try:
        sample_file, state_dir = _make_sample(tmp_path)
        canon = os.path.realpath(str(sample_file))

        ag_read(sample_file, state_dir, start_line=1, end_line=40, step_idx=1, confirm=True)
        ag_read(sample_file, state_dir, start_line=41, end_line=80, step_idx=2, confirm=True)
        state = read_session_state(state_dir)
        assert covering_read_step(state["files"][canon]["reads"], 10, 70, target_lines=200, min_tier=1) == 2

        res = ag_read(sample_file, state_dir, start_line=50, end_line=120, step_idx=3, confirm=True)
        assert res == {"decision": "allow", "overwrite": {"StartLine": 81, "EndLine": 120}}
    finally:
        clear_config_cache()


def test_read_not_trimmed_after_file_content_modified(tmp_path: Path) -> None:
    sample_file, state_dir = _make_sample(tmp_path, count=80)
    evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 1,
            "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 1, "EndLine": 40}},
        },
        state_dir=state_dir,
    )
    sample_file.write_text("\n".join(f"modified {i}" for i in range(1, 81)) + "\n", encoding="utf-8")
    res = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 2,
            "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 20, "EndLine": 60}},
        },
        state_dir=state_dir,
    )
    assert res == {"decision": "allow"}


def test_edit_and_write_invalidate_read_cache(tmp_path: Path) -> None:
    sample_file, state_dir = _make_sample(tmp_path, count=80)
    evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 1,
            "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 1, "EndLine": 40}},
        },
        state_dir=state_dir,
    )
    assert (
        evaluate_hook(
            {"conversationId": "c1", "stepIdx": 2, "toolCall": {"name": "edit_file", "args": {"Path": str(sample_file)}}},
            state_dir=state_dir,
        )
        == {"decision": "allow"}
    )
    assert (
        evaluate_hook(
            {
                "conversationId": "c1",
                "stepIdx": 3,
                "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 20, "EndLine": 60}},
            },
            state_dir=state_dir,
        )
        == {"decision": "allow"}
    )


def test_byte_offset_pagination_allowed_and_never_trimmed(tmp_path: Path) -> None:
    big = tmp_path / "big.txt"
    big.write_text(("x" * 100 + "\n") * 700, encoding="utf-8")
    state_dir = str(tmp_path / "state")

    assert (
        evaluate_hook(
            {"conversationId": "c1", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(big), "StartLine": 1, "EndLine": 400}}},
            state_dir=state_dir,
        )
        == {"decision": "allow"}
    )
    assert (
        evaluate_hook(
            {"conversationId": "c1", "stepIdx": 2, "toolCall": {"name": "read_file", "args": {"Path": str(big), "StartLine": 1, "EndLine": 800, "ByteOffset": 46080}}},
            state_dir=state_dir,
        )
        == {"decision": "allow"}
    )


def test_symlink_path_canonicalization_shares_trim_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_bounded_policy(tmp_path, monkeypatch)
    try:
        real_file, state_dir = _make_sample(tmp_path, count=80)
        link_file = tmp_path / "alias.py"
        link_file.symlink_to(real_file)

        assert ag_read(real_file, state_dir, start_line=1, end_line=30, step_idx=1, confirm=True) == {"decision": "allow"}
        res = ag_read(link_file, state_dir, start_line=15, end_line=50, step_idx=2, confirm=False)
        assert res == {"decision": "allow", "overwrite": {"StartLine": 31, "EndLine": 50}}
    finally:
        clear_config_cache()


def test_concurrent_reads_preserve_state_under_flock(tmp_path: Path) -> None:
    sample_file, state_dir = _make_sample(tmp_path, count=120)
    canon = os.path.realpath(str(sample_file))

    def _payload(idx: int) -> dict[str, object]:
        start = idx * 10 + 1
        end = start + 8
        return {
            "conversationId": "conc",
            "stepIdx": 100,
            "toolCall": {"id": f"conc-{idx}", "name": "read_file", "args": {"Path": str(sample_file), "StartLine": start, "EndLine": end}},
        }

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda idx: evaluate_hook(_payload(idx), state_dir=state_dir), range(6)))
    assert all(r == {"decision": "allow"} for r in results)

    state = read_session_state(state_dir)
    assert len(state["files"][canon]["pending_reads"]) == 6

    for idx in range(6):
        handle_post_tool_use("antigravity", _payload(idx), state_dir=state_dir, event_name="PostToolUse")
    assert len(read_session_state(state_dir)["files"][canon]["reads"]) == 6


def test_malformed_stdin_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("{not-valid-json"))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main([])
    assert rc == 0
    assert json.loads(buf.getvalue()) == {"decision": "allow"}


def test_inverted_line_range_does_not_poison_state_cache(tmp_path: Path) -> None:
    sample_file, state_dir = _make_sample(tmp_path, count=80)
    assert (
        evaluate_hook(
            {
                "conversationId": "inv",
                "stepIdx": 1,
                "toolCall": {"name": "read_file", "args": {"Path": str(sample_file), "StartLine": 50, "EndLine": 20}},
            },
            state_dir=state_dir,
        )
        == {"decision": "allow"}
    )
    assert not (Path(state_dir) / ".context_guard_state.json").exists()


@pytest.mark.parametrize(
    ("ext", "content", "expected_symbol"),
    [
        (".py", "def run(x: int) -> int:\n    return x\n", "def run"),
        (".md", "# Top\n\nBody\n\n## Sub\n\nText\n", "## Sub"),
        (".go", "package main\n\nfunc HandleRequest() {\n    _ = 1\n}\n", "func HandleRequest"),
        (".rs", "pub struct Engine;\n\npub fn run_query() {\n    let _ = 1;\n}\n", "fn run_query"),
        (".sql", "-- SQL View\n\nCREATE OR REPLACE VIEW v_orders AS\nSELECT 1 AS col;\n", "VIEW v_orders"),
    ],
)
def test_extract_outline_symbols_supports_core_languages(ext: str, content: str, expected_symbol: str) -> None:
    symbols = extract_outline_symbols(content, ext)
    assert any(expected_symbol in line for line in symbols)


def test_special_outlines_mcp_and_transcript_while_normal_source_unblocked(tmp_path: Path) -> None:
    src_md = tmp_path / "README.md"
    src_md.write_text("".join(f"## Sec {i}\n" + "line\n" * 15 for i in range(25)), encoding="utf-8")
    mcp_dir = tmp_path / ".system_generated" / "steps" / "3"
    mcp_dir.mkdir(parents=True)
    mcp_out = mcp_dir / "output.txt"
    mcp_out.write_text(
        json.dumps({"file_name": "res.py", "content": "\n".join(f"def fn_{i}():\n    pass" for i in range(900))}),
        encoding="utf-8",
    )
    logs_dir = tmp_path / ".system_generated" / "logs"
    logs_dir.mkdir(parents=True)
    transcript = logs_dir / "transcript.jsonl"
    transcript.write_text(
        "\n".join(json.dumps({"step_index": i, "content": "x" * 600}) for i in range(35)) + "\n",
        encoding="utf-8",
    )

    state_dir = str(tmp_path / "state")
    assert evaluate_hook({"conversationId": "s", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(src_md)}}}, state_dir=state_dir) == {"decision": "allow"}

    r_mcp = evaluate_hook({"conversationId": "s", "stepIdx": 2, "toolCall": {"name": "read_file", "args": {"Path": str(mcp_out)}}}, state_dir=state_dir)
    assert r_mcp["decision"] == "deny" and "CONTEXT-GUARD AUTO-OUTLINE" in r_mcp["reason"]

    r_tx = evaluate_hook({"conversationId": "s", "stepIdx": 3, "toolCall": {"name": "read_file", "args": {"Path": str(transcript)}}}, state_dir=state_dir)
    assert r_tx["decision"] == "deny" and "CONTEXT-GUARD AUTO-OUTLINE" in r_tx["reason"]


def test_auto_outline_falls_back_to_allow_when_state_cannot_be_saved(tmp_path: Path) -> None:
    mcp_dir = tmp_path / ".system_generated" / "steps" / "4"
    mcp_dir.mkdir(parents=True)
    mcp_out = mcp_dir / "output.txt"
    mcp_out.write_text(
        json.dumps({"file_name": "res.py", "content": "\n".join(f"v_{i} = {i}" for i in range(1500))}),
        encoding="utf-8",
    )

    class _FailSaveTxn:
        def __init__(self) -> None:
            self.state: dict[str, object] = {"files": {}}
            self.dirty = False

        def save(self) -> bool:
            return False

    @contextlib.contextmanager
    def _broken_locked_state(_state_dir: Path):
        yield _FailSaveTxn()

    outcome = handle_file_read_verdict(
        state_dir_path=tmp_path / "state",
        raw_path=str(mcp_out),
        start_line=1,
        end_line=-1,
        byte_offset=0,
        step_idx=1,
        locked_state_fn=_broken_locked_state,
    )
    assert outcome.decision == {"decision": "allow"}


def test_auto_step_seq_advances_and_prune_on_rewind_works(tmp_path: Path) -> None:
    sample_file, state_dir = _make_sample(tmp_path, count=100)
    canon = os.path.realpath(str(sample_file))

    claude_read(sample_file, state_dir, offset=1, limit=20, session_id="s-seq", confirm=True)
    evaluate_hook({"session_id": "s-seq", "tool_name": "Bash", "tool_input": {"command": "git status"}}, state_dir=state_dir, cli_harness="claude")
    claude_read(sample_file, state_dir, offset=30, limit=20, session_id="s-seq", confirm=True)

    state = read_session_state(state_dir)
    assert state["auto_step_seq"] >= 3
    assert len(state["files"][canon]["reads"]) == 2

    state["files"][canon]["reads"].append([60, 80, 50, 2])
    assert prune_state_on_rewind(state, current_step=3, inclusive=True) is True
    assert all(int(r[2]) < 3 for r in state["files"][canon]["reads"])
