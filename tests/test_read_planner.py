"""Tests for read planning, slice caps, byte offsets, range-trim telemetry, and step propagation."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from hooks import outcomes, pre_tool_use as ptu
from hooks.read_planner import (
    covering_read_step,
    handle_file_read_verdict,
    normalize_effective_bounds,
    normalize_recorded_ranges,
    trim_partially_covered_range,
)
from hooks.telemetry import HARNESS_READ_CAPS, cap_end_line_for_harness, load_telemetry_stats
from tests.helpers import read_outcomes_ledger, read_session_state, write_python_module


def test_byte_offset_pagination_logs_telemetry_without_trim(tmp_path: Path) -> None:
    big = write_python_module(tmp_path / "big_80kb.py", funcs=400, pad=180)
    state_dir = tmp_path / "state"

    assert (
        ptu.evaluate_hook(
            {"conversationId": "c1", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(big), "StartLine": 1, "EndLine": 400}}},
            state_dir=str(state_dir),
        )
        == {"decision": "allow"}
    )
    stats_before = load_telemetry_stats(state_dir / "telemetry_stats.json")
    allowed_before = stats_before["events"]["allowed_reads"]
    baseline_before = stats_before["baseline_bytes"]

    r_page = ptu.evaluate_hook(
        {"conversationId": "c1", "stepIdx": 2, "toolCall": {"name": "read_file", "args": {"Path": str(big), "StartLine": 1, "EndLine": 800, "ByteOffset": 46080}}},
        state_dir=str(state_dir),
    )
    assert r_page == {"decision": "allow"}

    stats_after = load_telemetry_stats(state_dir / "telemetry_stats.json")
    assert stats_after["events"]["allowed_reads"] == allowed_before + 1
    assert stats_after["baseline_bytes"] > baseline_before


def test_antigravity_uncapped_read_on_2000_line_50kb_file_records_capped_slice(tmp_path: Path) -> None:
    big = write_python_module(tmp_path / "two_thousand.py", funcs=100, pad=16, body_lines=20)
    assert big.stat().st_size > 46_080

    state_dir = tmp_path / "state"
    canon = os.path.realpath(str(big))

    assert (
        ptu.evaluate_hook(
            {"conversationId": "c1", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(big)}}},
            state_dir=str(state_dir),
        )
        == {"decision": "allow"}
    )
    state = read_session_state(state_dir)
    reads = state["files"][canon]["reads"]
    assert len(reads) == 1
    assert reads[0][0] == 1 and reads[0][1] <= 800

    # Because lines > 800 were not delivered, requesting lines 801..900 is allowed untouched
    assert (
        ptu.evaluate_hook(
            {"conversationId": "c1", "stepIdx": 2, "toolCall": {"name": "read_file", "args": {"Path": str(big), "StartLine": 801, "EndLine": 900}}},
            state_dir=str(state_dir),
        )
        == {"decision": "allow"}
    )


def test_harness_slice_caps_match_contract() -> None:
    ag_lines, ag_bytes = HARNESS_READ_CAPS["antigravity"]
    cl_lines, cl_bytes = HARNESS_READ_CAPS["claude"]
    assert ag_lines == 800 and ag_bytes == 46_080
    assert cl_lines == 2000 and cl_bytes == 80_000
    assert cap_end_line_for_harness("antigravity", 1, -1) == 800
    assert cap_end_line_for_harness("claude", 1, -1) == 2000
    assert cap_end_line_for_harness("claude", 500, 1200) == 1200


def test_effective_step_idx_survives_interleaved_auto_step_increment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mcp_dir = tmp_path / ".system_generated" / "steps" / "1"
    mcp_dir.mkdir(parents=True)
    mcp_out = mcp_dir / "output.txt"
    mcp_out.write_text(
        json.dumps({"file_name": "payload.py", "content": "\n".join(f"v_{i} = {i}" for i in range(1500))}),
        encoding="utf-8",
    )
    state_dir = tmp_path / "state"
    recorded: list[tuple[str, str, str]] = []

    def _capture_outcome(
        harness: str,
        model: str,
        kind: str,
        scope: str,
        ledger_path: Path | None = None,
        *,
        increment_total: bool = True,
    ) -> None:
        recorded.append((harness, kind, scope))
        outcomes.record_direct_outcome(harness, model, kind, scope, ledger_path, increment_total=increment_total)

    monkeypatch.setattr(ptu, "record_direct_outcome", _capture_outcome)

    out1 = ptu.evaluate_hook(
        {"session_id": "s-step", "tool_name": "Read", "tool_input": {"file_path": str(mcp_out)}},
        state_dir=str(state_dir),
        cli_harness="claude",
    )
    assert out1["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert ("claude", "outline", "applied") in recorded

    res = handle_file_read_verdict(
        state_dir_path=state_dir,
        raw_path=str(mcp_out),
        start_line=1,
        end_line=50,
        byte_offset=0,
        step_idx=0,
        auto_increment_step=True,
        harness="claude",
    )
    assert res.effective_step_idx >= 2


def test_camel_case_transcript_path_extracts_model_in_pre_tool_use(tmp_path: Path) -> None:
    tx = tmp_path / "transcript.jsonl"
    tx.write_text(
        json.dumps({"type": "USER_INPUT", "content": "hi"})
        + "\n"
        + json.dumps({"type": "assistant", "message": {"model": "gemini-3.1-pro-high"}})
        + "\n",
        encoding="utf-8",
    )
    mcp_dir = tmp_path / ".system_generated" / "steps" / "2"
    mcp_dir.mkdir(parents=True)
    mcp_out = mcp_dir / "output.txt"
    mcp_out.write_text(
        json.dumps({"file_name": "payload.py", "content": "\n".join(f"v_{i} = {i}" for i in range(1500))}),
        encoding="utf-8",
    )
    state_dir = tmp_path / "state"

    r1 = ptu.evaluate_hook(
        {
            "conversationId": "conv-m",
            "artifactDirectoryPath": str(state_dir),
            "transcriptPath": str(tx),
            "stepIdx": 1,
            "toolCall": {"name": "read_file", "args": {"Path": str(mcp_out)}},
        },
        state_dir=str(state_dir),
    )
    assert r1["decision"] == "deny"

    ledger = read_outcomes_ledger(state_dir)
    key = "antigravity|gemini-3.1-pro-high|outline"
    assert key in ledger.get("by_key", {})
    assert ledger["by_key"][key]["applied"] == 1


def test_range_trim_records_telemetry_and_direct_outcome(tmp_path: Path) -> None:
    target = write_python_module(tmp_path / "mod.py", funcs=25, body_lines=7)
    state_dir = tmp_path / "state"

    assert (
        ptu.evaluate_hook(
            {"conversationId": "c1", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 100}}},
            state_dir=str(state_dir),
        )
        == {"decision": "allow"}
    )
    res_trim = ptu.evaluate_hook(
        {"conversationId": "c1", "stepIdx": 2, "toolCall": {"name": "read_file", "args": {"Path": str(target), "StartLine": 50, "EndLine": 150}}},
        state_dir=str(state_dir),
    )
    assert res_trim == {"decision": "allow", "overwrite": {"StartLine": 101, "EndLine": 150}}

    stats = load_telemetry_stats(state_dir / "telemetry_stats.json")
    assert stats["events"]["ranges_trimmed"] == 1
    assert stats["saved_bytes"] > 0

    ledger = read_outcomes_ledger(state_dir)
    assert sum(row["total"] for k, row in ledger["by_key"].items() if k.endswith("|range_trim")) == 1


def test_trim_bounds_and_interval_normalization_edge_cases() -> None:
    reads = [[1, 50, 1], [100, 150, 2]]
    assert trim_partially_covered_range(reads, 60, 90, target_lines=200) is None  # disjoint
    assert trim_partially_covered_range(reads, 10, 40, target_lines=200) is None  # fully covered
    assert trim_partially_covered_range(reads, 30, 80, target_lines=200) == (51, 80)
    assert trim_partially_covered_range(reads, 70, 120, target_lines=200) == (70, 99)
    assert trim_partially_covered_range(reads, 1, -1, target_lines=200) == (51, 200)
    assert trim_partially_covered_range(reads, 1, -1, target_lines=0) is None
    assert normalize_effective_bounds(250, 300, target_lines=200) is None  # past EOF

    normed = normalize_recorded_ranges([[1, -1, 3], [0, 10, 1]], target_lines=200)
    assert normed == [[1, 200, 3]]
    assert covering_read_step(normed, 50, 150, target_lines=200) == 3


def test_antigravity_unbounded_read_ignores_cached_lines_above_harness_cap(
    tmp_path: Path,
) -> None:
    target = tmp_path / "big_1200.py"
    target.write_text("".join(f"x = {i}\n" for i in range(1, 1201)), encoding="utf-8")
    state_dir = str(tmp_path / "state_cap")

    res_tail = ptu.evaluate_hook(
        {
            "conversationId": "c-cap",
            "stepIdx": 1,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(target), "StartLine": 900, "EndLine": 1200},
            },
        },
        state_dir=state_dir,
    )
    assert res_tail == {"decision": "allow"}

    res_unbounded = ptu.evaluate_hook(
        {
            "conversationId": "c-cap",
            "stepIdx": 2,
            "toolCall": {"name": "read_file", "args": {"Path": str(target)}},
        },
        state_dir=state_dir,
    )
    assert res_unbounded == {"decision": "allow"}
    assert load_telemetry_stats(Path(state_dir) / "telemetry_stats.json")["events"].get("ranges_trimmed", 0) == 0


def test_telemetry_and_outcomes_resolve_default_paths_lazily(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hooks.telemetry as tele

    tele_path = tmp_path / "lazy_telemetry.json"
    out_path = tmp_path / "lazy_outcomes.jsonl"
    monkeypatch.setattr(tele, "DEFAULT_TELEMETRY_PATH", tele_path)
    monkeypatch.setattr(outcomes, "DEFAULT_OUTCOMES_PATH", out_path)

    outcomes.record_direct_outcome("claude", "gpt-5", "range_trim")
    assert out_path.is_file()
    loaded_outcomes = outcomes.load_outcomes()
    assert loaded_outcomes["by_key"]["claude|gpt-5|range_trim"]["total"] == 1

    tele_path.write_text(json.dumps({"saved_bytes": 777}), encoding="utf-8")
    assert tele.load_telemetry_stats().get("saved_bytes") == 777
