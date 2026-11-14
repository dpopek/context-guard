"""Model identity detection and caching for outcome telemetry."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from hooks import model_identity as mi, pre_tool_use
from hooks.local_repo_guard import load_guard_config
from tests.helpers import read_outcomes_ledger, read_session_state


def test_normalize_model_label() -> None:
    assert mi.normalize_model_label("  Claude-Fable-5-1 ") == "claude-fable-5-1"
    assert mi.normalize_model_label("gpt 6.1/sol:x") == "gpt6.1/sol:x"
    assert mi.normalize_model_label("a" * 60) == "a" * 48
    assert mi.normalize_model_label("") == "unknown"
    assert mi.normalize_model_label(None) == "unknown"


def test_claude_model_from_transcript_tail_skips_synthetic(tmp_path: Path) -> None:
    transcript = tmp_path / "t.jsonl"
    lines = [
        json.dumps({"type": "user", "message": {"role": "user", "content": "hi"}}),
        json.dumps({"type": "assistant", "message": {"model": "claude-fable-5-1", "content": []}}),
        json.dumps({"type": "assistant", "message": {"model": "<synthetic>", "content": []}}),
    ]
    transcript.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert mi.detect_claude_model(str(transcript)) == "claude-fable-5-1"
    assert mi.detect_claude_model(str(tmp_path / "missing.jsonl")) == "unknown"
    assert mi.detect_claude_model(None) == "unknown"


def test_claude_model_reads_only_the_tail(tmp_path: Path) -> None:
    transcript = tmp_path / "t.jsonl"
    early = json.dumps({"message": {"model": "claude-early"}})
    filler = json.dumps({"type": "user", "message": {"content": "x" * 1000}})
    transcript.write_text(early + "\n" + (filler + "\n") * 80, encoding="utf-8")
    assert transcript.stat().st_size > mi.TAIL_BYTES
    assert mi.detect_claude_model(str(transcript)) == "unknown"


def test_codex_model_prefers_rollout_turn_context_over_config() -> None:
    # CODEX_SESSIONS_DIR / CODEX_CONFIG_PATH point into tmp_path (tests/conftest.py).
    rollout = mi.CODEX_SESSIONS_DIR / "2026" / "10" / "30" / "rollout-2026-10-30T10-00-00-abc123.jsonl"
    rollout.parent.mkdir(parents=True)
    decoy = {"type": "event_msg", "payload": {"type": "user_message", "message": '"model": "decoy"'}}
    turn = {"type": "turn_context", "payload": {"cwd": "/w", "model": "gpt-6.1-sol"}}
    rollout.write_text(json.dumps(decoy) + "\n" + json.dumps(turn) + "\n", encoding="utf-8")
    mi.CODEX_CONFIG_PATH.write_text('model = "gpt-5-codex"\n', encoding="utf-8")
    assert mi.detect_codex_model("abc123") == "gpt-6.1-sol"
    assert mi.detect_codex_model("missing") == "gpt-5-codex"
    assert mi.detect_codex_model("../etc") == "gpt-5-codex"
    mi.CODEX_CONFIG_PATH.unlink()
    assert mi.detect_codex_model("missing") == "unknown"


def test_detect_model_antigravity_and_cursor_are_unknown() -> None:
    assert mi.detect_model("antigravity", "s1", None) == "unknown"
    assert mi.detect_model("cursor", "s1", None) == "unknown"


def test_pinned_label_wins_and_is_normalised() -> None:
    assert mi.GUARD_CONFIG_PATH is not None
    mi.GUARD_CONFIG_PATH.write_text(
        json.dumps({"model_labels": {"antigravity": " Gemini-3-Pro "}}), encoding="utf-8"
    )
    assert mi.detect_model("antigravity", "s1", None) == "gemini-3-pro"
    assert mi.detect_model("cursor", "s1", None) == "unknown"


def test_memoize_model_caches_and_refreshes_after_window(tmp_path: Path) -> None:
    transcript = tmp_path / "t.jsonl"
    transcript.write_text(json.dumps({"message": {"model": "claude-fable-5-1"}}) + "\n", encoding="utf-8")
    state: dict[str, Any] = {"files": {}}
    assert mi.memoize_model("claude", "s1", str(transcript), state, 10) == "claude-fable-5-1"
    assert (state["model"], state["model_step"]) == ("claude-fable-5-1", 10)
    transcript.write_text(json.dumps({"message": {"model": "claude-opus-5-5"}}) + "\n", encoding="utf-8")
    assert mi.memoize_model("claude", "s1", str(transcript), state, 29) == "claude-fable-5-1"
    assert mi.memoize_model("claude", "s1", str(transcript), state, 30) == "claude-opus-5-5"
    assert state["model_step"] == 30


def test_memoize_model_retries_unknown_on_next_step(tmp_path: Path) -> None:
    transcript = tmp_path / "t.jsonl"
    state: dict[str, Any] = {"files": {}}
    assert mi.memoize_model("claude", "s1", str(transcript), state, 1) == "unknown"
    transcript.write_text(json.dumps({"message": {"model": "claude-fable-5-1"}}) + "\n", encoding="utf-8")
    assert mi.memoize_model("claude", "s1", str(transcript), state, 1) == "unknown"
    assert mi.memoize_model("claude", "s1", str(transcript), state, 2) == "claude-fable-5-1"


def test_load_guard_config_keeps_only_known_harness_labels(tmp_path: Path) -> None:
    cfg = tmp_path / "config.json"
    cfg.write_text(
        json.dumps({"model_labels": {"claude": " x ", "codex": "", "bogus": "y", "cursor": 3}}),
        encoding="utf-8",
    )
    assert load_guard_config(cfg)["model_labels"] == {"claude": "x"}
    assert load_guard_config(tmp_path / "missing.json")["model_labels"] == {}
    cfg.write_text(json.dumps({"model_labels": ["a"]}), encoding="utf-8")
    assert load_guard_config(cfg)["model_labels"] == {}


def test_extract_antigravity_model_change() -> None:
    single = "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Argon High.\n</USER_SETTINGS_CHANGE>"
    assert mi.extract_antigravity_model_change(single) == "gemini4argonhigh"
    multi = (
        "<USER_SETTINGS_CHANGE>\n"
        "The user changed setting `Model Selection` from None to Gemini 4 Carbon (Medium). Do not comment.\n"
        "The user changed setting `Model Selection` from Gemini 4 Carbon (Medium) to Claude Sonnet 4.6.\n"
        "</USER_SETTINGS_CHANGE>"
    )
    assert mi.extract_antigravity_model_change(multi) == "claudesonnet4.6"
    assert mi.extract_antigravity_model_change("<USER_SETTINGS_CHANGE>\nchanged setting `Model Selection` from X to Auto.\n</USER_SETTINGS_CHANGE>") is None
    assert mi.extract_antigravity_model_change("<USER_SETTINGS_CHANGE>\nchanged setting `Model Selection` from X to unknown.\n</USER_SETTINGS_CHANGE>") is None
    assert mi.extract_antigravity_model_change("The user changed setting `Model Selection` from None to Gemini.") is None
    assert mi.extract_antigravity_model_change("<USER_SETTINGS_CHANGE>\nchanged setting `Model Selection` from None to Gemini.") is None
    with_user_decoy = (
        "<USER_SETTINGS_CHANGE>\n"
        "The user changed setting `Model Selection` from None to Gemini 4 Argon High.\n"
        "</USER_SETTINGS_CHANGE>\n"
        "<USER_REQUEST>\nFix changed setting `Model Selection` from X to Bogus Model\n</USER_REQUEST>"
    )
    assert mi.extract_antigravity_model_change(with_user_decoy) == "gemini4argonhigh"


def test_detect_antigravity_model_tail_head_and_ignores_tool_call_decoys(tmp_path: Path) -> None:
    conv_dir = tmp_path / "brain" / "conv1"
    log = conv_dir / ".system_generated" / "logs" / "transcript.jsonl"
    log.parent.mkdir(parents=True)

    step0 = json.dumps({
        "step_index": 0,
        "type": "USER_INPUT",
        "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Argon High.\n</USER_SETTINGS_CHANGE>",
    })
    swarm_decoy = json.dumps({
        "step_index": 1,
        "type": "PLANNER_RESPONSE",
        "tool_calls": [{"name": "swarm", "args": {"model": "decoy-swarm-model"}}],
    })
    log.write_text(step0 + "\n" + swarm_decoy + "\n", encoding="utf-8")
    assert mi.detect_antigravity_model(state_dir=conv_dir) == "gemini4argonhigh"

    # Pad past TAIL_BYTES so step 0 lives only in the head chunk, while tail has decoys.
    filler = json.dumps({
        "step_index": 2,
        "type": "PLANNER_RESPONSE",
        "model": "auto",
        "tool_calls": [{"name": "swarm", "args": {"model": "decoy-tail"}}],
        "text": "x" * 1000,
    })
    log.write_text(step0 + "\n" + (filler + "\n") * 75 + swarm_decoy + "\n", encoding="utf-8")
    assert log.stat().st_size > mi.TAIL_BYTES
    assert mi.detect_antigravity_model(state_dir=conv_dir) == "gemini4argonhigh"

    # Tail setting change wins over earlier head setting change.
    tail_change = json.dumps({
        "step_index": 80,
        "type": "USER_INPUT",
        "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from Gemini 4 Argon High to Claude Sonnet 4.6.\n</USER_SETTINGS_CHANGE>",
    })
    log.write_text(step0 + "\n" + (filler + "\n") * 75 + tail_change + "\n", encoding="utf-8")
    assert mi.detect_antigravity_model(state_dir=conv_dir) == "claudesonnet4.6"


def test_detect_antigravity_model_inherits_earlier_sibling(tmp_path: Path) -> None:
    brain = tmp_path / "brain"
    conv1 = brain / "conv1" / ".system_generated" / "logs" / "transcript.jsonl"
    conv2_dir = brain / "conv2"
    conv2 = conv2_dir / ".system_generated" / "logs" / "transcript.jsonl"
    conv3 = brain / "conv3" / ".system_generated" / "logs" / "transcript.jsonl"
    for p in (conv1, conv2, conv3):
        p.parent.mkdir(parents=True)

    conv1.write_text(
        json.dumps({
            "step_index": 0,
            "type": "USER_INPUT",
            "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Argon High.\n</USER_SETTINGS_CHANGE>",
        }) + "\n",
        encoding="utf-8",
    )
    conv2.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "hi"})
        + "\n"
        + json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "tool_calls": [{"args": {"model": "decoy"}}]})
        + "\n",
        encoding="utf-8",
    )
    conv3.write_text(
        json.dumps({
            "step_index": 0,
            "type": "USER_INPUT",
            "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Future Model.\n</USER_SETTINGS_CHANGE>",
        }) + "\n",
        encoding="utf-8",
    )
    os.utime(conv1, (1000, 1000))
    os.utime(conv2, (2000, 2000))
    os.utime(conv3, (3000, 3000))

    assert mi.detect_antigravity_model(state_dir=conv2_dir) == "gemini4argonhigh"


def test_memoize_model_and_pre_tool_use_carry_over_and_release_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fcntl_mod: Any = None
    try:
        import fcntl as fcntl_mod
    except ImportError:
        pass

    brain = tmp_path / "brain"
    conv1 = brain / "conv1" / ".system_generated" / "logs" / "transcript.jsonl"
    conv2_dir = brain / "conv2"
    conv2 = conv2_dir / ".system_generated" / "logs" / "transcript.jsonl"
    conv1.parent.mkdir(parents=True)
    conv2.parent.mkdir(parents=True)
    conv1.write_text(
        json.dumps({
            "step_index": 0,
            "type": "USER_INPUT",
            "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Argon High.\n</USER_SETTINGS_CHANGE>",
        }) + "\n",
        encoding="utf-8",
    )
    conv2.write_text(json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "continue"}) + "\n", encoding="utf-8")
    os.utime(conv1, (1000, 1000))
    os.utime(conv2, (2000, 2000))

    state: dict[str, Any] = {"files": {}}
    assert mi.memoize_model("antigravity", "s1", None, state, 1, state_dir=conv2_dir) == "gemini4argonhigh"
    assert state["model"] == "gemini4argonhigh"

    lock_free_during_outcome = False
    real_record = pre_tool_use.record_direct_outcome

    def _checked_record(
        harness: str,
        model: str,
        kind: str,
        outcome: str,
        ledger_path: Path | None,
        *,
        increment_total: bool = True,
    ) -> None:
        nonlocal lock_free_during_outcome
        if fcntl_mod is not None:
            lock_file = conv2_dir / ".context_guard_state.lock"
            with open(lock_file, "a+", encoding="utf-8") as fh:
                fcntl_mod.flock(fh.fileno(), fcntl_mod.LOCK_EX | fcntl_mod.LOCK_NB)
                fcntl_mod.flock(fh.fileno(), fcntl_mod.LOCK_UN)
                lock_free_during_outcome = True
        else:
            lock_free_during_outcome = True
        real_record(harness, model, kind, outcome, ledger_path, increment_total=increment_total)

    monkeypatch.setattr(pre_tool_use, "record_direct_outcome", _checked_record)
    res = pre_tool_use.evaluate_hook(
        {
            "conversationId": "conv2",
            "artifactDirectoryPath": str(conv2_dir),
            "stepIdx": 2,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "pytest tests/unit"}},
        },
        state_dir=str(conv2_dir),
    )
    assert res == {"decision": "allow", "overwrite": {"CommandLine": "pytest tests/unit -q --tb=short --no-header"}}
    assert lock_free_during_outcome is True
    assert read_session_state(conv2_dir)["model"] == "gemini4argonhigh"
    assert read_outcomes_ledger(conv2_dir)["by_key"]["antigravity|gemini4argonhigh|cli_rewrite"]["applied"] == 1


def test_detect_antigravity_model_fallbacks_and_outline_pull(tmp_path: Path) -> None:
    # PLANNER_RESPONSE modelName (skipping auto), assistant skipping <synthetic>, and transcript_full fallback.
    full_dir = tmp_path / "conv_full"
    full_log = full_dir / ".system_generated" / "logs" / "transcript_full.jsonl"
    full_log.parent.mkdir(parents=True)
    full_log.write_text(
        "\n".join([
            json.dumps({"type": "assistant", "message": {"model": "claude-sonnet-4-5"}}),
            json.dumps({"type": "assistant", "message": {"model": "<synthetic>"}}),
            json.dumps({"type": "PLANNER_RESPONSE", "model": "auto"}),
        ]) + "\n",
        encoding="utf-8",
    )
    assert mi.detect_antigravity_model(transcript_path=str(full_log)) == "claude-sonnet-4-5"
    assert mi.detect_antigravity_model(state_dir=full_dir) == "claude-sonnet-4-5"

    # When state_dir has no .system_generated/logs, sibling scan falls back to ANTIGRAVITY_BRAIN_DIR.
    assert mi.ANTIGRAVITY_BRAIN_DIR is not None
    seed_log = mi.ANTIGRAVITY_BRAIN_DIR / "prev" / ".system_generated" / "logs" / "transcript.jsonl"
    seed_log.parent.mkdir(parents=True)
    seed_log.write_text(
        json.dumps({"type": "PLANNER_RESPONSE", "model": "auto", "modelName": "Gemini 4 Pro"}) + "\n",
        encoding="utf-8",
    )
    isolated_state = tmp_path / "plain_state"
    res = pre_tool_use.evaluate_hook(
        {
            "conversationId": "plain-conv",
            "toolCall": {"name": "run_command", "args": {"CommandLine": "cg-outline app.py"}},
        },
        state_dir=str(isolated_state),
    )
    assert res == {"decision": "allow"}
    assert read_session_state(isolated_state)["model"] == "gemini4pro"
    assert read_outcomes_ledger(isolated_state)["by_key"]["antigravity|gemini4pro|outline_pull"]["applied"] == 1


def test_detect_antigravity_model_ignores_sidechain_sibling_and_caps_scan(tmp_path: Path) -> None:
    brain = tmp_path / "brain"
    conv1 = brain / "conv1" / ".system_generated" / "logs" / "transcript.jsonl"
    sub1 = brain / "sub1" / ".system_generated" / "logs" / "transcript.jsonl"
    conv2_dir = brain / "conv2"
    conv2 = conv2_dir / ".system_generated" / "logs" / "transcript.jsonl"
    for p in (conv1, sub1, conv2):
        p.parent.mkdir(parents=True)
    conv1.write_text(
        json.dumps({
            "step_index": 0,
            "type": "USER_INPUT",
            "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Argon High.\n</USER_SETTINGS_CHANGE>",
        }) + "\n",
        encoding="utf-8",
    )
    sub1.write_text(
        json.dumps({"step_index": 0, "type": "SYSTEM_MESSAGE", "content": "The following is a <SYSTEM_MESSAGE> subagent"})
        + "\n"
        + json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "model": "flash"})
        + "\n",
        encoding="utf-8",
    )
    conv2.write_text(json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "<USER_REQUEST>hi</USER_REQUEST>"}) + "\n", encoding="utf-8")
    os.utime(conv1, (1000, 1000))
    os.utime(sub1, (1500, 1500))
    os.utime(conv2, (2000, 2000))
    assert mi.detect_antigravity_model(state_dir=conv2_dir) == "gemini4argonhigh"

    # More than MAX_SIBLING_TRANSCRIPTS empty newer siblings prevent reaching older conv0.
    cap_brain = tmp_path / "cap_brain"
    conv0 = cap_brain / "conv0" / ".system_generated" / "logs" / "transcript.jsonl"
    conv0.parent.mkdir(parents=True)
    conv0.write_text(json.dumps({"type": "PLANNER_RESPONSE", "model": "gemini4pro"}) + "\n", encoding="utf-8")
    os.utime(conv0, (100, 100))
    for i in range(mi.MAX_SIBLING_TRANSCRIPTS):
        sib = cap_brain / f"empty_{i:02d}" / ".system_generated" / "logs" / "transcript.jsonl"
        sib.parent.mkdir(parents=True)
        sib.write_text(json.dumps({"type": "USER_INPUT", "content": "none"}) + "\n", encoding="utf-8")
        os.utime(sib, (200 + i, 200 + i))
    cur_dir = cap_brain / "cur"
    cur = cur_dir / ".system_generated" / "logs" / "transcript.jsonl"
    cur.parent.mkdir(parents=True)
    cur.write_text(json.dumps({"type": "USER_INPUT", "content": "hi"}) + "\n", encoding="utf-8")
    os.utime(cur, (500, 500))
    assert mi.detect_antigravity_model(state_dir=cur_dir) == "unknown"

    # Sidechain subagent siblings do NOT consume MAX_SIBLING_TRANSCRIPTS quota.
    sc_brain = tmp_path / "sc_brain"
    main_old = sc_brain / "main_old" / ".system_generated" / "logs" / "transcript.jsonl"
    main_old.parent.mkdir(parents=True)
    main_old.write_text(json.dumps({"type": "PLANNER_RESPONSE", "model": "gemini4pro"}) + "\n", encoding="utf-8")
    os.utime(main_old, (100, 100))
    for i in range(mi.MAX_SIBLING_TRANSCRIPTS + 3):
        sub = sc_brain / f"sub_{i:02d}" / ".system_generated" / "logs" / "transcript.jsonl"
        sub.parent.mkdir(parents=True)
        sub.write_text(
            json.dumps({"step_index": 0, "type": "SYSTEM_MESSAGE", "content": "<SYSTEM_MESSAGE>worker"}) + "\n",
            encoding="utf-8",
        )
        os.utime(sub, (200 + i, 200 + i))
    cur2_dir = sc_brain / "cur2"
    cur2 = cur2_dir / ".system_generated" / "logs" / "transcript.jsonl"
    cur2.parent.mkdir(parents=True)
    cur2.write_text(json.dumps({"type": "USER_INPUT", "content": "<USER_REQUEST>hi</USER_REQUEST>"}) + "\n", encoding="utf-8")
    os.utime(cur2, (500, 500))
    assert mi.detect_antigravity_model(state_dir=cur2_dir) == "gemini4pro"


def test_pre_tool_use_read_trim_refresh_and_claude_outline_pull_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fcntl_mod: Any = None
    try:
        import fcntl as fcntl_mod
    except ImportError:
        pass

    brain = tmp_path / "brain"
    conv_dir = brain / "conv1"
    log = conv_dir / ".system_generated" / "logs" / "transcript.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text(
        json.dumps({
            "step_index": 0,
            "type": "USER_INPUT",
            "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Argon High.\n</USER_SETTINGS_CHANGE>",
        }) + "\n",
        encoding="utf-8",
    )
    target = tmp_path / "app.py"
    target.write_text("\n".join(f"line {i}" for i in range(1, 51)) + "\n", encoding="utf-8")

    # Initial read at step 1 caches gemini4argonhigh.
    pre_tool_use.evaluate_hook(
        {"conversationId": "conv1", "artifactDirectoryPath": str(conv_dir), "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(target), "StartLine": 1, "EndLine": 10}}},
        state_dir=str(conv_dir),
    )
    # Switch model and trigger overlapping range_trim at step 1 + MODEL_REFRESH_STEPS.
    log.write_text(
        json.dumps({
            "step_index": 21,
            "type": "USER_INPUT",
            "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from Gemini 4 Argon High to Claude Sonnet 4.6.\n</USER_SETTINGS_CHANGE>",
        }) + "\n",
        encoding="utf-8",
    )
    lock_free = False
    real_record = pre_tool_use.record_direct_outcome

    def _checked(
        harness: str,
        model: str,
        kind: str,
        outcome: str,
        ledger_path: Path | None,
        *,
        increment_total: bool = True,
    ) -> None:
        nonlocal lock_free
        if fcntl_mod is not None:
            with open(conv_dir / ".context_guard_state.lock", "a+", encoding="utf-8") as fh:
                fcntl_mod.flock(fh.fileno(), fcntl_mod.LOCK_EX | fcntl_mod.LOCK_NB)
                fcntl_mod.flock(fh.fileno(), fcntl_mod.LOCK_UN)
        lock_free = True
        real_record(harness, model, kind, outcome, ledger_path, increment_total=increment_total)

    monkeypatch.setattr(pre_tool_use, "record_direct_outcome", _checked)
    trim_res = pre_tool_use.evaluate_hook(
        {"conversationId": "conv1", "artifactDirectoryPath": str(conv_dir), "stepIdx": 1 + mi.MODEL_REFRESH_STEPS, "toolCall": {"name": "read_file", "args": {"Path": str(target), "StartLine": 5, "EndLine": 20}}},
        state_dir=str(conv_dir),
    )
    assert trim_res["overwrite"] == {"StartLine": 11, "EndLine": 20}
    assert lock_free is True
    assert read_session_state(conv_dir)["model"] == "claudesonnet4.6"
    assert read_outcomes_ledger(conv_dir)["by_key"]["antigravity|claudesonnet4.6|range_trim"]["applied"] == 1

    # Claude outline_pull advances auto_step_seq before memoize so prior `unknown` refreshes.
    cstate = tmp_path / "cstate"
    cstate.mkdir()
    (cstate / ".context_guard_state.json").write_text(
        json.dumps({"files": {}, "auto_step_seq": 1, "model": "unknown", "model_step": 1}),
        encoding="utf-8",
    )
    ctr = tmp_path / "claude.jsonl"
    ctr.write_text(json.dumps({"type": "assistant", "message": {"model": "claude-opus-4-6"}}) + "\n", encoding="utf-8")
    pre_tool_use.evaluate_hook(
        {"session_id": "cs1", "tool_name": "Bash", "tool_input": {"command": "cg-outline app.py"}, "transcript_path": str(ctr)},
        state_dir=str(cstate),
        cli_harness="claude",
    )
    assert read_session_state(cstate)["model"] == "claude-opus-4-6"
    assert read_outcomes_ledger(cstate)["by_key"]["claude|claude-opus-4-6|outline_pull"]["applied"] == 1


def test_detect_antigravity_model_handles_oversized_sidechain_and_transcript_full_sibling(
    tmp_path: Path,
) -> None:
    brain = tmp_path / "brain"
    full_only = brain / "full_only" / ".system_generated" / "logs" / "transcript_full.jsonl"
    oversized_sc = brain / "oversized_sc" / ".system_generated" / "logs" / "transcript.jsonl"
    cur_dir = brain / "cur"
    cur_log = cur_dir / ".system_generated" / "logs" / "transcript.jsonl"
    for p in (full_only, oversized_sc, cur_log):
        p.parent.mkdir(parents=True)

    full_only.write_text(
        json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "model": "gemini4pro"}) + "\n",
        encoding="utf-8",
    )
    # Line 1 exceeds TAIL_BYTES (64 KB) so readline(TAIL_BYTES) truncates closing brace; still recognized as sidechain.
    oversized_sc.write_text(
        json.dumps({"step_index": 0, "type": "SYSTEM_MESSAGE", "content": "<SYSTEM_MESSAGE>\n" + ("s" * 70_000)})
        + "\n"
        + json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "model": "flash"})
        + "\n",
        encoding="utf-8",
    )
    cur_log.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "<USER_REQUEST>hi</USER_REQUEST>"}) + "\n",
        encoding="utf-8",
    )
    os.utime(full_only, (1000, 1000))
    os.utime(oversized_sc, (1500, 1500))
    os.utime(cur_log, (2000, 2000))
    assert mi.detect_antigravity_model(state_dir=cur_dir) == "gemini4pro"

    # Compacted main conversation with >70 KB <CONTEXT_SUMMARY> mentioning <SYSTEM_MESSAGE> is NOT skipped as sidechain.
    comp_brain = tmp_path / "comp_brain"
    comp_sib = comp_brain / "comp_sib" / ".system_generated" / "logs" / "transcript.jsonl"
    comp_cur_dir = comp_brain / "comp_cur"
    comp_cur = comp_cur_dir / ".system_generated" / "logs" / "transcript.jsonl"
    for p in (comp_sib, comp_cur):
        p.parent.mkdir(parents=True)
    comp_sib.write_text(
        json.dumps(
            {
                "content": "<CONTEXT_SUMMARY>\nMention of <SYSTEM_MESSAGE> and \"type\": \"SYSTEM_MESSAGE\".\n"
                + ("c" * 70_000),
                "step_index": 0,
                "type": "USER_INPUT",
            }
        )
        + "\n"
        + json.dumps({"step_index": 1, "type": "PLANNER_RESPONSE", "model": "claude-sonnet-4-6"})
        + "\n",
        encoding="utf-8",
    )
    comp_cur.write_text(
        json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "<USER_REQUEST>next</USER_REQUEST>"}) + "\n",
        encoding="utf-8",
    )
    os.utime(comp_sib, (1000, 1000))
    os.utime(comp_cur, (2000, 2000))
    assert mi.detect_antigravity_model(state_dir=comp_cur_dir) == "claude-sonnet-4-6"
