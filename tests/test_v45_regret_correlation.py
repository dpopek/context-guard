"""End-to-end regret, recovery, mutation reconciliation, and lock-ordering tests for spool/trim/CLI windows."""

from __future__ import annotations

import json
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from hooks import config, outcomes, pre_compact, pre_tool_use, session_end, state_store, telemetry
from hooks.post_tool_use import handle_post_tool_use
from spool import store as spool_store
from tests.helpers import claude_read, read_outcomes_ledger, write_python_module

_SPOOL_ID_RX = re.compile(r"\b(sp_[0-9a-f]{12})\b")


def _write_cfg(
    home_dir: Path,
    *,
    regret_window_steps: int = 4,
    **optimizers: str,
) -> None:
    cfg_path = home_dir / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(
        json.dumps({"optimizers": optimizers, "regret_window_steps": regret_window_steps}),
        encoding="utf-8",
    )
    config.clear_config_cache()


def _big_lines(count: int = 260, tag: str = "case") -> str:
    return "\n".join(
        f"FAILED tests/test_mod.py::test_{tag}_{i} - assertion mismatch detail {'z' * 55}"
        for i in range(1, count + 1)
    )


def _bash_pre(
    sd: Path,
    session_id: str,
    cmd: str,
    call_id: str,
    *,
    cwd: Path | None = None,
    permission_mode: str = "bypassPermissions",
) -> dict[str, Any]:
    tool_in: dict[str, Any] = {"command": cmd}
    payload: dict[str, Any] = {
        "hook_event_name": "PreToolUse",
        "session_id": session_id,
        "tool_use_id": call_id,
        "tool_name": "Bash",
        "tool_input": tool_in,
        "permission_mode": permission_mode,
    }
    if cwd is not None:
        payload["cwd"] = str(cwd)
    return pre_tool_use.evaluate_hook(payload, state_dir=str(sd), cli_harness="claude")


def _bash_post(
    sd: Path, session_id: str, cmd: str, output: str, call_id: str, *, cwd: Path | None = None
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "tool_use_id": call_id,
        "tool_name": "Bash",
        "tool_input": {"command": cmd},
        "tool_response": output,
    }
    if cwd is not None:
        payload["cwd"] = str(cwd)
    return handle_post_tool_use("claude", payload, state_dir=str(sd))


def _extract_spool_id(post_res: dict[str, Any]) -> str:
    txt = str((post_res.get("hookSpecificOutput") or {}).get("updatedToolOutput") or "")
    m = _SPOOL_ID_RX.search(txt)
    assert m is not None, f"missing spool_id in response: {txt!r}"
    return m.group(1)


def _edit_both(sd: Path, session_id: str, target: Path, call_id: str) -> None:
    payload: dict[str, Any] = {
        "session_id": session_id,
        "tool_use_id": call_id,
        "tool_name": "Edit",
        "tool_input": {"file_path": str(target), "old_string": "a", "new_string": "b"},
    }
    pre_tool_use.evaluate_hook(
        {"hook_event_name": "PreToolUse", **payload}, state_dir=str(sd), cli_harness="claude"
    )
    handle_post_tool_use("claude", {"hook_event_name": "PostToolUse", **payload}, state_dir=str(sd))


def _spool_row(sd: Path, kind: str = "output_spool") -> dict[str, Any]:
    by_key = read_outcomes_ledger(sd)["by_key"]
    matching = [v for k, v in by_key.items() if k.endswith(f"|{kind}")]
    assert matching, f"no outcomes row found for kind={kind!r}: {list(by_key)}"
    return matching[0]


def test_output_spool_targeted_slice_and_grep_resolve_without_regret(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool_dir = tmp_path / "spool"
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))
    _write_cfg(
        isolated_user_env,
        regret_window_steps=4,
        output_spool="active",
        cli_rewrites="off",
        auto_outline="off",
    )
    sd = tmp_path / "state"
    sd.mkdir()

    # 1) CLI cg-spool slice (<= 200 lines) resolves output_spool -> targeted/none/observed
    _bash_pre(sd, "s1", "pytest tests/", "c1", cwd=tmp_path)
    sid1 = _extract_spool_id(_bash_post(sd, "s1", "pytest tests/", _big_lines(260, "slice"), "c1", cwd=tmp_path))
    _bash_pre(sd, "s1", f"cg-spool slice {sid1} --start 1 --limit 80", "c2", cwd=tmp_path)

    # 2) MCP cg_spool_grep resolves output_spool -> targeted/none/observed
    _bash_pre(sd, "s2", "pytest tests/a", "c3", cwd=tmp_path)
    sid2 = _extract_spool_id(_bash_post(sd, "s2", "pytest tests/a", _big_lines(260, "grep"), "c3", cwd=tmp_path))
    pre_tool_use.evaluate_hook(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s2",
            "tool_use_id": "c4",
            "tool_name": "mcp__context-guard-spool__cg_spool_grep",
            "tool_input": {"spool_id": sid2, "pattern": "mismatch"},
            "cwd": str(tmp_path),
        },
        state_dir=str(sd),
        cli_harness="claude",
    )

    # 3) Direct bounded Read on sp_<id>.txt (limit 50 <= 200) resolves output_spool -> targeted/none/observed
    _bash_pre(sd, "s3", "pytest tests/b", "c5", cwd=tmp_path)
    sid3 = _extract_spool_id(_bash_post(sd, "s3", "pytest tests/b", _big_lines(260, "dread"), "c5", cwd=tmp_path))
    claude_read(spool_dir / f"{sid3}.txt", sd, offset=1, limit=50, session_id="s3", confirm=False, tool_use_id="c6", cwd=tmp_path)

    ledger = read_outcomes_ledger(sd)
    assert ledger["open_windows"] == {}
    row = _spool_row(sd, "output_spool")
    assert row["recovery"]["targeted"] == 3
    assert row["regret"] == {"none": 3, "suspected": 0, "confirmed": 0, "unknown": 0}
    assert row["evidence"]["observed"] == 3


def test_output_spool_full_read_above_200_lines_and_80_pct_resolves_suspected_regret(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool_dir = tmp_path / "spool"
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))
    _write_cfg(
        isolated_user_env,
        regret_window_steps=4,
        output_spool="active",
        cli_rewrites="off",
        auto_outline="off",
    )
    sd = tmp_path / "state"
    sd.mkdir()

    # Boundary A: 220/300 lines (< 80% of 300) stays targeted/none
    _bash_pre(sd, "sb1", "pytest t1", "b1", cwd=tmp_path)
    sid_b1 = _extract_spool_id(_bash_post(sd, "sb1", "pytest t1", _big_lines(300, "b1"), "b1", cwd=tmp_path))
    _bash_pre(sd, "sb1", f"cg-spool slice {sid_b1} --start 1 --limit 220", "b2", cwd=tmp_path)

    # Suspected Case A: 250/250 lines (> 200 and > 80% of 250) -> full/suspected/observed
    _bash_pre(sd, "sf1", "pytest t2", "f1", cwd=tmp_path)
    sid_f1 = _extract_spool_id(_bash_post(sd, "sf1", "pytest t2", _big_lines(250, "f1"), "f1", cwd=tmp_path))
    _bash_pre(sd, "sf1", f"cg-spool slice {sid_f1} --start 1 --limit 250", "f2", cwd=tmp_path)

    # Suspected Case B: direct unbounded Read of sp_<id>.txt -> full/suspected/observed
    _bash_pre(sd, "sf2", "pytest t3", "f3", cwd=tmp_path)
    sid_f2 = _extract_spool_id(_bash_post(sd, "sf2", "pytest t3", _big_lines(250, "f2"), "f3", cwd=tmp_path))
    claude_read(spool_dir / f"{sid_f2}.txt", sd, session_id="sf2", confirm=False, tool_use_id="f4", cwd=tmp_path)

    ledger = read_outcomes_ledger(sd)
    assert ledger["open_windows"] == {}
    row = _spool_row(sd, "output_spool")
    assert row["recovery"]["targeted"] == 1
    assert row["recovery"]["full"] == 2
    assert row["regret"]["none"] == 1
    assert row["regret"]["suspected"] == 2
    assert row["evidence"]["observed"] == 3


def test_output_spool_command_repeat_without_edit_resolves_confirmed_regret(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(tmp_path / "spool"))
    _write_cfg(
        isolated_user_env,
        regret_window_steps=4,
        output_spool="active",
        cli_rewrites="auto",
        auto_outline="off",
    )
    sd = tmp_path / "state"
    sd.mkdir()

    # Step 1: rewritten Bash command spools output -> opens cli:<sig> + spool:<id>
    _bash_pre(sd, "sr", "pytest tests/", "r1", cwd=tmp_path)
    _extract_spool_id(_bash_post(sd, "sr", "pytest tests/", _big_lines(260, "rep"), "r1", cwd=tmp_path))

    # Step 2 (no intervening edit): repeating `pytest tests/` resolves output_spool as full/suspected/observed
    _bash_pre(sd, "sr", "pytest tests/", "r2", cwd=tmp_path)
    spool_row = _spool_row(sd, "output_spool")
    assert spool_row["recovery"]["full"] == 1
    assert spool_row["regret"]["suspected"] == 1
    assert spool_row["regret"]["confirmed"] == 0
    assert spool_row["evidence"]["observed"] == 1
    assert not any(w["key"].endswith("|output_spool") for w in read_outcomes_ledger(sd)["open_windows"].values())

    # Identical repeat also applies to non-self MCP tools
    mcp_payload = {
        "hook_event_name": "PostToolUse",
        "session_id": "smcp",
        "tool_use_id": "m1",
        "tool_name": "mcp__srv__query",
        "tool_input": {"q": "select 1"},
        "tool_response": _big_lines(260, "mcp"),
        "cwd": str(tmp_path),
    }
    handle_post_tool_use("claude", mcp_payload, state_dir=str(sd))
    pre_tool_use.evaluate_hook(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "smcp",
            "tool_use_id": "m2",
            "tool_name": "mcp__srv__query",
            "tool_input": {"q": "select 1"},
            "cwd": str(tmp_path),
        },
        state_dir=str(sd),
        cli_harness="claude",
    )
    assert _spool_row(sd, "output_spool")["regret"]["suspected"] == 2
    assert _spool_row(sd, "output_spool")["regret"]["confirmed"] == 0


def test_edit_clears_cmd_sig_preventing_false_regret_while_preserving_later_slice_recovery(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(tmp_path / "spool"))
    _write_cfg(
        isolated_user_env,
        regret_window_steps=6,
        output_spool="active",
        cli_rewrites="auto",
        auto_outline="off",
    )
    sd = tmp_path / "state"
    sd.mkdir()
    src = tmp_path / "src" / "foo.py"
    src.parent.mkdir(parents=True)
    src.write_text("a = 1\n", encoding="utf-8")

    # Step 1: pytest rewritten + spooled
    _bash_pre(sd, "sed", "pytest tests/", "e1", cwd=tmp_path)
    sid = _extract_spool_id(_bash_post(sd, "sed", "pytest tests/", _big_lines(260, "ed"), "e1", cwd=tmp_path))

    # Step 2: Edit src/foo.py closes cli_rewrite (`none/none`) and clears cmd_sig inside open spool window
    _edit_both(sd, "sed", src, "e2")
    wins = read_outcomes_ledger(sd)["open_windows"]
    assert not any(w["key"].endswith("|cli_rewrite") for w in wins.values())
    spool_key = f"sed|spool:{sid}|output_spool"
    assert spool_key in wins and wins[spool_key]["meta"]["cmd_sig"] == ""
    assert _spool_row(sd, "cli_rewrite")["regret"]["none"] == 1

    # Step 3: Re-running pytest tests/ after the edit must record zero regret on output_spool
    _bash_pre(sd, "sed", "pytest tests/", "e3", cwd=tmp_path)
    assert _spool_row(sd, "output_spool")["regret"] == {"none": 0, "suspected": 0, "confirmed": 0, "unknown": 0}
    assert spool_key in read_outcomes_ledger(sd)["open_windows"]

    # Step 4: Later targeted slice still resolves the preserved spool window cleanly
    _bash_pre(sd, "sed", f"cg-spool slice {sid} --start 1 --limit 80", "e4", cwd=tmp_path)
    row = _spool_row(sd, "output_spool")
    assert row["recovery"]["targeted"] == 1
    assert row["regret"]["none"] == 1
    assert row["evidence"]["observed"] == 1
    assert not any(w["key"].endswith("|output_spool") for w in read_outcomes_ledger(sd)["open_windows"].values())


def test_cli_rewrite_verbose_override_regret_and_edit_clear(
    isolated_user_env: Path, tmp_path: Path
) -> None:
    _write_cfg(isolated_user_env, regret_window_steps=5, cli_rewrites="auto", output_spool="off")
    sd = tmp_path / "state"
    sd.mkdir()
    src = tmp_path / "app.py"
    src.write_text("a = 1\n", encoding="utf-8")

    # Quoted verbose guard sanity: quoted `--verbose` must never count as a verbose override
    assert spool_store.is_verbose_override_command('git log --grep="--verbose"') == (False, "")
    assert spool_store.is_verbose_override_command('pytest -k "--verbose"') == (False, "")

    # Case A: Rewrite pytest tests/ -> pytest -q tests/, then override with pytest -vv tests/ without edit
    d1 = _bash_pre(sd, "sv1", "pytest tests/", "v1", cwd=tmp_path)
    assert "-q" in str((d1.get("hookSpecificOutput") or {}).get("updatedInput", {}).get("command", ""))
    d2 = _bash_pre(sd, "sv1", "pytest -vv tests/", "v2", cwd=tmp_path)
    assert "updatedInput" not in (d2.get("hookSpecificOutput") or {})
    cli_row = _spool_row(sd, "cli_rewrite")
    assert cli_row["recovery"]["full"] == 1
    assert cli_row["regret"]["suspected"] == 1
    assert cli_row["regret"]["confirmed"] == 0
    assert cli_row["evidence"]["observed"] == 1

    # Case B: Edit clears cli_rewrite window with none/none so a subsequent verbose run records zero additional regret
    _bash_pre(sd, "sv2", "pytest tests/", "v3", cwd=tmp_path)
    _bash_pre(sd, "sv2", 'git log --grep="--verbose"', "v4", cwd=tmp_path)
    assert len(read_outcomes_ledger(sd)["open_windows"]) == 1
    _edit_both(sd, "sv2", src, "v5")
    assert read_outcomes_ledger(sd)["open_windows"] == {}
    _bash_pre(sd, "sv2", "pytest --verbose tests/", "v6", cwd=tmp_path)
    cli_after = _spool_row(sd, "cli_rewrite")
    assert cli_after["regret"]["suspected"] == 1
    assert cli_after["regret"]["confirmed"] == 0
    assert cli_after["regret"]["none"] == 1


def test_range_trim_prefix_reread_and_shell_bypass_confirmed_regret(
    isolated_user_env: Path, tmp_path: Path
) -> None:
    _write_cfg(isolated_user_env, regret_window_steps=6, range_trim="active", auto_outline="off")
    sd = tmp_path / "state"
    sd.mkdir()
    mod = write_python_module(tmp_path / "big_trim.py", funcs=26, body_lines=9)

    # Session 1: prefix trim [1, 100], disjoint read [151, 220] -> no regret; overlapping read [20, 60] -> suspected
    claude_read(mod, sd, offset=1, limit=100, session_id="srt1", tool_use_id="t1")
    r2 = claude_read(mod, sd, offset=1, limit=150, session_id="srt1", tool_use_id="t2")
    assert r2["hookSpecificOutput"]["updatedInput"]["offset"] == 101
    wins1 = [w for w in read_outcomes_ledger(sd)["open_windows"].values() if w["key"].endswith("|range_trim")]
    assert len(wins1) == 1 and wins1[0]["meta"] == {"trimmed_start": 1, "trimmed_end": 100}

    claude_read(mod, sd, offset=151, limit=70, session_id="srt1", tool_use_id="t3")
    assert _spool_row(sd, "range_trim")["regret"]["suspected"] == 0
    assert _spool_row(sd, "range_trim")["regret"]["confirmed"] == 0

    claude_read(mod, sd, offset=20, limit=41, session_id="srt1", tool_use_id="t4")
    rt_row = _spool_row(sd, "range_trim")
    assert rt_row["recovery"]["targeted"] == 1 and rt_row["regret"]["suspected"] == 1 and rt_row["regret"]["confirmed"] == 0

    # Session 2: shell bypass (`cat big_trim2.py`) resolves range_trim window as targeted/suspected/observed
    mod2 = write_python_module(tmp_path / "big_trim2.py", funcs=26, body_lines=9)
    canon2 = os.path.realpath(str(mod2))
    claude_read(mod2, sd, offset=1, limit=100, session_id="srt2", tool_use_id="t5")
    r4 = claude_read(mod2, sd, offset=1, limit=150, session_id="srt2", tool_use_id="t6")
    assert r4["hookSpecificOutput"]["updatedInput"]["offset"] == 101
    _bash_pre(sd, "srt2", f"cat {canon2}", "t7", cwd=tmp_path)
    rt_after = _spool_row(sd, "range_trim")
    assert rt_after["recovery"]["targeted"] == 2 and rt_after["regret"]["suspected"] == 2 and rt_after["regret"]["confirmed"] == 0
    assert read_outcomes_ledger(sd)["open_windows"] == {}


def test_compaction_and_session_end_close_spool_windows_and_clean_shadow_spools(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(tmp_path / "spool"))
    _write_cfg(isolated_user_env, regret_window_steps=6, output_spool="active", auto_outline="off")
    sd1 = tmp_path / "sd1"
    sd1.mkdir()
    src = tmp_path / "edited.py"
    src.write_text("x = 1\n", encoding="utf-8")

    # Active spool opens window + shadow_spools has an entry in sd1/shadow.json
    _bash_pre(sd1, "scmp", "pytest tests/", "c1", cwd=tmp_path)
    _extract_spool_id(_bash_post(sd1, "scmp", "pytest tests/", _big_lines(260, "cmp"), "c1", cwd=tmp_path))
    sh_path = telemetry.shadow_path_for(sd1)
    assert sh_path is not None
    telemetry.record_shadow_spool("claude", {"saved_bytes": 4096}, shadow_path=sh_path)
    # Single-file edit invalidation must NOT reset shadow_spools
    telemetry.invalidate_shadow_ledger(raw_path=str(src), shadow_path=sh_path)
    assert telemetry.load_shadow_ledger(sh_path)["shadow_spools"]["count"] == 1

    pre_compact.handle_pre_compact({"session_id": "scmp"}, state_dir=str(sd1))
    assert read_outcomes_ledger(sd1)["open_windows"] == {}
    cmp_row = _spool_row(sd1, "output_spool")
    assert cmp_row["recovery"]["none"] == 1 and cmp_row["regret"]["none"] == 1
    assert telemetry.load_shadow_ledger(sh_path)["shadow_spools"]["count"] == 1
    assert telemetry.invalidate_shadow_ledger(full_compact=True, shadow_path=sh_path)
    assert telemetry.load_shadow_ledger(sh_path)["shadow_spools"] == {
        "count": 0, "estimated_saved_bytes": 0, "last_ts": None, "by_harness": {}
    }

    # SessionEnd closes open output_spool window cleanly as none/none/observed
    sd2 = tmp_path / "sd2"
    sd2.mkdir()
    _bash_pre(sd2, "send", "pytest tests/", "s1", cwd=tmp_path)
    _extract_spool_id(_bash_post(sd2, "send", "pytest tests/", _big_lines(260, "end"), "s1", cwd=tmp_path))
    session_end.handle_session_end({"session_id": "send"}, state_dir=str(sd2))
    assert read_outcomes_ledger(sd2)["open_windows"] == {}
    end_row = _spool_row(sd2, "output_spool")
    assert end_row["recovery"]["none"] == 1 and end_row["regret"]["none"] == 1


def test_spool_hook_lock_ordering_never_nests_inside_locked_state(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hooks import post_tool_use as post_mod

    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(tmp_path / "spool"))
    _write_cfg(
        isolated_user_env,
        regret_window_steps=6,
        output_spool="active",
        range_trim="active",
        cli_rewrites="auto",
        auto_outline="off",
    )
    sd = tmp_path / "sd_lock"
    sd.mkdir()
    mod = write_python_module(tmp_path / "lock_mod.py", funcs=25, body_lines=9)

    lock_depth = 0
    observed_calls: list[tuple[str, int]] = []
    orig_locked_state = state_store.locked_state

    @contextmanager
    def _tracked_locked_state(*args: Any, **kwargs: Any) -> Iterator[Any]:
        nonlocal lock_depth
        lock_depth += 1
        try:
            with orig_locked_state(*args, **kwargs) as txn:
                yield txn
        finally:
            lock_depth -= 1

    monkeypatch.setattr(state_store, "locked_state", _tracked_locked_state)
    monkeypatch.setattr(pre_tool_use, "locked_state", _tracked_locked_state)

    def _wrap_pub(mod_obj: Any, attr: str) -> None:
        orig = getattr(mod_obj, attr)

        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            observed_calls.append((attr, lock_depth))
            return orig(*args, **kwargs)

        monkeypatch.setattr(mod_obj, attr, _wrapped)

    for target_mod, names in (
        (outcomes, (
            "open_outcome_window", "close_outcome_windows", "record_spool_followup",
            "record_spool_command_repeat", "record_cli_verbose_regret",
            "record_range_trim_regret", "reconcile_mutation_windows",
        )),
        (post_mod, ("open_outcome_window", "reconcile_mutation_windows", "record_telemetry_event")),
        (pre_tool_use, (
            "open_outcome_window", "close_outcome_windows", "reconcile_mutation_windows",
            "record_cli_verbose_regret", "record_range_trim_regret",
            "record_spool_command_repeat", "record_spool_followup", "classify_pre_tool_spool_followup",
        )),
        (spool_store, ("spool_post_tool_output", "classify_pre_tool_spool_followup")),
    ):
        for fn_name in names:
            _wrap_pub(target_mod, fn_name)

    _bash_pre(sd, "slock", "pytest tests/", "lk1", cwd=tmp_path)
    sid = _extract_spool_id(_bash_post(sd, "slock", "pytest tests/", _big_lines(260, "lk"), "lk1", cwd=tmp_path))
    _bash_pre(sd, "slock", f"cg-spool slice {sid} --start 1 --limit 50", "lk2", cwd=tmp_path)
    claude_read(mod, sd, offset=1, limit=100, session_id="slock", tool_use_id="lk3")
    claude_read(mod, sd, offset=1, limit=150, session_id="slock", tool_use_id="lk4")
    _edit_both(sd, "slock", mod, "lk5")

    assert len(observed_calls) >= 10
    nested = [(name, depth) for name, depth in observed_calls if depth != 0]
    assert nested == [], f"Detected outcomes/telemetry/spool calls inside locked_state: {nested}"
