"""TDD tests for bounded shell follow-up telemetry, shell parser hardening, and outline-pull rewinds."""

from __future__ import annotations

import json
import os
from pathlib import Path

from hooks import outcomes, pre_tool_use as ptu
from hooks.harness_adapter import NormalizedToolCall, can_rewrite_shell_command
from hooks.session_lifecycle import apply_compaction_boundary
from hooks.shell_parser import (
    extract_outline_pull_targets,
    extract_shell_read_targets,
    is_bounded_shell_read,
)
from services.outcomes_report import render_outcomes_report
from tests.helpers import read_outcomes_ledger, read_session_state


def test_shell_read_targets_stops_at_statement_separators(tmp_path: Path) -> None:
    a_py = tmp_path / "a.py"
    b_py = tmp_path / "b.py"
    a_py.write_text("a = 1\n", encoding="utf-8")
    b_py.write_text("b = 2\n", encoding="utf-8")
    canon_a = [os.path.realpath(a_py)]

    for cmd in (
        f"cat {a_py}; echo {b_py}",
        f"cat {a_py} && wc -l {b_py}",
        f"cat {a_py} || ls {b_py}",
        f"cat {a_py}\nls {b_py}",
        f"cat {a_py} & ls {b_py}",
        f"cat {a_py} 2>&1 | head -n 20",
        f"cat {a_py} &> {b_py}",
        f"sed -n '1,10p;20,30p' {a_py}",
    ):
        assert extract_shell_read_targets(cmd) == canon_a, cmd

    semi_cmd = f"cd {tmp_path} && cat a.py; echo b.py"
    assert extract_shell_read_targets(semi_cmd) == canon_a


def test_shell_read_and_outline_pull_targets_skip_input_redirections(tmp_path: Path) -> None:
    a_py = tmp_path / "a.py"
    other = tmp_path / "other.py"
    eof_file = tmp_path / "EOF"
    for p in (a_py, other, eof_file):
        p.write_text("x = 1\n", encoding="utf-8")
    canon_a = os.path.realpath(a_py)

    assert extract_shell_read_targets(f"cat {a_py} < {other}") == [canon_a]
    assert extract_shell_read_targets(f"cat {a_py} << EOF", cwd=str(tmp_path)) == [canon_a]
    assert extract_shell_read_targets(f"cat {a_py} <<- EOF", cwd=str(tmp_path)) == [canon_a]
    assert extract_shell_read_targets(f"sed -n '1,5p' {a_py} <<< {other}") == [canon_a]
    assert extract_shell_read_targets(f"cat {a_py} 0< {other}") == [canon_a]
    assert extract_shell_read_targets(f"cat <{other}") == []
    assert extract_shell_read_targets(f"cat 0<{other}") == []

    assert extract_outline_pull_targets(f"cg-outline {a_py} < {other}") == []
    assert extract_outline_pull_targets(f"cg-outline {a_py} << EOF", cwd=str(tmp_path)) == []
    assert extract_outline_pull_targets(f"cg-outline 0<{other}") == []


def test_extract_shell_read_targets_excludes_sed_in_place_edits(tmp_path: Path) -> None:
    a_py = tmp_path / "a.py"
    a_py.write_text("a = 1\n", encoding="utf-8")
    canon_a = os.path.realpath(a_py)

    for inplace_cmd in (
        f"sed -i 's/a/b/' {a_py}",
        f"sed -i '' 's/a/b/' {a_py}",
        f"sed -I '' 's/a/b/' {a_py}",
        f"sed -i.bak 's/a/b/' {a_py}",
        f"sed -Ei 's/a/b/' {a_py}",
        f"sed --in-place 's/a/b/' {a_py}",
        f"sed --in-place=.bak 's/a/b/' {a_py}",
    ):
        assert extract_shell_read_targets(inplace_cmd) == [], inplace_cmd

    for read_cmd in (
        f"sed -e 's/i/x/' {a_py}",
        f"sed -e'-i' {a_py}",
        f"sed -n '1,20p' {a_py}",
    ):
        assert extract_shell_read_targets(read_cmd) == [canon_a], read_cmd


def test_is_bounded_shell_read_sed_head_tail_and_pipelines() -> None:
    bounded_cmds = (
        "sed -n '10,80p' a.py",
        "sed -n '10,80p;81q' a.py",
        "sed -En -e '1,30p' -e '100,140p' a.py",
        "sed -n '10,+30p' a.py",
        "sed -n '42p' a.py",
        "sed -n '$p' a.py",
        "head a.py",
        "head -n 120 a.py",
        "head -120 a.py",
        "head --lines=120 a.py",
        "head -c 200 a.py",
        "tail a.py",
        "tail -n 80 a.py",
        "tail -80 a.py",
        "tail --lines=80 a.py",
        "nl -ba a.py | sed -n '10,80p'",
        "cat -n a.py | head -n 50",
        "tail -n +200 a.py | head -n 60",
        "sed -n '10,50p' a.py | nl -ba",
    )
    for cmd in bounded_cmds:
        assert is_bounded_shell_read(cmd) is True, cmd

    assert is_bounded_shell_read("sed -n '51,$p' a.py", total_lines=300) is True
    assert is_bounded_shell_read("tail -n +51 a.py", total_lines=300) is True

    unbounded_cmds = (
        "cat a.py",
        "nl -ba a.py",
        "sed '1,20p' a.py",
        "sed -n 'p' a.py",
        "sed -n '/def/p' a.py",
        "sed -n '1,$p' a.py",
        "sed -n '1,251p' a.py",
        "head -n 251 a.py",
        "head -n -5 a.py",
        "head -c 50000 a.py",
        "tail -n +1 a.py",
        "tail -n +50 a.py",
        "tail -f a.py",
        "head -n 5 a.py | xargs cat",
    )
    for cmd in unbounded_cmds:
        assert is_bounded_shell_read(cmd) is False, cmd

    assert is_bounded_shell_read("sed -n '50,$p' a.py", total_lines=300) is False
    assert is_bounded_shell_read("sed -n '50,$p' a.py", total_lines=None) is False
    assert is_bounded_shell_read("tail -n +50 a.py", total_lines=300) is False


def test_e2e_codex_bounded_shell_followups_and_non_codex_behavior(tmp_path: Path) -> None:
    target = tmp_path / "mod.py"
    target.write_text("\n".join(f"v_{i} = {i}" for i in range(300)) + "\n", encoding="utf-8")

    for idx, bounded_cmd in enumerate(
        (
            f"sed -n '1,60p' {target}",
            f"head -n 50 {target}",
            f"tail -n 40 {target}",
            f"nl -ba {target} | sed -n '10,50p'",
        )
    ):
        sd = tmp_path / f"cx_b_{idx}"
        ptu.evaluate_hook(
            {"session_id": f"cxb-{idx}", "tool_name": "exec_command", "tool_input": {"cmd": f"cg-outline {target}"}},
            state_dir=str(sd),
            cli_harness="codex",
        )
        ptu.evaluate_hook(
            {"session_id": f"cxb-{idx}", "tool_name": "exec_command", "tool_input": {"cmd": bounded_cmd}},
            state_dir=str(sd),
            cli_harness="codex",
        )
        row = read_outcomes_ledger(sd)["by_key"]["codex|unknown|outline_pull"]
        assert row["total"] == 1 and row["applied"] == 1
        assert row["recovery"]["targeted"] == 1 and row["recovery"]["full"] == 0, bounded_cmd
        assert "pending_followup_kind" not in read_session_state(sd)["files"][os.path.realpath(target)]

        # Second shell read does not double-count shell_bypass after targeted_followup resolved.
        ptu.evaluate_hook(
            {"session_id": f"cxb-{idx}", "tool_name": "exec_command", "tool_input": {"cmd": f"cat {target}"}},
            state_dir=str(sd),
            cli_harness="codex",
        )
        row2 = read_outcomes_ledger(sd)["by_key"]["codex|unknown|outline_pull"]
        assert row2["recovery"]["full"] == 0 and row2["total"] == 1

    # Unbounded Codex reads record full recovery + suspected regret.
    for idx, bad_cmd in enumerate((f"cat {target}", f"sed '1,20p' {target}", f"head -n 260 {target}")):
        sd = tmp_path / f"cx_u_{idx}"
        ptu.evaluate_hook(
            {"session_id": f"cxu-{idx}", "tool_name": "exec_command", "tool_input": {"cmd": f"cg-outline {target}"}},
            state_dir=str(sd),
            cli_harness="codex",
        )
        ptu.evaluate_hook(
            {"session_id": f"cxu-{idx}", "tool_name": "exec_command", "tool_input": {"cmd": bad_cmd}},
            state_dir=str(sd),
            cli_harness="codex",
        )
        row = read_outcomes_ledger(sd)["by_key"]["codex|unknown|outline_pull"]
        assert row["recovery"]["targeted"] == 0 and row["recovery"]["full"] == 1 and row["regret"]["suspected"] == 1, bad_cmd

    # Non-codex harness still treats bounded shell sed as full bypass, while sed -i does not trigger bypass.
    cl_sd = tmp_path / "cl_sed"
    ptu.evaluate_hook(
        {"session_id": "cls", "tool_name": "Bash", "tool_input": {"command": f"cg-outline {target}"}},
        state_dir=str(cl_sd),
        cli_harness="claude",
    )
    ptu.evaluate_hook(
        {"session_id": "cls", "tool_name": "Bash", "tool_input": {"command": f"sed -i.bak 's/v_0/v_x/' {target}"}},
        state_dir=str(cl_sd),
        cli_harness="claude",
    )
    assert read_outcomes_ledger(cl_sd)["by_key"]["claude|unknown|outline_pull"]["recovery"]["full"] == 0
    assert "pending_followup_kind" in read_session_state(cl_sd)["files"][os.path.realpath(target)]

    ptu.evaluate_hook(
        {"session_id": "cls", "tool_name": "Bash", "tool_input": {"command": f"sed -n '1,30p' {target}"}},
        state_dir=str(cl_sd),
        cli_harness="claude",
    )
    cl_row = read_outcomes_ledger(cl_sd)["by_key"]["claude|unknown|outline_pull"]
    assert cl_row["recovery"]["full"] == 1 and cl_row["regret"]["suspected"] == 1


def test_e2e_codex_mcp_auto_outline_bounded_sed_records_targeted_followup(tmp_path: Path) -> None:
    step_dir = tmp_path / ".system_generated" / "steps" / "9"
    step_dir.mkdir(parents=True)
    mcp_out = step_dir / "output.txt"
    mcp_out.write_text(json.dumps([{"i": i, "txt": "x" * 200} for i in range(90)]), encoding="utf-8")
    sd = tmp_path / "cx_mcp"

    r1 = ptu.evaluate_hook(
        {"session_id": "cxm", "tool_name": "Read", "tool_input": {"file_path": str(mcp_out)}},
        state_dir=str(sd),
        cli_harness="codex",
    )
    assert r1["hookSpecificOutput"]["permissionDecision"] == "deny"
    unwrapped = step_dir / "output_formatted.json"
    assert unwrapped.is_file()

    ptu.evaluate_hook(
        {"session_id": "cxm", "tool_name": "exec_command", "tool_input": {"cmd": f"sed -n '1,80p' {unwrapped}"}},
        state_dir=str(sd),
        cli_harness="codex",
    )
    row = read_outcomes_ledger(sd)["by_key"]["codex|unknown|outline"]
    assert row["total"] == 1 and row["applied"] == 1
    assert row["recovery"]["targeted"] == 1 and row["recovery"]["full"] == 0


def test_e2e_multi_target_outline_pull_scales_count_to_keep_rate_at_most_100_pct(tmp_path: Path) -> None:
    files = []
    for name in ("a.py", "b.py", "c.py"):
        f = tmp_path / name
        f.write_text("\n".join(f"k_{i} = {i}" for i in range(30)) + "\n", encoding="utf-8")
        files.append(f)

    sd = tmp_path / "multi_sd"
    ptu.evaluate_hook(
        {
            "conversationId": "c-multi",
            "stepIdx": 1,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "cg-outline " + " ".join(str(p) for p in files)}},
        },
        state_dir=str(sd),
    )
    for step, p in enumerate(files, start=2):
        ptu.evaluate_hook(
            {
                "conversationId": "c-multi",
                "stepIdx": step,
                "toolCall": {"name": "read_file", "args": {"Path": str(p), "StartLine": 1, "EndLine": 20}},
            },
            state_dir=str(sd),
        )
    ledger = read_outcomes_ledger(sd)
    row = ledger["by_key"]["antigravity|unknown|outline_pull"]
    assert row["total"] == 3 and row["applied"] == 3 and row["recovery"]["targeted"] == 3
    report = render_outcomes_report(ledger)
    assert "3 (100%)" in report

    # Nonexistent target still logs total=1, applied=1 without crashing.
    miss_sd = tmp_path / "miss_sd"
    ptu.evaluate_hook(
        {"conversationId": "c-miss", "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": "cg-outline no_such.py"}}},
        state_dir=str(miss_sd),
    )
    miss_row = read_outcomes_ledger(miss_sd)["by_key"]["antigravity|unknown|outline_pull"]
    assert miss_row["total"] == 1 and miss_row["applied"] == 1


def test_e2e_outline_pull_rewind_and_compaction_step_tracking(tmp_path: Path) -> None:
    a_py = tmp_path / "a.py"
    b_py = tmp_path / "b.py"
    body = "\n".join(f"line_{i} = {i}" for i in range(60)) + "\n"
    a_py.write_text(body, encoding="utf-8")
    b_py.write_text(body, encoding="utf-8")

    # Scenario A: rewind before cg-outline step must clear stale outline_pull_step=10 and prevent false full_bypass.
    sd_a = tmp_path / "sd_a"
    ptu.evaluate_hook(
        {"conversationId": "c-rw-a", "stepIdx": 5, "toolCall": {"name": "read_file", "args": {"Path": str(a_py), "StartLine": 1, "EndLine": 30}}},
        state_dir=str(sd_a),
    )
    ptu.evaluate_hook(
        {"conversationId": "c-rw-a", "stepIdx": 10, "toolCall": {"name": "run_command", "args": {"CommandLine": f"cg-outline {a_py}"}}},
        state_dir=str(sd_a),
    )
    assert read_session_state(sd_a)["files"][os.path.realpath(a_py)]["outline_pull_step"] == 10
    ptu.evaluate_hook(
        {"conversationId": "c-rw-a", "stepIdx": 8, "toolCall": {"name": "read_file", "args": {"Path": str(a_py)}}},
        state_dir=str(sd_a),
    )
    row_a = read_outcomes_ledger(sd_a)["by_key"]["antigravity|unknown|outline_pull"]
    assert row_a["recovery"]["full"] == 0 and row_a["recovery"]["targeted"] == 0

    # Scenario B: rewind to step 8 after cg-outline at step 6 preserves outline_pull_step=6 and records targeted_followup.
    sd_b = tmp_path / "sd_b"
    ptu.evaluate_hook(
        {"conversationId": "c-rw-b", "stepIdx": 6, "toolCall": {"name": "run_command", "args": {"CommandLine": f"cg-outline {a_py}"}}},
        state_dir=str(sd_b),
    )
    ptu.evaluate_hook(
        {"conversationId": "c-rw-b", "stepIdx": 10, "toolCall": {"name": "read_file", "args": {"Path": str(b_py), "StartLine": 1, "EndLine": 20}}},
        state_dir=str(sd_b),
    )
    ptu.evaluate_hook(
        {"conversationId": "c-rw-b", "stepIdx": 8, "toolCall": {"name": "read_file", "args": {"Path": str(a_py), "StartLine": 1, "EndLine": 40}}},
        state_dir=str(sd_b),
    )
    row_b = read_outcomes_ledger(sd_b)["by_key"]["antigravity|unknown|outline_pull"]
    assert row_b["recovery"]["targeted"] == 1 and row_b["recovery"]["full"] == 0

    # Scenario C: compaction boundary keeps outline_pull after checkpoint and drops earlier pull.
    state = {
        "files": {
            "early.py": {"sha256": "s1", "reads": [], "pending_followup_kind": "outline_pull", "outline_pull_step": 6},
            "late.py": {"sha256": "s2", "reads": [], "pending_followup_kind": "outline_pull", "outline_pull_step": 9},
        }
    }
    apply_compaction_boundary(state, checkpoint_step=8)
    assert "early.py" not in state["files"]
    assert state["files"]["late.py"]["pending_followup_kind"] == "outline_pull"


def test_can_rewrite_shell_command_guards_non_string_permission_mode_and_outcomes_zero_count(tmp_path: Path) -> None:
    norm = NormalizedToolCall(
        harness="claude",
        original_tool_name="Bash",
        original_tool_input={"command": "git status"},
        canonical_tool="run_command",
        canonical_args={"CommandLine": "git status"},
        session_id="s-guard",
        step_idx=1,
        cwd=str(tmp_path),
        artifact_dir=None,
        permission_mode=None,
    )
    assert can_rewrite_shell_command(norm) is False
    ledger = tmp_path / "outcomes.json"
    outcomes.record_direct_outcome("claude", "m", "outline_pull", "applied", ledger, count=0)
    assert not ledger.exists()
