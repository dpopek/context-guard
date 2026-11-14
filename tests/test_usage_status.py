"""cg_status shows real token usage only on --markdown, --json and --usage."""
from __future__ import annotations

import json
from pathlib import Path

import bin.cg_status as cg_status
from bin import token_usage


def seed_claude_transcript() -> None:
    path = token_usage.TRANSCRIPT_ROOTS["claude"] / "proj" / "s.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    line = {
        "type": "assistant",
        "timestamp": "2026-11-01T10:00:00Z",
        "message": {"id": "m1", "model": "claude-opus-5-5", "usage": {"input_tokens": 5, "cache_read_input_tokens": 95}},
    }
    path.write_text(json.dumps(line) + "\n", encoding="utf-8")


def test_usage_flag_prints_only_usage_sections(capsys) -> None:
    seed_claude_transcript()
    assert cg_status.main(["--usage"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("## Token Usage (real, from transcripts)")
    assert "| `claude` | claude-opus-5-5 | 1 | 5 | 95 | 0 | 0 | 95.0% |" in out
    assert "Token Savings Report" not in out


def test_markdown_appends_usage_sections(capsys) -> None:
    seed_claude_transcript()
    assert cg_status.main(["--markdown"]) == 0
    out = capsys.readouterr().out
    assert "Token Savings Report" in out
    assert "## Session Preamble" in out


def test_json_carries_token_usage(capsys) -> None:
    seed_claude_transcript()
    assert cg_status.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["token_usage"]["totals"]["claude|claude-opus-5-5"]["events"] == 1
    assert "saved_tokens" in payload


def test_usage_path_flag_selects_the_ledger(tmp_path: Path, capsys) -> None:
    ledger = tmp_path / "custom" / "token_usage.json"
    assert cg_status.main(["--usage", "--usage-path", str(ledger)]) == 0
    capsys.readouterr()
    assert ledger.is_file()


def test_short_hud_and_outcomes_never_ingest(monkeypatch, capsys) -> None:
    calls: list[tuple] = []
    monkeypatch.setattr(token_usage, "refresh_usage", lambda *args, **kwargs: calls.append(args))
    for argv in (["--short"], ["--claude-hud"], ["--outcomes"]):
        assert cg_status.main(argv) == 0
    capsys.readouterr()
    assert calls == []


def test_usage_failure_shows_error_class_and_keeps_other_sections(monkeypatch, capsys) -> None:
    def _broken(*_args, **_kwargs):
        raise OSError("disk gone")

    monkeypatch.setattr(token_usage, "refresh_usage", _broken)
    assert cg_status.main(["--markdown"]) == 0
    out = capsys.readouterr().out
    assert "Token Savings Report" in out
    assert "_Unavailable: OSError_" in out
    assert cg_status.main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["token_usage"] == {"error": "OSError"}


def test_non_oserror_usage_failure_keeps_the_report(monkeypatch, capsys) -> None:
    def _broken(*_args, **_kwargs):
        raise AttributeError("boom")

    monkeypatch.setattr(token_usage, "refresh_usage", _broken)
    assert cg_status.main(["--markdown"]) == 0
    out = capsys.readouterr().out
    assert "Token Savings Report" in out
    assert "_Unavailable: AttributeError_" in out
    assert "CG: n/a" not in out
    assert cg_status.main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["token_usage"] == {"error": "AttributeError"}


def test_cg_status_doctor_reports_healthy_environment_and_harnesses(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    plugin_root = tmp_path / "plugin"
    (plugin_root / "hooks").mkdir(parents=True)
    (plugin_root / "telemetry").mkdir(parents=True)
    (plugin_root / "hooks" / "hooks.json").write_text("{}", encoding="utf-8")
    (plugin_root / "hooks" / "pre_tool_use.py").write_text("# stub\n", encoding="utf-8")
    (plugin_root / "plugin.json").write_text('{"version": "0.0.0-test"}', encoding="utf-8")
    claude_cfg = tmp_path / "settings.json"
    cursor_cfg = tmp_path / "cursor_hooks.json"
    codex_cfg = tmp_path / "codex_hooks.json"
    pre_hook = plugin_root / "hooks" / "pre_tool_use.py"
    claude_cfg.write_text(
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": f"python3 {pre_hook}"}]}]}}),
        encoding="utf-8",
    )
    cursor_cfg.write_text(
        json.dumps({"version": 1, "hooks": {"preToolUse": [{"command": f"python3 {pre_hook}"}]}}),
        encoding="utf-8",
    )
    codex_cfg.write_text(
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": f"python3 {pre_hook}"}]}]}}),
        encoding="utf-8",
    )

    report = cg_status.run_doctor(
        plugin_root=plugin_root,
        claude_settings_path=claude_cfg,
        cursor_hooks_path=cursor_cfg,
        codex_hooks_path=codex_cfg,
    )
    assert report["ok"] is True
    assert report["python"]["ok"] is True
    assert report["flock"]["ok"] is True
    assert report["telemetry_dir"]["ok"] is True
    assert report["harnesses"] == {
        "antigravity": True,
        "claude": True,
        "cursor": True,
        "codex": True,
    }
    rendered = cg_status.render_doctor_report(report)
    assert "# Context-Guard Doctor" in rendered
    assert "OK" in rendered

    monkeypatch.setattr(cg_status, "ROOT", plugin_root)
    assert cg_status.main(["--doctor"]) == 0
    cli_out = capsys.readouterr().out
    assert "# Context-Guard Doctor" in cli_out


def test_cg_status_doctor_detects_unwritable_telemetry_dir(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    plugin_root = tmp_path / "broken_plugin"
    # Create telemetry as a regular file so mkdir(telemetry) fails with OSError
    plugin_root.mkdir(parents=True)
    (plugin_root / "telemetry").write_text("not a dir", encoding="utf-8")
    report = cg_status.run_doctor(plugin_root=plugin_root)
    assert report["telemetry_dir"]["ok"] is False
    assert report["harnesses"]["antigravity"] is False
    assert report["ok"] is False
    rendered = cg_status.render_doctor_report(report)
    assert "FAIL" in rendered

    monkeypatch.setattr(cg_status, "ROOT", plugin_root)
    assert cg_status.main(["--doctor"]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_normalize_line_bounds_unifies_start_end_offset_limit_and_inverted_bounds() -> None:
    from hooks.harness_adapter import normalize_line_bounds

    assert normalize_line_bounds(10, 25) == (10, 25, False)
    assert normalize_line_bounds(0, -1) == (1, -1, False)
    assert normalize_line_bounds(20, 10) == (20, -1, True)
    assert normalize_line_bounds(
        None, None, offset_raw=15, limit_raw=10, has_start_key=False, has_end_key=False
    ) == (15, 24, False)


def test_bin_modules_bootstrap_sys_path_independently(tmp_path: Path) -> None:
    import subprocess
    import sys

    repo_root = Path(__file__).resolve().parent.parent
    for rel in ("bin/harness_status.py", "bin/usage_report.py"):
        proc = subprocess.run(
            [sys.executable, str(repo_root / rel)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"{rel} failed: {proc.stderr}"


def test_checkout_without_local_stats_warns_when_installed_telemetry_exists(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    fake_home = tmp_path / "home"
    installed_root = fake_home / ".gemini" / "config" / "plugins" / "context-guard"
    (installed_root / "telemetry").mkdir(parents=True)
    (installed_root / "telemetry" / "stats.json").write_text('{"saved_tokens": 12345}', encoding="utf-8")

    checkout_root = tmp_path / "dev-checkout"
    (checkout_root / "telemetry").mkdir(parents=True)
    # Even if an orphaned token_usage.json exists in the checkout, missing stats.json must still warn.
    (checkout_root / "telemetry" / "token_usage.json").write_text("{}", encoding="utf-8")

    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.delenv("CONTEXT_GUARD_HOME", raising=False)
    monkeypatch.setattr(cg_status, "resolve_plugin_root", lambda default_root=None: checkout_root)

    msg = cg_status.detect_checkout_telemetry_mismatch()
    assert msg is not None
    assert str(checkout_root.resolve()) in msg
    assert "CONTEXT_GUARD_HOME" in msg

    assert cg_status.main(["--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["saved_tokens"] == 0
    assert "context-guard: running from checkout" in captured.err
    assert "CONTEXT_GUARD_HOME" in captured.err


def test_checkout_warning_suppressed_with_env_explicit_paths_or_local_stats(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    fake_home = tmp_path / "home"
    installed_root = fake_home / ".gemini" / "config" / "plugins" / "context-guard"
    (installed_root / "telemetry").mkdir(parents=True)
    (installed_root / "telemetry" / "stats.json").write_text('{"saved_tokens": 99}', encoding="utf-8")

    checkout_root = tmp_path / "dev-checkout"
    (checkout_root / "telemetry").mkdir(parents=True)

    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setattr(cg_status, "resolve_plugin_root", lambda default_root=None: checkout_root)

    # 1. Suppressed when CONTEXT_GUARD_HOME is explicitly set.
    monkeypatch.setenv("CONTEXT_GUARD_HOME", str(checkout_root))
    assert cg_status.detect_checkout_telemetry_mismatch() is None

    # 2. Suppressed when explicit CLI path flag is passed.
    monkeypatch.delenv("CONTEXT_GUARD_HOME", raising=False)
    custom_stats = tmp_path / "custom_stats.json"
    assert cg_status.main(["--short", "--stats-path", str(custom_stats)]) == 0
    assert capsys.readouterr().err == ""

    # 3. Suppressed when active root IS the installed plugin root.
    assert cg_status.detect_checkout_telemetry_mismatch(plugin_root=installed_root, home_dir=fake_home) is None

    # 4. Suppressed once checkout has its own stats.json.
    (checkout_root / "telemetry" / "stats.json").write_text('{"saved_tokens": 1}', encoding="utf-8")
    assert cg_status.detect_checkout_telemetry_mismatch() is None


def test_refresh_usage_migrates_legacy_antigravity_and_codex_preserving_claude(tmp_path: Path) -> None:
    roots = {name: tmp_path / name for name in ("antigravity", "claude", "codex", "cursor")}
    for r in roots.values():
        r.mkdir(parents=True)

    claude_file = roots["claude"] / "proj" / "s1.jsonl"
    claude_file.parent.mkdir(parents=True)
    claude_file.write_text(
        json.dumps(
            {
                "type": "assistant",
                "timestamp": "2026-11-12T10:00:00Z",
                "message": {"id": "c1", "model": "claude-opus-5-5", "usage": {"input_tokens": 500}},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    claude_stat = claude_file.stat()

    ag_file = roots["antigravity"] / "conv1" / ".system_generated" / "logs" / "transcript_full.jsonl"
    ag_file.parent.mkdir(parents=True)
    ag_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "step_index": 0,
                        "type": "USER_INPUT",
                        "content": "<USER_REQUEST>\nhi\n</USER_REQUEST>\n<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Carbon (Medium).\n</USER_SETTINGS_CHANGE>",
                    }
                ),
                json.dumps(
                    {
                        "step_index": 1,
                        "type": "PLANNER_RESPONSE",
                        "created_at": "2026-11-12T12:00:00Z",
                        "input_tokens": 18000,
                        "output_tokens": 120,
                        "cache_read_tokens": 0,
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    ag_stat = ag_file.stat()

    codex_file = roots["codex"] / "2026" / "11" / "12" / "rollout-1.jsonl"
    codex_file.parent.mkdir(parents=True)
    codex_file.write_text(
        "\n".join(
            [
                json.dumps({"type": "session_meta", "payload": {"originator": "Codex Desktop", "source": "vscode"}}),
                json.dumps(
                    {
                        "type": "response_item",
                        "payload": {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "x" * 400}]},
                    }
                ),
                json.dumps({"type": "turn_context", "payload": {"model": "gpt-5-codex"}}),
                json.dumps(
                    {
                        "type": "event_msg",
                        "timestamp": "2026-11-12T12:05:00Z",
                        "payload": {
                            "type": "token_count",
                            "info": {
                                "last_token_usage": {"input_tokens": 3000, "cached_input_tokens": 1000, "output_tokens": 50},
                                "total_token_usage": {"input_tokens": 3000, "output_tokens": 50, "total_tokens": 3050},
                            },
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    codex_stat = codex_file.stat()

    ledger = tmp_path / "token_usage.json"
    legacy_payload = {
        "cursors": {
            str(claude_file): {"inode": claude_stat.st_ino, "offset": claude_stat.st_size, "model": None, "preamble_done": True},
            str(ag_file): {"inode": ag_stat.st_ino, "offset": ag_stat.st_size, "model": None, "preamble_done": True},
            str(codex_file): {"inode": codex_stat.st_ino, "offset": codex_stat.st_size, "model": None, "preamble_done": True},
        },
        "seen_ids": {str(claude_file): ["c1"]},
        "cursor_estimates": {},
        "totals": {
            "claude|claude-opus-5-5": {"input": 500, "output": 0, "cache_read": 0, "cache_write": 0, "events": 1, "total_only": 0},
            "antigravity|unknown": {"input": 100, "output": 0, "cache_read": 0, "cache_write": 0, "events": 1, "total_only": 0},
        },
        "by_day": {
            "2026-11-12": {
                "claude": {"input": 500, "output": 0, "cache_read": 0, "cache_write": 0, "events": 1, "total_only": 0},
                "antigravity": {"input": 100, "output": 0, "cache_read": 0, "cache_write": 0, "events": 1, "total_only": 0},
            }
        },
        "preamble": {"claude": [500], "antigravity": [100]},
        "preamble_parts": [],
        "codex_preamble_parts": [],
        "component_use": {},
        "component_use_since": "2026-11-09",
        "backlog": {},
        "antigravity_coverage": {"planner": 1, "with_usage": 1},
        "skipped_lines": 0,
        "saved_tokens_at_start": 120,
        "started_at": "2026-11-09T18:00:00+00:00",
        "updated_at": "2026-11-12T18:00:00+00:00",
    }
    ledger.write_text(json.dumps(legacy_payload), encoding="utf-8")

    state = token_usage.refresh_usage(state_path=ledger, roots=roots, saved_tokens_now=999)
    assert state["schema_version"] == token_usage.USAGE_SCHEMA_VERSION
    assert state["schema_version"] == 3
    assert state["started_at"] == "2026-11-09T18:00:00+00:00"
    assert state["saved_tokens_at_start"] == 120
    assert state["totals"]["claude|claude-opus-5-5"]["events"] == 1
    assert "antigravity|unknown" not in state["totals"]
    assert "antigravity|gemini4carbonmedium" in state["totals"]
    assert len(state["codex_preamble_parts"]) == 1
    assert state["codex_preamble_parts"][0]["cohort"] == "codex (desktop)"


def test_harness_status_validates_json_and_verifies_targets_on_disk(tmp_path: Path) -> None:
    import os
    from bin import harness_status

    real_hook = tmp_path / "dir with spaces" / "hooks" / "pre_tool_use.py"
    real_hook.parent.mkdir(parents=True)
    real_hook.write_text("# stub\n", encoding="utf-8")

    claude_cfg = tmp_path / "claude.json"
    cursor_cfg = tmp_path / "cursor.json"
    codex_cfg = tmp_path / "codex.json"

    claude_cfg.write_text(
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": f'python3 "{real_hook}" --harness claude'}]}]}}),
        encoding="utf-8",
    )
    cursor_cfg.write_text(
        json.dumps({"version": 1, "hooks": {"preToolUse": [{"command": r"python C:\missing\hooks\pre_tool_use.py"}]}}),
        encoding="utf-8",
    )
    codex_cfg.write_text('{"command": "/not/inside/hooks/pre_tool_use.py"}', encoding="utf-8")

    status = harness_status.check_status(claude_cfg, cursor_cfg, codex_cfg)
    assert status == {"claude": True, "cursor": True, "codex": False}

    codex_cfg.write_text(json.dumps({"hooks": {"note": "/hooks/pre_tool_use.py"}}), encoding="utf-8")
    assert harness_status.check_status(claude_cfg, cursor_cfg, codex_cfg)["codex"] is False

    details = harness_status.verify_harness_hooks(claude_cfg, cursor_cfg, codex_cfg)
    assert details["claude"]["registered"] is True
    assert details["claude"]["target_exists"] is True
    assert details["claude"]["ok"] is True
    assert details["cursor"]["registered"] is True
    assert details["cursor"]["target_exists"] is False
    assert details["cursor"]["ok"] is False
    assert details["codex"]["registered"] is False
    assert details["codex"]["target_exists"] is False
    assert details["codex"]["ok"] is False

    if os.name != "nt":
        dangling = tmp_path / "dangling_hooks.json"
        dangling.symlink_to(tmp_path / "does_not_exist.json")
        assert harness_status.check_status(dangling, cursor_cfg, codex_cfg)["claude"] is False
        assert harness_status.verify_harness_hooks(dangling, cursor_cfg, codex_cfg)["claude"]["registered"] is False


def test_read_nonblocking_stdin_json_hybrid_zero_thread_leak_and_fallbacks(
    monkeypatch,
) -> None:
    import io
    import os
    import select
    import sys
    import threading

    spawned: list[threading.Thread] = []
    real_thread = threading.Thread

    def _spy_thread(*args, **kwargs):
        t = real_thread(*args, **kwargs)
        spawned.append(t)
        return t

    monkeypatch.setattr(threading, "Thread", _spy_thread)

    if sys.platform != "win32":
        r_fd, w_fd = os.pipe()
        try:
            with os.fdopen(r_fd, "r", encoding="utf-8") as r_stream:
                monkeypatch.setattr(sys, "stdin", r_stream)
                # Empty open pipe: times out in select without spawning any thread
                assert cg_status.read_nonblocking_stdin_json(timeout_s=0.01) == {}
                assert spawned == []

                # Write JSON without closing write fd: reads immediately without hanging or spawning threads
                os.write(w_fd, b'{"model": {"display_name": "Opus"}}')
                assert cg_status.read_nonblocking_stdin_json(timeout_s=0.05) == {
                    "model": {"display_name": "Opus"}
                }
                assert spawned == []
        finally:
            os.close(w_fd)

    # StringIO raises UnsupportedOperation in select -> falls back to daemon thread
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"session_id": "s1"}'))
    assert cg_status.read_nonblocking_stdin_json(timeout_s=0.05) == {"session_id": "s1"}
    assert len(spawned) == 1
    assert spawned[0].daemon is True

    # Simulated win32 path uses daemon thread fallback without calling select.select
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        select,
        "select",
        lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("select must not be called on win32")),
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"ok": true}'))
    assert cg_status.read_nonblocking_stdin_json(timeout_s=0.05) == {"ok": True}
    assert len(spawned) == 2

    # Invalid / non-dict JSON returns {}
    monkeypatch.setattr(sys, "stdin", io.StringIO("[1, 2, 3]"))
    assert cg_status.read_nonblocking_stdin_json(timeout_s=0.05) == {}


def test_run_doctor_subprocess_timeout_harness_details_and_win32_python3_stub(
    tmp_path: Path, monkeypatch
) -> None:
    import shutil
    import subprocess
    import sys

    plugin_root = tmp_path / "cg_plugin"
    (plugin_root / "hooks").mkdir(parents=True)
    (plugin_root / "telemetry").mkdir(parents=True)
    (plugin_root / ".git").mkdir()
    (plugin_root / "hooks.json").write_text("{}", encoding="utf-8")
    (plugin_root / "plugin.json").write_text('{"version": "3.99.0"}', encoding="utf-8")

    claude_cfg = tmp_path / "claude.json"
    cursor_cfg = tmp_path / "cursor.json"
    codex_cfg = tmp_path / "codex.json"
    claude_cfg.write_text(
        json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": "python3 /missing/hooks/pre_tool_use.py"}]}]}}),
        encoding="utf-8",
    )
    cursor_cfg.write_text('{"version": 1, "hooks": {}}', encoding="utf-8")
    codex_cfg.write_text('{"hooks": {}}', encoding="utf-8")

    def _timeout_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["git", "status"], timeout=3)

    monkeypatch.setattr(subprocess, "run", _timeout_run)

    stub_dir = tmp_path / "Microsoft" / "WindowsApps"
    stub_dir.mkdir(parents=True)
    stub_py3 = stub_dir / "python3.exe"
    stub_py3.write_bytes(b"")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(shutil, "which", lambda cmd: str(stub_py3) if cmd == "python3" else None)

    report = cg_status.run_doctor(
        plugin_root=plugin_root,
        claude_settings_path=claude_cfg,
        cursor_hooks_path=cursor_cfg,
        codex_hooks_path=codex_cfg,
    )
    assert report["git"]["clean"] is None
    assert report["harness_details"]["claude"]["registered"] is True
    assert report["harness_details"]["claude"]["target_exists"] is False
    assert report["python"]["python3_available"] is False
    assert report["python"]["python3_stub"] is True
    rendered = cg_status.render_doctor_report(report)
    assert "missing target" in rendered

    real_py3 = tmp_path / "Python312" / "python3.exe"
    real_py3.parent.mkdir(parents=True)
    real_py3.write_bytes(b"MZ")
    monkeypatch.setattr(shutil, "which", lambda cmd: str(real_py3) if cmd == "python3" else None)
    report_ok = cg_status.run_doctor(
        plugin_root=plugin_root,
        claude_settings_path=claude_cfg,
        cursor_hooks_path=cursor_cfg,
        codex_hooks_path=codex_cfg,
    )
    assert report_ok["python"]["python3_available"] is True
    assert report_ok["python"]["python3_stub"] is False
