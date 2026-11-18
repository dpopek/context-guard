"""Tests for deterministic replay, benchmark, public-JSON scrubber, release hygiene, secret scanner, and doctor sync."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from bin import cg_status, outcomes_report, replay_benchmark
from hooks import config
from spool import store as spool_store


def test_replay_covers_multi_harness_modes_pass2_and_outcomes_v4(capsys: Any) -> None:
    rep = replay_benchmark.run_deterministic_replay()
    assert rep["ok"] is True
    assert rep["isolated"] is True
    assert rep["read_ledger_schema"] == 2
    assert rep["outcomes_schema"] == 4
    by_mode = {m["mode"]: m for m in rep["modes"]}
    assert set(by_mode) == {"strict", "bounded"}
    for mode in ("strict", "bounded"):
        item = by_mode[mode]
        assert item["harnesses"] == ["antigravity", "claude", "cursor", "codex"]
        assert item["post_tool_batch_ok"] is True
        assert item["pass2_safe_allowed"] is True
        assert item["pass2_bad_blocked"] is True
        assert item["read_ledger_schema"] == 2
        assert item["outcomes_schema"] == 4
    strict_decs = {d["step"]: d["decision"] for d in by_mode["strict"]["decisions"]}
    bounded_decs = {d["step"]: d["decision"] for d in by_mode["bounded"]["decisions"]}
    assert strict_decs["antigravity:overlap_trim"] == "allow"
    assert bounded_decs["antigravity:overlap_trim"] == "modify"
    assert strict_decs["claude:post_spool"] == "spooled"
    assert bounded_decs["claude:post_spool"] == "spooled"
    assert strict_decs["claude:spool_slice_recovery"] == "allow"
    assert bounded_decs["claude:spool_slice_recovery"] == "allow"
    assert by_mode["bounded"]["bytes_saved"] > 0

    rendered_out = outcomes_report.render_outcomes_report({
        "schema_version": 4,
        "by_key": {"claude|opus|output_spool": {"total": 2, "recovery": {}, "regret": {}}},
    })
    assert "output_spool" in rendered_out and "0 (0%)" in rendered_out
    md_stats = cg_status.render_markdown_report(
        {"saved_bytes": 4000, "saved_tokens": 1000, "events": {"outputs_spooled": 3}, "by_harness": {}}
    )
    assert "outputs_spooled" in md_stats and "| 3 |" in md_stats

    rc = cg_status.main(["--replay"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Context-Guard Deterministic Replay" in out
    assert "`bounded`" in out


def test_benchmark_measures_isolated_latency_and_savings(capsys: Any) -> None:
    bench = replay_benchmark.run_deterministic_benchmark(iterations=2)
    assert bench["ok"] is True
    assert bench["isolated"] is True
    assert bench["measurement_scope"] == "synthetic_corpus"
    assert bench["cold_ms"] >= 0.0
    assert bench["warm_ms"] >= 0.0
    assert bench["in_process_cold_ms"] == bench["cold_ms"]
    assert bench["in_process_warm_ms"] == bench["warm_ms"]
    assert bench["in_process_warm_ms_per_call"] == bench["warm_ms_per_call"]
    assert bench["subprocess_hook_ms_per_call"] > 0.0
    assert bench["saved_bytes"] > 0
    assert bench["saved_tokens"] > 0
    assert bench["savings_pct"] > 0.0

    rc = cg_status.main(["--benchmark"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Context-Guard Deterministic Benchmark" in out
    assert "synthetic corpus (not live session A/B)" in out
    assert "In-process engine" in out
    assert "Subprocess E2E hook latency" in out
    assert "Bytes saved" in out
    assert "Tokens saved" in out


def test_public_json_scrubs_sensitive_paths_and_files(tmp_path: Path, capsys: Any) -> None:
    home_posix = "/" + "Users/jdoe_real/workspace/proj"
    home_win = "C:\\" + "Users\\jdoe_real\\secret.txt"
    priv_dom = "mycorp." + "atlassian.net"
    gcp_id = "corp-" + "data-987654:ds.t"
    local_mail = "alice@" + "corp-internal.local"
    raw_stats = {
        "saved_bytes": 1200,
        "saved_tokens": 300,
        "events": {"outputs_spooled": 3},
        "spool_dir": str(tmp_path / "spool"),
        "spool_path": home_posix + "/spool/sp_0123456789ab.txt",
        "spool_index": "spool_index.json",
        "receipts_path": str(tmp_path / "spool" / "receipts.jsonl"),
        "receipts_dir": str(tmp_path / "spool"),
        "receipts_index": {"sp_0123456789ab": "rcpt_1"},
        "workspace_id": "ws_0123456789abcdef",
        "canon_root": home_posix,
        "spool_id": "sp_0123456789ab",
        "session_id": "sess-secret-1",
        "shadow_path": str(tmp_path / "shadow.json"),
        "private_policy_stats": {"hits": 9},
        "config_path": home_posix + "/config.json",
        "notes": ["shadow.json", "private_policy_stats.json", "spool_index.json", "receipts.jsonl", "ws_0123456789abcdef", f"read {home_posix}"],
    }
    raw_usage = {
        "today": {"cost_usd": 1.25},
        "transcript_path": home_win,
        "endpoint": f"https://{priv_dom}/wiki",
    }
    raw_outcomes = {
        "schema_version": 4,
        "totals": {"interventions": 5, "regrets": 0},
        "policy_packs": [{"id": "internal_pack", "path": home_posix}],
    }
    raw_update = {"latest": "4.3.9", "cache_path": home_posix + "/update.json", "tag": f"{gcp_id} {local_mail}"}
    rcpt_summary = {
        "receipt_count": 7, "created_count": 3, "delivery_verified_count": 2,
        "recovery_count": 1, "integrity_failures": 1,
        "last_failure_ts": "2026-11-16T01:00:00Z", "last_event_ts": "2026-11-16T02:00:00Z",
    }

    bundle = replay_benchmark.build_public_json_bundle(raw_stats, raw_usage, raw_outcomes, raw_update, receipt_summary=rcpt_summary)
    dumped = json.dumps(bundle)
    assert bundle["public"] is True
    assert bundle["stats"]["saved_tokens"] == 300
    assert bundle["stats"]["events"]["outputs_spooled"] == 3
    assert bundle["outcomes"]["schema_version"] == 4
    assert bundle["spool_reliability"] == {
        "receipt_count": 7, "created_count": 3, "delivery_verified_count": 2,
        "recovery_count": 1, "integrity_failures": 1,
    }
    assert "receipts" not in bundle
    for secret_key in (
        "shadow.json", "private_policy_stats.json", "spool_index.json", "receipts.jsonl",
        "spool_dir", "spool_path", "spool_index", "receipts_path", "receipts_dir", "receipts_index",
        "workspace_id", "canon_root", "spool_id", "session_id", "sp_0123456789ab", "ws_0123456789abcdef",
        "sess-secret-1", "config_path", "transcript_path", "policy_packs", "jdoe_real", priv_dom, gcp_id, local_mail,
    ):
        assert secret_key not in dumped
    assert replay_benchmark.check_release_hygiene(tmp_path, public_bundle=bundle) == []

    stats_p, out_p, usage_p, upd_p = tmp_path / "stats.json", tmp_path / "outcomes.json", tmp_path / "usage.json", tmp_path / "update.json"
    stats_p.write_text(json.dumps({"saved_bytes": 400, "saved_tokens": 100, "shadow_path": "shadow.json"}), encoding="utf-8")
    out_p.write_text(json.dumps({"schema_version": 4, "totals": {"interventions": 2}}), encoding="utf-8")
    usage_p.write_text(json.dumps({}), encoding="utf-8")
    upd_p.write_text(json.dumps({"latest": "1.0.0"}), encoding="utf-8")
    rc = cg_status.main(["--stats-path", str(stats_p), "--outcomes-path", str(out_p), "--usage-path", str(usage_p), "--update-path", str(upd_p), "--public-json"])
    cli_out = capsys.readouterr().out
    assert rc == 0
    cli_bundle = json.loads(cli_out)
    assert cli_bundle["public"] is True
    assert "shadow.json" not in cli_out


def test_release_hygiene_allows_mit_publisher_and_flags_leaks(tmp_path: Path) -> None:
    assert replay_benchmark.check_release_hygiene() == []

    clean_root = tmp_path / "clean_repo"
    (clean_root / "tests").mkdir(parents=True)
    (clean_root / "package.json").write_text('{"publisher": "advox.context-guard-statusbar-item", "url": "https://example.atlassian.net"}', encoding="utf-8")
    (clean_root / "tests" / "test_sample.py").write_text(f'SAMPLE = "{"/" + "Users/dev/repo"}"\n', encoding="utf-8")
    assert replay_benchmark.check_release_hygiene(clean_root) == []

    dirty_root = tmp_path / "dirty_repo"
    (dirty_root / "docs").mkdir(parents=True)
    (dirty_root / "docs" / "internal.md").write_text("internal doc", encoding="utf-8")
    (dirty_root / "leak.py").write_text(
        "\n".join([
            f'A = "{"/" + "Users/jdoe_real/repo"}"',
            f'B = "{"mycorp." + "atlassian.net"}"',
            f'C = "{"corp-" + "data-987654:ds.t"}"',
            f'D = "{"alice@" + "corp-internal.local"}"',
            f'E = "{"hooks/" + "governance" + "_guard.py"}"',
        ]) + "\n",
        encoding="utf-8",
    )
    issues = replay_benchmark.check_release_hygiene(dirty_root)
    joined = "\n".join(issues)
    assert "docs/" in joined
    assert "home-directory" in joined
    assert "Atlassian" in joined
    assert ".local" in joined
    assert "GCP-style" in joined
    assert "removed private domain" in joined

    bad_bundle = {
        "stats": {"file": "private_policy_stats.json", "receipts_path": "/tmp/receipts.jsonl", "workspace_id": "ws_1", "spool_id": "sp_1", "session_id": "s1"},
        "note": "shadow.json",
    }
    bundle_issues = replay_benchmark.check_release_hygiene(clean_root, public_bundle=bad_bundle)
    for needle in ("private_policy_stats.json", "shadow.json", "receipts.jsonl", "receipts_path", "workspace_id", "spool_id", "session_id"):
        assert any(needle in i for i in bundle_issues)


def test_git_history_secrets_clean_on_repo_and_flags_synthetic_commit(tmp_path: Path) -> None:
    assert replay_benchmark.check_git_history_secrets() == []

    repo = tmp_path / "sec_repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "dev@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Dev"], check=True)
    (repo / "clean.txt").write_text("ok = true\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "clean.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "init"], check=True)
    assert replay_benchmark.check_git_history_secrets(repo) == []

    fake_google = "AIza" + "SyA1234567890abcdefghijklmnopqr"
    fake_gh = "ghp_" + "AbCdEf123456789012345678"
    (repo / "secret.txt").write_text(f"K1={fake_google}\nK2={fake_gh}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "secret.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "add secret"], check=True)
    found = replay_benchmark.check_git_history_secrets(repo)
    assert any("google_api_key" in item for item in found)
    assert any("github_token" in item for item in found)


def test_doctor_security_drift_rendering_and_resilience(monkeypatch: Any, tmp_path: Path) -> None:
    def _fake_drift(**_kwargs: Any) -> dict[str, Any]:
        return {
            "security_active": True,
            "ok": False,
            "drift_codes": ["NATIVE_FAIL_CLOSED_DRIFT"],
            "claude": {"degraded_older_cli": True},
            "cursor": {"fail_closed": False},
            "codex": {"trust_warning": True},
            "remediation": "re-run install_harnesses.py",
        }

    monkeypatch.setattr(config, "inspect_native_security_drift", _fake_drift, raising=False)
    report = cg_status.run_doctor(
        plugin_root=tmp_path,
        claude_settings_path=tmp_path / "claude.json",
        cursor_hooks_path=tmp_path / "cursor.json",
        codex_hooks_path=tmp_path / "codex.json",
    )
    assert "security_drift" in report
    assert report["security_drift"]["drift_codes"] == ["NATIVE_FAIL_CLOSED_DRIFT"]
    md = cg_status.render_doctor_report(report)
    assert "Native security sync" in md
    assert "NATIVE_FAIL_CLOSED_DRIFT" in md
    assert "degraded Claude < 2.1.295" in md
    assert "#27833" in md

    def _timeout_drift(**_kwargs: Any) -> dict[str, Any]:
        raise subprocess.TimeoutExpired(["claude"], 2)

    monkeypatch.setattr(config, "inspect_native_security_drift", _timeout_drift, raising=False)
    resilient = cg_status.run_doctor(plugin_root=tmp_path)
    assert "security_drift" in resilient
    assert "error" in resilient["security_drift"]


def test_doctor_reports_spool_health_and_hook_mismatch(monkeypatch: Any, tmp_path: Path) -> None:
    from bin.harness_status import CLAUDE_POST_SPOOL_MATCHER, CLAUDE_POST_SYNC_MATCHER

    plugin_root = tmp_path / "plugin"
    (plugin_root / "hooks").mkdir(parents=True)
    (plugin_root / "plugin.json").write_text("{}", encoding="utf-8")
    (plugin_root / "hooks.json").write_text("{}", encoding="utf-8")
    pre_hook = plugin_root / "hooks" / "pre_tool_use.py"
    post_hook = plugin_root / "hooks" / "post_tool_use.py"
    pre_hook.write_text("", encoding="utf-8")
    post_hook.write_text("", encoding="utf-8")

    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"optimizers": {"output_spool": "active"}}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    config.clear_config_cache()

    spool_dir = tmp_path / "spool"
    spool_store.build_post_tool_spool_response(
        "claude", {"tool_name": "Bash", "tool_input": {"command": "pytest"}, "tool_response": {"stdout": "\n".join(f"line {i}: " + ("x" * 70) for i in range(240))}, "cwd": str(tmp_path)},
        mode="active", session_id="s-doc", call_id="c-1", spool_dir=spool_dir,
    )
    (spool_dir / "sp_deadbeefcafe.txt").write_text("orphan\n", encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))

    claude_cfg = tmp_path / "claude.json"
    claude_cfg.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": f"python3 {pre_hook}"}]}]}}), encoding="utf-8")
    report = cg_status.run_doctor(
        plugin_root=plugin_root, claude_settings_path=claude_cfg,
        cursor_hooks_path=tmp_path / "cu.json", codex_hooks_path=tmp_path / "cx.json",
    )
    assert report["output_spool_mode"] == "active"
    assert report["harness_details"]["claude"]["spool_hook_ok"] is False
    assert report["spool_health"]["entry_count"] == 1
    assert report["spool_health"]["orphan_count"] == 1
    md = cg_status.render_doctor_report(report)
    assert "spool post-hook mismatch" in md and "Output spool" in md and "WARN" in md

    claude_cfg.write_text(json.dumps({"hooks": {
        "PreToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": f"python3 {pre_hook}"}]}],
        "PostToolUse": [
            {"matcher": CLAUDE_POST_SYNC_MATCHER, "hooks": [{"type": "command", "command": f"python3 {post_hook}"}]},
            {"matcher": CLAUDE_POST_SPOOL_MATCHER, "hooks": [{"type": "command", "command": f"python3 {post_hook}", "timeout": 10}]},
        ],
    }}), encoding="utf-8")
    ok_report = cg_status.run_doctor(
        plugin_root=plugin_root, claude_settings_path=claude_cfg,
        cursor_hooks_path=tmp_path / "cu.json", codex_hooks_path=tmp_path / "cx.json",
    )
    assert ok_report["harness_details"]["claude"]["spool_hook_ok"] is True


def test_doctor_warns_on_reliability_failures_and_outcomes_receipt_scoping(
    monkeypatch: Any, tmp_path: Path, capsys: Any,
) -> None:
    from spool import receipts as spool_receipts

    spool_dir = tmp_path / "spool_doc"
    monkeypatch.setenv("CONTEXT_GUARD_SPOOL_DIR", str(spool_dir))
    rcpt_path = spool_dir / "receipts.jsonl"
    spool_receipts.append_receipt(
        spool_receipts.build_receipt(
            event_type="spool_integrity_failure", harness="cli", session_id="s1",
            workspace_id="ws_0123456789abcdef", turn_key="", call_id="", spool_id="sp_0123456789ab",
            line_span=(0, 0), byte_span=(0, 10), delivery_evidence="unverified", spool_id_referenced=True,
            failure_kind="reliability_failure", reason="integrity_mismatch",
        ),
        receipts_path=rcpt_path,
    )
    cursor_mcp = tmp_path / "cursor_mcp.json"
    cursor_mcp.write_text(json.dumps({"mcpServers": {"context-guard-spool": {"command": "python3", "args": ["bin/cg_spool.py", "mcp"]}}}), encoding="utf-8")

    doc = cg_status.run_doctor(
        plugin_root=tmp_path, claude_settings_path=tmp_path / "cl.json",
        cursor_hooks_path=tmp_path / "cu.json", codex_hooks_path=tmp_path / "cx.json",
        cursor_mcp_path=cursor_mcp,
    )
    assert doc["spool_health"]["reliability_failures"] == 1
    assert doc["harness_details"]["cursor"]["cursor_mcp_stale"] is True
    md = cg_status.render_doctor_report(doc)
    assert "| Output spool | `WARN` |" in md
    assert "missing --workspace" in md

    # Custom --outcomes-path omits default spool receipts; default --outcomes includes them BEFORE _Schema: v4_
    custom_out = tmp_path / "custom_outcomes.json"
    custom_out.write_text(json.dumps({"schema_version": 4, "updated_at": "2026-11-16T00:00:00Z", "by_key": {}}), encoding="utf-8")
    assert cg_status.main(["--outcomes", "--outcomes-path", str(custom_out)]) == 0
    out_custom = capsys.readouterr().out
    assert "Spool Receipts & Integrity" not in out_custom
    assert out_custom.splitlines()[-1].startswith("_Schema: v4")

    assert cg_status.main(["--outcomes"]) == 0
    out_default = capsys.readouterr().out
    assert "Spool Receipts & Integrity" in out_default
    assert out_default.splitlines()[-1].startswith("_Schema: v4")


def test_compute_latency_percentiles_monotonic_and_benchmark_includes_p50_p95_p99() -> None:
    empty = replay_benchmark.compute_latency_percentiles([])
    assert empty == {
        "count": 0, "min_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0,
        "p99_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0,
    }

    single = replay_benchmark.compute_latency_percentiles([4.25])
    assert single["count"] == 1
    assert single["min_ms"] == single["p50_ms"] == single["p95_ms"] == single["p99_ms"] == single["max_ms"] == 4.25
    assert single["mean_ms"] == 4.25

    raw_samples = [12.5, 1.2, 3.4, 8.9, 45.0, 2.1, 5.6, 9.8, 15.3, 100.0]
    pct = replay_benchmark.compute_latency_percentiles(raw_samples)
    assert raw_samples[0] == 12.5
    assert pct["count"] == 10
    assert pct["min_ms"] == 1.2
    assert pct["max_ms"] == 100.0
    assert 0.0 <= pct["min_ms"] <= pct["p50_ms"] <= pct["p95_ms"] <= pct["p99_ms"] <= pct["max_ms"]

    bench = replay_benchmark.run_deterministic_benchmark(iterations=2)
    assert bench["ok"] is True
    for key in ("in_process_latency_ms", "subprocess_latency_ms"):
        lat = bench[key]
        assert lat["count"] >= 1
        assert 0.0 <= lat["min_ms"] <= lat["p50_ms"] <= lat["p95_ms"] <= lat["p99_ms"] <= lat["max_ms"]
    assert bench["backend_evaluation"]["migration_performed"] is False
    assert bench["backend_evaluation"]["read_ledger_schema"] == 2

    md = replay_benchmark.render_benchmark_report(bench)
    assert "In-process warm p50 / p95 / p99" in md
    assert "Read Ledger backend decision" in md
    assert "json_lock (schema v2, migration=False)" in md


def test_backend_storage_benchmark_skips_alternatives_until_limits_exposed_and_never_migrates(tmp_path: Path) -> None:
    calm = replay_benchmark.run_backend_storage_benchmark(
        operations=12, force_compare=False, p95_budget_ms=5000.0, p99_budget_ms=5000.0,
    )
    assert calm["schema_version"] == 1
    assert calm["ok"] is True
    assert calm["active_backend"] == "json_lock"
    assert calm["read_ledger_schema"] == 2
    assert calm["operations"] == 12
    assert calm["limits_exposed"] is False
    assert calm["alternatives_evaluated"] is False
    assert calm["alternatives"] == {}
    assert calm["migration_performed"] is False
    assert calm["decision"] == "retain_json_lock"
    jl = calm["json_lock"]
    assert jl["count"] == 12
    assert 0.0 <= jl["min_ms"] <= jl["p50_ms"] <= jl["p95_ms"] <= jl["p99_ms"] <= jl["max_ms"]

    forced = replay_benchmark.run_backend_storage_benchmark(
        operations=18, force_compare=True, p95_budget_ms=5000.0, p99_budget_ms=5000.0,
    )
    assert forced["ok"] is True
    assert forced["limits_exposed"] is False
    assert forced["alternatives_evaluated"] is True
    assert forced["migration_performed"] is False
    assert forced["read_ledger_schema"] == 2
    assert forced["decision"] == "retain_json_lock"
    assert set(forced["alternatives"]) == {"sqlite_wal", "segmented_jsonl"}
    assert forced["alternatives"]["segmented_jsonl"]["compactions"] >= 1
    for alt in forced["alternatives"].values():
        assert alt["count"] == 18
        assert 0.0 <= alt["min_ms"] <= alt["p50_ms"] <= alt["p95_ms"] <= alt["p99_ms"] <= alt["max_ms"]

    exposed = replay_benchmark.run_backend_storage_benchmark(
        operations=10, force_compare=False, p95_budget_ms=-1.0, p99_budget_ms=5000.0,
    )
    assert exposed["ok"] is True
    assert exposed["limits_exposed"] is True
    assert exposed["alternatives_evaluated"] is True
    assert exposed["migration_performed"] is False
    assert exposed["read_ledger_schema"] == 2
    assert exposed["decision"] == "evaluate_migration_proposal"
    assert set(exposed["alternatives"]) == {"sqlite_wal", "segmented_jsonl"}
    assert list(tmp_path.iterdir()) == []

