"""Tests for deterministic replay, benchmark, public-JSON scrubber, release hygiene, secret scanner, and doctor sync."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from bin import cg_status, replay_benchmark
from hooks import config


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
    assert by_mode["bounded"]["bytes_saved"] > 0

    rc = cg_status.main(["--replay"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Context-Guard Deterministic Replay" in out
    assert "`bounded`" in out


def test_benchmark_measures_isolated_latency_and_savings(capsys: Any) -> None:
    bench = replay_benchmark.run_deterministic_benchmark(iterations=2)
    assert bench["ok"] is True
    assert bench["isolated"] is True
    assert bench["cold_ms"] >= 0.0
    assert bench["warm_ms"] >= 0.0
    assert bench["saved_bytes"] > 0
    assert bench["saved_tokens"] > 0
    assert bench["savings_pct"] > 0.0

    rc = cg_status.main(["--benchmark"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Context-Guard Deterministic Benchmark" in out
    assert "Bytes saved" in out


def test_public_json_scrubs_sensitive_paths_and_files(tmp_path: Path, capsys: Any) -> None:
    home_posix = "/" + "Users/jdoe_real/workspace/proj"
    home_win = "C:\\" + "Users\\jdoe_real\\secret.txt"
    priv_dom = "mycorp." + "atlassian.net"
    gcp_id = "corp-" + "data-987654:ds.t"
    local_mail = "alice@" + "corp-internal.local"
    raw_stats = {
        "saved_bytes": 1200,
        "saved_tokens": 300,
        "shadow_path": str(tmp_path / "shadow.json"),
        "private_policy_stats": {"hits": 9},
        "config_path": home_posix + "/config.json",
        "notes": ["shadow.json", "private_policy_stats.json", f"read {home_posix}"],
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

    bundle = replay_benchmark.build_public_json_bundle(raw_stats, raw_usage, raw_outcomes, raw_update)
    dumped = json.dumps(bundle)
    assert bundle["public"] is True
    assert bundle["stats"]["saved_tokens"] == 300
    assert bundle["outcomes"]["schema_version"] == 4
    for secret_key in ("shadow.json", "private_policy_stats.json", "config_path", "transcript_path", "policy_packs", "jdoe_real", priv_dom, gcp_id, local_mail):
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

    bad_bundle = {"stats": {"file": "private_policy_stats.json"}, "note": "shadow.json"}
    bundle_issues = replay_benchmark.check_release_hygiene(clean_root, public_bundle=bad_bundle)
    assert any("private_policy_stats.json" in i for i in bundle_issues)
    assert any("shadow.json" in i for i in bundle_issues)


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
