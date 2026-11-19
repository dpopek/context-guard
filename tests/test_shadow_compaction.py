"""Hardening tests for shadow ledger compaction, LRU isolation, telemetry_core, and state_store."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from hooks import file_io, json_outliners, pre_compact, state_store, telemetry, telemetry_core


def test_pre_compact_survives_corrupt_shadow_field_types_and_preserves_global_shadow_spools(
    tmp_path: Path,
) -> None:
    sd = tmp_path / "state"
    sd.mkdir()
    sp = telemetry.shadow_path_for(sd)
    assert sp is not None

    ph_a = telemetry.pseudonymize_shadow_path("/repo/a.py")
    ph_b = telemetry.pseudonymize_shadow_path("/repo/b.py")
    now = time.time()
    corrupt_doc = {
        "schema_version": telemetry.SHADOW_SCHEMA_VERSION,
        "updated_at": "2026-11-19T00:00:00+00:00",
        "sessions": {
            "sess-A": {
                "updated_ts": now,
                "max_step": "bad-step",
                "checkpoint_step": None,
                "paths": {
                    ph_a: {
                        "content_sha256": 999,
                        "updated_ts": "not-a-float",
                        "reads": ["garbage", [1, "bad", 2, 2], [1, 20, 3, 2]],
                    },
                    "broken_entry": "not-a-dict",
                },
            },
            "sess-bad-ts": {
                "updated_ts": "not-a-float",
                "max_step": True,
                "checkpoint_step": "nope",
                "paths": "not-a-dict",
            },
            "sess-B": {
                "updated_ts": now,
                "max_step": 4,
                "checkpoint_step": 0,
                "paths": {
                    ph_b: {
                        "content_sha256": "sha-b",
                        "updated_ts": now,
                        "reads": [[1, 30, 4, 2]],
                    }
                },
            },
        },
        "shadow_spools": {
            "count": 5,
            "estimated_saved_bytes": 12345,
            "last_ts": "2026-11-19T00:00:00+00:00",
            "by_harness": {"claude": 5},
        },
    }
    sp.write_text(json.dumps(corrupt_doc), encoding="utf-8")

    # PreCompact on sess-A survives corrupt types, clears only sess-A paths, and preserves shadow_spools & sess-B.
    assert pre_compact.handle_pre_compact({"session_id": "sess-A"}, state_dir=str(sd)) == {}
    after = telemetry.load_shadow_ledger(sp, now_ts=now)
    assert after["sessions"]["sess-A"]["paths"] == {}
    assert after["sessions"]["sess-B"]["paths"][ph_b]["reads"] == [[1, 30, 4, 2]]
    assert after["shadow_spools"] == {
        "count": 5,
        "estimated_saved_bytes": 12345,
        "last_ts": "2026-11-19T00:00:00+00:00",
        "by_harness": {"claude": 5},
    }

    # Global compaction (session_id=None) resets shadow_spools cleanly.
    assert telemetry.invalidate_shadow_ledger(full_compact=True, shadow_path=sp, now_ts=now) is True
    after_global = telemetry.load_shadow_ledger(sp, now_ts=now)
    assert after_global["shadow_spools"] == {
        "count": 0,
        "estimated_saved_bytes": 0,
        "last_ts": None,
        "by_harness": {},
    }


def test_shadow_read_tier_zero_does_not_pollute_lru_slots(tmp_path: Path) -> None:
    sp = tmp_path / "shadow.json"
    # Cold session with achievable_tier < min_tier does not create ledger or session slot.
    assert (
        telemetry.record_shadow_read(
            "sess-cold",
            str(tmp_path / "cold.py"),
            1,
            40,
            1,
            0,
            "sha-cold",
            min_tier=2,
            shadow_path=sp,
            now_ts=1_000.0,
        )
        is False
    )
    assert not sp.exists()

    # Fill 200 LRU path slots in sess-lru.
    for idx in range(telemetry.SHADOW_MAX_PATHS):
        p = tmp_path / f"mod_{idx:03d}.py"
        assert (
            telemetry.record_shadow_read(
                "sess-lru",
                str(p),
                1,
                20,
                idx + 1,
                2,
                f"sha-{idx}",
                min_tier=2,
                shadow_path=sp,
                now_ts=2_000.0 + idx,
            )
            is True
        )

    # Low-tier reads (0 and 1 < min_tier=2) must return False and never evict or insert into LRU.
    low_p = tmp_path / "low_tier.py"
    low_hash = telemetry.pseudonymize_shadow_path(os.path.realpath(str(low_p)))
    assert (
        telemetry.record_shadow_read(
            "sess-lru",
            str(low_p),
            1,
            20,
            500,
            0,
            "sha-low",
            min_tier=2,
            shadow_path=sp,
            now_ts=3_000.0,
        )
        is False
    )
    assert (
        telemetry.record_shadow_read(
            "sess-lru",
            str(low_p),
            1,
            20,
            501,
            1,
            "sha-low",
            min_tier=2,
            shadow_path=sp,
            now_ts=3_001.0,
        )
        is False
    )
    loaded = telemetry.load_shadow_ledger(sp, now_ts=3_001.0)
    paths = loaded["sessions"]["sess-lru"]["paths"]
    assert len(paths) == telemetry.SHADOW_MAX_PATHS
    assert low_hash not in paths
    assert telemetry.pseudonymize_shadow_path(os.path.realpath(str(tmp_path / "mod_000.py"))) in paths


def test_shadow_read_merges_and_caps_intervals_at_64_and_telemetry_warns_on_oserror(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sp = tmp_path / "shadow_cap.json"
    target = tmp_path / "many_slices.py"
    target.write_text("x = 1\n", encoding="utf-8")
    for idx in range(70):
        start = idx * 10 + 1
        end = start + 3  # Non-adjacent disjoint intervals
        assert (
            telemetry.record_shadow_read(
                "sess-cap",
                str(target),
                start,
                end,
                idx + 1,
                2,
                "sha-many",
                min_tier=2,
                shadow_path=sp,
                now_ts=1_000.0 + idx,
            )
            is True
        )
    ph = telemetry.pseudonymize_shadow_path(os.path.realpath(str(target)))
    reads = telemetry.load_shadow_ledger(sp, now_ts=2_000.0)["sessions"]["sess-cap"]["paths"][ph]["reads"]
    assert len(reads) == telemetry.SHADOW_MAX_READS_PER_PATH == 64

    # _update_ledger emits warn() on OSError rather than failing silently.
    stats_blocker = tmp_path / "file_not_dir"
    stats_blocker.write_text("x", encoding="utf-8")
    telemetry.record_reliability_failure(stats_blocker / "stats.json")
    assert "telemetry ledger update failed" in capsys.readouterr().err


def test_telemetry_core_unknown_events_and_bounded_outline_baseline(tmp_path: Path) -> None:
    norm = telemetry_core.normalise_stats(
        {
            "events": {"outlines": 3, "custom_pack_blocks": 9, "bad_val": "x"},
            "baseline_bytes": 1000,
            "saved_bytes": 500,
        },
        now_str="2026-11-19T00:00:00+00:00",
    )
    assert norm["events"]["outlines"] == 3
    assert norm["events"]["custom_pack_blocks"] == 9
    assert norm["events"]["bad_val"] == 0

    big = tmp_path / "big.jsonl"
    lines = [f'{{"idx": {i}, "payload": "' + ("z" * 100) + '"}' for i in range(100)]
    big.write_text("\n".join(lines) + "\n", encoding="utf-8")
    stats = tmp_path / "stats.json"
    expected_slice = telemetry.measure_slice_bytes(str(big), 10, 34)
    assert expected_slice is not None and expected_slice < big.stat().st_size

    credit = telemetry.record_file_read_outcome(
        "claude",
        str(big),
        10,
        34,
        {"decision": "deny", "reason": "outline"},
        "outline",
        stats_path=stats,
    )
    assert credit.baseline_bytes == expected_slice
    assert telemetry.load_telemetry_stats(stats)["baseline_bytes"] == expected_slice


def test_state_store_persistence_error_readonly_snapshot_and_contract_delegations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert file_io.warn is state_store.warn is telemetry.warn
    assert not hasattr(json_outliners, "unwrap_and_outline_mcp_step_output")

    sd = tmp_path / "state_err"
    sd.mkdir()

    def _fail_replace(_src: str | os.PathLike[str], _dst: str | os.PathLike[str]) -> None:
        raise OSError("simulated atomic replace failure")

    with monkeypatch.context() as mp:
        mp.setattr(os, "replace", _fail_replace)
        with pytest.raises(state_store.StatePersistenceError):
            with state_store.locked_state(sd) as txn:
                txn.state["x"] = 1
                txn.dirty = True
    capsys.readouterr()

    # Read-only state_dir with existing state file (no .lock file) falls back cleanly with warn().
    ro_nolock = tmp_path / "ro_nolock"
    ro_nolock.mkdir()
    sf1 = state_store.state_file_in(ro_nolock)
    sf1.write_text(json.dumps({"read_ledger_schema": 2, "files": {"/a.py": {"reads": [[1, 5, 1, 2]]}}}), encoding="utf-8")
    ro_nolock.chmod(0o555)
    try:
        snap = state_store.read_state_snapshot(ro_nolock)
        assert "/a.py" in snap["files"]
        if sys.platform != "win32" and os.geteuid() != 0:
            assert "read_state_snapshot unlocked fallback" in capsys.readouterr().err
    finally:
        ro_nolock.chmod(0o755)

    # Read-only state_dir with existing .lock file acquires LOCK_SH cleanly.
    ro_with_lock = tmp_path / "ro_with_lock"
    ro_with_lock.mkdir()
    with state_store.locked_state(ro_with_lock) as txn:
        txn.state["files"]["/b.py"] = {"sha256": "x", "reads": [[1, 10, 1, 2]]}
        txn.dirty = True
    ro_with_lock.chmod(0o555)
    try:
        snap2 = state_store.read_state_snapshot(ro_with_lock)
        assert "/b.py" in snap2["files"]
    finally:
        ro_with_lock.chmod(0o755)


def test_replay_benchmark_aggregates_schema_v4_outcomes_totals() -> None:
    from services.replay_benchmark import build_public_json_bundle

    v4_outcomes = {
        "schema_version": 4,
        "policy_packs": ["/Users/alice/private-pack"],
        "by_key": {
            "claude|claude-sonnet-4-6|outline": {
                "total": 5,
                "applied": 4,
                "recovery": {"targeted": 3, "full": 1},
                "regret": {"suspected": 1, "confirmed": 0, "unknown": 3},
                "evidence": {"heuristic": 4},
            },
            "cursor|gpt-5|output_spool": {
                "total": 3,
                "applied": 3,
                "recovery": {"targeted": 2, "none": 1, "pending_or_unknown": 2},
                "regret": {"suspected": 0, "confirmed": 1, "unknown": 2},
                "evidence": {"observed": 2, "heuristic": 1},
            },
            "ignored-non-mapping": "corrupt",
        },
    }
    bundle = build_public_json_bundle({"saved_bytes": 1200}, {"totals": {}}, v4_outcomes)
    assert bundle["outcomes"]["schema_version"] == 4
    totals = bundle["outcomes"]["totals"]
    assert totals["interventions"] == 8
    assert totals["applied"] == 7
    assert totals["recovery"]["targeted"] == 5
    assert totals["recovery"]["full"] == 1
    assert totals["recovery"]["none"] == 1
    assert totals["recovery"]["pending_or_unknown"] == 2
    assert totals["regret"]["suspected"] == 1
    assert totals["regret"]["confirmed"] == 1
    assert totals["regret"]["unknown"] == 5
    assert totals["evidence"]["heuristic"] == 5
    assert totals["evidence"]["observed"] == 2
    dumped = json.dumps(bundle)
    assert "private-pack" not in dumped and "policy_packs" not in dumped

    legacy_bundle = build_public_json_bundle({}, {}, {"schema_version": 3, "totals": {"interventions": 2}})
    assert legacy_bundle["outcomes"]["totals"] == {"interventions": 2}


def test_default_install_uses_rollback_journal_and_honors_config_env_and_exit_codes(
    isolated_user_env: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from bin import install_harnesses
    from hooks import config as hooks_config
    from services import installer_service

    # 1. bin/install_harnesses.main honors CONTEXT_GUARD_CONFIG_PATH for preflight checks.
    bad_cfg = tmp_path / "env-config.json"
    bad_cfg.write_text("{corrupt-json", encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(bad_cfg))
    hooks_config.clear_config_cache()
    assert install_harnesses.main(["--install"]) == 2
    assert "error:" in capsys.readouterr().err
    bad_cfg.write_text('{"read_confirm_policy": "bounded"}\n', encoding="utf-8")
    hooks_config.clear_config_cache()

    # 2. Default install_all (pack_source=None) uses RollbackJournal and cleans .staging-* on failure.
    claude_cfg = tmp_path / "claude" / "settings.json"
    cursor_cfg = tmp_path / "cursor" / "hooks.json"
    codex_cfg = tmp_path / "codex" / "hooks.json"
    codex_toml = tmp_path / "codex" / "config.toml"
    ext_dir = tmp_path / "cursor-exts"
    ext_dir.mkdir(parents=True)
    orig_texts = {
        claude_cfg: '{"model": "keep"}\n',
        cursor_cfg: '{"version": 1, "hooks": {}}\n',
        codex_cfg: '{"hooks": {}}\n',
        codex_toml: 'model = "gpt-5"\n',
    }
    for path, content in orig_texts.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    plugin_root = Path(__file__).resolve().parent.parent
    monkeypatch.setattr(
        installer_service,
        "install_outline_pull",
        lambda *_a, **_kw: (_ for _ in ()).throw(OSError("simulated late write failure")),
    )
    with pytest.raises(OSError, match="simulated late write failure"):
        installer_service.install_all(
            plugin_root=plugin_root,
            claude_settings_path=claude_cfg,
            cursor_hooks_path=cursor_cfg,
            codex_hooks_path=codex_cfg,
            codex_config_path=codex_toml,
            cursor_extensions_dir=ext_dir,
        )
    for path, content in orig_texts.items():
        assert path.read_text(encoding="utf-8") == content
    assert list(ext_dir.glob(".staging-*")) == []
    assert list(ext_dir.glob(".rollback-*")) == []

    # 3. bin/install_harnesses.main exits 1 when any status begins with "error" or install_all raises.
    fake_root = tmp_path / "fake-plugin-root"
    fake_root.mkdir()
    monkeypatch.setattr(install_harnesses, "DEFAULT_PLUGIN_ROOT", fake_root)
    monkeypatch.setattr(
        install_harnesses,
        "install_all",
        lambda dry_run=False: {"claude": "updated", "cursor": "error (invalid json)"},
    )
    assert install_harnesses.main(["--install"]) == 1
    assert '"error (invalid json)"' in capsys.readouterr().out
    assert not (fake_root / "telemetry" / "install.json").exists()

    monkeypatch.setattr(
        install_harnesses,
        "install_all",
        lambda dry_run=False: (_ for _ in ()).throw(OSError("simulated boom")),
    )
    assert install_harnesses.main(["--install"]) == 1
    assert "error: simulated boom" in capsys.readouterr().err


def test_evidence_ledger_static_capability_ceiling_blocks_runtime_verified_upgrade() -> None:
    from evidence.ledger import (
        build_capability_attestation_key,
        collect_environment_metadata,
        compute_hook_config_fingerprint,
        resolve_capability_requirement,
    )

    fp = compute_hook_config_fingerprint("codex", {"optimizers": {"output_spool": "active"}})
    unsupported_pairs = (
        ("codex", "output_replacement"),
        ("codex", "content_verified_reads"),
        ("cursor", "output_replacement"),
        ("cursor", "prompt_cache_telemetry"),
        ("antigravity", "content_verified_reads"),
        ("antigravity", "native_fail_closed"),
        ("unknown_cli", "pre_tool_interception"),
    )
    for harness_id, capability_id in unsupported_pairs:
        key = build_capability_attestation_key(harness_id, capability_id, hook_config_fingerprint=fp)
        capped = resolve_capability_requirement(
            key,
            claimed_level="runtime_verified",
            runtime_probe_passed=True,
            verification_evidence="prose_probe_verified:/Users/alice/probe.log",
        )
        assert capped["evidence_level"] == "unsupported"
        assert capped["runtime_verified"] is False
        assert "alice" not in capped["verification_source"]

        exposed_claim = resolve_capability_requirement(
            key,
            claimed_level="harness_exposed",
            runtime_probe_passed=False,
            verification_evidence="prose_evidence",
        )
        assert exposed_claim["evidence_level"] == "unsupported"
        assert exposed_claim["runtime_verified"] is False

    env_meta = collect_environment_metadata(
        "codex",
        model_id="gpt-5",
        runtime_verifications={
            "output_replacement": "prose_claim_should_not_promote",
            "pre_tool_interception": "pre_tool_probe_ok",
        },
    )
    by_cap = {cap["capability_id"]: cap for cap in env_meta["required_capabilities"]}
    assert by_cap["output_replacement"]["evidence_level"] == "unsupported"
    assert by_cap["output_replacement"]["runtime_verified"] is False
    assert by_cap["pre_tool_interception"]["evidence_level"] == "runtime_verified"
    assert by_cap["pre_tool_interception"]["runtime_verified"] is True

    claude_key = build_capability_attestation_key("claude", "output_replacement", hook_config_fingerprint=fp)
    promoted = resolve_capability_requirement(
        claude_key,
        claimed_level="runtime_verified",
        runtime_probe_passed=True,
        verification_evidence="spool_probe_verified",
    )
    assert promoted["evidence_level"] == "runtime_verified"
    assert promoted["runtime_verified"] is True


def test_isolated_campaign_clears_config_cache_on_env_mutation(tmp_path: Path) -> None:
    from typing import Any, Mapping
    from evidence.runner import execute_isolated_campaign, plan_isolated_campaign
    from hooks import config as hooks_config

    hooks_config.clear_config_cache()
    plan = plan_isolated_campaign(
        "small_live_pilot",
        harness_id="claude",
        model_id="claude-sonnet-4-6",
        harness_build_id="2.1.300",
        task_count=1,
        repeats=1,
    )
    observed_policies: list[str] = []

    def _executor(spec: Mapping[str, Any], _run_ws: Path) -> Mapping[str, Any]:
        cfg_file = Path(os.environ["CONTEXT_GUARD_CONFIG_PATH"])
        policy = "bounded" if spec["arm"] == "context_guard" else "strict"
        cfg_file.write_text(json.dumps({"read_confirm_policy": policy}), encoding="utf-8")
        observed_policies.append(hooks_config.load_runtime_config()["read_confirm_policy"])
        return {"outcome_class": "passed", "passed": True, "turns": 1, "cost_usd": 0.01}

    execute_isolated_campaign(plan, _executor, workspace_parent=tmp_path / "campaigns", bootstrap_iters=200)
    assert observed_policies == ["strict", "bounded"]
