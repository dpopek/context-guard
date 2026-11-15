"""Tests for migration preflight checks, staged pack transactions, and rollback journal."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from bin.migration_guard import RollbackJournal, StagedPackTransaction, preflight_migration_check
from hooks.config import REQUIRED_CONFIG_KEYS
from hooks.policy_engine import PolicyPackLoadError
from policies.api import ALL_SECURITY_SCOPES


def _chmod_if_posix(path: Path, mode: int) -> None:
    if os.name != "nt":
        os.chmod(path, mode)


def _make_pack(
    pack_root: Path,
    *,
    pack_id: str = "sample-security",
    kind: str = "security",
    domains: tuple[str, ...] = ("governance_guard", "local_repo_guard", "bigquery_guard"),
    scopes: tuple[str, ...] = ALL_SECURITY_SCOPES,
    extra_files: dict[str, str] | None = None,
    inspect_body: str | None = None,
    api_version: int = 1,
    broken_syntax: bool = False,
    include_artifacts: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """Create a valid or broken synthetic policy pack tree and manifest entry."""
    pack_root.mkdir(parents=True, exist_ok=True)
    _chmod_if_posix(pack_root, 0o700)
    if broken_syntax:
        pack_src = "def broken(:\n"
    else:
        inspect_src = inspect_body or "def inspect_cfg(settings):\n    return []\n"
        pack_src = (
            "from policies.api import PolicyDecision, PolicyPackManifest\n"
            f"PACK_ID = {pack_id!r}\n"
            f"{inspect_src}\n"
            "def eval_fn(ctx):\n"
            "    return PolicyDecision(decision='allow')\n"
            "PACK_MANIFEST = PolicyPackManifest(\n"
            f"    pack_id={pack_id!r}, api_version={api_version},\n"
            f"    kind={kind!r}, covered_domains={domains!r},\n"
            "    evaluate=eval_fn, inspect_config=inspect_cfg,\n"
            ")\n"
        )
    files: dict[str, str] = {"pack.py": pack_src, **(extra_files or {})}
    file_hashes: dict[str, str] = {}
    for rel, content in sorted(files.items()):
        target = pack_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        _chmod_if_posix(target.parent, 0o700)
        target.write_text(content, encoding="utf-8")
        _chmod_if_posix(target, 0o600)
        file_hashes[rel] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if include_artifacts:
        (pack_root / "__pycache__").mkdir(exist_ok=True)
        (pack_root / "__pycache__" / "pack.cpython-39.pyc").write_bytes(b"pyc-bytes")
        (pack_root / ".hidden").mkdir(exist_ok=True)
        (pack_root / ".hidden" / "secret.py").write_text("X = 1\n", encoding="utf-8")
        (pack_root / "notes.txt").write_text("not python", encoding="utf-8")
    tree_sha = hashlib.sha256("".join(f"{k}:{file_hashes[k]}\n" for k in sorted(file_hashes)).encode("utf-8")).hexdigest()
    entry: dict[str, Any] = {
        "id": pack_id,
        "path": str(pack_root / "pack.py"),
        "enabled": True,
        "kind": kind,
        "file_hashes": file_hashes,
        "tree_sha256": tree_sha,
        "settings": {},
    }
    if kind == "security":
        entry["scopes"] = list(scopes)
    return pack_root, entry


def test_preflight_pure_no_writes_or_warnings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """preflight_migration_check performs zero disk writes and zero stderr output."""
    cfg_path = tmp_path / ".config" / "context-guard" / "config.json"
    pack_root, entry = _make_pack(cfg_path.parent / "policies" / "sample-security")
    raw_cfg: dict[str, Any] = {
        "enforce_governance_policy": True,
        "restricted_bq_datasets": ["raw_events"],
        "allowed_bq_views_dataset": "ai_views",
        "policy_packs": [entry],
    }
    errors, warnings = preflight_migration_check(raw_cfg, config_path=cfg_path)
    assert errors == []
    assert warnings == []
    assert not cfg_path.exists()
    captured = capsys.readouterr()
    assert captured.err == "" and captured.out == ""
    assert pack_root.exists()


def test_preflight_rejects_unmigrated_and_partial_legacy_security_keys(tmp_path: Path) -> None:
    """Legacy security keys fail unless covered by active verified security packs."""
    cfg_path = tmp_path / "cfg" / "config.json"
    base_cfg: dict[str, Any] = {
        "restricted_bq_datasets": ["raw_sales"],
        "allowed_bq_views_dataset": "ai_views",
        "enforce_governance_policy": True,
        "policy_packs": [],
    }
    errors, warnings = preflight_migration_check(base_cfg, config_path=cfg_path)
    assert warnings == []
    assert len(errors) == 3
    assert any("restricted_bq_datasets" in e for e in errors)
    assert any("allowed_bq_views_dataset" in e for e in errors)
    assert any("enforce_governance_policy" in e for e in errors)

    _, gov_only = _make_pack(
        cfg_path.parent / "policies" / "gov-only",
        pack_id="gov-only",
        domains=("governance_guard",),
    )
    partial_errors, _ = preflight_migration_check({**base_cfg, "policy_packs": [gov_only]}, config_path=cfg_path)
    assert len(partial_errors) == 2
    assert not any("enforce_governance_policy" in e for e in partial_errors)
    assert any("restricted_bq_datasets" in e for e in partial_errors)


def test_preflight_warns_repo_map_and_workspace_map_without_gitlab_pack(tmp_path: Path) -> None:
    """Missing gitlab coverage warns on repo_map_path or workspace docs/local_repository_map.json."""
    cfg_path = tmp_path / "cfg" / "config.json"
    errors, warnings = preflight_migration_check({"repo_map_path": str(tmp_path / "map.json"), "policy_packs": []}, config_path=cfg_path)
    assert errors == []
    assert len(warnings) == 1 and "repo_map_path" in warnings[0]

    ws = tmp_path / "workspace"
    (ws / "docs").mkdir(parents=True)
    (ws / "docs" / "local_repository_map.json").write_text("{}", encoding="utf-8")
    ws_errors, ws_warnings = preflight_migration_check({"workspace_root": str(ws), "policy_packs": []}, config_path=cfg_path)
    assert ws_errors == []
    assert len(ws_warnings) == 1 and "local_repository_map.json" in ws_warnings[0]

    _, gitlab_entry = _make_pack(cfg_path.parent / "policies" / "gitlab-pack", pack_id="gitlab-pack", domains=("local_repo_guard",))
    ok_errors, ok_warnings = preflight_migration_check(
        {"workspace_root": str(ws), "repo_map_path": str(tmp_path / "map.json"), "policy_packs": [gitlab_entry]},
        config_path=cfg_path,
    )
    assert ok_errors == [] and ok_warnings == []


def test_preflight_rejects_invalid_scopes_api_tampering_and_inspect_config(tmp_path: Path) -> None:
    """Preflight catches invalid scopes, api_version mismatch, hash tampering, syntax errors, and settings errors."""
    cfg_path = tmp_path / "cfg" / "config.json"
    policies_dir = cfg_path.parent / "policies"

    _, bad_scopes = _make_pack(policies_dir / "bad-scopes", pack_id="bad-scopes", scopes=())
    errs, _ = preflight_migration_check({"policy_packs": [bad_scopes]}, config_path=cfg_path)
    assert any("scopes" in e for e in errs)

    _, unknown_scope = _make_pack(policies_dir / "unk-scope", pack_id="unk-scope", scopes=("unknown_scope",))
    errs, _ = preflight_migration_check({"policy_packs": [unknown_scope]}, config_path=cfg_path)
    assert any("scopes" in e for e in errs)

    _, bad_api = _make_pack(policies_dir / "bad-api", pack_id="bad-api", api_version=2)
    errs, _ = preflight_migration_check({"policy_packs": [bad_api]}, config_path=cfg_path)
    assert any("invalid manifest contract" in e or "manifest mismatch" in e for e in errs)

    _, opt_manifest_entry = _make_pack(policies_dir / "kind-mismatch", pack_id="kind-mismatch", kind="optimization", domains=())
    kind_errs, _ = preflight_migration_check(
        {"policy_packs": [{**opt_manifest_entry, "kind": "security", "scopes": list(ALL_SECURITY_SCOPES)}]},
        config_path=cfg_path,
    )
    assert any("manifest mismatch" in e for e in kind_errs)

    root_tampered, tampered = _make_pack(policies_dir / "tampered", pack_id="tampered")
    (root_tampered / "pack.py").write_text("PACK_ID = 'tampered'\n", encoding="utf-8")
    errs, _ = preflight_migration_check({"policy_packs": [tampered]}, config_path=cfg_path)
    assert any("verification failed" in e for e in errs)

    _, broken_sec = _make_pack(policies_dir / "broken-sec", pack_id="broken-sec", broken_syntax=True)
    errs, _ = preflight_migration_check({"policy_packs": [broken_sec]}, config_path=cfg_path)
    assert any("verification failed" in e for e in errs)

    _, broken_opt = _make_pack(policies_dir / "broken-opt", pack_id="broken-opt", kind="optimization", domains=(), broken_syntax=True)
    opt_errs, opt_warns = preflight_migration_check({"policy_packs": [broken_opt]}, config_path=cfg_path)
    assert opt_errs == [] and any("verification failed" in w for w in opt_warns)

    _, pack_a = _make_pack(policies_dir / "my-pack", pack_id="my-pack")
    _, pack_b = _make_pack(policies_dir / "my_pack", pack_id="my_pack")
    dup_errs, _ = preflight_migration_check({"policy_packs": [pack_a, pack_b]}, config_path=cfg_path)
    assert any("collision" in e for e in dup_errs)

    _, bad_settings = _make_pack(
        policies_dir / "bad-settings",
        pack_id="bad-settings",
        inspect_body="def inspect_cfg(s):\n    return ['missing required dataset'] if not s.get('ok') else []\n",
    )
    set_errs, _ = preflight_migration_check({"policy_packs": [bad_settings]}, config_path=cfg_path)
    assert any("missing required dataset" in e for e in set_errs)


def test_staged_tx_prepare_private_policies_subdir_and_filters_non_py(tmp_path: Path) -> None:
    """StagedPackTransaction resolves private_policies/, copies only *.py into staging, and migrates settings."""
    cfg_path = tmp_path / "cfg" / "config.json"
    initial_cfg = {
        "restricted_bq_datasets": ["raw_sales"],
        "allowed_bq_views_dataset": "ai_views",
        "enforce_governance_policy": True,
        "repo_map_path": str(tmp_path / "repo_map.json"),
    }
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(initial_cfg), encoding="utf-8")

    repo_dir = tmp_path / "pack-repo"
    _make_pack(
        repo_dir / "private_policies",
        extra_files={"sub/helper.py": "HELPER_VALUE = 42\n"},
        include_artifacts=True,
    )

    tx = StagedPackTransaction(repo_dir, config_path=cfg_path)
    candidate = tx.prepare()
    assert json.loads(cfg_path.read_text(encoding="utf-8")) == initial_cfg
    assert not (tx.policies_dir / "sample-security").exists()

    staging_dirs = list(tx.policies_dir.glob(".staging-sample-security-*"))
    assert len(staging_dirs) == 1
    staging_dir = staging_dirs[0]
    assert (staging_dir / "pack.py").is_file()
    assert (staging_dir / "sub" / "helper.py").is_file()
    assert not (staging_dir / "notes.txt").exists()
    assert not (staging_dir / "__pycache__").exists()
    assert not (staging_dir / ".hidden").exists()
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(staging_dir).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(staging_dir / "pack.py").st_mode) == 0o600

    for key in REQUIRED_CONFIG_KEYS:
        assert key in candidate
    assert candidate["enforce_governance_policy"] is True
    assert candidate["restricted_bq_datasets"] == ["raw_sales"]
    migrated = candidate["policy_packs"][0]["settings"]
    assert migrated["enforce_governance_policy"] is True
    assert migrated["restricted_bq_datasets"] == ["raw_sales"]
    assert migrated["repo_map_path"] == initial_cfg["repo_map_path"]

    tx.validate()
    tx.activate()
    tx.commit()
    assert list(tx.policies_dir.glob(".staging-*")) == []
    assert list(tx.policies_dir.glob(".backup-*")) == []
    errors, warnings = preflight_migration_check(json.loads(cfg_path.read_text(encoding="utf-8")), config_path=cfg_path)
    assert errors == [] and warnings == []


def test_staged_tx_validate_failure_cleans_staging_with_zero_live_writes(tmp_path: Path) -> None:
    """Validation failure removes staging directory without modifying live config or packs."""
    cfg_path = tmp_path / "cfg" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    sentinel_cfg = '{"sentinel": true}\n'
    cfg_path.write_text(sentinel_cfg, encoding="utf-8")
    live_pack = cfg_path.parent / "policies" / "sample-security"
    live_pack.mkdir(parents=True)
    (live_pack / "pack.py").write_text("# existing live pack\n", encoding="utf-8")

    bad_src = tmp_path / "bad-src"
    _make_pack(
        bad_src,
        inspect_body="def inspect_cfg(s):\n    return ['invalid config domain']\n",
    )
    tx = StagedPackTransaction(bad_src, config_path=cfg_path)
    tx.prepare()
    assert len(list(tx.policies_dir.glob(".staging-*"))) == 1
    with pytest.raises(PolicyPackLoadError, match="invalid config domain"):
        tx.validate()
    assert list(tx.policies_dir.glob(".staging-*")) == []
    assert cfg_path.read_text(encoding="utf-8") == sentinel_cfg
    assert (live_pack / "pack.py").read_text(encoding="utf-8") == "# existing live pack\n"

    if hasattr(os, "symlink"):
        sym_src = tmp_path / "sym-src"
        _make_pack(sym_src)
        (sym_src / "leak.py").symlink_to(cfg_path)
        sym_tx = StagedPackTransaction(sym_src, config_path=cfg_path)
        with pytest.raises(PolicyPackLoadError, match="symlink/reparse"):
            sym_tx.prepare()


def test_staged_tx_activate_backup_commit_and_rollback_existing_and_fresh(tmp_path: Path) -> None:
    """Transaction activate/rollback preserves or removes config.json and packs accurately."""
    cfg_path = tmp_path / "existing" / "config.json"
    old_pack, _ = _make_pack(cfg_path.parent / "policies" / "sample-security", extra_files={"ver.py": "VER = 1\n"})
    original_cfg = json.dumps({"marker": "old-v1", "policy_packs": []})
    cfg_path.write_text(original_cfg, encoding="utf-8")

    new_src = tmp_path / "new-src"
    _make_pack(new_src, extra_files={"ver.py": "VER = 2\n"})
    tx = StagedPackTransaction(new_src, config_path=cfg_path)
    tx.prepare()
    tx.validate()
    tx.activate()
    assert (old_pack / "ver.py").read_text(encoding="utf-8") == "VER = 2\n"
    assert len(list(tx.policies_dir.glob(".backup-sample-security-*"))) == 1
    assert json.loads(cfg_path.read_text(encoding="utf-8"))["marker"] == "old-v1"
    tx.rollback()
    assert cfg_path.read_text(encoding="utf-8") == original_cfg
    assert (old_pack / "ver.py").read_text(encoding="utf-8") == "VER = 1\n"
    assert list(tx.policies_dir.glob(".backup-*")) == []

    fresh_cfg = tmp_path / "fresh" / "config.json"
    fresh_tx = StagedPackTransaction(new_src, config_path=fresh_cfg)
    fresh_tx.prepare()
    fresh_tx.validate()
    fresh_tx.activate()
    assert fresh_cfg.is_file()
    assert (fresh_tx.policies_dir / "sample-security" / "ver.py").is_file()
    fresh_tx.rollback()
    assert not fresh_cfg.exists()
    assert not (fresh_tx.policies_dir / "sample-security").exists()


def test_staged_tx_activation_failure_rolls_back_config_and_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Atomic write failure during activate() triggers automatic rollback to prior state."""
    cfg_path = tmp_path / "atomic" / "config.json"
    live_pack, _ = _make_pack(cfg_path.parent / "policies" / "sample-security", extra_files={"ver.py": "VER = 'before'\n"})
    cfg_path.write_text('{"before": true}\n', encoding="utf-8")
    new_src = tmp_path / "src"
    _make_pack(new_src, extra_files={"ver.py": "VER = 'after'\n"})

    tx = StagedPackTransaction(new_src, config_path=cfg_path)
    tx.prepare()
    tx.validate()
    monkeypatch.setattr(os, "replace", lambda _s, _d: (_ for _ in ()).throw(OSError("simulated disk full")))
    with pytest.raises(OSError, match="simulated disk full"):
        tx.activate()
    assert cfg_path.read_text(encoding="utf-8") == '{"before": true}\n'
    assert (live_pack / "ver.py").read_text(encoding="utf-8") == "VER = 'before'\n"
    assert list(tx.policies_dir.glob(".staging-*")) == []
    assert list(tx.policies_dir.glob(".backup-*")) == []


def test_rollback_journal_lifo_file_and_dir_swap_context_manager(tmp_path: Path) -> None:
    """RollbackJournal reverts files and directory swaps in LIFO order and cleans backups on commit."""
    existing = tmp_path / "existing.txt"
    existing.write_text("original", encoding="utf-8")
    fresh = tmp_path / "fresh.txt"
    live_dir = tmp_path / "live"
    live_dir.mkdir()
    (live_dir / "state.txt").write_text("old-dir", encoding="utf-8")
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    (new_dir / "state.txt").write_text("new-dir", encoding="utf-8")

    with pytest.raises(RuntimeError, match="abort"):
        with RollbackJournal() as journal:
            journal.record_file_backup(existing)
            journal.record_file_backup(fresh)
            existing.write_text("mutated", encoding="utf-8")
            fresh.write_text("created", encoding="utf-8")
            journal.swap_directory(new_dir, live_dir)
            assert (live_dir / "state.txt").read_text(encoding="utf-8") == "new-dir"
            raise RuntimeError("abort")

    assert existing.read_text(encoding="utf-8") == "original"
    assert not fresh.exists()
    assert (live_dir / "state.txt").read_text(encoding="utf-8") == "old-dir"
    assert list(tmp_path.glob(".rollback-bak-*")) == []

    swap_src = tmp_path / "swap-src"
    swap_src.mkdir()
    (swap_src / "state.txt").write_text("committed-dir", encoding="utf-8")
    with RollbackJournal() as ok_journal:
        ok_journal.record_file_backup(existing)
        existing.write_text("final", encoding="utf-8")
        ok_journal.swap_directory(swap_src, live_dir)
        ok_journal.commit()
    assert existing.read_text(encoding="utf-8") == "final"
    assert (live_dir / "state.txt").read_text(encoding="utf-8") == "committed-dir"
    assert list(tmp_path.glob(".rollback-bak-*")) == []


def test_staged_tx_uses_resolved_default_config_path_under_isolated_env(isolated_user_env: Path, tmp_path: Path) -> None:
    """Default config_path=None targets isolated user env config directory safely."""
    src = tmp_path / "pack-src"
    _make_pack(src)
    tx = StagedPackTransaction(src)
    expected_cfg = isolated_user_env / ".config" / "context-guard" / "config.json"
    assert tx.config_path == expected_cfg
    tx.prepare()
    tx.validate()
    tx.activate()
    tx.commit()
    assert expected_cfg.is_file()
    assert (isolated_user_env / ".config" / "context-guard" / "policies" / "sample-security" / "pack.py").is_file()
