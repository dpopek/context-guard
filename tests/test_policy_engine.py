"""Tests for Policy API v1, zero-TOCTOU verified-bytes pack loader, and Stage-2 scoped fail-closed engine."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from hooks import config as hooks_config
from hooks import policy_engine
from hooks.harness_adapter import NormalizedToolCall
from policies.api import POLICY_API_VERSION, PolicyContext, PolicyDecision, PolicyPackManifest


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree_sha(file_hashes: dict[str, str]) -> str:
    manifest_text = "".join(f"{k}:{file_hashes[k]}\n" for k in sorted(file_hashes))
    return _sha256(manifest_text.encode("utf-8"))


def _write_synthetic_pack(
    policies_dir: Path,
    pack_id: str = "synth-sec",
    *,
    helper_src: str = "def check_target(path):\n    return 'blocked.txt' in path\n",
    pack_src: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    pack_dir = policies_dir / pack_id
    pack_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(pack_dir, 0o700)
    init_file = pack_dir / "__init__.py"
    helper_file = pack_dir / "helper.py"
    pack_file = pack_dir / "pack.py"

    init_src = '"""Synthetic test pack."""\n'
    if pack_src is None:
        pack_src = (
            "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n"
            "from .helper import check_target\n\n"
            "def evaluate(ctx):\n"
            "    if ctx.canonical_tool == 'edit_file' and check_target(str(ctx.canonical_args.get('Path', ''))):\n"
            "        return PolicyDecision(decision='deny', reason='BLOCKED_BY_SYNTH')\n"
            "    if ctx.canonical_tool == 'run_command' and 'secret_cmd' in str(ctx.canonical_args.get('CommandLine', '')):\n"
            "        return PolicyDecision(decision='deny', reason='BLOCKED_CMD_BY_SYNTH')\n"
            "    return None\n\n"
            f"PACK_MANIFEST = PolicyPackManifest(pack_id={pack_id!r}, api_version=POLICY_API_VERSION, "
            "kind='security', covered_domains=('synthetic',), evaluate=evaluate)\n"
        )

    file_hashes: dict[str, str] = {}
    for target, src in ((init_file, init_src), (helper_file, helper_src), (pack_file, pack_src)):
        raw = src.encode("utf-8")
        target.write_bytes(raw)
        os.chmod(target, 0o600)
        file_hashes[target.name] = _sha256(raw)

    entry = {
        "id": pack_id,
        "path": str(pack_file),
        "enabled": True,
        "kind": "security",
        "scopes": ["file_mutation", "shell_command", "mcp_call"],
        "fallback_matchers": {
            "protected_path_prefixes": [".githooks/", "security/policy.yaml"],
            "shell_commands": ["psql"],
            "mcp_tool_regex": "^mcp_synth_.*",
        },
        "file_hashes": file_hashes,
        "tree_sha256": _tree_sha(file_hashes),
        "settings": {},
    }
    return pack_dir, entry


def _make_norm(
    *,
    tool: str = "edit_file",
    args: dict[str, Any] | None = None,
    orig: str | None = None,
    cwd: str = "/tmp/ws",
    mutated: tuple[str, ...] = (),
) -> NormalizedToolCall:
    eff_args = dict(args or {})
    return NormalizedToolCall(
        harness="claude",
        canonical_tool=tool,
        canonical_args=eff_args,
        original_tool_name=orig if orig is not None else tool,
        original_tool_input=eff_args,
        session_id="sess-1",
        step_idx=1,
        cwd=cwd,
        artifact_dir=None,
        mutated_paths=mutated,
        permission_mode=None,
    )


def test_runtime_config_defaults_to_strict_and_atlassian_off(isolated_user_env: Path, tmp_path: Path) -> None:
    cfg = hooks_config.load_runtime_config()
    assert cfg["read_confirm_policy"] == "strict"
    assert cfg["integrations"]["atlassian_twg"] == "off"
    assert set(hooks_config.REQUIRED_CONFIG_KEYS).issubset(set(cfg.keys()))

    win_local = tmp_path / "AppData" / "Local" / "context-guard"
    win_local.mkdir(parents=True)
    (win_local / "config.json").write_text("{}", encoding="utf-8")
    resolved = hooks_config.resolve_user_config_path(
        home=tmp_path / "no-home",
        env={"LOCALAPPDATA": str(tmp_path / "AppData" / "Local")},
        os_name="nt",
    )
    assert resolved == win_local / "config.json"


def test_verify_policy_pack_tree_detects_tampered_sibling_and_unpinned_files(isolated_user_env: Path) -> None:
    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    pack_dir, entry = _write_synthetic_pack(policies_dir, "synth-sec")

    verified = policy_engine.verify_policy_pack_tree(pack_dir, entry, trusted_roots=(policies_dir,))
    assert sorted(verified) == ["__init__.py", "helper.py", "pack.py"]

    # Tamper sibling helper.py while leaving pack.py untouched.
    (pack_dir / "helper.py").write_bytes(b"def check_target(p):\n    return False\n")
    with pytest.raises(policy_engine.PolicyPackLoadError):
        policy_engine.verify_policy_pack_tree(pack_dir, entry, trusted_roots=(policies_dir,))

    # Restore sibling, then drop an unpinned .json / .py / .pyc file inside pack_dir.
    (pack_dir / "helper.py").write_bytes(verified["helper.py"])
    for extra_name in ("rules.json", "shadow_mod.py", "helper.cpython-311.pyc"):
        extra = pack_dir / extra_name
        extra.write_bytes(b"{}" if extra_name.endswith(".json") else b"x = 1\n")
        os.chmod(extra, 0o600)
        with pytest.raises(policy_engine.PolicyPackLoadError):
            policy_engine.verify_policy_pack_tree(pack_dir, entry, trusted_roots=(policies_dir,))
        extra.unlink()


def test_pack_id_validation_and_duplicate_namespace_collision(isolated_user_env: Path) -> None:
    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    for bad_id in ("../escape", "Bad Caps", "has space", "dot.name", ""):
        with pytest.raises(policy_engine.PolicyPackLoadError):
            policy_engine.normalize_pack_ns(bad_id)

    pack_a, entry_a = _write_synthetic_pack(policies_dir, "my-pack")
    pack_b, entry_b = _write_synthetic_pack(policies_dir, "my_pack")
    runtime_cfg = {
        "read_confirm_policy": "strict",
        "optimizers": {},
        "integrations": {"atlassian_twg": "off"},
        "regret_window_steps": 2,
        "policy_packs": [entry_a, entry_b],
        "model_labels": {},
        "legacy_security_keys": (),
        "config_path": str(isolated_user_env / ".config" / "context-guard" / "config.json"),
        "config_error": None,
    }
    norm_mut = _make_norm(tool="edit_file", args={"Path": "/tmp/ws/app.py"}, mutated=("/tmp/ws/app.py",))
    dec = policy_engine.apply_policy_packs(norm_mut, runtime_cfg)
    assert dec is not None and dec["decision"] == "deny"

    norm_read = _make_norm(tool="read_file", args={"Path": "/tmp/ws/app.py"})
    assert policy_engine.apply_policy_packs(norm_read, runtime_cfg) is None


def test_verified_bytes_loader_is_toctou_free_and_isolates_policies_namespace(
    isolated_user_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    pack_dir, entry = _write_synthetic_pack(policies_dir, "toctou-pack")
    verified_bytes = policy_engine.verify_policy_pack_tree(pack_dir, entry, trusted_roots=(policies_dir,))

    # Even if an attacker mutates pack files right after verify_policy_pack_tree, loader compiles verified_bytes!
    monkeypatch.setattr(policy_engine, "verify_policy_pack_tree", lambda *a, **kw: verified_bytes)
    (pack_dir / "helper.py").write_bytes(b"def check_target(p):\n    raise AssertionError('disk bytes ran!')\n")

    manifest = policy_engine.load_verified_policy_pack(
        entry, config_path=policies_dir.parent / "config.json"
    )
    assert manifest.api_version == POLICY_API_VERSION
    assert manifest.pack_id == "toctou-pack"

    ctx = PolicyContext(
        harness="claude",
        call_id="c1",
        canonical_tool="edit_file",
        canonical_args={"Path": "/tmp/ws/blocked.txt"},
        mutated_paths=("/tmp/ws/blocked.txt",),
        original_tool_name="Edit",
        tool_input={"file_path": "/tmp/ws/blocked.txt"},
        cwd="/tmp/ws",
        session_id="s1",
        step_idx=1,
        state_dir=None,
        settings={},
    )
    dec = manifest.evaluate(ctx)
    assert dec is not None and dec.decision == "deny" and dec.reason == "BLOCKED_BY_SYNTH"
    assert POLICY_API_VERSION == 1


def test_stage2_scoped_fail_closed_behavior_matrix(isolated_user_env: Path) -> None:
    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    _, entry = _write_synthetic_pack(policies_dir, "broken-sec")
    bad_entry = {**entry, "tree_sha256": "0" * 64}
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"

    runtime_cfg = {
        "read_confirm_policy": "strict",
        "optimizers": {},
        "integrations": {"atlassian_twg": "off"},
        "regret_window_steps": 2,
        "policy_packs": [bad_entry],
        "model_labels": {},
        "legacy_security_keys": (),
        "config_path": str(cfg_path),
        "config_error": None,
    }
    # Matching protected prefix under file_mutation -> denied
    bad_edit = _make_norm(tool="edit_file", args={"Path": "/tmp/ws/.githooks/pre-commit"}, mutated=("/tmp/ws/.githooks/pre-commit",))
    res_bad = policy_engine.apply_policy_packs(bad_edit, runtime_cfg)
    assert res_bad is not None and res_bad["decision"] == "deny"

    # Read remains open even during security pack failure
    safe_read = _make_norm(tool="read_file", args={"Path": "/tmp/ws/.githooks/pre-commit"})
    assert policy_engine.apply_policy_packs(safe_read, runtime_cfg) is None

    # Broken pack missing scopes -> denies all 3 security scopes fail-closed
    no_scope_entry = {**bad_entry, "scopes": []}
    no_scope_cfg = {**runtime_cfg, "policy_packs": [no_scope_entry]}
    safe_edit = _make_norm(tool="edit_file", args={"Path": "/tmp/ws/src/main.py"}, mutated=("/tmp/ws/src/main.py",))
    res_noscope = policy_engine.apply_policy_packs(safe_edit, no_scope_cfg)
    assert res_noscope is not None and res_noscope["decision"] == "deny"
    assert policy_engine.apply_policy_packs(safe_read, no_scope_cfg) is None

    # Broken optimization pack warns and fails open
    opt_entry = {**no_scope_entry, "kind": "optimization", "id": "broken-opt"}
    opt_cfg = {**runtime_cfg, "policy_packs": [opt_entry]}
    assert policy_engine.apply_policy_packs(safe_edit, opt_cfg) is None


def test_evaluate_purity_and_pass2_overwrite_rejection(isolated_user_env: Path) -> None:
    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    marker = isolated_user_env / "side_effect_marker.txt"
    pack_src = (
        "from pathlib import Path\n"
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n"
        f"_MARKER = Path({str(marker)!r})\n\n"
        "def evaluate(ctx):\n"
        "    if ctx.canonical_tool == 'read_file':\n"
        "        return PolicyDecision(\n"
        "            decision='allow',\n"
        "            overwrite={'StartLine': 1, 'EndLine': 5},\n"
        "            metadata={'record': ctx.canonical_args.get('Path', '')},\n"
        "        )\n"
        "    return PolicyDecision(decision='allow', metadata={'record': 'noop'})\n\n"
        "def on_pre_decision(ctx, dec):\n"
        "    if dec is not None and dec.metadata.get('record'):\n"
        "        _MARKER.write_text(str(dec.metadata['record']), encoding='utf-8')\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        "    pack_id='purity-sec', api_version=POLICY_API_VERSION, kind='security',\n"
        "    covered_domains=('purity',), evaluate=evaluate, on_pre_decision=on_pre_decision,\n"
        ")\n"
    )
    _, entry = _write_synthetic_pack(policies_dir, "purity-sec", pack_src=pack_src)
    runtime_cfg = {
        "read_confirm_policy": "strict",
        "optimizers": {},
        "integrations": {"atlassian_twg": "off"},
        "regret_window_steps": 2,
        "policy_packs": [entry],
        "model_labels": {},
        "legacy_security_keys": (),
        "config_path": str(isolated_user_env / ".config" / "context-guard" / "config.json"),
        "config_error": None,
    }
    norm_read = _make_norm(tool="read_file", args={"Path": "/tmp/ws/a.py", "StartLine": 1, "EndLine": 100})
    dec, records, post_norm, ow = policy_engine.apply_policy_packs_with_records(norm_read, runtime_cfg)
    assert dec is None
    assert ow == {"StartLine": 1, "EndLine": 5}
    assert post_norm.canonical_args["EndLine"] == 5
    # evaluate() is strictly pure: side-effect marker not created until run_pre_decision_hooks runs!
    assert not marker.exists()
    policy_engine.run_pre_decision_hooks(records)
    assert marker.read_text(encoding="utf-8") == "/tmp/ws/a.py"

    # Security pack proposing overwrite in Pass-2 is denied!
    pass2_dec = policy_engine.verify_security_policies_post_transform(norm_read, runtime_cfg)
    assert pass2_dec is not None and pass2_dec["decision"] == "deny" and "Pass-2" in pass2_dec["reason"]

