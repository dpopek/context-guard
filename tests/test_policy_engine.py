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


def test_policy_loader_detects_tampered_sibling_module_and_unpinned_py_or_pyc_files(
    isolated_user_env: Path,
) -> None:
    from policies.loader import clear_pack_cache

    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    pack_dir, entry = _write_synthetic_pack(policies_dir, "pin-check")

    clear_pack_cache()
    loaded = policy_engine.load_verified_policy_pack(entry, config_path=cfg_path)
    assert loaded.pack_id == "pin-check"

    helper_file = pack_dir / "helper.py"
    orig_helper = helper_file.read_bytes()
    helper_file.write_bytes(b"def check_target(path):\n    return False\n")
    os.chmod(helper_file, 0o600)
    clear_pack_cache()
    with pytest.raises(policy_engine.PolicyPackLoadError, match="SHA-256 mismatch"):
        policy_engine.load_verified_policy_pack(entry, config_path=cfg_path)

    helper_file.write_bytes(orig_helper)
    os.chmod(helper_file, 0o600)
    clear_pack_cache()
    assert policy_engine.load_verified_policy_pack(entry, config_path=cfg_path).pack_id == "pin-check"

    extra_py = pack_dir / "extra.py"
    extra_py.write_text("EVIL = True\n", encoding="utf-8")
    os.chmod(extra_py, 0o600)
    clear_pack_cache()
    with pytest.raises(policy_engine.PolicyPackLoadError, match="unpinned"):
        policy_engine.load_verified_policy_pack(entry, config_path=cfg_path)
    extra_py.unlink()

    root_pyc = pack_dir / "helper.pyc"
    root_pyc.write_bytes(b"pyc-data")
    clear_pack_cache()
    with pytest.raises(policy_engine.PolicyPackLoadError, match="unpinned"):
        policy_engine.load_verified_policy_pack(entry, config_path=cfg_path)
    root_pyc.unlink()

    pycache = pack_dir / "__pycache__"
    pycache.mkdir()
    os.chmod(pycache, 0o700)
    (pycache / "pack.cpython-39.pyc").write_bytes(b"pyc-bytes")
    clear_pack_cache()
    with pytest.raises(policy_engine.PolicyPackLoadError, match="__pycache__"):
        policy_engine.load_verified_policy_pack(entry, config_path=cfg_path)


def test_pass2_four_cases_and_double_evaluate_idempotency(
    isolated_user_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json
    from hooks import pre_tool_use
    from tests.helpers import read_session_state

    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    ws = tmp_path / "ws"
    ws.mkdir()
    big = ws / "big.py"
    big.write_text("".join(f"x_{i} = {i}\n" for i in range(250)), encoding="utf-8")

    # Case 1: security pack Pass-1 overwrite rejected in Pass-2 -> must deny (never fall back to orig)
    case1_src = (
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n"
        "def evaluate(ctx):\n"
        "    if ctx.canonical_tool == 'read_file':\n"
        "        end_l = ctx.canonical_args.get('EndLine')\n"
        "        if end_l == -1:\n"
        "            return PolicyDecision(decision='allow', overwrite={'StartLine': 1, 'EndLine': 10})\n"
        "        if end_l == 10:\n"
        "            return PolicyDecision(decision='deny', reason='CASE1_SEC_OW_REJECTED')\n"
        "    return PolicyDecision(decision='allow')\n"
        "PACK_MANIFEST = PolicyPackManifest(pack_id='c1', api_version=POLICY_API_VERSION, kind='security', covered_domains=('c1',), evaluate=evaluate)\n"
    )
    _, e1 = _write_synthetic_pack(policies_dir, "c1", pack_src=case1_src)
    cfg_path.write_text(json.dumps({"read_confirm_policy": "bounded", "policy_packs": [e1]}), encoding="utf-8")
    hooks_config.clear_config_cache()
    sd1 = str(tmp_path / "sd1")
    d1 = pre_tool_use.evaluate_hook({"conversationId": "c1", "stepIdx": 1, "toolCall": {"name": "read_file", "args": {"Path": str(big), "StartLine": 1, "EndLine": -1}}}, state_dir=sd1)
    assert d1["decision"] == "deny" and "CASE1_SEC_OW_REJECTED" in d1["reason"]

    # Case 2: optimizer transform violates Pass-2 -> discard optimizer, allow safe post_pass1, zero pending/unwrap
    side = isolated_user_env / "p2_marker.txt"
    case2_src = (
        "from pathlib import Path\n"
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n"
        f"_M = Path({str(side)!r})\n"
        "def evaluate(ctx):\n"
        "    if ctx.canonical_tool == 'run_command' and 'git status -sb' in str(ctx.canonical_args.get('CommandLine', '')):\n"
        "        return PolicyDecision(decision='deny', reason='CASE2_CLI_REJECTED')\n"
        "    if ctx.canonical_tool == 'read_file' and ctx.canonical_args.get('StartLine') == 101:\n"
        "        return PolicyDecision(decision='deny', reason='CASE2_TRIM_REJECTED')\n"
        "    if ctx.canonical_tool == 'read_file' and str(ctx.canonical_args.get('Path', '')).endswith('mod.py'):\n"
        "        return PolicyDecision(decision='deny', reason='CASE2_UNWRAP_REJECTED')\n"
        "    return PolicyDecision(decision='allow', metadata={'tool': ctx.canonical_tool})\n"
        "def on_pre_decision(ctx, dec):\n"
        "    _M.write_text(_M.read_text(encoding='utf-8') + f'{ctx.canonical_tool};' if _M.exists() else f'{ctx.canonical_tool};', encoding='utf-8')\n"
        "PACK_MANIFEST = PolicyPackManifest(pack_id='c2', api_version=POLICY_API_VERSION, kind='security', covered_domains=('c2',), evaluate=evaluate, on_pre_decision=on_pre_decision)\n"
    )
    _, e2 = _write_synthetic_pack(policies_dir, "c2", pack_src=case2_src)
    cfg_path.write_text(json.dumps({"read_confirm_policy": "bounded", "policy_packs": [e2]}), encoding="utf-8")
    hooks_config.clear_config_cache()
    sd2 = str(tmp_path / "sd2")
    # 2a: cli_rewrite denied by Pass-2 -> original command allowed without overwrite; idempotent double evaluate
    r_cli = pre_tool_use.evaluate_hook({"session_id": "s2", "tool_name": "Bash", "tool_input": {"command": "git status"}, "permission_mode": "bypassPermissions"}, state_dir=sd2, cli_harness="claude")
    assert r_cli == {}
    assert side.read_text(encoding="utf-8") == "run_command;"
    # 2b: range_trim denied by Pass-2 -> allow original range without pending_reads commit
    assert pre_tool_use.evaluate_hook({"session_id": "s2", "tool_name": "Read", "tool_input": {"file_path": str(big), "offset": 1, "limit": 100}}, state_dir=sd2, cli_harness="claude") == {}
    r_trim = pre_tool_use.evaluate_hook({"session_id": "s2", "tool_name": "Read", "tool_input": {"file_path": str(big), "offset": 1, "limit": 200}}, state_dir=sd2, cli_harness="claude")
    assert r_trim == {} and not read_session_state(sd2).get("pending_reads")
    # 2c: auto_outline/TWG unwrap redirect denied in Pass-2 -> discard redirect, zero unwrap files created
    cfg_path.write_text(
        json.dumps({"read_confirm_policy": "bounded", "optimizers": {"auto_outline": "off"}, "integrations": {"atlassian_twg": "active"}, "policy_packs": [e2]}),
        encoding="utf-8",
    )
    hooks_config.clear_config_cache()
    sd2_unw = tmp_path / "sd2_unw"
    mcp = tmp_path / ".system_generated" / "steps" / "9" / "output.txt"
    mcp.parent.mkdir(parents=True)
    mcp.write_text(json.dumps({"file_name": "mod.py", "content": "\n".join(f"v_{i}={i}" for i in range(1500))}), encoding="utf-8")
    r_unw = pre_tool_use.evaluate_hook({"conversationId": "s2u", "stepIdx": 9, "toolCall": {"name": "read_file", "args": {"Path": str(mcp), "StartLine": 1, "EndLine": 50}}}, state_dir=str(sd2_unw))
    assert r_unw == {"decision": "allow"} and not (mcp.parent / "mod.py").exists()
    cfg_path.write_text(json.dumps({"read_confirm_policy": "bounded", "policy_packs": [e2]}), encoding="utf-8")
    hooks_config.clear_config_cache()

    # Case 3: Pass-2 security load/eval error -> immediate scoped deny (never passthrough)
    e3 = {**e2, "fallback_matchers": {"protected_path_prefixes": [".githooks/"], "shell_commands": ["git"]}}
    cfg_path.write_text(json.dumps({"read_confirm_policy": "bounded", "policy_packs": [e3]}), encoding="utf-8")
    hooks_config.clear_config_cache()
    orig_load = policy_engine.load_verified_policy_pack
    calls = {"n": 0}

    def _boom_on_pass2(entry_arg: Any, *, config_path: Path | None = None, cwd: str | None = None) -> Any:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise policy_engine.PolicyPackLoadError("tampered during Pass-2")
        return orig_load(entry_arg, config_path=config_path, cwd=cwd)

    monkeypatch.setattr(policy_engine, "load_verified_policy_pack", _boom_on_pass2)
    r_c3 = pre_tool_use.evaluate_hook({"session_id": "s3", "tool_name": "Bash", "tool_input": {"command": "git status"}, "permission_mode": "bypassPermissions"}, state_dir=str(tmp_path / "sd3"), cli_harness="claude")
    assert r_c3["hookSpecificOutput"]["permissionDecision"] == "deny"
    monkeypatch.setattr(policy_engine, "load_verified_policy_pack", orig_load)

    # Case 4: commit_planned_file_read raises OSError -> safe passthrough of allow_dec
    monkeypatch.setattr(pre_tool_use, "commit_planned_file_read", lambda _p: (_ for _ in ()).throw(OSError("readonly fs")))
    r_c4 = pre_tool_use.evaluate_hook({"session_id": "s4", "tool_name": "Read", "tool_input": {"file_path": str(big), "offset": 1, "limit": 200}}, state_dir=str(tmp_path / "sd4"), cli_harness="claude")
    assert r_c4 == {}


def test_open_verified_regular_bytes_passes_o_binary_and_verifies_crlf_pack(
    isolated_user_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from policies import loader as policies_loader

    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    pack_dir = policies_dir / "crlf-sec"
    pack_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(policies_dir, 0o700)
        os.chmod(pack_dir, 0o700)

    raw_crlf = (
        b"from policies.api import POLICY_API_VERSION, PolicyPackManifest\r\n"
        b"PACK_MANIFEST = PolicyPackManifest(\r\n"
        b"    pack_id='crlf-sec',\r\n"
        b"    api_version=POLICY_API_VERSION,\r\n"
        b"    kind='security',\r\n"
        b"    covered_domains=('crlf',),\r\n"
        b"    evaluate=lambda ctx: None,\r\n"
        b")\r\n"
    )
    pack_file = pack_dir / "pack.py"
    pack_file.write_bytes(raw_crlf)
    if os.name != "nt":
        os.chmod(pack_file, 0o600)

    fhash = _sha256(raw_crlf)
    tsha = _tree_sha({"pack.py": fhash})
    entry = {
        "id": "crlf-sec",
        "path": str(pack_file),
        "enabled": True,
        "kind": "security",
        "scopes": ["file_mutation"],
        "file_hashes": {"pack.py": fhash},
        "tree_sha256": tsha,
    }
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"

    had_o_binary = hasattr(os, "O_BINARY")
    target_bit = getattr(os, "O_BINARY", 1 << 28)
    if not had_o_binary:
        monkeypatch.setattr(policies_loader.os, "O_BINARY", target_bit, raising=False)
    real_open = os.open
    recorded_flags: list[int] = []

    def _wrapped_open(path: str, flags: int, mode: int = 0o777) -> int:
        recorded_flags.append(flags)
        delegate_flags = flags if had_o_binary else (flags & ~target_bit)
        return real_open(path, delegate_flags, mode)

    monkeypatch.setattr(policies_loader.os, "open", _wrapped_open)
    policy_engine.clear_pack_cache()
    manifest = policy_engine.load_verified_policy_pack(entry, config_path=cfg_path)
    assert manifest.pack_id == "crlf-sec"
    assert any((f & target_bit) == target_bit for f in recorded_flags)


def _write_domain_pack(
    policies_dir: Path,
    pack_id: str,
    *,
    kind: str = "security",
    domains: tuple[str, ...],
) -> dict[str, Any]:
    pack_src = (
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n"
        "def evaluate(ctx):\n"
        "    cmd = str(ctx.canonical_args.get('CommandLine', ''))\n"
        "    path = str(ctx.canonical_args.get('Path', ''))\n"
        "    if 'eval_block' in cmd or 'eval_block' in path:\n"
        "        return PolicyDecision(decision='deny', reason='EVAL_BLOCKED')\n"
        "    return None\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        f"    pack_id={pack_id!r}, api_version=POLICY_API_VERSION, kind={kind!r},\n"
        f"    covered_domains={domains!r}, evaluate=evaluate,\n"
        ")\n"
    )
    _, entry = _write_synthetic_pack(policies_dir, pack_id, pack_src=pack_src)
    return entry


def test_legacy_security_keys_require_verified_covered_domains(
    isolated_user_env: Path, tmp_path: Path
) -> None:
    import json
    from hooks import pre_tool_use

    assert set(hooks_config.LEGACY_SECURITY_CONFIG_KEYS).issubset(
        set(hooks_config.LEGACY_SECURITY_DOMAIN_MAP.keys())
    )

    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    policy_engine.clear_pack_cache()

    gov_entry = _write_domain_pack(policies_dir, "gov-only", domains=("governance_guard",))
    base_cfg: dict[str, Any] = {
        "read_confirm_policy": "strict",
        "optimizers": {},
        "integrations": {"atlassian_twg": "off"},
        "regret_window_steps": 2,
        "policy_packs": [gov_entry],
        "model_labels": {},
        "legacy_security_keys": ("restricted_bq_datasets",),
        "config_path": str(cfg_path),
        "config_error": None,
    }

    cmd_norm = _make_norm(tool="run_command", args={"CommandLine": "echo ok"})
    write_norm = _make_norm(tool="write_file", args={"Path": "/tmp/ws/a.py"}, mutated=("/tmp/ws/a.py",))
    mcp_norm = _make_norm(tool="call_mcp_tool", orig="mcp_bigquery_query", args={"ServerName": "bigquery"})
    read_norm = _make_norm(tool="read_file", args={"Path": "/tmp/ws/a.py"})

    for scoped_norm in (cmd_norm, write_norm, mcp_norm):
        dec = policy_engine.apply_policy_packs(scoped_norm, base_cfg)
        assert dec is not None and dec["decision"] == "deny"
        assert "UNMIGRATED SECURITY CONFIG" in dec["reason"]
        assert "restricted_bq_datasets" in dec["reason"]
    assert policy_engine.apply_policy_packs(read_norm, base_cfg) is None

    # End-to-end via evaluate_hook with config.json
    sample = tmp_path / "sample.py"
    sample.write_bytes(b"print('hi')\n")
    cfg_path.write_text(
        json.dumps({"restricted_bq_datasets": ["raw_sales"], "policy_packs": [gov_entry]}),
        encoding="utf-8",
    )
    hooks_config.clear_config_cache()
    sd = str(tmp_path / "sd_mig")
    for tool_name, tool_input in (
        ("Bash", {"command": "echo ok"}),
        ("Write", {"file_path": str(sample), "content": "x = 1\n"}),
        ("mcp_bigquery_query", {"query": "SELECT 1"}),
    ):
        hook_dec = pre_tool_use.evaluate_hook(
            {"session_id": "s-mig", "tool_name": tool_name, "tool_input": tool_input},
            state_dir=sd,
            cli_harness="claude",
        )
        assert hook_dec["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "UNMIGRATED SECURITY CONFIG" in hook_dec["hookSpecificOutput"]["permissionDecisionReason"]
    hook_read = pre_tool_use.evaluate_hook(
        {"session_id": "s-mig", "tool_name": "Read", "tool_input": {"file_path": str(sample)}},
        state_dir=sd,
        cli_harness="claude",
    )
    assert hook_read == {}

    # Two legacy keys with partial coverage (only bigquery_guard) still fail closed on enforce_governance_policy
    bq_entry = _write_domain_pack(policies_dir, "bq-only", domains=("bigquery_guard",))
    partial_cfg = {
        **base_cfg,
        "policy_packs": [bq_entry],
        "legacy_security_keys": ("restricted_bq_datasets", "enforce_governance_policy"),
    }
    for scoped_norm in (cmd_norm, write_norm, mcp_norm):
        p_dec = policy_engine.apply_policy_packs(scoped_norm, partial_cfg)
        assert p_dec is not None and p_dec["decision"] == "deny"
        assert "UNMIGRATED SECURITY CONFIG" in p_dec["reason"]
        assert "enforce_governance_policy" in p_dec["reason"]
    assert policy_engine.apply_policy_packs(read_norm, partial_cfg) is None

    # Full domain coverage skips migration block and delegates to manifest.evaluate
    full_entry = _write_domain_pack(policies_dir, "full-sec", domains=("bigquery_guard", "governance_guard"))
    full_cfg = {
        **base_cfg,
        "policy_packs": [full_entry],
        "legacy_security_keys": ("restricted_bq_datasets", "allowed_bq_views_dataset", "enforce_governance_policy"),
    }
    for ok_norm in (cmd_norm, write_norm, mcp_norm, read_norm):
        assert policy_engine.apply_policy_packs(ok_norm, full_cfg) is None
    blocked_cmd = _make_norm(tool="run_command", args={"CommandLine": "eval_block"})
    eval_dec = policy_engine.apply_policy_packs(blocked_cmd, full_cfg)
    assert eval_dec == {"decision": "deny", "reason": "EVAL_BLOCKED"}


def test_manifest_kind_mismatch_fails_closed_and_cannot_cover_legacy_domains(
    isolated_user_env: Path,
) -> None:
    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    cfg_path = isolated_user_env / ".config" / "context-guard" / "config.json"
    policy_engine.clear_pack_cache()

    spoofed_entry = _write_domain_pack(
        policies_dir,
        "spoofed-opt",
        kind="optimization",
        domains=("bigquery_guard", "governance_guard"),
    )
    # Entry claims kind='security' even though PACK_MANIFEST has kind='optimization'
    mismatched_entry = {**spoofed_entry, "kind": "security"}
    cfg_no_legacy: dict[str, Any] = {
        "read_confirm_policy": "strict",
        "optimizers": {},
        "integrations": {"atlassian_twg": "off"},
        "regret_window_steps": 2,
        "policy_packs": [mismatched_entry],
        "model_labels": {},
        "legacy_security_keys": (),
        "config_path": str(cfg_path),
        "config_error": None,
    }
    hook_edit = _make_norm(
        tool="edit_file",
        args={"Path": "/tmp/ws/.githooks/pre-commit"},
        mutated=("/tmp/ws/.githooks/pre-commit",),
    )
    dec_scoped = policy_engine.apply_policy_packs(hook_edit, cfg_no_legacy)
    assert dec_scoped is not None and dec_scoped["decision"] == "deny"
    assert "SECURITY PACK ERROR" in dec_scoped["reason"]

    app_edit = _make_norm(tool="edit_file", args={"Path": "/tmp/ws/app.py"}, mutated=("/tmp/ws/app.py",))
    assert policy_engine.apply_policy_packs(app_edit, cfg_no_legacy) is None

    # With legacy_security_keys active, mismatched manifest cannot grant domain coverage
    cfg_legacy = {**cfg_no_legacy, "legacy_security_keys": ("restricted_bq_datasets",)}
    dec_legacy = policy_engine.apply_policy_packs(app_edit, cfg_legacy)
    assert dec_legacy is not None and dec_legacy["decision"] == "deny"
    assert "UNMIGRATED SECURITY CONFIG" in dec_legacy["reason"]
    act_p2, p2_dec = policy_engine.reconcile_post_transform(app_edit, cfg_legacy, fallback_norm=app_edit)
    assert act_p2 == "deny" and p2_dec is not None and "UNMIGRATED SECURITY CONFIG" in p2_dec["reason"]
    assert policy_engine.apply_policy_packs(_make_norm(tool="read_file", args={"Path": "/tmp/ws/app.py"}), cfg_legacy) is None

def test_repeated_pack_deny_appends_operator_escalation_without_changing_decision(isolated_user_env: Path, tmp_path: Path) -> None:
    """Second consecutive block by the same rule tells the agent to stop and report; first block and decision unchanged."""
    import dataclasses

    policies_dir = isolated_user_env / ".config" / "context-guard" / "policies"
    _pack, entry = _write_synthetic_pack(policies_dir, "repeat-sec")
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
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    base = _make_norm(tool="edit_file", args={"Path": "/tmp/ws/blocked.txt"}, mutated=("/tmp/ws/blocked.txt",))

    def deny_at(call: str, state: Path | None = state_dir) -> dict[str, Any]:
        dec, _records, _norm, _ow = policy_engine.apply_policy_packs_with_records(
            dataclasses.replace(base, call_id=call), runtime_cfg, state_dir_path=state
        )
        assert dec is not None and dec["decision"] == "deny"
        return dec

    first = deny_at("c1")
    assert first["reason"] == "BLOCKED_BY_SYNTH"
    assert deny_at("c1")["reason"] == "BLOCKED_BY_SYNTH"  # Pass-2 re-evaluation of the same call is not a retry
    second = deny_at("c2")
    assert second["reason"].startswith("BLOCKED_BY_SYNTH")
    assert "report to the operator" in second["reason"].lower()
    assert deny_at("c2")["reason"] == second["reason"]
    # Without session state the message is never altered.
    assert deny_at("c3", None)["reason"] == "BLOCKED_BY_SYNTH"


def test_repeat_deny_escalation_respects_rule_identity_and_time_window(tmp_path: Path) -> None:
    from policies.repeat_deny import REPEAT_DENY_NOTE, REPEAT_DENY_WINDOW_S, escalate_repeat_deny

    def esc(reason: str, call: str, ts: float) -> str:
        return escalate_repeat_deny(reason, "gov", call, tmp_path, now_ts=ts)

    assert esc("Blocked `a.php`", "c1", 1000.0) == "Blocked `a.php`"
    assert esc("Blocked `b.php`", "c2", 1010.0).endswith(REPEAT_DENY_NOTE)  # quoted target ignored: same rule
    assert esc("Other rule", "c3", 1020.0) == "Other rule"
    assert esc("Other rule", "c4", 1020.0 + REPEAT_DENY_WINDOW_S + 1) == "Other rule"
    (tmp_path / "policy_deny_last.json").write_text("{not json", encoding="utf-8")
    assert esc("Other rule", "c5", 5000.0) == "Other rule"
