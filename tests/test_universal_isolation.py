"""Regression gates guaranteeing zero local-environment leakage in default plugin installs."""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
from pathlib import Path
from typing import Any

import pytest

from hooks import config as guard_config
from hooks.pre_tool_use import evaluate_hook
from hooks.shell_parser import rewrite_quiet_cli_flags

ROOT = Path(__file__).resolve().parent.parent


def _write_verified_pack(
    pack_dir: Path,
    pack_id: str,
    pack_src: str,
    *,
    scopes: list[str],
    fallback_matchers: dict[str, Any] | None = None,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pack_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(pack_dir.parent, 0o700)
    os.chmod(pack_dir, 0o700)
    pack_file = pack_dir / "pack.py"
    raw = pack_src.encode("utf-8")
    pack_file.write_bytes(raw)
    os.chmod(pack_file, 0o600)
    file_sha = hashlib.sha256(raw).hexdigest()
    tree_sha = hashlib.sha256(f"pack.py:{file_sha}\n".encode("utf-8")).hexdigest()
    return {
        "id": pack_id,
        "path": str(pack_file),
        "enabled": True,
        "kind": "security",
        "scopes": scopes,
        "fallback_matchers": dict(fallback_matchers or {}),
        "file_hashes": {"pack.py": file_sha},
        "tree_sha256": tree_sha,
        "settings": dict(settings or {}),
    }


def assert_allowed(res: dict[str, Any], harness: str) -> None:
    if harness == "antigravity":
        assert res.get("decision") == "allow", f"Expected Antigravity allow, got: {res}"
    else:
        hso = res.get("hookSpecificOutput")
        if isinstance(hso, dict):
            assert hso.get("permissionDecision") != "deny", f"Unexpected {harness} deny: {res}"
        else:
            assert res == {}, f"Expected empty allow dict for {harness}, got: {res}"


def assert_denied(res: dict[str, Any], harness: str, expected_substr: str = "") -> None:
    if harness == "antigravity":
        assert res.get("decision") == "deny", f"Expected Antigravity deny, got: {res}"
        reason = str(res.get("reason") or "")
    else:
        hso = res.get("hookSpecificOutput")
        assert isinstance(hso, dict), f"Expected {harness} hookSpecificOutput, got: {res}"
        assert hso.get("permissionDecision") == "deny", f"Expected {harness} deny, got: {res}"
        reason = str(hso.get("permissionDecisionReason") or "")
    if expected_substr:
        assert expected_substr.lower() in reason.lower(), f"Missing {expected_substr!r} in {reason!r}"


def _shell_call(harness: str, command: str, cwd: Path) -> dict[str, Any]:
    if harness == "antigravity":
        return {
            "conversationId": "c-univ",
            "stepIdx": 1,
            "cwd": str(cwd),
            "toolCall": {"name": "run_command", "args": {"CommandLine": command}},
        }
    tool_name = {"claude": "Bash", "cursor": "Shell", "codex": "exec_command"}[harness]
    inp = {"cmd": command} if harness == "codex" else {"command": command}
    return {
        "session_id": f"s-{harness}",
        "tool_name": tool_name,
        "tool_input": inp,
        "cwd": str(cwd),
    }


def _write_call(harness: str, target_path: Path, cwd: Path) -> dict[str, Any]:
    if harness == "antigravity":
        return {
            "conversationId": "c-univ",
            "stepIdx": 1,
            "cwd": str(cwd),
            "toolCall": {"name": "write_file", "args": {"Path": str(target_path)}},
        }
    if harness == "claude":
        return {
            "session_id": "s-claude",
            "tool_name": "Write",
            "tool_input": {"file_path": str(target_path)},
            "cwd": str(cwd),
        }
    if harness == "cursor":
        return {
            "session_id": "s-cursor",
            "tool_name": "StrReplace",
            "tool_input": {"path": str(target_path)},
            "cwd": str(cwd),
        }
    rel = target_path.relative_to(cwd).as_posix()
    patch = f"*** Begin Patch\n*** Add File: {rel}\n+ok\n*** End Patch"
    return {
        "session_id": "s-codex",
        "tool_name": "apply_patch",
        "tool_input": {"patch": patch},
        "cwd": str(cwd),
    }


def test_default_install_without_config_never_blocks_project_files_or_git_workflows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_config.clear_config_cache()
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(tmp_path / "absent_config.json"))
    cfg = guard_config.load_runtime_config()
    assert cfg["policy_packs"] == []
    assert cfg["config_error"] is None

    project = tmp_path / "external-webapp"
    project.mkdir()
    state_dir = str(tmp_path / "state")

    normal_project_targets = (
        project / ".husky" / "pre-commit",
        project / ".githooks" / "pre-commit",
        project / "scripts" / "audit" / "seo_audit.py",
        project / "scripts" / "hooks" / "post_deploy.sh",
        project / "tests" / "baselines" / "home_snapshot.json",
        project / "scripts" / "ci" / "run-quality-suite.sh",
        project / ".claude" / "settings.local.json",
    )
    normal_shell_commands = (
        "git add .",
        "git add -A",
        'git commit -m "chore: initial setup" --no-verify',
        'SKIP=eslint git commit -m "wip"',
        "HUSKY=0 git commit -m 'wip'",
        f"echo 'npx lint-staged' > {project / '.husky' / 'pre-commit'}",
    )

    for harness in ("antigravity", "claude", "cursor", "codex"):
        for target in normal_project_targets:
            res = evaluate_hook(
                _write_call(harness, target, project),
                state_dir=state_dir,
                cli_harness=harness,
            )
            assert_allowed(res, harness)
        for cmd in normal_shell_commands:
            res_sh = evaluate_hook(
                _shell_call(harness, cmd, project),
                state_dir=state_dir,
                cli_harness=harness,
            )
            assert_allowed(res_sh, harness)


def test_scoped_security_pack_enforces_only_declared_scopes_and_rejects_malformed_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_config.clear_config_cache()
    pack_src = (
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n\n"
        "def evaluate(ctx):\n"
        "    if ctx.canonical_tool == 'call_mcp_tool' or ctx.original_tool_name.startswith(('mcp_', 'mcp__')):\n"
        "        sql = str(ctx.canonical_args.get('Arguments', {}).get('query', '') or ctx.canonical_args.get('query', ''))\n"
        "        restricted = ctx.settings.get('restricted_datasets', [])\n"
        "        if any(f'{ds}.' in sql for ds in restricted):\n"
        "            return PolicyDecision(decision='deny', reason='Blocked by acme-mcp-sec: use safe views')\n"
        "    return None\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        "    pack_id='acme-mcp-sec', api_version=POLICY_API_VERSION,\n"
        "    kind='security', covered_domains=('synthetic-mcp',), evaluate=evaluate,\n"
        ")\n"
    )
    entry = _write_verified_pack(
        tmp_path / "policies" / "acme_mcp",
        "acme-mcp-sec",
        pack_src,
        scopes=["mcp_call"],
        fallback_matchers={"mcp_tool_regex": r"^mcp__?acme(?:__|$)"},
        settings={"restricted_datasets": ["acme_private_ds"]},
    )
    cfg_path = tmp_path / "mcp_only_config.json"
    cfg_path.write_text(json.dumps({"policy_packs": [entry]}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    state_dir = str(tmp_path / "state")
    project = tmp_path / "analytics-proj"
    project.mkdir()

    # Git add . and .husky edits remain allowed because only mcp_call scope is enforced
    assert_allowed(
        evaluate_hook(_shell_call("claude", "git add .", project), state_dir=state_dir, cli_harness="claude"),
        "claude",
    )
    assert_allowed(
        evaluate_hook(
            _write_call("claude", project / ".husky" / "pre-commit", project),
            state_dir=state_dir,
            cli_harness="claude",
        ),
        "claude",
    )

    # Scoped synthetic MCP query is hard-blocked
    mcp_payload = {
        "session_id": "s-claude",
        "tool_name": "mcp__acme__execute_sql",
        "tool_input": {"query": "SELECT * FROM acme_private_ds.orders"},
        "cwd": str(project),
    }
    assert_denied(
        evaluate_hook(mcp_payload, state_dir=state_dir, cli_harness="claude"),
        "claude",
        "safe views",
    )

    # Non-int regret_window_steps fails closed on scoped calls
    cfg_path.write_text(json.dumps({"regret_window_steps": "yes"}), encoding="utf-8")
    guard_config.clear_config_cache()
    assert guard_config.load_runtime_config()["config_error"] == "invalid 'regret_window_steps'"
    assert_denied(
        evaluate_hook(_shell_call("claude", "git status", project), state_dir=state_dir, cli_harness="claude"),
        "claude",
        "config error",
    )


def test_security_pack_respects_workspace_boundaries_and_windows_normcase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_config.clear_config_cache()
    ws_root = tmp_path / "workspace"
    ws_root.mkdir()
    cfg_path = tmp_path / "gov_config.json"

    pack_src = (
        "import os\n"
        "from pathlib import Path\n"
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n\n"
        "def _norm(p):\n"
        "    return os.path.normcase(os.path.abspath(str(p))).replace('\\\\', '/')\n\n"
        "def _is_guarded_repo_file(target_norm, guarded_roots):\n"
        "    for root in guarded_roots:\n"
        "        rn = _norm(root).rstrip('/') + '/'\n"
        "        if target_norm.startswith(rn):\n"
        "            rel = target_norm[len(rn):]\n"
        "            if any(rel.startswith(p) for p in ('tests/baselines/', 'scripts/audit/', 'scripts/hooks/', 'scripts/ci/')):\n"
        "                return True\n"
        "    return False\n\n"
        "def evaluate(ctx):\n"
        "    if ctx.canonical_tool not in ('edit_file', 'write_file'):\n"
        "        return None\n"
        "    raw = str(ctx.canonical_args.get('Path') or ctx.canonical_args.get('TargetFile') or '')\n"
        "    if not raw:\n"
        "        return None\n"
        "    tn = _norm(raw)\n"
        "    cfg_norm = _norm(ctx.settings.get('config_path', ''))\n"
        "    ws_norm = _norm(ctx.settings.get('workspace_root', ''))\n"
        "    if cfg_norm and tn == cfg_norm:\n"
        "        return PolicyDecision(decision='deny', reason='Blocked by synthetic governance: context_guard_config')\n"
        "    if '/.githooks/' in tn or '/.husky/' in tn or '/.claude/' in tn or tn.endswith('/guard_manifest.json'):\n"
        "        return PolicyDecision(decision='deny', reason='Blocked by synthetic governance: hook/manifest')\n"
        "    if ws_norm and tn.startswith(ws_norm.rstrip('/') + '/scripts/hooks/'):\n"
        "        return PolicyDecision(decision='deny', reason='Blocked by synthetic governance: workspace hook')\n"
        "    if _is_guarded_repo_file(tn, ctx.settings.get('guarded_repos', [])):\n"
        "        return PolicyDecision(decision='deny', reason='Blocked by synthetic governance: guarded repo')\n"
        "    return None\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        "    pack_id='acme-ws-gov', api_version=POLICY_API_VERSION,\n"
        "    kind='security', covered_domains=('synthetic-gov',), evaluate=evaluate,\n"
        ")\n"
    )
    guarded_repo = ws_root / "core-platform"
    (guarded_repo / ".git").mkdir(parents=True)
    (guarded_repo / "scripts" / "audit").mkdir(parents=True)
    (guarded_repo / "scripts" / "audit" / "guard_manifest.json").write_text("{}", encoding="utf-8")

    entry = _write_verified_pack(
        tmp_path / "policies" / "acme_gov",
        "acme-ws-gov",
        pack_src,
        scopes=["file_mutation"],
        fallback_matchers={"protected_path_prefixes": [".githooks/", ".husky/", ".claude/", "guard_manifest.json"]},
        settings={
            "workspace_root": str(ws_root),
            "config_path": str(cfg_path),
            "guarded_repos": [str(guarded_repo)],
        },
    )
    cfg_path.write_text(json.dumps({"workspace_root": str(ws_root), "policy_packs": [entry]}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    state_dir = str(tmp_path / "state")

    # 1. Unguarded client git repository generic dirs remain allowed
    client_repo = ws_root / "client-storefront"
    (client_repo / ".git").mkdir(parents=True)
    for generic_rel in (
        "tests/baselines/checkout.json",
        "scripts/audit/store_templates.php",
        "scripts/hooks/cache_warm.sh",
        "scripts/ci/run-quality-suite.sh",
    ):
        assert_allowed(
            evaluate_hook(
                _write_call("claude", client_repo / generic_rel, client_repo),
                state_dir=state_dir,
                cli_harness="claude",
            ),
            "claude",
        )
    # Real git/harness hooks and guard manifests in client_repo remain protected
    for real_gov_rel in (".githooks/pre-commit", ".husky/pre-commit", ".claude/settings.json", "guard_manifest.json"):
        assert_denied(
            evaluate_hook(
                _write_call("claude", client_repo / real_gov_rel, client_repo),
                state_dir=state_dir,
                cli_harness="claude",
            ),
            "claude",
            "governance",
        )

    # 2. Guarded repository files are denied
    for guarded_rel in (
        "tests/baselines/refactoring_slop.json",
        "scripts/audit/slop_scanner.py",
        "scripts/hooks/session_stop_guard.py",
        "scripts/ci/run-quality-suite.sh",
    ):
        assert_denied(
            evaluate_hook(
                _write_call("claude", guarded_repo / guarded_rel, guarded_repo),
                state_dir=state_dir,
                cli_harness="claude",
            ),
            "claude",
            "governance",
        )

    # 3. Workspace-level scripts/hooks/ and operator config.json remain protected
    assert_denied(
        evaluate_hook(
            _write_call("claude", ws_root / "scripts" / "hooks" / "custom_stop_guard.py", ws_root),
            state_dir=state_dir,
            cli_harness="claude",
        ),
        "claude",
        "governance",
    )
    assert_denied(
        evaluate_hook(_write_call("claude", cfg_path, ws_root), state_dir=state_dir, cli_harness="claude"),
        "claude",
        "governance",
    )

    # 4. Windows drive-letter paths & ntpath.normcase preserve symmetric Policy API checks
    win_raw = r"C:\Users\dev\client-storefront\tests\baselines\checkout.json"
    win_payload = {
        "session_id": "s-win",
        "tool_name": "Write",
        "tool_input": {"file_path": win_raw},
        "cwd": str(ws_root),
    }
    assert_allowed(evaluate_hook(win_payload, state_dir=state_dir, cli_harness="claude"), "claude")
    with monkeypatch.context() as mp_nt:
        mp_nt.setattr(os.path, "normcase", ntpath.normcase)
        assert_denied(
            evaluate_hook(_write_call("claude", cfg_path, ws_root), state_dir=state_dir, cli_harness="claude"),
            "claude",
            "context_guard_config",
        )


def test_inline_scripts_with_type_arrows_comparisons_and_str_replace_pass_cli_and_pack_hooks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_config.clear_config_cache()
    ws_root = tmp_path / "workspace"
    ws_root.mkdir()
    pack_src = (
        "import re\n"
        "from policies.api import POLICY_API_VERSION, PolicyDecision, PolicyPackManifest\n\n"
        "_WRITE_RE = re.compile(r\"(os\\.replace|open\\([^)]*['\\\"][wa]\\+?['\\\"]|>\\s*\\.husky/)\")\n\n"
        "def evaluate(ctx):\n"
        "    if ctx.canonical_tool != 'run_command':\n"
        "        return None\n"
        "    cmd = str(ctx.canonical_args.get('CommandLine') or '')\n"
        "    if '.husky/pre-commit' in cmd and _WRITE_RE.search(cmd):\n"
        "        return PolicyDecision(decision='deny', reason='Blocked by synthetic governance: shell mutation')\n"
        "    return None\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        "    pack_id='acme-shell-gov', api_version=POLICY_API_VERSION,\n"
        "    kind='security', covered_domains=('synthetic-gov',), evaluate=evaluate,\n"
        ")\n"
    )
    entry = _write_verified_pack(
        tmp_path / "policies" / "acme_shell",
        "acme-shell-gov",
        pack_src,
        scopes=["shell_command"],
        fallback_matchers={"protected_path_prefixes": [".husky/"]},
    )
    cfg_path = tmp_path / "gov_config.json"
    cfg_path.write_text(json.dumps({"workspace_root": str(ws_root), "policy_packs": [entry]}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_path))
    state_dir = str(tmp_path / "state")

    benign_inline_cmds = (
        'python3 -c "def fmt(s: str) -> str: return s.replace(\'a\', \'b\'); print(fmt(\'.husky\'))"',
        'python3 -c "x = 5; print(x >= 2, \'guard_manifest.json\')"',
        'node -e "const f = (s) => s.replace(/x/, \'y\'); console.log(f(\'.githooks\'))"',
        'python3 -c "import json; print(json.load(open(\'/Users/dev/.config/context-guard/config.json\')))"',
        'python3 -c "open(\'.husky/pre-commit\', \'r\').read()"',
        'python3 -c "open(\'.husky/pre-commit\', mode=\'rb\').read()"',
    )
    for cmd in benign_inline_cmds:
        assert rewrite_quiet_cli_flags(cmd) is None
        assert_allowed(
            evaluate_hook(_shell_call("claude", cmd, ws_root), state_dir=state_dir, cli_harness="claude"),
            "claude",
        )

    malicious_inline_cmds = (
        'python3 -c "import os; os.replace(\'/tmp/x\', \'.husky/pre-commit\')"',
        'python3 -c "open(\'.husky/pre-commit\', \'w\').write(\'exit 0\')"',
        'python3 -c "open(\'.husky/pre-commit\', \'a\')"',
        'python3 -c "open(\'.husky/pre-commit\', mode=\'w+\')"',
        "bash <<'EOF'\necho 'exit 0' > .husky/pre-commit\nEOF",
    )
    for cmd in malicious_inline_cmds:
        assert_denied(
            evaluate_hook(_shell_call("claude", cmd, ws_root), state_dir=state_dir, cli_harness="claude"),
            "claude",
            "governance",
        )


def test_exported_rules_agents_md_and_root_agents_md_enforce_universal_isolation() -> None:
    root_agents = ROOT / "AGENTS.md"
    assert root_agents.is_file(), "Root AGENTS.md with universal plugin isolation constitution must exist"
    root_text = root_agents.read_text(encoding="utf-8")
    assert "Universal Plugin Isolation" in root_text
    assert "test_version_source.py" in root_text

    exported_rules = (ROOT / "rules" / "AGENTS.md").read_text(encoding="utf-8")
    leaked_tokens = (
        "twg",
        "auth.conf",
        "Teamwork Graph",
        "test_version_source.py",
        "vscode-extension/README.md",
        "local_repository_map.md",
        "repos/<category>",
    )
    for tok in leaked_tokens:
        assert tok not in exported_rules, (
            f"Exported rules/AGENTS.md must stay universal across all user projects; leaked {tok!r}"
        )

    antigravity_home_re = re.compile(r'Path\.home\(\)\s*/\s*["\']Antigravity["\']')
    for folder in ("hooks", "bin", "policies", "integrations", "spool", "evidence"):
        for py_path in sorted((ROOT / folder).glob("*.py")):
            src = py_path.read_text(encoding="utf-8")
            assert antigravity_home_re.search(src) is None, (
                f"Hardcoded ~/Antigravity workspace path found in {py_path.relative_to(ROOT)}"
            )
    js_home_subpath_re = re.compile(
        r"""(?:os\.homedir\(\)|homeDir|effectiveHome|~/|~\\)[^;\n]*["'](?:Antigravity|workspace)["']|~[/\\](?:Antigravity|workspace)\b"""
    )
    for js_path in sorted((ROOT / "vscode-extension").glob("*.js")):
        js_src = js_path.read_text(encoding="utf-8")
        assert js_home_subpath_re.search(js_src) is None, (
            f"Hardcoded home subpath found in {js_path.relative_to(ROOT)}"
        )


def test_npm_and_pnpm_test_commands_are_not_silenced() -> None:
    for cmd in (
        "npm test",
        "npm run test",
        "pnpm test",
        "pnpm run test",
        "cd /repo && npm test",
        "cd /repo && pnpm test",
    ):
        assert rewrite_quiet_cli_flags(cmd) is None
