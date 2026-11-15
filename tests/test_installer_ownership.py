"""The installer removes only its own hook handlers, never another tool's."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bin.install_harnesses import install_all, uninstall_all

FOREIGN = "python3 /opt/other-tool/hooks/pre_tool_use.py --mode strict"
SIBLING = "/usr/local/bin/audit-log.sh"


def _seed(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    claude = tmp_path / "settings.json"
    own = "python3 /old/context-guard/hooks/pre_tool_use.py --harness claude"
    claude.write_text(
        json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": FOREIGN}]},
            {"matcher": "Read", "hooks": [
                {"type": "command", "command": own},
                {"type": "command", "command": SIBLING},
            ]},
        ]}}),
        encoding="utf-8",
    )
    cursor = tmp_path / "cursor_hooks.json"
    cursor.write_text(json.dumps({"version": 1, "hooks": {"preToolUse": [{"command": FOREIGN}]}}), encoding="utf-8")
    codex = tmp_path / "codex_hooks.json"
    codex.write_text('{"hooks": {}}', encoding="utf-8")
    toml = tmp_path / "config.toml"
    toml.write_text('model = "x"\n', encoding="utf-8")
    return claude, cursor, codex, toml


def _commands(cfg: Path, event: str) -> list[str]:
    out: list[str] = []
    for group in json.loads(cfg.read_text(encoding="utf-8")).get("hooks", {}).get(event, []):
        if "command" in group:
            out.append(group["command"])
        out.extend(h["command"] for h in group.get("hooks", []))
    return out


def test_install_and_uninstall_keep_foreign_handlers(tmp_path: Path) -> None:
    claude, cursor, codex, toml = _seed(tmp_path)
    plugin_root = Path(__file__).resolve().parent.parent
    install_all(plugin_root, claude, cursor, codex, toml)
    cmds = _commands(claude, "PreToolUse")
    assert FOREIGN in cmds and SIBLING in cmds
    assert not any("/old/context-guard/" in c for c in cmds)
    assert sum("--harness claude" in c for c in cmds) == 1
    assert FOREIGN in _commands(cursor, "preToolUse")

    uninstall_all(claude, cursor, codex, toml)
    assert _commands(claude, "PreToolUse") == [FOREIGN, SIBLING]
    assert _commands(cursor, "preToolUse") == [FOREIGN]


def test_workspace_session_start_and_stop_hooks_installed_idempotently_keeping_superset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib
    import os
    from bin.install_harnesses import compute_codex_trusted_hash
    from hooks import config as guard_config

    ws = tmp_path / "workspace"
    hooks_dir = ws / "scripts" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "session_baseline_guard.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    (hooks_dir / "session_stop_guard.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")

    pack_dir = tmp_path / "policies" / "acme_lifecycle"
    pack_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(pack_dir.parent, 0o700)
    os.chmod(pack_dir, 0o700)
    pack_src = (
        "from policies.api import POLICY_API_VERSION, InstallerHookSpec, PolicyPackManifest\n\n"
        "def evaluate(ctx):\n"
        "    return None\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        "    pack_id='acme-ws-lifecycle', api_version=POLICY_API_VERSION,\n"
        "    kind='security', covered_domains=('synthetic-ws',), evaluate=evaluate,\n"
        "    harness_matchers={\n"
        "        'claude': 'mcp__acme__.*',\n"
        "        'cursor': 'mcp__acme__.*',\n"
        "        'codex': 'mcp__acme__.*',\n"
        "    },\n"
        "    installer_hooks=(\n"
        "        InstallerHookSpec('claude', 'SessionStart', '{python} {workspace_root}/scripts/hooks/session_baseline_guard.py --capture-baseline', timeout=10),\n"
        "        InstallerHookSpec('claude', 'Stop', '{python} {workspace_root}/scripts/hooks/session_stop_guard.py --claude-hook', timeout=30),\n"
        "        InstallerHookSpec('cursor', 'sessionStart', '{python} {workspace_root}/scripts/hooks/session_baseline_guard.py --capture-baseline', timeout=10),\n"
        "        InstallerHookSpec('cursor', 'stop', '{python} {workspace_root}/scripts/hooks/session_stop_guard.py --cursor-hook', timeout=30),\n"
        "        InstallerHookSpec('codex', 'SessionStart', '{python} {workspace_root}/scripts/hooks/session_baseline_guard.py --capture-baseline', timeout=10),\n"
        "        InstallerHookSpec('codex', 'Stop', '{python} {workspace_root}/scripts/hooks/session_stop_guard.py --claude-hook', timeout=30),\n"
        "    ),\n"
        ")\n"
    ).encode("utf-8")
    pack_file = pack_dir / "pack.py"
    pack_file.write_bytes(pack_src)
    os.chmod(pack_file, 0o600)
    fsha = hashlib.sha256(pack_src).hexdigest()
    tsha = hashlib.sha256(f"pack.py:{fsha}\n".encode("utf-8")).hexdigest()
    entry = {
        "id": "acme-ws-lifecycle",
        "path": str(pack_file),
        "enabled": True,
        "kind": "security",
        "scopes": ["file_mutation"],
        "file_hashes": {"pack.py": fsha},
        "tree_sha256": tsha,
        "settings": {},
    }
    cfg_file = tmp_path / "cg_config.json"
    cfg_file.write_text(json.dumps({"workspace_root": str(ws), "policy_packs": [entry]}), encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_file))
    guard_config.clear_config_cache()

    superset_claude = '[ -n "$SUPERSET_HOME_DIR" ] && "$SUPERSET_HOME_DIR/hooks/notify.sh" || true'
    superset_cursor_start = "/Users/example/.superset/hooks/cursor-hook.sh SessionStart"
    superset_cursor_stop = "/Users/example/.superset/hooks/cursor-hook.sh Stop"

    claude = tmp_path / "settings.json"
    claude.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [{"hooks": [{"type": "command", "command": superset_claude}]}],
                    "Stop": [{"hooks": [{"type": "command", "command": superset_claude}]}],
                }
            }
        ),
        encoding="utf-8",
    )
    cursor = tmp_path / "cursor_hooks.json"
    cursor.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "sessionStart": [{"command": superset_cursor_start}],
                    "stop": [{"command": superset_cursor_stop}],
                },
            }
        ),
        encoding="utf-8",
    )
    codex = tmp_path / "codex_hooks.json"
    codex.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [{"hooks": [{"type": "command", "command": superset_claude}]}],
                    "Stop": [{"hooks": [{"type": "command", "command": superset_claude}]}],
                }
            }
        ),
        encoding="utf-8",
    )
    toml = tmp_path / "config.toml"
    toml.write_text('model = "gpt-5"\n', encoding="utf-8")

    plugin_root = Path(__file__).resolve().parent.parent
    install_all(plugin_root, claude, cursor, codex, toml, workspace_root=ws)
    first_claude = claude.read_text(encoding="utf-8")
    first_cursor = cursor.read_text(encoding="utf-8")
    first_codex = codex.read_text(encoding="utf-8")
    first_toml = toml.read_text(encoding="utf-8")
    assert "mcp__acme__.*" in first_claude
    assert "mcp__acme__.*" in first_codex

    # Re-running install_all deduplicates and produces byte-identical configs
    install_all(plugin_root, claude, cursor, codex, toml, workspace_root=ws)
    assert claude.read_text(encoding="utf-8") == first_claude
    assert cursor.read_text(encoding="utf-8") == first_cursor
    assert codex.read_text(encoding="utf-8") == first_codex
    assert toml.read_text(encoding="utf-8") == first_toml

    for cfg in (claude, codex):
        start_cmds = _commands(cfg, "SessionStart")
        stop_cmds = _commands(cfg, "Stop")
        assert superset_claude in start_cmds
        assert superset_claude in stop_cmds
        assert sum("session_baseline_guard.py --capture-baseline" in c for c in start_cmds) == 1
        assert sum("session_stop_guard.py --claude-hook" in c for c in stop_cmds) == 1

    codex_stop_groups = json.loads(first_codex)["hooks"]["Stop"]
    stop_handler = [
        h
        for grp in codex_stop_groups
        for h in grp.get("hooks", [])
        if "session_stop_guard.py --claude-hook" in h.get("command", "")
    ][0]
    assert stop_handler["timeout"] == 30
    expected_stop_hash = compute_codex_trusted_hash("stop", None, stop_handler["command"], timeout=30)
    assert f'trusted_hash = "{expected_stop_hash}"' in first_toml

    cursor_start_cmds = _commands(cursor, "sessionStart")
    cursor_stop_cmds = _commands(cursor, "stop")
    assert superset_cursor_start in cursor_start_cmds
    assert superset_cursor_stop in cursor_stop_cmds
    assert sum("session_baseline_guard.py --capture-baseline" in c for c in cursor_start_cmds) == 1
    assert sum("session_stop_guard.py --cursor-hook" in c for c in cursor_stop_cmds) == 1

    # Uninstall removes managed pack hooks while preserving Superset hooks
    uninstall_all(claude, cursor, codex, toml)
    assert _commands(claude, "SessionStart") == [superset_claude]
    assert _commands(claude, "Stop") == [superset_claude]
    assert _commands(codex, "SessionStart") == [superset_claude]
    assert _commands(codex, "Stop") == [superset_claude]
    assert _commands(cursor, "sessionStart") == [superset_cursor_start]
    assert _commands(cursor, "stop") == [superset_cursor_stop]

    # Also resolves workspace_root automatically from CONTEXT_GUARD_CONFIG_PATH when omitted
    install_all(plugin_root, claude, cursor, codex, toml)
    assert sum("session_stop_guard.py --claude-hook" in c for c in _commands(claude, "Stop")) == 1
    assert sum("session_stop_guard.py --cursor-hook" in c for c in _commands(cursor, "stop")) == 1


def test_codex_toml_lexical_scanner_preserves_comments_strings_arrays_and_indented_tables(
    tmp_path: Path,
) -> None:
    from bin.codex_toml import sync_codex_config_toml

    codex_hooks = tmp_path / "hooks.json"
    codex_config = tmp_path / "config.toml"
    state_header = f'[hooks.state."{codex_hooks}:pre_tool_use:0:0"]'
    initial = (
        '# Top comment with """ and [fake_table]\n'
        '# model_auto_compact_token_limit = 999\n'
        'model = "gpt-5"\n'
        'escaped = "a\\\\\\"b [not_a_table]"\n'
        "win_lit = 'C:\\\\temp\\\\ [not_a_table]'\n"
        'multiline_str = """\n'
        "[inside_multiline_str]\n"
        "model_auto_compact_token_limit = 1\n"
        '"""\n'
        "literal_multi = '''\n"
        "[inside_literal_multi]\n"
        "'''\n"
        "nested_arr = [\n"
        '  "[inside_array]",\n'
        "  [1, 2],\n"
        "]\n"
        "\n"
        "# Section comment for demo\n"
        "# Second line of demo comment\n"
        "[mcp_servers.demo]\n"
        'args = ["--flag"]\n'
        "\n"
        f"{state_header}\n"
        'trusted_hash = "sha256:old"\n'
        "\n"
        "# User comment before indented table\n"
        "  [indented_user_table]\n"
        'key = "keep_me"\n'
    )
    codex_config.write_text(initial, encoding="utf-8")
    hooks_data = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "^(Bash)$",
                    "hooks": [{"type": "command", "command": "python3 /opt/cg/hooks/pre_tool_use.py"}],
                }
            ]
        }
    }

    assert (
        sync_codex_config_toml(
            codex_hooks_path=codex_hooks,
            codex_config_path=codex_config,
            hooks_data=hooks_data,
            ensure_compact_limit=True,
            dry_run=False,
        )
        == "updated"
    )
    rendered = codex_config.read_text(encoding="utf-8")
    limit_line = "model_auto_compact_token_limit = 250000 # context-guard:managed"
    assert limit_line in rendered
    assert rendered.index(limit_line) < rendered.index("# Section comment for demo")
    assert rendered.index("nested_arr = [") < rendered.index(limit_line)
    assert "# User comment before indented table" in rendered
    assert "  [indented_user_table]" in rendered
    assert 'key = "keep_me"' in rendered
    assert 'trusted_hash = "sha256:old"' not in rendered

    # Idempotency check
    sync_codex_config_toml(
        codex_hooks_path=codex_hooks,
        codex_config_path=codex_config,
        hooks_data=hooks_data,
        ensure_compact_limit=True,
        dry_run=False,
    )
    assert codex_config.read_text(encoding="utf-8") == rendered

    # Uninstall removes managed limit line and hooks.state blocks cleanly
    sync_codex_config_toml(
        codex_hooks_path=codex_hooks,
        codex_config_path=codex_config,
        hooks_data={"hooks": {}},
        ensure_compact_limit=False,
        dry_run=False,
    )
    after_uninstall = codex_config.read_text(encoding="utf-8")
    assert "# context-guard:managed" not in after_uninstall
    assert "hooks.state" not in after_uninstall
    assert "# User comment before indented table" in after_uninstall
    assert "  [indented_user_table]" in after_uninstall
    assert "[inside_multiline_str]" in after_uninstall


def test_codex_toml_preserves_existing_user_compact_limit(tmp_path: Path) -> None:
    from bin.codex_toml import sync_codex_config_toml

    codex_hooks = tmp_path / "hooks.json"
    codex_config = tmp_path / "config.toml"
    codex_config.write_text(
        "model_auto_compact_token_limit = 180000\n\n[mcp_servers.demo]\ncommand = 'x'\n",
        encoding="utf-8",
    )
    sync_codex_config_toml(
        codex_hooks_path=codex_hooks,
        codex_config_path=codex_config,
        hooks_data={"hooks": {}},
        ensure_compact_limit=True,
        dry_run=False,
    )
    text = codex_config.read_text(encoding="utf-8")
    assert "model_auto_compact_token_limit = 180000" in text
    assert "# context-guard:managed" not in text

    sync_codex_config_toml(
        codex_hooks_path=codex_hooks,
        codex_config_path=codex_config,
        hooks_data={"hooks": {}},
        ensure_compact_limit=False,
        dry_run=False,
    )
    assert "model_auto_compact_token_limit = 180000" in codex_config.read_text(encoding="utf-8")


def test_installer_preserves_symlinks_and_skips_dangling_symlinks(tmp_path: Path) -> None:
    import os

    if os.name == "nt":
        return

    dots = tmp_path / "dotfiles"
    dots.mkdir()
    real_claude = dots / "claude.json"
    real_cursor = dots / "cursor.json"
    real_codex = dots / "codex.json"
    real_toml = dots / "config.toml"
    real_claude.write_text('{"hooks": {}}\n', encoding="utf-8")
    real_cursor.write_text('{"version": 1, "hooks": {}}\n', encoding="utf-8")
    real_codex.write_text('{"hooks": {}}\n', encoding="utf-8")
    real_toml.write_text('model = "gpt-5"\n', encoding="utf-8")

    home_cfgs = tmp_path / "home_cfgs"
    home_cfgs.mkdir()
    claude_link = home_cfgs / "settings.json"
    cursor_link = home_cfgs / "cursor_hooks.json"
    codex_link = home_cfgs / "codex_hooks.json"
    toml_link = home_cfgs / "config.toml"
    claude_link.symlink_to(real_claude)
    cursor_link.symlink_to(real_cursor)
    codex_link.symlink_to(real_codex)
    toml_link.symlink_to(real_toml)

    plugin_root = Path(__file__).resolve().parent.parent
    res = install_all(plugin_root, claude_link, cursor_link, codex_link, toml_link)
    assert res["claude"] == "updated"
    assert res["cursor"] == "updated"
    assert res["codex_hooks"] == "updated"
    assert res["codex_config"] == "updated"
    for link in (claude_link, cursor_link, codex_link, toml_link):
        assert link.is_symlink()
    assert (home_cfgs / "settings.json.bak").is_file()
    assert "pre_tool_use.py" in real_claude.read_text(encoding="utf-8")

    uninstall_all(claude_link, cursor_link, codex_link, toml_link)
    for link in (claude_link, cursor_link, codex_link, toml_link):
        assert link.is_symlink()
    assert "context-guard" not in real_claude.read_text(encoding="utf-8")

    dangling_claude = home_cfgs / "dangling_claude.json"
    dangling_cursor = home_cfgs / "dangling_cursor.json"
    dangling_codex = home_cfgs / "dangling_codex.json"
    dangling_toml = home_cfgs / "dangling_config.toml"
    for dlink in (dangling_claude, dangling_cursor, dangling_codex, dangling_toml):
        dlink.symlink_to(dots / f"missing_{dlink.name}")

    d_res = install_all(plugin_root, dangling_claude, dangling_cursor, dangling_codex, dangling_toml)
    assert d_res["claude"] == "skipped (not found)"
    assert d_res["cursor"] == "skipped (not found)"
    assert d_res["codex_hooks"] == "skipped (not found)"
    assert d_res["codex_config"] == "skipped (not found)"


def test_build_vscode_file_uri_location_hook_quoting_and_lazy_plugin_root(
    tmp_path: Path, monkeypatch
) -> None:
    from pathlib import PureWindowsPath
    from bin import install_harnesses

    win_loc = install_harnesses.build_vscode_file_uri_location(
        PureWindowsPath(r"C:\Users\Alice Smith\.cursor\extensions\advox.context-guard-statusbar-3.99.0")
    )
    assert win_loc == {
        "$mid": 1,
        "fsPath": r"C:\Users\Alice Smith\.cursor\extensions\advox.context-guard-statusbar-3.99.0",
        "external": "file:///C:/Users/Alice%20Smith/.cursor/extensions/advox.context-guard-statusbar-3.99.0",
        "path": "/C:/Users/Alice Smith/.cursor/extensions/advox.context-guard-statusbar-3.99.0",
        "scheme": "file",
    }

    space_dir = tmp_path / "dir with spaces" / "ext"
    space_dir.mkdir(parents=True)
    posix_loc = install_harnesses.build_vscode_file_uri_location(space_dir)
    assert posix_loc["external"].startswith("file:///")
    assert "%20" in posix_loc["external"]
    assert posix_loc["path"].startswith("/")
    assert posix_loc["fsPath"] == str(space_dir.resolve())

    assert (
        install_harnesses.format_hook_script_path(Path("/opt/my(proj)&1/hooks/pre_tool_use.py"))
        == '"/opt/my(proj)&1/hooks/pre_tool_use.py"'
    )
    assert (
        install_harnesses.format_hook_script_path(Path('/opt/my"proj/hooks/pre_tool_use.py'))
        == '"/opt/my\\"proj/hooks/pre_tool_use.py"'
    )
    assert (
        install_harnesses.format_hook_script_path(Path("C:/Users/Alice/hooks/pre_tool_use.py"))
        == "C:/Users/Alice/hooks/pre_tool_use.py"
    )

    assert hasattr(install_harnesses, "DEFAULT_PLUGIN_ROOT")
    lazy_root = tmp_path / "lazy-cg-root"
    (lazy_root / "hooks").mkdir(parents=True)
    (lazy_root / "bin").mkdir(parents=True)
    claude_cfg = tmp_path / "claude.json"
    claude_cfg.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_HOME", str(lazy_root))
    install_harnesses.install_all(
        claude_settings_path=claude_cfg,
        cursor_hooks_path=tmp_path / "missing_cursor.json",
        codex_hooks_path=tmp_path / "missing_codex.json",
        codex_config_path=tmp_path / "missing_config.toml",
    )
    assert str(lazy_root.resolve()).replace("\\", "/") in claude_cfg.read_text(encoding="utf-8")



