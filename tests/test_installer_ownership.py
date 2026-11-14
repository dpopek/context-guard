"""The installer removes only its own hook handlers, never another tool's."""
from __future__ import annotations

import json
from pathlib import Path

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
    tmp_path: Path,
) -> None:
    from bin.install_harnesses import compute_codex_trusted_hash

    ws = tmp_path / "workspace"
    hooks_dir = ws / "scripts" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "antigravity_stop_guard.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    (hooks_dir / "claude_stop_guard.py").write_text("#!/usr/bin/env python3\n", encoding="utf-8")

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
        assert sum("antigravity_stop_guard.py --capture-baseline" in c for c in start_cmds) == 1
        assert sum("claude_stop_guard.py --claude-hook" in c for c in stop_cmds) == 1

    codex_stop_groups = json.loads(first_codex)["hooks"]["Stop"]
    stop_handler = [
        h
        for grp in codex_stop_groups
        for h in grp.get("hooks", [])
        if "claude_stop_guard.py --claude-hook" in h.get("command", "")
    ][0]
    assert stop_handler["timeout"] == 30
    expected_stop_hash = compute_codex_trusted_hash("stop", None, stop_handler["command"], timeout=30)
    assert f'trusted_hash = "{expected_stop_hash}"' in first_toml

    cursor_start_cmds = _commands(cursor, "sessionStart")
    cursor_stop_cmds = _commands(cursor, "stop")
    assert superset_cursor_start in cursor_start_cmds
    assert superset_cursor_stop in cursor_stop_cmds
    assert sum("antigravity_stop_guard.py --capture-baseline" in c for c in cursor_start_cmds) == 1
    assert sum("claude_stop_guard.py --cursor-hook" in c for c in cursor_stop_cmds) == 1

    # Uninstall removes managed stop/baseline hooks while preserving Superset hooks
    uninstall_all(claude, cursor, codex, toml)
    assert _commands(claude, "SessionStart") == [superset_claude]
    assert _commands(claude, "Stop") == [superset_claude]
    assert _commands(codex, "SessionStart") == [superset_claude]
    assert _commands(codex, "Stop") == [superset_claude]
    assert _commands(cursor, "sessionStart") == [superset_cursor_start]
    assert _commands(cursor, "stop") == [superset_cursor_stop]

    # Also resolves workspace_root automatically from CONTEXT_GUARD_CONFIG_PATH when omitted
    cfg_file = tmp_path / "cg_config.json"
    cfg_file.write_text(json.dumps({"workspace_root": str(ws)}), encoding="utf-8")
    import os

    os.environ["CONTEXT_GUARD_CONFIG_PATH"] = str(cfg_file)
    try:
        install_all(plugin_root, claude, cursor, codex, toml)
    finally:
        os.environ.pop("CONTEXT_GUARD_CONFIG_PATH", None)
    assert sum("claude_stop_guard.py --claude-hook" in c for c in _commands(claude, "Stop")) == 1
    assert sum("claude_stop_guard.py --cursor-hook" in c for c in _commands(cursor, "stop")) == 1


