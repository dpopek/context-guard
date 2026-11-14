"""Cycle-free harness registration status detector and matcher constants."""

from __future__ import annotations

import sys
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

from hooks.local_repo_guard import BIGQUERY_MCP_SERVERS  # noqa: E402

DEFAULT_CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"
DEFAULT_CURSOR_HOOKS = Path.home() / ".cursor" / "hooks.json"
DEFAULT_CODEX_HOOKS = Path.home() / ".codex" / "hooks.json"

_BQ_SERVERS_SORTED = tuple(sorted(BIGQUERY_MCP_SERVERS))
_BQ_MCP_PATTERNS = "|".join(f"mcp__{srv}__.*" for srv in _BQ_SERVERS_SORTED)
_BQ_CURSOR_COLON_PATTERNS = "|".join(f"MCP:{srv}:.*" for srv in _BQ_SERVERS_SORTED)

CLAUDE_MATCHER = (
    f"Read|NotebookRead|Edit|MultiEdit|Write|NotebookEdit|Bash|mcp__gitlab__.*|{_BQ_MCP_PATTERNS}"
)
CURSOR_MATCHER = (
    f"Shell|Read|Edit|Write|StrReplace|MultiStrReplace|EditFile|WriteFile|DeleteFile|"
    f"read_file|edit_file|write_file|run_terminal_cmd|"
    f"MCP:gitlab:.*|{_BQ_CURSOR_COLON_PATTERNS}|mcp__gitlab__.*|{_BQ_MCP_PATTERNS}"
)
CODEX_MATCHER = f"^(Bash|shell|exec_command|exec|apply_patch|mcp__gitlab__.*|{_BQ_MCP_PATTERNS})$"


def check_status(
    claude_settings_path: Path | None = None,
    cursor_hooks_path: Path | None = None,
    codex_hooks_path: Path | None = None,
) -> dict[str, bool]:
    """Return whether Context-Guard is installed in each harness config."""
    claude_path = claude_settings_path if claude_settings_path is not None else DEFAULT_CLAUDE_SETTINGS
    cursor_path = cursor_hooks_path if cursor_hooks_path is not None else DEFAULT_CURSOR_HOOKS
    codex_path = codex_hooks_path if codex_hooks_path is not None else DEFAULT_CODEX_HOOKS
    result: dict[str, bool] = {}
    for name, path in (
        ("claude", claude_path),
        ("cursor", cursor_path),
        ("codex", codex_path),
    ):
        if not path.exists():
            result[name] = False
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            result[name] = False
            continue
        result[name] = ("/hooks/pre_tool_use.py" in text) or ("\\hooks\\pre_tool_use.py" in text)
    return result
