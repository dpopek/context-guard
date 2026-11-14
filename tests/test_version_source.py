"""The release version lives in the manifests only; code and tests read it from there."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

from hooks.local_repo_guard import load_guard_config

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_CONFIG_KEYS = tuple(
    k for k in load_guard_config(Path("/nonexistent_cfg.json")) if k != "config_error"
)


def _manifest_version(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["version"]


def _extract_cli_flags(script_path: Path) -> list[str]:
    tree = ast.parse(script_path.read_text(encoding="utf-8"), filename=str(script_path))
    flags: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ):
            for arg in node.args:
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and arg.value.startswith("--")
                ):
                    flags.append(arg.value)
    return sorted(set(flags))


def test_extension_manifest_matches_plugin_manifest() -> None:
    assert _manifest_version(ROOT / "vscode-extension" / "package.json") == _manifest_version(
        ROOT / "plugin.json"
    )


def test_no_version_literal_outside_the_manifests() -> None:
    version = _manifest_version(ROOT / "plugin.json")
    sources = [
        *ROOT.glob("hooks/*.py"),
        *ROOT.glob("bin/*.py"),
        *ROOT.glob("tests/*.py"),
        *ROOT.glob("vscode-extension/*.js"),
    ]
    hits = [
        f"{path.relative_to(ROOT)}:{lineno}"
        for path in sorted(sources)
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if version in line
    ]
    assert hits == []


def test_readme_version_modules_flags_and_config_stay_in_sync() -> None:
    version = _manifest_version(ROOT / "plugin.json")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    ext_readme = (ROOT / "vscode-extension" / "README.md").read_text(encoding="utf-8")

    assert f"# Context-Guard (v{version})" in readme
    assert f"advox.context-guard-statusbar-{version}" in readme
    assert f"context-guard-v{version}.zip" in readme

    production_modules = sorted(
        path.name
        for pattern in ("hooks/*.py", "bin/*.py", "vscode-extension/*.js")
        for path in ROOT.glob(pattern)
        if path.name != "__init__.py"
    )
    missing_modules = [mod for mod in production_modules if mod not in readme]
    assert missing_modules == [], f"Undocumented modules in README.md: {missing_modules}"

    for script in (ROOT / "bin" / "cg_status.py", ROOT / "bin" / "install_harnesses.py"):
        missing_flags = [flag for flag in _extract_cli_flags(script) if flag not in readme]
        assert missing_flags == [], f"Undocumented CLI flags from {script.name} in README.md: {missing_flags}"

    for ext_flag in (
        "--short",
        "--markdown",
        "--json",
        "--outcomes",
        "--usage",
        "--claude-hud",
        "--install",
        "--uninstall",
        "--status",
        "--dry-run",
    ):
        assert ext_flag in ext_readme, f"Missing CLI flag {ext_flag} in vscode-extension/README.md"

    missing_cfg = [key for key in REQUIRED_CONFIG_KEYS if f'"{key}"' not in readme and f"`{key}`" not in readme]
    assert missing_cfg == [], f"Undocumented config.json keys in README.md: {missing_cfg}"


def test_readme_and_plugin_description_conciseness_budgets() -> None:
    readme_path = ROOT / "README.md"
    ext_readme_path = ROOT / "vscode-extension" / "README.md"
    changelog_path = ROOT / "CHANGELOG.md"
    plugin_json = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
    version = plugin_json["version"]

    readme_bytes = readme_path.read_bytes()
    ext_readme_bytes = ext_readme_path.read_bytes()
    assert len(readme_bytes) <= 18_000, f"README.md exceeds 18 KB conciseness budget ({len(readme_bytes)} B)"
    assert len(ext_readme_bytes) <= 6_500, (
        f"vscode-extension/README.md exceeds 6.5 KB conciseness budget ({len(ext_readme_bytes)} B)"
    )

    for doc_path in (readme_path, ext_readme_path):
        long_bullets = [
            f"{doc_path.relative_to(ROOT)}:{lineno} ({len(line)} chars)"
            for lineno, line in enumerate(doc_path.read_text(encoding="utf-8").splitlines(), 1)
            if line.lstrip().startswith("- ") and len(line) > 220
        ]
        assert long_bullets == [], f"Markdown bullets exceed 220 chars: {long_bullets}"

    changelog = changelog_path.read_text(encoding="utf-8")
    assert f"## [{version}]" in changelog
    long_changelog_bullets = [
        f"CHANGELOG.md:{lineno} ({len(line)} chars)"
        for lineno, line in enumerate(changelog.splitlines(), 1)
        if line.lstrip().startswith("- ") and len(line) > 140
    ]
    assert long_changelog_bullets == [], f"CHANGELOG bullets exceed 140 chars: {long_changelog_bullets}"

    desc = plugin_json.get("description", "")
    assert 80 <= len(desc) <= 300, f"plugin.json description should be 80..300 chars, got {len(desc)}"

    for hook_name in ("pre-commit", "pre-push"):
        hook_path = ROOT / ".githooks" / hook_name
        assert hook_path.is_file(), f"Missing .githooks/{hook_name} guard hook"
        assert os.access(hook_path, os.X_OK), f".githooks/{hook_name} must be executable"
    pre_commit_text = (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    assert "tests/test_version_source.py" in pre_commit_text
    assert "tests/test_module_boundaries.py" in pre_commit_text



def test_plugin_manifests_are_portable_and_valid() -> None:
    plugin_json = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
    assert plugin_json.get("name") == "context-guard"
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{plugin_json['version']}]" in changelog
    bullet_lines = [line for line in changelog.splitlines() if line.lstrip().startswith("- ")]
    assert len(bullet_lines) >= 20
    for line in bullet_lines:
        assert len(line) <= 140, (
            f"CHANGELOG bullet exceeds 140 chars (keep entries concise/headline-style): {line!r}"
        )

    hooks_raw = (ROOT / "hooks.json").read_text(encoding="utf-8")
    assert "/Users/" not in hooks_raw
    assert "/home/" not in hooks_raw
    hooks_json = json.loads(hooks_raw)
    pre_inv_cmd = hooks_json["context-guard"]["PreInvocation"][0]["command"]
    pre_tool_cmd = hooks_json["context-guard"]["PreToolUse"][0]["hooks"][0]["command"]
    assert pre_inv_cmd == "python3 ./hooks/pre_invocation.py"
    assert pre_tool_cmd == "python3 ./hooks/pre_tool_use.py"
    assert (ROOT / "README.md").is_file()
