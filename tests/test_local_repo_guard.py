"""Hermetic unit tests for configurable Local-First GitLab & BigQuery guards."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hooks import state_store
from hooks.local_repo_guard import load_guard_config
from hooks.pre_tool_use import evaluate_hook
from hooks.telemetry import load_telemetry_stats


@pytest.fixture
def guard_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    state_dir = str(tmp_path / "state")
    repo_map_path = tmp_path / "local_repository_map.json"
    config_path = tmp_path / "config.json"

    repo_map_path.write_text(
        json.dumps(
            {
                "repositories": [
                    {
                        "name": "payments_service",
                        "canonical_name": "payments_service",
                        "category": "backend",
                        "relative_path": "services/payments_service",
                        "remote_slug": "acme-corp/backend/payments_service",
                    },
                    {
                        "name": "storefront-backend",
                        "canonical_name": "storefront-backend",
                        "category": "commerce",
                        "relative_path": "commerce/storefront/backend",
                        "remote_slug": "acme-corp/commerce/storefront/backend",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    config_path.write_text(
        json.dumps(
            {
                "workspace_root": str(tmp_path / "workspace"),
                "repo_map_path": str(repo_map_path),
                "repo_map_doc": str(tmp_path / "workspace/docs/local_repository_map.md"),
                "restricted_bq_datasets": ["raw_warehouse", "raw_events"],
                "allowed_bq_views_dataset": "analytics_views",
                "allowed_bq_views_hint": "analytics_views.v_orders, analytics_views.v_order_items",
                "bq_schema_doc": str(tmp_path / "workspace/docs/bigquery_views_schema.md"),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(config_path))
    return tmp_path, state_dir


def _bq_payload(query: str, tool: str = "execute_sql") -> dict[str, Any]:
    return {
        "toolCall": {
            "name": "call_mcp_tool",
            "args": {
                "ServerName": "bigquery",
                "ToolName": tool,
                "Arguments": {"query": query},
            },
        }
    }


def test_unconfigured_or_malformed_config_allows_gitlab_and_bigquery_immediately(
    guard_env: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, state_dir = guard_env
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(root / "nonexistent_config.json"))
    cfg = load_guard_config()
    assert cfg["restricted_bq_datasets"] == ()
    assert cfg["repo_map_path"] is None

    dec_gl = evaluate_hook(
        {
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "gitlab",
                    "ToolName": "search_repositories",
                    "Arguments": {"search": "payments_service"},
                },
            }
        },
        state_dir=state_dir,
    )
    assert dec_gl["decision"] == "allow"

    dec_bq = evaluate_hook(
        {
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "bigquery",
                    "ToolName": "execute_sql_readonly",
                    "Arguments": {"query": "SELECT * FROM raw_warehouse.orders LIMIT 5"},
                },
            }
        },
        state_dir=state_dir,
    )
    assert dec_bq["decision"] == "allow"

    bad_cfg_path = root / "malformed.json"
    bad_cfg_path.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(bad_cfg_path))
    bad_cfg = load_guard_config()
    assert bad_cfg["restricted_bq_datasets"] == ()
    assert bad_cfg["repo_map_path"] is None


def test_gitlab_search_matching_local_repo_blocked_on_first_call_with_exact_local_path(
    guard_env: tuple[Path, str],
) -> None:
    _root, state_dir = guard_env
    payload = {
        "toolCall": {
            "name": "call_mcp_tool",
            "args": {
                "ServerName": "gitlab",
                "ToolName": "search_repositories",
                "Arguments": {"search": "payments_service"},
            },
        }
    }
    first = evaluate_hook(payload, state_dir=state_dir)
    assert first["decision"] == "deny"
    assert "LOCAL-FIRST BLOCK" in first["reason"]
    assert "services/payments_service" in first["reason"]
    assert "repos/backend/payments_service" in first["reason"]

    second = evaluate_hook(payload, state_dir=state_dir)
    assert second["decision"] == "allow"


def test_gitlab_get_file_contents_for_known_slug_blocked_first_then_allowed_on_retry(
    guard_env: tuple[Path, str],
) -> None:
    _root, state_dir = guard_env
    payload = {
        "toolCall": {
            "name": "call_mcp_tool",
            "args": {
                "ServerName": "gitlab",
                "ToolName": "get_file_contents",
                "Arguments": {
                    "project_id": "acme-corp/commerce/storefront/backend",
                    "file_path": "composer.json",
                },
            },
        }
    }
    first = evaluate_hook(payload, state_dir=state_dir)
    assert first["decision"] == "deny"
    assert "commerce/storefront/backend" in first["reason"]
    assert "repos/commerce/storefront-backend" in first["reason"]

    second = evaluate_hook(payload, state_dir=state_dir)
    assert second["decision"] == "allow"


def test_gitlab_unknown_repo_blocked_if_no_local_check_performed_yet_then_allowed(
    guard_env: tuple[Path, str],
) -> None:
    _root, state_dir = guard_env
    payload = {
        "toolCall": {
            "name": "call_mcp_tool",
            "args": {
                "ServerName": "gitlab",
                "ToolName": "get_project",
                "Arguments": {"project_id": "external-org/nonexistent-remote-repo-xyz"},
            },
        }
    }
    first = evaluate_hook(payload, state_dir=state_dir)
    assert first["decision"] == "deny"
    assert "local_repository_map.md" in first["reason"]

    second = evaluate_hook(payload, state_dir=state_dir)
    assert second["decision"] == "allow"


def test_gitlab_unknown_repo_allowed_immediately_after_local_file_read(
    guard_env: tuple[Path, str],
) -> None:
    root, state_dir = guard_env
    sample_file = root / "local_check.md"
    sample_file.write_text("# Local repo check\n", encoding="utf-8")

    read_res = evaluate_hook(
        {
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(sample_file), "StartLine": 1, "EndLine": 1},
            }
        },
        state_dir=state_dir,
    )
    assert read_res["decision"] == "allow"

    gitlab_res = evaluate_hook(
        {
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "gitlab",
                    "ToolName": "get_project",
                    "Arguments": {"project_id": "external-org/brand-new-remote-repo"},
                },
            }
        },
        state_dir=state_dir,
    )
    assert gitlab_res["decision"] == "allow"


def test_gitlab_remote_only_tools_like_merge_requests_and_issues_always_allowed(
    guard_env: tuple[Path, str],
) -> None:
    _root, state_dir = guard_env
    for tool_name in ("get_merge_request_discussion", "list_issues", "my_issues", "whoami"):
        res = evaluate_hook(
            {
                "toolCall": {
                    "name": "call_mcp_tool",
                    "args": {
                        "ServerName": "gitlab",
                        "ToolName": tool_name,
                        "Arguments": {"project_id": "acme-corp/backend/payments_service"},
                    },
                }
            },
            state_dir=state_dir,
        )
        assert res["decision"] == "allow"


def test_bigquery_raw_table_query_blocked_first_then_allowed_on_retry(
    guard_env: tuple[Path, str],
) -> None:
    root, state_dir = guard_env
    payload = _bq_payload(
        "SELECT id, grand_total FROM `analytics-prod.raw_warehouse.orders` LIMIT 10",
        tool="execute_sql_readonly",
    )
    first = evaluate_hook(payload, state_dir=state_dir)
    assert first["decision"] == "deny"
    assert "BIGQUERY AI-VIEWS BLOCK" in first["reason"]
    assert "analytics_views.v_orders" in first["reason"]
    assert "allow_bq_raw_ddl_maintenance" in first["reason"]

    second = evaluate_hook(payload, state_dir=state_dir)
    assert second["decision"] == "deny"

    cfg_path = root / "config.json"
    cfg_data = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg_data["allow_bq_raw_ddl_maintenance"] = True
    cfg_path.write_text(json.dumps(cfg_data), encoding="utf-8")
    allowed = evaluate_hook(payload, state_dir=state_dir)
    assert allowed["decision"] == "allow"


def test_bigquery_ai_views_query_allowed_immediately(guard_env: tuple[Path, str]) -> None:
    _root, state_dir = guard_env
    safe_res = evaluate_hook(
        {
            "toolCall": {
                "name": "call_mcp_tool",
                "args": {
                    "ServerName": "data-agent-kit-plugin_dak-bigquery",
                    "ToolName": "execute_sql_readonly",
                    "Arguments": {
                        "query": "SELECT order_id, net_revenue_gbp FROM `analytics-prod.analytics_views.v_orders` LIMIT 10"
                    },
                },
            }
        },
        state_dir=state_dir,
    )
    assert safe_res["decision"] == "allow"


@pytest.mark.parametrize(
    "sql",
    [
        "CREATE OR REPLACE VIEW `analytics-prod.analytics_views.v_orders` AS "
        "SELECT id FROM `analytics-prod.raw_warehouse.orders`",
        "DROP SCHEMA `analytics-prod.raw_warehouse` CASCADE",
        "ALTER SCHEMA raw_events SET OPTIONS(default_table_expiration_days = 1)",
        "CREATE OR REPLACE VIEW analytics_views.v_ok AS SELECT 1; DROP TABLE raw_warehouse.orders",
        "TRUNCATE TABLE raw_events.clicks",
    ],
)
def test_bigquery_ddl_touching_restricted_datasets_blocked_first_then_allowed_on_retry(
    guard_env: tuple[Path, str], sql: str
) -> None:
    root, state_dir = guard_env
    first = evaluate_hook(_bq_payload(sql), state_dir=state_dir)
    assert first["decision"] == "deny"
    assert "BIGQUERY AI-VIEWS BLOCK" in first["reason"]
    second = evaluate_hook(_bq_payload(sql), state_dir=state_dir)
    assert second["decision"] == "deny"

    cfg_path = root / "config.json"
    cfg_data = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg_data["allow_bq_raw_ddl_maintenance"] = True
    cfg_path.write_text(json.dumps(cfg_data), encoding="utf-8")
    allowed = evaluate_hook(_bq_payload(sql), state_dir=state_dir)
    assert allowed["decision"] == "allow"


def test_gitlab_hatch_fails_open_when_the_retry_cannot_be_recorded(
    guard_env: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _state_dir = guard_env
    payloads = {
        "local match": {
            "ServerName": "gitlab",
            "ToolName": "get_file_contents",
            "Arguments": {
                "project_id": "acme-corp/commerce/storefront/backend",
                "file_path": "composer.json",
            },
        },
        "no local reads": {
            "ServerName": "gitlab",
            "ToolName": "get_project",
            "Arguments": {"project_id": "external-org/nonexistent-remote-repo-xyz"},
        },
    }

    def fail_replace(_src: str, _dst: str) -> None:
        raise OSError("simulated disk full")

    monkeypatch.setattr(state_store.os, "replace", fail_replace)
    for label, args in payloads.items():
        state_dir = str(root / f"state-hatch-{label.replace(' ', '-')}")
        payload = {"toolCall": {"name": "call_mcp_tool", "args": args}}
        res = evaluate_hook(payload, state_dir=state_dir)
        assert res["decision"] == "allow", f"Expected fail-open allow for {label}"


def test_bigquery_guard_drops_the_retry_promise_when_the_retry_cannot_be_recorded(
    guard_env: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _root, state_dir = guard_env
    payload = _bq_payload("SELECT id FROM `analytics-prod.raw_warehouse.orders` LIMIT 10")

    def fail_replace(_src: str, _dst: str) -> None:
        raise OSError("simulated disk full")

    monkeypatch.setattr(state_store.os, "replace", fail_replace)
    first = evaluate_hook(payload, state_dir=state_dir)
    second = evaluate_hook(payload, state_dir=state_dir)
    for res in (first, second):
        assert res["decision"] == "deny"
        assert "BIGQUERY AI-VIEWS BLOCK" in res["reason"]
        assert "allow_bq_raw_ddl_maintenance" in res["reason"]
        assert "repeat this exact BigQuery call" not in res["reason"]


def test_bigquery_guard_fails_closed_when_ledger_dir_cannot_be_created(
    guard_env: tuple[Path, str],
) -> None:
    root, _state_dir = guard_env
    blocker = root / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    state_dir = blocker / "state"

    res = evaluate_hook(
        _bq_payload("SELECT id FROM `analytics-prod.raw_warehouse.orders` LIMIT 10"),
        state_dir=str(state_dir),
    )

    assert res["decision"] == "deny"
    assert "BIGQUERY AI-VIEWS BLOCK" in res["reason"]
    assert "analytics_views.v_orders" in res["reason"]
    assert "allow_bq_raw_ddl_maintenance" in res["reason"]
    assert "repeat this exact BigQuery call" not in res["reason"]


def test_bigquery_guard_deny_is_counted_without_claiming_bytes(
    guard_env: tuple[Path, str],
) -> None:
    root, _state_dir = guard_env
    state_dir = root / "state-bq-telemetry"
    res = evaluate_hook(
        _bq_payload("SELECT id FROM `analytics-prod.raw_warehouse.orders` LIMIT 10"),
        state_dir=str(state_dir),
    )

    assert res["decision"] == "deny"
    stats = load_telemetry_stats(state_dir / "telemetry_stats.json")
    assert stats["events"]["mcp_guards"] == 1
    assert stats["baseline_bytes"] == 0
    assert stats["saved_bytes"] == 0
    assert "last_event" not in stats


def test_legacy_optimizer_keys_in_config_are_silently_ignored(
    guard_env: tuple[Path, str],
) -> None:
    root, _state_dir = guard_env
    missing_cfg = load_guard_config(root / "nonexistent_cfg.json")
    assert missing_cfg["config_error"] is None

    legacy_cfg = root / "legacy_cfg.json"
    legacy_cfg.write_text(
        json.dumps(
            {
                "wide_followup_limit": -1,
                "instruction_file_bypass_lines": "bad",
                "codex_multi_file_max_bytes": 9999,
                "outline_block_min_bytes": "invalid",
                "enforcement": {"outline": "warn", "reread": "block"},
            }
        ),
        encoding="utf-8",
    )
    loaded = load_guard_config(legacy_cfg)
    assert loaded["config_error"] is None
    assert "optimizer_config_error" not in loaded
    assert "enforcement" not in loaded
    assert "wide_followup_limit" not in loaded


def test_backtick_and_double_quoted_restricted_dataset_blocked_on_first_attempt(
    tmp_path: Path,
) -> None:
    from hooks.local_repo_guard import gate_bigquery_ai_views

    cfg = tmp_path / "config.json"
    cfg.write_text(
        json.dumps(
            {
                "restricted_bq_datasets": ["restricted_sales_raw"],
                "allowed_bq_views_dataset": "curated_views",
            }
        ),
        encoding="utf-8",
    )
    state_dir = tmp_path / "state"

    q_backtick = "SELECT * FROM `restricted_sales_raw`.`orders` LIMIT 5"
    res1 = gate_bigquery_ai_views(state_dir, "execute_sql_readonly", q_backtick, config_path=cfg)
    assert res1["decision"] == "deny"
    res2 = gate_bigquery_ai_views(state_dir, "execute_sql_readonly", q_backtick, config_path=cfg)
    assert res2["decision"] == "deny"

    q_proj_backtick = "SELECT * FROM `sample-proj`.`restricted_sales_raw`.`orders` LIMIT 5"
    res3 = gate_bigquery_ai_views(
        state_dir, "execute_sql_readonly", q_proj_backtick, config_path=cfg
    )
    assert res3["decision"] == "deny"

    q_double_quote = 'SELECT * FROM "restricted_sales_raw"."orders" LIMIT 5'
    res4 = gate_bigquery_ai_views(state_dir, "execute_sql", q_double_quote, config_path=cfg)
    assert res4["decision"] == "deny"


def test_non_bigquery_mcp_execute_sql_is_not_captured_by_bq_gate(
    tmp_path: Path,
) -> None:
    from hooks.local_repo_guard import (
        BIGQUERY_MCP_SERVERS,
        extract_bigquery_sql_target,
        is_bigquery_sql_tool_call,
    )

    state_dir = str(tmp_path / "state")
    for non_bq_tool in (
        "mcp_postgres_execute_sql",
        "mcp__supabase__execute_sql_readonly",
        "MCP:snowflake:execute_sql",
    ):
        assert is_bigquery_sql_tool_call(non_bq_tool, {}) is False
        assert extract_bigquery_sql_target(non_bq_tool, {"query": "SELECT 1"}) is None

    ag_res = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 1,
            "toolCall": {"name": "mcp_postgres_execute_sql", "args": {}},
        },
        state_dir=state_dir,
    )
    assert ag_res == {"decision": "allow"}

    cl_res = evaluate_hook(
        {"session_id": "s1", "tool_name": "mcp__supabase__execute_sql", "tool_input": {}},
        state_dir=state_dir,
        cli_harness="claude",
    )
    assert cl_res == {}

    for srv in BIGQUERY_MCP_SERVERS:
        for tool_name in (
            f"mcp_{srv}_execute_sql",
            f"mcp__{srv}__execute_sql_readonly",
            f"MCP:{srv}:execute_sql",
        ):
            assert is_bigquery_sql_tool_call(tool_name, {}) is True
            assert extract_bigquery_sql_target(tool_name, {"query": "SELECT 1"}) is not None


def test_cursor_and_claude_matchers_cover_all_bq_servers_and_notebook_read() -> None:
    import re
    from bin.install_harnesses import CLAUDE_MATCHER, CURSOR_MATCHER
    from hooks.local_repo_guard import BIGQUERY_MCP_SERVERS

    for srv in BIGQUERY_MCP_SERVERS:
        assert re.search(CURSOR_MATCHER, f"MCP:{srv}:execute_sql_readonly") is not None
        assert re.search(CURSOR_MATCHER, f"mcp__{srv}__execute_sql") is not None
        assert re.search(CLAUDE_MATCHER, f"mcp__{srv}__execute_sql_readonly") is not None
    assert re.search(CLAUDE_MATCHER, "NotebookRead") is not None


def test_uppercase_mcp_bigquery_prefix_matched_case_insensitively() -> None:
    from hooks.local_repo_guard import extract_bigquery_sql_target, is_bigquery_sql_tool_call

    for tool_name in ("MCP_bigquery_execute_sql", "MCP__bigquery__execute_sql_readonly"):
        assert is_bigquery_sql_tool_call(tool_name, {}) is True
        assert extract_bigquery_sql_target(tool_name, {"query": "SELECT 1"}) == (
            tool_name.split("bigquery")[-1].lstrip("_"),
            "SELECT 1",
        )


def test_config_cache_avoids_redundant_reads_and_invalidates_on_file_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import os
    from hooks import config as guard_config, local_repo_guard, model_identity

    guard_config.clear_config_cache()
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(
        json.dumps(
            {
                "allowed_bq_views_dataset": "ai_views_v1",
                "model_labels": {"claude": "claude-opus-4-6"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CONTEXT_GUARD_CONFIG_PATH", str(cfg_file))
    monkeypatch.setattr(model_identity, "GUARD_CONFIG_PATH", None)

    target_realpath = os.path.realpath(cfg_file)
    orig_read_text = Path.read_text
    disk_reads = 0

    def _counted_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        nonlocal disk_reads
        if os.path.realpath(self) == target_realpath:
            disk_reads += 1
        return orig_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _counted_read_text)

    first = guard_config.cached_raw_config()
    assert first == {"allowed_bq_views_dataset": "ai_views_v1", "model_labels": {"claude": "claude-opus-4-6"}}
    assert disk_reads == 1

    first["allowed_bq_views_dataset"] = "mutated_caller_copy"
    assert guard_config.cached_raw_config() == {
        "allowed_bq_views_dataset": "ai_views_v1",
        "model_labels": {"claude": "claude-opus-4-6"},
    }
    assert local_repo_guard.load_guard_config()["allowed_bq_views_dataset"] == "ai_views_v1"
    assert local_repo_guard.load_guard_config()["allowed_bq_views_dataset"] == "ai_views_v1"
    assert model_identity.pinned_model("claude") == "claude-opus-4-6"
    assert model_identity.pinned_model("claude") == "claude-opus-4-6"
    assert disk_reads == 1

    st_before = os.stat(cfg_file)
    cfg_file.write_text(
        json.dumps({"allowed_bq_views_dataset": "ai_views_v2"}),
        encoding="utf-8",
    )
    os.utime(cfg_file, ns=(st_before.st_atime_ns, st_before.st_mtime_ns))
    assert local_repo_guard.load_guard_config()["allowed_bq_views_dataset"] == "ai_views_v2"
    assert disk_reads == 2
    assert local_repo_guard.load_guard_config()["allowed_bq_views_dataset"] == "ai_views_v2"
    assert disk_reads == 2

    st_mid = os.stat(cfg_file)
    same_len_payload = json.dumps({"allowed_bq_views_dataset": "ai_views_v3"})
    assert len(same_len_payload.encode("utf-8")) == st_mid.st_size
    cfg_file.write_text(same_len_payload, encoding="utf-8")
    os.utime(cfg_file, ns=(st_mid.st_atime_ns, st_mid.st_mtime_ns + 1_000_000))
    assert local_repo_guard.load_guard_config()["allowed_bq_views_dataset"] == "ai_views_v3"
    assert disk_reads == 3

    capsys.readouterr()
    cfg_file.write_text("{corrupt-json", encoding="utf-8")
    assert guard_config.cached_raw_config() is None
    err_first = capsys.readouterr().err
    assert "context-guard" in err_first.lower()
    assert disk_reads == 4
    assert local_repo_guard.load_guard_config()["config_error"] == "invalid JSON syntax"
    assert capsys.readouterr().err == ""
    assert disk_reads == 4

    cfg_file.unlink()
    assert guard_config.cached_raw_config() is None
    deleted_cfg = local_repo_guard.load_guard_config()
    assert deleted_cfg["config_error"] is None
    assert deleted_cfg["allowed_bq_views_dataset"] == ""
    assert capsys.readouterr().err == ""
    assert disk_reads == 4

    monkeypatch.delenv("CONTEXT_GUARD_CONFIG_PATH", raising=False)
    alt_cfg = tmp_path / "alt_default_config.json"
    alt_cfg.write_text(json.dumps({"allowed_bq_views_dataset": "ai_views_alt"}), encoding="utf-8")
    monkeypatch.setattr(local_repo_guard, "DEFAULT_USER_CONFIG_PATH", alt_cfg)
    assert local_repo_guard.load_guard_config()["allowed_bq_views_dataset"] == "ai_views_alt"


def test_resolve_user_config_path_supports_xdg_and_windows_appdata(tmp_path: Path) -> None:
    from hooks import config as guard_config
    from hooks import local_repo_guard

    home = tmp_path / "home"
    xdg = tmp_path / "xdg"
    appdata = tmp_path / "appdata"
    home.mkdir()
    xdg.mkdir()
    appdata.mkdir()

    # Default falls back to ~/.config/context-guard/config.json when none exist
    assert guard_config.resolve_user_config_path(home=home, env={}, os_name="posix") == (
        home / ".config" / "context-guard" / "config.json"
    )

    # Linux XDG_CONFIG_HOME is used when present on disk and ~/.config does not exist
    xdg_cfg = xdg / "context-guard" / "config.json"
    xdg_cfg.parent.mkdir(parents=True)
    xdg_cfg.write_text("{}", encoding="utf-8")
    assert (
        guard_config.resolve_user_config_path(
            home=home, env={"XDG_CONFIG_HOME": str(xdg)}, os_name="posix"
        )
        == xdg_cfg
    )

    # Windows APPDATA is used on nt when ~/.config does not exist
    win_cfg = appdata / "context-guard" / "config.json"
    win_cfg.parent.mkdir(parents=True)
    win_cfg.write_text("{}", encoding="utf-8")
    assert (
        guard_config.resolve_user_config_path(
            home=home, env={"APPDATA": str(appdata)}, os_name="nt"
        )
        == win_cfg
    )

    # Windows backslash paths in local_repository_map and query_terms match cleanly
    repos = [
        {
            "name": "service-orders",
            "canonical_name": "service_orders",
            "relative_path": r"services\python\service_orders",
            "remote_slug": "commerce/services/service-orders",
        }
    ]
    matched = local_repo_guard.find_matching_local_repos(
        [r"services\python\service_orders"], repos
    )
    assert len(matched) == 1
    assert matched[0]["canonical_name"] == "service_orders"


def test_normalize_cmd_basename_handles_posix_windows_and_extensions() -> None:
    from hooks.file_io import normalize_cmd_basename

    assert normalize_cmd_basename("git") == "git"
    assert normalize_cmd_basename("/usr/bin/git") == "git"
    assert normalize_cmd_basename(r"C:\Windows\System32\CMD.EXE") == "cmd"
    assert normalize_cmd_basename(r"C:\tools\cg-outline.cmd") == "cg-outline"
    assert normalize_cmd_basename("PYTEST.BAT") == "pytest"
    assert normalize_cmd_basename("python3.11.exe") == "python3.11"
    assert normalize_cmd_basename("") == ""


def test_hooks_json_matcher_covers_gitlab_and_all_bigquery_mcp_servers() -> None:
    import re
    from hooks.local_repo_guard import BIGQUERY_MCP_SERVERS

    hooks_cfg = json.loads((Path(__file__).resolve().parent.parent / "hooks.json").read_text(encoding="utf-8"))
    pre_tool = hooks_cfg["context-guard"]["PreToolUse"][0]
    matcher = pre_tool["matcher"]
    assert pre_tool["hooks"][0]["command"] == "python3 ./hooks/pre_tool_use.py"
    assert re.fullmatch(matcher, "mcp_gitlab_search_repositories") is not None
    for srv in BIGQUERY_MCP_SERVERS:
        assert re.fullmatch(matcher, f"mcp_{srv}_execute_sql") is not None
        assert re.fullmatch(matcher, f"mcp_{srv}_execute_sql_readonly") is not None


def test_strip_sql_comments_handles_googlesql_prefixes_escapes_and_comments(tmp_path: Path) -> None:
    from hooks.local_repo_guard import gate_bigquery_ai_views, strip_sql_comments

    cfg = tmp_path / "config.json"
    cfg.write_text(
        json.dumps({"restricted_bq_datasets": ["raw_orders"], "allowed_bq_views_dataset": "ai_views"}),
        encoding="utf-8",
    )
    state_dir = tmp_path / "state"

    # Comments outside literals are stripped (replaced with spaces)
    safe_sql = (
        "SELECT * FROM ai_views.v_orders\n"
        "-- SELECT * FROM raw_orders.orders\n"
        "# SELECT * FROM raw_orders.orders\n"
        "/* raw_orders.orders */"
    )
    cleaned_safe = strip_sql_comments(safe_sql)
    assert "raw_orders" not in cleaned_safe
    assert gate_bigquery_ai_views(state_dir, "execute_sql_readonly", safe_sql, config_path=cfg)["decision"] == "allow"

    # Quoted literals (including raw/bytes prefixes, escaped backslashes, triple quotes, backticks)
    # must not open/close on '--', '#', '/*', or '\\' and hide subsequent raw_orders references.
    bypass_queries = (
        "SELECT '-- not comment' FROM raw_orders.orders",
        'SELECT "-- not comment" FROM raw_orders.orders',
        "SELECT '/*' FROM raw_orders.orders WHERE x = '*/'",
        r"SELECT '\\' FROM raw_orders.orders",
        r"SELECT r'\\' FROM raw_orders.orders",
        r'SELECT R"\\" FROM raw_orders.orders',
        r"SELECT rb'\\', br'\\' FROM raw_orders.orders",
        r"SELECT r'\'' FROM raw_orders.orders",
        "SELECT '''-- keep\n/* keep */''' FROM raw_orders.orders",
        'SELECT R"""# keep\n-- keep""" FROM raw_orders.orders',
        r"SELECT `col\\` FROM raw_orders.orders",
    )
    for sql in bypass_queries:
        res = gate_bigquery_ai_views(state_dir, "execute_sql_readonly", sql, config_path=cfg)
        assert res["decision"] == "deny", f"Bypass query unexpectedly allowed: {sql!r}"

