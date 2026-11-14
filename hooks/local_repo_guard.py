"""Local-First GitLab MCP and BigQuery views guards for Context-Guard PreToolUse hook."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from hooks.config import DEFAULT_USER_CONFIG_PATH, KNOWN_HARNESSES, cached_raw_config_status
from hooks.state_store import StateTxn, locked_state

GITLAB_REPO_LOOKUP_TOOLS = frozenset({
    "search_repositories", "list_projects", "get_project", "get_repository_tree",
    "get_file_contents", "get_branch", "list_branches", "get_commit", "get_file_blame",
})
BIGQUERY_MCP_SERVERS = frozenset({"bigquery", "data-agent-kit-plugin_dak-bigquery", "datacloud_bigquery_remote"})
BIGQUERY_SQL_TOOLS = frozenset({"execute_sql_readonly", "execute_sql"})


def load_guard_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load optional workspace and BigQuery guard configuration from disk or env."""
    default_cfg: dict[str, Any] = {
        "workspace_root": None, "repo_map_path": None, "repo_map_doc": "",
        "restricted_bq_datasets": (), "allowed_bq_views_dataset": "", "allowed_bq_views_hint": "",
        "bq_schema_doc": "", "allow_bq_raw_ddl_maintenance": False,
        "allow_governance_mutations": False, "enforce_governance_policy": False,
        "model_labels": {}, "config_error": None,
    }
    raw, config_err = cached_raw_config_status(config_path, default_path=DEFAULT_USER_CONFIG_PATH)
    if config_err is not None:
        return {**default_cfg, "config_error": config_err}
    if raw is None:
        return default_cfg

    if "restricted_bq_datasets" in raw and raw["restricted_bq_datasets"] is not None:
        rds = raw["restricted_bq_datasets"]
        if not isinstance(rds, list) or any(not isinstance(d, str) or not d.strip() for d in rds):
            return {**default_cfg, "config_error": "invalid 'restricted_bq_datasets': expected list of non-empty strings"}
    for str_key in (
        "allowed_bq_views_dataset", "allowed_bq_views_hint", "bq_schema_doc",
        "workspace_root", "repo_map_path", "repo_map_doc",
    ):
        if str_key in raw and raw[str_key] is not None and not isinstance(raw[str_key], str):
            return {**default_cfg, "config_error": f"invalid '{str_key}': expected string"}
    for bool_key in ("allow_bq_raw_ddl_maintenance", "allow_governance_mutations", "enforce_governance_policy"):
        if bool_key in raw and raw[bool_key] is not None and not isinstance(raw[bool_key], bool):
            return {**default_cfg, "config_error": f"invalid '{bool_key}': expected boolean"}

    ws_raw, map_raw, doc_raw = raw.get("workspace_root"), raw.get("repo_map_path"), raw.get("repo_map_doc")
    workspace_root = Path(ws_raw).expanduser() if isinstance(ws_raw, str) and ws_raw.strip() else None
    repo_map_path = (
        Path(map_raw).expanduser() if isinstance(map_raw, str) and map_raw.strip()
        else (workspace_root / "docs" / "local_repository_map.json" if workspace_root else None)
    )
    repo_map_doc = (
        doc_raw.strip() if isinstance(doc_raw, str) and doc_raw.strip()
        else (str(workspace_root / "docs" / "local_repository_map.md") if workspace_root else "")
    )
    raw_datasets = raw.get("restricted_bq_datasets")
    restricted_bq_datasets = tuple(d.strip() for d in raw_datasets if isinstance(d, str) and d.strip()) if isinstance(raw_datasets, list) else ()
    views_ds, views_hint = raw.get("allowed_bq_views_dataset"), raw.get("allowed_bq_views_hint")
    allowed_bq_views_dataset = views_ds.strip() if isinstance(views_ds, str) else ""
    allowed_bq_views_hint = (
        views_hint.strip() if isinstance(views_hint, str) and views_hint.strip()
        else (f"{allowed_bq_views_dataset}.*" if allowed_bq_views_dataset else "authorized views")
    )
    schema_raw, labels_raw = raw.get("bq_schema_doc"), raw.get("model_labels")
    bq_schema_doc = schema_raw.strip() if isinstance(schema_raw, str) else ""
    model_labels = (
        {h: v.strip() for h, v in labels_raw.items() if h in KNOWN_HARNESSES and isinstance(v, str) and v.strip()}
        if isinstance(labels_raw, dict) else {}
    )
    return {
        "workspace_root": workspace_root, "repo_map_path": repo_map_path, "repo_map_doc": repo_map_doc,
        "restricted_bq_datasets": restricted_bq_datasets, "allowed_bq_views_dataset": allowed_bq_views_dataset,
        "allowed_bq_views_hint": allowed_bq_views_hint, "bq_schema_doc": bq_schema_doc,
        "allow_bq_raw_ddl_maintenance": raw.get("allow_bq_raw_ddl_maintenance") is True,
        "allow_governance_mutations": raw.get("allow_governance_mutations") is True,
        "enforce_governance_policy": raw.get("enforce_governance_policy") is True,
        "model_labels": model_labels, "config_error": None,
    }


def extract_gitlab_lookup_target(tool_name: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Return (gitlab_tool_name, tool_arguments) if tool_call is a GitLab repo/file lookup."""
    if tool_name == "call_mcp_tool":
        server = str(args.get("ServerName") or "").strip().lower()
        sub_tool = str(args.get("ToolName") or "").strip()
        if server != "gitlab" or sub_tool not in GITLAB_REPO_LOOKUP_TOOLS:
            return None
        sub_args = args.get("Arguments")
        return (sub_tool, sub_args if isinstance(sub_args, dict) else {})

    for prefix in ("mcp_gitlab_", "mcp__gitlab__", "MCP:gitlab:"):
        if tool_name.startswith(prefix):
            sub_tool = tool_name.removeprefix(prefix)
            if sub_tool in GITLAB_REPO_LOOKUP_TOOLS:
                return (sub_tool, args)

    return None


def _extract_query_terms(tool_args: dict[str, Any]) -> list[str]:
    terms: list[str] = []
    for key in ("project_id", "search", "query", "repository", "name", "path"):
        val = tool_args.get(key)
        if isinstance(val, str) and val.strip():
            terms.append(val.strip())
    return terms


def _load_local_repositories(map_path: Path | None) -> list[dict[str, Any]]:
    if map_path is None or not map_path.is_file():
        return []
    try:
        data = json.loads(map_path.read_text(encoding="utf-8"))
        repos = data.get("repositories") if isinstance(data, dict) else None
        return [r for r in repos if isinstance(r, dict)] if isinstance(repos, list) else []
    except (OSError, ValueError, TypeError):
        return []


GENERIC_REPO_BASENAMES = frozenset({
    "project", "backend", "frontend", "production", "stage", "test", "upgradetest",
    "maintenance", "image", "docker", "native", "meta", "charts", "ci-cd",
    "ci-cd.yml", "traefik", "docker-swarm", "kubernetes",
})


def find_matching_local_repos(query_terms: list[str], repos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Match query terms against local repository remote_slug, name, canonical_name, relative_path, and aliases."""
    if not query_terms or not repos:
        return []
    exact_matches: list[dict[str, Any]] = []
    substring_matches: list[dict[str, Any]] = []
    norm_terms = [t.replace("\\", "/").lower().strip("/").removesuffix(".git") for t in query_terms if t.strip()]
    if not norm_terms:
        return []

    for repo in repos:
        candidates: set[str] = set()
        for field in ("remote_slug", "name", "canonical_name", "relative_path"):
            raw = repo.get(field)
            if isinstance(raw, str) and raw.strip():
                val = raw.replace("\\", "/").lower().strip("/")
                if val not in GENERIC_REPO_BASENAMES:
                    candidates.add(val)
        aliases = repo.get("aliases")
        if isinstance(aliases, list):
            for alias in aliases:
                if isinstance(alias, str) and alias.strip():
                    val = alias.replace("\\", "/").lower().strip("/")
                    if val not in GENERIC_REPO_BASENAMES:
                        candidates.add(val)

        if any(term in candidates for term in norm_terms):
            exact_matches.append(repo)
            continue

        if any(
            len(term) >= 3
            and any(
                term in cand or (len(cand) >= 6 and "/" in cand and cand in term)
                for cand in candidates
            )
            for term in norm_terms
        ):
            substring_matches.append(repo)

    return exact_matches if exact_matches else substring_matches[:5]


def _record_retry_hatch(txn: StateTxn, allowed_list: list[Any], query_sig: str) -> bool:
    """Persist the signature a deny's "repeat this call" promise relies on; True when saved."""
    allowed_list.append(query_sig)
    return txn.save()


def gate_gitlab_local_first(
    state_dir_path: Path, gitlab_tool: str, tool_args: dict[str, Any],
    map_path: Path | None = None, config_path: Path | None = None,
) -> dict[str, Any]:
    """Enforce Local-First repository resolution before allowing GitLab MCP repo/file lookups."""
    cfg = load_guard_config(config_path)
    config_error = cfg.get("config_error")
    if isinstance(config_error, str) and config_error:
        return {"decision": "deny", "reason": f"CONTEXT-GUARD GITLAB CONFIG ERROR (fail-closed): {config_error}"}
    effective_map_path = map_path or cfg["repo_map_path"]
    repos = _load_local_repositories(effective_map_path)
    if not repos:
        return {"decision": "allow"}

    ws_root = cfg["workspace_root"] or (effective_map_path.parent.parent if effective_map_path else Path.cwd())
    repo_map_doc = cfg["repo_map_doc"] or str(effective_map_path)

    query_terms = _extract_query_terms(tool_args)
    query_sig = f"{gitlab_tool}:{','.join(sorted(t.lower() for t in query_terms)) or '*'}"

    try:
        with locked_state(state_dir_path) as txn:
            state = txn.state
            allowed_list = state.setdefault("gitlab_fallback_allowed", [])
            if not isinstance(allowed_list, list):
                allowed_list = []
                state["gitlab_fallback_allowed"] = allowed_list

            if query_sig in allowed_list:
                return {"decision": "allow"}

            matches = find_matching_local_repos(query_terms, repos)
            if matches:
                if not _record_retry_hatch(txn, allowed_list, query_sig):
                    # Unsaved, the promised retry would be denied again forever: fail open, like the OSError path below.
                    return {"decision": "allow"}
                formatted_matches = []
                for m in matches[:4]:
                    rel, cat = m.get("relative_path") or m.get("local_path"), m.get("category") or ""
                    canon, slug = m.get("canonical_name") or m.get("name"), m.get("remote_slug") or ""
                    formatted_matches.append(f"  - `{ws_root}/{rel}` (alias: `{ws_root}/repos/{cat}/{canon}`, remote: `{slug}`)")
                match_block = "\n".join(formatted_matches)
                return {
                    "decision": "deny",
                    "reason": (
                        f"CONTEXT-GUARD LOCAL-FIRST BLOCK: You called `gitlab.{gitlab_tool}` for "
                        f"{query_terms}, which ALREADY EXISTS LOCALLY on disk:\n"
                        f"{match_block}\n\n"
                        "MANDATORY: Inspect the local repository first using `read_file` or `grep`. "
                        "If you genuinely need remote-only GitLab state (e.g., an unfetched remote branch/commit), "
                        "repeat this exact `gitlab` tool call a second time to proceed as a fallback."
                    ),
                }

            has_local_reads = bool(state.get("files"))
            if not has_local_reads:
                if not _record_retry_hatch(txn, allowed_list, query_sig):
                    # Unsaved, the promised retry would be denied again forever: fail open,
                    # like the OSError path below.
                    return {"decision": "allow"}
                return {
                    "decision": "deny",
                    "reason": (
                        f"CONTEXT-GUARD LOCAL-FIRST BLOCK: You called `gitlab.{gitlab_tool}` before checking "
                        f"local repositories in `{ws_root}`.\n"
                        f"1. Check `{repo_map_doc}` or `{ws_root}/repos/` first.\n"
                        "2. If the repository truly does not exist on disk, repeat this `gitlab` call to query GitLab remotely."
                    ),
                }

            return {"decision": "allow"}
    except OSError:
        return {"decision": "allow"}


def _match_eager_bigquery_sql_tool(tool_name: str) -> str | None:
    """Return the BigQuery SQL sub-tool name when `tool_name` targets a known BigQuery MCP server."""
    tool_low = tool_name.lower()
    if not tool_low.startswith(("mcp_", "mcp:")):
        return None
    for srv in BIGQUERY_MCP_SERVERS:
        for prefix_low in (f"mcp_{srv}_", f"mcp__{srv}__", f"mcp:{srv}:"):
            if tool_low.startswith(prefix_low):
                sub_tool = tool_low[len(prefix_low) :]
                if sub_tool in BIGQUERY_SQL_TOOLS:
                    return sub_tool
    return None


def is_bigquery_sql_tool_call(tool_name: str, args: Any) -> bool:
    """Return True if tool_name/args targets a BigQuery SQL execution tool, regardless of argument validity."""
    if tool_name == "call_mcp_tool":
        if not isinstance(args, dict):
            return False
        server = str(args.get("ServerName") or "").strip().lower()
        sub_tool = str(args.get("ToolName") or "").strip()
        return server in BIGQUERY_MCP_SERVERS and sub_tool in BIGQUERY_SQL_TOOLS

    return _match_eager_bigquery_sql_tool(tool_name) is not None


def extract_bigquery_sql_target(tool_name: str, args: dict[str, Any]) -> tuple[str, str] | None:
    """Return (bq_tool_name, sql_query) if tool_call is a BigQuery SQL execution."""
    if tool_name == "call_mcp_tool":
        server = str(args.get("ServerName") or "").strip().lower()
        sub_tool = str(args.get("ToolName") or "").strip()
        if server not in BIGQUERY_MCP_SERVERS or sub_tool not in BIGQUERY_SQL_TOOLS:
            return None
        sub_args = args.get("Arguments")
        if not isinstance(sub_args, dict):
            return None
        raw_sql = sub_args.get("query") or sub_args.get("sql")
        if isinstance(raw_sql, str) and raw_sql.strip():
            return (sub_tool, raw_sql.strip())
        return None

    sql_tool = _match_eager_bigquery_sql_tool(tool_name)
    if sql_tool is not None:
        raw_sql = args.get("query") or args.get("sql")
        if isinstance(raw_sql, str) and raw_sql.strip():
            return (sql_tool, raw_sql.strip())
    return None


def strip_sql_comments(sql_query: str) -> str:
    """Remove block and line comments outside SQL string literals and backtick identifiers."""
    out: list[str] = []
    i, n = 0, len(sql_query)
    while i < n:
        ch = sql_query[i]
        if ch in "rRbB" and (i == 0 or not (sql_query[i - 1].isalnum() or sql_query[i - 1] == "_")):
            if i + 2 < n and sql_query[i : i + 2].lower() in ("rb", "br") and sql_query[i + 2] in "'\"":
                out.append(sql_query[i : i + 2])
                i += 2
                continue
            if i + 1 < n and sql_query[i + 1] in "'\"":
                out.append(ch)
                i += 1
                continue
        if ch in "'\"`":
            delim = sql_query[i : i + 3] if ch != "`" and sql_query[i : i + 3] in ("'''", '"""') else ch
            out.append(delim)
            i += len(delim)
            while i < n:
                if sql_query[i] == "\\":
                    step = 2 if i + 1 < n else 1
                    out.append(sql_query[i : i + step])
                    i += step
                elif sql_query.startswith(delim, i):
                    out.append(delim)
                    i += len(delim)
                    break
                else:
                    out.append(sql_query[i])
                    i += 1
        elif sql_query.startswith("--", i) or ch == "#":
            end = sql_query.find("\n", i)
            out.append(" ")
            i = n if end == -1 else end + 1
        elif sql_query.startswith("/*", i):
            end = sql_query.find("*/", i + 2)
            out.append(" ")
            i = n if end == -1 else end + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def gate_bigquery_ai_views(
    state_dir_path: Path, bq_tool: str, sql_query: str, config_path: Path | None = None,
) -> dict[str, Any]:
    """Enforce hard Zero-Trust BigQuery views isolation against configured restricted raw datasets."""
    _ = state_dir_path
    cfg = load_guard_config(config_path)
    config_error = cfg.get("config_error")
    if isinstance(config_error, str) and config_error:
        return {"decision": "deny", "reason": f"CONTEXT-GUARD BIGQUERY CONFIG ERROR (fail-closed): {config_error}"}
    restricted_datasets: tuple[str, ...] = cfg["restricted_bq_datasets"]
    if not restricted_datasets or cfg.get("allow_bq_raw_ddl_maintenance") is True:
        return {"decision": "allow"}

    cleaned_sql = strip_sql_comments(sql_query)
    joined_restricted = "|".join(re.escape(ds) for ds in restricted_datasets)
    forbidden_re = re.compile(
        rf"\b(?:{joined_restricted})\s*[`\"']?\s*\."
        rf"|:[`\"']?(?:{joined_restricted})\b"
        rf"|\bSCHEMA\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?[`\"'\w.:-]*\b(?:{joined_restricted})\b",
        re.IGNORECASE,
    )
    if not forbidden_re.search(cleaned_sql):
        return {"decision": "allow"}

    ds_label = ", ".join(f"`{ds}`" for ds in restricted_datasets)
    schema_line = f"See `{cfg['bq_schema_doc']}` for full column schemas.\n" if cfg["bq_schema_doc"] else ""
    return {
        "decision": "deny",
        "reason": (
            f"CONTEXT-GUARD BIGQUERY AI-VIEWS BLOCK: Direct query to {ds_label} "
            f"via `{bq_tool}` is blocked by Zero-Trust data isolation rules.\n"
            f"Query the authorized views in `{cfg['allowed_bq_views_hint']}` instead.\n"
            f"{schema_line}"
            'Operator DDL maintenance requires `"allow_bq_raw_ddl_maintenance": true` in `config.json`.'
        ),
    }
