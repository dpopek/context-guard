"""Tests for MCP step, BigQuery tabular, TWG stdout, and transcript JSON/JSONL outliners."""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

from hooks.json_outliners import (
    TWG_STDOUT_OUTLINE_MIN_BYTES,
    prepare_twg_stdout_outline,
    unwrap_and_outline_twg_stdout,
)
from hooks.pre_tool_use import evaluate_hook
from hooks.read_planner import handle_file_read_verdict
from hooks.state_store import state_file_in


def test_small_twg_stdout_under_6kb_writes_no_files_to_cache_or_sibling(
    tmp_path: Path,
) -> None:
    twg_dir = tmp_path / "twg" / "run1"
    twg_dir.mkdir(parents=True)
    twg_file = twg_dir / "stdout.compact.json"

    base_obj: dict[str, Any] = {
        "apiVersion": "v2",
        "command": "jira.workitem.get",
        "data": {"key": "PROJ-101", "summary": "Small payload check", "pad": ""},
    }
    base_raw = json.dumps(base_obj)
    pad_len = 800 - len(base_raw)
    assert pad_len > 0
    base_obj["data"]["pad"] = "x" * pad_len
    twg_file.write_text(json.dumps(base_obj), encoding="utf-8")

    st_size = twg_file.stat().st_size
    assert st_size == 800
    assert st_size < TWG_STDOUT_OUTLINE_MIN_BYTES

    direct_cache = tmp_path / "direct_twg_cache"
    prepared_small = prepare_twg_stdout_outline(twg_file, st_size, cache_dir=direct_cache)
    assert prepared_small is not None
    assert prepared_small.unwrapped_target is None
    assert prepared_small.pending_write is None
    assert not direct_cache.exists()

    direct_res = unwrap_and_outline_twg_stdout(twg_file, st_size, cache_dir=direct_cache)
    assert direct_res is not None
    total_lines, inline_text, unwrapped_canon = direct_res
    assert total_lines > 1
    assert "full payload inline" in inline_text
    assert unwrapped_canon is None
    assert not direct_cache.exists() or list(direct_cache.iterdir()) == []
    assert not (twg_dir / "stdout_formatted.json").exists()

    sibling_res = unwrap_and_outline_twg_stdout(twg_file, st_size, cache_dir=None)
    assert sibling_res is not None
    assert sibling_res[2] is None
    assert not (twg_dir / "stdout_formatted.json").exists()

    state_dir = tmp_path / "state"
    res1 = evaluate_hook(
        {
            "conversationId": "conv-def10-twg",
            "stepIdx": 1,
            "toolCall": {"name": "read_file", "args": {"Path": str(twg_file)}},
        },
        state_dir=str(state_dir),
    )
    assert res1["decision"] == "deny"
    assert "CONTEXT-GUARD TWG INLINE READ" in res1["reason"]
    assert "PROJ-101" in res1["reason"]

    hook_cache = state_dir / "twg_cache"
    assert not hook_cache.exists() or list(hook_cache.iterdir()) == []
    assert not (twg_dir / "stdout_formatted.json").exists()

    res2 = evaluate_hook(
        {
            "conversationId": "conv-def10-twg",
            "stepIdx": 2,
            "toolCall": {"name": "read_file", "args": {"Path": str(twg_file)}},
        },
        state_dir=str(state_dir),
    )
    assert res2 == {"decision": "allow"}
    assert not hook_cache.exists() or list(hook_cache.iterdir()) == []
    assert not (twg_dir / "stdout_formatted.json").exists()

    saved = json.loads(state_file_in(state_dir).read_text(encoding="utf-8"))
    canon = os.path.realpath(str(twg_file))
    assert "unwrapped_path" not in saved["files"][canon]


def test_unredirected_twg_and_mcp_envelopes_preserve_physical_line_count(
    tmp_path: Path,
) -> None:
    state_twg = tmp_path / "state_twg_phys"
    twg_dir = tmp_path / "twg" / "run_phys"
    twg_dir.mkdir(parents=True)
    twg_compact = twg_dir / "stdout.compact.json"
    compact_payload = {
        "key": "PROJ-200",
        "fields": {f"field_{idx}": f"val_{idx}" for idx in range(20)},
    }
    twg_compact.write_text(json.dumps(compact_payload, separators=(",", ":")), encoding="utf-8")
    assert twg_compact.stat().st_size < 6144
    twg_canon = os.path.realpath(str(twg_compact))

    res1 = evaluate_hook(
        {
            "conversationId": "conv-twg-phys",
            "stepIdx": 1,
            "toolCall": {"name": "read_file", "args": {"Path": str(twg_compact)}},
        },
        state_dir=str(state_twg),
    )
    assert res1["decision"] == "deny"
    assert "TWG INLINE READ" in res1["reason"]

    res2 = evaluate_hook(
        {
            "conversationId": "conv-twg-phys",
            "stepIdx": 2,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(twg_compact), "StartLine": 1, "EndLine": 5},
            },
        },
        state_dir=str(state_twg),
    )
    assert res2 == {"decision": "allow"}
    saved_twg = json.loads(state_file_in(state_twg).read_text(encoding="utf-8"))
    assert saved_twg["files"][twg_canon]["outlined_total_lines"] >= 20
    assert saved_twg["files"][twg_canon]["reads"] == [[1, 1, 2]]

    res3 = evaluate_hook(
        {
            "conversationId": "conv-twg-phys",
            "stepIdx": 3,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(twg_compact), "StartLine": 1, "EndLine": 10},
            },
        },
        state_dir=str(state_twg),
    )
    assert res3 == {"decision": "allow"}

    state_mcp = tmp_path / "state_mcp_phys"
    step_dir = tmp_path / ".system_generated" / "steps" / "301"
    step_dir.mkdir(parents=True)
    mcp_txt = step_dir / "output.txt"
    inner_code = "\n".join(f"def phys_{i}() -> int:\n    return {i}\n" for i in range(55))
    mcp_txt.write_text(
        json.dumps(
            {
                "file_name": "unwrapped_phys.py",
                "file_path": "app/unwrapped_phys.py",
                "content": inner_code + "\n",
            }
        )
        + (" " * 16_000),
        encoding="utf-8",
    )
    mcp_canon = os.path.realpath(str(mcp_txt))

    out_m1 = handle_file_read_verdict(
        state_mcp, str(mcp_txt), 1, -1, 0, 1, can_redirect_path=False
    )
    assert out_m1.decision["decision"] == "deny"

    out_m2 = handle_file_read_verdict(
        state_mcp, str(mcp_txt), 1, 30, 0, 2, can_redirect_path=False
    )
    assert out_m2.decision["decision"] == "allow"
    saved_mcp = json.loads(state_file_in(state_mcp).read_text(encoding="utf-8"))
    assert saved_mcp["files"][mcp_canon]["reads"] == [[1, 1, 2]]


def test_transition_from_unredirected_envelope_to_unwrap_guards_coordinate_space(
    tmp_path: Path,
) -> None:
    def _make_multiline_mcp_envelope(step_no: str, inner_name: str) -> tuple[Path, Path]:
        step_dir = tmp_path / ".system_generated" / "steps" / step_no
        step_dir.mkdir(parents=True)
        out_txt = step_dir / "output.txt"
        target_py = step_dir / inner_name
        inner_src = "\n".join(f"def coord_{i}() -> int:\n    return {i}\n" for i in range(55))
        envelope = {
            "trace_lines": [f"meta_line_{idx}_" + ("x" * 350) for idx in range(45)],
            "file_name": inner_name,
            "file_path": f"pkg/{inner_name}",
            "content": inner_src + "\n",
        }
        out_txt.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        assert out_txt.stat().st_size >= 16_384
        return out_txt, target_py

    state_a = tmp_path / "state_coord_a"
    mcp_a, target_a = _make_multiline_mcp_envelope("302", "inner_coord_a.py")
    mcp_a_canon = os.path.realpath(str(mcp_a))
    target_a_canon = os.path.realpath(str(target_a))

    out_a1 = handle_file_read_verdict(state_a, str(mcp_a), 1, -1, 0, 1, can_redirect_path=False)
    assert out_a1.decision["decision"] == "deny"
    assert not target_a.exists()

    out_a2 = handle_file_read_verdict(state_a, str(mcp_a), 1, 30, 0, 2, can_redirect_path=False)
    assert out_a2.decision["decision"] == "allow"
    saved_a2 = json.loads(state_file_in(state_a).read_text(encoding="utf-8"))
    assert saved_a2["files"][mcp_a_canon]["reads"] == [[1, 30, 2]]
    assert "unwrapped_path" not in saved_a2["files"][mcp_a_canon]

    out_a3 = handle_file_read_verdict(state_a, str(mcp_a), 1, 60, 0, 3, can_redirect_path=True)
    assert out_a3.decision["decision"] == "allow"
    assert target_a.is_file()
    assert out_a3.decision["overwrite"] == {"Path": target_a_canon}

    state_b = tmp_path / "state_coord_b"
    mcp_b, target_b = _make_multiline_mcp_envelope("303", "inner_coord_b.py")
    target_b_canon = os.path.realpath(str(target_b))

    assert handle_file_read_verdict(state_b, str(mcp_b), 1, -1, 0, 1, can_redirect_path=False).decision["decision"] == "deny"
    assert handle_file_read_verdict(state_b, str(mcp_b), 1, 30, 0, 2, can_redirect_path=False).decision["decision"] == "allow"

    out_b3 = handle_file_read_verdict(state_b, str(mcp_b), 1, 20, 0, 3, can_redirect_path=True)
    assert out_b3.decision["decision"] == "allow"
    assert out_b3.decision["overwrite"] == {"Path": target_b_canon}

    out_b4 = handle_file_read_verdict(state_b, str(mcp_b), 1, 60, 0, 4, can_redirect_path=True)
    assert out_b4.decision["decision"] == "allow"
    assert out_b4.decision["overwrite"] == {"StartLine": 21, "EndLine": 60, "Path": target_b_canon}


def test_bigquery_tabular_outline_includes_unwrapped_at_path(tmp_path: Path) -> None:
    step_dir = tmp_path / ".system_generated" / "steps" / "42"
    step_dir.mkdir(parents=True)
    out_txt = step_dir / "output.txt"
    rows = [{"order_id": i, "revenue": f"{i * 100.5:.2f}", "notes": "x" * 60} for i in range(250)]
    payload = json.dumps(
        {"schema": {"fields": [{"name": "order_id", "type": "INTEGER"}]}, "rows": rows}
    )
    out_txt.write_text(payload, encoding="utf-8")

    state_dir = tmp_path / "state"
    res = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 1,
            "toolCall": {"name": "read_file", "args": {"Path": str(out_txt)}},
        },
        state_dir=str(state_dir),
    )
    assert res["decision"] == "deny"
    expected_unwrapped = os.path.realpath(str(step_dir / "output_formatted.json"))
    assert f"BigQuery/Tabular JSON result (250 rows), unwrapped at {expected_unwrapped}" in res["reason"]
    assert (step_dir / "output_formatted.json").is_file()


def test_auto_outline_gitlab_mcp_output_txt_and_escape_hatch(tmp_path: Path) -> None:
    state_dir = str(tmp_path / "state")
    step_dir = tmp_path / ".system_generated" / "steps" / "156"
    step_dir.mkdir(parents=True, exist_ok=True)
    out_txt = step_dir / "output.txt"
    php_lines = ["<?php", "namespace Acme\\Store\\Service;", "class OrderUpdateManage {"]
    for i in range(1, 180):
        php_lines.append(f"    public function handleStep{i}($order) {{ return {i}; }}")
    php_lines.append("}")
    payload_json = json.dumps(
        {
            "file_name": "OrderUpdateManage.php",
            "file_path": "app/code/Acme/Store/Service/OrderUpdateManage.php",
            "size": 52014,
            "encoding": "utf8",
            "content": "\n".join(php_lines),
        }
    )
    out_txt.write_text(payload_json + (" " * 10000), encoding="utf-8")

    res_first = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 10,
            "toolCall": {"name": "read_file", "args": {"Path": str(out_txt)}},
        },
        state_dir=state_dir,
    )
    assert res_first["decision"] == "deny"
    assert "CONTEXT-GUARD AUTO-OUTLINE" in res_first["reason"]
    assert "OrderUpdateManage.php" in res_first["reason"]
    assert "class OrderUpdateManage" in res_first["reason"]

    unwrapped_file = step_dir / "OrderUpdateManage.php"
    assert unwrapped_file.is_file()
    res_targeted = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 11,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(out_txt), "StartLine": 10, "EndLine": 40},
            },
        },
        state_dir=state_dir,
    )
    assert res_targeted == {
        "decision": "allow",
        "overwrite": {"Path": os.path.realpath(str(unwrapped_file))},
    }

    res_escape = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 12,
            "toolCall": {"name": "read_file", "args": {"Path": str(out_txt)}},
        },
        state_dir=state_dir,
    )
    assert res_escape == {"decision": "allow"}


def test_auto_outline_bigquery_mcp_output_txt_summary(tmp_path: Path) -> None:
    state_dir = str(tmp_path / "state")
    step_dir = tmp_path / ".system_generated" / "steps" / "30"
    step_dir.mkdir(parents=True, exist_ok=True)
    out_txt = step_dir / "output.txt"
    rows = [
        {
            "order_id": 1000 + i,
            "anonymized_contractor_id": f"hash_{i}" * 8,
            "difference": -12.5 * i,
        }
        for i in range(1, 300)
    ]
    bq_json = json.dumps(
        {
            "schema": {
                "fields": [
                    {"name": "order_id", "type": "INTEGER"},
                    {"name": "anonymized_contractor_id", "type": "STRING"},
                    {"name": "difference", "type": "FLOAT"},
                ]
            },
            "rows": rows,
        }
    )
    out_txt.write_text(bq_json, encoding="utf-8")

    res_first = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 15,
            "toolCall": {"name": "read_file", "args": {"Path": str(out_txt)}},
        },
        state_dir=state_dir,
    )
    assert res_first["decision"] == "deny"
    assert "CONTEXT-GUARD AUTO-OUTLINE" in res_first["reason"]
    assert "BigQuery/Tabular JSON result (299 rows)" in res_first["reason"]
    assert "order_id: INTEGER" in res_first["reason"]


def test_mcp_output_txt_handles_non_code_content_and_json_list(tmp_path: Path) -> None:
    state_dir = str(tmp_path / "state")
    step_dir = tmp_path / ".system_generated" / "steps" / "46"
    step_dir.mkdir(parents=True, exist_ok=True)
    out_txt = step_dir / "output.txt"
    lock_lines = (
        ["{", '  "packages": [']
        + [f'    {{"name": "pkg/{i}", "version": "1.{i}.0"}},' for i in range(400)]
        + ["  ]", "}"]
    )
    out_txt.write_text(
        json.dumps(
            {
                "file_name": "composer.lock",
                "file_path": "composer.lock",
                "content": "\n".join(lock_lines),
            }
        ),
        encoding="utf-8",
    )
    res_lock = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 20,
            "toolCall": {"name": "read_file", "args": {"Path": str(out_txt)}},
        },
        state_dir=state_dir,
    )
    assert res_lock["decision"] == "deny"
    assert "composer.lock (404 LOC, unwrapped at" in res_lock["reason"]
    assert (step_dir / "composer.lock").exists()

    step_dir_list = tmp_path / ".system_generated" / "steps" / "36"
    step_dir_list.mkdir(parents=True, exist_ok=True)
    out_list_txt = step_dir_list / "output.txt"
    repo_list = [
        {
            "id": i,
            "name": f"repo-{i}",
            "path_with_namespace": f"group/repo-{i}",
            "description": "x" * 600,
        }
        for i in range(30)
    ]
    out_list_txt.write_text(json.dumps(repo_list), encoding="utf-8")
    res_list = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 21,
            "toolCall": {"name": "read_file", "args": {"Path": str(out_list_txt)}},
        },
        state_dir=state_dir,
    )
    assert res_list["decision"] == "deny"
    assert "MCP JSON collection (30 items, unwrapped at" in res_list["reason"]
    assert (step_dir_list / "output_formatted.json").exists()

    step_dir_min = tmp_path / ".system_generated" / "steps" / "47"
    step_dir_min.mkdir(parents=True, exist_ok=True)
    out_min_txt = step_dir_min / "output.txt"
    min_content = "\n".join([f'{{"row": {i}, "blob": "{"m" * 900}"}}' for i in range(20)])
    out_min_txt.write_text(
        json.dumps(
            {
                "file_name": "composer.patches.json",
                "file_path": "composer.patches.json",
                "content": min_content,
            }
        ),
        encoding="utf-8",
    )
    res_min = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 22,
            "toolCall": {"name": "read_file", "args": {"Path": str(out_min_txt)}},
        },
        state_dir=state_dir,
    )
    assert res_min["decision"] == "deny"
    assert "composer.patches.json (20 LOC, unwrapped at" in res_min["reason"]
    assert (step_dir_min / "composer.patches.json").exists()


def test_twg_stdout_json_auto_outline_workitem_get_query_and_escape_hatch(
    tmp_path: Path,
) -> None:
    state_dir = str(tmp_path / "state")
    twg_dir = tmp_path / "T" / "twg" / "1793212572" / "run.dYIO2K"
    twg_dir.mkdir(parents=True, exist_ok=True)
    stdout_json = twg_dir / "stdout.json"

    workitem_payload = {
        "apiVersion": "v2",
        "command": "jira.workitem.get",
        "data": [
            {
                "key": "PROJ-763",
                "summary": "Check attribute synchronization in Magento",
                "status": {"name": "In Progress"},
                "issuetype": {"name": "Task"},
                "priority": None,
                "assignee": {"displayName": "Jan Kowalski"},
                "reporter": {"displayName": "Anna Nowak"},
                "labels": ["sync", "m2"],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": "Detailed ADF problem description here."}
                            ],
                        }
                    ],
                },
                "comment": {
                    "comments": [
                        {
                            "author": {"displayName": "Piotr Wisniewski"},
                            "created": "2026-10-28T10:00:00.000+0000",
                            "body": {
                                "type": "doc",
                                "content": [
                                    {
                                        "type": "paragraph",
                                        "content": [{"type": "text", "text": "Confirmed on staging."}],
                                    }
                                ],
                            },
                        }
                    ]
                },
                "padding": ["line_padding_entry_" * 3 for _ in range(320)],
            }
        ],
    }
    stdout_json.write_text(json.dumps(workitem_payload, indent=2), encoding="utf-8")
    assert stdout_json.stat().st_size >= 12 * 1024

    res1 = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 30,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(stdout_json), "StartLine": 1, "EndLine": 400},
            },
        },
        state_dir=state_dir,
    )
    assert res1["decision"] == "deny"
    assert "CONTEXT-GUARD AUTO-OUTLINE" in res1["reason"]
    assert "PROJ-763" in res1["reason"]
    assert "Check attribute synchronization in Magento" in res1["reason"]
    assert "Detailed ADF problem description here." in res1["reason"]
    assert "Confirmed on staging." in res1["reason"]

    res2 = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 31,
            "toolCall": {"name": "read_file", "args": {"Path": str(stdout_json)}},
        },
        state_dir=state_dir,
    )
    assert res2["decision"] == "allow"
    assert "twg_cache" in res2.get("overwrite", {}).get("Path", "")

    query_json = twg_dir / "query_wrap" / "stdout.json"
    query_json.parent.mkdir(parents=True, exist_ok=True)
    query_payload = {
        "apiVersion": "v2",
        "command": "jira.workitem.query",
        "data": {
            "issues": [
                {
                    "key": f"PROJ-{800 + i}",
                    "summary": f"Issue summary {i}",
                    "status": {"name": "Open"},
                    "priority": {"name": "Medium"},
                    "assignee": {"displayName": "Dev User"},
                    "extra": "z" * 400,
                }
                for i in range(30)
            ]
        },
    }
    query_json.write_text(json.dumps(query_payload, indent=2), encoding="utf-8")
    res_q = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 32,
            "toolCall": {"name": "read_file", "args": {"Path": str(query_json)}},
        },
        state_dir=state_dir,
    )
    assert res_q["decision"] == "deny"
    assert "PROJ-800 [Open]" in res_q["reason"]
    assert "Issue summary 0" in res_q["reason"]

    meta_json = twg_dir / "meta_wrap" / "stdout.json"
    meta_json.parent.mkdir(parents=True, exist_ok=True)
    meta_fields = [
        {
            "fieldId": f"customfield_{10000 + i}",
            "name": f"Optional Field {i}",
            "required": False,
            "schema": {"type": "string"},
            "pad": "p" * 350,
        }
        for i in range(35)
    ] + [
        {
            "fieldId": "customfield_10099",
            "name": "Target Branch",
            "required": True,
            "schema": {"type": "string"},
        }
    ]
    meta_payload = {
        "apiVersion": "v2",
        "command": "jira.workitem.field.create-metadata",
        "data": {"fields": meta_fields},
    }
    meta_json.write_text(json.dumps(meta_payload, indent=2), encoding="utf-8")
    res_meta = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 33,
            "toolCall": {"name": "read_file", "args": {"Path": str(meta_json)}},
        },
        state_dir=state_dir,
    )
    assert res_meta["decision"] == "deny"
    assert "customfield_10099 (Target Branch): required=True" in res_meta["reason"]

    compact_json = twg_dir / "compact_wrap" / "stdout.compact.json"
    compact_json.parent.mkdir(parents=True, exist_ok=True)
    compact_payload = {
        "apiVersion": "v2",
        "command": "jira.workitem.query",
        "data": {
            "issues": [
                {
                    "key": f"PROJ-{900 + i}",
                    "summary": f"Compact issue {i}",
                    "status": {"name": "To evaluate"},
                    "priority": {"name": "High"},
                    "assignee": {"displayName": "Compact User"},
                    "pad": "c" * 280,
                }
                for i in range(20)
            ]
        },
    }
    compact_json.write_text(json.dumps(compact_payload), encoding="utf-8")
    assert 6 * 1024 <= compact_json.stat().st_size < 12 * 1024

    res_comp = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 34,
            "toolCall": {"name": "read_file", "args": {"Path": str(compact_json)}},
        },
        state_dir=state_dir,
    )
    assert res_comp["decision"] == "deny"
    assert "PROJ-900 [To evaluate]" in res_comp["reason"]

    res_comp_range = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 35,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(compact_json), "StartLine": 1, "EndLine": 40},
            },
        },
        state_dir=state_dir,
    )
    assert res_comp_range["decision"] == "allow"
    comp_redirect = res_comp_range.get("overwrite", {}).get("Path", "")
    assert "twg_cache" in comp_redirect
    assert Path(comp_redirect).is_file()

    pair_dir = twg_dir / "pair_wrap"
    pair_dir.mkdir(parents=True, exist_ok=True)
    pair_compact = pair_dir / "stdout.compact.json"
    pair_pretty = pair_dir / "stdout.json"
    pair_compact.write_text(json.dumps(compact_payload), encoding="utf-8")
    pair_pretty.write_text(json.dumps(compact_payload, indent=2), encoding="utf-8")

    res_pair = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 36,
            "toolCall": {"name": "read_file", "args": {"Path": str(pair_compact)}},
        },
        state_dir=state_dir,
    )
    assert res_pair["decision"] == "deny"

    res_pair_range = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 37,
            "toolCall": {
                "name": "read_file",
                "args": {"Path": str(pair_compact), "StartLine": 1, "EndLine": 30},
            },
        },
        state_dir=state_dir,
    )
    assert res_pair_range["decision"] == "allow"
    pair_redirect = res_pair_range.get("overwrite", {}).get("Path", "")
    assert "twg_cache" in pair_redirect
    assert Path(pair_redirect).is_file()

    small_dir = twg_dir / "small_create"
    small_dir.mkdir(parents=True, exist_ok=True)
    small_compact = small_dir / "stdout.compact.json"
    small_payload = {
        "apiVersion": "v2",
        "command": "jira.workitem.create",
        "data": {"key": "PROJ-2999", "id": "199999"},
    }
    small_compact.write_text(json.dumps(small_payload), encoding="utf-8")
    assert small_compact.stat().st_size < 1024

    res_small = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 38,
            "toolCall": {"name": "read_file", "args": {"Path": str(small_compact)}},
        },
        state_dir=state_dir,
    )
    assert res_small["decision"] == "deny"
    assert "CONTEXT-GUARD TWG INLINE READ" in res_small["reason"]
    assert "PROJ-2999" in res_small["reason"]
    assert "No further `read_file` call is needed" in res_small["reason"]

    res_small_escape = evaluate_hook(
        {
            "conversationId": "c1",
            "stepIdx": 39,
            "toolCall": {"name": "read_file", "args": {"Path": str(small_compact)}},
        },
        state_dir=state_dir,
    )
    assert res_small_escape == {"decision": "allow"}
    assert not (small_dir / "stdout_formatted.json").exists()


def test_mcp_step_outline_splits_windows_path_and_unwraps_results_and_values(
    tmp_path: Path,
) -> None:
    from hooks.json_outliners import unwrap_and_outline_mcp_output

    win_step = tmp_path / ".system_generated" / "steps" / "10"
    win_step.mkdir(parents=True)
    win_out = win_step / "output.txt"
    py_body = "\n".join(f"def fn_{i}():\n    # {'x' * 30}\n    return {i}" for i in range(450))
    win_out.write_text(
        json.dumps({"file_path": r"C:\repo\sub\BigWinModule.py", "content": py_body}),
        encoding="utf-8",
    )
    win_res = unwrap_and_outline_mcp_output(win_out, win_out.stat().st_size)
    assert win_res is not None
    _, win_outline, win_unwrapped = win_res
    assert win_unwrapped == os.path.realpath(str(win_step / "BigWinModule.py"))
    assert "def fn_0" in win_outline

    for idx, key in enumerate(("results", "values")):
        sdir = tmp_path / ".system_generated" / "steps" / f"2{idx}"
        sdir.mkdir(parents=True)
        out_f = sdir / "output.txt"
        rows = [{"id": i, "label": f"row-{i}", "blob": "x" * 700} for i in range(25)]
        out_f.write_text(json.dumps({key: rows}), encoding="utf-8")
        res_coll = unwrap_and_outline_mcp_output(out_f, out_f.stat().st_size)
        assert res_coll is not None
        _, outline_txt, _ = res_coll
        assert "MCP JSON collection (25 items" in outline_txt
