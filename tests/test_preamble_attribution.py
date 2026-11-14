"""Claude Code preamble attribution per component and per plugin or MCP server."""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from bin.preamble_attribution import (
    CLAUDE_CLI_HARNESS,
    CLAUDE_DESKTOP_HARNESS,
    CODEX_CLI_HARNESS,
    CODEX_DESKTOP_HARNESS,
    MalformedAttachment,
    attribute_codex_record,
    attribute_record,
    codex_session_traits,
    find_candidates,
    is_claude_desktop_parts,
    measure_antigravity_preamble,
    median,
    merge_parts,
    split_claude_parts,
    split_codex_parts,
    summarize_parts,
    usage_keys,
)
from bin.token_usage import (
    antigravity_model_from_record,
    empty_usage_state,
    ingest_transcripts,
)

UUID = "8284aebe-c08d-4339-bf0c-ce45ca56f805"


def tokens(text: str) -> int:
    return len(text.encode("utf-8")) // 4


def attachment(kind: str, **fields: object) -> dict:
    return {"type": "attachment", "attachment": {"type": kind, **fields}}


def tool_call(name: str, **arguments: object) -> dict:
    return {"type": "tool_use", "id": "toolu_1", "name": name, "input": arguments}


def assistant(*blocks: dict) -> dict:
    return {"type": "assistant", "message": {"id": "msg_1", "content": list(blocks)}}


def test_median_rounds_down_between_the_middle_two() -> None:
    assert median([]) == 0
    assert median([3, 1, 2]) == 2
    assert median([1, 2, 3, 4]) == 2
    assert median([-5, 1]) == -2


def test_skill_listing_is_split_per_plugin_and_continuations_follow_their_entry() -> None:
    header = "<system-reminder>\nThe following skills are available for use with the Skill tool:\n\n"
    plugin = "- superpowers:brainstorming: Use before creative work\n  continued description\n"
    single = "- store-catalog: Look up products\n"
    second = "- superpowers:writing-plans: Use for plans\n"
    record = attachment("skill_listing", content=header + plugin + single + second)
    assert attribute_record(record) == {
        "skills": {"superpowers": tokens(plugin + second), "standalone": tokens(header + single)},
    }


def test_deferred_tools_are_split_per_server_with_uuid_names_shortened() -> None:
    names = ["WebFetch", "mcp__claude-in-chrome__navigate", f"mcp__{UUID}__getJiraIssue", "mcp__plugin_eng_github__search"]
    assert attribute_record(attachment("deferred_tools_delta", addedNames=names, removedNames=["Gone"])) == {
        "deferred_tools": {
            "builtin": tokens("WebFetch\n"),
            "mcp:claude-in-chrome": tokens("mcp__claude-in-chrome__navigate\n"),
            "mcp:8284aebe": tokens(f"mcp__{UUID}__getJiraIssue\n"),
            "mcp:plugin_eng_github": tokens("mcp__plugin_eng_github__search\n"),
        },
    }


def test_instructions_count_each_file_once_and_ignore_rendered() -> None:
    files = [{"path": "/u/CLAUDE.md", "type": "User", "content": "u" * 400}, {"type": "Project", "content": "p" * 80}]
    record = attachment("instructions", files=files, rendered="x" * 4000)
    assert attribute_record(record) == {"instructions": {"User": 100, "Project": 20}}


def test_system_prompt_agents_mcp_instructions_and_hooks() -> None:
    assert attribute_record(attachment("prompt_snapshot", systemPrompt=["a" * 40, "b" * 40])) == {
        "system_prompt": {"core": 20},
    }
    lines = ["- searchfit-seo:competitor-analyzer:AGENT: Analyze competitors", "- Explore: Read-only search agent"]
    assert attribute_record(attachment("agent_listing_delta", addedTypes=["x"], addedLines=lines)) == {
        "agents": {"searchfit-seo": tokens(lines[0] + "\n"), "standalone": tokens(lines[1] + "\n")},
    }
    blocks = attachment("mcp_instructions_delta", addedNames=["plugin:eng:github", UUID], addedBlocks=["c" * 400, "j" * 40])
    assert attribute_record(blocks) == {"mcp_instructions": {"mcp:plugin_eng_github": 100, "mcp:8284aebe": 10}}
    assert attribute_record(attachment("hook_additional_context", content=["h" * 400])) == {"hooks": {"all": 100}}


def test_hook_success_and_non_attachments_are_not_attributed() -> None:
    assert attribute_record(attachment("hook_success", stdout="h" * 400)) is None
    assert attribute_record({"type": "user", "message": {"content": "hi"}}) is None


def test_unknown_attachment_goes_to_other_under_its_type() -> None:
    record = attachment("date_change", newDate="2026-11-01" * 4, extra={"note": "n" * 40})
    assert attribute_record(record) == {"other": {"date_change": 20}}


@pytest.mark.parametrize(
    "record",
    [
        {"type": "attachment", "attachment": "text"},
        attachment("skill_listing", content=7),
        attachment("instructions", files="x"),
        attachment("instructions", files=[{"type": "User"}]),
        attachment("mcp_instructions_delta", addedNames=["a", "b"], addedBlocks=["only one"]),
    ],
)
def test_malformed_attachment_raises(record: dict) -> None:
    with pytest.raises(MalformedAttachment):
        attribute_record(record)


def test_merge_parts_adds_without_touching_inputs_and_drops_malformed_base() -> None:
    base = {"skills": {"superpowers": 10}, "hooks": "bad"}
    extra = {"skills": {"superpowers": 5, "standalone": 1}, "hooks": {"all": 2}}
    assert merge_parts(base, extra) == {"skills": {"superpowers": 15, "standalone": 1}, "hooks": {"all": 2}}
    assert base == {"skills": {"superpowers": 10}, "hooks": "bad"}
    assert merge_parts(None, extra) == extra


def test_usage_keys_map_tool_calls_to_plugins_and_servers() -> None:
    record = assistant(
        {"type": "text", "text": "hi"},
        tool_call("Skill", skill="superpowers:systematic-debugging"),
        tool_call("Skill", skill="store-catalog"),
        tool_call("Agent", subagent_type="searchfit-seo:competitor-analyzer:AGENT"),
        tool_call("Task", subagent_type="Explore"),
        tool_call("Agent", prompt="no type"),
        tool_call(f"mcp__{UUID}__getJiraIssue"),
        tool_call("Read", file_path="/x"),
    )
    assert usage_keys(record) == ["superpowers", "standalone", "searchfit-seo", "standalone", "mcp:8284aebe"]
    assert usage_keys({"type": "user", "message": {"content": [tool_call("Skill", skill="a:b")]}}) == []


def part(measured: int, **components: dict) -> dict:
    return {"measured": measured, "components": components}


def test_summarize_parts_takes_medians_and_the_remainder() -> None:
    entries = [
        part(80_000, skills={"superpowers": 6000, "standalone": 1000}, hooks={"all": 2000}),
        part(84_000, skills={"superpowers": 6200}, hooks={"all": 2000}),
        part(82_000, skills={"superpowers": 6100, "standalone": 900}, hooks={"all": 2000}),
        {"measured": 0, "components": {}},
        "garbage",
    ]
    assert summarize_parts(entries) == {
        "sessions": 3,
        "measured": 82_000,
        "components": {"skills": {"superpowers": 6100, "standalone": 900}, "hooks": {"all": 2000}},
        "unattributed": 73_000,
        "clamped": False,
    }


def test_negative_remainder_is_clamped_and_flagged() -> None:
    summary = summarize_parts([part(1000, skills={"superpowers": 3000})])
    assert summary["unattributed"] == 0 and summary["clamped"] is True
    assert summarize_parts([])["sessions"] == 0


def test_candidates_threshold_zero_calls_window_and_order() -> None:
    today = date(2026, 11, 1)
    first_day = (today - timedelta(days=29)).isoformat()
    outside = (today - timedelta(days=30)).isoformat()
    sessions = [
        part(
            80_000,
            skills={"superpowers": 6000, "split-plugin": 300, "standalone": 9000, "edge": 500},
            agents={"split-plugin": 300},
            deferred_tools={"mcp:old-call": 800, "mcp:recent-call": 900, "builtin": 9000},
            mcp_instructions={"mcp:old-call": 100},
            hooks={"all": 5000},
        )
        for _ in range(3)
    ]
    sessions.append(part(80_000, skills={"rare-plugin": 5000}))
    use = {
        "2026-10-30": {"superpowers": 3},
        first_day: {"mcp:recent-call": 1},
        outside: {"mcp:old-call": 4},
        "bad-day": {"edge": 1},
    }
    assert find_candidates(sessions, use, today) == [
        {"key": "mcp:old-call", "tokens": 900, "calls": 0},
        {"key": "split-plugin", "tokens": 600, "calls": 0},
    ]


def test_is_claude_desktop_parts_detects_ccd_servers_only() -> None:
    assert is_claude_desktop_parts({"deferred_tools": {"mcp:ccd_session": 40, "builtin": 500}}) is True
    assert is_claude_desktop_parts({"mcp_instructions": {"mcp:ccd_window": 25}}) is True
    assert is_claude_desktop_parts({"deferred_tools": {"mcp:claude-in-chrome": 80, "builtin": 500}}) is False
    assert is_claude_desktop_parts({"skills": {"mcp:ccd_fake": 100}}) is False
    assert is_claude_desktop_parts(None) is False
    assert is_claude_desktop_parts({"deferred_tools": "malformed"}) is False


def test_split_claude_parts_partitions_cli_and_desktop_preserving_order() -> None:
    cli_1 = part(30_100, deferred_tools={"builtin": 2000})
    desk_1 = part(86_500, deferred_tools={"builtin": 2000, "mcp:ccd_session": 120})
    cli_2 = part(31_400, skills={"superpowers": 4000})
    desk_2 = part(91_200, mcp_instructions={"mcp:ccd_host": 80})
    cohorts = split_claude_parts([cli_1, desk_1, {"measured": 0, "components": {}}, cli_2, "bad", desk_2])
    assert cohorts == {
        CLAUDE_CLI_HARNESS: [cli_1, cli_2],
        CLAUDE_DESKTOP_HARNESS: [desk_1, desk_2],
    }


def test_codex_session_traits_distinguishes_main_cohorts_and_subagents() -> None:
    assert codex_session_traits({"type": "response_item", "payload": {}}) is None
    assert codex_session_traits(
        {"type": "session_meta", "payload": {"originator": "Codex Desktop", "source": "vscode"}}
    ) == (False, CODEX_DESKTOP_HARNESS)
    assert codex_session_traits(
        {"type": "session_meta", "payload": {"originator": "codex_cli_rs", "source": "cli"}}
    ) == (False, CODEX_CLI_HARNESS)
    assert codex_session_traits(
        {
            "type": "session_meta",
            "payload": {
                "originator": "Codex Desktop",
                "parent_thread_id": "parent-1",
                "source": {"subagent": {"other": "guardian"}},
                "thread_source": "guardian_review",
            },
        }
    ) == (True, CODEX_DESKTOP_HARNESS)
    assert codex_session_traits(
        {
            "type": "session_meta",
            "payload": {
                "originator": "Codex Desktop",
                "parent_thread_id": "parent-1",
                "source": {"subagent": {"thread_spawn": {"parent_thread_id": "parent-1"}}},
                "thread_source": "subagent",
            },
        }
    ) == (True, CODEX_DESKTOP_HARNESS)
    assert codex_session_traits(
        {"type": "event_msg", "payload": {"type": "task_started", "turn_id": "external-import-turn-1"}}
    ) == (True, "")


def test_attribute_codex_record_splits_tools_instructions_skills_and_ignores_user_prompts() -> None:
    assert attribute_codex_record({"type": "session_meta", "payload": {"base_instructions": {"text": "x" * 100}}}) is None

    exec_desc = "Run JS code\n## clock\nClock tools\n## mcp__ologs__search\nOlogs body\n"
    tools_rec = {
        "type": "response_item",
        "payload": {
            "type": "additional_tools",
            "tools": [
                {
                    "type": "namespace",
                    "name": "functions",
                    "tools": [
                        {"type": "custom", "name": "exec", "description": exec_desc},
                        {"type": "function", "name": "wait", "description": "wait desc"},
                    ],
                },
                {"type": "function", "name": "mcp__gitlab__get_issue", "description": "get issue"},
            ],
        },
    }
    tools_parts = attribute_codex_record(tools_rec)
    assert tools_parts is not None
    assert "mcp:ologs" in tools_parts["deferred_tools"]
    assert "mcp:gitlab" in tools_parts["deferred_tools"]
    assert "builtin" in tools_parts["deferred_tools"]

    dev_msg = {
        "type": "response_item",
        "payload": {
            "type": "message",
            "role": "developer",
            "content": [
                {"type": "input_text", "text": "You are Codex.\n" + "x" * 80},
                {"type": "input_text", "text": "<app-context>\nDesktop\n</app-context>" + "a" * 40},
                {"type": "input_text", "text": "## Memory\nMEMORY_SUMMARY\n" + "m" * 40},
                {"type": "input_text", "text": "<skills_instructions>\n- superpowers:tdd: Use TDD\n</skills_instructions>"},
            ],
        },
    }
    dev_parts = attribute_codex_record(dev_msg)
    assert dev_parts is not None
    assert "core" in dev_parts["system_prompt"]
    assert "app_context" in dev_parts["other"]
    assert "memory" in dev_parts["instructions"]
    assert "superpowers" in dev_parts["skills"]

    agents_user = {
        "type": "response_item",
        "payload": {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "# AGENTS.md instructions for /repo\n" + "a" * 80}],
        },
    }
    assert attribute_codex_record(agents_user) == {"instructions": {"agents_md": tokens("# AGENTS.md instructions for /repo\n" + "a" * 80)}}
    chat_user = {
        "type": "response_item",
        "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Please fix the bug"}]},
    }
    assert attribute_codex_record(chat_user) is None


def test_split_codex_parts_partitions_cli_and_desktop() -> None:
    cli_entry = {"measured": 12_000, "cohort": CODEX_CLI_HARNESS, "components": {"system_prompt": {"core": 8000}}}
    desk_entry = {"measured": 24_000, "cohort": CODEX_DESKTOP_HARNESS, "components": {"other": {"app_context": 3000}}}
    assert split_codex_parts([cli_entry, desk_entry, {"measured": 0, "components": {}}]) == {
        CODEX_CLI_HARNESS: [cli_entry],
        CODEX_DESKTOP_HARNESS: [desk_entry],
    }


def test_measure_antigravity_preamble_estimates_gemini_agents_skills_and_mcp(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    (home / ".gemini").mkdir(parents=True)
    (home / ".gemini" / "GEMINI.md").write_text("g" * 400, encoding="utf-8")
    (ws / ".agents").mkdir(parents=True)
    (ws / ".agents" / "AGENTS.md").write_text("a" * 800, encoding="utf-8")
    skill_dir = home / ".gemini" / "config" / "skills" / "demo-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: demo-skill\ndescription: Short desc\n---\nbody\n", encoding="utf-8")
    mcp_dir = home / ".gemini" / "antigravity" / "mcp" / "github"
    mcp_dir.mkdir(parents=True)
    (mcp_dir / "search.json").write_text("{" + '"x":' + '"y"' * 50 + "}", encoding="utf-8")

    measured = dict(measure_antigravity_preamble(home, ws))
    assert measured["user GEMINI.md / AGENTS.md"] == 100
    assert measured["workspace AGENTS.md"] == 200
    assert measured["skills listing"] > 0
    assert measured["MCP tool schemas"] > 0


def test_codex_subagents_excluded_from_preamble_and_attributed_by_cohort(tmp_path: Path) -> None:
    import json

    roots = {name: tmp_path / name for name in ("antigravity", "claude", "codex", "cursor")}
    day_dir = roots["codex"] / "2026" / "11" / "12"
    day_dir.mkdir(parents=True)

    def _tok_line(inp: int, cached: int, out: int) -> str:
        return json.dumps(
            {
                "timestamp": "2026-11-12T10:00:00Z",
                "type": "event_msg",
                "payload": {
                    "type": "token_count",
                    "info": {
                        "last_token_usage": {"input_tokens": inp, "cached_input_tokens": cached, "output_tokens": out},
                        "total_token_usage": {"input_tokens": inp, "cached_input_tokens": cached, "output_tokens": out},
                    },
                },
            }
        )

    main_rollout = day_dir / "rollout-main.jsonl"
    main_rollout.write_text(
        "\n".join(
            [
                json.dumps({"timestamp": "2026-11-12T10:00:00Z", "type": "session_meta", "payload": {"originator": "Codex Desktop", "source": "vscode"}}),
                json.dumps({"type": "turn_context", "payload": {"model": "gpt-5.4"}}),
                json.dumps({"type": "response_item", "payload": {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "<app-context>\n" + "a" * 400 + "\n</app-context>"}]}}),
                _tok_line(20_000, 15_000, 50),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    guard_rollout = day_dir / "rollout-guardian.jsonl"
    guard_rollout.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-11-12T10:01:00Z",
                        "type": "session_meta",
                        "payload": {
                            "originator": "Codex Desktop",
                            "parent_thread_id": "main-1",
                            "source": {"subagent": {"other": "guardian"}},
                            "thread_source": "guardian_review",
                        },
                    }
                ),
                json.dumps({"type": "turn_context", "payload": {"model": "gpt-5.4"}}),
                _tok_line(45_000, 30_000, 20),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    state = empty_usage_state()
    ingest_transcripts(state, roots)
    assert state["totals"]["codex|gpt-5.4"]["events"] == 2
    assert state["preamble"]["codex"] == [20_000]
    assert len(state["codex_preamble_parts"]) == 1
    assert state["codex_preamble_parts"][0]["cohort"] == CODEX_DESKTOP_HARNESS
    assert state["codex_preamble_parts"][0]["measured"] == 20_000


def test_antigravity_model_selection_and_subagent_detection_in_transcripts(tmp_path: Path) -> None:
    import json

    assert antigravity_model_from_record(
        {
            "type": "USER_INPUT",
            "content": "<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Gemini 4 Carbon (Medium). Do not comment.\n</USER_SETTINGS_CHANGE>",
        }
    ) == "gemini4carbonmedium"

    roots = {name: tmp_path / name for name in ("antigravity", "claude", "codex", "cursor")}
    main_dir = roots["antigravity"] / "conv-main" / ".system_generated" / "logs"
    sub_dir = roots["antigravity"] / "conv-sub" / ".system_generated" / "logs"
    main_dir.mkdir(parents=True)
    sub_dir.mkdir(parents=True)

    (main_dir / "transcript_full.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "step_index": 0,
                        "type": "USER_INPUT",
                        "content": "<USER_REQUEST>\nhi\n</USER_REQUEST>\n<USER_SETTINGS_CHANGE>\nThe user changed setting `Model Selection` from None to Claude Sonnet 4.6 (Thinking).\n</USER_SETTINGS_CHANGE>",
                    }
                ),
                json.dumps(
                    {
                        "step_index": 1,
                        "type": "PLANNER_RESPONSE",
                        "created_at": "2026-11-12T12:00:00Z",
                        "input_tokens": 18000,
                        "output_tokens": 120,
                        "cache_read_tokens": 0,
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (sub_dir / "transcript_full.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"step_index": 0, "type": "USER_INPUT", "content": "<SYSTEM_MESSAGE>Subagent brief</SYSTEM_MESSAGE>"}),
                json.dumps(
                    {
                        "step_index": 1,
                        "type": "PLANNER_RESPONSE",
                        "created_at": "2026-11-12T12:01:00Z",
                        "input_tokens": 9000,
                        "output_tokens": 80,
                        "cache_read_tokens": 0,
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    state = empty_usage_state()
    ingest_transcripts(state, roots)
    assert "antigravity|claudesonnet4.6thinking" in state["totals"]
    assert state["preamble"]["antigravity"] == [18000]


def test_measure_antigravity_preamble_counts_lazy_mcp_stems_and_config_rules(tmp_path: Path) -> None:
    import json

    home = tmp_path / "home"
    (home / ".gemini" / "config" / "plugins" / "demo" / "rules").mkdir(parents=True)
    (home / ".gemini" / "GEMINI.md").write_text("g" * 400, encoding="utf-8")
    (home / ".gemini" / "config" / "AGENTS.md").write_text("c" * 800, encoding="utf-8")
    (home / ".gemini" / "config" / "plugins" / "demo" / "rules" / "AGENTS.md").write_text("r" * 400, encoding="utf-8")

    active_srv = home / ".gemini" / "antigravity" / "mcp" / "active_srv"
    disabled_srv = home / ".gemini" / "antigravity" / "mcp" / "disabled_srv"
    active_srv.mkdir(parents=True)
    disabled_srv.mkdir(parents=True)
    big_payload = json.dumps({"description": "x" * 20_000})
    (active_srv / "big_tool.json").write_text(big_payload, encoding="utf-8")
    (disabled_srv / "ignored_tool.json").write_text(big_payload, encoding="utf-8")
    (home / ".gemini" / "antigravity" / "mcp_config.json").write_text(
        json.dumps({"mcpServers": {"disabled_srv": {"disabled": True}, "active_srv": {"disabled": False}}}),
        encoding="utf-8",
    )

    measured = dict(measure_antigravity_preamble(home, None))
    assert measured["user GEMINI.md / AGENTS.md"] == 400
    assert 0 < measured["MCP tool schemas"] < 50


