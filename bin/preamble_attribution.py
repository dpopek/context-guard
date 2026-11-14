#!/usr/bin/env python3
"""Claude Code session preamble split per component and per plugin or MCP server, read from transcript attachments."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from datetime import date, timedelta
from typing import Any, Callable

COMPONENTS = (
    "system_prompt",
    "instructions",
    "skills",
    "deferred_tools",
    "agents",
    "mcp_instructions",
    "hooks",
    "other",
)
CANDIDATE_COMPONENTS = ("skills", "deferred_tools", "agents", "mcp_instructions")
GENERIC_KEYS = frozenset({"standalone", "builtin"})
CANDIDATE_MIN_TOKENS = 500
CANDIDATE_WINDOW_DAYS = 30
CODEX_TOOL_BYTES_PER_TOKEN = 5
DESKTOP_MCP_PREFIX = "mcp:ccd_"
CLAUDE_CLI_HARNESS = "claude (cli)"
CLAUDE_DESKTOP_HARNESS = "claude (desktop)"
CODEX_CLI_HARNESS = "codex (cli)"
CODEX_DESKTOP_HARNESS = "codex (desktop)"
_NOT_INJECTED = frozenset({"hook_success"})
_TARGET_FIELD = {"Skill": "skill", "Agent": "subagent_type", "Task": "subagent_type"}
_ENTRY_RE = re.compile(r"^- (\S+?):(?:\s|$)")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_UNSAFE_RE = re.compile(r"[^A-Za-z0-9_-]")


class MalformedAttachment(ValueError):
    """An attachment record without the fields its type requires."""


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def median(values: list[int]) -> int:
    """Median of integers, the mean of the middle two rounded down for an even count; 0 when empty."""
    if not values:
        return 0
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) // 2


def server_key(server: str) -> str:
    """`mcp:<server>`, characters outside [A-Za-z0-9_-] replaced by `_`, a UUID cut to its first 8 characters."""
    name = _UNSAFE_RE.sub("_", server)
    return "mcp:" + (name[:8] if _UUID_RE.match(name) else name)


def plugin_key(name: str) -> str:
    """The plugin prefix of a `plugin:name` skill or agent, or `standalone`."""
    prefix, separator, _ = name.partition(":")
    return prefix if separator and prefix else "standalone"


def tool_key(name: str) -> str:
    """`mcp:<server>` for an `mcp__<server>__<tool>` name, else `builtin`."""
    if name.startswith("mcp__"):
        server = name[len("mcp__") :].split("__", 1)[0]
        if server:
            return server_key(server)
    return "builtin"


def _texts(value: Any, field: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise MalformedAttachment(field)


def _listing(component: str, text: str, key_fn: Callable[[str], str] = plugin_key) -> list[tuple[str, str, str]]:
    """One part per line: a `- <name>: ...` line opens an entry, the lines after it belong to it."""
    key = "builtin" if key_fn is tool_key else "standalone"
    parts = []
    for line in text.splitlines():
        match = _ENTRY_RE.match(line)
        if match:
            key = key_fn(match.group(1))
        parts.append((component, key, line + "\n"))
    return parts


def _instruction_parts(attachment: dict[str, Any]) -> list[tuple[str, str, str]]:
    files = attachment.get("files")
    if not isinstance(files, list):
        raise MalformedAttachment("files")
    parts = []
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("content"), str):
            raise MalformedAttachment("files[].content")
        parts.append(("instructions", str(item.get("type") or "unknown"), item["content"]))
    return parts


def _mcp_instruction_parts(attachment: dict[str, Any]) -> list[tuple[str, str, str]]:
    names = _texts(attachment.get("addedNames", []), "addedNames")
    blocks = _texts(attachment.get("addedBlocks", []), "addedBlocks")
    if len(names) != len(blocks):
        raise MalformedAttachment("addedNames/addedBlocks")
    return [("mcp_instructions", server_key(name), block) for name, block in zip(names, blocks)]


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _strings(item)]
    return []


def _parts(attachment: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(component, key, injected text) triples of one attachment."""
    kind = attachment["type"]
    if kind == "prompt_snapshot":
        return [("system_prompt", "core", text) for text in _texts(attachment.get("systemPrompt"), "systemPrompt")]
    if kind == "instructions":
        return _instruction_parts(attachment)
    if kind == "skill_listing":
        return _listing("skills", "\n".join(_texts(attachment.get("content"), "content")))
    if kind == "deferred_tools_delta":
        names = _texts(attachment.get("addedNames", []), "addedNames")
        return [("deferred_tools", tool_key(name), name + "\n") for name in names]
    if kind == "agent_listing_delta":
        return _listing("agents", "\n".join(_texts(attachment.get("addedLines", []), "addedLines")))
    if kind == "mcp_instructions_delta":
        return _mcp_instruction_parts(attachment)
    if kind == "hook_additional_context":
        return [("hooks", "all", text) for text in _texts(attachment.get("content"), "content")]
    rest = {name: value for name, value in attachment.items() if name != "type"}
    return [("other", kind, text) for text in _strings(rest)]


def attribute_record(record: dict[str, Any]) -> dict[str, dict[str, int]] | None:
    """Tokens (UTF-8 bytes / 4) per component and key of one attachment record.

    None for records that are not attachments and for `hook_success` (a log of hook stdout, not injected).
    Raises MalformedAttachment when the attachment lacks the fields its type requires.
    """
    if record.get("type") != "attachment":
        return None
    attachment = record.get("attachment")
    if not isinstance(attachment, dict) or not isinstance(attachment.get("type"), str):
        raise MalformedAttachment("attachment.type")
    if attachment["type"] in _NOT_INJECTED:
        return None
    sizes: dict[tuple[str, str], int] = {}
    for component, key, text in _parts(attachment):
        sizes[(component, key)] = sizes.get((component, key), 0) + len(text.encode("utf-8"))
    result: dict[str, dict[str, int]] = {}
    for (component, key), size in sizes.items():
        if size // 4:
            result.setdefault(component, {})[key] = size // 4
    return result


def merge_parts(base: Any, extra: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """A new breakdown with `extra` added to `base`; malformed sections of `base` (read back from a ledger) are dropped."""
    merged: dict[str, dict[str, int]] = {}
    for source in (base if isinstance(base, dict) else {}, extra):
        for component, keys in source.items():
            if not isinstance(keys, dict):
                continue
            row = merged.setdefault(str(component), {})
            for key, value in keys.items():
                row[str(key)] = row.get(str(key), 0) + _int(value)
    return merged


def usage_keys(record: dict[str, Any]) -> list[str]:
    """One plugin or server key per attributable tool call of an assistant record: Skill, Agent or Task, and MCP tools."""
    message = record.get("message") if record.get("type") == "assistant" else None
    content = message.get("content") if isinstance(message, dict) else None
    keys: list[str] = []
    for block in content if isinstance(content, list) else []:
        if not isinstance(block, dict) or block.get("type") != "tool_use" or not isinstance(block.get("name"), str):
            continue
        name = block["name"]
        if name.startswith("mcp__"):
            keys.append(tool_key(name))
            continue
        field = _TARGET_FIELD.get(name)
        arguments = block.get("input")
        target = arguments.get(field) if field and isinstance(arguments, dict) else None
        if isinstance(target, str) and target:
            keys.append(plugin_key(target))
    return keys


def _clean_entries(entries: Any) -> list[dict[str, Any]]:
    return [
        entry
        for entry in (entries if isinstance(entries, list) else [])
        if isinstance(entry, dict) and _int(entry.get("measured")) and isinstance(entry.get("components"), dict)
    ]


def is_claude_desktop_parts(components: Any) -> bool:
    """True when a session's attributed components carry Claude Desktop host MCP servers (`mcp:ccd_*`)."""
    if not isinstance(components, dict):
        return False
    for section_name in ("deferred_tools", "mcp_instructions"):
        section = components.get(section_name)
        if isinstance(section, dict) and any(
            isinstance(key, str) and key.startswith(DESKTOP_MCP_PREFIX) for key in section
        ):
            return True
    return False


def split_claude_parts(entries: Any) -> dict[str, list[dict[str, Any]]]:
    """Partition clean `preamble_parts` entries into `claude (cli)` and `claude (desktop)` cohorts."""
    cli: list[dict[str, Any]] = []
    desktop: list[dict[str, Any]] = []
    for entry in _clean_entries(entries):
        if is_claude_desktop_parts(entry["components"]):
            desktop.append(entry)
        else:
            cli.append(entry)
    return {CLAUDE_CLI_HARNESS: cli, CLAUDE_DESKTOP_HARNESS: desktop}


def _section(entry: dict[str, Any], component: str) -> dict[str, Any]:
    keys = entry["components"].get(component)
    return keys if isinstance(keys, dict) else {}


def summarize_parts(entries: Any) -> dict[str, Any]:
    """Medians over stored sessions of the measured preamble, of each component key and of the unattributed remainder."""
    clean = _clean_entries(entries)
    components: dict[str, dict[str, int]] = {}
    for component in COMPONENTS:
        names = sorted({key for entry in clean for key in _section(entry, component)})
        medians = {name: median([_int(_section(entry, component).get(name)) for entry in clean]) for name in names}
        kept = {name: value for name, value in medians.items() if value}
        if kept:
            components[component] = kept
    remainders = [
        _int(entry["measured"])
        - sum(_int(value) for component in COMPONENTS for value in _section(entry, component).values())
        for entry in clean
    ]
    remainder = median(remainders)
    return {
        "sessions": len(clean),
        "measured": median([_int(entry["measured"]) for entry in clean]),
        "components": components,
        "unattributed": max(0, remainder),
        "clamped": remainder < 0,
    }


def find_candidates(
    entries: Any,
    component_use: Any,
    today: date,
    window_days: int = CANDIDATE_WINDOW_DAYS,
    min_tokens: int = CANDIDATE_MIN_TOKENS,
) -> list[dict[str, Any]]:
    """Plugins and servers whose median preamble share is above `min_tokens` and that had no call in the window ending `today`."""
    clean = _clean_entries(entries)
    start = (today - timedelta(days=window_days - 1)).isoformat()
    end = today.isoformat()
    calls: dict[str, int] = {}
    for day, row in component_use.items() if isinstance(component_use, dict) else []:
        if start <= str(day) <= end and isinstance(row, dict):
            for key, count in row.items():
                calls[str(key)] = calls.get(str(key), 0) + _int(count)
    names = sorted(
        {key for entry in clean for component in CANDIDATE_COMPONENTS for key in _section(entry, component)} - GENERIC_KEYS
    )
    found = []
    for name in names:
        share = median([sum(_int(_section(entry, component).get(name)) for component in CANDIDATE_COMPONENTS) for entry in clean])
        if share > min_tokens and not calls.get(name):
            found.append({"key": name, "tokens": share, "calls": 0})
    return sorted(found, key=lambda row: (-row["tokens"], row["key"]))


def codex_session_traits(record: dict[str, Any]) -> tuple[bool, str] | None:
    """Return `(is_sidechain, cohort)` from a Codex `session_meta` or external-import `task_started` record."""
    rec_type = record.get("type")
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    if rec_type == "session_meta":
        src = payload.get("source")
        is_sidechain = (
            bool(payload.get("parent_thread_id"))
            or (isinstance(src, dict) and "subagent" in src)
            or payload.get("thread_source") in ("subagent", "guardian_review")
        )
        orig = str(payload.get("originator") or "").lower()
        cohort = CODEX_DESKTOP_HARNESS if ("desktop" in orig or src == "vscode") else CODEX_CLI_HARNESS
        return is_sidechain, cohort
    if (
        rec_type == "event_msg"
        and payload.get("type") == "task_started"
        and str(payload.get("turn_id") or "").startswith("external-import-")
    ):
        return True, ""
    return None


def _codex_exec_tool_parts(desc: str) -> list[tuple[str, str, int]]:
    parts: list[tuple[str, str, int]] = []
    sections = desc.split("\n## ")
    if sections[0]:
        parts.append(("deferred_tools", "builtin", len(sections[0].encode("utf-8"))))
    for sec in sections[1:]:
        heading = sec.split("\n", 1)[0].strip()
        key = tool_key(heading) if heading.startswith("mcp__") else "builtin"
        parts.append(("deferred_tools", key, len(("\n## " + sec).encode("utf-8"))))
    return parts


def _codex_tools_parts(tools: Any) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for item in tools if isinstance(tools, list) else []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "namespace":
            out.extend(_codex_tools_parts(item.get("tools")))
            continue
        name = str(item.get("name") or "")
        desc = item.get("description")
        if name == "exec" and isinstance(desc, str):
            out.extend(_codex_exec_tool_parts(desc))
        elif name:
            size = len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
            out.append(("deferred_tools", tool_key(name), size))
    return out


def _codex_message_parts(
    role: str, content: Any, seen_hashes: list[str] | None = None
) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for item in content if isinstance(content, list) else []:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if not isinstance(text, str) or not text:
            continue
        if seen_hashes is not None:
            digest = hashlib.sha256(f"{role}\0{text}".encode("utf-8")).hexdigest()[:24]
            if digest in seen_hashes:
                continue
            seen_hashes.append(digest)
        stripped = text.lstrip()
        nbytes = len(text.encode("utf-8"))
        if stripped.startswith("<app-context>") or stripped.startswith("<codex_apps_"):
            out.append(("other", "app_context", nbytes))
        elif stripped.startswith(
            ("<collaboration_mode>", "<recommended_plugins>", "<multi_agent_role>", "<multi_agent_mode>")
        ):
            out.append(("other", "session_context", nbytes))
        elif "MEMORY_SUMMARY" in text or stripped.startswith("## Memory"):
            out.append(("instructions", "memory", nbytes))
        elif stripped.startswith("<skills_instructions>"):
            for comp, key, line in _listing("skills", text):
                out.append((comp, key, len(line.encode("utf-8"))))
        elif stripped.startswith("<tools>"):
            for comp, key, line in _listing("deferred_tools", text, key_fn=tool_key):
                out.append((comp, key, len(line.encode("utf-8"))))
        elif stripped.startswith(("# AGENTS.md", "<INSTRUCTIONS>")):
            out.append(("instructions", "agents_md", nbytes))
        elif stripped.startswith("<permissions instructions>"):
            out.append(("other", "permissions", nbytes))
        elif stripped.startswith("<environment_context>"):
            out.append(("other", "environment", nbytes))
        elif role == "developer":
            out.append(("system_prompt", "core", nbytes))
    return out


def _codex_sizes_to_parts(raw_parts: list[tuple[str, str, int]], divisor: int) -> dict[str, dict[str, int]] | None:
    if not raw_parts:
        return None
    sizes: dict[tuple[str, str], int] = {}
    for comp, key, nbytes in raw_parts:
        sizes[(comp, key)] = sizes.get((comp, key), 0) + nbytes
    result: dict[str, dict[str, int]] = {}
    for (comp, key), nbytes in sizes.items():
        if nbytes // divisor:
            result.setdefault(comp, {})[key] = nbytes // divisor
    return result or None


def attribute_codex_record(record: dict[str, Any]) -> dict[str, dict[str, int]] | None:
    """Tokens per component and key of one Codex `response_item` record."""
    if record.get("type") != "response_item":
        return None
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    ptype = payload.get("type")
    if ptype == "additional_tools":
        return _codex_sizes_to_parts(_codex_tools_parts(payload.get("tools")), CODEX_TOOL_BYTES_PER_TOKEN)
    if ptype == "message" and payload.get("role") in ("developer", "user"):
        return _codex_sizes_to_parts(_codex_message_parts(str(payload["role"]), payload.get("content")), 4)
    return None


def accumulate_codex_preamble(pending: dict[str, Any] | None, record: dict[str, Any]) -> dict[str, Any] | None:
    """Accumulate Codex preamble parts before first token_count, replacing tool snapshots and deduplicating messages."""
    if record.get("type") != "response_item":
        return pending
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return pending
    ptype = payload.get("type")
    if ptype != "additional_tools" and not (ptype == "message" and payload.get("role") in ("developer", "user")):
        return pending
    if isinstance(pending, dict) and ("tools" in pending or "messages" in pending or "seen" in pending):
        state: dict[str, Any] = {
            "tools": pending.get("tools") if isinstance(pending.get("tools"), dict) else None,
            "messages": pending.get("messages") if isinstance(pending.get("messages"), dict) else None,
            "seen": [item for item in (pending.get("seen") or []) if isinstance(item, str)],
        }
    elif isinstance(pending, dict):
        state = {"tools": None, "messages": pending, "seen": []}
    else:
        state = {"tools": None, "messages": None, "seen": []}

    if ptype == "additional_tools":
        raw_tools = payload.get("tools")
        parts = _codex_sizes_to_parts(_codex_tools_parts(raw_tools), CODEX_TOOL_BYTES_PER_TOKEN)
        if parts:
            state["tools"] = parts
            return state
        if isinstance(raw_tools, list) and state["tools"] is not None:
            state["tools"] = None
            return state
        return pending
    seen = state["seen"]
    parts = _codex_sizes_to_parts(_codex_message_parts(str(payload["role"]), payload.get("content"), seen), 4)
    if parts:
        state["messages"] = merge_parts(state["messages"], parts)
        return state
    return pending


def finalize_codex_preamble(pending: dict[str, Any] | None) -> dict[str, dict[str, int]] | None:
    """Combine the latest Codex tool snapshot and deduplicated message blocks into one breakdown dict."""
    if not isinstance(pending, dict) or not pending:
        return None
    if "tools" not in pending and "messages" not in pending and "seen" not in pending:
        return pending
    merged = merge_parts(pending.get("tools"), pending.get("messages") or {})
    return merged or None


def cap_parts_to_measured(measured: int, components: Any) -> dict[str, dict[str, int]]:
    """Clean component counts and proportionally scale them down when their sum exceeds `measured`."""
    if measured <= 0:
        return {}
    cleaned: dict[str, dict[str, int]] = {}
    if isinstance(components, dict):
        for comp, keys in components.items():
            if not isinstance(keys, dict):
                continue
            row = {str(k): _int(v) for k, v in keys.items() if _int(v)}
            if row:
                cleaned[str(comp)] = row
    total = sum(val for row in cleaned.values() for val in row.values())
    if total <= measured or not total:
        return cleaned
    scaled: dict[str, dict[str, int]] = {}
    for comp, row in cleaned.items():
        new_row = {key: (val * measured) // total for key, val in row.items() if (val * measured) // total}
        if new_row:
            scaled[comp] = new_row
    return scaled


def split_codex_parts(entries: Any) -> dict[str, list[dict[str, Any]]]:
    """Partition clean `codex_preamble_parts` entries into `codex (cli)` and `codex (desktop)` cohorts."""
    cli: list[dict[str, Any]] = []
    desktop: list[dict[str, Any]] = []
    for entry in _clean_entries(entries):
        measured = _int(entry["measured"])
        capped = cap_parts_to_measured(measured, entry["components"])
        normalized = {"measured": measured, "cohort": entry.get("cohort"), "components": capped}
        if entry.get("cohort") == CODEX_DESKTOP_HARNESS:
            desktop.append(normalized)
        else:
            cli.append(normalized)
    return {CODEX_CLI_HARNESS: cli, CODEX_DESKTOP_HARNESS: desktop}


def _read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _skill_frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    block = text[3:end] if end > 0 else ""
    return "\n".join(line for line in block.strip("\n").splitlines() if line.startswith(("name:", "description:")))


def _disabled_antigravity_mcp_servers(home: Path) -> set[str]:
    for cfg_path in (home / ".gemini" / "antigravity" / "mcp_config.json", home / ".gemini" / "config" / "mcp_config.json"):
        if not cfg_path.is_file():
            continue
        try:
            raw = json.loads(_read_text_safe(cfg_path))
        except ValueError:
            continue
        if isinstance(raw, dict) and isinstance(raw.get("mcpServers"), dict):
            return {
                str(name)
                for name, cfg in raw["mcpServers"].items()
                if isinstance(cfg, dict) and cfg.get("disabled") is True
            }
    return set()


def _sum_unique_text_bytes(paths: list[Path]) -> int:
    seen: set[Path] = set()
    total = 0
    for cand in paths:
        if not cand.is_file():
            continue
        try:
            resolved = cand.resolve()
        except OSError:
            resolved = cand
        if resolved not in seen:
            seen.add(resolved)
            total += len(_read_text_safe(resolved).encode("utf-8"))
    return total


def measure_antigravity_preamble(home: Path, project_dir: Path | None = None) -> tuple[tuple[str, int], ...]:
    """Estimate Antigravity pre-turn context (bytes / 4) from GEMINI.md, AGENTS.md, skills, and lazy MCP tool stems."""
    user_paths = [
        home / ".gemini" / "GEMINI.md",
        home / ".gemini" / "AGENTS.md",
        home / ".gemini" / "config" / "AGENTS.md",
        *sorted((home / ".gemini" / "config" / "plugins").glob("*/rules/*.md")),
    ]
    user_bytes = _sum_unique_text_bytes(user_paths)
    ws_bytes = (
        _sum_unique_text_bytes([project_dir / "AGENTS.md", project_dir / ".agents" / "AGENTS.md"])
        if project_dir is not None
        else 0
    )
    skill_paths = (
        sorted((home / ".gemini" / "config" / "skills").glob("*/SKILL.md"))
        + sorted((home / ".gemini" / "config" / "plugins").glob("*/skills/*/SKILL.md"))
        + sorted((home / ".gemini" / "antigravity" / "builtin" / "skills").glob("*/SKILL.md"))
    )
    skill_text = "\n".join(
        fm for fm in (_skill_frontmatter(_read_text_safe(p)) for p in skill_paths) if fm
    )
    disabled_servers = _disabled_antigravity_mcp_servers(home)
    mcp_blocks: list[str] = []
    mcp_root = home / ".gemini" / "antigravity" / "mcp"
    if mcp_root.is_dir():
        for srv_dir in sorted(mcp_root.iterdir()):
            if not srv_dir.is_dir() or srv_dir.name in disabled_servers:
                continue
            stems = sorted(p.stem for p in srv_dir.glob("*.json") if p.is_file())
            if stems:
                mcp_blocks.append(f"# {srv_dir.name}\nLazy:\n" + "\n".join(stems) + "\n")
    mcp_bytes = len("".join(mcp_blocks).encode("utf-8"))
    return (
        ("user GEMINI.md / AGENTS.md", user_bytes // 4),
        ("workspace AGENTS.md", ws_bytes // 4),
        ("skills listing", len(skill_text.encode("utf-8")) // 4),
        ("MCP tool schemas", mcp_bytes // 4),
    )
