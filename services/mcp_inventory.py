"""Passive MCP config/cache discovery, usage correlation, overlap detection, and opt-in stdio probe."""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import IO, Any, Mapping, Sequence

from core.platform_io import read_plugin_version
from services.codex_toml import parse_codex_mcp_servers
from services.preamble_attribution import CODEX_TOOL_BYTES_PER_TOKEN, cap_parts_to_measured, median, server_key
from spool.mcp_server import SPOOL_MCP_TOOL_SCHEMAS
from spool.receipts import same_workspace_dir

SUPPORTED_HARNESSES: tuple[str, ...] = ("antigravity", "claude", "codex", "cursor")
DEFAULT_PROBE_TIMEOUT_S: float = 3.0
MIN_PROBE_TIMEOUT_S: float = 0.2
MAX_PROBE_TIMEOUT_S: float = 30.0
MAX_PROBE_SERVERS: int = 16
MAX_PROBE_STDOUT_BYTES: int = 1_048_576
PROBE_SIDE_EFFECT_WARNING: str = (
    "Active probing (--probe) launches configured local stdio MCP servers to send JSON-RPC "
    "`initialize` and `tools/list`; servers may initiate network connections, spawn child processes, "
    "or trigger auth flows."
)
NATIVE_OVERLAP_PATTERNS: dict[str, tuple[str, ...]] = {
    "file_read": ("read_file", "read_text_file", "read_multiple_files", "get_file_contents", "view_file", "cat"),
    "file_write": ("write_file", "create_file", "edit_file", "patch_file", "replace_file_content"),
    "filesystem_list": ("list_dir", "list_directory", "directory_tree", "find_files", "search_files", "glob", "grep_search"),
    "shell_exec": ("run_command", "execute_command", "bash", "shell", "exec_command"),
    "git_cli": ("git_status", "git_diff", "git_log", "git_show", "git_commit"),
}

_POSIX_USER_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9._-]+")
_WIN_USER_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:(?:[/\\]|\\\\)Users(?:[/\\]|\\\\)[A-Za-z0-9._-]+", re.IGNORECASE)
_UNRESOLVED_TMPL_RE = re.compile(r"\$\{[^}]+\}")
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_SECRET_KV_RE = re.compile(r"(?i)\b(?:bearer\s+\S+|(?:token|api[_-]?key|secret|password|auth)=\S+)")
_SPOOL_SCHEMA_BYTES = len(json.dumps(SPOOL_MCP_TOOL_SCHEMAS, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
_SPOOL_TOOL_NAMES = tuple(str(item["name"]) for item in SPOOL_MCP_TOOL_SCHEMAS)


def _rel_to(target: Path, base: Path) -> Path | None:
    try:
        return target.relative_to(base)
    except ValueError:
        try:
            return target.resolve().relative_to(base.resolve())
        except (OSError, RuntimeError, ValueError):
            return None


def _redact_user_paths(text: str) -> str:
    cleaned = _WIN_USER_RE.sub("~", text)
    return _POSIX_USER_RE.sub("~", cleaned.replace("\\", "/") if cleaned != text else cleaned)


def format_display_path(path: Path, home: Path, workspace_root: Path | None = None) -> str:
    """Format a path relative to workspace or home without exposing OS user directories."""
    target, eff_home = Path(path), Path(home)
    if workspace_root is not None and (rel_ws := _rel_to(target, Path(workspace_root))) is not None:
        return "<workspace>" if str(rel_ws) == "." else f"<workspace>/{rel_ws.as_posix()}"
    if (rel_home := _rel_to(target, eff_home)) is not None:
        return "~" if str(rel_home) == "." else f"~/{rel_home.as_posix()}"
    return _redact_user_paths(target.as_posix())


def _sanitize_text(text: str, home: Path, workspace_root: Path | None = None) -> str:
    out = str(text)
    for base, repl in ((workspace_root, "<workspace>"), (home, "~")):
        if base is None:
            continue
        for cand in (str(base),):
            if cand:
                out = out.replace(cand, repl)
        try:
            res = str(base.resolve())
            if res:
                out = out.replace(res, repl)
        except (OSError, RuntimeError):
            pass
    return _redact_user_paths(_SECRET_KV_RE.sub("<redacted>", _URL_RE.sub("<url>", out)))


def _cmd_basename(cmd: str | None) -> str | None:
    if not isinstance(cmd, str) or not (cleaned := cmd.strip()):
        return None
    return Path(cleaned.replace("\\", "/")).name or None


def _nonneg_int(val: Any) -> int:
    return val if isinstance(val, int) and not isinstance(val, bool) and val > 0 else 0


def _make_server_record(
    name: str, harness: str, scope: str, source: str, transport: str, enabled: bool, command_basename: str | None
) -> dict[str, Any]:
    return {
        "name": name, "normalized_key": server_key(name), "harness": harness, "scope": scope, "source": source,
        "transport": transport, "enabled": enabled, "command_basename": command_basename,
        "schema_status": "unavailable", "tool_count": None, "tool_count_evidence": "unavailable", "tool_names": [],
        "schema_bytes": None, "schema_bytes_evidence": "unavailable", "estimated_tokens": None,
        "token_evidence": "unavailable", "lazy_listing_bytes": None, "lazy_listing_tokens": None,
        "calls_30d": None, "calls_evidence": "unavailable", "transcript_preamble_tokens": None,
        "transcript_tokens_evidence": "unavailable", "probe_status": "not_probed",
        "probe_duration_ms": None, "probe_error": None,
    }


def _is_bundled_spool(name: str, command: str | None, args: Sequence[str]) -> bool:
    if name == "context-guard-spool":
        return True
    return any(isinstance(t, str) and t.strip() and Path(t.strip().replace("\\", "/")).name == "cg_spool.py" for t in (command, *args))


def _apply_bundled_spool(srv: dict[str, Any]) -> None:
    divisor = CODEX_TOOL_BYTES_PER_TOKEN if srv["harness"] == "codex" else 4
    srv.update({
        "schema_status": "bundled", "tool_count": len(_SPOOL_TOOL_NAMES), "tool_count_evidence": "measured",
        "tool_names": list(_SPOOL_TOOL_NAMES), "schema_bytes": _SPOOL_SCHEMA_BYTES,
        "schema_bytes_evidence": "measured", "estimated_tokens": _SPOOL_SCHEMA_BYTES // divisor, "token_evidence": "estimated",
    })


def _apply_antigravity_cache(srv: dict[str, Any], cache_dir: Path) -> bool:
    if not cache_dir.is_dir():
        return False
    try:
        json_files = sorted((p for p in cache_dir.iterdir() if p.is_file() and p.suffix == ".json"), key=lambda p: p.name)
    except OSError:
        return False
    instr_path = cache_dir / "instructions.md"
    has_instr = instr_path.is_file()
    if not json_files and not has_instr:
        return False
    tool_names = [p.stem for p in json_files]
    schema_bytes = 0
    for p in (*json_files, *((instr_path,) if has_instr else ())):
        try:
            schema_bytes += p.stat().st_size
        except OSError:
            pass
    lazy_bytes = len((f"# {srv['name']}\nLazy:\n" + "\n".join(tool_names) + "\n").encode("utf-8")) if tool_names else 0
    srv.update({
        "schema_status": "cached", "tool_names": tool_names, "tool_count": len(tool_names),
        "tool_count_evidence": "measured", "lazy_listing_bytes": lazy_bytes, "lazy_listing_tokens": lazy_bytes // 4,
        "schema_bytes": schema_bytes, "schema_bytes_evidence": "measured", "estimated_tokens": schema_bytes // 4, "token_evidence": "estimated",
    })
    return True


def _read_json_mapping(
    cfg_path: Path, harness: str, home: Path, workspace_root: Path | None, issues: list[dict[str, str]]
) -> Mapping[str, Any] | None:
    if not cfg_path.is_file():
        return None
    disp = format_display_path(cfg_path, home, workspace_root)
    try:
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        issues.append({"path": disp, "harness": harness, "error": f"invalid_json: {_sanitize_text(exc.msg, home, workspace_root)}"})
        return None
    except ValueError as exc:
        issues.append({"path": disp, "harness": harness, "error": f"invalid_json: {_sanitize_text(str(exc), home, workspace_root)}"})
        return None
    except (OSError, UnicodeDecodeError) as exc:
        issues.append({"path": disp, "harness": harness, "error": f"read_error: {type(exc).__name__}"})
        return None
    if not isinstance(raw, Mapping):
        issues.append({"path": disp, "harness": harness, "error": "expected_json_object"})
        return None
    return raw


def _json_transport(cfg: Mapping[str, Any], allow_server_url: bool) -> str:
    if cfg.get("type") in ("http", "sse") or any(
        isinstance((v := cfg.get(k)), str) and v.strip() for k in (("serverUrl", "url") if allow_server_url else ("url",))
    ):
        return "http"
    return "stdio" if isinstance((cmd := cfg.get("command")), str) and cmd.strip() else "unknown"


def _add_json_servers(
    servers_obj: Any, harness: str, scope: str, source: str, disabled_names: set[str], allow_server_url: bool,
    out_servers: list[dict[str, Any]], out_probes: list[dict[str, Any] | None], *,
    seen_filter: set[str] | None = None, cache_root: Path | None = None, issues: list[dict[str, str]] | None = None,
) -> None:
    if servers_obj is None:
        return
    if not isinstance(servers_obj, Mapping):
        if issues is not None:
            issues.append({"path": source, "harness": harness, "error": "invalid_mcpServers_type"})
        return
    for raw_name, cfg in servers_obj.items():
        name = str(raw_name)
        if (seen_filter is not None and name in seen_filter) or not isinstance(cfg, Mapping):
            continue
        if seen_filter is not None:
            seen_filter.add(name)
        raw_cmd = cfg.get("command") if isinstance(cfg.get("command"), str) else None
        raw_args = [str(x) for x in cfg["args"] if isinstance(x, str)] if isinstance(cfg.get("args"), list) else []
        raw_cwd = cfg.get("cwd") if isinstance(cfg.get("cwd"), str) and cfg["cwd"].strip() else None
        raw_env = cfg.get("env")
        env_map = (
            {str(k): str(v) for k, v in raw_env.items() if isinstance(k, str) and isinstance(v, (str, int, float, bool))}
            if isinstance(raw_env, Mapping)
            else {}
        )
        enabled = not bool(cfg.get("disabled") is True or name in disabled_names)
        if cfg.get("disabled") is True:
            disabled_names.add(name)
        rec = _make_server_record(name, harness, scope, source, _json_transport(cfg, allow_server_url), enabled, _cmd_basename(raw_cmd))
        if not (cache_root is not None and _apply_antigravity_cache(rec, cache_root / name)) and _is_bundled_spool(name, raw_cmd, raw_args):
            _apply_bundled_spool(rec)
        out_servers.append(rec)
        probe_spec = (
            {"command": raw_cmd.strip(), "args": raw_args, "env": env_map, "cwd": raw_cwd}
            if rec["transport"] == "stdio" and raw_cmd and raw_cmd.strip()
            else None
        )
        out_probes.append(probe_spec)


def _workspace_key_matches(raw_key: str, workspace_root: Path) -> bool:
    if raw_key == str(workspace_root) or same_workspace_dir(raw_key, workspace_root):
        return True
    if os.path.normcase(os.path.normpath(raw_key)) == os.path.normcase(os.path.normpath(str(workspace_root))):
        return True
    try:
        return os.path.normcase(str(Path(raw_key).resolve())) == os.path.normcase(str(workspace_root.resolve()))
    except (OSError, RuntimeError):
        return False


def _discover_antigravity(
    home: Path, workspace_root: Path | None, servers: list[dict[str, Any]], probes: list[dict[str, Any] | None], issues: list[dict[str, str]]
) -> None:
    seen_names: set[str] = set()
    disabled_names: set[str] = set()
    cache_root = home / ".gemini" / "antigravity" / "mcp"
    for cfg_path in (home / ".gemini" / "antigravity" / "mcp_config.json", home / ".gemini" / "config" / "mcp_config.json"):
        if (data := _read_json_mapping(cfg_path, "antigravity", home, workspace_root, issues)) is not None:
            _add_json_servers(
                data.get("mcpServers"), "antigravity", "user", format_display_path(cfg_path, home, workspace_root),
                disabled_names, True, servers, probes, seen_filter=seen_names, cache_root=cache_root, issues=issues,
            )
    if cache_root.is_dir():
        try:
            subdirs = sorted((p for p in cache_root.iterdir() if p.is_dir()), key=lambda p: p.name)
        except OSError:
            subdirs = []
        for srv_dir in subdirs:
            if srv_dir.name in seen_names:
                continue
            rec = _make_server_record(
                srv_dir.name, "antigravity", "user", format_display_path(srv_dir, home, workspace_root),
                "ide_managed", srv_dir.name not in disabled_names, None,
            )
            if _apply_antigravity_cache(rec, srv_dir):
                servers.append(rec)
                probes.append(None)


def _discover_claude(
    home: Path, workspace_root: Path | None, servers: list[dict[str, Any]], probes: list[dict[str, Any] | None], issues: list[dict[str, str]]
) -> None:
    disabled_mcpjson: set[str] = set()
    if (data := _read_json_mapping(claude_json := home / ".claude.json", "claude", home, workspace_root, issues)) is not None:
        disp = format_display_path(claude_json, home, workspace_root)
        if isinstance(data.get("disabledMcpjsonServers"), list):
            disabled_mcpjson.update(str(x) for x in data["disabledMcpjsonServers"] if isinstance(x, str))
        _add_json_servers(data.get("mcpServers"), "claude", "user", disp, set(), False, servers, probes, issues=issues)
        if workspace_root is not None and isinstance((projects := data.get("projects")), Mapping):
            seen_ws: set[str] = set()
            for proj_key, proj_val in projects.items():
                if isinstance(proj_key, str) and isinstance(proj_val, Mapping) and _workspace_key_matches(proj_key, workspace_root):
                    if isinstance(proj_val.get("disabledMcpjsonServers"), list):
                        disabled_mcpjson.update(str(x) for x in proj_val["disabledMcpjsonServers"] if isinstance(x, str))
                    _add_json_servers(
                        proj_val.get("mcpServers"), "claude", "workspace", disp, set(), False,
                        servers, probes, seen_filter=seen_ws, issues=issues,
                    )
    if (sdata := _read_json_mapping(settings_json := home / ".claude" / "settings.json", "claude", home, workspace_root, issues)) is not None:
        if isinstance(sdata.get("disabledMcpjsonServers"), list):
            disabled_mcpjson.update(str(x) for x in sdata["disabledMcpjsonServers"] if isinstance(x, str))
        _add_json_servers(
            sdata.get("mcpServers"), "claude", "user", format_display_path(settings_json, home, workspace_root),
            set(), False, servers, probes, issues=issues,
        )
    if workspace_root is not None and (mdata := _read_json_mapping(dot_mcp := workspace_root / ".mcp.json", "claude", home, workspace_root, issues)) is not None:
        _add_json_servers(
            mdata.get("mcpServers"), "claude", "workspace", format_display_path(dot_mcp, home, workspace_root),
            disabled_mcpjson, False, servers, probes, issues=issues,
        )


def _discover_cursor(
    home: Path, workspace_root: Path | None, servers: list[dict[str, Any]], probes: list[dict[str, Any] | None], issues: list[dict[str, str]]
) -> None:
    targets = [(home / ".cursor" / "mcp.json", "user")]
    if workspace_root is not None and not same_workspace_dir(home, workspace_root):
        targets.append((workspace_root / ".cursor" / "mcp.json", "workspace"))
    for cfg_path, scope in targets:
        if (data := _read_json_mapping(cfg_path, "cursor", home, workspace_root, issues)) is not None:
            _add_json_servers(
                data.get("mcpServers"), "cursor", scope, format_display_path(cfg_path, home, workspace_root),
                set(), True, servers, probes, issues=issues,
            )


def _discover_codex(
    home: Path, workspace_root: Path | None, servers: list[dict[str, Any]], probes: list[dict[str, Any] | None], issues: list[dict[str, str]]
) -> None:
    targets = [(home / ".codex" / "config.toml", "user")]
    if workspace_root is not None and not same_workspace_dir(home, workspace_root):
        targets.append((workspace_root / ".codex" / "config.toml", "workspace"))
    for cfg_path, scope in targets:
        if not cfg_path.is_file():
            continue
        disp = format_display_path(cfg_path, home, workspace_root)
        try:
            text = cfg_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            issues.append({"path": disp, "harness": "codex", "error": f"read_error: {type(exc).__name__}"})
            continue
        for entry in parse_codex_mcp_servers(text):
            raw_cmd, raw_url = entry.get("command"), entry.get("url")
            raw_args = [str(x) for x in entry["args"] if isinstance(x, str)] if isinstance(entry.get("args"), list) else []
            raw_cwd = entry.get("cwd") if isinstance(entry.get("cwd"), str) and entry["cwd"].strip() else None
            raw_env = entry.get("env")
            env_map = (
                {str(k): str(v) for k, v in raw_env.items() if isinstance(k, str) and isinstance(v, (str, int, float, bool))}
                if isinstance(raw_env, Mapping)
                else {}
            )
            transport = "http" if isinstance(raw_url, str) and raw_url.strip() else ("stdio" if isinstance(raw_cmd, str) and raw_cmd.strip() else "unknown")
            rec = _make_server_record(str(entry["name"]), "codex", scope, disp, transport, bool(entry.get("enabled", True)), _cmd_basename(raw_cmd))
            if _is_bundled_spool(rec["name"], raw_cmd, raw_args):
                _apply_bundled_spool(rec)
            servers.append(rec)
            probe_spec = (
                {"command": raw_cmd.strip(), "args": raw_args, "env": env_map, "cwd": raw_cwd}
                if transport == "stdio" and isinstance(raw_cmd, str) and raw_cmd.strip()
                else None
            )
            probes.append(probe_spec)


def _discover_configs_internal(
    home: Path, workspace_root: Path | None = None, *, harnesses: Sequence[str] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any] | None], list[dict[str, str]]]:
    eff_home, eff_ws = Path(home), Path(workspace_root) if workspace_root is not None else None
    eff_harnesses = [h for h in SUPPORTED_HARNESSES if harnesses is None or h in harnesses]
    servers: list[dict[str, Any]] = []
    probes: list[dict[str, Any] | None] = []
    issues: list[dict[str, str]] = []
    dispatch = {"antigravity": _discover_antigravity, "claude": _discover_claude, "codex": _discover_codex, "cursor": _discover_cursor}
    for harness in eff_harnesses:
        dispatch[harness](eff_home, eff_ws, servers, probes, issues)
    return servers, probes, issues


def discover_passive_mcp_configs(
    home: Path, workspace_root: Path | None = None, *, harnesses: Sequence[str] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Discover configured/cached MCP servers across harnesses with zero subprocesses, network I/O, or secret leaks."""
    servers, _probes, issues = _discover_configs_internal(home, workspace_root, harnesses=harnesses)
    return servers, issues


def _decode_json_dict(raw: bytes) -> dict[str, Any] | None:
    try:
        obj = json.loads(raw.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except (UnicodeDecodeError, ValueError):
        return None


def _consume_rpc_frames(buf: bytearray) -> tuple[list[dict[str, Any]], bool]:
    msgs: list[dict[str, Any]] = []
    while True:
        while buf and buf[0] in b" \t\r\n":
            del buf[0]
        if not buf:
            break
        if buf[0:1] in (b"{", b"["):
            if (nl := buf.find(b"\n")) == -1:
                break
            raw_line = bytes(buf[:nl]).strip()
            del buf[: nl + 1]
            if (obj := _decode_json_dict(raw_line)) is None:
                return msgs, True
            msgs.append(obj)
            continue
        if (first_nl := buf.find(b"\n")) == -1:
            return (msgs, True) if len(buf) > 8192 else (msgs, False)
        if not bytes(buf[:first_nl]).lstrip().lower().startswith((b"content-length:", b"content-type:")):
            return msgs, True
        sep, sep_len = (idx, 4) if (idx := buf.find(b"\r\n\r\n")) != -1 else (buf.find(b"\n\n"), 2)
        if sep == -1:
            return (msgs, True) if len(buf) > 16384 else (msgs, False)
        content_len = next(
            (
                int(v)
                for h in bytes(buf[:sep]).decode("ascii", errors="replace").splitlines()
                if h.lower().startswith("content-length:") and (v := h.split(":", 1)[1].strip()).isdigit()
            ),
            None,
        )
        if content_len is None or content_len < 0:
            return msgs, True
        body_start, body_end = sep + sep_len, sep + sep_len + content_len
        if len(buf) < body_end:
            break
        body = bytes(buf[body_start:body_end])
        del buf[:body_end]
        if (obj := _decode_json_dict(body)) is None:
            return msgs, True
        msgs.append(obj)
    return msgs, False


def _pump_stdout(stream: IO[bytes], out_q: queue.Queue[bytes | None], max_bytes: int) -> None:
    read1_fn, seen = getattr(stream, "read1", None), 0
    try:
        while isinstance((chunk := read1_fn(4096) if callable(read1_fn) else stream.readline()), (bytes, bytearray)) and chunk:
            out_q.put(bytes(chunk))
            seen += len(chunk)
            if seen > max_bytes:
                break
    except (OSError, ValueError):
        pass
    finally:
        out_q.put(None)


def _drain_stderr(stream: IO[bytes]) -> None:
    try:
        while stream.read(4096):
            pass
    except (OSError, ValueError):
        pass


def _probe_result(
    status: str, start: float, *, tool_names: list[str] | None = None, schema_bytes: int | None = None, error: str | None = None
) -> dict[str, Any]:
    names = tool_names if tool_names is not None else []
    return {
        "probe_status": status, "tool_names": names, "tool_count": len(names) if status == "ok" else None,
        "schema_bytes": schema_bytes, "estimated_tokens": (schema_bytes // 4) if schema_bytes is not None else None,
        "probe_duration_ms": round((time.monotonic() - start) * 1000.0, 2), "probe_error": error,
    }


def _send_rpc(stdin: IO[bytes], payload: Mapping[str, Any]) -> None:
    stdin.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n")
    stdin.flush()


def _cleanup_proc(proc: subprocess.Popen[bytes], threads: Sequence[threading.Thread]) -> None:
    if proc.stdin is not None:
        try:
            proc.stdin.close()
        except OSError:
            pass
    if proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                pass
        except OSError:
            pass
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    for th in threads:
        th.join(timeout=0.1)


def probe_stdio_mcp_server(
    command: str, args: Sequence[str] = (), env: Mapping[str, str] | None = None, cwd: Path | None = None,
    *, timeout_s: float = DEFAULT_PROBE_TIMEOUT_S, max_stdout_bytes: int = MAX_PROBE_STDOUT_BYTES,
) -> dict[str, Any]:
    """Launch a stdio MCP server, run `initialize` + `tools/list`, and enforce strict timeout and cleanup."""
    start = time.monotonic()
    eff_timeout = max(MIN_PROBE_TIMEOUT_S, min(MAX_PROBE_TIMEOUT_S, float(timeout_s)))
    eff_max_bytes, deadline = max(1, int(max_stdout_bytes)), start + eff_timeout
    merged_env = {**os.environ, **{str(k): str(v) for k, v in env.items()}} if env else None
    try:
        proc = subprocess.Popen(
            [command, *[str(a) for a in args]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=merged_env, cwd=str(cwd) if cwd is not None else None, shell=False,
        )
    except (OSError, ValueError) as exc:
        err = f"{type(exc).__name__}: {exc.strerror or 'spawn failed'}" if isinstance(exc, OSError) else type(exc).__name__
        return _probe_result("spawn_error", start, error=err)

    out_q: queue.Queue[bytes | None] = queue.Queue()
    threads: list[threading.Thread] = []
    try:
        if proc.stdout is None or proc.stdin is None:
            return _probe_result("spawn_error", start, error="missing stdio pipes")
        threads.append(threading.Thread(target=_pump_stdout, args=(proc.stdout, out_q, eff_max_bytes), daemon=True))
        if proc.stderr is not None:
            threads.append(threading.Thread(target=_drain_stderr, args=(proc.stderr,), daemon=True))
        for th in threads:
            th.start()
        try:
            _send_rpc(
                proc.stdin,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "context-guard", "version": read_plugin_version(default="0.0.0")},
                    },
                },
            )
        except OSError:
            return _probe_result("protocol_error", start, error="stdin closed during initialize")

        buf, total_bytes, stage = bytearray(), 0, 1
        while True:
            if (rem := deadline - time.monotonic()) <= 0:
                return _probe_result("timeout", start, error="probe deadline exceeded")
            try:
                chunk = out_q.get(timeout=rem)
            except queue.Empty:
                return _probe_result("timeout", start, error="probe deadline exceeded")
            if chunk is None:
                return _probe_result("protocol_error", start, error="EOF before tools/list response")
            if (total_bytes := total_bytes + len(chunk)) > eff_max_bytes:
                return _probe_result("output_exceeded", start, error="stdout exceeded limit")
            buf.extend(chunk)
            msgs, proto_err = _consume_rpc_frames(buf)
            if proto_err:
                return _probe_result("protocol_error", start, error="malformed JSON-RPC frame")
            for msg in msgs:
                if msg.get("id") != stage:
                    continue
                if "error" in msg or not isinstance((res := msg.get("result")), Mapping):
                    return _probe_result("protocol_error", start, error=f"RPC error at stage {stage}")
                if stage == 1:
                    stage = 2
                    try:
                        _send_rpc(proc.stdin, {"jsonrpc": "2.0", "method": "notifications/initialized"})
                        _send_rpc(proc.stdin, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                    except OSError:
                        return _probe_result("protocol_error", start, error="stdin closed before tools/list")
                else:
                    if not isinstance((tools_list := res.get("tools")), list):
                        return _probe_result("protocol_error", start, error="tools/list missing tools array")
                    names = [str(it["name"]) for it in tools_list if isinstance(it, Mapping) and isinstance(it.get("name"), str)]
                    sbytes = len(json.dumps(tools_list, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
                    return _probe_result("ok", start, tool_names=names, schema_bytes=sbytes)
    finally:
        _cleanup_proc(proc, threads)


def analyze_mcp_overlaps(servers: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Detect duplicate active server definitions, duplicate tool names, and native tool overlaps."""
    overlaps: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    tool_providers: dict[tuple[str, str], dict[str, str]] = {}
    for srv in (s for s in servers if s.get("enabled") is True):
        harness, nkey, sname = str(srv.get("harness") or ""), str(srv.get("normalized_key") or ""), str(srv.get("name") or "")
        by_key.setdefault((harness, nkey), []).append(srv)
        raw_tools = srv.get("tool_names")
        matched_cats: dict[str, set[str]] = {}
        for tname in (raw_tools if isinstance(raw_tools, (list, tuple)) else ()):
            if not isinstance(tname, str) or not tname:
                continue
            tool_providers.setdefault((harness, tname), {})[nkey] = sname
            low = tname.strip().lower()
            tail = low.split("__", 2)[2] if low.startswith("mcp__") and low.count("__") >= 2 else low
            for cat, patterns in NATIVE_OVERLAP_PATTERNS.items():
                if low in patterns or tail in patterns:
                    matched_cats.setdefault(cat, set()).add(tname)
        for cat, matched in sorted(matched_cats.items()):
            overlaps.append({
                "kind": "native_tool_overlap", "harness": harness, "server": sname, "normalized_key": nkey,
                "category": cat, "matched_tools": sorted(matched),
                "detail": f"{sname} ({harness}) overlaps native {cat} tools: {', '.join(sorted(matched))}",
            })
    for (harness, nkey), group in sorted(by_key.items()):
        if len(group) > 1:
            overlaps.append({
                "kind": "duplicate_server_definition", "harness": harness, "normalized_key": nkey,
                "servers": [str(g.get("name") or "") for g in group],
                "scopes": [str(g.get("scope") or "") for g in group],
                "sources": [str(g.get("source") or "") for g in group],
                "detail": f"{nkey} defined {len(group)} times in {harness}",
            })
    for (harness, tname), providers in sorted(tool_providers.items()):
        if len(providers) > 1:
            overlaps.append({
                "kind": "duplicate_tool_name", "harness": harness, "tool_name": tname,
                "servers": sorted(providers.values()), "detail": f"Tool `{tname}` exposed by multiple active servers in {harness}",
            })
    return sorted(
        overlaps,
        key=lambda r: (str(r.get("kind") or ""), str(r.get("harness") or ""), str(r.get("normalized_key") or r.get("tool_name") or ""), str(r.get("category") or "")),
    )


def _extract_transcript_medians(usage_state: Mapping[str, Any] | None) -> dict[tuple[str, str], int]:
    if not isinstance(usage_state, Mapping):
        return {}
    buckets: dict[tuple[str, str], list[int]] = {}
    for harness, entries, is_codex in (("claude", usage_state.get("preamble_parts"), False), ("codex", usage_state.get("codex_preamble_parts"), True)):
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping) or not isinstance((comps := entry.get("components")), Mapping):
                continue
            measured = _nonneg_int(entry.get("measured"))
            eff_comps = cap_parts_to_measured(measured, comps) if (is_codex and measured > 0) else comps
            per_key: dict[str, int] = {}
            for sec_name in ("deferred_tools", "mcp_instructions"):
                if isinstance((sec := eff_comps.get(sec_name)), Mapping):
                    for k, v in sec.items():
                        if isinstance(k, str) and k.startswith("mcp:") and (tok := _nonneg_int(v)) > 0:
                            per_key[k] = per_key.get(k, 0) + tok
            for k, total in per_key.items():
                buckets.setdefault((harness, k), []).append(total)
    return {pair: median(vals) for pair, vals in buckets.items() if vals and median(vals) > 0}


def _correlate_usage(
    servers: list[dict[str, Any]], probes: list[dict[str, Any] | None],
    usage_state: Mapping[str, Any] | None, eff_harnesses: list[str],
) -> None:
    has_history = bool(usage_state and any(usage_state.get(k) for k in ("totals", "component_use", "preamble", "preamble_parts", "codex_preamble_parts", "cursor_estimates")))
    calls_by_key: dict[str, int] = {}
    if isinstance((comp_use := usage_state.get("component_use") if isinstance(usage_state, Mapping) else None), Mapping):
        for row in comp_use.values():
            if isinstance(row, Mapping):
                for k, v in row.items():
                    if (cnt := _nonneg_int(v)) > 0:
                        calls_by_key[str(k)] = calls_by_key.get(str(k), 0) + cnt
    t_medians = _extract_transcript_medians(usage_state)
    present_keys: set[tuple[str, str]] = set()
    for srv in servers:
        pair = (str(srv["harness"]), str(srv["normalized_key"]))
        present_keys.add(pair)
        if has_history:
            srv.update({"calls_30d": calls_by_key.get(pair[1], 0), "calls_evidence": "measured"})
        if (toks := t_medians.get(pair)) is not None and toks > 0:
            srv.update({"transcript_preamble_tokens": toks, "transcript_tokens_evidence": "measured"})
            if srv["schema_status"] == "unavailable":
                srv["schema_status"] = "transcript_only"
    for (harness, nkey), toks in sorted(t_medians.items()):
        if harness not in eff_harnesses or (harness, nkey) in present_keys:
            continue
        rec = _make_server_record(nkey[len("mcp:") :], harness, "ide_managed", "transcript_ledger", "ide_managed", True, None)
        rec.update({"schema_status": "transcript_only", "transcript_preamble_tokens": toks, "transcript_tokens_evidence": "measured"})
        if has_history:
            rec.update({"calls_30d": calls_by_key.get(nkey, 0), "calls_evidence": "measured"})
        servers.append(rec)
        probes.append(None)


def collect_mcp_inventory(
    home: Path, workspace_root: Path | None = None, usage_state: Mapping[str, Any] | None = None, *,
    harnesses: Sequence[str] | None = None, probe: bool = False,
    probe_servers: Sequence[str] | None = None, probe_timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
) -> dict[str, Any]:
    """Collect cross-harness MCP inventory, correlate usage telemetry, detect overlaps, and optionally probe stdio servers."""
    eff_home, eff_ws = Path(home), Path(workspace_root) if workspace_root is not None else None
    eff_harnesses = [h for h in SUPPORTED_HARNESSES if harnesses is None or h in harnesses]
    servers, probes, config_issues = _discover_configs_internal(eff_home, eff_ws, harnesses=eff_harnesses)
    _correlate_usage(servers, probes, usage_state, eff_harnesses)

    probed_ok, probed_failed = 0, 0
    if probe:
        selected, probed_count = ({str(s) for s in probe_servers} if probe_servers is not None else None), 0
        for srv, spec in zip(servers, probes):
            if not srv["enabled"] or (selected is not None and srv["name"] not in selected and srv["normalized_key"] not in selected):
                continue
            if srv["transport"] != "stdio" or spec is None or not spec["command"]:
                srv["probe_status"] = "skipped_remote_transport"
                continue
            raw_cmd, raw_args, raw_cwd = str(spec["command"]), list(spec["args"]), spec["cwd"]
            if eff_ws is not None:
                ws_str = str(eff_ws)
                raw_cmd = raw_cmd.replace("${workspaceFolder}", ws_str)
                raw_args = [a.replace("${workspaceFolder}", ws_str) for a in raw_args]
                raw_cwd = raw_cwd.replace("${workspaceFolder}", ws_str) if raw_cwd else None
            if any(_UNRESOLVED_TMPL_RE.search(tok) for tok in (raw_cmd, *raw_args, raw_cwd or "")):
                srv["probe_status"] = "skipped_missing_workspace"
                continue
            if probed_count >= MAX_PROBE_SERVERS:
                srv["probe_status"] = "skipped_probe_limit"
                continue
            probed_count += 1
            res = probe_stdio_mcp_server(raw_cmd, raw_args, env=spec["env"], cwd=Path(raw_cwd) if raw_cwd else eff_ws, timeout_s=probe_timeout_s)
            srv.update({
                "probe_status": res["probe_status"], "probe_duration_ms": res["probe_duration_ms"],
                "probe_error": _sanitize_text(res["probe_error"], eff_home, eff_ws) if res["probe_error"] else None,
            })
            if res["probe_status"] == "ok":
                probed_ok += 1
                sbytes = res["schema_bytes"]
                divisor = CODEX_TOOL_BYTES_PER_TOKEN if srv["harness"] == "codex" else 4
                srv.update({
                    "schema_status": "probed", "tool_names": list(res["tool_names"]),
                    "tool_count": res["tool_count"], "tool_count_evidence": "measured",
                    "schema_bytes": sbytes, "schema_bytes_evidence": "measured",
                    "estimated_tokens": (sbytes // divisor) if sbytes is not None else None,
                    "token_evidence": "estimated" if sbytes is not None else "unavailable",
                })
            else:
                probed_failed += 1

    enabled_list = [s for s in servers if s["enabled"]]
    measured_list = [s for s in enabled_list if s["schema_bytes"] is not None]
    enabled_count, measured_count = len(enabled_list), len(measured_list)
    if enabled_count == 0:
        completeness, tools_total, tools_ev, tok_total, tok_ev = "empty", None, "unavailable", None, "unavailable"
    elif measured_count == 0:
        completeness, tools_total, tools_ev, tok_total, tok_ev = "partial", None, "unavailable", None, "unavailable"
    else:
        completeness = "complete" if measured_count == enabled_count else "partial"
        tools_total = sum(int(s["tool_count"] or 0) for s in measured_list)
        tok_total = sum(int(s["estimated_tokens"] or 0) for s in measured_list)
        tools_ev, tok_ev = ("measured", "estimated") if completeness == "complete" else ("partial", "partial")

    return {
        "mode": "probe" if probe else "passive", "probe_warning": PROBE_SIDE_EFFECT_WARNING if probe else None,
        "harnesses_scanned": eff_harnesses, "servers": servers, "overlaps": analyze_mcp_overlaps(servers),
        "config_issues": config_issues,
        "summary": {
            "configured_servers": len(servers), "enabled_servers": enabled_count,
            "measured_schema_servers": measured_count, "unavailable_schema_servers": enabled_count - measured_count,
            "probed_ok": probed_ok, "probed_failed": probed_failed,
            "known_tools_total": tools_total, "known_tools_evidence": tools_ev,
            "estimated_schema_tokens_total": tok_total, "estimated_schema_tokens_evidence": tok_ev, "completeness": completeness,
        },
    }
