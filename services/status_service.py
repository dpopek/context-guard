"""Status, HUD, telemetry formatting, doctor diagnostics, and update notice rendering."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import subprocess
import sys
import threading
from typing import Any

from core.platform_io import LOCK_EX, LOCK_NB, LOCK_UN, flock, read_plugin_version, resolve_plugin_root, warn
from hooks import config, drift_probe
from hooks.outcomes import load_outcomes
from services import harness_status, token_usage, usage_report
from spool.store import inspect_spool_health

ROOT = resolve_plugin_root()
DEFAULT_UPDATE_PATH = ROOT / "telemetry" / "update.json"
_REPO_ROOT = Path(__file__).resolve().parent.parent
UPDATE_CHECK_SCRIPT = (
    (ROOT / "bin" / "update_check.py")
    if (ROOT / "bin" / "update_check.py").is_file()
    else (_REPO_ROOT / "bin" / "update_check.py")
)
UPDATE_LOCK_NAME = "update.lock"
UPDATE_RETRY_BACKOFF_S = 3600
INSTALLED_TELEMETRY_FILES = ("stats.json", "outcomes.json", "token_usage.json")


def detect_checkout_telemetry_mismatch(
    plugin_root: Path | None = None,
    home_dir: Path | None = None,
) -> str | None:
    """Return a diagnostic message when running from a checkout lacking stats.json while live ~/.gemini telemetry exists."""
    if os.environ.get("CONTEXT_GUARD_HOME", "").strip():
        return None
    try:
        active_root = (plugin_root if plugin_root is not None else resolve_plugin_root()).expanduser().resolve()
        effective_home = (home_dir if home_dir is not None else Path.home()).expanduser().resolve()
        installed_root = (effective_home / ".gemini" / "config" / "plugins" / "context-guard").resolve()
        if active_root == installed_root:
            return None
        if (active_root / "telemetry" / "stats.json").is_file():
            return None
        installed_telemetry = installed_root / "telemetry"
        if not any((installed_telemetry / name).is_file() for name in INSTALLED_TELEMETRY_FILES):
            return None
        return (
            f"running from checkout {active_root} without local stats.json while live telemetry exists at "
            f"{installed_telemetry}; set CONTEXT_GUARD_HOME={installed_root} or run "
            f"{installed_root / 'bin' / 'cg_status.py'}."
        )
    except OSError:
        return None


def plugin_version() -> str:
    """Release version from the plugin manifest, the single source of truth."""
    ver = read_plugin_version(ROOT, default="")
    return ver if ver else read_plugin_version(default="unavailable")


def format_compact_tokens(tokens: int) -> str:
    """Format an integer token count into compact human-readable notation."""
    val = max(0, int(tokens))
    if val >= 1_000_000:
        return f"{val / 1_000_000:.1f}M"
    if val >= 1_000:
        return f"{val / 1_000:.1f}k"
    return str(val)


def format_block_gauge(pct: float, width: int = 5) -> str:
    """Render a compact 5-segment Unicode progress bar (e.g. '▰▰▰▱▱')."""
    clamped = max(0.0, min(100.0, float(pct)))
    filled = int(round((clamped / 100.0) * width))
    if clamped > 0.0 and filled == 0:
        filled = 1
    filled = max(0, min(width, filled))
    return ("▰" * filled) + ("▱" * (width - filled))


def render_short_status(stats: dict[str, Any]) -> str:
    """Render compact single-line telemetry status, e.g. 'CG: -68.4k tok (-68.4%)'."""
    saved = max(0, int(stats.get("saved_tokens", 0) or 0))
    pct = max(0.0, float(stats.get("reduction_pct", 0.0) or 0.0))
    if saved == 0:
        return "CG: 0 tok (0.0%)"
    return f"CG: -{format_compact_tokens(saved)} tok (-{pct:.1f}%)"


def render_claude_hud(
    claude_stdin: dict[str, Any], stats: dict[str, Any], update: dict[str, Any] | None = None
) -> str:
    """Render Claude Code statusLine HUD combining session metadata, Context-Guard savings and a pending update."""
    parts: list[str] = []
    if isinstance(claude_stdin, dict):
        model_obj = claude_stdin.get("model")
        if isinstance(model_obj, dict) and model_obj.get("display_name"):
            parts.append(f"[{model_obj['display_name']}]")
        ctx_obj = claude_stdin.get("context_window")
        if isinstance(ctx_obj, dict) and ctx_obj.get("used_percentage") is not None:
            parts.append(f"Ctx {ctx_obj['used_percentage']}%")
    pct = max(0.0, float(stats.get("reduction_pct", 0.0) or 0.0))
    gauge = format_block_gauge(pct)
    parts.append(f"🛡️ {render_short_status(stats)} {gauge}")
    return " · ".join(parts) + render_update_suffix(update)


def load_update(path: Path) -> dict[str, Any] | None:
    """The release check result, or None when missing or unreadable; never moves or rewrites the file."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return raw if isinstance(raw, dict) else None


def render_update_suffix(update: dict[str, Any] | None) -> str:
    """' ⬆ <latest>' for a newer release, ' ⬆ install' for an installer run still due, '' otherwise."""
    if not isinstance(update, dict):
        return ""
    state = update.get("state")
    if state == "update_available" and update.get("latest"):
        return f" ⬆ {update['latest']}"
    if state == "install_pending":
        return " ⬆ install"
    return ""


def render_update_line(update: dict[str, Any] | None, plugin_root: Path) -> str:
    """One Markdown line naming the pending update and the commands that apply it; '' when current."""
    if not isinstance(update, dict):
        return ""
    state = update.get("state")
    root = shlex.quote(plugin_root.as_posix())
    installer = f"python3 {shlex.quote((plugin_root / 'bin' / 'install_harnesses.py').as_posix())} --install"
    if state == "update_available" and update.get("latest"):
        tag = shlex.quote(f"v{update['latest']}")
        return (
            f"> ⬆ Context-Guard {update['latest']} is available (checked out: {update.get('local')}). "
            f"Update: `git -C {root} fetch origin tag {tag} --no-tags"
            f" && git -C {root} merge --ff-only {tag} && {installer}`"
        )
    if state == "install_pending":
        return (
            f"> ⬆ Context-Guard {update.get('local')} is checked out but the installer has not run for it. "
            f"Run: `{installer}`"
        )
    return ""


def update_attempt_is_recent(update_path: Path, now_s: float) -> bool:
    """True when update.lock next to `update_path` was touched less than an hour ago: a check ran or is running."""
    try:
        touched = (update_path.parent / UPDATE_LOCK_NAME).stat().st_mtime
    except OSError:
        return False
    return now_s - touched < UPDATE_RETRY_BACKOFF_S


def spawn_update_check() -> None:
    """Start update_check.py detached; the status line never waits on git."""
    try:
        subprocess.Popen(
            [sys.executable, str(UPDATE_CHECK_SCRIPT)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        warn(f"update check not started: {type(exc).__name__}: {exc}")


def render_markdown_report(stats: dict[str, Any]) -> str:
    """Render a detailed Markdown report of cumulative Context-Guard token savings."""
    installed_at = str(stats.get("installed_at") or "unknown")
    updated_at = str(stats.get("updated_at") or installed_at)
    baseline_tok = max(0, int(stats.get("baseline_tokens", 0) or 0))
    saved_tok = max(0, int(stats.get("saved_tokens", 0) or 0))
    actual_tok = max(0, baseline_tok - saved_tok)
    pct = max(0.0, float(stats.get("reduction_pct", 0.0) or 0.0))
    ctx_windows = round(saved_tok / 200_000.0, 1)
    raw_events = stats.get("events")
    events = raw_events if isinstance(raw_events, dict) else {}
    raw_by_harness = stats.get("by_harness")
    by_harness = raw_by_harness if isinstance(raw_by_harness, dict) else {}

    lines = [
        f"# 🛡️ Context-Guard v{plugin_version()} — Token Savings Report",
        "",
        f"- **Installed since:** `{installed_at}`",
        f"- **Last updated:** `{updated_at}`",
        f"- **Baseline consumption (without Context-Guard):** `{baseline_tok:,}` tokens (`{format_compact_tokens(baseline_tok)}`)",
        f"- **Actual consumption (with Context-Guard):** `{actual_tok:,}` tokens (`{format_compact_tokens(actual_tok)}`)",
        f"- **Cumulative tokens saved:** **`-{saved_tok:,}` tokens (`-{format_compact_tokens(saved_tok)}`)**",
        f"- **Overall token reduction:** **`-{pct:.1f}%`**",
        f"- **Context Windows Saved (200k):** **`~{ctx_windows}x`**",
        "",
        "## Protection Breakdown by Mechanism",
        "",
        "| Mechanism | Count |",
        "|---|---:|",
        f"| AST & JSON Auto-Outlines (`outlines`) | {int(events.get('outlines', 0) or 0):,} |",
        f"| Overlapping Line Ranges Trimmed (`ranges_trimmed`) | {int(events.get('ranges_trimmed', 0) or 0):,} |",
        f"| Quiet CLI Flag Rewrites (`cli_rewrites`) | {int(events.get('cli_rewrites', 0) or 0):,} |",
        f"| Voluntary Outlines (`cg-outline`) | {int(events.get('outline_pulls', 0) or 0):,} |",
        f"| Local-Repo & BigQuery MCP Guards (`mcp_guards`) | {int(events.get('mcp_guards', 0) or 0):,} |",
        f"| Unmodified Allowed Reads (`allowed_reads`) | {int(events.get('allowed_reads', 0) or 0):,} |",
    ]
    for legacy_key, label in (
        ("outputs_spooled", "Oversized Outputs Spooled (`outputs_spooled`)"),
        ("wide_followup_blocks", "Historical Wide Follow-Up Reads Blocked (`wide_followup_blocks`)"),
        ("multi_file_blocks", "Historical Multi-File Batch Reads Blocked (`multi_file_blocks`)"),
        ("rereads_blocked", "Historical Duplicate Re-Reads Blocked (`rereads_blocked`)"),
        ("credit_reversals", "Credits Taken Back After Bypass (`credit_reversals`)"),
    ):
        legacy_val = int(events.get(legacy_key, 0) or 0)
        if legacy_val > 0:
            lines.append(f"| {label} | {legacy_val:,} |")
    lines.extend(_allow_breakdown_lines(stats))
    lines.extend(
        [
            "",
            "## Savings by Harness",
            "",
            "| Harness | Interceptions (`hits`) | Baseline Tokens | Saved Tokens | Reduction |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for h_name in ("antigravity", "claude", "cursor", "codex"):
        raw_h_obj = by_harness.get(h_name)
        h_obj = raw_h_obj if isinstance(raw_h_obj, dict) else {}
        h_hits = int(h_obj.get("hits", 0) or 0)
        h_base = int(h_obj.get("baseline_tokens", 0) or 0)
        h_saved = int(h_obj.get("saved_tokens", 0) or 0)
        h_pct = min(100.0, round(h_saved / h_base * 100.0, 1)) if h_base > 0 else 0.0
        lines.append(f"| `{h_name}` | {h_hits:,} | {h_base:,} | -{h_saved:,} | -{h_pct:.1f}% |")
    lines.extend(_shell_output_lines(stats))
    return "\n".join(lines) + "\n"


def _pct(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "n/a"
    return f"{round(100.0 * numerator / denominator):d}%"


def _bucket_rows(buckets: Any) -> list[tuple[str, int, int]]:
    """(key, count, bytes) rows of a `{key: {"count", "bytes"}}` map, most bytes first."""
    if not isinstance(buckets, dict):
        return []
    rows = [
        (str(key), int(val.get("count", 0) or 0), int(val.get("bytes", 0) or 0))
        for key, val in buckets.items()
        if isinstance(val, dict)
    ]
    return sorted(rows, key=lambda row: (-row[2], row[0]))


def _allow_breakdown_lines(stats: dict[str, Any]) -> list[str]:
    """Markdown tables of why unmodified reads passed; empty when the ledger has no breakdown."""
    section = stats.get("allow_breakdown")
    if not isinstance(section, dict):
        return []
    since = str(section.get("since") or "unknown")
    reasons = [row for row in _bucket_rows(section.get("reasons")) if row[0] != "outline_pull"]
    total_bytes = sum(nbytes for _, _, nbytes in reasons)
    lines = [
        "",
        f"## Unmodified Reads by Reason (since `{since}`)",
        "",
        "| Reason | Count | Tokens | Share |",
        "|---|---:|---:|---:|",
    ]
    for reason, count, nbytes in reasons:
        tok_cell = (
            "0 (excluded)"
            if reason == "binary_media" and nbytes == 0 and count > 0
            else f"{nbytes // 4:,}"
        )
        lines.append(f"| `{reason}` | {count:,} | {tok_cell} | {_pct(nbytes, total_bytes)} |")
    lines.extend(
        [
            "",
            f"## Wide Reads by Extension (since `{since}`)",
            "",
            "| Extension | Count | Tokens |",
            "|---|---:|---:|",
        ]
    )
    for ext, count, nbytes in _bucket_rows(section.get("extensions"))[:10]:
        lines.append(f"| `{ext}` | {count:,} | {nbytes // 4:,} |")
    lines.extend(_outline_pull_lines(section, since))
    return lines


def _outline_pull_lines(section: dict[str, Any], since: str) -> list[str]:
    """Markdown table of outline pulls per harness and how the next read of the file went."""
    raw = section.get("by_harness")
    by_harness = raw if isinstance(raw, dict) else {}
    rows = []
    for harness in sorted(by_harness):
        counts = {reason: count for reason, count, _ in _bucket_rows(by_harness[harness])}
        pulls = counts.get("outline_pull", 0)
        if pulls <= 0:
            continue
        bounded, wide = counts.get("after_pull", 0), counts.get("after_pull_wide", 0)
        rows.append(
            f"| `{harness}` | {pulls:,} | {bounded:,} | {wide:,} | {max(0, pulls - bounded - wide):,} |"
        )
    if not rows:
        return []
    return [
        "",
        f"## Outline Pull (since `{since}`)",
        "",
        "| Harness | Pulls | Next read bounded | Next read wide | No read yet |",
        "|---|---:|---:|---:|---:|",
        *rows,
    ]


def _counter(entry: dict[str, Any], key: str) -> int:
    return int(entry.get(key, 0) or 0)


def _shell_output_lines(stats: dict[str, Any]) -> list[str]:
    """Markdown tables of shell output size per harness and command family."""
    raw_section = stats.get("shell_output")
    section = raw_section if isinstance(raw_section, dict) else {}
    raw_harnesses = section.get("harnesses")
    harnesses = raw_harnesses if isinstance(raw_harnesses, dict) else None
    tables = (
        {h: f for h, f in harnesses.items() if isinstance(f, dict) and f}
        if isinstance(harnesses, dict)
        else {}
    )
    if not tables:
        return ["", "## Shell Output", "", "no shell data yet"]
    since = str(section.get("since") or "unknown")
    lines = ["", f"## Shell Output (since `{since}`)"]
    spilled = 0
    spilled_tokens = 0
    for harness in sorted(tables):
        lines.extend(
            [
                "",
                f"### `{harness}`",
                "",
                "| Family | Calls | Fail | Context tokens | Max | 20k+ chars | Sim hits | Sim saved |",
                "|---|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        rows = [(f, e) for f, e in tables[harness].items() if isinstance(e, dict)]
        for family, entry in sorted(rows, key=lambda row: (-_counter(row[1], "tokens"), row[0])):
            count = _counter(entry, "count")
            tokens = _counter(entry, "tokens")
            saved = _counter(entry, "sim_saved_tokens")
            raw_buckets = entry.get("buckets")
            buckets = raw_buckets if isinstance(raw_buckets, dict) else {}
            large = int(buckets.get("20-30k", 0) or 0) + int(buckets.get(">=30k", 0) or 0)
            spilled += _counter(entry, "spilled")
            spilled_tokens += _counter(entry, "spilled_tokens")
            lines.append(
                f"| `{family}` | {count:,} | {_pct(_counter(entry, 'fail'), count)} | {tokens:,} "
                f"| {_counter(entry, 'max_tokens'):,} | {_pct(large, count)} "
                f"| {_counter(entry, 'sim_hits'):,} | {saved:,} ({_pct(saved, tokens)}) |"
            )
    lines.extend(
        [
            "",
            f"- **Spilled to a file (Claude Code, 30k+ chars):** {spilled:,} calls, "
            f"{spilled_tokens:,} tokens kept out of context",
            f"- **Unparsed payloads:** {int(section.get('unparsed', 0) or 0):,}",
        ]
    )
    return lines


def _usage_inputs(
    stats: dict[str, Any], usage_path: Path | None
) -> tuple[dict[str, Any], int, usage_report.PreambleBreakdown]:
    """Refresh the usage ledger from the transcripts and measure the preamble components of the current directory."""
    saved_now = max(0, int(stats.get("saved_tokens", 0) or 0))
    state = token_usage.refresh_usage(usage_path, saved_tokens_now=saved_now)
    breakdown = usage_report.measure_preamble_components(usage_report.PREAMBLE_HOME, Path.cwd())
    return state, saved_now, breakdown


def usage_lines(stats: dict[str, Any], usage_path: Path | None, outcomes_path: Path | None = None) -> list[str]:
    """The usage sections; a failure shows its class name instead and leaves the rest of the report intact."""
    try:
        return usage_report.render_usage_sections(
            *_usage_inputs(stats, usage_path), stats_state=stats, outcomes_state=load_outcomes(outcomes_path)
        )
    except Exception as exc:
        return ["", "## Token Usage (real, from transcripts)", "", f"_Unavailable: {type(exc).__name__}_"]


def usage_json(stats: dict[str, Any], usage_path: Path | None, outcomes_path: Path | None = None) -> dict[str, Any]:
    """Return JSON-serializable usage telemetry summary; errors fall back to `{'error': <ExcType>}`."""
    try:
        return usage_report.usage_summary(
            *_usage_inputs(stats, usage_path), stats_state=stats, outcomes_state=load_outcomes(outcomes_path)
        )
    except Exception as exc:
        return {"error": type(exc).__name__}


def _read_stream_bounded(stream: Any, max_bytes: int) -> str:
    try:
        buf = getattr(stream, "buffer", None)
        if buf is not None and hasattr(buf, "read1"):
            chunk = buf.read1(max_bytes)
            if isinstance(chunk, (bytes, bytearray)):
                return bytes(chunk).decode("utf-8", errors="replace")
            return str(chunk) if chunk is not None else ""
        data = stream.read(max_bytes)
        if isinstance(data, (bytes, bytearray)):
            return bytes(data).decode("utf-8", errors="replace")
        return str(data) if data is not None else ""
    except (OSError, ValueError):
        return ""


def read_nonblocking_stdin_json(
    timeout_s: float = 0.05,
    max_bytes: int = 262_144,
) -> dict[str, Any]:
    """Read JSON from stdin if piped and ready; return {} on empty, timeout, or invalid input."""
    stream = sys.stdin
    if stream is None:
        return {}
    try:
        if stream.isatty():
            return {}
    except (OSError, ValueError):
        return {}

    raw = ""
    use_thread = sys.platform == "win32"
    if not use_thread:
        try:
            ready, _, _ = select.select([stream], [], [], timeout_s)
            if not ready:
                return {}
            raw = _read_stream_bounded(stream, max_bytes)
        except (OSError, ValueError, io.UnsupportedOperation):
            use_thread = True

    if use_thread:
        holder: list[str] = []

        def _worker() -> None:
            holder.append(_read_stream_bounded(stream, max_bytes))

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(timeout_s)
        if thread.is_alive() or not holder:
            return {}
        raw = holder[0]

    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _check_win32_python3() -> dict[str, Any]:
    p3 = shutil.which("python3")
    if not p3:
        return {"available": False, "path": None, "is_stub": False, "detail": "python3 not found on PATH"}
    is_windows_apps = "windowsapps" in p3.lower()
    try:
        size = Path(p3).stat().st_size
    except OSError:
        if is_windows_apps:
            return {"available": False, "path": None, "is_stub": True, "detail": f"0-byte WindowsApps stub: {p3}"}
        return {"available": True, "path": p3, "is_stub": False, "detail": p3}
    if size == 0:
        return {"available": False, "path": None, "is_stub": True, "detail": f"0-byte WindowsApps stub: {p3}"}
    return {"available": True, "path": p3, "is_stub": False, "detail": p3}


def run_doctor(
    plugin_root: Path | None = None,
    claude_settings_path: Path | None = None,
    cursor_hooks_path: Path | None = None,
    codex_hooks_path: Path | None = None,
    cursor_mcp_path: Path | None = None,
) -> dict[str, Any]:
    """Run cross-OS self-diagnostics across Python runtime, flock, telemetry dir, harnesses, and git."""
    root = plugin_root if plugin_root is not None else ROOT
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = (sys.version_info.major, sys.version_info.minor) >= (3, 9)
    py_info: dict[str, Any] = {"executable": sys.executable, "version": py_ver, "ok": py_ok}
    if sys.platform == "win32":
        p3_check = _check_win32_python3()
        py_info["python3_available"] = p3_check["available"]
        py_info["python3_path"] = p3_check["path"]
        py_info["python3_stub"] = p3_check["is_stub"]
        py_info["python3_detail"] = p3_check["detail"]
    telemetry_dir = root / "telemetry"
    telem_ok = False
    flock_ok = False
    flock_detail = "untested"
    flock_backend = "msvcrt" if sys.platform == "win32" else "fcntl"
    try:
        telemetry_dir.mkdir(parents=True, exist_ok=True)
        telem_ok = telemetry_dir.is_dir() and os.access(telemetry_dir, os.W_OK)
        if telem_ok:
            probe_lock = telemetry_dir / ".doctor_flock.lock"
            with open(probe_lock, "a+", encoding="utf-8") as fh:
                flock(fh.fileno(), LOCK_EX | LOCK_NB)
                flock(fh.fileno(), LOCK_UN)
            try:
                probe_lock.unlink()
            except OSError:
                pass
            flock_ok = True
            flock_detail = f"{flock_backend} lock/unlock succeeded"
        else:
            flock_detail = "telemetry directory is not writable"
    except OSError as exc:
        flock_detail = f"{type(exc).__name__}: {exc}"

    ag_ok = (
        ((root / "hooks.json").is_file() or (root / "hooks" / "hooks.json").is_file())
        and (root / "plugin.json").is_file()
    )
    out_spool_mode = str(config.load_runtime_config().get("optimizers", {}).get("output_spool", "off"))
    ext_harnesses = harness_status.check_status(
        claude_settings_path=claude_settings_path, cursor_hooks_path=cursor_hooks_path, codex_hooks_path=codex_hooks_path
    )
    harness_details = harness_status.verify_harness_hooks(
        claude_settings_path=claude_settings_path,
        cursor_hooks_path=cursor_hooks_path,
        codex_hooks_path=codex_hooks_path,
        output_spool_mode=out_spool_mode,
        cursor_mcp_path=cursor_mcp_path,
    )
    eff_spool = (
        None if (plugin_root is None or os.environ.get("CONTEXT_GUARD_SPOOL_DIR", "").strip()) else (telemetry_dir / "spool")
    )
    try:
        spool_health = inspect_spool_health(eff_spool)
    except OSError as exc:
        spool_health = {
            "spool_dir_exists": False,
            "entry_count": 0,
            "total_bytes": 0,
            "expired_count": 0,
            "orphan_count": 0,
            "summary_line": f"unavailable ({type(exc).__name__})",
        }
    harnesses = {"antigravity": ag_ok, **ext_harnesses}

    is_repo = (root / ".git").exists()
    git_clean: bool | None = None
    if is_repo:
        try:
            proc = subprocess.run(
                ["git", "-C", str(root), "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0:
                git_clean = proc.stdout.strip() == ""
        except (OSError, subprocess.SubprocessError):
            git_clean = None

    dups = usage_report.find_duplicate_skills()
    skill_hygiene = {
        "duplicate_count": len(dups),
        "duplicates": [{"name": name, "paths": [str(p) for p in paths]} for name, paths in dups],
        "ok": True,
    }
    security_drift: dict[str, Any] = {
        "security_active": False,
        "ok": True,
        "drift_codes": [],
        "claude": {},
        "cursor": {},
        "codex": {},
        "remediation": None,
    }
    inspect_fn = getattr(drift_probe, "inspect_native_security_drift", None)
    if callable(inspect_fn):
        try:
            drift_res = inspect_fn(
                claude_settings_path=claude_settings_path,
                cursor_hooks_path=cursor_hooks_path,
                codex_hooks_path=codex_hooks_path,
            )
            if isinstance(drift_res, dict):
                security_drift = drift_res
        except Exception as exc:
            security_drift = {**security_drift, "error": str(exc)}
    overall_ok = bool(py_ok and flock_ok and telem_ok and ag_ok)
    return {
        "ok": overall_ok,
        "version": plugin_version(),
        "platform": sys.platform,
        "python": py_info,
        "flock": {"backend": flock_backend, "ok": flock_ok, "detail": flock_detail},
        "telemetry_dir": {"path": str(telemetry_dir), "writable": telem_ok, "ok": telem_ok},
        "harnesses": harnesses,
        "harness_details": harness_details,
        "git": {"is_repo": is_repo, "clean": git_clean, "ok": True},
        "skill_hygiene": skill_hygiene,
        "security_drift": security_drift,
        "output_spool_mode": out_spool_mode,
        "spool_health": spool_health,
    }


def _format_security_drift_row(sec: dict[str, Any]) -> str:
    codes = [str(c) for c in (sec.get("drift_codes") or []) if c]
    raw_cl, raw_cx = sec.get("claude"), sec.get("codex")
    claude_i: dict[str, Any] = raw_cl if isinstance(raw_cl, dict) else {}
    codex_i: dict[str, Any] = raw_cx if isinstance(raw_cx, dict) else {}
    notes = list(codes)
    if claude_i.get("degraded_older_cli"):
        notes.append("degraded Claude < 2.1.295")
    codex_drift = bool(
        codex_i.get("trust_warning")
        or codex_i.get("features_hooks") is False
        or "27833" in str(codex_i)
        or (
            sec.get("security_active")
            and (codex_i.get("features_hooks_enabled") is False or codex_i.get("has_trust_level") is False)
        )
    )
    if codex_drift:
        notes.append("Codex trust / #27833")
    if sec.get("error"):
        notes.append(f"probe skipped ({sec['error']})")
    status = "WARN" if (notes or sec.get("ok") is False) else "OK"
    detail = "; ".join(notes) if notes else ("synced" if sec.get("security_active") else "inactive")
    return f"| Native security sync | `{status}` | `{detail}` |"


def render_doctor_report(report: dict[str, Any]) -> str:
    """Format `run_doctor` output as a concise Markdown diagnostic table."""
    py = report.get("python", {})
    fl = report.get("flock", {})
    td = report.get("telemetry_dir", {})
    hr = report.get("harnesses", {})
    hd = report.get("harness_details", {})
    gt = report.get("git", {})
    sh = report.get("skill_hygiene", {})
    lines = [
        f"# Context-Guard Doctor (v{report.get('version', 'unknown')})",
        "",
        "| Check | Status | Details |",
        "| :--- | :---: | :--- |",
        f"| Python runtime (`>= 3.9`) | `{'OK' if py.get('ok') else 'FAIL'}` | `{py.get('version')}` (`{py.get('executable')}`) |",
    ]
    if "python3_available" in py:
        p3_ok = bool(py.get("python3_available"))
        lines.append(f"| Windows `python3` | `{'OK' if p3_ok else 'WARN'}` | `{py.get('python3_detail')}` |")
    lines.extend(
        [
            f"| File locking (`flock`) | `{'OK' if fl.get('ok') else 'FAIL'}` | `{fl.get('backend')}` — {fl.get('detail')} |",
            f"| Telemetry directory | `{'OK' if td.get('ok') else 'FAIL'}` | `{td.get('path')}` (`writable={td.get('writable')}`) |",
            f"| Harness: `antigravity` | `{'OK' if hr.get('antigravity') else 'FAIL'}` | `hooks.json` & `plugin.json` |",
        ]
    )
    for name in ("claude", "cursor", "codex"):
        lines.append(
            harness_status.format_doctor_harness_row(
                name, bool(hr.get(name)), hd.get(name) if isinstance(hd, dict) else None
            )
        )
    raw_sp = report.get("spool_health")
    sp_h: dict[str, Any] = raw_sp if isinstance(raw_sp, dict) else {}
    sp_warn = (
        int(sp_h.get("expired_count", 0) or 0) > 0
        or int(sp_h.get("orphan_count", 0) or 0) > 0
        or int(sp_h.get("reliability_failures", 0) or 0) > 0
    )
    lines.append(
        f"| Output spool | `{'WARN' if sp_warn else 'OK'}` | `{sp_h.get('summary_line') or 'empty (0 entries, 0 B)'}` |"
    )
    git_detail = f"is_repo={gt.get('is_repo')}, clean={gt.get('clean')}"
    lines.append(f"| Git workspace | `OK` | `{git_detail}` |")
    dup_count = int(sh.get("duplicate_count", 0) or 0) if isinstance(sh, dict) else 0
    sh_status = "WARN" if dup_count > 0 else "OK"
    sh_detail = f"{dup_count} duplicate skill(s)" if dup_count > 0 else "0 duplicate skills"
    lines.append(f"| Skill hygiene | `{sh_status}` | `{sh_detail}` |")
    raw_sec = report.get("security_drift")
    sec: dict[str, Any] = raw_sec if isinstance(raw_sec, dict) else {}
    lines.append(_format_security_drift_row(sec))
    lines.append("")
    lines.append(f"**Overall status:** `{'OK' if report.get('ok') else 'FAIL'}`")
    return "\n".join(lines) + "\n"
