"""Deterministic replay, latency/savings benchmark, public JSON scrubber, and release hygiene."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from hooks import config, outcomes, policy_engine, post_tool_use, pre_tool_use, state_store, telemetry
from hooks.harness_adapter import normalize_pre_tool_payload

ALLOWED_TEST_USERS = frozenset({"dev", "x", "u", "user", "example", "acme", "alice", "bob", "jan"})
_SCRUB_KEYS = frozenset({
    "config_path", "transcript_path", "shadow_path", "private_policy_stats", "private_policy_stats_path",
    "policy_packs", "pack_details", "file_hashes", "tree_sha256", "repo_map_path", "workspace_root",
    "stats_path", "outcomes_path", "usage_path", "update_path", "state_dir", "home_dir", "shadow", "cwd",
})
_SENSITIVE_FILES = ("shadow.json", "private_policy_stats.json")
_SKIP_DIRS = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", ".venv", "venv"})
_POSIX_HOME_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/([A-Za-z0-9_][A-Za-z0-9._-]*)")
_WIN_HOME_RE = re.compile(r"[A-Za-z]:[/\\](?:Users)[/\\]([A-Za-z0-9_][A-Za-z0-9._-]*)")
_ATLASSIAN_RE = re.compile(r"\b([a-z0-9-]+)\.atlassian\.net\b", re.IGNORECASE)
_LOCAL_EMAIL_RE = re.compile(r"@([A-Za-z0-9_][A-Za-z0-9._-]*)\.local\b", re.IGNORECASE)
_GCP_PROJECT_RE = re.compile(r"\b([a-z][a-z0-9]*-[a-z][a-z0-9]*-\d{5,})(?::[A-Za-z0-9_]+\.[A-Za-z0-9_]+)?\b")
_REMOVED_MOD_RE = re.compile(
    r"(?:hooks[/.](?:governance|local_repo|bigquery)_guard|tests[/.]test_(?:governance|local_repo|bigquery)_[a-z_]+)\b"
)
_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{24,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)
_ENV_KEYS = ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA", "CONTEXT_GUARD_HOME", "CONTEXT_GUARD_CONFIG_PATH")


@contextmanager
def _isolated_runtime(root: Path, cfg_payload: Mapping[str, Any]) -> Iterator[dict[str, Path]]:
    """Redirect env vars, telemetry paths, and caches strictly into TemporaryDirectory."""
    res = root.resolve()
    home_d, cg_d, tel_d, state_d = res / "home", res / "cg_home", res / "telemetry", res / "state"
    for p in (home_d, res / "xdg", res / "appdata", res / "localappdata", cg_d, tel_d, state_d):
        p.mkdir(parents=True, exist_ok=True)
    cfg_p = res / "config.json"
    cfg_p.write_text(json.dumps(cfg_payload, indent=2), encoding="utf-8")
    saved_env = {k: os.environ.get(k) for k in _ENV_KEYS}
    saved_paths = (telemetry.DEFAULT_TELEMETRY_PATH, telemetry.DEFAULT_SHADOW_PATH, outcomes.DEFAULT_OUTCOMES_PATH)
    saved_cfg_default = config.DEFAULT_USER_CONFIG_PATH
    try:
        os.environ.update({
            "HOME": str(home_d), "USERPROFILE": str(home_d), "XDG_CONFIG_HOME": str(res / "xdg"),
            "APPDATA": str(res / "appdata"), "LOCALAPPDATA": str(res / "localappdata"),
            "CONTEXT_GUARD_HOME": str(cg_d), "CONTEXT_GUARD_CONFIG_PATH": str(cfg_p),
        })
        config.DEFAULT_USER_CONFIG_PATH = home_d / ".config" / "context-guard" / "config.json"
        telemetry.DEFAULT_TELEMETRY_PATH = tel_d / "stats.json"
        telemetry.DEFAULT_SHADOW_PATH = tel_d / "shadow.json"
        outcomes.DEFAULT_OUTCOMES_PATH = tel_d / "outcomes.json"
        config.clear_config_cache()
        policy_engine.clear_pack_cache()
        yield {
            "root": res, "home_dir": home_d, "cg_home": cg_d,
            "config_path": cfg_p, "stats_path": tel_d / "stats.json", "state_dir": state_d,
        }
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        config.DEFAULT_USER_CONFIG_PATH = saved_cfg_default
        telemetry.DEFAULT_TELEMETRY_PATH, telemetry.DEFAULT_SHADOW_PATH, outcomes.DEFAULT_OUTCOMES_PATH = saved_paths
        config.clear_config_cache()
        policy_engine.clear_pack_cache()


def _create_synthetic_pack(base_dir: Path) -> dict[str, Any]:
    pack_dir = base_dir / "policies" / "replay_sec"
    pack_dir.mkdir(parents=True, exist_ok=True)
    src = (
        "from __future__ import annotations\n"
        "from policies.api import ALL_SECURITY_SCOPES, PolicyDecision, PolicyPackManifest\n\n"
        "def evaluate(ctx):\n"
        "    cmd = str(ctx.canonical_args.get('CommandLine') or ctx.canonical_args.get('command') or '')\n"
        "    if 'forbidden_replay_cmd' in cmd:\n"
        "        return PolicyDecision(decision='deny', reason='blocked synthetic unsafe transform')\n"
        "    return None\n\n"
        "PACK_MANIFEST = PolicyPackManifest(\n"
        "    pack_id='replay_sec', api_version=1, kind='security',\n"
        "    covered_domains=ALL_SECURITY_SCOPES, evaluate=evaluate, harness_matchers={},\n"
        ")\n"
    ).encode("utf-8")
    entry_f = pack_dir / "pack.py"
    entry_f.write_bytes(src)
    fh = hashlib.sha256(src).hexdigest()
    tree = hashlib.sha256(f"pack.py:{fh}\n".encode("utf-8")).hexdigest()
    return {"id": "replay_sec", "path": str(entry_f), "enabled": True, "file_hashes": {"pack.py": fh}, "tree_sha256": tree}


def _create_corpus(ws: Path) -> tuple[Path, Path, list[str]]:
    ws.mkdir(parents=True, exist_ok=True)
    small_py, large_py = ws / "small_mod.py", ws / "large_mod.py"
    small_py.write_text("\n".join(f"VALUE_{i} = {i}" for i in range(1, 51)) + "\n", encoding="utf-8")
    lines = [f"def compute_item_{idx:03d}(x: int) -> int:\n    return (x + {idx}) * 2  # deterministic padding" for idx in range(200)]
    large_py.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return small_py, large_py, large_py.read_text(encoding="utf-8").splitlines()


def _decision_kind(res: Mapping[str, Any]) -> str:
    if res.get("overwrite") or res.get("updatedInput"):
        return "modify"
    if "permissionDecision" in res:
        return str(res["permissionDecision"])
    hso = res.get("hookSpecificOutput")
    if isinstance(hso, Mapping):
        if hso.get("updatedInput"):
            return "modify"
        if "permissionDecision" in hso:
            return str(hso["permissionDecision"])
    if res.get("permission") in {"allow", "deny", "ask"}:
        return str(res["permission"])
    return str(res.get("decision", "allow"))


def _replay_one_mode(root: Path, mode: str) -> dict[str, Any]:
    mode_dir = (root / f"mode_{mode}").resolve()
    cfg = {
        "read_confirm_policy": mode,
        "optimizers": {"range_trim": "active", "auto_outline": "active", "output_spool": "active", "cli_rewrites": "auto"},
        "regret_window_steps": 2,
        "policy_packs": [_create_synthetic_pack(mode_dir)],
    }
    with _isolated_runtime(mode_dir, cfg) as paths:
        small_py, large_py, all_lines = _create_corpus(mode_dir / "workspace")
        sdir, stats_p = str(paths["state_dir"]), paths["state_dir"] / "telemetry_stats.json"
        decisions: list[dict[str, str]] = []

        ag_p1 = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": str(large_py), "StartLine": 1, "EndLine": 120}, "id": "ag-1"}, "conversationId": f"ag-{mode}"}
        decisions.append({"step": "antigravity:cold_slice", "decision": _decision_kind(pre_tool_use.evaluate_hook(ag_p1, state_dir=sdir, cli_harness="antigravity"))})
        post_tool_use.handle_post_tool_use("antigravity", {**ag_p1, "toolResponse": "\n".join(all_lines[:120])}, stats_path=stats_p, state_dir=sdir)
        ag_p2 = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": str(large_py), "StartLine": 1, "EndLine": 240}, "id": "ag-2"}, "conversationId": f"ag-{mode}"}
        decisions.append({"step": "antigravity:overlap_trim", "decision": _decision_kind(pre_tool_use.evaluate_hook(ag_p2, state_dir=sdir, cli_harness="antigravity"))})
        post_tool_use.handle_post_tool_use("antigravity", {**ag_p2, "toolResponse": "\n".join(all_lines[120:240])}, stats_path=stats_p, state_dir=sdir)
        ag_p3 = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": str(large_py), "StartLine": 1, "EndLine": 240}, "id": "ag-3"}, "conversationId": f"ag-{mode}"}
        decisions.append({"step": "antigravity:warm_dup", "decision": _decision_kind(pre_tool_use.evaluate_hook(ag_p3, state_dir=sdir, cli_harness="antigravity"))})

        cl_p1 = {"tool_name": "Read", "tool_input": {"file_path": str(small_py), "offset": 1, "limit": 50}, "session_id": f"cl-{mode}", "tool_use_id": "cl-1"}
        decisions.append({"step": "claude:pre_1", "decision": _decision_kind(pre_tool_use.evaluate_hook(cl_p1, state_dir=sdir, cli_harness="claude"))})
        cl_p2 = {"tool_name": "Read", "tool_input": {"file_path": str(large_py), "offset": 241, "limit": 120}, "session_id": f"cl-{mode}", "tool_use_id": "cl-2"}
        decisions.append({"step": "claude:pre_batch", "decision": _decision_kind(pre_tool_use.evaluate_hook(cl_p2, state_dir=sdir, cli_harness="claude"))})
        batch_payload = {
            "session_id": f"cl-{mode}",
            "tool_calls": [{"tool_name": "Read", "tool_use_id": "cl-2", "tool_input": {"file_path": str(large_py), "offset": 241, "limit": 120}, "tool_response": [{"type": "text", "text": "\n".join(all_lines[240:360])}]}],
        }
        batch_res = post_tool_use.handle_post_tool_use("claude", batch_payload, stats_path=stats_p, state_dir=sdir, event_name="PostToolBatch")

        cu_sh = {"tool_name": "Shell", "tool_input": {"command": "pytest tests/"}, "session_id": f"cu-{mode}", "call_id": "cu-1"}
        decisions.append({"step": "cursor:shell", "decision": _decision_kind(pre_tool_use.evaluate_hook(cu_sh, state_dir=sdir, cli_harness="cursor"))})
        cx_sh = {"tool_name": "shell", "tool_input": {"command": "git status"}, "session_id": f"cx-{mode}", "call_id": "cx-1"}
        decisions.append({"step": "codex:shell", "decision": _decision_kind(pre_tool_use.evaluate_hook(cx_sh, state_dir=sdir, cli_harness="codex"))})

        rcfg = config.load_runtime_config(paths["config_path"])
        safe_n = normalize_pre_tool_payload({"tool_name": "Shell", "tool_input": {"command": "pytest -q tests/"}}, cli_harness="cursor")
        bad_n = normalize_pre_tool_payload({"tool_name": "Shell", "tool_input": {"command": "forbidden_replay_cmd"}}, cli_harness="cursor")
        p2_safe = policy_engine.verify_security_policies_post_transform(safe_n, rcfg, state_dir_path=paths["state_dir"])
        p2_bad = policy_engine.verify_security_policies_post_transform(bad_n, rcfg, state_dir_path=paths["state_dir"])

        sf = state_store.state_file_in(paths["state_dir"])
        sdata = json.loads(sf.read_text(encoding="utf-8")) if sf.is_file() else {}
        odata = outcomes.load_outcomes(outcomes.ledger_path_for(sdir))
        st = telemetry.load_telemetry_stats(stats_p)
        return {
            "mode": mode, "decisions": decisions, "harnesses": ["antigravity", "claude", "cursor", "codex"],
            "post_tool_batch_ok": batch_res is not None, "read_ledger_schema": int(sdata.get("read_ledger_schema", 0) or 0),
            "outcomes_schema": int(odata.get("schema_version", 0) or 0),
            "outcomes_totals": dict(odata.get("totals") or {}),
            "pass2_safe_allowed": p2_safe is None,
            "pass2_bad_blocked": isinstance(p2_bad, Mapping) and p2_bad.get("decision") == "deny",
            "bytes_saved": int(st.get("saved_bytes", 0) or 0), "tokens_saved": int(st.get("saved_tokens", 0) or 0),
        }


def run_deterministic_replay(modes: tuple[str, ...] = ("strict", "bounded")) -> dict[str, Any]:
    """Run deterministic multi-harness replay corpus inside isolated TemporaryDirectory."""
    with tempfile.TemporaryDirectory(prefix="cg_replay_") as td:
        mode_results = [_replay_one_mode(Path(td), m) for m in modes]
    ok = all(
        r["read_ledger_schema"] == state_store.READ_LEDGER_SCHEMA and r["outcomes_schema"] == outcomes.SCHEMA_VERSION
        and r["pass2_safe_allowed"] and r["pass2_bad_blocked"] for r in mode_results
    )
    return {"ok": ok, "isolated": True, "read_ledger_schema": state_store.READ_LEDGER_SCHEMA, "outcomes_schema": outcomes.SCHEMA_VERSION, "modes": mode_results}


def render_replay_report(result: Mapping[str, Any]) -> str:
    """Format replay result dict as a concise Markdown summary."""
    lines = [
        "## Context-Guard Deterministic Replay", "",
        f"- **Status:** `{'OK' if result.get('ok') else 'FAIL'}` | **Isolated:** `{result.get('isolated')}` | **Ledger:** `v{result.get('read_ledger_schema')}` | **Outcomes:** `v{result.get('outcomes_schema')}`",
        "", "| Mode | Harnesses | Pass-2 | Bytes Saved | Decisions |", "| :--- | :--- | :--- | ---: | :--- |",
    ]
    for item in result.get("modes") or []:
        p2 = "OK" if item.get("pass2_safe_allowed") and item.get("pass2_bad_blocked") else "FAIL"
        decs = ", ".join(f"{d['step']}={d['decision']}" for d in (item.get("decisions") or []))
        lines.append(f"| `{item.get('mode')}` | `4` | `{p2}` | `{item.get('bytes_saved', 0)}` | `{decs}` |")
    return "\n".join(lines) + "\n"


def run_deterministic_benchmark(iterations: int = 3) -> dict[str, Any]:
    """Measure isolated cold/warm latency and byte/token savings over synthetic corpus."""
    iters = max(1, int(iterations))
    cfg = {"read_confirm_policy": "bounded", "optimizers": {"range_trim": "active", "auto_outline": "active", "output_spool": "active", "cli_rewrites": "auto"}, "regret_window_steps": 2, "policy_packs": []}
    with tempfile.TemporaryDirectory(prefix="cg_bench_") as td:
        root = Path(td).resolve()
        with _isolated_runtime(root, cfg) as paths:
            small_py, large_py, all_lines = _create_corpus(root / "workspace")
            sdir, stats_p = str(paths["state_dir"]), paths["state_dir"] / "telemetry_stats.json"
            slice_text = "\n".join(all_lines[:120])
            overlap_text = "\n".join(all_lines[120:200])
            corpus: list[tuple[str, dict[str, Any]]] = [
                ("antigravity", {"toolCall": {"name": "view_file", "args": {"AbsolutePath": str(large_py), "StartLine": 1, "EndLine": 120}}, "conversationId": "bench-ag"}),
                ("claude", {"tool_name": "Read", "tool_input": {"file_path": str(small_py), "offset": 1, "limit": 50}, "session_id": "bench-cl"}),
                ("cursor", {"tool_name": "Shell", "tool_input": {"command": "git status"}, "session_id": "bench-cu"}),
                ("codex", {"tool_name": "shell", "tool_input": {"command": "pytest tests/"}, "session_id": "bench-cx"}),
            ]
            raw_bytes = large_py.stat().st_size + small_py.stat().st_size
            t0 = time.perf_counter()
            for idx, (harness, payload) in enumerate(corpus):
                pre_tool_use.evaluate_hook({**payload, "call_id": f"cold-{idx}", "tool_use_id": f"cold-{idx}"}, state_dir=sdir, cli_harness=harness)
                if harness == "antigravity":
                    tc = dict(payload["toolCall"]) if isinstance(payload.get("toolCall"), Mapping) else {}
                    post_tool_use.handle_post_tool_use(harness, {**payload, "toolCall": {**tc, "id": f"cold-{idx}"}, "toolResponse": slice_text}, stats_path=stats_p, state_dir=sdir)
            cold_ms = (time.perf_counter() - t0) * 1000.0
            t1 = time.perf_counter()
            for rep_i in range(iters):
                for idx, (harness, payload) in enumerate(corpus):
                    if harness == "antigravity":
                        ov = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": str(large_py), "StartLine": 1, "EndLine": 200}, "id": f"w-{rep_i}"}, "conversationId": "bench-ag"}
                        pre_tool_use.evaluate_hook(ov, state_dir=sdir, cli_harness="antigravity")
                        post_tool_use.handle_post_tool_use("antigravity", {**ov, "toolResponse": overlap_text}, stats_path=stats_p, state_dir=sdir)
                    else:
                        pre_tool_use.evaluate_hook({**payload, "call_id": f"w-{rep_i}-{idx}", "tool_use_id": f"w-{rep_i}-{idx}"}, state_dir=sdir, cli_harness=harness)
            warm_ms = (time.perf_counter() - t1) * 1000.0
            repo_root = Path(__file__).resolve().parent.parent
            pre_tool_script = repo_root / "hooks" / "pre_tool_use.py"
            sub_iters = max(1, min(iters, 3))
            sub_payload = {
                "tool_name": "Read",
                "tool_input": {"file_path": str(small_py), "offset": 1, "limit": 50},
                "session_id": "bench-cl-sub",
                "call_id": "bench-sub-0",
                "tool_use_id": "bench-sub-0",
            }
            sub_env = {
                **os.environ,
                "HOME": str(paths["home_dir"]),
                "USERPROFILE": str(paths["home_dir"]),
                "XDG_CONFIG_HOME": str(paths["root"] / "xdg"),
                "APPDATA": str(paths["root"] / "appdata"),
                "LOCALAPPDATA": str(paths["root"] / "localappdata"),
                "CONTEXT_GUARD_HOME": str(paths["cg_home"]),
                "CONTEXT_GUARD_CONFIG_PATH": str(paths["config_path"]),
                "TMPDIR": str(paths["state_dir"]),
                "TMP": str(paths["state_dir"]),
                "TEMP": str(paths["state_dir"]),
                "PYTHONPATH": str(repo_root),
                "PYTHONIOENCODING": "utf-8",
            }
            sub_env.pop("CONTEXT_GUARD_STATE_DIR", None)
            sub_ok = True
            t2 = time.perf_counter()
            for sub_i in range(sub_iters):
                call_payload = {**sub_payload, "call_id": f"bench-sub-{sub_i}", "tool_use_id": f"bench-sub-{sub_i}"}
                proc = subprocess.run(
                    [sys.executable, str(pre_tool_script), "--harness", "claude"],
                    input=json.dumps(call_payload),
                    text=True,
                    encoding="utf-8",
                    capture_output=True,
                    env=sub_env,
                    check=False,
                )
                if proc.returncode != 0:
                    sub_ok = False
            sub_ms = (time.perf_counter() - t2) * 1000.0
            st = telemetry.load_telemetry_stats(stats_p)
            saved_bytes, saved_tokens = int(st.get("saved_bytes", 0) or 0), int(st.get("saved_tokens", 0) or 0)
            baseline_bytes = int(st.get("baseline_bytes", 0) or 0)
            total_raw = max(1, baseline_bytes or (raw_bytes * iters))
            delivered = max(0, total_raw - saved_bytes)
            pct = round(min(100.0, (saved_bytes / total_raw) * 100.0), 2)
            warm_calls = max(1, iters * len(corpus))
    in_cold_ms, in_warm_ms = round(cold_ms, 3), round(warm_ms, 3)
    in_warm_per_call = round(warm_ms / warm_calls, 4)
    return {
        "ok": sub_ok,
        "isolated": True,
        "measurement_scope": "synthetic_corpus",
        "iterations": iters,
        "corpus_calls": len(corpus),
        "cold_ms": in_cold_ms,
        "warm_ms": in_warm_ms,
        "warm_ms_per_call": in_warm_per_call,
        "in_process_cold_ms": in_cold_ms,
        "in_process_warm_ms": in_warm_ms,
        "in_process_warm_ms_per_call": in_warm_per_call,
        "subprocess_hook_ms_per_call": round(sub_ms / sub_iters, 3),
        "raw_bytes": total_raw,
        "delivered_bytes": delivered,
        "saved_bytes": saved_bytes,
        "saved_tokens": saved_tokens,
        "savings_pct": pct,
    }


def render_benchmark_report(result: Mapping[str, Any]) -> str:
    """Format benchmark result dict as Markdown."""
    in_cold = result.get("in_process_cold_ms", result.get("cold_ms", 0))
    in_warm = result.get("in_process_warm_ms", result.get("warm_ms", 0))
    in_warm_pc = result.get("in_process_warm_ms_per_call", result.get("warm_ms_per_call", 0))
    sub_pc = result.get("subprocess_hook_ms_per_call", 0)
    return "\n".join([
        "## Context-Guard Deterministic Benchmark",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Status | `{'OK' if result.get('ok') else 'FAIL'}` |",
        "| Benchmark scope | `synthetic corpus (not live session A/B)` |",
        f"| In-process engine cold latency | `{in_cold} ms` |",
        f"| In-process engine warm latency (`{result.get('iterations', 0)}`x) | `{in_warm} ms` (`{in_warm_pc} ms/call`) |",
        f"| Subprocess E2E hook latency (`PreToolUse`) | `{sub_pc} ms/call` |",
        f"| Bytes saved (synthetic corpus) | `{result.get('saved_bytes', 0)}` (`{result.get('savings_pct', 0)}%`) |",
        f"| Tokens saved (synthetic est.) | `{result.get('saved_tokens', 0)}` |",
        "",
    ])


def _scrub_string(text: str) -> str:
    cleaned = text
    for name in _SENSITIVE_FILES:
        if name in cleaned:
            cleaned = cleaned.replace(name, "[redacted]")
    cleaned = _POSIX_HOME_RE.sub("[redacted-path]", cleaned)
    cleaned = _WIN_HOME_RE.sub("[redacted-path]", cleaned)
    cleaned = _ATLASSIAN_RE.sub(lambda m: m.group(0) if m.group(1).lower() in {"acme", "example"} else "[redacted-domain]", cleaned)
    cleaned = _LOCAL_EMAIL_RE.sub(lambda m: m.group(0) if m.group(1).lower() in {"acme", "example", "localhost"} else "[redacted-email]", cleaned)
    return _GCP_PROJECT_RE.sub("[redacted-project]", cleaned)


def _is_forbidden_key(key: str) -> bool:
    kl = key.lower()
    return kl in _SCRUB_KEYS or kl.endswith(("_path", "_paths", "_dir", "_dirs")) or any(
        tok in kl for tok in ("shadow", "private_policy", "policy_pack", "transcript")
    )


def _scrub_value(val: Any) -> Any:
    if isinstance(val, Mapping):
        return {
            str(k): _scrub_value(v)
            for k, v in val.items()
            if not _is_forbidden_key(str(k)) and not any(sf in str(k).lower() for sf in _SENSITIVE_FILES)
        }
    if isinstance(val, list):
        return [_scrub_value(elem) for elem in val if not (isinstance(elem, str) and any(sf in elem for sf in _SENSITIVE_FILES))]
    return _scrub_string(val) if isinstance(val, str) else val


def build_public_json_bundle(
    stats: Mapping[str, Any],
    usage: Mapping[str, Any],
    outcomes_data: Mapping[str, Any],
    update: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return scrubbed JSON telemetry bundle safe for public diagnostics and sharing."""
    raw = {
        "public": True,
        "stats": dict(stats),
        "token_usage": dict(usage),
        "outcomes": {
            "schema_version": outcomes_data.get("schema_version", outcomes.SCHEMA_VERSION),
            "totals": dict(outcomes_data.get("totals") or {}) if isinstance(outcomes_data.get("totals"), Mapping) else {},
        },
        "update": dict(update) if isinstance(update, Mapping) else {},
    }
    scrubbed = _scrub_value(raw)
    return scrubbed if isinstance(scrubbed, dict) else {"public": True}


def _collect_repo_files(repo_root: Path) -> list[Path]:
    if (repo_root / ".git").exists():
        proc = subprocess.run(["git", "-C", str(repo_root), "ls-files", "-z"], capture_output=True, timeout=10, check=False)
        if proc.returncode == 0 and proc.stdout:
            return [repo_root / rel for rel in proc.stdout.decode("utf-8", errors="replace").split("\0") if rel]
    collected: list[Path] = []
    for dp, dirs, files in os.walk(str(repo_root), followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        collected.extend(Path(dp) / fn for fn in sorted(files))
    return collected


def _scan_text_hygiene(rel: str, text: str, *, allow_synthetic_tests: bool) -> list[str]:
    issues: list[str] = []
    for pat in (_POSIX_HOME_RE, _WIN_HOME_RE):
        for m in pat.finditer(text):
            if allow_synthetic_tests and m.group(1).lower() in ALLOWED_TEST_USERS:
                continue
            issues.append(f"{rel}: home-directory path reference ({m.group(0)})")
            break
    for m in _ATLASSIAN_RE.finditer(text):
        if m.group(1).lower() not in {"acme", "example"}:
            issues.append(f"{rel}: private Atlassian domain ({m.group(0)})")
            break
    for m in _LOCAL_EMAIL_RE.finditer(text):
        if m.group(1).lower() not in {"acme", "example", "localhost"}:
            issues.append(f"{rel}: internal .local address ({m.group(0)})")
            break
    if (gm := _GCP_PROJECT_RE.search(text)) is not None:
        issues.append(f"{rel}: GCP-style project identifier ({gm.group(0)})")
    if _REMOVED_MOD_RE.search(text):
        issues.append(f"{rel}: removed private domain module reference")
    return issues


def check_release_hygiene(root: Path | None = None, public_bundle: Mapping[str, Any] | None = None) -> list[str]:
    """Pure query auditing tracked files and optional public bundle for release leaks."""
    repo_root = (root or state_store.resolve_plugin_root()).resolve()
    issues: list[str] = []
    if (repo_root / "docs").is_dir():
        issues.append("docs/: disallowed docs directory present")
    for path in _collect_repo_files(repo_root):
        try:
            rel = path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if rel == "docs" or rel.startswith("docs/"):
            issues.append(f"{rel}: disallowed docs/ artifact")
            continue
        if not path.is_file() or path.suffix.lower() in {".png", ".svg", ".ico", ".pyc", ".whl", ".zip"}:
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" not in raw[:4096]:
            issues.extend(_scan_text_hygiene(rel, raw.decode("utf-8", errors="replace"), allow_synthetic_tests=rel.startswith("tests/")))
    if public_bundle is not None:
        dumped = json.dumps(public_bundle, sort_keys=True)
        for sf in _SENSITIVE_FILES:
            if sf in dumped:
                issues.append(f"public_bundle: disallowed reference to {sf}")
        for fk in ("config_path", "transcript_path", "policy_packs"):
            if f'"{fk}"' in dumped:
                issues.append(f"public_bundle: disallowed key {fk}")
        issues.extend(_scan_text_hygiene("public_bundle", dumped, allow_synthetic_tests=False))
    return issues


def check_git_history_secrets(root: Path | None = None) -> list[str]:
    """Pure query scanning git history added lines for high-confidence secret patterns."""
    repo_root = (root or state_store.resolve_plugin_root()).resolve()
    if not (repo_root / ".git").exists():
        return []
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "log", "--all", "-p", "--no-color"],
        capture_output=True, text=True, errors="replace", timeout=15, check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        return []
    findings: list[str] = []
    commit_id = "unknown"
    for line in proc.stdout.splitlines():
        if line.startswith("commit "):
            commit_id = line.split()[1][:10]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for label, pat in _SECRET_RULES:
            if pat.search(line):
                findings.append(f"{commit_id}: matched {label}")
    return findings
