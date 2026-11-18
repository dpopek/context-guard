"""Deterministic replay, latency/savings benchmark, public JSON scrubber, and release hygiene."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from hooks import config, outcomes, policy_engine, post_tool_use, pre_tool_use, state_store, telemetry
from hooks.harness_adapter import normalize_pre_tool_payload

ALLOWED_TEST_USERS = frozenset({"dev", "x", "u", "user", "example", "acme", "alice", "bob", "jan"})
_SPOOL_ID_FIND_RE = re.compile(r"\bsp_[0-9a-f]{12}\b")
_WS_ID_FIND_RE = re.compile(r"\bws_[0-9a-f]{16}\b")
_SCRUB_KEYS = frozenset({
    "config_path", "transcript_path", "shadow_path", "private_policy_stats", "private_policy_stats_path",
    "policy_packs", "pack_details", "file_hashes", "tree_sha256", "repo_map_path", "workspace_root",
    "stats_path", "outcomes_path", "usage_path", "update_path", "state_dir", "home_dir", "shadow", "cwd",
    "spool_dir", "spool_path", "spool_index", "receipts_path", "receipts_dir", "receipts_index",
    "workspace_id", "canon_root", "spool_id", "session_id",
})
_SENSITIVE_FILES = ("shadow.json", "private_policy_stats.json", "spool_index.json", "receipts.jsonl")
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
_ENV_KEYS = ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA", "CONTEXT_GUARD_HOME", "CONTEXT_GUARD_CONFIG_PATH", "CONTEXT_GUARD_SPOOL_DIR")


@contextmanager
def _isolated_runtime(root: Path, cfg_payload: Mapping[str, Any]) -> Iterator[dict[str, Path]]:
    """Redirect env vars, telemetry paths, and caches strictly into TemporaryDirectory."""
    res = root.resolve()
    home_d, cg_d, tel_d, state_d, spool_d = res / "home", res / "cg_home", res / "telemetry", res / "state", res / "spool"
    for p in (home_d, res / "xdg", res / "appdata", res / "localappdata", cg_d, tel_d, state_d, spool_d):
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
            "CONTEXT_GUARD_SPOOL_DIR": str(spool_d),
        })
        config.DEFAULT_USER_CONFIG_PATH = home_d / ".config" / "context-guard" / "config.json"
        telemetry.DEFAULT_TELEMETRY_PATH = tel_d / "stats.json"
        telemetry.DEFAULT_SHADOW_PATH = tel_d / "shadow.json"
        outcomes.DEFAULT_OUTCOMES_PATH = tel_d / "outcomes.json"
        config.clear_config_cache()
        policy_engine.clear_pack_cache()
        yield {
            "root": res, "home_dir": home_d, "cg_home": cg_d, "spool_dir": spool_d,
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
    if "updated_mcp_tool_output" in res:
        return "spooled"
    if res.get("overwrite") or res.get("updatedInput"):
        return "modify"
    if "permissionDecision" in res:
        return str(res["permissionDecision"])
    hso = res.get("hookSpecificOutput")
    if isinstance(hso, Mapping):
        if "updatedToolOutput" in hso:
            return "spooled"
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
        ws_dir = str(mode_dir / "workspace")
        spool_out = "\n".join(f"line-{i:04d}: " + ("x" * 70) for i in range(260))
        spool_payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "pytest -vv tests/"},
            "tool_response": {"stdout": spool_out, "stderr": ""},
            "session_id": f"cl-{mode}",
            "tool_use_id": "cl-spool-1",
            "cwd": ws_dir,
        }
        spool_res = post_tool_use.handle_post_tool_use("claude", spool_payload, stats_path=stats_p, state_dir=sdir)
        decisions.append({"step": "claude:post_spool", "decision": _decision_kind(spool_res)})
        sp_hso = spool_res.get("hookSpecificOutput") if isinstance(spool_res, Mapping) else None
        sp_txt = str(sp_hso.get("updatedToolOutput") or "") if isinstance(sp_hso, Mapping) else ""
        sp_match = _SPOOL_ID_FIND_RE.search(sp_txt)
        if sp_match is not None:
            cl_slice = {
                "tool_name": "Bash",
                "tool_input": {"command": f"cg-spool slice {sp_match.group(0)} --start 1 --limit 80"},
                "session_id": f"cl-{mode}",
                "tool_use_id": "cl-spool-slice-1",
                "cwd": ws_dir,
            }
            decisions.append({"step": "claude:spool_slice_recovery", "decision": _decision_kind(pre_tool_use.evaluate_hook(cl_slice, state_dir=sdir, cli_harness="claude"))})

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
        and r["pass2_safe_allowed"] and r["pass2_bad_blocked"]
        and any(d["step"] == "claude:post_spool" and d["decision"] == "spooled" for d in r["decisions"])
        and any(d["step"] == "claude:spool_slice_recovery" and d["decision"] == "allow" for d in r["decisions"])
        for r in mode_results
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


def compute_latency_percentiles(samples_ms: Sequence[float]) -> dict[str, float]:
    """Compute monotonic latency percentiles (`min`, `p50`, `p95`, `p99`, `max`, `mean`) in ms."""
    ordered = sorted(
        max(0.0, float(val)) for val in samples_ms
        if not isinstance(val, bool) and isinstance(val, (int, float)) and math.isfinite(float(val))
    )
    count = len(ordered)
    if count == 0:
        return {"count": 0, "min_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0}
    min_v, max_v, mean_v = round(ordered[0], 4), round(ordered[-1], 4), round(sum(ordered) / count, 4)

    def _quantile(q: float) -> float:
        pos = q * (count - 1)
        lo, hi = int(math.floor(pos)), min(count - 1, int(math.floor(pos)) + 1)
        return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo), 4)

    p50_v = min(max_v, max(min_v, _quantile(0.50)))
    p95_v = min(max_v, max(p50_v, _quantile(0.95)))
    p99_v = min(max_v, max(p95_v, _quantile(0.99)))
    return {"count": count, "min_ms": min_v, "p50_ms": p50_v, "p95_ms": p95_v, "p99_ms": p99_v, "max_ms": max_v, "mean_ms": mean_v}


def _seed_ledger_entries(file_count: int = 30) -> dict[str, dict[str, Any]]:
    return {
        f"repo/src/mod_{idx:02d}.py": {
            "sha256": hashlib.sha256(f"seed-mod-{idx}".encode("utf-8")).hexdigest(),
            "reads": [[1, 120, idx + 1, 2], [160, 260, idx + 2, 2]],
        }
        for idx in range(file_count)
    }


def _bench_json_lock_backend(work_dir: Path, operations: int) -> dict[str, Any]:
    with state_store.locked_state(work_dir) as txn:
        txn.state["files"], txn.dirty = _seed_ledger_entries(30), True
    samples_ms: list[float] = []
    for op_i in range(operations):
        key, iv = f"repo/src/mod_{op_i % 30:02d}.py", [1 + (op_i % 8) * 25, 30 + (op_i % 8) * 25, 100 + op_i, 2]
        t0 = time.perf_counter()
        with state_store.locked_state(work_dir) as txn:
            ent = txn.state.setdefault("files", {}).setdefault(key, {"sha256": "", "reads": []})
            ent["reads"] = state_store.merge_intervals([*list(ent.get("reads") or []), iv])
            txn.state["auto_step_seq"], txn.dirty = 100 + op_i, True
        samples_ms.append((time.perf_counter() - t0) * 1000.0)
    sf, snap = state_store.state_file_in(work_dir), state_store.read_state_snapshot(work_dir)
    return {
        "backend": "json_lock", "read_ledger_schema": int(snap.get("read_ledger_schema", 0) or 0),
        "final_bytes": sf.stat().st_size if sf.is_file() else 0, **compute_latency_percentiles(samples_ms),
    }


def _bench_sqlite_wal_backend(work_dir: Path, operations: int) -> dict[str, Any]:
    work_dir.mkdir(parents=True, exist_ok=True)
    db_path, samples_ms, journal_mode = work_dir / "read_ledger_bench.sqlite3", [], "wal"
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        j_row = conn.execute("PRAGMA journal_mode=WAL").fetchone()
        if j_row and j_row[0]:
            journal_mode = str(j_row[0]).lower()
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("CREATE TABLE IF NOT EXISTS ledger_files (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, reads_json TEXT NOT NULL, step_seq INTEGER NOT NULL)")
        for path_k, entry in _seed_ledger_entries(30).items():
            conn.execute("INSERT OR REPLACE INTO ledger_files VALUES (?, ?, ?, ?)", (path_k, str(entry["sha256"]), json.dumps(entry["reads"], separators=(",", ":")), 1))
        conn.commit()
        for op_i in range(operations):
            key, iv = f"repo/src/mod_{op_i % 30:02d}.py", [1 + (op_i % 8) * 25, 30 + (op_i % 8) * 25, 100 + op_i, 2]
            t0 = time.perf_counter()
            row = conn.execute("SELECT sha256, reads_json FROM ledger_files WHERE path = ?", (key,)).fetchone()
            sha, reads = (str(row[0]), json.loads(str(row[1]))) if row else ("", [])
            merged = state_store.merge_intervals([*reads, iv])
            conn.execute("INSERT OR REPLACE INTO ledger_files VALUES (?, ?, ?, ?)", (key, sha, json.dumps(merged, separators=(",", ":")), 100 + op_i))
            conn.commit()
            samples_ms.append((time.perf_counter() - t0) * 1000.0)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
    finally:
        conn.close()
    final_bytes = sum(p.stat().st_size for p in work_dir.iterdir() if p.is_file())
    return {"backend": "sqlite_wal", "journal_mode": journal_mode, "final_bytes": final_bytes, **compute_latency_percentiles(samples_ms)}


def _bench_segmented_jsonl_backend(work_dir: Path, operations: int) -> dict[str, Any]:
    work_dir.mkdir(parents=True, exist_ok=True)
    snap_path, seg_path, lock_path = work_dir / "ledger_snapshot.json", work_dir / "segment_active.jsonl", work_dir / "segment.lock"
    snap_path.write_text(json.dumps({"read_ledger_schema": state_store.READ_LEDGER_SCHEMA, "files": _seed_ledger_entries(30)}, separators=(",", ":")), encoding="utf-8")
    seg_path.write_text("", encoding="utf-8")
    samples_ms: list[float] = []
    compactions = 0
    for op_i in range(operations):
        key, iv = f"repo/src/mod_{op_i % 30:02d}.py", [1 + (op_i % 8) * 25, 30 + (op_i % 8) * 25, 100 + op_i, 2]
        t0 = time.perf_counter()
        with open(lock_path, "a+", encoding="utf-8") as lock_fh:
            state_store.fcntl.flock(lock_fh.fileno(), state_store.fcntl.LOCK_EX)
            try:
                doc = json.loads(snap_path.read_text(encoding="utf-8"))
                files_map: dict[str, Any] = doc.setdefault("files", {})
                for line in seg_path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        rec = json.loads(line)
                        files_map[str(rec["path"])] = {"sha256": str(rec["sha256"]), "reads": rec["reads"]}
                ent = files_map.setdefault(key, {"sha256": "", "reads": []})
                merged = state_store.merge_intervals([*list(ent.get("reads") or []), iv])
                ent["reads"], doc["auto_step_seq"] = merged, 100 + op_i
                with open(seg_path, "a", encoding="utf-8") as seg_fh:
                    seg_fh.write(json.dumps({"path": key, "sha256": ent.get("sha256", ""), "reads": merged, "step": 100 + op_i}, separators=(",", ":")) + "\n")
                    seg_fh.flush()
                if (op_i + 1) % 16 == 0:
                    fd, tmp_name = tempfile.mkstemp(prefix=".seg_snap.", suffix=".tmp", dir=str(work_dir))
                    try:
                        with os.fdopen(fd, "w", encoding="utf-8") as tmp_fh:
                            json.dump(doc, tmp_fh, separators=(",", ":"))
                        os.replace(tmp_name, str(snap_path))
                    except OSError:
                        Path(tmp_name).unlink(missing_ok=True)
                        raise
                    seg_path.write_text("", encoding="utf-8")
                    compactions += 1
            finally:
                state_store.fcntl.flock(lock_fh.fileno(), state_store.fcntl.LOCK_UN)
        samples_ms.append((time.perf_counter() - t0) * 1000.0)
    final_bytes = (snap_path.stat().st_size if snap_path.is_file() else 0) + (seg_path.stat().st_size if seg_path.is_file() else 0)
    return {"backend": "segmented_jsonl", "compactions": compactions, "final_bytes": final_bytes, **compute_latency_percentiles(samples_ms)}


def run_backend_storage_benchmark(
    *, operations: int = 40, force_compare: bool = False, p95_budget_ms: float = 25.0, p99_budget_ms: float = 50.0,
) -> dict[str, Any]:
    """Benchmark Read Ledger v2 `json_lock` and conditionally compare alternatives in a temp dir."""
    ops, b_p95, b_p99 = max(1, int(operations)), float(p95_budget_ms), float(p99_budget_ms)
    with tempfile.TemporaryDirectory(prefix="cg_backend_bench_") as td:
        root = Path(td).resolve()
        json_lock = _bench_json_lock_backend(root / "json_lock", ops)
        limits_exposed = bool(float(json_lock["p95_ms"]) > b_p95 or float(json_lock["p99_ms"]) > b_p99)
        evaluate_alts = bool(limits_exposed or force_compare)
        alternatives: dict[str, dict[str, Any]] = (
            {"sqlite_wal": _bench_sqlite_wal_backend(root / "sqlite_wal", ops),
             "segmented_jsonl": _bench_segmented_jsonl_backend(root / "segmented_jsonl", ops)}
            if evaluate_alts else {}
        )
    schema_v = int(json_lock.get("read_ledger_schema") or state_store.READ_LEDGER_SCHEMA)
    return {
        "schema_version": 1, "ok": schema_v == state_store.READ_LEDGER_SCHEMA, "active_backend": "json_lock",
        "read_ledger_schema": state_store.READ_LEDGER_SCHEMA, "operations": ops,
        "p95_budget_ms": b_p95, "p99_budget_ms": b_p99, "limits_exposed": limits_exposed,
        "alternatives_evaluated": evaluate_alts, "migration_performed": False,
        "decision": "evaluate_migration_proposal" if limits_exposed else "retain_json_lock",
        "json_lock": json_lock, "alternatives": alternatives,
    }


def run_deterministic_benchmark(iterations: int = 3) -> dict[str, Any]:
    """Measure isolated cold/warm latency and byte/token savings over synthetic corpus."""
    iters = max(1, int(iterations))
    cfg = {"read_confirm_policy": "bounded", "optimizers": {"range_trim": "active", "auto_outline": "active", "output_spool": "active", "cli_rewrites": "auto"}, "regret_window_steps": 2, "policy_packs": []}
    warm_samples_ms: list[float] = []
    sub_samples_ms: list[float] = []
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
                    call_t0 = time.perf_counter()
                    if harness == "antigravity":
                        ov = {"toolCall": {"name": "view_file", "args": {"AbsolutePath": str(large_py), "StartLine": 1, "EndLine": 200}, "id": f"w-{rep_i}"}, "conversationId": "bench-ag"}
                        pre_tool_use.evaluate_hook(ov, state_dir=sdir, cli_harness="antigravity")
                        post_tool_use.handle_post_tool_use("antigravity", {**ov, "toolResponse": overlap_text}, stats_path=stats_p, state_dir=sdir)
                    else:
                        pre_tool_use.evaluate_hook({**payload, "call_id": f"w-{rep_i}-{idx}", "tool_use_id": f"w-{rep_i}-{idx}"}, state_dir=sdir, cli_harness=harness)
                    warm_samples_ms.append((time.perf_counter() - call_t0) * 1000.0)
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
                "CONTEXT_GUARD_SPOOL_DIR": str(paths["spool_dir"]),
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
                sub_t0 = time.perf_counter()
                proc = subprocess.run(
                    [sys.executable, str(pre_tool_script), "--harness", "claude"],
                    input=json.dumps(call_payload),
                    text=True,
                    encoding="utf-8",
                    capture_output=True,
                    env=sub_env,
                    check=False,
                )
                sub_samples_ms.append((time.perf_counter() - sub_t0) * 1000.0)
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
    backend_eval = run_backend_storage_benchmark(operations=20, force_compare=False)
    in_proc_pct = compute_latency_percentiles(warm_samples_ms)
    sub_pct = compute_latency_percentiles(sub_samples_ms)
    in_cold_ms, in_warm_ms = round(cold_ms, 3), round(warm_ms, 3)
    in_warm_per_call = round(warm_ms / warm_calls, 4)
    return {
        "ok": sub_ok and bool(backend_eval.get("ok", True)),
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
        "in_process_latency_ms": in_proc_pct,
        "subprocess_hook_ms_per_call": round(sub_ms / sub_iters, 3),
        "subprocess_latency_ms": sub_pct,
        "backend_evaluation": backend_eval,
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
    raw_in_lat = result.get("in_process_latency_ms")
    in_lat: Mapping[str, Any] = raw_in_lat if isinstance(raw_in_lat, Mapping) else {}
    raw_be = result.get("backend_evaluation")
    be: Mapping[str, Any] = raw_be if isinstance(raw_be, Mapping) else {}
    be_act = be.get("active_backend", "json_lock")
    be_sch = be.get("read_ledger_schema", state_store.READ_LEDGER_SCHEMA)
    be_mig = be.get("migration_performed", False)
    be_dec = be.get("decision", "retain_json_lock")
    return "\n".join([
        "## Context-Guard Deterministic Benchmark",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Status | `{'OK' if result.get('ok') else 'FAIL'}` |",
        "| Benchmark scope | `synthetic corpus (not live session A/B)` |",
        f"| In-process engine cold latency | `{in_cold} ms` |",
        f"| In-process engine warm latency (`{result.get('iterations', 0)}`x) | `{in_warm} ms` (`{in_warm_pc} ms/call`) |",
        f"| In-process warm p50 / p95 / p99 | `{in_lat.get('p50_ms', 0.0)} / {in_lat.get('p95_ms', 0.0)} / {in_lat.get('p99_ms', 0.0)} ms` |",
        f"| Subprocess E2E hook latency (`PreToolUse`) | `{sub_pc} ms/call` |",
        f"| Read Ledger backend decision | `{be_act} (schema v{be_sch}, migration={be_mig})` — `{be_dec}` |",
        f"| Bytes saved (synthetic corpus) | `{result.get('saved_bytes', 0)}` (`{result.get('savings_pct', 0)}%`) |",
        f"| Tokens saved (synthetic est.) | `{result.get('saved_tokens', 0)}` |",
        "",
    ])


def _scrub_string(text: str) -> str:
    cleaned = text
    for name in _SENSITIVE_FILES:
        if name in cleaned:
            cleaned = cleaned.replace(name, "[redacted]")
    cleaned = _SPOOL_ID_FIND_RE.sub("[redacted]", cleaned)
    cleaned = _WS_ID_FIND_RE.sub("[redacted]", cleaned)
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
    receipt_summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return scrubbed JSON telemetry bundle safe for public diagnostics and sharing."""
    raw: dict[str, Any] = {
        "public": True,
        "stats": dict(stats),
        "token_usage": dict(usage),
        "outcomes": {
            "schema_version": outcomes_data.get("schema_version", outcomes.SCHEMA_VERSION),
            "totals": dict(outcomes_data.get("totals") or {}) if isinstance(outcomes_data.get("totals"), Mapping) else {},
        },
        "update": dict(update) if isinstance(update, Mapping) else {},
    }
    if isinstance(receipt_summary, Mapping):
        raw["spool_reliability"] = {
            k: max(0, int(receipt_summary.get(k) or 0))
            for k in ("receipt_count", "created_count", "delivery_verified_count", "recovery_count", "integrity_failures")
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
        for fk in (
            "config_path", "transcript_path", "policy_packs", "receipts_path", "receipts_dir",
            "receipts_index", "workspace_id", "canon_root", "spool_id", "session_id", "receipts",
        ):
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
