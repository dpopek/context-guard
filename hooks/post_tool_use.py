#!/usr/bin/env python3
"""PostToolUse, PostToolBatch, and PostToolUseFailure hook for Read Ledger v2 & shell telemetry."""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path[:0] = [r] if (r := str(Path(__file__).resolve().parent.parent)) not in sys.path else []
from hooks import config, file_io, harness_adapter, policy_engine, read_planner  # noqa: E402
from hooks import session_lifecycle, state_store, telemetry  # noqa: E402
from hooks.outcomes import dispatch_direct_outcome, ledger_path_for, record_direct_outcome  # noqa: E402
from hooks.shell_output import classify_family, measure  # noqa: E402
from hooks.telemetry import record_shell_output, record_telemetry_event, warn  # noqa: E402
from policies.api import PolicyPostContext  # noqa: E402

_SHELL_TOOLS = {"claude": frozenset(("Bash",)), "codex": frozenset(("Bash", "shell", "exec_command", "exec")),
                "cursor": frozenset(("Shell", "run_terminal_cmd"))}
_READ_TOOLS = frozenset(("Read", "NotebookRead", "read_file", "view_file"))
_MUTATION_TOOLS = frozenset((
    "Edit", "MultiEdit", "Write", "NotebookEdit", "StrReplace", "MultiStrReplace", "EditFile",
    "WriteFile", "Delete", "DeleteFile", "apply_patch", "edit_file", "write_file",
    "replace_file_content", "multi_replace_file_content", "write_to_file",
))
_PATH_KEYS = ("file_path", "notebook_path", "path", "relative_workspace_path",
              "Path", "AbsolutePath", "TargetFile", "filePath")
_EXIT_RE = re.compile(r"^Exit code -?\d+$")
AG_MAX_LINES = 800
AG_MAX_BYTES = 40_000

@dataclass(frozen=True)
class ShellCall:
    """One shell call as the hook sees it; `output` None means it was not found in the payload."""
    command: str
    output: str | None
    outcome: str

def _command_of(payload: dict[str, Any]) -> str:
    ti = payload.get("tool_input")
    cmd = ti.get("command") or ti.get("cmd") or ti.get("CommandLine") if isinstance(ti, dict) else None
    if isinstance(cmd, str):
        return cmd
    return shlex.join(str(p) for p in cmd) if isinstance(cmd, list) else ""

def _output_of(data: dict[str, Any]) -> str | None:
    if isinstance((out := data.get("output")), str):
        return out
    parts = [s for k in ("stdout", "stderr") if isinstance((s := data.get(k)), str)]
    return "".join(parts) if parts else None

def _dict_shell_call(cmd: str, data: Any, code_key: str | None) -> ShellCall:
    if not isinstance(data, dict) or (out := _output_of(data)) is None:
        return ShellCall(cmd, None, "unknown")
    if code_key is None:
        return ShellCall(cmd, out, "ok")
    c = data.get(code_key)
    ok_int = isinstance(c, int) and not isinstance(c, bool)
    return ShellCall(cmd, out, ("ok" if c == 0 else "fail") if ok_int else "unknown")

def _claude_call(payload: dict[str, Any]) -> ShellCall:
    cmd = _command_of(payload)
    if payload.get("hook_event_name") != "PostToolUseFailure":
        return _dict_shell_call(cmd, payload.get("tool_response"), None)
    if not isinstance((err := payload.get("error")), str):
        return ShellCall(cmd, None, "unknown")
    first, _, rest = err.partition("\n")
    return ShellCall(cmd, rest, "fail") if _EXIT_RE.match(first.strip()) else ShellCall(cmd, err, "unknown")

def _codex_call(payload: dict[str, Any]) -> ShellCall:
    cmd, resp = _command_of(payload), payload.get("tool_response")
    if isinstance(resp, str):
        return ShellCall(cmd, resp, "unknown")
    return _dict_shell_call(cmd, resp, "exit_code")

def _cursor_call(payload: dict[str, Any]) -> ShellCall:
    cmd, data = _command_of(payload), payload.get("tool_output")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return ShellCall(cmd, None, "unknown")
    return _dict_shell_call(cmd, data, "exitCode")

_CALL_BUILDERS = {"claude": _claude_call, "codex": _codex_call, "cursor": _cursor_call}

def normalise_payload(harness: str, payload: dict[str, Any]) -> ShellCall | None:
    """The shell call in a PostToolUse payload; None for non-shell tools or an unknown harness."""
    if payload.get("tool_name") not in _SHELL_TOOLS.get(harness, ()):
        return None
    return _CALL_BUILDERS[harness](payload)

def extract_claude_batch_read_text(item: dict[str, Any]) -> str | None:
    """Extract plain delivered text from one Claude `PostToolBatch` `tool_calls` entry."""
    if not isinstance(item, dict) or bool(item.get("is_error")) or bool(item.get("truncated")):
        return None
    if isinstance((resp := item.get("tool_response")), str):
        return resp or None
    if not isinstance(resp, list) or not resp or not all(
        isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str) for b in resp
    ):
        return None
    return "\n".join(b["text"] for b in resp) or None

def _body_matches_pending(body: str, pending: dict[str, Any], expected_lines: int) -> bool:
    exp = pending.get("expected_norm_sha256")
    nb = body.replace("\r\n", "\n").replace("\r", "\n")
    if not isinstance(exp, str) or not exp or not nb:
        return False
    lines = (nb[:-1] if nb.endswith("\n") else nb).split("\n")
    return len(lines) == expected_lines and hmac.compare_digest(
        read_planner.normalize_read_body_fingerprint("\n".join(lines)), exp,
    )

def _is_redacted_output(val: Any) -> bool:
    if isinstance(val, str):
        low = val.lower()
        return not val.strip() or "[redacted]" in low or "content omitted" in low
    return val is None or (isinstance(val, dict) and bool(val.get("redacted")))

def _candidate_paths_from_payload(payload: dict[str, Any], cwd: str | None) -> tuple[str, ...]:
    srcs = [v for k in ("tool_input", "tool_response") if isinstance((v := payload.get(k)), dict)]
    if isinstance((tc := payload.get("toolCall")), dict) and isinstance(tc.get("args"), dict):
        srcs.append(tc["args"])
    if isinstance((tr := payload.get("tool_response")), dict) and isinstance((fo := tr.get("file")), dict):
        srcs.append(fo)
    return tuple(dict.fromkeys(
        cl if os.path.isabs(cl) or not cwd else str(Path(cwd) / cl)
        for s in srcs for k in _PATH_KEYS if isinstance((v := s.get(k)), str) and (cl := v.strip())
    ))

def _locate_pending_entry(
    files_map: dict[str, Any], cid: str, candidates: tuple[str, ...],
) -> tuple[str | None, dict[str, Any] | None, str]:
    raw_keys = list(dict.fromkeys(k for raw in candidates for k in (os.path.realpath(raw), raw)))
    raw_set = set(raw_keys)
    for k in dict.fromkeys([*raw_keys, *files_map]):
        if not isinstance((ent := files_map.get(k)), dict):
            continue
        if cid and isinstance((comp := ent.get("completed_read_ids")), dict) and cid in comp:
            return k, ent, "completed"
        if cid and isinstance((pend := ent.get("pending_reads")), dict) and cid in pend:
            return k, ent, "pending"
        if not cid and k in raw_set and isinstance((pm := ent.get("pending_reads")), dict):
            sy = next((c for c, r in pm.items() if isinstance(r, dict) and r.get("synthetic_id")), None)
            if sy:
                return k, ent, f"synth:{sy}"
    return None, None, "missing"

def _resolve_read_tier(
    harness: str, payload: dict[str, Any], pending: dict[str, Any], actual_target: str,
    *, is_batch: bool, is_failure: bool,
) -> tuple[int, bool]:
    """Return `(tier_or_provisional, is_final)` for a pending read."""
    resp = raw if isinstance((raw := payload.get("tool_response")), dict) else {}
    has_err = is_failure or bool(
        payload.get("is_error") or payload.get("error") or resp.get("is_error") or resp.get("error")
        or str(payload.get("status") or "").lower() in ("error", "failed", "failure")
    )
    if has_err or payload.get("truncated") or resp.get("truncated") or pending.get("synthetic_id"):
        return 0, True
    if int(pending.get("byte_offset") or 0) != 0:
        return 0, True
    es, de = int(pending.get("exec_start") or 0), int(pending.get("delivered_end") or -1)
    lines, s_bytes = de - es + 1, int(pending.get("slice_bytes") or 0)
    d_sha = file_io.compute_file_sha256(actual_target)
    if es < 1 or de < es or not d_sha or not hmac.compare_digest(d_sha, str(pending.get("sha256") or "")):
        return 0, True
    if harness in ("claude", "cursor"):
        if lines > read_planner.MAX_TIER2_LINES or s_bytes > telemetry.CLAUDE_COVERAGE_MAX_SLICE_BYTES:
            return 0, True
        if harness == "claude":
            if not is_batch:
                return 1, False  # Provisional only; NEVER stored in entry["reads"] or credited!
            text = extract_claude_batch_read_text(payload)
            return (2 if (text is not None and _body_matches_pending(text, pending, lines)) else 0), True
        out = payload.get("tool_output")
        if _is_redacted_output(out) or not isinstance(out, (str, dict)):
            return 0, True
        txt = out if isinstance(out, str) else (out.get("text") or out.get("content"))
        tier = (2 if _body_matches_pending(txt, pending, lines) else 0) if isinstance(txt, str) else 1
        return tier, True
    ok_ag = harness == "antigravity" and 1 <= lines <= AG_MAX_LINES and s_bytes <= AG_MAX_BYTES
    return (1 if ok_ag else 0), True

def _tool_name(payload: dict[str, Any]) -> str:
    tc = payload.get("toolCall")
    return str(payload.get("tool_name") or (tc.get("name") if isinstance(tc, dict) else "") or "")

def _extract_item_call_id(item: dict[str, Any]) -> str:
    tc = raw if isinstance((raw := item.get("toolCall")), dict) else {}
    return str(
        next((item[k] for k in ("tool_use_id", "call_id", "tool_call_id", "callId") if item.get(k)), "")
        or tc.get("id") or tc.get("callId") or ""
    )

def _apply_read_confirmation(
    harness: str, payload: dict[str, Any], state_dir_path: Path, cfg: dict[str, Any],
    stats_path: Path | None, *, eff_event: str, shadow_path: Path | None = None,
) -> None:
    if not state_store.state_file_in(state_dir_path).is_file():
        return
    min_tier = 1 if cfg.get("read_confirm_policy", "strict") == "bounded" else 2
    is_shadow = (cfg.get("optimizers") or {}).get("range_trim") == "shadow"
    raw_c = payload.get("tool_calls") if eff_event == "PostToolBatch" else None
    items = (
        [x for x in raw_c if isinstance(x, dict)] if eff_event == "PostToolBatch" and isinstance(raw_c, list)
        else ([payload] if eff_event == "PostToolUseFailure" or _tool_name(payload) in _READ_TOOLS else [])
    )
    if not items:
        return
    credits: list[tuple[str, int, int, int, str | None]] = []
    shadow_reads: list[tuple[str, int, int, int, int, str]] = []
    outcomes_path = ledger_path_for(str(state_dir_path))
    sess_id = str(payload.get("session_id") or payload.get("conversation_id") or payload.get("conversationId") or "default")
    cwd = raw.strip() if isinstance((raw := payload.get("cwd")), str) and raw.strip() else None
    is_batch, is_fail = eff_event == "PostToolBatch", eff_event == "PostToolUseFailure"
    with state_store.locked_state(state_dir_path) as txn:
        files_map, state_mod = txn.state.setdefault("files", {}), str(txn.state.get("model") or "unknown")
        for item in items:
            cid = _extract_item_call_id(item)
            canon, entry, st = _locate_pending_entry(files_map, cid, _candidate_paths_from_payload(item, cwd))
            if st in ("missing", "completed") or canon is None or entry is None:
                continue
            eff_cid = st.split(":", 1)[1] if st.startswith("synth:") else cid
            pm = entry.get("pending_reads")
            if not isinstance(pm, dict) or not isinstance((pend := pm.get(eff_cid)), dict):
                continue
            tier, is_final = _resolve_read_tier(
                harness, item, pend, str(pend.get("redirect_path") or canon),
                is_batch=is_batch, is_failure=is_fail,
            )
            if not is_final:
                pend.update({"post_stage": "tool_executed", "provisional_tier": tier, "credited": False})
                txn.dirty = True
                continue
            pm.pop(eff_cid, None)
            if not pm:
                entry.pop("pending_reads", None)
            credited = False
            if tier in (1, 2):
                iv = [int(pend["exec_start"]), int(pend["delivered_end"]), int(pend["step"]), tier]
                if isinstance((reads := entry.setdefault("reads", [])), list):
                    reads.append(iv)
                    entry["reads"] = state_store.merge_intervals(reads)
                if (redir := pend.get("redirect_path")):
                    read_planner.mirror_unwrapped_entry(
                        files_map, str(redir), int(pend["step"]), read_interval=iv,
                    )
                if is_shadow and not int(pend.get("byte_offset") or 0):
                    s_end = int(pend["delivered_end"]) if int(pend.get("delivered_end") or -1) > 0 else int(pend.get("exec_end") or -1)
                    if s_end > 0:
                        shadow_reads.append((str(pend.get("canonical_target") or canon), int(pend["exec_start"]), s_end, int(pend["step"]), tier, str(pend.get("sha256") or "")))
                if pend.get("is_trim") and tier >= min_tier and not pend.get("credited"):
                    credited, pm_m = True, pend.get("model")
                    mod = pm_m if isinstance(pm_m, str) and pm_m not in ("", "unknown") else state_mod
                    p_step = int(pend.get("step") or 0)
                    p_cid = None if pend.get("synthetic_id") else (cid or None)
                    credits.append((mod, int(pend.get("req_bytes") or 0), int(pend.get("saved_bytes") or 0), p_step, p_cid))
            if cid:
                session_lifecycle.record_completed_read_id(entry, cid, tier, credited)
            txn.dirty = True
    for mod, req_b, saved_b, p_step, p_cid in credits:
        record_telemetry_event(harness, "ranges_trimmed", req_b, saved_b, stats_path=stats_path)
        dispatch_direct_outcome(record_direct_outcome, harness, mod, "range_trim", "applied", outcomes_path,
                                session_id=sess_id, step_idx=p_step, call_id=p_cid)
    for s_canon, s_start, s_end, s_step, s_tier, s_sha in shadow_reads:
        telemetry.record_shadow_read(sess_id, s_canon, s_start, s_end, s_step, s_tier, s_sha, min_tier=min_tier, shadow_path=shadow_path)

def _apply_mutation_invalidation(payload: dict[str, Any], sdir: Path, shadow_path: Path | None = None) -> None:
    if (tn := _tool_name(payload)) not in _MUTATION_TOOLS:
        return
    cwd = raw.strip() if isinstance((raw := payload.get("cwd")), str) and raw.strip() else None
    targets = list(_candidate_paths_from_payload(payload, cwd))
    if tn == "apply_patch":
        src = payload.get("tool_input")
        targets.extend(harness_adapter.extract_apply_patch_paths(
            src if isinstance(src, (dict, str)) else "", cwd,
        ))
    if not targets:
        return
    if state_store.state_file_in(sdir).is_file():
        with state_store.locked_state(sdir) as txn:
            if session_lifecycle.invalidate_mutated_paths(txn.state, targets):
                txn.dirty = True
    if (shadow_path or telemetry.DEFAULT_SHADOW_PATH).is_file():
        for t in targets:
            telemetry.invalidate_shadow_ledger(raw_path=t, shadow_path=shadow_path)

def _warn_hook_error(exc: BaseException, context: str) -> None:
    e_type = type(exc).__name__
    state_store.run_telemetry_safely(lambda: warn(f"shell output hook failed: {e_type}"), context=context)

def handle_post_tool_use(
    harness: str, payload: dict[str, Any], stats_path: Path | None = None, *,
    state_dir: str | Path | None = None, event_name: str | None = None,
) -> dict[str, Any]:
    """Record shell telemetry, read confirmations (`PostToolUse`/`PostToolBatch`/`Failure`), and hooks."""
    try:
        sp = stats_path or ((Path(state_dir) / "telemetry_stats.json") if state_dir else None)
        ev = str(event_name or payload.get("hook_event_name") or payload.get("event") or "PostToolUse")
        if ev in ("PostToolUse", "PostToolUseFailure") and (call := normalise_payload(harness, payload)):
            meas = measure(call.output, harness) if call.output is not None else None
            record_shell_output(harness, classify_family(call.command), meas, call.outcome, sp)
        cfg = config.load_runtime_config()
        sdir = state_store.resolve_state_dir(payload, str(state_dir) if state_dir is not None else None)
        sh_path = telemetry.shadow_path_for(str(state_dir) if state_dir is not None else None)
        if ev == "PostToolUse":
            _apply_mutation_invalidation(payload, sdir, sh_path)
        _apply_read_confirmation(harness, payload, sdir, cfg, sp, eff_event=ev, shadow_path=sh_path)
        packs = cfg.get("policy_packs") or ()
        if ev != "PostToolBatch" and any(isinstance(p, dict) and p.get("enabled", True) for p in packs):
            norm = harness_adapter.normalize_pre_tool_payload(payload, cli_harness=harness)
            resp = payload.get("tool_response") or payload.get("toolResponse") or payload.get("result")
            err = payload.get("error") or (resp.get("error") if isinstance(resp, dict) else None)
            ok = ev != "PostToolUseFailure" and not bool(err) and payload.get("is_error") is not True
            policy_engine.run_post_tool_hooks(PolicyPostContext(
                harness=norm.harness, call_id=norm.call_id, canonical_tool=norm.canonical_tool,
                canonical_args=norm.canonical_args, mutated_paths=norm.mutated_paths,
                original_tool_name=norm.original_tool_name, tool_input=norm.original_tool_input,
                succeeded=ok, error=str(err) if err else None, cwd=norm.cwd, state_dir=str(sdir),
            ), cfg)
    except Exception as exc:  # noqa: BLE001 - hook must never fail tool execution
        _warn_hook_error(exc, "post_tool_use")
    return {}

def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: read PostToolUse/PostToolBatch JSON from stdin, emit `{}` and exit 0."""
    try:
        parser = argparse.ArgumentParser(add_help=False)
        for flag, default in (("--harness", "claude"), ("--event", None), ("--state-dir", None)):
            parser.add_argument(flag, default=default)
        args, _ = parser.parse_known_args(argv)
        if (raw := sys.stdin.read()).strip() and isinstance((pl := json.loads(raw)), dict):
            handle_post_tool_use(args.harness, pl, state_dir=args.state_dir, event_name=args.event)
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - hook must never fail tool execution
        _warn_hook_error(exc, "post_tool_use_main")
    return state_store.emit_json_and_sanitize_stdio({})

if __name__ == "__main__":
    raise SystemExit(main())
