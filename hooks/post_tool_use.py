#!/usr/bin/env python3
"""PostToolUse, PostToolBatch, and PostToolUseFailure hook for Read Ledger v2 & shell telemetry."""
from __future__ import annotations

import argparse, hmac, json, os, re, shlex, sys, time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path[:0] = [r] if (r := str(Path(__file__).resolve().parent.parent)) not in sys.path else []

from core.contracts import HARNESS_CAPABILITIES  # noqa: E402
from core.platform_io import warn  # noqa: E402
from hooks import config, file_io, harness_adapter, model_identity, policy_engine, read_planner  # noqa: E402
from hooks import session_lifecycle, state_store, telemetry  # noqa: E402
from hooks.outcomes import dispatch_direct_outcome, ledger_path_for, open_outcome_window, reconcile_mutation_windows, record_direct_outcome  # noqa: E402
from hooks.shell_output import classify_family, measure  # noqa: E402
from hooks.telemetry import record_shell_output, record_telemetry_event  # noqa: E402
from policies.api import PolicyPostContext  # noqa: E402
from policies.governor import apply_runtime_governor  # noqa: E402
from spool import receipts as spool_receipts, store as spool_store  # noqa: E402

_SHELL_TOOLS = {"claude": frozenset(("Bash",)), "codex": frozenset(("Bash", "shell", "exec_command", "exec")), "cursor": frozenset(("Shell", "run_terminal_cmd"))}
_READ_TOOLS = frozenset(("Read", "NotebookRead", "read_file", "view_file"))
_MUTATION_TOOLS = frozenset(("Edit", "MultiEdit", "Write", "NotebookEdit", "StrReplace", "MultiStrReplace", "EditFile", "WriteFile",
                             "Delete", "DeleteFile", "delete_file", "apply_patch", "edit_file", "write_file",
                             "replace_file_content", "multi_replace_file_content", "write_to_file"))
_PATH_KEYS = ("file_path", "notebook_path", "path", "relative_workspace_path", "Path", "AbsolutePath", "TargetFile", "filePath")
_EXIT_RE = re.compile(r"^Exit code -?\d+$")

@dataclass(frozen=True)
class ShellCall:
    """One shell call as the hook sees it; `output` None means it was not found in the payload."""
    command: str
    output: str | None
    outcome: str

def _command_of(payload: dict[str, Any]) -> str:
    ti = payload.get("tool_input")
    cmd = ti.get("command") or ti.get("cmd") or ti.get("CommandLine") if isinstance(ti, dict) else None
    return cmd if isinstance(cmd, str) else (shlex.join(str(p) for p in cmd) if isinstance(cmd, list) else "")

def _output_of(data: dict[str, Any]) -> str | None:
    if isinstance((out := data.get("output")), str): return out
    parts = [s for k in ("stdout", "stderr") if isinstance((s := data.get(k)), str)]
    return "".join(parts) if parts else None

def _dict_shell_call(cmd: str, data: Any, code_key: str | None) -> ShellCall:
    if not isinstance(data, dict) or (out := _output_of(data)) is None: return ShellCall(cmd, None, "unknown")
    if code_key is None: return ShellCall(cmd, out, "ok")
    c = data.get(code_key)
    return ShellCall(cmd, out, ("ok" if c == 0 else "fail") if isinstance(c, int) and not isinstance(c, bool) else "unknown")

def _claude_call(payload: dict[str, Any]) -> ShellCall:
    cmd = _command_of(payload)
    if payload.get("hook_event_name") != "PostToolUseFailure": return _dict_shell_call(cmd, payload.get("tool_response"), None)
    if not isinstance((err := payload.get("error")), str): return ShellCall(cmd, None, "unknown")
    first, _, rest = err.partition("\n")
    return ShellCall(cmd, rest, "fail") if _EXIT_RE.match(first.strip()) else ShellCall(cmd, err, "unknown")

def _codex_call(payload: dict[str, Any]) -> ShellCall:
    cmd, resp = _command_of(payload), payload.get("tool_response")
    return ShellCall(cmd, resp, "unknown") if isinstance(resp, str) else _dict_shell_call(cmd, resp, "exit_code")

def _cursor_call(payload: dict[str, Any]) -> ShellCall:
    cmd, data = _command_of(payload), payload.get("tool_output")
    if isinstance(data, str):
        try: data = json.loads(data)
        except ValueError: return ShellCall(cmd, None, "unknown")
    return _dict_shell_call(cmd, data, "exitCode")

_CALL_BUILDERS = {"claude": _claude_call, "codex": _codex_call, "cursor": _cursor_call}

def normalise_payload(harness: str, payload: dict[str, Any]) -> ShellCall | None:
    """The shell call in a PostToolUse payload; None for non-shell tools or an unknown harness."""
    return _CALL_BUILDERS[harness](payload) if payload.get("tool_name") in _SHELL_TOOLS.get(harness, ()) else None

def extract_claude_batch_read_text(item: dict[str, Any]) -> str | None:
    """Extract plain delivered text from one Claude `PostToolBatch` `tool_calls` entry."""
    if not isinstance(item, dict) or item.get("is_error") or item.get("truncated"): return None
    if isinstance((resp := item.get("tool_response")), str): return resp or None
    if not isinstance(resp, list) or not resp or not all(isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str) for b in resp): return None
    return "\n".join(b["text"] for b in resp) or None

def _body_matches_pending(body: str, pending: dict[str, Any], expected_lines: int) -> bool:
    exp, nb = pending.get("expected_norm_sha256"), body.replace("\r\n", "\n").replace("\r", "\n")
    if not isinstance(exp, str) or not exp or not nb: return False
    lines = (nb[:-1] if nb.endswith("\n") else nb).split("\n")
    return len(lines) == expected_lines and hmac.compare_digest(read_planner.normalize_read_body_fingerprint("\n".join(lines)), exp)

def _is_redacted_output(val: Any) -> bool:
    if isinstance(val, str):
        low = val.lower()
        return not val.strip() or "[redacted]" in low or "content omitted" in low
    return val is None or (isinstance(val, dict) and bool(val.get("redacted")))

def _candidate_paths_from_payload(payload: dict[str, Any], cwd: str | None) -> tuple[str, ...]:
    srcs = [v for k in ("tool_input", "tool_response") if isinstance((v := payload.get(k)), dict)]
    if isinstance((tc := payload.get("toolCall")), dict) and isinstance(tc.get("args"), dict): srcs.append(tc["args"])
    if isinstance((tr := payload.get("tool_response")), dict) and isinstance((fo := tr.get("file")), dict): srcs.append(fo)
    return tuple(dict.fromkeys(cl if os.path.isabs(cl) or not cwd else str(Path(cwd) / cl)
                               for s in srcs for k in _PATH_KEYS if isinstance((v := s.get(k)), str) and (cl := v.strip())))

def _locate_pending_entry(files_map: dict[str, Any], cid: str, candidates: tuple[str, ...]) -> tuple[str | None, dict[str, Any] | None, str]:
    raw_keys = list(dict.fromkeys(k for raw in candidates for k in (os.path.realpath(raw), raw)))
    raw_set = set(raw_keys)
    for k in dict.fromkeys([*raw_keys, *files_map]):
        if not isinstance((ent := files_map.get(k)), dict): continue
        if cid and isinstance((comp := ent.get("completed_read_ids")), dict) and cid in comp: return k, ent, "completed"
        if cid and isinstance((pend := ent.get("pending_reads")), dict) and cid in pend: return k, ent, "pending"
        if not cid and isinstance((pm := ent.get("pending_reads")), dict):
            for c, r in pm.items():
                if isinstance(r, dict) and r.get("synthetic_id") and (
                    k in raw_set or (isinstance((rp := r.get("redirect_path")), str) and rp and (rp in raw_set or os.path.realpath(rp) in raw_set))
                ):
                    return k, ent, f"synth:{c}"
    return None, None, "missing"

def _resolve_read_tier(harness: str, payload: dict[str, Any], pending: dict[str, Any], actual_target: str, *, is_batch: bool, is_failure: bool) -> tuple[int, bool]:
    """Return `(tier_or_provisional, is_final)` for a pending read."""
    resp = raw if isinstance((raw := payload.get("tool_response")), dict) else {}
    has_err = is_failure or bool(payload.get("is_error") or payload.get("error") or resp.get("is_error") or resp.get("error")
                                 or str(payload.get("status") or "").lower() in ("error", "failed", "failure"))
    if has_err or payload.get("truncated") or resp.get("truncated") or pending.get("synthetic_id") or int(pending.get("byte_offset") or 0) != 0:
        return 0, True
    es, de = int(pending.get("exec_start") or 0), int(pending.get("delivered_end") or -1)
    lines, s_bytes = de - es + 1, int(pending.get("slice_bytes") or 0)
    d_sha = file_io.compute_file_sha256(actual_target)
    if es < 1 or de < es or not d_sha or not hmac.compare_digest(d_sha, str(pending.get("sha256") or "")): return 0, True
    caps = HARNESS_CAPABILITIES.get(harness)
    if harness in ("claude", "cursor") and caps is not None:
        if lines > caps.max_lines or s_bytes > caps.max_coverage_bytes: return 0, True
        if harness == "claude":
            if not is_batch: return 1, False
            text = extract_claude_batch_read_text(payload)
            return (2 if (text is not None and _body_matches_pending(text, pending, lines)) else 0), True
        out = payload.get("tool_output")
        if _is_redacted_output(out) or not isinstance(out, (str, dict)) or (isinstance(out, dict) and not out): return 0, True
        if isinstance(out, str): return (2 if _body_matches_pending(out, pending, lines) else 0), True
        if "text" in out or "content" in out:
            txt = out.get("text") or out.get("content")
            return (2 if _body_matches_pending(txt, pending, lines) else 0) if isinstance(txt, str) and not _is_redacted_output(txt) else 0, True
        return 1, True
    ok_ag = harness == "antigravity" and caps is not None and 1 <= lines <= caps.max_lines and s_bytes <= caps.max_coverage_bytes
    return (1 if ok_ag else 0), True

def _tool_name(payload: dict[str, Any]) -> str:
    tc = payload.get("toolCall")
    return str(payload.get("tool_name") or (tc.get("name") if isinstance(tc, dict) else "") or "")

def _extract_item_call_id(item: dict[str, Any]) -> str:
    tc = raw if isinstance((raw := item.get("toolCall")), dict) else {}
    return str(next((item[k] for k in ("tool_use_id", "call_id", "tool_call_id", "callId") if item.get(k)), "") or tc.get("id") or tc.get("callId") or "")

def _extract_trimmed_spans(pend: dict[str, Any]) -> tuple[tuple[int, int], ...]:
    if isinstance((raw_spans := pend.get("trimmed_spans")), list):
        spans = tuple((int(sp[0]), int(sp[1])) for sp in raw_spans
                      if isinstance(sp, (list, tuple)) and len(sp) >= 2 and isinstance(sp[0], int) and not isinstance(sp[0], bool)
                      and isinstance(sp[1], int) and not isinstance(sp[1], bool) and 0 < sp[0] <= sp[1])
        if spans: return spans
    ts, te = pend.get("trimmed_start"), pend.get("trimmed_end")
    return ((int(ts), int(te)),) if isinstance(ts, int) and not isinstance(ts, bool) and isinstance(te, int) and not isinstance(te, bool) and 0 < ts <= te else ()

def _apply_read_confirmation(
    harness: str, payload: dict[str, Any], state_dir_path: Path, cfg: dict[str, Any], stats_path: Path | None, *,
    eff_event: str, shadow_path: Path | None = None, outcomes_path: Path | None = None,
) -> list[tuple[str, str, int, tuple[tuple[int, int], ...]]]:
    if not state_store.state_file_in(state_dir_path).is_file(): return []
    min_tier = 1 if cfg.get("read_confirm_policy", "strict") == "bounded" else 2
    is_shadow = (cfg.get("optimizers") or {}).get("range_trim") == "shadow"
    raw_c = payload.get("tool_calls") if eff_event == "PostToolBatch" else None
    items = ([x for x in raw_c if isinstance(x, dict)] if eff_event == "PostToolBatch" and isinstance(raw_c, list)
             else ([payload] if eff_event == "PostToolUseFailure" or _tool_name(payload) in _READ_TOOLS else []))
    if not items: return []
    credits, shadow_reads, trims = [], [], []
    sess_id = str(payload.get("session_id") or payload.get("conversation_id") or payload.get("conversationId") or "default")
    cwd = raw.strip() if isinstance((raw := payload.get("cwd")), str) and raw.strip() else None
    is_batch, is_fail = eff_event == "PostToolBatch", eff_event == "PostToolUseFailure"
    with state_store.locked_state(state_dir_path) as txn:
        files_map, state_mod = txn.state.setdefault("files", {}), str(txn.state.get("model") or "unknown")
        for item in items:
            cid = _extract_item_call_id(item)
            canon, entry, st = _locate_pending_entry(files_map, cid, _candidate_paths_from_payload(item, cwd))
            if st in ("missing", "completed") or canon is None or entry is None: continue
            eff_cid = st.split(":", 1)[1] if st.startswith("synth:") else cid
            pm = entry.get("pending_reads")
            if not isinstance(pm, dict) or not isinstance((pend := pm.get(eff_cid)), dict): continue
            tier, is_final = _resolve_read_tier(harness, item, pend, str(pend.get("redirect_path") or canon), is_batch=is_batch, is_failure=is_fail)
            if not is_final:
                pend.update({"post_stage": "tool_executed", "provisional_tier": tier, "credited": False})
                txn.dirty = True
                continue
            pm.pop(eff_cid, None)
            if not pm: entry.pop("pending_reads", None)
            credited = False
            if tier in (1, 2):
                iv = [int(pend["exec_start"]), int(pend["delivered_end"]), int(pend["step"]), tier]
                if isinstance((reads := entry.setdefault("reads", [])), list):
                    reads.append(iv); entry["reads"] = state_store.merge_intervals(reads)
                if redir := pend.get("redirect_path"):
                    read_planner.mirror_unwrapped_entry(files_map, str(redir), int(pend["step"]), read_interval=iv)
                if is_shadow and not int(pend.get("byte_offset") or 0):
                    s_end = int(pend["delivered_end"]) if int(pend["delivered_end"]) > 0 else int(pend.get("exec_end") or -1)
                    if s_end > 0: shadow_reads.append((str(pend.get("canonical_target") or canon), int(pend["exec_start"]), s_end, int(pend["step"]), tier, str(pend.get("sha256") or "")))
                if pend.get("is_trim") and tier >= min_tier and not pend.get("credited"):
                    credited, pm_m = True, pend.get("model")
                    mod = pm_m if isinstance(pm_m, str) and pm_m not in ("", "unknown") else state_mod
                    p_step = int(pend.get("step") or 0)
                    credits.append((mod, int(pend.get("req_bytes") or 0), int(pend.get("saved_bytes") or 0), p_step, None if pend.get("synthetic_id") else (cid or None)))
                    if spans := _extract_trimmed_spans(pend): trims.append((mod, str(pend.get("canonical_target") or canon), p_step, spans))
            if cid: session_lifecycle.record_completed_read_id(entry, cid, tier, credited)
            txn.dirty = True
    for mod, req_b, saved_b, p_step, p_cid in credits:
        record_telemetry_event(harness, "ranges_trimmed", req_b, saved_b, stats_path=stats_path)
        dispatch_direct_outcome(record_direct_outcome, harness, mod, "range_trim", "applied", outcomes_path, session_id=sess_id, step_idx=p_step, call_id=p_cid)
    for s_canon, s_start, s_end, s_step, s_tier, s_sha in shadow_reads:
        telemetry.record_shadow_read(sess_id, s_canon, s_start, s_end, s_step, s_tier, s_sha, min_tier=min_tier, shadow_path=shadow_path)
    return trims

def _apply_mutation_invalidation(payload: dict[str, Any], sdir: Path, shadow_path: Path | None = None) -> list[str]:
    if (tn := _tool_name(payload)) not in _MUTATION_TOOLS: return []
    cwd = raw.strip() if isinstance((raw := payload.get("cwd")), str) and raw.strip() else None
    targets = list(_candidate_paths_from_payload(payload, cwd))
    if tn == "apply_patch":
        src = payload.get("tool_input")
        targets.extend(harness_adapter.extract_apply_patch_paths(src if isinstance(src, (dict, str)) else "", cwd))
    if not targets: return []
    if state_store.state_file_in(sdir).is_file():
        with state_store.locked_state(sdir) as txn:
            if session_lifecycle.invalidate_mutated_paths(txn.state, targets): txn.dirty = True
    if (shadow_path or telemetry.DEFAULT_SHADOW_PATH).is_file():
        for t in targets: telemetry.invalidate_shadow_ledger(raw_path=t, shadow_path=shadow_path)
    return list(dict.fromkeys(os.path.realpath(t) for t in targets if t))

def _batch_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance((raw_c := payload.get("tool_calls")), list): return []
    inherited: dict[str, Any] = {k: payload[k] for k in ("cwd", "session_id", "conversation_id", "conversationId", "workspace_roots") if k in payload}
    return [{**inherited, **item} for item in raw_c if isinstance(item, dict)]

def _run_post_hook_for_item(harness: str, item: dict[str, Any], cfg: dict[str, Any], sdir: Path, *, is_failure: bool) -> None:
    norm = harness_adapter.normalize_pre_tool_payload(item, cli_harness=harness)
    resp = item.get("tool_response") or item.get("toolResponse") or item.get("result")
    err = item.get("error") or (resp.get("error") if isinstance(resp, dict) else None)
    ok = not is_failure and not bool(err) and item.get("is_error") is not True
    policy_engine.run_post_tool_hooks(PolicyPostContext(
        harness=norm.harness, call_id=norm.call_id, canonical_tool=norm.canonical_tool, canonical_args=norm.canonical_args,
        mutated_paths=norm.mutated_paths, original_tool_name=norm.original_tool_name, tool_input=norm.original_tool_input,
        succeeded=ok, error=str(err) if err else None, cwd=norm.cwd, state_dir=str(sdir)), cfg)

def _advance_spool_step_and_model(harness: str, sess_id: str, payload: dict[str, Any], sdir: Path) -> tuple[int, str]:
    raw_s = payload.get("stepIdx")
    step_idx = raw_s if isinstance(raw_s, int) and not isinstance(raw_s, bool) and raw_s > 0 else 0
    snap = state_store.read_state_snapshot(sdir)
    step_idx = step_idx if step_idx > 0 else int(snap.get("auto_step_seq") or 0)
    mod = str(snap.get("model") or "")
    if step_idx <= 0:
        with state_store.locked_state(sdir) as txn:
            cur = int(txn.state.get("auto_step_seq") or 0)
            if cur <= 0: txn.state["auto_step_seq"], txn.dirty = (cur := 1), True
            step_idx, mod = cur, mod or str(txn.state.get("model") or "")
    if not mod or mod == "unknown":
        tr = payload.get("transcript_path") or payload.get("transcriptPath")
        mod = model_identity.detect_model(harness, sess_id, tr if isinstance(tr, str) else None, state_dir=sdir)
    return step_idx, mod or "unknown"

def _warn_hook_error(exc: BaseException, context: str) -> None:
    state_store.run_telemetry_safely(lambda: warn(f"shell output hook failed: {type(exc).__name__}"), context=context)

def handle_post_tool_use(harness: str, payload: dict[str, Any], stats_path: Path | None = None, *,
                         state_dir: str | Path | None = None, event_name: str | None = None) -> dict[str, Any]:
    """Record shell telemetry, read confirmations (`PostToolUse`/`PostToolBatch`/`Failure`), and hooks."""
    try:
        t0 = time.perf_counter()
        sp = stats_path or ((Path(state_dir) / "telemetry_stats.json") if state_dir else None)
        ev = str(event_name or payload.get("hook_event_name") or payload.get("event") or "PostToolUse")
        if ev in ("PostToolUse", "PostToolUseFailure") and (call := normalise_payload(harness, payload)):
            record_shell_output(harness, classify_family(call.command), measure(call.output, harness) if call.output is not None else None, call.outcome, sp)
        cfg = config.load_runtime_config()
        sdir = state_store.resolve_state_dir(payload, sd_str := (str(state_dir) if state_dir is not None else None))
        cfg = apply_runtime_governor(cfg, harness, state_dir=sd_str, payload=payload)
        sh_path, out_p = telemetry.shadow_path_for(sd_str), ledger_path_for(sd_str)
        sess_id = str(payload.get("session_id") or payload.get("conversation_id") or payload.get("conversationId") or "default")
        cid, out_mode = _extract_item_call_id(payload), str((cfg.get("optimizers") or {}).get("output_spool") or "off")
        eff_spool_dir = spool_store.resolve_spool_dir(str(sdir) if state_dir is not None else None)
        ws_roots = tuple(str(r) for r in raw_wr) if isinstance((raw_wr := payload.get("workspace_roots")), (list, tuple)) else None
        if ev == "PostToolUse" and out_mode in ("active", "shadow"):
            nat = isinstance((rs := payload.get("stepIdx")), int) and not isinstance(rs, bool) and rs > 0
            tid = payload.get("turn_id") if payload.get("turn_id") is not None else payload.get("turnId")
            snap = {} if nat else state_store.read_state_snapshot(sdir)
            tc = ("harness_native" if (nat or (isinstance(tid, str) and bool(tid.strip())) or (isinstance(tid, int) and not isinstance(tid, bool) and tid > 0))
                  else ("transcript_derived" if ((isinstance((lsi := snap.get("last_step_index")), int) and not isinstance(lsi, bool) and lsi >= 0)
                                                 or any(isinstance(v, str) and bool(v.strip()) for v in (snap.get("transcript_path"), payload.get("transcript_path"), payload.get("transcriptPath"))))
                        else "unobserved"))
            cur_step = rs if nat else max(1, snap_s if isinstance((snap_s := snap.get("auto_step_seq")), int) and not isinstance(snap_s, bool) else 1)
            spool_dec, spool_meta = spool_store.spool_post_tool_output(
                harness, payload, mode=out_mode, session_id=sess_id, call_id=cid, workspace_root=payload.get("cwd"),
                workspace_roots=ws_roots, turn_key=f"{sess_id}:step:{cur_step}", spool_dir=eff_spool_dir,
                turn_correlation=tc, hook_duration_ms=round((time.perf_counter() - t0) * 1000.0, 3))
            spool_resp = harness_adapter.format_post_tool_spool_response(harness, spool_dec)
        else:
            spool_resp, spool_meta = {}, None
            if ev == "PostToolBatch":
                spool_receipts.persist_spool_delivery_verification(payload, harness=harness, session_id=sess_id, workspace_root=payload.get("cwd"), workspace_roots=ws_roots, spool_dir=eff_spool_dir)

        batch_items = _batch_items(payload) if ev == "PostToolBatch" else []
        mut_sources = batch_items if ev == "PostToolBatch" else ([payload] if ev == "PostToolUse" else [])
        mut_paths, had_mutation = [], False
        for src_item in mut_sources:
            if _tool_name(src_item) in _MUTATION_TOOLS:
                had_mutation = True
                mut_paths.extend(_apply_mutation_invalidation(src_item, sdir, sh_path))
        mut_paths = list(dict.fromkeys(mut_paths))

        trims = _apply_read_confirmation(harness, payload, sdir, cfg, sp, eff_event=ev, shadow_path=sh_path, outcomes_path=out_p)
        step_idx, mod = _advance_spool_step_and_model(harness, sess_id, payload, sdir) if (out_mode == "active" and spool_meta is not None) else (0, "unknown")
        reg_win = max(1, int(cfg.get("regret_window_steps") or 2))
        if spool_meta is not None and out_mode == "active":
            record_telemetry_event(harness, "outputs_spooled", int(spool_meta["total_bytes"]), int(spool_meta["saved_bytes"]), stats_path=sp, event_id=cid or None)
            dispatch_direct_outcome(record_direct_outcome, harness, mod, "output_spool", "applied", out_p, session_id=sess_id, step_idx=step_idx, call_id=cid or None)
            open_outcome_window(harness, mod, "output_spool", sess_id, f"spool:{spool_meta['spool_id']}", step_idx, regret_window_steps=reg_win,
                                ledger_path=out_p, meta={"cmd_sig": str(spool_meta.get("cmd_sig") or ""), "total_lines": int(spool_meta.get("total_lines") or 0)})
        elif spool_meta is not None and out_mode == "shadow":
            telemetry.record_shadow_spool(harness, spool_meta, state_dir=sd_str, shadow_path=sh_path)
        for mod_rt, canon_rt, p_step, spans in trims:
            rt_meta: dict[str, Any] = {"trimmed_start": spans[0][0], "trimmed_end": spans[0][1], **({"trimmed_spans": [[s, e] for s, e in spans]} if len(spans) > 1 else {})}
            open_outcome_window(harness, mod_rt, "range_trim", sess_id, canon_rt, p_step, regret_window_steps=reg_win, ledger_path=out_p, meta=rt_meta)
        if had_mutation: reconcile_mutation_windows(sess_id, mut_paths, ledger_path=out_p)
        if any(isinstance(p, dict) and p.get("enabled", True) for p in (cfg.get("policy_packs") or ())):
            for h_item in (batch_items if ev == "PostToolBatch" else [payload]):
                _run_post_hook_for_item(harness, h_item, cfg, sdir, is_failure=(ev == "PostToolUseFailure"))
        return spool_resp
    except Exception as exc:  # noqa: BLE001 - hook must never fail tool execution
        _warn_hook_error(exc, "post_tool_use")
        return {}

def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: read PostToolUse/PostToolBatch JSON from stdin, emit JSON response and exit 0."""
    res: dict[str, Any] = {}
    try:
        parser = argparse.ArgumentParser(add_help=False)
        for flag, default in (("--harness", "claude"), ("--event", None), ("--state-dir", None)): parser.add_argument(flag, default=default)
        args, _ = parser.parse_known_args(argv)
        if (raw := sys.stdin.read()).strip() and isinstance((pl := json.loads(raw)), dict):
            res = handle_post_tool_use(args.harness, pl, state_dir=args.state_dir, event_name=args.event)
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - hook must never fail tool execution
        _warn_hook_error(exc, "post_tool_use_main")
    return state_store.emit_json_and_sanitize_stdio(res or {})

if __name__ == "__main__":
    raise SystemExit(main())
