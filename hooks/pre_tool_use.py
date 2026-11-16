#!/usr/bin/env python3
"""Context-Guard PreToolUse hook engine: Policy API v1 enforcement, silent trims, and telemetry."""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping

sys.path[:0] = [r] if (r := str(Path(__file__).resolve().parent.parent)) not in sys.path else []

from hooks import config, model_identity  # noqa: E402
from hooks.file_io import compute_file_sha256, count_file_lines_streaming  # noqa: E402
from hooks.outcomes import (close_outcome_windows, consume_outcome_windows, dispatch_direct_outcome,  # noqa: E402
                            ledger_path_for, open_outcome_window, reconcile_mutation_windows,
                            record_cli_verbose_regret, record_direct_outcome, record_range_trim_regret,
                            record_spool_command_repeat, record_spool_followup)
from hooks.telemetry import (DEFAULT_SHADOW_PATH, invalidate_shadow_ledger, record_file_read_outcome,  # noqa: E402
                             record_shadow_read, record_telemetry_count, shadow_path_for)
from hooks.harness_adapter import (NormalizedToolCall, can_rewrite_shell_command, detect_harness,  # noqa: E402
                                   format_pre_tool_output, normalize_line_bounds, normalize_pre_tool_payload)
from hooks.policy_engine import (apply_overwrite_to_call, apply_policy_packs_with_records,  # noqa: E402
                                 reconcile_post_transform, run_pre_decision_hooks,
                                 verify_security_policies_post_transform)
from hooks.read_planner import FOLLOWUP_TARGETED_MAX_LINES, commit_planned_file_read, plan_file_read_verdict  # noqa: E402
from hooks.session_lifecycle import invalidate_mutated_paths, prune_state_on_rewind  # noqa: E402
from hooks.shell_parser import (command_uses_rtk, extract_outline_pull_targets, extract_shell_read_targets,  # noqa: E402
                                is_bounded_shell_read, is_outline_pull, rewrite_quiet_cli_flags)
from hooks.state_store import (advance_session_step, emit_json_and_sanitize_stdio, locked_state,  # noqa: E402
                               resolve_state_dir, run_telemetry_safely, state_file_in, warn)
from policies.governor import apply_runtime_governor  # noqa: E402
from spool.store import (classify_pre_tool_spool_followup, compute_command_signature,  # noqa: E402
                         is_verbose_override_command, resolve_spool_dir)

_ORIG_VERIFY_P2 = verify_security_policies_post_transform
_SELF_CLI_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:cg-spool(?:\.(?:exe|cmd|bat))?|cg_spool\.py)(?![A-Za-z0-9_-])", re.I)
_SELF_MCP_LEAVES = frozenset(("cg_spool_slice", "cg_spool_grep", "cg_spool_list"))

STATIC_POLICY_INTERNAL_DENY_REASON = "CONTEXT-GUARD POLICY ENGINE INTERNAL ERROR (fail-closed): Unable to evaluate active security policies; call blocked."

def _static_harness_deny_output(harness: str, reason: str) -> dict[str, Any]:
    if harness == "antigravity": return {"decision": "deny", "reason": reason}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}

def _has_active_security(runtime_cfg: Mapping[str, Any]) -> bool:
    if (isinstance(runtime_cfg.get("config_error"), str) and runtime_cfg["config_error"]) or runtime_cfg.get("legacy_security_keys"):
        return True
    packs = runtime_cfg.get("policy_packs")
    return isinstance(packs, list) and any(isinstance(e, Mapping) and e.get("enabled", True) and str(e.get("kind") or "security") == "security" for e in packs)

def _snapshot_session_state(state_dir_path: Path) -> dict[str, Any]:
    """Capture a consistent snapshot of session ledger state without creating new files."""
    probe = state_dir_path
    while not probe.exists() and probe != probe.parent: probe = probe.parent
    writable, state, sf = os.access(probe, os.W_OK), {}, state_file_in(state_dir_path)
    if sf.is_file():
        try:
            with locked_state(state_dir_path, create=False) as txn: state = dict(txn.state)
        except OSError:
            writable = False
            try:
                loaded = json.loads(sf.read_text(encoding="utf-8"))
                if isinstance(loaded, dict): state = loaded
            except (OSError, json.JSONDecodeError): pass
    snap = {k: copy.deepcopy(v) for k, v in state.items() if k != "files"}
    snap["has_local_reads"], snap["state_dir_writable"] = isinstance(state.get("files"), dict) and bool(state.get("files")), writable
    return snap

def _format_deny_safely(dec: dict[str, Any], norm: NormalizedToolCall, fallback: str) -> dict[str, Any]:
    try:
        return format_pre_tool_output(dec, norm)
    except Exception:
        return _static_harness_deny_output(norm.harness, str(dec.get("reason") or fallback))

def _memoize_session_model(state_dir_path: Path, norm: NormalizedToolCall, transcript_path: str | None, step_hint: int = 1) -> str:
    try:
        with locked_state(state_dir_path) as txn:
            prev = (txn.state.get("model"), txn.state.get("model_step"))
            raw_seq = txn.state.get("auto_step_seq")
            auto_seq = raw_seq if isinstance(raw_seq, int) and not isinstance(raw_seq, bool) else 0
            eff_step = step_hint if step_hint > 0 else max(1, auto_seq)
            if norm.harness != "antigravity" and step_hint <= 0 and auto_seq == 0:
                txn.state["auto_step_seq"], txn.dirty = eff_step, True
            model = model_identity.memoize_model(norm.harness, norm.session_id, transcript_path, txn.state, eff_step, state_dir=state_dir_path)
            if (txn.state.get("model"), txn.state.get("model_step")) != prev:
                txn.dirty = True
    except OSError:
        return model_identity.detect_model(norm.harness, norm.session_id, transcript_path, state_dir=state_dir_path)
    return model

def _handle_file_mutation(state_dir_path: Path, raw_paths: str | tuple[str, ...], shadow_path: Path | None = None) -> dict[str, Any]:
    targets = (raw_paths,) if isinstance(raw_paths, str) else raw_paths
    if targets:
        try:
            with locked_state(state_dir_path) as txn:
                if invalidate_mutated_paths(txn.state, targets): txn.dirty = True
        except OSError:
            pass
        if (shadow_path or DEFAULT_SHADOW_PATH).is_file():
            run_telemetry_safely(lambda: [invalidate_shadow_ledger(raw_path=t, shadow_path=shadow_path) for t in targets], context="shadow_invalidate")
    return {"decision": "allow"}

def _reconcile_p2(cand_norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
                  fallback_norm: NormalizedToolCall | None, state_dir_path: Path, snapshot: Mapping[str, Any]) -> tuple[str, dict[str, Any] | None]:
    vfn = None if verify_security_policies_post_transform is _ORIG_VERIFY_P2 else verify_security_policies_post_transform
    return reconcile_post_transform(cand_norm, runtime_cfg, fallback_norm=fallback_norm, state_dir_path=state_dir_path, session_state_snapshot=snapshot, verify_fn=vfn)

def _pop_followup(entry: dict[str, Any]) -> tuple[Any, Any]:
    return entry.pop("pending_followup_kind", None), entry.pop("outline_pull_step", None)

def _safe_warn(msg: str, context: str) -> None:
    run_telemetry_safely(lambda: warn(msg), context=context)

def _is_non_self_mcp(norm: NormalizedToolCall) -> bool:
    tn, ti = norm.original_tool_name, norm.original_tool_input
    if not (tn.startswith(("mcp__", "MCP:")) or norm.canonical_tool == "call_mcp_tool"):
        return False
    inner = str(ti.get("name") or ti.get("tool_name") or "") if tn == "call_mcp_tool" and isinstance(ti, Mapping) else tn
    return inner.rsplit("__", 1)[-1].rsplit(":", 1)[-1] not in _SELF_MCP_LEAVES

def _apply_spool_followup(sess_id: str, norm: NormalizedToolCall, step_idx: int,
                          sp_dir: str | None, outcomes_path: Path | None) -> bool:
    fu = classify_pre_tool_spool_followup(
        norm.original_tool_name, norm.original_tool_input, spool_dir=resolve_spool_dir(sp_dir),
        workspace_root=norm.cwd, workspace_roots=norm.workspace_roots, session_id=norm.session_id)
    if fu is None:
        return False
    record_spool_followup(sess_id, str(fu["spool_id"]), str(fu["recovery"]), str(fu["regret"]), step_idx,
                          evidence=str(fu.get("evidence") or "observed"), ledger_path=outcomes_path)
    return True

def evaluate_hook(payload: dict[str, Any], state_dir: str | None = None, cli_harness: str | None = None) -> dict[str, Any]:
    """Evaluate PreToolUse hook payload across Antigravity, Claude Code, Cursor, and Codex."""
    runtime_cfg = config.load_runtime_config()
    try:
        orig_norm = normalize_pre_tool_payload(payload, cli_harness=cli_harness)
    except Exception as exc:
        err_t = type(exc).__name__
        run_telemetry_safely(lambda: warn(f"normalize fallback ({err_t})"), context="normalize_fallback")
        try:
            fb_h: str = detect_harness(payload, cli_harness=cli_harness)
        except Exception:
            fb_h = (
                cli_harness if cli_harness in ("claude", "cursor", "codex", "antigravity")
                else ("antigravity" if ("toolCall" in payload or "conversationId" in payload) else "claude")
            )
        if _has_active_security(runtime_cfg):
            return _static_harness_deny_output(fb_h, STATIC_POLICY_INTERNAL_DENY_REASON)
        return {"decision": "allow"} if fb_h == "antigravity" else {}

    if orig_norm.harness == "antigravity" and not isinstance(payload.get("toolCall"), dict):
        return {"decision": "allow"}
    try:
        state_dir_path = resolve_state_dir(payload, state_dir)
        runtime_cfg = apply_runtime_governor(runtime_cfg, orig_norm.harness, state_dir=state_dir_path, payload=payload)
        snapshot = _snapshot_session_state(state_dir_path)
        block_dec, eval_records, norm, pack_ow = apply_policy_packs_with_records(orig_norm, runtime_cfg, state_dir_path=state_dir_path, session_state_snapshot=snapshot)
        if block_dec is not None:
            saved_ok = run_pre_decision_hooks(eval_records)
            trig = eval_records[-1][2] if eval_records else None
            if (
                not saved_ok and trig is not None and trig.decision == "deny"
                and trig.metadata.get("fail_open_if_retry_unsaved") is True
            ):
                return format_pre_tool_output({"decision": "allow"}, orig_norm)
            return _format_deny_safely(block_dec, orig_norm, STATIC_POLICY_INTERNAL_DENY_REASON)

        if pack_ow:
            sec_ow = any(m.kind == "security" and d is not None and isinstance(d.overwrite, Mapping) and d.overwrite for m, _c, d in eval_records)
            st_p2, dec_p2 = _reconcile_p2(norm, runtime_cfg, fallback_norm=None if sec_ow else orig_norm, state_dir_path=state_dir_path, snapshot=snapshot)
            if st_p2 == "deny":
                run_pre_decision_hooks(eval_records)
                return _format_deny_safely(dec_p2 or {}, orig_norm, STATIC_POLICY_INTERNAL_DENY_REASON)
            if st_p2 == "discard":
                norm, pack_ow = orig_norm, None

        tool_name, args, step_idx = norm.canonical_tool, norm.canonical_args, norm.step_idx
        stats_path = (Path(state_dir) / "telemetry_stats.json") if state_dir else None
        outcomes_path, shadow_path = ledger_path_for(state_dir), shadow_path_for(state_dir)
        eff_cid = None if norm.has_synthetic_call_id else (norm.call_id or None)
        reg_win = int(runtime_cfg.get("regret_window_steps") or 2)
        tr_raw = payload.get("transcript_path") or payload.get("transcriptPath")
        transcript_path = tr_raw if isinstance(tr_raw, str) else None
        sp_dir_arg = str(state_dir_path) if state_dir is not None else None
        allow_dec: dict[str, Any] = {"decision": "allow", "overwrite": pack_ow} if pack_ow else {"decision": "allow"}
        _allow = lambda d, n: (run_pre_decision_hooks(eval_records), format_pre_tool_output(d, n))[1]
        _deny = lambda d, n: (run_pre_decision_hooks(eval_records), _format_deny_safely(d or {}, n, STATIC_POLICY_INTERNAL_DENY_REASON))[1]
        _close_win = lambda s: (run_telemetry_safely(lambda: close_outcome_windows(norm.session_id, s, ledger_path=outcomes_path), context="close_windows") if s > 0 else None)

        if tool_name in ("edit_file", "write_file"):
            targets: tuple[str, ...] = tuple(norm.mutated_paths) or (
                (rp.strip(),) if isinstance((rp := args.get("Path") or args.get("TargetFile") or args.get("AbsolutePath")), str) and rp.strip() else ()
            )
            cur_s = step_idx
            if targets:
                _handle_file_mutation(state_dir_path, targets, shadow_path=shadow_path)
                if norm.harness != "antigravity" and step_idx <= 0:
                    cur_s = advance_session_step(state_dir_path)
            run_telemetry_safely(lambda: reconcile_mutation_windows(norm.session_id, targets, ledger_path=outcomes_path), context="reconcile_mutation")
            _close_win(cur_s)
            return _allow(allow_dec, norm)

        if tool_name in ("read_file", "view_file"):
            raw_path = args.get("Path") or args.get("AbsolutePath")
            if not isinstance(raw_path, str) or not raw_path.strip():
                return _allow(allow_dec, norm)
            path_arg_key = "AbsolutePath" if "AbsolutePath" in args and "Path" not in args else "Path"
            start_line, end_line, is_inv = normalize_line_bounds(
                args.get("StartLine"), args.get("EndLine"), has_start_key="StartLine" in args, has_end_key="EndLine" in args)
            if is_inv:
                return _allow(allow_dec, norm)
            off_raw = args.get("ByteOffset") or args.get("ContentOffset")
            byte_offset = int(off_raw) if isinstance(off_raw, int) and off_raw > 0 else 0
            opt_cfg = runtime_cfg.get("optimizers", {})
            auto_mode, trim_mode = str(opt_cfg.get("auto_outline", "active")), str(opt_cfg.get("range_trim", "active"))
            enable_twg = runtime_cfg.get("integrations", {}).get("atlassian_twg") == "active"
            allow_auto_outline, can_trim = (auto_mode == "active"), (trim_mode == "active")
            min_tier = 1 if runtime_cfg.get("read_confirm_policy", "strict") == "bounded" else 2
            planned = plan_file_read_verdict(
                state_dir_path=state_dir_path, raw_path=raw_path.strip(), start_line=start_line, end_line=end_line,
                byte_offset=byte_offset, step_idx=step_idx, allow_auto_outline=allow_auto_outline, path_arg_key=path_arg_key,
                auto_increment_step=(norm.harness != "antigravity" and step_idx <= 0), harness=norm.harness, read_tool=tool_name,
                can_trim=can_trim, can_redirect_path=(allow_auto_outline or enable_twg), call_id=norm.call_id,
                synthetic_id=norm.has_synthetic_call_id, model=str(snapshot.get("model") or "unknown"), min_tier=min_tier)
            ov_plan = planned.outcome.decision.get("overwrite")
            p2_act, p2_dec = (_reconcile_p2(apply_overwrite_to_call(norm, ov_plan), runtime_cfg, fallback_norm=norm, state_dir_path=state_dir_path, snapshot=snapshot)
                              if isinstance(ov_plan, dict) and ov_plan else ("allow", None))
            if p2_act == "deny":
                return _deny(p2_dec, norm)
            if p2_act == "discard":
                read_outcome, dec, kind = planned.outcome, dict(allow_dec), "none"
            else:
                if planned.outcome.intervention == "range_trim" and isinstance(planned.meta.get("pending"), dict):
                    planned.meta["pending"]["model"] = _memoize_session_model(state_dir_path, norm, transcript_path, planned.outcome.effective_step_idx or step_idx)
                try:
                    read_outcome = commit_planned_file_read(planned)
                    dec, kind = dict(read_outcome.decision), (read_outcome.intervention or "none")
                except OSError as exc:
                    _safe_warn(f"commit_planned_file_read fallback ({type(exc).__name__})", "commit_read")
                    read_outcome, dec, kind = planned.outcome, dict(allow_dec), "none"
            output = _allow(dec, norm)

            def _record_read_telemetry() -> None:
                if kind != "range_trim":
                    record_file_read_outcome(norm.harness, raw_path.strip(), start_line, end_line, dec if kind == "outline" else {"decision": "allow"}, kind, stats_path, byte_offset=byte_offset)
                eff_step = read_outcome.effective_step_idx or step_idx
                if trim_mode == "shadow" and kind != "outline" and byte_offset == 0 and isinstance((pend := planned.meta.get("pending")), dict):
                    s_end = int(pend["delivered_end"]) if int(pend.get("delivered_end") or -1) > 0 else end_line
                    record_shadow_read(norm.session_id, str(pend.get("canonical_target") or raw_path.strip()), int(pend.get("exec_start") or start_line),
                                       s_end, eff_step, 0, str(pend.get("sha256") or ""), min_tier=min_tier, shadow_path=shadow_path)
                if kind == "outline" or read_outcome.followup_resolution is not None:
                    mod = _memoize_session_model(state_dir_path, norm, transcript_path, eff_step)
                    if kind == "outline":
                        dispatch_direct_outcome(record_direct_outcome, norm.harness, mod, "outline", "applied", outcomes_path, session_id=norm.session_id, step_idx=eff_step, call_id=eff_cid)
                        if planned.meta.get("pk_name") == "outline":
                            open_outcome_window(norm.harness, mod, "outline", norm.session_id, planned.canon, eff_step, regret_window_steps=reg_win, ledger_path=outcomes_path)
                    if read_outcome.followup_resolution is not None:
                        p_kind, p_out = read_outcome.followup_resolution
                        dispatch_direct_outcome(record_direct_outcome, norm.harness, mod, p_kind, p_out, outcomes_path, increment_total=False, session_id=norm.session_id, step_idx=eff_step, call_id=eff_cid)
                        consume_outcome_windows(norm.session_id, (planned.canon, *planned.meta.get("peers", ())), kind=p_kind, ledger_path=outcomes_path)
                _apply_spool_followup(norm.session_id, orig_norm, eff_step, sp_dir_arg, outcomes_path)
                if kind != "outline":
                    record_range_trim_regret(norm.session_id, planned.canon or os.path.realpath(raw_path.strip()), start_line, None if end_line == -1 else end_line, eff_step, ledger_path=outcomes_path)
                if eff_step > 0:
                    close_outcome_windows(norm.session_id, eff_step, ledger_path=outcomes_path)

            run_telemetry_safely(_record_read_telemetry, context="read_telemetry")
            return output

        if tool_name == "run_command":
            cmd_line = args.get("CommandLine")
            if not isinstance(cmd_line, str) or not cmd_line.strip():
                return _allow(allow_dec, norm)
            auto_step = advance_session_step(state_dir_path) if (norm.harness != "antigravity" and step_idx <= 0) else 0
            cur_cmd_step = step_idx if step_idx > 0 else auto_step
            raw_cwd = args.get("Cwd")
            cmd_cwd = norm.cwd or (raw_cwd.strip() if isinstance(raw_cwd, str) and raw_cwd.strip() else None)
            is_pull, pull_step, shell_targets = is_outline_pull(cmd_line), [cur_cmd_step], []
            if is_pull:
                pull_targets = [(t, sha) for t in extract_outline_pull_targets(cmd_line, cmd_cwd) for sha in (compute_file_sha256(t),) if sha is not None]
                pull_count = max(1, len(pull_targets))
                if pull_targets:
                    def _stamp_pull() -> None:
                        with locked_state(state_dir_path) as txn:
                            prev_max = int(txn.state.get("max_tool_step_idx") or 0)
                            if step_idx > 0 and prev_max > 0 and step_idx < prev_max: prune_state_on_rewind(txn.state, step_idx, inclusive=True)
                            cur_seq = int(txn.state.get("auto_step_seq") or 0)
                            eff_step = step_idx if step_idx > 0 else ((auto_step if auto_step > 0 else cur_seq + 1) if norm.harness != "antigravity" else cur_seq)
                            if step_idx <= 0 and norm.harness != "antigravity": txn.state["auto_step_seq"] = max(cur_seq, eff_step)
                            pull_step[0] = eff_step
                            txn.state["max_tool_step_idx"] = max(eff_step, int(txn.state.get("max_tool_step_idx") or 0))
                            files_map = txn.state.setdefault("files", {})
                            for target, sha in pull_targets:
                                re_ = files_map.get(target)
                                entry = dict(re_) if isinstance(re_, dict) and re_.get("sha256") == sha else {"sha256": sha, "reads": []}
                                entry["pending_followup_kind"], entry["outline_pull_step"] = "outline_pull", eff_step
                                files_map[target] = entry
                            txn.dirty = True
                    run_telemetry_safely(_stamp_pull, context="stamp_outline_pull")

                def _record_pull() -> None:
                    record_telemetry_count(norm.harness, "outline_pulls", stats_path)
                    mod = _memoize_session_model(state_dir_path, norm, transcript_path, pull_step[0])
                    dispatch_direct_outcome(record_direct_outcome, norm.harness, mod, "outline_pull", "applied", outcomes_path, count=pull_count, session_id=norm.session_id, step_idx=pull_step[0], call_id=eff_cid)
                    for target, _ in pull_targets: open_outcome_window(norm.harness, mod, "outline_pull", norm.session_id, target, pull_step[0], regret_window_steps=reg_win, ledger_path=outcomes_path)
                run_telemetry_safely(_record_pull, context="outline_pull")
            elif (shell_targets := extract_shell_read_targets(cmd_line, cmd_cwd)):
                def _record_shell_followups() -> None:
                    if not state_file_in(state_dir_path).is_file(): return
                    shell_shas, resolved = {t: compute_file_sha256(t) for t in shell_targets}, []
                    with locked_state(state_dir_path, create=False) as txn:
                        prev_max = int(txn.state.get("max_tool_step_idx") or 0)
                        rewound = step_idx > 0 and prev_max > 0 and step_idx < prev_max
                        if rewound and prune_state_on_rewind(txn.state, step_idx, inclusive=True): txn.dirty = True
                        if step_idx > int(txn.state.get("max_tool_step_idx") or 0): txn.state["max_tool_step_idx"], txn.dirty = step_idx, True
                        if isinstance((files_map := txn.state.get("files")), dict):
                            for target in shell_targets:
                                if not isinstance((entry := files_map.get(target)), dict): continue
                                p_kind, p_step = _pop_followup(entry)
                                kl = int(entry.get("outlined_total_lines") or 0)
                                if p_kind is not None or p_step is not None: txn.dirty = True
                                for other in (entry.get("unwrapped_path"), entry.get("mirror_source")):
                                    if isinstance((o_ent := files_map.get(other) if isinstance(other, str) else None), dict):
                                        op, ops = _pop_followup(o_ent)
                                        kl = kl or int(o_ent.get("outlined_total_lines") or 0)
                                        if op is not None or ops is not None: txn.dirty, p_kind = True, (op if p_kind is None else p_kind)
                                sha = shell_shas.get(target)
                                if p_kind in ("outline", "outline_pull") and (not entry.get("sha256") or not sha or entry.get("sha256") == sha):
                                    resolved.append((target, p_kind, kl))
                    if rewound:
                        if (shadow_path or DEFAULT_SHADOW_PATH).is_file(): invalidate_shadow_ledger(session_id=norm.session_id, max_step=step_idx, inclusive_rewind=True, shadow_path=shadow_path)
                        close_outcome_windows(norm.session_id, rewind_step=step_idx, ledger_path=outcomes_path)
                    if resolved:
                        mod = _memoize_session_model(state_dir_path, norm, transcript_path, cur_cmd_step)
                        counts: dict[tuple[str, str], int] = {}
                        by_kind: dict[str, list[str]] = {}
                        for target, p_kind, kl in resolved:
                            bounded = norm.harness == "codex" and is_bounded_shell_read(cmd_line, total_lines=(kl or count_file_lines_streaming(target)), max_lines=FOLLOWUP_TARGETED_MAX_LINES)
                            key = (p_kind, "targeted_followup" if bounded else "shell_bypass")
                            counts[key] = counts.get(key, 0) + 1
                            by_kind.setdefault(p_kind, []).append(target)
                        for (p_kind, out_name), cnt in counts.items(): dispatch_direct_outcome(record_direct_outcome, norm.harness, mod, p_kind, out_name, outcomes_path, increment_total=False, session_id=norm.session_id, step_idx=cur_cmd_step, call_id=eff_cid, count=cnt)
                        for p_kind, tgts in by_kind.items(): consume_outcome_windows(norm.session_id, tgts, kind=p_kind, ledger_path=outcomes_path)
                run_telemetry_safely(_record_shell_followups, context="shell_bypass")

            is_verb, base_sig = is_verbose_override_command(cmd_line)
            cmd_sig = "" if (is_pull or _SELF_CLI_RE.search(cmd_line)) else compute_command_signature(orig_norm.original_tool_name or "Bash", cmd_line)
            def _correlate_shell() -> None:
                if is_verb and base_sig:
                    record_cli_verbose_regret(norm.session_id, base_sig, cur_cmd_step, ledger_path=outcomes_path)
                if not _apply_spool_followup(norm.session_id, orig_norm, cur_cmd_step, sp_dir_arg, outcomes_path) and cmd_sig:
                    record_spool_command_repeat(norm.session_id, cmd_sig, cur_cmd_step, ledger_path=outcomes_path)
                for t in shell_targets:
                    record_range_trim_regret(norm.session_id, os.path.realpath(t), 1, None, cur_cmd_step, is_shell_bypass=True, ledger_path=outcomes_path)
                if (ws := pull_step[0] if is_pull else cur_cmd_step) > 0:
                    close_outcome_windows(norm.session_id, ws, ledger_path=outcomes_path)
            run_telemetry_safely(_correlate_shell, context="shell_correlation")

            enable_twg = runtime_cfg.get("integrations", {}).get("atlassian_twg") == "active"
            cli_mode = str(runtime_cfg.get("optimizers", {}).get("cli_rewrites", "auto"))
            rtk_yield = command_uses_rtk(cmd_line) or (cli_mode == "auto" and config.scan_hooks_for_rtk(cwd=cmd_cwd))
            if not is_verb and cli_mode in ("auto", "force") and not rtk_yield and can_rewrite_shell_command(norm):
                rewritten = rewrite_quiet_cli_flags(cmd_line, enable_atlassian_twg=enable_twg)
                if rewritten is not None and rewritten != cmd_line:
                    cand_ow = {"CommandLine": rewritten}
                    p2_act, p2_dec = _reconcile_p2(apply_overwrite_to_call(norm, cand_ow), runtime_cfg, fallback_norm=norm, state_dir_path=state_dir_path, snapshot=snapshot)
                    if p2_act == "deny": return _deny(p2_dec, norm)
                    if p2_act == "allow":
                        output = _allow({"decision": "allow", "overwrite": {**pack_ow, **cand_ow} if pack_ow else cand_ow}, norm)
                        def _rec_cli() -> None:
                            record_telemetry_count(norm.harness, "cli_rewrites", stats_path)
                            mod = _memoize_session_model(state_dir_path, norm, transcript_path, cur_cmd_step)
                            cli_step = cur_cmd_step or (1 if norm.harness != "antigravity" else 0)
                            dispatch_direct_outcome(record_direct_outcome, norm.harness, mod, "cli_rewrite", "applied", outcomes_path, session_id=norm.session_id, step_idx=cli_step, call_id=eff_cid)
                            if cli_sig := compute_command_signature(orig_norm.original_tool_name or "Bash", cmd_line):
                                open_outcome_window(norm.harness, mod, "cli_rewrite", norm.session_id, f"cli:{cli_sig}", cli_step, regret_window_steps=reg_win, ledger_path=outcomes_path, meta={"base_sig": cli_sig})
                        run_telemetry_safely(_rec_cli, context="cli_rewrites")
                        return output
            return _allow(allow_dec, norm)

        def _correlate_other() -> None:
            cur_s = step_idx if step_idx > 0 else (advance_session_step(state_dir_path) if norm.harness != "antigravity" else 0)
            if not _apply_spool_followup(norm.session_id, orig_norm, cur_s, sp_dir_arg, outcomes_path) and _is_non_self_mcp(orig_norm):
                record_spool_command_repeat(norm.session_id, compute_command_signature(orig_norm.original_tool_name, orig_norm.original_tool_input), cur_s, ledger_path=outcomes_path)
            if cur_s > 0: close_outcome_windows(norm.session_id, cur_s, ledger_path=outcomes_path)
        run_telemetry_safely(_correlate_other, context="mcp_correlation")
        return _allow(allow_dec, norm)
    except Exception as exc:
        _safe_warn(f"optimizer fallback ({type(exc).__name__})", "optimizer_fallback")
        if _has_active_security(runtime_cfg): return _static_harness_deny_output(orig_norm.harness, STATIC_POLICY_INTERNAL_DENY_REASON)
        return {} if orig_norm.harness != "antigravity" else {"decision": "allow"}

def _fail_closed_exit(harness_hint: str | None, msg: str) -> int:
    _safe_warn(msg, "main_fallback")
    try: sec = _has_active_security(config.load_runtime_config())
    except Exception: sec = True
    if not sec: return emit_json_and_sanitize_stdio({} if harness_hint in ("claude", "cursor", "codex") else {"decision": "allow"})
    h = harness_hint if harness_hint in ("claude", "cursor", "codex") else "antigravity"
    if h == "codex": sys.stderr.write(f"{STATIC_POLICY_INTERNAL_DENY_REASON}\n")
    emit_json_and_sanitize_stdio(_static_harness_deny_output(h, STATIC_POLICY_INTERNAL_DENY_REASON))
    return 2

def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint reading PreToolUse JSON from stdin and printing decision JSON to stdout."""
    harness_hint: str | None = None
    try:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--harness", default=None)
        harness_hint = parser.parse_known_args(argv)[0].harness
        if not (raw_in := sys.stdin.read()).strip(): return _fail_closed_exit(harness_hint, "pre_tool_use main fallback (empty stdin)")
        if not isinstance((pl := json.loads(raw_in)), dict): return _fail_closed_exit(harness_hint, "pre_tool_use main fallback (non-dict payload)")
        out_obj = evaluate_hook(pl, cli_harness=harness_hint)
        hso = out_obj.get("hookSpecificOutput") if isinstance(out_obj, Mapping) else None
        if isinstance(hso, Mapping) and hso.get("permissionDecision") == "deny" and (harness_hint == "codex" or detect_harness(pl, cli_harness=harness_hint) == "codex"):
            sys.stderr.write(f"{hso.get('permissionDecisionReason') or STATIC_POLICY_INTERNAL_DENY_REASON}\n")
            emit_json_and_sanitize_stdio(out_obj)
            return 2
        return emit_json_and_sanitize_stdio(out_obj)
    except (Exception, SystemExit) as exc:
        return _fail_closed_exit(harness_hint, f"pre_tool_use main fallback ({type(exc).__name__})")

if __name__ == "__main__":
    try: raise SystemExit(main())
    except SystemExit: raise
    except BaseException as exc:
        sys.stderr.write(f"context-guard pre_tool_use fatal ({type(exc).__name__})\n")
        raise SystemExit(2)
