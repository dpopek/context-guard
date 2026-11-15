#!/usr/bin/env python3
"""Context-Guard PreToolUse hook engine: Policy API v1 enforcement, silent trims, and telemetry."""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

_PLUGIN_ROOT = str(Path(__file__).resolve().parent.parent)
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from hooks.config import load_runtime_config  # noqa: E402
from hooks.file_io import compute_file_sha256, count_file_lines_streaming  # noqa: E402
from hooks.harness_adapter import (  # noqa: E402
    NormalizedToolCall,
    can_rewrite_shell_command,
    detect_harness,
    format_pre_tool_output,
    normalize_line_bounds,
    normalize_pre_tool_payload,
)
from hooks.model_identity import detect_model, memoize_model  # noqa: E402
from hooks.outcomes import ledger_path_for, record_direct_outcome  # noqa: E402
from hooks.policy_engine import (  # noqa: E402
    apply_overwrite_to_call,
    apply_policy_packs_with_records,
    run_pre_decision_hooks,
    verify_security_policies_post_transform,
)
from hooks.read_planner import FOLLOWUP_TARGETED_MAX_LINES, handle_file_read_verdict  # noqa: E402
from hooks.session_lifecycle import prune_state_on_rewind  # noqa: E402
from hooks.shell_parser import (  # noqa: E402
    extract_outline_pull_targets,
    extract_shell_read_targets,
    is_bounded_shell_read,
    is_outline_pull,
    rewrite_quiet_cli_flags,
)
from hooks.state_store import (  # noqa: E402
    advance_session_step,
    emit_json_and_sanitize_stdio,
    locked_state,
    resolve_state_dir,
    run_telemetry_safely,
    state_file_in,
    warn,
)
from hooks.telemetry import record_file_read_outcome, record_telemetry_count  # noqa: E402

STATIC_POLICY_INTERNAL_DENY_REASON = (
    "CONTEXT-GUARD POLICY ENGINE INTERNAL ERROR (fail-closed): "
    "Unable to evaluate active security policies; call blocked."
)


def _static_harness_deny_output(harness: str, reason: str) -> dict[str, Any]:
    if harness == "antigravity":
        return {"decision": "deny", "reason": reason}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _has_active_security(runtime_cfg: Mapping[str, Any]) -> bool:
    if isinstance(runtime_cfg.get("config_error"), str) and runtime_cfg["config_error"]:
        return True
    packs = runtime_cfg.get("policy_packs")
    if not isinstance(packs, list):
        return False
    return any(
        isinstance(entry, Mapping)
        and entry.get("enabled", True)
        and str(entry.get("kind") or "security") == "security"
        for entry in packs
    )


def _snapshot_session_state(state_dir_path: Path) -> dict[str, Any]:
    """Capture a consistent snapshot of session ledger state without creating new files."""
    probe = state_dir_path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    writable = os.access(probe, os.W_OK)
    state: dict[str, Any] = {}
    sf = state_file_in(state_dir_path)
    if sf.is_file():
        try:
            with locked_state(state_dir_path, create=False) as txn:
                state = dict(txn.state)
        except OSError:
            writable = False
            try:
                loaded = json.loads(sf.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    state = loaded
            except (OSError, json.JSONDecodeError):
                state = {}
    snapshot = {k: copy.deepcopy(v) for k, v in state.items() if k != "files"}
    snapshot["has_local_reads"] = bool(state.get("files")) if isinstance(state.get("files"), dict) else False
    snapshot["state_dir_writable"] = writable
    return snapshot


def _format_deny_safely(dec: dict[str, Any], norm: NormalizedToolCall, fallback_reason: str) -> dict[str, Any]:
    try:
        return format_pre_tool_output(dec, norm)
    except Exception:
        return _static_harness_deny_output(norm.harness, str(dec.get("reason") or fallback_reason))


def _memoize_session_model(
    state_dir_path: Path, norm: NormalizedToolCall, transcript_path: str | None, step_hint: int = 1
) -> str:
    try:
        with locked_state(state_dir_path) as txn:
            prev = (txn.state.get("model"), txn.state.get("model_step"))
            raw_seq = txn.state.get("auto_step_seq")
            auto_seq = raw_seq if isinstance(raw_seq, int) and not isinstance(raw_seq, bool) else 0
            eff_step = step_hint if step_hint > 0 else max(1, auto_seq)
            if norm.harness != "antigravity" and step_hint <= 0 and auto_seq == 0:
                txn.state["auto_step_seq"] = eff_step
                txn.dirty = True
            model = memoize_model(
                norm.harness, norm.session_id, transcript_path, txn.state, eff_step, state_dir=state_dir_path
            )
            if (txn.state.get("model"), txn.state.get("model_step")) != prev:
                txn.dirty = True
    except OSError:
        return detect_model(norm.harness, norm.session_id, transcript_path, state_dir=state_dir_path)
    return model


def _handle_file_mutation(state_dir_path: Path, raw_paths: str | tuple[str, ...]) -> dict[str, Any]:
    targets = (raw_paths,) if isinstance(raw_paths, str) else raw_paths
    if not targets:
        return {"decision": "allow"}
    try:
        with locked_state(state_dir_path) as txn:
            files = txn.state["files"]
            for raw_path in targets:
                if not raw_path:
                    continue
                canon = os.path.realpath(raw_path)
                if canon in files or raw_path in files:
                    files.pop(canon, None)
                    files.pop(raw_path, None)
                    txn.dirty = True
    except OSError:
        pass
    return {"decision": "allow"}


def evaluate_hook(payload: dict[str, Any], state_dir: str | None = None, cli_harness: str | None = None) -> dict[str, Any]:
    """Evaluate PreToolUse hook payload across Antigravity, Claude Code, Cursor, and Codex."""
    runtime_cfg = load_runtime_config()
    try:
        orig_norm = normalize_pre_tool_payload(payload, cli_harness=cli_harness)
    except Exception as exc:
        norm_err = exc
        run_telemetry_safely(
            lambda: warn(f"normalize fallback ({type(norm_err).__name__}): {norm_err}"), context="normalize_fallback"
        )
        try:
            fallback_harness: str = detect_harness(payload, cli_harness=cli_harness)
        except Exception:
            fallback_harness = (
                cli_harness
                if cli_harness in ("claude", "cursor", "codex", "antigravity")
                else ("antigravity" if ("toolCall" in payload or "conversationId" in payload) else "claude")
            )
        if _has_active_security(runtime_cfg):
            return _static_harness_deny_output(fallback_harness, STATIC_POLICY_INTERNAL_DENY_REASON)
        return {"decision": "allow"} if fallback_harness == "antigravity" else {}

    if orig_norm.harness == "antigravity" and not isinstance(payload.get("toolCall"), dict):
        return {"decision": "allow"}

    try:
        state_dir_path = resolve_state_dir(payload, state_dir)
        snapshot = _snapshot_session_state(state_dir_path)
        block_decision, eval_records, norm, pack_overwrite = apply_policy_packs_with_records(
            orig_norm, runtime_cfg, state_dir_path=state_dir_path, session_state_snapshot=snapshot
        )
        if block_decision is not None:
            saved_ok = run_pre_decision_hooks(eval_records)
            trigger_dec = eval_records[-1][2] if eval_records else None
            if (
                not saved_ok
                and trigger_dec is not None
                and trigger_dec.decision == "deny"
                and trigger_dec.metadata.get("fail_open_if_retry_unsaved") is True
            ):
                return format_pre_tool_output({"decision": "allow"}, orig_norm)
            return _format_deny_safely(block_decision, orig_norm, STATIC_POLICY_INTERNAL_DENY_REASON)

        if pack_overwrite:
            p2_pack_block = verify_security_policies_post_transform(
                norm,
                runtime_cfg,
                state_dir_path=state_dir_path,
                session_state_snapshot=snapshot,
            )
            if p2_pack_block is not None:
                norm = orig_norm
                pack_overwrite = None

        tool_name, args, step_idx = norm.canonical_tool, norm.canonical_args, norm.step_idx
        stats_path = (Path(state_dir) / "telemetry_stats.json") if state_dir else None
        outcomes_path = ledger_path_for(state_dir)
        transcript_raw = payload.get("transcript_path") or payload.get("transcriptPath")
        transcript_path = transcript_raw if isinstance(transcript_raw, str) else None
        allow_dec: dict[str, Any] = {"decision": "allow", "overwrite": pack_overwrite} if pack_overwrite else {"decision": "allow"}

        if tool_name in ("edit_file", "write_file"):
            targets: tuple[str, ...] = tuple(norm.mutated_paths)
            if not targets:
                raw_path = args.get("Path") or args.get("TargetFile") or args.get("AbsolutePath")
                if isinstance(raw_path, str) and raw_path.strip():
                    targets = (raw_path.strip(),)
            if targets:
                _handle_file_mutation(state_dir_path, targets)
                if norm.harness != "antigravity" and step_idx <= 0:
                    advance_session_step(state_dir_path)
            run_pre_decision_hooks(eval_records)
            return format_pre_tool_output(allow_dec, norm)

        if tool_name in ("read_file", "view_file"):
            raw_path = args.get("Path") or args.get("AbsolutePath")
            if not isinstance(raw_path, str) or not raw_path.strip():
                run_pre_decision_hooks(eval_records)
                return format_pre_tool_output(allow_dec, norm)
            path_arg_key = "AbsolutePath" if "AbsolutePath" in args and "Path" not in args else "Path"
            start_line, end_line, is_inverted_end = normalize_line_bounds(
                args.get("StartLine"), args.get("EndLine"), has_start_key="StartLine" in args, has_end_key="EndLine" in args
            )
            if is_inverted_end:
                run_pre_decision_hooks(eval_records)
                return format_pre_tool_output(allow_dec, norm)
            offset_raw = args.get("ByteOffset") or args.get("ContentOffset")
            byte_offset = int(offset_raw) if isinstance(offset_raw, int) and offset_raw > 0 else 0
            stripped_path = raw_path.strip()
            allow_auto_outline = runtime_cfg.get("optimizers", {}).get("auto_outline", "active") != "off"
            read_outcome = handle_file_read_verdict(
                state_dir_path=state_dir_path,
                raw_path=stripped_path,
                start_line=start_line,
                end_line=end_line,
                byte_offset=byte_offset,
                step_idx=step_idx,
                allow_auto_outline=allow_auto_outline,
                path_arg_key=path_arg_key,
                auto_increment_step=(norm.harness != "antigravity" and step_idx <= 0),
                harness=norm.harness,
                read_tool=tool_name,
            )
            dec, kind = dict(read_outcome.decision), read_outcome.intervention
            if isinstance(dec.get("overwrite"), dict) and dec["overwrite"]:
                p2_read_block = verify_security_policies_post_transform(
                    apply_overwrite_to_call(norm, dec["overwrite"]),
                    runtime_cfg,
                    state_dir_path=state_dir_path,
                    session_state_snapshot=snapshot,
                )
                if p2_read_block is not None:
                    dec = {"decision": "allow"}
                    kind = "none"
            run_pre_decision_hooks(eval_records)
            output = format_pre_tool_output(dec, norm)

            def _record_read_telemetry() -> None:
                record_file_read_outcome(norm.harness, stripped_path, start_line, end_line, dec, kind, stats_path, byte_offset=byte_offset)
                eff_step = read_outcome.effective_step_idx or step_idx
                if kind in ("outline", "range_trim") or read_outcome.followup_resolution is not None:
                    model = _memoize_session_model(state_dir_path, norm, transcript_path, eff_step)
                    if kind in ("outline", "range_trim"):
                        record_direct_outcome(norm.harness, model, kind, "applied", outcomes_path)
                    if read_outcome.followup_resolution is not None:
                        p_kind, p_out = read_outcome.followup_resolution
                        record_direct_outcome(norm.harness, model, p_kind, p_out, outcomes_path, increment_total=False)

            run_telemetry_safely(_record_read_telemetry, context="read_telemetry")
            return output

        if tool_name == "run_command":
            cmd_line = args.get("CommandLine")
            if not isinstance(cmd_line, str) or not cmd_line.strip():
                run_pre_decision_hooks(eval_records)
                return format_pre_tool_output(allow_dec, norm)
            auto_step = advance_session_step(state_dir_path) if (norm.harness != "antigravity" and step_idx <= 0) else 0
            raw_cwd = args.get("Cwd")
            cmd_cwd = norm.cwd or (raw_cwd.strip() if isinstance(raw_cwd, str) and raw_cwd.strip() else None)
            if is_outline_pull(cmd_line):
                pull_targets = [
                    (t, sha) for t in extract_outline_pull_targets(cmd_line, cmd_cwd)
                    for sha in (compute_file_sha256(t),) if sha is not None
                ]
                pull_count = max(1, len(pull_targets))
                if pull_targets:
                    def _stamp_pull() -> None:
                        with locked_state(state_dir_path) as txn:
                            prev_max = int(txn.state.get("max_tool_step_idx") or 0)
                            if step_idx > 0 and prev_max > 0 and step_idx < prev_max:
                                prune_state_on_rewind(txn.state, step_idx, inclusive=True)
                            if step_idx > 0:
                                eff_step = step_idx
                            elif norm.harness != "antigravity":
                                eff_step = auto_step if auto_step > 0 else int(txn.state.get("auto_step_seq") or 0) + 1
                                txn.state["auto_step_seq"] = max(int(txn.state.get("auto_step_seq") or 0), eff_step)
                            else:
                                eff_step = int(txn.state.get("auto_step_seq") or 0)
                            if eff_step > int(txn.state.get("max_tool_step_idx") or 0):
                                txn.state["max_tool_step_idx"] = eff_step
                            files_map = txn.state.setdefault("files", {})
                            for target, sha in pull_targets:
                                raw_e = files_map.get(target)
                                entry = dict(raw_e) if isinstance(raw_e, dict) and raw_e.get("sha256") == sha else {"sha256": sha, "reads": []}
                                entry["pending_followup_kind"] = "outline_pull"
                                entry["outline_pull_step"] = eff_step
                                files_map[target] = entry
                            txn.dirty = True
                    run_telemetry_safely(_stamp_pull, context="stamp_outline_pull")

                def _record_pull() -> None:
                    record_telemetry_count(norm.harness, "outline_pulls", stats_path)
                    model = _memoize_session_model(state_dir_path, norm, transcript_path, step_idx)
                    if pull_count > 1:
                        record_direct_outcome(norm.harness, model, "outline_pull", "applied", outcomes_path, count=pull_count)
                    else:
                        record_direct_outcome(norm.harness, model, "outline_pull", "applied", outcomes_path)

                run_telemetry_safely(_record_pull, context="outline_pull")
            elif (shell_targets := extract_shell_read_targets(cmd_line, cmd_cwd)):
                def _record_shell_followups() -> None:
                    if not state_file_in(state_dir_path).is_file():
                        return
                    shell_shas = {t: compute_file_sha256(t) for t in shell_targets}
                    resolved: list[tuple[str, str, int]] = []
                    with locked_state(state_dir_path, create=False) as txn:
                        prev_max = int(txn.state.get("max_tool_step_idx") or 0)
                        if step_idx > 0 and prev_max > 0 and step_idx < prev_max and prune_state_on_rewind(txn.state, step_idx, inclusive=True):
                            txn.dirty = True
                        if step_idx > int(txn.state.get("max_tool_step_idx") or 0):
                            txn.state["max_tool_step_idx"] = step_idx
                            txn.dirty = True
                        files_map = txn.state.get("files")
                        if isinstance(files_map, dict):
                            for target in shell_targets:
                                entry = files_map.get(target)
                                if not isinstance(entry, dict):
                                    continue
                                p_kind = entry.pop("pending_followup_kind", None)
                                p_step = entry.pop("outline_pull_step", None)
                                known_lines = int(entry.get("outlined_total_lines") or 0)
                                if p_kind is not None or p_step is not None:
                                    txn.dirty = True
                                for other in (entry.get("unwrapped_path"), entry.get("mirror_source")):
                                    if isinstance(other, str) and isinstance(files_map.get(other), dict):
                                        o_ent = files_map[other]
                                        other_p = o_ent.pop("pending_followup_kind", None)
                                        other_ps = o_ent.pop("outline_pull_step", None)
                                        if not known_lines:
                                            known_lines = int(o_ent.get("outlined_total_lines") or 0)
                                        if other_p is not None or other_ps is not None:
                                            txn.dirty = True
                                            p_kind = other_p if p_kind is None else p_kind
                                sha = shell_shas.get(target)
                                if p_kind in ("outline", "outline_pull") and (not entry.get("sha256") or not sha or entry.get("sha256") == sha):
                                    resolved.append((target, p_kind, known_lines))
                    if resolved:
                        model = _memoize_session_model(state_dir_path, norm, transcript_path, step_idx)
                        counts: dict[tuple[str, str], int] = {}
                        for target, p_kind, known_lines in resolved:
                            bounded = norm.harness == "codex" and is_bounded_shell_read(
                                cmd_line, total_lines=(known_lines or count_file_lines_streaming(target)), max_lines=FOLLOWUP_TARGETED_MAX_LINES
                            )
                            out_name = "targeted_followup" if bounded else "shell_bypass"
                            counts[(p_kind, out_name)] = counts.get((p_kind, out_name), 0) + 1
                        for (p_kind, out_name), cnt in counts.items():
                            if cnt > 1:
                                record_direct_outcome(norm.harness, model, p_kind, out_name, outcomes_path, increment_total=False, count=cnt)
                            else:
                                record_direct_outcome(norm.harness, model, p_kind, out_name, outcomes_path, increment_total=False)
                run_telemetry_safely(_record_shell_followups, context="shell_bypass")

            enable_twg = runtime_cfg.get("integrations", {}).get("atlassian_twg") == "active"
            cli_mode = str(runtime_cfg.get("optimizers", {}).get("cli_rewrites", "auto"))
            if cli_mode != "off" and can_rewrite_shell_command(norm):
                rewritten = rewrite_quiet_cli_flags(cmd_line, enable_atlassian_twg=enable_twg)
                if rewritten is not None and rewritten != cmd_line:
                    cand_overwrite = {"CommandLine": rewritten}
                    p2_cmd_block = verify_security_policies_post_transform(
                        apply_overwrite_to_call(norm, cand_overwrite),
                        runtime_cfg,
                        state_dir_path=state_dir_path,
                        session_state_snapshot=snapshot,
                    )
                    if p2_cmd_block is None:
                        run_pre_decision_hooks(eval_records)
                        merged_ow = {**pack_overwrite, **cand_overwrite} if pack_overwrite else cand_overwrite
                        output = format_pre_tool_output({"decision": "allow", "overwrite": merged_ow}, norm)

                        def _record_rewrite() -> None:
                            record_telemetry_count(norm.harness, "cli_rewrites", stats_path)
                            model = _memoize_session_model(state_dir_path, norm, transcript_path, step_idx)
                            record_direct_outcome(norm.harness, model, "cli_rewrite", "applied", outcomes_path)

                        run_telemetry_safely(_record_rewrite, context="cli_rewrites")
                        return output
            run_pre_decision_hooks(eval_records)
            return format_pre_tool_output(allow_dec, norm)

        run_pre_decision_hooks(eval_records)
        return format_pre_tool_output(allow_dec, norm)
    except Exception as exc:
        opt_err = exc
        run_telemetry_safely(
            lambda: warn(f"optimizer fallback ({type(opt_err).__name__}): {opt_err}"), context="optimizer_fallback"
        )
        if _has_active_security(runtime_cfg):
            return _static_harness_deny_output(orig_norm.harness, STATIC_POLICY_INTERNAL_DENY_REASON)
        return {} if orig_norm.harness != "antigravity" else {"decision": "allow"}


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint reading PreToolUse JSON from stdin and printing decision JSON to stdout."""
    fallback: dict[str, Any] = {"decision": "allow"}
    out_obj: dict[str, Any] = fallback
    harness_hint: str | None = None
    try:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--harness", default=None)
        cli_args, _ = parser.parse_known_args(argv)
        harness_hint = cli_args.harness
        fallback = {} if harness_hint in ("claude", "cursor", "codex") else {"decision": "allow"}
        out_obj = fallback
        raw_input = sys.stdin.read()
        if raw_input and raw_input.strip():
            payload = json.loads(raw_input)
            if isinstance(payload, dict):
                out_obj = evaluate_hook(payload, cli_harness=harness_hint)
    except (Exception, SystemExit) as exc:
        main_err = exc
        run_telemetry_safely(lambda: warn(f"pre_tool_use main fallback ({type(main_err).__name__})"), context="main_fallback")
        try:
            sec_active = _has_active_security(load_runtime_config())
        except Exception:
            sec_active = True
        if sec_active:
            h = harness_hint if harness_hint in ("claude", "cursor", "codex", "antigravity") else "antigravity"
            emit_json_and_sanitize_stdio(_static_harness_deny_output(h, STATIC_POLICY_INTERNAL_DENY_REASON))
            return 2
        out_obj = fallback
    return emit_json_and_sanitize_stdio(out_obj)


if __name__ == "__main__":
    raise SystemExit(main())
