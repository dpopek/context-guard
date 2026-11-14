#!/usr/bin/env python3
"""Context-Guard PreToolUse hook engine: security/isolation guards, silent trims, and telemetry."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

_PLUGIN_ROOT = str(Path(__file__).resolve().parent.parent)
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from hooks.file_io import compute_file_sha256, count_file_lines_streaming  # noqa: E402
from hooks.governance_guard import STATIC_GOVERNANCE_INTERNAL_DENY_REASON, evaluate_governance_and_shell_guards, payload_may_require_fail_closed_guard, record_mutated_repos_in_state  # noqa: E402
from hooks.harness_adapter import NormalizedToolCall, can_rewrite_shell_command, detect_harness, format_pre_tool_output, normalize_line_bounds, normalize_pre_tool_payload  # noqa: E402
from hooks.local_repo_guard import extract_bigquery_sql_target, extract_gitlab_lookup_target, gate_bigquery_ai_views, gate_gitlab_local_first, is_bigquery_sql_tool_call, load_guard_config  # noqa: E402
from hooks.model_identity import detect_model, memoize_model  # noqa: E402
from hooks.outcomes import ledger_path_for, record_direct_outcome  # noqa: E402
from hooks.read_planner import FOLLOWUP_TARGETED_MAX_LINES, handle_file_read_verdict  # noqa: E402
from hooks.session_lifecycle import prune_state_on_rewind  # noqa: E402
from hooks.shell_parser import extract_outline_pull_targets, extract_shell_read_targets, is_bounded_shell_read, is_outline_pull, rewrite_quiet_cli_flags  # noqa: E402
from hooks.state_store import advance_session_step, emit_json_and_sanitize_stdio, locked_state, resolve_state_dir, run_telemetry_safely, state_file_in, warn  # noqa: E402
from hooks.telemetry import record_file_read_outcome, record_telemetry_count  # noqa: E402

STATIC_BQ_INTERNAL_DENY_REASON = "CONTEXT-GUARD BIGQUERY GUARD INTERNAL ERROR (fail-closed): Unable to verify BigQuery dataset isolation; query blocked."


def _static_harness_deny_output(harness: str, reason: str) -> dict[str, Any]:
    if harness == "antigravity":
        return {"decision": "deny", "reason": reason}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}


def _raw_payload_targets_bigquery(payload: dict[str, Any]) -> bool:
    """Inspect raw unnormalized payload to preserve fail-closed BigQuery isolation if normalization fails."""
    try:
        tc = payload.get("toolCall")
        if isinstance(tc, dict) and is_bigquery_sql_tool_call(str(tc.get("name") or ""), tc.get("args")):
            return True
        raw_tool = payload.get("tool_name")
        if isinstance(raw_tool, str) and is_bigquery_sql_tool_call(raw_tool, payload.get("tool_input")):
            return True
    except Exception:
        return True
    return False


def _memoize_session_model(state_dir_path: Path, norm: NormalizedToolCall, transcript_path: str | None, step_hint: int = 1) -> str:
    try:
        with locked_state(state_dir_path) as txn:
            prev = (txn.state.get("model"), txn.state.get("model_step"))
            raw_seq = txn.state.get("auto_step_seq")
            auto_seq = raw_seq if isinstance(raw_seq, int) and not isinstance(raw_seq, bool) else 0
            eff_step = step_hint if step_hint > 0 else max(1, auto_seq)
            if norm.harness != "antigravity" and step_hint <= 0 and auto_seq == 0:
                txn.state["auto_step_seq"] = eff_step
                txn.dirty = True
            model = memoize_model(norm.harness, norm.session_id, transcript_path, txn.state, eff_step, state_dir=state_dir_path)
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


def _handle_bigquery_mandatory_gate(payload: dict[str, Any], norm: NormalizedToolCall, state_dir: str | None) -> dict[str, Any]:
    """Mandatory fail-closed boundary for BigQuery SQL calls."""
    try:
        bq_target = extract_bigquery_sql_target(norm.canonical_tool, norm.canonical_args)
        if bq_target is None:
            dec: dict[str, Any] = {
                "decision": "deny",
                "reason": "CONTEXT-GUARD BIGQUERY MALFORMED CALL (fail-closed): Missing or invalid SQL query arguments for BigQuery execution tool.",
            }
        else:
            dec = gate_bigquery_ai_views(state_dir_path=resolve_state_dir(payload, state_dir), bq_tool=bq_target[0], sql_query=bq_target[1])
        try:
            output = format_pre_tool_output(dec, norm)
        except Exception as fmt_exc:
            fmt_err = fmt_exc
            run_telemetry_safely(lambda: warn(f"bigquery formatter error ({type(fmt_err).__name__}): {fmt_err}"), context="bq_guard_format")
            output = _static_harness_deny_output(norm.harness, STATIC_BQ_INTERNAL_DENY_REASON)
        if dec.get("decision") == "deny":
            stats_path = (Path(state_dir) / "telemetry_stats.json") if state_dir else None
            run_telemetry_safely(lambda: record_telemetry_count(norm.harness, "mcp_guards", stats_path), context="bq_mcp_guards")
        return output
    except Exception as exc:
        bq_err = exc
        run_telemetry_safely(lambda: warn(f"bigquery guard internal error ({type(bq_err).__name__}): {bq_err}"), context="bq_guard")
        try:
            return format_pre_tool_output({"decision": "deny", "reason": STATIC_BQ_INTERNAL_DENY_REASON}, norm)
        except Exception:
            return _static_harness_deny_output(norm.harness, STATIC_BQ_INTERNAL_DENY_REASON)


def handle_gitlab_mandatory_gate(payload: dict[str, Any], norm: NormalizedToolCall, state_dir: str | None) -> dict[str, Any]:
    """Phase B Local-First GitLab gate: fail-closed on config_error, fail-open with warn on runtime OSError."""
    config_error: str | None = None
    try:
        cfg = load_guard_config()
        raw_err = cfg.get("config_error")
        if isinstance(raw_err, str) and raw_err:
            config_error = raw_err
        gitlab_target = extract_gitlab_lookup_target(norm.canonical_tool, norm.canonical_args)
        if gitlab_target is None:
            return {"decision": "allow"} if norm.harness == "antigravity" else {}
        gitlab_tool, gitlab_args = gitlab_target
        state_dir_path = resolve_state_dir(payload, state_dir)
        stats_path = (Path(state_dir) / "telemetry_stats.json") if state_dir else None
        dec = gate_gitlab_local_first(state_dir_path=state_dir_path, gitlab_tool=gitlab_tool, tool_args=gitlab_args)
        if norm.harness != "antigravity" and norm.step_idx <= 0:
            advance_session_step(state_dir_path)
        output = format_pre_tool_output(dec, norm)
        if dec.get("decision") == "deny":
            run_telemetry_safely(lambda: record_telemetry_count(norm.harness, "mcp_guards", stats_path), context="gitlab_mcp_guards")
        return output
    except Exception as exc:
        gl_err = exc
        run_telemetry_safely(lambda: warn(f"gitlab guard internal error ({type(gl_err).__name__}): {gl_err}"), context="gitlab_guard")
        if config_error is not None:
            reason = f"CONTEXT-GUARD GITLAB CONFIG ERROR (fail-closed): {config_error}"
            try:
                return format_pre_tool_output({"decision": "deny", "reason": reason}, norm)
            except Exception:
                return _static_harness_deny_output(norm.harness, reason)
        return {"decision": "allow"} if norm.harness == "antigravity" else {}


def evaluate_hook(payload: dict[str, Any], state_dir: str | None = None, cli_harness: str | None = None) -> dict[str, Any]:
    """Evaluate PreToolUse hook payload across Antigravity, Claude Code, Cursor, and Codex."""
    try:
        norm = normalize_pre_tool_payload(payload, cli_harness=cli_harness)
    except Exception as exc:
        norm_err = exc
        run_telemetry_safely(lambda: warn(f"normalize fallback ({type(norm_err).__name__}): {norm_err}"), context="normalize_fallback")
        try:
            fallback_harness: str = detect_harness(payload, cli_harness=cli_harness)
        except Exception:
            fallback_harness = cli_harness if cli_harness in ("claude", "cursor", "codex", "antigravity") else ("antigravity" if ("toolCall" in payload or "conversationId" in payload) else "claude")
        if _raw_payload_targets_bigquery(payload):
            return _static_harness_deny_output(fallback_harness, STATIC_BQ_INTERNAL_DENY_REASON)
        return {"decision": "allow"} if fallback_harness == "antigravity" else {}

    if norm.harness == "antigravity" and not isinstance(payload.get("toolCall"), dict):
        return {"decision": "allow"}

    if is_bigquery_sql_tool_call(norm.canonical_tool, norm.canonical_args):
        return _handle_bigquery_mandatory_gate(payload, norm, state_dir)

    guard_cfg: dict[str, Any] = {}
    if payload_may_require_fail_closed_guard(norm) or norm.canonical_tool == "run_command":
        try:
            guard_cfg = load_guard_config()
            gov_dec = evaluate_governance_and_shell_guards(norm, guard_cfg)
            if gov_dec is not None:
                try:
                    return format_pre_tool_output(gov_dec, norm)
                except Exception:
                    return _static_harness_deny_output(norm.harness, str(gov_dec.get("reason") or STATIC_GOVERNANCE_INTERNAL_DENY_REASON))
        except Exception as exc:
            gov_err = exc
            run_telemetry_safely(lambda: warn(f"governance guard internal error ({type(gov_err).__name__}): {gov_err}"), context="governance_guard")
            if payload_may_require_fail_closed_guard(norm):
                return _static_harness_deny_output(norm.harness, STATIC_GOVERNANCE_INTERNAL_DENY_REASON)

    if extract_gitlab_lookup_target(norm.canonical_tool, norm.canonical_args) is not None:
        return handle_gitlab_mandatory_gate(payload, norm, state_dir)

    try:
        tool_name, args, step_idx = norm.canonical_tool, norm.canonical_args, norm.step_idx
        state_dir_path = resolve_state_dir(payload, state_dir)
        stats_path = (Path(state_dir) / "telemetry_stats.json") if state_dir else None
        outcomes_path = ledger_path_for(state_dir)
        transcript_raw = payload.get("transcript_path") or payload.get("transcriptPath")
        transcript_path = transcript_raw if isinstance(transcript_raw, str) else None

        if tool_name in ("edit_file", "write_file"):
            targets: tuple[str, ...] = tuple(norm.mutated_paths)
            if not targets:
                raw_path = args.get("Path") or args.get("TargetFile") or args.get("AbsolutePath")
                if isinstance(raw_path, str) and raw_path.strip():
                    targets = (raw_path.strip(),)
            if not targets:
                return format_pre_tool_output({"decision": "allow"}, norm)
            dec = _handle_file_mutation(state_dir_path, targets)
            if norm.harness != "antigravity" and step_idx <= 0:
                advance_session_step(state_dir_path)
            output = format_pre_tool_output(dec, norm)
            run_telemetry_safely(lambda: record_mutated_repos_in_state(state_dir_path, norm, guard_cfg.get("workspace_root")), context="record_mutated_repos")
            return output

        if tool_name in ("read_file", "view_file"):
            raw_path = args.get("Path") or args.get("AbsolutePath")
            if not isinstance(raw_path, str) or not raw_path.strip():
                return format_pre_tool_output({"decision": "allow"}, norm)
            path_arg_key = "AbsolutePath" if "AbsolutePath" in args and "Path" not in args else "Path"
            start_line, end_line, is_inverted_end = normalize_line_bounds(
                args.get("StartLine"), args.get("EndLine"), has_start_key="StartLine" in args, has_end_key="EndLine" in args
            )
            if is_inverted_end:
                return format_pre_tool_output({"decision": "allow"}, norm)
            offset_raw = args.get("ByteOffset") or args.get("ContentOffset")
            byte_offset = int(offset_raw) if isinstance(offset_raw, int) and offset_raw > 0 else 0
            stripped_path = raw_path.strip()
            read_outcome = handle_file_read_verdict(
                state_dir_path=state_dir_path, raw_path=stripped_path, start_line=start_line, end_line=end_line,
                byte_offset=byte_offset, step_idx=step_idx, allow_auto_outline=True, path_arg_key=path_arg_key,
                auto_increment_step=(norm.harness != "antigravity" and step_idx <= 0), harness=norm.harness, read_tool=tool_name,
            )
            dec, kind = read_outcome.decision, read_outcome.intervention
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
                return format_pre_tool_output({"decision": "allow"}, norm)
            auto_step = advance_session_step(state_dir_path) if (norm.harness != "antigravity" and step_idx <= 0) else 0
            raw_cwd = args.get("Cwd")
            cmd_cwd = norm.cwd or (raw_cwd.strip() if isinstance(raw_cwd, str) and raw_cwd.strip() else None)
            if is_outline_pull(cmd_line):
                pull_targets = [(t, sha) for t in extract_outline_pull_targets(cmd_line, cmd_cwd) for sha in (compute_file_sha256(t),) if sha is not None]
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
                            bounded = norm.harness == "codex" and is_bounded_shell_read(cmd_line, total_lines=(known_lines or count_file_lines_streaming(target)), max_lines=FOLLOWUP_TARGETED_MAX_LINES)
                            out_name = "targeted_followup" if bounded else "shell_bypass"
                            counts[(p_kind, out_name)] = counts.get((p_kind, out_name), 0) + 1
                        for (p_kind, out_name), cnt in counts.items():
                            if cnt > 1:
                                record_direct_outcome(norm.harness, model, p_kind, out_name, outcomes_path, increment_total=False, count=cnt)
                            else:
                                record_direct_outcome(norm.harness, model, p_kind, out_name, outcomes_path, increment_total=False)
                run_telemetry_safely(_record_shell_followups, context="shell_bypass")
            run_telemetry_safely(lambda: record_mutated_repos_in_state(state_dir_path, norm, guard_cfg.get("workspace_root")), context="record_mutated_repos")
            if can_rewrite_shell_command(norm):
                rewritten = rewrite_quiet_cli_flags(cmd_line)
                if rewritten is not None and rewritten != cmd_line:
                    output = format_pre_tool_output({"decision": "allow", "overwrite": {"CommandLine": rewritten}}, norm)

                    def _record_rewrite() -> None:
                        record_telemetry_count(norm.harness, "cli_rewrites", stats_path)
                        model = _memoize_session_model(state_dir_path, norm, transcript_path, step_idx)
                        record_direct_outcome(norm.harness, model, "cli_rewrite", "applied", outcomes_path)

                    run_telemetry_safely(_record_rewrite, context="cli_rewrites")
                    return output
            return format_pre_tool_output({"decision": "allow"}, norm)

        return format_pre_tool_output({"decision": "allow"}, norm)
    except Exception as exc:
        opt_err = exc
        run_telemetry_safely(lambda: warn(f"optimizer fallback ({type(opt_err).__name__}): {opt_err}"), context="optimizer_fallback")
        return {} if norm.harness != "antigravity" else {"decision": "allow"}


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint reading PreToolUse JSON from stdin and printing decision JSON to stdout."""
    fallback: dict[str, Any] = {"decision": "allow"}
    out_obj: dict[str, Any] = fallback
    try:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--harness", default=None)
        cli_args, _ = parser.parse_known_args(argv)
        fallback = {} if cli_args.harness in ("claude", "cursor", "codex") else {"decision": "allow"}
        out_obj = fallback
        raw_input = sys.stdin.read()
        if raw_input and raw_input.strip():
            payload = json.loads(raw_input)
            if isinstance(payload, dict):
                out_obj = evaluate_hook(payload, cli_harness=cli_args.harness)
    except (Exception, SystemExit) as exc:
        main_err = exc
        run_telemetry_safely(lambda: warn(f"pre_tool_use main fallback ({type(main_err).__name__})"), context="main_fallback")
        out_obj = fallback
    return emit_json_and_sanitize_stdio(out_obj)


if __name__ == "__main__":
    raise SystemExit(main())
