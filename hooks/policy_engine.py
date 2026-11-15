"""Stage-2 scoped fail-closed policy pack evaluation and lifecycle dispatch."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterator, Mapping

from hooks.config import resolve_user_config_path
from hooks.harness_adapter import NormalizedToolCall
from hooks.state_store import warn
from policies.api import (
    ALL_SECURITY_SCOPES,
    PolicyContext,
    PolicyDecision,
    PolicyPackManifest,
    PolicyPostContext,
)
from policies.loader import (
    PACK_MODULE_PREFIX,
    SAFE_PACK_ID_RE,
    PolicyPackLoadError,
    clear_pack_cache,
    compile_verified_manifest,
    get_cached_manifest,
    normalize_pack_ns,
    verify_pack_tree_bytes,
)

__all__ = [
    "PolicyPackLoadError",
    "SAFE_PACK_ID_RE",
    "apply_overwrite_to_call",
    "apply_policy_packs",
    "apply_policy_packs_with_records",
    "clear_pack_cache",
    "infer_tool_scopes",
    "load_verified_policy_pack",
    "normalize_pack_ns",
    "notify_session_transition",
    "run_post_tool_hooks",
    "run_pre_decision_hooks",
    "verify_policy_pack_tree",
    "verify_security_policies_post_transform",
]

_READ_ONLY_TOOLS = frozenset({"read_file", "view_file"})
_MUTATING_TOOLS = frozenset({
    "edit_file", "write_file", "edit", "multiedit", "multi_edit", "write", "notebookedit", "strreplace", "multistrreplace",
    "editfile", "writefile", "deletefile", "delete", "delete_file", "create_file", "replace_file_content",
    "multi_replace_file_content", "write_to_file", "apply_patch",
})
_SHELL_TOOLS = frozenset({"run_command", "bash", "shell", "exec", "exec_command", "shell_command", "run_terminal_cmd"})


def _trusted_pack_roots(config_path: Path | None = None, extra_roots: tuple[Path, ...] = ()) -> tuple[Path, ...]:
    candidates: list[Path] = [Path(r) for r in extra_roots]
    if config_path is not None:
        candidates.append(config_path.expanduser().parent / "policies")
    candidates.extend((resolve_user_config_path().parent / "policies", Path.home() / ".config" / "context-guard" / "policies"))
    for var in ("XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA"):
        if (val := str(os.environ.get(var) or "").strip()):
            candidates.append(Path(val).expanduser() / "context-guard" / "policies")
    out: list[Path] = []
    seen: set[str] = set()
    for root in candidates:
        res = os.path.realpath(str(root))
        if res not in seen:
            seen.add(res)
            out.append(Path(res))
    return tuple(out)


def verify_policy_pack_tree(
    pack_root: Path,
    entry: Mapping[str, Any],
    *,
    trusted_roots: tuple[Path, ...] = (),
    cwd: str | None = None,
    config_path: Path | None = None,
) -> dict[str, bytes]:
    """Verify pack tree security and hashes against trusted roots, returning verified source bytes."""
    eff_roots = _trusted_pack_roots(config_path=config_path, extra_roots=trusted_roots)
    return verify_pack_tree_bytes(pack_root, entry, trusted_roots=eff_roots, cwd=cwd)


def load_verified_policy_pack(
    entry: Mapping[str, Any], *, config_path: Path | None = None, cwd: str | None = None
) -> PolicyPackManifest:
    """Verify and compile a PolicyPackManifest strictly from verified in-memory bytes."""
    pack_id = str(entry.get("id") or "")
    normalize_pack_ns(pack_id)
    raw_path = entry.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip() or Path(raw_path).expanduser().name != "pack.py":
        raise PolicyPackLoadError(f"pack entrypoint must be pack.py for {pack_id!r}")
    pack_root = Path(raw_path).expanduser().parent
    tree_sha = str(entry.get("tree_sha256") or "")
    cached = get_cached_manifest(pack_id, pack_root, tree_sha)
    if cached is not None:
        return cached
    verified_bytes = verify_policy_pack_tree(pack_root, entry, config_path=config_path, cwd=cwd)
    return compile_verified_manifest(pack_id, pack_root, verified_bytes, tree_sha)


def infer_tool_scopes(norm: NormalizedToolCall) -> tuple[str, ...]:
    """Infer security policy scopes (`file_mutation`, `shell_command`, `mcp_call`) for a normalized tool call."""
    ctool, otool = norm.canonical_tool.lower(), norm.original_tool_name.lower()
    scopes: list[str] = []
    if ctool not in _READ_ONLY_TOOLS and (norm.mutated_paths or ctool in _MUTATING_TOOLS or otool in _MUTATING_TOOLS):
        scopes.append("file_mutation")
    if ctool in _SHELL_TOOLS or otool in _SHELL_TOOLS:
        scopes.append("shell_command")
    if ctool == "call_mcp_tool" or otool.startswith(("mcp_", "mcp:", "mcp__")) or ctool.startswith(("mcp_", "mcp:", "mcp__")):
        scopes.append("mcp_call")
    return tuple(scopes)


def _fallback_matches_entry(norm: NormalizedToolCall, scope: str, matchers: Any) -> bool:
    if not isinstance(matchers, Mapping):
        return True
    prefixes = matchers.get("protected_path_prefixes")
    if scope == "file_mutation":
        if not isinstance(prefixes, (list, tuple)):
            return True
        cands = [str(p).replace("\\", "/") for p in norm.mutated_paths if str(p).strip()]
        cands.extend(
            str(norm.canonical_args.get(k)).strip().replace("\\", "/")
            for k in ("Path", "AbsolutePath", "TargetFile", "file_path", "path")
            if isinstance(norm.canonical_args.get(k), str) and str(norm.canonical_args.get(k)).strip()
        )
        return any(isinstance(pref, str) and pref and pref.replace("\\", "/") in c for c in cands for pref in prefixes)
    if scope == "shell_command":
        cmds = matchers.get("shell_commands")
        if not isinstance(cmds, (list, tuple)) and not isinstance(prefixes, (list, tuple)):
            return True
        cmd = str(norm.canonical_args.get("CommandLine") or "")
        return (
            isinstance(cmds, (list, tuple)) and any(isinstance(c, str) and c and re.search(rf"\b{re.escape(c)}\b", cmd) for c in cmds)
        ) or (
            isinstance(prefixes, (list, tuple)) and any(isinstance(pref, str) and pref and pref in cmd for pref in prefixes)
        )
    if scope == "mcp_call":
        rx_raw = matchers.get("mcp_tool_regex")
        if not isinstance(rx_raw, str) or not rx_raw.strip():
            return True
        try:
            rx = re.compile(rx_raw)
        except re.error:
            return True
        srv = str(norm.canonical_args.get("ServerName") or "")
        return any(bool(rx.search(c)) for c in (norm.original_tool_name, norm.canonical_tool, f"mcp_{srv}") if c)
    return True


def _scoped_fail_closed(norm: NormalizedToolCall, entry: Mapping[str, Any] | None, reason: str) -> dict[str, Any] | None:
    tool_scopes = infer_tool_scopes(norm)
    if not tool_scopes:
        return None
    if entry is None:
        return {"decision": "deny", "reason": reason}
    raw_scopes = entry.get("scopes")
    if not isinstance(raw_scopes, (list, tuple)) or not raw_scopes:
        return {"decision": "deny", "reason": reason}
    declared = {s for s in raw_scopes if s in ALL_SECURITY_SCOPES}
    if not declared or len(declared) != len(raw_scopes):
        return {"decision": "deny", "reason": reason}
    matchers = entry.get("fallback_matchers")
    if any(sc in declared and _fallback_matches_entry(norm, sc, matchers) for sc in tool_scopes):
        return {"decision": "deny", "reason": reason}
    return None


def _pack_namespace_collisions(packs: list[Mapping[str, Any]]) -> set[str]:
    seen_ids: set[str] = set()
    seen_ns: set[str] = set()
    bad: set[str] = set()
    for p in packs:
        pid = str(p.get("id") or "")
        try:
            ns = normalize_pack_ns(pid)
        except PolicyPackLoadError:
            bad.add(pid)
            continue
        if pid in seen_ids or ns in seen_ns:
            bad.update((pid, ns))
        seen_ids.add(pid)
        seen_ns.add(ns)
    return bad


def _with_overwrite(norm: NormalizedToolCall, overwrite: Mapping[str, Any]) -> NormalizedToolCall:
    ow = dict(overwrite)
    new_orig, new_canon, mutated = {**norm.original_tool_input, **ow}, {**norm.canonical_args, **ow}, norm.mutated_paths
    if norm.canonical_tool == "run_command" and "CommandLine" not in ow and isinstance(ow.get("command") or ow.get("cmd"), str):
        new_canon["CommandLine"] = str(ow.get("command") or ow.get("cmd"))
    for k in ("Path", "AbsolutePath", "TargetFile", "file_path", "path"):
        v = ow.get(k)
        if isinstance(v, str) and v.strip():
            raw = v.strip()
            resolved = raw if (os.path.isabs(raw) or raw.startswith("/") or not norm.cwd) else str(Path(norm.cwd) / raw)
            new_canon.setdefault("Path", resolved)
            if norm.canonical_tool not in _READ_ONLY_TOOLS and norm.mutated_paths:
                mutated = (resolved,)
            break
    return NormalizedToolCall(
        harness=norm.harness, canonical_tool=norm.canonical_tool, canonical_args=new_canon,
        original_tool_name=norm.original_tool_name, original_tool_input=new_orig,
        session_id=norm.session_id, step_idx=norm.step_idx, cwd=norm.cwd,
        artifact_dir=norm.artifact_dir, mutated_paths=mutated, permission_mode=norm.permission_mode, call_id=norm.call_id,
    )


def apply_overwrite_to_call(norm: NormalizedToolCall, overwrite: Mapping[str, Any]) -> NormalizedToolCall:
    """Return a copy of `norm` merged with an optimizer or policy-pack `overwrite` payload."""
    return _with_overwrite(norm, overwrite)


def apply_policy_packs_with_records(
    norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
    state_dir_path: Path | None = None, session_state_snapshot: Mapping[str, Any] | None = None, security_only: bool = False,
) -> tuple[dict[str, Any] | None, list[tuple[PolicyPackManifest, PolicyContext, PolicyDecision | None]], NormalizedToolCall, dict[str, Any] | None]:
    """Evaluate active policy packs with Stage-2 scoped fail-closed fallback and pure evaluate() records."""
    tool_scopes, cfg_err = infer_tool_scopes(norm), runtime_cfg.get("config_error")
    if isinstance(cfg_err, str) and cfg_err:
        return ({"decision": "deny", "reason": f"CONTEXT-GUARD CONFIG ERROR (fail-closed): {cfg_err}"} if tool_scopes else None), [], norm, None
    packs = [p for p in (runtime_cfg.get("policy_packs") or []) if isinstance(p, Mapping) and p.get("enabled", True)]
    if tuple(runtime_cfg.get("legacy_security_keys") or ()) and not any(p.get("kind") == "security" for p in packs):
        return ({"decision": "deny", "reason": "CONTEXT-GUARD UNMIGRATED SECURITY CONFIG (fail-closed): Run install_pack.py --stage."} if tool_scopes else None), [], norm, None
    if runtime_cfg.get("repo_map_path") and not packs:
        warn("repo_map_path configured without a loaded policy pack; failing open")

    collisions = _pack_namespace_collisions(packs)
    cfg_path_raw = runtime_cfg.get("config_path")
    cfg_path = Path(str(cfg_path_raw)) if isinstance(cfg_path_raw, str) and cfg_path_raw else None
    eval_records: list[tuple[PolicyPackManifest, PolicyContext, PolicyDecision | None]] = []
    cur_norm = norm
    cur_overwrite: dict[str, Any] = {}
    for entry in packs:
        kind, pid = str(entry.get("kind") or "security"), str(entry.get("id") or "")
        if security_only and kind != "security":
            continue
        if pid in collisions or f"{PACK_MODULE_PREFIX}{re.sub(r'[^a-z0-9_]', '_', pid)}" in collisions:
            if kind == "security" and tool_scopes:
                return {"decision": "deny", "reason": f"CONTEXT-GUARD PACK COLLISION (fail-closed): {pid}"}, eval_records, cur_norm, (cur_overwrite or None)
            if kind != "security":
                warn(f"optimization policy pack collision skipped: {pid}")
            continue
        try:
            manifest = load_verified_policy_pack(entry, config_path=cfg_path, cwd=cur_norm.cwd)
        except PolicyPackLoadError as exc:
            if kind == "security":
                deny_dec = _scoped_fail_closed(cur_norm, entry, f"CONTEXT-GUARD SECURITY PACK ERROR (fail-closed): {exc}")
                if deny_dec is not None:
                    return deny_dec, eval_records, cur_norm, (cur_overwrite or None)
            else:
                warn(f"optimization pack {pid!r} skipped: {exc}")
            continue
        ctx = PolicyContext(
            harness=cur_norm.harness, call_id=getattr(cur_norm, "call_id", "") or "", canonical_tool=cur_norm.canonical_tool,
            canonical_args=dict(cur_norm.canonical_args), mutated_paths=cur_norm.mutated_paths,
            original_tool_name=cur_norm.original_tool_name, tool_input=dict(cur_norm.original_tool_input),
            cwd=cur_norm.cwd, session_id=cur_norm.session_id, step_idx=cur_norm.step_idx,
            state_dir=str(state_dir_path) if state_dir_path else None, settings=dict(entry.get("settings") or {}),
            permission_mode=cur_norm.permission_mode, session_state_snapshot=dict(session_state_snapshot or {}),
            raw_command=str(cur_norm.canonical_args.get("CommandLine") or "") or None,
        )
        try:
            dec = manifest.evaluate(ctx)
        except Exception as exc:
            if kind == "security":
                deny_dec = _scoped_fail_closed(cur_norm, entry, f"CONTEXT-GUARD POLICY EVALUATE ERROR (fail-closed): {type(exc).__name__}")
                if deny_dec is not None:
                    return deny_dec, eval_records, cur_norm, (cur_overwrite or None)
            else:
                warn(f"optimization pack {pid!r} crashed: {type(exc).__name__}")
            continue
        eval_records.append((manifest, ctx, dec))
        if dec is not None and dec.decision == "deny":
            return {"decision": "deny", "reason": dec.reason or f"Blocked by policy pack {pid}"}, eval_records, cur_norm, (cur_overwrite or None)
        if dec is not None and isinstance(dec.overwrite, Mapping) and dec.overwrite:
            if security_only and kind == "security":
                return {"decision": "deny", "reason": f"Disallowed overwrite proposed by security pack {pid} in Pass-2"}, eval_records, cur_norm, (cur_overwrite or None)
            cur_overwrite.update(dict(dec.overwrite))
            cur_norm = _with_overwrite(cur_norm, dec.overwrite)
    return None, eval_records, cur_norm, (cur_overwrite or None)


def apply_policy_packs(
    norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
    state_dir_path: Path | None = None, session_state_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Evaluate configured policy packs and return block decision or Pass-1 overwrite decision if any."""
    dec, _, _, overwrite = apply_policy_packs_with_records(
        norm, runtime_cfg, state_dir_path=state_dir_path, session_state_snapshot=session_state_snapshot, security_only=False
    )
    return dec if dec is not None else ({"decision": "allow", "overwrite": overwrite} if overwrite else None)


def verify_security_policies_post_transform(
    transformed_norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
    state_dir_path: Path | None = None, session_state_snapshot: Mapping[str, Any] | None = None, verify_only: bool = True,
) -> dict[str, Any] | None:
    """Re-verify transformed tool arguments against security packs without side effects."""
    _ = verify_only
    dec, _, _, _ = apply_policy_packs_with_records(
        transformed_norm, runtime_cfg, state_dir_path=state_dir_path, session_state_snapshot=session_state_snapshot, security_only=True
    )
    return dec


def run_pre_decision_hooks(
    eval_records: list[tuple[PolicyPackManifest, PolicyContext, PolicyDecision | None]],
) -> bool:
    """Invoke side-effect callbacks for evaluated packs outside locked_state().

    Returns False if any callback raised OSError (so callers can apply fail-open
    fallbacks for retryable hatches backed by disk state), True otherwise.
    """
    saved_ok = True
    for manifest, ctx, dec in eval_records:
        if manifest.on_pre_decision is not None:
            try:
                manifest.on_pre_decision(ctx, dec)
            except OSError as exc:
                saved_ok = False
                warn(f"on_pre_decision OSError ({type(exc).__name__}): {exc}")
            except Exception as exc:
                warn(f"on_pre_decision error ignored ({type(exc).__name__}): {exc}")
    return saved_ok


def _iter_enabled_manifests(runtime_cfg: Mapping[str, Any], *, cwd: str | None = None) -> Iterator[tuple[PolicyPackManifest, dict[str, Any]]]:
    cfg_path_raw = runtime_cfg.get("config_path")
    cfg_path = Path(str(cfg_path_raw)) if isinstance(cfg_path_raw, str) and cfg_path_raw else None
    for entry in runtime_cfg.get("policy_packs") or []:
        if not isinstance(entry, Mapping) or not entry.get("enabled", True):
            continue
        try:
            yield load_verified_policy_pack(entry, config_path=cfg_path, cwd=cwd), dict(entry.get("settings") or {})
        except PolicyPackLoadError:
            continue


def run_post_tool_hooks(post_ctx: PolicyPostContext, runtime_cfg: Mapping[str, Any]) -> None:
    """Invoke post-tool completion callbacks on verified packs."""
    for manifest, settings in _iter_enabled_manifests(runtime_cfg, cwd=post_ctx.cwd):
        if manifest.on_tool_completed is not None:
            try:
                manifest.on_tool_completed(PolicyPostContext(
                    harness=post_ctx.harness, call_id=post_ctx.call_id, canonical_tool=post_ctx.canonical_tool,
                    canonical_args=post_ctx.canonical_args, mutated_paths=post_ctx.mutated_paths,
                    original_tool_name=post_ctx.original_tool_name, tool_input=post_ctx.tool_input,
                    succeeded=post_ctx.succeeded, error=post_ctx.error, cwd=post_ctx.cwd,
                    state_dir=post_ctx.state_dir, settings=settings,
                ))
            except Exception as exc:
                warn(f"on_tool_completed error ignored ({type(exc).__name__}): {exc}")


def notify_session_transition(event: str, state: dict[str, Any], runtime_cfg: Mapping[str, Any]) -> None:
    """Notify active packs of rewind/compaction/session_end transitions."""
    for manifest, settings in _iter_enabled_manifests(runtime_cfg):
        if manifest.on_session_transition is not None:
            try:
                manifest.on_session_transition(event, state, settings)
            except Exception as exc:
                warn(f"on_session_transition error ignored ({type(exc).__name__}): {exc}")
