"""Scoped fail-closed policy pack evaluation and lifecycle dispatch."""
from __future__ import annotations

import dataclasses, os, re
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from core.platform_io import warn
from hooks.config import LEGACY_SECURITY_DOMAIN_MAP, resolve_user_config_path
from hooks.harness_adapter import NormalizedToolCall
from policies.api import ALL_SECURITY_SCOPES, PolicyContext, PolicyDecision, PolicyPackManifest, PolicyPostContext
from policies.loader import (
    SAFE_PACK_ID_RE, PolicyPackLoadError, clear_pack_cache, compile_verified_manifest,
    get_cached_manifest, normalize_pack_ns, verify_pack_tree_bytes,
)
from policies.repeat_deny import escalate_repeat_deny

__all__ = [
    "PolicyPackLoadError", "SAFE_PACK_ID_RE", "apply_overwrite_to_call", "apply_policy_packs",
    "apply_policy_packs_with_records", "clear_pack_cache", "infer_tool_scopes", "load_verified_policy_pack",
    "normalize_pack_ns", "notify_session_transition", "reconcile_post_transform", "run_post_tool_hooks",
    "run_pre_decision_hooks", "verify_policy_pack_tree", "verify_security_policies_post_transform", "warn",
]

_READ_ONLY_TOOLS = frozenset({"read_file", "view_file", "notebookread"})
_MUTATING_TOOLS = frozenset({
    "edit_file", "write_file", "edit", "multiedit", "multi_edit", "write", "notebookedit", "strreplace", "multistrreplace",
    "editfile", "writefile", "deletefile", "delete", "delete_file", "create_file", "replace_file_content",
    "multi_replace_file_content", "write_to_file", "apply_patch",
})
_SHELL_TOOLS = frozenset({"run_command", "bash", "shell", "exec", "exec_command", "shell_command", "run_terminal_cmd"})
_PATH_ARG_KEYS = ("Path", "AbsolutePath", "TargetFile", "file_path", "path", "notebook_path", "filePath")


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
    pack_root: Path, entry: Mapping[str, Any], *,
    trusted_roots: tuple[Path, ...] = (), cwd: str | None = None, config_path: Path | None = None,
) -> dict[str, bytes]:
    """Verify pack tree security and hashes against trusted roots, returning verified source bytes."""
    return verify_pack_tree_bytes(pack_root, entry, trusted_roots=_trusted_pack_roots(config_path=config_path, extra_roots=trusted_roots), cwd=cwd)


def load_verified_policy_pack(
    entry: Mapping[str, Any], *, config_path: Path | None = None, cwd: str | None = None,
) -> PolicyPackManifest:
    """Verify and compile a PolicyPackManifest strictly from verified in-memory bytes."""
    pack_id = str(entry.get("id") or "")
    normalize_pack_ns(pack_id)
    raw_path = entry.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip() or Path(raw_path).expanduser().name != "pack.py":
        raise PolicyPackLoadError(f"pack entrypoint must be pack.py for {pack_id!r}")
    pack_root, tree_sha = Path(raw_path).expanduser().parent, str(entry.get("tree_sha256") or "")
    if (cached := get_cached_manifest(pack_id, pack_root, tree_sha)) is not None:
        return cached
    return compile_verified_manifest(pack_id, pack_root, verify_policy_pack_tree(pack_root, entry, config_path=config_path, cwd=cwd), tree_sha)


def infer_tool_scopes(norm: NormalizedToolCall) -> tuple[str, ...]:
    """Infer security policy scopes (`file_mutation`, `shell_command`, `mcp_call`) for a normalized tool call."""
    ctool, otool = norm.canonical_tool.lower(), norm.original_tool_name.lower()
    scopes: list[str] = []
    if ctool not in _READ_ONLY_TOOLS and (norm.mutated_paths or ctool == "delete_file" or ctool in _MUTATING_TOOLS or otool in _MUTATING_TOOLS):
        scopes.append("file_mutation")
    if ctool in _SHELL_TOOLS or otool in _SHELL_TOOLS:
        scopes.append("shell_command")
    if ctool == "call_mcp_tool" or otool.startswith(("mcp_", "mcp:", "mcp__")) or ctool.startswith(("mcp_", "mcp:", "mcp__")):
        scopes.append("mcp_call")
    return tuple(scopes)


def _canonical_path(raw: str, cwd: str | None) -> str:
    joined = raw if (os.path.isabs(raw) or raw.startswith("/") or not cwd) else os.path.join(cwd, raw)
    return os.path.realpath(joined).replace("\\", "/")


def _prefix_variants(pref: str) -> tuple[str, ...]:
    norm = pref.replace("\\", "/")
    if os.path.isabs(pref) or pref.startswith("/"):
        real = os.path.realpath(pref).replace("\\", "/")
        if pref.endswith(("/", "\\")) and not real.endswith("/"):
            real += "/"
        return (real,) if real == norm else (norm, real)
    return (norm,)


def _fallback_matches_entry(norm: NormalizedToolCall, scope: str, matchers: Any) -> bool:
    if not isinstance(matchers, Mapping):
        return True
    prefixes = matchers.get("protected_path_prefixes")
    if scope == "file_mutation":
        if not isinstance(prefixes, (list, tuple)):
            return True
        raw_cands = [s for p in norm.mutated_paths if (s := str(p).strip())]
        raw_cands.extend(v.strip() for k in _PATH_ARG_KEYS if isinstance((v := norm.canonical_args.get(k)), str) and v.strip())
        cands = [_canonical_path(raw, norm.cwd) for raw in raw_cands]
        return any(pv in c for c in cands for pref in prefixes if isinstance(pref, str) and pref for pv in _prefix_variants(pref))
    if scope == "shell_command":
        cmds = matchers.get("shell_commands")
        if not isinstance(cmds, (list, tuple)) and not isinstance(prefixes, (list, tuple)):
            return True
        cmd = str(norm.canonical_args.get("CommandLine") or "")
        return (isinstance(cmds, (list, tuple)) and any(isinstance(c, str) and c and re.search(rf"\b{re.escape(c)}\b", cmd) for c in cmds)) or (
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
    return {"decision": "deny", "reason": reason} if any(sc in declared and _fallback_matches_entry(norm, sc, matchers) for sc in tool_scopes) else None


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


def _is_pack_collision(pid: str, collisions: set[str]) -> bool:
    if pid in collisions:
        return True
    try:
        return normalize_pack_ns(pid) in collisions
    except PolicyPackLoadError:
        return True


def _with_overwrite(norm: NormalizedToolCall, overwrite: Mapping[str, Any]) -> NormalizedToolCall:
    ow = dict(overwrite)
    new_orig, new_canon, mutated = {**norm.original_tool_input, **ow}, {**norm.canonical_args, **ow}, norm.mutated_paths
    if norm.canonical_tool == "run_command" and "CommandLine" not in ow and isinstance(ow.get("command") or ow.get("cmd"), str):
        new_canon["CommandLine"] = str(ow.get("command") or ow.get("cmd"))
    for k in _PATH_ARG_KEYS:
        if isinstance((v := ow.get(k)), str) and v.strip():
            raw = v.strip()
            resolved = raw if (os.path.isabs(raw) or raw.startswith("/") or not norm.cwd) else str(Path(norm.cwd) / raw)
            new_canon["Path"] = resolved
            if norm.canonical_tool.lower() not in _READ_ONLY_TOOLS and (norm.mutated_paths or norm.canonical_tool.lower() in _MUTATING_TOOLS):
                mutated = (resolved,)
            break
    return dataclasses.replace(norm, canonical_args=new_canon, original_tool_input=new_orig, mutated_paths=mutated)


def apply_overwrite_to_call(norm: NormalizedToolCall, overwrite: Mapping[str, Any]) -> NormalizedToolCall:
    """Return a copy of `norm` merged with an optimizer or policy-pack `overwrite` payload."""
    return _with_overwrite(norm, overwrite)


def _run_policy_pass(
    norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
    state_dir_path: Path | None = None, session_state_snapshot: Mapping[str, Any] | None = None, security_only: bool = False,
) -> tuple[dict[str, Any] | None, list[tuple[PolicyPackManifest, PolicyContext, PolicyDecision | None]], NormalizedToolCall, dict[str, Any] | None, bool]:
    """Evaluate active policy packs, returning `(decision, records, norm, overwrite, is_security_error)`."""
    tool_scopes, cfg_err = infer_tool_scopes(norm), runtime_cfg.get("config_error")
    if isinstance(cfg_err, str) and cfg_err:
        dec = {"decision": "deny", "reason": f"CONTEXT-GUARD CONFIG ERROR (fail-closed): {cfg_err}"} if tool_scopes else None
        return dec, [], norm, None, bool(dec)
    packs = [p for p in (runtime_cfg.get("policy_packs") or []) if isinstance(p, Mapping) and p.get("enabled", True)]
    legacy_keys = tuple(runtime_cfg.get("legacy_security_keys") or ())
    if legacy_keys and not any(p.get("kind") == "security" for p in packs):
        dec = {"decision": "deny", "reason": "CONTEXT-GUARD UNMIGRATED SECURITY CONFIG (fail-closed): Run install_pack.py --stage."} if tool_scopes else None
        return dec, [], norm, None, bool(dec)
    if runtime_cfg.get("repo_map_path") and not packs:
        warn("repo_map_path configured without a loaded policy pack; failing open")

    collisions = _pack_namespace_collisions(packs)
    cfg_path_raw = runtime_cfg.get("config_path")
    cfg_path = Path(str(cfg_path_raw)) if isinstance(cfg_path_raw, str) and cfg_path_raw else None
    eval_records: list[tuple[PolicyPackManifest, PolicyContext, PolicyDecision | None]] = []
    covered_security_domains: set[str] = set()
    cur_norm = norm
    cur_overwrite: dict[str, Any] = {}
    for entry in packs:
        kind, pid = str(entry.get("kind") or "security"), str(entry.get("id") or "")
        if security_only and kind != "security":
            continue
        if _is_pack_collision(pid, collisions):
            if kind == "security" and tool_scopes:
                return {"decision": "deny", "reason": f"CONTEXT-GUARD PACK COLLISION (fail-closed): {pid}"}, eval_records, cur_norm, (cur_overwrite or None), True
            if kind != "security":
                warn(f"optimization policy pack collision skipped: {pid}")
            continue
        try:
            manifest = load_verified_policy_pack(entry, config_path=cfg_path, cwd=cur_norm.cwd)
            if manifest.kind != kind:
                raise PolicyPackLoadError(f"manifest kind {manifest.kind!r} does not match entry kind {kind!r}")
        except PolicyPackLoadError as exc:
            if kind == "security":
                if (deny_dec := _scoped_fail_closed(cur_norm, entry, f"CONTEXT-GUARD SECURITY PACK ERROR (fail-closed): {exc}")) is not None:
                    return deny_dec, eval_records, cur_norm, (cur_overwrite or None), True
            else:
                warn(f"optimization pack {pid!r} skipped: {exc}")
            continue
        if kind == "security":
            covered_security_domains.update(str(d) for d in manifest.covered_domains)
        ctx = PolicyContext(
            harness=cur_norm.harness, call_id=cur_norm.call_id, canonical_tool=cur_norm.canonical_tool,
            canonical_args=dict(cur_norm.canonical_args), mutated_paths=cur_norm.mutated_paths,
            original_tool_name=cur_norm.original_tool_name, tool_input=dict(cur_norm.original_tool_input),
            cwd=cur_norm.cwd, session_id=cur_norm.session_id, step_idx=cur_norm.step_idx,
            state_dir=str(state_dir_path) if state_dir_path else None, settings=dict(entry.get("settings") or {}),
            permission_mode=cur_norm.permission_mode, session_state_snapshot=dict(session_state_snapshot or {}),
            raw_command=str(cur_norm.canonical_args.get("CommandLine") or "") or None,
        )
        try:
            p_dec = manifest.evaluate(ctx)
        except Exception as exc:
            if kind == "security":
                if (deny_dec := _scoped_fail_closed(cur_norm, entry, f"CONTEXT-GUARD POLICY EVALUATE ERROR (fail-closed): {type(exc).__name__}")) is not None:
                    return deny_dec, eval_records, cur_norm, (cur_overwrite or None), True
            else:
                warn(f"optimization pack {pid!r} crashed: {type(exc).__name__}")
            continue
        eval_records.append((manifest, ctx, p_dec))
        if p_dec is not None and p_dec.decision == "deny":
            reason = p_dec.reason or f"Blocked by policy pack {pid}"
            if not security_only:  # Pass-2 re-verification is side-effect free and may run twice per call
                reason = escalate_repeat_deny(reason, pid, cur_norm.call_id, state_dir_path)
            return {"decision": "deny", "reason": reason}, eval_records, cur_norm, (cur_overwrite or None), False
        if p_dec is not None and isinstance(p_dec.overwrite, Mapping) and p_dec.overwrite:
            if security_only and kind == "security":
                return {"decision": "deny", "reason": f"Disallowed overwrite proposed by security pack {pid} in Pass-2"}, eval_records, cur_norm, (cur_overwrite or None), False
            cur_overwrite.update(dict(p_dec.overwrite))
            cur_norm = _with_overwrite(cur_norm, p_dec.overwrite)
    if legacy_keys and tool_scopes:
        for lkey in legacy_keys:
            req = LEGACY_SECURITY_DOMAIN_MAP.get(str(lkey), frozenset())
            if not req or not (covered_security_domains & req):
                reason = f"CONTEXT-GUARD UNMIGRATED SECURITY CONFIG (fail-closed): Legacy key {lkey!r} lacks verified pack domain coverage ({sorted(req)}). Run install_pack.py --stage."
                return {"decision": "deny", "reason": reason}, eval_records, cur_norm, (cur_overwrite or None), True
    return None, eval_records, cur_norm, (cur_overwrite or None), False


def apply_policy_packs_with_records(
    norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
    state_dir_path: Path | None = None, session_state_snapshot: Mapping[str, Any] | None = None, security_only: bool = False,
) -> tuple[dict[str, Any] | None, list[tuple[PolicyPackManifest, PolicyContext, PolicyDecision | None]], NormalizedToolCall, dict[str, Any] | None]:
    """Evaluate active policy packs with scoped fail-closed fallback and pure evaluate() records."""
    dec, recs, out_norm, ow, _ = _run_policy_pass(norm, runtime_cfg, state_dir_path=state_dir_path,
                                                   session_state_snapshot=session_state_snapshot, security_only=security_only)
    return dec, recs, out_norm, ow


def apply_policy_packs(
    norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
    state_dir_path: Path | None = None, session_state_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Evaluate configured policy packs and return block decision or Pass-1 overwrite decision if any."""
    dec, _, _, overwrite = apply_policy_packs_with_records(norm, runtime_cfg, state_dir_path=state_dir_path, session_state_snapshot=session_state_snapshot)
    return dec if dec is not None else ({"decision": "allow", "overwrite": overwrite} if overwrite else None)


def _verify_security_with_status(
    transformed_norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
    state_dir_path: Path | None = None, session_state_snapshot: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, bool]:
    dec, _, _, _, sec_err = _run_policy_pass(transformed_norm, runtime_cfg, state_dir_path=state_dir_path,
                                             session_state_snapshot=session_state_snapshot, security_only=True)
    return dec, sec_err


def verify_security_policies_post_transform(
    transformed_norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
    state_dir_path: Path | None = None, session_state_snapshot: Mapping[str, Any] | None = None, verify_only: bool = True,
) -> dict[str, Any] | None:
    """Re-verify transformed tool arguments against security packs without side effects."""
    _ = verify_only
    dec, _ = _verify_security_with_status(transformed_norm, runtime_cfg, state_dir_path=state_dir_path, session_state_snapshot=session_state_snapshot)
    return dec


def reconcile_post_transform(
    candidate_norm: NormalizedToolCall, runtime_cfg: Mapping[str, Any], *,
    fallback_norm: NormalizedToolCall | None = None, state_dir_path: Path | None = None,
    session_state_snapshot: Mapping[str, Any] | None = None, verify_fn: Callable[..., Any] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """Run Pass-2 resolution: `'allow'` candidate, `'discard'` to safe fallback, or `'deny'`."""
    def _verify(target: NormalizedToolCall) -> tuple[dict[str, Any] | None, bool]:
        if verify_fn is not None and verify_fn is not verify_security_policies_post_transform:
            res = verify_fn(target, runtime_cfg, state_dir_path=state_dir_path, session_state_snapshot=session_state_snapshot)
            return (res[0], bool(res[1])) if isinstance(res, tuple) and len(res) == 2 else (res, False)
        return _verify_security_with_status(target, runtime_cfg, state_dir_path=state_dir_path, session_state_snapshot=session_state_snapshot)

    p2_dec, sec_err = _verify(candidate_norm)
    if p2_dec is None:
        return "allow", None
    if sec_err or fallback_norm is None:
        return "deny", p2_dec
    fb_dec, _ = _verify(fallback_norm)
    return ("deny", fb_dec) if fb_dec is not None else ("discard", None)


def run_pre_decision_hooks(eval_records: list[tuple[PolicyPackManifest, PolicyContext, PolicyDecision | None]]) -> bool:
    """Invoke side-effect callbacks for evaluated packs outside locked_state()."""
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
    packs = [p for p in (runtime_cfg.get("policy_packs") or []) if isinstance(p, Mapping) and p.get("enabled", True)]
    collisions = _pack_namespace_collisions(packs)
    cfg_path_raw = runtime_cfg.get("config_path")
    cfg_path = Path(str(cfg_path_raw)) if isinstance(cfg_path_raw, str) and cfg_path_raw else None
    for entry in packs:
        pid = str(entry.get("id") or "")
        if _is_pack_collision(pid, collisions):
            warn(f"policy pack namespace collision skipped: {pid}")
            continue
        try:
            manifest = load_verified_policy_pack(entry, config_path=cfg_path, cwd=cwd)
            if manifest.kind != (kind := str(entry.get("kind") or "security")):
                raise PolicyPackLoadError(f"manifest kind {manifest.kind!r} does not match entry kind {kind!r}")
            yield manifest, dict(entry.get("settings") or {})
        except PolicyPackLoadError as exc:
            warn(f"policy pack {pid!r} skipped: {exc}")


def run_post_tool_hooks(post_ctx: PolicyPostContext, runtime_cfg: Mapping[str, Any]) -> None:
    """Invoke post-tool completion callbacks on verified packs."""
    for manifest, settings in _iter_enabled_manifests(runtime_cfg, cwd=post_ctx.cwd):
        if manifest.on_tool_completed is not None:
            try:
                manifest.on_tool_completed(dataclasses.replace(post_ctx, settings=settings))
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
