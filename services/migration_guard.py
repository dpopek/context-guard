"""Staged policy pack transactions, rollback journal, and migration preflight checks."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Mapping

from core.platform_io import atomic_write_bytes, check_unsafe_link, warn
from hooks.config import (
    LEGACY_SECURITY_CONFIG_KEYS,
    LEGACY_SECURITY_DOMAIN_MAP,
    REQUIRED_CONFIG_KEYS,
    default_runtime_config,
    resolve_user_config_path,
)
from hooks.policy_engine import PolicyPackLoadError, verify_policy_pack_tree
from policies.api import ALL_SECURITY_SCOPES, POLICY_API_VERSION, VALID_POLICY_KINDS
from policies.loader import compile_verified_manifest, normalize_pack_ns

__all__ = ["RollbackJournal", "StagedPackTransaction", "preflight_migration_check", "resolve_effective_config_path"]

_GITLAB_DOMAINS = frozenset({"local_repo_guard", "gitlab", "gitlab_guard", "local_repo"})
_MIGRATABLE_KEYS = (
    "workspace_root",
    "repo_map_path",
    "repo_map_doc",
    "restricted_bq_datasets",
    "allowed_bq_views_dataset",
    "allowed_bq_views_hint",
    "bq_schema_doc",
    "allow_bq_raw_ddl_maintenance",
    "allow_governance_mutations",
    "enforce_governance_policy",
)


def resolve_effective_config_path(config_path: Path | None = None) -> Path:
    """Resolve explicit `config_path`, `CONTEXT_GUARD_CONFIG_PATH`, or `resolve_user_config_path()`."""
    if config_path is not None:
        return Path(config_path).expanduser()
    env_override = os.environ.get("CONTEXT_GUARD_CONFIG_PATH", "").strip()
    if env_override:
        return Path(env_override).expanduser()
    return resolve_user_config_path()


def _chmod_posix(path: str | Path, mode: int) -> None:
    if os.name != "nt":
        os.chmod(path, mode)


def _remove_path(target: Path) -> None:
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)


def _write_bytes_preserving_symlink(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    real_path = Path(os.path.realpath(str(path))) if path.is_symlink() else path
    atomic_write_bytes(real_path, data, mode=mode, prefix=".cg-mig-")


def _extract_manifest_hints(pack_py_text: str) -> tuple[str | None, str | None]:
    try:
        tree = ast.parse(pack_py_text)
    except SyntaxError:
        return None, None
    env = {
        s.targets[0].id: s.value.value
        for s in tree.body
        if isinstance(s, ast.Assign)
        and len(s.targets) == 1
        and isinstance(s.targets[0], ast.Name)
        and isinstance(s.value, ast.Constant)
        and isinstance(s.value.value, str)
    }

    def _lit(x: ast.AST) -> str | None:
        if isinstance(x, ast.Constant) and isinstance(x.value, str):
            return x.value
        return env.get(x.id) if isinstance(x, ast.Name) else None

    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            fn_name = n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
            if fn_name == "PolicyPackManifest":
                kw = {k.arg: _lit(k.value) for k in n.keywords}
                pid = kw.get("pack_id") or (_lit(n.args[0]) if n.args else env.get("PACK_ID"))
                kind = kw.get("kind") or (_lit(n.args[2]) if len(n.args) >= 3 else None)
                return pid, kind
    return env.get("PACK_ID"), None


def _revert_journal_op(kind: str, target: Path, payload: Any, mode: int) -> None:
    """Revert a single recorded rollback journal operation."""
    if kind == "file":
        if payload is None:
            try:
                target.unlink(missing_ok=True)
            except NotADirectoryError:
                return
            return
        _write_bytes_preserving_symlink(target, payload, mode=mode)
        return
    if kind in ("dir_swap", "dir_remove"):
        _remove_path(target)
        if payload is not None and (payload.exists() or payload.is_symlink()):
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(payload), str(target))


class RollbackJournal:
    """LIFO rollback journal for atomic file mutations, directory swaps, and staged removals."""

    def __init__(self) -> None:
        self._ops: list[tuple[str, Path, Any, int]] = []
        self._seen: set[str] = set()

    def __enter__(self) -> RollbackJournal:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None:
            self.rollback()

    def record_file_backup(self, target: Path) -> None:
        """Snapshot existing file bytes/mode or absence sentinel before mutating target."""
        path = Path(target).expanduser()
        key = os.path.normcase(os.path.abspath(str(path)))
        if key not in self._seen:
            self._seen.add(key)
            snap = (path.read_bytes(), os.stat(str(path)).st_mode & 0o777) if path.exists() else (None, 0o600)
            self._ops.append(("file", path, snap[0], snap[1]))

    def swap_directory(self, src_dir: Path, dst_dir: Path, *, backup_path: Path | None = None) -> None:
        """Move existing dst_dir to a temporary backup and move src_dir into dst_dir."""
        src, dst = Path(src_dir).expanduser(), Path(dst_dir).expanduser()
        backup: Path | None = None
        if dst.exists() or dst.is_symlink():
            backup = (
                Path(backup_path).expanduser()
                if backup_path is not None
                else (dst.parent / f".rollback-bak-{dst.name}-{os.getpid()}-{len(self._ops)}")
            )
            _remove_path(backup)
            shutil.move(str(dst), str(backup))
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
        except Exception:
            if backup is not None and (backup.exists() or backup.is_symlink()):
                shutil.move(str(backup), str(dst))
            raise
        self._ops.append(("dir_swap", dst, backup, 0))

    def stage_directory_removal(self, target_dir: Path, *, backup_path: Path | None = None) -> None:
        """Move existing target_dir to a temporary backup until commit or rollback."""
        dst = Path(target_dir).expanduser()
        if not dst.exists() and not dst.is_symlink():
            return
        backup = (
            Path(backup_path).expanduser()
            if backup_path is not None
            else (dst.parent / f".rollback-del-{dst.name}-{os.getpid()}-{len(self._ops)}")
        )
        backup.parent.mkdir(parents=True, exist_ok=True)
        _remove_path(backup)
        shutil.move(str(dst), str(backup))
        self._ops.append(("dir_remove", dst, backup, 0))

    def rollback(self) -> None:
        """Revert recorded file edits, directory swaps, and staged removals in strict LIFO order."""
        first_err: Exception | None = None
        for kind, target, payload, mode in reversed(self._ops):
            try:
                _revert_journal_op(kind, target, payload, mode)
            except Exception as exc:
                first_err = first_err or exc
        self._ops.clear()
        self._seen.clear()
        if first_err is not None:
            raise first_err

    def commit(self) -> None:
        """Clear the journal before best-effort backup cleanup so cleanup errors never trigger rollback."""
        ops = list(self._ops)
        self._ops.clear()
        self._seen.clear()
        for kind, _t, payload, _m in ops:
            if kind in ("dir_swap", "dir_remove") and payload is not None and (payload.exists() or payload.is_symlink()):
                try:
                    _remove_path(payload)
                except OSError as exc:
                    warn(f"rollback journal commit backup cleanup skipped ({payload}): {type(exc).__name__}: {exc}")


def preflight_migration_check(
    raw_cfg: Mapping[str, Any],
    config_path: Path | None = None,
    *,
    extra_trusted_roots: tuple[Path, ...] = (),
) -> tuple[list[str], list[str]]:
    """Pure preflight check returning `(errors, warnings)` with zero writes or stderr warnings."""
    if not isinstance(raw_cfg, Mapping):
        return ["config root must be a JSON object"], []
    eff_cfg = resolve_effective_config_path(config_path)
    raw_packs = raw_cfg.get("policy_packs", [])
    if not isinstance(raw_packs, list):
        return ["invalid 'policy_packs': expected list"], []
    errors: list[str] = []
    warnings: list[str] = []
    covered_domains: set[str] = set()
    seen_ns: set[str] = set()
    for entry in raw_packs:
        if not isinstance(entry, Mapping):
            errors.append("policy_packs entries must be JSON objects")
            continue
        if not entry.get("enabled", True):
            continue
        pid = str(entry.get("id") or "")
        try:
            ns = normalize_pack_ns(pid)
        except PolicyPackLoadError as exc:
            errors.append(str(exc))
            continue
        if ns in seen_ns:
            errors.append(f"duplicate policy pack id or namespace collision: {pid!r}")
            continue
        seen_ns.add(ns)
        kind = str(entry.get("kind") or "security")
        if kind not in VALID_POLICY_KINDS:
            errors.append(f"pack {pid!r} has invalid kind {kind!r}")
            continue
        scopes = entry.get("scopes")
        if kind == "security" and (
            not isinstance(scopes, (list, tuple))
            or not scopes
            or any(not isinstance(s, str) or s not in ALL_SECURITY_SCOPES for s in scopes)
        ):
            errors.append(f"security pack {pid!r} must declare valid non-empty scopes")
            continue
        raw_path = entry.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip() or Path(raw_path).expanduser().name != "pack.py":
            (errors if kind == "security" else warnings).append(f"pack {pid!r} entrypoint must point to pack.py")
            continue
        pack_root = Path(raw_path).expanduser().parent
        try:
            verified = verify_policy_pack_tree(pack_root, entry, trusted_roots=extra_trusted_roots, config_path=eff_cfg)
            manifest = compile_verified_manifest(pid, pack_root, verified, str(entry.get("tree_sha256") or ""))
        except (PolicyPackLoadError, SyntaxError, UnicodeDecodeError) as exc:
            (errors if kind == "security" else warnings).append(f"pack {pid!r} verification failed: {exc}")
            continue
        if manifest.api_version != POLICY_API_VERSION or manifest.kind != kind:
            errors.append(f"pack {pid!r} manifest mismatch (api={manifest.api_version}, kind={manifest.kind!r})")
            continue
        if manifest.inspect_config is not None:
            try:
                errors.extend(f"pack {pid!r} settings: {i}" for i in manifest.inspect_config(dict(entry.get("settings") or {})) if i)
            except Exception as exc:
                errors.append(f"pack {pid!r} inspect_config failed: {type(exc).__name__}")
                continue
        if kind == "security":
            covered_domains.update(str(d) for d in manifest.covered_domains)
    for key in LEGACY_SECURITY_CONFIG_KEYS:
        req = LEGACY_SECURITY_DOMAIN_MAP.get(key, frozenset())
        if raw_cfg.get(key) not in (None, False, "", []) and not (covered_domains & req):
            errors.append(f"unmigrated legacy security key {key!r} without verified pack covering {sorted(req)}")
    if not (covered_domains & _GITLAB_DOMAINS):
        rm_raw, ws_raw = raw_cfg.get("repo_map_path"), raw_cfg.get("workspace_root")
        if isinstance(rm_raw, str) and rm_raw.strip():
            warnings.append("repo_map_path configured without verified gitlab/local_repo_guard pack coverage")
        elif (
            isinstance(ws_raw, str)
            and ws_raw.strip()
            and "\x00" not in ws_raw
            and os.path.isfile(os.path.join(os.path.expanduser(ws_raw), "docs", "local_repository_map.json"))
        ):
            warnings.append("workspace_root has docs/local_repository_map.json without verified gitlab coverage")
    return errors, warnings


class StagedPackTransaction:
    """Two-phase staged pack installer with validation, atomic activation, and rollback."""

    def __init__(self, pack_source: Path, config_path: Path | None = None, journal: RollbackJournal | None = None) -> None:
        self.pack_source = Path(pack_source).expanduser()
        self.config_path = resolve_effective_config_path(config_path)
        self.journal = journal if journal is not None else RollbackJournal()
        self.policies_dir = self.config_path.parent / "policies"
        self._pack_id: str | None = None
        self._staging_dir: Path | None = None
        self._candidate_cfg: dict[str, Any] | None = None
        self._pack_entry: dict[str, Any] | None = None
        self._validated = False

    def _cleanup_staging(self) -> None:
        if self._staging_dir is not None and self._staging_dir.exists():
            shutil.rmtree(self._staging_dir, ignore_errors=True)
        self._staging_dir = None

    def prepare(self) -> dict[str, Any]:
        """Stage *.py files into `.staging-<pack_id>-<pid>` and build candidate config in memory."""
        src_root = self.pack_source if (self.pack_source / "pack.py").is_file() else self.pack_source / "private_policies"
        if not (src_root / "pack.py").is_file() or check_unsafe_link(src_root):
            raise PolicyPackLoadError(f"invalid pack source (missing pack.py or symlink/reparse): {self.pack_source}")
        hint_id, hint_kind = _extract_manifest_hints((src_root / "pack.py").read_text(encoding="utf-8"))
        pack_id = hint_id if hint_id is not None else src_root.name
        raw_cfg = json.loads(self.config_path.read_text(encoding="utf-8")) if self.config_path.is_file() else {}
        if not isinstance(raw_cfg, dict) or not isinstance(raw_cfg.get("policy_packs", []), list):
            raise ValueError(f"invalid config root or policy_packs in {self.config_path}")
        raw_packs: list[Any] = raw_cfg.get("policy_packs", [])
        staging_dir = self.policies_dir / f".staging-{re.sub(r'[^a-z0-9_-]', '_', pack_id.lower()) or 'pack'}-{os.getpid()}"
        _remove_path(staging_dir)
        for pdir in (self.policies_dir, staging_dir):
            pdir.mkdir(parents=True, exist_ok=True)
            _chmod_posix(pdir, 0o700)
        file_hashes: dict[str, str] = {}
        try:
            for dirpath, dirnames, filenames in os.walk(str(src_root), followlinks=False):
                cur = Path(dirpath)
                dirnames[:] = sorted(d for d in dirnames if d != "__pycache__" and not d.startswith("."))
                if any(check_unsafe_link(cur / d) for d in dirnames):
                    raise PolicyPackLoadError(f"symlink/reparse directory rejected in {cur}")
                for fname in sorted(f for f in filenames if f.endswith(".py")):
                    src_file = cur / fname
                    if check_unsafe_link(src_file):
                        raise PolicyPackLoadError(f"symlink/reparse file rejected: {fname}")
                    rel = src_file.relative_to(src_root).as_posix()
                    dst_file = staging_dir / rel
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    _chmod_posix(dst_file.parent, 0o700)
                    raw_bytes = src_file.read_bytes()
                    dst_file.write_bytes(raw_bytes)
                    _chmod_posix(dst_file, 0o600)
                    file_hashes[rel] = hashlib.sha256(raw_bytes).hexdigest()
            tree_sha = hashlib.sha256(
                "".join(f"{k}:{file_hashes[k]}\n" for k in sorted(file_hashes)).encode("utf-8")
            ).hexdigest()
            existing = next((p for p in raw_packs if isinstance(p, dict) and p.get("id") == pack_id), {})
            kind = hint_kind or str(existing.get("kind") or "security")
            settings = {**{k: raw_cfg[k] for k in _MIGRATABLE_KEYS if k in raw_cfg}, **dict(existing.get("settings") or {})}
            entry: dict[str, Any] = {
                "id": pack_id,
                "path": str(self.policies_dir / pack_id / "pack.py"),
                "enabled": existing.get("enabled", True),
                "kind": kind,
                "file_hashes": file_hashes,
                "tree_sha256": tree_sha,
                "settings": settings,
            }
            if kind == "security":
                entry["scopes"] = list(existing.get("scopes") or ALL_SECURITY_SCOPES)
                if isinstance(existing.get("fallback_matchers"), Mapping):
                    entry["fallback_matchers"] = dict(existing["fallback_matchers"])
            candidate: dict[str, Any] = {
                **{k: v for k, v in default_runtime_config().items() if k in REQUIRED_CONFIG_KEYS},
                **raw_cfg,
                "policy_packs": [*[dict(p) for p in raw_packs if isinstance(p, dict) and p.get("id") != pack_id], entry],
            }
        except Exception:
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise
        self._pack_id = pack_id
        self._staging_dir = staging_dir
        self._pack_entry = entry
        self._candidate_cfg = candidate
        self._validated = False
        return dict(candidate)

    def validate(self) -> None:
        """Validate staged pack tree and candidate configuration; clean staging on failure."""
        if self._staging_dir is None or self._pack_entry is None or self._candidate_cfg is None or self._pack_id is None:
            raise ValueError("StagedPackTransaction.prepare() must be called before validate()")
        staged_entry = {**self._pack_entry, "path": str(self._staging_dir / "pack.py")}
        staged_packs = [staged_entry if p.get("id") == self._pack_id else p for p in self._candidate_cfg["policy_packs"]]
        try:
            verify_policy_pack_tree(self._staging_dir, staged_entry, trusted_roots=(self.policies_dir,), config_path=self.config_path)
            errors, _ = preflight_migration_check(
                {**self._candidate_cfg, "policy_packs": staged_packs},
                self.config_path,
                extra_trusted_roots=(self.policies_dir,),
            )
            if errors:
                raise PolicyPackLoadError("; ".join(errors))
        except Exception:
            self._cleanup_staging()
            self._validated = False
            raise
        self._validated = True

    def activate(self) -> dict[str, Any]:
        """Atomically activate staged pack directory and write candidate config.json."""
        if self._staging_dir is None or self._candidate_cfg is None or self._pack_id is None:
            raise ValueError("StagedPackTransaction.prepare() must be called before activate()")
        if not self._validated:
            self.validate()
        live_dir = self.policies_dir / self._pack_id
        backup_dir = self.policies_dir / f".backup-{self._pack_id}-{os.getpid()}"
        self.journal.record_file_backup(self.config_path)
        try:
            self.journal.swap_directory(self._staging_dir, live_dir, backup_path=backup_dir)
            self._staging_dir = None
            _write_bytes_preserving_symlink(
                self.config_path, (json.dumps(self._candidate_cfg, indent=2) + "\n").encode("utf-8"), mode=0o600
            )
        except Exception:
            self.rollback()
            raise
        return dict(self._candidate_cfg)

    def rollback(self) -> None:
        """Revert journaled files/swaps and remove any remaining staging directory."""
        try:
            self.journal.rollback()
        finally:
            self._cleanup_staging()

    def commit(self) -> None:
        """Commit the linked RollbackJournal before cleaning up any remaining staging directory."""
        self.journal.commit()
        self._cleanup_staging()
