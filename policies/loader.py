"""TOCTOU-free whole-pack verification and in-memory verified-bytes module loader."""

from __future__ import annotations

import hashlib
import hmac
import importlib.abc
import importlib.machinery
import importlib.util
import os
import re
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping

from policies.api import POLICY_API_VERSION, PolicyPackManifest

SAFE_PACK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
PACK_MODULE_PREFIX = "_cg_pack_"
_PACK_CACHE: dict[tuple[str, str, str], PolicyPackManifest] = {}


class PolicyPackLoadError(RuntimeError):
    """Raised when a configured policy pack fails integrity, trust, or API validation."""


def normalize_pack_ns(pack_id: str) -> str:
    """Return unique Python module package name for a validated pack_id."""
    if not isinstance(pack_id, str) or not SAFE_PACK_ID_RE.fullmatch(pack_id):
        raise PolicyPackLoadError(f"invalid pack_id: {pack_id!r}")
    return f"{PACK_MODULE_PREFIX}{re.sub(r'[^a-z0-9_]', '_', pack_id)}"


def _is_reparse_point(st: Any) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _path_is_under(candidate: str, root: str) -> bool:
    c_norm, r_norm = os.path.normcase(os.path.abspath(candidate)), os.path.normcase(os.path.abspath(root))
    return c_norm == r_norm or c_norm.startswith(r_norm if r_norm.endswith(os.sep) else r_norm + os.sep)


def _check_stat_security(st: Any, name: str, *, want_dir: bool, expected_uid: int | None) -> None:
    if stat.S_ISLNK(st.st_mode) or _is_reparse_point(st):
        raise PolicyPackLoadError(f"symlink/reparse rejected in pack tree: {name}")
    if (want_dir and not stat.S_ISDIR(st.st_mode)) or (not want_dir and not stat.S_ISREG(st.st_mode)):
        raise PolicyPackLoadError(f"unexpected file type in pack tree: {name}")
    if os.name != "nt":
        if (st.st_mode & 0o022) != 0:
            raise PolicyPackLoadError(f"group/world-writable path rejected: {name}")
        if expected_uid is not None and st.st_uid not in (expected_uid, 0):
            raise PolicyPackLoadError(f"untrusted owner uid on {name}")


def _assert_safe_dir(dir_path: Path, *, expected_uid: int | None) -> None:
    try:
        st = os.lstat(str(dir_path))
    except OSError as exc:
        raise PolicyPackLoadError(f"unreadable pack directory {dir_path.name}") from exc
    _check_stat_security(st, dir_path.name, want_dir=True, expected_uid=expected_uid)


def _open_verified_regular_bytes(path: Path, *, expected_uid: int | None) -> bytes:
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise PolicyPackLoadError(f"cannot open {path.name}: {type(exc).__name__}") from exc
    try:
        _check_stat_security(os.fstat(fd), path.name, want_dir=False, expected_uid=expected_uid)
        chunks: list[bytes] = []
        while (chunk := os.read(fd, 65536)):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _check_safe_tree_root(pack_root: Path, *, trusted_roots: tuple[Path, ...], cwd: str | None, expected_uid: int | None) -> Path:
    expanded = pack_root.expanduser()
    for target in (expanded, expanded.parent):
        try:
            st = os.lstat(str(target))
        except OSError as exc:
            raise PolicyPackLoadError(f"cannot stat pack path: {target.name}") from exc
        if _is_reparse_point(st):
            raise PolicyPackLoadError(f"reparse point rejected: {target.name}")
        if stat.S_ISLNK(st.st_mode) and not any(_path_is_under(os.path.realpath(str(target)), str(r)) for r in trusted_roots):
            raise PolicyPackLoadError(f"symlink outside trusted root: {target.name}")
    real_root_str = os.path.realpath(str(expanded))
    if cwd and _path_is_under(real_root_str, os.path.realpath(cwd)):
        raise PolicyPackLoadError("pack_root inside active workspace cwd is rejected")
    matched = [r for r in trusted_roots if _path_is_under(real_root_str, str(r))]
    if not matched:
        raise PolicyPackLoadError("pack_root is outside trusted policy roots")
    real_root, base_root = Path(real_root_str), max(matched, key=lambda r: len(str(r)))
    inner_parents = [p for p in reversed(real_root.parents) if p != base_root and _path_is_under(str(p), str(base_root))]
    for seg in (base_root, *inner_parents, real_root):
        _assert_safe_dir(seg, expected_uid=expected_uid)
    return real_root


def verify_pack_tree_bytes(
    pack_root: Path, entry: Mapping[str, Any], *, trusted_roots: tuple[Path, ...], cwd: str | None = None
) -> dict[str, bytes]:
    """Verify pack tree security, file_hashes & tree_sha256; return verified in-memory source bytes."""
    raw_hashes, tree_sha = entry.get("file_hashes"), entry.get("tree_sha256")
    if not isinstance(raw_hashes, Mapping) or not raw_hashes:
        raise PolicyPackLoadError("missing or empty file_hashes")
    if not isinstance(tree_sha, str) or not _SHA256_HEX_RE.fullmatch(tree_sha):
        raise PolicyPackLoadError("missing or invalid tree_sha256")
    pinned: dict[str, str] = {}
    for raw_k, raw_v in raw_hashes.items():
        if not isinstance(raw_k, str) or not isinstance(raw_v, str) or not _SHA256_HEX_RE.fullmatch(raw_v):
            raise PolicyPackLoadError("malformed file_hashes entry")
        if raw_k.startswith("/") or "\\" in raw_k or ".." in raw_k.split("/") or not raw_k.endswith(".py"):
            raise PolicyPackLoadError(f"unsafe file_hashes key: {raw_k!r}")
        pinned[raw_k] = raw_v
    if "pack.py" not in pinned:
        raise PolicyPackLoadError("file_hashes must pin pack.py")

    expected_uid = getattr(os, "geteuid", lambda: None)()
    real_root = _check_safe_tree_root(pack_root, trusted_roots=trusted_roots, cwd=cwd, expected_uid=expected_uid)
    verified_bytes: dict[str, bytes] = {}
    actual_hashes: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(str(real_root), followlinks=False):
        dpath = Path(dirpath)
        _assert_safe_dir(dpath, expected_uid=expected_uid)
        for dname in dirnames:
            try:
                lst = os.lstat(str(dpath / dname))
            except OSError as exc:
                raise PolicyPackLoadError(f"cannot stat subdir {dname}") from exc
            if stat.S_ISLNK(lst.st_mode) or _is_reparse_point(lst) or dname == "__pycache__":
                raise PolicyPackLoadError(f"disallowed directory in pack tree: {dname}")
        for fname in filenames:
            fpath = dpath / fname
            try:
                lst = os.lstat(str(fpath))
            except OSError as exc:
                raise PolicyPackLoadError(f"cannot stat file {fname}") from exc
            if stat.S_ISLNK(lst.st_mode) or _is_reparse_point(lst):
                raise PolicyPackLoadError(f"symlink/reparse file rejected: {fname}")
            rel = fpath.relative_to(real_root).as_posix()
            if not fname.endswith(".py") or rel not in pinned:
                raise PolicyPackLoadError(f"unpinned or non-python file rejected in pack tree: {rel}")
            raw_bytes = _open_verified_regular_bytes(fpath, expected_uid=expected_uid)
            digest = hashlib.sha256(raw_bytes).hexdigest()
            if not hmac.compare_digest(digest, pinned[rel]):
                raise PolicyPackLoadError(f"SHA-256 mismatch for {rel}")
            verified_bytes[rel], actual_hashes[rel] = raw_bytes, digest
    if set(actual_hashes) != set(pinned):
        raise PolicyPackLoadError(f"missing pinned pack files: {sorted(set(pinned) - set(actual_hashes))}")
    computed_tree = hashlib.sha256("".join(f"{k}:{actual_hashes[k]}\n" for k in sorted(actual_hashes)).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(computed_tree, tree_sha):
        raise PolicyPackLoadError("tree_sha256 mismatch")
    return verified_bytes


class _VerifiedBytesLoader(importlib.abc.Loader):
    """Source-only importlib Loader executing exact pre-verified in-memory bytes with zero disk re-open."""

    def __init__(self, origin: str, source_bytes: bytes, package_name: str, is_pkg: bool) -> None:
        self.origin, self.source_bytes, self.package_name, self.is_pkg = origin, source_bytes, package_name, is_pkg

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        module.__file__, module.__package__ = self.origin, self.package_name
        module.__dict__["__cached__"] = None
        if self.is_pkg:
            module.__path__ = []
        exec(compile(self.source_bytes.decode("utf-8"), self.origin, "exec", dont_inherit=True), module.__dict__)


class _VerifiedPackFinder(importlib.abc.MetaPathFinder):
    """Scoped MetaPathFinder serving modules strictly from verified in-memory source bytes."""

    def __init__(self, root_pkg: str, pack_root: Path, verified_files: dict[str, bytes]) -> None:
        self.root_pkg, self.pack_root, self.verified_files = root_pkg, pack_root, verified_files

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> importlib.machinery.ModuleSpec | None:
        _ = (path, target)
        if fullname != self.root_pkg and not fullname.startswith(self.root_pkg + "."):
            return None
        parts = [] if fullname == self.root_pkg else fullname[len(self.root_pkg) + 1 :].split(".")
        pkg_rel = "/".join([*parts, "__init__.py"]) if parts else "__init__.py"
        if pkg_rel in self.verified_files:
            origin = str(self.pack_root / pkg_rel)
            return importlib.util.spec_from_loader(fullname, _VerifiedBytesLoader(origin, self.verified_files[pkg_rel], fullname, True), origin=origin, is_package=True)
        if fullname == self.root_pkg:
            return importlib.util.spec_from_loader(fullname, _VerifiedBytesLoader(str(self.pack_root), b"", self.root_pkg, True), origin=str(self.pack_root), is_package=True)
        mod_rel = "/".join(parts) + ".py"
        if mod_rel in self.verified_files:
            origin = str(self.pack_root / mod_rel)
            return importlib.util.spec_from_loader(fullname, _VerifiedBytesLoader(origin, self.verified_files[mod_rel], fullname.rsplit(".", 1)[0], False), origin=origin, is_package=False)
        return None


def compile_verified_manifest(pack_id: str, pack_root: Path, verified_bytes: dict[str, bytes], tree_sha: str) -> PolicyPackManifest:
    """Compile and cache PolicyPackManifest strictly from verified in-memory bytes."""
    ns = normalize_pack_ns(pack_id)
    cache_key = (pack_id, os.path.realpath(str(pack_root)), tree_sha)
    if cache_key in _PACK_CACHE:
        return _PACK_CACHE[cache_key]
    for mod_key in [k for k in sys.modules if k == ns or k.startswith(ns + ".")]:
        sys.modules.pop(mod_key, None)
    finder = _VerifiedPackFinder(ns, pack_root, verified_bytes)
    sys.meta_path.insert(0, finder)
    try:
        pack_mod = importlib.import_module(f"{ns}.pack")
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
    manifest = getattr(pack_mod, "PACK_MANIFEST", None)
    if not isinstance(manifest, PolicyPackManifest) or manifest.api_version != POLICY_API_VERSION or manifest.pack_id != pack_id or not callable(manifest.evaluate):
        raise PolicyPackLoadError(f"invalid manifest contract for {pack_id!r}")
    _PACK_CACHE[cache_key] = manifest
    return manifest


def get_cached_manifest(pack_id: str, pack_root: Path, tree_sha: str) -> PolicyPackManifest | None:
    """Return cached PolicyPackManifest if present for exact pack_id, realpath, and tree_sha."""
    return _PACK_CACHE.get((pack_id, os.path.realpath(str(pack_root)), tree_sha))


def clear_pack_cache() -> None:
    """Clear in-memory loaded policy pack cache (used by tests)."""
    _PACK_CACHE.clear()
