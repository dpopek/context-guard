"""Tests for Context-Guard Layer 0 stdlib foundation (`core/`)."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORE_DIR = ROOT / "core"
FORBIDDEN_INTERNAL_DEPS = frozenset(
    {"hooks", "policies", "spool", "integrations", "services", "evidence", "bin"}
)
UNIX_ONLY_STDLIB = frozenset({"fcntl", "pwd", "grp", "termios", "resource", "pty"})


def test_core_package_ast_invariants() -> None:
    """Enforce Layer 0 zero-dependency, zero-assert, zero-facade, and Py3.9+ AST rules on core/."""
    assert CORE_DIR.is_dir(), "core/ package directory must exist"
    py_files = sorted(CORE_DIR.glob("*.py"))
    expected = {"__init__.py", "platform_io.py", "contracts.py", "scrub.py", "shell_lexer.py"}
    assert {p.name for p in py_files} == expected

    match_cls = getattr(ast, "Match", None)
    violations: list[str] = []
    for path in py_files:
        src = path.read_text(encoding="utf-8")
        lines = src.splitlines()
        if len(lines) > 800:
            violations.append(f"{path.name}: {len(lines)} LOC > 800")
        tree = ast.parse(src, filename=str(path))
        has_future = any(
            isinstance(stmt, ast.ImportFrom)
            and stmt.module == "__future__"
            and any(a.name == "annotations" for a in stmt.names)
            for stmt in tree.body
        )
        if not has_future:
            violations.append(f"{path.name}: missing 'from __future__ import annotations'")
        for stmt in tree.body:
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    if alias.name.split(".")[0] in UNIX_ONLY_STDLIB:
                        violations.append(f"{path.name}:{stmt.lineno} unguarded {alias.name}")
            elif isinstance(stmt, ast.ImportFrom):
                if (stmt.module or "").split(".")[0] in UNIX_ONLY_STDLIB:
                    violations.append(f"{path.name}:{stmt.lineno} unguarded {stmt.module}")
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                violations.append(f"{path.name}:{node.lineno} production assert forbidden")
            elif isinstance(node, ast.ExceptHandler) and node.type is None:
                violations.append(f"{path.name}:{node.lineno} bare except forbidden")
            elif match_cls is not None and isinstance(node, match_cls):
                violations.append(f"{path.name}:{node.lineno} match/case requires Py3.10+")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in FORBIDDEN_INTERNAL_DEPS:
                        violations.append(f"{path.name}:{node.lineno} forbidden import {alias.name}")
                    if alias.asname and alias.asname == alias.name:
                        violations.append(f"{path.name}:{node.lineno} identity alias {alias.name} as {alias.asname}")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = mod.split(".")[0]
                if top in FORBIDDEN_INTERNAL_DEPS:
                    violations.append(f"{path.name}:{node.lineno} forbidden import from {mod}")
                for alias in node.names:
                    if alias.asname and alias.asname == alias.name:
                        violations.append(f"{path.name}:{node.lineno} identity re-export {alias.name} as {alias.asname}")
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("isinstance", "issubclass")
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.BinOp)
                and isinstance(node.args[1].op, ast.BitOr)
            ):
                violations.append(f"{path.name}:{node.lineno} runtime union in {node.func.id}()")
    assert violations == [], f"core/ AST invariant violations: {violations}"


def test_platform_io_flock_posix_and_windows_msvcrt(tmp_path: Path) -> None:
    """Verify POSIX flock (including LOCK_SH) and Windows msvcrt.locking fallback behavior."""
    from core import platform_io

    assert platform_io.LOCK_SH != 0
    assert platform_io.LOCK_EX != 0
    assert platform_io.LOCK_NB != 0
    assert platform_io.LOCK_UN != 0
    assert len({platform_io.LOCK_SH, platform_io.LOCK_EX, platform_io.LOCK_NB, platform_io.LOCK_UN}) == 4

    lock_path = tmp_path / "shared.lock"
    lock_path.write_text("", encoding="utf-8")
    if os.name != "nt":
        with open(lock_path, "rb") as fh1, open(lock_path, "rb") as fh2:
            platform_io.flock(fh1.fileno(), platform_io.LOCK_SH)
            platform_io.flock(fh2.fileno(), platform_io.LOCK_SH | platform_io.LOCK_NB)
            with pytest.raises(BlockingIOError):
                platform_io.flock(fh2.fileno(), platform_io.LOCK_EX | platform_io.LOCK_NB)
            platform_io.flock(fh2.fileno(), platform_io.LOCK_UN)
            platform_io.flock(fh1.fileno(), platform_io.LOCK_UN)

    calls: list[tuple[int, int, int]] = []
    fail_mode: dict[str, bool] = {"active": False}

    class _FakeMsvcrt:
        LK_LOCK = 1
        LK_NBLCK = 2
        LK_UNLCK = 0

        @staticmethod
        def locking(fd: int, mode: int, nbytes: int) -> None:
            if fail_mode["active"]:
                raise OSError("lock contention")
            calls.append((fd, mode, nbytes))

    with open(lock_path, "a+", encoding="utf-8") as fh:
        platform_io.flock(fh, platform_io.LOCK_EX, posix_fcntl=None, win_msvcrt=_FakeMsvcrt)
        platform_io.flock(fh.fileno(), platform_io.LOCK_SH, posix_fcntl=None, win_msvcrt=_FakeMsvcrt)
        platform_io.flock(fh, platform_io.LOCK_UN, posix_fcntl=None, win_msvcrt=_FakeMsvcrt)
        assert [c[1:] for c in calls] == [(_FakeMsvcrt.LK_LOCK, 1), (_FakeMsvcrt.LK_LOCK, 1), (_FakeMsvcrt.LK_UNLCK, 1)]

        fail_mode["active"] = True
        with pytest.raises(BlockingIOError):
            platform_io.flock(
                fh.fileno(),
                platform_io.LOCK_SH | platform_io.LOCK_NB,
                posix_fcntl=None,
                win_msvcrt=_FakeMsvcrt,
            )
        with pytest.raises(OSError):
            platform_io.flock(fh.fileno(), platform_io.LOCK_EX, posix_fcntl=None, win_msvcrt=_FakeMsvcrt)
        # Missing backend is a safe no-op; invalid op raises OSError.
        platform_io.flock(fh.fileno(), platform_io.LOCK_EX, posix_fcntl=None, win_msvcrt=None)
        with pytest.raises(OSError):
            platform_io.flock(fh.fileno(), 0, posix_fcntl=None, win_msvcrt=_FakeMsvcrt)


def test_platform_io_links_atomic_writes_quarantine_and_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify unsafe-link checks, atomic byte/JSON writes, quarantine, warn, and plugin version resolution."""
    from core import platform_io

    regular = tmp_path / "regular.json"
    regular.write_text('{"a": 1}', encoding="utf-8")
    assert platform_io.check_unsafe_link(regular) is False
    assert platform_io.check_unsafe_link(tmp_path / "missing.json") is False

    real_lstat = os.lstat
    reparse_path = tmp_path / "reparse.json"
    reparse_path.write_text("{}", encoding="utf-8")

    def _fake_lstat(p: str | os.PathLike[str]) -> os.stat_result:
        res = real_lstat(p)
        if os.path.abspath(os.fspath(p)) == os.path.abspath(str(reparse_path)):
            mode = (res.st_mode & ~stat.S_IFMT(res.st_mode)) | stat.S_IFLNK
            return os.stat_result(
                (mode, res.st_ino, res.st_dev, res.st_nlink, res.st_uid, res.st_gid, res.st_size, 0, 0, 0)
            )
        return res

    with monkeypatch.context() as mp:
        mp.setattr(os, "lstat", _fake_lstat)
        assert platform_io.check_unsafe_link(reparse_path) is True

    byte_target = tmp_path / "sub" / "data.bin"
    platform_io.atomic_write_bytes(byte_target, b"hello\n")
    assert byte_target.read_bytes() == b"hello\n"
    if os.name != "nt":
        assert (byte_target.stat().st_mode & 0o777) == 0o600
    assert [p for p in byte_target.parent.iterdir() if p.suffix == ".tmp"] == []

    json_target = tmp_path / "ledger.json"
    platform_io.write_json_atomic(json_target, {"b": 2, "a": [1]}, prefix=".out.")
    assert json_target.read_text(encoding="utf-8") == '{\n  "b": 2,\n  "a": [\n    1\n  ]\n}\n'
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".out.")) == []

    assert platform_io.read_json_object_or_quarantine(tmp_path / "absent.json") is None
    corrupt_target = tmp_path / "corrupt.json"
    corrupt_target.write_text("[1, 2]", encoding="utf-8")
    assert platform_io.read_json_object_or_quarantine(corrupt_target) is None
    assert not corrupt_target.exists()
    assert len(list(tmp_path.glob("corrupt.json.corrupt-*"))) == 1
    assert "was not a JSON object" in capsys.readouterr().err

    corrupt_syntax = tmp_path / "bad_syntax.json"
    corrupt_syntax.write_text("{broken", encoding="utf-8")
    assert platform_io.read_json_object_or_quarantine(corrupt_syntax) is None
    assert len(list(tmp_path.glob("bad_syntax.json.corrupt-*"))) == 1
    capsys.readouterr()

    assert platform_io.read_json_object_or_quarantine(json_target) == {"b": 2, "a": [1]}

    # resolve_plugin_root & read_plugin_version
    custom_root = tmp_path / "plugin_root"
    custom_root.mkdir()
    (custom_root / "plugin.json").write_text(json.dumps({"version": "9.4.2"}), encoding="utf-8")
    assert platform_io.read_plugin_version(custom_root) == "9.4.2"
    assert platform_io.read_plugin_version(tmp_path / "empty_root", default="fallback") == "fallback"

    with monkeypatch.context() as mp:
        mp.setattr(os, "lstat", _fake_lstat)
        (tmp_path / "plugin.json").write_text(json.dumps({"version": "9.9.9"}), encoding="utf-8")
        # reparse.json is mocked unsafe; check symlinked manifest on custom dir when symlink works
        sym_dir = tmp_path / "sym_plugin"
        sym_dir.mkdir()
        try:
            (sym_dir / "plugin.json").symlink_to(custom_root / "plugin.json")
            assert platform_io.read_plugin_version(sym_dir, default="blocked") == "blocked"
        except OSError:
            pass

    monkeypatch.setenv("CONTEXT_GUARD_HOME", str(custom_root))
    assert platform_io.resolve_plugin_root() == custom_root.resolve()
    assert platform_io.read_plugin_version() == "9.4.2"


def test_platform_io_warn_timestamps_and_numeric_coercion(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify safe warn diagnostics, ISO timestamps, and strict bool/NaN/Inf numeric coercion."""
    from core import platform_io

    class _Exploding:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    closed = io.StringIO()
    closed.close()
    with monkeypatch.context() as mp:
        mp.setattr(sys, "stderr", closed)
        platform_io.warn(_Exploding())
        platform_io.warn("safe message")

    buf = io.StringIO()
    with monkeypatch.context() as mp:
        mp.setattr(sys, "stderr", buf)
        platform_io.warn("operator alert")
    assert buf.getvalue() == "context-guard: operator alert\n"

    ts_iso = platform_io.now_iso()
    ts_z = platform_io.utc_now_iso_z()
    assert ts_iso.endswith("+00:00") and "T" in ts_iso
    assert ts_z.endswith("Z") and len(ts_z) == 20

    assert platform_io.coerce_int(True, 7) == 7
    assert platform_io.coerce_int(False, 7) == 7
    assert platform_io.coerce_int(None, 7) == 7
    assert platform_io.coerce_int(42, 7) == 42
    assert platform_io.coerce_int("  -12 ", 7) == -12
    assert platform_io.coerce_int("3.8", 7) == 3
    assert platform_io.coerce_int(float("nan"), 7) == 7
    assert platform_io.coerce_int(float("inf"), 7) == 7
    assert platform_io.coerce_int("inf", 7) == 7
    assert platform_io.coerce_int("bad", 7) == 7

    assert platform_io.coerce_float(True, 1.5) == 1.5
    assert platform_io.coerce_float(None, 1.5) == 1.5
    assert platform_io.coerce_float("2.25", 1.5) == 2.25
    assert platform_io.coerce_float(float("nan"), 1.5) == 1.5
    assert platform_io.coerce_float(float("-inf"), 1.5) == 1.5
    assert platform_io.coerce_float("not-float", 1.5) == 1.5

    assert platform_io.safe_finite_int(15, -1) == 15
    assert platform_io.safe_finite_int(15.9, -1) == 15
    assert platform_io.safe_finite_int(True, -1) == -1
    assert platform_io.safe_finite_int("15", -1) == -1
    assert platform_io.safe_finite_int(float("nan"), -1) == -1
    assert platform_io.safe_finite_int(float("inf"), -1) == -1


def test_contracts_capabilities_value_objects_and_outline_materialization(tmp_path: Path) -> None:
    """Verify canonical harness caps, immutable dataclasses, PendingRead roundtrip, and unwrap materialization."""
    from core import contracts

    assert contracts.HARNESS_CAPABILITIES == {
        "antigravity": contracts.HarnessReadCaps(800, 46_080, 46_080),
        "claude": contracts.HarnessReadCaps(2_000, 80_000, 60_000),
        "cursor": contracts.HarnessReadCaps(2_000, 80_000, 80_000),
        "codex": contracts.HarnessReadCaps(2_000, 100_000, 100_000),
    }
    assert contracts.MAX_FORMAT_JSON_BYTES == 512 * 1024
    assert contracts.MAX_OUTLINE_FILE_BYTES == 2 * 1024 * 1024

    iv = contracts.ReadInterval.from_raw([1, 50, 3, 2])
    assert iv == contracts.ReadInterval(1, 50, 3, 2)
    assert iv is not None and iv.to_list() == [1, 50, 3, 2]
    assert contracts.ReadInterval.from_raw([True, 50, 3, 2]) is None
    assert contracts.ReadInterval.from_raw([1, 50, 3, 9]) is None
    assert contracts.ReadInterval.from_raw([1, 50, 3]) is None

    pending = contracts.PendingRead(
        raw_path="src/app.py",
        canonical_target="/repo/src/app.py",
        exec_start=11,
        exec_end=40,
        delivered_end=40,
        target_lines=100,
        step=5,
        sha256="abc123",
        expected_norm_sha256="def456",
        slice_bytes=900,
        byte_offset=0,
        redirect_path=None,
        is_trim=True,
        is_redirect=False,
        req_bytes=1500,
        trimmed_bytes=900,
        saved_bytes=600,
        synthetic_id=False,
        post_stage="pending",
        credited=False,
        model="claude-sonnet-4-6",
        ts=1700000000.5,
        trimmed_start=1,
        trimmed_end=10,
        trimmed_spans=((1, 10), (41, 60)),
    )
    as_dict = pending.to_dict()
    assert as_dict["trimmed_spans"] == [[1, 10], [41, 60]]
    assert contracts.PendingRead.from_dict(as_dict) == pending

    unwrapped_target = tmp_path / "nested" / "unwrapped.py"
    pw = contracts.PendingUnwrapWrite(target_path=unwrapped_target, content="x = 1\n")
    meta = contracts.PlannerMeta(
        sha256="abc123",
        step_idx=5,
        auto_increment_step=False,
        is_outline=False,
        pending_write=pw,
        target_lines=100,
        call_id="c-1",
        pending_read=pending,
        clear_followups=True,
        peer_paths=("/repo/other.py",),
        expected_reads_snapshot=((1, 10, 1, 2),),
    )
    assert meta.pending_read == pending
    assert meta.expected_reads_snapshot == ((1, 10, 1, 2),)

    planned_canon = os.path.realpath(str(unwrapped_target))
    prepared = contracts.PreparedOutline(
        total_lines=10,
        outline_text=f"# test.py (10 LOC, unwrapped at {planned_canon})\npreview",
        unwrapped_target=unwrapped_target,
        pending_write=pw,
    )
    actual = contracts.materialize_unwrap_write(pw)
    assert actual == planned_canon
    assert unwrapped_target.read_text(encoding="utf-8") == "x = 1\n"
    assert f"unwrapped at {actual}" in contracts.finalize_outline_text(prepared, actual)
    assert "unwrapped at" not in contracts.finalize_outline_text(prepared, None)
    assert contracts.materialize_unwrap_write(None) is None

    act = contracts.WindowAction(kind="resolve", outcome_dims=("targeted", "suspected", "observed"))
    win = contracts.OutcomeWindow(
        session_id="s|1",
        key="claude|sonnet|range_trim",
        target_path="/repo/a.py",
        kind="range_trim",
        step_idx=3,
        expires_step=11,
        meta={"trimmed_spans": [[1, 10], [41, 50]]},
    )
    shadow = contracts.ShadowEntry.from_dict(
        {"content_sha256": "s1", "updated_ts": "bad", "reads": [[1, 20, 1, 2], ["bad"]]}
    )
    spool_dec = contracts.SpoolDecision(
        harness="claude",
        updated_output="summary",
        shape="str",
        meta={"spool_id": "sp_0123456789ab"},
    )
    assert act.kind == "resolve" and win.target_path == "/repo/a.py"
    win_legacy = contracts.OutcomeWindow.from_dict(
        {"session_id": "s|1", "key": "claude|sonnet|range_trim", "step_idx": 3, "expires_step": 11},
        legacy_key="s|1|/repo/a.py|range_trim",
    )
    assert win_legacy is not None
    assert win_legacy.target_path == "/repo/a.py" and win_legacy.kind == "range_trim"
    assert shadow.updated_ts == 0.0 and len(shadow.reads) == 1
    assert spool_dec.shape == "str"


def test_scrub_redacts_paths_secrets_files_and_identifiers() -> None:
    """Verify home path scrubbing, PII string scrubbing, dict/list filtering, and ID hashing."""
    from core import scrub

    home_str = str(Path.home())
    hp_out = scrub.scrub_home_paths(f"python3 {home_str}/cg/hooks/pre.py /Users/alice/work/app.py")
    assert home_str not in hp_out
    assert "/Users/alice" not in hp_out
    assert "/cg/hooks/pre.py" in hp_out
    assert "/work/app.py" in hp_out

    assert "[redacted-path]" in scrub.scrub_home_paths(r"C:\Users\bob\cfg.json")
    assert "bob" not in scrub.scrub_home_paths(r"C:\Users\bob\cfg.json")
    assert "[redacted-path]" in scrub.scrub_home_paths(r"\Users\bob\cfg.json")
    assert "bob" not in scrub.scrub_home_paths(r"\Users\bob\cfg.json")
    assert "bob" not in scrub.scrub_string(r"\Users\bob\file.txt")

    gcp_sample = "corp-" + "data-987654:ds.tbl"
    local_mail = "alice@" + "corp-internal.local"
    dom_sample = "mycorp." + "atlassian.net"
    jdoe_path = "/" + "Users/jdoe_real/secret/notes.txt"
    noisy = f"err at {jdoe_path} file:///home/alice/x.py {local_mail} {dom_sample} {gcp_sample}"
    cleaned = scrub.scrub_string(noisy)
    for forbidden in ("jdoe_real", "secret/notes.txt", "x.py", local_mail, dom_sample, gcp_sample):
        assert forbidden not in cleaned
    assert "[redacted-path]" in cleaned
    assert "[redacted-email]" in cleaned
    assert "[redacted-domain]" in cleaned
    assert "[redacted-project]" in cleaned

    sample_obj: dict[str, Any] = {
        "config_path": "/Users/alice/config.json",
        "spool_id": "sp_0123456789ab",
        "workspace_id": "ws_0123456789abcdef",
        "notes": ["shadow.json", "ok item sp_0123456789ab", jdoe_path],
        "nested": ("a", Path("/Users/bob/file.txt")),
        "count": 3,
    }
    kept_files = scrub.scrub_value(sample_obj, drop_path_keys=True, drop_sensitive_files=False)
    assert "config_path" not in kept_files
    assert kept_files["spool_id"] == "sp_0123456789ab"
    assert kept_files["count"] == 3
    assert "jdoe_real" not in json.dumps(kept_files)
    assert "bob" not in json.dumps(kept_files)

    kept_paths = scrub.scrub_value(sample_obj, drop_path_keys=False, drop_sensitive_files=False)
    assert "config_path" in kept_paths
    assert "alice" not in kept_paths["config_path"]

    public_scrubbed = scrub.scrub_value(sample_obj, drop_path_keys=True, drop_sensitive_files=True)
    dumped = json.dumps(public_scrubbed)
    for banned in ("shadow.json", "sp_0123456789ab", "ws_0123456789abcdef", "spool_id", "workspace_id"):
        assert banned not in dumped

    assert scrub.hash_session_id("s1") == "sha256:" + hashlib.sha256(b"s1").hexdigest()[:16]
    assert scrub.scrub_workspace_id("ws_0123456789abcdef") == "ws_0123456789abcdef"
    assert scrub.scrub_workspace_id("/Users/alice/repo").startswith("ws_")
    assert scrub.scrub_workspace_id("  ") == ""
    assert scrub.scrub_source_hash("a1b2c3d4e5f6") == "a1b2c3d4e5f6"
    assert scrub.scrub_source_hash("raw-path").startswith("sha256:")
    assert scrub.scrub_source_hash("") == ""


def test_shell_lexer_preparation_segmentation_quoting_and_wrappers() -> None:
    """Verify canonical shell command preparation, segmentation, tokenization, and wrapper stripping."""
    from core import shell_lexer

    assert shell_lexer.normalize_cmd_basename(r"C:\Git\bin\GIT.EXE") == "git"
    assert shell_lexer.normalize_cmd_basename("/usr/local/bin/PYTEST.CMD") == "pytest"
    assert shell_lexer.normalize_cmd_basename("cg-outline.bat") == "cg-outline"

    assert shell_lexer.split_leading_cd_prefix("cd '/tmp/my repo'; git status") == (
        "cd '/tmp/my repo'; ",
        "git status",
    )
    assert shell_lexer.split_leading_cd_prefix("pytest -q") == ("", "pytest -q")

    prepared = shell_lexer.prepare_shell_lines("# comment\ncd repo\ngrep 'a|b' f.py && pytest")
    assert shell_lexer.split_unquoted_segments(prepared) == ["cd repo", "grep 'a|b' f.py", "pytest"]
    with pytest.raises(ValueError):
        shell_lexer.prepare_shell_lines('echo "unterminated')

    assert shell_lexer.split_shell_segments('git log "unterminated | x') == ['git log "unterminated', "x"]
    assert shell_lexer.split_shell_segments("echo ok && (rtk status)", include_subshells=True) == [
        "echo ok",
        "rtk status",
    ]

    assert shell_lexer.tokenize_shell_segment(r"C:\Python313\python.exe -m pytest -q") == [
        r"C:\Python313\python.exe",
        "-m",
        "pytest",
        "-q",
    ]
    assert shell_lexer.tokenize_shell_segment(r"cat pkg\a.py", os_name="nt") == ["cat", r"pkg\a.py"]
    assert shell_lexer.tokenize_shell_segment(r'cat "C:\Users\alice\a|b.py"') == [
        "cat",
        r"C:\Users\alice\a|b.py",
    ]
    assert shell_lexer.tokenize_shell_segment('cat "unterminated') is None
    assert shell_lexer.tokenize_shell_segment('cat "unterminated', fallback_split=True) == [
        "cat",
        '"unterminated',
    ]

    assert shell_lexer.strip_command_wrappers(["FOO=1", "env", "-i", "VAR=x", "/usr/bin/rtk", "status"]) == [
        "/usr/bin/rtk",
        "status",
    ]
    assert shell_lexer.strip_command_wrappers(["command", "-v", "rtk"]) == ["command", "-v", "rtk"]
    assert shell_lexer.strip_command_wrappers(
        ["taskpolicy", "-c", "utility", "-d", "utility", "nice", "-n", "15", "python3", "-m", "pytest"],
        wrappers=shell_lexer.SHELL_FAMILY_WRAPPERS,
    ) == ["python3", "-m", "pytest"]

    assert shell_lexer.first_segment_tokens("cd repo && bash -lc 'git log'") == ["bash", "-lc", "git log"]
