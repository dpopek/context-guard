"""hooks/state_store.py is the leaf shared by pre_tool_use and outcomes."""
from __future__ import annotations

import ast
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

import hooks.pre_tool_use as ptu
from hooks import state_store

fcntl: Any
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    from hooks import file_io as fcntl


def test_state_store_imports_nothing_from_hooks() -> None:
    tree = ast.parse(Path(state_store.__file__).read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("hooks"):
            offenders.append(node.module or "")
        if isinstance(node, ast.Import):
            offenders.extend(a.name for a in node.names if a.name.startswith("hooks"))
    assert offenders == []


def test_pre_tool_use_uses_the_owner_objects() -> None:
    from hooks import read_planner

    assert ptu.locked_state is state_store.locked_state
    assert ptu.resolve_state_dir is state_store.resolve_state_dir
    assert read_planner.merge_intervals is state_store.merge_intervals
    assert ptu.warn is state_store.warn


def test_save_then_load_round_trip_creates_parent_dir(tmp_path: Path) -> None:
    nested_dir = tmp_path / "nested"
    state = {"files": {"/p/a.py": {"sha256": "x", "reads": [[1, 10, 1, 2]]}}, "auto_step_seq": 3, "read_ledger_schema": 2}
    with state_store.locked_state(nested_dir) as txn:
        txn.state.update(state)
        txn.dirty = True
    state_file = nested_dir / state_store.STATE_FILENAME
    with state_store.locked_state(nested_dir) as txn:
        assert txn.state == state
    assert json.loads(state_file.read_text(encoding="utf-8")) == state
    leftovers = [p for p in state_file.parent.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []


def test_load_state_defaults_when_missing_or_malformed(tmp_path: Path) -> None:
    with state_store.locked_state(tmp_path / "missing_dir") as txn:
        assert txn.state == {"files": {}, "read_ledger_schema": 2}
    bad_dir = tmp_path / "bad_dir"
    bad_dir.mkdir(parents=True, exist_ok=True)
    (bad_dir / state_store.STATE_FILENAME).write_text("[1, 2]", encoding="utf-8")
    with state_store.locked_state(bad_dir) as txn:
        assert txn.state == {"files": {}, "read_ledger_schema": 2}


def test_merge_intervals_merges_adjacent_and_keeps_open_end() -> None:
    merged = state_store.merge_intervals([[1, 10, 1, 2], [11, 20, 2, 2], [40, -1, 3, 2]])
    assert merged == [[1, 20, 2, 2], [40, -1, 3, 2]]


def _write_ledger(state_dir: Path, state: dict) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / state_store.STATE_FILENAME
    state_file.write_text(json.dumps(state), encoding="utf-8")
    return state_file


def _lock_is_free(state_dir: Path) -> bool:
    with open(state_dir / state_store.LOCK_FILENAME, "a+", encoding="utf-8") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return True


def test_locked_state_without_dirty_leaves_the_ledger_untouched(tmp_path: Path) -> None:
    state_file = _write_ledger(tmp_path, {"files": {}, "read_ledger_schema": 2, "x": 1})
    before = (state_file.read_bytes(), state_file.stat().st_mtime_ns)

    with state_store.locked_state(tmp_path) as txn:
        txn.state["x"] = 2

    assert (state_file.read_bytes(), state_file.stat().st_mtime_ns) == before


def test_locked_state_saves_on_exit_when_dirty(tmp_path: Path) -> None:
    _write_ledger(tmp_path, {"files": {}})

    with state_store.locked_state(tmp_path) as txn:
        txn.state["x"] = 2
        txn.dirty = True

    assert json.loads((tmp_path / state_store.STATE_FILENAME).read_text(encoding="utf-8"))["x"] == 2


def test_locked_state_saves_on_early_return(tmp_path: Path) -> None:
    def mark() -> str:
        with state_store.locked_state(tmp_path) as txn:
            txn.state["x"] = 3
            txn.dirty = True
            return "returned"

    assert mark() == "returned"
    assert json.loads((tmp_path / state_store.STATE_FILENAME).read_text(encoding="utf-8"))["x"] == 3


def test_locked_state_discards_changes_and_unlocks_on_exception(tmp_path: Path) -> None:
    state_file = _write_ledger(tmp_path, {"files": {}, "x": 1})

    with pytest.raises(RuntimeError):
        with state_store.locked_state(tmp_path) as txn:
            txn.state["x"] = 2
            txn.dirty = True
            raise RuntimeError("boom")

    assert json.loads(state_file.read_text(encoding="utf-8"))["x"] == 1
    assert _lock_is_free(tmp_path)


def test_locked_state_create_false_raises_and_creates_nothing(tmp_path: Path) -> None:
    missing = tmp_path / "absent"

    with pytest.raises(OSError):
        with state_store.locked_state(missing, create=False):
            pass

    assert not missing.exists()


def test_locked_state_creates_dir_and_starts_from_empty_ledger(tmp_path: Path) -> None:
    fresh = tmp_path / "new" / "dir"

    with state_store.locked_state(fresh) as txn:
        assert txn.state == {"files": {}, "read_ledger_schema": 2}

    assert fresh.is_dir()
    assert not (fresh / state_store.STATE_FILENAME).exists()


def test_txn_save_writes_immediately_and_clears_dirty(tmp_path: Path) -> None:
    with state_store.locked_state(tmp_path) as txn:
        txn.state["x"] = 4
        txn.dirty = True
        assert txn.save() is True
        assert txn.dirty is False
        assert json.loads(txn.state_file.read_text(encoding="utf-8"))["x"] == 4


def test_resolve_state_dir_prefers_explicit_then_artifact_dir_then_sanitised_session() -> None:
    assert state_store.resolve_state_dir({"session_id": "s"}, "/explicit") == Path("/explicit")
    assert state_store.resolve_state_dir({"artifactDirectoryPath": "/art"}, None) == Path("/art")
    assert state_store.resolve_state_dir({"session_id": "a/b c"}, None) == (
        Path(tempfile.gettempdir()) / "context-guard-a_b_c"
    )
    assert state_store.resolve_state_dir({}, None) == Path(tempfile.gettempdir()) / "context-guard-default"


# Other ledgers keep their own single lock site; only the session ledger is owned here.
_OTHER_LEDGER_LOCKS = {
    ("file_io.py", "flock"),
    ("telemetry.py", "_update_ledger"),
    ("outcomes.py", "record_direct_outcome"),
}


# Reading or writing the ledger without `locked_state` would bypass the lock.
_UNLOCKED_HELPERS = {
    "_load_state_unlocked",
    "_open_or_quarantine_state_unlocked",
    "_save_state_atomic_unlocked",
}


def _session_ledger_access_outside_owner() -> list[str]:
    names = {state_store.STATE_FILENAME, state_store.LOCK_FILENAME}
    offenders: list[str] = []
    for path in sorted(Path(state_store.__file__).parent.glob("*.py")):
        if path.name == "state_store.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if (path.name, fn.name) in _OTHER_LEDGER_LOCKS:
                continue
            for node in ast.walk(fn):
                if isinstance(node, ast.Attribute) and node.attr == "flock":
                    offenders.append(f"{path.name}:{node.lineno} flock in {fn.name}")
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in names:
                offenders.append(f"{path.name}:{node.lineno} {node.value}")
            elif isinstance(node, ast.ImportFrom) and node.module == "fcntl":
                offenders.append(f"{path.name}:{node.lineno} from fcntl import")
            elif isinstance(node, ast.alias) and node.name in _UNLOCKED_HELPERS:
                offenders.append(f"{path.name} imports {node.name}")
            elif isinstance(node, ast.Attribute) and node.attr in _UNLOCKED_HELPERS:
                offenders.append(f"{path.name}:{node.lineno} {node.attr}")
    return offenders


def test_only_state_store_locks_or_names_the_session_ledger() -> None:
    assert _session_ledger_access_outside_owner() == []


def _ledger_with_malformed_entries() -> dict:
    return {
        "files": {
            "not_a_dict": "x",
            "reads_not_list": {"sha256": "a", "reads": "oops", "outlined": True, "outlined_step": 9},
            "good": {"sha256": "b", "reads": [[1, 10, 2, 2], [11, 20, 8, 2], [5, 6]]},
        }
    }


def test_filter_reads_deletes_malformed_entries_in_both_directions() -> None:
    past = _ledger_with_malformed_entries()
    assert state_store.filter_reads(past, lambda step: step < 5) is True
    assert past["files"] == {"good": {"sha256": "b", "reads": [[1, 10, 2, 2]]}}

    future = _ledger_with_malformed_entries()
    assert state_store.filter_reads(future, lambda step: step > 5) is True
    assert future["files"] == {"good": {"sha256": "b", "reads": [[11, 20, 8, 2]]}}


def test_filter_reads_keeps_outlined_entry_and_drops_empty_ones() -> None:
    state = {
        "files": {
            "outlined_only": {"reads": [[1, 5, 9, 2]], "outlined": True, "outlined_step": 3, "unwrapped_path": "/u"},
            "emptied": {"reads": [[1, 5, 9, 2]]},
        }
    }

    assert state_store.filter_reads(state, lambda step: step < 4) is True

    assert state["files"] == {
        "outlined_only": {"reads": [], "outlined": True, "outlined_step": 3, "unwrapped_path": "/u"}
    }


def test_filter_reads_outline_predicate_overrides_read_predicate() -> None:
    state = {"files": {"f": {"reads": [[1, 5, 1, 2]], "outlined": True, "outlined_step": 1, "unwrapped_path": "/u"}}}

    assert state_store.filter_reads(state, lambda step: True, lambda step: False) is True

    assert state["files"] == {"f": {"reads": [[1, 5, 1, 2]]}}


def test_filter_reads_reports_no_change() -> None:
    state = {
        "files": {
            "f": {"reads": [[1, 5, 1, 2]]},
            "outlined": {"reads": [], "outlined": True, "outlined_step": 2, "unwrapped_path": "/u"},
        }
    }

    assert state_store.filter_reads(state, lambda step: True) is False
    assert set(state["files"]) == {"f", "outlined"}
    assert state_store.filter_reads({"files": "bad"}, lambda step: True) is False


def test_no_hook_module_imports_bin() -> None:
    # bin/ holds entry points that import hooks; a hook importing bin closes a package cycle.
    hooks_dir = Path(__file__).resolve().parent.parent / "hooks"
    offenders = []
    for path in sorted(hooks_dir.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "bin":
                offenders.append(f"{path.name}:{node.lineno}")
            elif isinstance(node, ast.Import) and any(a.name.split(".")[0] == "bin" for a in node.names):
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


def test_resolve_state_dir_precedence_and_collision_free_subagents(tmp_path: Path) -> None:
    # Explicit state_dir overrides artifactDirectoryPath AND still isolates agent_id.
    triple = state_store.resolve_state_dir(
        {"artifactDirectoryPath": "/art", "session_id": "s", "agent_id": "sub_1"},
        str(tmp_path),
    )
    assert triple.parent == tmp_path / "subagents"
    assert triple.name.startswith("sub_1-")

    # artifactDirectoryPath without explicit state_dir returns directly without subagents/ suffix.
    assert (
        state_store.resolve_state_dir(
            {"artifactDirectoryPath": "/art", "session_id": "s", "agent_id": "sub_1"}, None
        )
        == Path("/art")
    )

    # Adversarial IDs never collide: parent "s--agent-a" vs ("s", "a"), and "a/b" vs "a_b".
    parent_tricky = state_store.resolve_state_dir({"session_id": "s--agent-a"}, None)
    sub_a = state_store.resolve_state_dir({"session_id": "s", "agent_id": "a"}, None)
    sub_slash = state_store.resolve_state_dir({"session_id": "s", "agent_id": "a/b"}, None)
    sub_under = state_store.resolve_state_dir({"session_id": "s", "agent_id": "a_b"}, None)
    assert len({parent_tricky, sub_a, sub_slash, sub_under}) == 4

    # Review Focus #1: whitespace-only or non-str agent_id stays on parent base dir.
    for blank in ("", "   ", None, 123):
        assert state_store.resolve_state_dir({"session_id": "s", "agent_id": blank}, str(tmp_path)) == tmp_path


def test_advance_session_step_requires_existing_dir_and_increments(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert state_store.advance_session_step(missing) == 0
    assert not missing.exists()

    state_dir = tmp_path / "existing"
    state_dir.mkdir()
    assert state_store.advance_session_step(state_dir) == 1
    assert state_store.advance_session_step(state_dir) == 2


def test_filter_reads_prunes_reads_and_outline_metadata() -> None:
    state = {
        "files": {
            "f": {
                "sha256": "h",
                "reads": [[1, 10, 2, 2], [11, 20, 8, 2]],
                "outlined": True,
                "outlined_step": 3,
                "outlined_total_lines": 900,
                "unwrapped_path": "/tmp/u.py",
            }
        }
    }
    assert state_store.filter_reads(state, lambda step: step > 5) is True
    assert state["files"]["f"] == {
        "sha256": "h",
        "reads": [[11, 20, 8, 2]],
    }


def _pre_worker(state_dir_str: str, files: list[str]) -> None:
    from hooks.pre_tool_use import evaluate_hook

    for idx, fpath in enumerate(files):
        evaluate_hook(
            {"session_id": "conc", "tool_name": "Read", "tool_input": {"file_path": fpath}},
            state_dir=state_dir_str,
            cli_harness="claude",
        )
        if idx < 5:
            evaluate_hook(
                {"session_id": "conc", "tool_name": "Bash", "tool_input": {"command": "echo hi"}},
                state_dir=state_dir_str,
                cli_harness="claude",
            )


def _post_worker(stats_str: str, count: int) -> None:
    from hooks.post_tool_use import handle_post_tool_use

    for i in range(count):
        handle_post_tool_use(
            "claude",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "pytest -q"},
                "tool_response": {"stdout": f"passed {i}\n", "stderr": ""},
            },
            stats_path=Path(stats_str),
        )


def test_concurrent_pre_and_post_tool_use_preserve_all_counters(tmp_path: Path) -> None:
    import multiprocessing
    from hooks.telemetry import load_telemetry_stats

    state_dir = tmp_path / "state"
    state_dir.mkdir()
    stats_path = state_dir / "telemetry_stats.json"
    w1_files: list[str] = []
    w2_files: list[str] = []
    for i in range(15):
        f1 = tmp_path / f"w1_{i}.txt"
        f2 = tmp_path / f"w2_{i}.txt"
        f1.write_text(f"hello {i}\n", encoding="utf-8")
        f2.write_text(f"world {i}\n", encoding="utf-8")
        w1_files.append(str(f1))
        w2_files.append(str(f2))

    ctx = multiprocessing.get_context("spawn")
    procs = [
        ctx.Process(target=_pre_worker, args=(str(state_dir), w1_files)),
        ctx.Process(target=_pre_worker, args=(str(state_dir), w2_files)),
        ctx.Process(target=_post_worker, args=(str(stats_path), 15)),
        ctx.Process(target=_post_worker, args=(str(stats_path), 15)),
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=20)
        assert p.exitcode == 0

    with state_store.locked_state(state_dir, create=False) as txn:
        assert txn.state["auto_step_seq"] == 40  # 2 * (15 Reads + 5 Bash calls)
    st = load_telemetry_stats(stats_path)
    assert st["events"]["allowed_reads"] == 30
    total_shell = sum(fam["count"] for fam in st["shell_output"]["harnesses"]["claude"].values())
    assert total_shell == 30


def test_filter_reads_ignores_malformed_step_elements() -> None:
    state = {
        "files": {
            "f": {
                "sha256": "h",
                "reads": [[1, 10, "bad_read", 2], [11, 20, True, 2], [21, 30, 8, 2]],
                "outlined": True,
                "outlined_step": "corrupt_step",
                "outlined_total_lines": 500,
            }
        }
    }
    assert state_store.filter_reads(state, lambda step: step > 5) is True
    assert state["files"]["f"] == {
        "sha256": "h",
        "reads": [[21, 30, 8, 2]],
    }


def test_windows_msvcrt_flock_adapter_locks_unlocks_and_raises_blocking_io(tmp_path: Path) -> None:
    from hooks import file_io

    calls: list[tuple[int, int, int]] = []
    fail_next = False

    class _FakeMsvcrt:
        LK_LOCK = 1
        LK_NBLCK = 2
        LK_UNLCK = 0

        @staticmethod
        def locking(fd: int, mode: int, nbytes: int) -> None:
            if fail_next:
                raise OSError("Windows lock contention")
            calls.append((fd, mode, nbytes))

    lock_file = tmp_path / "win.lock"
    with open(lock_file, "a+", encoding="utf-8") as fh:
        file_io.flock(fh.fileno(), file_io.LOCK_EX, posix_fcntl=None, win_msvcrt=_FakeMsvcrt)
        file_io.flock(fh, file_io.LOCK_UN, posix_fcntl=None, win_msvcrt=_FakeMsvcrt)
        assert len(calls) == 2
        assert calls[0][1:] == (_FakeMsvcrt.LK_LOCK, 1)
        assert calls[1][1:] == (_FakeMsvcrt.LK_UNLCK, 1)

        fail_next = True
        with pytest.raises(BlockingIOError):
            file_io.flock(
                fh.fileno(),
                file_io.LOCK_EX | file_io.LOCK_NB,
                posix_fcntl=None,
                win_msvcrt=_FakeMsvcrt,
            )


def test_read_ledger_schema_v2_cold_upgrade_purge_and_4tuple_downgrade_defense(tmp_path: Path) -> None:
    state_file = _write_ledger(
        tmp_path,
        {
            "auto_step_seq": 5,
            "files": {
                "/tmp/a.py": {
                    "sha256": "abc",
                    "reads": [[1, 20, 2]],
                    "pending_reads": {"call_1": {"step": 2}},
                    "completed_read_ids": {"call_0": {"tier": 2, "credited": False}},
                },
                "/tmp/out.py": {
                    "sha256": "def",
                    "reads": [[1, 10, 1]],
                    "outlined": True,
                    "outlined_step": 1,
                },
            },
        },
    )
    with state_store.locked_state(tmp_path) as txn:
        assert txn.state["read_ledger_schema"] == state_store.READ_LEDGER_SCHEMA == 2
        assert txn.state["auto_step_seq"] == 5
        assert txn.state["files"]["/tmp/a.py"]["reads"] == []
        assert "pending_reads" not in txn.state["files"]["/tmp/a.py"]
        assert "completed_read_ids" not in txn.state["files"]["/tmp/a.py"]
        assert txn.state["files"]["/tmp/out.py"]["outlined"] is True
        assert txn.state["files"]["/tmp/out.py"]["reads"] == []

    persisted = json.loads(state_file.read_text(encoding="utf-8"))
    assert persisted["read_ledger_schema"] == 2
    assert persisted["files"]["/tmp/a.py"]["reads"] == []

    # Reject 3-tuples, bool tiers, and out-of-range tiers in merge_intervals and filter_reads.
    assert state_store.merge_intervals([[1, 10, 1], [1, 10, 1, True], [1, 10, 1, 0], [1, 10, 1, 3]]) == []
    assert state_store.merge_intervals([[1, 10, 1, 2], [11, 20, 2, 1]]) == [[1, 10, 1, 2], [11, 20, 2, 1]]
    assert state_store.merge_intervals([[1, 10, 1, 2], [11, 20, 2, 2]]) == [[1, 20, 2, 2]]
    mixed: dict[str, Any] = {
        "read_ledger_schema": 2,
        "files": {
            "/tmp/b.py": {
                "sha256": "x",
                "reads": [[1, 10, 1], [1, 10, 1, False], [1, 10, 1, 9], [1, 10, 2, 2]],
                "pending_reads": {"keep": {"step": 2}, "drop": {"step": 9}},
            }
        },
    }
    assert state_store.filter_reads(mixed, lambda s: s < 5) is True
    assert mixed["files"]["/tmp/b.py"]["reads"] == [[1, 10, 2, 2]]
    assert mixed["files"]["/tmp/b.py"]["pending_reads"] == {"keep": {"step": 2}}




