"""Owner of the per-session state ledger and its shared primitives.

This is the leaf module that both `hooks.pre_tool_use` and `hooks.outcomes` import.
It must never import anything from `hooks`, or the two would form an import cycle.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

fcntl: Any
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    _win_msvcrt: Any = None
    try:
        import msvcrt as _win_msvcrt
    except ImportError:
        pass

    class _WindowsFcntlCompat:
        LOCK_EX, LOCK_NB, LOCK_UN = 2, 4, 8

        @staticmethod
        def flock(fd: int | Any, operation: int) -> None:
            if _win_msvcrt is None:
                return
            raw_fd = fd.fileno() if hasattr(fd, "fileno") else int(fd)
            try:
                os.lseek(raw_fd, 0, os.SEEK_SET)
            except OSError:
                pass
            if operation & 8:
                try:
                    _win_msvcrt.locking(raw_fd, _win_msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
                return
            non_blocking = bool(operation & 4)
            mode = _win_msvcrt.LK_NBLCK if non_blocking else _win_msvcrt.LK_LOCK
            try:
                _win_msvcrt.locking(raw_fd, mode, 1)
            except OSError as exc:
                if non_blocking:
                    raise BlockingIOError(str(exc)) from exc
                raise

    fcntl = _WindowsFcntlCompat()


def warn(message: object) -> None:
    """Operator-facing diagnostic; never raises or leaves dirty C buffers on fd 2."""
    try:
        text = f"context-guard: {message}\n"
    except Exception:
        text = "context-guard: <unprintable diagnostic>\n"
    try:
        stream = sys.stderr
        if stream is None:
            return
        raw_stderr = sys.__stderr__
        if raw_stderr is not None and stream is raw_stderr:
            os.write(raw_stderr.fileno(), text.encode("utf-8", errors="replace"))
        else:
            stream.write(text)
            stream.flush()
    except Exception:
        pass


def run_telemetry_safely(op: Callable[[], object], context: str = "telemetry") -> None:
    """Execute a post-decision telemetry/observation side effect without ever raising Exception."""
    try:
        op()
    except Exception as exc:
        try:
            warn(f"{context} error ignored after decision ({type(exc).__name__}): {exc}")
        except Exception:
            try:
                warn(f"{context} error ignored after decision ({type(exc).__name__})")
            except Exception:
                pass


def sanitize_stderr_before_exit() -> None:
    """Ensure CPython Py_FinalizeEx will not exit with status 120 due to buffered writes on a broken stderr."""
    if sys.stderr is None:
        return
    try:
        sys.stderr.flush()
    except Exception:
        try:
            sys.stderr = io.StringIO()
        except Exception:
            pass


def emit_json_and_sanitize_stdio(payload: dict[str, Any]) -> int:
    """Emit a single JSON line to stdout once and neutralize broken stdout/stderr buffers before exit."""
    line = json.dumps(payload) + "\n"
    if sys.stdout is not None:
        try:
            sys.stdout.write(line)
            sys.stdout.flush()
        except Exception:
            try:
                sys.stdout = io.StringIO()
            except Exception:
                pass
    sanitize_stderr_before_exit()
    return 0


def _load_state_unlocked(state_file: Path) -> dict[str, Any]:
    if not state_file.is_file():
        return {"files": {}}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("files"), dict):
            return data
    except (OSError, ValueError, TypeError):
        pass
    return {"files": {}}


def _open_or_quarantine_state_unlocked(state_file: Path) -> dict[str, Any]:
    """Load session state under the lock; quarantine corrupt files and warn on failure."""
    if not state_file.is_file():
        return {"files": {}}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("files"), dict):
            return data
        detail = "missing or non-dict 'files' map"
    except (OSError, ValueError, TypeError) as exc:
        detail = f"{type(exc).__name__}: {exc}"
    quarantine_path = state_file.with_name(f"{state_file.name}.corrupt")
    try:
        os.replace(str(state_file), str(quarantine_path))
        warn(f"corrupt session state ({detail}) quarantined to {quarantine_path}")
    except OSError as q_exc:
        warn(f"corrupt session state ({detail}) reset in memory; quarantine failed: {q_exc}")
    return {"files": {}}


def _save_state_atomic_unlocked(state_file: Path, state: dict[str, Any]) -> bool:
    """Persist state via mkstemp + os.replace; False (plus a stderr note) when the ledger could not be written."""
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".context_guard_state.", suffix=".tmp", dir=str(state_file.parent))
    except OSError as exc:
        warn(f"state not saved ({state_file}): {exc}")
        return False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, separators=(",", ":"))
        os.replace(tmp_path, str(state_file))
        return True
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        warn(f"state not saved ({state_file}): {exc}")
        return False


STATE_FILENAME = ".context_guard_state.json"
LOCK_FILENAME = ".context_guard_state.lock"
MUTATED_REPOS_SCHEMA = 2


def resolve_plugin_root(default_root: Path | None = None) -> Path:
    """Canonical Context-Guard root: CONTEXT_GUARD_HOME env override, explicit default, or checkout root."""
    env_home = os.environ.get("CONTEXT_GUARD_HOME", "").strip()
    if env_home:
        return Path(env_home).expanduser().resolve()
    if default_root is not None:
        return Path(default_root).expanduser().resolve()
    return Path(__file__).resolve().parent.parent


def resolve_state_dir(payload: dict[str, Any], state_dir: str | None) -> Path:
    """Session ledger directory: explicit override, then the harness artifact dir, then a temp dir per session."""
    if state_dir:
        base = Path(state_dir)
    else:
        artifact_dir = payload.get("artifactDirectoryPath")
        if isinstance(artifact_dir, str) and artifact_dir.strip():
            return Path(artifact_dir.strip())
        conv_id = str(
            payload.get("conversationId")
            or payload.get("session_id")
            or payload.get("conversation_id")
            or "default"
        )
        safe_conv = re.sub(r"[^a-zA-Z0-9_.-]", "_", conv_id)
        base = Path(tempfile.gettempdir()) / f"context-guard-{safe_conv}"

    raw_agent = payload.get("agent_id")
    if isinstance(raw_agent, str) and raw_agent.strip():
        agent_clean = raw_agent.strip()
        safe_agent = re.sub(r"[^a-zA-Z0-9_.-]", "_", agent_clean)[:32] or "agent"
        agent_digest = hashlib.sha256(agent_clean.encode("utf-8")).hexdigest()[:12]
        return base / "subagents" / f"{safe_agent}-{agent_digest}"
    return base


def advance_session_step(state_dir_path: Path) -> int:
    """Increment and return `auto_step_seq` when `state_dir_path` already exists; 0 otherwise."""
    if not state_dir_path.is_dir():
        return 0
    try:
        with locked_state(state_dir_path, create=False) as txn:
            next_step = int(txn.state.get("auto_step_seq") or 0) + 1
            txn.state["auto_step_seq"] = next_step
            txn.dirty = True
            return next_step
    except OSError as exc:
        warn(f"advance_session_step skipped: {exc}")
        return 0


def state_file_in(state_dir_path: Path) -> Path:
    return state_dir_path / STATE_FILENAME


class StateTxn:
    """One locked read-modify-write of the session ledger; see `locked_state`."""

    def __init__(self, state_file: Path, state: dict[str, Any]) -> None:
        self.state_file = state_file
        self.state = state
        self.dirty = False

    def save(self) -> bool:
        """Persist `state` now, still under the lock; True when written. Clears `dirty` either way."""
        self.dirty = False
        return _save_state_atomic_unlocked(self.state_file, self.state)


@contextmanager
def locked_state(state_dir_path: Path, *, create: bool = True) -> Iterator[StateTxn]:
    """Hold the session ledger lock and yield its state; save on a normal exit when `dirty` is set.

    OSError propagates, including FileNotFoundError when `create` is False and the directory
    is missing: each caller owns its own failure policy. An exception inside the block
    discards the changes. A failed exit save is only logged; call `txn.save()` inside the
    block when the result matters. Not re-entrant: never call while already inside a
    `locked_state` block.
    """
    if create:
        state_dir_path.mkdir(parents=True, exist_ok=True)
    elif not state_dir_path.is_dir():
        raise FileNotFoundError(str(state_dir_path))
    state_file = state_file_in(state_dir_path)
    with open(state_dir_path / LOCK_FILENAME, "a+", encoding="utf-8") as lock_fh:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            txn = StateTxn(state_file, _open_or_quarantine_state_unlocked(state_file))
            if "mutated_repos" in txn.state and txn.state.get("mutated_repos_schema") != MUTATED_REPOS_SCHEMA:
                txn.state.pop("mutated_repos", None)
                txn.state["mutated_repos_schema"] = MUTATED_REPOS_SCHEMA
                txn.dirty = True
            yield txn
            if txn.dirty:
                txn.save()
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def filter_reads(
    state: dict[str, Any],
    keep_read: Callable[[int], bool],
    keep_outline: Callable[[int], bool] | None = None,
) -> bool:
    """Drop read ranges and outlines whose step fails the predicate; True when anything changed.

    `keep_outline` defaults to `keep_read`. An entry that is not a dict, whose `reads` is not a
    list, or that is left with neither reads nor an outline is deleted; read records shorter
    than [start, end, step] are dropped.
    """
    raw_files = state.get("files")
    files_map: dict[str, Any] = raw_files if isinstance(raw_files, dict) else {}
    keep_out = keep_outline or keep_read
    mutated = False
    for path_key in list(files_map):
        entry = files_map[path_key]
        reads = entry.get("reads") if isinstance(entry, dict) else None
        if not isinstance(reads, list):
            del files_map[path_key]
            mutated = True
            continue
        def _valid_triple(item: Any) -> bool:
            return (isinstance(item, list) and len(item) >= 3
                    and all(isinstance(x, int) and not isinstance(x, bool) for x in item[:3]))

        kept = [r for r in reads if _valid_triple(r) and keep_read(r[2])]
        if len(kept) != len(reads):
            entry["reads"] = kept
            mutated = True
        raw_out_step = entry.get("outlined_step")
        out_step = raw_out_step if isinstance(raw_out_step, int) and not isinstance(raw_out_step, bool) else 0
        if entry.get("outlined") and not keep_out(out_step):
            for k in ("outlined", "outlined_step", "outlined_total_lines",
                      "unwrapped_path", "pending_followup_kind", "outline_pull_step", "mirror_source"):
                entry.pop(k, None)
            mutated = True
        if entry.get("pending_followup_kind") == "outline_pull":
            raw_pull_step = entry.get("outline_pull_step")
            pull_step = raw_pull_step if isinstance(raw_pull_step, int) and not isinstance(raw_pull_step, bool) else 0
            if not keep_out(pull_step):
                entry.pop("pending_followup_kind", None)
                entry.pop("outline_pull_step", None)
                mutated = True
        if not kept and not entry.get("outlined") and entry.get("pending_followup_kind") != "outline_pull":
            del files_map[path_key]
            mutated = True
    return mutated


def merge_intervals(reads: list[list[int]]) -> list[list[int]]:
    """Merge overlapping or adjacent [start, end, step_idx] intervals in memory."""
    parsed: list[tuple[int, float, int]] = []
    for entry in reads:
        if len(entry) >= 3:
            r_start, r_end, r_step = int(entry[0]), int(entry[1]), int(entry[2])
            parsed.append((r_start, float("inf") if r_end == -1 else float(r_end), r_step))

    if not parsed:
        return []

    parsed.sort(key=lambda item: (item[0], item[1]))
    merged: list[list[float | int]] = [[parsed[0][0], parsed[0][1], parsed[0][2]]]
    for nxt_start, nxt_end, nxt_step in parsed[1:]:
        cur = merged[-1]
        if cur[1] + 1 >= nxt_start:
            cur[1] = max(cur[1], nxt_end)
            cur[2] = max(int(cur[2]), nxt_step)
        else:
            merged.append([nxt_start, nxt_end, nxt_step])

    return [[int(m[0]), -1 if m[1] == float("inf") else int(m[1]), int(m[2])] for m in merged]
