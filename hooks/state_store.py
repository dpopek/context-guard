"""Owner of the per-session state ledger and its shared primitives.

This leaf module must never import anything from `hooks` (avoids cycles with `hooks.outcomes`).
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

STATE_FILENAME = ".context_guard_state.json"
LOCK_FILENAME = ".context_guard_state.lock"
MUTATED_REPOS_SCHEMA = 2
READ_LEDGER_SCHEMA = 2
VALID_CONFIRM_TIERS = (1, 2)
_OUTLINE_META_KEYS = (
    "outlined", "outlined_step", "outlined_total_lines", "unwrapped_path",
    "pending_followup_kind", "outline_pull_step", "mirror_source",
)

def warn(message: object) -> None:
    """Operator-facing diagnostic; never raises or leaves dirty C buffers on fd 2."""
    try:
        text = f"context-guard: {message}\n"
    except Exception:
        text = "context-guard: <unprintable diagnostic>\n"
    try:
        if (stream := sys.stderr) is None:
            return
        if (raw := sys.__stderr__) is not None and stream is raw:
            os.write(raw.fileno(), text.encode("utf-8", errors="replace"))
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
        detail = ""
        try:
            detail = f": {exc}"
        except Exception:
            pass
        try:
            warn(f"{context} error ignored after decision ({type(exc).__name__}){detail}")
        except Exception:
            pass

def _neutralize_stream(attr: str) -> None:
    try:
        setattr(sys, attr, io.StringIO())
    except Exception:
        pass

def sanitize_stderr_before_exit() -> None:
    """Ensure CPython Py_FinalizeEx will not exit 120 due to buffered writes on broken stderr."""
    if sys.stderr is not None:
        try:
            sys.stderr.flush()
        except Exception:
            _neutralize_stream("stderr")

def emit_json_and_sanitize_stdio(payload: dict[str, Any]) -> int:
    """Emit one JSON line to stdout and neutralize broken stdout/stderr buffers before exit."""
    line = json.dumps(payload) + "\n"
    if sys.stdout is not None:
        try:
            sys.stdout.write(line)
            sys.stdout.flush()
        except Exception:
            _neutralize_stream("stdout")
    sanitize_stderr_before_exit()
    return 0

def _fresh_state() -> dict[str, Any]:
    return {"files": {}, "read_ledger_schema": READ_LEDGER_SCHEMA}

def _read_state_raw(state_file: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not state_file.is_file():
        return _fresh_state(), None
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("files"), dict):
            return data, None
        return None, "missing or non-dict 'files' map"
    except (OSError, ValueError, TypeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"

def _open_or_quarantine_state_unlocked(state_file: Path) -> dict[str, Any]:
    """Load session state under the lock; quarantine corrupt files and warn on failure."""
    data, detail = _read_state_raw(state_file)
    if data is not None:
        return data
    quarantine_path = state_file.with_name(f"{state_file.name}.corrupt")
    try:
        os.replace(str(state_file), str(quarantine_path))
        warn(f"corrupt session state ({detail}) quarantined to {quarantine_path}")
    except OSError as q_exc:
        warn(f"corrupt session state ({detail}) reset in memory; quarantine failed: {q_exc}")
    return _fresh_state()

def _save_state_atomic_unlocked(state_file: Path, state: dict[str, Any]) -> bool:
    """Persist state via mkstemp + os.replace; False (with stderr note) on failure."""
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".cg_state.", suffix=".tmp", dir=str(state_file.parent))
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

def is_valid_read_interval(item: Any) -> bool:
    """Return True iff `item` is a 4-tuple `[start, end, step, confirm_tier]` with valid tier."""
    return (
        isinstance(item, (list, tuple)) and len(item) >= 4
        and all(isinstance(x, int) and not isinstance(x, bool) for x in item[:4])
        and int(item[3]) in VALID_CONFIRM_TIERS
    )

def _purge_stale_read_ledger_unlocked(state: dict[str, Any]) -> None:
    if isinstance((files_map := state.get("files")), dict):
        for entry in files_map.values():
            if isinstance(entry, dict):
                if "reads" in entry:
                    entry["reads"] = []
                entry.pop("pending_reads", None)
                entry.pop("completed_read_ids", None)
    state["read_ledger_schema"] = READ_LEDGER_SCHEMA

def resolve_plugin_root(default_root: Path | None = None) -> Path:
    """Canonical Context-Guard root: CONTEXT_GUARD_HOME override, explicit default, or checkout."""
    if (env_home := os.environ.get("CONTEXT_GUARD_HOME", "").strip()):
        return Path(env_home).expanduser().resolve()
    if default_root is not None:
        return Path(default_root).expanduser().resolve()
    return Path(__file__).resolve().parent.parent

def resolve_state_dir(payload: dict[str, Any], state_dir: str | None) -> Path:
    """Session ledger directory: explicit override, harness artifact dir, or temp dir."""
    if state_dir:
        base = Path(state_dir)
    else:
        if isinstance((art := payload.get("artifactDirectoryPath")), str) and art.strip():
            return Path(art.strip())
        conv_id = str(
            payload.get("conversationId") or payload.get("session_id")
            or payload.get("conversation_id") or "default"
        )
        base = Path(tempfile.gettempdir()) / f"context-guard-{re.sub(r'[^a-zA-Z0-9_.-]', '_', conv_id)}"
    if isinstance((raw_agent := payload.get("agent_id")), str) and raw_agent.strip():
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

@contextmanager
def _dir_lock(state_dir_path: Path) -> Iterator[None]:
    with open(state_dir_path / LOCK_FILENAME, "a+", encoding="utf-8") as lock_fh:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

def read_state_snapshot(state_dir_path: Path) -> dict[str, Any]:
    """Read session ledger under lock without creating files or persisting schema writes."""
    state_file = state_file_in(state_dir_path)
    if not state_dir_path.is_dir() or not state_file.is_file():
        return _fresh_state()
    with _dir_lock(state_dir_path):
        data, _ = _read_state_raw(state_file)
        state = data if data is not None else _fresh_state()
        if state.get("read_ledger_schema") != READ_LEDGER_SCHEMA:
            _purge_stale_read_ledger_unlocked(state)
        return state

class StateTxn:
    """One locked read-modify-write of the session ledger; see `locked_state`."""

    def __init__(self, state_file: Path, state: dict[str, Any]) -> None:
        self.state_file, self.state, self.dirty = state_file, state, False

    def save(self) -> bool:
        """Persist `state` now, still under the lock; True when written. Clears `dirty`."""
        self.dirty = False
        return _save_state_atomic_unlocked(self.state_file, self.state)

@contextmanager
def locked_state(state_dir_path: Path, *, create: bool = True) -> Iterator[StateTxn]:
    """Hold the session ledger lock and yield its state; save on normal exit when `dirty`."""
    if create:
        state_dir_path.mkdir(parents=True, exist_ok=True)
    elif not state_dir_path.is_dir():
        raise FileNotFoundError(str(state_dir_path))
    state_file = state_file_in(state_dir_path)
    with _dir_lock(state_dir_path):
        txn = StateTxn(state_file, _open_or_quarantine_state_unlocked(state_file))
        st = txn.state
        if "mutated_repos" in st and st.get("mutated_repos_schema") != MUTATED_REPOS_SCHEMA:
            st.pop("mutated_repos", None)
            st["mutated_repos_schema"], txn.dirty = MUTATED_REPOS_SCHEMA, True
        if st.get("read_ledger_schema") != READ_LEDGER_SCHEMA:
            _purge_stale_read_ledger_unlocked(st)
            txn.dirty = True
        yield txn
        if txn.dirty:
            txn.save()

def _is_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)

def filter_reads(
    state: dict[str, Any], keep_read: Callable[[int], bool],
    keep_outline: Callable[[int], bool] | None = None,
) -> bool:
    """Drop read ranges, pending reads, and outlines failing predicates; True when mutated."""
    raw_files = state.get("files")
    files_map: dict[str, Any] = raw_files if isinstance(raw_files, dict) else {}
    keep_out, mutated = (keep_outline or keep_read), False
    for path_key in list(files_map):
        entry = files_map[path_key]
        reads = entry.get("reads") if isinstance(entry, dict) else None
        if not isinstance(reads, list):
            del files_map[path_key]
            mutated = True
            continue
        kept = [[int(r[0]), int(r[1]), int(r[2]), int(r[3])] for r in reads
                if is_valid_read_interval(r) and keep_read(int(r[2]))]
        if len(kept) != len(reads):
            entry["reads"], mutated = kept, True
        raw_pending, kept_pending = entry.get("pending_reads"), {}
        if isinstance(raw_pending, dict):
            kept_pending = {
                cid: rec for cid, rec in raw_pending.items()
                if isinstance(cid, str) and isinstance(rec, dict)
                and _is_int(rec.get("step")) and keep_read(int(rec["step"]))
            }
            if len(kept_pending) != len(raw_pending):
                mutated = True
                if kept_pending:
                    entry["pending_reads"] = kept_pending
                else:
                    entry.pop("pending_reads", None)
        elif "pending_reads" in entry:
            entry.pop("pending_reads", None)
            mutated = True
        out_s = int(r) if _is_int((r := entry.get("outlined_step"))) else 0
        if entry.get("outlined") and not keep_out(out_s):
            for k in _OUTLINE_META_KEYS:
                entry.pop(k, None)
            mutated = True
        if entry.get("pending_followup_kind") == "outline_pull" and not keep_out(
            int(rp) if _is_int((rp := entry.get("outline_pull_step"))) else 0
        ):
            entry.pop("pending_followup_kind", None)
            entry.pop("outline_pull_step", None)
            mutated = True
        has_pull = entry.get("pending_followup_kind") == "outline_pull"
        if not (kept or kept_pending or entry.get("outlined") or has_pull):
            del files_map[path_key]
            mutated = True
    return mutated

def merge_intervals(reads: list[list[int]]) -> list[list[int]]:
    """Merge overlapping/adjacent `[start, end, step_idx, confirm_tier]` sharing `confirm_tier`."""
    by_tier: dict[int, list[tuple[int, float, int]]] = {}
    for e in reads:
        if is_valid_read_interval(e):
            by_tier.setdefault(int(e[3]), []).append(
                (int(e[0]), float("inf") if int(e[1]) == -1 else float(e[1]), int(e[2])),
            )
    if not by_tier:
        return []
    out: list[list[int]] = []
    for tier, parsed in by_tier.items():
        parsed.sort(key=lambda item: (item[0], item[1]))
        merged: list[list[float | int]] = [[parsed[0][0], parsed[0][1], parsed[0][2]]]
        for nxt_s, nxt_e, nxt_step in parsed[1:]:
            if merged[-1][1] + 1 >= nxt_s:
                merged[-1][1], merged[-1][2] = max(merged[-1][1], nxt_e), max(int(merged[-1][2]), nxt_step)
            else:
                merged.append([nxt_s, nxt_e, nxt_step])
        out.extend([int(m[0]), -1 if m[1] == float("inf") else int(m[1]), int(m[2]), tier] for m in merged)
    out.sort(key=lambda item: (item[0], float("inf") if item[1] == -1 else float(item[1]), item[3]))
    return out
