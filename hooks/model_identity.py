"""Model identity for outcome telemetry across Antigravity, Claude Code, and Codex."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from hooks.config import KNOWN_HARNESSES, cached_raw_config

UNKNOWN_MODEL = "unknown"
MODEL_REFRESH_STEPS = 20
TAIL_BYTES = 64 * 1024
MAX_LABEL_LEN = 48

CODEX_SESSIONS_DIR = Path.home() / ".codex" / "sessions"
CODEX_CONFIG_PATH = Path.home() / ".codex" / "config.toml"
GUARD_CONFIG_PATH: Path | None = None
ANTIGRAVITY_BRAIN_DIR = Path.home() / ".gemini" / "antigravity" / "brain"
MAX_SIBLING_TRANSCRIPTS = 25

_MODEL_FIELD_RE = re.compile(r'"model"\s*:\s*"([^"\\]*)"')
_TOML_MODEL_RE = re.compile(r'^\s*model\s*=\s*"([^"]+)"', re.MULTILINE)
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_LABEL_BAD_CHARS_RE = re.compile(r"[^a-z0-9._:/-]")
_AG_MODEL_CHANGE_RE = re.compile(r"changed setting `Model Selection` from .+? to ([^\n<]+)")
_AG_SETTINGS_BLOCK_RE = re.compile(r"<USER_SETTINGS_CHANGE>(.*?)</USER_SETTINGS_CHANGE>", re.DOTALL)
_AG_SIDECHAIN_HEAD_RE = re.compile(r'(?<!\\)"type"\s*:\s*"SYSTEM_MESSAGE"|(?<!\\)"content"\s*:\s*"\s*<SYSTEM_MESSAGE>')


def normalize_model_label(raw: Any) -> str:
    """Lowercase slug limited to `[a-z0-9._:/-]` and MAX_LABEL_LEN; empty becomes `unknown`."""
    return _LABEL_BAD_CHARS_RE.sub("", raw.strip().lower())[:MAX_LABEL_LEN] or UNKNOWN_MODEL if isinstance(raw, str) else UNKNOWN_MODEL


def _read_tail(path: Path, max_bytes: int = TAIL_BYTES) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
            return fh.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _parse_json_dict(raw_line: str) -> dict[str, Any] | None:
    try:
        rec = json.loads(raw_line) if raw_line.strip() else None
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def _valid_model(raw: Any) -> str | None:
    if isinstance(raw, str) and raw.strip() and not raw.strip().startswith("<"):
        norm = normalize_model_label(raw)
        return norm if norm not in (UNKNOWN_MODEL, "auto") else None
    return None


def extract_antigravity_model_change(content: str) -> str | None:
    """Extract the latest `<USER_SETTINGS_CHANGE>` `Model Selection` slug, ignoring `Auto`/`unknown`."""
    if not isinstance(content, str) or "<USER_SETTINGS_CHANGE>" not in content:
        return None
    matches = _AG_MODEL_CHANGE_RE.findall("\n".join(_AG_SETTINGS_BLOCK_RE.findall(content)))
    return _valid_model(matches[-1].split(". ", 1)[0].rstrip(". ").strip()) if matches else None


def _antigravity_model_from_record(rec: dict[str, Any]) -> str | None:
    rtype = rec.get("type")
    if rtype == "USER_INPUT":
        return extract_antigravity_model_change(str(rec.get("content") or ""))
    if rtype == "PLANNER_RESPONSE":
        return next((m for k in ("model", "modelName", "model_name") for m in (_valid_model(rec.get(k)),) if m), None)
    if rtype == "assistant" and isinstance(rec.get("message"), dict):
        return _valid_model(rec["message"].get("model"))
    return None


def _is_antigravity_sidechain_start(raw_line: str) -> bool:
    rec = _parse_json_dict(raw_line)
    if rec is None:
        return bool(_AG_SIDECHAIN_HEAD_RE.search(raw_line)) and "<USER_REQUEST>" not in raw_line
    if rec.get("type") not in ("SYSTEM_MESSAGE", "USER_INPUT") or rec.get("step_index") not in (0, None):
        return False
    content = str(rec.get("content") or "")
    return "<SYSTEM_MESSAGE>" in content and (rec.get("type") == "SYSTEM_MESSAGE" or "<USER_REQUEST>" not in content)


def _scan_ag_lines_reverse(text: str) -> str | None:
    return next(
        (m for ln in reversed(text.splitlines()) for r in (_parse_json_dict(ln),) if r for m in (_antigravity_model_from_record(r),) if m),
        None,
    )


def _antigravity_model_in_transcript(path: Path, *, ignore_sidechain: bool = False) -> tuple[str | None, bool]:
    try:
        size = path.stat().st_size
        if size <= 0:
            return None, False
        if size <= TAIL_BYTES:
            text = _read_tail(path, size)
            if ignore_sidechain and _is_antigravity_sidechain_start(next((ln for ln in text.splitlines() if ln.strip()), "")):
                return None, True
            return _scan_ag_lines_reverse(text), False
        start = size - TAIL_BYTES - 1
        with path.open("rb") as fh:
            if ignore_sidechain and _is_antigravity_sidechain_start(fh.readline(TAIL_BYTES).decode("utf-8", errors="replace")):
                return None, True
            fh.seek(start)
            raw_tail = fh.read()
            tail_b = raw_tail if start == 0 else (raw_tail[1:] if raw_tail[:1] == b"\n" else raw_tail.partition(b"\n")[2])
            found = _scan_ag_lines_reverse(tail_b.decode("utf-8", errors="replace"))
            if found:
                return found, False
            fh.seek(0)
            raw_head = fh.read(TAIL_BYTES)
    except OSError:
        return None, False
    nl = raw_head.rfind(b"\n")
    return (_scan_ag_lines_reverse(raw_head[: nl + 1].decode("utf-8", errors="replace")) if nl != -1 else None), False


def detect_antigravity_model(
    transcript_path: str | None = None, state_dir: Path | None = None, brain_dir: Path | None = None
) -> str:
    """Detect Antigravity model from explicit transcript, session log, or earlier sibling transcript."""
    scanned: set[Path] = set()
    logs_dir = (state_dir / ".system_generated" / "logs") if state_dir is not None else None
    logs = (logs_dir / "transcript.jsonl", logs_dir / "transcript_full.jsonl") if logs_dir else ()
    own_log = next((p for p in logs if p.is_file()), None)
    for cand in [*([Path(transcript_path)] if transcript_path else []), *logs]:
        try:
            cand_res = cand.resolve()
        except OSError:
            cand_res = cand
        if cand_res in scanned or not cand.is_file():
            continue
        found, _ = _antigravity_model_in_transcript(cand)
        if found:
            return found
        scanned.add(cand_res)
    eff_brain = brain_dir if brain_dir is not None else (state_dir.parent if state_dir is not None and logs_dir and logs_dir.is_dir() else ANTIGRAVITY_BRAIN_DIR)
    try:
        own_mtime: float | None = own_log.stat().st_mtime if own_log is not None else None
    except OSError:
        own_mtime = None
    if eff_brain.is_dir():
        candidates: list[tuple[float, Path]] = []
        try:
            for log_dir in eff_brain.glob("*/.system_generated/logs"):
                t_compact, t_full = log_dir / "transcript.jsonl", log_dir / "transcript_full.jsonl"
                sib_log = t_compact if t_compact.is_file() else (t_full if t_full.is_file() else None)
                if sib_log is None:
                    continue
                try:
                    mtime = sib_log.stat().st_mtime
                    if sib_log.resolve() not in scanned and (own_mtime is None or mtime <= own_mtime):
                        candidates.append((mtime, sib_log))
                except OSError:
                    continue
        except OSError:
            pass
        checked = 0
        for _, cand in sorted(candidates, key=lambda item: (item[0], str(item[1])), reverse=True):
            if checked >= MAX_SIBLING_TRANSCRIPTS:
                break
            found, is_sidechain = _antigravity_model_in_transcript(cand, ignore_sidechain=True)
            if is_sidechain:
                continue
            checked += 1
            if found:
                return found
    return UNKNOWN_MODEL


def detect_claude_model(transcript_path: str | None) -> str:
    """Newest `"model": "..."` in the transcript tail that is not a `<synthetic>`-style placeholder."""
    if not transcript_path:
        return UNKNOWN_MODEL
    for match in reversed(_MODEL_FIELD_RE.findall(_read_tail(Path(transcript_path)))):
        if match and not match.startswith("<"):
            return normalize_model_label(match)
    return UNKNOWN_MODEL


def _model_from_rollout(rollout: Path) -> str | None:
    try:
        with rollout.open("r", encoding="utf-8", errors="replace") as fh:
            for _, line in zip(range(200), fh):
                rec = _parse_json_dict(line)
                payload = rec.get("payload") if rec and rec.get("type") == "turn_context" else None
                if isinstance(payload, dict) and isinstance(payload.get("model"), str):
                    return payload["model"]
    except OSError:
        pass
    return None


def detect_codex_model(session_id: str | None, sessions_dir: Path | None = None, config_path: Path | None = None) -> str:
    """Rollout `turn_context` of this session first, then `model = "..."` from config.toml."""
    if session_id and _SESSION_ID_RE.match(session_id):
        try:
            rollouts = sorted((sessions_dir or CODEX_SESSIONS_DIR).glob(f"*/*/*/rollout-*-{session_id}.jsonl"), reverse=True)
        except OSError:
            rollouts = []
        for rollout in rollouts:
            model = _model_from_rollout(rollout)
            if model:
                return normalize_model_label(model)
    try:
        match = _TOML_MODEL_RE.search((config_path or CODEX_CONFIG_PATH).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        match = None
    return normalize_model_label(match.group(1)) if match else UNKNOWN_MODEL


def pinned_model(harness: str, config_path: Path | None = None) -> str | None:
    """Operator pin from `model_labels` in the guard config, or None."""
    raw_cfg = cached_raw_config(config_path or GUARD_CONFIG_PATH)
    labels = raw_cfg.get("model_labels") if isinstance(raw_cfg, dict) else None
    raw = labels.get(harness) if isinstance(labels, dict) and harness in KNOWN_HARNESSES else None
    return normalize_model_label(raw) if isinstance(raw, str) and raw.strip() else None


def detect_model(
    harness: str, session_id: str | None, transcript_path: str | None, config_path: Path | None = None, state_dir: Path | None = None
) -> str:
    return (
        pinned_model(harness, config_path=config_path)
        or (
            detect_claude_model(transcript_path) if harness == "claude"
            else detect_antigravity_model(transcript_path=transcript_path, state_dir=state_dir) if harness == "antigravity"
            else detect_codex_model(session_id) if harness == "codex" else UNKNOWN_MODEL
        )
    )


def memoize_model(
    harness: str, session_id: str | None, transcript_path: str | None, state: dict[str, Any], current_step: int, state_dir: Path | None = None
) -> str:
    """Cached `detect_model`: refreshes every MODEL_REFRESH_STEPS when known, else next step."""
    cached, cached_step = state.get("model"), state.get("model_step")
    if isinstance(cached, str) and cached and isinstance(cached_step, int) and not isinstance(cached_step, bool):
        if 0 <= current_step - cached_step < (MODEL_REFRESH_STEPS if cached != UNKNOWN_MODEL else 1):
            return cached
    model = detect_model(harness, session_id, transcript_path, state_dir=state_dir)
    state["model"], state["model_step"] = model, int(current_step)
    return model
