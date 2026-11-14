"""Shell command families and output size measurement (pure functions)."""
from __future__ import annotations

import dataclasses

import pytest

from hooks.shell_output import BUCKETS, SIM_MARKER, SPILL_PREVIEW_TOKENS, classify_family, measure


@pytest.mark.parametrize(
    "command, family",
    [
        ("git log --oneline -20", "git_log"),
        ("git show HEAD", "git_log"),
        ("git reflog", "git_log"),
        ("git -C /repo log -5", "git_log"),
        ("git diff --stat", "git_diff"),
        ("git status -sb", "git_other"),
        ("git grep foo", "search"),
        ("rg -n foo src", "search"),
        ("grep -rn foo .", "search"),
        ("ag foo", "search"),
        ("ls -la", "list"),
        ("find . -name '*.py'", "list"),
        ("fd py", "list"),
        ("tree -L 2", "list"),
        ("du -sh .", "list"),
        ("tail -n 50 app.log", "read"),
        ("cat a.txt", "read"),
        ("wc -l a.py", "read"),
        ("pytest -q", "test"),
        ("python3 -m pytest -q tests/", "test"),
        ("taskpolicy -c utility -d utility nice -n 15 python3 -m pytest -q", "test"),
        ("env -i PATH=/bin HOME=/h /usr/bin/python3 -m pytest -q", "test"),
        ("jest --ci", "test"),
        ("npx vitest run", "test"),
        ("npm test", "test"),
        ("npm run test:unit", "test"),
        ("cargo test", "test"),
        ("go test ./...", "test"),
        ("npm install", "build"),
        ("npm ci", "build"),
        ("yarn install", "build"),
        ("npm run build", "build"),
        ("pip install -r requirements.txt", "build"),
        ("python3 -m pip install requests", "build"),
        ("cargo build --release", "build"),
        ("make all", "build"),
        ("tsc -p tsconfig.app.json", "build"),
        ("docker build -t x .", "build"),
        ("docker ps", "container"),
        ("kubectl get pods", "container"),
        ("VAR=1 git log", "git_log"),
        ("cd /repo && rg foo", "search"),
        ("git log | head -5", "git_log"),
        ("bash -lc 'git diff'", "git_diff"),
        ("echo cat", "other"),
        ("python3 script.py", "other"),
        ("npm run lint", "other"),
        ("", "other"),
        ('"unterminated', "other"),
        ("bash -lc 'git log | head'", "git_log"),
        ("bash -lc 'cd x && rg foo'", "search"),
        ("cd x\ngit log", "git_log"),
        ("# note\ngit status", "git_other"),
        ("grep 'a|b' file.txt", "search"),
        ("echo 'git log | x'", "other"),
        ('git log "unterminated | x', "git_log"),
        ("python3 -u -m pytest -q", "test"),
        ("python -X dev -m pytest", "test"),
        ("python3 -W error -m pip install x", "build"),
        ("python3 -u script.py", "other"),
        ("uv run pytest", "test"),
        ("poetry run pytest -q", "test"),
        ("uv run python -m pytest", "test"),
        ("uv run --frozen pytest", "test"),
        ("uv pip install x", "other"),
        ("uv sync", "other"),
        (r"C:\Python313\python.exe -m pytest -q", "test"),
        (r"C:\Git\bin\GIT.EXE diff --stat", "git_diff"),
        ("PYTEST.CMD tests/", "test"),
        (r"C:\tools\RG.BAT foo src", "search"),
        (r"C:\Windows\System32\bash.exe -lc 'git log -n 5'", "git_log"),
    ],
)
def test_classify_family(command: str, family: str) -> None:
    assert classify_family(command) == family


def _lines(count: int, width: int = 99) -> str:
    return ("x" * width + "\n") * count


@pytest.mark.parametrize(
    "chars, bucket",
    [
        (0, "<1k"),
        (999, "<1k"),
        (1000, "1-5k"),
        (4999, "1-5k"),
        (5000, "5-20k"),
        (19999, "5-20k"),
        (20000, "20-30k"),
        (29999, "20-30k"),
        (30000, ">=30k"),
    ],
)
def test_bucket_edges(chars: int, bucket: str) -> None:
    assert measure("a" * chars, "codex").bucket == bucket


def test_bucket_labels_are_fixed() -> None:
    assert BUCKETS == ("<1k", "1-5k", "5-20k", "20-30k", ">=30k")


def test_tokens_come_from_utf8_bytes() -> None:
    m = measure("ż" * 1000, "claude")
    assert (m.chars, m.tokens, m.bucket) == (1000, 500, "1-5k")


def test_head_tail_rule_saves_the_middle() -> None:
    text = _lines(200)  # 20,000 chars, 5,000 tokens
    m = measure(text, "claude")
    kept_bytes = 60 * 100 + len(SIM_MARKER) + 1 + 40 * 100
    assert m.sim_hit is True
    assert m.sim_saved_tokens == 5000 - kept_bytes // 4
    assert m.spilled is False


def test_threshold_is_exclusive() -> None:
    at_threshold = _lines(160, 49)
    assert len(at_threshold) == 8000
    assert measure(at_threshold, "claude").sim_hit is False
    assert measure(at_threshold + "x", "claude").sim_hit is True


def test_exactly_100_lines_is_not_a_hit() -> None:
    m = measure(_lines(100), "claude")
    assert (m.sim_hit, m.sim_saved_tokens) == (False, 0)


def test_long_lines_under_100_lines_are_not_a_hit() -> None:
    m = measure(_lines(50, 199), "claude")
    assert m.chars == 10000
    assert (m.sim_hit, m.sim_saved_tokens) == (False, 0)


def test_spilled_claude_output_is_never_a_hit() -> None:
    text = _lines(400)  # 40,000 chars
    claude = measure(text, "claude")
    assert (claude.spilled, claude.sim_hit, claude.sim_saved_tokens) == (True, False, 0)
    codex = measure(text, "codex")
    assert (codex.spilled, codex.sim_hit) == (False, True)


def test_measurement_is_frozen() -> None:
    m = measure("a", "claude")
    with pytest.raises(dataclasses.FrozenInstanceError):
        m.tokens = 9  # type: ignore[misc]


def test_spilled_output_counts_only_its_preview_in_context() -> None:
    m = measure(_lines(400), "claude")  # 40,000 chars, 10,000 tokens
    assert SPILL_PREVIEW_TOKENS == 500
    assert (m.tokens, m.context_tokens) == (10000, 500)


def test_small_spilled_output_is_capped_by_its_own_size() -> None:
    m = measure("x" * 30000, "claude")  # 7,500 tokens
    assert m.spilled is True and m.context_tokens == 500
    assert measure("x" * 400, "claude").context_tokens == 100


def test_unspilled_output_counts_in_full() -> None:
    m = measure(_lines(400), "codex")
    assert (m.spilled, m.tokens, m.context_tokens) == (False, 10000, 10000)
