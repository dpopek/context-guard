"""The shell_output section of stats.json: sums, coercion and isolation from savings totals."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.status_service import render_markdown_report
from hooks.shell_output import BUCKETS, measure
from hooks.telemetry import load_telemetry_stats, record_shell_output, record_telemetry_event

BIG = ("x" * 99 + "\n") * 150  # 15,000 chars, 3,750 tokens, 150 lines: a simulated hit


def _zero_buckets() -> dict[str, int]:
    return {b: 0 for b in BUCKETS}


def test_records_sum_per_harness_and_family(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    record_shell_output("claude", "test", measure(BIG, "claude"), "ok", stats)
    record_shell_output("claude", "test", measure("boom\n", "claude"), "fail", stats)
    section = load_telemetry_stats(stats)["shell_output"]
    entry = section["harnesses"]["claude"]["test"]
    assert entry["count"] == 2
    assert (entry["ok"], entry["fail"], entry["unknown"]) == (1, 1, 0)
    assert (entry["tokens"], entry["max_tokens"]) == (3751, 3750)
    assert entry["sim_hits"] == 1
    assert entry["sim_saved_tokens"] == measure(BIG, "claude").sim_saved_tokens
    assert entry["spilled"] == 0
    assert entry["buckets"] == {**_zero_buckets(), "<1k": 1, "5-20k": 1}
    assert section["since"]
    assert section["unparsed"] == 0


def test_spilled_output_is_counted(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    record_shell_output("claude", "list", measure(("x" * 99 + "\n") * 400, "claude"), "ok", stats)
    entry = load_telemetry_stats(stats)["shell_output"]["harnesses"]["claude"]["list"]
    assert (entry["spilled"], entry["sim_hits"], entry["buckets"][">=30k"]) == (1, 0, 1)


def test_spilled_claude_output_counts_its_preview_in_context(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    record_shell_output("claude", "list", measure(("x" * 99 + "\n") * 400, "claude"), "ok", stats)  # 10,000 tokens
    entry = load_telemetry_stats(stats)["shell_output"]["harnesses"]["claude"]["list"]
    assert (entry["tokens"], entry["max_tokens"], entry["spilled_tokens"]) == (500, 500, 10000)


def test_unspilled_codex_output_counts_in_full(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    record_shell_output("codex", "list", measure(("x" * 99 + "\n") * 400, "codex"), "ok", stats)
    entry = load_telemetry_stats(stats)["shell_output"]["harnesses"]["codex"]["list"]
    assert (entry["tokens"], entry["max_tokens"], entry["spilled_tokens"]) == (10000, 10000, 0)


def test_ledger_without_spilled_tokens_normalises_to_zero(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    old = {"shell_output": {"since": "t", "unparsed": 0, "harnesses": {"claude": {"list": {"count": 2, "spilled": 1}}}}}
    stats.write_text(json.dumps(old), encoding="utf-8")
    entry = load_telemetry_stats(stats)["shell_output"]["harnesses"]["claude"]["list"]
    assert (entry["spilled"], entry["spilled_tokens"]) == (1, 0)


def test_unparsed_call_counts_only_count_unknown_and_unparsed(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    record_shell_output("codex", "list", None, "unknown", stats)
    section = load_telemetry_stats(stats)["shell_output"]
    entry = section["harnesses"]["codex"]["list"]
    assert section["unparsed"] == 1
    assert (entry["count"], entry["unknown"], entry["tokens"]) == (1, 1, 0)
    assert entry["buckets"] == _zero_buckets()


def test_unknown_outcome_label_counts_as_unknown(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    record_shell_output("cursor", "other", measure("a", "cursor"), "weird", stats)
    entry = load_telemetry_stats(stats)["shell_output"]["harnesses"]["cursor"]["other"]
    assert (entry["ok"], entry["fail"], entry["unknown"]) == (0, 0, 1)


def test_shell_records_leave_savings_totals_untouched(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    record_shell_output("claude", "test", measure(BIG, "claude"), "ok", stats)
    data = load_telemetry_stats(stats)
    assert (data["baseline_bytes"], data["saved_bytes"]) == (0, 0)
    assert all(count == 0 for count in data["events"].values())
    assert data["by_harness"]["claude"] == {"baseline_tokens": 0, "saved_tokens": 0, "hits": 0}


def test_garbage_section_is_reset_and_survives_other_events(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    stats.write_text(json.dumps({"shell_output": "junk", "events": {}}), encoding="utf-8")
    record_shell_output("cursor", "build", measure("ok\n", "cursor"), "ok", stats)
    record_telemetry_event("cursor", "allowed_reads", 400, 0, stats)
    data = load_telemetry_stats(stats)
    assert data["shell_output"]["harnesses"]["cursor"]["build"]["count"] == 1
    assert data["events"]["allowed_reads"] == 1


def test_nested_garbage_is_coerced(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    stats.write_text(
        json.dumps(
            {
                "shell_output": {
                    "since": 5,
                    "unparsed": "x",
                    "harnesses": {"claude": {"git_log": {"count": "3", "buckets": "bad"}}, "codex": "bad"},
                }
            }
        ),
        encoding="utf-8",
    )
    section = load_telemetry_stats(stats)["shell_output"]
    assert (section["since"], section["unparsed"]) == ("", 0)
    expected = {
        "count": 3, "ok": 0, "fail": 0, "unknown": 0, "tokens": 0, "max_tokens": 0,
        "spilled": 0, "spilled_tokens": 0, "sim_hits": 0, "sim_saved_tokens": 0, "buckets": _zero_buckets(),
    }
    assert section["harnesses"] == {"claude": {"git_log": expected}}


def test_ledger_without_the_section_has_none(tmp_path: Path) -> None:
    assert "shell_output" not in load_telemetry_stats(tmp_path / "missing.json")


def test_unwritable_ledger_is_best_effort(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    record_shell_output("claude", "other", measure("a", "claude"), "ok", blocker / "stats.json")
    assert blocker.read_text(encoding="utf-8") == "x"
    assert not (blocker / "stats.json").exists()


def test_unexpected_error_is_warned_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import hooks.telemetry as telemetry_mod

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("bad")

    monkeypatch.setattr(telemetry_mod, "apply_shell_output", boom)
    record_shell_output("claude", "other", measure("a", "claude"), "ok", tmp_path / "stats.json")
    err = capsys.readouterr().err
    assert "shell output telemetry skipped: RuntimeError" in err
    assert "bad" not in err


def test_markdown_report_renders_the_shell_output_table(tmp_path: Path) -> None:
    stats = tmp_path / "stats.json"
    record_shell_output("claude", "test", measure(BIG, "claude"), "ok", stats)
    record_shell_output("claude", "test", measure("boom\n", "claude"), "fail", stats)
    record_shell_output("codex", "list", None, "unknown", stats)
    record_shell_output("claude", "list", measure(("x" * 99 + "\n") * 400, "claude"), "ok", stats)
    md = render_markdown_report(load_telemetry_stats(stats))
    saved = measure(BIG, "claude").sim_saved_tokens
    assert "## Shell Output (since `" in md
    assert "### `claude`" in md and "### `codex`" in md
    assert f"| `test` | 2 | 50% | 3,751 | 3,750 | 0% | 1 | {saved:,} ({round(100 * saved / 3751)}%) |" in md
    assert "- **Unparsed payloads:** 1" in md
    assert "| Family | Calls | Fail | Context tokens | Max |" in md
    assert "- **Spilled to a file (Claude Code, 30k+ chars):** 1 calls, 10,000 tokens kept out of context" in md
    assert md.index("## Savings by Harness") < md.index("## Shell Output")


def test_markdown_report_without_shell_data_says_so(tmp_path: Path) -> None:
    md = render_markdown_report(load_telemetry_stats(tmp_path / "missing.json"))
    assert md.rstrip().endswith("## Shell Output\n\nno shell data yet")
