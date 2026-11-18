"""Contract tests for unified `cg` CLI cohesion, `cg doctor`, `cg help`, and `cg eval` conformance modes."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from bin.cg import main as cg_main, run_doctor_cli
from bin.cg_eval import render_evidence_markdown
from policies.api import (
    CONFORMANCE_SCHEMA_VERSION,
    CORE_SCHEMA_VERSIONS,
    DOCTOR_SCHEMA_VERSION,
    PLATFORM_MATRIX_SCHEMA_VERSION,
    POLICY_API_VERSION,
    SUPPORTED_HARNESS_IDS,
)
from spool.receipts import load_receipt_rows, receipts_path_for
from spool.store import spool_tool_output

ROOT = Path(__file__).resolve().parent.parent

ALL_SUBCOMMANDS: tuple[str, ...] = (
    "budget",
    "doctor",
    "eval",
    "explain",
    "export",
    "status",
    "spool",
    "outline",
)


def _manifest_version() -> str:
    return str(json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))["version"])


def test_cg_top_level_help_version_and_unknown_subcommand(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_version = _manifest_version()

    for help_args in ([], ["--help"], ["-h"], ["help"]):
        assert cg_main(help_args) == 0
        captured = capsys.readouterr()
        assert "Usage: cg <command>" in captured.out
        for sub in (*ALL_SUBCOMMANDS, "help"):
            assert sub in captured.out
        assert captured.err == ""

    for ver_flag in ("--version", "-V"):
        assert cg_main([ver_flag]) == 0
        ver_out = capsys.readouterr()
        assert ver_out.out.strip() == f"context-guard {expected_version}"
        assert ver_out.err == ""

    assert cg_main(["unknown"]) == 1
    unk_top = capsys.readouterr()
    assert unk_top.out == ""
    assert "unknown subcommand 'unknown'" in unk_top.err
    assert "cg --help" in unk_top.err

    assert cg_main(["help", "unknown"]) == 1
    unk_help = capsys.readouterr()
    assert unk_help.out == ""
    assert "unknown subcommand 'unknown'" in unk_help.err
    assert "cg --help" in unk_help.err


def test_cg_help_delegates_cleanly_across_all_subcommands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for cmd in ALL_SUBCOMMANDS:
        rc = cg_main(["help", cmd])
        captured = capsys.readouterr()
        assert rc == 0, f"cg help {cmd} returned {rc}: stderr={captured.err!r}"
        assert "usage:" in captured.out.lower(), f"cg help {cmd} missing usage header: {captured.out!r}"
        assert captured.err == ""


def test_cg_doctor_supports_markdown_json_contracts_and_invalid_args(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_version = _manifest_version()

    assert run_doctor_cli([]) == 0
    md_default = capsys.readouterr()
    assert f"# Context-Guard Doctor (v{expected_version})" in md_default.out
    assert "## Platform Contracts" not in md_default.out
    assert md_default.err == ""

    assert cg_main(["doctor", "--markdown"]) == 0
    md_explicit = capsys.readouterr()
    assert f"# Context-Guard Doctor (v{expected_version})" in md_explicit.out
    assert "## Platform Contracts" not in md_explicit.out

    assert cg_main(["doctor", "--json"]) == 0
    doc_plain: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert doc_plain["ok"] is True
    assert doc_plain["version"] == expected_version
    assert doc_plain["schema_version"] == DOCTOR_SCHEMA_VERSION
    assert doc_plain["policy_api_version"] == POLICY_API_VERSION
    assert doc_plain["core_schema_versions"] == CORE_SCHEMA_VERSIONS
    assert "deprecation_policy" not in doc_plain
    assert "capability_matrix" not in doc_plain

    assert cg_main(["doctor", "--contracts", "--json"]) == 0
    doc_contracts: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert doc_contracts["ok"] is True
    assert doc_contracts["schema_version"] == DOCTOR_SCHEMA_VERSION
    assert doc_contracts["policy_api_version"] == POLICY_API_VERSION
    assert doc_contracts["core_schema_versions"] == CORE_SCHEMA_VERSIONS
    dep = doc_contracts["deprecation_policy"]
    assert dep["policy_api_version"] == POLICY_API_VERSION
    assert dep["policy_api_v2_mandated"] is False
    assert dep["external_sdk_shipped"] is False
    mat = doc_contracts["capability_matrix"]
    assert set(mat["harnesses"]) == set(SUPPORTED_HARNESS_IDS)

    assert cg_main(["doctor", "--contracts", "--markdown"]) == 0
    md_contracts = capsys.readouterr().out
    assert f"# Context-Guard Doctor (v{expected_version})" in md_contracts
    assert "## Platform Contracts (`--contracts`)" in md_contracts
    assert "Policy API Version: `1`" in md_contracts

    assert cg_main(["doctor", "--bad", "--json"]) == 2
    bad_json = capsys.readouterr()
    assert json.loads(bad_json.out) == {"ok": False, "error": "invalid_arguments"}

    assert cg_main(["doctor", "--json", "--markdown"]) == 2
    conflict_json = capsys.readouterr()
    assert json.loads(conflict_json.out) == {"ok": False, "error": "invalid_arguments"}

    assert cg_main(["doctor", "--bad"]) == 2
    bad_plain = capsys.readouterr()
    assert bad_plain.out == ""
    assert bad_plain.err != ""


def test_cohesive_four_pillars_json_and_invalid_arg_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # 1. doctor
    assert cg_main(["doctor", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert cg_main(["doctor", "--markdown"]) == 0
    assert "# Context-Guard Doctor" in capsys.readouterr().out

    # 2. budget (isolated paths)
    iso_home = tmp_path / "home"
    iso_ws = tmp_path / "ws"
    iso_usage = tmp_path / "token_usage.json"
    iso_home.mkdir()
    iso_ws.mkdir()
    budget_base = [
        "budget",
        "--home",
        str(iso_home),
        "--workspace",
        str(iso_ws),
        "--usage-path",
        str(iso_usage),
    ]
    assert cg_main([*budget_base, "--json"]) == 0
    budget_json = json.loads(capsys.readouterr().out)
    assert "preamble" in budget_json and "mcp" in budget_json
    assert cg_main([*budget_base, "--markdown"]) == 0
    assert "# Context-Guard" in capsys.readouterr().out

    # 3. explain (isolated spool + receipt)
    exp_ws = tmp_path / "exp_ws"
    (exp_ws / ".git").mkdir(parents=True)
    state_dir = tmp_path / "state"
    spool_dir = state_dir / "spool"
    rcpt_path = receipts_path_for(spool_dir)
    spooled = spool_tool_output(
        "\n".join(f"cohesion_line_{idx:04d}: " + ("x" * 70) for idx in range(240)) + "\n",
        session_id="sess_cohesion",
        call_id="call_cohesion",
        harness="claude",
        tool_name="Bash",
        workspace_root=exp_ws,
        isolation="workspace",
        spool_dir=spool_dir,
        receipts_path=rcpt_path,
    )
    assert spooled is not None
    ev_id = load_receipt_rows(rcpt_path)[0]["event_id"]
    explain_base = [
        "explain",
        ev_id,
        "--receipts-path",
        str(rcpt_path),
        "--spool-dir",
        str(spool_dir),
        "--state-dir",
        str(state_dir),
    ]
    assert cg_main([*explain_base, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert cg_main([*explain_base, "--markdown"]) == 0
    assert ev_id in capsys.readouterr().out

    # 4. eval
    assert cg_main(["eval", "--cursor-conformance", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert cg_main(["eval", "--cursor-conformance", "--markdown"]) == 0
    assert "# Context-Guard Cursor CLI Conformance Gate" in capsys.readouterr().out

    # Consistent invalid-argument JSON contract (exit 2) across all 4 pillars
    for pillar in ("doctor", "budget", "explain", "eval"):
        rc = cg_main([pillar, "--unknown-cohesion-flag", "--json"])
        err_payload = json.loads(capsys.readouterr().out)
        assert rc == 2, f"Expected exit 2 for {pillar}"
        assert err_payload["ok"] is False
        assert err_payload["error"] == "invalid_arguments"


def test_cg_eval_conformance_and_platform_matrix_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cg_main(["eval", "--conformance", "--json"]) == 0
    conf_json: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert conf_json["schema_version"] == CONFORMANCE_SCHEMA_VERSION
    assert conf_json["ok"] is True
    assert conf_json["gates_passed"] == 10
    assert conf_json["gates_total"] == 10
    assert conf_json["failed_gates"] == []
    assert "# Context-Guard Platform Conformance Report" in render_evidence_markdown(conf_json)

    assert cg_main(["eval", "--conformance", "--markdown"]) == 0
    conf_md = capsys.readouterr().out
    assert "# Context-Guard Platform Conformance Report" in conf_md
    assert "`PASS` (`10/10` gates)" in conf_md

    assert cg_main(["eval", "--platform-matrix", "--json"]) == 0
    mat_json: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert mat_json["schema_version"] == PLATFORM_MATRIX_SCHEMA_VERSION
    assert mat_json["policy_api_version"] == POLICY_API_VERSION
    assert set(mat_json["harnesses"]) == set(SUPPORTED_HARNESS_IDS)
    assert "primary_release_metric" in mat_json["effectiveness_summary"]
    assert "# Context-Guard Platform Capability & Limitation Matrix" in render_evidence_markdown(mat_json)

    out_md = tmp_path / "out" / "platform_matrix.md"
    assert cg_main(["eval", "--platform-matrix", "--markdown", "--output", str(out_md)]) == 0
    stdout_md = capsys.readouterr().out
    assert "# Context-Guard Platform Capability & Limitation Matrix" in stdout_md
    assert out_md.is_file()
    assert out_md.read_text(encoding="utf-8") == stdout_md

    for mode_flag in ("--conformance", "--platform-matrix"):
        assert cg_main(["eval", mode_flag, "--plan", "--json"]) == 2
        assert json.loads(capsys.readouterr().out)["error"] == "invalid_arguments"
        assert cg_main(["eval", mode_flag, "--runs-file", str(tmp_path / "runs.json"), "--json"]) == 2
        assert json.loads(capsys.readouterr().out)["error"] == "invalid_arguments"

    dir_out = tmp_path / "existing_dir"
    dir_out.mkdir()
    assert cg_main(["eval", "--platform-matrix", "--output", str(dir_out), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "unsafe_output_path"

    sym_out = tmp_path / "sym_matrix.md"
    symlink_created = False
    try:
        sym_out.symlink_to(tmp_path / "target_matrix.md")
        symlink_created = True
    except OSError:
        assert os.name == "nt"
    if symlink_created:
        assert cg_main(["eval", "--platform-matrix", "--output", str(sym_out), "--json"]) == 2
        assert json.loads(capsys.readouterr().out)["error"] == "unsafe_output_path"
