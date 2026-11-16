"""Tests for spool workspace identity resolution, isolation config, and domain separation."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re

from spool.receipts import (
    compute_scope_key,
    compute_scoped_spool_id,
    read_spool_isolation_config,
    resolve_workspace_identity,
)


def test_resolve_workspace_identity_git_root_worktree_home_anchor_template_and_multi_root(
    tmp_path: Path,
) -> None:
    """Resolve .git dirs/worktree files to canonical root and reject anchors, home, templates, or multi-roots."""
    repo = tmp_path / "repo_alpha"
    sub = repo / "src" / "pkg"
    sub.mkdir(parents=True)
    (repo / ".git").mkdir()

    ws_id_root, canon_root, err_root = resolve_workspace_identity(repo)
    ws_id_sub, canon_sub, err_sub = resolve_workspace_identity(sub)
    assert err_root is None and err_sub is None
    expected_canon = os.path.realpath(str(repo))
    expected_id = "ws_" + hashlib.sha256(
        f"cg-ws-v1:{os.path.normcase(expected_canon)}".encode("utf-8")
    ).hexdigest()[:16]
    assert canon_root == expected_canon
    assert canon_sub == expected_canon
    assert ws_id_root == expected_id
    assert ws_id_sub == expected_id
    assert re.fullmatch(r"^ws_[0-9a-f]{16}$", ws_id_root)

    # .git worktree file (not a directory) also marks a workspace root
    wt_root = tmp_path / "wt_beta"
    wt_sub = wt_root / "nested"
    wt_sub.mkdir(parents=True)
    (wt_root / ".git").write_text("gitdir: ../repo_alpha/.git/worktrees/wt_beta\n", encoding="utf-8")
    wt_id, wt_canon, wt_err = resolve_workspace_identity(wt_sub)
    assert wt_err is None
    assert wt_canon == os.path.realpath(str(wt_root))
    assert wt_id != ws_id_root

    # Non-marker directory falls back to realpath(dir)
    plain = tmp_path / "plain_dir"
    plain.mkdir()
    plain_id, plain_canon, plain_err = resolve_workspace_identity(plain)
    assert plain_err is None
    assert plain_canon == os.path.realpath(str(plain))
    assert re.fullmatch(r"^ws_[0-9a-f]{16}$", plain_id)

    # file:// URI decoding (including %20 space)
    spaced = tmp_path / "my project"
    spaced.mkdir()
    uri = spaced.as_uri()
    uri_id, uri_canon, uri_err = resolve_workspace_identity(uri)
    assert uri_err is None
    assert uri_canon == os.path.realpath(str(spaced))
    assert re.fullmatch(r"^ws_[0-9a-f]{16}$", uri_id)

    # Invalid / unresolved inputs fail closed
    anchor = Path(os.path.realpath(str(tmp_path))).anchor
    for bad in ("", "   ", "${workspaceFolder}", "relative/path", anchor, str(Path.home()), str(tmp_path / "missing")):
        bid, bcanon, berr = resolve_workspace_identity(bad)
        assert (bid, bcanon, berr) == ("", "", "workspace_unresolved")

    # Multi-root without narrowing cwd -> workspace_ambiguous; cwd inside one root narrows cleanly
    amb_id, amb_canon, amb_err = resolve_workspace_identity(
        None, workspace_roots=[repo.as_uri(), wt_root.as_uri()]
    )
    assert (amb_id, amb_canon, amb_err) == ("", "", "workspace_ambiguous")

    nar_id, nar_canon, nar_err = resolve_workspace_identity(
        sub, workspace_roots=[repo.as_uri(), wt_root.as_uri()]
    )
    assert nar_err is None
    assert nar_canon == expected_canon
    assert nar_id == expected_id


def test_read_spool_isolation_config_defaults_and_rejects_invalid_values(tmp_path: Path) -> None:
    """Default to workspace, accept session/global, reject invalid spool shapes, fail open on bad JSON."""
    assert read_spool_isolation_config(tmp_path / "absent.json") == ("workspace", None)

    for mode in ("workspace", "session", "global"):
        cfg = tmp_path / f"{mode}.json"
        cfg.write_text(f'{{"spool": {{"isolation": "{mode}"}}}}', encoding="utf-8")
        assert read_spool_isolation_config(cfg) == (mode, None)

    no_spool = tmp_path / "no_spool.json"
    no_spool.write_text('{"read_confirm_policy": "strict"}', encoding="utf-8")
    assert read_spool_isolation_config(no_spool) == ("workspace", None)

    bad_shape = tmp_path / "bad_shape.json"
    bad_shape.write_text('{"spool": "bad"}', encoding="utf-8")
    assert read_spool_isolation_config(bad_shape) == ("", "invalid_spool_config")

    bad_mode = tmp_path / "bad_mode.json"
    bad_mode.write_text('{"spool": {"isolation": "tenant"}}', encoding="utf-8")
    assert read_spool_isolation_config(bad_mode) == ("", "invalid_spool_config")

    corrupt_json = tmp_path / "corrupt.json"
    corrupt_json.write_text("{not valid json", encoding="utf-8")
    assert read_spool_isolation_config(corrupt_json) == ("workspace", None)


def test_compute_scoped_spool_id_separates_domains() -> None:
    """Produce valid sp_<12hex> IDs isolated across workspace, session, and global domains."""
    sha = "a" * 64
    k_a, e_a = compute_scope_key("workspace", workspace_id="ws_1111111111111111")
    k_b, e_b = compute_scope_key("workspace", workspace_id="ws_2222222222222222")
    k_s, e_s = compute_scope_key("session", session_id="sess-1")
    k_g, e_g = compute_scope_key("global")
    assert (e_a, e_b, e_s, e_g) == (None, None, None, None)

    ids = [
        compute_scoped_spool_id(k_a, sha),
        compute_scoped_spool_id(k_b, sha),
        compute_scoped_spool_id(k_s, sha),
        compute_scoped_spool_id(k_g, sha),
    ]
    assert all(re.fullmatch(r"^sp_[0-9a-f]{12}$", sid) for sid in ids)
    assert len(set(ids)) == 4
    assert compute_scope_key("workspace", workspace_id="") == ("", "workspace_unresolved")
    assert compute_scope_key("session", session_id="") == ("", "session_unresolved")
