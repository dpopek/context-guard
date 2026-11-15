"""Optional third-party CLI and document integrations for Context-Guard."""

from __future__ import annotations

from integrations.atlassian_twg import (
    TWG_STDOUT_FILENAMES,
    TWG_STDOUT_OUTLINE_MIN_BYTES,
    extract_adf_plain_text,
    prepare_twg_stdout_outline,
    rewrite_twg_cli_command,
    unwrap_and_outline_twg_stdout,
)

__all__ = [
    "TWG_STDOUT_FILENAMES",
    "TWG_STDOUT_OUTLINE_MIN_BYTES",
    "extract_adf_plain_text",
    "prepare_twg_stdout_outline",
    "rewrite_twg_cli_command",
    "unwrap_and_outline_twg_stdout",
]
