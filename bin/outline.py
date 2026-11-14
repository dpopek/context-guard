#!/usr/bin/env python3
"""Command-line entry point for the structural outline generator in `hooks/outline.py`."""

from __future__ import annotations

import sys
from pathlib import Path

_PLUGIN_ROOT = str(Path(__file__).resolve().parent.parent)
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

from hooks.outline import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
