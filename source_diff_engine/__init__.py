"""Uninstalled-source bridge for the package stored under ``src/``.

This bridge keeps ``python -m source_diff_engine.main`` usable from a
checkout without adding compatibility modules for individual implementation
files. Installed environments use the normal package discovered by
setuptools.
"""

from __future__ import annotations

from pathlib import Path


_SRC_PACKAGE = Path(__file__).resolve().parents[1] / "src" / "source_diff_engine"
__path__ = [str(_SRC_PACKAGE)]
