from __future__ import annotations

import os
from pathlib import Path
from time import time_ns


_REPO_ROOT = Path(__file__).resolve().parent
_PYTEST_TEMP_ROOT = (_REPO_ROOT / ".tmp" / "pytest-runtime").resolve()
_PYTEST_TEMP_ROOT.mkdir(parents=True, exist_ok=True)

for _env_name in ("TMPDIR", "TEMP", "TMP"):
    os.environ.setdefault(_env_name, str(_PYTEST_TEMP_ROOT))


def pytest_configure(config) -> None:
    if getattr(config.option, "basetemp", None):
        return
    config.option.basetemp = str(_PYTEST_TEMP_ROOT / f"basetemp-{os.getpid()}-{time_ns()}")
