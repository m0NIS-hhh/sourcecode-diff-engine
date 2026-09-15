from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from source_diff_engine.output.consistency import verify_run


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify run-level and pair-level output consistency")
    parser.add_argument("run_root", type=str, help="Path to <output-dir>/<run-id>")
    args = parser.parse_args()

    report = verify_run(Path(args.run_root))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
