from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure the repository root is importable when the script is executed directly.
ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from source_diff_engine.app_service import create_analyzer, ensure_llm_ready
from source_diff_engine.config_loader import load_config
from source_diff_engine.directory.runner import review_existing_directory_run


def main() -> int:
    parser = argparse.ArgumentParser(description="Run LLM review pass for an existing directory-analysis run")
    parser.add_argument("run_root", type=str, help="Path to an existing <output-dir>/<run-id>")
    parser.add_argument("--config", default="configs/config.example.json", type=str, help="Config file path")
    parser.add_argument("--review-score-threshold", type=float, default=None, help="Optional score threshold override")
    parser.add_argument("--review-top-n", type=int, default=None, help="Optional top-N override")
    parser.add_argument("--resume", action="store_true", help="Resume from high_risk_review_checkpoint.json if present")
    args = parser.parse_args()

    cfg = load_config(args.config)
    llm_cfg = cfg["llm"]
    analyzer = create_analyzer(llm_cfg)
    llm_runtime = ensure_llm_ready(
        analyzer,
        llm_mode=str(llm_cfg.get("mode", "try")),
        skip_preflight=bool(llm_cfg.get("skip_preflight", False)),
    )
    if not bool(llm_runtime.get("llm_enabled", False)):
        raise RuntimeError(f"LLM unavailable for review pass: {llm_runtime.get('llm_fallback_reason', 'unknown')}")

    report = review_existing_directory_run(
        analyzer=analyzer,
        run_root=args.run_root,
        review_score_threshold=args.review_score_threshold,
        review_top_n=args.review_top_n,
        resume=bool(args.resume),
    )
    summary_path = Path(args.run_root) / "high_risk_review_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
    print(
        json.dumps(
            {
                "run_root": report["run_root"],
                "completed_count": len(report.get("results", [])),
                "summary": summary,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
