from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from source_diff_engine.app_service import (
    build_run_context,
    create_analyzer,
    ensure_llm_ready,
    make_run_id,
    resolve_effective_llm_mode,
    resolve_output_root,
    review_directory_diff,
    review_single_pair,
    summarize_run,
    verify_run,
)
from source_diff_engine.config_loader import load_config


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Source Diff Engine analysis")
    parser.add_argument("--config", default="configs/config.example.json", help="Config path")
    parser.add_argument("--data-folder", default=".", help="Base folder for relative input paths")
    parser.add_argument("--old-file", default="", help="Old file path")
    parser.add_argument("--new-file", default="", help="New file path")
    parser.add_argument("--old-root", default="", help="Old source root")
    parser.add_argument("--new-root", default="", help="New source root")
    parser.add_argument("--language", default="auto", help="Language: auto/python/java/php")
    parser.add_argument("--profile", default="", help="Analysis profile")
    parser.add_argument("--llm-mode", default="", help="LLM mode override: off|try|required")
    parser.add_argument("--skip-llm-preflight", action="store_true", help="Skip LLM preflight")
    parser.add_argument("--output-root", default="artifacts/outputs", help="Output root")
    parser.add_argument("--run-id", default="", help="Run id; generated when omitted")
    parser.add_argument("--max-files", type=int, default=0)
    parser.add_argument("--include-ext", action="append", default=[])
    parser.add_argument("--exclude-dir", action="append", default=[])
    parser.add_argument("--exclude-glob", action="append", default=[])
    parser.add_argument("--max-file-size-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--max-units-per-file", type=int, default=0)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--retry-failed-files", type=int, default=0)
    parser.add_argument("--checkpoint-file", default="")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--min-total-units", type=int, default=1)
    parser.add_argument("--max-zero-unit-ratio", type=float, default=0.95)
    parser.add_argument("--fail-on-invalid-quality", action="store_true")
    parser.add_argument("--review-score-threshold", type=float, default=7.0)
    parser.add_argument("--review-top-n", type=int, default=0)
    parser.add_argument("--enable-llm-review-pass", action="store_true")
    return parser


def run(args: argparse.Namespace) -> Dict[str, Any]:
    has_file_mode = bool(args.old_file.strip() and args.new_file.strip())
    has_dir_mode = bool(args.old_root.strip() and args.new_root.strip())
    if has_file_mode == has_dir_mode:
        raise ValueError("Provide exactly one input mode: --old-file/--new-file or --old-root/--new-root")
    cfg = load_config(args.config)
    analyzer = create_analyzer(cfg["llm"])
    profile = str(args.profile or cfg.get("analysis", {}).get("profile", "generic"))
    llm_runtime = ensure_llm_ready(
        analyzer,
        llm_mode=resolve_effective_llm_mode(
            llm_mode_override=str(args.llm_mode or ""),
            configured_llm_mode=str(cfg["llm"].get("mode", "")),
            analysis_profile=profile,
        ),
        skip_preflight=bool(args.skip_llm_preflight or cfg["llm"].get("skip_preflight", False)),
    )
    llm_runtime["analysis_profile"] = profile
    output_root = resolve_output_root(args.output_root)
    run_id = make_run_id(args.run_id)
    mode = "single_file" if has_file_mode else "directory"
    context = build_run_context(output_root=output_root, run_id=run_id, mode=mode, llm_cfg=cfg["llm"], llm_runtime=llm_runtime, extra_meta={"analysis_profile": profile})
    run_root = Path(context["run_root"])
    if has_file_mode:
        result = review_single_pair(analyzer=analyzer, data_folder=args.data_folder, old_file=args.old_file, new_file=args.new_file, language=args.language, run_root=run_root, llm_runtime=llm_runtime, run_cfg=cfg["run"], analysis_profile=profile)
    else:
        result = review_directory_diff(
            analyzer=analyzer, data_folder=args.data_folder, old_root=args.old_root, new_root=args.new_root,
            output_root=output_root, run_id=run_id, language=args.language, run_root=run_root,
            llm_cfg=cfg["llm"], llm_runtime=llm_runtime,
            max_units_per_file=args.max_units_per_file or int(cfg["run"]["max_diff_units"]), max_files=max(0, args.max_files), workers=max(1, args.workers), fail_fast=args.fail_fast,
            retry_failed_files=max(0, args.retry_failed_files), checkpoint_file=str(Path(args.checkpoint_file).resolve()) if args.checkpoint_file else str(run_root / "directory_checkpoint.json"), resume=args.resume,
            min_total_units=max(0, args.min_total_units), max_zero_unit_ratio=max(0.0, min(1.0, args.max_zero_unit_ratio)), fail_on_invalid_quality=args.fail_on_invalid_quality,
            review_score_threshold=max(0.0, min(10.0, args.review_score_threshold)), review_top_n=max(0, args.review_top_n), enable_llm_review_pass=args.enable_llm_review_pass,
            analysis_profile=profile, include_extensions=list(args.include_ext or []), exclude_dirs=list(args.exclude_dir or []), exclude_globs=list(args.exclude_glob or []), max_file_size_bytes=max(0, args.max_file_size_bytes),
        )
    verification = verify_run(run_root)
    summary = summarize_run(run_root)
    return {"ok": bool(verification.get("ok", False)) and summary.get("analysis_quality") != "invalid", "run_root": str(run_root.resolve()), "summary": summary, "verification": verification, "overview": result.get("overview", {}), "language": result.get("language", args.language), "llm_runtime": llm_runtime}


def main(argv: List[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        result = run(args)
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
