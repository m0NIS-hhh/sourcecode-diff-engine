from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

from source_diff_engine.analysis.profiles import DEFAULT_ANALYSIS_PROFILE, normalize_analysis_profile
from source_diff_engine.app_service import (
    build_run_context,
    create_analyzer,
    doctor as doctor_service,
    ensure_llm_ready,
    make_run_id,
    resolve_effective_llm_mode,
    resolve_output_root,
    review_directory_diff,
    review_single_pair,
    smoke as smoke_service,
)
from source_diff_engine.config_loader import load_config
from source_diff_engine.logger_config import get_logger

logger = get_logger(__name__)


def _print_json(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _build_common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", default="config.json", type=str, help="Config file path")
    parser.add_argument("--llm-mode", type=str, default="", help="LLM mode override: off|try|required")
    parser.add_argument("--skip-llm-preflight", action="store_true", help="Skip LLM preflight and attempt live requests directly")
    parser.add_argument("--profile", type=str, default="", help="Analysis profile override")
    return parser


def _add_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("data_folder", type=str, help="Input folder")
    parser.add_argument("--old_file", type=str, default="", help="Old file path (relative to data_folder or absolute)")
    parser.add_argument("--new_file", type=str, default="", help="New file path (relative to data_folder or absolute)")
    parser.add_argument("--old_root", type=str, default="", help="Old source root for directory mode")
    parser.add_argument("--new_root", type=str, default="", help="New source root for directory mode")
    parser.add_argument("--language", default="auto", type=str, help="Language (python/java/php/auto)")
    parser.add_argument("--max-files", type=int, default=0, help="Max files to analyze in directory mode (0=all)")
    parser.add_argument("--include-ext", action="append", default=[], help="Directory mode included extension, e.g. .py. Repeatable.")
    parser.add_argument("--exclude-dir", action="append", default=[], help="Directory mode excluded directory name. Repeatable.")
    parser.add_argument("--exclude-glob", action="append", default=[], help="Directory mode excluded glob. Repeatable.")
    parser.add_argument("--max-file-size-bytes", type=int, default=1024 * 1024, help="Directory mode max file size before skipping (0=disabled)")
    parser.add_argument(
        "--max-units-per-file",
        type=int,
        default=0,
        help="Max diff units analyzed per file in directory mode (0=use config/run.max_diff_units)",
    )
    parser.add_argument("--workers", type=int, default=1, help="Worker threads for directory mode")
    parser.add_argument("--fail-fast", action="store_true", help="Stop directory run on first failed file")
    parser.add_argument("--retry-failed-files", type=int, default=0, help="Retry count for failed files in directory mode")
    parser.add_argument(
        "--checkpoint-file",
        type=str,
        default="",
        help="Checkpoint file path for directory mode (default: <output-root>/<run-id>/directory_checkpoint.json)",
    )
    parser.add_argument("--resume", action="store_true", help="Resume directory mode from checkpoint")
    parser.add_argument("--output-root", type=str, default="artifacts/outputs", help="Output root directory")
    parser.add_argument("--run-id", type=str, default="", help="Run id for output subdirectory")
    parser.add_argument("--min-total-units", type=int, default=1, help="Minimum total diff units expected for init quality gate")
    parser.add_argument("--max-zero-unit-ratio", type=float, default=0.95, help="Maximum allowed ratio of modified files with 0 parsed units")
    parser.add_argument("--fail-on-invalid-quality", action="store_true", help="Fail directory mode when init quality gate is invalid")
    parser.add_argument("--review-score-threshold", type=float, default=7.0, help="Score threshold for exporting high-risk review queue entries")
    parser.add_argument("--review-top-n", type=int, default=0, help="Optional cap for exported high-risk review queue entries (0=all)")
    parser.add_argument(
        "--enable-llm-review-pass",
        action="store_true",
        help="Run an extra LLM review pass for queued high-risk directory units when LLM is enabled",
    )


def _build_analyzer_from_config(
    config: Dict[str, Any],
    *,
    llm_mode_override: str = "",
    skip_preflight_override: bool = False,
    profile_override: str = "",
) -> tuple[Any, Dict[str, Any]]:
    llm_cfg = config["llm"]
    analyzer = create_analyzer(llm_cfg)
    profile = normalize_analysis_profile(profile_override or config.get("analysis", {}).get("profile", DEFAULT_ANALYSIS_PROFILE))
    llm_runtime = ensure_llm_ready(
        analyzer,
        llm_mode=resolve_effective_llm_mode(
            llm_mode_override=str(llm_mode_override or ""),
            configured_llm_mode=str(llm_cfg.get("mode", "")),
            analysis_profile=profile,
        ),
        skip_preflight=bool(skip_preflight_override or llm_cfg.get("skip_preflight", False)),
    )
    llm_runtime["analysis_profile"] = profile
    return analyzer, llm_runtime


def _run_file_mode(args: argparse.Namespace, cfg: Dict[str, Any], analyzer: Any, llm_runtime: Dict[str, Any]) -> Dict[str, Any]:
    run_id = make_run_id(args.run_id)
    output_root = resolve_output_root(args.output_root)
    run_context = build_run_context(
        output_root=output_root,
        run_id=run_id,
        mode="single_file",
        llm_cfg=cfg["llm"],
        llm_runtime=llm_runtime,
        extra_meta={"analysis_profile": llm_runtime.get("analysis_profile", cfg.get("analysis", {}).get("profile", DEFAULT_ANALYSIS_PROFILE))},
    )
    run_root = Path(run_context["run_root"])
    result = review_single_pair(
        analyzer=analyzer,
        data_folder=args.data_folder,
        old_file=args.old_file,
        new_file=args.new_file,
        language=args.language,
        run_root=run_root,
        llm_runtime=llm_runtime,
        run_cfg=cfg["run"],
        analysis_profile=str(llm_runtime.get("analysis_profile", cfg.get("analysis", {}).get("profile", DEFAULT_ANALYSIS_PROFILE))),
    )
    return result


def _run_directory_mode(args: argparse.Namespace, cfg: Dict[str, Any], analyzer: Any, llm_runtime: Dict[str, Any]) -> Dict[str, Any]:
    run_id = make_run_id(args.run_id)
    output_root = resolve_output_root(args.output_root)
    run_context = build_run_context(
        output_root=output_root,
        run_id=run_id,
        mode="directory",
        llm_cfg=cfg["llm"],
        llm_runtime=llm_runtime,
        extra_meta={"analysis_profile": llm_runtime.get("analysis_profile", cfg.get("analysis", {}).get("profile", DEFAULT_ANALYSIS_PROFILE))},
    )
    run_root = Path(run_context["run_root"])
    result = review_directory_diff(
        analyzer=analyzer,
        data_folder=args.data_folder,
        old_root=args.old_root,
        new_root=args.new_root,
        output_root=output_root,
        run_id=run_id,
        language=args.language,
        run_root=run_root,
        llm_cfg=cfg["llm"],
        llm_runtime=llm_runtime,
        max_units_per_file=(int(args.max_units_per_file) if int(args.max_units_per_file) > 0 else int(cfg["run"]["max_diff_units"])),
        max_files=int(args.max_files),
        workers=max(1, int(args.workers)),
        fail_fast=bool(args.fail_fast),
        retry_failed_files=max(0, int(args.retry_failed_files)),
        checkpoint_file=(str(Path(args.checkpoint_file).resolve()) if (args.checkpoint_file or "").strip() else str(run_root / "directory_checkpoint.json")),
        resume=bool(args.resume),
        min_total_units=max(0, int(args.min_total_units)),
        max_zero_unit_ratio=max(0.0, min(1.0, float(args.max_zero_unit_ratio))),
        fail_on_invalid_quality=bool(args.fail_on_invalid_quality),
        review_score_threshold=max(0.0, min(10.0, float(args.review_score_threshold))),
        review_top_n=max(0, int(args.review_top_n)),
        enable_llm_review_pass=bool(args.enable_llm_review_pass),
        analysis_profile=str(llm_runtime.get("analysis_profile", cfg.get("analysis", {}).get("profile", DEFAULT_ANALYSIS_PROFILE))),
        include_extensions=list(args.include_ext or []),
        exclude_dirs=list(args.exclude_dir or []),
        exclude_globs=list(args.exclude_glob or []),
        max_file_size_bytes=max(0, int(args.max_file_size_bytes)),
    )
    return result


def _handle_run(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    analyzer, llm_runtime = _build_analyzer_from_config(
        cfg,
        llm_mode_override=str(args.llm_mode or ""),
        skip_preflight_override=bool(args.skip_llm_preflight),
        profile_override=str(args.profile or ""),
    )
    has_file_mode = bool((args.old_file or "").strip() and (args.new_file or "").strip())
    has_dir_mode = bool((args.old_root or "").strip() and (args.new_root or "").strip())
    if has_file_mode and has_dir_mode:
        raise ValueError("Use either file mode (--old_file/--new_file) or directory mode (--old_root/--new_root).")
    if not has_file_mode and not has_dir_mode:
        raise ValueError("Missing input: provide file mode or directory mode arguments.")

    if has_dir_mode:
        result = _run_directory_mode(args, cfg, analyzer, llm_runtime)
        logger.info("directory analysis done: %d unit rows", len(result.get("concise_rows", [])))
        logger.info("run_root=%s llm_enabled=%s analysis_quality=%s", result["run_root"], llm_runtime["llm_enabled"], result["overview"]["analysis_quality"])
        _print_json(
            {
                "run_root": result["run_root"],
                "language": args.language,
                "llm_enabled": bool(llm_runtime.get("llm_enabled", False)),
                "analysis_quality": result["overview"].get("analysis_quality", "unknown"),
            }
        )
        return 0

    result = _run_file_mode(args, cfg, analyzer, llm_runtime)
    logger.info("analysis done: %d results", len(result.get("concise_rows", [])))
    logger.info("run_root=%s llm_enabled=%s analysis_quality=%s", result["run_root"], llm_runtime["llm_enabled"], result["overview"]["analysis_quality"])
    _print_json(
        {
            "run_root": result["run_root"],
            "language": result["language"],
            "llm_enabled": bool(llm_runtime.get("llm_enabled", False)),
            "analysis_quality": result["overview"].get("analysis_quality", "unknown"),
        }
    )
    return 0


def _handle_doctor(args: argparse.Namespace) -> int:
    report = doctor_service(
        config_path=args.config,
        output_root=args.output_root,
        smoke_output_root=args.smoke_output_root,
        llm_mode=args.llm_mode,
        skip_llm_preflight=args.skip_llm_preflight,
        analysis_profile=str(args.profile or ""),
    )
    _print_json(report)
    return 0 if report.get("ok", False) else 1


def _handle_smoke(args: argparse.Namespace) -> int:
    report = smoke_service(
        config_path=args.config,
        output_root=args.output_root,
        run_id=args.run_id,
        language=args.language,
        llm_mode=args.llm_mode,
        skip_llm_preflight=args.skip_llm_preflight,
        analysis_profile=str(args.profile or ""),
    )
    _print_json(report)
    return 0 if report.get("ok", False) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Source diff engine CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", parents=[_build_common_parser()], help="Analyze a file pair or directory diff")
    _add_run_arguments(run_parser)
    run_parser.set_defaults(func=_handle_run)

    doctor_parser = subparsers.add_parser("doctor", parents=[_build_common_parser()], help="Check runtime and engine prerequisites")
    doctor_parser.add_argument("--output-root", type=str, default="artifacts/outputs", help="Output root directory")
    doctor_parser.add_argument("--smoke-output-root", type=str, default="", help="Optional output root for the built-in smoke run")
    doctor_parser.set_defaults(func=_handle_doctor)

    smoke_parser = subparsers.add_parser("smoke", parents=[_build_common_parser()], help="Run a deterministic end-to-end smoke test")
    smoke_parser.add_argument("--output-root", type=str, default="artifacts/outputs", help="Output root directory")
    smoke_parser.add_argument("--run-id", type=str, default="smoke", help="Run id for output subdirectory")
    smoke_parser.add_argument("--language", type=str, default="auto", help="Language (python/java/php/auto)")
    smoke_parser.set_defaults(func=_handle_smoke)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
