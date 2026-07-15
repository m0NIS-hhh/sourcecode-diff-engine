from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app_service import (  # noqa: E402
    build_run_context,
    make_run_id,
    resolve_output_root,
    review_directory_diff,
    review_single_pair,
    verify_run,
)
from config_loader import load_config  # noqa: E402
from output_writer import write_json_atomic  # noqa: E402
from main import _build_analyzer_from_config  # noqa: E402


def _load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
    return default


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def build_codex_summary(run_root: Path, verification: Dict[str, Any]) -> Dict[str, Any]:
    summary = _load_json(run_root / "summary.json", {})
    overview = _load_json(run_root / "overview.json", {})
    high_risk = _as_list(_load_json(run_root / "high_risk_index.json", []))
    failed_pairs = _as_list(_load_json(run_root / "failed_pairs.json", []))
    meta = _load_json(run_root / "meta.json", {})

    top_findings = []
    for item in high_risk[:10]:
        if not isinstance(item, dict):
            continue
        top_findings.append(
            {
                "rel_path": str(item.get("rel_path", "")),
                "unit_index": int(item.get("unit_index", 0) or 0),
                "artifact": str(item.get("artifact", "")),
                "risk_score": float(item.get("risk_score", item.get("primary_score", 0.0)) or 0.0),
                "vulnerability_type": str(item.get("vulnerability_type", "")),
                "change_type": str(item.get("change_type", "")),
                "review_required": bool(item.get("review_required", False)),
                "evidence_status": str(item.get("evidence_status", "")),
            }
        )

    artifact_paths = {
        "run_root": str(run_root.resolve()),
        "summary_json": str((run_root / "summary.json").resolve()),
        "summary_md": str((run_root / "summary.md").resolve()),
        "overview_json": str((run_root / "overview.json").resolve()),
        "high_risk_index_json": str((run_root / "high_risk_index.json").resolve()),
        "failed_pairs_json": str((run_root / "failed_pairs.json").resolve()),
        "codex_summary_json": str((run_root / "codex_summary.json").resolve()),
    }

    return {
        "ok": bool(verification.get("ok", False)) and str(summary.get("analysis_quality", "unknown")) != "invalid",
        "schema_version": str(summary.get("schema_version", overview.get("schema_version", ""))),
        "mode": str(summary.get("mode", meta.get("mode", ""))),
        "analysis_profile": str(summary.get("analysis_profile", overview.get("analysis_profile", ""))),
        "analysis_quality": str(summary.get("analysis_quality", overview.get("analysis_quality", "unknown"))),
        "llm_enabled": bool(summary.get("llm_enabled", meta.get("llm_enabled", False))),
        "llm_preflight": str(summary.get("llm_preflight", meta.get("llm_preflight", ""))),
        "total_files_analyzed": int(summary.get("total_files_analyzed", overview.get("total_files_analyzed", 0)) or 0),
        "total_units": int(summary.get("total_units", overview.get("total_units", 0)) or 0),
        "failed_file_count": int(summary.get("failed_file_count", overview.get("failed_file_count", 0)) or 0),
        "skipped_file_count": int(summary.get("skipped_file_count", overview.get("skipped_file_count", 0)) or 0),
        "high_risk_unit_count": int(summary.get("high_risk_unit_count", overview.get("high_risk_unit_count", 0)) or 0),
        "quality_issues": _as_list(summary.get("quality_issues", overview.get("quality_issues", []))),
        "verification": verification,
        "top_findings": top_findings,
        "failed_pairs": failed_pairs[:20],
        "artifact_paths": artifact_paths,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Source Diff Engine with skill-friendly JSON output")
    parser.add_argument("--config", default="config.json.example", help="Config path")
    parser.add_argument("--data-folder", default=".", help="Base folder for relative input paths")
    parser.add_argument("--old-file", default="", help="Old file path")
    parser.add_argument("--new-file", default="", help="New file path")
    parser.add_argument("--old-root", default="", help="Old source root")
    parser.add_argument("--new-root", default="", help="New source root")
    parser.add_argument("--language", default="auto", help="Language: auto/python/java/php")
    parser.add_argument("--profile", default="security", help="Analysis profile")
    parser.add_argument("--llm-mode", default="", help="LLM mode override: off|try|required")
    parser.add_argument("--skip-llm-preflight", action="store_true", help="Skip LLM preflight")
    parser.add_argument("--output-root", default="artifacts/skill_runs", help="Output root")
    parser.add_argument("--run-id", default="", help="Run id; generated when omitted")
    parser.add_argument("--max-files", type=int, default=0, help="Directory mode max files")
    parser.add_argument("--include-ext", action="append", default=[], help="Directory mode included extension, e.g. .py. Repeatable.")
    parser.add_argument("--exclude-dir", action="append", default=[], help="Directory mode excluded directory name. Repeatable.")
    parser.add_argument("--exclude-glob", action="append", default=[], help="Directory mode excluded glob. Repeatable.")
    parser.add_argument("--max-file-size-bytes", type=int, default=1024 * 1024, help="Directory mode max file size before skipping (0=disabled)")
    parser.add_argument("--max-units-per-file", type=int, default=0, help="Directory mode max units per file")
    parser.add_argument("--workers", type=int, default=1, help="Directory mode worker count")
    parser.add_argument("--review-score-threshold", type=float, default=7.0, help="High-risk queue threshold")
    parser.add_argument("--review-top-n", type=int, default=0, help="High-risk queue cap")
    parser.add_argument("--enable-llm-review-pass", action="store_true", help="Run extra LLM review pass for high-risk directory units")
    return parser


def run(args: argparse.Namespace) -> Dict[str, Any]:
    has_file_mode = bool(args.old_file.strip() and args.new_file.strip())
    has_dir_mode = bool(args.old_root.strip() and args.new_root.strip())
    if has_file_mode == has_dir_mode:
        raise ValueError("Provide exactly one input mode: --old-file/--new-file or --old-root/--new-root")

    cfg = load_config(args.config)
    analyzer, llm_runtime = _build_analyzer_from_config(
        cfg,
        llm_mode_override=str(args.llm_mode or ""),
        skip_preflight_override=bool(args.skip_llm_preflight),
        profile_override=str(args.profile or ""),
    )
    profile = str(llm_runtime.get("analysis_profile", args.profile or "security"))
    output_root = resolve_output_root(args.output_root)
    run_id = make_run_id(args.run_id or f"skill_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    if has_file_mode:
        run_context = build_run_context(
            output_root=output_root,
            run_id=run_id,
            mode="single_file",
            llm_cfg=cfg["llm"],
            llm_runtime=llm_runtime,
            extra_meta={"analysis_profile": profile, "skill_wrapper": True},
        )
        result = review_single_pair(
            analyzer=analyzer,
            data_folder=args.data_folder,
            old_file=args.old_file,
            new_file=args.new_file,
            language=args.language,
            run_root=Path(run_context["run_root"]),
            llm_runtime=llm_runtime,
            run_cfg=cfg["run"],
            analysis_profile=profile,
        )
    else:
        run_id = make_run_id(run_id)
        output_root = resolve_output_root(args.output_root)
        run_context = build_run_context(
            output_root=output_root,
            run_id=run_id,
            mode="directory",
            llm_cfg=cfg["llm"],
            llm_runtime=llm_runtime,
            extra_meta={"analysis_profile": profile, "skill_wrapper": True},
        )
        result = review_directory_diff(
            analyzer=analyzer,
            data_folder=args.data_folder,
            old_root=args.old_root,
            new_root=args.new_root,
            output_root=output_root,
            run_id=run_id,
            language=args.language,
            run_root=Path(run_context["run_root"]),
            llm_cfg=cfg["llm"],
            llm_runtime=llm_runtime,
            max_units_per_file=(int(args.max_units_per_file) if int(args.max_units_per_file) > 0 else int(cfg["run"]["max_diff_units"])),
            max_files=max(0, int(args.max_files)),
            workers=max(1, int(args.workers)),
            fail_fast=False,
            retry_failed_files=0,
            checkpoint_file=str(Path(run_context["run_root"]) / "directory_checkpoint.json"),
            resume=False,
            min_total_units=1,
            max_zero_unit_ratio=0.95,
            fail_on_invalid_quality=False,
            review_score_threshold=max(0.0, min(10.0, float(args.review_score_threshold))),
            review_top_n=max(0, int(args.review_top_n)),
            enable_llm_review_pass=bool(args.enable_llm_review_pass),
            analysis_profile=profile,
            include_extensions=list(args.include_ext or []),
            exclude_dirs=list(args.exclude_dir or []),
            exclude_globs=list(args.exclude_glob or []),
            max_file_size_bytes=max(0, int(args.max_file_size_bytes)),
        )

    run_root = Path(result["run_root"])
    verification = verify_run(run_root)
    codex_summary = build_codex_summary(run_root, verification)
    write_json_atomic(run_root / "codex_summary.json", codex_summary)
    return codex_summary


def main(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
