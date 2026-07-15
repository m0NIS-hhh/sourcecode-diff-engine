from __future__ import annotations

from typing import Any, Dict, List, Optional


SCHEMA_VERSION = "3.0"


def build_top_risky_file_entry(
    *,
    rel_path: str,
    language: str,
    status: str,
    risk_score: float,
    unit_count: int,
    vulnerability_type: str = "",
    change_intent: str = "",
    security_impact: str = "",
    attack_surface_impact: str = "",
    review_required: bool = False,
    evidence_status: str = "",
    module: Optional[str] = None,
) -> Dict[str, Any]:
    rel = str(rel_path or "")
    module_name = module if module is not None else (rel.split("/", 1)[0] if "/" in rel else ".")
    return {
        "rel_path": rel,
        "language": str(language or ""),
        "module": str(module_name or "."),
        "status": str(status or ""),
        "risk_score": float(risk_score or 0.0),
        "unit_count": int(unit_count or 0),
        "vulnerability_type": str(vulnerability_type or ""),
        "change_intent": str(change_intent or ""),
        "security_impact": str(security_impact or ""),
        "attack_surface_impact": str(attack_surface_impact or ""),
        "review_required": bool(review_required),
        "evidence_status": str(evidence_status or ""),
    }


def build_pair_summary(file_row: Dict[str, Any], init_report: Dict[str, Any]) -> Dict[str, Any]:
    detail = file_row.get("detail", {}) if isinstance(file_row.get("detail"), dict) else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "rel_path": str(file_row.get("rel_path", "")),
        "status": str(file_row.get("status", "")),
        "language": str(file_row.get("language", "")),
        "unit_count": int(file_row.get("unit_count", 0) or 0),
        "overview": file_row.get("overview", {}) if isinstance(file_row.get("overview"), dict) else {},
        "file_summary": detail.get("file_summary", {}) if isinstance(detail.get("file_summary"), dict) else {},
        "init_report": init_report if isinstance(init_report, dict) else {},
    }


def build_single_file_overview(
    *,
    file_summary: Dict[str, Any],
    overview: Dict[str, Any],
    top_risky_files: List[Dict[str, Any]],
    analysis_quality: str,
    quality_issues: List[str],
    total_units: int,
    analysis_profile: str = "generic",
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "single_file",
        "analysis_profile": str(analysis_profile or "generic"),
        "total_files_analyzed": 1,
        "total_units": int(total_units),
        "failed_file_count": 0,
        "by_vulnerability_type": dict(overview.get("by_vulnerability_type", {}))
        if isinstance(overview.get("by_vulnerability_type"), dict)
        else {},
        "by_change_type": dict(overview.get("by_change_type", {})) if isinstance(overview.get("by_change_type"), dict) else {},
        "high_risk_unit_count": int(overview.get("high_risk_unit_count", 0) or 0),
        "top_risky_files": list(top_risky_files),
        "analysis_quality": str(analysis_quality),
        "quality_issues": list(quality_issues),
        "file_summary": dict(file_summary) if isinstance(file_summary, dict) else {},
        "analysis_axes": dict(file_summary.get("analysis_axes", {})) if isinstance(file_summary.get("analysis_axes"), dict) else {},
    }


def build_single_file_detailed(
    *,
    rel_path: str,
    status: str,
    language: str,
    detail: Dict[str, Any],
    overview: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "single_file",
        "file": {
            "rel_path": str(rel_path),
            "status": str(status),
            "language": str(language),
            "detail": dict(detail) if isinstance(detail, dict) else {},
            "overview": dict(overview) if isinstance(overview, dict) else {},
        },
    }


def build_single_file_init_overview(
    *,
    rel_path: str,
    status: str,
    unit_count: int,
    analysis_quality: str,
    quality_issues: List[str],
    no_changes_only: bool,
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "single_file_init",
        "analysis_quality": str(analysis_quality),
        "quality_issues": list(quality_issues),
        "summary": {
            "total_units": int(unit_count),
            "analysis_quality": str(analysis_quality),
            "no_changes_only": bool(no_changes_only),
        },
        "files": [
            {
                "rel_path": str(rel_path),
                "status": str(status),
                "unit_count": int(unit_count),
                "zero_unit_reason": "identical" if bool(no_changes_only) else "",
            }
        ],
    }


def build_directory_runtime(
    *,
    max_files: int,
    max_units_per_file: int,
    workers: int,
    fail_fast: bool,
    retry_failed_files: int,
    resume: bool,
    checkpoint_file: str,
    resumed_file_count: int,
    fail_fast_triggered: bool,
    total_files_scanned: int = 0,
    selected_files: int = 0,
    skipped_files: int = 0,
    retried_files: int = 0,
    llm_request_count: int = 0,
    static_fallback_count: int = 0,
) -> Dict[str, Any]:
    return {
        "max_files": int(max_files),
        "max_units_per_file": int(max_units_per_file),
        "workers": int(workers),
        "fail_fast": bool(fail_fast),
        "retry_failed_files": max(0, int(retry_failed_files)),
        "resume": bool(resume),
        "checkpoint_file": str(checkpoint_file or ""),
        "resumed_file_count": int(resumed_file_count),
        "fail_fast_triggered": bool(fail_fast_triggered),
        "total_files_scanned": max(0, int(total_files_scanned)),
        "selected_files": max(0, int(selected_files)),
        "skipped_files": max(0, int(skipped_files)),
        "retried_files": max(0, int(retried_files)),
        "llm_request_count": max(0, int(llm_request_count)),
        "static_fallback_count": max(0, int(static_fallback_count)),
    }


def build_directory_pair_summary(
    *,
    old_file_count: int,
    new_file_count: int,
    pair_count: int,
    filtered_pair_count: int,
    filtered_out_identical_modified_count: int,
    full_pair_count: int,
) -> Dict[str, Any]:
    return {
        "old_file_count": int(old_file_count),
        "new_file_count": int(new_file_count),
        "pair_count": int(pair_count),
        "filtered_pair_count": int(filtered_pair_count),
        "filtered_out_identical_modified_count": int(filtered_out_identical_modified_count),
        "full_pair_count": int(full_pair_count),
    }


def build_directory_detailed(
    *,
    old_root: str,
    new_root: str,
    runtime: Dict[str, Any],
    pair_summary: Dict[str, Any],
    file_rows: List[Dict[str, Any]],
    failed_files: List[Dict[str, Any]],
    init_quality: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "directory",
        "old_root": str(old_root),
        "new_root": str(new_root),
        "runtime": dict(runtime),
        "pair_summary": dict(pair_summary),
        "files": list(file_rows),
        "failed_files": list(failed_files),
        "init_analysis_summary": dict(init_quality),
    }


def build_directory_overview(
    *,
    total_units: int,
    file_rows: List[Dict[str, Any]],
    failed_files: List[Dict[str, Any]],
    resumed_file_count: int,
    fail_fast_triggered: bool,
    by_vulnerability_type: Dict[str, int],
    by_change_type: Dict[str, int],
    by_language: Dict[str, Dict[str, int]],
    by_module: Dict[str, Dict[str, int]],
    top_risky_files: List[Dict[str, Any]],
    high_risk_unit_count: int,
    init_quality: Dict[str, Any],
    pair_summary: Dict[str, Any],
    runtime_metrics: Optional[Dict[str, Any]] = None,
    failure_categories: Optional[Dict[str, int]] = None,
    analysis_axes: Optional[Dict[str, Any]] = None,
    analysis_profile: str = "generic",
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "directory",
        "analysis_profile": str(analysis_profile or "generic"),
        "total_units": int(total_units),
        "total_files_analyzed": len(file_rows),
        "failed_file_count": len(failed_files),
        "resumed_file_count": int(resumed_file_count),
        "fail_fast_triggered": bool(fail_fast_triggered),
        "failure_categories": dict(failure_categories) if isinstance(failure_categories, dict) else {},
        "by_vulnerability_type": dict(by_vulnerability_type),
        "by_change_type": dict(by_change_type),
        "by_language": dict(by_language),
        "by_module": dict(by_module),
        "top_risky_files": list(top_risky_files),
        "high_risk_unit_count": int(high_risk_unit_count),
        "decode_fallback_file_count": int(init_quality.get("decode_fallback_file_count", 0) or 0),
        "decode_fallback_file_ratio": float(init_quality.get("decode_fallback_file_ratio", 0.0) or 0.0),
        "read_error_file_count": int(init_quality.get("read_error_file_count", 0) or 0),
        "pair_summary": dict(pair_summary),
        "runtime_metrics": dict(runtime_metrics) if isinstance(runtime_metrics, dict) else {},
        "analysis_quality": str(init_quality.get("analysis_quality", "unknown")),
        "quality_issues": list(init_quality.get("quality_issues", [])) if isinstance(init_quality.get("quality_issues"), list) else [],
        "init_analysis_summary": dict(init_quality),
        "analysis_axes": dict(analysis_axes) if isinstance(analysis_axes, dict) else {},
    }


def build_directory_init_overview(
    *,
    old_root: str,
    new_root: str,
    pair_summary: Dict[str, Any],
    runtime: Dict[str, Any],
    init_quality: Dict[str, Any],
    init_rows: List[Dict[str, Any]],
    analysis_profile: str = "generic",
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "directory_init",
        "analysis_profile": str(analysis_profile or "generic"),
        "old_root": str(old_root),
        "new_root": str(new_root),
        "pair_summary": dict(pair_summary),
        "runtime": dict(runtime),
        "analysis_quality": str(init_quality.get("analysis_quality", "unknown")),
        "quality_issues": list(init_quality.get("quality_issues", [])) if isinstance(init_quality.get("quality_issues"), list) else [],
        "summary": dict(init_quality),
        "files": list(init_rows),
    }


def build_review_queue_summary(
    *,
    review_score_threshold: float,
    review_top_n: int,
    high_risk_index: List[Dict[str, Any]],
    high_risk_review_queue: List[Dict[str, Any]],
    enable_llm_review_pass: bool,
    high_risk_review_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "score_threshold": round(max(0.0, min(10.0, float(review_score_threshold))), 2),
        "top_n": max(0, int(review_top_n)),
        "candidate_count": len(high_risk_index),
        "queued_count": len(high_risk_review_queue),
        "review_required_count": sum(1 for row in high_risk_review_queue if bool(row.get("review_required", False))),
        "llm_eligible_count": sum(1 for row in high_risk_review_queue if bool(row.get("llm_review_eligible", False))),
        "manual_review_count": sum(1 for row in high_risk_review_queue if str(row.get("review_kind", "")) == "manual"),
        "llm_review_pass_enabled": bool(enable_llm_review_pass),
        "llm_review_completed_count": len(high_risk_review_results),
    }


def build_run_meta(
    *,
    run_id: str,
    output_root: str,
    run_root: str,
    mode: str,
    llm_model: str,
    llm_api_style: str,
    llm_api_key_env: str,
    llm_runtime: Dict[str, Any],
    extra_fields: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    meta = {
        "schema_version": SCHEMA_VERSION,
        "run_id": str(run_id),
        "output_root": str(output_root),
        "run_root": str(run_root),
        "mode": str(mode),
        "llm_model": str(llm_model or ""),
        "llm_api_style": str(llm_api_style or ""),
        "llm_api_key_env": str(llm_api_key_env or ""),
    }
    if isinstance(llm_runtime, dict):
        for key, value in llm_runtime.items():
            meta[str(key)] = value
    if isinstance(extra_fields, dict):
        for key, value in extra_fields.items():
            meta[str(key)] = value
    return meta
