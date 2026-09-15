from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from source_diff_engine.output.schema import SCHEMA_VERSION
from source_diff_engine.pipeline.results import normalize_evidence

HIGH_RISK_UNIT_THRESHOLD = 7.0


_INVALID_WIN_CHARS = re.compile(r'[<>:"|?*\x00-\x1F]')


def normalize_run_id(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    text = text.replace("\\", "_").replace("/", "_")
    text = _INVALID_WIN_CHARS.sub("_", text)
    return text.strip(" .") or "run"


def sanitize_rel_path(rel_path: str) -> str:
    parts = [p for p in str(rel_path or "").replace("\\", "/").split("/") if p]
    safe_parts = []
    for part in parts:
        name = _INVALID_WIN_CHARS.sub("_", part).strip(" .")
        safe_parts.append(name or "_")
    return "/".join(safe_parts) if safe_parts else "_"


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def build_high_risk_index_entries(
    *,
    rel_path: str,
    status: str,
    language: str,
    concise_rows: List[Dict[str, Any]],
    units: List[Dict[str, Any]],
    score_threshold: float = HIGH_RISK_UNIT_THRESHOLD,
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for unit_index, row in enumerate(concise_rows):
        try:
            score = float(row.get("primary_score", row.get("analysis_score", row.get("vulnerability_score", 0.0))))
        except Exception:
            score = 0.0
        if score < float(score_threshold):
            continue
        unit_detail = units[unit_index] if unit_index < len(units) and isinstance(units[unit_index], dict) else {}
        unit_meta = unit_detail.get("unit", {}) if isinstance(unit_detail.get("unit"), dict) else {}
        entries.append(
            {
                "rel_path": str(rel_path),
                "status": str(status),
                "language": str(language),
                "unit_index": unit_index,
                "old_unit": unit_meta.get("old_unit"),
                "new_unit": unit_meta.get("new_unit"),
                "artifact": unit_meta.get("artifact", ""),
                "file_path": unit_meta.get("file_path", ""),
                "hunk_header": unit_meta.get("hunk_header", ""),
                "old_line_range": unit_meta.get("old_line_range", [0, 0]),
                "new_line_range": unit_meta.get("new_line_range", [0, 0]),
                "old_focus_line_range": unit_meta.get("old_focus_line_range", unit_meta.get("old_line_range", [0, 0])),
                "new_focus_line_range": unit_meta.get("new_focus_line_range", unit_meta.get("new_line_range", [0, 0])),
                "old_enclosing_symbol": str(
                    ((unit_meta.get("old_symbol_context", {}) or {}).get("display", "")) if isinstance(unit_meta.get("old_symbol_context"), dict) else ""
                ),
                "new_enclosing_symbol": str(
                    ((unit_meta.get("new_symbol_context", {}) or {}).get("display", "")) if isinstance(unit_meta.get("new_symbol_context"), dict) else ""
                ),
                "risk_score": round(score, 2),
                "change_type": str(row.get("change_type", "")),
                "change_intent": str(row.get("change_intent", "")),
                "vulnerability_type": str(row.get("vulnerability_type", "")),
                "analysis_score": float(row.get("analysis_score", row.get("vulnerability_score", 0.0)) or 0.0),
                "primary_score": float(row.get("primary_score", row.get("analysis_score", row.get("vulnerability_score", 0.0))) or 0.0),
                "security_impact": str(row.get("security_impact", "")),
                "attack_surface_impact": str(row.get("attack_surface_impact", "")),
                "review_required": bool(row.get("review_required", False)),
                "evidence_status": str(normalize_evidence(row.get("evidence", {})).get("convenience_summary", {}).get("evidence_status", "")),
            }
        )
    return entries


def build_run_summary(
    *,
    mode: str,
    run_root: str,
    llm_runtime: Dict[str, Any],
    overview: Dict[str, Any],
    top_risky_files: List[Dict[str, Any]],
) -> Dict[str, Any]:
    analysis_profile = str(overview.get("analysis_profile", llm_runtime.get("analysis_profile", "generic")) or "generic")
    summary: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "mode": str(mode),
        "run_root": str(run_root),
        "analysis_profile": analysis_profile,
        "llm_enabled": bool(llm_runtime.get("llm_enabled", False)),
        "llm_preflight": str(llm_runtime.get("llm_preflight", "")),
        "llm_error_category": str(llm_runtime.get("llm_error_category", "")),
        "llm_request_count": max(0, int(llm_runtime.get("llm_request_count", 0) or 0)),
        "llm_preflight_request_count": max(0, int(llm_runtime.get("llm_preflight_request_count", 0) or 0)),
        "llm_analysis_request_count": max(0, int(llm_runtime.get("llm_analysis_request_count", 0) or 0)),
        "llm_source_review_request_count": max(0, int(llm_runtime.get("llm_source_review_request_count", 0) or 0)),
        "llm_review_pass_request_count": max(0, int(llm_runtime.get("llm_review_pass_request_count", 0) or 0)),
        "llm_retry_count": max(0, int(llm_runtime.get("llm_retry_count", 0) or 0)),
        "llm_failure_categories": dict(llm_runtime.get("llm_failure_categories", {}))
        if isinstance(llm_runtime.get("llm_failure_categories"), dict)
        else {},
        "static_fallback_count": max(0, int(llm_runtime.get("static_fallback_count", 0) or 0)),
        "analysis_quality": str(overview.get("analysis_quality", "unknown")),
        "quality_issues": list(overview.get("quality_issues", [])) if isinstance(overview.get("quality_issues"), list) else [],
        "total_files_analyzed": int(overview.get("total_files_analyzed", 0) or 0),
        "total_units": int(overview.get("total_units", 0) or 0),
        "failed_file_count": int(overview.get("failed_file_count", 0) or 0),
        "high_risk_unit_count": int(overview.get("high_risk_unit_count", 0) or 0),
        "decode_fallback_file_count": int(overview.get("decode_fallback_file_count", 0) or 0),
        "decode_fallback_file_ratio": float(overview.get("decode_fallback_file_ratio", 0.0) or 0.0),
        "read_error_file_count": int(overview.get("read_error_file_count", 0) or 0),
        "skipped_file_count": int(overview.get("skipped_file_count", 0) or 0),
        "not_executed_file_count": int(overview.get("not_executed_file_count", 0) or 0),
        "skipped_by_reason": dict(overview.get("skipped_by_reason", {})) if isinstance(overview.get("skipped_by_reason"), dict) else {},
        "by_vulnerability_type": dict(overview.get("by_vulnerability_type", {}))
        if isinstance(overview.get("by_vulnerability_type"), dict)
        else {},
        "by_change_type": dict(overview.get("by_change_type", {})) if isinstance(overview.get("by_change_type"), dict) else {},
        "analysis_axes": dict(overview.get("analysis_axes", {})) if isinstance(overview.get("analysis_axes"), dict) else {},
        "top_risky_files": top_risky_files[:10],
    }
    if str(llm_runtime.get("llm_fallback_reason", "")).strip():
        summary["llm_fallback_reason"] = str(llm_runtime.get("llm_fallback_reason", ""))
    if isinstance(overview.get("review_queue"), dict):
        summary["review_queue"] = dict(overview.get("review_queue", {}))
    return summary


def _first_str_list(values: Any, limit: int = 3) -> List[str]:
    if not isinstance(values, list):
        return []
    out: List[str] = []
    for item in values:
        text = str(item).strip()
        if not text:
            continue
        out.append(text)
        if len(out) >= limit:
            break
    return out


def build_file_result_explanation(file_summary: Dict[str, Any]) -> Dict[str, Any]:
    primary = file_summary.get("primary_conclusion", {}) if isinstance(file_summary.get("primary_conclusion"), dict) else {}
    evidence = normalize_evidence(primary.get("evidence", {}))
    observed_s2s = evidence.get("observed_facts", {}).get("source_to_sink", {})
    inferred_s2s = evidence.get("inferred_assessment", {}).get("source_to_sink", {})
    findings = evidence.get("ranked_candidates", [])
    primary_finding = findings[0] if findings and isinstance(findings[0], dict) else {}
    summary = evidence.get("convenience_summary", {})
    return {
        "analysis_profile": str(file_summary.get("analysis_profile", "generic")),
        "change_type": str(primary.get("change_type", "")),
        "change_intent": str(primary.get("change_intent", "")),
        "behavioral_impact": str(primary.get("behavioral_impact", "")),
        "interface_impact": str(primary.get("interface_impact", "")),
        "security_impact": str(primary.get("security_impact", "")),
        "attack_surface_impact": str(primary.get("attack_surface_impact", "")),
        "vulnerability_type": str(primary.get("vulnerability_type", "")),
        "vulnerability_score": float(primary.get("vulnerability_score", 0.0) or 0.0),
        "analysis_score": float(primary.get("analysis_score", primary.get("vulnerability_score", 0.0)) or 0.0),
        "primary_score": float(primary.get("primary_score", primary.get("analysis_score", primary.get("vulnerability_score", 0.0))) or 0.0),
        "primary_evidence": str(primary_finding.get("evidence", "")),
        "analysis_backend": str(primary.get("analysis_backend", "")),
        "decision_path": str(primary.get("decision_path", "")),
        "analysis_reason": str(primary.get("analysis_reason", "")),
        "review_required": bool(primary.get("review_required", False)),
        "evidence_status": str(summary.get("evidence_status", "")),
        "observed_chain_completeness": str(summary.get("observed_chain_completeness", "")),
        "inferred_chain_completeness": str(summary.get("inferred_chain_completeness", "")),
        "inference_level": str(summary.get("inference_level", "")),
        "assessment_basis": str(summary.get("assessment_basis", "")),
        "review_reasons": list(summary.get("review_reasons", [])) if isinstance(summary.get("review_reasons"), list) else [],
        "observed_sources": _first_str_list(observed_s2s.get("sources")),
        "observed_guards": _first_str_list(observed_s2s.get("guards")),
        "observed_sinks": _first_str_list(observed_s2s.get("sinks")),
        "observed_condition_chain": str(observed_s2s.get("condition_chain", "")),
        "inferred_sources": _first_str_list(inferred_s2s.get("sources")),
        "inferred_guards": _first_str_list(inferred_s2s.get("guards")),
        "inferred_sinks": _first_str_list(inferred_s2s.get("sinks")),
        "inferred_condition_chain": str(inferred_s2s.get("condition_chain", "")),
        "security_fix_units": int(file_summary.get("security_fix_units", 0) or 0),
        "new_vulnerability_units": int(file_summary.get("new_vulnerability_units", 0) or 0),
        "new_attack_surface_units": int(file_summary.get("new_attack_surface_units", 0) or 0),
        "analysis_axes": dict(file_summary.get("analysis_axes", {})) if isinstance(file_summary.get("analysis_axes"), dict) else {},
    }


def build_run_summary_markdown(summary: Dict[str, Any]) -> str:
    top = summary.get("top_risky_files", []) if isinstance(summary.get("top_risky_files"), list) else []
    lines = [
        f"Mode: {summary.get('mode', '')}",
        f"Run root: {summary.get('run_root', '')}",
        f"Analysis profile: {summary.get('analysis_profile', '')}",
        f"LLM enabled: {summary.get('llm_enabled', False)}",
        f"LLM preflight: {summary.get('llm_preflight', '')}",
        f"Analysis quality: {summary.get('analysis_quality', '')}",
        f"Files analyzed: {summary.get('total_files_analyzed', 0)}",
        f"Units analyzed: {summary.get('total_units', 0)}",
        f"Failed files: {summary.get('failed_file_count', 0)}",
        f"High-risk units: {summary.get('high_risk_unit_count', 0)}",
        f"Decode fallback files: {summary.get('decode_fallback_file_count', 0)} ({float(summary.get('decode_fallback_file_ratio', 0.0) or 0.0):.2%})",
        f"Read error files: {summary.get('read_error_file_count', 0)}",
    ]
    skipped_count = int(summary.get("skipped_file_count", 0) or 0)
    if skipped_count:
        lines.append(f"Skipped files: {skipped_count}")
        skipped_by_reason = summary.get("skipped_by_reason", {})
        if isinstance(skipped_by_reason, dict) and skipped_by_reason:
            reason_text = ", ".join(f"{key}={value}" for key, value in sorted(skipped_by_reason.items()))
            lines.append(f"Skipped by reason: {reason_text}")
    not_executed_count = int(summary.get("not_executed_file_count", 0) or 0)
    if not_executed_count:
        lines.append(f"Not executed after fail-fast: {not_executed_count}")
    if summary.get("llm_error_category"):
        lines.append(f"LLM error category: {summary.get('llm_error_category', '')}")
    if summary.get("llm_fallback_reason"):
        lines.append(f"LLM fallback reason: {summary.get('llm_fallback_reason', '')}")
    quality_issues = summary.get("quality_issues", [])
    if quality_issues:
        lines.append(f"Quality issues: {', '.join(str(item) for item in quality_issues)}")
    review_queue = summary.get("review_queue", {})
    if isinstance(review_queue, dict) and review_queue:
        lines.append(
            "Review queue: "
            f"candidates={int(review_queue.get('candidate_count', 0) or 0)}, "
            f"queued={int(review_queue.get('queued_count', 0) or 0)}, "
            f"llm_eligible={int(review_queue.get('llm_eligible_count', 0) or 0)}"
        )
    if top:
        lines.append("Top risky files:")
        for item in top:
            lines.append(
                f"- {item.get('rel_path', '')} | score={float(item.get('risk_score', 0.0) or 0.0):.2f} | type={item.get('vulnerability_type', item.get('status', ''))}"
            )
    return "\n".join(lines) + "\n"
