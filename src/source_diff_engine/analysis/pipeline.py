from __future__ import annotations

import json
from typing import Any, Dict, List

from source_diff_engine.analysis.profiles import (
    DEFAULT_ANALYSIS_PROFILE,
    get_analysis_profile,
    normalize_analysis_profile,
    profile_enables_domain,
    profile_primary_strategy,
    profile_summary,
)
from source_diff_engine.analysis.domains.attack_surface import score_attack_surface_result as _score_attack_surface_result_impl
from source_diff_engine.analysis.domains.behavior import score_behavior_result as _score_behavior_result_impl
from source_diff_engine.analysis.domains.generic import (
    classify_generic_axes as _classify_generic_axes_impl,
    score_generic_result as _score_generic_result_impl,
)
from source_diff_engine.analysis.domains.security import score_security_result as _score_security_result_impl
from source_diff_engine.logger_config import get_logger
from source_diff_engine.output.schema import SCHEMA_VERSION
from source_diff_engine.pipeline.attack_surface import (
    added_lines as _added_lines_impl,
    detect_added_scope as _detect_added_scope_impl,
)
from source_diff_engine.pipeline.fix_assessment import (
    assess_modification_security_intent as _assess_modification_security_intent_impl,
    security_fix_with_llm as _security_fix_with_llm_impl,
)
from source_diff_engine.pipeline.new_vuln import (
    assess_added_risk as _assess_added_risk_impl,
    merge_new_vulnerability as _merge_new_vulnerability_impl,
    review_new_vulnerability_with_llm as _review_new_vulnerability_with_llm_impl,
)
from source_diff_engine.pipeline.results import (
    CHANGE_NEW_CODE,
    CHANGE_NON_SECURITY,
    CHANGE_REMOVED,
    CHANGE_SECURITY_FIX,
    VULN_NONE,
    build_base_result as _build_base_result_impl,
    build_file_summary as _build_file_summary_impl,
    decision_confidence_label as _decision_confidence_label_impl,
    extract_unit_read_summary as _extract_unit_read_summary_impl,
    finalize_evidence as _finalize_evidence_impl,
    make_unit_detail as _make_unit_detail_impl,
    normalize_score as _normalize_score_impl,
    with_analysis_provenance as _with_analysis_provenance_impl,
)
from source_diff_engine.source_analyzer import SourceAnalyzer

logger = get_logger(__name__)


def assess_modification_security_intent(old_code: str, new_code: str, language: str = "python") -> Dict[str, Any]:
    return _assess_modification_security_intent_impl(old_code, new_code, language)


def assess_added_risk(
    code: str,
    language: str = "python",
    new_symbol_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return _assess_added_risk_impl(code, language=language, new_symbol_context=new_symbol_context)


def _detect_added_scope(
    old_code: str,
    new_code: str,
    artifact: str,
    new_symbol_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return _detect_added_scope_impl(old_code, new_code, artifact, new_symbol_context=new_symbol_context)


def _build_base_result(change_type: str, vuln_type: str, score: float, evidence: str) -> Dict[str, Any]:
    return _build_base_result_impl(change_type, vuln_type, score, evidence)


def _with_analysis_provenance(result: Dict[str, Any], fix_assessment: Dict[str, Any]) -> Dict[str, Any]:
    return _with_analysis_provenance_impl(result, fix_assessment)


def _apply_profile_defaults(result: Dict[str, Any], analysis_profile: str) -> Dict[str, Any]:
    profile = get_analysis_profile(normalize_analysis_profile(analysis_profile))
    merged = dict(result if isinstance(result, dict) else {})
    merged.update(profile_summary(profile))
    merged["analysis_profile"] = profile.get("name", DEFAULT_ANALYSIS_PROFILE)
    return merged


def _security_fix_with_llm(
    analyzer: SourceAnalyzer,
    unit: Dict[str, Any],
    intent: Dict[str, Any] | None = None,
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    return _security_fix_with_llm_impl(analyzer, unit, intent=intent, analysis_profile=analysis_profile)


def _extract_unit_read_summary(unit: Dict[str, Any]) -> Dict[str, Any]:
    return _extract_unit_read_summary_impl(unit)


def _decision_confidence_label(confidence: float) -> str:
    return _decision_confidence_label_impl(confidence)


def _review_new_vulnerability_with_llm(
    analyzer: SourceAnalyzer,
    unit: Dict[str, Any],
    part2: Dict[str, Any],
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Dict[str, Any]:
    return _review_new_vulnerability_with_llm_impl(analyzer, unit, part2, analysis_profile=analysis_profile)


def _merge_new_vulnerability(base_result: Dict[str, Any], part2: Dict[str, Any], raw_change_type: str) -> Dict[str, Any]:
    return _merge_new_vulnerability_impl(base_result, part2, raw_change_type)


def _classify_generic_axes(
    *,
    raw_change_type: str,
    part2: Dict[str, Any],
    part3: Dict[str, Any],
    security_domain_enabled: bool,
    security_fix: bool = False,
) -> Dict[str, Any]:
    return _classify_generic_axes_impl(
        raw_change_type=raw_change_type,
        new_vulnerability=part2,
        attack_surface=part3,
        security_domain_enabled=security_domain_enabled,
        security_fix=security_fix,
    )


def _score_generic_result(raw_change_type: str, generic_axes: Dict[str, Any], part3: Dict[str, Any]) -> float:
    return _score_generic_result_impl(raw_change_type, generic_axes, part3)


def _score_behavior_result(generic_axes: Dict[str, Any], part3: Dict[str, Any]) -> float:
    return _score_behavior_result_impl(generic_axes, part3)


def _score_attack_surface_result(part3: Dict[str, Any]) -> float:
    return _score_attack_surface_result_impl(part3)


def _score_security_result(
    *,
    security_domain_enabled: bool,
    part2: Dict[str, Any],
    base_result: Dict[str, Any],
    security_fix: bool,
) -> float:
    return _score_security_result_impl(
        security_domain_enabled=security_domain_enabled,
        new_vulnerability=part2,
        base_result=base_result,
        security_fix=security_fix,
    )


def _primary_score_for_profile(
    *,
    analysis_profile: str,
    analysis_score: float,
    security_score: float,
    behavior_score: float,
    attack_surface_score: float,
) -> float:
    profile = get_analysis_profile(normalize_analysis_profile(analysis_profile))
    strategy = profile_primary_strategy(profile)
    if strategy == "security":
        return round(max(analysis_score, security_score), 2)
    if strategy == "api_surface":
        return round(max(analysis_score, attack_surface_score), 2)
    if strategy == "behavior":
        return round(max(analysis_score, behavior_score), 2)
    return round(analysis_score, 2)


def _apply_result_metadata(
    *,
    result: Dict[str, Any],
    generic_axes: Dict[str, Any],
    part2: Dict[str, Any],
    part3: Dict[str, Any],
    analysis_profile: str,
    security_domain_enabled: bool,
    analysis_backend: str,
    decision_path: str,
    analysis_reason: str,
    confidence: float,
    review_required: bool,
    review_reasons: List[str] | None = None,
    chain_inferred: bool = False,
) -> Dict[str, Any]:
    merged = dict(result if isinstance(result, dict) else {})
    merged.update(generic_axes)
    merged["analysis_profile"] = normalize_analysis_profile(analysis_profile)
    merged["analysis_backend"] = str(analysis_backend or "static")
    merged["decision_path"] = str(decision_path or merged.get("decision_path", "static"))
    merged["analysis_reason"] = str(analysis_reason or merged.get("analysis_reason", merged.get("decision_path", "static")))
    merged["confidence"] = max(0.0, min(1.0, float(confidence)))
    merged["attack_surface_impact"] = (
        "expanded" if bool(part3.get("has_new_attack_surface", False)) else str(merged.get("attack_surface_impact", "none"))
    )
    merged["review_required"] = bool(review_required)
    if security_domain_enabled and bool(part2.get("has_new_vulnerability", False)):
        merged["security_impact"] = "introduced_risk"
    merged["evidence"] = _finalize_evidence_impl(
        merged.get("evidence", {}),
        change_type=str(merged.get("change_type", "")),
        vulnerability_type=str(merged.get("vulnerability_type", "")),
        analysis_backend=analysis_backend,
        chain_inferred=bool(chain_inferred),
        confidence=float(merged.get("confidence", 0.0)),
        review_required=bool(merged.get("review_required", False)),
        reasoning_summary=str(analysis_reason or merged.get("analysis_reason", "")),
        review_reasons=list(review_reasons or []),
    )
    merged["primary_score"] = _primary_score_for_profile(
        analysis_profile=analysis_profile,
        analysis_score=float(merged.get("analysis_score", merged.get("vulnerability_score", 0.0))),
        security_score=float(merged.get("security_score", merged.get("vulnerability_score", 0.0))),
        behavior_score=float(merged.get("behavior_score", merged.get("analysis_score", 0.0))),
        attack_surface_score=float(merged.get("attack_surface_score", merged.get("analysis_score", 0.0))),
    )
    return merged


def analyze_diff_units(
    analyzer: SourceAnalyzer,
    diff_units: List[Dict[str, Any]],
    output_file: str,
    detailed_output_file: str,
    overview_output_file: str,
    language: str = "python",
    git_diff_text: str = "",
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> List[Dict[str, Any]]:
    result = analyze_diff_units_in_memory(
        analyzer=analyzer,
        diff_units=diff_units,
        language=language,
        git_diff_text=git_diff_text,
        analysis_profile=analysis_profile,
    )
    concise_rows = result["concise_rows"]
    unit_rows = result["unit_rows"]
    detailed_doc = result["detailed_doc"]
    overview = result["overview"]

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(concise_rows, f, ensure_ascii=False, indent=2)
    with open(detailed_output_file, "w", encoding="utf-8") as f:
        json.dump(detailed_doc, f, ensure_ascii=False, indent=2)
    with open(overview_output_file, "w", encoding="utf-8") as f:
        json.dump(overview, f, ensure_ascii=False, indent=2)

    logger.info("pipeline done: %d concise units, %d detailed units", len(concise_rows), len(unit_rows))
    return unit_rows


def analyze_diff_units_in_memory(
    analyzer: SourceAnalyzer,
    diff_units: List[Dict[str, Any]],
    language: str = "python",
    git_diff_text: str = "",
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Dict[str, Any]:
    profile = get_analysis_profile(normalize_analysis_profile(analysis_profile))
    profile_name = str(profile.get("name", DEFAULT_ANALYSIS_PROFILE))
    security_enabled = profile_enables_domain(profile, "security")
    behavior_enabled = profile_enables_domain(profile, "behavior")
    attack_surface_enabled = profile_enables_domain(profile, "attack_surface")
    concise_rows: List[Dict[str, Any]] = []
    unit_rows: List[Dict[str, Any]] = []

    for unit in diff_units:
        old_code = unit.get("old_code", "")
        new_code = unit.get("new_code", "")
        raw_change_type = str(unit.get("change_type", "modification"))
        unit["language"] = language

        intent = assess_modification_security_intent(old_code, new_code, language=language)
        added_block = "\n".join(_added_lines_impl(old_code, new_code))
        part2 = assess_added_risk(
            added_block,
            language=language,
            new_symbol_context=unit.get("new_symbol_context"),
        )
        part3 = _detect_added_scope(
            old_code=old_code,
            new_code=new_code,
            artifact=str(unit.get("new_unit") or unit.get("old_unit") or unit.get("file_path") or ""),
            new_symbol_context=unit.get("new_symbol_context"),
        )

        if raw_change_type == "added":
            base_result = _build_base_result(CHANGE_NEW_CODE, VULN_NONE, 1.0, "new code path; generic analysis")
            debug = {
                "llm_review_invoked": False,
                "analysis_backend": "static",
                "decision_path": "generic_added_code",
                "analysis_reason": "generic_added_code",
                "has_observed_complete_chain": False,
                "review_required": False,
                "review_reasons": [],
                "chain_inferred": False,
            }
            reasons = ["added code is treated as a generic expansion by default"]
        elif raw_change_type == "removed":
            base_result = _build_base_result(CHANGE_REMOVED, VULN_NONE, 0.0, "removed code path; generic contraction")
            debug = {
                "llm_review_invoked": False,
                "analysis_backend": "static",
                "decision_path": "generic_removed_code",
                "analysis_reason": "generic_removed_code",
                "has_observed_complete_chain": False,
                "review_required": False,
                "review_reasons": [],
                "chain_inferred": False,
            }
            reasons = ["removed code is treated as a generic contraction"]
        else:
            base_result = _build_base_result(CHANGE_NON_SECURITY, VULN_NONE, 0.8 if intent["non_security_only"] else 1.2, "generic change analysis")
            debug = {
                "llm_review_invoked": False,
                "analysis_backend": "static",
                "decision_path": "generic_change",
                "analysis_reason": "generic_change",
                "has_observed_complete_chain": False,
                "review_required": False,
                "review_reasons": [],
                "chain_inferred": False,
            }
            reasons = intent["reasons"]

        security_fix = bool(intent["is_security_fix"])
        non_security_only = bool(intent["non_security_only"])

        if security_enabled and security_fix:
            base_result, debug = _security_fix_with_llm(analyzer, unit, intent=intent, analysis_profile=profile_name)
            reasons = intent["reasons"]
        elif security_enabled:
            part2 = _review_new_vulnerability_with_llm(analyzer, unit, part2, analysis_profile=profile_name)
        else:
            part2 = dict(part2)
            part2["llm_review_invoked"] = False
            part2["llm_confirmed"] = False
            part2["llm_review_confidence"] = 0.0
            part2["llm_review_required"] = False

        generic_axes = _classify_generic_axes(
            raw_change_type=raw_change_type,
            part2=part2,
            part3=part3,
            security_domain_enabled=security_enabled,
            security_fix=security_fix,
        )
        merged_result = _merge_new_vulnerability(base_result, part2, raw_change_type)
        review_required = bool(debug.get("review_required", False)) or bool(
            security_enabled and part2.get("llm_review_required", False)
        ) or bool(attack_surface_enabled and part3.get("has_new_attack_surface", False) and part3.get("attack_surface_level", "none") in {"medium", "high"})
        review_reasons: List[str] = list(debug.get("review_reasons", [])) if isinstance(debug.get("review_reasons"), list) else []
        if security_enabled and bool(part2.get("llm_review_required", False)):
            review_reasons.append("llm_security_review_requested")
        if attack_surface_enabled and part3.get("has_new_attack_surface", False) and part3.get("attack_surface_level", "none") in {"medium", "high"}:
            review_reasons.append(f"attack_surface_{part3.get('attack_surface_level', 'unknown')}")
        analysis_score = _score_generic_result(raw_change_type, generic_axes, part3)
        behavior_score = _score_behavior_result(generic_axes, part3) if behavior_enabled else analysis_score
        attack_surface_score = _score_attack_surface_result(part3) if attack_surface_enabled else analysis_score
        security_score = _score_security_result(
            security_domain_enabled=security_enabled,
            part2=part2,
            base_result=base_result,
            security_fix=security_fix,
        )
        merged_result["analysis_score"] = analysis_score
        merged_result["behavior_score"] = behavior_score
        merged_result["attack_surface_score"] = attack_surface_score
        merged_result["security_score"] = security_score
        merged_result = _apply_result_metadata(
            result=merged_result,
            generic_axes=generic_axes,
            part2=part2,
            part3=part3,
            analysis_profile=profile_name,
            security_domain_enabled=security_enabled,
            analysis_backend=str(debug.get("analysis_backend", "static")),
            decision_path=str(debug.get("decision_path", "static")),
            analysis_reason=str(debug.get("analysis_reason", debug.get("decision_path", "static"))),
            confidence=float(debug.get("confidence", 0.5)),
            review_required=review_required,
            review_reasons=review_reasons,
            chain_inferred=bool(debug.get("chain_inferred", False)),
        )
        concise_rows.append(merged_result)

        fix_assessment_result = dict(merged_result)
        fix_assessment = {
            "is_security_fix": security_fix,
            "non_security_only": non_security_only,
            "llm_review_invoked": bool(debug.get("llm_review_invoked", False)),
            "reasons": reasons,
            "result": fix_assessment_result,
            "analysis_backend": str(debug.get("analysis_backend", "static")),
            "decision_path": str(debug.get("decision_path", "static")),
            "analysis_reason": str(debug.get("analysis_reason", debug.get("decision_path", "static"))),
            "confidence": float(debug.get("confidence", 0.5)),
            "confidence_level": _decision_confidence_label(float(debug.get("confidence", 0.5))),
            "review_required": review_required,
            "review_reasons": review_reasons,
            "llm_raw_empty": bool(debug.get("llm_raw_empty", False)),
            "has_observed_complete_chain": bool(debug.get("has_observed_complete_chain", False)),
            "evidence": dict(fix_assessment_result.get("evidence", {})) if isinstance(fix_assessment_result.get("evidence"), dict) else {},
            "read_quality": _extract_unit_read_summary(unit),
        }
        unit_rows.append(_make_unit_detail_impl(unit, raw_change_type, fix_assessment, part2, part3))

    file_summary = _build_file_summary_impl(unit_rows, analysis_profile=profile_name)
    detailed_doc = {"git_diff": git_diff_text, "language": language, "units": unit_rows, "file_summary": file_summary}

    by_vuln: Dict[str, int] = {}
    by_change: Dict[str, int] = {}
    high_risk_count = 0
    for row in concise_rows:
        vt = str(row.get("vulnerability_type", VULN_NONE))
        ct = str(row.get("change_type", CHANGE_NON_SECURITY))
        by_vuln[vt] = by_vuln.get(vt, 0) + 1
        by_change[ct] = by_change.get(ct, 0) + 1
        primary_score = _normalize_score_impl(row.get("primary_score", row.get("analysis_score", row.get("vulnerability_score", 0.0))), 0.0)
        if primary_score >= 7.0:
            high_risk_count += 1

    overview = {
        "schema_version": SCHEMA_VERSION,
        "analysis_profile": profile_name,
        "total_units": len(concise_rows),
        "by_vulnerability_type": by_vuln,
        "by_change_type": by_change,
        "high_risk_unit_count": high_risk_count,
        "security_fix_unit_count": by_change.get(CHANGE_SECURITY_FIX, 0),
        "new_vulnerability_unit_count": sum(1 for row in unit_rows if bool(row.get("new_vuln_check", {}).get("has_new_vulnerability", False))),
        "new_attack_surface_unit_count": sum(1 for row in unit_rows if bool(row.get("new_attack_surface", {}).get("has_new_attack_surface", False))),
        "decode_fallback_unit_count": sum(1 for row in unit_rows if bool(((row.get("unit", {}) or {}).get("source_read_summary", {}) or {}).get("any_decode_fallback", False))),
        "read_error_unit_count": sum(
            int((((row.get("unit", {}) or {}).get("source_read_summary", {}) or {}).get("read_error_count", 0) or 0))
            for row in unit_rows
        ),
        "file_summary": file_summary,
        "analysis_profile": profile_name,
        "analysis_axes": dict(file_summary.get("analysis_axes", {})) if isinstance(file_summary.get("analysis_axes"), dict) else {},
    }
    return {"concise_rows": concise_rows, "unit_rows": unit_rows, "file_summary": file_summary, "detailed_doc": detailed_doc, "overview": overview}
