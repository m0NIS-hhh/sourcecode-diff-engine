from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from source_diff_engine.analysis.profiles import (
    DEFAULT_ANALYSIS_PROFILE,
    get_analysis_profile,
    normalize_analysis_profile,
    profile_primary_strategy,
)


CHANGE_SECURITY_FIX = "\u6f0f\u6d1e\u4fee\u590d"
CHANGE_NON_SECURITY = "\u975e\u5b89\u5168\u6027\u4fee\u6539"
CHANGE_NEW_CODE = "\u65b0\u589e\u4ee3\u7801"
CHANGE_REMOVED = "\u5220\u9664\u4ee3\u7801"

VULN_NONE = "\u65e0\u65b0\u589e\u6f0f\u6d1e"
VULN_PENDING = "\u5f85\u4eba\u5de5\u590d\u6838"
VULN_HARDENING = "\u5b89\u5168\u52a0\u56fa"

DEFAULT_S2S = {
    "sources": [],
    "guards": [],
    "sinks": [],
    "condition_chain": "",
}

EVIDENCE_STATUS_VALUES = {"not_applicable", "missing", "partial", "observed", "inferred"}
CHAIN_COMPLETENESS_VALUES = {"not_applicable", "missing", "partial", "complete"}
INFERENCE_LEVEL_VALUES = {"none", "supplemental", "primary"}
DEFAULT_EVIDENCE_SUMMARY = {
    "evidence_status": "missing",
    "observed_chain_completeness": "missing",
    "inferred_chain_completeness": "missing",
    "inference_level": "none",
    "assessment_basis": "static",
    "candidate_count": 0,
    "primary_evidence": "",
    "review_required": False,
    "review_reasons": [],
}


def normalize_score(value: Any, default: float = 0.0) -> float:
    try:
        score = float(value)
    except Exception:
        score = float(default)
    if 10.0 < score <= 100.0:
        score = score / 10.0
    return max(0.0, min(10.0, score))


def to_str_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def normalize_s2s(value: Any) -> Dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    chain = raw.get("condition_chain", "")
    if isinstance(chain, list):
        chain = " -> ".join(str(item) for item in chain if str(item).strip())
    chain_str = str(chain).strip()
    return {
        "sources": to_str_list(raw.get("sources")),
        "guards": to_str_list(raw.get("guards")),
        "sinks": to_str_list(raw.get("sinks")),
        "condition_chain": chain_str,
    }


def chain_completeness(s2s: Dict[str, Any]) -> str:
    if not isinstance(s2s, dict):
        return "missing"
    sources = to_str_list(s2s.get("sources"))
    guards = to_str_list(s2s.get("guards"))
    sinks = to_str_list(s2s.get("sinks"))
    chain = str(s2s.get("condition_chain", "")).strip()
    if not sources and not guards and not sinks and not chain:
        return "missing"
    if sources and guards and sinks and chain:
        return "complete"
    return "partial"


def has_complete_s2s(s2s: Dict[str, Any]) -> bool:
    return chain_completeness(s2s) == "complete"


def assessment_basis(analysis_backend: Any, default: str = "static") -> str:
    backend = str(analysis_backend or "").strip().lower()
    if backend in {"llm", "static", "inferred"}:
        return backend
    return str(default or "static")


def analysis_score(row: Dict[str, Any]) -> float:
    return normalize_score(row.get("analysis_score", row.get("vulnerability_score", 0.0)), 0.0)


def primary_score(row: Dict[str, Any], analysis_profile: str = DEFAULT_ANALYSIS_PROFILE) -> float:
    profile = get_analysis_profile(normalize_analysis_profile(analysis_profile))
    strategy = profile_primary_strategy(profile)
    if strategy == "security":
        return normalize_score(row.get("security_score", row.get("vulnerability_score", row.get("analysis_score", 0.0))), 0.0)
    if strategy == "api_surface":
        return normalize_score(row.get("attack_surface_score", row.get("analysis_score", row.get("vulnerability_score", 0.0))), 0.0)
    if strategy == "behavior":
        return normalize_score(row.get("behavior_score", row.get("analysis_score", row.get("vulnerability_score", 0.0))), 0.0)
    return normalize_score(row.get("analysis_score", row.get("vulnerability_score", 0.0)), 0.0)


def evidence_status(
    *,
    change_type: str,
    vulnerability_type: str,
    observed_s2s: Dict[str, Any],
    inferred_s2s: Dict[str, Any],
    inferred_origin: str = "",
) -> str:
    observed = chain_completeness(observed_s2s)
    inferred = chain_completeness(inferred_s2s)
    if str(vulnerability_type or "") in {VULN_NONE, VULN_PENDING} and str(change_type or "") in {
        CHANGE_NON_SECURITY,
        CHANGE_NEW_CODE,
        CHANGE_REMOVED,
    }:
        return "not_applicable"
    if observed == "complete":
        return "observed"
    if inferred == "complete":
        return "inferred"
    if observed == "partial" or inferred == "partial":
        return "partial"
    if observed == "missing" and inferred == "missing":
        return "missing"
    return "missing"


def normalize_review_reasons(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()][:10]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def normalize_inference_level(value: Any, default: str = "none") -> str:
    level = str(value or "").strip().lower()
    if level in INFERENCE_LEVEL_VALUES:
        return level
    return str(default or "none")


def derive_inference_level(
    *,
    observed_s2s: Dict[str, Any],
    inferred_s2s: Dict[str, Any],
    reasoning_summary: str,
    confidence: float,
    inferred_origin: str = "",
) -> str:
    observed = chain_completeness(observed_s2s)
    inferred = chain_completeness(inferred_s2s)
    has_inferred_content = (
        inferred != "missing"
        or str(inferred_origin or "").strip() == "llm_inference"
        or (bool(str(reasoning_summary or "").strip()) and float(confidence or 0.0) > 0.0)
    )
    if not has_inferred_content:
        return "none"
    if observed == "complete":
        return "supplemental"
    return "primary"


def normalize_candidate_support(value: Any) -> Dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    s2s = normalize_s2s(raw.get("source_to_sink", {}))
    support_chain = str(raw.get("chain_completeness", "") or "")
    completeness = support_chain if support_chain in CHAIN_COMPLETENESS_VALUES else chain_completeness(s2s)
    inference_level = normalize_inference_level(
        raw.get("inference_level", "primary" if str(raw.get("evidence_status", "")).strip() == "inferred" else "none")
    )
    status = str(raw.get("evidence_status", "") or "").strip()
    if status not in EVIDENCE_STATUS_VALUES:
        if completeness == "complete":
            status = "inferred" if inference_level == "primary" else "observed"
        elif completeness in {"missing", "partial"}:
            status = completeness
        else:
            status = "missing"
    return {
        "source_to_sink": s2s,
        "evidence_status": status,
        "chain_completeness": completeness,
        "inference_level": inference_level,
    }


def build_ranked_candidate(
    *,
    vulnerability_type: Any,
    score: Any,
    evidence: Any = "",
    supporting_source_to_sink: Any = None,
    support_status: str = "",
    support_inference_level: str = "none",
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    candidate = dict(extra) if isinstance(extra, dict) else {}
    candidate["vulnerability_type"] = str(vulnerability_type or VULN_PENDING).strip() or VULN_PENDING
    candidate["score"] = round(normalize_score(score, 0.0), 2)
    candidate["evidence"] = str(evidence or "").strip()
    candidate["supporting_facts"] = normalize_candidate_support(
        {
            "source_to_sink": supporting_source_to_sink,
            "evidence_status": str(support_status or "").strip(),
            "inference_level": str(support_inference_level or "none").strip(),
        }
    )
    return candidate


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for item in findings:
        finding_type = str(item.get("type", "")).strip() or VULN_PENDING
        evidence = str(item.get("evidence", "")).strip() or "no evidence"
        score = round(normalize_score(item.get("score", 0.0), 0.0), 2)
        key = (finding_type, evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": finding_type, "score": score, "evidence": evidence})
    return out


def build_base_result(change_type: str, vuln_type: str, score: float, evidence: str) -> Dict[str, Any]:
    score_norm = round(normalize_score(score, 0.0), 2)
    return {
        "change_type": change_type,
        "change_intent": "unclear",
        "behavioral_impact": "unknown",
        "interface_impact": "none",
        "security_impact": "none" if vuln_type == VULN_NONE else ("review_required" if vuln_type == VULN_PENDING else "hardening"),
        "attack_surface_impact": "none",
        "capability_expansion": [],
        "analysis_score": score_norm,
        "primary_score": score_norm,
        "security_score": score_norm if vuln_type != VULN_NONE else 0.0,
        "behavior_score": score_norm,
        "attack_surface_score": score_norm,
        "vulnerability_type": vuln_type,
        "vulnerability_score": score_norm,
        "evidence": {
            "observed_facts": {
                "source_to_sink": dict(DEFAULT_S2S),
            },
            "inferred_assessment": {
                "source_to_sink": dict(DEFAULT_S2S),
                "summary": "",
                "confidence": 0.0,
                "reasoning_basis": "static",
            },
            "ranked_candidates": [
                build_ranked_candidate(
                    vulnerability_type=vuln_type,
                    score=score_norm,
                    evidence=evidence,
                    support_status="not_applicable",
                )
            ],
            "convenience_summary": {
                "evidence_status": "not_applicable",
                "observed_chain_completeness": "not_applicable",
                "inferred_chain_completeness": "not_applicable",
                "inference_level": "none",
                "assessment_basis": "static",
                "candidate_count": 1,
                "primary_evidence": str(evidence or ""),
                "review_required": False,
                "review_reasons": [],
            },
        },
        "analysis_backend": "static",
        "decision_path": "static",
        "analysis_reason": "static",
        "confidence": 0.0,
        "review_required": False,
    }


def with_analysis_provenance(result: Dict[str, Any], fix_assessment: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(result if isinstance(result, dict) else {})
    merged["analysis_backend"] = str(fix_assessment.get("analysis_backend", merged.get("analysis_backend", "static")) or "static")
    merged["decision_path"] = str(fix_assessment.get("decision_path", merged.get("decision_path", "static")) or "static")
    merged["analysis_reason"] = str(
        fix_assessment.get("analysis_reason", merged.get("analysis_reason", merged.get("decision_path", "static"))) or merged.get("decision_path", "static")
    )
    try:
        merged["confidence"] = float(fix_assessment.get("confidence", merged.get("confidence", 0.0)) or 0.0)
    except Exception:
        merged["confidence"] = 0.0
    merged["review_required"] = bool(fix_assessment.get("review_required", merged.get("review_required", False))) or bool(
        merged.get("review_required", False)
    )
    return merged


def normalize_evidence(value: Any) -> Dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    observed_raw = raw.get("observed_facts", {}) if isinstance(raw.get("observed_facts"), dict) else {}
    inferred_raw = raw.get("inferred_assessment", {}) if isinstance(raw.get("inferred_assessment"), dict) else {}
    ranked_raw = raw.get("ranked_candidates", []) if isinstance(raw.get("ranked_candidates"), list) else []
    summary_raw = raw.get("convenience_summary", {}) if isinstance(raw.get("convenience_summary"), dict) else {}
    ranked_candidates = dedupe_candidates(ranked_raw)
    primary_candidate = ranked_candidates[0] if ranked_candidates else {}
    evidence_status = str(
        summary_raw.get("evidence_status", summary_raw.get("verdict", "")) or ""
    ).strip()
    observed_completeness = str(
        summary_raw.get(
            "observed_chain_completeness",
            summary_raw.get("observed_chain_status", ""),
        )
        or ""
    ).strip()
    inferred_completeness = str(
        summary_raw.get("inferred_chain_completeness", "") or ""
    ).strip()
    inference_level = normalize_inference_level(summary_raw.get("inference_level", ""))
    assessment = assessment_basis(summary_raw.get("assessment_basis", "static"))
    observed_s2s = normalize_s2s(observed_raw.get("source_to_sink", {}))
    inferred_s2s = normalize_s2s(inferred_raw.get("source_to_sink", {}))
    inferred_origin = str(inferred_raw.get("evidence_origin", "") or "").strip()
    if inferred_origin not in {"static_analysis", "llm_inference"}:
        inferred_origin = "static_analysis"
    if not observed_s2s.get("sources") and not observed_s2s.get("guards") and not observed_s2s.get("sinks") and not observed_s2s.get("condition_chain"):
        observed_s2s = normalize_s2s(observed_s2s)
    return {
        "observed_facts": {
            "source_to_sink": observed_s2s,
            "evidence_origin": str(observed_raw.get("evidence_origin", "static_analysis") or "static_analysis"),
        },
        "inferred_assessment": {
            "source_to_sink": inferred_s2s,
            "summary": str(inferred_raw.get("summary", "") or ""),
            "confidence": normalize_confidence(inferred_raw.get("confidence", 0.0)),
            "reasoning_basis": str(inferred_raw.get("reasoning_basis", "") or ""),
            "evidence_origin": inferred_origin,
        },
        "ranked_candidates": ranked_candidates,
        "convenience_summary": {
            "evidence_status": evidence_status if evidence_status in EVIDENCE_STATUS_VALUES else "",
            "observed_chain_completeness": observed_completeness if observed_completeness in CHAIN_COMPLETENESS_VALUES else "",
            "inferred_chain_completeness": inferred_completeness if inferred_completeness in CHAIN_COMPLETENESS_VALUES else "",
            "inference_level": inference_level,
            "assessment_basis": assessment,
            "candidate_count": int(summary_raw.get("candidate_count", len(ranked_candidates)) or 0),
            "primary_evidence": str(summary_raw.get("primary_evidence", primary_candidate.get("evidence", "")) or ""),
            "review_required": bool(summary_raw.get("review_required", False)),
            "review_reasons": normalize_review_reasons(summary_raw.get("review_reasons", [])),
        },
    }


def normalize_confidence(value: Any, default: float = 0.0) -> float:
    try:
        confidence = float(value)
    except Exception:
        confidence = float(default)
    return max(0.0, min(1.0, confidence))


def finalize_evidence(
    evidence: Any,
    *,
    change_type: str,
    vulnerability_type: str,
    analysis_backend: Any,
    chain_inferred: bool,
    confidence: float,
    review_required: bool,
    reasoning_summary: str,
    review_reasons: Any = None,
) -> Dict[str, Any]:
    normalized = normalize_evidence(evidence)
    observed_s2s = normalize_s2s(normalized["observed_facts"].get("source_to_sink", {}))
    inferred_s2s = normalize_s2s(normalized["inferred_assessment"].get("source_to_sink", {}))
    existing_inferred_origin = str(
        normalized["inferred_assessment"].get("evidence_origin", "") or ""
    ).strip()
    inferred_origin = (
        existing_inferred_origin
        if existing_inferred_origin in {"static_analysis", "llm_inference"}
        else ("llm_inference" if assessment_basis(analysis_backend) == "llm" and has_complete_s2s(inferred_s2s) else "static_analysis")
    )
    basis = "inferred" if bool(chain_inferred) else (
        "static" if chain_completeness(observed_s2s) == "complete" else assessment_basis(analysis_backend)
    )
    evidence_summary_status = evidence_status(
        change_type=change_type,
        vulnerability_type=vulnerability_type,
        observed_s2s=observed_s2s,
        inferred_s2s=inferred_s2s,
        inferred_origin=inferred_origin,
    )
    observed_completeness = "not_applicable" if evidence_summary_status == "not_applicable" else chain_completeness(observed_s2s)
    inferred_completeness = "not_applicable" if evidence_summary_status == "not_applicable" else chain_completeness(inferred_s2s)
    inference_level = "none" if evidence_summary_status == "not_applicable" else derive_inference_level(
        observed_s2s=observed_s2s,
        inferred_s2s=inferred_s2s,
        reasoning_summary=reasoning_summary,
        confidence=confidence,
        inferred_origin=inferred_origin,
    )
    ranked_candidates = list(normalized.get("ranked_candidates", []))
    primary_candidate = ranked_candidates[0] if ranked_candidates else {}
    normalized["observed_facts"]["source_to_sink"] = observed_s2s
    normalized["observed_facts"]["evidence_origin"] = "static_analysis"
    normalized["inferred_assessment"] = {
        "source_to_sink": inferred_s2s,
        "summary": str(reasoning_summary or ""),
        "confidence": normalize_confidence(confidence),
        "reasoning_basis": "llm" if inferred_origin == "llm_inference" else "static",
        "evidence_origin": inferred_origin,
    }
    normalized["convenience_summary"] = {
        "evidence_status": evidence_summary_status,
        "observed_chain_completeness": observed_completeness,
        "inferred_chain_completeness": inferred_completeness,
        "inference_level": inference_level,
        "assessment_basis": basis,
        "candidate_count": len(ranked_candidates),
        "primary_evidence": str(primary_candidate.get("evidence", "") or ""),
        "review_required": bool(review_required),
        "review_reasons": normalize_review_reasons(review_reasons),
    }
    return normalized


def line_range_from_code(start_line: Any, code: str) -> List[int]:
    try:
        start = int(start_line)
    except Exception:
        start = 0
    if start <= 0:
        return [0, 0]
    count = max(1, len((code or "").splitlines()))
    return [start, start + count - 1]


def extract_unit_read_summary(unit: Dict[str, Any]) -> Dict[str, Any]:
    raw = unit.get("source_read_summary", {})
    if not isinstance(raw, dict):
        return {"channels": {}, "any_decode_fallback": False, "decode_fallback_count": 0, "read_error_count": 0, "bom_detected": False}
    channels = raw.get("channels", {})
    if not isinstance(channels, dict):
        channels = {}
    decode_fallback_count = sum(1 for item in channels.values() if isinstance(item, dict) and bool(item.get("used_fallback", False)))
    read_error_count = sum(1 for item in channels.values() if isinstance(item, dict) and str(item.get("quality", "")) == "read_error")
    return {
        "channels": channels,
        "any_decode_fallback": decode_fallback_count > 0,
        "decode_fallback_count": decode_fallback_count,
        "read_error_count": read_error_count,
        "bom_detected": any(bool(item.get("bom_detected", False)) for item in channels.values() if isinstance(item, dict)),
    }


def decision_confidence_label(confidence: float) -> str:
    score = max(0.0, min(1.0, float(confidence)))
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def dedupe_candidates(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        vuln_type = str(item.get("vulnerability_type", VULN_PENDING)).strip() or VULN_PENDING
        score = round(normalize_score(item.get("score", 0.0), 0.0), 2)
        support = normalize_candidate_support(item.get("supporting_facts", {}))
        support_s2s = normalize_s2s(support.get("source_to_sink", {}))
        if not has_complete_s2s(support_s2s):
            support_s2s = normalize_s2s(
                {
                    "sources": item.get("source_hits", support_s2s.get("sources", [])),
                    "guards": item.get("guard_hits", support_s2s.get("guards", [])),
                    "sinks": item.get("sink_hits", support_s2s.get("sinks", [])),
                    "condition_chain": item.get("condition_chain", support_s2s.get("condition_chain", "")),
                }
            )
        source_hits = tuple(to_str_list(support_s2s.get("sources")))
        sink_hits = tuple(to_str_list(support_s2s.get("sinks")))
        key = (vuln_type, str(support.get("evidence_status", "")), source_hits, sink_hits)
        if key in seen:
            continue
        seen.add(key)
        candidate = dict(item)
        candidate["vulnerability_type"] = vuln_type
        candidate["score"] = score
        candidate["evidence"] = str(item.get("evidence", "")).strip()
        candidate["supporting_facts"] = {
            **support,
            "source_to_sink": support_s2s,
        }
        out.append(candidate)
    out.sort(key=lambda item: normalize_score(item.get("score", 0.0), 0.0), reverse=True)
    return out[:5]


def make_unit_detail(
    unit: Dict[str, Any],
    raw_change_type: str,
    fix_assessment: Dict[str, Any],
    new_vuln_check: Dict[str, Any],
    new_attack_surface: Dict[str, Any],
) -> Dict[str, Any]:
    read_summary = extract_unit_read_summary(unit)
    return {
        "unit": {
            "old_unit": unit.get("old_unit"),
            "new_unit": unit.get("new_unit"),
            "raw_change_type": raw_change_type,
            "similarity": float(unit.get("similarity", 0.0)),
            "artifact": str(unit.get("new_unit") or unit.get("old_unit") or unit.get("file_path") or ""),
            "file_path": unit.get("file_path"),
            "hunk_header": unit.get("hunk_header"),
            "old_line_range": line_range_from_code(unit.get("old_start"), str(unit.get("old_code", ""))),
            "new_line_range": line_range_from_code(unit.get("new_start"), str(unit.get("new_code", ""))),
            "old_focus_line_range": unit.get("old_focus_line_range", line_range_from_code(unit.get("old_start"), str(unit.get("old_code", "")))),
            "new_focus_line_range": unit.get("new_focus_line_range", line_range_from_code(unit.get("new_start"), str(unit.get("new_code", "")))),
            "old_symbol_context": unit.get("old_symbol_context", {}),
            "new_symbol_context": unit.get("new_symbol_context", {}),
            "source_read_summary": read_summary,
        },
        "fix_assessment": fix_assessment,
        "new_vuln_check": new_vuln_check,
        "new_attack_surface": new_attack_surface,
    }


def _count_values(values: List[str]) -> Dict[str, int]:
    return dict(Counter(str(item) for item in values if str(item).strip()))


def _top_unit_summaries(concise_candidates: List[Dict[str, Any]], limit: int = 3) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for unit_index, row in enumerate(concise_candidates[: max(0, int(limit))]):
        evidence = normalize_evidence(row.get("evidence", {}))
        summary = evidence.get("convenience_summary", {})
        out.append(
            {
                "unit_index": unit_index,
                "change_type": str(row.get("change_type", "")),
                "change_intent": str(row.get("change_intent", "")),
                "vulnerability_type": str(row.get("vulnerability_type", "")),
                "vulnerability_score": round(normalize_score(row.get("vulnerability_score", 0.0), 0.0), 2),
                "analysis_score": round(analysis_score(row), 2),
                "primary_score": round(normalize_score(row.get("primary_score", analysis_score(row)), 0.0), 2),
                "review_required": bool(row.get("review_required", False)),
                "evidence_status": str(summary.get("evidence_status", "")),
            }
        )
    return out


def build_file_summary(unit_rows: List[Dict[str, Any]], analysis_profile: str = DEFAULT_ANALYSIS_PROFILE) -> Dict[str, Any]:
    profile = normalize_analysis_profile(analysis_profile)
    concise_candidates: List[Dict[str, Any]] = []
    for row in unit_rows:
        fix_assessment = row.get("fix_assessment", {}) if isinstance(row.get("fix_assessment"), dict) else {}
        result = fix_assessment.get("result", {})
        if isinstance(result, dict):
            concise_candidates.append(with_analysis_provenance(result, fix_assessment))

    concise_candidates.sort(key=lambda item: (primary_score(item, profile), analysis_score(item)), reverse=True)
    primary = concise_candidates[0] if concise_candidates else build_base_result(CHANGE_NON_SECURITY, VULN_NONE, 0.0, "empty")
    primary = dict(primary)
    primary["analysis_score"] = round(analysis_score(primary), 2)
    primary["primary_score"] = round(primary_score(primary, profile), 2)
    primary["security_score"] = round(normalize_score(primary.get("security_score", primary.get("vulnerability_score", 0.0)), 0.0), 2)
    primary["behavior_score"] = round(normalize_score(primary.get("behavior_score", primary.get("analysis_score", 0.0)), 0.0), 2)
    primary["attack_surface_score"] = round(normalize_score(primary.get("attack_surface_score", primary.get("analysis_score", 0.0)), 0.0), 2)

    security_fix_units = sum(
        1
        for row in unit_rows
        if isinstance(row.get("fix_assessment"), dict)
        and bool(row["fix_assessment"].get("is_security_fix", False))
    )
    new_vulnerability_units = sum(
        1
        for row in unit_rows
        if isinstance(row.get("new_vuln_check"), dict)
        and bool(row["new_vuln_check"].get("has_new_vulnerability", False))
    )
    new_attack_surface_units = sum(
        1
        for row in unit_rows
        if isinstance(row.get("new_attack_surface"), dict)
        and bool(row["new_attack_surface"].get("has_new_attack_surface", False))
    )
    review_required_units = sum(
        1
        for row in unit_rows
        if (isinstance(row.get("fix_assessment"), dict) and bool(row["fix_assessment"].get("review_required", False)))
        or (isinstance(row.get("new_vuln_check"), dict) and bool(row["new_vuln_check"].get("llm_review_required", False)))
    )
    high_risk_unit_count = sum(1 for row in concise_candidates if primary_score(row, profile) >= 7.0)

    return {
        "analysis_profile": profile,
        "primary_conclusion_strategy": profile_primary_strategy(get_analysis_profile(profile)),
        "unit_count": len(unit_rows),
        "security_fix_units": security_fix_units,
        "new_vulnerability_units": new_vulnerability_units,
        "new_attack_surface_units": new_attack_surface_units,
        "high_risk_unit_count": high_risk_unit_count,
        "review_required_unit_count": review_required_units,
        "analysis_axes": {
            "change": {
                "by_change_type": _count_values([str(row.get("change_type", CHANGE_NON_SECURITY)) for row in concise_candidates]),
                "by_change_intent": _count_values([str(row.get("change_intent", "unclear")) for row in concise_candidates]),
            },
            "security": {
                "by_vulnerability_type": _count_values([str(row.get("vulnerability_type", VULN_NONE)) for row in concise_candidates]),
                "by_security_impact": _count_values([str(row.get("security_impact", "none")) for row in concise_candidates]),
                "security_fix_units": security_fix_units,
                "new_vulnerability_units": new_vulnerability_units,
                "high_risk_unit_count": high_risk_unit_count,
            },
            "attack_surface": {
                "new_attack_surface_units": new_attack_surface_units,
                "by_attack_surface_impact": _count_values([str(row.get("attack_surface_impact", "none")) for row in concise_candidates]),
            },
            "behavior": {
                "by_behavioral_impact": _count_values([str(row.get("behavioral_impact", "unknown")) for row in concise_candidates]),
                "by_interface_impact": _count_values([str(row.get("interface_impact", "none")) for row in concise_candidates]),
            },
            "evidence": {
                "by_evidence_status": _count_values(
                    [str(normalize_evidence(row.get("evidence", {})).get("convenience_summary", {}).get("evidence_status", "not_applicable")) for row in concise_candidates]
                ),
                "by_observed_chain_completeness": _count_values(
                    [
                        str(
                            normalize_evidence(row.get("evidence", {})).get("convenience_summary", {}).get(
                                "observed_chain_completeness",
                                "not_applicable",
                            )
                        )
                        for row in concise_candidates
                    ]
                ),
                "by_inferred_chain_completeness": _count_values(
                    [
                        str(
                            normalize_evidence(row.get("evidence", {})).get("convenience_summary", {}).get(
                                "inferred_chain_completeness",
                                "not_applicable",
                            )
                        )
                        for row in concise_candidates
                    ]
                ),
                "by_inference_level": _count_values(
                    [
                        str(
                            normalize_evidence(row.get("evidence", {})).get("convenience_summary", {}).get(
                                "inference_level",
                                "none",
                            )
                        )
                        for row in concise_candidates
                    ]
                ),
                "by_assessment_basis": _count_values(
                    [
                        str(
                            normalize_evidence(row.get("evidence", {})).get("convenience_summary", {}).get(
                                "assessment_basis",
                                "static",
                            )
                        )
                        for row in concise_candidates
                    ]
                ),
                "review_required_unit_count": review_required_units,
            },
        },
        "high_risk_units": _top_unit_summaries(
            [row for row in concise_candidates if primary_score(row, profile) >= 7.0]
        ),
        "primary_conclusion": primary,
    }
