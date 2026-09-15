from __future__ import annotations

from source_diff_engine.analysis.pipeline import _build_base_result, _merge_new_vulnerability, _security_fix_with_llm
from source_diff_engine.pipeline.results import extract_unit_read_summary, normalize_evidence
from source_diff_engine.source_analyzer import SourceAnalyzer


CHANGE_SECURITY_FIX = "\u6f0f\u6d1e\u4fee\u590d"
CHANGE_NON_SECURITY = "\u975e\u5b89\u5168\u6027\u4fee\u6539"
CHANGE_NEW_CODE = "\u65b0\u589e\u4ee3\u7801"
VULN_PENDING = "\u5f85\u4eba\u5de5\u590d\u6838"
VULN_PATH = "\u8def\u5f84\u904d\u5386\u98ce\u9669"
VULN_SQLI = "SQL\u6ce8\u5165\u98ce\u9669"


def test_source_analyzer_normalizes_llm_schema_shapes() -> None:
    data = {
        "change_type": "security fix",
        "vulnerability_type": "sql injection",
        "vulnerability_score": "8.2",
        "source_to_sink_conditions": {
            "sources": ["user_input"],
            "guards": ["input_validation"],
            "sinks": ["database_query"],
            "condition_chain": ["sanitization", "parameter_binding"],
        },
        "vulnerability_findings": [
            {
                "type": "sql injection",
                "score": "8.2",
                "evidence": "User input is not sanitized before use.",
            }
        ],
    }
    out = SourceAnalyzer._normalize_schema(data)
    assert out["change_type"] == CHANGE_SECURITY_FIX
    assert out["vulnerability_type"] == VULN_SQLI
    assert out["source_to_sink_conditions"]["condition_chain"] == "sanitization -> parameter_binding"
    assert isinstance(out["vulnerability_findings"], list)
    assert len(out["vulnerability_findings"]) == 1
    assert out["valid"] is True


def test_source_analyzer_rejects_legacy_aliases_and_loose_findings() -> None:
    data = {
        "change_type": "Code Refactoring",
        "vulnerability_type": "SQL Injection",
        "vulnerability_score": "8.2",
        "source_to_sink_conditions": {
            "sources": ["user_input"],
            "guards": ["input_validation"],
            "sinks": ["database_query"],
            "condition_chain": "user_input -> database_query",
        },
        "vulnerability_findings": "User input is not sanitized before use.",
    }
    out = SourceAnalyzer._normalize_schema(data)
    assert out["valid"] is False


def test_extract_unit_read_summary_requires_canonical_channels_shape() -> None:
    summary = extract_unit_read_summary(
        {
            "source_read_summary": {
                "channels": {
                    "old_source": {"quality": "exact", "used_fallback": False, "bom_detected": False},
                    "new_source": {"quality": "fallback_decode", "used_fallback": True, "bom_detected": True},
                }
            }
        }
    )
    assert summary["decode_fallback_count"] == 1
    assert summary["read_error_count"] == 0
    assert summary["bom_detected"] is True

    legacy = extract_unit_read_summary({"source_read_summary": {"old_source": {"quality": "exact"}}})
    assert legacy["channels"] == {}


def test_normalize_evidence_accepts_legacy_summary_aliases_and_bad_confidence() -> None:
    normalized = normalize_evidence(
        {
            "inferred_assessment": {"confidence": "not-a-number"},
            "convenience_summary": {
                "verdict": "partial",
                "observed_chain_status": "partial",
            },
            "ranked_candidates": [None, {"vulnerability_type": "cmdi", "score": "8.2", "evidence": "x"}],
        }
    )
    summary = normalized["convenience_summary"]
    assert summary["evidence_status"] == "partial"
    assert summary["observed_chain_completeness"] == "partial"
    assert normalized["inferred_assessment"]["confidence"] == 0.0
    assert len(normalized["ranked_candidates"]) == 1


def test_finalize_evidence_keeps_static_basis_when_llm_is_supplemental() -> None:
    from source_diff_engine.pipeline.results import finalize_evidence

    evidence = finalize_evidence(
        {
            "observed_facts": {
                "source_to_sink": {
                    "sources": ["request.args"],
                    "guards": ["validate"],
                    "sinks": ["cursor.execute"],
                    "condition_chain": "source -> guard -> sink",
                },
                "evidence_origin": "static_analysis",
            },
            "inferred_assessment": {
                "source_to_sink": {
                    "sources": ["llm source"],
                    "guards": ["llm guard"],
                    "sinks": ["llm sink"],
                    "condition_chain": "llm source -> llm guard -> llm sink",
                },
                "evidence_origin": "llm_inference",
            },
            "ranked_candidates": [],
        },
        change_type=CHANGE_NON_SECURITY,
        vulnerability_type=VULN_SQLI,
        analysis_backend="llm",
        chain_inferred=False,
        confidence=0.9,
        review_required=False,
        reasoning_summary="llm supplemental review",
    )
    summary = evidence["convenience_summary"]
    assert summary["evidence_status"] == "observed"
    assert summary["inference_level"] == "supplemental"
    assert summary["assessment_basis"] == "static"
    assert evidence["inferred_assessment"]["reasoning_basis"] == "llm"


def test_finalize_evidence_does_not_label_static_fallback_as_llm_inference() -> None:
    from source_diff_engine.pipeline.results import finalize_evidence

    evidence = finalize_evidence(
        {
            "observed_facts": {
                "source_to_sink": {
                    "sources": ["request"],
                    "guards": ["validate"],
                    "sinks": ["open"],
                    "condition_chain": "source -> guard -> sink",
                }
            },
            "inferred_assessment": {
                "source_to_sink": {
                    "sources": ["request"],
                    "guards": ["validate"],
                    "sinks": ["open"],
                    "condition_chain": "source -> guard -> sink",
                },
                "evidence_origin": "static_analysis",
            },
        },
        change_type=CHANGE_SECURITY_FIX,
        vulnerability_type=VULN_PATH,
        analysis_backend="llm",
        chain_inferred=True,
        confidence=0.4,
        review_required=True,
        reasoning_summary="static fallback",
    )
    assert evidence["inferred_assessment"]["evidence_origin"] == "static_analysis"
    assert evidence["inferred_assessment"]["reasoning_basis"] == "static"
    assert evidence["convenience_summary"]["assessment_basis"] == "inferred"


def test_finalize_evidence_keeps_partial_llm_chain_partial() -> None:
    from source_diff_engine.pipeline.results import finalize_evidence

    evidence = finalize_evidence(
        {
            "observed_facts": {
                "source_to_sink": {
                    "sources": ["request.args"],
                    "guards": [],
                    "sinks": ["cursor.execute"],
                    "condition_chain": "",
                }
            },
            "inferred_assessment": {
                "source_to_sink": {
                    "sources": ["request.args"],
                    "guards": [],
                    "sinks": ["cursor.execute"],
                    "condition_chain": "",
                },
                "evidence_origin": "llm_inference",
            },
        },
        change_type=CHANGE_NEW_CODE,
        vulnerability_type=VULN_SQLI,
        analysis_backend="llm",
        chain_inferred=True,
        confidence=0.9,
        review_required=True,
        reasoning_summary="LLM identified a possible flow but no complete condition chain.",
    )

    assert evidence["convenience_summary"]["evidence_status"] == "partial"
    assert evidence["convenience_summary"]["inferred_chain_completeness"] == "partial"
    assert evidence["convenience_summary"]["inference_level"] == "primary"


class _FakeLLM:
    enabled = True


class _FakeAnalyzer:
    llm = _FakeLLM()

    @staticmethod
    def analyze_function_pair(**kwargs):
        return {
            "change_type": CHANGE_SECURITY_FIX,
            "vulnerability_type": VULN_PENDING,
            "vulnerability_score": 0.0,
            "source_to_sink_conditions": {"sources": [], "guards": [], "sinks": [], "condition_chain": ""},
            "vulnerability_findings": [],
            "analysis_backend": "llm",
            "decision_path": "llm_primary",
            "analysis_reason": "llm_primary",
            "confidence": 0.4,
            "review_required": True,
            "llm_raw_text": "",
        }


def test_security_fix_branch_backfills_complete_s2s_when_llm_output_is_empty() -> None:
    unit = {
        "old_unit": "old.java:1",
        "new_unit": "new.java:1",
        "old_code": "return candidate.normalize().startsWith(base.normalize());",
        "new_code": (
            "Path b = base.toAbsolutePath().normalize();\n"
            "Path c = candidate.toAbsolutePath().normalize();\n"
            "return c.startsWith(b) && c.getNameCount() >= b.getNameCount();"
        ),
        "similarity": 0.5,
        "language": "java",
    }
    result, debug = _security_fix_with_llm(_FakeAnalyzer(), unit)
    s2s = result["evidence"]["inferred_assessment"]["source_to_sink"]
    assert result["change_type"] == CHANGE_SECURITY_FIX
    assert float(result["vulnerability_score"]) >= 5.0
    assert len(s2s["sources"]) > 0
    assert len(s2s["guards"]) > 0
    assert len(s2s["sinks"]) > 0
    assert "->" in s2s["condition_chain"]
    assert debug["llm_raw_empty"] is True
    assert debug["analysis_backend"] == "llm"
    assert debug["decision_path"] == "llm_primary"
    assert result["evidence"]["observed_facts"]["evidence_origin"] == "static_analysis"
    assert result["evidence"]["inferred_assessment"]["evidence_origin"] == "static_analysis"


class _HighConfidenceAnalyzer:
    llm = _FakeLLM()

    @staticmethod
    def analyze_function_pair(**kwargs):
        return {
            "change_type": CHANGE_SECURITY_FIX,
            "vulnerability_type": VULN_PATH,
            "vulnerability_score": 9.0,
            "source_to_sink_conditions": {
                "sources": ["candidate path input"],
                "guards": ["toAbsolutePath().normalize()", "startsWith(base)", "getNameCount() >= baseCount"],
                "sinks": ["path containment decision"],
                "condition_chain": "source -> guard -> sink",
            },
            "vulnerability_findings": [
                {"type": VULN_PATH, "score": 9.0, "evidence": "hardened path boundary checks"}
            ],
            "analysis_backend": "llm",
            "decision_path": "llm_primary",
            "analysis_reason": "llm_primary",
            "confidence": 0.95,
            "review_required": True,
            "llm_raw_text": '{"change_type":"\u6f0f\u6d1e\u4fee\u590d"}',
        }


def test_security_fix_branch_keeps_review_required_even_when_chain_is_complete() -> None:
    unit = {
        "old_unit": "old.java:1",
        "new_unit": "new.java:1",
        "old_code": "return candidate.normalize().startsWith(base.normalize());",
        "new_code": (
            "Path b = base.toAbsolutePath().normalize();\n"
            "Path c = candidate.toAbsolutePath().normalize();\n"
            "return c.startsWith(b) && c.getNameCount() >= b.getNameCount();"
        ),
        "similarity": 0.5,
        "language": "java",
    }
    result, debug = _security_fix_with_llm(_HighConfidenceAnalyzer(), unit)
    assert result["vulnerability_type"] == VULN_PATH
    assert float(result["vulnerability_score"]) >= 7.0
    assert debug["llm_raw_empty"] is False
    assert debug["has_complete_chain"] is True
    assert debug["review_required"] is True
    assert result["evidence"]["observed_facts"]["evidence_origin"] == "static_analysis"
    assert result["evidence"]["inferred_assessment"]["evidence_origin"] == "llm_inference"


class _PendingHighConfidenceAnalyzer:
    llm = _FakeLLM()

    @staticmethod
    def analyze_function_pair(**kwargs):
        return {
            "change_type": CHANGE_SECURITY_FIX,
            "vulnerability_type": VULN_PENDING,
            "vulnerability_score": 9.0,
            "source_to_sink_conditions": {
                "sources": ["input"],
                "guards": ["guard"],
                "sinks": ["sink"],
                "condition_chain": "source -> guard -> sink",
            },
            "vulnerability_findings": [
                {"type": VULN_PENDING, "score": 9.0, "evidence": "insufficiently certain"}
            ],
            "analysis_backend": "llm",
            "decision_path": "llm_primary",
            "analysis_reason": "llm_primary",
            "confidence": 0.95,
            "review_required": True,
            "llm_raw_text": '{"change_type":"\u6f0f\u6d1e\u4fee\u590d"}',
        }


def test_security_fix_branch_keeps_review_required_when_main_type_is_pending() -> None:
    unit = {
        "old_unit": "old.java:1",
        "new_unit": "new.java:1",
        "old_code": "a",
        "new_code": "b",
        "similarity": 0.5,
        "language": "java",
    }
    _, debug = _security_fix_with_llm(_PendingHighConfidenceAnalyzer(), unit)
    assert debug["has_complete_chain"] is True
    assert debug["review_required"] is True


def test_merge_new_vulnerability_preserves_multiple_candidate_findings() -> None:
    base = _build_base_result("non_security", "none", 1.0, "baseline")
    part2 = {
        "has_new_vulnerability": True,
        "vulnerability_type": "cmdi",
        "score": 8.6,
        "source_hits": ["request.args"],
        "sink_hits": ["os.system("],
        "candidates": [
            {
                "rule_id": "cmdi",
                "vulnerability_type": "cmdi",
                "score": 8.6,
                "source_hits": ["request.args"],
                "sink_hits": ["os.system("],
            },
            {
                "rule_id": "sqli",
                "vulnerability_type": "sqli",
                "score": 8.2,
                "source_hits": ["request.args"],
                "sink_hits": ["cursor.execute("],
            },
        ],
    }
    merged = _merge_new_vulnerability(base, part2, raw_change_type="added")
    findings = merged["evidence"]["ranked_candidates"]
    assert len(findings) >= 2
    types = {str(x.get("vulnerability_type", "")) for x in findings}
    assert "cmdi" in types
    assert "sqli" in types
