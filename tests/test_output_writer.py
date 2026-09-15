from __future__ import annotations

import json
from pathlib import Path

from source_diff_engine.output.writer import (
    build_high_risk_index_entries,
    build_file_result_explanation,
    build_run_summary,
    build_run_summary_markdown,
    normalize_run_id,
    sanitize_rel_path,
    write_json_atomic,
    write_text_atomic,
)
from source_diff_engine.output.schema import build_top_risky_file_entry


def test_normalize_run_id_strips_invalid_chars() -> None:
    assert normalize_run_id(" demo:run/001 ") == "demo_run_001"
    assert normalize_run_id("...") == "run"
    assert normalize_run_id("") == ""


def test_sanitize_rel_path_handles_windows_invalid_chars() -> None:
    rel = r"a\b\c:d?.py"
    out = sanitize_rel_path(rel)
    assert out == "a/b/c_d_.py"


def test_write_json_atomic_writes_final_file(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b.json"
    write_json_atomic(target, {"k": 1})
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["k"] == 1
    assert not (target.with_suffix(".json.tmp")).exists()


def test_write_text_atomic_writes_final_file(tmp_path: Path) -> None:
    target = tmp_path / "x" / "y.txt"
    write_text_atomic(target, "hello")
    assert target.read_text(encoding="utf-8") == "hello"
    assert not (target.with_suffix(".txt.tmp")).exists()


def test_build_run_summary_and_markdown() -> None:
    summary = build_run_summary(
        mode="single_file",
        run_root="D:/tmp/run1",
        llm_runtime={
            "llm_enabled": False,
            "llm_preflight": "failed_fallback_static",
            "llm_error_category": "network_blocked",
            "llm_fallback_reason": "connection refused",
            "llm_preflight_request_count": 1,
            "llm_analysis_request_count": 2,
            "llm_source_review_request_count": 1,
            "llm_review_pass_request_count": 0,
            "llm_retry_count": 1,
            "llm_failure_categories": {"network_blocked": 1},
        },
        overview={
            "analysis_quality": "valid",
            "quality_issues": [],
            "total_files_analyzed": 1,
            "total_units": 2,
            "failed_file_count": 0,
            "high_risk_unit_count": 1,
            "decode_fallback_file_count": 1,
            "decode_fallback_file_ratio": 0.5,
            "read_error_file_count": 0,
            "skipped_file_count": 3,
            "skipped_by_reason": {"binary_file": 1, "excluded_dir": 2},
            "by_vulnerability_type": {"cmdi": 1},
            "by_change_type": {"new_code": 2},
            "review_queue": {"candidate_count": 2, "queued_count": 1, "llm_eligible_count": 1},
        },
        top_risky_files=[{"rel_path": "a.py", "risk_score": 8.2, "vulnerability_type": "cmdi"}],
    )
    assert summary["llm_error_category"] == "network_blocked"
    assert summary["llm_analysis_request_count"] == 2
    assert summary["llm_failure_categories"] == {"network_blocked": 1}
    assert summary["skipped_file_count"] == 3
    assert summary["skipped_by_reason"] == {"binary_file": 1, "excluded_dir": 2}
    assert summary["review_queue"]["queued_count"] == 1
    text = build_run_summary_markdown(summary)
    assert "Run root: D:/tmp/run1" in text
    assert "LLM fallback reason: connection refused" in text
    assert "Decode fallback files: 1 (50.00%)" in text
    assert "Skipped files: 3" in text
    assert "Skipped by reason: binary_file=1, excluded_dir=2" in text
    assert "Review queue: candidates=2, queued=1, llm_eligible=1" in text
    assert "- a.py | score=8.20 | type=cmdi" in text


def test_build_file_result_explanation() -> None:
    explanation = build_file_result_explanation(
        {
            "security_fix_units": 1,
            "new_vulnerability_units": 0,
            "new_attack_surface_units": 1,
            "primary_conclusion": {
                "change_type": "security_fix",
                "vulnerability_type": "security_hardening",
                "vulnerability_score": 5.0,
                "analysis_backend": "static",
                "decision_path": "static_security_fix",
                "analysis_reason": "heuristic_security_fix",
                "evidence": {
                    "observed_facts": {
                        "source_to_sink": {
                            "sources": ["request"],
                            "guards": ["validate(x)"],
                            "sinks": ["exec(x)"],
                            "condition_chain": "request -> validate -> exec",
                        }
                    },
                    "inferred_assessment": {
                        "source_to_sink": {
                            "sources": ["request"],
                            "guards": ["validate(x)"],
                            "sinks": ["exec(x)"],
                            "condition_chain": "request -> validate -> exec",
                        }
                    },
                    "ranked_candidates": [
                        {
                            "evidence": "guard added before sink",
                            "supporting_facts": {
                                "source_to_sink": {
                                    "sources": ["request"],
                                    "guards": ["validate(x)"],
                                    "sinks": ["exec(x)"],
                                    "condition_chain": "request -> validate -> exec",
                                },
                                "evidence_status": "observed",
                                "chain_completeness": "complete",
                                "inference_level": "none",
                            },
                        }
                    ],
                    "convenience_summary": {
                        "evidence_status": "observed",
                        "observed_chain_completeness": "complete",
                        "inferred_chain_completeness": "complete",
                        "inference_level": "none",
                        "assessment_basis": "static",
                        "review_reasons": [],
                    },
                },
            },
        }
    )
    assert explanation["observed_sources"] == ["request"]
    assert explanation["observed_guards"] == ["validate(x)"]
    assert explanation["observed_sinks"] == ["exec(x)"]
    assert explanation["analysis_backend"] == "static"
    assert explanation["decision_path"] == "static_security_fix"
    assert explanation["primary_evidence"] == "guard added before sink"
    assert explanation["evidence_status"] == "observed"


def test_build_high_risk_index_entries_are_unit_level() -> None:
    entries = build_high_risk_index_entries(
        rel_path="a.py",
        status="modified",
        language="python",
        concise_rows=[
            {"change_type": "new_code", "vulnerability_type": "cmdi", "vulnerability_score": 8.1},
            {"change_type": "new_code", "vulnerability_type": "none", "vulnerability_score": 2.0},
        ],
        units=[
            {
                "unit": {
                    "old_unit": "a.py:1",
                    "new_unit": "a.py:2",
                    "artifact": "a.py:2",
                    "file_path": "a.py",
                    "hunk_header": "@@ -1 +1 @@",
                    "old_line_range": [1, 1],
                    "new_line_range": [1, 2],
                    "old_focus_line_range": [1, 1],
                    "new_focus_line_range": [2, 2],
                    "old_symbol_context": {"display": "Runner.run"},
                    "new_symbol_context": {"display": "Runner.run"},
                }
            }
        ],
    )
    assert len(entries) == 1
    assert entries[0]["unit_index"] == 0
    assert entries[0]["artifact"] == "a.py:2"
    assert entries[0]["new_enclosing_symbol"] == "Runner.run"


def test_top_risky_file_entry_preserves_profile_selected_risk_score() -> None:
    entry = build_top_risky_file_entry(
        rel_path="a.py",
        language="python",
        status="modified",
        risk_score=6.4,
        unit_count=1,
    )
    assert entry["risk_score"] == 6.4
