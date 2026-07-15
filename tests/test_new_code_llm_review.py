from __future__ import annotations

from analysis_pipeline import analyze_diff_units_in_memory


class _LLMEnabled:
    enabled = True


class _NewCodeReviewAnalyzer:
    llm = _LLMEnabled()

    @staticmethod
    def analyze_function_pair(**kwargs):
        assert kwargs["scenario"] == "new_code"
        return {
            "change_type": "new code",
            "vulnerability_type": "SQL Injection",
            "vulnerability_score": 9.1,
            "source_to_sink_conditions": {
                "sources": ["request.args['sql']"],
                "guards": ["no parameterization guard"],
                "sinks": ["cursor.execute(sql)"],
                "condition_chain": "request args -> missing parameterization guard -> cursor.execute",
            },
            "vulnerability_findings": [
                {
                    "type": "SQL Injection",
                    "score": 9.1,
                    "evidence": "query parameter flows into cursor.execute without parameterization",
                }
            ],
            "analysis_backend": "llm",
            "decision_path": "llm_primary",
            "analysis_reason": "llm_primary",
            "confidence": 0.91,
            "review_required": True,
            "llm_raw_text": '{"change_type":"new code"}',
        }


def test_new_code_high_risk_branch_uses_llm_review_when_available() -> None:
    result = analyze_diff_units_in_memory(
        analyzer=_NewCodeReviewAnalyzer(),
        diff_units=[
            {
                "old_unit": None,
                "new_unit": "a.py:added->1",
                "change_type": "added",
                "old_code": "",
                "new_code": "sql = request.args.get('sql')\ncursor.execute(sql)\n",
                "similarity": 0.0,
                "file_path": "a.py",
            }
        ],
        language="python",
        git_diff_text="",
        analysis_profile="security",
    )

    row = result["concise_rows"][0]
    unit = result["unit_rows"][0]
    assert float(row["vulnerability_score"]) >= 9.1
    assert row["analysis_profile"] == "security"
    assert unit["new_vuln_check"]["llm_review_invoked"] is True
    assert unit["new_vuln_check"]["llm_confirmed"] is True
    assert float(unit["new_vuln_check"]["llm_review_confidence"]) >= 0.9
    inferred = row["evidence"]["inferred_assessment"]["source_to_sink"]
    assert "cursor.execute" in " ".join(inferred["sinks"])
    assert any("parameterization" in finding["evidence"] for finding in row["evidence"]["ranked_candidates"])
