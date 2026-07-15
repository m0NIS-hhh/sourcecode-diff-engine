from __future__ import annotations

from source_analyzer import SourceAnalyzer


def test_normalize_schema_accepts_prompt_contract_vulnerability_types() -> None:
    cases = [
        ("ssrf", SourceAnalyzer.VULNERABILITY_TYPE_MAP["ssrf"]),
        ("unsafe reflection", SourceAnalyzer.VULNERABILITY_TYPE_MAP["unsafe reflection"]),
        ("file upload", SourceAnalyzer.VULNERABILITY_TYPE_MAP["file upload"]),
    ]

    for raw_type, expected in cases:
        normalized = SourceAnalyzer._normalize_schema(
            {
                "change_type": "new code",
                "vulnerability_type": raw_type,
                "vulnerability_score": 7.4,
                "source_to_sink_conditions": {
                    "sources": ["request.args['target']"],
                    "guards": [],
                    "sinks": ["client.get(target)"],
                    "condition_chain": "request.args['target'] -> client.get(target)",
                },
                "vulnerability_findings": [
                    {
                        "type": raw_type,
                        "score": 7.4,
                        "evidence": "code-grounded evidence",
                    }
                ],
                "confidence": 0.8,
                "review_required": True,
                "analysis_backend": "llm",
                "decision_path": "llm_primary",
                "analysis_reason": "llm_primary",
            }
        )

        assert normalized["vulnerability_type"] == expected
        assert normalized["vulnerability_findings"][0]["type"] == expected
        assert normalized["valid"] is True


def test_normalize_schema_rejects_legacy_vulnerability_aliases() -> None:
    normalized = SourceAnalyzer._normalize_schema(
        {
            "change_type": "new code",
            "vulnerability_type": "sqli",
            "vulnerability_score": 7.4,
            "source_to_sink_conditions": {
                "sources": ["request.args['target']"],
                "guards": [],
                "sinks": ["client.get(target)"],
                "condition_chain": "request.args['target'] -> client.get(target)",
            },
            "vulnerability_findings": [
                {
                    "type": "sqli",
                    "score": 7.4,
                    "evidence": "code-grounded evidence",
                }
            ],
            "confidence": 0.8,
            "review_required": True,
            "analysis_backend": "llm",
            "decision_path": "llm_primary",
            "analysis_reason": "llm_primary",
        }
    )

    assert normalized["valid"] is False
