from __future__ import annotations

from source_diff_engine.llm.client import OpenCodeLLM
from source_diff_engine.source_analyzer import SourceAnalyzer


def test_parse_response_handles_fenced_json_and_normalizes_schema() -> None:
    content = """```json
{
  "change_type": "\\u6f0f\\u6d1e\\u4fee\\u590d",
  "vulnerability_type": "\\u547d\\u4ee4\\u6267\\u884c\\u98ce\\u9669",
  "vulnerability_score": "9.7",
  "source_to_sink_conditions": {"sources": "request.args", "guards": [], "sinks": ["os.system(cmd)"], "condition_chain": "source->sink"},
  "vulnerability_findings": [{"type": "\\u547d\\u4ee4\\u6267\\u884c\\u98ce\\u9669", "score": "9", "evidence": "user input to os.system"}]
}
```"""
    parsed = SourceAnalyzer._parse_response(content)
    assert parsed["valid"] is True
    assert isinstance(parsed["source_to_sink_conditions"]["sources"], list)
    assert parsed["vulnerability_findings"][0]["type"] == "\u547d\u4ee4\u6267\u884c\u98ce\u9669"
    assert parsed["vulnerability_score"] == 9.7


class _FakeResponse:
    output_text = ""
    output = []

    @staticmethod
    def model_dump():
        return {
            "status": "completed",
            "output_text": '{"ok": true}',
            "output": [],
            "usage": {"output_tokens": 5},
        }


def test_extract_responses_text_falls_back_to_model_dump_output_text() -> None:
    text = OpenCodeLLM._extract_responses_text(_FakeResponse())
    assert text == '{"ok": true}'
