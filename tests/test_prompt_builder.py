from __future__ import annotations

from source_diff_engine.llm.prompt_builder import PromptBuilder


def test_prompt_builder_builds_active_prompts() -> None:
    builder = PromptBuilder("prompts.yaml")
    payload = {
        "old_unit": "a.py:1",
        "new_unit": "a.py:2",
        "similarity": "0.5",
        "old_code": "old()",
        "new_code": "new()",
        "local_context": "{}",
    }

    fix_prompt = builder.build("security_review_fix", **payload)
    new_code_prompt = builder.build("security_review_new_code", **payload)
    review_prompt = builder.build(
        "source_review",
        scenario="security_fix",
        old_unit="a.py:1",
        new_unit="a.py:2",
        old_code="old()",
        new_code="new()",
        analysis_json="{}",
    )

    assert "Return exactly one JSON object" in fix_prompt
    assert "Return exactly one JSON object" in new_code_prompt
    assert '"review_required"' in review_prompt


def test_prompt_builder_security_prompts_cover_runtime_supported_vulnerability_types() -> None:
    builder = PromptBuilder("prompts.yaml")
    payload = {
        "old_unit": "a.py:1",
        "new_unit": "a.py:2",
        "similarity": "0.5",
        "old_code": "old()",
        "new_code": "new()",
        "local_context": "{}",
    }

    runtime_types = {
        "command execution",
        "sql injection",
        "path traversal",
        "deserialization",
        "credential leak",
        "xss",
        "code injection",
        "security hardening",
        "ssrf",
        "unsafe reflection",
        "file upload",
        "none",
        "unknown",
    }
    prompts = [
        builder.build("security_review", **payload),
        builder.build("security_review_fix", **payload),
        builder.build("security_review_new_code", **payload),
        builder.build("security_review_hardening", **payload),
    ]

    for prompt in prompts:
        for vuln_type in runtime_types:
            assert vuln_type in prompt
