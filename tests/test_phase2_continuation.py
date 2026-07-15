from __future__ import annotations

from analysis_pipeline import CHANGE_SECURITY_FIX, _detect_added_scope, analyze_diff_units_in_memory, assess_added_risk


class _LLMEnabled:
    enabled = True


class _LLMDisabled:
    enabled = False


class _LowScoreFixAnalyzer:
    llm = _LLMEnabled()

    @staticmethod
    def analyze_function_pair(**kwargs):
        return {
            "change_type": "婕忔礊淇",
            "vulnerability_type": "瀹夊叏鍔犲浐",
            "vulnerability_score": 1.0,
            "source_to_sink_conditions": {"sources": [], "guards": [], "sinks": [], "condition_chain": ""},
            "vulnerability_findings": [
                {
                    "type": "瀹夊叏鍔犲浐",
                    "score": 1.0,
                    "evidence": "guard added for command path",
                }
            ],
            "analysis_backend": "llm",
            "decision_path": "llm_primary",
            "analysis_reason": "llm_primary",
            "confidence": 0.8,
            "review_required": True,
            "llm_raw_text": "{\"change_type\":\"婕忔礊淇\"}",
        }


class _ShouldNotBeCalledAnalyzer:
    llm = _LLMEnabled()

    @staticmethod
    def analyze_function_pair(**kwargs):
        raise AssertionError("non-security branch should not invoke LLM review")


class _StaticOnlyAnalyzer:
    llm = _LLMDisabled()


def test_phase2_non_security_modification_keeps_low_score_and_skips_llm() -> None:
    result = analyze_diff_units_in_memory(
        analyzer=_ShouldNotBeCalledAnalyzer(),
        diff_units=[
            {
                "old_unit": "a.py:1",
                "new_unit": "a.py:1",
                "change_type": "modification",
                "old_code": "def metrics_name(v):\n    return v\n",
                "new_code": "def metrics_name(value):\n    return value\n",
                "similarity": 0.95,
            }
        ],
        language="python",
        git_diff_text="",
        analysis_profile="generic",
    )
    row = result["concise_rows"][0]
    unit = result["unit_rows"][0]
    assert row["change_type"] == "非安全性修改"
    assert float(row["vulnerability_score"]) <= 2.0
    assert unit["fix_assessment"]["is_security_fix"] is False
    assert unit["fix_assessment"]["llm_review_invoked"] is False


def test_phase2_security_fix_score_floor_is_enforced_in_pipeline() -> None:
    result = analyze_diff_units_in_memory(
        analyzer=_LowScoreFixAnalyzer(),
        diff_units=[
            {
                "old_unit": "a.py:1",
                "new_unit": "a.py:1",
                "change_type": "modification",
                "old_code": "def run(cmd):\n    os.system(cmd)\n",
                "new_code": "def run(cmd):\n    if not cmd.startswith('safe_'):\n        raise ValueError('bad')\n    subprocess.run(['echo', cmd])\n",
                "similarity": 0.7,
            }
        ],
        language="python",
        git_diff_text="",
        analysis_profile="security",
    )
    row = result["concise_rows"][0]
    unit = result["unit_rows"][0]
    assert row["change_type"] == CHANGE_SECURITY_FIX
    assert float(row["vulnerability_score"]) >= 5.0
    assert unit["fix_assessment"]["is_security_fix"] is True


def test_phase2_added_scope_returns_attack_surface_level() -> None:
    scope = _detect_added_scope(
        old_code="",
        new_code="@app.route('/run')\ndef run(cmd):\n    os.system(cmd)\n",
        artifact="api.py",
    )
    assert scope["has_new_attack_surface"] is True
    assert scope["attack_surface_level"] == "high"


def test_phase2_added_scope_uses_symbol_context_for_entrypoint_flags() -> None:
    scope = _detect_added_scope(
        old_code="class ApiController:\n    def run(self, value):\n        return value\n",
        new_code="class ApiController:\n    def run(self, value):\n        logger.info(value)\n        return value\n",
        artifact="api.py",
        new_symbol_context={
            "language": "python",
            "display": "ApiController.run",
            "symbols": [
                {"kind": "class", "name": "ApiController", "signature": "class ApiController", "line_range": [1, 10]},
                {"kind": "function", "name": "run", "signature": "def run(self, value):", "line_range": [2, 4]},
            ],
            "innermost_symbol": {"kind": "function", "name": "run", "signature": "def run(self, value):", "line_range": [2, 4]},
        },
    )
    assert scope["has_new_attack_surface"] is True
    assert "entrypoint_like_symbol_context" in scope["attack_surface_flags"]
    assert "handler_or_controller_context" in scope["attack_surface_flags"]
    assert scope["attack_surface_level"] == "medium"


def test_phase2_added_scope_marks_magic_method_context() -> None:
    scope = _detect_added_scope(
        old_code="class Runner:\n    pass\n",
        new_code="class Runner:\n    def __call__(self, cmd):\n        return cmd\n",
        artifact="runner.py",
        new_symbol_context={
            "language": "python",
            "display": "Runner.__call__",
            "symbols": [
                {"kind": "class", "name": "Runner", "signature": "class Runner", "line_range": [1, 4]},
                {"kind": "function", "name": "__call__", "signature": "def __call__(self, cmd):", "line_range": [2, 3]},
            ],
            "innermost_symbol": {"kind": "function", "name": "__call__", "signature": "def __call__(self, cmd):", "line_range": [2, 3]},
        },
    )
    assert "constructor_or_magic_method_context" in scope["attack_surface_flags"]
    assert "entrypoint_like_symbol_context" in scope["attack_surface_flags"]


def test_phase2_added_scope_filters_java_bean_noise_from_new_entries() -> None:
    scope = _detect_added_scope(
        old_code="public class DeviceInfo {\n}\n",
        new_code=(
            "public class DeviceInfo {\n"
            "    public String getName() { return name; }\n"
            "    public void setName(String name) { this.name = name; }\n"
            "    public boolean isActive() { return active; }\n"
            "    public DeviceInfo name(String name) { this.name = name; return this; }\n"
            "    public DeviceInfo build() { return this; }\n"
            "}\n"
        ),
        artifact="DeviceInfo.java",
        new_symbol_context={"language": "java"},
    )
    assert scope["has_new_attack_surface"] is False
    assert scope["new_callable_entries"] == []
    assert "new_callable_entry" not in scope["attack_surface_flags"]


def test_phase2_added_risk_uses_lightweight_dataflow_from_parameters() -> None:
    risk = assess_added_risk(
        "def run(command):\n    cmd = command\n    os.system(cmd)\n",
        language="python",
    )
    assert risk["has_new_vulnerability"] is True
    assert any(str(hit).startswith("tainted_var:") for hit in risk.get("source_hits", []))


def test_phase2_unit_detail_preserves_hunk_and_symbol_metadata() -> None:
    result = analyze_diff_units_in_memory(
        analyzer=_ShouldNotBeCalledAnalyzer(),
        diff_units=[
            {
                "old_unit": "a.py:10",
                "new_unit": "a.py:10",
                "change_type": "modification",
                "old_code": "def run(value):\n    return value\n",
                "new_code": "def run(user_value):\n    return user_value\n",
                "similarity": 0.98,
                "file_path": "a.py",
                "old_start": 10,
                "new_start": 10,
                "old_focus_line_range": [10, 11],
                "new_focus_line_range": [10, 13],
                "hunk_header": "@@ -10,2 +10,4 @@",
                "old_symbol_context": {
                    "language": "python",
                    "line_range": [10, 11],
                    "display": "run",
                    "symbols": [{"kind": "function", "name": "run", "signature": "def run(cmd)", "line_range": [10, 11]}],
                    "innermost_symbol": {"kind": "function", "name": "run", "signature": "def run(value)", "line_range": [10, 11]},
                },
                "new_symbol_context": {
                    "language": "python",
                    "line_range": [10, 13],
                    "display": "run",
                    "symbols": [{"kind": "function", "name": "run", "signature": "def run(cmd)", "line_range": [10, 13]}],
                    "innermost_symbol": {"kind": "function", "name": "run", "signature": "def run(user_value)", "line_range": [10, 13]},
                },
            }
        ],
        language="python",
        git_diff_text="",
        analysis_profile="generic",
    )

    unit_meta = result["unit_rows"][0]["unit"]
    assert unit_meta["hunk_header"] == "@@ -10,2 +10,4 @@"
    assert unit_meta["old_line_range"] == [10, 11]
    assert unit_meta["new_focus_line_range"] == [10, 13]
    assert unit_meta["new_symbol_context"]["display"] == "run"


def test_phase2_pipeline_passes_symbol_context_into_static_checks() -> None:
    result = analyze_diff_units_in_memory(
        analyzer=_StaticOnlyAnalyzer(),
        diff_units=[
            {
                "old_unit": "api.py:1",
                "new_unit": "api.py:1",
                "change_type": "added",
                "old_code": "",
                "new_code": "class ApiController:\n    def run(self, cmd):\n        os.system(cmd)\n",
                "similarity": 0.0,
                "file_path": "api.py",
                "new_symbol_context": {
                    "language": "python",
                    "display": "ApiController.run",
                    "symbols": [
                        {"kind": "class", "name": "ApiController", "signature": "class ApiController", "line_range": [1, 4]},
                        {"kind": "function", "name": "run", "signature": "def run(self, cmd):", "line_range": [2, 3]},
                    ],
                    "innermost_symbol": {"kind": "function", "name": "run", "signature": "def run(self, cmd):", "line_range": [2, 3]},
                },
            }
        ],
        language="python",
        git_diff_text="",
        analysis_profile="generic",
    )
    unit = result["unit_rows"][0]
    assert "symbol_name:run" in unit["new_vuln_check"].get("entrypoint_hits", [])
    assert "entrypoint_like_symbol_context" in unit["new_attack_surface"]["attack_surface_flags"]
