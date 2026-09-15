from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from source_diff_engine.analysis.pipeline import analyze_diff_units
from source_diff_engine.source_analyzer import SourceAnalyzer

TEMP_ROOT = Path(".tmp/test-runs")


def test_llm_fallback_still_outputs_complete_files() -> None:
    root = TEMP_ROOT / f"tmp_{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    output = root / "vulnerability_analysis_results.json"
    detailed = root / "vulnerability_analysis_results_detailed.json"
    overview = root / "vulnerability_analysis_overview.json"

    analyzer = SourceAnalyzer(
        model="gpt-5.3-codex",
        base_url="",
        api_key="",  # force fallback
        prompts_file="prompts.yaml",
    )
    diff_units = [
        {
            "old_unit": "a.py:1->1",
            "new_unit": "a.py:1->1",
            "similarity": 0.7,
            "change_type": "modification",
            "old_code": "def run(cmd):\n    return cmd\n",
            "new_code": "def run(cmd):\n    if len(cmd) > 64:\n        raise ValueError('too long')\n    return cmd\n",
            "file_path": "a.py",
        }
    ]
    analyze_diff_units(analyzer, diff_units, str(output), str(detailed), str(overview))
    concise = json.loads(output.read_text(encoding="utf-8"))
    detail = json.loads(detailed.read_text(encoding="utf-8"))
    over = json.loads(overview.read_text(encoding="utf-8"))

    assert len(concise) == 1
    assert isinstance(detail, dict)
    assert "git_diff" in detail
    assert "units" in detail and isinstance(detail["units"], list) and len(detail["units"]) == 1
    assert "file_summary" in detail
    assert "language" in detail
    assert over.get("schema_version") == "3.0"
    assert over.get("total_units") == 1
    assert "by_vulnerability_type" in over
    assert "by_change_type" in over
    assert "high_risk_unit_count" in over
    row = concise[0]
    assert "change_type" in row
    assert "vulnerability_type" in row
    assert "vulnerability_score" in row
    assert "evidence" in row
    assert {
        "change_type",
        "change_intent",
        "behavioral_impact",
        "interface_impact",
        "security_impact",
        "attack_surface_impact",
        "capability_expansion",
        "vulnerability_type",
        "vulnerability_score",
        "evidence",
        "analysis_backend",
        "decision_path",
        "analysis_reason",
        "confidence",
        "review_required",
    }.issubset(set(row.keys()))
    drow = detail["units"][0]
    assert "unit" in drow
    assert "fix_assessment" in drow
    assert "new_vuln_check" in drow
    assert "new_attack_surface" in drow
    assert drow["fix_assessment"]["analysis_backend"] == "static"
    assert drow["fix_assessment"]["decision_path"] == "generic_change"
    assert drow["fix_assessment"]["analysis_reason"] == "generic_change"
    assert "evidence" in drow["fix_assessment"]
    assert detail["file_summary"]["primary_conclusion"]["analysis_backend"] == "static"
    assert detail["file_summary"]["primary_conclusion"]["decision_path"] == "generic_change"
    assert detail["file_summary"]["primary_conclusion"]["analysis_reason"] == "generic_change"
    shutil.rmtree(root, ignore_errors=True)
