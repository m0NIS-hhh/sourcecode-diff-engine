from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from analysis_pipeline import CHANGE_SECURITY_FIX, analyze_diff_units, assess_modification_security_intent
from preprocessor import SourcePreprocessor
from source_analyzer import SourceAnalyzer

FIXTURE_ROOT = Path("tests/fixtures/basic")
TEMP_ROOT = Path(".tmp/test-runs")


def test_java_path_boundary_fix_is_security_fix_intent() -> None:
    old_code = """
boolean isInside(Path base, Path candidate) {
    return candidate.normalize().startsWith(base.normalize());
}
"""
    new_code = """
boolean isInside(Path base, Path candidate) {
    Path b = base.toAbsolutePath().normalize();
    Path c = candidate.toAbsolutePath().normalize();
    return c.startsWith(b) && c.getNameCount() >= b.getNameCount();
}
"""
    intent = assess_modification_security_intent(old_code, new_code, language="java")
    assert intent["is_security_fix"] is True


def test_java_security_fix_path_goes_through_security_review_branch() -> None:
    root = TEMP_ROOT / f"tmp_java_fix_{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    output = root / "vulnerability_analysis_results.json"
    detailed = root / "vulnerability_analysis_results_detailed.json"
    overview = root / "vulnerability_analysis_overview.json"

    old_file = FIXTURE_ROOT / "old.java"
    new_file = FIXTURE_ROOT / "new.java"
    pre = SourcePreprocessor(language="java")
    data = pre.process_source_diff(str(old_file), str(new_file))
    assert len(data["diff_units"]) >= 1

    analyzer = SourceAnalyzer(
        model="gpt-5.3-codex",
        base_url="",
        api_key="",  # keep deterministic fallback path in CI
        prompts_file="prompts.yaml",
    )
    analyze_diff_units(
        analyzer=analyzer,
        diff_units=data["diff_units"],
        output_file=str(output),
        detailed_output_file=str(detailed),
        overview_output_file=str(overview),
        language="java",
        analysis_profile="security",
    )

    rows = json.loads(output.read_text(encoding="utf-8"))
    assert len(rows) >= 1
    row = rows[0]
    assert row["analysis_profile"] == "security"
    assert row["change_type"] == CHANGE_SECURITY_FIX
    assert float(row.get("vulnerability_score", 0.0)) >= 5.0
    assert "evidence" in row
    assert "ranked_candidates" in row["evidence"]
    shutil.rmtree(root, ignore_errors=True)
