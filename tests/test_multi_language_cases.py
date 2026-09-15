from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from source_diff_engine.analysis.pipeline import analyze_diff_units
from source_diff_engine.preprocess.source_preprocessor import SourcePreprocessor
from source_diff_engine.source_analyzer import SourceAnalyzer

REQUIRED_FIELDS = [
    "change_type",
    "vulnerability_type",
    "vulnerability_score",
    "evidence",
]

FIXTURE_ROOT = Path("tests/fixtures/basic")
TEMP_ROOT = Path(".tmp/test-runs")


def _run_pair(old_file: Path, new_file: Path, language: str) -> None:
    root = TEMP_ROOT / f"tmp_matrix_{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    output = root / "vulnerability_analysis_results.json"
    detailed = root / "vulnerability_analysis_results_detailed.json"
    overview = root / "vulnerability_analysis_overview.json"

    pre = SourcePreprocessor(language=language)
    data = pre.process_source_diff(str(old_file), str(new_file))
    assert len(data["diff_units"]) >= 1

    analyzer = SourceAnalyzer(
        model="gpt-5.3-codex",
        base_url="",
        api_key="",
        prompts_file="prompts.yaml",
    )
    analyze_diff_units(
        analyzer=analyzer,
        diff_units=data["diff_units"],
        output_file=str(output),
        detailed_output_file=str(detailed),
        overview_output_file=str(overview),
        language=language,
    )
    concise = json.loads(output.read_text(encoding="utf-8"))
    assert len(concise) >= 1
    for row in concise:
        for key in REQUIRED_FIELDS:
            assert key in row

    shutil.rmtree(root, ignore_errors=True)


def test_python_pairs_protocol() -> None:
    root = FIXTURE_ROOT
    pairs = [(root / "old.py", root / "new.py")]
    for old_file, new_file in pairs:
        _run_pair(old_file, new_file, "python")


def test_java_pairs_protocol() -> None:
    root = FIXTURE_ROOT
    pairs = [(root / "old.java", root / "new.java")]
    for old_file, new_file in pairs:
        _run_pair(old_file, new_file, "java")


def test_php_pairs_protocol() -> None:
    root = FIXTURE_ROOT
    pairs = [(root / "old.php", root / "new.php")]
    for old_file, new_file in pairs:
        _run_pair(old_file, new_file, "php")
