from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from analysis_pipeline import analyze_diff_units
from source_analyzer import SourceAnalyzer

TEMP_ROOT = Path(".tmp/test-runs")


def test_single_hunk_can_emit_multiple_vulnerability_results() -> None:
    root = TEMP_ROOT / f"tmp_multi_{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    output = root / "vulnerability_analysis_results.json"
    detailed = root / "vulnerability_analysis_results_detailed.json"
    overview = root / "vulnerability_analysis_overview.json"

    old_code = """def parse_chunk_header(line: str) -> tuple[int, str]:
    size_part, _, ext = line.partition(';')
    size = int(size_part.strip(), 16)
    return size, ext.strip()
def render_index(names: list[str]) -> str:
    rows = []
    for name in names:
        rows.append(f'<li><a href="{name}">{name}</a></li>')
    return '<ul>' + ''.join(rows) + '</ul>'
def json_key_sql(key: str) -> str:
    alias = f'"{key}"'
    return f'SELECT payload ->> %s AS {alias} FROM events'
"""

    new_code = """from html import escape
from urllib.parse import quote
import re
def parse_chunk_header(line: str) -> tuple[int, str]:
    size_part, _, ext = line.partition(';')
    if '\\r' in ext or '\\n' in ext:
        raise ValueError('invalid chunk extension')
    size = int(size_part.strip(), 16)
    return size, ext.strip()
def render_index(names: list[str]) -> str:
    rows = []
    for name in names:
        rows.append(f'<li><a href="{quote(name)}">{escape(name)}</a></li>')
    return '<ul>' + ''.join(rows) + '</ul>'
_ALIAS = re.compile(r'^[A-Za-z0-9_]+$')
def json_key_sql(key: str) -> str:
    safe = key if _ALIAS.match(key) else 'key_alias'
    alias = f'"{safe}"'
    return f'SELECT payload ->> %s AS {alias} FROM events'
"""

    analyzer = SourceAnalyzer(
        model="gpt-5.3-codex",
        base_url="",
        api_key="",  # force fallback
        prompts_file="prompts.yaml",
    )
    diff_units = [
        {
            "old_unit": "tests/fixtures/basic/old.py:1",
            "new_unit": "tests/fixtures/basic/new.py:1",
            "similarity": 0.6,
            "change_type": "modification",
            "old_code": old_code,
            "new_code": new_code,
            "file_path": "tests/fixtures/basic/new.py",
        }
    ]

    analyze_diff_units(
        analyzer=analyzer,
        diff_units=diff_units,
        output_file=str(output),
        detailed_output_file=str(detailed),
        overview_output_file=str(overview),
        language="python",
    )
    concise = json.loads(output.read_text(encoding="utf-8"))
    detail = json.loads(detailed.read_text(encoding="utf-8"))
    assert len(concise) == 1
    assert isinstance(detail, dict)
    assert len(detail.get("units", [])) == 1
    assert all(float(row.get("vulnerability_score", 0.0)) > 0.0 for row in concise)
    for row in concise:
        for key in (
            "change_type",
            "vulnerability_type",
            "vulnerability_score",
            "evidence",
        ):
            assert key in row
    drow = detail["units"][0]
    assert "fix_assessment" in drow
    assert "new_vuln_check" in drow
    assert "new_attack_surface" in drow

    shutil.rmtree(root, ignore_errors=True)
