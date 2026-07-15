from __future__ import annotations

import json
from pathlib import Path

from scripts.verify_run_consistency import verify_run


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _build_minimal_run(run_root: Path) -> None:
    _write_json(run_root / "meta.json", {"schema_version": "3.0"})
    _write_json(
        run_root / "overview.json",
        {
            "schema_version": "3.0",
            "total_files_analyzed": 1,
            "total_units": 1,
            "high_risk_unit_count": 1,
        },
    )
    _write_json(run_root / "results.json", [])
    _write_json(run_root / "detailed.json", {"schema_version": "3.0"})
    _write_json(run_root / "init_overview.json", {"schema_version": "3.0"})
    _write_json(run_root / "failed_pairs.json", [])
    _write_json(run_root / "high_risk_index.json", [{"rel_path": "a.py", "risk_score": 9.0}])
    _write_json(
        run_root / "pairs" / "a.py" / "results.json",
        [
            {
                "change_type": "\u6f0f\u6d1e\u4fee\u590d",
                "vulnerability_type": "\u5b89\u5168\u52a0\u56fa",
                "vulnerability_score": 9.0,
                "evidence": {
                    "observed_facts": {"source_to_sink": {"sources": [], "guards": [], "sinks": [], "condition_chain": "source -> guard -> sink"}},
                    "inferred_assessment": {
                        "source_to_sink": {"sources": [], "guards": [], "sinks": [], "condition_chain": "source -> guard -> sink"},
                        "summary": "",
                        "confidence": 0.0,
                        "reasoning_basis": "static",
                    },
                    "ranked_candidates": [],
                    "convenience_summary": {"verdict": "missing", "observed_chain_status": "partial", "assessment_basis": "static"},
                },
            }
        ],
    )


def test_verify_run_consistency_passes_on_consistent_run(tmp_path: Path) -> None:
    run_root = tmp_path / "run_ok"
    _build_minimal_run(run_root)
    report = verify_run(run_root)
    assert report["ok"] is True
    assert report["issues"] == []


def test_verify_run_consistency_fails_on_mismatch(tmp_path: Path) -> None:
    run_root = tmp_path / "run_bad"
    _build_minimal_run(run_root)
    _write_json(
        run_root / "overview.json",
        {
            "schema_version": "3.0",
            "total_files_analyzed": 2,
            "total_units": 3,
            "high_risk_unit_count": 0,
        },
    )
    report = verify_run(run_root)
    assert report["ok"] is False
    issues_text = " ".join(report["issues"])
    assert "total_files_analyzed_mismatch" in issues_text
    assert "total_units_mismatch" in issues_text
