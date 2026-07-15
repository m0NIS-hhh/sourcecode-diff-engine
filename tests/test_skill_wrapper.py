from __future__ import annotations

import json
from pathlib import Path

from scripts import run_skill_diff


def test_build_codex_summary_extracts_key_artifacts(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    (run_root / "summary.json").write_text(
        json.dumps(
            {
                "schema_version": "3.0",
                "mode": "single_file",
                "analysis_profile": "security",
                "analysis_quality": "valid",
                "total_files_analyzed": 1,
                "total_units": 2,
                "failed_file_count": 0,
                "skipped_file_count": 3,
                "high_risk_unit_count": 1,
                "llm_enabled": False,
                "llm_preflight": "disabled_by_mode",
                "quality_issues": [],
            }
        ),
        encoding="utf-8",
    )
    (run_root / "overview.json").write_text("{}", encoding="utf-8")
    (run_root / "meta.json").write_text("{}", encoding="utf-8")
    (run_root / "failed_pairs.json").write_text("[]", encoding="utf-8")
    (run_root / "high_risk_index.json").write_text(
        json.dumps(
            [
                {
                    "rel_path": "a.py",
                    "unit_index": 0,
                    "artifact": "a.py:1",
                    "risk_score": 8.6,
                    "vulnerability_type": "cmdi",
                    "change_type": "new_code",
                    "review_required": True,
                    "evidence_status": "observed",
                }
            ]
        ),
        encoding="utf-8",
    )

    out = run_skill_diff.build_codex_summary(run_root, {"ok": True, "issues": []})
    assert out["ok"] is True
    assert out["skipped_file_count"] == 3
    assert out["high_risk_unit_count"] == 1
    assert out["top_findings"][0]["rel_path"] == "a.py"
    assert out["artifact_paths"]["codex_summary_json"].endswith("codex_summary.json")


def test_skill_wrapper_runs_single_file_and_writes_codex_summary(tmp_path: Path, monkeypatch) -> None:
    old_path = tmp_path / "old.py"
    new_path = tmp_path / "new.py"
    old_path.write_text("def f(x):\n    return x\n", encoding="utf-8")
    new_path.write_text("def f(x):\n    y = x.strip()\n    return y\n", encoding="utf-8")

    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    args = run_skill_diff._build_parser().parse_args(
        [
            "--config",
            "config.json.example",
            "--data-folder",
            str(tmp_path),
            "--old-file",
            old_path.name,
            "--new-file",
            new_path.name,
            "--language",
            "python",
            "--profile",
            "generic",
            "--llm-mode",
            "off",
            "--output-root",
            str(tmp_path / "outputs"),
            "--run-id",
            "skill_test",
        ]
    )

    result = run_skill_diff.run(args)
    assert result["ok"] is True
    run_root = Path(result["artifact_paths"]["run_root"])
    assert (run_root / "codex_summary.json").exists()
    saved = json.loads((run_root / "codex_summary.json").read_text(encoding="utf-8"))
    assert saved["verification"]["ok"] is True
