from __future__ import annotations

import json
from pathlib import Path

from directory_runner import run_directory_analysis
from source_analyzer import SourceAnalyzer


def _build_analyzer() -> SourceAnalyzer:
    return SourceAnalyzer(
        model="gpt-5.3-codex",
        base_url="",
        api_key="",
        prompts_file="prompts.yaml",
    )


def _evidence(score: float, evidence: str, *, vuln_type: str = "x", sources: list[str] | None = None, guards: list[str] | None = None, sinks: list[str] | None = None, chain: str = "") -> dict:
    src = list(sources or [])
    grd = list(guards or [])
    snk = list(sinks or [])
    return {
        "observed_facts": {"source_to_sink": {"sources": src, "guards": grd, "sinks": snk, "condition_chain": chain}},
        "inferred_assessment": {
            "source_to_sink": {"sources": src, "guards": grd, "sinks": snk, "condition_chain": chain},
            "summary": evidence,
            "confidence": 0.0,
            "reasoning_basis": "static",
        },
        "ranked_candidates": [
            {
                "vulnerability_type": vuln_type,
                "score": score,
                "evidence": evidence,
                "source_hits": src,
                "guard_hits": grd,
                "sink_hits": snk,
                "condition_chain": chain,
            }
        ],
        "convenience_summary": {
            "verdict": "observed" if src and snk and chain else "missing",
            "observed_chain_status": "complete" if src and grd and snk and chain else ("partial" if src or grd or snk or chain else "missing"),
            "assessment_basis": "static",
            "primary_evidence": evidence,
            "review_required": False,
        },
    }


def test_run_level_and_pair_level_counts_are_consistent(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "directory_runner.build_directory_pairs",
        lambda **_: {
            "old_root": "old",
            "new_root": "new",
            "old_file_count": 2,
            "new_file_count": 2,
            "pair_count": 2,
            "pairs": [
                {"rel_path": "a.py", "status": "modified", "old_path": "old/a.py", "new_path": "new/a.py"},
                {"rel_path": "b.py", "status": "modified", "old_path": "old/b.py", "new_path": "new/b.py"},
            ],
        },
    )
    monkeypatch.setattr("directory_runner._files_identical", lambda *_: False)
    monkeypatch.setattr("directory_runner._write_checkpoint", lambda *_: None)

    def fake_analyze_pair(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        rel = str(pair["rel_path"])
        score = 8.1 if rel == "a.py" else 1.0
        row = {
            "change_type": "\u65b0\u589e\u4ee3\u7801",
            "vulnerability_type": "\u547d\u4ee4\u6267\u884c\u98ce\u9669" if score >= 7.0 else "\u65e0\u65b0\u589e\u6f0f\u6d1e",
            "vulnerability_score": score,
            "evidence": _evidence(score, "e", vuln_type="x", sources=["input"], sinks=["exec"], chain="s-g-k"),
        }
        return {
            "pair_key": pair["_pair_key"],
            "file_row": {
                "rel_path": rel,
                "status": "modified",
                "language": "python",
                "unit_count": 1,
                "overview": {"total_units": 1},
                "detail": {
                    "units": [
                        {
                            "unit": {
                                "old_unit": f"{rel}:1",
                                "new_unit": f"{rel}:1",
                                "artifact": f"{rel}:1",
                                "file_path": rel,
                                "hunk_header": "@@ -1 +1 @@",
                                "old_line_range": [1, 1],
                                "new_line_range": [1, 1],
                                "old_focus_line_range": [1, 1],
                                "new_focus_line_range": [1, 1],
                                "old_symbol_context": {"display": "run"},
                                "new_symbol_context": {"display": "run"},
                            }
                        }
                    ],
                    "file_summary": {"primary_conclusion": row},
                },
            },
            "concise_rows": [row],
            "init_report": {
                "file_kind": "text",
                "hunk_count": 1,
                "added_line_count": 3,
                "deleted_line_count": 1,
                "zero_unit_reason": "",
                "diff_return_code": 1,
                "read_summary": {
                    "decode_fallback_count": 0,
                    "read_error_count": 0,
                },
            },
            "git_diff_text": "@@ -1 +1 @@",
        }

    monkeypatch.setattr("directory_runner._analyze_pair", fake_analyze_pair)

    out_root = tmp_path / "outputs"
    result = run_directory_analysis(
        analyzer=_build_analyzer(),
        old_root="old",
        new_root="new",
        output_root=str(out_root),
        run_id="consistency",
        language="auto",
        max_units_per_file=1,
        max_files=0,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=str(tmp_path / "cp.json"),
        resume=False,
    )
    run_root = Path(result["run_root"])
    overview = json.loads((run_root / "overview.json").read_text(encoding="utf-8"))
    high_index = json.loads((run_root / "high_risk_index.json").read_text(encoding="utf-8"))
    summary = json.loads((run_root / "summary.json").read_text(encoding="utf-8"))

    pair_results = list((run_root / "pairs").rglob("results.json"))
    all_rows = []
    for path in pair_results:
        all_rows.extend(json.loads(path.read_text(encoding="utf-8")))

    assert overview["total_files_analyzed"] == len(pair_results) == 2
    assert overview["total_units"] == len(all_rows) == 2
    assert overview["high_risk_unit_count"] == 1
    assert summary["total_files_analyzed"] == 2
    assert overview["decode_fallback_file_count"] == 0
    assert overview["read_error_file_count"] == 0
    assert len(high_index) == 1
    assert high_index[0]["new_enclosing_symbol"] == "run"
    assert high_index[0]["new_focus_line_range"] == [1, 1]
    assert overview["by_change_type"] == {"\u65b0\u589e\u4ee3\u7801": 2}
