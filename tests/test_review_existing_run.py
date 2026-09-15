from __future__ import annotations

import json
from pathlib import Path

from source_diff_engine.directory.runner import review_existing_directory_run


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


class _ReviewAnalyzer:
    class _LLM:
        enabled = True

    llm = _LLM()

    @staticmethod
    def analyze_function_pair(**kwargs):
        assert kwargs["scenario"] == "new_code"
        assert "cursor.execute(sql)" in kwargs["new_code"]
        return {
            "change_type": "new code",
            "vulnerability_type": "SQL Injection",
            "vulnerability_score": 9.4,
            "source_to_sink_conditions": {
                "sources": ["request.args['sql']"],
                "guards": [],
                "sinks": ["cursor.execute(sql)"],
                "condition_chain": "request.args -> cursor.execute",
            },
            "vulnerability_findings": [
                {
                    "type": "SQL Injection",
                    "score": 9.4,
                    "evidence": "tainted sql reaches cursor.execute",
                }
            ],
            "confidence": 0.95,
            "review_required": False,
        }


def _review_evidence(score: float, evidence: str) -> dict:
    return {
        "observed_facts": {
            "source_to_sink": {
                "sources": ["request.args['sql']"],
                "guards": [],
                "sinks": ["cursor.execute(sql)"],
                "condition_chain": "request.args -> cursor.execute",
            }
        },
        "inferred_assessment": {
            "source_to_sink": {
                "sources": ["request.args['sql']"],
                "guards": [],
                "sinks": ["cursor.execute(sql)"],
                "condition_chain": "request.args -> cursor.execute",
            },
            "summary": evidence,
            "confidence": 0.95,
            "reasoning_basis": "llm",
        },
        "ranked_candidates": [
            {
                "vulnerability_type": "SQL注入风险",
                "score": score,
                "evidence": evidence,
                "source_hits": ["request.args['sql']"],
                "guard_hits": [],
                "sink_hits": ["cursor.execute(sql)"],
                "condition_chain": "request.args -> cursor.execute",
            }
        ],
        "convenience_summary": {},
    }


def test_review_existing_directory_run_replays_targets_from_meta_and_queue(tmp_path: Path) -> None:
    old_root = tmp_path / "old"
    new_root = tmp_path / "new"
    run_root = tmp_path / "outputs" / "run1"

    _write(old_root / "a.py", "def run(request, cursor):\n    return None\n")
    _write(
        new_root / "a.py",
        "def run(request, cursor):\n    sql = request.args.get('sql')\n    cursor.execute(sql)\n",
    )

    _write_json(
        run_root / "meta.json",
        {
            "schema_version": "3.0",
            "mode": "directory",
            "old_root": str(old_root),
            "new_root": str(new_root),
        },
    )
    _write_json(
        run_root / "high_risk_review_queue.json",
        [
                {
                    "rel_path": "a.py",
                    "unit_index": 0,
                    "artifact": "a.py:1",
                    "risk_score": 8.8,
                    "change_type": "新增代码",
                    "review_required": True,
                    "llm_review_eligible": True,
                }
        ],
    )

    report = review_existing_directory_run(
        analyzer=_ReviewAnalyzer(),
        run_root=str(run_root),
        review_score_threshold=7.0,
        review_top_n=5,
    )

    results = report["results"]
    assert len(results) == 1
    assert results[0]["rel_path"] == "a.py"
    assert results[0]["llm_verdict"] == "SQL注入风险"
    assert results[0]["review_required"] is False
    assert "cursor.execute" in results[0]["llm_reason"]

    summary = json.loads((run_root / "high_risk_review_summary.json").read_text(encoding="utf-8"))
    assert summary["selected_count"] == 1
    assert summary["completed_count"] == 1


def test_review_existing_directory_run_resumes_from_checkpoint(tmp_path: Path) -> None:
    old_root = tmp_path / "old"
    new_root = tmp_path / "new"
    run_root = tmp_path / "outputs" / "run2"

    _write(old_root / "a.py", "def run(request, cursor):\n    return None\n")
    _write(old_root / "b.py", "def run(request, cursor):\n    return None\n")
    _write(new_root / "a.py", "def run(request, cursor):\n    sql = request.args.get('sql')\n    cursor.execute(sql)\n")
    _write(new_root / "b.py", "def run(request, cursor):\n    sql = request.args.get('sql')\n    cursor.execute(sql)\n")

    _write_json(
        run_root / "meta.json",
        {
            "schema_version": "3.0",
            "mode": "directory",
            "old_root": str(old_root),
            "new_root": str(new_root),
        },
    )
    _write_json(
        run_root / "high_risk_review_queue.json",
        [
            {"rel_path": "a.py", "unit_index": 0, "artifact": "a.py:1", "risk_score": 8.8, "change_type": "新增代码", "review_required": True, "llm_review_eligible": True},
            {"rel_path": "b.py", "unit_index": 0, "artifact": "b.py:1", "risk_score": 8.5, "change_type": "新增代码", "review_required": True, "llm_review_eligible": True},
        ],
    )
    _write_json(
        run_root / "high_risk_review_checkpoint.json",
        {
            "version": 1,
            "selected": ["a.py|0|a.py:1", "b.py|0|b.py:1"],
            "completed": {
                "a.py|0|a.py:1": {
                    "rel_path": "a.py",
                    "unit_index": 0,
                    "artifact": "a.py:1",
                    "risk_score": 8.8,
                    "change_type": "SQL Injection",
                    "llm_verdict": "SQL注入风险",
                    "llm_confidence": 0.95,
                    "review_required": False,
                    "llm_reason": "cached result",
                    "evidence": _review_evidence(9.2, "cached result"),
                }
            },
        },
    )

    calls = {"count": 0}

    class _ResumeAnalyzer:
        class _LLM:
            enabled = True

        llm = _LLM()

        @staticmethod
        def analyze_function_pair(**kwargs):
            calls["count"] += 1
            return {
                "change_type": "new code",
                "vulnerability_type": "SQL Injection",
                "vulnerability_score": 9.2,
                "source_to_sink_conditions": {
                    "sources": ["request.args['sql']"],
                    "guards": [],
                    "sinks": ["cursor.execute(sql)"],
                    "condition_chain": "request.args -> cursor.execute",
                },
                "vulnerability_findings": [
                    {"type": "SQL Injection", "score": 9.2, "evidence": "tainted sql reaches cursor.execute"}
                ],
                "confidence": 0.96,
                "review_required": False,
            }

    report = review_existing_directory_run(
        analyzer=_ResumeAnalyzer(),
        run_root=str(run_root),
        review_score_threshold=7.0,
        review_top_n=5,
        resume=True,
    )

    results = report["results"]
    assert calls["count"] == 1
    assert len(results) == 2
    assert any(item["rel_path"] == "a.py" for item in results)
    assert any(item["rel_path"] == "b.py" for item in results)


def test_review_existing_directory_run_recovers_from_corrupt_checkpoint(tmp_path: Path) -> None:
    old_root = tmp_path / "old"
    new_root = tmp_path / "new"
    run_root = tmp_path / "outputs" / "run3"

    _write(old_root / "a.py", "def run(request, cursor):\n    return None\n")
    _write(new_root / "a.py", "def run(request, cursor):\n    sql = request.args.get('sql')\n    cursor.execute(sql)\n")
    _write_json(
        run_root / "meta.json",
        {
            "schema_version": "3.0",
            "mode": "directory",
            "old_root": str(old_root),
            "new_root": str(new_root),
        },
    )
    _write_json(
        run_root / "high_risk_review_queue.json",
        [
            {
                "rel_path": "a.py",
                "unit_index": 0,
                "artifact": "a.py:1",
                "risk_score": 8.8,
                "change_type": "新增代码",
                "review_required": True,
                "llm_review_eligible": True,
            }
        ],
    )
    checkpoint_path = run_root / "high_risk_review_checkpoint.json"
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_path.write_text("{not-json", encoding="utf-8")

    class _CorruptCheckpointAnalyzer:
        class _LLM:
            enabled = True

        llm = _LLM()

        @staticmethod
        def analyze_function_pair(**kwargs):
            return {
                "change_type": "new code",
                "vulnerability_type": "SQL Injection",
                "vulnerability_score": 9.2,
                "source_to_sink_conditions": {
                    "sources": ["request.args['sql']"],
                    "guards": [],
                    "sinks": ["cursor.execute(sql)"],
                    "condition_chain": "request.args -> cursor.execute",
                },
                "vulnerability_findings": [
                    {"type": "SQL Injection", "score": 9.2, "evidence": "fresh review"}
                ],
                "confidence": 0.96,
                "review_required": False,
            }

    report = review_existing_directory_run(
        analyzer=_CorruptCheckpointAnalyzer(),
        run_root=str(run_root),
        review_score_threshold=7.0,
        review_top_n=5,
        resume=True,
    )

    assert len(report["results"]) == 1
    saved_checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    assert saved_checkpoint["selected"] == ["a.py|0|a.py:1"]
    assert "a.py|0|a.py:1" in saved_checkpoint["completed"]
    summary = json.loads((run_root / "high_risk_review_summary.json").read_text(encoding="utf-8"))
    assert summary["checkpoint_status"] == "corrupt_reset"
