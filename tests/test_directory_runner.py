from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from source_diff_engine.directory.runner import _analyze_pair, _prioritize_pairs_for_sampling, _resolve_language, run_directory_analysis
from source_diff_engine.source_analyzer import SourceAnalyzer


def _build_analyzer() -> SourceAnalyzer:
    return SourceAnalyzer(
        model="gpt-5.3-codex",
        base_url="",
        api_key="",
        prompts_file="prompts.yaml",
    )


def _output_paths(prefix: str) -> tuple[str, str, str]:
    uid = uuid.uuid4().hex
    out_root = f"{prefix}_{uid}_outputs"
    run_id = f"run_{uid}"
    cp = f"{prefix}_{uid}_cp.json"
    return out_root, run_id, cp


def _cleanup(*paths: str) -> None:
    for p in paths:
        try:
            Path(p).unlink(missing_ok=True)
        except Exception:
            pass


def _fake_pairs() -> dict:
    return {
        "old_root": "old",
        "new_root": "new",
        "old_file_count": 2,
        "new_file_count": 2,
        "pair_count": 2,
        "pairs": [
            {"rel_path": "a.py", "status": "modified", "old_path": "old/a.py", "new_path": "new/a.py"},
            {"rel_path": "b.py", "status": "modified", "old_path": "old/b.py", "new_path": "new/b.py"},
        ],
    }


def _evidence(score: float, evidence: str, *, sources: list[str] | None = None, guards: list[str] | None = None, sinks: list[str] | None = None, chain: str = "") -> dict:
    src = list(sources or [])
    grd = list(guards or [])
    snk = list(sinks or [])
    return {
        "observed_facts": {
            "source_to_sink": {
                "sources": src,
                "guards": grd,
                "sinks": snk,
                "condition_chain": chain,
            }
        },
        "inferred_assessment": {
            "source_to_sink": {
                "sources": src,
                "guards": grd,
                "sinks": snk,
                "condition_chain": chain,
            },
            "summary": evidence,
            "confidence": 0.0,
            "reasoning_basis": "static",
        },
        "ranked_candidates": [
            {
                "vulnerability_type": "cmdi",
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


def _fake_result(pair_key: str, rel: str, score: float) -> dict:
    row = {
        "change_type": "new_code",
        "vulnerability_type": "cmdi",
        "vulnerability_score": score,
        "evidence": _evidence(score, "x", sources=["input"], sinks=["exec"], chain="s-g-k"),
    }
    return {
        "pair_key": pair_key,
        "file_row": {
            "rel_path": rel,
            "status": "modified",
            "language": "python",
            "unit_count": 1,
            "overview": {"total_units": 1},
            "detail": {"file_summary": {"primary_conclusion": row}},
        },
        "concise_rows": [row],
    }


def test_resolve_language_auto_prefers_file_extension() -> None:
    assert _resolve_language("auto", old_path="", new_path="a/b/c.java") == "java"
    assert _resolve_language("auto", old_path="", new_path="x/y/z.php") == "php"
    assert _resolve_language("auto", old_path="only_old.py", new_path="") == "python"


def test_resolve_language_explicit() -> None:
    assert _resolve_language("java", old_path="a.py", new_path="b.py") == "java"
    assert _resolve_language("php", old_path="a.py", new_path="b.py") == "php"


def test_resolve_language_auto_rejects_unsupported_extension() -> None:
    with pytest.raises(ValueError, match=r"only \.py, \.java, and \.php are supported"):
        _resolve_language("auto", old_path="", new_path="a/b/c.txt")


def test_analyze_pair_uses_resolved_language_for_preprocessor(monkeypatch) -> None:
    seen: dict[str, str] = {}

    class _FakePreprocessor:
        def __init__(self, language: str):
            seen["language"] = language

        @staticmethod
        def infer_language_from_paths(old_path: str = "", new_path: str = "") -> str:
            return "java"

        @staticmethod
        def process_source_diff(old_source: str, new_source: str) -> dict:
            return {
                "diff_units": [
                    {
                        "old_unit": "A.java:1",
                        "new_unit": "A.java:1",
                        "similarity": 1.0,
                        "change_type": "modification",
                        "old_code": "class A {}",
                        "new_code": "class A {}",
                        "file_path": "A.java",
                        "old_start": 1,
                        "new_start": 1,
                        "hunk_header": "@@ -1,1 +1,1 @@",
                    }
                ],
                "diff_text": "",
                "init_report": {},
            }

    monkeypatch.setattr("source_diff_engine.directory.runner.SourcePreprocessor", _FakePreprocessor)
    monkeypatch.setattr(
        "source_diff_engine.directory.runner.analyze_diff_units_in_memory",
        lambda **kwargs: {
            "concise_rows": [],
            "overview": {},
            "detailed_doc": {"units": [], "file_summary": {}},
        },
    )

    out = _analyze_pair(
        analyzer=_build_analyzer(),
        pair={
            "_pair_key": "modified|A.java",
            "rel_path": "A.java",
            "status": "modified",
            "old_path": "old/A.java",
            "new_path": "new/A.java",
        },
        language="auto",
        max_units_per_file=1,
    )
    assert seen["language"] == "java"
    assert out["file_row"]["language"] == "java"


def test_analyze_pair_builds_symbol_context_for_added_file(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    new_file = tmp_path / "new.py"
    new_file.write_text("def run(cmd):\n    return cmd\n", encoding="utf-8")

    def fake_analyze_diff_units_in_memory(**kwargs):
        captured["diff_units"] = kwargs["diff_units"]
        return {
            "concise_rows": [],
            "overview": {},
            "detailed_doc": {"units": [], "file_summary": {}},
        }

    monkeypatch.setattr("source_diff_engine.directory.runner.analyze_diff_units_in_memory", fake_analyze_diff_units_in_memory)

    _analyze_pair(
        analyzer=_build_analyzer(),
        pair={
            "_pair_key": "added|new.py",
            "rel_path": "new.py",
            "status": "added",
            "old_path": "",
            "new_path": str(new_file),
        },
        language="auto",
        max_units_per_file=1,
    )
    diff_units = captured["diff_units"]
    assert isinstance(diff_units, list) and len(diff_units) == 1
    unit = diff_units[0]
    assert unit["new_focus_line_range"] == [1, 2]
    assert unit["new_symbol_context"]["display"] == "run"
    assert unit["old_symbol_context"] == {}


def test_analyze_pair_builds_fallback_symbol_context_for_whole_added_java_file(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    new_file = tmp_path / "DeviceController.java"
    new_file.write_text(
        "public class DeviceController {\n"
        "    public void doGet(HttpServletRequest request, HttpServletResponse response) {\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    def fake_analyze_diff_units_in_memory(**kwargs):
        captured["diff_units"] = kwargs["diff_units"]
        return {
            "concise_rows": [],
            "overview": {},
            "detailed_doc": {"units": [], "file_summary": {}},
        }

    monkeypatch.setattr("source_diff_engine.directory.runner.analyze_diff_units_in_memory", fake_analyze_diff_units_in_memory)

    _analyze_pair(
        analyzer=_build_analyzer(),
        pair={
            "_pair_key": "added|DeviceController.java",
            "rel_path": "DeviceController.java",
            "status": "added",
            "old_path": "",
            "new_path": str(new_file),
        },
        language="auto",
        max_units_per_file=1,
    )
    diff_units = captured["diff_units"]
    unit = diff_units[0]
    assert unit["new_symbol_context"]["display"] == "DeviceController"
    assert unit["new_symbol_context"]["innermost_symbol"]["name"] == "DeviceController"


def test_analyze_pair_reports_real_added_line_count_for_synthetic_added_file(monkeypatch, tmp_path: Path) -> None:
    new_file = tmp_path / "new.py"
    new_file.write_text("def run(cmd):\n    return cmd\n\nprint(run('x'))\n", encoding="utf-8")

    monkeypatch.setattr(
        "source_diff_engine.directory.runner.analyze_diff_units_in_memory",
        lambda **kwargs: {
            "concise_rows": [],
            "overview": {},
            "detailed_doc": {"units": [], "file_summary": {}},
        },
    )

    out = _analyze_pair(
        analyzer=_build_analyzer(),
        pair={
            "_pair_key": "added|new.py",
            "rel_path": "new.py",
            "status": "added",
            "old_path": "",
            "new_path": str(new_file),
        },
        language="auto",
        max_units_per_file=1,
    )
    assert out["init_report"]["diff_engine"] == "synthetic_added_removed"
    assert out["init_report"]["added_line_count"] == 4
    assert out["init_report"]["deleted_line_count"] == 0


def test_analyze_pair_reports_real_deleted_line_count_for_synthetic_removed_file(monkeypatch, tmp_path: Path) -> None:
    old_file = tmp_path / "old.php"
    old_file.write_text("<?php\nfunction run($cmd) {\n    return $cmd;\n}\n", encoding="utf-8")

    monkeypatch.setattr(
        "source_diff_engine.directory.runner.analyze_diff_units_in_memory",
        lambda **kwargs: {
            "concise_rows": [],
            "overview": {},
            "detailed_doc": {"units": [], "file_summary": {}},
        },
    )

    out = _analyze_pair(
        analyzer=_build_analyzer(),
        pair={
            "_pair_key": "removed|old.php",
            "rel_path": "old.php",
            "status": "removed",
            "old_path": str(old_file),
            "new_path": "",
        },
        language="auto",
        max_units_per_file=1,
    )
    assert out["init_report"]["diff_engine"] == "synthetic_added_removed"
    assert out["init_report"]["added_line_count"] == 0
    assert out["init_report"]["deleted_line_count"] == 4


def test_directory_runner_supports_limits_and_resume(monkeypatch) -> None:
    out_root, run_id, cp = _output_paths("dir_resume")
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    memory_cp: dict = {"version": 1, "completed": {}}
    memory_ov: dict = {}

    def fake_load_checkpoint(_):
        return json.loads(json.dumps(memory_cp))

    def fake_write_checkpoint(_, data):
        memory_cp.clear()
        memory_cp.update(json.loads(json.dumps(data)))

    def fake_write_json(path, data):
        p = str(path).replace("\\", "/")
        if p.endswith("/overview.json") and not p.endswith("/init_overview.json"):
            memory_ov.clear()
            memory_ov.update(json.loads(json.dumps(data)))

    monkeypatch.setattr("source_diff_engine.directory.runner._load_checkpoint", fake_load_checkpoint)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", fake_write_checkpoint)
    monkeypatch.setattr("source_diff_engine.directory.runner.write_json_atomic", fake_write_json)
    monkeypatch.setattr("source_diff_engine.directory.runner.write_text_atomic", lambda *args, **kwargs: None)

    def fake_analyze_pair(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        return _fake_result(pair["_pair_key"], pair["rel_path"], 8.5)

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fake_analyze_pair)
    analyzer = _build_analyzer()

    first = run_directory_analysis(
        analyzer=analyzer,
        old_root="old",
        new_root="new",
        output_root=out_root,
        run_id=run_id,
        language="auto",
        max_units_per_file=1,
        max_files=1,
        workers=2,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=cp,
        resume=False,
    )
    assert first["overview"]["total_files_analyzed"] == 1

    second = run_directory_analysis(
        analyzer=analyzer,
        old_root="old",
        new_root="new",
        output_root=out_root,
        run_id=run_id,
        language="auto",
        max_units_per_file=1,
        max_files=1,
        workers=2,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=cp,
        resume=True,
    )
    assert second["overview"]["resumed_file_count"] == 1
    assert second["overview"]["schema_version"] == "3.0"
    assert memory_ov["resumed_file_count"] == 1
    assert memory_ov["schema_version"] == "3.0"


def test_directory_runner_fail_fast_records_failure(monkeypatch) -> None:
    out_root, run_id, cp = _output_paths("dir_fail_fast")
    memory_det: dict = {}
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)
    monkeypatch.setattr("source_diff_engine.directory.runner.write_text_atomic", lambda *args, **kwargs: None)

    def capture_detail(path, data):
        if str(path).endswith("detailed.json"):
            memory_det.clear()
            memory_det.update(json.loads(json.dumps(data)))

    monkeypatch.setattr("source_diff_engine.directory.runner.write_json_atomic", capture_detail)

    def fail_on_first(analyzer, pair, language, max_units_per_file):
        if pair["rel_path"] == "a.py":
            raise RuntimeError("boom")
        return _fake_result(pair["_pair_key"], pair["rel_path"], 3.2)

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fail_on_first)
    analyzer = _build_analyzer()
    result = run_directory_analysis(
        analyzer=analyzer,
        old_root="old",
        new_root="new",
        output_root=out_root,
        run_id=run_id,
        language="auto",
        max_units_per_file=1,
        max_files=0,
        workers=1,
        fail_fast=True,
        retry_failed_files=0,
        checkpoint_file=cp,
        resume=False,
    )
    assert result["overview"]["fail_fast_triggered"] is True
    assert result["overview"]["failed_file_count"] >= 1
    assert len(memory_det["failed_files"]) >= 1
    assert memory_det["failed_files"][0]["failure_category"] == "analysis_error"
    assert result["overview"]["not_executed_file_count"] == 1
    assert result["overview"]["not_executed_files"][0]["rel_path"] == "b.py"


def test_directory_runner_retry_failed_file_then_succeeds(monkeypatch) -> None:
    out_root, run_id, cp = _output_paths("dir_retry")
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)
    monkeypatch.setattr("source_diff_engine.directory.runner.write_json_atomic", lambda *args, **kwargs: None)
    monkeypatch.setattr("source_diff_engine.directory.runner.write_text_atomic", lambda *args, **kwargs: None)
    state = {"a": 0}

    def fail_then_pass(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        if pair["rel_path"] == "a.py":
            state["a"] += 1
            if state["a"] == 1:
                raise RuntimeError("first attempt failed")
        return _fake_result(pair["_pair_key"], pair["rel_path"], 8.0)

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fail_then_pass)
    analyzer = _build_analyzer()
    result = run_directory_analysis(
        analyzer=analyzer,
        old_root="old",
        new_root="new",
        output_root=out_root,
        run_id=run_id,
        language="auto",
        max_units_per_file=1,
        max_files=0,
        workers=1,
        fail_fast=False,
        retry_failed_files=1,
        checkpoint_file=cp,
        resume=False,
    )
    assert result["overview"]["failed_file_count"] == 0
    assert result["overview"]["total_files_analyzed"] == 2
    assert result["overview"]["runtime_metrics"]["retried_files"] == 1
    assert result["overview"]["runtime_metrics"]["completed_files"] == 2
    assert state["a"] == 2


def test_directory_runner_overview_exports_runtime_metrics_and_failure_categories(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)

    def fail_on_a_then_pass_b(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        if pair["rel_path"] == "a.py":
            raise PermissionError("denied")
        result = _fake_result(pair["_pair_key"], pair["rel_path"], 2.0)
        result["concise_rows"][0]["analysis_backend"] = "static"
        return result

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fail_on_a_then_pass_b)
    result = run_directory_analysis(
        analyzer=_build_analyzer(),
        old_root="old",
        new_root="new",
        output_root=str(tmp_path / "outputs"),
        run_id="runtime_metrics",
        language="auto",
        max_units_per_file=1,
        max_files=0,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=str(tmp_path / "cp.json"),
        resume=False,
    )

    overview = result["overview"]
    runtime = overview["runtime_metrics"]
    assert runtime["selected_files"] == 2
    assert runtime["completed_files"] == 1
    assert runtime["failed_files"] == 1
    assert runtime["static_fallback_count"] == 1
    assert overview["failure_categories"] == {"permission_error": 1}
    assert result["detailed"]["runtime"]["total_files_scanned"] == 2
    assert result["detailed"]["runtime"]["selected_files"] == 2


def test_directory_runner_exports_manifest_skipped_files(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "source_diff_engine.directory.runner.build_directory_pairs",
        lambda **_: {
            "old_root": "old",
            "new_root": "new",
            "old_file_count": 1,
            "new_file_count": 1,
            "pair_count": 1,
            "pairs": _fake_pairs()["pairs"][:1],
            "skipped_files": [{"rel_path": "vendor/lib.py", "side": "new", "reason": "excluded_dir", "path": "new/vendor/lib.py"}],
            "skipped_by_reason": {"excluded_dir": 1},
        },
    )
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)
    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", lambda analyzer, pair, language, max_units_per_file, analysis_profile=None: _fake_result(pair["_pair_key"], pair["rel_path"], 2.0))

    result = run_directory_analysis(
        analyzer=_build_analyzer(),
        old_root="old",
        new_root="new",
        output_root=str(tmp_path / "outputs"),
        run_id="skipped",
        language="auto",
        max_units_per_file=1,
        max_files=0,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=str(tmp_path / "cp.json"),
        resume=False,
    )

    assert result["overview"]["skipped_file_count"] == 1
    assert result["overview"]["skipped_by_reason"] == {"excluded_dir": 1}
    assert result["detailed"]["runtime"]["manifest_skipped_files"] == 1
    assert result["init_overview"]["skipped_files"][0]["reason"] == "excluded_dir"


def test_directory_runner_filters_identical_modified_before_max_files(monkeypatch) -> None:
    out_root, run_id, cp = _output_paths("dir_filter")
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)
    monkeypatch.setattr("source_diff_engine.directory.runner.write_json_atomic", lambda *args, **kwargs: None)
    monkeypatch.setattr("source_diff_engine.directory.runner.write_text_atomic", lambda *args, **kwargs: None)
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda old, new: str(old).endswith("a.py"))

    seen: list[str] = []

    def fake_analyze_pair(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        seen.append(str(pair["rel_path"]))
        return _fake_result(pair["_pair_key"], pair["rel_path"], 2.0)

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fake_analyze_pair)
    analyzer = _build_analyzer()
    result = run_directory_analysis(
        analyzer=analyzer,
        old_root="old",
        new_root="new",
        output_root=out_root,
        run_id=run_id,
        language="auto",
        max_units_per_file=1,
        max_files=1,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=cp,
        resume=False,
    )
    assert result["overview"]["total_files_analyzed"] == 1
    assert seen == ["b.py"]
    assert result["overview"]["pair_summary"]["filtered_out_identical_modified_count"] == 1


def test_directory_runner_prioritizes_riskier_pairs_before_max_files() -> None:
    ranked = _prioritize_pairs_for_sampling(
        [
            {"rel_path": "pkg/model/UiDeviceInfo.java", "status": "added"},
            {"rel_path": "pkg/rest/controller/UserRestController.java", "status": "modified"},
            {"rel_path": "pkg/servlet/FileDownload.java", "status": "modified"},
            {"rel_path": "pkg/package-info.java", "status": "modified"},
        ]
    )
    top_two = [item["rel_path"] for item in ranked[:2]]
    assert "pkg/rest/controller/UserRestController.java" in top_two
    assert "pkg/servlet/FileDownload.java" in top_two
    assert ranked[-1]["rel_path"] == "pkg/package-info.java"


def test_directory_runner_marks_invalid_quality_when_all_modified_are_zero_units(monkeypatch) -> None:
    out_root, run_id, cp = _output_paths("dir_quality")
    memory_init: dict = {}
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)
    monkeypatch.setattr("source_diff_engine.directory.runner.write_text_atomic", lambda *args, **kwargs: None)

    def capture_write(path, data):
        if str(path).endswith("init_overview.json"):
            memory_init.clear()
            memory_init.update(json.loads(json.dumps(data)))

    monkeypatch.setattr("source_diff_engine.directory.runner.write_json_atomic", capture_write)

    def fake_zero_units(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        return {
            "pair_key": pair["_pair_key"],
            "file_row": {
                "rel_path": pair["rel_path"],
                "status": "modified",
                "language": "python",
                "unit_count": 0,
                "overview": {"total_units": 0},
                "detail": {"file_summary": {"primary_conclusion": {"vulnerability_score": 0.0}}},
            },
            "concise_rows": [],
            "init_report": {
                "file_kind": "text",
                "hunk_count": 0,
                "added_line_count": 0,
                "deleted_line_count": 0,
                "zero_unit_reason": "parse_empty",
                "diff_return_code": 1,
            },
        }

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fake_zero_units)
    analyzer = _build_analyzer()
    result = run_directory_analysis(
        analyzer=analyzer,
        old_root="old",
        new_root="new",
        output_root=out_root,
        run_id=run_id,
        language="auto",
        max_units_per_file=1,
        max_files=0,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=cp,
        resume=False,
        min_total_units=1,
        max_zero_unit_ratio=0.5,
    )
    assert result["overview"]["analysis_quality"] == "invalid"
    assert result["overview"]["schema_version"] == "3.0"
    assert result["init_overview"]["schema_version"] == "3.0"
    assert "zero_unit_ratio_exceeded" in " ".join(result["overview"]["quality_issues"])
    assert memory_init["analysis_quality"] == "invalid"
    assert memory_init["schema_version"] == "3.0"
    assert memory_init["summary"]["zero_unit_reason_breakdown"]["parse_empty"] == 2


def test_directory_runner_marks_no_changes_when_all_modified_files_are_identical(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: True)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)

    analyzer = _build_analyzer()
    result = run_directory_analysis(
        analyzer=analyzer,
        old_root="old",
        new_root="new",
        output_root=str(tmp_path / "outputs"),
        run_id="dir_no_changes",
        language="auto",
        max_units_per_file=1,
        max_files=0,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=str(tmp_path / "cp.json"),
        resume=False,
    )
    assert result["overview"]["analysis_quality"] == "no_changes"
    assert result["init_overview"]["analysis_quality"] == "no_changes"
    assert result["overview"]["total_files_analyzed"] == 0
    assert result["init_overview"]["summary"]["zero_unit_reason_breakdown"] == {"identical": 2}


def test_directory_runner_does_not_emit_legacy_flat_filenames(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)

    def fake_analyze_pair(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        return _fake_result(pair["_pair_key"], pair["rel_path"], 2.0)

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fake_analyze_pair)
    analyzer = _build_analyzer()

    out_root = str(tmp_path / "outputs")
    run_id = "regression_no_legacy"
    cp = str(tmp_path / "cp.json")
    result = run_directory_analysis(
        analyzer=analyzer,
        old_root="old",
        new_root="new",
        output_root=out_root,
        run_id=run_id,
        language="auto",
        max_units_per_file=1,
        max_files=1,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=cp,
        resume=False,
    )
    run_root = Path(result["run_root"])
    legacy = [
        run_root / "vulnerability_analysis_results.json",
        run_root / "vulnerability_analysis_results_detailed.json",
        run_root / "vulnerability_analysis_overview.json",
        run_root / "init_analysis_overview.json",
    ]
    assert all(not p.exists() for p in legacy)


def test_directory_runner_meta_merges_overrides(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)

    def fake_analyze_pair(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        return _fake_result(pair["_pair_key"], pair["rel_path"], 2.0)

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fake_analyze_pair)
    analyzer = _build_analyzer()

    out_root = str(tmp_path / "outputs")
    run_id = "meta_override"
    cp = str(tmp_path / "cp.json")
    result = run_directory_analysis(
        analyzer=analyzer,
        old_root="old",
        new_root="new",
        output_root=out_root,
        run_id=run_id,
        language="auto",
        max_units_per_file=1,
        max_files=1,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=cp,
        resume=False,
        meta_overrides={
            "llm_model": "test-model",
            "llm_enabled": False,
            "llm_preflight": "failed_fallback_static",
            "llm_fallback_reason": "connection error",
        },
    )

    run_root = Path(result["run_root"])
    meta = json.loads((run_root / "meta.json").read_text(encoding="utf-8"))
    assert meta["llm_model"] == "test-model"
    assert meta["llm_enabled"] is False
    assert meta["llm_preflight"] == "failed_fallback_static"
    assert meta["llm_fallback_reason"] == "connection error"
    assert (run_root / "summary.json").exists()
    assert (run_root / "summary.md").exists()


def test_directory_runner_high_risk_index_tracks_units_not_files(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)

    def fake_analyze_pair(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        rows = [
            {
                "change_type": "new_code",
                "vulnerability_type": "cmdi",
                "vulnerability_score": 8.6,
                "evidence": _evidence(8.6, "x", sources=["input"], sinks=["exec"], chain="s-g-k"),
            },
            {
                "change_type": "new_code",
                "vulnerability_type": "sqli",
                "vulnerability_score": 7.8,
                "evidence": _evidence(7.8, "y", sources=["query"], sinks=["cursor.execute"], chain="s-g-k"),
            },
        ]
        return {
            "pair_key": pair["_pair_key"],
            "file_row": {
                "rel_path": pair["rel_path"],
                "status": "modified",
                "language": "python",
                "unit_count": 2,
                "overview": {"total_units": 2},
                "detail": {
                    "units": [
                        {
                            "unit": {
                                "old_unit": "a.py:1",
                                "new_unit": "a.py:2",
                                "artifact": "a.py:2",
                                "file_path": "a.py",
                                "hunk_header": "@@ -1,2 +1,4 @@",
                                "old_line_range": [1, 2],
                                "new_line_range": [1, 4],
                                "old_focus_line_range": [2, 2],
                                "new_focus_line_range": [2, 3],
                                "old_symbol_context": {"display": "Runner.run"},
                                "new_symbol_context": {"display": "Runner.run"},
                            }
                        },
                        {
                            "unit": {
                                "old_unit": "a.py:3",
                                "new_unit": "a.py:4",
                                "artifact": "a.py:4",
                                "file_path": "a.py",
                                "hunk_header": "@@ -3,1 +4,2 @@",
                                "old_line_range": [3, 3],
                                "new_line_range": [4, 5],
                                "old_focus_line_range": [3, 3],
                                "new_focus_line_range": [4, 5],
                                "old_symbol_context": {"display": "Runner.audit"},
                                "new_symbol_context": {"display": "Runner.audit"},
                            }
                        },
                    ],
                    "file_summary": {"primary_conclusion": rows[0]},
                },
            },
            "concise_rows": rows,
            "init_report": {},
            "git_diff_text": "",
        }

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fake_analyze_pair)
    result = run_directory_analysis(
        analyzer=_build_analyzer(),
        old_root="old",
        new_root="new",
        output_root=str(tmp_path / "outputs"),
        run_id="high_risk_units",
        language="auto",
        max_units_per_file=2,
        max_files=1,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=str(tmp_path / "cp.json"),
        resume=False,
    )

    run_root = Path(result["run_root"])
    high_risk_index = json.loads((run_root / "high_risk_index.json").read_text(encoding="utf-8"))
    assert len(high_risk_index) == 2
    assert {row["unit_index"] for row in high_risk_index} == {0, 1}
    assert all("artifact" in row for row in high_risk_index)
    assert all("hunk_header" in row for row in high_risk_index)
    assert all("new_focus_line_range" in row for row in high_risk_index)
    assert high_risk_index[0]["new_enclosing_symbol"] in {"Runner.run", "Runner.audit"}


def test_directory_runner_exports_high_risk_review_queue(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)

    def fake_analyze_pair(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        rows = [
            {
                "change_type": "new_code",
                "vulnerability_type": "cmdi",
                "vulnerability_score": 8.9,
                "evidence": _evidence(8.9, "x", sources=["input"], sinks=["exec"], chain="s-g-k"),
            },
            {
                "change_type": "new_code",
                "vulnerability_type": "ssrf",
                "vulnerability_score": 7.4,
                "evidence": _evidence(7.4, "y", sources=["url"], sinks=["http"], chain="s-g-k"),
            },
        ]
        return {
            "pair_key": pair["_pair_key"],
            "file_row": {
                "rel_path": pair["rel_path"],
                "status": "modified",
                "language": "python",
                "unit_count": 2,
                "overview": {"total_units": 2},
                "detail": {
                    "units": [
                        {
                            "unit": {
                                "old_unit": "a.py:1",
                                "new_unit": "a.py:2",
                                "artifact": "a.py:2",
                                "file_path": "a.py",
                                "hunk_header": "@@ -1,1 +1,2 @@",
                                "old_line_range": [1, 1],
                                "new_line_range": [1, 2],
                                "old_focus_line_range": [1, 1],
                                "new_focus_line_range": [2, 2],
                                "old_symbol_context": {"display": "Runner.run"},
                                "new_symbol_context": {"display": "Runner.run"},
                            },
                            "fix_assessment": {"is_security_fix": False, "review_required": True},
                            "new_vuln_check": {
                                "has_new_vulnerability": True,
                                "rule_id": "cmdi",
                                "candidates": [{"rule_id": "cmdi"}],
                                "llm_review_invoked": False,
                                "llm_review_confidence": 0.0,
                                "llm_review_required": False,
                            },
                        },
                        {
                            "unit": {
                                "old_unit": "a.py:3",
                                "new_unit": "a.py:4",
                                "artifact": "a.py:4",
                                "file_path": "a.py",
                                "hunk_header": "@@ -3,1 +4,2 @@",
                                "old_line_range": [3, 3],
                                "new_line_range": [4, 5],
                                "old_focus_line_range": [3, 3],
                                "new_focus_line_range": [4, 5],
                                "old_symbol_context": {"display": "Runner.audit"},
                                "new_symbol_context": {"display": "Runner.audit"},
                            },
                            "fix_assessment": {"is_security_fix": False, "review_required": False},
                            "new_vuln_check": {
                                "has_new_vulnerability": True,
                                "rule_id": "ssrf",
                                "candidates": [{"rule_id": "ssrf"}],
                                "llm_review_invoked": False,
                                "llm_review_confidence": 0.0,
                                "llm_review_required": False,
                            },
                        },
                    ],
                    "file_summary": {"primary_conclusion": rows[0]},
                },
            },
            "concise_rows": rows,
            "init_report": {},
            "git_diff_text": "",
        }

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fake_analyze_pair)
    result = run_directory_analysis(
        analyzer=_build_analyzer(),
        old_root="old",
        new_root="new",
        output_root=str(tmp_path / "outputs"),
        run_id="review_queue",
        language="auto",
        max_units_per_file=2,
        max_files=1,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=str(tmp_path / "cp.json"),
        resume=False,
        review_score_threshold=7.5,
        review_top_n=1,
        meta_overrides={"llm_enabled": True},
    )

    run_root = Path(result["run_root"])
    queue = json.loads((run_root / "high_risk_review_queue.json").read_text(encoding="utf-8"))
    overview = json.loads((run_root / "overview.json").read_text(encoding="utf-8"))
    assert len(queue) == 1
    assert queue[0]["risk_score"] == 8.9
    assert queue[0]["review_required"] is True
    assert queue[0]["llm_review_eligible"] is True
    assert queue[0]["review_kind"] == "llm"
    assert queue[0]["pair_summary_path"].endswith("pairs/a.py/summary.json")
    assert queue[0]["pair_units_path"].endswith("pairs/a.py/units.json")
    assert overview["review_queue"]["score_threshold"] == 7.5
    assert overview["review_queue"]["top_n"] == 1
    assert overview["review_queue"]["candidate_count"] == 2
    assert overview["review_queue"]["queued_count"] == 1
    assert overview["review_queue"]["llm_eligible_count"] == 1


def test_directory_runner_executes_optional_llm_review_pass(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("source_diff_engine.directory.runner.build_directory_pairs", lambda **_: _fake_pairs())
    monkeypatch.setattr("source_diff_engine.directory.runner._files_identical", lambda *_: False)
    monkeypatch.setattr("source_diff_engine.directory.runner._write_checkpoint", lambda *_: None)

    class _ReviewAnalyzer:
        class _LLM:
            enabled = True

        llm = _LLM()

        @staticmethod
        def analyze_function_pair(**kwargs):
            assert kwargs["scenario"] == "new_code"
            return {
                "change_type": "new code",
                "vulnerability_type": "SQL Injection",
                "vulnerability_score": 9.3,
                "source_to_sink_conditions": {
                    "sources": ["request.args['sql']"],
                    "guards": [],
                    "sinks": ["cursor.execute(sql)"],
                    "condition_chain": "request.args -> cursor.execute",
                },
                "vulnerability_findings": [
                    {
                        "type": "SQL Injection",
                        "score": 9.3,
                        "evidence": "tainted sql reaches cursor.execute",
                    }
                ],
                "confidence": 0.94,
                "review_required": False,
            }

    def fake_analyze_pair(analyzer, pair, language, max_units_per_file, analysis_profile=None):
        row = {
            "change_type": "new_code",
            "vulnerability_type": "cmdi",
            "vulnerability_score": 8.8,
            "evidence": _evidence(8.8, "x", sources=["input"], sinks=["exec"], chain="s-g-k"),
        }
        diff_unit = {
            "old_unit": None,
            "new_unit": "a.py:added->1",
            "change_type": "added",
            "old_code": "",
            "new_code": "sql = request.args.get('sql')\ncursor.execute(sql)\n",
            "similarity": 0.0,
            "file_path": "a.py",
            "new_symbol_context": {"display": "Runner.run"},
        }
        return {
            "pair_key": pair["_pair_key"],
            "file_row": {
                "rel_path": pair["rel_path"],
                "status": "modified",
                "language": "python",
                "unit_count": 1,
                "overview": {"total_units": 1},
                "detail": {
                    "units": [
                        {
                            "unit": {
                                "old_unit": None,
                                "new_unit": "a.py:added->1",
                                "artifact": "a.py:added->1",
                                "file_path": "a.py",
                                "hunk_header": "@@ -0,0 +1,2 @@",
                                "old_line_range": [0, 0],
                                "new_line_range": [1, 2],
                                "old_focus_line_range": [0, 0],
                                "new_focus_line_range": [1, 2],
                                "old_symbol_context": {},
                                "new_symbol_context": {"display": "Runner.run"},
                            },
                            "fix_assessment": {"is_security_fix": False, "review_required": True},
                            "new_vuln_check": {
                                "has_new_vulnerability": True,
                                "rule_id": "cmdi",
                                "candidates": [{"rule_id": "cmdi"}],
                                "llm_review_invoked": False,
                                "llm_review_confidence": 0.0,
                                "llm_review_required": False,
                            },
                        }
                    ],
                    "file_summary": {"primary_conclusion": row},
                },
            },
            "concise_rows": [row],
            "init_report": {},
            "git_diff_text": "",
            "diff_units": [diff_unit],
        }

    monkeypatch.setattr("source_diff_engine.directory.runner._analyze_pair", fake_analyze_pair)
    result = run_directory_analysis(
        analyzer=_ReviewAnalyzer(),
        old_root="old",
        new_root="new",
        output_root=str(tmp_path / "outputs"),
        run_id="review_pass",
        language="auto",
        max_units_per_file=1,
        max_files=1,
        workers=1,
        fail_fast=False,
        retry_failed_files=0,
        checkpoint_file=str(tmp_path / "cp.json"),
        resume=False,
        review_score_threshold=7.0,
        review_top_n=0,
        enable_llm_review_pass=True,
        meta_overrides={"llm_enabled": True},
    )

    run_root = Path(result["run_root"])
    review_results = json.loads((run_root / "high_risk_review_results.json").read_text(encoding="utf-8"))
    overview = json.loads((run_root / "overview.json").read_text(encoding="utf-8"))
    assert len(review_results) == 1
    assert review_results[0]["llm_verdict"] == "SQL注入风险"
    assert review_results[0]["review_required"] is False
    assert "cursor.execute" in review_results[0]["llm_reason"]
    assert overview["review_queue"]["llm_review_pass_enabled"] is True
    assert overview["review_queue"]["llm_review_completed_count"] == 1
