from __future__ import annotations

import json
from pathlib import Path

import pytest

from source_diff_engine.app_service import (
    doctor,
    ensure_llm_ready,
    resolve_effective_llm_mode,
    resolve_output_root,
    smoke,
    write_single_file_outputs,
)
from source_diff_engine.llm.client import LLMErrorInfo


def _evidence(score: float, evidence: str, *, vuln_type: str = "cmdi", sources: list[str] | None = None, guards: list[str] | None = None, sinks: list[str] | None = None, chain: str = "") -> dict:
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
                "supporting_facts": {
                    "source_to_sink": {"sources": src, "guards": grd, "sinks": snk, "condition_chain": chain},
                    "evidence_status": "observed" if src and grd and snk and chain else ("partial" if src or grd or snk or chain else "missing"),
                    "chain_completeness": "complete" if src and grd and snk and chain else ("partial" if src or grd or snk or chain else "missing"),
                    "inference_level": "none",
                },
            }
        ],
        "convenience_summary": {
            "evidence_status": "observed" if src and grd and snk and chain else ("partial" if src or grd or snk or chain else "missing"),
            "observed_chain_completeness": "complete" if src and grd and snk and chain else ("partial" if src or grd or snk or chain else "missing"),
            "inferred_chain_completeness": "complete" if src and grd and snk and chain else ("partial" if src or grd or snk or chain else "missing"),
            "inference_level": "none",
            "assessment_basis": "static",
            "primary_evidence": evidence,
            "review_required": False,
            "review_reasons": [],
        },
    }


class _LLMDisabled:
    enabled = False

    @staticmethod
    def preflight(skip_models_check: bool = False) -> None:
        raise AssertionError("preflight should not be called when llm is disabled")

    @staticmethod
    def disable(reason: str = "") -> None:
        raise AssertionError("disable should not be called when llm is already disabled")


class _LLMPreflightOK:
    enabled = True

    @staticmethod
    def preflight(skip_models_check: bool = False) -> None:
        return None

    @staticmethod
    def disable(reason: str = "") -> None:
        raise AssertionError("disable should not be called on successful preflight")


class _LLMPreflightFail:
    enabled = True

    def __init__(self) -> None:
        self.disabled_reason = ""
        self.last_error_info = LLMErrorInfo(
            category="network_blocked",
            detail="connection failed",
            status_code=0,
            retryable=True,
        )

    @staticmethod
    def preflight(skip_models_check: bool = False) -> None:
        raise RuntimeError("connection failed")

    def disable(self, reason: str = "") -> None:
        self.enabled = False
        self.disabled_reason = str(reason)


class _Analyzer:
    def __init__(self, llm: object) -> None:
        self.llm = llm


def test_resolve_output_root_is_relative_to_cwd_not_data_folder(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    resolved = resolve_output_root("outputs")
    assert resolved == str((tmp_path / "outputs").resolve())


def test_ensure_llm_ready_skips_preflight_when_llm_disabled() -> None:
    info = ensure_llm_ready(_Analyzer(_LLMDisabled()), llm_mode="try", skip_preflight=False)
    assert info["llm_enabled"] is False
    assert info["llm_preflight"] == "skipped_no_api_key"
    assert info["llm_fallback_reason"] == "missing_api_key"
    assert info["llm_error_category"] == "missing_api_key"


def test_ensure_llm_ready_marks_ok_when_preflight_passes() -> None:
    info = ensure_llm_ready(_Analyzer(_LLMPreflightOK()), llm_mode="try", skip_preflight=False)
    assert info["llm_enabled"] is True
    assert info["llm_preflight"] == "ok"
    assert info["llm_fallback_reason"] == ""


def test_ensure_llm_ready_can_skip_preflight() -> None:
    info = ensure_llm_ready(_Analyzer(_LLMPreflightOK()), llm_mode="try", skip_preflight=True)
    assert info["llm_enabled"] is True
    assert info["llm_preflight"] == "skipped_by_flag"


def test_ensure_llm_ready_falls_back_to_static_when_preflight_fails() -> None:
    llm = _LLMPreflightFail()
    info = ensure_llm_ready(_Analyzer(llm), llm_mode="try", skip_preflight=False)
    assert info["llm_enabled"] is False
    assert info["llm_preflight"] == "failed_fallback_static"
    assert "connection failed" in info["llm_fallback_reason"]
    assert info["llm_error_category"] == "network_blocked"
    assert llm.enabled is False
    assert "preflight_failed:network_blocked" in llm.disabled_reason


def test_ensure_llm_ready_raises_when_llm_is_required() -> None:
    with pytest.raises(RuntimeError, match="connection failed"):
        ensure_llm_ready(_Analyzer(_LLMPreflightFail()), llm_mode="required", skip_preflight=False)


def test_ensure_llm_ready_turns_llm_off_by_mode() -> None:
    llm = _LLMPreflightFail()
    info = ensure_llm_ready(_Analyzer(llm), llm_mode="off", skip_preflight=False)
    assert info["llm_enabled"] is False
    assert info["llm_preflight"] == "disabled_by_mode"
    assert info["llm_fallback_reason"] == "llm_mode_off"


def test_resolve_effective_llm_mode_prefers_explicit_override() -> None:
    assert (
        resolve_effective_llm_mode(
            llm_mode_override="required",
            configured_llm_mode="off",
            analysis_profile="generic",
        )
        == "required"
    )


def test_resolve_effective_llm_mode_uses_profile_when_config_missing() -> None:
    assert resolve_effective_llm_mode(configured_llm_mode="", analysis_profile="generic") == "off"
    assert resolve_effective_llm_mode(configured_llm_mode="", analysis_profile="security") == "try"
    assert resolve_effective_llm_mode(configured_llm_mode="", analysis_profile="security-strict") == "required"


def test_write_single_file_outputs_high_risk_index_is_unit_level(tmp_path: Path) -> None:
    run_root = tmp_path / "single_run"
    mem = {
        "concise_rows": [
            {
                "change_type": "new_code",
                "vulnerability_type": "cmdi",
                "vulnerability_score": 8.6,
                "evidence": _evidence(8.6, "x", vuln_type="cmdi", sources=["input"], sinks=["exec"], chain="s-g-k"),
            },
            {
                "change_type": "new_code",
                "vulnerability_type": "none",
                "vulnerability_score": 2.0,
                "evidence": _evidence(2.0, "y", vuln_type="none", chain="source -> guard -> sink"),
            },
        ],
        "overview": {
            "by_vulnerability_type": {"cmdi": 1, "none": 1},
            "by_change_type": {"new_code": 2},
            "high_risk_unit_count": 1,
        },
        "detailed_doc": {
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
            "file_summary": {
                "primary_conclusion": {
                    "change_type": "new_code",
                    "vulnerability_type": "cmdi",
                    "vulnerability_score": 8.6,
                    "analysis_backend": "static",
                    "decision_path": "static_new_code",
                    "analysis_reason": "new_code_branch",
                    "evidence": _evidence(8.6, "x", vuln_type="cmdi", sources=["input"], sinks=["exec"], chain="s-g-k"),
                }
            },
        },
    }

    overview = write_single_file_outputs(
        run_root=run_root,
        rel_path="a.py",
        status="modified",
        language="python",
        mem=mem,
        diff_text="@@ -1,1 +1,2 @@",
        llm_runtime={"llm_enabled": False, "llm_preflight": "skipped_no_api_key", "llm_error_category": "", "llm_fallback_reason": ""},
    )

    high_risk_index = json.loads((run_root / "high_risk_index.json").read_text(encoding="utf-8"))
    assert overview["analysis_quality"] == "valid"
    assert len(high_risk_index) == 1
    assert high_risk_index[0]["unit_index"] == 0
    assert high_risk_index[0]["artifact"] == "a.py:2"
    assert high_risk_index[0]["new_enclosing_symbol"] == "Runner.run"


def test_write_single_file_outputs_marks_no_changes_when_no_units(tmp_path: Path) -> None:
    run_root = tmp_path / "single_empty"
    overview = write_single_file_outputs(
        run_root=run_root,
        rel_path="a.py",
        status="modified",
        language="python",
        mem={
            "concise_rows": [],
            "overview": {"by_vulnerability_type": {}, "by_change_type": {}, "high_risk_unit_count": 0},
            "detailed_doc": {"units": [], "file_summary": {"primary_conclusion": {}}},
        },
        diff_text="",
        llm_runtime={"llm_enabled": False, "llm_preflight": "skipped_no_api_key", "llm_error_category": "", "llm_fallback_reason": ""},
    )
    init_overview = json.loads((run_root / "init_overview.json").read_text(encoding="utf-8"))
    assert overview["analysis_quality"] == "no_changes"
    assert init_overview["analysis_quality"] == "no_changes"
    assert json.loads((run_root / "high_risk_index.json").read_text(encoding="utf-8")) == []


def test_smoke_returns_verified_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    output_root = tmp_path / "smoke_outputs"
    report = smoke(config_path=str(Path(__file__).resolve().parents[1] / "configs" / "config.example.json"), output_root=str(output_root), run_id="smoke_test", llm_mode="off")
    assert report["ok"] is True
    assert report["verification"]["ok"] is True
    assert Path(report["run_root"]).exists()
    assert report["summary"]["analysis_quality"] in {"valid", "no_changes"}


def test_doctor_reports_ok_with_static_smoke(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report = doctor(
        config_path=str(Path(__file__).resolve().parents[1] / "configs" / "config.example.json"),
        output_root=str(tmp_path / "doctor_outputs"),
        smoke_output_root=str(tmp_path / "doctor_smoke"),
        llm_mode="off",
        skip_llm_preflight=True,
    )
    assert report["ok"] is True
    assert report["checks"]["config"]["ok"] is True
    assert report["checks"]["output_root_writable"]["ok"] is True
    assert report["checks"]["smoke"]["ok"] is True
