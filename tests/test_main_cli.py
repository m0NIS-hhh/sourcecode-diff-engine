from __future__ import annotations

import json
import tomllib
from pathlib import Path

from source_diff_engine import main


def test_pyproject_declares_console_entrypoint_for_standard_cli() -> None:
    project_root = Path(__file__).resolve().parents[1]
    with (project_root / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)

    assert pyproject["project"]["scripts"]["source-diff-engine"] == "source_diff_engine.main:main"


def test_build_analyzer_from_config_uses_profile_default_llm_mode(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(main, "create_analyzer", lambda cfg: "analyzer")

    def fake_ensure_llm_ready(analyzer, *, llm_mode, skip_preflight):
        captured["analyzer"] = analyzer
        captured["llm_mode"] = llm_mode
        captured["skip_preflight"] = skip_preflight
        return {"llm_enabled": False, "llm_mode": llm_mode}

    monkeypatch.setattr(main, "ensure_llm_ready", fake_ensure_llm_ready)
    analyzer, runtime = main._build_analyzer_from_config(
        {
            "analysis": {"profile": "security-strict"},
            "llm": {"skip_preflight": False},
            "run": {"max_diff_units": 3},
        }
    )
    assert analyzer == "analyzer"
    assert captured["llm_mode"] == "required"
    assert runtime["analysis_profile"] == "security-strict"


def test_main_doctor_subcommand_routes_to_service(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    def fake_doctor_service(**kwargs):
        captured.update(kwargs)
        return {"ok": True, "checks": {"smoke": {"ok": True}}, "issues": []}

    monkeypatch.setattr(main, "doctor_service", fake_doctor_service)
    code = main.main(
        [
            "doctor",
            "--config",
            "configs/config.example.json",
            "--output-root",
            "out",
            "--smoke-output-root",
            "smoke_out",
            "--llm-mode",
            "off",
            "--skip-llm-preflight",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["ok"] is True
    assert captured["config_path"] == "configs/config.example.json"
    assert captured["output_root"] == "out"
    assert captured["smoke_output_root"] == "smoke_out"
    assert captured["llm_mode"] == "off"
    assert captured["skip_llm_preflight"] is True


def test_main_smoke_subcommand_routes_to_service(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    def fake_smoke_service(**kwargs):
        captured.update(kwargs)
        return {"ok": True, "run_root": "x", "verification": {"ok": True}}

    monkeypatch.setattr(main, "smoke_service", fake_smoke_service)
    code = main.main(
        [
            "smoke",
            "--config",
            "configs/config.example.json",
            "--output-root",
            "out",
            "--run-id",
            "smoke_case",
            "--language",
            "python",
            "--llm-mode",
            "off",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["ok"] is True
    assert captured["config_path"] == "configs/config.example.json"
    assert captured["output_root"] == "out"
    assert captured["run_id"] == "smoke_case"
    assert captured["language"] == "python"
    assert captured["llm_mode"] == "off"


def test_main_run_subcommand_routes_single_file_mode(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "load_config", lambda path: {"llm": {"mode": "try", "skip_preflight": False}, "run": {"max_diff_units": 3}})
    monkeypatch.setattr(main, "_build_analyzer_from_config", lambda cfg, **kwargs: ("analyzer", {"llm_enabled": False}))

    captured: dict[str, object] = {}

    def fake_review_single_pair(**kwargs):
        captured.update(kwargs)
        return {"concise_rows": [], "overview": {"analysis_quality": "valid"}, "run_root": str(tmp_path / "out" / "r1"), "language": "python"}

    monkeypatch.setattr(main, "review_single_pair", fake_review_single_pair)
    code = main.main(
        [
            "run",
            str(tmp_path),
            "--old_file",
            "old.py",
            "--new_file",
            "new.py",
            "--output-root",
            "out",
            "--run-id",
            "r1",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["analysis_quality"] == "valid"
    assert captured["data_folder"] == str(tmp_path)
    assert captured["old_file"] == "old.py"
    assert captured["new_file"] == "new.py"
    assert (tmp_path / "out" / "r1" / "meta.json").exists()


def test_main_run_subcommand_routes_directory_mode(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "load_config", lambda path: {"llm": {"mode": "try", "skip_preflight": False}, "run": {"max_diff_units": 3}})
    monkeypatch.setattr(main, "_build_analyzer_from_config", lambda cfg, **kwargs: ("analyzer", {"llm_enabled": False}))

    captured: dict[str, object] = {}

    def fake_review_directory_diff(**kwargs):
        captured.update(kwargs)
        return {"concise_rows": [], "overview": {"analysis_quality": "valid"}, "run_root": str(tmp_path / "out" / "r2")}

    monkeypatch.setattr(main, "review_directory_diff", fake_review_directory_diff)
    code = main.main(
        [
            "run",
            str(tmp_path),
            "--old_root",
            "old",
            "--new_root",
            "new",
            "--output-root",
            "out",
            "--run-id",
            "r2",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["analysis_quality"] == "valid"
    assert captured["data_folder"] == str(tmp_path)
    assert captured["old_root"] == "old"
    assert captured["new_root"] == "new"


def test_main_reports_missing_config_as_cli_error(monkeypatch, capsys) -> None:
    code = main.main(["doctor", "--config", "missing-config.json", "--llm-mode", "off"])
    output = json.loads(capsys.readouterr().out)

    assert code == 1
    assert output["ok"] is False
    assert any("Config file not found" in issue for issue in output["issues"])
