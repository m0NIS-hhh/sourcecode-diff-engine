from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import run_diff


REGRESSION_ROOT = Path("tests/fixtures/regression")


def _case_dirs() -> list[Path]:
    if not REGRESSION_ROOT.exists():
        return []
    return sorted(path for path in REGRESSION_ROOT.glob("*/*") if (path / "expected.json").exists())


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _collect_rule_ids(run_root: Path) -> set[str]:
    detailed = _load_json(run_root / "detailed.json")
    detail = detailed.get("file", {}).get("detail", {})
    units = detail.get("units", []) if isinstance(detail, dict) else []
    rule_ids: set[str] = set()
    for unit in units:
        check = unit.get("new_vuln_check", {}) if isinstance(unit, dict) else {}
        rule_id = str(check.get("rule_id", "")).strip()
        if rule_id:
            rule_ids.add(rule_id)
        candidates = check.get("candidates", [])
        if isinstance(candidates, list):
            for candidate in candidates:
                if isinstance(candidate, dict) and str(candidate.get("rule_id", "")).strip():
                    rule_ids.add(str(candidate["rule_id"]).strip())
    return rule_ids


@pytest.mark.parametrize("case_dir", _case_dirs(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_regression_fixture_expectations(case_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    expected = _load_json(case_dir / "expected.json")
    language = str(expected["language"])
    file_name = str(expected["file_name"])

    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    args = run_diff._build_parser().parse_args(
        [
            "--config",
            "configs/config.example.json",
            "--data-folder",
            str(case_dir),
            "--old-file",
            str(Path("old") / file_name),
            "--new-file",
            str(Path("new") / file_name),
            "--language",
            language,
            "--profile",
            str(expected.get("profile", "security")),
            "--llm-mode",
            "off",
            "--output-root",
            str(tmp_path / "runs"),
            "--run-id",
            f"regression_{case_dir.parent.name}_{case_dir.name}",
        ]
    )

    summary = run_diff.run(args)
    assert summary["ok"] is True
    summary_payload = summary["summary"]
    assert summary_payload["analysis_quality"] == "valid"
    assert summary_payload["high_risk_unit_count"] >= int(expected.get("expected_high_risk_min", 0))
    assert summary_payload["high_risk_unit_count"] <= int(expected.get("expected_high_risk_max", 999))

    top_findings = summary_payload.get("top_findings", [])
    if expected.get("must_review") is not None and top_findings:
        assert any(bool(item.get("review_required", False)) == bool(expected["must_review"]) for item in top_findings)
    if expected.get("expected_evidence_status") and top_findings:
        assert any(str(item.get("evidence_status", "")) == str(expected["expected_evidence_status"]) for item in top_findings)

    run_root = Path(summary["run_root"])
    rule_ids = _collect_rule_ids(run_root)
    for rule_id in expected.get("expected_rule_ids", []):
        assert rule_id in rule_ids
    for rule_id in expected.get("forbidden_rule_ids", []):
        assert rule_id not in rule_ids
