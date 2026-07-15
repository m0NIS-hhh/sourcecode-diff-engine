from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


REQUIRED_RUN_FILES = [
    "meta.json",
    "results.json",
    "detailed.json",
    "overview.json",
    "init_overview.json",
    "failed_pairs.json",
    "high_risk_index.json",
]


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_score(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _primary_score(row: Dict[str, Any]) -> float:
    return _safe_score(row.get("primary_score", row.get("analysis_score", row.get("vulnerability_score", 0.0))))


def verify_run(run_root: Path) -> Dict[str, Any]:
    issues: List[str] = []
    details: Dict[str, Any] = {"run_root": str(run_root.resolve())}

    missing = [name for name in REQUIRED_RUN_FILES if not (run_root / name).exists()]
    details["missing_run_files"] = missing
    if missing:
        issues.append(f"missing_run_files={missing}")

    overview_path = run_root / "overview.json"
    if not overview_path.exists():
        return {
            "ok": False,
            "issues": issues + ["overview.json missing"],
            "details": details,
        }
    overview = _load_json(overview_path)

    pair_results_files = sorted((run_root / "pairs").rglob("results.json")) if (run_root / "pairs").exists() else []
    pair_results_count = len(pair_results_files)
    total_units_from_pairs = 0
    high_risk_from_pairs = 0
    invalid_pair_results: List[str] = []
    for file_path in pair_results_files:
        try:
            payload = _load_json(file_path)
        except Exception:
            invalid_pair_results.append(str(file_path))
            continue
        rows = payload if isinstance(payload, list) else []
        total_units_from_pairs += len(rows)
        high_risk_from_pairs += sum(1 for row in rows if _primary_score(row) >= 7.0)
    if invalid_pair_results:
        issues.append(f"invalid_pair_results_json_count={len(invalid_pair_results)}")

    total_files_analyzed = int(overview.get("total_files_analyzed", 0) or 0)
    total_units = int(overview.get("total_units", 0) or 0)
    high_risk_unit_count = int(overview.get("high_risk_unit_count", 0) or 0)
    details["analysis_profile"] = str(overview.get("analysis_profile", "generic"))
    details["overview"] = {
        "total_files_analyzed": total_files_analyzed,
        "total_units": total_units,
        "high_risk_unit_count": high_risk_unit_count,
    }
    details["computed"] = {
        "pair_results_file_count": pair_results_count,
        "total_units_from_pairs": total_units_from_pairs,
        "high_risk_from_pairs_score_ge_7": high_risk_from_pairs,
    }

    if total_files_analyzed != pair_results_count:
        issues.append(f"total_files_analyzed_mismatch({total_files_analyzed}!={pair_results_count})")
    if total_units != total_units_from_pairs:
        issues.append(f"total_units_mismatch({total_units}!={total_units_from_pairs})")
    if high_risk_unit_count != high_risk_from_pairs:
        issues.append(f"high_risk_unit_count_mismatch({high_risk_unit_count}!={high_risk_from_pairs})")

    high_risk_index_path = run_root / "high_risk_index.json"
    if high_risk_index_path.exists():
        try:
            high_risk_index = _load_json(high_risk_index_path)
            high_risk_index_count = len(high_risk_index) if isinstance(high_risk_index, list) else 0
        except Exception:
            high_risk_index_count = -1
            issues.append("high_risk_index_invalid_json")
    else:
        high_risk_index_count = -1
    details["computed"]["high_risk_index_count"] = high_risk_index_count
    if high_risk_index_count >= 0 and high_risk_index_count != high_risk_unit_count:
        issues.append(f"high_risk_index_count_mismatch({high_risk_index_count}!={high_risk_unit_count})")

    return {
        "ok": len(issues) == 0,
        "issues": issues,
        "details": details,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify run-level and pair-level output consistency")
    parser.add_argument("run_root", type=str, help="Path to <output-dir>/<run-id>")
    args = parser.parse_args()

    report = verify_run(Path(args.run_root))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
