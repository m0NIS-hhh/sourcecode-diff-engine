from __future__ import annotations

from typing import Any, Dict, List


def module_name(rel_path: str) -> str:
    parts = [x for x in str(rel_path or "").split("/") if x]
    return parts[0] if parts else "."


def score_value(row: Dict[str, Any]) -> float:
    try:
        return float(row.get("primary_score", row.get("analysis_score", row.get("vulnerability_score", 0.0))))
    except Exception:
        return 0.0


def zero_unit_reason(file_row: Dict[str, Any], init_report: Dict[str, Any]) -> str:
    if int(file_row.get("unit_count", 0)) > 0:
        return ""
    status = str(file_row.get("status", ""))
    if status == "added":
        return "added_file"
    if status == "removed":
        return "removed_file"
    reason = str(init_report.get("zero_unit_reason", "")).strip()
    return reason or "unknown"


def compute_init_quality(
    init_rows: List[Dict[str, Any]],
    min_total_units: int,
    max_zero_unit_ratio: float,
) -> Dict[str, Any]:
    modified_rows = [r for r in init_rows if str(r.get("status", "")) == "modified"]
    total_modified = len(modified_rows)
    total_units = sum(int(r.get("unit_count", 0)) for r in init_rows)
    zero_modified = [r for r in modified_rows if int(r.get("unit_count", 0)) == 0]
    zero_count = len(zero_modified)
    ratio = (float(zero_count) / float(total_modified)) if total_modified > 0 else 0.0
    decode_fallback_count = sum(int(row.get("decode_fallback_count", 0) or 0) for row in init_rows)
    read_error_count = sum(int(row.get("read_error_count", 0) or 0) for row in init_rows)
    decode_fallback_ratio = (float(decode_fallback_count) / float(len(init_rows))) if init_rows else 0.0

    reason_breakdown: Dict[str, int] = {}
    for row in zero_modified:
        reason = str(row.get("zero_unit_reason", "") or "unknown")
        reason_breakdown[reason] = reason_breakdown.get(reason, 0) + 1

    no_changes_only = bool(total_modified > 0) and bool(zero_modified) and zero_count == total_modified and set(reason_breakdown).issubset({"identical"})
    issues: List[str] = []
    if total_units < int(min_total_units):
        issues.append(f"total_units_below_threshold({total_units}<{int(min_total_units)})")
    if total_modified > 0 and ratio > float(max_zero_unit_ratio):
        issues.append(f"zero_unit_ratio_exceeded({ratio:.4f}>{float(max_zero_unit_ratio):.4f})")
    if read_error_count > 0:
        issues.append(f"read_errors_detected({read_error_count})")
    if no_changes_only and not issues:
        analysis_quality = "no_changes"
    else:
        analysis_quality = "invalid" if issues else "valid"

    return {
        "analysis_quality": analysis_quality,
        "quality_issues": issues,
        "thresholds": {
            "min_total_units": int(min_total_units),
            "max_zero_unit_ratio": float(max_zero_unit_ratio),
        },
        "modified_file_count": total_modified,
        "zero_unit_modified_file_count": zero_count,
        "zero_unit_modified_ratio": round(ratio, 4),
        "decode_fallback_file_count": int(decode_fallback_count),
        "decode_fallback_file_ratio": round(decode_fallback_ratio, 4),
        "read_error_file_count": int(read_error_count),
        "zero_unit_reason_breakdown": reason_breakdown,
        "total_units": int(total_units),
        "no_changes_only": no_changes_only,
    }
