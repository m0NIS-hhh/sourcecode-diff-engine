from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from source_diff_engine.output.schema import build_pair_summary
from source_diff_engine.output.writer import sanitize_rel_path, write_json_atomic, write_text_atomic


def pair_output_dir(run_root: Path, rel_path: str) -> Path:
    safe_rel = sanitize_rel_path(rel_path)
    return run_root / "pairs" / safe_rel


def write_pair_outputs(
    *,
    run_root: Path,
    file_row: Dict[str, Any],
    concise_rows: List[Dict[str, Any]],
    init_report: Dict[str, Any],
    git_diff_text: str,
    write_json=write_json_atomic,
    write_text=write_text_atomic,
) -> None:
    rel_path = str(file_row.get("rel_path", ""))
    pair_dir = pair_output_dir(run_root, rel_path)
    detail = file_row.get("detail", {}) if isinstance(file_row.get("detail"), dict) else {}
    units = detail.get("units", []) if isinstance(detail, dict) else []

    write_json(pair_dir / "summary.json", build_pair_summary(file_row, init_report))
    write_json(pair_dir / "results.json", concise_rows)
    write_json(pair_dir / "units.json", units if isinstance(units, list) else [])
    if (git_diff_text or "").strip():
        write_text(pair_dir / "diff.patch", git_diff_text)
