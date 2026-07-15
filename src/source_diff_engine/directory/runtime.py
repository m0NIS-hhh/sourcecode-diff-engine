from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from source_diff_engine.preprocess.source_preprocessor import SourcePreprocessor


def line_range_for_code(code: str, start_line: int = 1) -> List[int]:
    if start_line <= 0:
        return [0, 0]
    line_count = max(1, len((code or "").splitlines()))
    return [start_line, start_line + line_count - 1]


def attach_synthetic_symbol_context(
    pre: SourcePreprocessor,
    code: str,
    start_line: int,
) -> Dict[str, Any]:
    line_range = line_range_for_code(code, start_line=start_line)
    symbols = pre._extract_symbols_from_source(code, pre.language)
    context = pre._build_symbol_context(symbols, line_range)
    if not str(context.get("display", "")).strip() and symbols:
        start, end = line_range
        overlapping = [
            symbol
            for symbol in symbols
            if int(symbol.get("start_line", 0)) <= end and int(symbol.get("end_line", 0)) >= start
        ]
        if not overlapping:
            overlapping = list(symbols)
        overlapping.sort(
            key=lambda symbol: (
                -(int(symbol.get("end_line", 0)) - int(symbol.get("start_line", 0))),
                int(symbol.get("start_line", 0)),
            )
        )
        fallback = pre._symbol_view(overlapping[0]) if overlapping else {}
        if fallback:
            context["display"] = str(fallback.get("name", ""))
            context["symbols"] = [fallback]
            context["innermost_symbol"] = dict(fallback)
    context["language"] = pre.language
    return context


def read_source_snapshot(path: str) -> Dict[str, Any]:
    read_result = SourcePreprocessor.read_text_with_metadata(path)
    metadata = read_result.get("metadata", {}) if isinstance(read_result.get("metadata"), dict) else {}
    return {
        "text": str(read_result.get("text", "")),
        "metadata": dict(metadata),
    }


def build_added_or_removed_unit(pair: Dict[str, Any], status: str, pre: SourcePreprocessor) -> Dict[str, Any]:
    rel = str(pair["rel_path"])
    if status == "added":
        new_snapshot = read_source_snapshot(str(pair["new_path"]))
        new_code = str(new_snapshot.get("text", ""))
        new_focus = line_range_for_code(new_code, start_line=1)
        return {
            "old_unit": None,
            "new_unit": f"{rel}:added->1",
            "similarity": 0.0,
            "change_type": "added",
            "old_code": "",
            "new_code": new_code,
            "file_path": rel,
            "old_start": 0,
            "new_start": 1,
            "old_focus_line_range": [0, 0],
            "new_focus_line_range": new_focus,
            "old_symbol_context": {},
            "new_symbol_context": attach_synthetic_symbol_context(pre, new_code, start_line=1),
            "hunk_header": "@@ -0,0 +1,1 @@",
            "source_read_summary": SourcePreprocessor._build_read_summary(
                old_source=SourcePreprocessor._empty_read_metadata(label="source", path=str(pair.get("old_path") or "")),
                new_source=dict(new_snapshot.get("metadata", {})),
                diff_stdout=SourcePreprocessor._empty_read_metadata(label="diff_stdout"),
                diff_stderr=SourcePreprocessor._empty_read_metadata(label="diff_stderr"),
            ),
        }

    old_snapshot = read_source_snapshot(str(pair["old_path"]))
    old_code = str(old_snapshot.get("text", ""))
    old_focus = line_range_for_code(old_code, start_line=1)
    return {
        "old_unit": f"{rel}:1->removed",
        "new_unit": None,
        "similarity": 0.0,
        "change_type": "removed",
        "old_code": old_code,
        "new_code": "",
        "file_path": rel,
        "old_start": 1,
        "new_start": 0,
        "old_focus_line_range": old_focus,
        "new_focus_line_range": [0, 0],
        "old_symbol_context": attach_synthetic_symbol_context(pre, old_code, start_line=1),
        "new_symbol_context": {},
        "hunk_header": "@@ -1,1 +0,0 @@",
        "source_read_summary": SourcePreprocessor._build_read_summary(
            old_source=dict(old_snapshot.get("metadata", {})),
            new_source=SourcePreprocessor._empty_read_metadata(label="source", path=str(pair.get("new_path") or "")),
            diff_stdout=SourcePreprocessor._empty_read_metadata(label="diff_stdout"),
            diff_stderr=SourcePreprocessor._empty_read_metadata(label="diff_stderr"),
        ),
    }


def synthetic_init_report(pair: Dict[str, Any], status: str, diff_units: List[Dict[str, Any]]) -> Dict[str, Any]:
    old_path = str(pair.get("old_path") or "")
    new_path = str(pair.get("new_path") or "")
    added_line_count = 0
    deleted_line_count = 0
    old_source_meta = SourcePreprocessor._empty_read_metadata(label="source", path=old_path)
    new_source_meta = SourcePreprocessor._empty_read_metadata(label="source", path=new_path)
    if status == "added" and new_path:
        new_snapshot = read_source_snapshot(new_path)
        added_line_count = len(str(new_snapshot.get("text", "")).splitlines())
        new_source_meta = dict(new_snapshot.get("metadata", {}))
    elif status == "removed" and old_path:
        old_snapshot = read_source_snapshot(old_path)
        deleted_line_count = len(str(old_snapshot.get("text", "")).splitlines())
        old_source_meta = dict(old_snapshot.get("metadata", {}))

    return {
        "diff_engine": "synthetic_added_removed",
        "old_source": old_path,
        "new_source": new_path,
        "diff_return_code": 0,
        "stderr": "",
        "unit_count": len(diff_units),
        "hunk_count": 1 if diff_units else 0,
        "added_line_count": added_line_count,
        "deleted_line_count": deleted_line_count,
        "file_kind": "text",
        "is_identical": False,
        "zero_unit_reason": "",
        "read_summary": SourcePreprocessor._build_read_summary(
            old_source=old_source_meta,
            new_source=new_source_meta,
            diff_stdout=SourcePreprocessor._empty_read_metadata(label="diff_stdout"),
            diff_stderr=SourcePreprocessor._empty_read_metadata(label="diff_stderr"),
        ),
    }


def resolve_language(explicit_language: str, old_path: str, new_path: str) -> str:
    mode = (explicit_language or "auto").strip().lower()
    if mode == "auto":
        return SourcePreprocessor.infer_language_from_paths(old_path=old_path, new_path=new_path)
    return SourcePreprocessor.normalize_language(mode)


def pair_risk_priority(item: Dict[str, Any]) -> int:
    rel_path = str(item.get("rel_path", "")).replace("\\", "/").lower()
    name = Path(rel_path).name.lower()
    status = str(item.get("status", "")).lower()

    score = 0
    if status == "modified":
        score += 8
    elif status == "added":
        score += 5
    elif status == "removed":
        score += 2

    strong_path_keywords = (
        "/rest/controller/",
        "/controller/",
        "/servlet/",
        "/filter/",
        "/reactive/",
        "/api/",
        "/web/",
    )
    if any(keyword in rel_path for keyword in strong_path_keywords):
        score += 10

    name_signals = {
        "controller": 8,
        "servlet": 8,
        "filter": 7,
        "handler": 6,
        "endpoint": 6,
        "upload": 5,
        "download": 5,
        "auth": 5,
        "token": 4,
        "login": 4,
        "logout": 4,
        "filetransfer": 4,
        "logretrieval": 4,
        "checkin": 4,
        "connect": 4,
        "ota": 4,
    }
    for keyword, weight in name_signals.items():
        if keyword in name:
            score += weight

    if "/security/" in rel_path or "/auth/" in rel_path:
        score += 5
    if name == "package-info.java":
        score -= 10

    low_signal_name_keywords = (
        "dto",
        "entity",
        "model",
        "enum",
        "setting",
        "settings",
        "config",
        "configuration",
        "response",
        "request",
        "auditrecord",
        "auditrecords",
    )
    if any(keyword in name for keyword in low_signal_name_keywords):
        score -= 4
    if rel_path.endswith("/package-info.java"):
        score -= 8
    return score


def prioritize_pairs_for_sampling(pairs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ranked = list(pairs)
    ranked.sort(key=lambda item: (-pair_risk_priority(item), str(item.get("rel_path", "")).replace("\\", "/").lower()))
    return ranked


def file_fingerprint(path: str) -> str:
    if not path:
        return "-"
    p = Path(path)
    try:
        stat = p.stat()
    except OSError:
        return "missing"
    return f"{stat.st_size}:{stat.st_mtime_ns}"


def files_identical(path_a: str, path_b: str) -> bool:
    if not path_a or not path_b:
        return False
    pa = Path(path_a)
    pb = Path(path_b)
    try:
        sa = pa.stat()
        sb = pb.stat()
    except OSError:
        return False
    if sa.st_size != sb.st_size:
        return False
    if sa.st_size == 0:
        return True
    chunk_size = 1024 * 1024
    try:
        with pa.open("rb") as fa, pb.open("rb") as fb:
            while True:
                ba = fa.read(chunk_size)
                bb = fb.read(chunk_size)
                if ba != bb:
                    return False
                if not ba:
                    return True
    except OSError:
        return False


def pair_key(pair: Dict[str, Any]) -> str:
    rel = str(pair.get("rel_path", ""))
    status = str(pair.get("status", "unknown"))
    old_fp = file_fingerprint(str(pair.get("old_path") or ""))
    new_fp = file_fingerprint(str(pair.get("new_path") or ""))
    return f"{status}|{rel}|{old_fp}|{new_fp}"


def load_checkpoint(checkpoint_file: str) -> Dict[str, Any]:
    path = Path(checkpoint_file)
    if not path.exists():
        return {"version": 1, "completed": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "completed": {}}
    if not isinstance(data, dict):
        return {"version": 1, "completed": {}}
    completed = data.get("completed", {})
    if not isinstance(completed, dict):
        completed = {}
    return {"version": 1, "completed": completed}


def write_checkpoint(checkpoint_file: str, checkpoint_data: Dict[str, Any]) -> None:
    path = Path(checkpoint_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(checkpoint_data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def checkpoint_hit(
    checkpoint_data: Dict[str, Any],
    pair_key_value: str,
) -> Optional[Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]]:
    completed = checkpoint_data.get("completed", {})
    entry = completed.get(pair_key_value)
    if not isinstance(entry, dict):
        return None
    file_row = entry.get("file_row")
    concise_rows = entry.get("concise_rows")
    init_report = entry.get("init_report", {})
    if not isinstance(file_row, dict) or not isinstance(concise_rows, list):
        return None
    if not isinstance(init_report, dict):
        init_report = {}
    return file_row, concise_rows, init_report


def analyze_with_retry(
    analyze_pair_fn,
    *,
    analyzer: Any,
    pair: Dict[str, Any],
    language: str,
    max_units_per_file: int,
    retry_failed_files: int,
    analysis_profile: str,
) -> Dict[str, Any]:
    attempts = 0
    last_error: Optional[Exception] = None
    total = max(0, int(retry_failed_files)) + 1
    while attempts < total:
        attempts += 1
        try:
            try:
                out = analyze_pair_fn(
                    analyzer=analyzer,
                    pair=pair,
                    language=language,
                    max_units_per_file=max_units_per_file,
                    analysis_profile=analysis_profile,
                )
            except TypeError as exc:
                if "analysis_profile" not in str(exc):
                    raise
                out = analyze_pair_fn(
                    analyzer=analyzer,
                    pair=pair,
                    language=language,
                    max_units_per_file=max_units_per_file,
                )
            out["attempts"] = attempts
            return out
        except Exception as exc:
            last_error = exc
            if attempts >= total:
                break
    assert last_error is not None
    raise last_error
