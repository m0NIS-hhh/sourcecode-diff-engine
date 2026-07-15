from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from source_diff_engine.analysis.pipeline import analyze_diff_units_in_memory
from source_diff_engine.directory.manifest import build_directory_pairs
from source_diff_engine.directory.outputs import write_pair_outputs as _write_pair_outputs_impl
from source_diff_engine.directory.quality import (
    compute_init_quality as _compute_init_quality_impl,
    module_name as _module_name_impl,
    score_value as _score_value_impl,
    zero_unit_reason as _zero_unit_reason_impl,
)
from source_diff_engine.directory.review import (
    build_high_risk_review_queue as _build_high_risk_review_queue_impl,
    review_existing_directory_run,
    run_high_risk_review_pass as _run_high_risk_review_pass_impl,
)
from source_diff_engine.directory.runtime import (
    analyze_with_retry as _analyze_with_retry_impl,
    build_added_or_removed_unit as _build_added_or_removed_unit_impl,
    checkpoint_hit as _checkpoint_hit_impl,
    files_identical as _files_identical_impl,
    load_checkpoint as _load_checkpoint_impl,
    pair_key as _pair_key_impl,
    prioritize_pairs_for_sampling as _prioritize_pairs_for_sampling_impl,
    resolve_language as _resolve_language_impl,
    synthetic_init_report as _synthetic_init_report_impl,
    write_checkpoint as _write_checkpoint_impl,
)
from source_diff_engine.logger_config import get_logger
from source_diff_engine.output.schema import (
    SCHEMA_VERSION,
    build_directory_detailed,
    build_directory_init_overview,
    build_directory_overview,
    build_directory_pair_summary,
    build_directory_runtime,
    build_review_queue_summary,
    build_top_risky_file_entry,
)
from source_diff_engine.analysis.profiles import DEFAULT_ANALYSIS_PROFILE, normalize_analysis_profile
from source_diff_engine.output.writer import (
    build_high_risk_index_entries,
    build_run_summary,
    build_run_summary_markdown,
    write_json_atomic,
    write_text_atomic,
)
from source_diff_engine.pipeline.results import normalize_evidence
from source_diff_engine.preprocess.source_preprocessor import SourcePreprocessor
from source_diff_engine.source_analyzer import SourceAnalyzer

logger = get_logger(__name__)


def _increment_count(counter: Dict[str, int], key: Any) -> None:
    text = str(key or "").strip()
    if not text:
        return
    counter[text] = counter.get(text, 0) + 1


def _failure_category(exc: Exception) -> str:
    message = str(exc or "").strip().lower()
    if isinstance(exc, FileNotFoundError):
        return "missing_file"
    if isinstance(exc, PermissionError):
        return "permission_error"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ValueError):
        return "invalid_input"
    if "llm" in message or "preflight" in message or "api key" in message:
        return "llm_runtime"
    if "decode" in message or "encoding" in message or "unicode" in message:
        return "decode_error"
    return "analysis_error"


def _resolve_language(explicit_language: str, old_path: str, new_path: str) -> str:
    return _resolve_language_impl(explicit_language, old_path, new_path)


def _prioritize_pairs_for_sampling(pairs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return _prioritize_pairs_for_sampling_impl(pairs)


def _files_identical(path_a: str, path_b: str) -> bool:
    return _files_identical_impl(path_a, path_b)


def _pair_key(pair: Dict[str, Any]) -> str:
    return _pair_key_impl(pair)


def _load_checkpoint(checkpoint_file: str) -> Dict[str, Any]:
    return _load_checkpoint_impl(checkpoint_file)


def _write_checkpoint(checkpoint_file: str, checkpoint_data: Dict[str, Any]) -> None:
    _write_checkpoint_impl(checkpoint_file, checkpoint_data)


def _checkpoint_hit(
    checkpoint_data: Dict[str, Any],
    pair_key_value: str,
) -> Optional[Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]]:
    return _checkpoint_hit_impl(checkpoint_data, pair_key_value)


def _compute_init_quality(
    init_rows: List[Dict[str, Any]],
    min_total_units: int,
    max_zero_unit_ratio: float,
) -> Dict[str, Any]:
    return _compute_init_quality_impl(init_rows, min_total_units, max_zero_unit_ratio)


def _module_name(rel_path: str) -> str:
    return _module_name_impl(rel_path)


def _score_value(row: Dict[str, Any]) -> float:
    return _score_value_impl(row)


def _zero_unit_reason(file_row: Dict[str, Any], init_report: Dict[str, Any]) -> str:
    return _zero_unit_reason_impl(file_row, init_report)


def _write_pair_outputs(
    run_root: Path,
    file_row: Dict[str, Any],
    concise_rows: List[Dict[str, Any]],
    init_report: Dict[str, Any],
    git_diff_text: str,
) -> None:
    _write_pair_outputs_impl(
        run_root=run_root,
        file_row=file_row,
        concise_rows=concise_rows,
        init_report=init_report,
        git_diff_text=git_diff_text,
        write_json=write_json_atomic,
        write_text=write_text_atomic,
    )


def _build_high_risk_review_queue(
    run_root: Path,
    file_rows: List[Dict[str, Any]],
    high_risk_index: List[Dict[str, Any]],
    review_score_threshold: float,
    review_top_n: int,
    llm_enabled: bool,
) -> List[Dict[str, Any]]:
    return _build_high_risk_review_queue_impl(
        run_root=run_root,
        file_rows=file_rows,
        high_risk_index=high_risk_index,
        review_score_threshold=review_score_threshold,
        review_top_n=review_top_n,
        llm_enabled=llm_enabled,
    )


def _run_high_risk_review_pass(
    analyzer: SourceAnalyzer,
    result_by_key: Dict[str, Dict[str, Any]],
    pairs: List[Dict[str, Any]],
    high_risk_review_queue: List[Dict[str, Any]],
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> List[Dict[str, Any]]:
    return _run_high_risk_review_pass_impl(
        analyzer=analyzer,
        result_by_key=result_by_key,
        pairs=pairs,
        high_risk_review_queue=high_risk_review_queue,
        analysis_profile=normalize_analysis_profile(analysis_profile),
    )


def _analyze_pair(
    analyzer: SourceAnalyzer,
    pair: Dict[str, Any],
    language: str,
    max_units_per_file: int,
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Dict[str, Any]:
    status = str(pair["status"])
    old_path = str(pair.get("old_path") or "")
    new_path = str(pair.get("new_path") or "")
    rel_path = str(pair["rel_path"])
    pair_key_value = str(pair["_pair_key"])
    file_lang = _resolve_language(language, old_path=old_path, new_path=new_path)
    pre = SourcePreprocessor(language=file_lang)

    init_report: Dict[str, Any]
    git_diff_text = ""
    if status == "modified":
        data = pre.process_source_diff(old_path, new_path)
        diff_units = list(data.get("diff_units", []))[: max(0, int(max_units_per_file))]
        git_diff_text = str(data.get("diff_text", ""))
        raw_init = data.get("init_report", {})
        init_report = dict(raw_init) if isinstance(raw_init, dict) else {}
    else:
        diff_units = [_build_added_or_removed_unit_impl(pair, status=status, pre=pre)]
        diff_units = diff_units[: max(0, int(max_units_per_file))]
        init_report = _synthetic_init_report_impl(pair, status=status, diff_units=diff_units)

    mem = analyze_diff_units_in_memory(
        analyzer=analyzer,
        diff_units=diff_units,
        language=file_lang,
        git_diff_text=git_diff_text,
        analysis_profile=normalize_analysis_profile(analysis_profile),
    )
    concise_rows = list(mem["concise_rows"])
    file_row = {
        "rel_path": rel_path,
        "status": status,
        "language": file_lang,
        "unit_count": len(concise_rows),
        "overview": mem["overview"],
        "detail": mem["detailed_doc"],
    }
    return {
        "pair_key": pair_key_value,
        "file_row": file_row,
        "concise_rows": concise_rows,
        "init_report": init_report,
        "git_diff_text": git_diff_text,
        "diff_units": diff_units,
    }


def _analyze_with_retry(
    analyzer: SourceAnalyzer,
    pair: Dict[str, Any],
    language: str,
    max_units_per_file: int,
    retry_failed_files: int,
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Dict[str, Any]:
    return _analyze_with_retry_impl(
        _analyze_pair,
        analyzer=analyzer,
        pair=pair,
        language=language,
        max_units_per_file=max_units_per_file,
        retry_failed_files=retry_failed_files,
        analysis_profile=analysis_profile,
    )


def run_directory_analysis(
    analyzer: SourceAnalyzer,
    old_root: str,
    new_root: str,
    output_root: str,
    run_id: str,
    language: str,
    max_units_per_file: int,
    max_files: int,
    workers: int,
    fail_fast: bool,
    retry_failed_files: int,
    checkpoint_file: str,
    resume: bool,
    min_total_units: int = 1,
    max_zero_unit_ratio: float = 0.95,
    fail_on_invalid_quality: bool = False,
    meta_overrides: Optional[Dict[str, Any]] = None,
    review_score_threshold: float = 7.0,
    review_top_n: int = 0,
    enable_llm_review_pass: bool = False,
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
    include_extensions: Optional[List[str]] = None,
    exclude_dirs: Optional[List[str]] = None,
    exclude_globs: Optional[List[str]] = None,
    max_file_size_bytes: int = 1024 * 1024,
) -> Dict[str, Any]:
    run_root = Path(output_root) / run_id
    run_root.mkdir(parents=True, exist_ok=True)
    analysis_profile = normalize_analysis_profile(analysis_profile)

    pair_doc = build_directory_pairs(
        old_root=old_root,
        new_root=new_root,
        include_extensions={str(x).lower() for x in include_extensions} if include_extensions else None,
        exclude_dirs={str(x).lower() for x in exclude_dirs} if exclude_dirs else None,
        exclude_globs={str(x) for x in exclude_globs} if exclude_globs else None,
        max_file_size_bytes=max(0, int(max_file_size_bytes)),
    )
    original_pairs = list(pair_doc["pairs"])
    manifest_skipped_files = list(pair_doc.get("skipped_files", [])) if isinstance(pair_doc.get("skipped_files", []), list) else []
    manifest_skipped_by_reason = (
        dict(pair_doc.get("skipped_by_reason", {})) if isinstance(pair_doc.get("skipped_by_reason", {}), dict) else {}
    )
    filtered_pairs: List[Dict[str, Any]] = []
    skipped_identical_modified = 0
    for item in original_pairs:
        status = str(item.get("status", ""))
        if status == "modified":
            old_path = str(item.get("old_path") or "")
            new_path = str(item.get("new_path") or "")
            if _files_identical(old_path, new_path):
                skipped_identical_modified += 1
                continue
        filtered_pairs.append(item)

    pairs = _prioritize_pairs_for_sampling(filtered_pairs)
    if max_files > 0:
        pairs = pairs[: max_files]

    checkpoint_data = _load_checkpoint(checkpoint_file) if checkpoint_file else {"version": 1, "completed": {}}
    result_by_key: Dict[str, Dict[str, Any]] = {}
    failed_files: List[Dict[str, Any]] = []
    pending_pairs: List[Dict[str, Any]] = []
    resumed_file_count = 0
    retried_file_count = 0
    failure_categories: Dict[str, int] = {}

    for item in pairs:
        key = _pair_key(item)
        item["_pair_key"] = key
        if resume:
            hit = _checkpoint_hit(checkpoint_data, key)
            if hit is not None:
                file_row, concise_rows, init_report = hit
                result_by_key[key] = {
                    "file_row": file_row,
                    "concise_rows": concise_rows,
                    "init_report": init_report,
                    "git_diff_text": "",
                    "outputs_written": False,
                }
                resumed_file_count += 1
                continue
        pending_pairs.append(item)

    fail_fast_triggered = False
    if workers <= 1:
        for item in pending_pairs:
            rel_path = str(item.get("rel_path", ""))
            try:
                result = _analyze_with_retry(
                    analyzer=analyzer,
                    pair=item,
                    language=language,
                    max_units_per_file=max_units_per_file,
                    retry_failed_files=retry_failed_files,
                    analysis_profile=analysis_profile,
                )
                if int(result.get("attempts", 1) or 1) > 1:
                    retried_file_count += 1
            except Exception as exc:
                logger.exception("directory file analysis failed: %s", rel_path)
                category = _failure_category(exc)
                _increment_count(failure_categories, category)
                failed_files.append(
                    {
                        "rel_path": rel_path,
                        "status": str(item.get("status", "")),
                        "failure_category": category,
                        "error": str(exc),
                        "attempts": max(0, int(retry_failed_files)) + 1,
                    }
                )
                if fail_fast:
                    fail_fast_triggered = True
                    break
                continue
            result_by_key[result["pair_key"]] = {
                "file_row": result["file_row"],
                "concise_rows": result["concise_rows"],
                "init_report": result.get("init_report", {}),
                "git_diff_text": str(result.get("git_diff_text", "")),
                "diff_units": result.get("diff_units", []),
                "outputs_written": False,
            }
            _write_pair_outputs(
                run_root=run_root,
                file_row=result["file_row"],
                concise_rows=result["concise_rows"],
                init_report=result.get("init_report", {}),
                git_diff_text=str(result.get("git_diff_text", "")),
            )
            result_by_key[result["pair_key"]]["outputs_written"] = True
            if checkpoint_file:
                checkpoint_data["completed"][result["pair_key"]] = {
                    "file_row": result["file_row"],
                    "concise_rows": result["concise_rows"],
                    "init_report": result.get("init_report", {}),
                }
                _write_checkpoint(checkpoint_file, checkpoint_data)
    else:
        executor = ThreadPoolExecutor(max_workers=max(1, int(workers)))
        future_map = {
            executor.submit(
                _analyze_with_retry,
                analyzer,
                item,
                language,
                max_units_per_file,
                retry_failed_files,
                analysis_profile,
            ): item
            for item in pending_pairs
        }
        try:
            for future in as_completed(future_map):
                item = future_map[future]
                rel_path = str(item.get("rel_path", ""))
                try:
                    result = future.result()
                    if int(result.get("attempts", 1) or 1) > 1:
                        retried_file_count += 1
                except Exception as exc:
                    logger.exception("directory file analysis failed: %s", rel_path)
                    category = _failure_category(exc)
                    _increment_count(failure_categories, category)
                    failed_files.append(
                        {
                            "rel_path": rel_path,
                            "status": str(item.get("status", "")),
                            "failure_category": category,
                            "error": str(exc),
                            "attempts": max(0, int(retry_failed_files)) + 1,
                        }
                    )
                    if fail_fast:
                        fail_fast_triggered = True
                        for running in future_map:
                            if not running.done():
                                running.cancel()
                        break
                    continue
                result_by_key[result["pair_key"]] = {
                    "file_row": result["file_row"],
                    "concise_rows": result["concise_rows"],
                    "init_report": result.get("init_report", {}),
                    "git_diff_text": str(result.get("git_diff_text", "")),
                    "diff_units": result.get("diff_units", []),
                    "outputs_written": False,
                }
                _write_pair_outputs(
                    run_root=run_root,
                    file_row=result["file_row"],
                    concise_rows=result["concise_rows"],
                    init_report=result.get("init_report", {}),
                    git_diff_text=str(result.get("git_diff_text", "")),
                )
                result_by_key[result["pair_key"]]["outputs_written"] = True
                if checkpoint_file:
                    checkpoint_data["completed"][result["pair_key"]] = {
                        "file_row": result["file_row"],
                        "concise_rows": result["concise_rows"],
                        "init_report": result.get("init_report", {}),
                    }
                    _write_checkpoint(checkpoint_file, checkpoint_data)
        finally:
            executor.shutdown(wait=not fail_fast_triggered, cancel_futures=fail_fast_triggered)

    file_rows: List[Dict[str, Any]] = []
    init_rows: List[Dict[str, Any]] = []
    all_concise_rows: List[Dict[str, Any]] = []
    high_risk_index: List[Dict[str, Any]] = []
    static_fallback_count = 0
    for item in pairs:
        key = str(item.get("_pair_key", ""))
        data = result_by_key.get(key)
        if not data:
            continue
        if not bool(data.get("outputs_written", False)):
            _write_pair_outputs(
                run_root=run_root,
                file_row=data["file_row"],
                concise_rows=data["concise_rows"],
                init_report=data.get("init_report", {}),
                git_diff_text=str(data.get("git_diff_text", "")),
            )
        file_row = data["file_row"]
        init_report = data.get("init_report", {})
        file_rows.append(file_row)
        all_concise_rows.extend(data["concise_rows"])
        static_fallback_count += sum(
            1
            for row in data["concise_rows"]
            if str(row.get("analysis_backend", "static")).strip().lower() != "llm"
        )
        detail = file_row.get("detail", {}) if isinstance(file_row.get("detail"), dict) else {}
        units = detail.get("units", []) if isinstance(detail.get("units"), list) else []
        high_risk_index.extend(
            build_high_risk_index_entries(
                rel_path=str(file_row.get("rel_path", "")),
                status=str(file_row.get("status", "")),
                language=str(file_row.get("language", "")),
                concise_rows=data["concise_rows"],
                units=units,
            )
        )
        init_rows.append(
            {
                "pair_key": key,
                "rel_path": str(file_row.get("rel_path", "")),
                "status": str(file_row.get("status", "")),
                "unit_count": int(file_row.get("unit_count", 0)),
                "file_kind": str(init_report.get("file_kind", "unknown")),
                "hunk_count": int(init_report.get("hunk_count", 0) or 0),
                "added_line_count": int(init_report.get("added_line_count", 0) or 0),
                "deleted_line_count": int(init_report.get("deleted_line_count", 0) or 0),
                "zero_unit_reason": _zero_unit_reason(file_row, init_report if isinstance(init_report, dict) else {}),
                "diff_return_code": int(init_report.get("diff_return_code", 0) or 0),
                "decode_fallback_count": int(((init_report.get("read_summary", {}) or {}).get("decode_fallback_count", 0) or 0)),
                "read_error_count": int(((init_report.get("read_summary", {}) or {}).get("read_error_count", 0) or 0)),
            }
        )

    by_vuln: Dict[str, int] = {}
    by_change: Dict[str, int] = {}
    high_risk = 0
    by_language: Dict[str, Dict[str, int]] = {}
    by_module: Dict[str, Dict[str, int]] = {}
    risky_file_candidates: List[Dict[str, Any]] = []
    analysis_axes: Dict[str, Dict[str, Any]] = {
        "change": {"by_change_type": {}, "by_change_intent": {}},
        "security": {"by_vulnerability_type": {}, "by_security_impact": {}, "review_required_unit_count": 0},
        "attack_surface": {"by_attack_surface_impact": {}},
        "behavior": {"by_behavioral_impact": {}, "by_interface_impact": {}},
        "evidence": {
            "by_evidence_status": {},
            "by_observed_chain_completeness": {},
            "by_inferred_chain_completeness": {},
            "by_inference_level": {},
            "by_assessment_basis": {},
            "review_required_unit_count": 0,
        },
    }

    for row in all_concise_rows:
        vt = str(row.get("vulnerability_type", "unknown_vuln"))
        ct = str(row.get("change_type", "unknown_change"))
        evidence = normalize_evidence(row.get("evidence", {}))
        evidence_summary = evidence.get("convenience_summary", {})
        by_vuln[vt] = by_vuln.get(vt, 0) + 1
        by_change[ct] = by_change.get(ct, 0) + 1
        if _score_value(row) >= 7.0:
            high_risk += 1
        _increment_count(analysis_axes["change"]["by_change_type"], row.get("change_type"))
        _increment_count(analysis_axes["change"]["by_change_intent"], row.get("change_intent"))
        _increment_count(analysis_axes["security"]["by_vulnerability_type"], row.get("vulnerability_type"))
        _increment_count(analysis_axes["security"]["by_security_impact"], row.get("security_impact"))
        _increment_count(analysis_axes["attack_surface"]["by_attack_surface_impact"], row.get("attack_surface_impact"))
        _increment_count(analysis_axes["behavior"]["by_behavioral_impact"], row.get("behavioral_impact"))
        _increment_count(analysis_axes["behavior"]["by_interface_impact"], row.get("interface_impact"))
        _increment_count(analysis_axes["evidence"]["by_evidence_status"], evidence_summary.get("evidence_status"))
        _increment_count(analysis_axes["evidence"]["by_observed_chain_completeness"], evidence_summary.get("observed_chain_completeness"))
        _increment_count(analysis_axes["evidence"]["by_inferred_chain_completeness"], evidence_summary.get("inferred_chain_completeness"))
        _increment_count(analysis_axes["evidence"]["by_inference_level"], evidence_summary.get("inference_level"))
        _increment_count(analysis_axes["evidence"]["by_assessment_basis"], evidence_summary.get("assessment_basis"))
        if bool(row.get("review_required", False)):
            analysis_axes["security"]["review_required_unit_count"] += 1
            analysis_axes["evidence"]["review_required_unit_count"] += 1

    for file_row in file_rows:
        rel = str(file_row.get("rel_path", ""))
        lang = str(file_row.get("language", "unknown"))
        module = _module_name(rel)
        detail = file_row.get("detail", {})
        summary = detail.get("file_summary", {}) if isinstance(detail, dict) else {}
        primary_conclusion = summary.get("primary_conclusion", {}) if isinstance(summary.get("primary_conclusion"), dict) else {}
        primary_evidence = normalize_evidence(primary_conclusion.get("evidence", {}))
        file_score = _score_value(primary_conclusion) if isinstance(primary_conclusion, dict) else 0.0
        unit_count = int(file_row.get("unit_count", 0))
        file_high_risk = 1 if file_score >= 7.0 else 0

        if lang not in by_language:
            by_language[lang] = {"file_count": 0, "unit_count": 0, "high_risk_file_count": 0}
        by_language[lang]["file_count"] += 1
        by_language[lang]["unit_count"] += unit_count
        by_language[lang]["high_risk_file_count"] += file_high_risk

        if module not in by_module:
            by_module[module] = {"file_count": 0, "unit_count": 0, "high_risk_file_count": 0}
        by_module[module]["file_count"] += 1
        by_module[module]["unit_count"] += unit_count
        by_module[module]["high_risk_file_count"] += file_high_risk

        risky_file_candidates.append(
            build_top_risky_file_entry(
                rel_path=rel,
                language=lang,
                module=module,
                status=str(file_row.get("status", "")),
                risk_score=round(file_score, 2),
                unit_count=unit_count,
                vulnerability_type=str(primary_conclusion.get("vulnerability_type", "")),
                change_intent=str(primary_conclusion.get("change_intent", "")),
                security_impact=str(primary_conclusion.get("security_impact", "")),
                attack_surface_impact=str(primary_conclusion.get("attack_surface_impact", "")),
                review_required=bool(primary_conclusion.get("review_required", False)),
                evidence_status=str(primary_evidence.get("convenience_summary", {}).get("evidence_status", "")),
            )
        )

    top_risky_files = sorted(
        risky_file_candidates,
        key=lambda x: (float(x.get("risk_score", 0.0)), int(x.get("unit_count", 0))),
        reverse=True,
    )[:20]
    init_quality = _compute_init_quality(
        init_rows=init_rows,
        min_total_units=min_total_units,
        max_zero_unit_ratio=max_zero_unit_ratio,
    )
    if not pairs and skipped_identical_modified > 0 and not failed_files:
        init_quality["analysis_quality"] = "no_changes"
        init_quality["quality_issues"] = []
        init_quality["no_changes_only"] = True
        init_quality["zero_unit_reason_breakdown"] = {"identical": skipped_identical_modified}
    elif init_quality["analysis_quality"] != "valid":
        logger.warning(
            "directory init quality invalid: issues=%s total_units=%s zero_ratio=%.4f",
            init_quality.get("quality_issues", []),
            init_quality.get("total_units", 0),
            float(init_quality.get("zero_unit_modified_ratio", 0.0)),
        )
        if bool(fail_on_invalid_quality) and init_quality["analysis_quality"] == "invalid":
            raise RuntimeError(f"directory init quality invalid: {init_quality.get('quality_issues', [])}")

    runtime = build_directory_runtime(
        max_files=max_files,
        max_units_per_file=max_units_per_file,
        workers=workers,
        fail_fast=fail_fast,
        retry_failed_files=retry_failed_files,
        resume=resume,
        checkpoint_file=checkpoint_file,
        resumed_file_count=resumed_file_count,
        fail_fast_triggered=fail_fast_triggered,
        total_files_scanned=pair_doc["pair_count"],
        selected_files=len(pairs),
        skipped_files=max(0, int(pair_doc["pair_count"]) - len(pairs)),
        retried_files=retried_file_count,
        llm_request_count=int(getattr(getattr(analyzer, "llm", None), "request_count", 0) or 0),
        static_fallback_count=static_fallback_count,
    )
    runtime["manifest_skipped_files"] = len(manifest_skipped_files)
    runtime["manifest_skipped_by_reason"] = manifest_skipped_by_reason
    pair_summary = build_directory_pair_summary(
        old_file_count=pair_doc["old_file_count"],
        new_file_count=pair_doc["new_file_count"],
        pair_count=len(pairs),
        filtered_pair_count=len(filtered_pairs),
        filtered_out_identical_modified_count=skipped_identical_modified,
        full_pair_count=pair_doc["pair_count"],
    )
    pair_summary["manifest_skipped_file_count"] = len(manifest_skipped_files)
    pair_summary["manifest_skipped_by_reason"] = manifest_skipped_by_reason
    detailed = build_directory_detailed(
        old_root=pair_doc["old_root"],
        new_root=pair_doc["new_root"],
        runtime=runtime,
        pair_summary=pair_summary,
        file_rows=file_rows,
        failed_files=failed_files,
        init_quality=init_quality,
    )
    detailed["skipped_files"] = manifest_skipped_files
    overview = build_directory_overview(
        total_units=len(all_concise_rows),
        file_rows=file_rows,
        failed_files=failed_files,
        resumed_file_count=resumed_file_count,
        fail_fast_triggered=fail_fast_triggered,
        by_vulnerability_type=by_vuln,
        by_change_type=by_change,
        by_language=by_language,
        by_module=by_module,
        top_risky_files=top_risky_files,
        high_risk_unit_count=high_risk,
        init_quality=init_quality,
        pair_summary=pair_summary,
        runtime_metrics={
            "selected_files": len(pairs),
            "completed_files": len(file_rows),
            "failed_files": len(failed_files),
            "skipped_files": max(0, int(pair_doc["pair_count"]) - len(pairs)),
            "manifest_skipped_files": len(manifest_skipped_files),
            "retried_files": retried_file_count,
            "llm_request_count": int(getattr(getattr(analyzer, "llm", None), "request_count", 0) or 0),
            "static_fallback_count": static_fallback_count,
        },
        failure_categories=failure_categories,
        analysis_axes=analysis_axes,
        analysis_profile=analysis_profile,
    )
    overview["skipped_files"] = manifest_skipped_files[:200]
    overview["skipped_file_count"] = len(manifest_skipped_files)
    overview["skipped_by_reason"] = manifest_skipped_by_reason
    init_overview = build_directory_init_overview(
        old_root=pair_doc["old_root"],
        new_root=pair_doc["new_root"],
        pair_summary=pair_summary,
        runtime=runtime,
        init_quality=init_quality,
        init_rows=init_rows,
        analysis_profile=analysis_profile,
    )
    init_overview["skipped_files"] = manifest_skipped_files[:200]
    init_overview["skipped_file_count"] = len(manifest_skipped_files)
    init_overview["skipped_by_reason"] = manifest_skipped_by_reason
    high_risk_index = sorted(
        high_risk_index,
        key=lambda x: (float(x.get("risk_score", 0.0)), str(x.get("rel_path", "")), int(x.get("unit_index", 0))),
        reverse=True,
    )
    llm_enabled = bool((meta_overrides or {}).get("llm_enabled", False))
    high_risk_review_queue = _build_high_risk_review_queue(
        run_root=run_root,
        file_rows=file_rows,
        high_risk_index=high_risk_index,
        review_score_threshold=review_score_threshold,
        review_top_n=review_top_n,
        llm_enabled=llm_enabled,
    )
    high_risk_review_results = (
        _run_high_risk_review_pass(
            analyzer=analyzer,
            result_by_key=result_by_key,
            pairs=pairs,
            high_risk_review_queue=high_risk_review_queue,
            analysis_profile=analysis_profile,
        )
        if bool(enable_llm_review_pass)
        else []
    )
    review_queue_summary = build_review_queue_summary(
        review_score_threshold=review_score_threshold,
        review_top_n=review_top_n,
        high_risk_index=high_risk_index,
        high_risk_review_queue=high_risk_review_queue,
        enable_llm_review_pass=enable_llm_review_pass,
        high_risk_review_results=high_risk_review_results,
    )
    meta = {
        "schema_version": SCHEMA_VERSION,
        "mode": "directory",
        "run_id": run_id,
        "output_root": str(Path(output_root).resolve()),
        "run_root": str(run_root.resolve()),
        "analysis_profile": analysis_profile,
        "old_root": pair_doc["old_root"],
        "new_root": pair_doc["new_root"],
        "review_score_threshold": round(max(0.0, min(10.0, float(review_score_threshold))), 2),
        "review_top_n": max(0, int(review_top_n)),
        "enable_llm_review_pass": bool(enable_llm_review_pass),
    }
    if isinstance(meta_overrides, dict):
        for key, value in meta_overrides.items():
            meta[str(key)] = value
    write_json_atomic(run_root / "meta.json", meta)
    write_json_atomic(run_root / "results.json", all_concise_rows)
    write_json_atomic(run_root / "detailed.json", detailed)
    write_json_atomic(run_root / "overview.json", overview)
    write_json_atomic(run_root / "init_overview.json", init_overview)
    write_json_atomic(run_root / "failed_pairs.json", failed_files)
    write_json_atomic(run_root / "high_risk_index.json", high_risk_index)
    overview["review_queue"] = review_queue_summary
    write_json_atomic(run_root / "overview.json", overview)
    write_json_atomic(run_root / "high_risk_review_queue.json", high_risk_review_queue)
    write_json_atomic(run_root / "high_risk_review_results.json", high_risk_review_results)
    summary = build_run_summary(
        mode="directory",
        run_root=str(run_root.resolve()),
        llm_runtime=meta,
        overview=overview,
        top_risky_files=top_risky_files,
    )
    summary["review_queue"] = review_queue_summary
    write_json_atomic(run_root / "summary.json", summary)
    write_text_atomic(run_root / "summary.md", build_run_summary_markdown(summary))

    return {
        "concise_rows": all_concise_rows,
        "detailed": detailed,
        "overview": overview,
        "init_overview": init_overview,
        "run_root": str(run_root),
        "high_risk_review_queue": high_risk_review_queue,
        "high_risk_review_results": high_risk_review_results,
    }
