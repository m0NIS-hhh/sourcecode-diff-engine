from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from source_diff_engine.directory.outputs import pair_output_dir
from source_diff_engine.directory.runtime import build_added_or_removed_unit, resolve_language
from source_diff_engine.directory.manifest import build_directory_pairs
from source_diff_engine.output.writer import write_json_atomic
from source_diff_engine.pipeline.results import build_ranked_candidate, normalize_evidence, normalize_s2s
from source_diff_engine.preprocess.source_preprocessor import SourcePreprocessor
from source_diff_engine.source_analyzer import SourceAnalyzer


def build_high_risk_review_queue(
    *,
    run_root: Path,
    file_rows: List[Dict[str, Any]],
    high_risk_index: List[Dict[str, Any]],
    review_score_threshold: float,
    review_top_n: int,
    llm_enabled: bool,
) -> List[Dict[str, Any]]:
    file_row_map = {
        str(row.get("rel_path", "")): row
        for row in file_rows
        if isinstance(row, dict) and str(row.get("rel_path", "")).strip()
    }
    queue: List[Dict[str, Any]] = []
    threshold = max(0.0, min(10.0, float(review_score_threshold)))

    for entry in high_risk_index:
        if float(entry.get("risk_score", 0.0) or 0.0) < threshold:
            continue
        rel_path = str(entry.get("rel_path", ""))
        file_row = file_row_map.get(rel_path, {})
        detail = file_row.get("detail", {}) if isinstance(file_row.get("detail"), dict) else {}
        units = detail.get("units", []) if isinstance(detail.get("units"), list) else []
        unit_index = int(entry.get("unit_index", 0) or 0)
        unit_detail = units[unit_index] if 0 <= unit_index < len(units) and isinstance(units[unit_index], dict) else {}
        fix_assessment = unit_detail.get("fix_assessment", {}) if isinstance(unit_detail.get("fix_assessment"), dict) else {}
        new_vuln_check = unit_detail.get("new_vuln_check", {}) if isinstance(unit_detail.get("new_vuln_check"), dict) else {}
        fix_review_required = bool(fix_assessment.get("review_required", False))
        llm_review_required = bool(new_vuln_check.get("llm_review_required", False))
        review_required = fix_review_required or llm_review_required or (float(entry.get("risk_score", 0.0) or 0.0) >= 8.0)
        llm_review_invoked = bool(new_vuln_check.get("llm_review_invoked", False))
        llm_review_eligible = bool(llm_enabled) and bool(new_vuln_check.get("has_new_vulnerability", False)) and (not llm_review_invoked)
        new_vuln_candidates = new_vuln_check.get("candidates", []) if isinstance(new_vuln_check.get("candidates"), list) else []

        queue.append(
            {
                **entry,
                "review_required": review_required,
                "review_kind": "llm" if llm_review_eligible else "manual",
                "llm_review_eligible": llm_review_eligible,
                "llm_review_invoked": llm_review_invoked,
                "llm_review_confidence": float(new_vuln_check.get("llm_review_confidence", 0.0) or 0.0),
                "llm_review_required": llm_review_required,
                "fix_review_required": fix_review_required,
                "is_security_fix": bool(fix_assessment.get("is_security_fix", False)),
                "has_new_vulnerability": bool(new_vuln_check.get("has_new_vulnerability", False)),
                "rule_id": str(new_vuln_check.get("rule_id", "")),
                "candidate_count": len(new_vuln_candidates),
                "pair_summary_path": str((pair_output_dir(run_root, rel_path) / "summary.json").relative_to(run_root)).replace("\\", "/"),
                "pair_units_path": str((pair_output_dir(run_root, rel_path) / "units.json").relative_to(run_root)).replace("\\", "/"),
            }
        )

    queue.sort(
        key=lambda x: (
            bool(x.get("review_required", False)),
            bool(x.get("llm_review_eligible", False)),
            float(x.get("risk_score", 0.0)),
            str(x.get("rel_path", "")),
            int(x.get("unit_index", 0)),
        ),
        reverse=True,
    )
    if int(review_top_n) > 0:
        queue = queue[: int(review_top_n)]
    return queue


def build_review_reason(review: Dict[str, Any]) -> str:
    evidence = normalize_evidence(review.get("evidence", {}))
    s2s = evidence.get("inferred_assessment", {}).get("source_to_sink", {})
    findings = evidence.get("ranked_candidates", [])
    summary = evidence.get("convenience_summary", {})
    evidence = ""
    if findings and isinstance(findings[0], dict):
        evidence = str(findings[0].get("evidence", "")).strip()
    chain = str(s2s.get("condition_chain", "")).strip()
    review_reasons = summary.get("review_reasons", []) if isinstance(summary.get("review_reasons"), list) else []
    reason_text = ", ".join(str(item).strip() for item in review_reasons if str(item).strip())
    parts = [part for part in (evidence, chain, reason_text) if part]
    return " | ".join(parts)[:500]


def build_review_evidence(normalized: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, Any]:
    observed = normalize_s2s(normalized.get("source_to_sink_conditions", {}))
    observed_complete = bool(observed.get("sources")) and bool(observed.get("guards")) and bool(observed.get("sinks")) and bool(observed.get("condition_chain"))
    observed_any = any(observed.get(key) for key in ("sources", "guards", "sinks")) or bool(observed.get("condition_chain"))
    findings = normalized.get("vulnerability_findings", []) if isinstance(normalized.get("vulnerability_findings"), list) else []
    ranked_candidates = [
        build_ranked_candidate(
            vulnerability_type=item.get("type", normalized.get("vulnerability_type", "unknown")),
            score=item.get("score", normalized.get("vulnerability_score", 0.0)),
            evidence=item.get("evidence", ""),
            supporting_source_to_sink=observed,
            support_status="observed",
            support_inference_level="none",
        )
        for item in findings
        if isinstance(item, dict)
    ]
    return {
        "observed_facts": {"source_to_sink": observed},
        "inferred_assessment": {
            "source_to_sink": observed,
            "summary": str((ranked_candidates[0].get("evidence", "") if ranked_candidates else "")),
            "confidence": float(normalized.get("confidence", row.get("confidence", 0.0)) or 0.0),
            "reasoning_basis": str(normalized.get("analysis_backend", row.get("analysis_backend", "llm")) or "llm"),
        },
        "ranked_candidates": ranked_candidates,
        "convenience_summary": {
            "evidence_status": "observed" if observed_complete else ("partial" if observed_any else "missing"),
            "observed_chain_completeness": "complete" if observed_complete else ("partial" if observed_any else "missing"),
            "inferred_chain_completeness": "complete" if observed_complete else ("partial" if observed_any else "missing"),
            "inference_level": "none",
            "assessment_basis": str(normalized.get("analysis_backend", row.get("analysis_backend", "llm")) or "llm"),
            "candidate_count": len(ranked_candidates),
            "primary_evidence": str((ranked_candidates[0].get("evidence", "") if ranked_candidates else "")),
            "review_required": bool(normalized.get("review_required", row.get("review_required", True))),
            "review_reasons": ["review_pass_revalidation"],
        },
    }


def review_item_key(entry: Dict[str, Any]) -> str:
    return "|".join(
        [
            str(entry.get("rel_path", "")),
            str(entry.get("unit_index", 0)),
            str(entry.get("artifact", "")),
        ]
    )


def review_scenario_for_unit(unit: Dict[str, Any], queue_entry: Optional[Dict[str, Any]] = None) -> str:
    raw_change_type = str(unit.get("change_type", "")).strip().lower()
    queue_change_type = str((queue_entry or {}).get("change_type", "")).strip().lower()
    combined = f"{raw_change_type} {queue_change_type}"
    if "new" in combined or "新增" in combined or "鏂板" in combined:
        return "new_code"
    if "security" in combined or "修复" in combined or "加固" in combined or "淇" in combined or "鍔犲浐" in combined:
        return "security_fix"
    if raw_change_type == "added":
        return "new_code"
    return "security_fix"


def run_high_risk_review_pass(
    *,
    analyzer: SourceAnalyzer,
    result_by_key: Dict[str, Dict[str, Any]],
    pairs: List[Dict[str, Any]],
    high_risk_review_queue: List[Dict[str, Any]],
    analysis_profile: str,
) -> List[Dict[str, Any]]:
    if not bool(getattr(analyzer.llm, "enabled", False)):
        return []

    pair_by_rel = {str(item.get("rel_path", "")): item for item in pairs}
    reviewed: List[Dict[str, Any]] = []
    for entry in high_risk_review_queue:
        if not bool(entry.get("llm_review_eligible", False)):
            continue
        rel_path = str(entry.get("rel_path", ""))
        pair = pair_by_rel.get(rel_path, {})
        pair_key_value = str(pair.get("_pair_key", ""))
        data = result_by_key.get(pair_key_value, {})
        diff_units = data.get("diff_units", []) if isinstance(data.get("diff_units"), list) else []
        unit_index = int(entry.get("unit_index", 0) or 0)
        if unit_index < 0 or unit_index >= len(diff_units):
            continue
        unit = diff_units[unit_index]
        if not isinstance(unit, dict):
            continue
        scenario = review_scenario_for_unit(unit, entry)
        row = analyzer.analyze_function_pair(
            old_unit=unit.get("old_unit"),
            new_unit=unit.get("new_unit"),
            old_code=unit.get("old_code", ""),
            new_code=unit.get("new_code", ""),
            similarity=unit.get("similarity", 0.0),
            scenario=scenario,
            language=str(data.get("file_row", {}).get("language", unit.get("language", "python"))),
            artifact=str(unit.get("new_unit") or unit.get("old_unit") or unit.get("file_path") or ""),
            old_symbol_context=unit.get("old_symbol_context"),
            new_symbol_context=unit.get("new_symbol_context"),
            analysis_profile=analysis_profile,
        )
        normalized = SourceAnalyzer._normalize_schema(row)
        verdict = str(normalized.get("vulnerability_type", "")).strip() or "unknown"
        review_evidence = build_review_evidence(normalized, row)
        reviewed.append(
            {
                "rel_path": rel_path,
                "unit_index": unit_index,
                "artifact": str(entry.get("artifact", "")),
                "risk_score": float(entry.get("risk_score", 0.0) or 0.0),
                "change_type": str(normalized.get("change_type", "")),
                "llm_verdict": verdict,
                "llm_confidence": float(normalized.get("confidence", row.get("confidence", 0.0)) or 0.0),
                "review_required": bool(normalized.get("review_required", row.get("review_required", True))),
                "llm_reason": build_review_reason({"evidence": review_evidence}),
                "evidence": review_evidence,
            }
        )
    reviewed.sort(
        key=lambda x: (float(x.get("risk_score", 0.0)), float(x.get("llm_confidence", 0.0)), str(x.get("rel_path", "")), int(x.get("unit_index", 0))),
        reverse=True,
    )
    return reviewed


def load_review_target_diff_units(pair: Dict[str, Any], language: str) -> Tuple[List[Dict[str, Any]], str]:
    status = str(pair.get("status", ""))
    old_path = str(pair.get("old_path") or "")
    new_path = str(pair.get("new_path") or "")
    file_lang = resolve_language(language, old_path=old_path, new_path=new_path)
    pre = SourcePreprocessor(language=file_lang)
    if status == "modified":
        data = pre.process_source_diff(old_path, new_path)
        return list(data.get("diff_units", [])), file_lang
    return [build_added_or_removed_unit(pair, status=status, pre=pre)], file_lang


def review_existing_directory_run(
    analyzer: SourceAnalyzer,
    run_root: str,
    review_score_threshold: Optional[float] = None,
    review_top_n: Optional[int] = None,
    resume: bool = False,
    analysis_profile: str = "generic",
) -> Dict[str, Any]:
    root = Path(run_root)
    meta = json.loads((root / "meta.json").read_text(encoding="utf-8"))
    old_root = str(meta.get("old_root", "")).strip()
    new_root = str(meta.get("new_root", "")).strip()
    if not old_root or not new_root:
        raise ValueError("run meta missing old_root/new_root; cannot replay review targets")

    pair_doc = build_directory_pairs(old_root=old_root, new_root=new_root)
    pair_by_rel = {str(item.get("rel_path", "")): item for item in pair_doc.get("pairs", [])}

    queue_path = root / "high_risk_review_queue.json"
    if queue_path.exists():
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
    else:
        index = json.loads((root / "high_risk_index.json").read_text(encoding="utf-8"))
        queue = list(index) if isinstance(index, list) else []
    if not isinstance(queue, list):
        raise ValueError("high_risk_review_queue.json is not a JSON array")

    threshold = None if review_score_threshold is None else max(0.0, min(10.0, float(review_score_threshold)))
    top_n = None if review_top_n is None else max(0, int(review_top_n))
    checkpoint_path = root / "high_risk_review_checkpoint.json"
    checkpoint: Dict[str, Any] = {"version": 1, "selected": [], "completed": {}}
    if resume and checkpoint_path.exists():
        try:
            loaded = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                checkpoint["selected"] = loaded.get("selected", [])
                checkpoint["completed"] = loaded.get("completed", {})
        except Exception:
            checkpoint = {"version": 1, "selected": [], "completed": {}}

    selected: List[Dict[str, Any]] = []
    for entry in queue:
        if not isinstance(entry, dict):
            continue
        score = float(entry.get("risk_score", 0.0) or 0.0)
        if threshold is not None and score < threshold:
            continue
        selected.append(entry)
    selected.sort(
        key=lambda x: (
            bool(x.get("review_required", False)),
            bool(x.get("llm_review_eligible", False)),
            float(x.get("risk_score", 0.0)),
            str(x.get("rel_path", "")),
            int(x.get("unit_index", 0)),
        ),
        reverse=True,
    )
    if top_n is not None and top_n > 0:
        selected = selected[:top_n]
    selected_keys = [review_item_key(entry) for entry in selected]
    checkpoint["selected"] = selected_keys

    if not bool(getattr(analyzer.llm, "enabled", False)):
        raise RuntimeError("LLM is disabled; cannot execute review pass")

    results: List[Dict[str, Any]] = []
    completed = checkpoint.setdefault("completed", {})
    for entry in selected:
        item_key = review_item_key(entry)
        if resume and item_key in completed and isinstance(completed[item_key], dict):
            results.append(completed[item_key])
            continue
        rel_path = str(entry.get("rel_path", ""))
        pair = pair_by_rel.get(rel_path)
        if not pair:
            continue
        diff_units, file_lang = load_review_target_diff_units(pair, language="auto")
        unit_index = int(entry.get("unit_index", 0) or 0)
        if unit_index < 0 or unit_index >= len(diff_units):
            continue
        unit = diff_units[unit_index]
        scenario = review_scenario_for_unit(unit, entry)
        row = analyzer.analyze_function_pair(
            old_unit=unit.get("old_unit"),
            new_unit=unit.get("new_unit"),
            old_code=unit.get("old_code", ""),
            new_code=unit.get("new_code", ""),
            similarity=unit.get("similarity", 0.0),
            scenario=scenario,
            language=file_lang,
            artifact=str(unit.get("new_unit") or unit.get("old_unit") or unit.get("file_path") or ""),
            old_symbol_context=unit.get("old_symbol_context"),
            new_symbol_context=unit.get("new_symbol_context"),
            analysis_profile=analysis_profile,
        )
        normalized = SourceAnalyzer._normalize_schema(row)
        review_evidence = build_review_evidence(normalized, row)
        results.append(
            {
                "rel_path": rel_path,
                "unit_index": unit_index,
                "artifact": str(entry.get("artifact", "")),
                "risk_score": float(entry.get("risk_score", 0.0) or 0.0),
                "change_type": str(normalized.get("change_type", "")),
                "llm_verdict": str(normalized.get("vulnerability_type", "")).strip() or "unknown",
                "llm_confidence": float(normalized.get("confidence", row.get("confidence", 0.0)) or 0.0),
                "review_required": bool(normalized.get("review_required", row.get("review_required", True))),
                "llm_reason": build_review_reason({"evidence": review_evidence}),
                "evidence": review_evidence,
            }
        )
        completed[item_key] = results[-1]
        checkpoint_path.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2), encoding="utf-8")

    results.sort(
        key=lambda x: (float(x.get("risk_score", 0.0)), float(x.get("llm_confidence", 0.0)), str(x.get("rel_path", "")), int(x.get("unit_index", 0))),
        reverse=True,
    )
    write_json_atomic(root / "high_risk_review_results.json", results)
    write_json_atomic(
        root / "high_risk_review_summary.json",
        {
            "run_root": str(root.resolve()),
            "selected_count": len(selected),
            "completed_count": len(results),
            "score_threshold": threshold,
            "top_n": top_n,
        },
    )
    return {"run_root": str(root), "selected": selected, "results": results}
