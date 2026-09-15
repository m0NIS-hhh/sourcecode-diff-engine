from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from source_diff_engine.pipeline.attack_surface import added_lines, removed_lines
from source_diff_engine.analysis.profiles import DEFAULT_ANALYSIS_PROFILE, normalize_analysis_profile
from source_diff_engine.pipeline.results import (
    CHANGE_NON_SECURITY,
    CHANGE_SECURITY_FIX,
    VULN_HARDENING,
    VULN_PENDING,
    build_ranked_candidate,
    dedupe_findings,
    has_complete_s2s,
    normalize_score,
    normalize_s2s,
)
from source_diff_engine.source_analyzer import SourceAnalyzer


def assess_modification_security_intent(old_code: str, new_code: str, language: str = "python") -> Dict[str, Any]:
    language = (language or "python").lower()
    added = added_lines(old_code, new_code)
    removed = removed_lines(old_code, new_code)
    added_lower = "\n".join(added).lower()
    removed_lower = "\n".join(removed).lower()
    merged_lower = f"{old_code or ''}\n{new_code or ''}".lower()

    rules = {
        "python": {
            "dangerous_removed": ["eval(", "exec(", "os.system(", "subprocess.run(", "shell=true", "pickle.loads("],
            "security_guards_added": [
                "raise valueerror",
                "raise typeerror",
                "escape(",
                "quote(",
                "len(",
                "startswith(",
                "endswith(",
                "is_safe_",
                "auth",
                "token",
                "permission",
            ],
            "non_security_signals": ["cache", "metrics", "benchmark", "perf", "latency", "refactor", "rename", "logger."],
            "source_markers": ["request.", "input(", "args", "form", "json", "sys.argv", "os.environ"],
            "sink_markers": ["os.system(", "subprocess.", "eval(", "exec(", "open(", "cursor.execute("],
        },
        "java": {
            "dangerous_removed": ["runtime.getruntime().exec(", "processbuilder(", "scriptenginemanager"],
            "security_guards_added": [
                "toabsolutepath()",
                "normalize()",
                "getnamecount()",
                "startswith(",
                "isauthenticated(",
                "haspermission(",
                "validate(",
                "sanitize(",
                "escape(",
            ],
            "non_security_signals": ["decrement", "increment", "cache", "metric", "optimiz", "memory", "thread", "refactor"],
            "source_markers": ["request.get", "getparameter(", "getheader(", "query", "path", "filename"],
            "sink_markers": ["runtime.getruntime().exec(", "processbuilder(", "statement.execute", "files.write", "files.read"],
        },
        "php": {
            "dangerous_removed": ["eval(", "system(", "exec(", "shell_exec(", "passthru("],
            "security_guards_added": [
                "filter_var(",
                "htmlspecialchars(",
                "mysqli_real_escape_string(",
                "preg_match(",
                "intval(",
                "strlen(",
                "hash_equals(",
            ],
            "non_security_signals": ["cache", "log", "perf", "memory", "refactor", "cleanup"],
            "source_markers": ["$_get", "$_post", "$_request", "$_cookie", "$_server"],
            "sink_markers": ["system(", "exec(", "shell_exec(", "eval(", "mysqli_query(", "fopen(", "include(", "require("],
        },
    }
    lang = rules.get(language, rules["python"])

    removed_dangerous = [kw for kw in lang["dangerous_removed"] if kw in removed_lower]
    added_guards = [kw for kw in lang["security_guards_added"] if kw in added_lower]
    non_security_hits = [kw for kw in lang["non_security_signals"] if kw in added_lower]
    source_hits = [kw for kw in lang["source_markers"] if kw in merged_lower]
    sink_hits = [kw for kw in lang["sink_markers"] if kw in merged_lower]

    has_security_signal = bool(removed_dangerous or added_guards)
    has_security_context = bool(source_hits or sink_hits or added_guards)
    is_security_fix = has_security_signal and has_security_context
    non_security_only = bool(non_security_hits) and not is_security_fix

    reasons: List[str] = []
    if removed_dangerous:
        reasons.append("removed dangerous call patterns")
    if added_guards:
        reasons.append("added security guard/check logic")
    if non_security_hits and not is_security_fix:
        reasons.append("changes look like performance/maintenance updates")
    if not reasons:
        reasons.append("no explicit security-fix signal detected")

    return {
        "is_security_fix": is_security_fix,
        "non_security_only": non_security_only,
        "classification": "security_fix" if is_security_fix else "non_security",
        "reasons": reasons,
        "security_evidence": {
            "added_guard_signals": added_guards,
            "removed_dangerous_signals": removed_dangerous,
            "source_context_signals": source_hits,
            "sink_context_signals": sink_hits,
        },
    }


def infer_s2s_from_fix(
    unit: Dict[str, Any],
    language: str = "python",
    intent: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    old_code = str(unit.get("old_code", "") or "")
    new_code = str(unit.get("new_code", "") or "")
    added = added_lines(old_code, new_code)
    added_text = "\n".join(added).lower()
    all_text = f"{old_code}\n{new_code}".lower()

    source_markers = {
        "python": ["request.", "input(", "args", "form", "json", "path", "filename", "token", "cmd"],
        "java": ["request.get", "query", "header", "param", "path", "filename", "token", "candidate"],
        "php": ["$_get", "$_post", "$_request", "$_cookie", "$_server", "path", "filename", "token"],
    }
    sink_markers = {
        "python": ["os.system(", "subprocess.", "eval(", "exec(", "open(", "cursor.execute(", "send_file("],
        "java": ["runtime.getruntime().exec(", "processbuilder(", "files.read", "files.write", "statement.execute", "startswith("],
        "php": ["system(", "exec(", "shell_exec(", "eval(", "mysqli_query(", "fopen(", "include(", "require("],
    }
    guard_markers = ["if ", "validate", "sanitize", "escape", "normalize", "length", "len(", "getnamecount(", "startswith(", "auth", "permission", "token", "status"]

    lang = (language or "python").lower()
    sources = [m for m in source_markers.get(lang, source_markers["python"]) if m in added_text or m in all_text]
    sinks = [m for m in sink_markers.get(lang, sink_markers["python"]) if m in added_text or m in all_text]
    guards = [line.strip() for line in added if any(k in line.lower() for k in guard_markers)]

    intent_evidence = (intent or {}).get("security_evidence", {}) if isinstance(intent, dict) else {}
    if isinstance(intent_evidence, dict):
        sources.extend([str(x) for x in intent_evidence.get("source_context_signals", []) if str(x).strip()])
        sinks.extend([str(x) for x in intent_evidence.get("sink_context_signals", []) if str(x).strip()])
        guards.extend([str(x) for x in intent_evidence.get("added_guard_signals", []) if str(x).strip()])

    sources = list(dict.fromkeys([str(x).strip() for x in sources if str(x).strip()]))[:6]
    guards = list(dict.fromkeys([str(x).strip() for x in guards if str(x).strip()]))[:8]
    sinks = list(dict.fromkeys([str(x).strip() for x in sinks if str(x).strip()]))[:6]
    chain_parts: List[str] = []
    if sources:
        chain_parts.append(sources[0])
    if guards:
        chain_parts.append(guards[0])
    if sinks:
        chain_parts.append(sinks[0])
    return {
        "sources": [str(x)[:220] for x in sources],
        "guards": [str(x)[:220] for x in guards],
        "sinks": [str(x)[:220] for x in sinks],
        "condition_chain": " -> ".join(chain_parts),
    }


def security_fix_with_llm(
    analyzer: SourceAnalyzer,
    unit: Dict[str, Any],
    intent: Optional[Dict[str, Any]] = None,
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    profile_name = normalize_analysis_profile(analysis_profile)
    row = analyzer.analyze_function_pair(
        old_unit=unit.get("old_unit"),
        new_unit=unit.get("new_unit"),
        old_code=unit.get("old_code", ""),
        new_code=unit.get("new_code", ""),
        similarity=unit.get("similarity", 0.0),
        scenario="security_fix",
        language=str(unit.get("language", "python")),
        artifact=str(unit.get("new_unit") or unit.get("old_unit") or unit.get("file_path") or ""),
        old_symbol_context=unit.get("old_symbol_context"),
        new_symbol_context=unit.get("new_symbol_context"),
        analysis_profile=profile_name,
    )
    normalized = SourceAnalyzer._normalize_schema(row)
    backend = str(normalized.get("analysis_backend", row.get("analysis_backend", "static"))).strip() or "static"
    decision_path = str(normalized.get("decision_path", row.get("decision_path", ""))).strip()
    analysis_reason = str(normalized.get("analysis_reason", row.get("analysis_reason", ""))).strip()
    raw_text = str(row.get("llm_raw_text", "") or "")
    model_was_empty = not bool(raw_text.strip())

    findings: List[Dict[str, Any]] = []
    for item in normalized.get("vulnerability_findings", []):
        if not isinstance(item, dict):
            continue
        evidence = str(item.get("evidence", "")).strip()
        if not evidence:
            continue
        findings.append(
            {
                "type": str(item.get("type", normalized.get("vulnerability_type", VULN_PENDING))) or VULN_PENDING,
                "score": normalize_score(item.get("score", normalized.get("vulnerability_score", 5.0)), 5.0),
                "evidence": evidence,
            }
        )

    if not findings:
        evidence_parts: List[str] = []
        intent_evidence = (intent or {}).get("security_evidence", {}) if isinstance(intent, dict) else {}
        if isinstance(intent_evidence, dict):
            for key in ("removed_dangerous_signals", "added_guard_signals"):
                values = [str(x) for x in intent_evidence.get(key, []) if str(x).strip()]
                if values:
                    evidence_parts.append(f"{key}={values}")
        if backend != "llm":
            fallback_evidence = "Static heuristic security-fix synthesis."
        elif model_was_empty:
            fallback_evidence = "LLM returned empty response text; heuristic security-fix synthesis used."
        else:
            fallback_evidence = "LLM returned limited structured findings; normalized top-level result used."
        if evidence_parts:
            fallback_evidence = f"{fallback_evidence} {'; '.join(evidence_parts)}"
        findings = [{"type": VULN_HARDENING, "score": 5.0, "evidence": fallback_evidence}]

    findings = dedupe_findings(findings)
    findings.sort(key=lambda x: normalize_score(x.get("score", 0.0), 0.0), reverse=True)
    findings = findings[:5]

    primary = findings[0]
    primary_score = max(5.0, normalize_score(primary.get("score", 5.0), 5.0))
    primary["score"] = round(primary_score, 2)

    llm_s2s = normalize_s2s(normalized.get("source_to_sink_conditions", {}))
    static_s2s = normalize_s2s(
        infer_s2s_from_fix(
            unit,
            language=str(unit.get("language", "python")),
            intent=intent,
        )
    )
    s2s = llm_s2s
    chain_inferred = False
    if not has_complete_s2s(s2s):
        s2s = static_s2s
        chain_inferred = True

    resolved_type = str(primary.get("type", "")).strip() or VULN_HARDENING
    if resolved_type == VULN_PENDING:
        resolved_type = VULN_HARDENING
        primary["type"] = VULN_HARDENING

    result = {
        "change_type": CHANGE_SECURITY_FIX,
        "vulnerability_type": resolved_type,
        "vulnerability_score": round(max(5.0, min(10.0, primary_score)), 2),
        "evidence": {
            "observed_facts": {
                "source_to_sink": static_s2s,
                "evidence_origin": "static_analysis",
            },
            "inferred_assessment": {
                "source_to_sink": s2s,
                "summary": str(primary.get("evidence", "") or ""),
                "confidence": float(row.get("confidence", 0.7) or 0.7),
                "reasoning_basis": backend,
                "evidence_origin": "llm_inference" if has_complete_s2s(llm_s2s) else "static_analysis",
            },
            "ranked_candidates": [
                build_ranked_candidate(
                    vulnerability_type=item.get("type", resolved_type),
                    score=item.get("score", primary_score),
                    evidence=item.get("evidence", ""),
                    supporting_source_to_sink=s2s,
                    support_status="inferred" if chain_inferred else ("observed" if has_complete_s2s(s2s) else "partial"),
                    support_inference_level="primary" if chain_inferred else "none",
                )
                for item in findings
            ],
            "convenience_summary": {},
        },
    }

    confidence = float(row.get("confidence", 0.7))
    review_required_raw = bool(row.get("review_required", True))
    has_observed_complete_chain = has_complete_s2s(normalize_s2s(normalized.get("source_to_sink_conditions", {})))
    review_required_final = review_required_raw or (not has_observed_complete_chain) or chain_inferred
    review_reasons: List[str] = []
    if review_required_raw:
        review_reasons.append("llm_requested_manual_review")
    if not has_observed_complete_chain:
        review_reasons.append("observed_chain_incomplete")
    if chain_inferred:
        review_reasons.append("inferred_chain_used")

    debug = {
        "llm_review_invoked": bool(getattr(analyzer.llm, "enabled", False)),
        "analysis_backend": backend,
        "decision_path": "llm_primary" if backend == "llm" else "static_security_fix",
        "analysis_reason": analysis_reason or decision_path or ("llm_primary" if backend == "llm" else "static_security_fix"),
        "confidence": confidence,
        "review_required": review_required_final,
        "review_reasons": review_reasons,
        "llm_raw_empty": model_was_empty,
        "has_observed_complete_chain": has_observed_complete_chain,
        "has_complete_chain": has_observed_complete_chain,
        "chain_inferred": chain_inferred,
    }
    return result, debug
