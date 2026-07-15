from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from source_diff_engine.pipeline.attack_surface import extract_symbol_context_signals
from source_diff_engine.analysis.profiles import DEFAULT_ANALYSIS_PROFILE, normalize_analysis_profile
from source_diff_engine.pipeline.results import (
    CHANGE_NEW_CODE,
    CHANGE_REMOVED,
    CHANGE_SECURITY_FIX,
    VULN_NONE,
    VULN_PENDING,
    DEFAULT_S2S,
    build_ranked_candidate,
    dedupe_candidates,
    dedupe_findings,
    normalize_s2s,
    normalize_score,
    to_str_list,
)
from source_diff_engine.source_analyzer import SourceAnalyzer


def assess_added_risk(
    code: str,
    language: str = "python",
    new_symbol_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    text = code or ""
    lowered = text.lower()
    java_explicit_source_names = {
        "request",
        "req",
        "response",
        "resp",
        "body",
        "payload",
        "file",
        "multipartfile",
        "upload",
        "filename",
        "filepath",
        "path",
        "customerid",
        "deviceid",
        "userid",
        "sid",
        "tokenid",
        "notifyemail",
        "url",
        "uri",
        "target",
        "cmd",
        "command",
        "sql",
        "query",
    }

    def _extract_signature_params(line: str, lang: str) -> str:
        text_line = str(line or "")
        if not text_line.strip():
            return ""
        if lang == "python":
            match = re.search(r"^\s*def\s+\w+\s*\((.*?)\)\s*:", text_line)
            return str(match.group(1) if match else "")
        if lang == "php":
            match = re.search(r"^\s*function\s+\w+\s*\((.*?)\)", text_line)
            return str(match.group(1) if match else "")

        prefix = re.search(
            r"^\s*(?:public|private|protected)?\s*(?:static\s+)?[\w<>\?,\[\]\s]+\s+\w+\s*\(",
            text_line,
        )
        if not prefix:
            return ""
        open_index = prefix.end() - 1
        depth = 0
        for idx in range(open_index, len(text_line)):
            ch = text_line[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text_line[open_index + 1 : idx]
        return ""

    def _split_param_segments(raw_params: str) -> List[str]:
        text_inner = str(raw_params or "")
        if not text_inner.strip():
            return []
        segments: List[str] = []
        current: List[str] = []
        paren_depth = 0
        angle_depth = 0
        bracket_depth = 0
        for ch in text_inner:
            if ch == "," and paren_depth == 0 and angle_depth == 0 and bracket_depth == 0:
                piece = "".join(current).strip()
                if piece:
                    segments.append(piece)
                current = []
                continue
            current.append(ch)
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)
            elif ch == "<":
                angle_depth += 1
            elif ch == ">":
                angle_depth = max(0, angle_depth - 1)
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
        tail = "".join(current).strip()
        if tail:
            segments.append(tail)
        return segments

    def _extract_param_taints(lines: List[str], lang: str) -> set[str]:
        tainted: set[str] = set()
        keyword_hints = (
            "input",
            "cmd",
            "command",
            "query",
            "sql",
            "path",
            "file",
            "filename",
            "url",
            "token",
            "user",
            "payload",
            "arg",
            "data",
        )

        for line in lines:
            raw_params = _extract_signature_params(line, lang)
            if not raw_params:
                continue
            for seg in _split_param_segments(raw_params):
                token = seg.strip()
                if not token:
                    continue
                name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\s*\])?\s*$", token)
                name = name_match.group(1) if name_match else ""
                name = re.sub(r"[^A-Za-z0-9_]", "", name).lstrip("$")
                if not name:
                    continue
                lname = name.lower()
                if lang == "java":
                    type_lower = token.lower()
                    annotated_source = any(
                        marker in type_lower
                        for marker in ("@requestparam", "@pathvariable", "@requestbody", "@requestpart", "@requestheader")
                    )
                    typed_source = any(
                        marker in type_lower
                        for marker in ("httpservletrequest", "multipartfile", "inputstream", "jsonnode", "jsonobject", "map<", "list<")
                    )
                    if annotated_source or typed_source or lname in java_explicit_source_names:
                        tainted.add(lname)
                        continue
                if any(k in lname for k in keyword_hints):
                    tainted.add(lname)
        return tainted

    def _collect_tainted_flow(lines: List[str], lang: str, sink_markers: List[str]) -> Dict[str, Any]:
        tainted = _extract_param_taints(lines, lang)
        assign_pattern = re.compile(r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?\$?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
        java_rhs_source_markers = (
            "request.",
            "request.getparameter(",
            "request.getheader(",
            "request.getquerystring(",
            "request.getrequesturi(",
            "request.getinputstream(",
            "request.getparametermap(",
            "request.getpart(",
            "request.getparts(",
            "req.getparameter(",
            "req.getheader(",
            "req.getquerystring(",
            "req.getrequesturi(",
            "req.getinputstream(",
            "req.getparametermap(",
            "req.getpart(",
            "req.getparts(",
            "multipartfile",
            ".getoriginalfilename(",
            ".getname(",
        )
        generic_source_markers = (
            "request.",
            "input(",
            "args",
            "form",
            "json",
            "$_get",
            "$_post",
            "$_request",
            "$_cookie",
            "$_server",
        )
        guard_markers = (
            "if ",
            "validate",
            "sanitize",
            "escape",
            "normalize",
            "len(",
            "length",
            "hash_equals",
            "preg_match",
            "startswith(",
            "endswith(",
        )
        source_hits: List[str] = [f"tainted_var:{name}" for name in sorted(tainted)]
        guard_hits: List[str] = []
        sink_hits: List[str] = []

        for line in lines:
            lowered_line = line.lower()
            if any(marker in lowered_line for marker in guard_markers):
                guard_hits.append(line.strip())

            assign = assign_pattern.match(line)
            if assign:
                lhs = assign.group(1).lower()
                rhs = assign.group(2).lower()
                if any(name in rhs for name in tainted):
                    tainted.add(lhs)
                    source_hits.append(f"tainted_var:{lhs}")
                elif lang == "java" and any(marker in rhs for marker in java_rhs_source_markers):
                    tainted.add(lhs)
                    source_hits.append(f"tainted_var:{lhs}")
                elif any(marker in rhs for marker in generic_source_markers):
                    tainted.add(lhs)
                    source_hits.append(f"tainted_var:{lhs}")

            if any(marker in lowered_line for marker in sink_markers):
                mentioned = [name for name in sorted(tainted) if re.search(rf"\b{re.escape(name)}\b", lowered_line)]
                if mentioned:
                    sink_hits.extend([f"tainted_sink:{name}" for name in mentioned])

        return {
            "source_hits": list(dict.fromkeys(source_hits)),
            "guard_hits": list(dict.fromkeys([item for item in guard_hits if item])),
            "sink_hits": list(dict.fromkeys(sink_hits)),
        }

    def _match_markers(markers: List[str]) -> List[str]:
        return [marker for marker in markers if marker and marker in lowered]

    def _source_hits_for_rule(
        *,
        explicit_sources: List[str],
        tainted_hits: List[str],
        rule_id: str,
    ) -> List[str]:
        hits = list(explicit_sources)
        for hit in tainted_hits:
            lowered_hit = str(hit).lower()
            if rule_id == "deserialization":
                if any(token in lowered_hit for token in ("inputstream", "stream", "request", "req", "obj", "ois")):
                    hits.append(hit)
            elif rule_id in {"ssrf", "java_service_bridge_ssrf"}:
                if any(token in lowered_hit for token in ("url", "uri", "address", "target", "host", "connection", "parameters", "urlrequest")):
                    hits.append(hit)
            elif rule_id == "path_traversal":
                if any(token in lowered_hit for token in ("path", "file", "filename", "name", "body")):
                    hits.append(hit)
            elif rule_id in {"cmdi", "java_service_bridge_cmdi"}:
                if any(token in lowered_hit for token in ("cmd", "command", "script", "action", "advancedscript")):
                    hits.append(hit)
            elif rule_id == "sqli":
                if any(token in lowered_hit for token in ("sql", "query")):
                    hits.append(hit)
            else:
                hits.append(hit)
        return list(dict.fromkeys(hits))

    def _bridge_sink_hits(rule_id: str) -> List[str]:
        bridge_map = {
            "java_service_bridge_cmdi": ["executeadvancedscript", "executeaction"],
            "java_service_bridge_ssrf": [
                "testconnection",
                "testhostconnectivity",
                "testtcpportconnectivity",
                "isurlreachable",
            ],
        }
        hits: List[str] = []
        for marker in bridge_map.get(rule_id, []):
            if marker in lowered:
                hits.append(f"bridge_call:{marker}")
        return hits

    lines = text.splitlines()
    symbol_signals = extract_symbol_context_signals(new_symbol_context, language=language)

    rule_specs = {
        "python": [
            {"rule_id": "cmdi", "vulnerability_type": "命令执行风险", "risk_level": "high", "score": 8.8, "sources": ["request.", "input(", "args", "form", "json"], "sinks": ["os.system(", "subprocess.", "eval(", "exec("]},
            {"rule_id": "sqli", "vulnerability_type": "SQL注入风险", "risk_level": "high", "score": 8.6, "sources": ["request.", "input(", "args", "form", "json", "sql"], "sinks": ["cursor.execute("]},
            {"rule_id": "path_traversal", "vulnerability_type": "路径穿越风险", "risk_level": "high", "score": 8.4, "sources": ["request.", "path", "filename", "file"], "sinks": ["open(", "send_file(", "pathlib.path("]},
            {"rule_id": "ssrf", "vulnerability_type": "SSRF风险", "risk_level": "high", "score": 8.2, "sources": ["request.", "url", "uri"], "sinks": ["requests.", "urllib.", "httpx.", "urlopen("]},
        ],
        "java": [
            {"rule_id": "deserialization", "vulnerability_type": "反序列化风险", "risk_level": "high", "score": 8.9, "sources": ["request.getinputstream", "inputstream"], "sinks": ["objectinputstream", "readobject("]},
            {"rule_id": "cmdi", "vulnerability_type": "命令执行风险", "risk_level": "high", "score": 8.8, "sources": ["request.get", "@requestparam", "@requestbody"], "sinks": ["runtime.getruntime().exec(", "processbuilder("]},
            {"rule_id": "path_traversal", "vulnerability_type": "路径穿越风险", "risk_level": "high", "score": 8.5, "sources": ["request.get", "@requestbody", "multipartfile", "path", "filename", "body"], "sinks": ["files.write", "files.read", "paths.get("]},
            {"rule_id": "ssrf", "vulnerability_type": "SSRF风险", "risk_level": "high", "score": 8.4, "sources": ["request.get", "@requestparam", "@requestbody", "url", "address"], "sinks": ["new url(", "openconnection()", "httpclient", "socket("]},
            {"rule_id": "java_service_bridge_cmdi", "vulnerability_type": "命令执行风险", "risk_level": "high", "score": 8.1, "sources": ["@requestparam", "@requestbody", "request.get"], "sinks": ["executeadvancedscript", "executeaction"]},
            {"rule_id": "java_service_bridge_ssrf", "vulnerability_type": "SSRF风险", "risk_level": "high", "score": 8.0, "sources": ["@requestparam", "@requestbody", "request.get"], "sinks": ["testconnection", "testhostconnectivity", "testtcpportconnectivity", "isurlreachable"]},
        ],
        "php": [
            {"rule_id": "cmdi", "vulnerability_type": "命令执行风险", "risk_level": "high", "score": 8.8, "sources": ["$_get", "$_post", "$_request", "$_cookie", "$_server"], "sinks": ["system(", "exec(", "shell_exec(", "passthru(", "eval("]},
            {"rule_id": "sqli", "vulnerability_type": "SQL注入风险", "risk_level": "high", "score": 8.5, "sources": ["$_get", "$_post", "$_request", "$_cookie", "$_server"], "sinks": ["mysqli_query(", "pdo->query(", "query("]},
        ],
    }
    lang = (language or "python").lower()
    rules = rule_specs.get(lang, rule_specs["python"])
    candidates: List[Dict[str, Any]] = []

    flow = _collect_tainted_flow(lines, lang, [sink for rule in rules for sink in rule["sinks"]])

    for rule in rules:
        explicit_sinks = _match_markers(rule["sinks"])
        explicit_sources = _match_markers(rule["sources"])
        bridge_hits = _bridge_sink_hits(str(rule["rule_id"]))
        sink_hits = list(explicit_sinks)
        sink_hits.extend(bridge_hits)
        if not sink_hits:
            continue

        source_hits = _source_hits_for_rule(
            explicit_sources=explicit_sources,
            tainted_hits=flow["source_hits"],
            rule_id=str(rule["rule_id"]),
        )
        if not source_hits or not sink_hits:
            continue

        guard_hits = list(flow["guard_hits"])
        guard_label = guard_hits[0] if guard_hits else "missing guard"
        enriched = {
            "rule_id": str(rule["rule_id"]),
            "vulnerability_type": str(rule["vulnerability_type"]),
            "risk_level": str(rule["risk_level"]),
            "score": round(min(10.0, float(rule["score"]) + float(symbol_signals.get("priority_boost", 0.0))), 2),
            "source_hits": list(dict.fromkeys(source_hits)),
            "guard_hits": guard_hits,
            "sink_hits": list(dict.fromkeys(sink_hits)),
            "context_hits": list(symbol_signals.get("context_hits", [])),
            "entrypoint_hits": list(symbol_signals.get("entrypoint_hits", [])),
            "condition_chain": " -> ".join(
                [
                    (source_hits[0] if source_hits else "source"),
                    f"guard:{guard_label}" if guard_hits else guard_label,
                    (sink_hits[0] if sink_hits else "sink"),
                ]
            ),
        }

        candidates.append(enriched)

    if not candidates:
        reasons = ["no obvious source+sink exploit chain detected in newly added code"]
        if symbol_signals["attack_surface_flags"]:
            reasons.append("symbol context looks entrypoint-adjacent, but source+sink evidence is still missing")
        return {
            "has_new_vulnerability": False,
            "risk_level": "low",
            "vulnerability_type": VULN_NONE,
            "source_hits": [],
            "guard_hits": [],
            "sink_hits": [],
            "context_hits": list(symbol_signals["context_hits"]),
            "entrypoint_hits": list(symbol_signals["entrypoint_hits"]),
            "condition_chain": "",
            "score": 1.0,
            "rule_id": "",
            "candidates": [],
            "reasons": reasons,
        }

    candidates.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
    top = candidates[0]
    return {
        "has_new_vulnerability": True,
        "risk_level": str(top["risk_level"]),
        "vulnerability_type": str(top["vulnerability_type"]),
        "source_hits": list(top["source_hits"]),
        "guard_hits": list(top.get("guard_hits", [])),
        "sink_hits": list(top["sink_hits"]),
        "context_hits": list(top.get("context_hits", [])),
        "entrypoint_hits": list(top.get("entrypoint_hits", [])),
        "score": normalize_score(top.get("score", 8.0), 8.0),
        "rule_id": str(top.get("rule_id", "")),
        "condition_chain": str(top.get("condition_chain", "")),
        "candidates": candidates[:5],
        "reasons": [
            f"new code matches vulnerability rule={top.get('rule_id', '')}",
            "new code contains both user-controlled sources and dangerous sinks",
            "guard-like signals detected; review exploitability carefully" if top.get("guard_hits") else "no clear protective guard detected",
            "symbol context increases review priority for this risky path" if top.get("context_hits") or top.get("entrypoint_hits") else "symbol context does not add extra priority",
        ],
    }


def review_new_vulnerability_with_llm(
    analyzer: SourceAnalyzer,
    unit: Dict[str, Any],
    part2: Dict[str, Any],
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Dict[str, Any]:
    reviewed = dict(part2)
    reviewed["llm_review_invoked"] = False
    reviewed["llm_confirmed"] = False
    reviewed["llm_review_confidence"] = 0.0
    reviewed["llm_review_required"] = False

    if not bool(part2.get("has_new_vulnerability", False)):
        return reviewed
    if not bool(getattr(analyzer.llm, "enabled", False)):
        return reviewed

    profile_name = normalize_analysis_profile(analysis_profile)
    reviewed["llm_review_invoked"] = True
    row = analyzer.analyze_function_pair(
        old_unit=unit.get("old_unit"),
        new_unit=unit.get("new_unit"),
        old_code=unit.get("old_code", ""),
        new_code=unit.get("new_code", ""),
        similarity=unit.get("similarity", 0.0),
        scenario="new_code",
        language=str(unit.get("language", "python")),
        artifact=str(unit.get("new_unit") or unit.get("old_unit") or unit.get("file_path") or ""),
        old_symbol_context=unit.get("old_symbol_context"),
        new_symbol_context=unit.get("new_symbol_context"),
        analysis_profile=profile_name,
    )
    normalized = SourceAnalyzer._normalize_schema(row)
    reviewed["llm_review_confidence"] = float(row.get("confidence", normalized.get("confidence", 0.0)) or 0.0)
    reviewed["llm_review_required"] = bool(row.get("review_required", normalized.get("review_required", False)))
    if isinstance(row.get("review_notes"), list):
        reviewed["llm_review_notes"] = [str(x) for x in row.get("review_notes", [])][:10]

    if str(normalized.get("change_type", "")).strip() in {CHANGE_SECURITY_FIX, CHANGE_REMOVED}:
        return reviewed

    s2s = normalize_s2s(normalized.get("source_to_sink_conditions", {}))
    top_type = str(normalized.get("vulnerability_type", VULN_PENDING)).strip() or VULN_PENDING
    top_score = normalize_score(normalized.get("vulnerability_score", 0.0), 0.0)
    findings = normalized.get("vulnerability_findings", [])

    llm_candidates: List[Dict[str, Any]] = []
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            evidence = str(finding.get("evidence", "")).strip()
            vuln_type = str(finding.get("type", top_type)).strip() or top_type
            score = normalize_score(finding.get("score", top_score), top_score)
            if vuln_type in {VULN_NONE, VULN_PENDING} or score < 5.0 or not evidence:
                continue
            llm_candidates.append(
                {
                    "rule_id": "llm_review",
                    "vulnerability_type": vuln_type,
                    "score": score,
                    "source_hits": list(s2s.get("sources", [])),
                    "guard_hits": list(s2s.get("guards", [])),
                    "sink_hits": list(s2s.get("sinks", [])),
                    "condition_chain": str(s2s.get("condition_chain", "")),
                    "evidence": evidence,
                }
            )

    if not llm_candidates and top_type not in {VULN_NONE, VULN_PENDING} and top_score >= 5.0:
        llm_candidates.append(
            {
                "rule_id": "llm_review",
                "vulnerability_type": top_type,
                "score": top_score,
                "source_hits": list(s2s.get("sources", [])),
                "guard_hits": list(s2s.get("guards", [])),
                "sink_hits": list(s2s.get("sinks", [])),
                "condition_chain": str(s2s.get("condition_chain", "")),
                "evidence": "LLM top-level assessment for risky added code.",
            }
        )

    if not llm_candidates:
        return reviewed

    candidates = list(part2.get("candidates", [])) if isinstance(part2.get("candidates"), list) else []
    candidates.extend(llm_candidates)
    candidates = dedupe_candidates(candidates)
    if not candidates:
        return reviewed

    top = candidates[0]
    reviewed["candidates"] = candidates
    reviewed["vulnerability_type"] = str(top.get("vulnerability_type", reviewed.get("vulnerability_type", VULN_PENDING)))
    reviewed["score"] = normalize_score(top.get("score", reviewed.get("score", 0.0)), reviewed.get("score", 0.0))
    reviewed["source_hits"] = to_str_list(top.get("source_hits"))
    reviewed["guard_hits"] = to_str_list(top.get("guard_hits"))
    reviewed["sink_hits"] = to_str_list(top.get("sink_hits"))
    reviewed["condition_chain"] = str(top.get("condition_chain", "")).strip()
    reviewed["llm_confirmed"] = True
    return reviewed


def merge_new_vulnerability(base_result: Dict[str, Any], part2: Dict[str, Any], raw_change_type: str) -> Dict[str, Any]:
    if not part2.get("has_new_vulnerability", False):
        return base_result

    merged = dict(base_result)
    merged["analysis_score"] = round(normalize_score(merged.get("analysis_score", merged.get("vulnerability_score", 0.0)), 0.0), 2)
    merged["primary_score"] = round(normalize_score(merged.get("primary_score", merged.get("analysis_score", merged.get("vulnerability_score", 0.0))), 0.0), 2)
    base_evidence = merged.get("evidence", {}) if isinstance(merged.get("evidence"), dict) else {}
    ranked_candidates = list(base_evidence.get("ranked_candidates", [])) if isinstance(base_evidence.get("ranked_candidates"), list) else []
    candidates = part2.get("candidates", [])
    if not isinstance(candidates, list) or not candidates:
        candidates = [
            {
                "rule_id": str(part2.get("rule_id", "")),
                "vulnerability_type": str(part2.get("vulnerability_type", VULN_PENDING)),
                "score": normalize_score(part2.get("score", 8.0), 8.0),
                "source_hits": list(part2.get("source_hits", [])),
                "guard_hits": list(part2.get("guard_hits", [])),
                "sink_hits": list(part2.get("sink_hits", [])),
                "condition_chain": str(part2.get("condition_chain", "")),
            }
        ]

    findings: List[Dict[str, Any]] = []
    for cand in candidates[:3]:
        evidence = str(cand.get("evidence", "")).strip()
        if not evidence:
            evidence = f"rule={cand.get('rule_id', '')}; new source hits={cand.get('source_hits', [])}, sink hits={cand.get('sink_hits', [])}"
        findings.append(
            {
                "type": str(cand.get("vulnerability_type", VULN_PENDING)),
                "score": normalize_score(cand.get("score", 8.0), 8.0),
                "evidence": evidence,
            }
        )
        ranked_candidates.append(
            build_ranked_candidate(
                vulnerability_type=cand.get("vulnerability_type", VULN_PENDING),
                score=cand.get("score", 8.0),
                evidence=evidence,
                supporting_source_to_sink={
                    "sources": cand.get("source_hits", []),
                    "guards": cand.get("guard_hits", []),
                    "sinks": cand.get("sink_hits", []),
                    "condition_chain": cand.get("condition_chain", ""),
                },
                support_status="inferred",
                support_inference_level="primary",
                extra={"rule_id": str(cand.get("rule_id", ""))},
            )
        )

    findings = dedupe_findings(findings)
    findings.sort(key=lambda x: normalize_score(x.get("score", 0.0), 0.0), reverse=True)
    findings = findings[:5]
    ranked_candidates = dedupe_candidates(ranked_candidates)

    primary = findings[0]
    merged["vulnerability_type"] = str(primary.get("type", VULN_PENDING))
    merged["vulnerability_score"] = round(normalize_score(primary.get("score", part2.get("score", 8.0)), part2.get("score", 8.0)), 2)
    merged["security_score"] = merged["vulnerability_score"]
    merged["analysis_score"] = max(
        merged.get("analysis_score", 0.0),
        merged["vulnerability_score"],
        normalize_score(part2.get("score", 0.0), 0.0),
    )
    merged["primary_score"] = max(merged.get("primary_score", 0.0), merged["analysis_score"])
    observed_s2s = normalize_s2s(
        ((base_evidence.get("observed_facts", {}) or {}).get("source_to_sink", DEFAULT_S2S))
    )
    inferred_s2s = normalize_s2s(
        ((base_evidence.get("inferred_assessment", {}) or {}).get("source_to_sink", DEFAULT_S2S))
    )
    if primary.get("type") == part2.get("vulnerability_type"):
        guards = list(part2.get("guard_hits", []))
        chain = str(part2.get("condition_chain", "")).strip()
        inferred_s2s = {
            "sources": list(part2.get("source_hits", [])),
            "guards": guards,
            "sinks": list(part2.get("sink_hits", [])),
            "condition_chain": chain or "new code input source -> missing/insufficient guard -> newly introduced dangerous sink",
        }
        if raw_change_type == "added":
            merged["change_type"] = CHANGE_NEW_CODE
    merged["evidence"] = {
        "observed_facts": {"source_to_sink": observed_s2s},
        "inferred_assessment": {
            "source_to_sink": inferred_s2s,
            "summary": str(primary.get("evidence", "") or ""),
            "confidence": 0.0,
            "reasoning_basis": "static",
        },
        "ranked_candidates": ranked_candidates,
        "convenience_summary": {},
    }
    return merged
