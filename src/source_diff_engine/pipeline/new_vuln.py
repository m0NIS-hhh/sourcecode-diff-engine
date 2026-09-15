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
        "filter",
        "uid",
        "name",
        "module",
        "classname",
        "class",
        "plugin",
        "template",
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
            "filter",
            "uid",
            "name",
            "module",
            "class",
            "plugin",
            "template",
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
            "$_files",
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
            elif rule_id == "template_injection":
                if any(token in lowered_hit for token in ("template", "tpl", "view", "body", "html")):
                    hits.append(hit)
            elif rule_id == "nosql_injection":
                if any(token in lowered_hit for token in ("query", "filter", "json", "body", "name", "user")):
                    hits.append(hit)
            elif rule_id == "ldap_injection":
                if any(token in lowered_hit for token in ("filter", "uid", "user", "name", "query")):
                    hits.append(hit)
            elif rule_id == "xpath_injection":
                if any(token in lowered_hit for token in ("xpath", "query", "name", "user", "filter")):
                    hits.append(hit)
            elif rule_id == "dynamic_loading":
                if any(token in lowered_hit for token in ("module", "class", "plugin", "name", "target")):
                    hits.append(hit)
            elif rule_id == "file_upload":
                if any(token in lowered_hit for token in ("file", "upload", "filename", "name", "tmp")):
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

    def _has_python_safe_subprocess_call() -> bool:
        if lang != "python" or "subprocess." not in lowered:
            return False
        dangerous_non_subprocess = any(marker in lowered for marker in ("os.system(", "eval(", "exec("))
        if dangerous_non_subprocess or "shell=true" in lowered.replace(" ", ""):
            return False
        compact = re.sub(r"\s+", "", lowered)
        if "shell=false" in compact:
            return True
        return bool(re.search(r"subprocess\.(?:run|call|popen|check_call|check_output)\s*\(\s*\[", lowered, flags=re.S))

    def _has_parameterized_sql_call(rule_id: str) -> bool:
        if rule_id != "sqli":
            return False
        if lang == "python":
            for line in lines:
                line_l = line.lower()
                if "cursor.execute(" not in line_l:
                    continue
                if re.search(r"cursor\.execute\s*\(\s*(?:[rubf]*[\"'][^\"']*[\"'])\s*,", line_l):
                    return True
            return False
        if lang == "php":
            return "mysqli_real_escape_string(" in lowered or ("->prepare(" in lowered and "->execute(" in lowered)
        return False

    def _has_path_containment_guard(rule_id: str) -> bool:
        if rule_id != "path_traversal":
            return False
        if lang == "python":
            compact = re.sub(r"\s+", "", lowered)
            return (".resolve()" in compact and (".startswith(" in compact or ".relative_to(" in compact)) or (
                "os.path.abspath(" in compact and "os.path.commonpath(" in compact
            )
        if lang == "java":
            compact = re.sub(r"\s+", "", lowered)
            return (".normalize()" in compact or ".torealpath(" in compact) and (".startswith(" in compact or ".relativize(" in compact)
        return False

    def _has_authorized_java_bridge_guard(rule_id: str) -> bool:
        if lang != "java" or rule_id not in {"java_service_bridge_cmdi", "java_service_bridge_ssrf"}:
            return False
        return any(marker in lowered for marker in ("@preauthorize", "@postauthorize", "@secured", "@rolesallowed"))

    def _has_safe_deserialization_call(rule_id: str) -> bool:
        if rule_id != "deserialization" or lang != "python":
            return False
        compact = re.sub(r"\s+", "", lowered)
        return "yaml.safe_load(" in compact or ("yaml.load(" in compact and "safeloader" in compact)

    def _is_rule_suppressed_by_safe_pattern(rule_id: str) -> bool:
        if rule_id == "cmdi" and _has_python_safe_subprocess_call():
            return True
        if _has_parameterized_sql_call(rule_id):
            return True
        if _has_path_containment_guard(rule_id):
            return True
        if _has_authorized_java_bridge_guard(rule_id):
            return True
        if _has_safe_deserialization_call(rule_id):
            return True
        return False

    lines = text.splitlines()
    symbol_signals = extract_symbol_context_signals(new_symbol_context, language=language)

    rule_specs = {
        "python": [
            {"rule_id": "cmdi", "vulnerability_type": "命令执行风险", "risk_level": "high", "score": 8.8, "sources": ["request.", "input(", "args", "form", "json"], "sinks": ["os.system(", "subprocess.", "eval(", "exec("]},
            {"rule_id": "deserialization", "vulnerability_type": "反序列化风险", "risk_level": "high", "score": 8.7, "sources": ["request.", "input(", "args", "form", "json", "data"], "sinks": ["pickle.loads(", "pickle.load(", "yaml.load("]},
            {"rule_id": "sqli", "vulnerability_type": "SQL注入风险", "risk_level": "high", "score": 8.6, "sources": ["request.", "input(", "args", "form", "json", "sql"], "sinks": ["cursor.execute("]},
            {"rule_id": "path_traversal", "vulnerability_type": "路径穿越风险", "risk_level": "high", "score": 8.4, "sources": ["request.", "path", "filename", "file"], "sinks": ["open(", "send_file(", "pathlib.path("]},
            {"rule_id": "ssrf", "vulnerability_type": "SSRF风险", "risk_level": "high", "score": 8.2, "sources": ["request.", "url", "uri"], "sinks": ["requests.", "urllib.", "httpx.", "urlopen("]},
            {"rule_id": "template_injection", "vulnerability_type": "模板注入风险", "risk_level": "high", "score": 8.3, "sources": ["request.", "input(", "args", "form", "json", "template", "tpl"], "sinks": ["render_template_string(", "jinja2.template(", ".from_string("]},
            {"rule_id": "nosql_injection", "vulnerability_type": "NoSQL注入风险", "risk_level": "high", "score": 8.2, "sources": ["request.", "input(", "args", "form", "json", "query", "filter"], "sinks": [".find_one(", ".find(", ".aggregate(", "collection.find", "mongo.db"]},
            {"rule_id": "dynamic_loading", "vulnerability_type": "动态加载风险", "risk_level": "high", "score": 8.0, "sources": ["request.", "input(", "args", "form", "json", "module", "class", "plugin"], "sinks": ["importlib.import_module(", "__import__(", "pkg_resources.load_entry_point("]},
        ],
        "java": [
            {"rule_id": "deserialization", "vulnerability_type": "反序列化风险", "risk_level": "high", "score": 8.9, "sources": ["request.getinputstream", "inputstream"], "sinks": ["objectinputstream", "readobject("]},
            {"rule_id": "cmdi", "vulnerability_type": "命令执行风险", "risk_level": "high", "score": 8.8, "sources": ["request.get", "@requestparam", "@requestbody"], "sinks": ["runtime.getruntime().exec(", "processbuilder("]},
            {"rule_id": "path_traversal", "vulnerability_type": "路径穿越风险", "risk_level": "high", "score": 8.5, "sources": ["request.get", "@requestbody", "multipartfile", "path", "filename", "body"], "sinks": ["files.write", "files.read", "paths.get("]},
            {"rule_id": "ssrf", "vulnerability_type": "SSRF风险", "risk_level": "high", "score": 8.4, "sources": ["request.get", "@requestparam", "@requestbody", "url", "address"], "sinks": ["new url(", "openconnection()", "httpclient", "socket("]},
            {"rule_id": "java_service_bridge_cmdi", "vulnerability_type": "命令执行风险", "risk_level": "high", "score": 8.1, "sources": ["@requestparam", "@requestbody", "request.get"], "sinks": ["executeadvancedscript", "executeaction"]},
            {"rule_id": "java_service_bridge_ssrf", "vulnerability_type": "SSRF风险", "risk_level": "high", "score": 8.0, "sources": ["@requestparam", "@requestbody", "request.get"], "sinks": ["testconnection", "testhostconnectivity", "testtcpportconnectivity", "isurlreachable"]},
            {"rule_id": "ldap_injection", "vulnerability_type": "LDAP注入风险", "risk_level": "high", "score": 8.3, "sources": ["request.get", "@requestparam", "@requestbody", "filter", "uid", "name"], "sinks": ["ldaptemplate.search", "dircontext.search", "ctx.search("]},
            {"rule_id": "xpath_injection", "vulnerability_type": "XPath注入风险", "risk_level": "high", "score": 8.2, "sources": ["request.get", "@requestparam", "@requestbody", "xpath", "name"], "sinks": ["xpath.evaluate(", "xpathexpression.evaluate(", "xpath.compile("]},
            {"rule_id": "dynamic_loading", "vulnerability_type": "动态加载风险", "risk_level": "high", "score": 8.1, "sources": ["request.get", "@requestparam", "@requestbody", "class", "classname", "module", "plugin"], "sinks": ["class.forname(", "classloader.loadclass(", "method.invoke("]},
        ],
        "php": [
            {"rule_id": "cmdi", "vulnerability_type": "命令执行风险", "risk_level": "high", "score": 8.8, "sources": ["$_get", "$_post", "$_request", "$_cookie", "$_server"], "sinks": ["system(", "exec(", "shell_exec(", "passthru(", "eval("]},
            {"rule_id": "sqli", "vulnerability_type": "SQL注入风险", "risk_level": "high", "score": 8.5, "sources": ["$_get", "$_post", "$_request", "$_cookie", "$_server"], "sinks": ["mysqli_query(", "pdo->query(", "query("]},
            {"rule_id": "path_traversal", "vulnerability_type": "路径穿越风险", "risk_level": "high", "score": 8.4, "sources": ["$_get", "$_post", "$_request", "$_cookie", "$_server", "path", "file", "filename"], "sinks": ["file_get_contents(", "file_put_contents(", "fopen(", "readfile(", "unlink("]},
            {"rule_id": "file_upload", "vulnerability_type": "文件上传风险", "risk_level": "high", "score": 8.3, "sources": ["$_files", "$_post", "$_request", "upload", "filename", "file"], "sinks": ["move_uploaded_file(", "copy(", "rename("]},
        ],
    }
    lang = (language or "python").lower()
    rules = rule_specs.get(lang, rule_specs["python"])
    candidates: List[Dict[str, Any]] = []

    flow = _collect_tainted_flow(lines, lang, [sink for rule in rules for sink in rule["sinks"]])

    for rule in rules:
        if _is_rule_suppressed_by_safe_pattern(str(rule["rule_id"])):
            continue

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
        # Marker co-occurrence is not a data-flow edge. Require a tainted sink
        # hit, or a source and sink marker on the same line, before creating a
        # candidate.
        rule_sink_markers = [str(marker).lower() for marker in rule["sinks"]]
        has_reachable_sink = bool(flow["sink_hits"]) or any(
            any(marker in line.lower() for marker in rule_sink_markers)
            and any(source in line.lower() for source in rule["sources"])
            for line in lines
        )
        if not has_reachable_sink:
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

    # Keep the static rule result available after LLM candidates are merged or reordered.
    reviewed["static_source_hits"] = list(part2.get("source_hits", []))
    reviewed["static_guard_hits"] = list(part2.get("guard_hits", []))
    reviewed["static_sink_hits"] = list(part2.get("sink_hits", []))
    reviewed["static_condition_chain"] = str(part2.get("condition_chain", "") or "")

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
        candidate_status = "inferred" if str(cand.get("rule_id", "")).strip() == "llm_review" else (
            "observed"
            if all(
                [
                    cand.get("source_hits"),
                    cand.get("guard_hits"),
                    cand.get("sink_hits"),
                    str(cand.get("condition_chain", "")).strip(),
                ]
            )
            else "partial"
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
                support_status=candidate_status,
                support_inference_level="primary" if candidate_status == "inferred" else "none",
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
    static_s2s = normalize_s2s(
        {
            "sources": part2.get("static_source_hits", part2.get("source_hits", [])),
            "guards": part2.get("static_guard_hits", part2.get("guard_hits", [])),
            "sinks": part2.get("static_sink_hits", part2.get("sink_hits", [])),
            "condition_chain": part2.get("static_condition_chain", part2.get("condition_chain", "")),
        }
    )
    if primary.get("type") == part2.get("vulnerability_type"):
        if bool(part2.get("llm_confirmed", False)):
            inferred_s2s = normalize_s2s(
                {
                    "sources": part2.get("source_hits", []),
                    "guards": part2.get("guard_hits", []),
                    "sinks": part2.get("sink_hits", []),
                    "condition_chain": part2.get("condition_chain", ""),
                }
            )
        if raw_change_type == "added":
            merged["change_type"] = CHANGE_NEW_CODE
    merged["evidence"] = {
        "observed_facts": {
            "source_to_sink": static_s2s if part2.get("has_new_vulnerability") else observed_s2s,
            "evidence_origin": "static_analysis",
        },
        "inferred_assessment": {
            "source_to_sink": inferred_s2s,
            "summary": str(primary.get("evidence", "") or ""),
            "confidence": 0.0,
            "reasoning_basis": "static",
            "evidence_origin": "llm_inference" if bool(part2.get("llm_confirmed", False)) else "static_analysis",
        },
        "ranked_candidates": ranked_candidates,
        "convenience_summary": {},
    }
    return merged
