from __future__ import annotations

from source_diff_engine.analysis.pipeline import assess_added_risk


def test_static_rules_classify_command_exec_risk() -> None:
    code = "cmd = request.args.get('cmd')\nos.system(cmd)"
    risk = assess_added_risk(code)
    assert risk["has_new_vulnerability"] is True
    assert risk["risk_level"] == "high"
    assert risk["rule_id"] == "cmdi"


def test_static_rules_detect_java_exec_risk() -> None:
    code = 'String cmd = request.getParameter("cmd");\nRuntime.getRuntime().exec(cmd);'
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["risk_level"] == "high"
    assert len(risk["source_hits"]) > 0
    assert len(risk["sink_hits"]) > 0


def test_static_rules_detect_php_exec_risk() -> None:
    code = '$cmd = $_GET["cmd"];\nsystem($cmd);'
    risk = assess_added_risk(code, language="php")
    assert risk["has_new_vulnerability"] is True
    assert risk["risk_level"] == "high"
    assert len(risk["source_hits"]) > 0
    assert len(risk["sink_hits"]) > 0


def test_static_rules_detect_python_deserialization_risk() -> None:
    code = "payload = request.get_data()\nobj = pickle.loads(payload)"
    risk = assess_added_risk(code, language="python")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "deserialization"


def test_static_rules_suppress_python_safe_yaml_load() -> None:
    code = "payload = request.get_data()\nobj = yaml.safe_load(payload)"
    risk = assess_added_risk(code, language="python")
    assert risk["has_new_vulnerability"] is False


def test_static_rules_keep_multiple_candidates_for_new_vuln() -> None:
    code = (
        "cmd = request.args.get('cmd')\n"
        "sql = request.args.get('sql')\n"
        "os.system(cmd)\n"
        "cursor.execute(sql)\n"
    )
    risk = assess_added_risk(code, language="python")
    assert risk["has_new_vulnerability"] is True
    assert isinstance(risk.get("candidates"), list)
    assert len(risk["candidates"]) >= 2


def test_static_rules_detect_java_deserialization_risk() -> None:
    code = (
        "ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\n"
        "Object obj = ois.readObject();\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["risk_level"] == "high"
    assert risk["rule_id"] == "deserialization"


def test_static_rules_detect_java_ssrf_risk() -> None:
    code = (
        'String target = request.getParameter("url");\n'
        "URL u = new URL(target);\n"
        "URLConnection c = u.openConnection();\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["risk_level"] == "high"
    assert risk["rule_id"] == "ssrf"


def test_static_rules_detect_java_request_param_command_exec_risk() -> None:
    code = (
        '@PostMapping("/run")\n'
        'public void run(@RequestParam("cmd") String cmd) {\n'
        "    Runtime.getRuntime().exec(cmd);\n"
        "}\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "cmdi"
    assert any("@requestparam" in str(hit).lower() or "tainted_var:cmd" in str(hit).lower() for hit in risk["source_hits"])


def test_static_rules_detect_java_request_body_path_traversal_risk() -> None:
    code = (
        '@PostMapping("/upload")\n'
        "public void save(@RequestBody String body) throws Exception {\n"
        "    Files.write(Paths.get(body), body.getBytes());\n"
        "}\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "path_traversal"
    assert any("body" in str(hit).lower() for hit in risk["source_hits"])


def test_static_rules_detect_java_multipart_filename_path_traversal_risk() -> None:
    code = (
        '@PostMapping("/upload")\n'
        'public void upload(@RequestParam("file") MultipartFile file) throws Exception {\n'
        "    String name = file.getOriginalFilename();\n"
        "    Files.write(Paths.get(name), file.getBytes());\n"
        "}\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "path_traversal"
    assert any("filename" in str(hit).lower() or "tainted_var:name" in str(hit).lower() or "tainted_var:file" in str(hit).lower() for hit in risk["source_hits"])


def test_static_rules_detect_java_service_bridge_execution_risk() -> None:
    code = (
        '@PostMapping("/execute")\n'
        "public ResponseEntity<?> executeAdvancedScript(@RequestBody String advancedScriptJson) {\n"
        "    AdvancedScriptDto advancedScriptToExecute = new AdvancedScriptDto(advancedScriptJson);\n"
        "    return ResponseEntity.ok(this.advancedScriptService.executeAdvancedScript(sessionId, advancedScriptToExecute));\n"
        "}\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "java_service_bridge_cmdi"
    assert any("bridge_call:executeadvancedscript" in str(hit).lower() for hit in risk["sink_hits"])


def test_static_rules_detect_java_server_control_execute_action_risk() -> None:
    code = (
        '@PostMapping\n'
        'public ResponseEntity<Void> executeAction(HttpSession session, @RequestParam(value="action") String action) throws IOException {\n'
        "    this.nacServerControlService.executeAction(sessionId, action);\n"
        "    return ResponseEntity.ok().build();\n"
        "}\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "java_service_bridge_cmdi"
    assert any("tainted_var:action" in str(hit).lower() for hit in risk["source_hits"])
    assert any("bridge_call:executeaction" in str(hit).lower() for hit in risk["sink_hits"])


def test_static_rules_detect_java_service_bridge_ssrf_risk() -> None:
    code = (
        '@PutMapping("/connection-test")\n'
        "public ResponseEntity<Boolean> testConnection(HttpSession session, @RequestBody DataExportConnectionTestDto connectionData) {\n"
        "    return ResponseEntity.ok(this.dataExportService.testConnection(sessionId, connectionData));\n"
        "}\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "java_service_bridge_ssrf"
    assert str(risk["vulnerability_type"]).startswith("SSRF")
    assert any("bridge_call:testconnection" in str(hit).lower() for hit in risk["sink_hits"])


def test_static_rules_detect_java_service_bridge_host_connectivity_risk() -> None:
    code = (
        '@PostMapping("/host-connectivity")\n'
        'public ResponseEntity<String> testHostConnectivity(HttpSession session, @RequestParam(value="address") String address) throws RemoteException {\n'
        "    return ResponseEntity.ok((Object)this.nacTestToolService.testHostConnectivity(address));\n"
        "}\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "java_service_bridge_ssrf"
    assert any("tainted_var:address" in str(hit).lower() for hit in risk["source_hits"])
    assert any("bridge_call:testhostconnectivity" in str(hit).lower() for hit in risk["sink_hits"])


def test_static_rules_detect_java_service_bridge_tcp_connectivity_risk() -> None:
    code = (
        '@PostMapping(value={"/tcp-port-connectivity"}, consumes={"application/json"})\n'
        "public ResponseEntity<String> testTcpPortConnectivity(HttpSession session, @Validated @RequestBody TcpPortConnectivityParametersDto parameters) throws RemoteException {\n"
        "    return ResponseEntity.ok((Object)this.nacTestToolService.testTcpPortConnectivity(parameters));\n"
        "}\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "java_service_bridge_ssrf"
    assert any("tainted_var:parameters" in str(hit).lower() for hit in risk["source_hits"])
    assert any("bridge_call:testtcpportconnectivity" in str(hit).lower() for hit in risk["sink_hits"])


def test_static_rules_detect_java_service_bridge_url_reachability_risk() -> None:
    code = (
        '@GetMapping(value={"/TestUrl"}, produces={"application/json"})\n'
        "public ResponseEntity<Boolean> testUrl(@RequestBody TestUrlRequest urlRequest, HttpSession session) throws RemoteException {\n"
        "    boolean reachable = this.lwtService.isUrlReachable(urlRequest.getUrl(), customerId, dbContext);\n"
        "    return ResponseEntity.ok((Object)reachable);\n"
        "}\n"
    )
    risk = assess_added_risk(code, language="java")
    assert risk["has_new_vulnerability"] is True
    assert risk["rule_id"] == "java_service_bridge_ssrf"
    assert any("tainted_var:urlrequest" in str(hit).lower() for hit in risk["source_hits"])
    assert any("bridge_call:isurlreachable" in str(hit).lower() for hit in risk["sink_hits"])


def test_static_rules_capture_guard_signals_for_review() -> None:
    code = (
        "import re\n"
        "def run(cmd):\n"
        "    if not re.fullmatch(r'[A-Za-z0-9_]+', cmd):\n"
        "        raise ValueError('bad')\n"
        "    os.system(cmd)\n"
    )
    risk = assess_added_risk(code, language="python")
    assert risk["has_new_vulnerability"] is True
    assert len(risk.get("guard_hits", [])) >= 1
    assert "guard" in str(risk.get("condition_chain", "")).lower()


def test_static_rules_symbol_context_only_adjusts_priority() -> None:
    code = "cmd = request.args.get('cmd')\nos.system(cmd)"
    plain = assess_added_risk(code, language="python")
    contextual = assess_added_risk(
        code,
        language="python",
        new_symbol_context={
            "language": "python",
            "display": "ApiController.run",
            "symbols": [
                {"kind": "class", "name": "ApiController", "signature": "class ApiController", "line_range": [1, 20]},
                {"kind": "function", "name": "run", "signature": "def run(cmd):", "line_range": [5, 8]},
            ],
            "innermost_symbol": {"kind": "function", "name": "run", "signature": "def run(cmd):", "line_range": [5, 8]},
        },
    )
    assert plain["has_new_vulnerability"] is True
    assert contextual["has_new_vulnerability"] is True
    assert float(contextual["score"]) > float(plain["score"])
    assert "symbol_name:run" in contextual.get("entrypoint_hits", [])
    assert "symbol_role:controller" in contextual.get("context_hits", [])


def test_static_rules_symbol_context_does_not_replace_source_sink_evidence() -> None:
    risk = assess_added_risk(
        "def run(value):\n    return value\n",
        language="python",
        new_symbol_context={
            "language": "python",
            "display": "ApiController.run",
            "symbols": [
                {"kind": "class", "name": "ApiController", "signature": "class ApiController", "line_range": [1, 20]},
                {"kind": "function", "name": "run", "signature": "def run(value):", "line_range": [5, 6]},
            ],
            "innermost_symbol": {"kind": "function", "name": "run", "signature": "def run(value):", "line_range": [5, 6]},
        },
    )
    assert risk["has_new_vulnerability"] is False
    assert "symbol_name:run" in risk.get("entrypoint_hits", [])
    assert "missing" in " ".join(str(item) for item in risk.get("reasons", [])).lower()


def test_static_rules_do_not_join_unrelated_source_and_sink_markers() -> None:
    risk = assess_added_risk(
        "def log_request(request):\n"
        "    audit = request.args.get('audit')\n"
        "    command = 'fixed-command'\n"
        "    os.system(command)\n",
        language="python",
    )
    assert risk["has_new_vulnerability"] is False
    assert risk["candidates"] == []
    assert "source+sink" in " ".join(risk["reasons"])
