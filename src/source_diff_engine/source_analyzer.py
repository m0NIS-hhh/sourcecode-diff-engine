from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from source_diff_engine.analysis.profiles import DEFAULT_ANALYSIS_PROFILE, normalize_analysis_profile
from source_diff_engine.analysis.tools import build_local_context
from source_diff_engine.llm.client import OpenCodeLLM
from source_diff_engine.logger_config import get_logger
from source_diff_engine.llm.prompt_builder import PromptBuilder

logger = get_logger(__name__)


class SourceAnalyzer:
    CHANGE_SECURITY_FIX = "\u6f0f\u6d1e\u4fee\u590d"
    CHANGE_NON_SECURITY = "\u975e\u5b89\u5168\u6027\u4fee\u6539"
    CHANGE_NEW_CODE = "\u65b0\u589e\u4ee3\u7801"
    CHANGE_REMOVED = "\u5220\u9664\u4ee3\u7801"

    VULN_NONE = "\u65e0\u65b0\u589e\u6f0f\u6d1e"
    VULN_PENDING = "\u5f85\u4eba\u5de5\u590d\u6838"
    VULN_HARDENING = "\u5b89\u5168\u52a0\u56fa"

    CANONICAL_CHANGE_TYPES = {
        CHANGE_SECURITY_FIX,
        CHANGE_NON_SECURITY,
        CHANGE_NEW_CODE,
        CHANGE_REMOVED,
    }
    SCENARIO_PROMPT_MAP = {
        "security_fix": "security_review_fix",
        "new_code": "security_review_new_code",
        "hardening": "security_review_hardening",
    }
    LLM_CHANGE_TYPE_VALUES = {
        "security fix",
        "non_security",
        "new code",
        "removed",
        "unknown",
    }
    LLM_VULNERABILITY_TYPE_VALUES = {
        "command execution",
        "sql injection",
        "path traversal",
        "deserialization",
        "credential leak",
        "xss",
        "code injection",
        "security hardening",
        "ssrf",
        "unsafe reflection",
        "file upload",
        "none",
        "unknown",
    }
    CHANGE_TYPE_MAP = {
        "security fix": CHANGE_SECURITY_FIX,
        CHANGE_SECURITY_FIX: CHANGE_SECURITY_FIX,
        "non_security": CHANGE_NON_SECURITY,
        CHANGE_NON_SECURITY: CHANGE_NON_SECURITY,
        "new code": CHANGE_NEW_CODE,
        CHANGE_NEW_CODE: CHANGE_NEW_CODE,
        "removed": CHANGE_REMOVED,
        CHANGE_REMOVED: CHANGE_REMOVED,
        "unknown": CHANGE_NON_SECURITY,
    }
    VULNERABILITY_TYPE_MAP = {
        "command execution": "\u547d\u4ee4\u6267\u884c\u98ce\u9669",
        "\u547d\u4ee4\u6267\u884c\u98ce\u9669": "\u547d\u4ee4\u6267\u884c\u98ce\u9669",
        "code injection": "\u4ee3\u7801\u6ce8\u5165\u98ce\u9669",
        "\u4ee3\u7801\u6ce8\u5165\u98ce\u9669": "\u4ee3\u7801\u6ce8\u5165\u98ce\u9669",
        "sql injection": "SQL\u6ce8\u5165\u98ce\u9669",
        "sql\u6ce8\u5165\u98ce\u9669": "SQL\u6ce8\u5165\u98ce\u9669",
        "deserialization": "\u53cd\u5e8f\u5217\u5316\u98ce\u9669",
        "\u53cd\u5e8f\u5217\u5316\u98ce\u9669": "\u53cd\u5e8f\u5217\u5316\u98ce\u9669",
        "credential leak": "\u51ed\u8bc1\u6cc4\u9732\u98ce\u9669",
        "\u51ed\u8bc1\u6cc4\u9732\u98ce\u9669": "\u51ed\u8bc1\u6cc4\u9732\u98ce\u9669",
        "file upload": "\u6587\u4ef6\u4e0a\u4f20\u98ce\u9669",
        "\u6587\u4ef6\u4e0a\u4f20\u98ce\u9669": "\u6587\u4ef6\u4e0a\u4f20\u98ce\u9669",
        "path traversal": "\u8def\u5f84\u904d\u5386\u98ce\u9669",
        "\u8def\u5f84\u904d\u5386\u98ce\u9669": "\u8def\u5f84\u904d\u5386\u98ce\u9669",
        "xss": "XSS\u98ce\u9669",
        "xss\u98ce\u9669": "XSS\u98ce\u9669",
        "none": VULN_NONE,
        VULN_NONE: VULN_NONE,
        "unknown": VULN_PENDING,
        VULN_PENDING: VULN_PENDING,
        "security hardening": VULN_HARDENING,
        VULN_HARDENING: VULN_HARDENING,
        "ssrf": "SSRF\u98ce\u9669",
        "SSRF\u98ce\u9669": "SSRF\u98ce\u9669",
        "unsafe reflection": "\u4e0d\u5b89\u5168\u53cd\u5c04\u98ce\u9669",
        "\u4e0d\u5b89\u5168\u53cd\u5c04\u98ce\u9669": "\u4e0d\u5b89\u5168\u53cd\u5c04\u98ce\u9669",
    }

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str,
        prompts_file: str = "prompts.yaml",
        temperature: float = 0.1,
        timeout: int = 90,
        max_retries: int = 3,
        max_tokens: int = 4096,
        api_style: str = "auto",
        max_schema_retries: int = 2,
        enable_source_review: bool = True,
    ):
        self.prompt_builder = PromptBuilder(prompts_file)
        self.llm = OpenCodeLLM(
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=temperature,
            timeout=timeout,
            request_retries=max_retries,
            max_tokens=max_tokens,
            api_style=api_style,
        )
        self.max_schema_retries = max(0, int(max_schema_retries))
        self.enable_source_review = bool(enable_source_review)
        key_hash = hashlib.sha256((api_key or "").encode("utf-8")).hexdigest()[:12] if api_key else "none"
        logger.info("analyzer initialized model=%s base_url=%s api_key_hash=%s", model, base_url, key_hash)

    def analyze_function_pair(
        self,
        old_unit: Optional[str],
        new_unit: Optional[str],
        old_code: str = "",
        new_code: str = "",
        similarity: float = 0.0,
        scenario: str = "security_fix",
        language: str = "python",
        artifact: str = "",
        old_symbol_context: Optional[Dict[str, Any]] = None,
        new_symbol_context: Optional[Dict[str, Any]] = None,
        analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
    ) -> Dict[str, Any]:
        fallback = {
            "old_unit": old_unit,
            "new_unit": new_unit,
            "change_type": self.CHANGE_NON_SECURITY,
            "vulnerability_type": self.VULN_PENDING,
            "vulnerability_score": 0.0,
            "source_to_sink_conditions": {
                "sources": [],
                "guards": [],
                "sinks": [],
                "condition_chain": "",
            },
            "vulnerability_findings": [],
            "analysis_backend": "static",
            "decision_path": "llm_unavailable",
            "analysis_reason": "llm_unavailable",
            "ai_analysis_raw": {"error": "LLM unavailable or request failed; fell back to static analysis."},
            "old_code": old_code,
            "new_code": new_code,
            "confidence": 0.3,
            "review_required": True,
            "valid": True,
        }
        if not self.llm.enabled:
            return fallback

        context = build_local_context(
            old_code,
            new_code,
            language=language,
            artifact=artifact,
            old_symbol_context=old_symbol_context,
            new_symbol_context=new_symbol_context,
        )
        prompt_name = self.SCENARIO_PROMPT_MAP.get(scenario, "security_review")
        profile_name = normalize_analysis_profile(analysis_profile)
        if profile_name == "generic":
            prompt_name = "generic_review"
        elif profile_name == "behavior-review":
            prompt_name = "behavior_review"
        elif profile_name == "api-surface":
            prompt_name = "api_surface_review"
        prompt = self.prompt_builder.build(
            prompt_name,
            old_unit=old_unit or "",
            new_unit=new_unit or "",
            similarity=f"{similarity:.4f}",
            old_code=old_code,
            new_code=new_code,
            local_context=json.dumps(context, ensure_ascii=False),
        )
        messages = [
            {"role": "system", "content": self.prompt_builder.build("system")},
            {"role": "user", "content": prompt},
        ]
        try:
            content = self.llm.invoke(messages)
            parsed = self._parse_response(content)
            retries = 0
            while not parsed["valid"] and retries < self.max_schema_retries:
                repair_prompt = self._build_repair_prompt(content)
                repaired = self.llm.invoke(
                    [
                        {"role": "system", "content": "Return exactly one valid JSON object and nothing else."},
                        {"role": "user", "content": repair_prompt},
                    ]
                )
                content = repaired
                parsed = self._parse_response(repaired)
                retries += 1

            if not parsed.get("valid", False):
                fallback["ai_analysis_raw"] = {"error": "invalid_llm_schema"}
                fallback["analysis_reason"] = "llm_schema_invalid"
                fallback["error"] = "invalid_llm_schema"
                return fallback

            if self.enable_source_review and parsed.get("valid"):
                review = self._run_source_review(
                    scenario=scenario,
                    old_unit=old_unit or "",
                    new_unit=new_unit or "",
                    old_code=old_code,
                    new_code=new_code,
                    analysis=parsed,
                )
                parsed["confidence"] = review.get("confidence", parsed.get("confidence", 0.7))
                parsed["review_required"] = bool(review.get("review_required", parsed.get("review_required", False)))
                issues = review.get("issues", [])
                if issues:
                    parsed["review_notes"] = issues

            parsed.update(
                {
                    "old_unit": old_unit,
                    "new_unit": new_unit,
                    "old_code": old_code,
                    "new_code": new_code,
                    "analysis_backend": "llm",
                    "decision_path": "llm_primary",
                    "analysis_reason": "llm_primary",
                    "analysis_profile": profile_name,
                    "ai_analysis_raw": parsed.copy(),
                    "llm_raw_text": content,
                }
            )
            parsed.pop("valid", None)
            return parsed
        except Exception as exc:
            logger.exception("llm analysis failed: old_unit=%s new_unit=%s similarity=%.4f", old_unit, new_unit, similarity)
            fallback["error"] = str(exc)
            fallback["ai_analysis_raw"] = {"error": str(exc)}
            fallback["analysis_reason"] = "llm_runtime_failed"
            return fallback

    def _build_repair_prompt(self, invalid_content: str) -> str:
        try:
            return self.prompt_builder.build("repair_json", invalid_content=invalid_content)
        except Exception:
            return (
                "Repair the following content into exactly one valid JSON object.\n"
                "Keep these top-level keys only: change_type, vulnerability_type, vulnerability_score, "
                "source_to_sink_conditions, vulnerability_findings, confidence, review_required.\n"
                "source_to_sink_conditions must include sources, guards, sinks, condition_chain.\n"
                "Return JSON only.\n\n"
                f"Original content:\n{invalid_content}"
            )

    def _run_source_review(
        self,
        scenario: str,
        old_unit: str,
        new_unit: str,
        old_code: str,
        new_code: str,
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            prompt = self.prompt_builder.build(
                "source_review",
                scenario=scenario,
                old_unit=old_unit,
                new_unit=new_unit,
                old_code=old_code,
                new_code=new_code,
                analysis_json=json.dumps(analysis, ensure_ascii=False),
            )
            resp = self.llm.invoke(
                [
                    {"role": "system", "content": "You are a strict reviewer. Return JSON only."},
                    {"role": "user", "content": prompt},
                ]
            )
            raw = self._extract_json_object(resp)
            data = json.loads(raw)
            if not isinstance(data, dict):
                return {"review_required": True, "confidence": 0.4, "issues": ["source_review \u683c\u5f0f\u65e0\u6548"]}
            confidence = data.get("confidence", 0.7)
            try:
                confidence = float(confidence)
            except Exception:
                confidence = 0.7
            return {
                "review_required": bool(data.get("review_required", False)),
                "confidence": max(0.0, min(1.0, confidence)),
                "issues": [str(x) for x in data.get("issues", [])][:10] if isinstance(data.get("issues"), list) else [],
            }
        except Exception as exc:
            logger.warning("source_review failed: %s", exc)
            return {"review_required": True, "confidence": 0.5, "issues": ["source_review \u5931\u8d25\uff0c\u5efa\u8bae\u4eba\u5de5\u590d\u6838"]}

    @staticmethod
    def _normalize_score_scale(value: Any, default: float = 0.0) -> float:
        try:
            score = float(value)
        except Exception:
            score = float(default)
        if 10.0 < score <= 100.0:
            score = score / 10.0
        return max(0.0, min(10.0, score))

    @classmethod
    def _normalize_change_type_value(cls, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        return cls.CHANGE_TYPE_MAP.get(raw.lower(), cls.CHANGE_TYPE_MAP.get(raw, ""))

    @classmethod
    def _normalize_vulnerability_type_value(cls, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        return cls.VULNERABILITY_TYPE_MAP.get(raw.lower(), cls.VULNERABILITY_TYPE_MAP.get(raw, ""))

    @classmethod
    def _parse_response(cls, content: str) -> Dict[str, Any]:
        default = {
            "change_type": cls.CHANGE_NON_SECURITY,
            "vulnerability_type": cls.VULN_PENDING,
            "vulnerability_score": 0.0,
            "source_to_sink_conditions": {"sources": [], "guards": [], "sinks": [], "condition_chain": ""},
            "vulnerability_findings": [],
            "confidence": 0.5,
            "review_required": True,
            "valid": False,
        }
        try:
            raw = cls._extract_json_object(content)
            data = json.loads(raw)
            if not isinstance(data, dict):
                return default
            return cls._normalize_schema(data)
        except Exception:
            return default

    @staticmethod
    def _extract_json_object(content: str) -> str:
        text = (content or "").strip()
        if text.startswith("{") and text.endswith("}"):
            return text
        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL | re.IGNORECASE)
        if fenced:
            return fenced.group(1)
        first = text.find("{")
        last = text.rfind("}")
        if first >= 0 and last > first:
            return text[first : last + 1]
        raise ValueError("no json object found")

    @classmethod
    def _normalize_schema(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        contract_valid = True

        change_type = cls._normalize_change_type_value(data.get("change_type", cls.CHANGE_NON_SECURITY))
        if not change_type:
            contract_valid = False
        out["change_type"] = change_type if change_type in cls.CANONICAL_CHANGE_TYPES else cls.CHANGE_NON_SECURITY

        vulnerability_type = cls._normalize_vulnerability_type_value(data.get("vulnerability_type", cls.VULN_PENDING))
        if not vulnerability_type:
            contract_valid = False
        out["vulnerability_type"] = vulnerability_type or cls.VULN_PENDING
        top_score = cls._normalize_score_scale(data.get("vulnerability_score", 0.0), default=0.0)

        s2s = data.get("source_to_sink_conditions", {})
        if not isinstance(s2s, dict):
            contract_valid = False
            s2s = {}
        chain = s2s.get("condition_chain", "")
        if isinstance(chain, list):
            chain = " -> ".join(str(x) for x in chain if str(x).strip())
        chain_str = str(chain).strip()
        out["source_to_sink_conditions"] = {
            "sources": cls._to_str_list(s2s.get("sources")),
            "guards": cls._to_str_list(s2s.get("guards")),
            "sinks": cls._to_str_list(s2s.get("sinks")),
            "condition_chain": chain_str[:260],
        }

        findings = data.get("vulnerability_findings", [])
        normalized_findings: List[Dict[str, Any]] = []
        if not isinstance(findings, list):
            contract_valid = False
            findings = []
        for item in findings[:20]:
            if not isinstance(item, dict):
                contract_valid = False
                continue
            item_type = cls._normalize_vulnerability_type_value(item.get("type", out["vulnerability_type"]))
            if not item_type:
                contract_valid = False
                continue
            item_score = cls._normalize_score_scale(item.get("score", top_score), default=top_score)
            evidence = str(item.get("evidence", "")).strip()[:500]
            if not evidence:
                contract_valid = False
                continue
            normalized_findings.append({"type": item_type, "score": item_score, "evidence": evidence})

        if normalized_findings:
            top_score = max([top_score, max(float(x.get("score", 0.0)) for x in normalized_findings)])
        out["vulnerability_score"] = cls._apply_score_policy(
            change_type=out["change_type"],
            vulnerability_type=out["vulnerability_type"],
            score=top_score,
        )

        out["vulnerability_findings"] = [
            {
                "type": str(x["type"])[:120],
                "score": cls._apply_score_policy(
                    change_type=out["change_type"],
                    vulnerability_type=str(x["type"]),
                    score=cls._normalize_score_scale(x.get("score", out["vulnerability_score"]), default=out["vulnerability_score"]),
                ),
                "evidence": str(x["evidence"])[:500],
            }
            for x in normalized_findings
        ]

        if out["vulnerability_score"] >= 5.0 and not cls._has_complete_chain(out["source_to_sink_conditions"]):
            contract_valid = False
            out["vulnerability_type"] = cls.VULN_PENDING
            out["vulnerability_score"] = 0.0
            out["vulnerability_findings"] = [
                {
                    "type": cls.VULN_PENDING,
                    "score": 0.0,
                    "evidence": "\u8bc1\u636e\u94fe\u4e0d\u5b8c\u6574\uff1a\u7f3a\u5c11\u660e\u786e source/sink\uff0c\u9700\u8981\u4eba\u5de5\u590d\u6838",
                }
            ]

        try:
            confidence = float(data.get("confidence", 0.7))
        except Exception:
            confidence = 0.7
        out["confidence"] = max(0.0, min(1.0, confidence))
        out["review_required"] = bool(data.get("review_required", out["confidence"] < 0.6))
        backend = str(data.get("analysis_backend", "")).strip().lower()
        out["analysis_backend"] = backend if backend in {"llm", "static"} else ("llm" if data.get("llm_raw_text") else "static")
        out["decision_path"] = str(data.get("decision_path", "")).strip() or ("llm_primary" if out["analysis_backend"] == "llm" else "static")
        out["analysis_reason"] = str(data.get("analysis_reason", "")).strip() or out["decision_path"]
        out["valid"] = contract_valid and cls._schema_valid(out)
        return out

    @classmethod
    def _apply_score_policy(cls, change_type: str, vulnerability_type: str, score: float) -> float:
        normalized = cls._normalize_score_scale(score, default=0.0)
        if vulnerability_type in {cls.VULN_NONE}:
            return min(normalized, 2.0)
        if change_type == cls.CHANGE_NON_SECURITY:
            return min(normalized, 2.0)
        if change_type == cls.CHANGE_SECURITY_FIX and vulnerability_type not in {cls.VULN_NONE, cls.VULN_PENDING}:
            return max(5.0, normalized)
        return normalized

    @staticmethod
    def _has_complete_chain(chain: Dict[str, Any]) -> bool:
        if not isinstance(chain, dict):
            return False
        sources = chain.get("sources", [])
        sinks = chain.get("sinks", [])
        cond = str(chain.get("condition_chain", "")).strip()
        return bool(sources) and bool(sinks) and bool(cond)

    @staticmethod
    def _to_str_list(value: Any) -> List[str]:
        if isinstance(value, list):
            out: List[str] = []
            for item in value:
                text = str(item).strip()
                if text:
                    out.append(text[:220])
            return out
        if value is None:
            return []
        text = str(value).strip()
        return [text[:220]] if text else []

    @staticmethod
    def _schema_valid(data: Dict[str, Any]) -> bool:
        required = [
            "change_type",
            "vulnerability_type",
            "vulnerability_score",
            "source_to_sink_conditions",
            "vulnerability_findings",
            "confidence",
            "review_required",
            "analysis_backend",
            "decision_path",
            "analysis_reason",
        ]
        if not all(key in data for key in required):
            return False
        s2s = data.get("source_to_sink_conditions", {})
        if not isinstance(s2s, dict):
            return False
        for key in ("sources", "guards", "sinks", "condition_chain"):
            if key not in s2s:
                return False
        findings = data.get("vulnerability_findings", [])
        if not isinstance(findings, list):
            return False
        for item in findings:
            if not isinstance(item, dict):
                return False
            if not all(key in item for key in ("type", "score", "evidence")):
                return False
        return True
