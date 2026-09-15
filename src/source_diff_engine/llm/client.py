from __future__ import annotations

import random
import re
import socket
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from openai import OpenAI

from source_diff_engine.logger_config import get_logger

logger = get_logger(__name__)


@dataclass
class LLMErrorInfo:
    category: str
    detail: str
    status_code: int = 0
    retryable: bool = False


class OpenCodeLLM:
    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str,
        temperature: float = 0.1,
        timeout: int = 90,
        request_retries: int = 3,
        max_tokens: int = 4096,
        api_style: str = "auto",
    ):
        self.model = model
        self.api_key = api_key or ""
        self.base_url = base_url
        self.temperature = float(temperature)
        self.timeout = int(timeout)
        self.request_retries = max(0, int(request_retries))
        self.max_tokens = int(max_tokens)
        style = (api_style or "auto").strip().lower()
        self.api_style = style if style in {"auto", "chat", "responses"} else "auto"
        self._resolved_api_style: Optional[str] = None
        self.disabled_reason: str = ""
        self.request_count: int = 0
        self.preflight_request_count: int = 0
        self.analysis_request_count: int = 0
        self.source_review_request_count: int = 0
        self.review_pass_request_count: int = 0
        self.retry_count: int = 0
        self.failure_categories: Dict[str, int] = {}
        self.client: Any = None
        self.last_error_info: Optional[LLMErrorInfo] = None
        if self.api_key:
            self.client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=self.timeout, max_retries=0)

    @property
    def enabled(self) -> bool:
        return self.client is not None

    def disable(self, reason: str = "") -> None:
        self.client = None
        self._resolved_api_style = None
        self.disabled_reason = str(reason or "").strip()

    @staticmethod
    def _extract_status_code(exc: Exception) -> int:
        code = getattr(exc, "status_code", None)
        if isinstance(code, int):
            return code
        resp = getattr(exc, "response", None)
        if resp is not None:
            status = getattr(resp, "status_code", None)
            if isinstance(status, int):
                return status
        return 0

    @classmethod
    def _classify_error(cls, exc: Exception) -> LLMErrorInfo:
        status = cls._extract_status_code(exc)
        message = cls._sanitize_error_detail(str(exc).strip() or exc.__class__.__name__)
        lowered = message.lower()
        retryable = False
        category = "unknown"

        if isinstance(exc, (httpx.ConnectError, socket.gaierror)):
            category = "network_blocked"
            retryable = True
        elif isinstance(exc, httpx.ConnectTimeout):
            category = "network_timeout"
            retryable = True
        elif isinstance(exc, httpx.ReadTimeout):
            category = "read_timeout"
            retryable = True
        elif status == 401:
            category = "auth_failed"
        elif status == 403:
            category = "permission_denied"
        elif status == 404:
            category = "not_found"
        elif status == 429:
            category = "rate_limited"
            retryable = True
        elif status >= 500:
            category = "server_error"
            retryable = True
        elif "name or service not known" in lowered or "nodename nor servname" in lowered:
            category = "dns_failed"
            retryable = True
        elif "proxy" in lowered:
            category = "proxy_failed"
            retryable = True
        elif "unsupported" in lowered and "chat" in lowered:
            category = "api_style_unsupported"
        elif "unsupported" in lowered and "responses" in lowered:
            category = "api_style_unsupported"
        elif "model" in lowered and "not found" in lowered:
            category = "model_not_found"
        elif "connection error" in lowered:
            category = "network_blocked"
            retryable = True

        if category == "unknown":
            retryable = status == 0 or status == 429 or status >= 500
        return LLMErrorInfo(
            category=category,
            detail=message,
            status_code=status,
            retryable=retryable,
        )

    @staticmethod
    def _sanitize_error_detail(detail: str, limit: int = 300) -> str:
        text = str(detail or "").strip()
        text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
        text = re.sub(r"(?i)(api[-_ ]?key|authorization|token)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]", text)
        text = re.sub(r"sk-[A-Za-z0-9_-]{12,}", "sk-[REDACTED]", text)
        return text[:limit]

    def metrics(self) -> Dict[str, Any]:
        return {
            "request_count": int(self.request_count),
            "preflight_request_count": int(self.preflight_request_count),
            "analysis_request_count": int(self.analysis_request_count),
            "source_review_request_count": int(self.source_review_request_count),
            "review_pass_request_count": int(self.review_pass_request_count),
            "retry_count": int(self.retry_count),
            "failure_categories": dict(sorted(self.failure_categories.items())),
        }

    def _record_operation_request(self, operation: str) -> None:
        name = str(operation or "").strip().lower()
        if "preflight" in name:
            self.preflight_request_count += 1
        elif "source review" in name:
            self.source_review_request_count += 1
        elif "review pass" in name:
            self.review_pass_request_count += 1
        else:
            self.analysis_request_count += 1

    @classmethod
    def _is_retryable(cls, exc: Exception) -> bool:
        return cls._classify_error(exc).retryable

    @staticmethod
    def _messages_to_responses_input(messages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for msg in messages:
            role = str(msg.get("role", "user") or "user")
            content = str(msg.get("content", "") or "")
            out.append(
                {
                    "role": role,
                    "content": [
                        {
                            "type": "input_text",
                            "text": content,
                        }
                    ],
                }
            )
        return out

    @staticmethod
    def _extract_text_from_dump_output(output: Any) -> str:
        if not isinstance(output, list):
            return ""
        chunks: List[str] = []
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if isinstance(part, dict):
                    text = part.get("text")
                    if isinstance(text, str) and text.strip():
                        chunks.append(text.strip())
                        continue
                    text = part.get("output_text")
                    if isinstance(text, str) and text.strip():
                        chunks.append(text.strip())
        return "\n".join(chunks).strip()

    @staticmethod
    def _extract_responses_text(resp: Any) -> str:
        text = getattr(resp, "output_text", None)
        if isinstance(text, str) and text.strip():
            return text.strip()

        output = getattr(resp, "output", None)
        if isinstance(output, list):
            chunks: List[str] = []
            for item in output:
                content = getattr(item, "content", None)
                if not isinstance(content, list):
                    continue
                for part in content:
                    part_text = getattr(part, "text", None)
                    if isinstance(part_text, str) and part_text.strip():
                        chunks.append(part_text.strip())
            merged = "\n".join(chunks).strip()
            if merged:
                return merged

        if hasattr(resp, "model_dump"):
            try:
                dump = resp.model_dump()
            except Exception:
                dump = None
            if isinstance(dump, dict):
                dump_text = dump.get("output_text")
                if isinstance(dump_text, str) and dump_text.strip():
                    return dump_text.strip()
                parsed = OpenCodeLLM._extract_text_from_dump_output(dump.get("output"))
                if parsed:
                    return parsed
        return ""

    @staticmethod
    def _collect_streamed_responses_text(stream: Any) -> str:
        done_chunks: List[str] = []
        delta_chunks: List[str] = []
        for event in stream:
            event_type = str(getattr(event, "type", "") or "")
            if event_type == "response.output_text.done":
                text = getattr(event, "text", None)
                if isinstance(text, str) and text.strip():
                    done_chunks.append(text.strip())
            elif event_type == "response.output_text.delta":
                delta = getattr(event, "delta", None)
                if isinstance(delta, str) and delta:
                    delta_chunks.append(delta)
        if done_chunks:
            return "\n".join(done_chunks).strip()
        return "".join(delta_chunks).strip()

    def _invoke_chat(self, messages: List[Dict[str, str]]) -> str:
        payload: Dict[str, Any] = {
            "model": self.model.strip(),
            "messages": messages,
            "temperature": self.temperature,
        }
        if self.max_tokens > 0:
            payload["max_tokens"] = self.max_tokens
        resp = self.client.chat.completions.create(**payload)
        return resp.choices[0].message.content or ""

    def _invoke_responses(self, messages: List[Dict[str, str]]) -> str:
        payload: Dict[str, Any] = {
            "model": self.model.strip(),
            "input": self._messages_to_responses_input(messages),
            "store": False,
        }
        if self.max_tokens > 0:
            payload["max_output_tokens"] = self.max_tokens
        with self.client.responses.stream(**payload) as stream:
            streamed_text = self._collect_streamed_responses_text(stream)
            resp = stream.get_final_response()
        if streamed_text:
            return streamed_text
        text = self._extract_responses_text(resp)
        if text.strip():
            return text.strip()

        dump: Dict[str, Any] = {}
        if hasattr(resp, "model_dump"):
            try:
                raw = resp.model_dump()
                if isinstance(raw, dict):
                    dump = raw
            except Exception:
                dump = {}

        usage = dump.get("usage", {})
        output_tokens = usage.get("output_tokens") if isinstance(usage, dict) else None
        if isinstance(output_tokens, int) and output_tokens > 0:
            raise RuntimeError("responses API returned empty text while output_tokens > 0")
        raise RuntimeError("responses API returned empty text")

    def _try_invoke_once(self, messages: List[Dict[str, str]], style: str) -> str:
        if style == "responses":
            return self._invoke_responses(messages)
        return self._invoke_chat(messages)

    def _candidate_styles(self, prefer_resolved: bool = False) -> List[str]:
        if prefer_resolved and self._resolved_api_style in {"chat", "responses"}:
            return [self._resolved_api_style]
        if self.api_style in {"chat", "responses"}:
            return [self.api_style]
        return ["chat", "responses"]

    @staticmethod
    def _retry_delay_seconds(attempt_index: int) -> float:
        return min(8.0, (2 ** attempt_index) + random.uniform(0.1, 0.5))

    def diagnose_connectivity(self) -> Dict[str, Any]:
        parsed = urlparse(str(self.base_url or "").strip())
        host = parsed.hostname or ""
        port = int(parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme else 0))
        dns: Dict[str, Any] = {"host": host, "ok": False, "resolved_ip": "", "error": ""}
        if host:
            try:
                dns["resolved_ip"] = socket.getaddrinfo(host, port or 443)[0][4][0]
                dns["ok"] = True
            except Exception as exc:
                dns["error"] = str(exc)
        return {
            "base_url": self.base_url,
            "model": self.model,
            "api_style": self.api_style,
            "resolved_api_style": self._resolved_api_style or "",
            "client_enabled": bool(self.client),
            "api_key_present": bool(self.api_key),
            "dns": dns,
            "last_error": {
                "category": self.last_error_info.category,
                "detail": self.last_error_info.detail,
                "status_code": self.last_error_info.status_code,
                "retryable": self.last_error_info.retryable,
            }
            if self.last_error_info
            else {},
        }

    def _run_with_style_retries(
        self,
        *,
        operation: str,
        styles: List[str],
        call: Callable[[str], Any],
    ) -> tuple[Any, str]:
        last_exc: Exception | None = None
        self.last_error_info = None
        for attempt_index in range(self.request_retries + 1):
            attempt_start = time.time()
            saw_retryable = False
            for style in styles:
                logger.info(
                    "%s start: model=%s api_style=%s attempt=%d/%d",
                    operation,
                    self.model,
                    style,
                    attempt_index + 1,
                    self.request_retries + 1,
                )
                try:
                    self.request_count += 1
                    self._record_operation_request(operation)
                    result = call(style)
                    elapsed = time.time() - attempt_start
                    logger.info(
                        "%s success: model=%s api_style=%s attempt=%d elapsed=%.2fs",
                        operation,
                        self.model,
                        style,
                        attempt_index + 1,
                        elapsed,
                    )
                    return result, style
                except Exception as exc:
                    last_exc = exc
                    err = self._classify_error(exc)
                    self.last_error_info = err
                    self.failure_categories[err.category] = self.failure_categories.get(err.category, 0) + 1
                    if err.retryable:
                        saw_retryable = True
                    logger.warning(
                        "%s failed: model=%s api_style=%s attempt=%d category=%s status=%s error=%s",
                        operation,
                        self.model,
                        style,
                        attempt_index + 1,
                        err.category,
                        err.status_code,
                        err.detail,
                    )
            if last_exc is None:
                break
            if attempt_index >= self.request_retries or not saw_retryable:
                raise last_exc
            self.retry_count += 1
            time.sleep(self._retry_delay_seconds(attempt_index))
        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"{operation} failed with unknown error")

    def preflight(self, skip_models_check: bool = False) -> None:
        if not self.client:
            raise RuntimeError("LLM client disabled: missing API key")

        model_ids: List[str] = []
        if not bool(skip_models_check):
            try:
                models = self.client.models.list()
                model_ids = [str(getattr(m, "id", "") or "") for m in getattr(models, "data", [])]
            except Exception as exc:
                logger.warning("llm preflight models.list failed: error=%s", exc)

        if model_ids and self.model not in model_ids:
            preview = ", ".join(sorted([m for m in model_ids if m])[:12])
            logger.warning(
                "configured model not found in models.list: model=%s available_preview=%s (continue with live probe)",
                self.model,
                preview,
            )

        ping_messages = [{"role": "user", "content": "ping"}]
        try:
            _, style = self._run_with_style_retries(
                operation="llm preflight",
                styles=self._candidate_styles(),
                call=lambda current_style: self._try_invoke_once(ping_messages, current_style),
            )
        except Exception as exc:
            err = self.last_error_info or self._classify_error(exc)
            raise RuntimeError(f"LLM preflight failed [{err.category}] for model={self.model}: {err.detail}") from exc
        self._resolved_api_style = style

    def invoke(self, messages: List[Dict[str, str]], operation: str = "llm request") -> str:
        if not self.client:
            raise RuntimeError("LLM client disabled: missing API key")

        content, style = self._run_with_style_retries(
            operation=operation,
            styles=self._candidate_styles(prefer_resolved=True),
            call=lambda current_style: self._try_invoke_once(messages, current_style),
        )
        self._resolved_api_style = style
        return content
