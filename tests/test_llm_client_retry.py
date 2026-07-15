from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from llm_client import OpenCodeLLM


class _RetryableError(RuntimeError):
    def __init__(self, message: str, status_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code


class _NonRetryableError(RuntimeError):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


def _make_llm(*, api_style: str = "chat", request_retries: int = 2) -> OpenCodeLLM:
    llm = OpenCodeLLM(
        model="test-model",
        api_key="x",
        base_url="https://example.invalid/v1",
        request_retries=request_retries,
        api_style=api_style,
    )
    llm.client = SimpleNamespace(
        models=SimpleNamespace(
            list=lambda: SimpleNamespace(data=[SimpleNamespace(id="test-model")]),
        )
    )
    return llm


@pytest.mark.parametrize(
    ("status_code", "message"),
    [
        (0, "timeout"),
        (429, "rate limited"),
        (503, "server overloaded"),
    ],
)
def test_preflight_retries_retryable_failures(monkeypatch: pytest.MonkeyPatch, status_code: int, message: str) -> None:
    llm = _make_llm(api_style="chat", request_retries=2)
    calls = {"count": 0}
    sleeps: list[float] = []

    monkeypatch.setattr("llm_client.random.uniform", lambda _a, _b: 0.25)
    monkeypatch.setattr("llm_client.time.sleep", lambda seconds: sleeps.append(seconds))

    def fake_try_invoke_once(messages: list[dict[str, str]], style: str) -> str:
        calls["count"] += 1
        assert messages == [{"role": "user", "content": "ping"}]
        assert style == "chat"
        if calls["count"] == 1:
            raise _RetryableError(message, status_code=status_code)
        return "pong"

    monkeypatch.setattr(llm, "_try_invoke_once", fake_try_invoke_once)

    llm.preflight()

    assert calls["count"] == 2
    assert sleeps == [1.25]
    assert llm._resolved_api_style == "chat"


def test_preflight_falls_through_to_next_style_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    llm = _make_llm(api_style="auto", request_retries=3)
    calls: list[str] = []
    sleeps: list[float] = []

    monkeypatch.setattr("llm_client.time.sleep", lambda seconds: sleeps.append(seconds))

    def fake_try_invoke_once(_messages: list[dict[str, str]], style: str) -> str:
        calls.append(style)
        if style == "chat":
            raise _NonRetryableError("chat unsupported", status_code=400)
        return "pong"

    monkeypatch.setattr(llm, "_try_invoke_once", fake_try_invoke_once)

    llm.preflight()

    assert calls == ["chat", "responses"]
    assert sleeps == []
    assert llm._resolved_api_style == "responses"


def test_preflight_does_not_retry_non_retryable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    llm = _make_llm(api_style="chat", request_retries=3)
    calls = {"count": 0}
    sleeps: list[float] = []

    monkeypatch.setattr("llm_client.time.sleep", lambda seconds: sleeps.append(seconds))

    def fake_try_invoke_once(_messages: list[dict[str, str]], _style: str) -> str:
        calls["count"] += 1
        raise _NonRetryableError("bad request", status_code=401)

    monkeypatch.setattr(llm, "_try_invoke_once", fake_try_invoke_once)

    with pytest.raises(RuntimeError, match=r"LLM preflight failed \[auth_failed\] for model=test-model: bad request"):
        llm.preflight()

    assert calls["count"] == 1
    assert sleeps == []
    assert llm.last_error_info is not None
    assert llm.last_error_info.category == "auth_failed"


def test_invoke_retries_retryable_failure_with_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    llm = _make_llm(api_style="chat", request_retries=2)
    calls = {"count": 0}
    sleeps: list[float] = []
    messages = [{"role": "user", "content": "hello"}]

    monkeypatch.setattr("llm_client.random.uniform", lambda _a, _b: 0.25)
    monkeypatch.setattr("llm_client.time.sleep", lambda seconds: sleeps.append(seconds))

    def fake_try_invoke_once(current_messages: list[dict[str, str]], style: str) -> str:
        calls["count"] += 1
        assert current_messages == messages
        assert style == "chat"
        if calls["count"] == 1:
            raise _RetryableError("timeout")
        return "ok"

    monkeypatch.setattr(llm, "_try_invoke_once", fake_try_invoke_once)

    result = llm.invoke(messages)

    assert result == "ok"
    assert calls["count"] == 2
    assert sleeps == [1.25]
    assert llm._resolved_api_style == "chat"


def test_classify_connect_error_as_network_blocked() -> None:
    llm = _make_llm()
    err = llm._classify_error(httpx.ConnectError("blocked"))
    assert err.category == "network_blocked"
    assert err.retryable is True


def test_preflight_can_skip_models_check(monkeypatch: pytest.MonkeyPatch) -> None:
    llm = _make_llm(api_style="chat", request_retries=0)
    calls = {"models": 0, "invoke": 0}

    def fake_models_list():
        calls["models"] += 1
        raise AssertionError("models.list should be skipped")

    llm.client = SimpleNamespace(models=SimpleNamespace(list=fake_models_list))

    def fake_try_invoke_once(messages: list[dict[str, str]], style: str) -> str:
        calls["invoke"] += 1
        assert messages == [{"role": "user", "content": "ping"}]
        assert style == "chat"
        return "pong"

    monkeypatch.setattr(llm, "_try_invoke_once", fake_try_invoke_once)
    llm.preflight(skip_models_check=True)
    assert calls["models"] == 0
    assert calls["invoke"] == 1
