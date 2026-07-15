from __future__ import annotations

import json
from pathlib import Path

from config_loader import AUTH_TOKEN_ENVS, load_config


def test_load_config_prefers_llm_api_key_env(tmp_path: Path, monkeypatch) -> None:
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"llm": {"base_url": "https://example.invalid/v1"}}), encoding="utf-8")
    for env_name in AUTH_TOKEN_ENVS:
        monkeypatch.delenv(env_name, raising=False)
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "legacy-token")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-token")
    monkeypatch.setenv("LLM_API_KEY", "llm-token")

    cfg = load_config(str(cfg_path))
    assert cfg["llm"]["api_key"] == "llm-token"
    assert cfg["llm"]["api_key_env"] == "LLM_API_KEY"


def test_load_config_uses_openai_api_key_when_llm_api_key_missing(tmp_path: Path, monkeypatch) -> None:
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"llm": {}}), encoding="utf-8")
    for env_name in AUTH_TOKEN_ENVS:
        monkeypatch.delenv(env_name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-token")

    cfg = load_config(str(cfg_path))
    assert cfg["llm"]["api_key"] == "openai-token"
    assert cfg["llm"]["api_key_env"] == "OPENAI_API_KEY"


def test_load_config_ignores_api_key_when_env_missing(tmp_path: Path, monkeypatch) -> None:
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"llm": {"api_key": "stale-config-secret"}}), encoding="utf-8")
    for env_name in AUTH_TOKEN_ENVS:
        monkeypatch.delenv(env_name, raising=False)

    cfg = load_config(str(cfg_path))
    assert cfg["llm"]["api_key"] == ""
    assert cfg["llm"]["api_key_env"] == ""
