from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from source_diff_engine.analysis.profiles import DEFAULT_ANALYSIS_PROFILE, normalize_analysis_profile


AUTH_TOKEN_ENVS: List[str] = [
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
]


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _resolve_api_key() -> tuple[str, str]:
    for env_name in AUTH_TOKEN_ENVS:
        value = os.getenv(env_name, "")
        if str(value).strip():
            return str(value).strip(), env_name
    return "", ""


def _normalize_llm_mode(value: str) -> str:
    mode = str(value or "try").strip().lower()
    return mode if mode in {"off", "try", "required"} else "try"


def load_config(path: str = "config.json") -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    analysis = cfg.setdefault("analysis", {})
    analysis.setdefault("profile", DEFAULT_ANALYSIS_PROFILE)
    analysis["profile"] = normalize_analysis_profile(os.getenv("ANALYSIS_PROFILE", analysis.get("profile", DEFAULT_ANALYSIS_PROFILE)))

    llm = cfg.setdefault("llm", {})
    llm.setdefault("model", "gpt-5.3-codex")
    llm.setdefault("base_url", "")
    llm.setdefault("max_tokens", 4096)
    llm.setdefault("temperature", 0.1)
    llm.setdefault("timeout", 90)
    llm.setdefault("max_retries", 3)
    llm.setdefault("api_style", "auto")
    llm.setdefault("mode", "try")
    llm.setdefault("skip_preflight", False)

    llm["model"] = os.getenv("LLM_MODEL", str(llm["model"]))
    llm["base_url"] = os.getenv("LLM_BASE_URL", str(llm["base_url"]))
    llm["max_tokens"] = _env_int("LLM_MAX_TOKENS", int(llm["max_tokens"]))
    llm["timeout"] = _env_int("LLM_TIMEOUT", int(llm["timeout"]))
    llm["max_retries"] = _env_int("LLM_MAX_RETRIES", int(llm["max_retries"]))
    llm["temperature"] = _env_float("LLM_TEMPERATURE", float(llm["temperature"]))
    llm["api_style"] = os.getenv("LLM_API_STYLE", str(llm["api_style"])).strip().lower()
    llm["mode"] = _normalize_llm_mode(os.getenv("LLM_MODE", str(llm["mode"])))
    llm["skip_preflight"] = str(os.getenv("LLM_SKIP_PREFLIGHT", str(llm["skip_preflight"]))).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    api_key, api_key_env = _resolve_api_key()
    llm["api_key"] = api_key
    llm["api_key_env"] = api_key_env

    run = cfg.setdefault("run", {})
    run["min_similarity"] = _env_float("MIN_SIMILARITY", float(run.get("min_similarity", 0.0)))
    run["max_similarity"] = _env_float("MAX_SIMILARITY", float(run.get("max_similarity", 1.0)))
    run["max_diff_units"] = _env_int("MAX_DIFF_UNITS", int(run.get("max_diff_units", 300)))
    return cfg
