from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Tuple


DEFAULT_ANALYSIS_PROFILE = "generic"

PROFILE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "generic": {
        "name": "generic",
        "enabled_domains": ("generic", "behavior", "attack_surface"),
        "primary_conclusion_strategy": "generic",
        "llm_mode": "off",
        "review_policy": {
            "security": False,
            "behavior": True,
            "attack_surface": True,
        },
    },
    "security": {
        "name": "security",
        "enabled_domains": ("generic", "behavior", "attack_surface", "security"),
        "primary_conclusion_strategy": "security",
        "llm_mode": "try",
        "review_policy": {
            "security": True,
            "behavior": True,
            "attack_surface": True,
        },
    },
    "security-strict": {
        "name": "security-strict",
        "enabled_domains": ("generic", "behavior", "attack_surface", "security"),
        "primary_conclusion_strategy": "security",
        "llm_mode": "required",
        "review_policy": {
            "security": True,
            "behavior": True,
            "attack_surface": True,
        },
    },
    "api-surface": {
        "name": "api-surface",
        "enabled_domains": ("generic", "attack_surface"),
        "primary_conclusion_strategy": "api_surface",
        "llm_mode": "off",
        "review_policy": {
            "security": False,
            "behavior": False,
            "attack_surface": True,
        },
    },
    "behavior-review": {
        "name": "behavior-review",
        "enabled_domains": ("generic", "behavior", "attack_surface"),
        "primary_conclusion_strategy": "behavior",
        "llm_mode": "off",
        "review_policy": {
            "security": False,
            "behavior": True,
            "attack_surface": True,
        },
    },
}


def normalize_analysis_profile(value: Any) -> str:
    profile = str(value or DEFAULT_ANALYSIS_PROFILE).strip().lower().replace("_", "-")
    return profile if profile in PROFILE_DEFINITIONS else DEFAULT_ANALYSIS_PROFILE


def get_analysis_profile(value: Any) -> Dict[str, Any]:
    profile = PROFILE_DEFINITIONS[normalize_analysis_profile(value)]
    return deepcopy(profile)


def profile_domains(profile: Dict[str, Any]) -> Tuple[str, ...]:
    domains = profile.get("enabled_domains", ()) if isinstance(profile, dict) else ()
    return tuple(str(item) for item in domains if str(item).strip())


def profile_llm_mode(profile: Dict[str, Any]) -> str:
    return str(profile.get("llm_mode", DEFAULT_ANALYSIS_PROFILE) if isinstance(profile, dict) else DEFAULT_ANALYSIS_PROFILE).strip().lower()


def profile_primary_strategy(profile: Dict[str, Any]) -> str:
    return str(profile.get("primary_conclusion_strategy", DEFAULT_ANALYSIS_PROFILE) if isinstance(profile, dict) else DEFAULT_ANALYSIS_PROFILE).strip().lower()


def profile_enables_domain(profile: Dict[str, Any], domain: str) -> bool:
    return str(domain or "").strip().lower() in set(profile_domains(profile))


def profile_summary(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "analysis_profile": str(profile.get("name", DEFAULT_ANALYSIS_PROFILE) if isinstance(profile, dict) else DEFAULT_ANALYSIS_PROFILE),
        "enabled_domains": list(profile_domains(profile)),
        "primary_conclusion_strategy": profile_primary_strategy(profile),
        "llm_mode": profile_llm_mode(profile),
        "security_enabled": profile_enables_domain(profile, "security"),
    }
