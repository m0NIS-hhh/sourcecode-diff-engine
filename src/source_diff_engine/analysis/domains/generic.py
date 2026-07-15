from __future__ import annotations

from typing import Any, Dict, List


def classify_generic_axes(
    *,
    raw_change_type: str,
    new_vulnerability: Dict[str, Any],
    attack_surface: Dict[str, Any],
    security_domain_enabled: bool,
    security_fix: bool = False,
) -> Dict[str, Any]:
    if raw_change_type == "added":
        change_intent = "feature_addition"
        behavioral_impact = "new_behavior"
    elif raw_change_type == "removed":
        change_intent = "deletion"
        behavioral_impact = "behavior_removed"
    elif security_fix:
        change_intent = "hardening"
        behavioral_impact = "hardening_change"
    elif bool(attack_surface.get("has_new_feature", False)):
        change_intent = "feature_addition"
        behavioral_impact = "behavior_changed"
    elif bool(attack_surface.get("has_new_attack_surface", False)):
        change_intent = "behavior_modification"
        behavioral_impact = "behavior_changed"
    else:
        change_intent = "refactor_or_maintenance"
        behavioral_impact = "localized_change"

    new_entries = list(attack_surface.get("new_callable_entries", [])) if isinstance(attack_surface.get("new_callable_entries"), list) else []
    has_surface = bool(attack_surface.get("has_new_attack_surface", False))
    if has_surface or new_entries:
        interface_impact = "expanded"
    elif raw_change_type == "removed":
        interface_impact = "reduced"
    else:
        interface_impact = "unchanged"

    if bool(new_vulnerability.get("has_new_vulnerability", False)) and security_domain_enabled:
        security_impact = "introduced_risk"
    elif security_fix:
        security_impact = "hardening"
    elif raw_change_type == "removed":
        security_impact = "risk_reduction"
    elif security_domain_enabled:
        security_impact = "none"
    else:
        security_impact = "unassessed"

    if has_surface or new_entries:
        attack_surface_impact = "expanded"
    elif raw_change_type == "removed":
        attack_surface_impact = "reduced"
    else:
        attack_surface_impact = "none"

    capability_expansion: List[str] = []
    if isinstance(attack_surface.get("feature_signals"), list):
        capability_expansion.extend(str(item) for item in attack_surface.get("feature_signals", []) if str(item).strip())
    if isinstance(attack_surface.get("attack_surface_flags"), list):
        capability_expansion.extend(str(item) for item in attack_surface.get("attack_surface_flags", []) if str(item).strip())
    if new_entries:
        capability_expansion.extend(f"new_callable:{item}" for item in new_entries if str(item).strip())

    return {
        "change_intent": change_intent,
        "behavioral_impact": behavioral_impact,
        "interface_impact": interface_impact,
        "security_impact": security_impact,
        "attack_surface_impact": attack_surface_impact,
        "capability_expansion": list(dict.fromkeys(capability_expansion))[:10],
    }


def score_generic_result(raw_change_type: str, generic_axes: Dict[str, Any], attack_surface: Dict[str, Any]) -> float:
    score = 0.5
    if raw_change_type in {"added", "removed"}:
        score += 0.4
    if str(generic_axes.get("change_intent", "")).strip() in {"feature_addition", "behavior_modification", "hardening"}:
        score += 0.6
    if str(generic_axes.get("behavioral_impact", "")).strip() in {"new_behavior", "behavior_changed", "behavior_removed", "hardening_change"}:
        score += 1.0
    if str(generic_axes.get("interface_impact", "")).strip() in {"expanded", "reduced"}:
        score += 0.5
    if str(generic_axes.get("attack_surface_impact", "")).strip() == "expanded":
        score += 1.8
    if bool(attack_surface.get("has_new_attack_surface", False)):
        score += 0.5
        level = str(attack_surface.get("attack_surface_level", "")).strip().lower()
        if level == "high":
            score += 1.0
        elif level == "medium":
            score += 0.5
        elif level == "low":
            score += 0.2
    if str(generic_axes.get("security_impact", "")).strip() == "introduced_risk":
        score += 0.6
    return round(min(10.0, score), 2)
