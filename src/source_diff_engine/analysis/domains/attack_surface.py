from __future__ import annotations

from typing import Any, Dict


def score_attack_surface_result(attack_surface: Dict[str, Any]) -> float:
    score = 0.5
    if bool(attack_surface.get("has_new_attack_surface", False)):
        score += 2.0
    level = str(attack_surface.get("attack_surface_level", "")).strip().lower()
    if level == "high":
        score += 2.0
    elif level == "medium":
        score += 1.0
    elif level == "low":
        score += 0.5
    if bool(attack_surface.get("new_callable_entries", [])):
        score += 0.5
    return round(min(10.0, score), 2)
