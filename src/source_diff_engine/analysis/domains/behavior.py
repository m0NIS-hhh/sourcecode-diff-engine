from __future__ import annotations

from typing import Any, Dict

from source_diff_engine.analysis.domains.generic import score_generic_result


def score_behavior_result(generic_axes: Dict[str, Any], attack_surface: Dict[str, Any]) -> float:
    score = score_generic_result("", generic_axes, attack_surface)
    if str(generic_axes.get("behavioral_impact", "")).strip() in {"new_behavior", "behavior_changed", "behavior_removed"}:
        score = min(10.0, score + 0.8)
    return round(score, 2)
