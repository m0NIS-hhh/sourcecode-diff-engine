from __future__ import annotations

from typing import Any, Dict

from source_diff_engine.pipeline.results import normalize_score


def score_security_result(
    *,
    security_domain_enabled: bool,
    new_vulnerability: Dict[str, Any],
    base_result: Dict[str, Any],
    security_fix: bool,
) -> float:
    if not security_domain_enabled:
        return 0.0
    score = normalize_score(new_vulnerability.get("score", 0.0), 0.0) if bool(new_vulnerability.get("has_new_vulnerability", False)) else 0.0
    score = max(score, normalize_score(base_result.get("vulnerability_score", 0.0), 0.0))
    if security_fix:
        score = max(score, 5.0)
    return round(min(10.0, score), 2)
