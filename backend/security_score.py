from __future__ import annotations

from collections import Counter
from typing import Iterable, Mapping

SEVERITY_PENALTIES = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 10,
    "LOW": 5,
}

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _read_severity(item: Mapping[str, object]) -> str:
    severity = str(item.get("severity", "LOW")).upper()
    return severity if severity in SEVERITY_PENALTIES else "LOW"


def _read_confidence(item: Mapping[str, object]) -> int:
    try:
        confidence = int(item.get("confidence", 60))
    except (TypeError, ValueError):
        confidence = 60
    return max(0, min(confidence, 100))


def _decision_multiplier(item: Mapping[str, object]) -> float:
    decision = str(item.get("review_decision", "needs_manual_review")).lower()
    if decision == "confirmed":
        return 1.1
    if decision == "pending_ai_review":
        return 1.0
    return 0.9


def _weighted_penalty(item: Mapping[str, object]) -> int:
    base_penalty = SEVERITY_PENALTIES[_read_severity(item)]
    confidence_factor = 0.5 + (_read_confidence(item) / 200)
    penalty = round(base_penalty * confidence_factor * _decision_multiplier(item))
    return max(1, penalty)


def calculate_security_score(vulnerabilities: Iterable[Mapping[str, object]]) -> dict[str, object]:
    vulnerabilities = list(vulnerabilities)
    severity_breakdown = Counter(_read_severity(item) for item in vulnerabilities)
    total_penalty = sum(_weighted_penalty(item) for item in vulnerabilities)
    average_confidence = round(
        sum(_read_confidence(item) for item in vulnerabilities) / max(len(vulnerabilities), 1),
        2,
    )
    score = max(0, 100 - total_penalty)

    return {
        "security_score": score,
        "total_vulnerabilities": len(vulnerabilities),
        "severity_breakdown": {level: severity_breakdown.get(level, 0) for level in SEVERITY_ORDER},
        "total_penalty": total_penalty,
        "average_confidence": average_confidence if vulnerabilities else 0,
    }
