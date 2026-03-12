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


def calculate_security_score(vulnerabilities: Iterable[Mapping[str, object]]) -> dict[str, object]:
    vulnerabilities = list(vulnerabilities)
    severity_breakdown = Counter(_read_severity(item) for item in vulnerabilities)
    total_penalty = sum(SEVERITY_PENALTIES[_read_severity(item)] for item in vulnerabilities)
    score = max(0, 100 - total_penalty)

    return {
        "security_score": score,
        "total_vulnerabilities": len(vulnerabilities),
        "severity_breakdown": {level: severity_breakdown.get(level, 0) for level in SEVERITY_ORDER},
        "total_penalty": total_penalty,
    }
