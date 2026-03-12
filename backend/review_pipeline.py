from __future__ import annotations

from collections import Counter
from typing import Any, Sequence

from ai_engine import ExplanationEngine
from scanner import (
    analyze_code,
    compute_code_statistics,
    infer_language,
    initial_confidence_for_severity,
    merge_code_statistics,
)
from security_score import calculate_security_score

OWASP_TOP_10 = (
    "A01 Broken Access Control",
    "A02 Cryptographic Failures",
    "A03 Injection",
    "A04 Insecure Design",
    "A05 Security Misconfiguration",
    "A06 Vulnerable Components",
    "A07 Identification & Authentication Failures",
    "A08 Software & Data Integrity Failures",
    "A09 Logging & Monitoring Failures",
    "A10 Server Side Request Forgery",
)


def review_source(
    code: str,
    filename: str | None = None,
    language: str | None = None,
    engine: ExplanationEngine | None = None,
) -> dict[str, Any]:
    raw_findings = analyze_code(code=code, filename=filename, language=language)
    statistics = [compute_code_statistics(code=code, findings=raw_findings, filename=filename, language=language)]

    return _finalize_review(
        raw_findings=raw_findings,
        statistics=statistics,
        source={
            "filename": filename or "pasted-code",
            "language": infer_language(filename=filename, language=language),
        },
        engine=engine,
    )


def review_bundle(
    files: Sequence[dict[str, str]],
    source: dict[str, Any],
    engine: ExplanationEngine | None = None,
) -> dict[str, Any]:
    raw_findings: list[dict[str, Any]] = []
    statistics: list[dict[str, Any]] = []

    for file_item in files:
        code = file_item["code"]
        filename = file_item["filename"]
        language = file_item.get("language")
        file_findings = analyze_code(code=code, filename=filename, language=language)
        raw_findings.extend(file_findings)
        statistics.append(compute_code_statistics(code=code, findings=file_findings, filename=filename, language=language))

    if "language" not in source:
        source["language"] = "multi-file"

    return _finalize_review(
        raw_findings=raw_findings,
        statistics=statistics,
        source=source,
        engine=engine,
    )


def _finalize_review(
    raw_findings: Sequence[dict[str, Any]],
    statistics: Sequence[dict[str, Any]],
    source: dict[str, Any],
    engine: ExplanationEngine | None = None,
) -> dict[str, Any]:
    prepared_findings = _prepare_stage_one_findings(raw_findings)
    merged_statistics = merge_code_statistics(statistics)
    stage_one = _build_stage_one_summary(prepared_findings, merged_statistics)

    explanation_engine = engine or ExplanationEngine()
    reviewed_findings, stage_two = explanation_engine.review_findings(prepared_findings)
    finalized_findings = _apply_owasp_stage(reviewed_findings)

    score_payload = calculate_security_score(finalized_findings)
    owasp_summary = _build_owasp_summary(finalized_findings)
    stage_three = _build_stage_three_summary(finalized_findings, owasp_summary, score_payload)

    return {
        **score_payload,
        "vulnerabilities": finalized_findings,
        "statistics": merged_statistics,
        "owasp_summary": owasp_summary,
        "review_stages": [stage_one, stage_two, stage_three],
        "source": source,
    }


def _prepare_stage_one_findings(raw_findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []

    for finding in raw_findings:
        statistical_confidence = initial_confidence_for_severity(str(finding.get("severity", "LOW")))
        item = finding.copy()
        item["confidence"] = statistical_confidence
        item["review_decision"] = "pending_ai_review"
        item["ai_provider"] = "gemini"
        item["review_pipeline"] = {
            "stage_1": {
                "name": "Stage 1 - Statistical Pattern Analysis",
                "status": "flagged",
                "signal": str(item.get("rule_id", "unknown-rule")),
                "confidence": statistical_confidence,
                "summary": str(item.get("description", "Pattern-based review flagged this code for manual inspection.")),
            }
        }
        prepared.append(item)

    return prepared


def _build_stage_one_summary(findings: Sequence[dict[str, Any]], statistics: dict[str, Any]) -> dict[str, Any]:
    finding_counts = Counter(str(item.get("type", "Unknown")) for item in findings)

    return {
        "id": "stage_1_statistical_analysis",
        "name": "Stage 1 - Statistical Pattern Analysis",
        "status": "completed",
        "summary": (
            f"Scanned {statistics.get('file_count', 0)} file(s) and {statistics.get('non_empty_lines', 0)} non-empty lines. "
            f"Deterministic rules flagged {len(findings)} suspicious code path(s)."
        ),
        "details": {
            **statistics,
            "finding_types": dict(finding_counts),
        },
    }


def _apply_owasp_stage(findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    finalized: list[dict[str, Any]] = []

    for finding in findings:
        item = finding.copy()
        category = str(item.get("owasp_category", "A04 Insecure Design"))
        if category not in OWASP_TOP_10:
            category = "A04 Insecure Design"
            item["owasp_category"] = category

        review_pipeline = dict(item.get("review_pipeline") or {})
        review_pipeline["stage_3"] = {
            "name": "Stage 3 - OWASP Correlation & Risk Scoring",
            "status": "mapped",
            "category": category,
            "summary": f"Mapped this issue to {category} and included it in the weighted security score.",
        }
        item["review_pipeline"] = review_pipeline
        finalized.append(item)

    return finalized


def _build_owasp_summary(findings: Sequence[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("owasp_category", "A04 Insecure Design")) for item in findings)
    return {category: counts.get(category, 0) for category in OWASP_TOP_10}


def _build_stage_three_summary(
    findings: Sequence[dict[str, Any]],
    owasp_summary: dict[str, int],
    score_payload: dict[str, Any],
) -> dict[str, Any]:
    populated_categories = sum(1 for count in owasp_summary.values() if count > 0)

    return {
        "id": "stage_3_owasp_correlation",
        "name": "Stage 3 - OWASP Correlation & Risk Scoring",
        "status": "completed",
        "summary": (
            f"Normalized {len(findings)} finding(s) across {populated_categories} OWASP category bucket(s) "
            f"and calculated a final security score of {score_payload['security_score']}."
        ),
        "details": {
            "owasp_summary": owasp_summary,
            "severity_breakdown": score_payload["severity_breakdown"],
            "security_score": score_payload["security_score"],
            "total_penalty": score_payload["total_penalty"],
        },
    }
