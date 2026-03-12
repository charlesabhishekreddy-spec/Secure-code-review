from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Callable, Sequence

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".java": "java",
    ".ts": "typescript",
    ".tsx": "typescript",
}

USER_INPUT_TOKENS = (
    "user_input",
    "input(",
    "request",
    "req.",
    "req[",
    "params",
    "query",
    "argv",
    "sys.argv",
    "stdin",
    "body",
    "form",
    "filename",
    "filepath",
    "path",
    "url",
)

RulePredicate = Callable[[str, int, Sequence[str], str], bool]


@dataclass(frozen=True)
class Rule:
    identifier: str
    vulnerability_type: str
    severity: str
    owasp_category: str
    pattern: re.Pattern[str]
    description: str
    predicate: RulePredicate | None = None


def infer_language(filename: str | None = None, language: str | None = None) -> str:
    if language:
        normalized = language.strip().lower()
        if normalized in {"py", "python"}:
            return "python"
        if normalized in {"js", "jsx", "javascript"}:
            return "javascript"
        if normalized in {"java"}:
            return "java"
        if normalized in {"ts", "tsx", "typescript"}:
            return "typescript"
        return normalized

    extension = Path(filename or "").suffix.lower()
    return SUPPORTED_EXTENSIONS.get(extension, "plaintext")


def _contains_user_input_reference(line: str) -> bool:
    lowered = line.lower()
    return any(token in lowered for token in USER_INPUT_TOKENS)


def _allow_if_runtime_input_or_string_building(line: str, _line_number: int, _lines: Sequence[str], _language: str) -> bool:
    return _contains_user_input_reference(line) or any(
        token in line for token in ("+", "format(", "%s", "%d", "${", "{")
    )


def _allow_if_user_input(line: str, _line_number: int, _lines: Sequence[str], _language: str) -> bool:
    return _contains_user_input_reference(line)


def _allow_all(_line: str, _line_number: int, _lines: Sequence[str], _language: str) -> bool:
    return True


RULES: tuple[Rule, ...] = (
    Rule(
        identifier="sql-inline-query",
        vulnerability_type="SQL Injection",
        severity="HIGH",
        owasp_category="A03 Injection",
        pattern=re.compile(
            r'(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*(?:\+|format\s*\(|\$\{[^}]+\}|\{[^}]+\}|%\s*[sdrf])'
        ),
        description="SQL statements built from runtime values can let attackers alter the query structure.",
        predicate=_allow_if_runtime_input_or_string_building,
    ),
    Rule(
        identifier="sql-execute-concat",
        vulnerability_type="SQL Injection",
        severity="HIGH",
        owasp_category="A03 Injection",
        pattern=re.compile(
            r'(?i)\b(?:execute|query|rawQuery)\s*\(.*(?:\+|format\s*\(|\$\{[^}]+\}|\{[^}]+\}|%\s*[sdrf])'
        ),
        description="Database execution calls using string interpolation are vulnerable to SQL injection.",
        predicate=_allow_if_runtime_input_or_string_building,
    ),
    Rule(
        identifier="command-os-system",
        vulnerability_type="Command Injection",
        severity="CRITICAL",
        owasp_category="A03 Injection",
        pattern=re.compile(
            r"(?i)\b(?:os\.system|Runtime\.getRuntime\(\)\.exec|child_process\.(?:exec|execSync))\s*\("
        ),
        description="Shell commands composed at runtime can be hijacked by attacker-controlled input.",
        predicate=_allow_all,
    ),
    Rule(
        identifier="command-shell-true",
        vulnerability_type="Command Injection",
        severity="CRITICAL",
        owasp_category="A03 Injection",
        pattern=re.compile(r"(?i)\bsubprocess\.(?:run|Popen|call)\s*\(.*shell\s*=\s*True"),
        description="Running subprocesses through a shell exposes the command parser to injection payloads.",
        predicate=_allow_all,
    ),
    Rule(
        identifier="xss-dangerous-html",
        vulnerability_type="Cross Site Scripting (XSS)",
        severity="HIGH",
        owasp_category="A03 Injection",
        pattern=re.compile(r"(?i)\b(?:dangerouslySetInnerHTML|innerHTML\s*=|outerHTML\s*=|document\.write\s*\()"),
        description="Rendering unsanitized HTML lets attackers execute JavaScript in a victim's browser.",
        predicate=_allow_all,
    ),
    Rule(
        identifier="hardcoded-secret-assignment",
        vulnerability_type="Hardcoded Secret",
        severity="HIGH",
        owasp_category="A07 Identification & Authentication Failures",
        pattern=re.compile(
            r'(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret)\b\s*[:=]\s*["\'][^"\']{8,}["\']'
        ),
        description="Embedded credentials are easy to leak through source control, logs, or client bundles.",
        predicate=_allow_all,
    ),
    Rule(
        identifier="hardcoded-aws-key",
        vulnerability_type="Hardcoded Secret",
        severity="CRITICAL",
        owasp_category="A07 Identification & Authentication Failures",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        description="Cloud access keys in source code can expose production infrastructure.",
        predicate=_allow_all,
    ),
    Rule(
        identifier="insecure-http",
        vulnerability_type="Insecure API Call",
        severity="MEDIUM",
        owasp_category="A02 Cryptographic Failures",
        pattern=re.compile(r"http://[A-Za-z0-9.\-:_/?#=&%]+"),
        description="Plain HTTP exposes credentials and payloads to interception and tampering.",
        predicate=_allow_all,
    ),
    Rule(
        identifier="weak-crypto",
        vulnerability_type="Weak Cryptography",
        severity="MEDIUM",
        owasp_category="A02 Cryptographic Failures",
        pattern=re.compile(r"(?i)\b(?:md5|sha1)\b"),
        description="Broken hash algorithms are vulnerable to collisions and should not protect sensitive data.",
        predicate=_allow_all,
    ),
    Rule(
        identifier="unsafe-file-handling",
        vulnerability_type="Unsafe File Handling",
        severity="HIGH",
        owasp_category="A05 Security Misconfiguration",
        pattern=re.compile(
            r"(?i)\b(?:open|readFile(?:Sync)?|writeFile(?:Sync)?|sendFile|FileInputStream|Files\.readAllBytes)\s*\(.*(?:user|input|req\.|request\.|query\.|params\.|filename|filepath|path)"
        ),
        description="Using attacker-controlled paths can lead to traversal, overwrite, or disclosure issues.",
        predicate=_allow_if_user_input,
    ),
    Rule(
        identifier="insecure-deserialization-pickle",
        vulnerability_type="Insecure Deserialization",
        severity="CRITICAL",
        owasp_category="A08 Software & Data Integrity Failures",
        pattern=re.compile(r"(?i)\b(?:pickle\.loads?|yaml\.load|jsonpickle\.decode|unserialize)\s*\("),
        description="Unsafe deserialization can execute attacker-supplied code during object reconstruction.",
        predicate=_allow_all,
    ),
    Rule(
        identifier="insecure-deserialization-java",
        vulnerability_type="Insecure Deserialization",
        severity="CRITICAL",
        owasp_category="A08 Software & Data Integrity Failures",
        pattern=re.compile(r"(?i)\b(?:ObjectInputStream|BinaryFormatter)\b"),
        description="Object deserialization without strict validation can trigger remote code execution.",
        predicate=_allow_all,
    ),
    Rule(
        identifier="ssrf-runtime-url",
        vulnerability_type="Server-Side Request Forgery (SSRF)",
        severity="HIGH",
        owasp_category="A10 Server Side Request Forgery",
        pattern=re.compile(
            r"(?i)\b(?:requests\.(?:get|post)|httpx\.(?:get|post)|fetch|axios\.(?:get|post)|urllib\.request\.urlopen)\s*\(.*(?:user|input|req\.|request\.|query\.|params\.|url)"
        ),
        description="Fetching attacker-supplied URLs can expose internal services and metadata endpoints.",
        predicate=_allow_if_user_input,
    ),
)

SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

STATISTICAL_CONFIDENCE = {
    "CRITICAL": 96,
    "HIGH": 88,
    "MEDIUM": 76,
    "LOW": 64,
}


def analyze_code(code: str, filename: str | None = None, language: str | None = None) -> list[dict[str, object]]:
    normalized_language = infer_language(filename=filename, language=language)
    lines = code.splitlines()
    findings: list[dict[str, object]] = []
    seen: set[tuple[int, str, str]] = set()

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for rule in RULES:
            match = rule.pattern.search(line)
            if not match:
                continue
            if rule.predicate and not rule.predicate(line, line_number, lines, normalized_language):
                continue

            finding_key = (line_number, rule.vulnerability_type, filename or "")
            if finding_key in seen:
                continue

            findings.append(
                {
                    "line": line_number,
                    "type": rule.vulnerability_type,
                    "severity": rule.severity,
                    "owasp_category": rule.owasp_category,
                    "snippet": stripped,
                    "matched_text": match.group(0),
                    "filename": filename or "pasted-code",
                    "language": normalized_language,
                    "rule_id": rule.identifier,
                    "description": rule.description,
                }
            )
            seen.add(finding_key)

    return sorted(
        findings,
        key=lambda item: (
            str(item.get("filename", "")),
            int(item["line"]),
            SEVERITY_RANK.get(str(item["severity"]).upper(), 99),
            str(item["type"]),
        ),
    )


def initial_confidence_for_severity(severity: str) -> int:
    normalized = str(severity).upper()
    return STATISTICAL_CONFIDENCE.get(normalized, 60)


def compute_code_statistics(
    code: str,
    findings: Sequence[dict[str, object]] | None = None,
    filename: str | None = None,
    language: str | None = None,
) -> dict[str, object]:
    normalized_language = infer_language(filename=filename, language=language)
    lines = code.splitlines()
    non_empty_lines = [line for line in lines if line.strip()]
    suspicious_lines = {int(item["line"]) for item in findings or []}
    imports = 0
    functions = 0
    classes = 0
    comments = 0

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith(("#", "//", "/*", "*")):
            comments += 1
        if re.search(r"^\s*(import|from)\s+", raw_line) or re.search(r"^\s*require\s*\(", raw_line):
            imports += 1
        if re.search(r"^\s*(def|async def|function)\s+\w+", raw_line) or "=>" in raw_line:
            functions += 1
        if re.search(r"^\s*class\s+\w+", raw_line):
            classes += 1

    suspicious_density = round((len(suspicious_lines) / max(len(non_empty_lines), 1)) * 100, 2)

    return {
        "filename": filename or "pasted-code",
        "language": normalized_language,
        "total_lines": len(lines),
        "non_empty_lines": len(non_empty_lines),
        "comment_lines": comments,
        "import_lines": imports,
        "function_count": functions,
        "class_count": classes,
        "suspicious_lines": len(suspicious_lines),
        "suspicious_density": suspicious_density,
        "rule_hits": len(findings or []),
    }


def merge_code_statistics(statistics: Sequence[dict[str, object]]) -> dict[str, object]:
    stats_list = list(statistics)
    language_counts = Counter(str(item.get("language", "plaintext")) for item in stats_list)
    total_lines = sum(int(item.get("total_lines", 0)) for item in stats_list)
    non_empty_lines = sum(int(item.get("non_empty_lines", 0)) for item in stats_list)
    suspicious_lines = sum(int(item.get("suspicious_lines", 0)) for item in stats_list)
    comment_lines = sum(int(item.get("comment_lines", 0)) for item in stats_list)
    import_lines = sum(int(item.get("import_lines", 0)) for item in stats_list)
    function_count = sum(int(item.get("function_count", 0)) for item in stats_list)
    class_count = sum(int(item.get("class_count", 0)) for item in stats_list)
    suspicious_density = round((suspicious_lines / max(non_empty_lines, 1)) * 100, 2)

    return {
        "file_count": len(stats_list),
        "languages": dict(language_counts),
        "total_lines": total_lines,
        "non_empty_lines": non_empty_lines,
        "comment_lines": comment_lines,
        "import_lines": import_lines,
        "function_count": function_count,
        "class_count": class_count,
        "suspicious_lines": suspicious_lines,
        "suspicious_density": suspicious_density,
    }
