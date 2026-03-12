from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
import fnmatch
from pathlib import Path
import re
from typing import Callable, Sequence

from project_config import load_project_config

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

SECRET_NAME_PATTERN = re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret)")
SQL_KEYWORD_PATTERN = re.compile(r"(?i)\b(select|insert|update|delete)\b")

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
    ),
    Rule(
        identifier="command-os-system",
        vulnerability_type="Command Injection",
        severity="CRITICAL",
        owasp_category="A03 Injection",
        pattern=re.compile(
            r"(?i)\b(?:os\.system|Runtime\.getRuntime\(\)\.exec|child_process\.(?:exec|execSync)|exec\s*\()"
        ),
        description="Shell commands composed at runtime can be hijacked by attacker-controlled input.",
    ),
    Rule(
        identifier="command-shell-true",
        vulnerability_type="Command Injection",
        severity="CRITICAL",
        owasp_category="A03 Injection",
        pattern=re.compile(r"(?i)\bsubprocess\.(?:run|Popen|call)\s*\(.*shell\s*=\s*True"),
        description="Running subprocesses through a shell exposes the command parser to injection payloads.",
    ),
    Rule(
        identifier="xss-dangerous-html",
        vulnerability_type="Cross Site Scripting (XSS)",
        severity="HIGH",
        owasp_category="A03 Injection",
        pattern=re.compile(r"(?i)\b(?:dangerouslySetInnerHTML|innerHTML\s*=|outerHTML\s*=|document\.write\s*\()"),
        description="Rendering unsanitized HTML lets attackers execute JavaScript in a victim's browser.",
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
    ),
    Rule(
        identifier="hardcoded-aws-key",
        vulnerability_type="Hardcoded Secret",
        severity="CRITICAL",
        owasp_category="A07 Identification & Authentication Failures",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        description="Cloud access keys in source code can expose production infrastructure.",
    ),
    Rule(
        identifier="insecure-http",
        vulnerability_type="Insecure API Call",
        severity="MEDIUM",
        owasp_category="A02 Cryptographic Failures",
        pattern=re.compile(r"http://[A-Za-z0-9.\-:_/?#=&%]+"),
        description="Plain HTTP exposes credentials and payloads to interception and tampering.",
    ),
    Rule(
        identifier="weak-crypto",
        vulnerability_type="Weak Cryptography",
        severity="MEDIUM",
        owasp_category="A02 Cryptographic Failures",
        pattern=re.compile(r"(?i)\b(?:md5|sha1)\b"),
        description="Broken hash algorithms are vulnerable to collisions and should not protect sensitive data.",
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
    ),
    Rule(
        identifier="insecure-deserialization-pickle",
        vulnerability_type="Insecure Deserialization",
        severity="CRITICAL",
        owasp_category="A08 Software & Data Integrity Failures",
        pattern=re.compile(r"(?i)\b(?:pickle\.loads?|yaml\.load|jsonpickle\.decode|unserialize)\s*\("),
        description="Unsafe deserialization can execute attacker-supplied code during object reconstruction.",
    ),
    Rule(
        identifier="insecure-deserialization-java",
        vulnerability_type="Insecure Deserialization",
        severity="CRITICAL",
        owasp_category="A08 Software & Data Integrity Failures",
        pattern=re.compile(r"(?i)\b(?:ObjectInputStream|BinaryFormatter)\b"),
        description="Object deserialization without strict validation can trigger remote code execution.",
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


def initial_confidence_for_severity(severity: str) -> int:
    normalized = str(severity).upper()
    return STATISTICAL_CONFIDENCE.get(normalized, 60)


class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(self, lines: Sequence[str], filename: str) -> None:
        self.lines = list(lines)
        self.filename = filename
        self.findings: list[dict[str, object]] = []
        self.tainted_names: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous_taint = set(self.tainted_names)
        for argument in node.args.args:
            if _name_suggests_user_input(argument.arg):
                self.tainted_names.add(argument.arg)
        self.generic_visit(node)
        self.tainted_names = previous_taint

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        target_names = [name for target in node.targets for name in _extract_target_names(target)]

        if any(SECRET_NAME_PATTERN.search(name) for name in target_names) and _constant_string(node.value):
            self._add_finding(
                node,
                rule_id="py-ast-hardcoded-secret",
                vulnerability_type="Hardcoded Secret",
                severity="HIGH",
                owasp_category="A07 Identification & Authentication Failures",
                description="Python AST analysis found a constant credential-like assignment.",
            )

        if self._expr_is_tainted(node.value):
            self.tainted_names.update(target_names)

        if self._expr_contains_sql_build(node.value) and self._expr_is_tainted(node.value):
            self._add_finding(
                node,
                rule_id="py-ast-sql-build",
                vulnerability_type="SQL Injection",
                severity="HIGH",
                owasp_category="A03 Injection",
                description="Python AST analysis found a SQL statement built from tainted input.",
            )

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        target_names = _extract_target_names(node.target)
        if any(SECRET_NAME_PATTERN.search(name) for name in target_names) and node.value and _constant_string(node.value):
            self._add_finding(
                node,
                rule_id="py-ast-hardcoded-secret",
                vulnerability_type="Hardcoded Secret",
                severity="HIGH",
                owasp_category="A07 Identification & Authentication Failures",
                description="Python AST analysis found a constant credential-like assignment.",
            )
        if node.value and self._expr_is_tainted(node.value):
            self.tainted_names.update(target_names)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        dotted_name = _call_name(node)
        first_arg = node.args[0] if node.args else None

        if dotted_name in {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"}:
            shell_true = any(keyword.arg == "shell" and _literal_truthy(keyword.value) for keyword in node.keywords)
            if shell_true or (first_arg is not None and self._expr_is_tainted(first_arg)):
                self._add_finding(
                    node,
                    rule_id="py-ast-command-injection",
                    vulnerability_type="Command Injection",
                    severity="CRITICAL",
                    owasp_category="A03 Injection",
                    description="Python AST analysis found a shell execution sink reachable with tainted input.",
                )

        if dotted_name.endswith("execute") or dotted_name.endswith("query"):
            if first_arg is not None and (self._expr_contains_sql_build(first_arg) or self._expr_is_tainted(first_arg)):
                self._add_finding(
                    node,
                    rule_id="py-ast-sql-execute",
                    vulnerability_type="SQL Injection",
                    severity="HIGH",
                    owasp_category="A03 Injection",
                    description="Python AST analysis found a database execution sink using a tainted statement.",
                )

        if dotted_name in {"hashlib.md5", "hashlib.sha1"}:
            self._add_finding(
                node,
                rule_id="py-ast-weak-crypto",
                vulnerability_type="Weak Cryptography",
                severity="MEDIUM",
                owasp_category="A02 Cryptographic Failures",
                description="Python AST analysis found usage of a weak cryptographic hash.",
            )

        if dotted_name in {"pickle.load", "pickle.loads", "yaml.load", "jsonpickle.decode"}:
            self._add_finding(
                node,
                rule_id="py-ast-deserialization",
                vulnerability_type="Insecure Deserialization",
                severity="CRITICAL",
                owasp_category="A08 Software & Data Integrity Failures",
                description="Python AST analysis found unsafe deserialization of untrusted data.",
            )

        if dotted_name in {"requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen"} and first_arg is not None:
            if self._expr_is_tainted(first_arg):
                self._add_finding(
                    node,
                    rule_id="py-ast-ssrf",
                    vulnerability_type="Server-Side Request Forgery (SSRF)",
                    severity="HIGH",
                    owasp_category="A10 Server Side Request Forgery",
                    description="Python AST analysis found an outbound request sink using a tainted URL.",
                )
            elif _http_literal(first_arg):
                self._add_finding(
                    node,
                    rule_id="py-ast-insecure-http",
                    vulnerability_type="Insecure API Call",
                    severity="MEDIUM",
                    owasp_category="A02 Cryptographic Failures",
                    description="Python AST analysis found an HTTP request without transport encryption.",
                )

        if dotted_name == "open" and first_arg is not None and self._expr_is_tainted(first_arg):
            self._add_finding(
                node,
                rule_id="py-ast-unsafe-file",
                vulnerability_type="Unsafe File Handling",
                severity="HIGH",
                owasp_category="A05 Security Misconfiguration",
                description="Python AST analysis found a file operation using a tainted path.",
            )

        self.generic_visit(node)

    def _expr_is_tainted(self, expr: ast.AST | None) -> bool:
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in self.tainted_names or _name_suggests_user_input(expr.id)
        if isinstance(expr, ast.Attribute):
            return _attribute_name(expr) in {"request", "req", "query", "params", "body", "form", "url"}
        if isinstance(expr, ast.Subscript):
            return self._expr_is_tainted(expr.value)
        if isinstance(expr, ast.BinOp):
            return self._expr_is_tainted(expr.left) or self._expr_is_tainted(expr.right)
        if isinstance(expr, ast.JoinedStr):
            return any(self._expr_is_tainted(value.value) for value in expr.values if isinstance(value, ast.FormattedValue))
        if isinstance(expr, ast.Call):
            call_name = _call_name(expr)
            if call_name == "input":
                return True
            return any(self._expr_is_tainted(argument) for argument in expr.args)
        if isinstance(expr, ast.Dict):
            return any(self._expr_is_tainted(value) for value in expr.values)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_is_tainted(element) for element in expr.elts)
        return False

    def _expr_contains_sql_build(self, expr: ast.AST | None) -> bool:
        if expr is None:
            return False
        if _constant_string(expr) and SQL_KEYWORD_PATTERN.search(_constant_string(expr) or ""):
            return True
        if isinstance(expr, ast.BinOp):
            return self._expr_contains_sql_build(expr.left) or self._expr_contains_sql_build(expr.right)
        if isinstance(expr, ast.JoinedStr):
            string_parts = [value.value for value in expr.values if isinstance(value, ast.Constant) and isinstance(value.value, str)]
            return any(SQL_KEYWORD_PATTERN.search(part) for part in string_parts)
        if isinstance(expr, ast.Call):
            if _call_name(expr).endswith("format"):
                return any(self._expr_contains_sql_build(argument) for argument in expr.args[:1])
        return False

    def _add_finding(
        self,
        node: ast.AST,
        *,
        rule_id: str,
        vulnerability_type: str,
        severity: str,
        owasp_category: str,
        description: str,
    ) -> None:
        line_number = int(getattr(node, "lineno", 1))
        snippet = self.lines[line_number - 1].strip() if 0 < line_number <= len(self.lines) else ""
        self.findings.append(
            {
                "line": line_number,
                "type": vulnerability_type,
                "severity": severity,
                "owasp_category": owasp_category,
                "snippet": snippet,
                "matched_text": snippet,
                "filename": self.filename or "pasted-code",
                "language": "python",
                "rule_id": rule_id,
                "description": description,
                "detection_method": "python-ast",
            }
        )


def _call_name(node: ast.Call) -> str:
    return _attribute_name(node.func)


def _attribute_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _attribute_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _extract_target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for element in node.elts for name in _extract_target_names(element)]
    return []


def _constant_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_truthy(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and bool(node.value)


def _http_literal(node: ast.AST | None) -> bool:
    literal = _constant_string(node)
    return bool(literal and literal.startswith("http://"))


def _name_suggests_user_input(name: str) -> bool:
    lowered = name.lower()
    suspicious_fragments = ("user", "input", "request", "req", "query", "param", "body", "path", "file", "url", "name")
    return any(fragment in lowered for fragment in suspicious_fragments)


def _contains_user_input_reference(line: str) -> bool:
    lowered = line.lower()
    return any(token in lowered for token in USER_INPUT_TOKENS)


def _regex_findings(code: str, filename: str | None = None, language: str | None = None) -> list[dict[str, object]]:
    normalized_language = infer_language(filename=filename, language=language)
    lines = code.splitlines()
    findings: list[dict[str, object]] = []

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for rule in RULES:
            match = rule.pattern.search(line)
            if not match:
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
                    "detection_method": "regex",
                }
            )

    return findings


def _python_ast_findings(code: str, filename: str) -> list[dict[str, object]]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    visitor = PythonSecurityVisitor(code.splitlines(), filename)
    visitor.visit(tree)
    return visitor.findings


def _javascript_flow_findings(code: str, filename: str, language: str) -> list[dict[str, object]]:
    lines = code.splitlines()
    findings: list[dict[str, object]] = []
    tainted_names: set[str] = set()
    assignment_pattern = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)")

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        assignment_match = assignment_pattern.search(stripped)
        if assignment_match:
            variable_name = assignment_match.group(1)
            expression = assignment_match.group(2)
            if _contains_user_input_reference(expression) or any(name in expression for name in tainted_names):
                tainted_names.add(variable_name)

        if "innerHTML" in stripped or "dangerouslySetInnerHTML" in stripped:
            if any(name in stripped for name in tainted_names) or _contains_user_input_reference(stripped):
                findings.append(
                    _build_flow_finding(
                        line_number=line_number,
                        stripped=stripped,
                        filename=filename,
                        language=language,
                        rule_id="js-flow-xss",
                        vulnerability_type="Cross Site Scripting (XSS)",
                        severity="HIGH",
                        owasp_category="A03 Injection",
                        description="JavaScript flow analysis found untrusted content flowing into an HTML rendering sink.",
                        detection_method="javascript-flow",
                    )
                )

        if any(keyword in stripped for keyword in ("exec(", "execSync(", "spawn(", "spawnSync(")):
            if any(name in stripped for name in tainted_names) or _contains_user_input_reference(stripped):
                findings.append(
                    _build_flow_finding(
                        line_number=line_number,
                        stripped=stripped,
                        filename=filename,
                        language=language,
                        rule_id="js-flow-command",
                        vulnerability_type="Command Injection",
                        severity="CRITICAL",
                        owasp_category="A03 Injection",
                        description="JavaScript flow analysis found untrusted input reaching a command execution sink.",
                        detection_method="javascript-flow",
                    )
                )

        if any(keyword in stripped for keyword in ("fetch(", "axios.get(", "axios.post(")):
            if any(name in stripped for name in tainted_names) or _contains_user_input_reference(stripped):
                findings.append(
                    _build_flow_finding(
                        line_number=line_number,
                        stripped=stripped,
                        filename=filename,
                        language=language,
                        rule_id="js-flow-ssrf",
                        vulnerability_type="Server-Side Request Forgery (SSRF)",
                        severity="HIGH",
                        owasp_category="A10 Server Side Request Forgery",
                        description="JavaScript flow analysis found a tainted URL reaching an outbound request call.",
                        detection_method="javascript-flow",
                    )
                )

        if any(keyword in stripped for keyword in ("readFile(", "readFileSync(", "writeFile(", "writeFileSync(")):
            if any(name in stripped for name in tainted_names) or _contains_user_input_reference(stripped):
                findings.append(
                    _build_flow_finding(
                        line_number=line_number,
                        stripped=stripped,
                        filename=filename,
                        language=language,
                        rule_id="js-flow-file",
                        vulnerability_type="Unsafe File Handling",
                        severity="HIGH",
                        owasp_category="A05 Security Misconfiguration",
                        description="JavaScript flow analysis found a tainted path reaching a file system sink.",
                        detection_method="javascript-flow",
                    )
                )

        if SQL_KEYWORD_PATTERN.search(stripped) and (any(name in stripped for name in tainted_names) or "${" in stripped):
            findings.append(
                _build_flow_finding(
                    line_number=line_number,
                    stripped=stripped,
                    filename=filename,
                    language=language,
                    rule_id="js-flow-sql",
                    vulnerability_type="SQL Injection",
                    severity="HIGH",
                    owasp_category="A03 Injection",
                    description="JavaScript flow analysis found a SQL string constructed from runtime input.",
                    detection_method="javascript-flow",
                )
            )

    return findings


def _build_flow_finding(
    *,
    line_number: int,
    stripped: str,
    filename: str,
    language: str,
    rule_id: str,
    vulnerability_type: str,
    severity: str,
    owasp_category: str,
    description: str,
    detection_method: str,
) -> dict[str, object]:
    return {
        "line": line_number,
        "type": vulnerability_type,
        "severity": severity,
        "owasp_category": owasp_category,
        "snippet": stripped,
        "matched_text": stripped,
        "filename": filename,
        "language": language,
        "rule_id": rule_id,
        "description": description,
        "detection_method": detection_method,
    }


def _is_suppressed(finding: dict[str, object], filename: str, config_path_patterns: Sequence[str], suppressed_rule_ids: Sequence[str], suppressed_types: Sequence[str]) -> bool:
    if finding.get("rule_id") in suppressed_rule_ids:
        return True
    if finding.get("type") in suppressed_types:
        return True
    normalized_filename = filename.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized_filename, pattern) for pattern in config_path_patterns)


def _merge_findings(findings: Sequence[dict[str, object]], filename: str) -> list[dict[str, object]]:
    merged: dict[tuple[object, ...], dict[str, object]] = {}

    for finding in findings:
        key = (
            filename or finding.get("filename") or "pasted-code",
            finding.get("line"),
            finding.get("type"),
            finding.get("snippet"),
        )
        entry = merged.get(key)
        if not entry:
            base_confidence = initial_confidence_for_severity(str(finding.get("severity", "LOW")))
            merged[key] = {
                **finding,
                "rule_ids": [finding.get("rule_id")],
                "signals": [finding.get("description")],
                "detection_methods": [finding.get("detection_method", "regex")],
                "confidence": base_confidence,
            }
            continue

        rule_ids = set(str(item) for item in entry.get("rule_ids", []))
        rule_ids.add(str(finding.get("rule_id")))
        entry["rule_ids"] = sorted(rule_ids)

        signals = set(str(item) for item in entry.get("signals", []))
        signals.add(str(finding.get("description")))
        entry["signals"] = sorted(signals)

        methods = set(str(item) for item in entry.get("detection_methods", []))
        methods.add(str(finding.get("detection_method", "regex")))
        entry["detection_methods"] = sorted(methods)

        entry["confidence"] = min(
            99,
            max(int(entry.get("confidence", 60)), initial_confidence_for_severity(str(entry.get("severity", "LOW"))))
            + (4 * (len(methods) - 1)),
        )

    return sorted(
        merged.values(),
        key=lambda item: (
            str(item.get("filename", "")),
            int(item["line"]),
            SEVERITY_RANK.get(str(item["severity"]).upper(), 99),
            str(item["type"]),
        ),
    )


def scan_code_with_metadata(code: str, filename: str | None = None, language: str | None = None) -> dict[str, object]:
    normalized_language = infer_language(filename=filename, language=language)
    normalized_filename = filename or "pasted-code"
    config = load_project_config()

    raw_findings = _regex_findings(code=code, filename=normalized_filename, language=normalized_language)
    if normalized_language == "python" and config.prefer_python_ast:
        raw_findings.extend(_python_ast_findings(code=code, filename=normalized_filename))
    if normalized_language in {"javascript", "typescript"}:
        raw_findings.extend(_javascript_flow_findings(code=code, filename=normalized_filename, language=normalized_language))

    merged_findings = _merge_findings(raw_findings, normalized_filename)
    filtered_findings: list[dict[str, object]] = []
    suppressed_count = 0

    for finding in merged_findings:
        if _is_suppressed(
            finding,
            normalized_filename,
            config.suppress_paths,
            config.suppress_rule_ids,
            config.suppress_types,
        ):
            suppressed_count += 1
            continue
        filtered_findings.append(finding)

    truncated_count = max(0, len(filtered_findings) - config.max_findings_per_file)
    filtered_findings = filtered_findings[: config.max_findings_per_file]

    return {
        "findings": filtered_findings,
        "suppressed_count": suppressed_count,
        "truncated_count": truncated_count,
        "config_path": config.config_path,
    }


def analyze_code(code: str, filename: str | None = None, language: str | None = None) -> list[dict[str, object]]:
    return list(scan_code_with_metadata(code=code, filename=filename, language=language)["findings"])


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
    detection_methods = Counter(str(method) for item in findings or [] for method in item.get("detection_methods", []))

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
    average_confidence = round(
        sum(int(item.get("confidence", initial_confidence_for_severity(str(item.get("severity", "LOW"))))) for item in findings or [])
        / max(len(findings or []), 1),
        2,
    )

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
        "average_confidence": average_confidence if findings else 0,
        "detection_methods": dict(detection_methods),
    }


def merge_code_statistics(statistics: Sequence[dict[str, object]]) -> dict[str, object]:
    stats_list = list(statistics)
    language_counts = Counter(str(item.get("language", "plaintext")) for item in stats_list)
    detection_method_counts = Counter(
        method for item in stats_list for method, count in dict(item.get("detection_methods", {})).items() for _ in range(int(count))
    )
    total_lines = sum(int(item.get("total_lines", 0)) for item in stats_list)
    non_empty_lines = sum(int(item.get("non_empty_lines", 0)) for item in stats_list)
    suspicious_lines = sum(int(item.get("suspicious_lines", 0)) for item in stats_list)
    comment_lines = sum(int(item.get("comment_lines", 0)) for item in stats_list)
    import_lines = sum(int(item.get("import_lines", 0)) for item in stats_list)
    function_count = sum(int(item.get("function_count", 0)) for item in stats_list)
    class_count = sum(int(item.get("class_count", 0)) for item in stats_list)
    suspicious_density = round((suspicious_lines / max(non_empty_lines, 1)) * 100, 2)
    average_confidence = round(
        sum(float(item.get("average_confidence", 0)) for item in stats_list) / max(len(stats_list), 1),
        2,
    )

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
        "average_confidence": average_confidence if stats_list else 0,
        "detection_methods": dict(detection_method_counts),
    }
