from __future__ import annotations

from collections import Counter
import json
import os
import re
from typing import Any

REVIEW_RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "review_id": {"type": "string"},
        "explanation": {"type": "string"},
        "attack_scenario": {"type": "string"},
        "fix": {"type": "string"},
        "patched_code": {"type": "string"},
        "review_decision": {"type": "string"},
        "confidence": {"type": "integer"},
    },
    "required": [
        "review_id",
        "explanation",
        "attack_scenario",
        "fix",
        "patched_code",
        "review_decision",
        "confidence",
    ],
    "additionalProperties": False,
}

GEMINI_BATCH_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "reviews": {
            "type": "array",
            "items": REVIEW_RESULT_SCHEMA,
        }
    },
    "required": ["reviews"],
    "additionalProperties": False,
}

SEVERITY_PRIORITY = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

FIX_LIBRARY: dict[str, dict[str, str]] = {
    "SQL Injection": {
        "python": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))',
        "javascript": 'const [rows] = await db.execute("SELECT * FROM users WHERE id = ?", [userInput]);',
        "java": 'PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");\nstmt.setString(1, userInput);\nResultSet rs = stmt.executeQuery();',
        "default": "Use a prepared statement or parameterized query so input is bound as data, not executable SQL.",
    },
    "Command Injection": {
        "python": 'subprocess.run(["/usr/bin/id", user_input], check=True, shell=False)',
        "javascript": 'execFile("id", [userInput], { shell: false }, (error, stdout) => {\n  if (error) throw error;\n  console.log(stdout);\n});',
        "java": 'ProcessBuilder processBuilder = new ProcessBuilder("id", userInput);\nProcess process = processBuilder.start();',
        "default": "Avoid shell interpretation. Pass command arguments as a fixed list and validate each allowed value.",
    },
    "Cross Site Scripting (XSS)": {
        "python": 'return templates.TemplateResponse("profile.html", {"request": request, "bio": sanitize_html(user_bio)})',
        "javascript": "<div>{userContent}</div>\n\n// or for raw DOM access\nelement.textContent = userContent;",
        "java": "out.print(StringEscapeUtils.escapeHtml4(userContent));",
        "default": "Render untrusted content as text, or sanitize it with a vetted HTML sanitizer before rendering.",
    },
    "Hardcoded Secret": {
        "python": 'api_key = os.environ["API_KEY"]',
        "javascript": "const apiKey = process.env.API_KEY;",
        "java": 'String apiKey = System.getenv("API_KEY");',
        "default": "Load credentials from environment variables or a managed secrets store instead of source code.",
    },
    "Insecure API Call": {
        "python": 'response = httpx.get("https://api.example.com/v1/users", timeout=10.0)',
        "javascript": 'const response = await fetch("https://api.example.com/v1/users");',
        "java": 'HttpRequest request = HttpRequest.newBuilder()\n    .uri(URI.create("https://api.example.com/v1/users"))\n    .build();',
        "default": "Use HTTPS endpoints and enforce certificate validation for all outbound requests.",
    },
    "Weak Cryptography": {
        "python": 'digest = hashlib.sha256(data.encode("utf-8")).hexdigest()',
        "javascript": 'const digest = crypto.createHash("sha256").update(data).digest("hex");',
        "java": 'MessageDigest digest = MessageDigest.getInstance("SHA-256");',
        "default": "Replace MD5 and SHA-1 with SHA-256 or stronger, or use a dedicated password hashing function for passwords.",
    },
    "Unsafe File Handling": {
        "python": 'safe_root = Path("/srv/app/uploads").resolve()\ncandidate = (safe_root / requested_name).resolve()\nif safe_root not in candidate.parents:\n    raise ValueError("Blocked path traversal")\nwith candidate.open("rb") as handle:\n    data = handle.read()',
        "javascript": 'const safeRoot = path.resolve("/srv/app/uploads");\nconst candidate = path.resolve(safeRoot, requestedName);\nif (!candidate.startsWith(safeRoot)) {\n  throw new Error("Blocked path traversal");\n}\nconst data = await fs.promises.readFile(candidate, "utf8");',
        "java": 'Path safeRoot = Paths.get("/srv/app/uploads").toRealPath();\nPath candidate = safeRoot.resolve(requestedName).normalize();\nif (!candidate.startsWith(safeRoot)) {\n    throw new SecurityException("Blocked path traversal");\n}',
        "default": "Resolve the path against an allow-listed directory and reject any path that escapes the trusted root.",
    },
    "Insecure Deserialization": {
        "python": "data = json.loads(payload)",
        "javascript": "const data = JSON.parse(payload);",
        "java": "ObjectMapper mapper = new ObjectMapper();\nPayload data = mapper.readValue(payload, Payload.class);",
        "default": "Use safe data formats such as JSON and deserialize into explicit schemas instead of arbitrary objects.",
    },
    "Server-Side Request Forgery (SSRF)": {
        "python": 'parsed = urlparse(user_supplied_url)\nif parsed.scheme != "https" or parsed.hostname not in ALLOWLISTED_HOSTS:\n    raise ValueError("Blocked target")\nresponse = httpx.get(user_supplied_url, timeout=5.0)',
        "javascript": 'const parsed = new URL(userSuppliedUrl);\nif (parsed.protocol !== "https:" || !allowlistedHosts.has(parsed.hostname)) {\n  throw new Error("Blocked target");\n}\nconst response = await fetch(parsed.toString());',
        "java": 'URI uri = URI.create(userSuppliedUrl);\nif (!"https".equalsIgnoreCase(uri.getScheme()) || !allowlistedHosts.contains(uri.getHost())) {\n    throw new SecurityException("Blocked target");\n}',
        "default": "Validate the hostname and scheme against a strict allowlist before making outbound requests.",
    },
}

EXPLANATION_LIBRARY: dict[str, dict[str, str]] = {
    "SQL Injection": {
        "explanation": "The application is stitching data into a SQL statement instead of sending it as a bound parameter.",
        "attack": "An attacker can submit a value like `1 OR 1=1` and change which rows are returned or even modify data.",
        "fix": "Use parameterized queries or prepared statements so the database parses the SQL once and treats input as plain data.",
    },
    "Command Injection": {
        "explanation": "The code is invoking an operating system command in a way that can let input change the final command line.",
        "attack": "If a filename or user argument contains shell metacharacters, an attacker can execute arbitrary commands on the host.",
        "fix": "Avoid the shell entirely, validate allowed arguments, and pass command arguments as a fixed array.",
    },
    "Cross Site Scripting (XSS)": {
        "explanation": "The application is rendering untrusted content as HTML or scriptable DOM content.",
        "attack": "A malicious payload such as `<script>fetch('/session')</script>` can run in another user's browser and steal data.",
        "fix": "Render untrusted content as text, or sanitize HTML with a trusted library before injecting it into the page.",
    },
    "Hardcoded Secret": {
        "explanation": "A credential appears to be embedded directly in the codebase.",
        "attack": "If the repository is leaked, shared, or logged, attackers can reuse the secret to access external systems.",
        "fix": "Move credentials into environment variables or a secrets manager and rotate the exposed value.",
    },
    "Insecure API Call": {
        "explanation": "The code is calling an HTTP endpoint without transport encryption.",
        "attack": "Anyone positioned on the network path can read or tamper with the request and response data.",
        "fix": "Switch the endpoint to HTTPS and enforce TLS validation on the client.",
    },
    "Weak Cryptography": {
        "explanation": "The code relies on a hash algorithm that is no longer considered strong for security-sensitive use cases.",
        "attack": "Attackers can exploit collisions or weak resistance to undermine integrity checks or hashed secrets.",
        "fix": "Replace MD5 and SHA-1 with SHA-256 or stronger, or use Argon2, bcrypt, or scrypt for passwords.",
    },
    "Unsafe File Handling": {
        "explanation": "The code appears to open or return files based on user-controlled path input.",
        "attack": "An attacker can try `../../etc/passwd` style traversal payloads to read or overwrite files outside the intended directory.",
        "fix": "Resolve the path against a trusted base directory, normalize it, and reject anything that escapes that directory.",
    },
    "Insecure Deserialization": {
        "explanation": "The application deserializes data into executable or complex objects without strong validation.",
        "attack": "A crafted payload can trigger gadget chains, unsafe constructors, or arbitrary code execution during deserialization.",
        "fix": "Use safe formats like JSON, deserialize into explicit schemas, and reject untrusted binary object payloads.",
    },
    "Server-Side Request Forgery (SSRF)": {
        "explanation": "The server is making outbound requests to a URL that may be influenced by untrusted input.",
        "attack": "An attacker can force the server to call internal services or cloud metadata endpoints that are not public.",
        "fix": "Validate target URLs against a strict allowlist, block private address ranges, and require HTTPS.",
    },
}

LOCAL_CONFIDENCE_CAP = {
    "CRITICAL": 84,
    "HIGH": 78,
    "MEDIUM": 70,
    "LOW": 62,
}


class ExplanationEngine:
    def __init__(self) -> None:
        self.provider = os.getenv("CODESENTINEL_AI_PROVIDER", "gemini").lower()
        self.gemini_api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.gemini_batch_size = max(1, int(os.getenv("CODESENTINEL_GEMINI_BATCH_SIZE", "8")))
        self.max_ai_findings = max(0, int(os.getenv("CODESENTINEL_MAX_AI_FINDINGS", "24")))
        self._gemini_client: Any | None = None

    def enrich_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        reviewed, _stage_meta = self.review_findings(findings)
        return reviewed

    def review_findings(self, findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        reviewed_findings: list[dict[str, Any]] = []
        provider_counts: Counter[str] = Counter()
        decision_counts: Counter[str] = Counter()
        fallback_reasons: Counter[str] = Counter()
        batch_calls = 0

        gemini_results: dict[str, dict[str, str | int]] = {}
        failed_review_ids: set[str] = set()
        skipped_due_to_cap: set[str] = set()

        ai_candidate_ids = self._select_ai_candidate_ids(findings)
        ai_candidate_set = set(ai_candidate_ids)

        if self.provider == "gemini" and self.gemini_api_key and ai_candidate_ids:
            batches = [
                ai_candidate_ids[index:index + self.gemini_batch_size]
                for index in range(0, len(ai_candidate_ids), self.gemini_batch_size)
            ]
            batch_calls = len(batches)

            for batch_ids in batches:
                batch_findings = [(review_id, findings[int(review_id.split("_")[1])]) for review_id in batch_ids]
                batch_results = self._try_gemini_batch(batch_findings)
                if not batch_results:
                    failed_review_ids.update(batch_ids)
                    continue

                gemini_results.update(batch_results)
                missing_ids = set(batch_ids) - set(batch_results)
                failed_review_ids.update(missing_ids)

        if self.max_ai_findings and len(findings) > len(ai_candidate_ids):
            skipped_due_to_cap = {
                self._review_id(index)
                for index, _finding in enumerate(findings)
                if self._review_id(index) not in ai_candidate_set
            }

        for index, finding in enumerate(findings):
            review_id = self._review_id(index)
            provider_used = "local"
            fallback_reason: str | None = None

            if review_id in gemini_results:
                reviewed_finding = self._merge_gemini_review(finding, gemini_results[review_id])
                provider_used = "gemini"
            else:
                if self.provider != "gemini":
                    fallback_reason = "Gemini review is disabled by configuration."
                elif not self.gemini_api_key:
                    fallback_reason = "GEMINI_API_KEY is not configured."
                elif review_id in skipped_due_to_cap:
                    fallback_reason = (
                        f"Skipped Gemini review to keep scan latency bounded to the top {self.max_ai_findings} finding(s)."
                    )
                elif review_id in failed_review_ids:
                    fallback_reason = "Gemini batch review failed or returned an incomplete response."
                else:
                    fallback_reason = "Gemini review was not applied."

                reviewed_finding = self._apply_local_review(finding, fallback_reason)

            reviewed_findings.append(reviewed_finding)
            provider_counts[provider_used] += 1
            decision_counts[str(reviewed_finding["review_decision"])] += 1
            if fallback_reason:
                fallback_reasons[fallback_reason] += 1

        if provider_counts.get("gemini", 0) and provider_counts.get("local", 0):
            status = "completed_with_fallback"
        elif provider_counts.get("gemini", 0):
            status = "completed"
        elif findings:
            status = "fallback"
        else:
            status = "completed"

        summary = (
            f"Primary AI provider: Gemini. Reviewed {len(findings)} finding(s); "
            f"{provider_counts.get('gemini', 0)} with Gemini in {batch_calls} batch call(s) and "
            f"{provider_counts.get('local', 0)} via deterministic fallback."
        )

        return reviewed_findings, {
            "id": "stage_2_gemini_ai_review",
            "name": "Stage 2 - Gemini AI Review",
            "status": status,
            "summary": summary,
            "details": {
                "primary_provider": "gemini",
                "providers_used": dict(provider_counts),
                "decision_breakdown": dict(decision_counts),
                "fallback_reasons": dict(fallback_reasons),
                "model": self.gemini_model,
                "batch_size": self.gemini_batch_size,
                "batch_calls": batch_calls,
                "max_ai_findings": self.max_ai_findings,
            },
        }

    def _select_ai_candidate_ids(self, findings: list[dict[str, Any]]) -> list[str]:
        if self.max_ai_findings <= 0 or not findings:
            return []

        prioritized_indices = sorted(
            range(len(findings)),
            key=lambda index: (
                SEVERITY_PRIORITY.get(str(findings[index].get("severity", "LOW")).upper(), 99),
                -int(findings[index].get("confidence", 0)),
                int(findings[index].get("line", 0)),
                index,
            ),
        )
        selected = prioritized_indices[: self.max_ai_findings]
        return [self._review_id(index) for index in selected]

    def _compact_finding_for_ai(self, review_id: str, finding: dict[str, Any]) -> dict[str, Any]:
        return {
            "review_id": review_id,
            "line": int(finding.get("line", 0)),
            "type": str(finding.get("type", "")),
            "severity": str(finding.get("severity", "")),
            "owasp_category": str(finding.get("owasp_category", "")),
            "filename": str(finding.get("filename", "")),
            "language": str(finding.get("language", "")),
            "snippet": str(finding.get("snippet", "")),
            "description": str(finding.get("description", "")),
        }

    def _apply_local_review(self, finding: dict[str, Any], fallback_reason: str | None) -> dict[str, Any]:
        enriched = finding.copy()
        enriched.update(self._local_explanation(finding))

        review_pipeline = dict(enriched.get("review_pipeline") or {})
        review_pipeline["stage_2"] = {
            "name": "Stage 2 - Gemini AI Review",
            "status": "fallback_applied",
            "provider": "local",
            "confidence": int(enriched.get("confidence", 0)),
            "summary": "Gemini was not used for this finding, so deterministic local guidance was applied.",
            "fallback_reason": fallback_reason,
        }
        enriched["review_pipeline"] = review_pipeline
        enriched["ai_provider"] = "local"
        return enriched

    def _merge_gemini_review(self, finding: dict[str, Any], gemini_result: dict[str, str | int]) -> dict[str, Any]:
        enriched = finding.copy()
        enriched.update(gemini_result)

        review_pipeline = dict(enriched.get("review_pipeline") or {})
        review_pipeline["stage_2"] = {
            "name": "Stage 2 - Gemini AI Review",
            "status": "validated",
            "provider": "gemini",
            "confidence": int(enriched.get("confidence", 0)),
            "summary": "Gemini validated the stage 1 signal and generated contextual remediation guidance.",
            "fallback_reason": None,
        }
        enriched["review_pipeline"] = review_pipeline
        enriched["ai_provider"] = "gemini"
        return enriched

    def _local_explanation(self, finding: dict[str, Any]) -> dict[str, str | int]:
        vulnerability_type = str(finding.get("type", ""))
        language = str(finding.get("language", "default")).lower()
        explanation_entry = EXPLANATION_LIBRARY.get(vulnerability_type, {})
        fix_entry = FIX_LIBRARY.get(vulnerability_type, {})
        severity = str(finding.get("severity", "LOW")).upper()

        patched_code = fix_entry.get(language) or fix_entry.get("default") or "Refactor the code to remove the unsafe pattern."
        fix_text = explanation_entry.get("fix", "Replace the unsafe pattern with a safer implementation.")
        base_confidence = int(finding.get("confidence", 60))
        confidence = min(base_confidence, LOCAL_CONFIDENCE_CAP.get(severity, 60))

        return {
            "explanation": explanation_entry.get(
                "explanation",
                "CodeSentinel found a pattern that is frequently associated with a security weakness.",
            ),
            "attack_scenario": explanation_entry.get(
                "attack",
                "An attacker may be able to abuse this behavior to reach code paths or data you did not intend to expose.",
            ),
            "fix": fix_text,
            "patched_code": patched_code,
            "review_decision": "needs_manual_review",
            "confidence": confidence,
        }

    def _try_gemini_batch(self, batch_findings: list[tuple[str, dict[str, Any]]]) -> dict[str, dict[str, str | int]] | None:
        if not batch_findings:
            return {}

        client = self._get_gemini_client()
        if client is None:
            return None

        try:
            from google.genai import types
        except ImportError:
            return None

        prompt = {
            "task": "Validate a batch of secure code review findings, explain the risk, and propose safe replacements.",
            "instructions": [
                "You are stage 2 in a three-stage application security review system.",
                "Stage 1 has already flagged deterministic security signals.",
                "Return JSON only.",
                "Return one review object for every review_id you are given.",
                "Set review_decision to confirmed when the finding is strongly supported by the snippet.",
                "Set review_decision to needs_manual_review when surrounding context is required.",
                "Set confidence to an integer from 0 to 100.",
            ],
            "findings": [self._compact_finding_for_ai(review_id, finding) for review_id, finding in batch_findings],
        }

        try:
            response = client.models.generate_content(
                model=self.gemini_model,
                contents=json.dumps(prompt),
                config=types.GenerateContentConfig(
                    system_instruction="You are a senior application security engineer. Return strict JSON only.",
                    response_mime_type="application/json",
                    response_json_schema=GEMINI_BATCH_RESPONSE_SCHEMA,
                    temperature=0.1,
                ),
            )
        except Exception:
            return None

        parsed = getattr(response, "parsed", None)
        if isinstance(parsed, dict):
            return self._validate_batch_payload(parsed)

        text = getattr(response, "text", "") or ""
        try:
            parsed = json.loads(text.strip())
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, flags=re.DOTALL)
            if not match:
                return None
            try:
                parsed = json.loads(match.group(0))
            except json.JSONDecodeError:
                return None

        return self._validate_batch_payload(parsed)

    def _validate_batch_payload(self, payload: Any) -> dict[str, dict[str, str | int]] | None:
        if not isinstance(payload, dict):
            return None

        reviews = payload.get("reviews")
        if not isinstance(reviews, list):
            return None

        validated: dict[str, dict[str, str | int]] = {}
        for review in reviews:
            validated_item = self._validate_review_payload(review)
            if not validated_item:
                continue
            review_id = str(review["review_id"])
            validated[review_id] = validated_item

        return validated if validated else None

    def _validate_review_payload(self, payload: Any) -> dict[str, str | int] | None:
        if not isinstance(payload, dict):
            return None

        required_fields = {"review_id", "explanation", "attack_scenario", "fix", "patched_code", "review_decision", "confidence"}
        if not required_fields.issubset(payload):
            return None

        review_decision = str(payload["review_decision"]).strip().lower()
        if review_decision not in {"confirmed", "needs_manual_review"}:
            return None

        try:
            confidence = int(payload["confidence"])
        except (TypeError, ValueError):
            return None

        confidence = max(0, min(confidence, 100))

        return {
            "explanation": str(payload["explanation"]),
            "attack_scenario": str(payload["attack_scenario"]),
            "fix": str(payload["fix"]),
            "patched_code": str(payload["patched_code"]),
            "review_decision": review_decision,
            "confidence": confidence,
        }

    def _get_gemini_client(self) -> Any | None:
        if self._gemini_client is not None:
            return self._gemini_client

        try:
            from google import genai
        except ImportError:
            return None

        self._gemini_client = genai.Client(api_key=self.gemini_api_key)
        return self._gemini_client

    def _review_id(self, index: int) -> str:
        return f"finding_{index}"
