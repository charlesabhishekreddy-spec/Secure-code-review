# CodeSentinel

CodeSentinel is an AI-assisted secure code review platform that scans source code for OWASP Top 10 aligned vulnerabilities, explains the risk in plain English, and recommends patched replacements.

The review flow is intentionally split into three stages:

1. Statistical pattern analysis using deterministic static-analysis rules.
2. Gemini AI validation for contextual explanation, confidence, and remediation.
3. OWASP Top 10 correlation plus weighted security scoring.

To keep scan latency reasonable on larger repositories, stage 2 uses batched Gemini reviews and caps AI validation to
the highest-priority findings by default.

Recent hardening in this build adds:

- AST-backed Python checks plus JavaScript/TypeScript flow heuristics
- Project-level suppressions via `.codesentinel.yml`
- Gemini snippet redaction and local AI response caching
- Async GitHub repository scan jobs with polling and repo-result cache
- Optional API token protection, in-memory rate limiting, and JSON request logging
- Monaco markers, result filters, secure patch diff view, and local scan history comparison

## Stack

- Frontend: React, Vite, TailwindCSS, Monaco Editor
- Backend: FastAPI
- Scanner: Regex and pattern-based static analysis
- AI engine: Gemini-primary review stage with deterministic local fallback

## Project Structure

```text
codesentinel/
  backend/
    ai_engine.py
    cache_store.py
    jobs.py
    main.py
    project_config.py
    review_pipeline.py
    scanner.py
    security_score.py
    tests/
    requirements.txt
  demo/
    insecure_demo.py
    insecure_demo.js
    insecure_demo.java
  frontend/
    index.html
    package.json
    postcss.config.js
    tailwind.config.js
    vite.config.js
    src/
      api/
      components/
      context/
      pages/
```

## Backend Setup

```bash
cd backend
python -m venv .venv --without-pip
python -m pip --python .\.venv install --upgrade pip setuptools wheel
python -m pip --python .\.venv install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload --port 8000
```

If `.\.venv` already exists from a partial run, you can skip recreation and start at the first `python -m pip --python .\.venv ...` command.

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_BASE_URL=http://127.0.0.1:8000` if your API runs on a different host.

Copy `backend/.env.example` to `backend/.env` and `frontend/.env.example` to `frontend/.env` if you want to customize defaults.

## Optional AI Enrichment

Gemini is the primary AI review stage. If no Gemini key is configured, the backend falls back to deterministic local guidance and marks findings as needing manual review. To enable Gemini-backed enrichment, set:

```bash
CODESENTINEL_AI_PROVIDER=gemini
GEMINI_API_KEY=your_key
GEMINI_MODEL=gemini-2.5-flash
CODESENTINEL_GEMINI_BATCH_SIZE=8
CODESENTINEL_MAX_AI_FINDINGS=24
```

Performance tuning:

- `CODESENTINEL_GEMINI_BATCH_SIZE`: number of findings reviewed per Gemini request
- `CODESENTINEL_MAX_AI_FINDINGS`: maximum number of findings sent to Gemini per scan
- `CODESENTINEL_ENABLE_AI_CACHE`: reuse prior Gemini reviews for matching sanitized snippets
- findings above the AI cap still appear in the report, but use deterministic local remediation so scans stay fast

Operational controls:

- `CODESENTINEL_API_TOKEN`: require `Authorization: Bearer <token>` on API calls
- `CODESENTINEL_RATE_LIMIT_WINDOW_SECONDS` and `CODESENTINEL_RATE_LIMIT_MAX_REQUESTS`: simple in-memory rate limiting
- `CODESENTINEL_ENABLE_REPO_CACHE` and `CODESENTINEL_REPO_CACHE_TTL_SECONDS`: cache GitHub scan results for repeat scans
- `CODESENTINEL_LOG_LEVEL`: control backend JSON request log verbosity

## API Endpoints

- `POST /scan`
- `POST /upload`
- `POST /scan-github`
- `POST /scan-github/jobs`
- `GET /scan-jobs/{job_id}`
- `GET /health`

## GitHub Repository Scan Notes

- Supported repo URL formats:
  - `https://github.com/owner/repo`
  - `https://github.com/owner/repo.git`
  - `https://github.com/owner/repo/tree/main`
- You can also provide an explicit branch in the scanner UI.
- The frontend now uses the async job endpoints for repository scans and polls progress until completion.
- Repository scans ignore common build and dependency folders such as `node_modules`, `dist`, `build`, `vendor`, and `.venv`.
- If GitHub rate-limits anonymous requests, add `GITHUB_TOKEN` to `backend/.env`.
- Repeat scans of the same repository branch can be served from the local repo cache until the TTL expires.

## Response Highlights

Each scan response includes:

- `review_stages`: stage-by-stage execution summaries
- `statistics`: stage 1 source metrics and suspicious-density data
- `owasp_summary`: stage 3 category totals
- `vulnerabilities[*].review_pipeline`: per-finding stage trace
- `vulnerabilities[*].rule_ids` and `vulnerabilities[*].detection_methods`: evidence attached to each finding

## Demo Files

Use the samples in `demo/` to verify SQL injection, command injection, XSS, hardcoded secrets, weak crypto, unsafe file handling, and insecure deserialization detections.

## Tests

```bash
cd backend
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
```
