# CodeSentinel

CodeSentinel is an AI-assisted secure code review platform that scans source code for OWASP Top 10 aligned vulnerabilities, explains the risk in plain English, and recommends patched replacements.

## Stack

- Frontend: React, Vite, TailwindCSS, Monaco Editor
- Backend: FastAPI
- Scanner: Regex and pattern-based static analysis
- AI engine: Local explanation generator with optional Gemini-backed enrichment

## Project Structure

```text
codesentinel/
  backend/
    ai_engine.py
    main.py
    scanner.py
    security_score.py
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

The backend works offline with deterministic explanations. To enable Gemini-backed enrichment, set:

```bash
set GEMINI_API_KEY=your_key
set CODESENTINEL_AI_PROVIDER=gemini
set GEMINI_MODEL=gemini-2.5-flash
```

## API Endpoints

- `POST /scan`
- `POST /upload`
- `POST /scan-github`
- `GET /health`

## Demo Files

Use the samples in `demo/` to verify SQL injection, command injection, XSS, hardcoded secrets, weak crypto, unsafe file handling, and insecure deserialization detections.
