from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import re
from typing import Any
from zipfile import ZipFile

import httpx
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from ai_engine import ExplanationEngine
from review_pipeline import review_bundle, review_source
from scanner import SUPPORTED_EXTENSIONS

load_dotenv()

app = FastAPI(
    title="CodeSentinel API",
    version="1.0.0",
    description="AI-powered secure code review API for OWASP Top 10 aligned findings.",
)

allowed_origins = [origin.strip() for origin in os.getenv("CODESENTINEL_CORS_ORIGINS", "*").split(",") if origin.strip()]
configured_origins = allowed_origins or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins,
    allow_credentials=configured_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_CODE_SIZE = int(os.getenv("CODESENTINEL_MAX_CODE_BYTES", "200000"))
MAX_REPO_FILES = int(os.getenv("CODESENTINEL_MAX_REPO_FILES", "200"))
MAX_REPO_TOTAL_BYTES = int(os.getenv("CODESENTINEL_MAX_REPO_BYTES", "3000000"))

engine = ExplanationEngine()


class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1)
    filename: str | None = None
    language: str | None = None


class GitHubScanRequest(BaseModel):
    repo_url: str = Field(..., min_length=1)
    branch: str | None = None


class VulnerabilityResponse(BaseModel):
    line: int
    type: str
    severity: str
    owasp_category: str
    explanation: str
    attack_scenario: str
    fix: str
    patched_code: str
    snippet: str
    filename: str
    language: str
    review_decision: str
    confidence: int
    ai_provider: str
    review_pipeline: dict[str, Any]


class ScanResponse(BaseModel):
    security_score: int
    total_vulnerabilities: int
    severity_breakdown: dict[str, int]
    total_penalty: int
    vulnerabilities: list[VulnerabilityResponse]
    statistics: dict[str, Any]
    owasp_summary: dict[str, int]
    review_stages: list[dict[str, Any]]
    source: dict[str, Any]


def _scan_payload(code: str, filename: str | None = None, language: str | None = None) -> dict[str, Any]:
    if len(code.encode("utf-8")) > MAX_CODE_SIZE:
        raise HTTPException(status_code=413, detail="Submitted code exceeds the maximum allowed size.")

    return review_source(code=code, filename=filename, language=language, engine=engine)


def _parse_github_url(repo_url: str) -> tuple[str, str]:
    match = re.match(r"^https?://github\.com/([^/\s]+)/([^/\s#]+?)(?:\.git)?/?$", repo_url.strip())
    if not match:
        raise HTTPException(status_code=400, detail="Provide a valid public GitHub repository URL.")
    owner, repo = match.groups()
    return owner, repo


async def _download_github_archive(owner: str, repo: str, branch: str | None = None) -> tuple[bytes, str]:
    headers = {"Accept": "application/vnd.github+json"}
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        selected_branch = branch
        if not selected_branch:
            metadata_response = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
            if metadata_response.status_code == 404:
                raise HTTPException(status_code=404, detail="GitHub repository was not found.")
            metadata_response.raise_for_status()
            selected_branch = metadata_response.json().get("default_branch")

        archive_response = await client.get(
            f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{selected_branch}",
            headers=headers,
        )
        if archive_response.status_code == 404:
            raise HTTPException(status_code=404, detail="Repository branch was not found.")
        archive_response.raise_for_status()
        return archive_response.content, str(selected_branch)


def _collect_archive_files(archive_bytes: bytes) -> tuple[list[dict[str, str]], int]:
    files: list[dict[str, str]] = []
    scanned_files = 0
    total_bytes = 0

    with ZipFile(BytesIO(archive_bytes)) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue

            extension = Path(member.filename).suffix.lower()
            if extension not in SUPPORTED_EXTENSIONS:
                continue

            if scanned_files >= MAX_REPO_FILES:
                break

            if member.file_size > MAX_CODE_SIZE:
                continue

            if total_bytes + member.file_size > MAX_REPO_TOTAL_BYTES:
                continue

            payload = archive.read(member)
            total_bytes += len(payload)

            try:
                decoded = payload.decode("utf-8")
            except UnicodeDecodeError:
                decoded = payload.decode("utf-8", errors="ignore")

            files.append({"filename": member.filename, "code": decoded})
            scanned_files += 1

    return files, scanned_files


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan_code(payload: ScanRequest) -> dict[str, Any]:
    return _scan_payload(code=payload.code, filename=payload.filename, language=payload.language)


@app.post("/upload", response_model=ScanResponse)
async def upload_code(file: UploadFile = File(...)) -> dict[str, Any]:
    extension = Path(file.filename or "").suffix.lower()
    if extension not in {".py", ".js", ".java", ".jsx", ".ts", ".tsx"}:
        raise HTTPException(status_code=400, detail="Only .py, .js, .jsx, .ts, .tsx, and .java files are supported.")

    contents = await file.read()
    if len(contents) > MAX_CODE_SIZE:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds the maximum allowed size.")

    try:
        decoded = contents.decode("utf-8")
    except UnicodeDecodeError:
        decoded = contents.decode("utf-8", errors="ignore")

    return _scan_payload(code=decoded, filename=file.filename)


@app.post("/scan-github", response_model=ScanResponse)
async def scan_github_repository(payload: GitHubScanRequest) -> dict[str, Any]:
    owner, repo = _parse_github_url(payload.repo_url)
    archive_bytes, resolved_branch = await _download_github_archive(owner, repo, payload.branch)
    files, scanned_files = _collect_archive_files(archive_bytes)
    return review_bundle(
        files=files,
        source={
            "filename": f"{owner}/{repo}",
            "language": "multi-file",
            "repository": payload.repo_url,
            "branch": resolved_branch,
            "scanned_files": scanned_files,
        },
        engine=engine,
    )
