from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import unquote, urlparse
from zipfile import BadZipFile, ZipFile

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
SUPPORTED_REPO_EXTENSIONS = ", ".join(sorted(SUPPORTED_EXTENSIONS))
IGNORED_REPO_SEGMENTS = {
    ".git",
    ".github",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "venv",
    "vendor",
}

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


def _parse_github_url(repo_url: str, explicit_branch: str | None = None) -> tuple[str, str, str | None]:
    parsed = urlparse(repo_url.strip())
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise HTTPException(status_code=400, detail="Provide a valid GitHub repository URL.")

    parts = [unquote(part) for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Repository URL must include both owner and repository name.")

    owner = parts[0].strip()
    repo = parts[1].strip()
    if repo.endswith(".git"):
        repo = repo[:-4]

    if not owner or not repo:
        raise HTTPException(status_code=400, detail="Repository URL must include both owner and repository name.")

    branch = explicit_branch.strip() if explicit_branch and explicit_branch.strip() else None

    if len(parts) > 2:
        if parts[2] == "tree" and len(parts) >= 4:
            branch = "/".join(parts[3:])
        elif parts[2] not in {"tree"}:
            raise HTTPException(
                status_code=400,
                detail="Use a repository URL like https://github.com/owner/repo or a branch URL like /tree/main.",
            )

    return owner, repo, branch


def _raise_github_error(response: httpx.Response, context: str) -> None:
    if response.status_code == 404:
        raise HTTPException(status_code=404, detail=f"GitHub {context} was not found.")

    if response.status_code == 403:
        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining == "0":
            raise HTTPException(
                status_code=429,
                detail="GitHub API rate limit reached. Add GITHUB_TOKEN in backend/.env or retry later.",
            )
        raise HTTPException(status_code=403, detail=f"GitHub denied the {context} request.")

    raise HTTPException(
        status_code=502,
        detail=f"GitHub {context} request failed with status {response.status_code}.",
    )


async def _fetch_default_branch(client: httpx.AsyncClient, owner: str, repo: str, headers: dict[str, str]) -> str | None:
    try:
        metadata_response = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach GitHub metadata service: {exc!s}") from exc

    if metadata_response.is_success:
        default_branch = metadata_response.json().get("default_branch")
        return str(default_branch) if default_branch else None

    if metadata_response.status_code == 404:
        raise HTTPException(status_code=404, detail="GitHub repository was not found.")

    if metadata_response.status_code == 403:
        return None

    _raise_github_error(metadata_response, "repository metadata")
    return None


async def _download_github_archive(owner: str, repo: str, branch: str | None = None) -> tuple[bytes, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "CodeSentinel/1.0",
    }
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        candidate_branches: list[str] = []
        if branch:
            candidate_branches.append(branch)
        else:
            default_branch = await _fetch_default_branch(client, owner, repo, headers)
            if default_branch:
                candidate_branches.append(default_branch)
            for fallback_branch in ("main", "master"):
                if fallback_branch not in candidate_branches:
                    candidate_branches.append(fallback_branch)

        last_not_found = False
        for selected_branch in candidate_branches:
            try:
                archive_response = await client.get(
                    f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{selected_branch}",
                    headers=headers,
                )
            except httpx.RequestError as exc:
                raise HTTPException(status_code=502, detail=f"Could not download the GitHub repository archive: {exc!s}") from exc

            if archive_response.is_success:
                return archive_response.content, str(selected_branch)
            if archive_response.status_code == 404:
                last_not_found = True
                continue
            _raise_github_error(archive_response, "repository archive")

        if last_not_found:
            raise HTTPException(
                status_code=404,
                detail="Repository branch was not found. Provide a valid branch or use a /tree/<branch> GitHub URL.",
            )

        raise HTTPException(status_code=502, detail="Could not determine a downloadable GitHub branch archive.")


def _is_ignored_repo_path(filename: str) -> bool:
    parts = {part.lower() for part in Path(filename).parts}
    return any(part in IGNORED_REPO_SEGMENTS for part in parts)


def _collect_archive_files(archive_bytes: bytes) -> tuple[list[dict[str, str]], int]:
    files: list[dict[str, str]] = []
    scanned_files = 0
    total_bytes = 0

    try:
        with ZipFile(BytesIO(archive_bytes)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue

                if _is_ignored_repo_path(member.filename):
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
    except BadZipFile as exc:
        raise HTTPException(status_code=502, detail="GitHub returned an invalid repository archive.") from exc

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
    owner, repo, branch = _parse_github_url(payload.repo_url, payload.branch)
    archive_bytes, resolved_branch = await _download_github_archive(owner, repo, branch)
    files, scanned_files = _collect_archive_files(archive_bytes)
    if not files:
        raise HTTPException(
            status_code=422,
            detail=f"No supported source files were found in the repository. Supported extensions: {SUPPORTED_REPO_EXTENSIONS}.",
        )
    return review_bundle(
        files=files,
        source={
            "filename": f"{owner}/{repo}",
            "language": "multi-file",
            "repository": payload.repo_url,
            "branch": resolved_branch or branch,
            "scanned_files": scanned_files,
        },
        engine=engine,
    )
