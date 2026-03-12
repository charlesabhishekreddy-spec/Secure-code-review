from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from io import BytesIO
import json
import logging
import os
from pathlib import Path
from threading import Lock
from time import monotonic, perf_counter, time
import re
from typing import Any
from urllib.parse import unquote, urlparse
from uuid import uuid4
from zipfile import BadZipFile, ZipFile

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ai_engine import ExplanationEngine
from cache_store import JsonCacheStore
from jobs import job_store
from review_pipeline import review_bundle, review_source
from scanner import SUPPORTED_EXTENSIONS

load_dotenv()

LOG_LEVEL = os.getenv("CODESENTINEL_LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format="%(message)s")
logger = logging.getLogger("codesentinel.api")

BASE_DIR = Path(__file__).resolve().parent
TMP_DIR = BASE_DIR / ".tmp"
TMP_DIR.mkdir(exist_ok=True)

app = FastAPI(
    title="CodeSentinel API",
    version="1.1.0",
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

API_TOKEN = os.getenv("CODESENTINEL_API_TOKEN", "").strip()
RATE_LIMIT_WINDOW_SECONDS = max(1, int(os.getenv("CODESENTINEL_RATE_LIMIT_WINDOW_SECONDS", "60")))
RATE_LIMIT_MAX_REQUESTS = max(0, int(os.getenv("CODESENTINEL_RATE_LIMIT_MAX_REQUESTS", "45")))
REPO_CACHE_TTL_SECONDS = max(0, int(os.getenv("CODESENTINEL_REPO_CACHE_TTL_SECONDS", "900")))
ENABLE_REPO_CACHE = os.getenv("CODESENTINEL_ENABLE_REPO_CACHE", "true").lower() != "false"

AUTH_EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}
BACKGROUND_SCAN_TASKS: set[asyncio.Task[Any]] = set()
RATE_LIMIT_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
RATE_LIMIT_LOCK = Lock()
REPO_CACHE = JsonCacheStore(TMP_DIR / "repo_scan_cache.json")


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
    rule_ids: list[str] = Field(default_factory=list)
    detection_methods: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    review_pipeline: dict[str, Any]


class ScanResponse(BaseModel):
    security_score: int
    total_vulnerabilities: int
    severity_breakdown: dict[str, int]
    total_penalty: int
    average_confidence: float = 0
    vulnerabilities: list[VulnerabilityResponse]
    statistics: dict[str, Any]
    owasp_summary: dict[str, int]
    review_stages: list[dict[str, Any]]
    source: dict[str, Any]


class ScanJobResponse(BaseModel):
    job_id: str
    status: str
    kind: str
    source: dict[str, Any]
    created_at: str
    updated_at: str
    progress: dict[str, Any]
    result: dict[str, Any] | None = None
    error: str | None = None


def _new_engine() -> ExplanationEngine:
    return ExplanationEngine()


def _scan_payload(code: str, filename: str | None = None, language: str | None = None) -> dict[str, Any]:
    if len(code.encode("utf-8")) > MAX_CODE_SIZE:
        raise HTTPException(status_code=413, detail="Submitted code exceeds the maximum allowed size.")

    return review_source(code=code, filename=filename, language=language, engine=_new_engine())


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


def _repo_cache_key(owner: str, repo: str, branch: str | None) -> str:
    raw = f"{owner}/{repo}:{branch or 'default'}"
    return re.sub(r"[^A-Za-z0-9:_/-]", "_", raw)


def _get_cached_repo_scan(owner: str, repo: str, branch: str | None, repo_url: str) -> dict[str, Any] | None:
    if not ENABLE_REPO_CACHE or REPO_CACHE_TTL_SECONDS <= 0:
        return None

    cached_entry = REPO_CACHE.get(_repo_cache_key(owner, repo, branch))
    if not isinstance(cached_entry, dict):
        return None

    cached_at = float(cached_entry.get("cached_at", 0))
    if (time() - cached_at) > REPO_CACHE_TTL_SECONDS:
        return None

    result = cached_entry.get("result")
    if not isinstance(result, dict):
        return None

    hydrated = json.loads(json.dumps(result))
    hydrated_source = dict(hydrated.get("source") or {})
    hydrated_source["repository"] = repo_url
    hydrated_source["cache_hit"] = True
    hydrated["source"] = hydrated_source
    return hydrated


def _store_cached_repo_scan(owner: str, repo: str, branch: str | None, result: dict[str, Any]) -> None:
    if not ENABLE_REPO_CACHE or REPO_CACHE_TTL_SECONDS <= 0:
        return

    REPO_CACHE.set(
        _repo_cache_key(owner, repo, branch),
        {
            "cached_at": time(),
            "result": result,
        },
    )


def _extract_bearer_token(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.headers.get("X-API-Token", "").strip()


def _consume_rate_limit(request: Request) -> tuple[bool, int]:
    if RATE_LIMIT_MAX_REQUESTS <= 0:
        return True, RATE_LIMIT_MAX_REQUESTS

    forwarded_for = request.headers.get("X-Forwarded-For", "")
    client_key = forwarded_for.split(",")[0].strip() or (request.client.host if request.client else "unknown")
    now = monotonic()

    with RATE_LIMIT_LOCK:
        bucket = RATE_LIMIT_BUCKETS[client_key]
        while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
            return False, 0
        bucket.append(now)
        return True, max(0, RATE_LIMIT_MAX_REQUESTS - len(bucket))


def _schedule_scan_task(coroutine: Any) -> None:
    task = asyncio.create_task(coroutine)
    BACKGROUND_SCAN_TASKS.add(task)
    task.add_done_callback(BACKGROUND_SCAN_TASKS.discard)


async def _scan_github_repository(
    repo_url: str,
    branch: str | None = None,
    *,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    owner, repo, parsed_branch = _parse_github_url(repo_url, branch)

    if progress_callback is not None:
        await progress_callback(stage="cache_lookup", message="Checking repository cache.")
    cached = _get_cached_repo_scan(owner, repo, parsed_branch, repo_url)
    if cached is not None:
        return cached

    if progress_callback is not None:
        await progress_callback(stage="download", message="Downloading repository archive from GitHub.")
    archive_bytes, resolved_branch = await _download_github_archive(owner, repo, parsed_branch)

    if progress_callback is not None:
        await progress_callback(stage="extract", message="Extracting supported source files from the repository archive.")
    files, scanned_files = await asyncio.to_thread(_collect_archive_files, archive_bytes)

    if not files:
        raise HTTPException(
            status_code=422,
            detail=f"No supported source files were found in the repository. Supported extensions: {SUPPORTED_REPO_EXTENSIONS}.",
        )

    if progress_callback is not None:
        await progress_callback(
            stage="review",
            message=f"Reviewing {scanned_files} source file(s) through the three-stage pipeline.",
            scanned_files=scanned_files,
        )

    result = await asyncio.to_thread(
        review_bundle,
        files,
        {
            "filename": f"{owner}/{repo}",
            "language": "multi-file",
            "repository": repo_url,
            "branch": resolved_branch or parsed_branch,
            "scanned_files": scanned_files,
            "cache_hit": False,
        },
        _new_engine(),
    )
    _store_cached_repo_scan(owner, repo, resolved_branch or parsed_branch, result)
    return result


async def _run_github_scan_job(job_id: str, repo_url: str, branch: str | None) -> None:
    async def _progress_callback(*, stage: str, message: str, **details: Any) -> None:
        job_store.update(
            job_id,
            status="running",
            progress={
                "stage": stage,
                "message": message,
                **details,
            },
        )

    try:
        await _progress_callback(stage="queued", message="Repository scan has been queued.")
        result = await _scan_github_repository(repo_url, branch, progress_callback=_progress_callback)
        job_store.update(
            job_id,
            status="completed",
            progress={"stage": "completed", "message": "Repository scan finished successfully."},
            result=result,
            error=None,
        )
    except HTTPException as exc:
        job_store.update(
            job_id,
            status="failed",
            progress={"stage": "failed", "message": "Repository scan failed."},
            error=str(exc.detail),
        )
    except Exception as exc:
        logger.exception("Repository scan job failed")
        job_store.update(
            job_id,
            status="failed",
            progress={"stage": "failed", "message": "Repository scan failed unexpectedly."},
            error=str(exc),
        )


@app.middleware("http")
async def security_middleware(request: Request, call_next: Any) -> JSONResponse:
    request_id = uuid4().hex
    request.state.request_id = request_id
    start = perf_counter()

    if API_TOKEN and request.url.path not in AUTH_EXEMPT_PATHS:
        provided_token = _extract_bearer_token(request)
        if provided_token != API_TOKEN:
            response = JSONResponse(status_code=401, content={"detail": "A valid API token is required for this request."})
            response.headers["X-Request-ID"] = request_id
            return response

    allowed, remaining = _consume_rate_limit(request)
    if not allowed:
        response = JSONResponse(
            status_code=429,
            content={"detail": f"Rate limit exceeded. Retry after {RATE_LIMIT_WINDOW_SECONDS} seconds."},
        )
        response.headers["X-Request-ID"] = request_id
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_MAX_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = "0"
        return response

    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled API error")
        raise

    duration_ms = round((perf_counter() - start) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    if RATE_LIMIT_MAX_REQUESTS > 0:
        response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_MAX_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

    logger.info(
        json.dumps(
            {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "client": request.client.host if request.client else "unknown",
            }
        )
    )
    return response


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
    return await _scan_github_repository(payload.repo_url, payload.branch)


@app.post("/scan-github/jobs", response_model=ScanJobResponse)
async def create_scan_job(payload: GitHubScanRequest) -> dict[str, Any]:
    job = job_store.create(
        kind="github_repository_scan",
        source={
            "repository": payload.repo_url,
            "branch": payload.branch,
        },
    )
    _schedule_scan_task(_run_github_scan_job(job.job_id, payload.repo_url, payload.branch))
    return job.__dict__


@app.get("/scan-jobs/{job_id}", response_model=ScanJobResponse)
async def get_scan_job(job_id: str) -> dict[str, Any]:
    job = job_store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job was not found.")
    return job
