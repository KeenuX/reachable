"""FastAPI application for the local reachable dashboard."""
from __future__ import annotations

from email import policy
from email.parser import BytesParser
import html
import json
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .advisories import normalize_osv_cache
from .analyzer import (
    analyze_project,
    build_analysis_dependencies,
)
from .config import setting
from .models import AnalysisResult


PACKAGE_ASSETS = Path(__file__).resolve().parent / "assets"


def _find_root() -> Path:
    """Find a checkout's assets first, then fall back to packaged assets."""
    configured = setting("REACHABLE_PROJECT_ROOT")
    candidates = [Path(configured).expanduser()] if configured else []
    candidates.extend([Path.cwd(), Path(__file__).resolve().parents[2], PACKAGE_ASSETS])
    for candidate in candidates:
        candidate = candidate.resolve()
        if all((candidate / name).is_dir() for name in ("data", "static", "fixtures")):
            return candidate
    return PACKAGE_ASSETS


ROOT = _find_root()
STATIC_DIR = ROOT / "static"
DATA_DIR = ROOT / "data"
DEMO_DIR = ROOT / "fixtures" / "demo_app"
RESULTS: dict[str, dict[str, Any]] = {}

DEFAULT_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_UPLOAD_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_UPLOAD_FILES = 1000


class AnalyzeRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    include_tests: bool = False


def _integer_setting(name: str, default: int) -> int:
    value = setting(name)
    try:
        parsed = int(value) if value is not None else default
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _safe_path(raw: str) -> Path:
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if candidate.is_symlink():
        raise HTTPException(status_code=400, detail="Project path must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail="Project path could not be resolved") from exc
    if not resolved.is_dir():
        raise HTTPException(status_code=400, detail="Project path must be an existing directory")
    return resolved


def _load_records_with_source(project: Path, *, demo: bool = False) -> tuple[list[Any], str]:
    def read_records(path: Path, *, local: bool) -> list[Any]:
        if path.is_symlink():
            message = "Project OSV cache must not be a symlink" if local else "Configured OSV cache must not be a symlink"
            raise HTTPException(status_code=400 if local else 500, detail=message)
        try:
            with path.open(encoding="utf-8") as handle:
                payload: Any = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            message = "Project OSV cache is not valid JSON" if local else "OSV cache is not valid JSON"
            raise HTTPException(status_code=400 if local else 500, detail=message) from exc
        try:
            return normalize_osv_cache(payload)
        except (TypeError, ValueError) as exc:
            message = (
                "Project OSV cache does not match the OSV schema"
                if local
                else "OSV cache does not match the OSV schema"
            )
            raise HTTPException(status_code=400 if local else 500, detail=message) from exc

    for name in (
        "osv_records.json",
        "osv.json",
        "pip-audit.json",
        "data/osv_records.json",
        "data/osv.json",
        "data/pip-audit.json",
    ):
        local = project / name
        if local.is_symlink():
            raise HTTPException(status_code=400, detail="Project OSV cache must not be a symlink")
        if local.is_file():
            return read_records(local, local=True), "project"

    cache_value = setting("REACHABLE_OSV_CACHE")
    if cache_value:
        configured = Path(cache_value).expanduser()
        if not configured.is_absolute():
            configured = Path.cwd() / configured
        if configured.is_symlink():
            raise HTTPException(status_code=500, detail="Configured OSV cache must not be a symlink")
        if configured.is_file():
            return read_records(configured, local=False), "configured"

    # The bundled records are demo data. They are intentionally available to
    # the explicit demo route only; an arbitrary project without its own
    # inventory must receive an honest empty result instead of demo alerts.
    if not demo:
        return [], "none"
    for cache in (DATA_DIR / "osv_cache.json", PACKAGE_ASSETS / "data" / "osv_cache.json"):
        if cache.is_symlink():
            raise HTTPException(status_code=500, detail="Bundled OSV cache must not be a symlink")
        if cache.is_file():
            return read_records(cache, local=False), "bundled"
    raise HTTPException(status_code=500, detail="Offline OSV cache is unavailable")


def _load_records(project: Path, *, demo: bool = False) -> list[Any]:
    """Load the selected local cache while retaining the old list API."""

    records, _ = _load_records_with_source(project, demo=demo)
    return records


def _dependencies(
    project: Path,
    advisories: list[Any] | None = None,
    demo: bool = False,
    *,
    include_tests: bool = False,
) -> dict[str, Any]:
    result = build_analysis_dependencies(project, include_tests=include_tests)
    if demo:
        result.update({
            "transitivelib": {"direct": False, "declared": False, "sources": ["demo"]},
            "parent-pkg": {"direct": False, "declared": False, "sources": ["demo"]},
        })
    return result


def _package_key(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(".", "_")


def _relevant_records(records: list[Any], dependencies: dict[str, Any], demo: bool) -> list[Any]:
    if demo:
        return records
    packages = {_package_key(str(name)) for name in dependencies}
    return [
        advisory
        for advisory in records
        if _package_key(str(advisory.package)) in packages and _is_python_advisory(advisory)
    ]


def _is_python_advisory(advisory: Any) -> bool:
    return str(advisory.ecosystem).lower() in {"pypi", "python", ""}


def _display_path(project: Path) -> str:
    """Return a stable, non-machine-specific path for API and report output."""
    try:
        relative = project.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return project.name or "project"
    return relative.as_posix() or project.name or "project"


def _attach_source_snippets(payload: dict[str, Any], project: Path) -> None:
    """Attach small, repository-relative source windows to evidence findings."""
    root = project.resolve()
    for finding in payload.get("findings", []):
        snippets: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for evidence in finding.get("call_chain") or finding.get("evidence") or []:
            relative = evidence.get("file")
            line = evidence.get("line")
            if not isinstance(relative, str) or not isinstance(line, int) or line < 1:
                continue
            source = root / relative
            if source.is_symlink():
                continue
            try:
                resolved = source.resolve(strict=True)
                resolved.relative_to(root)
                lines = resolved.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError, RuntimeError, ValueError):
                continue
            if not lines:
                continue
            key = (relative, line)
            if key in seen:
                continue
            seen.add(key)
            start = max(1, line - 2)
            end = min(len(lines), line + 2)
            snippets.append({
                "file": resolved.relative_to(root).as_posix(),
                "lines": [{"number": number, "text": lines[number - 1]} for number in range(start, end + 1)],
                "highlight": line,
            })
        finding["snippets"] = snippets


def _result_payload(
    analysis_id: str,
    result: AnalysisResult,
    display_path: str,
    advisory_source: str = "unknown",
) -> dict[str, Any]:
    payload = result.to_dict()
    payload.update({
        "id": analysis_id,
        "analysis_id": analysis_id,
        "status": "completed",
        "project_root": display_path,
        "path": display_path,
        "project_path": display_path,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "advisory_source": advisory_source,
        "results": payload["findings"],
    })
    if not payload["findings"]:
        payload["message"] = "No relevant advisories were found for this project."
    return payload


def _run_analysis(
    project: Path,
    include_tests: bool = False,
    demo: bool = False,
    *,
    display_path: str | None = None,
) -> dict[str, Any]:
    all_records, record_source = _load_records_with_source(project, demo=demo)
    dependencies = _dependencies(project, all_records, demo, include_tests=include_tests)
    if demo:
        records = all_records
    elif record_source == "project":
        # A project-local inventory is authoritative: retain advisories even
        # when the package is not imported so the result can honestly say
        # PACKAGE_NOT_IMPORTED instead of silently dropping an alert.
        records = [advisory for advisory in all_records if _is_python_advisory(advisory)]
    else:
        records = _relevant_records(all_records, dependencies, demo)
    symbol_map = DATA_DIR / "symbol_map.json"
    result = analyze_project(
        project,
        records,
        symbol_map_path=symbol_map if symbol_map.is_file() and not symbol_map.is_symlink() else None,
        dependencies=dependencies,
        include_tests=include_tests,
    )
    analysis_id = uuid.uuid4().hex
    payload = _result_payload(
        analysis_id,
        result,
        display_path or _display_path(project),
        advisory_source=record_source,
    )
    _attach_source_snippets(payload, project)
    RESULTS[analysis_id] = payload
    return payload


def _markdown(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# Reachable security report",
        "",
        f"Project: `{payload.get('project_path', '')}`",
        "",
        f"**{summary.get('total', 0)} alerts:** {summary.get('reachable', 0)} reachable, "
        f"{summary.get('not_proven_reachable', 0)} not proven reachable, "
        f"{summary.get('unknown', 0)} unknown.",
        "",
    ]
    for finding in payload.get("alerts", []):
        lines.extend([
            f"## {finding.get('advisory_id', 'unknown')} — {finding.get('status', 'UNKNOWN')}",
            "",
            f"- Package: `{finding.get('package', 'unknown')}`",
            f"- Installed version: `{finding.get('installed_version') or 'unknown'}`",
            f"- Severity: `{finding.get('severity') or 'unknown'}`",
            f"- Fixed version: `{finding.get('fixed_version') or 'unknown'}`",
            f"- Reason: `{finding.get('reason_code', finding.get('reason', 'UNKNOWN'))}`",
            f"- Confidence: `{finding.get('confidence', 'low')}`",
            f"- Symbol source: `{finding.get('symbol_source', 'none')}`",
            f"- Why: {finding.get('why', finding.get('message', 'No explanation provided.'))}",
            "",
        ])
        references = finding.get("references") or []
        if references:
            lines.append("References:")
            lines.extend(f"- {reference}" for reference in references)
            lines.append("")
        chain = finding.get("call_chain") or finding.get("evidence") or []
        if chain:
            lines.append("Evidence:")
            lines.extend(
                f"- `{item.get('file', '?')}:{item.get('line', '?')}` — "
                f"{item.get('symbol') or item.get('detail') or item.get('kind', 'source')}"
                for item in chain
            )
            lines.append("")
    return "\n".join(lines)


def _html_report(payload: dict[str, Any]) -> str:
    markdown = _markdown(payload)
    escaped = html.escape(markdown)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Reachable report</title>"
        "<style>body{font:16px system-ui;max-width:900px;margin:3rem auto;padding:0 1rem;"
        "background:#f7f4ee;color:#23211e}pre{white-space:pre-wrap;background:#efece4;"
        "padding:1.5rem;border-radius:20px}</style></head><body><pre>"
        + escaped
        + "</pre></body></html>"
    )


def _error_code(status_code: int) -> str:
    return {
        400: "invalid_request",
        404: "not_found",
        413: "upload_too_large",
        422: "invalid_request",
    }.get(
        status_code, "analysis_error"
    )


async def _request_body(request: Request) -> bytes:
    limit = _integer_setting("REACHABLE_MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_BYTES)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > limit:
                raise HTTPException(status_code=413, detail="Uploaded request is too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Upload content length is invalid") from None
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail="Uploaded request is too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _multipart_parts(content_type: str, body: bytes) -> list[tuple[str, str | None, bytes]]:
    if "\r" in content_type or "\n" in content_type or not content_type.lower().startswith("multipart/form-data"):
        raise HTTPException(status_code=400, detail="Upload must use multipart/form-data")
    try:
        header = content_type.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise HTTPException(status_code=400, detail="Upload content type is invalid") from exc
    message = BytesParser(policy=policy.default).parsebytes(
        b"MIME-Version: 1.0\r\nContent-Type: " + header + b"\r\n\r\n" + body
    )
    if not message.is_multipart():
        raise HTTPException(status_code=400, detail="Multipart boundary is missing")
    parts: list[tuple[str, str | None, bytes]] = []
    for part in message.iter_parts():
        disposition = part.get("Content-Disposition")
        if not disposition or part.get_content_disposition() != "form-data":
            continue
        field_name = part.get_param("name", header="content-disposition")
        if not isinstance(field_name, str) or not field_name:
            raise HTTPException(status_code=400, detail="Upload field name is missing")
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""
        parts.append((field_name, filename, payload))
    return parts


def _safe_upload_name(filename: str) -> tuple[str, ...]:
    if not filename or "\x00" in filename:
        raise HTTPException(status_code=400, detail="Uploaded file name is invalid")
    normalized = filename.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise HTTPException(status_code=400, detail="Uploaded file path must be relative")
    parts = tuple(normalized.split("/"))
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise HTTPException(status_code=400, detail="Uploaded file path is unsafe")
    if len(normalized) > 4096:
        raise HTTPException(status_code=400, detail="Uploaded file path is too long")
    return parts


def _parse_upload(content_type: str | None, body: bytes) -> tuple[list[tuple[tuple[str, ...], bytes]], bool]:
    if not content_type:
        raise HTTPException(status_code=400, detail="Upload content type is missing")
    files: list[tuple[tuple[str, ...], bytes]] = []
    include_tests = False
    max_files = _integer_setting("REACHABLE_MAX_UPLOAD_FILES", DEFAULT_MAX_UPLOAD_FILES)
    max_file_bytes = _integer_setting("REACHABLE_MAX_UPLOAD_FILE_BYTES", DEFAULT_MAX_UPLOAD_FILE_BYTES)
    for field_name, filename, payload in _multipart_parts(content_type, body):
        if filename is None:
            if field_name == "include_tests":
                include_tests = payload.decode("utf-8", "replace").strip().lower() in {"1", "true", "yes", "on"}
            continue
        if len(files) >= max_files:
            raise HTTPException(status_code=413, detail="Too many uploaded files")
        if len(payload) > max_file_bytes:
            raise HTTPException(status_code=413, detail="An uploaded file is too large")
        files.append((_safe_upload_name(filename), payload))
    if not files:
        raise HTTPException(status_code=400, detail="At least one project file is required")
    return files, include_tests


def _write_upload(temp_root: Path, files: list[tuple[tuple[str, ...], bytes]]) -> None:
    seen: set[tuple[str, ...]] = set()
    root = temp_root.resolve()
    for parts, payload in files:
        if parts in seen:
            raise HTTPException(status_code=400, detail="Uploaded file paths must be unique")
        seen.add(parts)
        current = root
        for part in parts[:-1]:
            current /= part
            if current.is_symlink():
                raise HTTPException(status_code=400, detail="Uploaded paths must not contain symlinks")
            if current.exists() and not current.is_dir():
                raise HTTPException(status_code=400, detail="Uploaded path has a file/directory conflict")
            try:
                current.mkdir(exist_ok=True)
            except OSError as exc:
                raise HTTPException(status_code=400, detail="Uploaded directory could not be created") from exc
            if current.is_symlink():
                raise HTTPException(status_code=400, detail="Uploaded paths must not contain symlinks")
        destination = current / parts[-1]
        if destination.exists() or destination.is_symlink():
            raise HTTPException(status_code=400, detail="Uploaded file paths must be unique")
        try:
            destination.resolve().relative_to(root)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Uploaded file path is unsafe") from exc
        try:
            with destination.open("xb") as handle:
                handle.write(payload)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Uploaded file could not be stored") from exc
        if destination.is_symlink():
            raise HTTPException(status_code=400, detail="Uploaded paths must not contain symlinks")


def _uploaded_project_root(temp_root: Path) -> Path:
    entries = [entry for entry in temp_root.iterdir() if not entry.is_symlink()]
    if len(entries) != 1 or not entries[0].is_dir():
        return temp_root
    nested = entries[0]
    markers = {"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "osv_records.json", "osv.json"}
    if any((nested / marker).is_file() for marker in markers) or any(nested.glob("requirements*.txt")):
        return nested
    return temp_root


app = FastAPI(title="reachable", version="0.1.0")


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": _error_code(exc.status_code), "message": detail}},
    )


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, __: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": {"code": "invalid_request", "message": "Request validation failed"}},
    )


@app.exception_handler(Exception)
async def unexpected_error(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "analysis_error", "message": "Analysis could not be completed"}},
    )


@app.get("/api/demo")
def demo() -> dict[str, Any]:
    return _run_analysis(DEMO_DIR.resolve(), demo=True)


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    project = _safe_path(request.path)
    return _run_analysis(project, request.include_tests)


async def _analyze_upload(request: Request) -> dict[str, Any]:
    body = await _request_body(request)
    files, include_tests = _parse_upload(request.headers.get("content-type"), body)
    with tempfile.TemporaryDirectory(prefix="reachable-upload-") as directory:
        temp_root = Path(directory)
        _write_upload(temp_root, files)
        project = _uploaded_project_root(temp_root)
        return _run_analysis(project, include_tests, display_path="uploaded-project")


@app.post("/api/analyze/upload")
async def analyze_upload(request: Request) -> dict[str, Any]:
    """Analyze browser-selected project files in a cleaned-up temp directory."""

    return await _analyze_upload(request)


@app.post("/api/upload", include_in_schema=False)
async def upload_alias(request: Request) -> dict[str, Any]:
    return await _analyze_upload(request)


@app.get("/api/results/{analysis_id}")
def get_result(analysis_id: str) -> dict[str, Any]:
    payload = RESULTS.get(analysis_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Analysis result not found")
    return payload


@app.get("/api/export/{analysis_id}")
def export_result(analysis_id: str, format: str = Query("markdown", pattern="^(markdown|html)$")):
    payload = RESULTS.get(analysis_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Analysis result not found")
    if format == "html":
        return HTMLResponse(
            _html_report(payload),
            headers={"Content-Disposition": "attachment; filename=reachable-report.html"},
        )
    return PlainTextResponse(
        _markdown(payload),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=reachable-report.md"},
    )


if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index() -> HTMLResponse:
        index_path = STATIC_DIR / "index.html"
        content = index_path.read_text(encoding="utf-8")
        if setting("REACHABLE_DEMO") == "1":
            content = content.replace("<body>", '<body data-demo="true">', 1)
        return HTMLResponse(content)
