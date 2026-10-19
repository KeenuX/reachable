"""FastAPI application for the local reachable dashboard."""
from __future__ import annotations

import ast
import html
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .advisories import load_osv_cache, normalize_osv_cache
from .analyzer import analyze_project
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


class AnalyzeRequest(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    include_tests: bool = False


def _safe_path(raw: str) -> Path:
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail="Project path could not be resolved") from exc
    if not resolved.is_dir():
        raise HTTPException(status_code=400, detail="Project path must be an existing directory")
    return resolved


def _load_records(project: Path) -> list[Any]:
    local = project / "osv_records.json"
    if local.is_file() and not local.is_symlink():
        try:
            with local.open(encoding="utf-8") as handle:
                payload: Any = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="Project OSV cache is not valid JSON") from exc
        if isinstance(payload, dict):
            payload = payload.get("records", payload)
        try:
            return normalize_osv_cache(payload)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Project OSV cache does not match the OSV schema") from exc
    cache_value = setting("REACHABLE_OSV_CACHE")
    cache = Path(cache_value).expanduser() if cache_value else DATA_DIR / "osv_cache.json"
    if not cache.is_file() or cache.is_symlink():
        raise HTTPException(status_code=500, detail="Offline OSV cache is unavailable")
    try:
        return load_osv_cache(cache)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=500, detail="Offline OSV cache is not valid") from exc


def _iter_python_files(project: Path):
    root = project.resolve()
    for source in sorted(root.rglob("*.py")):
        if source.is_symlink():
            continue
        try:
            resolved = source.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            continue
        yield resolved


def _dependencies(project: Path, advisories: list[Any], demo: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {}
    pyproject = project / "pyproject.toml"
    if pyproject.is_file() and not pyproject.is_symlink():
        # A minimal, dependency-free parser for common PEP 621 lists.
        text = pyproject.read_text(encoding="utf-8")
        match = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.S)
        if match:
            for raw in re.findall(r"[\"']([A-Za-z0-9_.-]+)", match.group(1)):
                result[raw] = {"direct": True}
    imported: set[str] = set()
    for source in _iter_python_files(project):
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0].replace("_", "-") for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0].replace("_", "-"))
    # If a project declares dependencies, an imported package missing from that
    # declaration is conservatively treated as transitive. Source-only demo
    # projects have no declaration, so their imported packages remain direct.
    if pyproject.is_file():
        declared = {str(name).replace("_", "-").lower() for name in result}
        for advisory in advisories:
            package = advisory.package
            normalized = package.lower().replace("_", "-")
            if normalized in imported and normalized not in declared:
                result[package] = {"direct": False}
    if demo:
        result.update({"transitivelib": {"direct": False}, "parent-pkg": {"direct": False}})
    return result


def _display_path(project: Path) -> str:
    """Return a stable, non-machine-specific path for API and report output."""
    try:
        relative = project.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return project.name or "project"
    return relative.as_posix() or project.name or "project"


def _result_payload(analysis_id: str, result: AnalysisResult, display_path: str) -> dict[str, Any]:
    payload = result.to_dict()
    payload.update({
        "id": analysis_id,
        "analysis_id": analysis_id,
        "status": "completed",
        "project_root": display_path,
        "path": display_path,
        "project_path": display_path,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "results": payload["findings"],
    })
    return payload


def _run_analysis(project: Path, include_tests: bool = False, demo: bool = False) -> dict[str, Any]:
    records = _load_records(project)
    symbol_map = DATA_DIR / "symbol_map.json"
    result = analyze_project(
        project,
        records,
        symbol_map_path=symbol_map if symbol_map.is_file() and not symbol_map.is_symlink() else None,
        dependencies=_dependencies(project, records, demo),
        include_tests=include_tests,
    )
    analysis_id = uuid.uuid4().hex
    payload = _result_payload(analysis_id, result, _display_path(project))
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
            f"- Reason: `{finding.get('reason_code', finding.get('reason', 'UNKNOWN'))}`",
            f"- Confidence: `{finding.get('confidence', 'low')}`",
            f"- Symbol source: `{finding.get('symbol_source', 'none')}`",
            f"- Why: {finding.get('why', finding.get('message', 'No explanation provided.'))}",
            "",
        ])
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
    return {400: "invalid_request", 404: "not_found", 422: "invalid_request"}.get(
        status_code, "analysis_error"
    )


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


@app.get("/api/demo")
def demo() -> dict[str, Any]:
    return _run_analysis(DEMO_DIR.resolve(), demo=True)


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    project = _safe_path(request.path)
    return _run_analysis(project, request.include_tests)


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
