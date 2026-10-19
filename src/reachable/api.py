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

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .advisories import load_osv_cache, normalize_osv_cache
from .analyzer import analyze_project
from .models import AnalysisResult

def _find_root() -> Path:
    configured = os.environ.get("REACHABLE_PROJECT_ROOT")
    candidates = [Path(configured).expanduser()] if configured else []
    candidates.extend([Path.cwd(), Path(__file__).resolve().parents[2]])
    for candidate in candidates:
        if (candidate / "data").is_dir() and (candidate / "static").is_dir():
            return candidate.resolve()
    return Path.cwd().resolve()


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
        resolved = candidate.resolve()
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid project path: {exc}") from exc
    if not resolved.is_dir():
        raise HTTPException(status_code=400, detail="Project path must be an existing directory")
    return resolved


def _load_records(project: Path) -> list[Any]:
    local = project / "osv_records.json"
    if local.is_file():
        with local.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        return normalize_osv_cache(payload.get("records", payload))
    cache = Path(os.environ.get("REACHABLE_OSV_CACHE", str(DATA_DIR / "osv_cache.json")))
    if not cache.is_file():
        raise HTTPException(status_code=500, detail="Offline OSV cache is unavailable")
    return load_osv_cache(cache)


def _dependencies(project: Path, advisories: list[Any], demo: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {}
    pyproject = project / "pyproject.toml"
    if pyproject.is_file():
        # A minimal, dependency-free parser for common PEP 621 lists.
        text = pyproject.read_text(encoding="utf-8")
        match = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.S)
        if match:
            for raw in re.findall(r"[\"']([A-Za-z0-9_.-]+)", match.group(1)):
                result[raw] = {"direct": True}
    imported: set[str] = set()
    for source in project.rglob("*.py"):
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0].replace("_", "-") for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0].replace("_", "-"))
    for advisory in advisories:
        package = advisory.package
        if package not in result and package.replace("_", "-") in imported:
            result[package] = {"direct": False}
    if demo:
        result.update({"transitivelib": {"direct": False}, "parent-pkg": {"direct": False}})
    return result


def _result_payload(analysis_id: str, result: AnalysisResult) -> dict[str, Any]:
    payload = result.to_dict()
    payload.update({
        "id": analysis_id,
        "analysis_id": analysis_id,
        "status": "completed",
        "path": result.project_root,
        "project_path": result.project_root,
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
        symbol_map_path=symbol_map if symbol_map.is_file() else None,
        dependencies=_dependencies(project, records, demo),
        include_tests=include_tests,
    )
    analysis_id = uuid.uuid4().hex
    payload = _result_payload(analysis_id, result)
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
            lines.extend(f"- `{item.get('file', '?')}:{item.get('line', '?')}` — {item.get('symbol') or item.get('detail') or item.get('kind', 'source')}" for item in chain)
            lines.append("")
    return "\n".join(lines)


def _html_report(payload: dict[str, Any]) -> str:
    markdown = _markdown(payload)
    escaped = html.escape(markdown)
    return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Reachable report</title><style>body{font:16px system-ui;max-width:900px;margin:3rem auto;padding:0 1rem;background:#f7f4ee;color:#23211e}pre{white-space:pre-wrap;background:#efece4;padding:1.5rem;border-radius:20px}</style></head><body><pre>" + escaped + "</pre></body></html>"


app = FastAPI(title="reachable", version="0.1.0")


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
        return HTMLResponse(_html_report(payload), headers={"Content-Disposition": "attachment; filename=reachable-report.html"})
    return PlainTextResponse(_markdown(payload), media_type="text/markdown", headers={"Content-Disposition": "attachment; filename=reachable-report.md"})


if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index() -> HTMLResponse:
        index_path = STATIC_DIR / "index.html"
        return HTMLResponse(index_path.read_text(encoding="utf-8"))
