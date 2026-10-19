"""Command line entry points for reachable."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .advisories import load_osv_cache, normalize_osv_cache
from .analyzer import analyze_project, build_analysis_dependencies
from .config import setting

PACKAGE_ASSETS = Path(__file__).resolve().parent / "assets"


def _root() -> Path:
    configured = setting("REACHABLE_PROJECT_ROOT")
    candidates = [Path(configured).expanduser()] if configured else []
    candidates.extend([Path.cwd(), Path(__file__).resolve().parents[2], PACKAGE_ASSETS])
    for candidate in candidates:
        candidate = candidate.resolve()
        if (candidate / "data").is_dir():
            return candidate
    return PACKAGE_ASSETS


def _scan(path: Path) -> int:
    root = path.expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"project path is not a directory: {path}")
    base = _root()
    is_demo = root == (base / "fixtures" / "demo_app").resolve()
    inventory = None
    for name in ("osv_records.json", "osv.json", "pip-audit.json", "data/osv_records.json", "data/osv.json", "data/pip-audit.json"):
        candidate = root / name
        if candidate.is_file() and not candidate.is_symlink():
            with candidate.open(encoding="utf-8") as handle:
                inventory = normalize_osv_cache(json.load(handle))
            break
    if inventory is None:
        cache_value = setting("REACHABLE_OSV_CACHE")
        cache = Path(cache_value).expanduser() if cache_value else None
        if cache is not None and cache.is_file() and not cache.is_symlink():
            inventory = load_osv_cache(cache)
    if inventory is None and is_demo:
        inventory = load_osv_cache(base / "data" / "osv_cache.json")
    advisories = inventory or []
    dependencies = build_analysis_dependencies(root)
    if is_demo:
        dependencies["transitivelib"] = {"direct": False}
    package_keys = {str(name).strip().lower().replace("-", "_").replace(".", "_") for name in dependencies}
    if not is_demo:
        advisories = [item for item in advisories if str(item.package).strip().lower().replace("-", "_").replace(".", "_") in package_keys]
    symbol_map = base / "data" / "symbol_map.json"
    result = analyze_project(
        root,
        advisories,
        symbol_map_path=symbol_map if symbol_map.is_file() and not symbol_map.is_symlink() else None,
        dependencies=dependencies,
    )
    payload = result.to_dict()
    try:
        payload["project_root"] = root.relative_to(base).as_posix()
    except ValueError:
        payload["project_root"] = root.name or "project"
    print(json.dumps(payload, indent=2))
    return 1 if result.summary["reachable"] else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="reachable", description="Offline dependency reachability analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan a Python project")
    scan.add_argument("path", type=Path)
    serve = subparsers.add_parser("serve", help="serve the local dashboard")
    serve.add_argument("--demo", action="store_true", help="use the bundled offline demo assets")
    serve.add_argument("--port", type=int, default=int(setting("REACHABLE_PORT", "8000") or "8000"))
    args = parser.parse_args()
    if args.command == "scan":
        return _scan(args.path)
    if args.demo:
        os.environ["REACHABLE_DEMO"] = "1"
    import uvicorn

    uvicorn.run("reachable.api:app", host="127.0.0.1", port=args.port, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
