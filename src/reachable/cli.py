"""Command line entry points for reachable."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .advisories import load_osv_cache
from .analyzer import analyze_project


def _root() -> Path:
    configured = os.environ.get("REACHABLE_PROJECT_ROOT")
    candidates = [Path(configured).expanduser()] if configured else []
    candidates.extend([Path.cwd(), Path(__file__).resolve().parents[2]])
    for candidate in candidates:
        if (candidate / "data").is_dir():
            return candidate.resolve()
    return Path.cwd().resolve()


def _scan(path: Path) -> int:
    root = path.expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"project path is not a directory: {path}")
    cache = Path(os.environ.get("REACHABLE_OSV_CACHE", str(_root() / "data" / "osv_cache.json")))
    advisories = load_osv_cache(cache)
    symbol_map = _root() / "data" / "symbol_map.json"
    dependencies = None
    if root == (_root() / "fixtures" / "demo_app").resolve():
        dependencies = {"transitivelib": {"direct": False}}
    result = analyze_project(
        root,
        advisories,
        symbol_map_path=symbol_map if symbol_map.is_file() else None,
        dependencies=dependencies,
    )
    print(json.dumps(result.to_dict(), indent=2))
    return 1 if result.summary["reachable"] else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="reachable", description="Offline dependency reachability analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan a Python project")
    scan.add_argument("path", type=Path)
    serve = subparsers.add_parser("serve", help="serve the local dashboard")
    serve.add_argument("--demo", action="store_true", help="start with the offline demo")
    serve.add_argument("--port", type=int, default=int(os.environ.get("REACHABLE_PORT", "8000")))
    args = parser.parse_args()
    if args.command == "scan":
        return _scan(args.path)
    import uvicorn
    uvicorn.run("reachable.api:app", host="127.0.0.1", port=args.port, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
