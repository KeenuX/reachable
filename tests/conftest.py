"""Shared contract fixtures that tolerate an implementation arriving later."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEMO_FIXTURE = ROOT / "tests" / "fixtures" / "demo_app"


def _load_app():
    candidates = []
    configured = os.environ.get("REACHABLE_TEST_APP")
    if configured and ":" in configured:
        candidates.append(configured)
    candidates.extend(("reachable.api:app", "reachable.main:app", "reachable.app:app"))
    errors = []
    for candidate in candidates:
        module_name, attribute = candidate.split(":", 1)
        try:
            module = importlib.import_module(module_name)
            application = getattr(module, attribute)
            return application() if callable(application) and not hasattr(application, "routes") else application
        except (ImportError, ModuleNotFoundError, AttributeError) as exc:
            errors.append(f"{candidate}: {exc}")
    pytest.skip("FastAPI application is not available yet; tried " + "; ".join(errors))


@pytest.fixture
def app():
    return _load_app()


@pytest.fixture
def client(app):
    httpx = pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    # Importing httpx here gives a useful skip when only the backend package is installed.
    assert httpx is not None
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def demo_project(tmp_path):
    destination = tmp_path / "demo_app"
    import shutil

    shutil.copytree(DEMO_FIXTURE, destination, ignore=shutil.ignore_patterns("expected_results.json"))
    return destination
