from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from reachable.advisories import normalize_osv_cache, normalize_osv_record
from reachable.analyzer import analyze_project, discover_console_scripts, discover_dependencies
from reachable.api import app
from reachable.models import Status


def _record(package: str, *, advisory_id: str = "LOCAL-1", symbol: str = "upload_pkg.run") -> dict[str, object]:
    return {
        "id": advisory_id,
        "summary": "A local advisory",
        "details": f"The affected function is `{symbol}()`.",
        "severity": "high",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": package},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            "database_specific": {"affected_functions": [symbol]},
        }],
        "references": [{"url": "https://example.invalid/advisory"}],
    }


def test_dependency_metadata_is_read_without_executing_setup_py(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "metadata-project"
dependencies = ["alpha-pkg==1.2.3"]

[project.optional-dependencies]
test = ["beta-pkg>=2"]

[project.scripts]
metadata-command = "metadata.cli:main"
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "requirements-dev.txt").write_text("gamma-pkg==3.4.5\n", encoding="utf-8")
    (tmp_path / "setup.cfg").write_text(
        """
[options]
install_requires =
    delta-pkg>=4

[options.extras_require]
test =
    zeta-pkg==6.0
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "setup.py").write_text(
        """
from setuptools import setup
Path("should-not-exist").write_text("executed")
install_requires = ["epsilon-pkg==5.0"]
setup(install_requires=install_requires)
""".strip(),
        encoding="utf-8",
    )

    dependencies = discover_dependencies(tmp_path)

    assert dependencies["alpha-pkg"]["installed_version"] == "1.2.3"
    assert dependencies["gamma-pkg"]["installed_version"] == "3.4.5"
    assert dependencies["epsilon-pkg"]["installed_version"] == "5.0"
    assert dependencies["beta-pkg"]["optional"] is True
    assert dependencies["zeta-pkg"]["optional"] is True
    assert not (tmp_path / "should-not-exist").exists()
    assert discover_console_scripts(tmp_path) == {"metadata-command": "metadata.cli:main"}


def test_osv_cache_accepts_supported_envelopes_and_exposes_metadata() -> None:
    record = _record("upload-pkg")
    for payload in ([record], {"records": [record]}, {"vulnerabilities": [record]}):
        advisories = normalize_osv_cache(payload)
        assert len(advisories) == 1
        advisory = advisories[0]
        assert advisory.severity == "high"
        assert advisory.fixed_version == "2.0.0"
        assert advisory.references == ["https://example.invalid/advisory"]


def test_console_script_is_an_entry_point_and_orphan_function_is_not(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
import vulnerable_pkg

def orphan_function():
    return vulnerable_pkg.connect()
""".strip(),
        encoding="utf-8",
    )
    advisory = normalize_osv_record({
        "id": "ENTRY-1",
        "details": "The affected function is `vulnerable_pkg.connect()`.",
        "affected": [{
            "package": {"name": "vulnerable-pkg"},
            "database_specific": {"affected_functions": ["vulnerable_pkg.connect"]},
        }],
    })

    orphan = analyze_project(tmp_path, [advisory])
    assert orphan.findings[0].status is Status.NOT_PROVEN_REACHABLE

    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "entry-project"
[project.scripts]
entry-command = "app:orphan_function"
""".strip(),
        encoding="utf-8",
    )
    discovered = analyze_project(tmp_path, [advisory])
    assert discovered.findings[0].status is Status.REACHABLE
    assert discovered.findings[0].call_chain[0].kind == "entry"


def test_api_filters_bundled_records_and_returns_local_finding_metadata(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "local-project"
dependencies = ["upload-pkg==1.0.0"]
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("import upload_pkg\nupload_pkg.run()\n", encoding="utf-8")
    (tmp_path / "osv_records.json").write_text(
        json.dumps({"records": [_record("upload-pkg")]}),
        encoding="utf-8",
    )
    client = TestClient(app)

    response = client.post("/api/analyze", json={"path": str(tmp_path)})

    assert response.status_code == 200, response.text
    finding = response.json()["alerts"][0]
    assert finding["installed_version"] == "1.0.0"
    assert finding["severity"] == "high"
    assert finding["fixed_version"] == "2.0.0"
    assert finding["references"] == ["https://example.invalid/advisory"]

    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    empty_response = client.post("/api/analyze", json={"path": str(unrelated)})
    assert empty_response.status_code == 200
    assert empty_response.json()["alerts"] == []
    assert "No relevant advisories" in empty_response.json()["message"]


def test_upload_analyzes_files_in_a_temp_project_and_rejects_unsafe_limits(monkeypatch) -> None:
    client = TestClient(app)
    files = [
        ("files", ("project/app.py", "import upload_pkg\nupload_pkg.run()\n", "text/x-python")),
        ("files", ("project/osv_records.json", json.dumps([_record("upload-pkg")]), "application/json")),
    ]

    response = client.post("/api/analyze/upload", files=files)

    assert response.status_code == 200, response.text
    assert response.json()["project_path"] == "uploaded-project"
    assert response.json()["summary"]["reachable"] == 1
    assert all("reachable-upload-" not in json.dumps(item) for item in response.json()["alerts"])

    traversal = client.post(
        "/api/analyze/upload",
        files=[("files", ("../outside.py", "pass\n", "text/x-python"))],
    )
    assert traversal.status_code == 400
    assert traversal.json()["error"]["code"] == "invalid_request"

    monkeypatch.setenv("REACHABLE_MAX_UPLOAD_FILES", "1")
    excessive = client.post(
        "/api/analyze/upload",
        files=[
            ("files", ("one.py", "pass\n", "text/x-python")),
            ("files", ("two.py", "pass\n", "text/x-python")),
        ],
    )
    assert excessive.status_code == 413
    assert excessive.json()["error"]["code"] == "upload_too_large"


def test_route_decorator_and_real_source_snippets_are_reported(client, tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "route-project"
dependencies = ["route-pkg==1.0.0"]
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
from route_pkg import vulnerable

class Router:
    def get(self, path):
        return lambda function: function

router = Router()

@router.get("/")
def home():
    return vulnerable()
""".lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "osv_records.json").write_text(
        json.dumps([_record("route-pkg", symbol="route_pkg.vulnerable")]),
        encoding="utf-8",
    )

    response = client.post("/api/analyze", json={"path": str(tmp_path)})

    assert response.status_code == 200, response.text
    finding = response.json()["alerts"][0]
    assert finding["status"] == "REACHABLE"
    assert finding["advisory_text"]
    assert finding["snippets"]
    assert finding["snippets"][0]["file"] == "app.py"
    assert any(line["number"] == finding["snippets"][0]["highlight"] for line in finding["snippets"][0]["lines"])


def test_pip_audit_inventory_is_accepted_without_network(client, tmp_path):
    (tmp_path / "requirements.txt").write_text("pip-audit-pkg==1.0.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import pip_audit_pkg\n", encoding="utf-8")
    (tmp_path / "pip-audit.json").write_text(
        json.dumps([{
            "name": "pip-audit-pkg",
            "version": "1.0.0",
            "id": "PIP-AUDIT-001",
            "description": "Package-level issue.",
            "fix_versions": ["1.1.0"],
            "aliases": ["CVE-2099-0001"],
            "urls": ["https://example.invalid/pip-audit-001"],
        }]),
        encoding="utf-8",
    )

    response = client.post("/api/analyze", json={"path": str(tmp_path)})

    assert response.status_code == 200, response.text
    finding = response.json()["alerts"][0]
    assert finding["advisory_id"] == "PIP-AUDIT-001"
    assert finding["status"] == "UNKNOWN"
    assert finding["reason_code"] == "NO_SYMBOL_IN_ADVISORY"
    assert finding["installed_version"] == "1.0.0"
    assert finding["fixed_version"] == "1.1.0"
    assert finding["references"] == ["https://example.invalid/pip-audit-001"]
