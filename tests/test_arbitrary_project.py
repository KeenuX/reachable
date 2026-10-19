from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest


def _record(
    advisory_id: str,
    package: str,
    symbol: str | None = None,
    *,
    version: str | None = None,
    severity: str | None = None,
    references: list[str] | None = None,
) -> dict:
    affected = {
        "package": {"ecosystem": "PyPI", "name": package},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
    }
    if version is not None:
        affected["versions"] = [version]
    if symbol is not None:
        affected["database_specific"] = {"affected_functions": [symbol]}
    record = {
        "id": advisory_id,
        "summary": f"Advisory for {package}",
        "details": f"The affected callable is `{symbol}()`." if symbol else "Package advisory.",
        "affected": [affected],
        "references": [
            {"type": "ADVISORY", "url": url}
            for url in (references or [])
        ],
    }
    if severity is not None:
        # The API contract accepts the normalized advisory severity used by
        # the local cache. The field is deliberately kept at the record root
        # so this fixture remains easy to read as an OSV-shaped record.
        record["severity"] = severity
    return record


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_project(
    root: Path,
    *,
    source: str = "print('no alerts')\n",
    records: object | None = None,
    requirements: str | None = None,
    pyproject: str | None = None,
) -> Path:
    root.mkdir()
    (root / "app.py").write_text(source, encoding="utf-8")
    if records is not None:
        _write_json(root / "osv_records.json", records)
    if requirements is not None:
        (root / "requirements.txt").write_text(requirements, encoding="utf-8")
    if pyproject is not None:
        (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    return root


def _analysis(client, project: Path) -> dict:
    response = client.post("/api/analyze", json={"path": str(project)})
    assert response.status_code in {200, 202}, response.text
    payload = response.json()
    if payload.get("status") in {"queued", "running"}:
        analysis_id = payload.get("analysis_id") or payload.get("id")
        assert analysis_id, "queued analyses must return analysis_id"
        response = client.get(f"/api/results/{analysis_id}")
        assert response.status_code == 200, response.text
        payload = response.json()
    assert payload.get("status") == "completed"
    return payload


@pytest.mark.parametrize("cache_shape", ["list", "vulnerabilities", "records"])
def test_arbitrary_project_loads_each_supported_local_osv_cache_shape(
    client, tmp_path, cache_shape
):
    record = _record("LOCAL-CACHE-001", "cache-only-pkg")
    payload = {
        "list": [record],
        "vulnerabilities": {"vulnerabilities": [record]},
        "records": {"records": [record]},
    }[cache_shape]
    project = _write_project(
        tmp_path / "local-cache",
        records=payload,
        pyproject="""\
[project]
name = "local-cache-project"
version = "0.1.0"
dependencies = ["cache-only-pkg==1.0.0"]
""",
    )

    result = _analysis(client, project)

    assert [alert["advisory_id"] for alert in result["alerts"]] == ["LOCAL-CACHE-001"]
    assert result["summary"] == {
        "total": 1,
        "reachable": 0,
        "not_proven_reachable": 0,
        "unknown": 1,
    }


def test_arbitrary_project_without_local_cache_does_not_receive_bundled_demo_alerts(
    client, tmp_path
):
    project = _write_project(
        tmp_path / "unrelated-project",
        source="def unrelated():\n    return 'not a demo dependency'\n",
    )

    result = _analysis(client, project)

    assert result["alerts"] == []
    assert result["results"] == []
    assert result["summary"] == {
        "total": 0,
        "reachable": 0,
        "not_proven_reachable": 0,
        "unknown": 0,
    }


def test_no_advisory_inventory_returns_a_completed_empty_state(client, tmp_path):
    project = _write_project(tmp_path / "empty-project", records=[])

    result = _analysis(client, project)
    analysis_id = result["analysis_id"]
    persisted = client.get(f"/api/results/{analysis_id}")

    assert persisted.status_code == 200
    assert persisted.json()["status"] == "completed"
    assert persisted.json()["alerts"] == []
    assert persisted.json()["results"] == []
    assert persisted.json()["summary"] == {
        "total": 0,
        "reachable": 0,
        "not_proven_reachable": 0,
        "unknown": 0,
    }


@pytest.mark.parametrize("declaration", ["requirements", "pyproject"])
def test_requirements_and_pyproject_declarations_separate_direct_and_transitive_alerts(
    client, tmp_path, declaration
):
    direct = _record("DIRECT-DECLARED-001", "direct-pkg", "direct_pkg.vulnerable")
    transitive = _record(
        "TRANSITIVE-UNDECLARED-001", "transitive-pkg", "transitive_pkg.vulnerable"
    )
    source = """\
from direct_pkg import safe
from transitive_pkg import vulnerable


def main():
    safe()
    vulnerable()


if __name__ == "__main__":
    main()
"""
    dependency_files = {
        "requirements": {
            "requirements": "# direct runtime dependency\ndirect-pkg==1.0.0\n",
        },
        "pyproject": {
            "pyproject": """\
[project]
name = "arbitrary-project"
version = "0.1.0"
dependencies = ["direct-pkg==1.0.0"]
""",
        },
    }[declaration]
    project = _write_project(
        tmp_path / declaration,
        source=source,
        records=[direct, transitive],
        **dependency_files,
    )

    alerts = {
        alert["advisory_id"]: alert for alert in _analysis(client, project)["alerts"]
    }

    assert alerts["DIRECT-DECLARED-001"]["status"] == "NOT_PROVEN_REACHABLE"
    assert alerts["DIRECT-DECLARED-001"]["reason_code"] == "SYMBOL_NOT_CALLED"
    assert alerts["TRANSITIVE-UNDECLARED-001"]["status"] == "UNKNOWN"
    assert alerts["TRANSITIVE-UNDECLARED-001"]["reason_code"] == "TRANSITIVE_DEPENDENCY"


def test_pyproject_console_script_is_a_reachability_entry_point(client, tmp_path):
    project = tmp_path / "console-project"
    project.mkdir()
    (project / "app.py").write_text(
        "@router.get('/')\ndef unrelated_route():\n    return 'ok'\n",
        encoding="utf-8",
    )
    (project / "cli.py").write_text(
        "from console_pkg import vulnerable\n\ndef main():\n    return vulnerable()\n",
        encoding="utf-8",
    )
    (project / "pyproject.toml").write_text(
        """\
[project]
name = "console-project"
version = "0.1.0"

[project.scripts]
console-tool = "cli:main"
""",
        encoding="utf-8",
    )
    _write_json(
        project / "osv_records.json",
        [_record("CONSOLE-ENTRY-001", "console-pkg", "console_pkg.vulnerable")],
    )

    alerts = _analysis(client, project)["alerts"]
    finding = next(alert for alert in alerts if alert["advisory_id"] == "CONSOLE-ENTRY-001")

    assert finding["status"] == "REACHABLE"
    assert finding["reason_code"] == "CALL_CHAIN_FOUND"
    assert len(finding["evidence"]) >= 2
    assert finding["evidence"][0]["file"] == "cli.py"
    assert any(
        item["file"] == "cli.py" and item["symbol"] == "console_pkg.vulnerable"
        for item in finding["evidence"]
    )


def test_api_results_include_declared_version_severity_and_references(client, tmp_path):
    reference_urls = [
        "https://example.invalid/advisories/METADATA-001",
        "https://example.invalid/tracker/METADATA-001",
    ]
    project = _write_project(
        tmp_path / "metadata-project",
        source="""\
from metadata_pkg import vulnerable


def main():
    return vulnerable()


if __name__ == "__main__":
    main()
""",
        requirements="metadata-pkg==1.2.3\n",
        records=[
            _record(
                "METADATA-001",
                "metadata-pkg",
                "metadata_pkg.vulnerable",
                version="1.2.3",
                severity="high",
                references=reference_urls,
            )
        ],
    )

    finding = _analysis(client, project)["alerts"][0]

    assert finding["advisory_id"] == "METADATA-001"
    assert finding["installed_version"] == "1.2.3"
    assert finding["severity"] == "high"
    assert finding["references"] == reference_urls


def _multipart_temp_root(monkeypatch, tmp_path: Path) -> Path:
    upload_root = tmp_path / "multipart-temp"
    upload_root.mkdir()
    monkeypatch.setenv("TMPDIR", str(upload_root))
    monkeypatch.setenv("TMP", str(upload_root))
    monkeypatch.setenv("TEMP", str(upload_root))
    monkeypatch.setattr(tempfile, "tempdir", str(upload_root))
    return upload_root


def test_multipart_folder_upload_analyzes_relative_files_and_cleans_up(
    client, monkeypatch, tmp_path
):
    upload_root = _multipart_temp_root(monkeypatch, tmp_path)
    advisory = _record("UPLOAD-001", "uploaded-pkg", "uploaded_pkg.vulnerable")
    files = [
        (
            "files",
            (
                "app.py",
                b"from uploaded_pkg import vulnerable\n\ndef main():\n    return vulnerable()\n",
                "text/x-python",
            ),
        ),
        (
            "files",
            (
                "pkg/__init__.py",
                b"# nested project file\n",
                "text/x-python",
            ),
        ),
        (
            "files",
            (
                "osv_records.json",
                json.dumps([advisory]).encode("utf-8"),
                "application/json",
            ),
        ),
    ]

    response = client.post("/api/analyze/upload", files=files)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["alerts"][0]["advisory_id"] == "UPLOAD-001"
    serialized = json.dumps(payload)
    assert str(tmp_path) not in serialized
    assert str(upload_root) not in serialized
    assert not any(upload_root.iterdir()), "uploaded project must be removed after analysis"


def test_multipart_folder_upload_rejects_path_traversal_and_cleans_up(
    client, monkeypatch, tmp_path
):
    upload_root = _multipart_temp_root(monkeypatch, tmp_path)
    escaped = tmp_path / "escaped.py"

    response = client.post(
        "/api/analyze/upload",
        files=[
            (
                "files",
                ("../escaped.py", b"outside = True\n", "text/x-python"),
            )
        ],
    )

    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == "invalid_request"
    assert not escaped.exists()
    assert not any(upload_root.iterdir()), "rejected uploads must not leave temp directories"
