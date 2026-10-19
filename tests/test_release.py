from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from reachable.analyzer import analyze_project
from reachable.api import app
from reachable.advisories import normalize_osv_record


ROOT = Path(__file__).resolve().parents[1]


def test_demo_api_is_stable_and_does_not_leak_machine_paths():
    payload = TestClient(app).get("/api/demo").json()
    assert payload["summary"] == {"total": 5, "reachable": 2, "not_proven_reachable": 1, "unknown": 2}
    assert payload["project_path"] == "fixtures/demo_app"
    serialized = json.dumps(payload)
    assert str(ROOT.resolve()) not in serialized
    assert "OneDrive" not in serialized


def test_api_errors_use_documented_envelope():
    client = TestClient(app)
    response = client.post("/api/analyze", json={"path": "does-not-exist"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert "message" in response.json()["error"]


def test_project_osv_records_accepts_a_json_list(tmp_path):
    (tmp_path / "osv_records.json").write_text(
        json.dumps([
            {
                "id": "LIST-RECORD",
                "details": "No callable is provided.",
                "affected": [{"package": {"ecosystem": "PyPI", "name": "list-only"}}],
            }
        ]),
        encoding="utf-8",
    )
    response = TestClient(app).post("/api/analyze", json={"path": str(tmp_path)})
    assert response.status_code == 200
    assert response.json()["alerts"][0]["status"] == "UNKNOWN"


def test_analyzer_does_not_follow_source_symlinks(tmp_path):
    outside = Path(tempfile.mkdtemp()) / "outside.py"
    outside.write_text("import secretlib\nsecretlib.run()\n", encoding="utf-8")
    (tmp_path / "link.py").symlink_to(outside)
    advisory = normalize_osv_record(
        {
            "id": "SYMLINK-TEST",
            "details": "The affected function is `secretlib.run()`.",
            "affected": [{"package": {"name": "secretlib"}}],
        }
    )
    result = analyze_project(tmp_path, [advisory])
    assert result.findings[0].status.value == "NOT_PROVEN_REACHABLE"
    assert all("outside.py" not in evidence.file for evidence in result.findings[0].evidence)
