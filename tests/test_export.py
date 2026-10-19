from __future__ import annotations

import pytest


def _analysis_id(payload):
    return payload.get("analysis_id") or payload.get("id")


def test_markdown_export_has_stable_report_headings(client, demo_project):
    response = client.post("/api/analyze", json={"path": str(demo_project)})
    assert response.status_code in {200, 202}, response.text
    analysis_id = _analysis_id(response.json())
    assert analysis_id

    exported = client.get(f"/api/export/{analysis_id}", params={"format": "markdown"})
    assert exported.status_code == 200, exported.text
    assert "#" in exported.text
    assert "REACHABLE" in exported.text or "Status" in exported.text
    assert exported.headers.get("content-type", "").startswith("text/markdown")


def test_html_export_escapes_report_content(client, demo_project):
    response = client.post("/api/analyze", json={"path": str(demo_project)})
    assert response.status_code in {200, 202}, response.text
    analysis_id = _analysis_id(response.json())
    assert analysis_id
    exported = client.get(f"/api/export/{analysis_id}", params={"format": "html"})
    assert exported.status_code == 200, exported.text
    assert "<html" in exported.text.lower() or "<!doctype" in exported.text.lower()
    assert "<script>alert" not in exported.text.lower()
