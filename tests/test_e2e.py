from __future__ import annotations

import json
from pathlib import Path

import pytest

EXPECTED = json.loads((Path(__file__).parent / "fixtures/demo_app/expected_results.json").read_text())


def _analysis_id(payload):
    return payload.get("analysis_id") or payload.get("id")


def _alerts(payload):
    return payload.get("alerts") or payload.get("results") or []


@pytest.mark.e2e
def test_demo_analysis_matches_ground_truth(client, demo_project):
    response = client.post("/api/analyze", json={"path": str(demo_project), "include_tests": False})
    assert response.status_code in {200, 202}, response.text
    payload = response.json()

    if payload.get("status") in {"queued", "running"} or not _alerts(payload):
        analysis_id = _analysis_id(payload)
        assert analysis_id, "queued analyses must return analysis_id"
        response = client.get(f"/api/results/{analysis_id}")
        assert response.status_code == 200, response.text
        payload = response.json()

    observed = {item["advisory_id"]: item for item in _alerts(payload)}
    assert set(observed) == set(EXPECTED)
    for advisory_id, expected in EXPECTED.items():
        result = observed[advisory_id]
        assert result["status"] == expected["status"]
        assert result["reason_code"] == expected["reason_code"]
        assert result["symbol_source"] == expected["symbol_source"]
        if result["status"] == "REACHABLE":
            assert result["evidence"]
            assert all(item["file"] and item["line"] > 0 for item in result["evidence"])


def test_analyze_rejects_a_path_that_does_not_exist(client):
    response = client.post("/api/analyze", json={"path": "../../definitely-not-a-project"})
    assert 400 <= response.status_code < 500
