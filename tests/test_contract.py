from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_STATUSES = {"REACHABLE", "NOT_PROVEN_REACHABLE", "UNKNOWN"}
EXPECTED_REASONS = {
    "CALL_CHAIN_FOUND", "PACKAGE_NOT_IMPORTED", "SYMBOL_NOT_CALLED",
    "NO_SYMBOL_IN_ADVISORY", "DYNAMIC_CODE_BLOCKS_ANALYSIS",
    "TRANSITIVE_DEPENDENCY", "PARSE_ERROR",
}
EXPECTED_SOURCES = {"osv_structured", "curated_map", "inferred_from_text", "none"}


def test_api_contract_documents_required_routes_and_invariants():
    contract = (ROOT / "docs" / "API.md").read_text(encoding="utf-8")
    for route in ("POST /api/analyze", "GET /api/results/{analysis_id}", "GET /api/export/{analysis_id}"):
        assert route in contract
    for value in EXPECTED_STATUSES | EXPECTED_REASONS | EXPECTED_SOURCES:
        assert value in contract
    assert "127.0.0.1" in contract
    assert "shell=True" in contract


def test_demo_ground_truth_covers_required_statuses_and_uncertainty():
    expected = json.loads((ROOT / "tests/fixtures/demo_app/expected_results.json").read_text())
    assert {item["status"] for item in expected.values()} == EXPECTED_STATUSES
    assert expected["GHSA-demo-reachable"]["reason_code"] == "CALL_CHAIN_FOUND"
    assert expected["GHSA-demo-dynamic"]["reason_code"] == "DYNAMIC_CODE_BLOCKS_ANALYSIS"
    assert expected["GHSA-demo-transitive"]["reason_code"] == "TRANSITIVE_DEPENDENCY"
    for result in expected.values():
        assert result["reason_code"] in EXPECTED_REASONS
        assert result["symbol_source"] in EXPECTED_SOURCES


@pytest.mark.parametrize("required", ["pyproject.toml", "requirements.lock", ".python-version", "Dockerfile", "Makefile", ".env.example", "README.md"])
def test_reproducibility_file_exists(required):
    assert (ROOT / required).is_file()
