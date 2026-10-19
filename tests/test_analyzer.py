from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from reachable.advisories import load_osv_cache, normalize_osv_record, resolve_symbols
from reachable.analyzer import analyze_project
from reachable.models import ReasonCode, Status, SymbolSource


ROOT = Path(__file__).parents[1]


class AdvisoryResolutionTests(unittest.TestCase):
    def test_structured_symbols_win_over_curated_and_text(self) -> None:
        advisory = normalize_osv_record({
            "id": "PYSEC-structured",
            "details": "The `demo.parse()` entry point is affected.",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"}}],
            "database_specific": {"affected_functions": ["demo.safe"]},
        })
        symbols = resolve_symbols(advisory, {"demo": {"symbols": ["demo.other"]}})
        self.assertEqual([item.name for item in symbols], ["demo.safe"])
        self.assertEqual(symbols[0].source, SymbolSource.OSV_STRUCTURED)

    def test_curated_and_text_fallbacks_are_labelled(self) -> None:
        curated = normalize_osv_record({
            "id": "curated", "affected": [{"package": {"name": "demo"}}]
        })
        result = resolve_symbols(curated, {"demo": {"symbols": ["demo.parse"]}})
        self.assertEqual(result[0].source, SymbolSource.CURATED_MAP)

        inferred = normalize_osv_record({
            "id": "inferred", "details": "Call `demo.parse()` to reproduce.",
            "affected": [{"package": {"name": "demo"}}]
        })
        result = resolve_symbols(inferred)
        self.assertEqual([item.name for item in result], ["demo.parse"])
        self.assertEqual(result[0].source, SymbolSource.INFERRED_FROM_TEXT)


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.advisories = load_osv_cache(ROOT / "data" / "osv_cache.json")

    def test_demo_ground_truth_has_evidence_for_reachable_paths(self) -> None:
        result = analyze_project(
            ROOT / "fixtures" / "demo_app",
            self.advisories,
            symbol_map_path=ROOT / "data" / "symbol_map.json",
            dependencies={"transitivelib": False},
        )
        findings = {item.advisory_id: item for item in result.findings}
        expected = json.loads((ROOT / "fixtures" / "demo_app" / "expected_results.json").read_text())
        for advisory_id, assertion in expected.items():
            finding = findings[advisory_id]
            self.assertEqual(finding.status.value, assertion["status"])
            self.assertEqual(finding.reason.value, assertion["reason"])
            if finding.status is Status.REACHABLE:
                self.assertGreaterEqual(len(finding.call_chain), 2)
                self.assertTrue(all(item.file and item.line > 0 for item in finding.call_chain))
                self.assertEqual(finding.symbol_source.value, assertion["symbol_source"])

    def test_dynamic_and_parse_errors_are_unknown_with_locations(self) -> None:
        result = analyze_project(
            ROOT / "fixtures" / "demo_app",
            [self.advisories[3]],
            symbol_map_path=ROOT / "data" / "symbol_map.json",
        )
        finding = result.findings[0]
        self.assertEqual(finding.reason, ReasonCode.DYNAMIC_CODE_BLOCKS_ANALYSIS)
        self.assertTrue(finding.evidence[0].file.endswith("app.py"))
        self.assertGreater(finding.evidence[0].line, 0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "broken.py").write_text("def broken(:\n")
            advisory = normalize_osv_record({
                "id": "broken", "details": "`broken.parse()`", 
                "affected": [{"package": {"name": "broken"}}],
            })
            result = analyze_project(root, [advisory])
            self.assertEqual(result.findings[0].status, Status.UNKNOWN)
            self.assertEqual(result.findings[0].reason, ReasonCode.PARSE_ERROR)
            self.assertEqual(result.parse_errors[0].file, "broken.py")

    def test_transitive_alert_is_unknown(self) -> None:
        advisory = next(item for item in self.advisories if item.id == "DEMO-TRANSITIVE")
        result = analyze_project(
            ROOT / "fixtures" / "demo_app",
            [advisory],
            symbol_map_path=ROOT / "data" / "symbol_map.json",
            dependencies={"transitivelib": {"direct": False}},
        )
        self.assertEqual(result.findings[0].reason, ReasonCode.TRANSITIVE_DEPENDENCY)
        self.assertEqual(result.findings[0].status, Status.UNKNOWN)

    def test_missing_symbols_never_become_reachable(self) -> None:
        advisory = normalize_osv_record({
            "id": "no-symbol",
            "summary": "Package-level description only",
            "affected": [{"package": {"name": "demo"}}],
        })
        result = analyze_project(ROOT / "fixtures" / "demo_app", [advisory])
        self.assertEqual(result.findings[0].status, Status.UNKNOWN)
        self.assertEqual(result.findings[0].reason, ReasonCode.NO_SYMBOL_IN_ADVISORY)


if __name__ == "__main__":
    unittest.main()
