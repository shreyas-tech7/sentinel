#!/usr/bin/env python3
"""Unit tests for validation/score.py. Run: python -m unittest validation.test_score
or, from the validation/ directory: python -m unittest test_score
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import score


class LoadTruthTests(unittest.TestCase):
    def test_parses_names_categories_and_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "expectedresults-1.2.csv"
            csv_path.write_text(
                "# test name, category, real vulnerability, cwe, v1.2\n"
                "BenchmarkTest00001,pathtraver,true,22\n"
                "BenchmarkTest00002,sqli,FALSE,89\n"
            )
            truth = score.load_truth(csv_path)
        self.assertEqual(truth["BenchmarkTest00001"], ("pathtraver", True))
        self.assertEqual(truth["BenchmarkTest00002"], ("sqli", False))


class LoadVerdictsTests(unittest.TestCase):
    def test_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "verdicts.json"
            path.write_text(
                json.dumps(
                    [
                        {"test_name": "BenchmarkTest00001", "category": "sqli", "vulnerable": True},
                        {"test_name": "BenchmarkTest00001", "category": "sqli", "vulnerable": False},
                    ]
                )
            )
            with self.assertRaises(ValueError):
                score.load_verdicts(path)


class ScoreTests(unittest.TestCase):
    TRUTH = {
        "T1": ("sqli", True),
        "T2": ("sqli", False),
        "T3": ("sqli", True),
        "T4": ("xss", False),
        "T5": ("xss", True),
    }

    def test_confusion_cells(self):
        verdicts = {"T1": True, "T2": True, "T3": False, "T4": False, "T5": True}
        counts = score.score(self.TRUTH, verdicts)
        self.assertEqual(counts["sqli"], {"TP": 1, "FP": 1, "FN": 1, "TN": 0})
        self.assertEqual(counts["xss"], {"TP": 1, "FP": 0, "FN": 0, "TN": 1})

    def test_only_verdict_set_is_scored(self):
        counts = score.score(self.TRUTH, {"T1": True})
        self.assertEqual(sum(sum(c.values()) for c in counts.values()), 1)

    def test_unknown_test_name_raises(self):
        with self.assertRaises(KeyError):
            score.score(self.TRUTH, {"T999": True})


class MetricsTests(unittest.TestCase):
    def test_perfect(self):
        m = score.metrics({"TP": 5, "FP": 0, "FN": 0, "TN": 5})
        self.assertEqual((m["precision"], m["recall"], m["f1"]), (1.0, 1.0, 1.0))

    def test_division_by_zero_yields_none(self):
        m = score.metrics({"TP": 0, "FP": 0, "FN": 0, "TN": 4})
        self.assertIsNone(m["precision"])
        self.assertIsNone(m["recall"])
        self.assertIsNone(m["f1"])

    def test_known_values(self):
        m = score.metrics({"TP": 3, "FP": 1, "FN": 2, "TN": 0})
        self.assertAlmostEqual(m["precision"], 0.75)
        self.assertAlmostEqual(m["recall"], 0.6)
        self.assertAlmostEqual(m["f1"], 2 * 0.75 * 0.6 / 1.35)

    def test_totals(self):
        counts = {
            "a": {"TP": 1, "FP": 2, "FN": 3, "TN": 4},
            "b": {"TP": 5, "FP": 6, "FN": 7, "TN": 8},
        }
        self.assertEqual(score.totals(counts), {"TP": 6, "FP": 8, "FN": 10, "TN": 12})


class RenderTests(unittest.TestCase):
    def test_markdown_has_total_row(self):
        counts = {"sqli": {"TP": 1, "FP": 0, "FN": 1, "TN": 2}}
        table = score.render_markdown(counts, "SENTINEL")
        self.assertIn("| sqli | 4 | 1 | 0 | 1 | 2 |", table)
        self.assertIn("**all (SENTINEL)**", table)


if __name__ == "__main__":
    unittest.main()
