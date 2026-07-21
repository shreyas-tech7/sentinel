#!/usr/bin/env python3
"""Unit tests for validation/score.py. Run: python -m unittest validation.test_score
or, from the validation/ directory: python -m unittest test_score
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import run_comparator
import sample_benchmark
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


class FindExpectedCsvTests(unittest.TestCase):
    def test_discovers_java_suite_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "expectedresults-1.2.csv").write_text("# header\n")
            self.assertEqual(score.find_expected_csv(root).name, "expectedresults-1.2.csv")

    def test_discovers_python_suite_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "expectedresults-0.1.csv").write_text("# header\n")
            self.assertEqual(score.find_expected_csv(root).name, "expectedresults-0.1.csv")

    def test_explicit_path_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "expectedresults-1.2.csv").write_text("# header\n")
            chosen = root / "custom.csv"
            chosen.write_text("# header\n")
            self.assertEqual(score.find_expected_csv(root, chosen), chosen)

    def test_missing_csv_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                score.find_expected_csv(Path(tmp))

    def test_ambiguous_csv_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "expectedresults-1.2.csv").write_text("# header\n")
            (root / "expectedresults-0.1.csv").write_text("# header\n")
            with self.assertRaises(ValueError):
                score.find_expected_csv(root)


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


class SamplerExclusionTests(unittest.TestCase):
    """The --exclude / --categories draw used to build non-overlapping samples."""

    POOL = {
        "sqli": ["T1", "T2", "T3", "T4"],
        "cmdi": ["T5", "T6", "T7", "T8"],
    }

    def test_excluded_names_are_never_drawn(self):
        drawn = sample_benchmark.draw(self.POOL, 2, seed=42, exclude={"T1", "T2", "T5"})
        names = {name for name, _ in drawn}
        self.assertEqual(names & {"T1", "T2", "T5"}, set())
        self.assertEqual(len(names), 4)

    def test_draw_is_disjoint_from_a_prior_draw(self):
        first = sample_benchmark.draw(self.POOL, 2, seed=42)
        prior = {name for name, _ in first}
        second = sample_benchmark.draw(self.POOL, 2, seed=42, exclude=prior)
        self.assertEqual(prior & {name for name, _ in second}, set())

    def test_categories_restricts_the_draw(self):
        drawn = sample_benchmark.draw(self.POOL, 2, seed=42, categories=["sqli"])
        self.assertEqual({category for _, category in drawn}, {"sqli"})

    def test_draw_is_capped_by_remaining_pool(self):
        drawn = sample_benchmark.draw(self.POOL, 10, seed=42, exclude={"T1"})
        self.assertEqual(len(drawn), 7)

    def test_load_excluded_reads_only_the_name_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            prior = Path(tmp) / "prior.csv"
            prior.write_text("test_name,category\nT1,sqli\nT2,cmdi\n")
            self.assertEqual(sample_benchmark.load_excluded([prior]), {"T1", "T2"})

    def test_load_excluded_unions_multiple_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.csv"
            b = Path(tmp) / "b.csv"
            a.write_text("test_name,category\nT1,sqli\n")
            b.write_text("test_name,category\nT2,cmdi\n")
            self.assertEqual(sample_benchmark.load_excluded([a, b]), {"T1", "T2"})


class ComparatorIsolationTests(unittest.TestCase):
    """Helpers behind run_comparator.py's disposable-venv guarantee.

    The end-to-end install is not exercised here (it needs network and ~1 min);
    it is recorded in validation/owasp-benchmark-results.md. These cover the
    pure logic that decides where the venv interpreter lives and whether the
    host environment moved.
    """

    def test_witness_versions_covers_the_packages_semgrep_disturbs(self):
        versions = run_comparator.witness_versions()
        self.assertEqual(set(versions), set(run_comparator.WITNESS_PACKAGES))
        self.assertIn("mcp", versions)

    def test_absent_package_reports_a_sentinel_not_a_crash(self):
        versions = run_comparator.witness_versions()
        for value in versions.values():
            self.assertIsInstance(value, str)

    def test_venv_python_rejects_a_directory_without_an_interpreter(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                run_comparator.venv_python(Path(tmp))

    def test_venv_python_finds_the_interpreter_for_this_platform(self):
        import sys as _sys

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subdir = "Scripts" if _sys.platform == "win32" else "bin"
            name = "python.exe" if _sys.platform == "win32" else "python"
            (root / subdir).mkdir()
            (root / subdir / name).write_text("")
            self.assertEqual(run_comparator.venv_python(root), root / subdir / name)


if __name__ == "__main__":
    unittest.main()
