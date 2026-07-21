#!/usr/bin/env python3
"""Prove the silent-failure guards actually fire on the failures that happened.

Two real incidents motivate `harness_guard`, and a guard nobody has watched fail
is a guard nobody knows works. Each is reconstructed here against the real
scripts — not a mock of them — with deliberately broken input, and asserted to
abort loudly rather than produce a score:

  * **CRLF-mangled case list** (v8.0) — a sample written with Windows line
    endings leaves `\\r` on every name. Lookups miss, nothing is scanned, and the
    run reports a clean sweep of negatives.
  * **Unparseable files in the batch** (v8.0) — 28 files failed under the wrong
    interpreter, were absent from the tool's report, and would have been scored
    as 28 clean negatives.

The control cases matter as much as the failures: a guard that rejects healthy
input is worse than none, so each mode is paired with a well-formed run that must
still score.

Standard library only.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness_guard import (  # noqa: E402
    CaseCountMismatch,
    require_clean_names,
    require_count,
    require_exact_cases,
)

HERE = Path(__file__).resolve().parent
CASES = [("BenchmarkTest00001", "sqli", "true"), ("BenchmarkTest00002", "xss", "false")]


def _run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HERE / script), *args],
        capture_output=True,
        text=True,
        cwd=HERE,
    )


class GuardUnitTests(unittest.TestCase):
    """The primitives, exercised directly."""

    def test_require_count_passes_on_a_match(self):
        require_count(98, 98, "x")  # must not raise

    def test_require_count_raises_on_a_short_run(self):
        with self.assertRaises(CaseCountMismatch) as ctx:
            require_count(70, 98, "python batch")
        self.assertIn("processed 70", str(ctx.exception))
        self.assertIn("asked for 98", str(ctx.exception))

    def test_require_exact_cases_names_what_went_missing(self):
        with self.assertRaises(CaseCountMismatch) as ctx:
            require_exact_cases({"a", "b"}, {"a", "b", "c"}, "scoring")
        self.assertIn("never processed", str(ctx.exception))
        self.assertIn("c", str(ctx.exception))

    def test_require_exact_cases_catches_a_substitution(self):
        """Equal totals, different sets — the case require_count cannot see."""
        require_count(2, 2, "x")  # count alone is satisfied
        with self.assertRaises(CaseCountMismatch):
            require_exact_cases({"a", "z"}, {"a", "b"}, "scoring")

    def test_require_clean_names_flags_a_trailing_carriage_return(self):
        with self.assertRaises(CaseCountMismatch) as ctx:
            require_clean_names(["BenchmarkTest00001\r"], "sample.csv")
        self.assertIn("stray whitespace", str(ctx.exception))

    def test_require_clean_names_accepts_well_formed_names(self):
        require_clean_names(["BenchmarkTest00001"], "sample.csv")  # must not raise


class CrlfMangledCaseListTests(unittest.TestCase):
    """Failure mode 1: a case list written with the wrong line endings."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

        self.root = self.tmp / "bench"
        self.root.mkdir()
        with (self.root / "expectedresults-1.2.csv").open("w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["name", "category", "real"])
            writer.writerows(CASES)

        self.verdicts = self.tmp / "verdicts.json"
        self.verdicts.write_text(
            json.dumps(
                [
                    {"test_name": n, "category": c, "vulnerable": True}
                    for n, c, _ in CASES
                ]
            ),
            encoding="utf-8",
        )

    def _sample(self, name: str, terminator: str) -> Path:
        path = self.tmp / name
        rows = "".join(f"{n},{c}{terminator}" for n, c, _ in CASES)
        path.write_bytes((f"test_name,category{terminator}" + rows).encode())
        return path

    def test_a_healthy_sample_still_scores(self):
        """Control: the guard must not reject a well-formed run."""
        result = _run(
            "score.py",
            "--benchmark-root", str(self.root),
            "--verdicts", str(self.verdicts),
            "--sample", str(self._sample("clean.csv", "\n")),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"TP"', result.stdout)

    def test_a_crlf_mangled_sample_csv_aborts_instead_of_scoring(self):
        """A stray CR inside a CSV destroys row structure rather than the name.

        Python's csv reader treats a bare `\\r` as a row terminator, so
        `BenchmarkTest00001\\r,sqli` splits into two rows and the case list comes
        out short with an empty name in it — not as a name with `\\r` glued on.
        The set comparison is what catches this shape; the whitespace guard never
        sees it. Asserted as observed, not as first assumed.
        """
        sample = self.tmp / "mangled.csv"
        rows = "".join(f"{n}\r,{c}\n" for n, c, _ in CASES)
        sample.write_bytes(("test_name,category\n" + rows).encode())

        result = _run(
            "score.py",
            "--benchmark-root", str(self.root),
            "--verdicts", str(self.verdicts),
            "--sample", str(sample),
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("case set does not match", result.stderr)
        self.assertNotIn('"TP"', result.stdout, "aborted runs must not emit a score")

    def test_a_crlf_mangled_name_list_aborts_instead_of_scoring(self):
        """The incident's actual shape: a newline-delimited list, not a CSV.

        A file list round-tripped through the wrong line endings leaves `\\r` on
        every entry. Those names are not equal to any real case id, so every
        lookup misses and the scan covers nothing while still exiting 0. Here the
        mangled names reach the scorer through the verdicts file, where they
        survive intact — and the whitespace guard is what fires.
        """
        mangled = self.tmp / "mangled-verdicts.json"
        mangled.write_text(
            json.dumps(
                [
                    {"test_name": f"{n}\r", "category": c, "vulnerable": True}
                    for n, c, _ in CASES
                ]
            ),
            encoding="utf-8",
        )

        result = _run(
            "score.py",
            "--benchmark-root", str(self.root),
            "--verdicts", str(mangled),
            "--sample", str(self._sample("clean2.csv", "\n")),
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("stray whitespace", result.stderr)
        self.assertIn("line endings", result.stderr)
        self.assertNotIn('"TP"', result.stdout, "aborted runs must not emit a score")

    def test_without_the_guard_a_mangled_run_would_have_scored(self):
        """The counterfactual, made explicit: this is what used to happen.

        Same mangled verdict names, no `--sample` and no clean-name check — the
        old code path. It produces a full results table off names that match
        nothing, which is exactly the silent failure the guard exists to stop.
        """
        mangled_names = [f"{n}\r" for n, _, _ in CASES]
        with self.assertRaises(CaseCountMismatch):
            require_clean_names(mangled_names, "file-list")
        # ...and the set comparison independently rejects them, so neither guard
        # is load-bearing alone.
        with self.assertRaises(CaseCountMismatch):
            require_exact_cases(mangled_names, [n for n, _, _ in CASES], "scoring")


class UnparseableBatchTests(unittest.TestCase):
    """Failure mode 2: files the tool never analyzed, scored as clean negatives."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

        self.sample = self.tmp / "sample.csv"
        with self.sample.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["test_name", "category"])
            writer.writerows([(n, c) for n, c, _ in CASES])

        self.out = self.tmp / "verdicts.json"

    def _report(self, path: Path, errors: list[dict], results: list[dict]) -> Path:
        path.write_text(
            json.dumps({"errors": errors, "results": results}), encoding="utf-8"
        )
        return path

    def test_a_clean_report_still_converts(self):
        """Control: no errors, every sampled case accounted for."""
        report = self._report(
            self.tmp / "clean.json",
            errors=[],
            results=[
                {
                    "filename": "/b/BenchmarkTest00001.py",
                    "issue_severity": "HIGH",
                    "test_id": "B608",
                    "test_name": "hardcoded_sql_expressions",
                }
            ],
        )
        result = _run(
            "bandit_to_verdicts.py",
            "--report", str(report),
            "--sample", str(self.sample),
            "--out", str(self.out),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(self.out.read_text())), len(CASES))

    def test_files_that_failed_to_parse_abort_the_conversion(self):
        report = self._report(
            self.tmp / "errored.json",
            errors=[{"filename": "/b/BenchmarkTest00002.py", "reason": "syntax error"}],
            results=[],
        )
        result = _run(
            "bandit_to_verdicts.py",
            "--report", str(report),
            "--sample", str(self.sample),
            "--out", str(self.out),
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("must not be scored as negatives", result.stderr)
        self.assertFalse(self.out.exists(), "aborted runs must not write verdicts")

    def test_a_truncated_sample_cannot_be_scored_against_a_full_run(self):
        """The count guard on score.py: fewer verdicts than the sample asked for."""
        root = self.tmp / "bench"
        root.mkdir()
        with (root / "expectedresults-1.2.csv").open("w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["name", "category", "real"])
            writer.writerows(CASES)

        short = self.tmp / "short-verdicts.json"
        short.write_text(
            json.dumps([{"test_name": CASES[0][0], "category": "sqli", "vulnerable": True}]),
            encoding="utf-8",
        )

        result = _run(
            "score.py",
            "--benchmark-root", str(root),
            "--verdicts", str(short),
            "--sample", str(self.sample),
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("never processed", result.stderr)
        self.assertIn("BenchmarkTest00002", result.stderr)


if __name__ == "__main__":
    unittest.main()
