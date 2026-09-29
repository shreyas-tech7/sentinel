"""Scanner orchestration + CLI end-to-end tests."""

import json
import tempfile
import unittest
from pathlib import Path

from sentinel.scanner import scan_report, scan_path, _included
from sentinel.cli import main as cli_main


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "app.py").write_text(
            "from flask import request\n"
            "def go(cursor):\n"
            "    q = f\"SELECT * FROM t WHERE a = '{request.args.get('id')}'\"\n"
            "    cursor.execute(q)\n"
        )
        (root / "node_modules" / "lib.js").parent.mkdir()
        (root / "node_modules" / "lib.js").write_text("el.innerHTML = location.hash;")
        (root / "skip.txt").write_text("not code\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_report_shape(self):
        report = scan_report(Path(self.tmp.name))
        self.assertEqual(report["tool"], "sentinel")
        self.assertIn("version", report)
        self.assertEqual(1, report["stats"]["files_scanned"])
        self.assertGreaterEqual(len(report["findings"]), 1)
        f = report["findings"][0]
        for key in ("rule_id", "vuln_class", "cwe", "severity", "confidence",
                    "file", "line", "message", "snippet", "language"):
            self.assertIn(key, f)

    def test_skips_node_modules(self):
        report = scan_report(Path(self.tmp.name))
        files = [f["file"] for f in report["findings"]]
        self.assertTrue(all(not f.startswith("node_modules") for f in files))

    def test_deterministic(self):
        a = scan_report(Path(self.tmp.name))
        b = scan_report(Path(self.tmp.name))
        self.assertEqual(a["findings"], b["findings"])

    def test_include_globs(self):
        report = scan_report(Path(self.tmp.name), ("*.py",))
        self.assertEqual(1, report["stats"]["files_scanned"])
        self.assertTrue(_included("routes/search.ts", ("routes/",)))
        self.assertFalse(_included("lib/util.ts", ("routes/",)))
        self.assertTrue(_included("sql_injection/sqli_php_01.php", ("sqli*",)))
        self.assertFalse(_included("xss/xss_php_01.php", ("sqli*",)))


class TestCli(unittest.TestCase):
    def test_scan_json_roundtrip(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = cli_main(["scan", "bench/corpus/sql_injection/sqli_php_mysqli_01.php",
                               "--json", str(out), "--table"])
            self.assertEqual(0, rc)
            report = json.loads(out.read_text())
            self.assertEqual("sql_injection", report["findings"][0]["vuln_class"])

    def test_version(self):
        from sentinel import __version__
        self.assertGreaterEqual(int(__version__.split(".")[0]), 4)


class TestBenchmarkHarness(unittest.TestCase):
    def test_corpus_scores_complete_and_strong(self):
        """End-to-end: run the harness scorer on the real corpus.

        The corpus is fully labeled, so the scorer must accept it in complete
        mode and — since every vulnerable sample was validated against the
        analyzer during development — precision must be perfect. Recall is
        asserted at 1.0 because a rule regression should fail CI loudly.
        """
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from bench.run_benchmark import TARGETS, score_target
        result = score_target("corpus", TARGETS["corpus"], Path("/tmp/bench-targets"))
        self.assertEqual("ok", result["status"])
        self.assertEqual(1.0, result["overall"]["precision"])
        self.assertEqual(1.0, result["overall"]["recall"])
        self.assertGreaterEqual(result["overall"]["tp"], 35)

    def test_metrics_math(self):
        from bench.run_benchmark import metrics
        m = metrics(tp=8, fp=2, fn=2)
        self.assertEqual(0.8, m["precision"])
        self.assertEqual(0.8, m["recall"])
        self.assertEqual(0.8, round(m["f1"], 4))
        empty = metrics(tp=0, fp=0, fn=0)
        self.assertIsNone(empty["precision"])
        self.assertIsNone(empty["f1"])


if __name__ == "__main__":
    unittest.main()
