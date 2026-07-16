#!/usr/bin/env python3
"""Self-test for ``score.py`` on the synthetic fixtures.

This asserts the SCORER is correct — it does not measure SENTINEL's accuracy. The
fixtures under ``fixtures/`` are arranged so the confusion matrix and every derived
metric are known in advance; this file pins those known values.

Runs two ways:

    pytest validation/                # discovered as test_* functions
    python validation/test_score.py   # standalone, no pytest required (exit 0/1)
"""

from __future__ import annotations

import io
import json
import math
import sys
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import score  # noqa: E402  (path adjusted above)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FINDINGS = FIXTURES / "sample-findings.json"
BENCHMARK_TRUTH = FIXTURES / "sample-benchmark-truth.csv"
JUICE_TRUTH = FIXTURES / "sample-juice-shop-truth.json"


def _close(a: float, b: float) -> bool:
    return math.isclose(a, b, rel_tol=0, abs_tol=1e-9)


# ── Benchmark adapter ────────────────────────────────────────────────────────────


def test_benchmark_confusion_matrix() -> None:
    findings = score.load_findings(FINDINGS)
    truth = score.parse_benchmark_truth(BENCHMARK_TRUTH)
    result = score.score_benchmark(findings, truth)
    assert (result.tp, result.fp, result.fn, result.tn) == (3, 1, 2, 2)
    assert result.cases_scored == 8
    assert result.findings_total == 5
    assert result.findings_matched == 4
    assert result.findings_unmatched == 1  # BenchmarkTest09999 is not in the truth


def test_benchmark_metrics() -> None:
    findings = score.load_findings(FINDINGS)
    truth = score.parse_benchmark_truth(BENCHMARK_TRUTH)
    m = score.score_benchmark(findings, truth).metrics()
    assert _close(m.precision, 3 / 4)  # 0.75
    assert _close(m.recall, 3 / 5)  # 0.60
    assert _close(m.specificity, 2 / 3)  # 0.6667
    assert _close(m.f1, 2 * 0.75 * 0.6 / (0.75 + 0.6))  # 0.6667
    assert _close(m.false_negative_rate, 2 / 5)  # 0.40
    assert _close(m.youden_j, 0.6 + 2 / 3 - 1)  # 0.2667


def test_benchmark_match_cwe_is_consistent() -> None:
    # Every fixture finding carries the correct CWE for its case, so requiring a
    # CWE match must not change the matrix.
    findings = score.load_findings(FINDINGS)
    truth = score.parse_benchmark_truth(BENCHMARK_TRUTH)
    plain = score.score_benchmark(findings, truth, match_cwe=False)
    strict = score.score_benchmark(findings, truth, match_cwe=True)
    assert (plain.tp, plain.fp, plain.fn, plain.tn) == (strict.tp, strict.fp, strict.fn, strict.tn)


def test_benchmark_empty_findings_no_crash() -> None:
    truth = score.parse_benchmark_truth(BENCHMARK_TRUTH)
    result = score.score_benchmark([], truth)
    # 5 real cases become false negatives; 3 non-real become true negatives.
    assert (result.tp, result.fp, result.fn, result.tn) == (0, 0, 5, 3)
    m = result.metrics()
    assert _close(m.precision, 0.0)  # no division-by-zero
    assert _close(m.recall, 0.0)
    assert _close(m.false_negative_rate, 1.0)


def test_empty_truth_no_crash() -> None:
    result = score.score_benchmark([], {})
    assert (result.tp, result.fp, result.fn, result.tn) == (0, 0, 0, 0)
    m = result.metrics()
    assert _close(m.precision, 0.0)
    assert _close(m.f1, 0.0)
    assert _close(m.youden_j, -1.0)  # 0 recall + 0 specificity - 1


# ── Juice Shop adapter ───────────────────────────────────────────────────────────


def test_juice_shop_coverage() -> None:
    findings = score.load_findings(FINDINGS)
    challenges = score.parse_juice_shop_truth(JUICE_TRUTH)
    result = score.score_juice_shop(findings, challenges)
    assert result.tp == 3  # CWE 89, 79, 22 are asserted by findings
    assert result.fn == 3  # CWE 639, 1427, 918 are not
    assert result.fp is None and result.tn is None  # coverage-only
    m = result.metrics()
    assert _close(m.recall, 0.5)
    assert m.specificity is None and m.youden_j is None
    assert set(result.uncovered) == {
        "View another user's basket",
        "Prompt injection of the bot",
        "SSRF via image URL upload",
    }


# ── Serialization & CLI ──────────────────────────────────────────────────────────


def test_result_json_roundtrips() -> None:
    findings = score.load_findings(FINDINGS)
    truth = score.parse_benchmark_truth(BENCHMARK_TRUTH)
    payload = score.score_benchmark(findings, truth).as_dict()
    reparsed = json.loads(json.dumps(payload))
    assert reparsed["confusion_matrix"] == {"tp": 3, "fn": 2, "fp": 1, "tn": 2}
    assert reparsed["metrics"]["precision"] == 0.75
    assert reparsed["metrics"]["recall"] == 0.6


def test_cli_run_exit_codes() -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = score.run(
            ["--findings", str(FINDINGS), "--truth", str(BENCHMARK_TRUTH), "--format", "benchmark"]
        )
    assert rc == 0
    assert "Confusion matrix" in buf.getvalue()

    # Missing findings file is an input error, not a crash.
    missing = str(FIXTURES / "does-not-exist.json")
    rc = score.run(["--findings", missing, "--truth", str(BENCHMARK_TRUTH), "--format", "benchmark"])
    assert rc == 1


# ── Standalone runner (no pytest) ────────────────────────────────────────────────


def _main() -> int:
    tests = sorted(
        (name, obj)
        for name, obj in globals().items()
        if name.startswith("test_") and callable(obj)
    )
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 — surface any error in the harness
            failures += 1
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok    {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_main())
