# Scorer fixtures (synthetic)

Everything in this directory is **synthetic test data for [`score.py`](../score.py)**. None of it is a
real audit, a real target, or a measurement of SENTINEL's accuracy. It exists so
[`test_score.py`](../test_score.py) can assert the scorer computes a known confusion matrix correctly —
it validates the *scorer*, not SENTINEL.

| File | What it is | Arranged to yield |
|---|---|---|
| [`sample-findings.json`](sample-findings.json) | Five fake findings in the [tooling.md finding schema](../../skill/references/tooling.md#machine-readable-findings). Four reference cases in the truth CSV; one references `BenchmarkTest09999`, absent from it. | 4 matched findings, 1 unmatched |
| [`sample-benchmark-truth.csv`](sample-benchmark-truth.csv) | Eight fake OWASP-Benchmark-shaped rows (5 real-vulnerable, 3 not). | TP 3 · FP 1 · FN 2 · TN 2 |
| [`sample-juice-shop-truth.json`](sample-juice-shop-truth.json) | Six fake Juice-Shop-shaped challenges. Three carry a CWE the findings assert; three do not. | covered 3 / 6 (recall 0.5) |

The expected metrics that fall out of these counts (precision 0.75, recall 0.60, specificity 0.6667,
F1 0.6667, Youden's J 0.2667 for the benchmark adapter) are the hard-coded assertions in
[`test_score.py`](../test_score.py). If you change a fixture, that test will fail until you update the
expected numbers — which is the point.

These CWE ids (89, 79, 22, 639, 1427, 918, 327) and Benchmark test names are illustrative and do not
correspond to any real Benchmark case or Juice Shop challenge id.
