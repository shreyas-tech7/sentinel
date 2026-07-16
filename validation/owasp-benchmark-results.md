# OWASP Benchmark Results

**Target:** [OWASP Benchmark](https://owasp.org/www-project-benchmark/) (BenchmarkJava) — ~2,700 synthetic
Java test cases, each labelled real-vulnerable or not in a shipped `expectedresults-*.csv`, with a category
and CWE per case.

**What it proves:** per-case true/false-positive accuracy against an explicit oracle. Because every case
is individually labelled, Benchmark yields a real confusion matrix — including the false positives — which
no self-graded audit of the maintainer's own code could produce. Its blind spot (synthetic, injection-
heavy, no authorization-gap cases) is documented in [METHODOLOGY.md](METHODOLOGY.md#known-limitations).

**Ground rule:** [static source review only](METHODOLOGY.md) — SENTINEL reads the Benchmark source and
reasons about each case. It does not deploy, execute, or attack the suite.

## Reproduction

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
# The oracle ships with the target: BenchmarkJava/expectedresults-1.2.csv

# Run a SENTINEL static pass (Phases 0-3) over the cloned source; export findings
# as an array of tooling.md-schema objects -> findings.json. No dynamic testing.

python validation/score.py \
    --findings findings.json \
    --truth   BenchmarkJava/expectedresults-1.2.csv \
    --format  benchmark --match-cwe
```

`--match-cwe` requires a finding to share the case's CWE, not merely land on the same file, so a finding of
the wrong class does not get credit. Add `--json` for a machine-readable object suitable for a CI gate. The
finding→case matching and every metric are defined in [METHODOLOGY.md](METHODOLOGY.md#how-a-finding-is-matched-to-a-label).

## Status

**No full-corpus measured numbers are reported here.** Producing them means running the reproduction steps
above across all ~2,700 cases of the live Benchmark — a large SENTINEL pass that was **not** performed as
part of building this harness. In keeping with the repo's standing discipline (see
[`examples/README.md`](../examples/README.md) and [`CHANGELOG.md`](../CHANGELOG.md)), this file documents
the protocol and ships the scorer rather than printing a precision/recall/F1 figure for SENTINEL that was
never actually measured. When the corpus pass is run, its confusion matrix and metrics drop straight out
of the command above; paste them under this heading with the Benchmark version and the finding-export date.

## Harness self-test (proves the scorer, not SENTINEL)

The scorer is verified independently of any real pass, against the synthetic
[fixtures](fixtures/README.md) whose confusion matrix is known by construction (TP 3 · FP 1 · FN 2 · TN 2).
**This tests the arithmetic in `score.py`. It is not a measurement of SENTINEL's accuracy on the OWASP
Benchmark** — the fixtures are fake findings against fake Benchmark rows.

```console
$ python validation/score.py \
    --findings validation/fixtures/sample-findings.json \
    --truth   validation/fixtures/sample-benchmark-truth.csv \
    --format  benchmark

SENTINEL validation - benchmark adapter
findings file: validation\fixtures\sample-findings.json
truth file:    validation\fixtures\sample-benchmark-truth.csv
match rule:    test-case id
------------------------------------------------------------
Confusion matrix
                    flagged   not flagged
  real vuln           3           2
  not vuln            1           2
------------------------------------------------------------
cases scored:      8
findings:          5 total, 4 matched, 1 unmatched
------------------------------------------------------------
precision            0.7500
recall (TPR)         0.6000
specificity (TNR)    0.6667
F1                   0.6667
Youden's J           0.2667
false-negative rate  0.4000
```

The one *unmatched* finding is intentional — it references a case (`BenchmarkTest09999`) absent from the
truth file, exercising the scorer's handling of a finding it cannot place. The self-test
([`test_score.py`](test_score.py)) asserts every number above; run it with `python validation/test_score.py`
(or `pytest validation/`).
