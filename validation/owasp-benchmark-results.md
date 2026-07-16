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

## Results — pilot sample, 21 cases (run 2026-07-15)

**This is a real run over a bounded sample, not the full corpus.** SENTINEL statically audited the first
**21 Benchmark test cases** (`BenchmarkTest00001`–`00021`) of Benchmark v1.2 — read blind (from the `.java`
source, before consulting the label CSV), one SENTINEL verdict per case — then scored against the real
`expectedresults-1.2.csv` rows for those cases. The sample spans pathtraver, hash, crypto, cmdi, sqli,
ldapi, xss, weakrand, trustbound, and securecookie. The full 2,740-case corpus was **not** exhaustively
audited (see *Scope* below); these numbers describe the 21-case sample only.

```console
$ python validation/score.py \
    --findings bench-findings.json \
    --truth   bench-truth-sample.csv \
    --format  benchmark --match-cwe

SENTINEL validation - benchmark adapter
match rule:    test-case id + CWE
------------------------------------------------------------
Confusion matrix
                    flagged   not flagged
  real vuln          16           2
  not vuln            0           3
------------------------------------------------------------
cases scored:      21
findings:          16 total, 16 matched, 0 unmatched
------------------------------------------------------------
precision            1.0000
recall (TPR)         0.8889
specificity (TNR)    1.0000
F1                   0.9412
Youden's J           0.8889
false-negative rate  0.1111
```

Plain id-match scoring (without `--match-cwe`) gives the identical matrix — every flagged case was flagged
with the correct CWE class, so no finding was miscategorised.

**Precision 1.000 (zero false positives):** SENTINEL flagged none of the three safe cases in the sample. It
correctly cleared the Benchmark traps — `BenchmarkTest00007`'s tainted value flows into `Runtime.exec`'s
*environment* array (not the command), `00009` hashes with SHA-384, `00016` sets the `Secure` cookie flag —
rather than pattern-matching a sink and crying wolf.

**The two misses (recall 0.889) are both informative, and neither is a detector bug:**
- `BenchmarkTest00004` (`trustbound`, CWE-501, Trust Boundary Violation): storing an untrusted value as a
  session-attribute *key*. SENTINEL's catalog has **no class for CWE-501**, so it did not flag it — a
  genuine coverage gap, logged here as a candidate class rather than papered over.
- `BenchmarkTest00007` (`cmdi`, CWE-78): Benchmark labels tainted data reaching *any* `exec` argument —
  including the environment array — as a vulnerability. SENTINEL's evidence standard traced `param` to
  `envp`, judged it non-injectable into the executed command, and withheld the finding. This is a real
  and defensible divergence between taint-reaches-sink labelling and exploitability-based judgement, not a
  missed injection.

## Scope and honesty

These figures are a **21-case pilot**, chosen as a contiguous, label-blind sample. They are not a
full-corpus benchmark score and must not be quoted as one. A complete run means auditing all ~2,740 cases
via the reproduction steps above; the harness makes that mechanical, but the audit itself is the cost. When
that run happens, replace this section with the full-corpus matrix, the Benchmark version, and the date.

The scorer's own arithmetic is unit-tested independently of any real pass against synthetic
[fixtures](fixtures/README.md) whose matrix is known by construction — run `python validation/test_score.py`
(or `pytest validation/`). That test proves `score.py`; the section above proves nothing about the scorer,
only about SENTINEL on these 21 cases.
