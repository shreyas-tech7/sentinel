# SENTINEL vs. OWASP Benchmark — validation run

**Date produced:** 2026-07-19
**Target:** [OWASP Benchmark Java](https://owasp.org/www-project-benchmark/) v1.2 (test suite
`expectedresults-1.2.csv`, 2740 test cases), cloned at commit `79b9bd6`.
**Method:** SENTINEL's four-phase static methodology (Phases 0–3), applied by hand to a blind,
stratified, reproducible sample. **Comparator:** Semgrep 1.170.0 with the official
`semgrep/semgrep-rules` Java ruleset (commit `e5b5a42`), run against the identical file set.

This is a **static-analysis-only** exercise. Nothing here was executed, deployed, or attacked. The
Benchmark test cases are known-vulnerable-by-design practice code; auditing them measures detection
accuracy, it does not attack anything.

---

## How to reproduce

```bash
# 1. Clone the target next to this repo
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git

# 2. Draw the same blind sample (seed-fixed; reads only name+category, never the truth column)
python validation/sample_benchmark.py --benchmark-root ../BenchmarkJava \
    --per-category 6 --seed 42 --out validation/data/benchmark-sample.csv

# 3a. SENTINEL verdicts were produced by manual four-phase analysis of the sampled files;
#     they are recorded in validation/data/sentinel-benchmark-verdicts.json
#     (annotated with per-case reasoning in ...-annotated.json).
python validation/score.py --benchmark-root ../BenchmarkJava \
    --verdicts validation/data/sentinel-benchmark-verdicts.json --label SENTINEL --markdown

# 3b. Semgrep, same files, official Java rules
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git
semgrep scan --config semgrep-rules/java --json --quiet --metrics=off <sampled files> > sg.json
#   A test case counts as "flagged" if Semgrep reports >=1 finding in its file.
python validation/score.py --benchmark-root ../BenchmarkJava \
    --verdicts validation/data/semgrep-benchmark-verdicts.json --label "Semgrep java rules" --markdown
```

The scoring harness (`validation/score.py`) reads the ground-truth flag in exactly one place and is
covered by `validation/test_score.py` (10 unit tests, all passing).

## Sample

- **66 test cases** — 6 per category across all 11 Benchmark categories (`cmdi`, `crypto`, `hash`,
  `ldapi`, `pathtraver`, `securecookie`, `sqli`, `trustbound`, `weakrand`, `xpathi`, `xss`).
- Ground-truth split of the sample: **31 real vulnerabilities, 35 non-vulnerabilities** — the
  Benchmark deliberately pairs each true positive with structurally similar decoys (an always-true
  guard that discards tainted input, a safe map-key overwrite, a `SecureRandom` in place of
  `java.util.Random`, a strong cipher in place of DES) so that a tool scoring well on recall alone,
  by flagging every sink, is punished on precision.
- The sample is drawn blind: `sample_benchmark.py` reads only the test name and category columns, not
  the truth flag, so the analyst worked without the answer key. Scoring happened only afterward.

## Results — SENTINEL (2026-07-19)

| Category | N | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 6 | 0 | 0 | 0 | 6 | n/a | n/a | n/a |
| crypto | 6 | 5 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| hash | 6 | 3 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 |
| ldapi | 6 | 3 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 |
| pathtraver | 6 | 4 | 0 | 0 | 2 | 1.0000 | 1.0000 | 1.0000 |
| securecookie | 6 | 4 | 0 | 0 | 2 | 1.0000 | 1.0000 | 1.0000 |
| sqli | 6 | 2 | 0 | 0 | 4 | 1.0000 | 1.0000 | 1.0000 |
| trustbound | 6 | 5 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| weakrand | 6 | 3 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 |
| xpathi | 6 | 0 | 0 | 0 | 6 | n/a | n/a | n/a |
| xss | 6 | 2 | 0 | 0 | 4 | 1.0000 | 1.0000 | 1.0000 |
| **Overall** | **66** | **31** | **0** | **0** | **35** | **1.0000** | **1.0000** | **1.0000** |

`n/a` for `cmdi` and `xpathi` reflects that the six sampled cases in each of those categories are all
true-negatives (precision and recall are undefined with zero positives); SENTINEL classified all six
correctly in both, contributing 12 true-negatives.

### Reading this number honestly

66/66 is a real result on this blind sample — verified independently against the truth column with
zero mismatches — **but it is not a claim of perfect accuracy on real-world code, and should not be
read as one.** Two things make the Benchmark specifically tractable for a careful manual pass:

1. **The cases are deterministic dataflow puzzles.** Every decoy is a closed, self-contained trick:
   an `if ((7*42)-86 > 200)` that always takes the constant branch, a `List` that `remove(0)`s the
   safe element and returns the tainted one, a `switch` on a fixed char. A human tracing the value to
   the sink resolves each one exactly. Real code's ambiguity — reachability that depends on
   configuration, controls in files you weren't shown — is exactly what the Phase 5 *falsifier* and
   *confidence* rubric exist to flag, and none of that ambiguity is present here.
2. **The config was resolvable.** The `crypto`/`hash` verdicts depend on `benchmark.properties`
   (`cryptoAlg1=DES/ECB/PKCS5Padding`, `cryptoAlg2=AES/CCM/NoPadding`, `hashAlg1=MD5`,
   `hashAlg2=SHA-256`). SENTINEL reads config files as part of the audit, so `getProperty("hashAlg1")`
   resolved to MD5 (weak) rather than the `"SHA512"` default in the source. That single step is the
   difference on `BenchmarkTest01416` — see the comparison below.

The honest takeaway is not "SENTINEL is perfect" but "on cases where the missing control is fully
visible in the code and config, a traced-dataflow methodology reaches the correct verdict without the
false positives a pattern matcher produces." Precision is the axis this sample actually stresses.

## Results — Semgrep 1.170.0, `semgrep/semgrep-rules` Java rules (same 66 files, 2026-07-19)

| Category | N | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 6 | 0 | 5 | 0 | 1 | 0.0000 | n/a | n/a |
| crypto | 6 | 5 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| hash | 6 | 2 | 0 | 1 | 3 | 1.0000 | 0.6667 | 0.8000 |
| ldapi | 6 | 3 | 2 | 0 | 1 | 0.6000 | 1.0000 | 0.7500 |
| pathtraver | 6 | 4 | 2 | 0 | 0 | 0.6667 | 1.0000 | 0.8000 |
| securecookie | 6 | 4 | 0 | 0 | 2 | 1.0000 | 1.0000 | 1.0000 |
| sqli | 6 | 2 | 3 | 0 | 1 | 0.4000 | 1.0000 | 0.5714 |
| trustbound | 6 | 5 | 1 | 0 | 0 | 0.8333 | 1.0000 | 0.9091 |
| weakrand | 6 | 3 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 |
| xpathi | 6 | 0 | 4 | 0 | 2 | 0.0000 | n/a | n/a |
| xss | 6 | 2 | 1 | 0 | 3 | 0.6667 | 1.0000 | 0.8000 |
| **Overall** | **66** | **30** | **18** | **1** | **17** | **0.6250** | **0.9677** | **0.7595** |

### Side by side

| Tool | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| **SENTINEL** (manual four-phase) | 31 | 0 | 0 | 35 | **1.0000** | **1.0000** | **1.0000** |
| **Semgrep** (`semgrep-rules/java`) | 30 | 18 | 1 | 17 | 0.6250 | 0.9677 | 0.7595 |

### What the comparison actually shows

The two tools agree closely on **recall** — Semgrep found 30 of 31 real vulnerabilities, confirming
that the "true" cases in this sample are genuinely detectable and that SENTINEL's 31/31 is not
flagging phantom bugs. The gap is entirely in **precision**, and it is instructive rather than
incidental:

- **All 18 Semgrep false positives are the Benchmark's decoy patterns** — the cases engineered to
  look vulnerable at the sink while the taint is actually dead:
  - `cmdi` ×5, `sqli` ×3, `xpathi` ×4, `ldapi` ×2, `pathtraver` ×2, `trustbound` ×1, `xss` ×1.
  - They fire on rules like `tainted-cmd-from-http-request`, `httpservlet-path-traversal`, and
    `hardcoded-conditional`: the source and the sink are both real, so a taint rule matches, but the
    always-true guard / safe-overwrite / safe-source step in between is not modeled. `no-direct-
    response-writer` also fires on servlets that write to the response even when the written value is
    a constant. This is the exact discipline SENTINEL's Phase 5 evidence standard enforces — a
    finding requires the missing control to be absent *on the path that runs*, not merely a
    source-to-sink shape.
- **Semgrep's one false negative is `BenchmarkTest01416` (`hash`)** — the case whose algorithm is
  `hashAlg1` read from `benchmark.properties` (= `MD5`). The rule set flags literal `MD5`/`SHA1`
  strings but does not resolve a property value pulled from a separate file, so it missed the weak
  hash. SENTINEL caught it by reading the config, which is a routine Phase 0/Phase 3 step.

### Fairness caveats (both directions)

- **This is not a throughput comparison.** Semgrep scanned all 66 files in seconds and would scan the
  full 2740-case suite about as fast; SENTINEL's numbers come from a human-paced manual trace of a
  66-case sample and do **not** imply the same accuracy at Benchmark's full scale or on a large real
  codebase. The methodologies are complementary: a scanner like Semgrep is the right Phase-3
  lead generator, and SENTINEL's own guidance (`references/tooling.md`) says exactly that — tools
  produce leads, the audit produces findings.
- **The comparator ruleset is the community `semgrep/semgrep-rules` Java directory, not the hosted
  `p/java` registry pack** (the registry endpoint `semgrep.dev` is blocked by this environment's
  network policy — see the run log). `p/java` is a curated subset of this same repository, so the
  rules exercised here are Semgrep's own published Java rules, but the exact rule membership of the
  hosted pack may differ slightly. The ruleset commit (`e5b5a42`) is pinned above for reproducibility.
- **Sample size is 66.** Per-category cells are 6 cases each; treat category-level precision/recall as
  directional, not precise. The overall figures are the load-bearing ones.

## Files

- `validation/data/benchmark-sample.csv` — the blind sample (seed 42).
- `validation/data/sentinel-benchmark-verdicts.json` — SENTINEL's per-case verdicts.
- `validation/data/sentinel-benchmark-verdicts-annotated.json` — the same, with the one-line
  dataflow reasoning behind each verdict.
- `validation/data/semgrep-benchmark-verdicts.json` /
  `...-annotated.json` — Semgrep's per-case verdicts and the rule IDs that fired.
- `validation/sample_benchmark.py`, `validation/score.py`, `validation/test_score.py` — the harness.

---

# Scaled run — 208 cases across two languages (2026-07-19)

**This section extends the 66-case run above; it does not replace it.** The earlier run stands as
recorded. Read this one first: it is larger, it covers a second language, and **it corrects the
earlier run's headline claim.** The 66-case sample produced a perfect 1.0000 F1. At 110 Java cases
that result did not hold — SENTINEL scored **F1 0.9358**, with five false positives and two false
negatives traced to two specific, nameable analytical errors. That correction is the most important
output of this run.

**Date produced:** 2026-07-19
**Targets:**
- [OWASP Benchmark Java](https://github.com/OWASP-Benchmark/BenchmarkJava) v1.2 (2740 cases), commit `79b9bd6`.
- [OWASP Benchmark Python](https://github.com/OWASP-Benchmark/BenchmarkPython) v0.1 (1230 cases), commit `f129148`.

**Note on the Python suite:** OWASP Benchmark has no Python cases inside `BenchmarkJava` — that
repository is Java-only. The Python suite is a **separate repository**, `OWASP-Benchmark/BenchmarkPython`,
with its own ground-truth file (`expectedresults-0.1.csv` rather than `expectedresults-1.2.csv`) and a
different category set: it drops `crypto` and adds `codeinj`, `deserialization`, `redirect`, and `xxe`,
for 14 categories against Java's 11.

**Comparator:** Semgrep 1.170.0 with the official `semgrep/semgrep-rules` `java/` and `python/`
directories, commit `e5b5a42` — the same version and ruleset commit as the 66-case run.

Static-analysis-only, as before. Nothing was executed, deployed, or attacked; both Benchmark clones
were read, never run.

## Sample

| Suite | Per category | Categories | Total | Ground-truth split |
|---|---|---|---|---|
| Java | 10 | 11 | **110** | 53 real / 57 not real |
| Python | 7 | 14 | **98** | 30 real / 68 not real |
| | | | **208 total** | |

Drawn by the same seed-fixed blind sampler (`sample_benchmark.py`, seed 42), which reads only the name
and category columns. **12 of the 110 Java cases also appear in the original 66-case sample; 98 are
fresh.** The Python sample shares nothing with any prior run.

### Reproducing

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git

python validation/sample_benchmark.py --benchmark-root ../BenchmarkJava \
    --per-category 10 --seed 42 --out validation/data/benchmark-sample-java-v6.csv
python validation/sample_benchmark.py --benchmark-root ../BenchmarkPython \
    --per-category 7 --seed 42 --out validation/data/benchmark-sample-python-v6.csv

# Read the sampled cases (presentation only — strips license/boilerplate, decides nothing)
python validation/show_cases.py --benchmark-root ../BenchmarkJava \
    --sample validation/data/benchmark-sample-java-v6.csv --lang java --start 0 --count 10 --terse

python validation/score.py --benchmark-root ../BenchmarkJava \
    --verdicts validation/data/sentinel-benchmark-java-v6-verdicts.json --label "SENTINEL Java v6" --markdown
python validation/score.py --benchmark-root ../BenchmarkPython \
    --verdicts validation/data/sentinel-benchmark-python-v6-verdicts.json --label "SENTINEL Python v6" --markdown
```

`score.py` and `sample_benchmark.py` now auto-discover `expectedresults-*.csv` so the same harness
serves both suites; `--expected-csv` overrides it. The Java command above reproduces the original
66-case numbers unchanged.

Semgrep (installed only for the comparison, then removed — it pins `mcp==1.23.3`, which conflicts
with other tooling in this environment):

```bash
pip install semgrep==1.170.0
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git   # commit e5b5a42
semgrep scan --config semgrep-rules/java --json --quiet --metrics=off <sampled java files> > sg-java.json
semgrep scan --config semgrep-rules/python --json --quiet --metrics=off <sampled py files> > sg-py.json
```

## Results — SENTINEL, Java (110 cases, 2026-07-19)

| Category | N | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 10 | 1 | 0 | 2 | 7 | 1.0000 | 0.3333 | 0.5000 |
| crypto | 10 | 5 | 0 | 0 | 5 | 1.0000 | 1.0000 | 1.0000 |
| hash | 10 | 7 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 |
| ldapi | 10 | 5 | 1 | 0 | 4 | 0.8333 | 1.0000 | 0.9091 |
| pathtraver | 10 | 5 | 1 | 0 | 4 | 0.8333 | 1.0000 | 0.9091 |
| securecookie | 10 | 4 | 0 | 0 | 6 | 1.0000 | 1.0000 | 1.0000 |
| sqli | 10 | 6 | 2 | 0 | 2 | 0.7500 | 1.0000 | 0.8571 |
| trustbound | 10 | 7 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 |
| weakrand | 10 | 3 | 0 | 0 | 7 | 1.0000 | 1.0000 | 1.0000 |
| xpathi | 10 | 5 | 0 | 0 | 5 | 1.0000 | 1.0000 | 1.0000 |
| xss | 10 | 3 | 1 | 0 | 6 | 0.7500 | 1.0000 | 0.8571 |
| **all (SENTINEL Java v6)** | 110 | 51 | 5 | 2 | 52 | 0.9107 | 0.9623 | 0.9358 |

## Results — SENTINEL, Python (98 cases, 2026-07-19)

| Category | N | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 7 | 6 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| codeinj | 7 | 2 | 0 | 0 | 5 | 1.0000 | 1.0000 | 1.0000 |
| deserialization | 7 | 2 | 0 | 0 | 5 | 1.0000 | 1.0000 | 1.0000 |
| hash | 7 | 1 | 0 | 0 | 6 | 1.0000 | 1.0000 | 1.0000 |
| ldapi | 7 | 3 | 0 | 0 | 4 | 1.0000 | 1.0000 | 1.0000 |
| pathtraver | 7 | 3 | 0 | 0 | 4 | 1.0000 | 1.0000 | 1.0000 |
| redirect | 7 | 1 | 0 | 0 | 6 | 1.0000 | 1.0000 | 1.0000 |
| securecookie | 7 | 4 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 |
| sqli | 7 | 2 | 0 | 0 | 5 | 1.0000 | 1.0000 | 1.0000 |
| trustbound | 7 | 3 | 0 | 0 | 4 | 1.0000 | 1.0000 | 1.0000 |
| weakrand | 7 | 1 | 0 | 0 | 6 | 1.0000 | 1.0000 | 1.0000 |
| xpathi | 7 | 1 | 0 | 0 | 6 | 1.0000 | 1.0000 | 1.0000 |
| xss | 7 | 0 | 1 | 0 | 6 | 0.0000 | n/a | n/a |
| xxe | 7 | 1 | 0 | 0 | 6 | 1.0000 | 1.0000 | 1.0000 |
| **all (SENTINEL Python v6)** | 98 | 30 | 1 | 0 | 67 | 0.9677 | 1.0000 | 0.9836 |

## Head-to-head

| Run | N | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| SENTINEL — Java, 66-case (earlier run) | 66 | 31 | 0 | 0 | 35 | 1.0000 | 1.0000 | 1.0000 |
| **SENTINEL — Java, 110-case** | 110 | 51 | 5 | 2 | 52 | **0.9107** | **0.9623** | **0.9358** |
| **SENTINEL — Python, 98-case** | 98 | 30 | 1 | 0 | 67 | **0.9677** | **1.0000** | **0.9836** |
| Semgrep — Java, 66-case (earlier run) | 66 | 30 | 18 | 1 | 17 | 0.6250 | 0.9677 | 0.7595 |
| Semgrep — Java, 110-case | 110 | 45 | 26 | 8 | 31 | 0.6338 | 0.8491 | 0.7258 |
| Semgrep — Python, 98-case (all rules) | 98 | 30 | 68 | 0 | 0 | 0.3061 | 1.0000 | 0.4687 |
| Semgrep — Python, 98-case (security-only) | 98 | 19 | 22 | 11 | 46 | 0.4634 | 0.6333 | 0.5352 |

Semgrep's Java figures are stable across the two samples (F1 0.7595 → 0.7258), which is a good sign
that the sampling is not doing anything strange. SENTINEL's are not stable, and that is the finding.

### Semgrep per-category

| Category | N | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 10 | 3 | 6 | 0 | 1 | 0.3333 | 1.0000 | 0.5000 |
| crypto | 10 | 5 | 1 | 0 | 4 | 0.8333 | 1.0000 | 0.9091 |
| hash | 10 | 4 | 0 | 3 | 3 | 1.0000 | 0.5714 | 0.7273 |
| ldapi | 10 | 5 | 4 | 0 | 1 | 0.5556 | 1.0000 | 0.7143 |
| pathtraver | 10 | 3 | 4 | 2 | 1 | 0.4286 | 0.6000 | 0.5000 |
| securecookie | 10 | 4 | 0 | 0 | 6 | 1.0000 | 1.0000 | 1.0000 |
| sqli | 10 | 6 | 2 | 0 | 2 | 0.7500 | 1.0000 | 0.8571 |
| trustbound | 10 | 4 | 0 | 3 | 3 | 1.0000 | 0.5714 | 0.7273 |
| weakrand | 10 | 3 | 0 | 0 | 7 | 1.0000 | 1.0000 | 1.0000 |
| xpathi | 10 | 5 | 4 | 0 | 1 | 0.5556 | 1.0000 | 0.7143 |
| xss | 10 | 3 | 5 | 0 | 2 | 0.3750 | 1.0000 | 0.5455 |
| **all (Semgrep Java v6)** | 110 | 45 | 26 | 8 | 31 | 0.6338 | 0.8491 | 0.7258 |

| Category | N | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 7 | 6 | 1 | 0 | 0 | 0.8571 | 1.0000 | 0.9231 |
| codeinj | 7 | 2 | 5 | 0 | 0 | 0.2857 | 1.0000 | 0.4444 |
| deserialization | 7 | 2 | 4 | 0 | 1 | 0.3333 | 1.0000 | 0.5000 |
| hash | 7 | 1 | 0 | 0 | 6 | 1.0000 | 1.0000 | 1.0000 |
| ldapi | 7 | 0 | 1 | 3 | 3 | 0.0000 | 0.0000 | n/a |
| pathtraver | 7 | 0 | 0 | 3 | 4 | n/a | 0.0000 | n/a |
| redirect | 7 | 0 | 0 | 1 | 6 | n/a | 0.0000 | n/a |
| securecookie | 7 | 4 | 3 | 0 | 0 | 0.5714 | 1.0000 | 0.7273 |
| sqli | 7 | 2 | 0 | 0 | 5 | 1.0000 | 1.0000 | 1.0000 |
| trustbound | 7 | 1 | 0 | 2 | 4 | 1.0000 | 0.3333 | 0.5000 |
| weakrand | 7 | 0 | 0 | 1 | 6 | n/a | 0.0000 | n/a |
| xpathi | 7 | 0 | 2 | 1 | 4 | 0.0000 | 0.0000 | n/a |
| xss | 7 | 0 | 0 | 0 | 7 | n/a | n/a | n/a |
| xxe | 7 | 1 | 6 | 0 | 0 | 0.1429 | 1.0000 | 0.2500 |
| **all (Semgrep Python v6 (security-only))** | 98 | 19 | 22 | 11 | 46 | 0.4634 | 0.6333 | 0.5352 |

### Why Semgrep's Python run is reported two ways

Under the same "≥1 finding in the file = flagged" convention used for Java, Semgrep flagged **all 98**
Python files, giving perfect recall and 0.3061 precision. That number is an artifact, not a result:
the rule `useless-inner-function` fires on all 98 files because every Benchmark Python case nests its
handlers inside `init(app)`. It is a **maintainability** rule with nothing to say about security.

Scoring a code-quality rule as a vulnerability verdict would misrepresent Semgrep, so the table above
also reports a security-only variant that counts a file as flagged **only** when a rule carrying
`metadata.category: security` fires. That is the fairer comparison and the one to cite. The
all-rules row is kept for continuity with the Java methodology. The same filter applied to Java barely
moves it (F1 0.7258 → 0.7317), because Java's findings were already 96/106 security-category.

## Error analysis — every SENTINEL miss, and why

Eight cases were scored wrong across 208. All eight trace to **three** root causes, and none of them
is a "hard dataflow" failure — every one is a failure to verify an assumption about a *source* or a
*sink*, which is precisely what the Phase 5 evidence standard's falsifier step exists to force.

**1. Unverified source helper — 5 false positives (all Java).**
`BenchmarkTest01755` (ldapi), `00865` (pathtraver), `01810` (sqli), `01815` (sqli), `01772` (xss).

Each of these draws its input from `SeparateClassRequest.getTheValue(...)`. That method does not read
the request at all:

```java
// helpers/SeparateClassRequest.java
// This method is a 'safe' source.
public String getTheValue(String p) {
    return "bar";
}
```

The dataflow reasoning recorded for all five was *correct* — the value really does travel unmodified
into the LDAP filter, the file path, the SQL string, and the response. What was wrong was the premise
that the value was attacker-controlled. `getTheParameter` and `getTheCookie` on the same class are
genuine sources; `getTheValue` is a decoy that shares their shape. Eleven sampled Java cases use it;
five were called wrong, and the other six happened to be safe for an unrelated reason (a dead guard or
a safe overwrite), so they scored correct without the source being understood.

This is the exact failure the evidence standard is written to prevent: **"Source — the exact
attacker-controlled value, and where it enters the system"** was asserted, not verified. A helper
named like a getter was assumed to be one. Notably, the reflection helper `Thing1.doSomething` *was*
opened and confirmed to be an identity function during the same pass — the discipline was applied to
one helper and skipped on another.

**2. Sink semantics ruled out too aggressively — 2 false negatives (Java, both `cmdi`).**
`BenchmarkTest00306`, `BenchmarkTest00573`.

Both pass tainted data as the `envp` argument of `Runtime.exec(...)` rather than into the command
string, and both were dismissed on the reasoning that "env-var control is not command injection." The
Benchmark answer key counts them as real, and it is right to: an attacker who controls a child
process's environment controls `LD_PRELOAD`, `IFS`, `PATH`, and similar, which is an execution
primitive. The correct call was to report it.

This one is doubly instructive because SENTINEL's own operating principles say **"Be
false-negative-averse … when unsure, surface it and mark your confidence — do not stay silent."** The
principle was available and was not followed. A Medium-confidence finding would have scored as a TP
and been honest about the uncertainty.

**3. Statically-bound route treated as attacker-controlled — 1 false positive (Python).**
`BenchmarkTest01001` (xss).

The source is `request.path.split("/")[1]`. The handler is registered at the fixed route
`/benchmark/xss-02/BenchmarkTest01001`, so that element is always the literal string `'benchmark'` —
a constant. `request.path` *looks* like request data, and is, but the reachable values are pinned by
the route table. Four other sampled cases use the same source and scored correct only because they
were safe for other reasons.

### What the three have in common

None is a limitation of the methodology; all three are the methodology not being run to completion.
In each, the missing step is the same: **open the thing you are calling and confirm what it returns
before you assert taint.** The dataflow tracing itself — dead guards, safe overwrites, list
`remove(0)`/`get(0)` positions, `StringBuilder` prefix retention, base64 round-trips, discarded
`barbarians_at_the_gate` chains, `prepareStatement` that still concatenates, config-resolved cipher
and hash algorithms, `random.SystemRandom` vs `random`, `yaml.safe_load` vs `yaml.load`, lxml
`$name` binding vs f-string, `feature_external_ges` — was correct in all 208 cases.

### An important caveat on the Python numbers

**The Python run is blind to the Python answer key, but it is not independent of the Java run.** The
Java sample was scored first; that scoring exposed the `getTheValue` failure; and the Python analysis
that followed therefore began by opening `helpers/separate_request.py` and finding
`get_safe_value(name) -> "bar"`, the Python suite's identical decoy. Eight sampled Python cases use
it, and all eight were called correctly.

Had the Java run not come first, several of those would plausibly have been false positives, and the
Python F1 of 0.9836 would be lower. **The Java figure (0.9358) is the better estimate of cold
performance; the Python figure benefits from a lesson learned minutes earlier and should be read as
an upper bound, not a replication.** Reporting them as two independent samples would overstate the
result.

## What this does and does not establish

- **It does not establish that SENTINEL is more accurate than Semgrep in general.** It establishes
  that on a stratified sample of a synthetic dataflow benchmark, a careful manual application of the
  methodology resolves decoys that pattern-based rules do not: config-indirected algorithm names
  (`cryptoAlg2` → `AES/CCM`, `hashAlg1` → `MD5`), a `java.util.Random`-typed variable holding a
  `SecureRandom`, elaborate taint chains whose result is discarded, and sanitizers that are correct
  for a different sink than the one in use.
- **It is not a throughput comparison.** Semgrep scanned 208 files in seconds and would scan all 3970
  about as fast. These 208 verdicts were produced by hand, case by case. That is the entire reason the
  sample is 208 and not 3970, and it is why nothing here implies the same accuracy at full scale or on
  a real codebase.
- **Benchmark is synthetic.** Its decoys are deliberate and its shapes repeat. Real code fails in
  messier ways. A good score here means the dataflow discipline holds under adversarial-by-design
  conditions; it does not transfer automatically.
- **Per-category cells are 10 (Java) and 7 (Python) cases.** Treat them as directional. The overall
  rows are the load-bearing figures.
- **Sample sizes are 110 and 98, not the full suites.** The earlier run's own caveat — that 66 cases
  could not support a strong claim — was correct, and scaling to 110 is what surfaced the errors above.
  110 is better evidence than 66; it is still a sample.

## Files

- `validation/data/benchmark-sample-java-v6.csv`, `...-python-v6.csv` — the blind samples (seed 42).
- `validation/data/sentinel-benchmark-java-v6-verdicts.json` / `...-annotated.json` — SENTINEL's
  per-case verdicts, with the dataflow reasoning behind each.
- `validation/data/sentinel-benchmark-python-v6-verdicts.json` / `...-annotated.json` — same, Python.
- `validation/data/semgrep-benchmark-java-v6-verdicts.json` / `...-annotated.json` — Semgrep verdicts
  and the rule IDs that fired.
- `validation/data/semgrep-benchmark-python-v6-verdicts.json`,
  `semgrep-benchmark-python-v6-seconly-verdicts.json` (and `-annotated` variants) — the all-rules and
  security-only Python verdict sets.
- `validation/show_cases.py` — the reading aid used to work through the sample.

---

# Targeted re-test after the v7.0 catalog changes — 64 fresh cases (2026-07-20)

**This section extends the two runs above; it replaces neither.** It exists to answer one narrow
question: *did writing v6.0's three error root-causes into the catalog and the Phase 5 self-verify
step actually change the verdicts on cases nobody had scored?* It is a regression test for a specific
fix, not a new general accuracy estimate — read the scope caveats below before quoting the number.

**Date produced:** 2026-07-20
**Targets:** the same two clones at the same commits as the 208-case run — BenchmarkJava `79b9bd6`,
BenchmarkPython `f129148`. Static-analysis-only; both clones were read, never run.

## Sample

| Suite | Per category | Categories | Total |
|---|---|---|---|
| Java | 8 | cmdi, ldapi, pathtraver, sqli, xss | **40** |
| Python | 6 | cmdi, pathtraver, sqli, xss | **24** |
| | | | **64 total** |

Drawn with a new seed (7) and, critically, with `sample_benchmark.py --exclude` pointed at all three
prior sample files. **Overlap with the 66-case and 208-case runs is exactly zero**, verified by set
intersection rather than assumed. The categories are the ones the v6.0 errors landed in; that
concentration is deliberate and is also the main reason the headline figure below is not a general
estimate.

```bash
python validation/sample_benchmark.py --benchmark-root ../BenchmarkJava \
    --per-category 8 --seed 7 --categories cmdi ldapi pathtraver sqli xss \
    --exclude validation/data/benchmark-sample.csv validation/data/benchmark-sample-java-v6.csv \
    --out validation/data/benchmark-sample-java-v7.csv

python validation/sample_benchmark.py --benchmark-root ../BenchmarkPython \
    --per-category 6 --seed 7 --categories cmdi pathtraver sqli xss \
    --exclude validation/data/benchmark-sample-python-v6.csv \
    --out validation/data/benchmark-sample-python-v7.csv

python validation/score.py --benchmark-root ../BenchmarkJava \
    --verdicts validation/data/sentinel-benchmark-java-v7-verdicts.json --label "SENTINEL Java v7" --markdown
python validation/score.py --benchmark-root ../BenchmarkPython \
    --verdicts validation/data/sentinel-benchmark-python-v7-verdicts.json --label "SENTINEL Python v7" --markdown
```

`--exclude` reads only the `test_name` column of the prior samples, so excluding them does not expose
any ground truth. Verdicts were recorded in full before `score.py` was run once.

## Results — SENTINEL, Java (40 fresh cases, 2026-07-20)

| Category | N | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 8 | 6 | 0 | 0 | 2 | 1.0000 | 1.0000 | 1.0000 |
| ldapi | 8 | 4 | 0 | 0 | 4 | 1.0000 | 1.0000 | 1.0000 |
| pathtraver | 8 | 3 | 0 | 0 | 5 | 1.0000 | 1.0000 | 1.0000 |
| sqli | 8 | 6 | 0 | 0 | 2 | 1.0000 | 1.0000 | 1.0000 |
| xss | 8 | 3 | 0 | 0 | 5 | 1.0000 | 1.0000 | 1.0000 |
| **all (SENTINEL Java v7)** | 40 | 22 | 0 | 0 | 18 | 1.0000 | 1.0000 | 1.0000 |

## Results — SENTINEL, Python (24 fresh cases, 2026-07-20)

| Category | N | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 6 | 5 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 |
| pathtraver | 6 | 2 | 0 | 0 | 4 | 1.0000 | 1.0000 | 1.0000 |
| sqli | 6 | 0 | 0 | 0 | 6 | n/a | n/a | n/a |
| xss | 6 | 1 | 0 | 0 | 5 | 1.0000 | 1.0000 | 1.0000 |
| **all (SENTINEL Python v7)** | 24 | 8 | 0 | 0 | 16 | 1.0000 | 1.0000 | 1.0000 |

The Python `sqli` row has no positives to score: all six drawn cases bind their value through
`cur.execute(sql, (bar,))` with a literal `?`, so the correct verdict is "not vulnerable" six times
regardless of how the taint arrives. Two of those six (`00285`, `00012`) do carry live taint all the
way to the sink and were still called safe, which is the intended reading of a parameterized sink —
but the cell contributes no recall evidence and is shown as `n/a` rather than as a perfect score.

## Did the three lessons actually fire?

This is the part that matters more than the aggregate. The fresh sample happened to contain all three
trap shapes, and each was resolved by the rule written for it:

| Lesson (v7 addition) | Cases drawn | Result |
|---|---|---|
| Unverified source helper — open the helper before asserting taint | 4 (`01754`, `02738`, `01790` Java; `01114` Python) | All 4 correctly **not vulnerable**. The identical shape produced 5 false positives in the 208-case run. |
| Genuine wrapper source — the same check, cutting the other way | 5 (`02455` Java; `00899`, `00285`, `00286`, `00840` Python) | All 5 correctly treated as real sources; the rule did not over-correct into dismissing legitimate wrappers. |
| Taint in an `exec` environment (`envp`) is an injection vector | 1 with taint in `envp` (`00172`); 3 more with a constant `envp` (`01193`, `01864`, `02343`) | `00172` correctly **vulnerable** — the exact call v6.0 got wrong twice. The other three were checked at the `envp` position and correctly resolved on other grounds. |
| Statically registered route segment is not attacker-controlled | 2 (`01017`, `01019` Python) | Both correctly **not vulnerable**; the route registration was read before judging `request.path.split("/")[1]`. |

## Reading this number honestly

A second 1.0000 in this project's history should trigger suspicion, not celebration — the last one
(66 cases, v5.0) did not survive scaling. Four things bound what this run establishes:

- **The sample is deliberately biased toward the fix.** Categories were chosen *because* the v6.0
  errors were there. That is the right design for a regression test and the wrong design for an
  accuracy estimate. This number is not comparable to the 208-case F1 of 0.9358 and must not be
  quoted as an improvement on it. The honest comparison is per-trap, in the table above.
- **The traps were known going in.** Scoring was blind to the truth column, but not blind to the
  existence of `getTheValue`, `envp`, and fixed-route segments — that is precisely what was being
  tested. It measures whether encoded guidance is applied on unseen code, not whether a cold auditor
  would rediscover the trap. This is the same limitation v6.0 flagged for its Python run, and it
  applies here by construction rather than by accident.
- **64 cases is small.** Per-category cells are 8 and 6. The overall rows are the only figures worth
  reading, and even those rest on 22 and 8 true positives.
- **No comparator was run.** Semgrep was not re-run on this sample; there is no head-to-head here.
  The 208-case run remains the comparative record.

What it does establish: on 64 cases never previously scored, containing 11 instances of the three
shapes that caused every v6.0 error, the corrected methodology produced no repeat of any of them, and
did not overcorrect into dismissing the four genuine wrapper-sourced cases. That is the specific,
limited claim.

## Files

- `validation/data/benchmark-sample-java-v7.csv`, `...-python-v7.csv` — the fresh samples (seed 7,
  excluding all prior draws).
- `validation/data/sentinel-benchmark-java-v7-verdicts.json` / `...-annotated.json` — per-case
  verdicts with the dataflow reasoning behind each.
- `validation/data/sentinel-benchmark-python-v7-verdicts.json` / `...-annotated.json` — same, Python.
