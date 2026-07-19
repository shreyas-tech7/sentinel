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
