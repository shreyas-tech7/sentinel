# Validation Methodology

SENTINEL is a source-review methodology, and a methodology's only honest accuracy claim is one measured
against ground truth someone else defined. This directory checks SENTINEL against **public, purpose-built
targets** — anyone can clone them and re-score — instead of against the maintainer's own projects, where
the person grading the audit also wrote the code and the labels.

The deliverable of the v4.0 validation work is this **harness plus an honest status**, not a headline
number. The harness — [`score.py`](score.py) and its [fixtures](fixtures/README.md) — is reproducible and
tested; a full-corpus measurement is a large pass that a reader runs against the live target (see the
[Status](#status) section) rather than a figure asserted here without the run behind it.

## The ground rule, first

> **Static source review only. No live attacks, no exploitation, no dynamic testing — including against
> these validation targets.**

This is the same rule SENTINEL applies to any codebase, and it is not relaxed because a target was built
to be attacked. SENTINEL reads the OWASP Benchmark's source and Juice Shop's source, reasons about
whether a control is present and reachable, and emits findings. It never sends a payload, never stands the
app up, never confirms a bug by triggering it. That boundary is a feature — it is what makes the tool safe
to point at code you do not own — and it also bounds what the score can mean: a static pass measures
whether the *shape of a vulnerability* is present in source, not whether it *fires* at runtime. The
[Known limitations](#known-limitations) section returns to this.

## The targets, and why these two

| Target | Shape | What it exercises |
|---|---|---|
| [OWASP Benchmark](https://owasp.org/www-project-benchmark/) | ~2,700 synthetic Java test cases, each labelled real-vulnerable or not, with a category and CWE | Per-case true/false-positive accuracy against an explicit oracle |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | One deliberately-vulnerable Node/Angular application with a published challenge list | App-shaped realism: does the review surface the weakness classes a real app hides, including its LLM / prompt-injection challenges |

They are complementary and neither alone is sufficient. Benchmark gives something rare — a large, per-item
labelled corpus — so it can produce a real confusion matrix, including the false positives a tool would
rather not count. But it is synthetic: every case is a minimal source pattern, injection classes are
over-represented, and it contains none of the absent-control authorization gaps that are SENTINEL's
highest-yield class (there is no cross-tenant object to leak in a single-file test case). Juice Shop
supplies the missing realism — a whole application with business logic, an admin surface, and modern
LLM/chatbot challenges — but it is not labelled per line, so it cannot yield a per-line false-positive
rate. Scored together, one measures precision honestly and the other measures recall against a realistic
surface.

## How a finding is matched to a label

A SENTINEL finding is a JSON object in the schema under
[*Machine-readable findings*](../skill/references/tooling.md#machine-readable-findings) in `tooling.md`:
an `id`, a `classification.cwe` list, a `location.file`/`line`/`symbol`, and the evidence fields. The two
adapters map that object to a label differently, because the two targets are labelled differently.

**Benchmark — match by test-case id.** Every Benchmark case lives in its own file, `BenchmarkTestNNNNN.java`.
The scorer reads the test-case id out of the finding's `location.file` (or `symbol`/`title`) and looks it
up in the `expectedresults` CSV. A case is *flagged* if at least one finding references its id. With
`--match-cwe`, the finding must additionally share the case's CWE, which suppresses cross-category
coincidental matches (a path-traversal finding does not get credit for a case labelled SQL injection).
Findings whose id is absent from the truth file are counted as **unmatched** and excluded from the matrix
rather than silently dropped — an unmatched finding is a scoring-input problem the reader should see.

**Juice Shop — match by weakness class (CWE).** Juice Shop has no per-line oracle, so the finding→label
match is at the class level: a challenge is *covered* when some finding asserts the challenge's CWE. When
a challenge carries no CWE, the adapter falls back to a deliberately-weak category-keyword overlap so the
challenge is not silently un-scorable; CWE is the signal that actually decides coverage.

## Scoring rules

**Benchmark (per-case confusion matrix).** For each labelled case:

| | finding present | no finding |
|---|---|---|
| **real-vulnerable case** | TP | FN |
| **non-vulnerable case** | FP | TN |

**Juice Shop (coverage / recall over challenge classes).** Only two cells are defined, and this is the
honest core of the adapter:

| | class surfaced | class missed |
|---|---|---|
| **challenge** | TP (covered) | FN (uncovered) |

There is no FP or TN here. Without a labelled negative set, any "false positive" count would be an
artefact of which findings happened to be in the file, not a property of Juice Shop — so the adapter
reports FP and TN as `n/a` and derives recall only. Calling this a precision measurement would be the
exact kind of overclaim this repo exists to catch.

## Metrics

From the matrix (let `TP, FP, FN, TN` be the counts):

- **Precision** = `TP / (TP + FP)` — of what SENTINEL flagged, how much was real. Low precision is noise
  that trains reviewers to ignore the tool.
- **Recall (TPR, sensitivity)** = `TP / (TP + FN)` — of the real vulnerabilities, how many were caught.
- **Specificity (TNR)** = `TN / (TN + FP)` — of the safe cases, how many were left alone.
- **F1** = `2 · precision · recall / (precision + recall)` — the harmonic mean, penalizing a tool that
  wins one at the other's expense.
- **Youden's J** = `recall + specificity − 1` — a single prevalence-independent number in `[−1, 1]`; `0`
  is coin-flip, `1` is perfect. It rewards catching real bugs *and* leaving safe code alone, which is why
  it is reported alongside F1.
- **False-negative rate** = `FN / (TP + FN)` = `1 − recall`.

**Why the false-negative rate is the one to watch.** SENTINEL is deliberately false-negative-averse: a
missed authorization bug ships an exploitable hole, while a false positive costs a reviewer a few minutes
to dismiss. The tool's whole posture — read the code, name the falsifier, prefer to flag-and-explain over
stay-silent — trades some precision for recall on purpose. So a validation run that showed high precision
but a high false-negative rate would be a *worse* result for this tool than the reverse, and the harness
prints the false-negative rate explicitly so that trade is never hidden inside an F1 average. All divisions
are guarded: an empty finding set or empty truth file yields `0.0`, never a crash.

## Reproduction

Prerequisites: `git`, `python` (3.9+, standard library only — nothing to `pip install`), and a SENTINEL
static pass over the target that exports findings JSON.

```bash
# 1. Clone the target (read the source; do NOT deploy or attack it).
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git        # or juice-shop
#    The label file ships with the target:
#    BenchmarkJava/expectedresults-1.2.csv

# 2. Run a SENTINEL static pass over the cloned source (Phases 0–3), and export
#    each finding as a JSON object in the tooling.md schema, collected into one
#    array (or an object with a "findings" array). No dynamic testing.
#    -> findings.json

# 3. Score.
python validation/score.py \
    --findings findings.json \
    --truth   BenchmarkJava/expectedresults-1.2.csv \
    --format  benchmark --match-cwe

# Juice Shop: export its challenge list to id/name/category/cwe (JSON or CSV) and:
python validation/score.py \
    --findings findings.json \
    --truth   juice-shop-challenges.json \
    --format  juice-shop

# Machine-readable output for a CI gate or a tracker:
python validation/score.py --findings findings.json --truth <truth> --format benchmark --json
```

The scorer itself is verified independently of any real pass by the **harness self-test**
([`test_score.py`](test_score.py)) against the synthetic [fixtures](fixtures/README.md), which pin a known
confusion matrix. Run it with `python validation/test_score.py` (or `pytest validation/`). That test
proves the arithmetic; it does not — and is careful not to — assert anything about SENTINEL's accuracy on
a real target.

## Status

No full-corpus measurement is reported in this directory. The numbers you will find here
([owasp-benchmark-results.md](owasp-benchmark-results.md), [juice-shop-results.md](juice-shop-results.md))
are the harness self-test on synthetic fixtures, labelled as such. A corpus-scale figure is produced by
running the reproduction steps above against the live target — a large pass that was **not** performed as
part of building this harness — and this repo does not print a precision/recall/F1 number for SENTINEL
that it did not actually measure. See the note in
[`examples/README.md`](../examples/README.md) for the same discipline applied to the example reports: a
claim the tool never ran is exactly what SENTINEL is built to catch, and it will not manufacture one about
itself.

## Known limitations

- **Benchmark is synthetic and skewed.** It over-represents injection sinks and contains essentially none
  of the broken-object-level-authorization cases that are SENTINEL's most valuable class — the absence of
  a check has no token for a per-file test case to encode. A strong Benchmark score says little about the
  authorization findings that matter most on real apps.
- **A static-only pass cannot confirm exploitability.** Static review measures the presence and shape of a
  weakness, not that it fires at runtime. Some Benchmark "real" cases are guarded by sanitizers a purely
  syntactic reading would miss (inflating false positives), and some "safe" cases only differ from a real
  one by a value flowing through a branch a static pass may not track (risking false negatives). The score
  is bounded by this, by design — see the ground rule.
- **Scoring depends on the finding→case matching heuristic.** Benchmark matching keys on the test-case id
  in `location.file`; a findings export that omits or mangles that id will under-count matches (surfaced as
  the *unmatched* count, not hidden). Juice Shop matching keys on CWE, so a finding with a missing or
  wrong CWE will fail to cover a challenge it genuinely found. The heuristic is transparent and adjustable,
  but it is a heuristic, and the coverage number moves with it.
- **Juice Shop measures recall, not precision.** It has no labelled negatives, so it cannot tell you how
  noisy SENTINEL is — only how much of a realistic surface it covers. Read it alongside Benchmark's
  precision, never on its own.
