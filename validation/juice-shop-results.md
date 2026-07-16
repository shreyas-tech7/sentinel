# OWASP Juice Shop Results

**Target:** [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — an intentionally insecure,
full-featured Node/Angular web application. Its vulnerabilities are catalogued as a shipped **challenge
list** (`data/static/challenges.yml`) spanning broken access control, injection, XSS, SSRF, and — unlike
Benchmark — a set of **LLM / prompt-injection** challenges against its support chatbot.

**What it proves:** app-shaped realism that a synthetic per-file suite can't. Juice Shop is a real
application with real routing, real auth, and real data flows, so it exercises the authorization-gap and
LLM classes that dominate SENTINEL's catalog and that Benchmark omits entirely. Because Juice Shop labels
*challenges* rather than every source line, this adapter measures **recall over challenge classes** — did
the static review surface the weakness behind each challenge — not a per-line true/false-positive rate. It
is a coverage check, and it is honest about being one: with no per-line "clean" oracle there is no
meaningful false-positive or specificity figure, so the adapter reports `n/a` for those rather than
inventing them.

**Ground rule:** [static source review only](METHODOLOGY.md) — SENTINEL reads the Juice Shop source and
reasons about the weakness behind each challenge. It does **not** launch the app, solve challenges, or
exploit anything. The scoreboard is used as a label list, never as a live target.

## Reproduction

```bash
git clone https://github.com/juice-shop/juice-shop.git
# The challenge list (the oracle) ships with the target:
#   juice-shop/data/static/challenges.yml
# Convert it to the adapter's JSON shape (id · name · category · cwe) -> juice-truth.json.

# Run a SENTINEL static pass (Phases 0-3) over the cloned source — including Phase 3
# section D, since Juice Shop integrates an LLM chatbot — and export findings as an
# array of tooling.md-schema objects -> findings.json. No dynamic testing.

python validation/score.py \
    --findings findings.json \
    --truth   juice-truth.json \
    --format  juice-shop
```

A finding covers a challenge when it shares the challenge's CWE class (with a category fallback). The
matching rule and the coverage-vs-confusion-matrix distinction are defined in
[METHODOLOGY.md](METHODOLOGY.md#how-a-finding-is-matched-to-a-label).

## Status

**No full-challenge-list coverage numbers are reported here.** Producing them means running the
reproduction steps above across every challenge of a pinned Juice Shop release — a large SENTINEL pass that
was **not** performed as part of building this harness. Consistent with the repo's standing discipline (see
[`examples/README.md`](../examples/README.md) and [`CHANGELOG.md`](../CHANGELOG.md)), this file documents
the protocol and ships the scorer rather than printing a coverage figure for SENTINEL that was never
actually measured. When the pass is run, record the Juice Shop version, the finding-export date, and the
list of uncovered challenge classes under this heading — the misses are the point, because each one is a
catalog gap to close.

## Harness self-test (proves the scorer, not SENTINEL)

The scorer is verified independently of any real pass, against a synthetic
[fixture](fixtures/README.md) of six challenge classes (SQLi, reflected XSS, path traversal, IDOR, prompt
injection, SSRF) whose coverage is known by construction. **This tests the arithmetic in `score.py`. It is
not a measurement of SENTINEL's accuracy on Juice Shop** — the fixtures are fake findings against a fake
challenge list.

```console
$ python validation/score.py \
    --findings validation/fixtures/sample-findings.json \
    --truth   validation/fixtures/sample-juice-shop-truth.json \
    --format  juice-shop

SENTINEL validation - juice-shop adapter
findings file: validation\fixtures\sample-findings.json
truth file:    validation\fixtures\sample-juice-shop-truth.json
match rule:    CWE class coverage (category fallback)
------------------------------------------------------------
Confusion matrix
                    flagged   not flagged
  real vuln           3           3
  not vuln          n/a         n/a
  (coverage-only adapter: FP/TN not applicable - see METHODOLOGY.md)
------------------------------------------------------------
cases scored:      6
findings:          5 total, 3 matched, 0 unmatched
------------------------------------------------------------
precision            1.0000
recall (TPR)         0.5000
specificity (TNR)       n/a
F1                   0.6667
false-negative rate  0.5000
------------------------------------------------------------
uncovered challenge classes:
  - View another user's basket
  - Prompt injection of the bot
  - SSRF via image URL upload
```

The three uncovered classes are intentional — the fixture's findings deliberately omit IDOR, prompt
injection, and SSRF so the self-test exercises the adapter's miss-reporting, which is exactly the output a
real pass mines for catalog gaps. The self-test ([`test_score.py`](test_score.py)) asserts the recall and
coverage numbers above; run it with `python validation/test_score.py` (or `pytest validation/`).
