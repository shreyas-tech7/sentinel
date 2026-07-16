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

## Results — backend pilot, 6 files (run 2026-07-15)

**This is a real run over a bounded slice of the app, not the full challenge list.** SENTINEL statically
audited six backend source files of a current Juice Shop `main` checkout and produced **seven real
findings**, each traced to a concrete source line:

| Finding | File | Class | CWE |
|---|---|---|---|
| SQL injection (login bypass) | `routes/login.ts` | `req.body.email` interpolated into a `sequelize.query` template | CWE-89 |
| SQL injection (product search) | `routes/search.ts` | `req.query.q` interpolated into a `SELECT ... LIKE` | CWE-89 |
| IDOR (any user's basket) | `routes/basket.ts` | `findOne({ where: { id: req.params.id } })`, no ownership check | CWE-639 |
| SSRF (image URL upload) | `routes/profileImageUrlUpload.ts` | `fetch(req.body.imageUrl)`, no internal-range block | CWE-918 |
| Open redirect | `routes/redirect.ts` | substring allow-list (`url.includes`) then `res.redirect(toUrl)` | CWE-601 |
| Weak password hashing | `lib/insecurity.ts` | `crypto.createHash('md5')` | CWE-916 |
| Hard-coded signing key | `lib/insecurity.ts` | RSA private key literal used to sign JWTs | CWE-798 |

Scored as **challenge-class coverage** over a truth set of nine distinct server-side weakness classes drawn
from Juice Shop's real `data/static/challenges.yml` (the file ships no CWE field, so each class was assigned
its CWE from the underlying weakness):

```console
$ python validation/score.py \
    --findings juice-findings.json \
    --truth   juice-truth.json \
    --format  juice-shop

SENTINEL validation - juice-shop adapter
match rule:    CWE class coverage (category fallback)
------------------------------------------------------------
Confusion matrix
                    flagged   not flagged
  real vuln           5           4
  not vuln          n/a         n/a
  (coverage-only adapter: FP/TN not applicable - see METHODOLOGY.md)
------------------------------------------------------------
cases scored:      9
findings:          7 total, 5 matched, 0 unmatched
------------------------------------------------------------
precision            1.0000
recall (TPR)         0.5556
F1                   0.7143
false-negative rate  0.4444
------------------------------------------------------------
uncovered challenge classes:
  - SSTi
  - XXE Data Access
  - NoSQL Manipulation
  - Chatbot Prompt Injection
```

**Read the misses correctly.** Recall here is 0.556 because this pilot opened **six backend files**, and the
four uncovered classes live in files it never read — not because the classes are undetectable. Three of them
are squarely in SENTINEL's catalog and a fuller pass that opened the relevant files would be expected to
reach them: **SSTi** and **NoSQL injection** map to `SENT-INJ-01` (template / operator injection), and
**Chatbot Prompt Injection** maps to `SENT-LLM-01`. Only **XXE (CWE-611)** is a genuine catalog gap — like
CWE-501 in the Benchmark run, it has no dedicated SENTINEL class and is logged here as a candidate.

## Scope and honesty

This is a **6-file backend pilot**, not a whole-app audit; the coverage figure is bounded by which files
were opened, and must not be quoted as SENTINEL's ceiling on Juice Shop. A complete pass audits every
challenge-linked file across a pinned release. The seven findings above are real (each names a file and a
sink); the truth-set CWEs were assigned by hand because the challenge file carries none — that mapping is
the one hand-authored input, disclosed here rather than hidden. The scorer itself is unit-tested against
synthetic fixtures — `python validation/test_score.py`.
