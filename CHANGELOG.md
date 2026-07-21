# Changelog

All notable changes to SENTINEL are recorded here. The version tracks the skill's
`metadata.version` in [`skill/SKILL.md`](skill/SKILL.md). Bump the version whenever the
vulnerability catalog or the OWASP / API / LLM / CWE framework-mapping tables change, per
[CONTRIBUTING.md](CONTRIBUTING.md).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [7.0.0] — 2026-07-20

**The corrections become checks.** 6.0.0's most valuable output was not its bigger sample — it was
catching that a perfect score was a small-sample artifact and naming the three assumption failures
behind all eight of its errors. Those findings lived in a results file, where they improved nothing.
This release writes them into the catalog, the Phase 3 scan, and the Phase 5 self-verify step, then
tests whether that changed any verdicts on cases nobody had scored.

No phase, rubric, schema, or check changed. The six phases (0–5), STRIDE core, severity and confidence
rubrics, evidence standard, prose report template, findings schema, standards-currency check, and the
`security-audit` skill name are all untouched. Every change below is additive.

### Added
- **Catalog: a cross-cutting "Before you assert taint — evaluating a source" section**
  (`skill/references/vulnerability-catalog.md`), placed ahead of the class entries because it applies
  to all of them. Two checks, both drawn from real 6.0.0 errors:
  - *Open the helper before trusting its name.* A value arriving via a wrapper or utility method is
    not a verified source until that method's body is read. A getter-shaped name may return a
    constant, a config value, or a fixed test string, and it will sit beside genuine sources with an
    identical signature. Five of the eight 6.0.0 errors were this exact shape.
  - *Check whether the route or URL segment is statically registered.* Route-derived segments are
    request data, but their reachable values are pinned by how the handler is registered; a handler
    bound to a fixed literal route reaches a given segment with exactly one possible value. One
    6.0.0 error was this.
- **Catalog: `envp` and environment-driven execution under SENT-INJ-01.** Taint reaching a child
  process's environment — `Runtime.exec`'s `envp`, `subprocess`'s `env=`, an `env` object passed to
  `spawn`/`execFile` — is a genuine execution primitive (`LD_PRELOAD`, `IFS`, `PATH`,
  `PYTHONPATH`, `BASH_ENV`), not a lesser issue. Two 6.0.0 false negatives came from ruling this out
  because the taint was not in the command string. Mirrored in the Phase 3 section B injection line
  of `SKILL.md`.
- **`SKILL.md` Phase 5: a "Verify the source, not just the flow" self-verify step.** The most common
  way a well-traced finding turns out wrong is that its premise was never checked. Applying the
  discipline to one helper and skipping it on the next is how it fails in practice — 6.0.0 opened
  `Thing1.doSomething` and confirmed it, then assumed `getTheValue` in the same pass.
- **`SKILL.md` Operating Principles: "One sink found is not the file finished."** Read every file and
  function to its end and look for co-located but distinct issues; vibe-coded files concentrate
  defects rather than spreading them evenly, so the highest-yield place to find the second finding is
  the file that produced the first.
- **Targeted re-test on 64 fresh Benchmark cases** (`validation/owasp-benchmark-results.md`, new dated
  section; the 66-case and 208-case runs are preserved above it). 40 Java + 24 Python, drawn with a
  new seed and **zero overlap** with any prior sample, verified by set intersection.
  - Results: **40/40 Java and 24/24 Python correct** (P 1.0000 / R 1.0000 / F1 1.0000 on each).
  - **This is a regression test, not an accuracy estimate, and is not comparable to the 208-case
    F1 of 0.9358** — the categories were chosen *because* the errors were there, and the traps were
    known going in. The results file states both limits explicitly and the 0.9358 baseline stands
    unchanged. The per-trap table is the meaningful result: 4 decoy-helper cases correctly cleared,
    5 genuine wrapper-sourced cases correctly kept (no overcorrection), 1 tainted-`envp` case
    correctly reported, 2 statically-bound route cases correctly cleared.
- **Blind Juice Shop pass — 10 fresh route modules** (`validation/juice-shop-results.md`, new dated
  section; both earlier passes preserved). Closes the gap the 6.0.0 pass flagged against itself.
  - Scope drawn seed-fixed from `routes/*.ts` **before any marker, `solveIf`, or `challenges.yml`
    entry was read**. **Precision 1.0000, recall 0.9167, F1 0.9565** over 12 documented challenges,
    plus **7 real findings the challenge list does not track** (unauthenticated full-config
    disclosure, a key-directory traversal and its browsable index, a CAPTCHA that returns its own
    answer and is replayable, a fail-open wallet check, a swallowed image-write failure).
  - Six of the ten drawn files carried no documented challenge and induced **no false positives** —
    the failure mode a blind scope exists to expose.
  - The single miss (`redirectCryptoCurrencyChallenge`) was **left unclaimed deliberately**: it is
    solved by redirecting to an address already on the allowlist, which is intended behaviour, and
    attaching it to the open-redirect finding for a free 12/12 would have relabelled a discovery
    challenge as a vulnerability.
- **`login.ts` / `user.ts` end-to-end re-read**, testing the new operating principle against the
  files 6.0.0 under-covered: **5/14 → 13/13, recovering all nine previously missed challenges.**
  `login.ts`'s eight misses all sit *below* its first sink (seven hardcoded credential pairs in
  `verifyPreLoginChallenges`, including a test credential and an OAuth password that is the base64 of
  its own reversed email). `user.ts`'s sits *above* its reported sink, inside a `vuln-code-snippet
  hide-start`/`hide-end` block — so the rule is **read the whole scope**, not "keep reading downward".
- **`validation/run_comparator.py`** — comparison scanners now run in a disposable virtualenv.

### Changed
- **`validation/sample_benchmark.py` grows `--exclude` and `--categories`**, so a new draw can be
  proven disjoint from every previous one rather than assumed to be. `--exclude` reads only the
  `test_name` column of prior samples, preserving blindness.
- **Comparison runs no longer touch the system Python environment.** Installing Semgrep for the 5.0.0
  and 6.0.0 comparisons downgraded `mcp`, `jsonschema`, and `opentelemetry-api` in the active
  environment both times, and both times it was undone by hand afterwards. `run_comparator.py`
  installs the pinned tool into a throwaway venv, invokes it from that interpreter, and removes the
  tree in a `finally` block; `--verify-isolation` compares host package versions before and after and
  exits non-zero if any moved. Verified by actually installing `semgrep==1.170.0` — the same version
  responsible for both incidents — and confirming `mcp==1.26.0` and `jsonschema==4.26.0` unchanged,
  `semgrep` absent from the host, and no temp directory left behind. Documented in
  `validation/owasp-benchmark-results.md`.
- Validation harness tests: 15 → 25, covering the sampler's exclusion/category logic and the
  comparator's isolation helpers.

### Unchanged
- The six phases, the STRIDE core, the severity and confidence rubrics, the four-part evidence
  standard, the prose report template, the Plain-English brief, `schema/finding.schema.json`
  (`schema_version` 1.0), the standards-currency check, all 45 `SENT-*` classes, and the
  `security-audit` skill name.
- **The 208-case Benchmark record and the original 10-file Juice Shop pass are preserved verbatim**,
  with their own dates and their own caveats. The 0.9358 F1 remains the project's cold-performance
  baseline; nothing in this release supersedes it.
- The three redacted example reports.

## [6.0.0] — 2026-07-19

**Validation at scale, and a corrected headline.** This release is entirely about evidence: it scales
the external validation to the size the 4.0.0 work actually called for, adds a second language, and
scores the Juice Shop pass against ground truth instead of listing findings. No phase, rubric, schema,
or check from 5.0.0 changed — the six-phase workflow, STRIDE core, severity and confidence rubrics,
evidence standard, prose report template, findings schema, standards-currency check, and the
`security-audit` skill name are all untouched.

The most important thing in this release is a correction. **5.0.0 reported a perfect 1.0000 F1 on a
66-case blind Benchmark sample. That result did not survive scaling.** At 110 Java cases SENTINEL
scores **F1 0.9358**, and the eight cases it got wrong are documented individually with root causes.
The earlier run is preserved, not overwritten; the new numbers are stated as superseding it.

### Added
- **Scaled Benchmark validation — 208 blind cases across two languages** (`validation/owasp-benchmark-results.md`,
  new dated section; the 66-case run is preserved above it).
  - **110 Java cases** (10/category × 11) from BenchmarkJava v1.2 @ `79b9bd6`, and **98 Python cases**
    (7/category × 14) from **BenchmarkPython v0.1 @ `f129148`** — a *separate repository*, since
    BenchmarkJava contains no Python at all. Drawn by the existing seed-fixed blind sampler.
  - Real, unrounded results:

    | Run | N | TP | FP | FN | TN | Precision | Recall | F1 |
    |---|---|---|---|---|---|---|---|---|
    | SENTINEL — Java | 110 | 51 | 5 | 2 | 52 | 0.9107 | 0.9623 | **0.9358** |
    | SENTINEL — Python | 98 | 30 | 1 | 0 | 67 | 0.9677 | 1.0000 | **0.9836** |
    | Semgrep 1.170.0 — Java | 110 | 45 | 26 | 8 | 31 | 0.6338 | 0.8491 | 0.7258 |
    | Semgrep 1.170.0 — Python (security-category rules) | 98 | 19 | 22 | 11 | 46 | 0.4634 | 0.6333 | 0.5352 |

  - Semgrep re-run at the same scale on the identical files, same version and same ruleset commit
    (`e5b5a42`) as the 66-case comparison, so the head-to-head stays apples-to-apples. Its Java figures
    are stable across both samples (F1 0.7595 → 0.7258); SENTINEL's are not, which is the finding.
  - **Semgrep's Python result is reported two ways, deliberately.** Under the Java convention (≥1
    finding in the file = flagged) it flags all 98 files for F1 0.4687 — an artifact, because the
    *maintainability* rule `useless-inner-function` fires on every Benchmark Python case. A
    security-category-only variant is reported alongside it and is the figure to cite.
  - **Full error analysis.** All eight Java/Python misses trace to three named causes: treating
    `SeparateClassRequest.getTheValue` (which returns a hardcoded `"bar"`) as a real source (5 FPs);
    ruling out tainted `Runtime.exec` `envp` as non-exploitable, against SENTINEL's own
    false-negative-averse principle (2 FNs); and treating a statically-bound Flask route segment as
    attacker-controlled (1 FP). Not one miss came from failing to trace a dataflow.
  - Records honestly that the Python run, while blind to its own answer key, is **not independent** of
    the Java run — the `getTheValue` lesson carried over to its Python twin `get_safe_value` — so the
    Java figure is the better estimate of cold performance and the Python figure is an upper bound.
- **Scored Juice Shop coverage pass** (`validation/juice-shop-results.md`, new dated section; the
  five-finding slice is preserved). 10 files, 2150 lines, 40 documented challenges, **21 findings** each
  carrying the full source · sink · missing-control · falsifier evidence standard.
  **Precision 1.0000, recall 0.7750, F1 0.8732** (TP 31 / FP 0 / FN 9).
  - **Phase 3 section D is now genuinely exercised** — the gap the 4.0.0 ask flagged. `routes/chat.ts`
    is a real agentic surface (an `ai`-SDK `streamText` loop with four tools), and all three documented
    challenges implemented there were found: `generateCoupon` bounds its discount only inside a zod
    `.describe()` string with no server-side clamp (`chatbotPromptInjection` + `chatbotGreedyInjection`),
    the system prompt carries a `CONFIDENTIAL` block recoverable by injection, and tool-call events
    stream to every caller with the role gate living in a client-set cookie (`aiDebugging`). Indirect
    prompt injection via user-writable review text is reported as an unscored finding.
  - Records one finding **correctly not made**: the `$where` string concatenation in `getProductReviews`
    is not injectable, because `Number()` coerces any payload to `NaN`. Reporting it would have been a
    false positive; the falsifier step is what caught that.
  - The nine misses are documented: eight from reading `login.ts`, producing the SQL-injection finding,
    and stopping before a block of hardcoded plaintext credentials; one from seeing
    `security.sanitizeLegacy` applied and never asking whether a one-pass regex is an adequate sanitiser.
- **`validation/score_juiceshop.py`** — derives the Juice Shop answer key from the target rather than by
  hand, unioning the app's own `vuln-code-snippet` markers with `solveIf(challenges.<key>)` call sites
  and validating every key against `data/static/challenges.yml`.
- **`validation/show_cases.py`** — a presentation-only reading aid for working through a Benchmark
  sample. It strips license headers and provably-inert boilerplate and decides nothing, consistent with
  the standing rule that tools produce leads and the audit produces findings.

### Changed
- `validation/score.py` and `validation/sample_benchmark.py` now **auto-discover** `expectedresults-*.csv`
  instead of hardcoding the Java suite's filename, so one harness serves both Benchmark suites
  (`--expected-csv` overrides; an ambiguous checkout is an error rather than a silent coin flip). The
  original 66-case numbers reproduce **exactly** under the changed harness — verified before any new
  analysis was run.
- `validation/test_score.py` — 10 tests to 15, covering ground-truth discovery for both suites,
  explicit-path precedence, and the missing/ambiguous cases.
- `README.md` — the 66-case figure is no longer the headline; the 208-case table leads, states plainly
  that it supersedes the earlier perfect score, and the scope limits now name the not-blind status of
  the Juice Shop pass and Benchmark's synthetic nature.

### Deliberately not done
- **DVWA / NodeGoat.** Flagged as worthwhile since 4.0.0 and deprioritised a third time. Adding a PHP or
  second Node/Mongo target would broaden the validated set beyond Java, Python, and Node/Express, and it
  remains the obvious next step — but it was not started rather than rushed.

## [5.0.0] — 2026-07-19

**Proof and interoperability.** Building directly on 4.0.0 (produced in the same session), this release
makes SENTINEL's findings machine-consumable, keeps the standards it cites from silently ageing, proves
the regression-audit mode end-to-end, and puts SENTINEL's accuracy next to an established tool's on the
same test cases. As with every release since 1.0, the six-phase workflow, STRIDE core, severity and
confidence rubrics, evidence standard, prose report template, and the `security-audit` skill name are
all unchanged — everything below is additive.

### Added
- **Findings interoperability schema** (`schema/finding.schema.json`, JSON Schema draft 2020-12) — a
  stable, versioned (`schema_version` `"1.0"`) contract for one SENTINEL finding: `id`, `title`,
  `severity`, `confidence`, a **structured `classification`** (`sentinel_class`, `owasp[]`, and `cwe[]`
  as separate fields — never one concatenated string), a structured `location` (`file`/`line`/
  `function_or_endpoint`), `analysis`, `attack_scenario`, `impact`, `remediation_summary`, plus optional
  `remediation_code`, `falsifier`, and `references`.
  - A new **"Structured findings export"** step after Phase 5 in `SKILL.md` serializes every finding in
    the prose report to this schema. It is **additive and mechanical** — the Markdown report format,
    phase names, numbering, and severity rubric are untouched, and the export re-decides nothing.
  - `docs/FINDINGS_SCHEMA.md` documents the contract with a worked example, and states plainly that it
    exists for **Gauntlet** and **ReconBrief** to consume — SENTINEL does not call into either, and
    building the consumer side is out of scope here.
  - `scripts/check_schema.py` (stdlib-only, in CI) keeps the schema and its documented example in sync.
- **Standards-currency check** (`scripts/check_standards_currency.py` + `references/standards-versions.md`)
  — records the edition of each cited standard (OWASP Top 10, API Security Top 10, LLM Top 10, CWE
  list/Top 25, ASVS) and flags, **for human review**, when a newer edition exists. It never auto-migrates
  the catalog; adopting a new edition remains a deliberate, reviewed project. Added an ASVS row to the
  catalog's framework-mapping table so the manifest tracks exactly what the catalog cites. Wired into CI.
- **Comparative external validation** — Semgrep 1.170.0 (official `semgrep/semgrep-rules` Java ruleset)
  run against the *same* 66-case blind OWASP Benchmark sample and scored by the same harness, reported
  side by side in `validation/owasp-benchmark-results.md` (dated 2026-07-19): SENTINEL P/R/F1 =
  1.0000/1.0000/1.0000 vs. Semgrep 0.6250/0.9677/0.7595. The two agree closely on recall; the precision
  gap is entirely Semgrep firing on the Benchmark's dead-taint decoys — the exact discipline SENTINEL's
  evidence standard enforces. The registry endpoint `semgrep.dev` was blocked by the environment, so the
  ruleset was sourced from its canonical GitHub repo (commit pinned); this is documented in the results.
- **Regression-audit proof** (`validation/regression-mode-example.md`) — a worked, end-to-end example on
  a real Juice Shop fix pass (local, uncommitted) where each Phase 4 re-audit bucket fires on genuine
  code: one finding **Resolved**, one **Still open**, one **Regressed** (control added then removed,
  caught by `git log -S`), one **Newly introduced** by the fix pass.
- **New re-audit bucket — Regressed.** Phase 4's re-audit delta gains an explicit **Regressed** bucket
  (a control that was added and later re-opened/weakened), distinct from "Still open" (never fixed). The
  prior Resolved / Still open / Newly introduced buckets are unchanged.

### Version note
No separate 4.0.0 was ever released before this session — the live skill was at 3.0.0. The [4.0.0] entry
below and this [5.0.0] entry are two milestones completed back-to-back and shipped together: 4.0.0 is the
credibility/validation body of work, 5.0.0 the interoperability/proof body of work. They are recorded
separately to keep the two goals legible, not to imply two historical releases.

## [4.0.0] — 2026-07-19

**Credibility and universality.** This release makes SENTINEL's accuracy externally checkable and closes
the last major stack gap. The six-phase workflow, STRIDE core, severity/confidence rubrics, evidence
standard, and report template are all unchanged — this is a MAJOR bump only because it adds an
externally-reproducible validation suite and a new stack playbook the catalog now routes to.

> **Version note.** A separate 4.0.0 was planned earlier but never cut; the live skill was still at
> 3.0.0. This is the real next major release after 3.0.0. The interoperability/proof work that was
> scoped as "5.0" landed in the same session and is recorded under [5.0.0] below; the two entries
> describe two milestones completed back-to-back, not two historical releases.

### Added
- **Java / Spring stack playbook** (`references/stack-playbooks/java-spring.md`) — servlets, Spring
  MVC/Boot, JDBC/JPA. Covers the method-vs-URL authorization gap, string-built SQL/JPQL, `Runtime.exec`/
  `ProcessBuilder` command injection, servlet-writer XSS, mass assignment via `@ModelAttribute`, weak
  crypto/hash/`Random` (including algorithms resolved from a properties file), insecure cookies, and
  trust-boundary violations into the session. Brings the playbook count 12 → 13. Indexed in
  `stack-playbooks.md` and cross-linked to catalog + remediation entries; `scripts/check_repo.py` passes.
- **External validation suite** (`validation/`) — a reproducible, static-analysis-only accuracy harness:
  - `validation/sample_benchmark.py` draws a blind, seed-fixed, stratified sample of OWASP Benchmark
    cases (reads only name+category, never the truth flag).
  - `validation/score.py` computes per-category TP/FP/FN/TN and precision/recall/F1 against the Benchmark
    ground truth, reading the truth column in exactly one place; `validation/test_score.py` covers it
    with 10 unit tests.
  - `validation/owasp-benchmark-results.md` — **dated 2026-07-19**, real numbers on a 66-case blind
    sample: SENTINEL 31 TP / 0 FP / 0 FN / 35 TN (precision 1.0000, recall 1.0000, F1 1.0000), verified
    against the answer key with zero mismatches, with an explicit honesty note on why the Benchmark's
    deterministic cases are tractable for a traced-dataflow pass.
  - `validation/juice-shop-results.md` — **dated 2026-07-19**, a five-finding audit of a Juice Shop v20.1.1
    Express/TypeScript slice (SQLi, basket IDOR, unverified password change, sandboxed-eval RCE, MD5
    password hashing), each cross-referenced to the documented Juice Shop challenge that is its ground
    truth.

### Unchanged (deliberately)
- The six-phase workflow, STRIDE step, report template, severity and confidence rubrics, the evidence
  standard, and the read-only/report-only default. No phase name, number, or output-format section moved.

## [3.0.0] — 2026-07-13

Broadens SENTINEL from a Next.js/Supabase-plus-LLM tool into a framework for **any language, framework,
or artifact type** — while keeping the six-phase workflow, the STRIDE core, the severity/confidence
rubrics, and the report template exactly as they were. Nothing in v2.1.0's voice or output format was
replaced; v3.0 adds lenses and reference depth on top. This is a MAJOR bump because Phase 0 gains a new
job (artifact classification) and the report gains an optional audience mode — both extensions, not
rewrites — and because the reference layout changed (see "Restructured").

### Added
- **Five vulnerability classes** (40 → 45), each with a matching fail-closed remediation:
  - `SENT-INJ-09` — unsafe deserialization of untrusted data (`pickle`, `yaml.load`, `unserialize`,
    `Marshal.load`), and `SENT-INJ-10` — path traversal / unsafe file-path handling (incl. zip slip,
    PHP file inclusion, CLI `--output` escapes).
  - `SENT-ASYNC-03` — non-idempotent webhook and queue consumers (at-least-once redelivery double-fires
    the side effect; a signed event is still replayable).
  - `SENT-PLAT-01` — overscoped platform permissions and privileges (extension manifests, bot intents,
    mobile grants, CLI `sudo`), and `SENT-PLAT-02` — unvalidated cross-context messages (`postMessage`
    origin, extension `sender`, deep links, Electron IPC). These form a new catalog category **I —
    Platform & artifact boundaries** and a new Phase 3 scan group I.
- **Phase 0 artifact-type classification.** Before assuming "web app with routes," Phase 0 now classifies
  the target (web app, backend API, mobile, browser extension, chat bot, CLI, desktop) and routes the
  audit through the matching playbook; mixed artifacts (mobile app + backend) are audited as both with a
  shared trust-boundary map. Phase 0 also formalizes the mechanical inventory (dependency map, entry-point
  table, data-flow sketch) as compact tables.
- **Non-AI-app decoupling.** Phase 3 section D (AI/LLM features) is now explicitly conditional: it runs
  only when Phase 0 detects an actual LLM/agent integration, and the report says so plainly when it's
  skipped. Sections A–C and E–I always run. A `SKILL.md` clarifier states that "vibe-coded" describes how
  code was built, not whether it has AI features — a plain CRUD app is fully in scope.
- **Re-audit (regression delta) mode.** On request after remediation, Phase 4 re-runs the full audit and
  presents a delta over the standard template — *Resolved / Still open / Newly introduced* — with explicit
  scrutiny for bugs introduced by the fixes themselves.
- **Plain-English Executive Brief** (dual-audience output). An optional translation layer over the same
  analysis for non-technical audiences: a single "is this safe to ship" answer, findings restated with
  real-world analogies, grouped "Fix before launch" / "Worth doing, not urgent." The technical report stays
  the default and remains available; the rubric underneath is never softened to produce the brief.
- **New stack playbooks** — Python (Django/Flask/**FastAPI**), **Firebase** (Firestore/RTDB rules — the
  direct equivalent of RLS misconfiguration), **PHP** (Laravel/WordPress), and **Node+Mongo** (NoSQL
  operator injection). Existing Supabase, Next.js, serverless/edge, LLM/RAG, Rails, Go, and mobile
  playbooks were carried over and polished.
- **New reference `artifact-playbooks.md`** — entry-point maps, traps, and tests for browser extensions,
  chat bots, CLI tools, and desktop/Electron apps, where "route handler" is the wrong model.
- **Async scan (category F) extended** with stale closures over shared mutable state, improper listener/
  timer/subscription cleanup, and webhook/queue idempotency.

### Restructured
- **`references/stack-playbooks.md` is now an index** into `references/stack-playbooks/`, one file per
  stack, so an audit loads only the playbook it needs. All prior playbook content is preserved; the file
  that used to hold everything now holds the table of contents and the "adding a playbook" guidance.

### Unchanged (deliberately)
- The six-phase workflow, the STRIDE step, the report output template, the Critical/High/Medium/Low
  severity rubric, the separate confidence rubric, the evidence standard (source · sink · missing control ·
  falsifier), and the read-only / report-only default. The three `examples/` reports remain in their
  original v1.0.0 format, labeled as such.

## [2.1.0] — 2026-07-10

Closes the coverage gaps that the v2 threat model implied but no vulnerability class caught — most
notably the STRIDE *repudiation* leg, which Phase 2 enumerated with nowhere to report it. Adds
tool-assisted evidence as a first-class, deliberately advisory reference, and an evidence standard that
governs when a lead is allowed to become a finding. The six-phase workflow and the report format are
unchanged, so this is a MINOR bump per [CONTRIBUTING.md](CONTRIBUTING.md).

### Added
- **Seven vulnerability classes** (33 → 40), each with a matching fail-closed remediation:
  - `SENT-AUTHZ-08` — insecure password reset and account recovery (predictable tokens, no expiry or
    single-use, host-header-poisoned reset links, sessions surviving a reset).
  - `SENT-AUTHZ-09` — Cross-Site Request Forgery. Previously mentioned in the Django and Rails playbooks
    but mis-cross-linked to the CORS/headers class; it now has its own entry, and the playbooks point at it.
  - `SENT-INJ-08` — excessive data exposure in responses (the read-path counterpart to mass assignment).
  - `SENT-CRYPTO-01` — weak or absent credential hashing; `SENT-CRYPTO-02` — predictable randomness in
    values that grant access. OWASP A02:2021 had no class before this.
  - `SENT-LOG-01` — no audit trail on privileged or financial actions, which closes STRIDE *repudiation*;
    `SENT-LOG-02` — secrets and PII written to logs and telemetry.
- **Phase 3 scan groups G (cryptography & randomness) and H (logging, monitoring & audit trail).**
  Groups A–F keep their letters, so existing cross-references still resolve.
- **`skill/references/tooling.md`** — the static-analysis integration `SKILL.md` flagged as the v3
  direction, done as a whole: the "tools produce leads, the audit produces findings" discipline, a
  per-ecosystem scanner table with each tool's documented blind spots, a ripgrep pattern pack keyed to
  catalog classes, the `git log -S` archaeology that makes Phase 4 mechanical rather than aspirational,
  and a JSON/SARIF finding schema for CI.
- **Evidence standard** in Phase 5: a finding must name its source, sink, missing control on the live
  path, and — new — a **falsifier**, the configuration that would prove it a non-issue. Below-High
  confidence findings state the falsifier in the report. A pattern match with no falsifier is not a finding.
- **Confidence rubric**, previously prose in the docs, now explicit and separate from severity.
- **`scripts/check_repo.py` + `.github/workflows/ci.yml`** — CI enforces the invariants CONTRIBUTING
  states in prose: every intra-repo link and heading anchor resolves, every `SENT-*` class exists in
  *both* the catalog and the remediation patterns, and no credential-shaped strings are committed.
  Gitleaks now runs against this repo's own history.

### Changed
- Severity guidance: rate the **exposed gap**, not the code's apparent intent — a semantically incomplete
  control scores as if absent. A missing audit log is never Critical on its own.
- Generic / Unknown Stack playbook extended with CSRF, credential-hashing, randomness, and audit-trail
  traps, so the new classes reach stacks with no named playbook.
- `docs/methodology.md`, `docs/how-to-use.md`, `examples/README.md`, and both standalone prompts were
  still documenting the **four-phase** workflow after the v2.0.0 upgrade. All are now six-phase, and the
  output format everywhere includes *Code Health Notes*.

### Notes
- The three reports in `examples/` were produced under the v1.0.0 format and are preserved as written
  rather than retrofitted; `examples/README.md` now says so. Rewriting a real audit after the fact to
  demonstrate a feature it never ran is the kind of thing this project exists to catch.

## [2.0.0] — 2026-07-01

The v2 upgrade broadens SENTINEL from a security-vulnerability scanner to a security *and code-health*
auditor, and generalizes it beyond the Next.js/Supabase stack. The four original phases are intact;
two new phases wrap around them (now six phases, 0–5).

### Added
- **Phase 0 — Pre-audit inventory**: structural map, AI-authorship signal detection, and an
  iteration-depth estimate that calibrates the skepticism of every later phase.
- **Phase 4 — Iterative regression audit**: operationalizes the finding that AI-assisted code tends to
  get *less* secure over successive refinement passes, even security-focused ones. Degrades to a
  static pass when no git history is available.
- **Phase 3 categories E & F**: architectural & structural integrity (orphan modules/state, pattern
  consistency, dead code masking controls) and asynchronous logic & state management (unhandled async
  paths, swallowed errors, races, boundary inputs).
- **Catalog**: new `SENT-ARCH-01…05` (dead code masking a control, orphan state, cosmetic abstraction,
  context-window pattern abandonment, security-focused regression trap) and `SENT-ASYNC-01…02`
  (swallowed async errors, non-atomic writes to shared state) classes, with matching fixes in
  `remediation-patterns.md`. Explicit registry-resolution guidance added to SENT-SUPPLY-02.
- **Playbooks**: a Generic / Unknown Stack playbook now opens the file, plus new Django/Flask, Rails,
  Go, and React Native/Flutter playbooks.
- **Output format**: a non-blocking **Code Health Notes** section after Systemic Recommendations.
- **Operating principle**: SENTINEL is read-only and report-only by default — it proposes fixes and
  never applies or deletes on its own initiative.

### Changed
- Renumbered "Phase 4 — Deliver remediation" to Phase 5; skill description, phase cross-references,
  and reference-loading guidance updated throughout.

## [1.0.0] — 2026-07-01

Initial public release. The four-phase methodology is stable and unchanged from the private
skill; this release adds the reference corpus, documentation, and redacted example reports
around it.

### Added
- **Skill** — `security-audit` persona (SENTINEL) with the fixed four-phase workflow: establish
  context and trust boundaries, STRIDE threat model, adversarial code scan, severity-rated
  remediation with drop-in secure code.
- **Vulnerability catalog** (`skill/references/vulnerability-catalog.md`) — vibe-coding
  vulnerability classes across Authorization, Injection & Sinks, Secrets & Config, Supply Chain,
  and LLM & Agents, each mapped to OWASP Top 10:2021, OWASP API Security Top 10:2023,
  OWASP Top 10 for LLM Applications:2025, and CWE.
- **Stack playbooks** (`skill/references/stack-playbooks.md`) — Supabase, Next.js 14 App Router,
  generic serverless/edge, and LLM/RAG.
- **Remediation patterns** (`skill/references/remediation-patterns.md`) — before/after secure code
  keyed to catalog IDs, prioritizing TypeScript / Next.js / Supabase SQL.
- **Standalone prompts** (`prompts/`) — a paste-anywhere master prompt and a quick single-file
  variant, both faithful to the skill's output format.
- **Docs** (`docs/`) — methodology deep dive, STRIDE threat-modeling guide, Supabase RLS guide,
  and installation / usage instructions.
- **Example reports** (`examples/`) — three redacted audits demonstrating the methodology on a
  Next.js + Supabase app, a RAG chatbot site, and a near-static marketing site.
- **Governance** — MIT license, security policy, contribution guide, code of conduct, issue
  templates, and CI notes.

[3.0.0]: https://github.com/shreyas-tech7/sentinel/releases/tag/v3.0.0
[2.1.0]: https://github.com/shreyas-tech7/sentinel/releases/tag/v2.1.0
[2.0.0]: https://github.com/shreyas-tech7/sentinel/releases/tag/v2.0.0
[1.0.0]: https://github.com/shreyas-tech7/sentinel/releases/tag/v1.0.0
