# Changelog

All notable changes to SENTINEL are recorded here. The version tracks the skill's
`metadata.version` in [`skill/SKILL.md`](skill/SKILL.md). Bump the version whenever the
vulnerability catalog or the OWASP / API / LLM / CWE framework-mapping tables change, per
[CONTRIBUTING.md](CONTRIBUTING.md).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
