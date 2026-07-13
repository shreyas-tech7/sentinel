# Methodology

SENTINEL is a fixed six-phase workflow driven by a persona, not a checklist you eyeball or a linter you
run. This document explains what each phase does, why they run in this order, and the operating stances
that make the difference between an audit and a scan. The authoritative procedure is
[`../skill/SKILL.md`](../skill/SKILL.md); this is the reasoning behind it.

## Why a persona and a fixed order

A linter matches patterns. An auditor reasons about *intent* — what this system is supposed to protect,
who wants to reach it, and where a control was supposed to be but isn't. That reasoning is what finds
broken authorization, because broken authorization is the *absence* of code, and you can't grep for an
absence. You have to know a check should be there.

So SENTINEL runs as a persona with stances (below) and a defined sequence:

```
Phase 0          Phase 1           Phase 2         Phase 3            Phase 4          Phase 5
Inventory   →    Orient       →    Model      →    Scan          →    Regress     →    Fix
structure &      context &         STRIDE per      adversarial        did iteration    self-verify,
AI signals       trust boundaries  boundary        data-flow trace    erode controls?  severity-rated
                                                                                       remediation
```

**The order is load-bearing.** Each phase is the input to the next:

- You cannot calibrate suspicion without an **inventory**. Phase 0 estimates how much of this code was
  generated, and how deeply iterated — which sets the prior for everything after it.
- You cannot threat-model what you have not **oriented** to. STRIDE on an unknown boundary is guesswork;
  STRIDE on a mapped one is targeted.
- You cannot **scan** efficiently without a threat model. The model produces a ranked list of the most
  exploitable vectors, so the scan spends its attention where blast radius is highest instead of reading
  every line with equal suspicion.
- You cannot judge a control by its presence alone. Phase 4 asks the question a single-snapshot scan
  cannot: was this control **weaker last week**, and did an iteration hollow it out?
- You cannot **fix** responsibly without having scanned and then *re-checked*. Phase 5 begins with
  self-verification precisely because a fast scan over-produces; the discipline is to downgrade the
  theoretical before you hand the user a report.

Inventory → orient → model → scan → regress → fix is the same loop a careful human reviewer runs. Fixing
the order into the workflow is what keeps a fast pass from degenerating into pattern-matching.

## The operating stances

These are held for the entire review. They are assumptions about *where to look*, chosen because they
match how vibe-coded apps actually fail.

### Assume it was vibe-coded
Treat the code as if written quickly to make a feature work. Assume deep authorization checks, strict
server-side validation, and secure secrets handling were **not** done until the code proves otherwise.
This is not cynicism; it is the correct prior. Generated and rapidly-built code reliably implements the
happy path (there is something on screen to make work) and reliably omits the security-relevant parts
(nothing on screen demands them). Starting from "it's probably fine" biases you toward missing exactly
the class of bug that is most common.

### Be false-negative-averse
A missed vulnerability ships to production; a flagged non-issue costs a few minutes of triage. Those are
not symmetric. So when unsure, **surface it and label confidence** rather than staying silent. The cost
of this stance — some false positives — is paid down by Phase 5 self-verification and explicit confidence
labels, which let the user triage instead of drowning.

### Report only what you can trace
The counterweight to false-negative aversion. A finding requires a **source**, a **sink**, a **missing
control** on the live path, and — the discipline that keeps the stance above from producing noise — a
**falsifier**: the specific policy, middleware, or framework default that, if it existed where you cannot
see, would make this a non-issue. If you can't name what would prove you wrong, you don't understand the
finding well enough to report it. This is why a scanner's output is never a finding: a pattern match has
no falsifier attached.

### Think like an attacker, write like a senior engineer
Trace how hostile input moves through the system — the attacker's job. Then explain the finding and the
fix the way a thoughtful staff engineer would in code review — the defender's job. The first half finds
the bug; the second half makes it fixable. A finding no one can act on is not a finding.

### Trust no input and no boundary by default
Every client-supplied value — path and query params, request bodies, headers, file uploads, webhook
payloads, and any JWT claim a user can edit — is hostile until validated server-side. And crucially:
**authentication is not authorization.** Knowing *who* someone is (they logged in) says nothing about
*what* they may touch (this specific object, this admin function). Conflating the two is the root of the
single most common finding, IDOR.

### "Looks normal" is not "is safe"
Idiomatic-looking code is exactly where authorization and validation gaps hide, because the happy path
works perfectly. `supabase.from('invoices').select('*').eq('id', id)` reads like clean, ordinary code. It
is also a cross-tenant data leak if there's no ownership scope and no RLS. The tell is not ugliness; it
is a missing control behind working code.

## Phase 0 — Pre-audit inventory

Orientation *before* orientation: compact tables, never a report section of its own. Phase 0 answers two
questions — "what's here?" (mechanical inventory) and "how suspicious should I be?" (AI-authorship
signal) — and hands both to every phase after it.

1. **Mechanical inventory.** A dependency map (from whichever manifest applies — flag unpinned, abandoned,
   or hallucinated packages), an entry-point table (every route, handler, server action, webhook, queue
   consumer, CLI/cron entry, bot command, extension listener, each tagged with its trigger and *declared*
   auth), a data-flow sketch, and a preliminary trust-boundary list. Plus the structural map: a module
   imported by many consumers has a large blast radius (audit it first); one importing from many sources
   may be a God Module where checks get lost.
2. **Artifact-type classification.** Before assuming "web app with routes," state what the target actually
   is — web app, backend API, mobile app, browser extension, chat bot, CLI tool, or desktop app — because
   the entry-point model differs by type, and route the rest of the audit through the matching playbook. A
   mixed artifact (mobile app + its backend) is audited as both, over a shared trust-boundary map. Note
   here too whether an LLM/agent integration is present — that switch turns Phase 3 section D on or off.
3. **AI-generation markers.** Excessive comments explaining trivial logic, unresolved TODOs, near-duplicate
   functions separated by many lines, abrupt style shifts mid-file, monolithic files grown feature by
   feature, and — from git — a handful of large AI-assisted commits versus many small human-reviewed ones.
   High AI-commit density with low human-review density raises the prior on everything downstream — the
   condition the [Phase 4](#phase-4--iterative-regression-audit) regression audit exists to exploit. This
   lens only *raises* scrutiny on flagged sections; it never lowers it, and a hand-written file still gets
   the full audit.

Phase 0 never blocks the audit. Without repo or git access, say so plainly and proceed with what you have.
The mechanical commands for this phase are in
[`../skill/references/tooling.md`](../skill/references/tooling.md).

## Phase 1 — Establish context and trust boundaries

Orient before judging. Name three things explicitly:

1. **Target stack** — languages, frameworks, runtimes (server / serverless / edge), database engines,
   auth providers, third-party APIs. Above all, *which code runs on the client versus the server*,
   because that line determines what an attacker can read and tamper with. A secret in a Client Component
   is already public; the same secret in a Server Action is not.
2. **Trust boundaries** — every place untrusted data crosses into a more-trusted zone: client→server,
   edge→database, webhook→backend, app→third-party API, user-content→any interpreter (SQL, shell, HTML,
   template). For each, state what is attacker-controlled.
3. **High-value assets** — where secrets, PII, payments, auth tokens, admin functions, and any
   data-writing or money-spending operation live. These are what the rest of the audit protects.

Orientation is what turns the later phases from generic to specific. See
[threat-modeling.md](threat-modeling.md) for worked boundary maps.

## Phase 2 — Threat model (STRIDE)

For each entry point and boundary from Phase 1, enumerate threats with STRIDE (Spoofing, Tampering,
Repudiation, Information disclosure, Denial of service, Elevation of privilege), then **prioritize by
blast radius**, weighting auth, payment, and data-layer boundaries most heavily. The output is a short,
ranked list of the most exploitable vectors to verify in Phase 3. STRIDE's value here is coverage: it
forces you to consider each category at each boundary, so you don't only look for the vulnerability class
you happened to think of first. The full mapping to web/serverless/LLM boundaries is in
[threat-modeling.md](threat-modeling.md).

## Phase 3 — Adversarial code scan

The core technique is **data-flow tracing**: follow each attacker-controlled value from its entry point
to every sensitive sink, and check whether a *server-side* control stops it on the way. A sink is
anywhere data becomes action — a query, a command, an HTML render, an authorization decision, a paid API
call. Between source and sink there should be a control (an ownership check, a parameterization, an
encode, a validation). The finding is a source that reaches a sink with the control missing.

The scan evaluates against the classes in
[`../skill/references/vulnerability-catalog.md`](../skill/references/vulnerability-catalog.md) — the
exhaustive checklist with detection guidance and classification for each — and the stack-specific
manifestations in
[`../skill/references/stack-playbooks.md`](../skill/references/stack-playbooks.md). The catalog is the
heart of the scan; it is loaded on demand rather than memorized, so it can be kept current as OWASP, the
API/LLM Top 10s, and CWE evolve.

The scan runs nine groups, not just the classic vulnerability ones: authorization (A), injection and
sinks (B), secrets and configuration (C), LLM and agents (D), architecture and structure (E), async logic
and state (F), cryptography and randomness (G), logging and audit trail (H), and platform and artifact
boundaries (I). Groups E and F exist because structural and async defects *cause and mask* security bugs —
a swallowed error fails open, dead code hides a control that protects nothing. Group H exists because the
STRIDE **repudiation** leg has nowhere else to land: Phase 2 asks "can this action be denied afterward?"
and only an audit-trail class can answer it. Group I exists because a browser extension, a chat bot, or a
CLI tool has entry points that never appear in a route table — a message listener, a bot command, an
`--output` flag — and its own permission model to overscope. Group D is **conditional**: it runs only when
Phase 0 detects an actual LLM or agent integration, and the report says so when it is skipped; a plain
CRUD app gets every group except that one.

Tools help here, and only here, and only as leads. `semgrep`, `gitleaks`, and the grep pack in
[`../skill/references/tooling.md`](../skill/references/tooling.md) generate candidates cheaply so the
scan's attention goes to the classes no tool can see. **A tool hit is a coordinate, not a conclusion.**

## Phase 4 — Iterative regression audit

The phase that a point-in-time scan structurally cannot perform, built on a counterintuitive empirical
claim: **AI-assisted code tends to get *less* secure over successive refinement passes — including the
passes that explicitly asked for security improvements.** Each iteration optimizes for the visible
instruction. Controls that nothing on screen demands quietly erode.

Three signatures, in descending order of how mechanically they can be found:

1. **A control's occurrence count went down.** `git log -S 'requireUser'` lists exactly the commits that
   changed how many times that string appears. A commit that *removes* instances of `verify`, `policy`, or
   `enable row level security` is the highest-quality lead the whole audit produces. Open the diff and ask
   whether the control moved or simply stopped existing — those look identical in a summary and are
   opposite findings.
2. **Security-instructed code deserves more suspicion, not less.** Code written under a "make this secure"
   instruction is where you find controls that are *structurally present but semantically incomplete*: a
   JWT check that verifies the signature but never pins the algorithm; parameterized queries added to new
   endpoints while an old raw query nearby was left alone. A half-present control is worse than an absent
   one, because it silences the reviewer who would have caught the absence.
3. **Inter-session boundaries.** Where naming conventions, error handling, or abstraction level shift
   abruptly between adjacent files, two generations met with no shared context. Each side assumes the
   other validated. Trace the actual call path across the seam.

This phase is a **detection lens, not a report section.** Its security findings enter the normal severity
rubric; the rest becomes Code Health Notes. Without git history it degrades to a static pass — run the
same signatures on adjacent code and *say in the report that history was unavailable*. Never imply the
phase ran fully when it did not.

## Phase 5 — Deliver remediation

**Self-verification first.** A false-negative-averse scan deliberately over-produces. Before anything
reaches the user, re-read each prospective finding and ask: is the vulnerable path actually reachable? Is
it purely theoretical? Does it rest on a wrong assumption about the syntax or the framework's behavior?
Discard or downgrade what fails. Assign an explicit **confidence** to what remains. This step is what
separates SENTINEL from a scanner that cries wolf: the report distinguishes "High severity, High
confidence" from "Medium severity, Low confidence — verify at runtime," so the user can triage instead of
being buried.

The gate is the **evidence standard**: name the source, the sink, the missing control on the live path,
and the falsifier. Anything that cannot fill all four is not yet a finding. When confidence is below High,
the falsifier goes *into* the report — it tells the reader exactly which file or policy to open to close
the item out, and it converts an uncertain finding from noise into a work item.

Then produce the report in the fixed [output format](#the-output-format-and-severity-rubric). Every
Critical and High finding ships with secure, drop-in remediation code drawn from
[`../skill/references/remediation-patterns.md`](../skill/references/remediation-patterns.md), adapted to
the project's stack and always **failing closed** — the default outcome, and the outcome on any error, is
deny.

### Confidence, and why it is separate from severity

Severity is *how bad if real*. Confidence is *how sure it's real*. They are independent, and reporting
both is the honest thing to do:

- A `using (true)` RLS policy on a user table is **Critical / High confidence** — you can see it and its
  impact is total.
- A possible race condition on a balance update where you can't see the transaction boundaries is
  **High / Medium confidence** — the impact is serious but reachability depends on code you haven't been
  shown.

Collapsing the two would either overstate certainty or understate risk. Keeping them separate lets the
user act rationally.

### Two audiences over one analysis

The technical report is the default and drives remediation. When the audience is non-technical — a
founder asking "is this safe to launch," a client, an investor deck — SENTINEL can also produce a
**Plain-English Executive Brief**: a single yes / yes-once-fixed / no answer, each finding restated with a
real-world analogy instead of a CWE ID, grouped into "Fix before launch" and "Worth doing, not urgent."
This is a *translation layer over the same findings*, not a lighter pass — the severity and confidence
underneath are unchanged, and a Critical never gets softened into the second bucket to make the brief more
reassuring. The technical report stays one request away.

### Re-auditing after a fix

When fixes have been applied, SENTINEL re-runs the full scan and reports a **delta** over the same template
— *Resolved / Still open / Newly introduced* — confirming each closed finding by pointing at the control
that now stops it (a fix that only relocates the vulnerable code is not "resolved"), and scrutinizing the
patch diffs themselves for bugs the fix introduced. It is the same rigor, presented as a diff.

## Handling large codebases

An audit that silently reviews 10% of a system and reports "looks good" is worse than useless — it
manufactures false assurance. So when the input is too large for one exhaustive pass, SENTINEL:

1. flags the **global architectural patterns** it can see (how auth is done, where the data layer is,
   whether RLS is the boundary),
2. completes a **thorough analysis of the portion in hand**, and
3. **names what it did not review** and asks for specific downstream files or directories in sequence.

The rule is absolute: **never skip code silently; name the boundary of the review.** This is also why
the report always ends with *Residual Risk and Verification Constraints* — the review's own limits are
part of its output.

## The output format and severity rubric

The report structure is fixed so results are consistent across the skill, the
[standalone prompts](../prompts/sentinel-master-prompt.md), and the
[example reports](../examples/):

```
## Executive Summary          — scope/stack, counts by severity, the single highest-impact risk
## Threat Model Summary        — key assets, entry points, top prioritized threats
## Findings (Critical → Low)   — per the finding template, with drop-in fixes for Critical/High
## Systemic Recommendations    — cross-cutting, architectural corrections
## Code Health Notes           — non-blocking structural observations; never pads the severity count
## Residual Risk & Constraints — what wasn't reviewed; what needs runtime/dynamic testing
```

**Code Health Notes is informational in both directions.** It is where plain dead code, cosmetic
abstractions, and naming drift go — the things that explain *why* a codebase is hard to secure. It is
never a place to soften something exploitable. A dead code path that used to gate access, or a swallowed
error that fails open, is a security finding at full severity, in the main Findings section.

**Severity rubric:**

| Severity | Definition |
|---|---|
| **Critical** | Unauthenticated remote code execution, cross-tenant data access bypass, or zero-barrier financial loss. |
| **High** | Authenticated vertical privilege escalation or extensive sensitive-data exposure. |
| **Medium** | Exploitable flaw requiring complex preconditions or with limited blast radius. |
| **Low** | Defense-in-depth gaps, hardening, or security-relevant code cleanliness. |

Rate the **exposed gap**, not the code's apparent intent. A control that is present but semantically
incomplete scores exactly as if it were absent — that is the whole point of the Phase 4 regression class.
Conversely, a missing audit log is never Critical on its own: it grants an attacker nothing. If it feels
Critical, the real finding is the unlogged action's own class.

## What this methodology is not

It is not a guarantee. A static review of source cannot observe runtime configuration, deployed
infrastructure, or environment secrets, and it cannot prove the absence of a vulnerability — only find
present ones and name its own blind spots. It complements, and does not replace, dynamic testing,
dependency scanning in CI, and (for high-stakes systems) a human penetration test. The
[how-to-use guide](how-to-use.md) covers wiring the automatable parts into CI as follow-through.
