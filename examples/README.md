# Example Reports

Three redacted SENTINEL audits, one per project, chosen to show the methodology across very different
attack surfaces:

| Report | Surface | Leads with |
|---|---|---|
| [PromptVault](promptvault-audit-redacted.md) | Next.js + Supabase community app, user-generated content | Object-level authorization / RLS on UGC |
| [BJJ Academy](bjj-academy-audit-redacted.md) | Marketing site + RAG chatbot + admin dashboard | The LLM/RAG surface + admin function-level authz |
| [Atlas Marketing](atlas-marketing-audit-redacted.md) | Near-static agency site, Formspree forms | "Small surface, still worth auditing" |

## What these are

Real audits of the author's own deployed projects, rewritten for publication. They exist to demonstrate
how the workflow reads on a real system — the orientation, the threat model, the findings ordered by
severity, and the fixes — not to catalog live weaknesses.

**These are applied examples only — they are not the source of the methodology.** As of v4.0, the
[vulnerability catalog](../skill/references/vulnerability-catalog.md) and severity rubric are derived
from public, citable standards (OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP Top 10 for
LLM Applications:2025, the 2025 CWE Top 25, and ASVS 5.0), and the tool's accuracy is checked against
public ground truth in [`validation/`](../validation/) rather than against these three audits. A good report is not a wall of Criticals; it's
a proportionate picture of a system's risk, and these reflect that.

> **These three reports were produced under the v1.0.0 report format**, before v2.0.0 added the Phase 0
> inventory, the Phase 4 regression audit, and the *Code Health Notes* section. They are preserved as
> written rather than retrofitted, because rewriting a real audit after the fact to demonstrate a feature
> it never ran would be exactly the kind of thing this project exists to catch. A current audit produces
> the six sections listed below; these show five. Their OWASP/CWE classification IDs likewise reflect the
> **2021 editions** current when the audits ran — the catalog itself moved to the 2025 editions in v4.0,
> but these preserved reports are not rewritten to match. See [CHANGELOG.md](../CHANGELOG.md).

## Redaction policy (applied to every report without exception)

1. **No real secrets.** No API keys, tokens, JWTs, service-role keys, connection strings, or `.env`
   contents appear — not even realistic-looking fakes. Secrets are shown only as obvious placeholders:
   `<REDACTED_API_KEY>`, `sb-service-role-key-REDACTED`.
2. **Only remediated findings.** Every vulnerability shown was **fixed before publication**. Nothing here
   advertises a live, unpatched hole in a running deployment. Each report states this in a header line.
3. **Sanitized internals.** Real internal table names, private route paths, and storage bucket ids are
   replaced with representative equivalents and marked `[sanitized]`. They do not reveal the real schema.
4. **Representative findings are labeled.** Where a finding illustrates a class the methodology checks for
   rather than reproducing a specific real defect, it is tagged **`# representative finding`**. Treat
   tagged findings as instructive examples of what SENTINEL looks for, modeled on the project's
   architecture — not as claims about the exact code that shipped.

> **Standard disclaimer (applies to all three reports):** These reports are redacted and educational. The
> vulnerabilities shown were remediated prior to publication. Secrets are placeholders and internal
> identifiers are sanitized. This is **not** a current representation of the deployed system.

## How to read a SENTINEL report

Every current report has the same six sections:

1. **Executive Summary** — scope and stack, a count of findings by severity, and the single
   highest-impact risk in one sentence. Read this first; it's the whole report in miniature.
2. **Threat Model Summary** — the key assets, entry points, and the top prioritized threats (from the
   STRIDE pass). This is *why* the findings that follow were the ones worth chasing.
3. **Findings (Critical → Low)** — the substance, ordered by severity. Each finding carries:
   - **Severity** (how bad if real) and **Confidence** (how sure it's real) — read as a pair. A
     `High / Medium confidence` finding is serious but needs verification; a `Critical / High confidence`
     is both bad and certain. Below-High-confidence findings also name the *falsifier* — the specific
     policy or file that would close the item out.
   - **Classification** — the OWASP / API / LLM ID and CWE, so it's cross-referenceable.
   - **Location**, **Vulnerability Analysis**, **Attack Scenario**, **Impact**, and **Remediation** with
     before/after code. Fixes fail closed.
4. **Systemic Recommendations** — cross-cutting corrections that prevent whole classes (centralized
   authorization, RLS everywhere, schema validation at boundaries, rate limiting, CI secret-scanning,
   cross-tenant tests). Often more valuable than any single finding.
5. **Code Health Notes** *(added in v2.0.0; absent from the three reports here)* — non-blocking
   structural observations: dead code, cosmetic abstractions, naming drift. It explains why a codebase is
   hard to secure. It never pads the severity count, and it is never used to soften something exploitable
   — a dead code path that used to gate access is a security finding at full severity, in section 3.
6. **Residual Risk & Verification Constraints** — the boundary of the review: what wasn't covered and what
   still needs runtime or environment-level testing. The report naming its own blind spots is a feature.

The finding IDs (`SENT-AUTHZ-01`, etc.) reference the
[vulnerability catalog](../skill/references/vulnerability-catalog.md); the remediations mirror the
[remediation patterns](../skill/references/remediation-patterns.md). If you want to run your own audit,
start at [docs/how-to-use.md](../docs/how-to-use.md).
