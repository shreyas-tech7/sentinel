# Standards Mapping

Every classification in the [vulnerability catalog](../skill/references/vulnerability-catalog.md) points at
a public, versioned standard. This document explains which standards SENTINEL cites, why, and how to read
the `Classification` line that carries them. It is the reference behind the catalog's
[Framework editions referenced](../skill/references/vulnerability-catalog.md#framework-editions-referenced)
table, not a substitute for it — the catalog remains the single source of truth for per-class IDs.

## Why standards, not vibes

A severity number an auditor pulled from intuition is unfalsifiable. A severity number tied to
*A01:2025 Broken Access Control · CWE-639 (#24 on the CWE Top 25)* is a claim a reader can check against an
external, dated authority — and disagree with in a way that resolves. As of v4.0 the catalog's severity
tendencies and its classifications are derived from citable editions of OWASP, CWE, and ASVS precisely so
that findings are **defensible on their own terms**, independent of who ran the audit.

This is the same discipline the methodology holds everywhere else: *tools produce leads; the audit produces
findings*. A classification is not decoration and not a scanner's tag — it is the paper trail that lets a
finding survive scrutiny. A class that cannot be pinned to a recognized weakness is a class that has not
been thought through, which is why the [contribution bar](../CONTRIBUTING.md#how-to-add-a-vulnerability-class)
requires a current-edition OWASP/API/LLM ID *and* a CWE ID for every entry.

## The reference frameworks SENTINEL cites

Classifications draw on five public frameworks, at the exact editions below. This mirrors the catalog's
editions table; keep the two in step.

| Framework | Edition used | Role in a Classification line | Source |
|---|---|---|---|
| OWASP Top 10 | **2025** | Primary web-risk category (`A0x:2025`) | <https://owasp.org/Top10/2025/> |
| OWASP API Security Top 10 | **2023** | API-specific analogue (`APIx:2023`) | <https://owasp.org/API-Security/editions/2023/en/0x11-t10/> |
| OWASP Top 10 for LLM Applications | **2025** | AI/agent classes only (`LLMxx:2025`) | <https://genai.owasp.org/llm-top-10/> |
| CWE Top 25 | **2025 edition** (analysis window Jun 2024 – Jun 2025) | Precise weakness + Top-25 rank (`CWE-nnn`) | <https://cwe.mitre.org/top25/> |
| OWASP ASVS | **5.0.0** (2025-05-30) | Verification chapter to test against (`ASVS 5.0 ch. n`) | <https://owasp.org/www-project-application-security-verification-standard/> |

**OWASP Top 10:2025** is the industry's baseline risk taxonomy for web applications. SENTINEL uses it as the
primary axis because it is the standard a founder, a client, or an insurer will already recognize, and
because the 2025 edition's own reshuffle tracks how modern apps actually fail (see the migration below).

**OWASP API Security Top 10:2023** is the current edition, and the right lens for the object- and
function-level authorization failures that dominate vibe-coded backends — BOLA (`API1`), Broken Object
Property Level Authorization (`API3`), and Broken Function Level Authorization (`API5`) are sharper names for
what the web Top 10 files broadly under Broken Access Control. SENTINEL cites it alongside the web category
wherever an endpoint, not a page, is the unit of risk.

**OWASP Top 10 for LLM Applications:2025** is the current edition and the only framework that names
prompt injection, improper output handling, excessive agency, and unbounded consumption as first-class
risks. It appears **only on the category-D classes**, which run only when Phase 0 detects an actual model or
agent integration — a plain CRUD app carries no `LLMxx:2025` id anywhere.

**CWE Top 25:2025** grounds severity in observed prevalence. Citing a CWE with its rank
(`CWE-79 — #1`, `CWE-89 — #2`, `CWE-352 — #3`) is what turns "this feels bad" into "this is a top-ranked
weakness by real-world frequency." The classes SENTINEL flags most aggressively map straight onto the top of
the list:

| CWE | Weakness | 2025 rank | Cited by (example) |
|---|---|---|---|
| CWE-79 | Cross-Site Scripting | 1 | SENT-INJ-02 |
| CWE-89 | SQL Injection | 2 | SENT-INJ-01 |
| CWE-352 | Cross-Site Request Forgery | 3 | SENT-AUTHZ-09 |
| CWE-862 | Missing Authorization | 4 | SENT-AUTHZ-02 |
| CWE-22 | Path Traversal | 6 | SENT-INJ-10 |
| CWE-78 | OS Command Injection | 9 | SENT-INJ-01 |
| CWE-94 | Code Injection | 10 | SENT-INJ-01 |
| CWE-434 | Unrestricted File Upload | 12 | SENT-INJ-06 |
| CWE-502 | Deserialization of Untrusted Data | 15 | SENT-INJ-09 |
| CWE-284 | Improper Access Control | 19 *(new entrant)* | SENT-AUTHZ-07 |
| CWE-200 | Exposure of Sensitive Information | 20 | SENT-SECRET-01 |
| CWE-306 | Missing Authentication for Critical Function | 21 | SENT-AUTHZ-03 |
| CWE-918 | Server-Side Request Forgery | 22 | SENT-INJ-07 |
| CWE-639 | Authorization Bypass Through User-Controlled Key | 24 *(new entrant)* | SENT-AUTHZ-01 |
| CWE-770 | Allocation of Resources Without Limits | 25 *(new entrant)* | SENT-INJ-05, SENT-LLM-04 |

**OWASP ASVS 5.0.0** is a verification standard, not a risk list — its 17 chapters (V1 Encoding and
Sanitization … V16 Security Logging and Error Handling, V17 WebRTC) tell you *what to test to prove a control
holds*. SENTINEL cites it at chapter level on classes that map cleanly, so a finding carries not just a
risk name but the checklist a re-tester opens next. It is the falsifier's companion: `ASVS 5.0 ch. 8`
against an authorization finding says exactly which requirements would close it out.

## The 2021 → 2025 OWASP migration

The 2025 edition renumbers the web Top 10, folds one category in, and adds two. Every catalog `A0x:2025`
reference already reflects this; the table is here so a reader coming from a 2021-era mental model can
translate.

| 2021 category | 2025 destination | What changed |
|---|---|---|
| A01 Broken Access Control | **A01** Broken Access Control | Rank held; now also absorbs SSRF |
| A02 Cryptographic Failures | **A04** Cryptographic Failures | Down two |
| A03 Injection | **A05** Injection | Down two |
| A04 Insecure Design | **A06** Insecure Design | Down two |
| A05 Security Misconfiguration | **A02** Security Misconfiguration | **Up three (#5 → #2)** |
| A06 Vulnerable and Outdated Components | **A03** Software Supply Chain Failures | Renamed and broadened into a new supply-chain category |
| A07 Identification and Authentication Failures | **A07** Authentication Failures | Renamed |
| A08 Software or Data Integrity Failures | **A08** Software or Data Integrity Failures | Unchanged |
| A09 Security Logging and Monitoring Failures | **A09** Security Logging and Alerting Failures | Renamed |
| A10 Server-Side Request Forgery (SSRF) | *folded into* **A01** | No longer a standalone category |

**Two categories are new in 2025:**

- **A03 Software Supply Chain Failures** — the successor to 2021's A06, widened past "vulnerable components"
  to cover the whole software supply chain (build systems, dependency provenance, install-time execution).
  SENTINEL's `SENT-SUPPLY-01`/`SENT-SUPPLY-02` — including hallucinated/typosquatted packages — sit here.
- **A10 Mishandling of Exceptional Conditions** — genuinely new, with no 2021 predecessor. It covers
  swallowed exceptions, fail-open error handling, and inconsistent error states (CWE-703, CWE-390, CWE-755,
  CWE-636).

**The notable moves.** Security Misconfiguration climbing from #5 to #2 is the headline: insecure defaults
are now the second-most-prevalent web risk, which matches the vibe-coding failure mode exactly — code that
*works* before anyone hardened it. Cryptographic Failures and Injection both slid down two places (to A04 and
A05) — not because they got safer, but because access-control and configuration failures got relatively more
common. And SSRF losing its standalone slot into A01 is why `SENT-INJ-07` now classifies as
*A01:2025 (Broken Access Control)* rather than *A10:2021*.

**A10:2025 validates category F.** SENTINEL has flagged swallowed and fail-open errors as first-class
security findings since before OWASP gave them a top-10 slot — that is the whole of scan
[category F](../skill/references/vulnerability-catalog.md#sent-async-01--swallowed-async-errors-and-silent-fallback-returns)
(async logic and state), built on the empirical claim that a catch block which logs and returns `null`
fails open. The 2025 edition's new A10 is OWASP arriving at the same conclusion independently. The catalog
does not need to move to meet it; the class was already there.

## How to read a Classification line

Each catalog entry ends with a single `Classification` line. Take `SENT-AUTHZ-01` (IDOR):

```
Classification: OWASP A01:2025 (Broken Access Control) · API1:2023 (Broken Object Level
Authorization) · CWE-639 (Authorization Bypass Through User-Controlled Key — #24 on the 2025
CWE Top 25), CWE-284 (Improper Access Control) · ASVS 5.0 ch. 8 (Authorization)
```

Read left to right, one framework per ` · ` segment:

| Segment | What it tells you | Framework |
|---|---|---|
| `OWASP A01:2025 (Broken Access Control)` | The primary web-risk category | OWASP Top 10:2025 |
| `API1:2023 (Broken Object Level Authorization)` | The API-specific analogue, when the unit of risk is an endpoint | OWASP API Top 10:2023 |
| `CWE-639 (… — #24 on the 2025 CWE Top 25)` | The precise weakness, plus its prevalence rank | CWE Top 25:2025 |
| `CWE-284 (Improper Access Control)` | A secondary or parent weakness, comma-joined inside the CWE segment | CWE dictionary |
| `ASVS 5.0 ch. 8 (Authorization)` | The verification chapter that would prove the control holds | ASVS 5.0.0 |

Two reading rules. **` · ` separates frameworks; a comma separates multiple CWEs within the CWE segment** —
a class often names one ranked Top-25 weakness plus a broader parent. And **not every class carries all five
axes**: an AI class carries an `LLMxx:2025` id in place of (or beside) the web category; ASVS is cited only
where a class maps cleanly to a chapter; a rank annotation (`#24`) appears only when the CWE is on the 2025
Top 25. A line is complete when it names the primary OWASP category and at least one CWE — the rest sharpen
it. The catalog's own [How to read an entry](../skill/references/vulnerability-catalog.md#how-to-read-an-entry)
table defines the surrounding fields.

## Maintenance

Standards age on a fixed cadence; the catalog is designed to be refreshed edition-by-edition rather than
rewritten. When a new edition of any framework above ships, update **three places, in this order**:

1. **The catalog** — the
   [Framework editions referenced](../skill/references/vulnerability-catalog.md#framework-editions-referenced)
   table and the mapping paragraph beneath it, then every per-class `Classification` line the new edition
   touches. The catalog is the source of truth; changes start here.
2. **`metadata.version` in [`../skill/SKILL.md`](../skill/SKILL.md)** — per the
   [versioning convention](../CONTRIBUTING.md#versioning-convention), *any* change to the OWASP / API / LLM /
   CWE mapping tables is at least a **MINOR** bump, with a matching CHANGELOG entry. Refreshing to a new
   edition is exactly that case. SKILL.md's own
   [Maintaining this skill](../skill/SKILL.md#maintaining-this-skill) note carries the same instruction.
3. **This document** — the framework table, the CWE-rank table, and the migration table, so the mapping a
   reader translates against stays current.

Note that `scripts/check_repo.py` validates cross-reference integrity (links, anchors, class parity) and
secret shapes — it does **not** verify that a classification names the right edition or the correct CWE.
That correctness is a human-review responsibility; the checklist above is what keeps it from drifting.
