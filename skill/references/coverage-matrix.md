# Coverage Matrix

<!-- GENERATED FILE — do not edit by hand.
     Regenerate with: python scripts/gen_coverage_matrix.py
     Source of truth: vulnerability-catalog.md -->

Every SENTINEL vulnerability class mapped to its standards classification, generated from the
[catalog](vulnerability-catalog.md). OWASP uses the 2025 editions (API Security 2023, LLM 2025);
CWE and ASVS (5.0) columns list the identifiers each class cites. Click a `SENT-*` id for the full
entry — detection guidance, severity tendency, and the cross-linked fix.

**45 classes.**

| Class | Title | OWASP / API / LLM | CWE | ASVS 5.0 |
|---|---|---|---|---|
| [SENT-AUTHZ-01](vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor) | Broken Object Level Authorization / IDOR | A01:2025, API1:2023 | CWE-639, CWE-284 | V8 |
| [SENT-AUTHZ-02](vulnerability-catalog.md#sent-authz-02--broken-function-level-authorization) | Broken Function Level Authorization | A01:2025, API5:2023 | CWE-862, CWE-285 | V8 |
| [SENT-AUTHZ-03](vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network) | Authorization enforced only in middleware or network | A01:2025, API5:2023 | CWE-306, CWE-862, CWE-1220 | V8 |
| [SENT-AUTHZ-04](vulnerability-catalog.md#sent-authz-04--missing-auth-on-server-actions--route-handlers) | Missing auth on Server Actions / Route Handlers | A01:2025, API2:2023, API5:2023 | CWE-306, CWE-862 | V4, V8 |
| [SENT-AUTHZ-05](vulnerability-catalog.md#sent-authz-05--insecure-session-and-claims-handling) | Insecure session and claims handling | A07:2025, A04:2025 | CWE-347, CWE-522, CWE-807 | V7, V9 |
| [SENT-AUTHZ-06](vulnerability-catalog.md#sent-authz-06--auth-redirect--oauth-callback-misconfiguration) | Auth redirect / OAuth callback misconfiguration | A01:2025 | CWE-601, CWE-384 | — |
| [SENT-AUTHZ-07](vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive) | Missing database-layer access control (RLS disabled or permissive) | A01:2025, API1:2023 | CWE-1220, CWE-732, CWE-284 | V8 |
| [SENT-AUTHZ-08](vulnerability-catalog.md#sent-authz-08--insecure-password-reset-and-account-recovery) | Insecure password reset and account recovery | A07:2025, API2:2023 | CWE-640, CWE-644, CWE-330, CWE-204 | V6 |
| [SENT-AUTHZ-09](vulnerability-catalog.md#sent-authz-09--cross-site-request-forgery-csrf) | Cross-Site Request Forgery (CSRF) | A01:2025 | CWE-352, CWE-1275 | V3, V7 |
| [SENT-INJ-01](vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template) | Injection (SQL / command / code / template) | A05:2025 | CWE-89, CWE-78, CWE-94, CWE-1336 | V1 |
| [SENT-INJ-02](vulnerability-catalog.md#sent-inj-02--cross-site-scripting-xss) | Cross-Site Scripting (XSS) | A05:2025 | CWE-79 | V1, V3 |
| [SENT-INJ-03](vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation) | Mass assignment / over-allocation | A01:2025, API3:2023 | CWE-915, CWE-639 | — |
| [SENT-INJ-04](vulnerability-catalog.md#sent-inj-04--check-then-act-race-conditions) | Check-then-act race conditions | A06:2025, API6:2023 | CWE-362, CWE-367 | — |
| [SENT-INJ-05](vulnerability-catalog.md#sent-inj-05--missing-rate-limits-on-heavy-or-metered-operations) | Missing rate limits on heavy or metered operations | A06:2025, API4:2023 | CWE-770, CWE-799 | — |
| [SENT-INJ-06](vulnerability-catalog.md#sent-inj-06--insecure-file-upload) | Insecure file upload | A06:2025, A02:2025 | CWE-434, CWE-22 | V5 |
| [SENT-INJ-07](vulnerability-catalog.md#sent-inj-07--server-side-request-forgery-ssrf) | Server-Side Request Forgery (SSRF) | A01:2025, API7:2023 | CWE-918 | V4 |
| [SENT-INJ-08](vulnerability-catalog.md#sent-inj-08--excessive-data-exposure-in-responses) | Excessive data exposure in responses | A01:2025, A06:2025, API3:2023 | CWE-213, CWE-200 | — |
| [SENT-INJ-09](vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data) | Unsafe deserialization of untrusted data | A08:2025 | CWE-502 | V1 |
| [SENT-INJ-10](vulnerability-catalog.md#sent-inj-10--path-traversal-and-unsafe-file-path-handling) | Path traversal and unsafe file-path handling | A01:2025 | CWE-22, CWE-434, CWE-98 | V5 |
| [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets) | Hard-coded or client-exposed secrets | A02:2025, A04:2025 | CWE-798, CWE-200 | V13, V14 |
| [SENT-SECRET-02](vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode) | Permissive CORS, missing headers, debug mode | A02:2025 | CWE-942, CWE-16, CWE-1021, CWE-489 | V13 |
| [SENT-SECRET-03](vulnerability-catalog.md#sent-secret-03--public-storage-buckets--default-open-configuration) | Public storage buckets / default-open configuration | A02:2025 | CWE-732, CWE-284 | — |
| [SENT-SECRET-04](vulnerability-catalog.md#sent-secret-04--unverified-webhook-payloads) | Unverified webhook payloads | A08:2025 | CWE-345, CWE-347 | — |
| [SENT-SUPPLY-01](vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies) | Unpinned or unmaintained dependencies | A03:2025 | CWE-1104, CWE-1395 | — |
| [SENT-SUPPLY-02](vulnerability-catalog.md#sent-supply-02--hallucinated-or-typosquatted-packages) | Hallucinated or typosquatted packages | A08:2025, A03:2025, LLM03:2025 | CWE-1357, CWE-829 | — |
| [SENT-LLM-01](vulnerability-catalog.md#sent-llm-01--prompt-injection) | Prompt injection | LLM01:2025 | CWE-1427 | — |
| [SENT-LLM-02](vulnerability-catalog.md#sent-llm-02--improper-output-handling) | Improper output handling | LLM05:2025 | CWE-79, CWE-116, CWE-74 | — |
| [SENT-LLM-03](vulnerability-catalog.md#sent-llm-03--excessive-agency) | Excessive agency | LLM06:2025 | CWE-862, CWE-269 | — |
| [SENT-LLM-04](vulnerability-catalog.md#sent-llm-04--denial-of-wallet-on-metered-model-apis) | Denial-of-wallet on metered model APIs | API4:2023, LLM10:2025 | CWE-770, CWE-400 | — |
| [SENT-LLM-05](vulnerability-catalog.md#sent-llm-05--sensitive-disclosure--system-prompt-as-boundary) | Sensitive disclosure / system-prompt-as-boundary | LLM02:2025, LLM07:2025 | CWE-200, CWE-522 | — |
| [SENT-LLM-06](vulnerability-catalog.md#sent-llm-06--rag-poisoning-and-non-row-scoped-vector-stores) | RAG poisoning and non-row-scoped vector stores | LLM08:2025, LLM04:2025 | CWE-1220, CWE-284 | — |
| [SENT-ARCH-01](vulnerability-catalog.md#sent-arch-01--dead-code-masking-a-security-control) | Dead code masking a security control | A06:2025 | CWE-561, CWE-1164, CWE-862, CWE-306, CWE-20 | — |
| [SENT-ARCH-02](vulnerability-catalog.md#sent-arch-02--orphan-state-and-missing-cleanup) | Orphan state and missing cleanup | A06:2025 | CWE-459, CWE-772, CWE-457 | — |
| [SENT-ARCH-03](vulnerability-catalog.md#sent-arch-03--cosmetic-abstraction-hiding-a-missing-check) | Cosmetic abstraction hiding a missing check | A06:2025 | CWE-1120, CWE-710 | — |
| [SENT-ARCH-04](vulnerability-catalog.md#sent-arch-04--context-window-pattern-abandonment) | Context-window pattern abandonment | A06:2025 | CWE-710, CWE-862, CWE-20, CWE-89 | — |
| [SENT-ARCH-05](vulnerability-catalog.md#sent-arch-05--security-focused-regression-trap) | Security-focused regression trap | A06:2025, A04:2025 | CWE-358, CWE-693 | — |
| [SENT-ASYNC-01](vulnerability-catalog.md#sent-async-01--swallowed-async-errors-and-silent-fallback-returns) | Swallowed async errors and silent fallback returns | A10:2025, A06:2025 | CWE-390, CWE-703, CWE-392, CWE-636 | V16 |
| [SENT-ASYNC-02](vulnerability-catalog.md#sent-async-02--non-atomic-writes-to-shared-state) | Non-atomic writes to shared state | A06:2025 | CWE-362, CWE-667, CWE-820 | — |
| [SENT-ASYNC-03](vulnerability-catalog.md#sent-async-03--non-idempotent-webhook-and-queue-consumers) | Non-idempotent webhook and queue consumers | A06:2025 | CWE-837, CWE-362 | — |
| [SENT-CRYPTO-01](vulnerability-catalog.md#sent-crypto-01--weak-or-absent-credential-hashing) | Weak or absent credential hashing | A04:2025, A07:2025 | CWE-916, CWE-327, CWE-759, CWE-256 | V6, V11 |
| [SENT-CRYPTO-02](vulnerability-catalog.md#sent-crypto-02--predictable-randomness-in-security-sensitive-values) | Predictable randomness in security-sensitive values | A04:2025 | CWE-330, CWE-338, CWE-340 | V11 |
| [SENT-LOG-01](vulnerability-catalog.md#sent-log-01--no-audit-trail-on-privileged-or-financial-actions) | No audit trail on privileged or financial actions | A09:2025 | CWE-778, CWE-223, CWE-117 | V16 |
| [SENT-LOG-02](vulnerability-catalog.md#sent-log-02--secrets-and-pii-written-to-logs-and-telemetry) | Secrets and PII written to logs and telemetry | A09:2025, A04:2025 | CWE-532, CWE-200 | V16, V14 |
| [SENT-PLAT-01](vulnerability-catalog.md#sent-plat-01--overscoped-platform-permissions-and-privileges) | Overscoped platform permissions and privileges | A06:2025, A02:2025 | CWE-250, CWE-272 | — |
| [SENT-PLAT-02](vulnerability-catalog.md#sent-plat-02--unvalidated-cross-context-messages) | Unvalidated cross-context messages | A01:2025, A06:2025 | CWE-346, CWE-940, CWE-926 | — |
