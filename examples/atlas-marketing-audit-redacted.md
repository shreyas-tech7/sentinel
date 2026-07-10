# SENTINEL Audit — Atlas Marketing Site (Redacted)

> **Redacted & educational.** The findings below were **remediated prior to publication**. Any secrets are
> placeholders; third-party service names and embed sources are sanitized (`[sanitized]`) where needed.
> Findings tagged **`# representative finding`** illustrate a class the methodology checks for; untagged
> findings reflect the real, since-remediated issue. This is **not** a current representation of the
> deployed system. See [examples/README.md](README.md).

---

## Executive Summary

- **Scope & stack.** Atlas — an agency marketing site. Near-static: Next.js 14 on Vercel, no database and
  no application secrets of its own, a contact/lead form that posts to **Formspree**, and a few
  third-party embeds (video and a booking widget) via iframes. This is the "small attack surface, still
  worth auditing" case. Reviewed: `next.config.mjs`, the form component and its submission path, the
  embed configuration, and dependency hygiene.
- **Findings by severity:** **0 Critical · 0 High · 1 Medium · 3 Low.**
- **Highest-impact risk.** The site shipped **without security response headers** (no HSTS, no
  `X-Content-Type-Options`, no framing/`Referrer-Policy` controls), leaving it more exposed to clickjacking,
  MIME-sniffing, and downgrade than a conservative header set would. Remediated by adding a header set in
  `next.config.mjs`. The audit's real value here was confirming what is *not* wrong: no data layer to leak,
  no secrets in the bundle, and the form's trust boundary correctly offloaded.

## Threat Model Summary

- **Key assets:** the site's integrity and reputation (defacement/clickjacking), and the contact-form
  submissions (routed to a third party). There is no first-party database, auth, or secret store.
- **Entry points:** the public contact form (client → Formspree); the third-party iframe embeds
  (external origin → the page); the build/dependency supply chain.
- **Top prioritized threats (STRIDE, by blast radius):**
  1. **Tampering / UI-redress:** can the site be framed for clickjacking, or content-type-confused? →
     drove the headers review.
  2. **Spoofing / abuse (form):** where does form data go, and can the endpoint be abused for spam?
  3. **Supply chain:** are build dependencies pinned and audited?
  4. **Information disclosure:** anything sensitive in the client bundle? (None found.)

---

## Findings (ordered Critical to Low)

### [MEDIUM] - Missing security response headers

- **Severity:** Medium  |  **Confidence:** High
- **Classification:** OWASP A05:2021 (Security Misconfiguration) · CWE-693 (Protection Mechanism Failure),
  CWE-1021 (clickjacking) — catalog
  [SENT-SECRET-02](../skill/references/vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
- **Location:** `next.config.mjs` (no `headers()` export)
- **Vulnerability Analysis:** The app served no security headers. Without `X-Frame-Options` /
  frame-ancestors the page can be framed for clickjacking; without `X-Content-Type-Options: nosniff`
  browsers may MIME-sniff responses; without `Strict-Transport-Security` a first-request downgrade is
  possible. Low complexity to exploit, limited blast radius on a static site — hence Medium.
- **Attack Scenario:** An attacker frames the site inside a transparent overlay on a look-alike page to
  trick a visitor into clicking the booking/contact controls (clickjacking), or leverages MIME-sniffing on
  a served asset.
- **Impact:** UI-redress against visitors and reduced transport/anti-sniffing hardening. No data exposure
  (there is none to expose).
- **Remediation:** Add a conservative header set. **Note the deliberate omission of a strict CSP** here:
  the site embeds third-party video and a booking widget via iframes, and a naive CSP would break them; a
  header set without CSP was chosen so `frame-src`/embed compatibility is preserved. A properly-scoped CSP
  (allow-listing the specific embed origins and using `frame-ancestors 'self'`) is the stronger follow-up.
  ```js
  // ✅ next.config.mjs
  const securityHeaders = [
    { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
    { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
    { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  ];
  export default {
    async headers() { return [{ source: '/:path*', headers: securityHeaders }]; },
  };
  ```

### [LOW] - Contact form relies on the third party for all validation and abuse control
**`# representative finding`**

- **Severity:** Low  |  **Confidence:** Medium
- **Classification:** OWASP A04:2021 (Insecure Design) · CWE-770 — catalog
  [SENT-INJ-05](../skill/references/vulnerability-catalog.md#sent-inj-05--missing-rate-limits-on-heavy-or-metered-operations)
- **Location:** contact form component `components/Contact[sanitized].tsx`
- **Vulnerability Analysis:** The form posts directly to Formspree [sanitized] from the client. Offloading
  submissions to a managed provider is a *correct* trust decision (there's no first-party backend to
  attack, and Formspree is the receiving trust boundary). The residual gap is that there is no client-side
  spam mitigation (honeypot/CAPTCHA), so the public endpoint can be scripted for spam within the provider's
  limits.
- **Attack Scenario:** A bot submits the form repeatedly, filling the provider inbox/quota.
- **Impact:** Spam / inbox-quota nuisance. No data or integrity impact — the boundary is the provider's.
- **Remediation:** Enable the provider's spam protections (honeypot field / CAPTCHA / reCAPTCHA) and any
  per-form rate limit the provider offers. Confirm the provider endpoint id [sanitized] isn't reused across
  sites in a way that leaks submissions.

### [LOW] - Third-party iframe embeds without an explicit frame policy
**`# representative finding`**

- **Severity:** Low  |  **Confidence:** Medium
- **Classification:** OWASP A05:2021 · CWE-1021 — catalog
  [SENT-SECRET-02](../skill/references/vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
- **Location:** embed blocks (video + booking widget) [sanitized]
- **Vulnerability Analysis:** The page embeds third-party content via iframes. The embeds are from
  expected providers, but there was no explicit allow-list (`frame-src` in a CSP) constraining what may be
  framed, and the `iframe` elements lacked `sandbox`/`referrerpolicy` attributes. Low risk given trusted
  sources, but an unconstrained embed policy is looser than necessary.
- **Remediation:** Add `referrerpolicy="no-referrer"` and a minimal `sandbox` to the iframes, and, when a
  scoped CSP is introduced (see the Medium), allow-list only the specific embed origins in `frame-src`.

### [LOW] - Dependencies not pinned; no audit gate in CI
**`# representative finding`**

- **Severity:** Low  |  **Confidence:** High
- **Classification:** OWASP A06:2021 (Vulnerable and Outdated Components) · CWE-1104 — catalog
  [SENT-SUPPLY-01](../skill/references/vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies)
- **Location:** `package.json`, CI config
- **Vulnerability Analysis:** Even a static site ships a build toolchain. Ranges were floating and there was
  no `npm audit` / secret-scan gate, so a future advisory in a transitive build dependency could go
  unnoticed. Pure defense-in-depth.
- **Remediation:** Commit the lockfile, and add the secret-scan + `npm audit --omit=dev --audit-level=high`
  workflow from [`.github/workflows/ci.md`](../.github/workflows/ci.md).

---

## Systemic Recommendations

- **Adopt a scoped CSP** as the natural next step: allow-list the specific embed origins in `frame-src`,
  set `frame-ancestors 'self'`, and keep the header set from the Medium finding. This closes the clickjacking
  and embed-policy items together without breaking the video/booking embeds.
- **Push validation and abuse control to the boundary that owns the data** — here, the form provider.
  Enable its spam controls rather than adding a first-party backend the site otherwise doesn't need.
- **Add the CI floor** (secret scan + dependency audit) even for static sites; it's cheap and catches the
  supply-chain and accidental-secret classes.
- **Re-audit if the surface grows.** The moment this site gains a database, auth, or a server-side API, the
  threat model changes categorically and warrants a full review — not the light pass a static site needs.

## Residual Risk and Verification Constraints

- Static review of a near-static site. It did not assess Vercel project configuration, DNS/TLS setup, or the
  security posture of the third-party form and embed providers themselves (their handling of submitted data
  is outside this code review — confirm their policies independently).
- The absence of a first-party data layer and application secrets was verified against the codebase; if any
  server-side function or environment secret is added later, that assumption no longer holds.
- Clickjacking/embed severity assumes the current trusted embed sources; introducing a new or user-supplied
  embed source would require re-rating.
