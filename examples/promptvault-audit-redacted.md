# SENTINEL Audit — PromptVault (Redacted)

> **Redacted & educational.** The vulnerabilities below were **remediated prior to publication**. Secrets
> are placeholders; internal table names, routes, and bucket ids are sanitized (`[sanitized]`) and do not
> reflect the real schema. Findings tagged **`# representative finding`** illustrate a class the
> methodology checks for, modeled on the project's architecture, rather than reproducing exact shipped
> code. This is **not** a current representation of the deployed system. See
> [examples/README.md](README.md).

---

## Executive Summary

- **Scope & stack.** PromptVault — a community platform for discovering and managing AI prompts. Next.js
  14 (App Router) on Vercel; Supabase (Postgres + Auth + Storage) as the backend; public sign-up and
  OAuth; user-generated content (prompts, collections) governed by Postgres Row Level Security. Reviewed:
  the Route Handlers and Server Actions under `app/[sanitized]/`, the Supabase policies for the
  content tables, and the auth callback flow. Client vs server boundary noted throughout.
- **Findings by severity:** **1 Critical · 1 High · 2 Medium · 1 Low.**
- **Highest-impact risk.** A permissive Row Level Security policy on the private-prompts table
  [sanitized] allowed any authenticated user to read other users' *private* prompts by calling the
  Supabase REST endpoint directly — a cross-tenant confidentiality bypass on user content. Remediated by
  replacing the permissive policy with per-command owner-scoped policies.

> **Verified safe (noted to avoid a false positive):** the Supabase **anon** key shipped in the client
> bundle via `NEXT_PUBLIC_SUPABASE_ANON_KEY` is *correct* — that key is public by design and identifies
> the project, not the user. It is only safe **because** RLS is the enforced boundary, which is exactly
> why the Critical below mattered.

## Threat Model Summary

- **Key assets:** users' private prompts and collections; account/profile records; the content-moderation
  and feature-flagging surface; the Supabase `service_role` key (server-only).
- **Entry points:** the public REST/Realtime surface Supabase exposes to the browser (authenticated with
  the public anon key + the user's JWT); Server Actions for creating/editing prompts; the OAuth callback
  route; the public search/browse endpoints.
- **Top prioritized threats (STRIDE, by blast radius):**
  1. **Information disclosure / Elevation (data layer):** can one user read or write another's content by
     calling Postgres directly, bypassing the React app? → drove the RLS review.
  2. **Tampering (mass assignment):** can a user set fields the UI doesn't expose (visibility, authorship,
     moderation state) on a write?
  3. **Spoofing / redirection (auth callback):** can the post-login redirect be pointed off-origin?
  4. **Denial of service:** are the public, unauthenticated browse/search endpoints rate-limited?

---

## Findings (ordered Critical to Low)

### [CRITICAL] - Permissive RLS policy exposes other users' private prompts
**`# representative finding`**

- **Severity:** Critical  |  **Confidence:** High
- **Classification:** OWASP A01:2021 (Broken Access Control) · API1:2023 (BOLA) · CWE-1220, CWE-284 —
  catalog [SENT-AUTHZ-07](../skill/references/vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
- **Location:** Supabase policy on `private_prompts` [sanitized] table
- **Vulnerability Analysis:** RLS was enabled on the table, but the `SELECT` policy was written
  `using (true)` — a placeholder added to stop a "row-level security policy violated" error during
  development and never tightened. Enabled-but-permissive reads as "protected" to a glance, but grants
  every authenticated caller read access to every row. The app's own queries filtered by owner in
  TypeScript, so the UI looked correct; the policy did not enforce it.
- **Attack Scenario:** An authenticated user opens DevTools, copies the public anon key and their JWT, and
  requests another user's private prompts straight from the REST API, omitting the app's owner filter:
  ```
  GET /rest/v1/private_prompts?select=*&id=eq.<OTHER_USERS_ROW>   [sanitized]
  apikey: <ANON_KEY>            # public by design
  Authorization: Bearer <THEIR_OWN_JWT>
  ```
  With `using (true)`, the row is returned. Iterating ids enumerates the private content of the platform.
- **Impact:** Cross-tenant read of all users' private prompts — a confidentiality bypass over the
  platform's core user-generated content. Single authenticated request per row; no other precondition.
- **Remediation:** Replace the permissive policy with explicit, per-command, owner-scoped policies. There
  is no implicit allow — with RLS on and no matching policy, access is denied (fail closed).
  ```sql
  -- ❌ Before
  create policy "select_all" on private_prompts for select using (true);

  -- ✅ After
  alter table private_prompts enable row level security;
  alter table private_prompts force row level security;
  drop policy if exists "select_all" on private_prompts;

  create policy "pp_select_own" on private_prompts for select
    using (auth.uid() = owner_id);
  create policy "pp_insert_own" on private_prompts for insert
    with check (auth.uid() = owner_id);
  create policy "pp_update_own" on private_prompts for update
    using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
  create policy "pp_delete_own" on private_prompts for delete
    using (auth.uid() = owner_id);
  ```
  Verified with the two-account REST test in
  [docs/supabase-rls-guide.md](../docs/supabase-rls-guide.md): user A can no longer read user B's row.

### [HIGH] - Mass assignment on prompt update allows setting non-editable fields
**`# representative finding`**

- **Severity:** High  |  **Confidence:** High
- **Classification:** OWASP A01:2021 · API3:2023 (Broken Object Property Level Authorization) · CWE-915 —
  catalog [SENT-INJ-03](../skill/references/vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
- **Location:** `updatePrompt` Server Action, `app/[sanitized]/actions.ts`
- **Vulnerability Analysis:** The update action spread the client-supplied object into the write
  (`.update({ ...input })`). The edit form only exposes `title` and `body`, but the endpoint accepts any
  column — including `visibility`, `is_featured` [sanitized], and `owner_id`. A user can flip a private
  prompt to public on someone else's behalf (combined with the Critical, before its fix) or set the
  featured flag the moderation team controls.
- **Attack Scenario:** The user replays the Server Action's POST with extra fields:
  ```json
  { "id": "<own_prompt>", "title": "x", "is_featured": true, "visibility": "public" }
  ```
  The extra keys ride the same `...input` spread into the row.
- **Impact:** Users set fields reserved to the product/moderation surface; authorship or visibility
  integrity is broken. Escalates if any settable field grants privilege.
- **Remediation:** Validate against a strict allow-list schema; write only the permitted fields, scoped to
  the owner.
  ```ts
  // ✅ After
  import { z } from 'zod';
  const PromptPatch = z.object({
    title: z.string().min(1).max(120),
    body: z.string().min(1).max(20_000),
  }).strict();                                   // unknown keys rejected

  export async function updatePrompt(raw: unknown) {
    'use server';
    const user = await requireUser();
    const data = PromptPatch.parse(raw);
    const { count } = await supabaseServer
      .from('prompts').update(data)
      .eq('id', promptId).eq('owner_id', user.id); // owner from session, not client
    if (!count) throw new AuthError(404, 'Not found');
  }
  ```
  `visibility` and moderation flags change only through dedicated, separately-authorized actions.

### [MEDIUM] - Open redirect on the OAuth callback `next` parameter
**`# representative finding`**

- **Severity:** Medium  |  **Confidence:** High
- **Classification:** OWASP A01:2021 · CWE-601 (Open Redirect) — catalog
  [SENT-AUTHZ-06](../skill/references/vulnerability-catalog.md#sent-authz-06--auth-redirect--oauth-callback-misconfiguration)
- **Location:** `app/auth/callback/route.ts` [sanitized]
- **Vulnerability Analysis:** After exchanging the OAuth code, the handler redirected to a `next` query
  parameter echoed straight into `redirect()`. It works for the intended in-app path and also accepts an
  absolute off-origin URL.
- **Attack Scenario:** A phishing link sends the victim through the app's own trusted login domain with
  `?next=https://evil.example/looks-like-promptvault`; after a real login they land on the attacker's
  page, lending it the app's credibility. If any token were carried in the redirect it could be
  exfiltrated.
- **Impact:** Trusted-domain redirection usable for phishing/consent abuse. Blast radius limited to social
  attacks here (no token in the URL), hence Medium.
- **Remediation:** Allow only same-origin relative paths.
  ```ts
  // ✅ After
  function safeNext(next: string | null) {
    return next && next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard';
  }
  return NextResponse.redirect(new URL(safeNext(searchParams.get('next')), origin));
  ```

### [MEDIUM] - No rate limit on public browse/search endpoints
**`# representative finding`**

- **Severity:** Medium  |  **Confidence:** Medium
- **Classification:** OWASP A04:2021 · API4:2023 (Unrestricted Resource Consumption) · CWE-770 — catalog
  [SENT-INJ-05](../skill/references/vulnerability-catalog.md#sent-inj-05--missing-rate-limits-on-heavy-or-metered-operations)
- **Location:** `app/api/search/route.ts` [sanitized]
- **Vulnerability Analysis:** The public search endpoint runs an unauthenticated, relatively expensive
  query with no per-IP throttle. Not exploitable for data access, but scriptable into a resource-exhaustion
  / cost-amplification nuisance against the database.
- **Attack Scenario:** A script issues the search in a tight loop with varied terms to bypass any cache,
  driving database load.
- **Impact:** Degraded availability and cost under load; no confidentiality/integrity impact — hence
  Medium/Medium-confidence pending runtime load data.
- **Remediation:** Add a shared-store rate limit keyed by IP (and user id when authenticated), per catalog
  [SENT-INJ-05](../skill/references/remediation-patterns.md#sent-inj-05--per-user-rate-limiting):
  ```ts
  const { success } = await limiter.limit(`search:${ip}`);
  if (!success) return new Response('Too Many Requests', { status: 429 });
  ```

### [LOW] - Floating dependency ranges without a committed audit gate
**`# representative finding`**

- **Severity:** Low  |  **Confidence:** High
- **Classification:** OWASP A06:2021 (Vulnerable and Outdated Components) · CWE-1104 — catalog
  [SENT-SUPPLY-01](../skill/references/vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies)
- **Location:** `package.json`, CI config
- **Vulnerability Analysis:** Security-relevant dependencies used caret ranges and there was no
  `npm audit` gate in CI, so a future transitive advisory could ship unnoticed. Defense-in-depth, not an
  active exploit.
- **Remediation:** Pin security-sensitive deps, keep the lockfile committed, and add the audit + secret
  scan from [`.github/workflows/ci.md`](../.github/workflows/ci.md) (`npm audit --omit=dev
  --audit-level=high`). Enable Dependabot for tracked updates.

---

## Systemic Recommendations

- **Make RLS the enforced boundary everywhere, and test it.** The Critical was a single permissive policy;
  the systemic fix is a standing **cross-tenant authorization test** in CI (two seeded users, each asserts
  it cannot read/write the other's rows across every content table) so a future "quick fix" can't silently
  reopen this class. See the [RLS guide](../docs/supabase-rls-guide.md).
- **Centralize write validation.** Every Server Action that writes user content should go through a
  strict, per-model schema (allow-list) — eliminating mass assignment as a class rather than per-endpoint.
- **A thin Data Access Layer** wrapping Supabase calls, so owner-scoping and validation are enforced in one
  audited place instead of re-derived per handler.
- **Keep the `service_role` key server-only** and assert its absence from the client bundle in CI
  (secret scan). Confirmed absent in this review.
- **Wire secret-scanning + dependency audit into CI** as the automated floor (addresses the Low and future
  regressions).

## Residual Risk and Verification Constraints

- This was a **static source and policy review**. It did not include a live penetration test, a load test
  (the search rate-limit severity is pending real traffic data), or a review of Vercel project
  environment configuration and secret storage.
- RLS findings were verified against the policy definitions and the two-account REST test in a
  non-production environment; production policy parity should be confirmed on deploy.
- Realtime subscriptions, database views, and any `SECURITY DEFINER` functions were noted but not
  exhaustively enumerated — they can bypass base-table policies and warrant their own pass.
- Third-party OAuth provider configuration (allowed redirect URLs at the provider) is environment-level and
  outside a code review; confirm it independently.
