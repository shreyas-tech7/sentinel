# The Supabase RLS Guide

Row Level Security is the single highest-impact control in a Supabase app, and a disabled or permissive
RLS policy is the most common serious flaw SENTINEL finds in vibe-coded apps. This is a standalone deep
dive: why database-layer authorization beats app-layer, the misconfigurations that recur, how to *test*
that a policy actually blocks cross-tenant reads, and the correct patterns. It stands on its own — you
don't need the rest of SENTINEL to use it — but it maps to catalog entry
[SENT-AUTHZ-07](../skill/references/vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
and remediation
[SENT-AUTHZ-07](../skill/references/remediation-patterns.md#sent-authz-07--enable-rls-and-write-an-owner-scoped-policy).

## Why the database is the authorization boundary

In a traditional app, the browser talks to your server, and your server talks to the database over a
private connection. Authorization lives in the server, and the database trusts it.

Supabase inverts this. **The browser talks to the database directly**, over a public REST/Realtime API,
authenticated with a key that ships in your client bundle:

```
  Traditional:   Browser ──▶ Your server (authz here) ──▶ Database (trusts the server)

  Supabase:      Browser ──▶ Supabase API / Postgres  (authz MUST be here)
                    │
                    └── carries the public "anon" key + the user's JWT
```

The `anon` (publishable) key is **public by design** — it identifies the *project*, not the *user*.
Anyone can open DevTools, copy it, and issue their own requests against your tables and storage,
completely bypassing your React app and any check written in TypeScript. So the only place an
authorization check can actually stop a hostile request is *inside the database*, evaluated on every
query. That mechanism is Row Level Security.

**Corollary that trips people up:** a filter in your app code is not a control.

```ts
// This looks like it scopes the query to the current user. It does not.
const { data } = await supabase.from('notes').select('*').eq('user_id', session.user.id);
```

An attacker doesn't run your code. They call
`GET /rest/v1/notes?select=*` with the anon key and no filter, and if there's no policy, they get every
row. The `.eq(...)` only shapes *your* honest request. Ownership must be enforced by a policy the database
applies regardless of what the client asks for.

## How RLS evaluates (the mental model)

- With `alter table t enable row level security;`, Postgres denies all access to `t` **by default** —
  fail closed. Access is only granted by a policy that returns true.
- A policy has a `USING` expression (which existing rows are *visible* to reads/updates/deletes) and,
  for writes, a `WITH CHECK` expression (which new/modified rows are *allowed*).
- Inside a policy you have `auth.uid()` (the authenticated user's id from their JWT) and `auth.jwt()`
  (the full claims). These are how a policy knows who is asking.
- Policies are **per-command**. A `SELECT` policy does nothing for `INSERT`. You need policies for every
  command a client can perform.
- The `service_role` key **bypasses RLS entirely**. It is a server-only secret; if it reaches the client
  the whole model collapses (catalog
  [SENT-SECRET-01](../skill/references/vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)).

## The misconfigurations that recur

### 1. RLS disabled on a client-reachable table
The default failure. The table works from day one because `anon` can already read it, so nobody enables
RLS. The app behaves identically whether the table is protected or wide open — which is exactly why the
gap is invisible until someone queries the REST endpoint directly.

### 2. `USING (true)` — RLS "on," everyone allowed
Often added to silence an error ("row-level security policy violated") without understanding it. RLS is
technically enabled, so a naive check passes, but the policy grants everyone everything.

```sql
-- Looks protected. Is not.
create policy p on notes for select using (true);
```

### 3. A read policy but no write policy (or vice versa)
A `SELECT` policy scopes reads correctly, but there's no `INSERT`/`UPDATE`/`DELETE` policy — so either
writes are denied entirely (the app breaks and someone "fixes" it with `using (true)`), or a broad
`FOR ALL` policy was used that doesn't actually check `with check` on writes, letting a user write rows
they shouldn't (including reassigning `user_id`).

### 4. Ownership enforced only in TypeScript
Covered above: `.eq('user_id', me)` with no matching policy. The most common *silent* case, because the
app looks correct in review.

### 5. Trusting `user_metadata` for roles
`auth.jwt() -> 'user_metadata'` is **user-editable** — a user can update their own `user_metadata`
through the auth API. A policy or check that grants admin based on it is bypassable. Use `app_metadata`
(server-controlled) or, better, a `profiles.role` column that only the server can write.

```sql
-- ❌ user_metadata is user-editable — this is a privilege-escalation policy.
create policy admin_all on secrets for all
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
```

### 6. Views, `SECURITY DEFINER` functions, and Realtime that bypass policy
A view runs with the privileges of its owner unless created with `security_invoker = true`, so it can
expose rows the base-table policy would block. A `SECURITY DEFINER` function likewise runs as its
definer. Realtime subscriptions and Storage objects need their own policies. Each is a side door around
the table policy.

### 7. Public Storage buckets for private files
Storage is governed by policies on `storage.objects`. A bucket left public for avatars, then reused for
documents, leaks those documents by guessable URL (catalog
[SENT-SECRET-03](../skill/references/vulnerability-catalog.md#sent-secret-03--public-storage-buckets--default-open-configuration)).

## The correct pattern: enable, force, one policy per command

```sql
alter table documents enable row level security;
alter table documents force row level security;   -- enforce even for the table owner role

create policy "documents_select_own" on documents for select
  using (auth.uid() = owner_id);

create policy "documents_insert_own" on documents for insert
  with check (auth.uid() = owner_id);             -- the NEW row must be owned by the caller

create policy "documents_update_own" on documents for update
  using (auth.uid() = owner_id)                    -- may only target your rows
  with check (auth.uid() = owner_id);              -- and may not reassign ownership away

create policy "documents_delete_own" on documents for delete
  using (auth.uid() = owner_id);
```

For a shared-tenant model, replace `auth.uid() = owner_id` with membership in the row's tenant, resolved
through a server-controlled table:

```sql
create policy "docs_select_tenant" on documents for select
  using (exists (
    select 1 from memberships m
    where m.tenant_id = documents.tenant_id and m.user_id = auth.uid()
  ));
```

Index the columns your policies filter on (`owner_id`, `tenant_id`) — every query now carries the policy
predicate, so an unindexed one is a performance cliff.

## How to test that a policy actually blocks cross-tenant reads

Reasoning about a policy is not the same as proving it. Test it. Two reliable methods:

### Method A — the two-account REST test (closest to a real attacker)
1. Create users **A** and **B**, each with a row only they should see.
2. Sign in as **A** and capture: the project's `anon` key and A's `access_token` (JWT).
3. Query **B's** row directly against the REST API as A:

```bash
curl "https://<project>.supabase.co/rest/v1/documents?id=eq.<B_ROW_ID>&select=*" \
  -H "apikey: <ANON_KEY>" \
  -H "Authorization: Bearer <A_ACCESS_TOKEN>"
```

A correct policy returns `[]`. Any row in the response is a **Critical** cross-tenant leak. Repeat for
writes (`POST`/`PATCH`/`DELETE` against B's row) — reads passing does not mean writes are scoped.

### Method B — simulate a user inside SQL
In the SQL editor you can impersonate a role and a JWT claim set to see what a policy permits, without
leaving the database:

```sql
-- Act as the authenticated role with A's uid, then try to read B's rows.
set local role authenticated;
select set_config('request.jwt.claims', json_build_object('sub', '<A_USER_ID>')::text, true);

select count(*) from documents where owner_id = '<B_USER_ID>';  -- expect 0
reset role;
```

Expect `0`. A non-zero count means the policy does not isolate tenants.

### Automate it
Turn the two-account test into a CI check: a small test that signs in as two seeded users and asserts
each cannot read or write the other's rows. Cross-tenant authorization tests are the regression net that
keeps a future "quick fix" from silently reopening the hole. This is a standing SENTINEL *Systemic
Recommendation*.

## Also run the built-in advisor

Supabase's **Security Advisor** (dashboard, and via the API/MCP `get_advisors` with `type: "security"`)
flags tables with RLS disabled and other misconfigurations. It's a fast first sweep — but it detects
*disabled* RLS, not *permissive* policies, so it complements, and does not replace, the two-account test
above.

## The one-paragraph version

The Supabase client key is public, so the browser is effectively talking straight to your database.
That makes the database — not your app code — the authorization boundary. Enable RLS on every
client-reachable table, write an explicit owner- or tenant-scoped policy for every command (with
`WITH CHECK` on writes so ownership can't be reassigned), never trust `user_metadata` for roles, keep the
`service_role` key server-only, and prove isolation with a two-account cross-tenant test wired into CI.
Everything else is detail.
