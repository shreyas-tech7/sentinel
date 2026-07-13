# Supabase (Postgres + Auth + Storage)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
The database is a public API. The client talks to Postgres directly with a key that ships to the
browser, so **Row Level Security is the authorization layer** — not your TypeScript.

## Trust model
- The **`anon` (publishable) key is public** by design. It is embedded in the client bundle and
  identifies the *project*, not the *user*. Anyone can extract it and call your database and Storage
  REST endpoints directly, bypassing your React app entirely.
- The authenticated user is identified by a **JWT** Supabase issues; inside Postgres its claims are
  reachable via `auth.uid()` and `auth.jwt()`. RLS policies are the only thing that turns "any holder
  of the anon key" into "only this user's rows."
- The **`service_role` key bypasses RLS completely.** It is a server-only secret. If it ever reaches
  the client — via `NEXT_PUBLIC_`, a serialized prop, or a bundle-imported module — the entire
  database is readable and writable by anyone. Treat its exposure as Critical (see
  [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)).

## Top traps
1. **RLS disabled on a client-reachable table.** The flagship failure. The app works because `anon` can
   read the table; nobody notices there is no policy. → [SENT-AUTHZ-07](../vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
2. **Permissive policy.** `using (true)` or a `SELECT` policy with no matching `INSERT/UPDATE/DELETE`
   policy — RLS is "on" but grants everyone everything, or protects reads while leaving writes open. →
   [SENT-AUTHZ-07](../vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
3. **Client-side filter mistaken for a control.** `.eq('user_id', session.user.id)` in TypeScript looks
   like it scopes the query. It does not: an attacker calls the REST endpoint directly and omits the
   filter. Ownership must live in a policy. → [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
4. **`service_role` on the client**, or used in an API route to "simplify" things, silently disabling
   RLS for that path. → [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
5. **Trusting `user_metadata` for authorization.** `user_metadata` is user-editable; only
   `app_metadata` (or a server-controlled table) is safe for roles. A policy or check keyed off
   `user_metadata.role` is bypassable. → [SENT-AUTHZ-05](../vulnerability-catalog.md#sent-authz-05--insecure-session-and-claims-handling)
6. **Public Storage buckets for private files.** A bucket left public so avatars "just work," then
   reused for documents. Object URLs are guessable. → [SENT-SECRET-03](../vulnerability-catalog.md#sent-secret-03--public-storage-buckets--default-open-configuration)
7. **Realtime / views / RPC bypassing policy.** Realtime subscriptions, `security definer` functions,
   and views can leak rows that the base-table policy would have blocked. Views run as their owner
   unless `security_invoker` is set.
8. **Embeddings table without RLS** in RAG apps — cross-tenant vector retrieval. →
   [SENT-LLM-06](../vulnerability-catalog.md#sent-llm-06--rag-poisoning-and-non-row-scoped-vector-stores)

## How to test
- **Enumerate unprotected tables.** In the dashboard, use the **Security Advisor** (it flags tables
  with RLS disabled). Or query it:
  ```sql
  select relname
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity = false;
  ```
  Any client-reachable table in that list is a finding.
- **List permissive policies.** `select * from pg_policies where schemaname = 'public';` — inspect every
  `qual`/`with_check` for `true` or a missing command.
- **Prove cross-tenant isolation with two accounts.** Sign in as user A, capture the `anon` key and A's
  JWT, then call the REST endpoint for a row owned by user B directly (curl against
  `/rest/v1/<table>?id=eq.<B_row>`). A correct policy returns empty; a broken one returns B's row. This
  is the definitive test — see [../../../docs/supabase-rls-guide.md](../../../docs/supabase-rls-guide.md).
- **Grep the client bundle** for the service-role key shape and for `service_role` / `SERVICE_ROLE`
  anywhere a client component can import.
