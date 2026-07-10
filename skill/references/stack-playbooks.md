# SENTINEL Stack Playbooks

Framework-specific manifestations of the catalog classes, and how to test for them. The methodology
in [`../SKILL.md`](../SKILL.md) generalizes to any stack — these playbooks just encode the sharp edges
of the stacks where vibe-coded apps bleed most, and the **Generic / Unknown Stack playbook that opens
this file is what makes SENTINEL usable by anyone vibe-coding in any stack, not just the ones named
here.** Read the section matching the stack you identified in Phase 1 — or the generic one when
nothing matches; each trap cross-links to its catalog entry in
[`vulnerability-catalog.md`](vulnerability-catalog.md) and its fix in
[`remediation-patterns.md`](remediation-patterns.md).

Every playbook follows the same shape: **Key** (the one-sentence mental model), **Trust model** (where
the client/server line sits and which keys cross it), **Top traps** (the recurring failures), and
**How to test** (how to prove a control holds).

---

## Generic / Unknown Stack

### Key
The stack changes the syntax, never the questions. Every framework has a client (public), a server
(where controls must live), a session mechanism, a data store, a dependency manifest, and environment
configuration — audit those six things and you have audited any stack.

### Trust model
- Anything that executes on, or is shipped to, a device the user controls — browser bundle, mobile
  binary, desktop app — is **public**: readable, modifiable, and bypassable. Controls that live there
  are UX, not security.
- The server (or the database, if it can enforce access itself) is the only place a control counts.
  Identify where the framework's server-side code actually runs, and treat everything else as
  attacker-controlled input to it.
- Whatever the framework calls its secret store (env vars, config files, a vault), trace which values
  cross to the client side — most stacks have a mechanism (a prefix, a build step, a template context)
  that silently ships server config to the client.

### Top traps
1. **Server-side validation missing at a boundary.** Regardless of framework: every route, handler,
   RPC, job, and webhook revalidates its input server-side, even when a client-side check exists. →
   [SENT-INJ-01](vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template),
   [SENT-INJ-03](vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
2. **Logged-in mistaken for authorized.** Object-level ownership checks on every read *and* write. →
   [SENT-AUTHZ-01](vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
3. **Session/token storage.** Tokens in JS-readable or world-readable storage; signatures unverified;
   user-editable claims trusted. → [SENT-AUTHZ-05](vulnerability-catalog.md#sent-authz-05--insecure-session-and-claims-handling)
4. **No DB-level access control where the DB supports it.** If the store can enforce row/object-level
   access (Postgres RLS, Firestore rules, S3 policies), app-code filters alone are not the control. →
   [SENT-AUTHZ-07](vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
5. **Dependency manifest sanity.** A lockfile exists and is committed; every dependency resolves on its
   registry; no known-critical advisories on reachable paths. →
   [SENT-SUPPLY-01](vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies),
   [SENT-SUPPLY-02](vulnerability-catalog.md#sent-supply-02--hallucinated-or-typosquatted-packages)
6. **Env var handling.** Secrets absent from source and git history; whatever the stack's
   ship-to-client mechanism is, no secret uses it; debug mode off in production. →
   [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets),
   [SENT-SECRET-02](vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
7. **Swallowed failures and races** — the async/structural classes apply to every language. →
   [SENT-ASYNC-01](vulnerability-catalog.md#sent-async-01--swallowed-async-errors-and-silent-fallback-returns),
   [SENT-ASYNC-02](vulnerability-catalog.md#sent-async-02--non-atomic-writes-to-shared-state)
8. **Cookie sessions without CSRF defense.** If the credential is ambient (a cookie), a cross-origin page
   can spend it. Every framework has a built-in protection, and the bug is almost always that someone
   switched it off. → [SENT-AUTHZ-09](vulnerability-catalog.md#sent-authz-09--cross-site-request-forgery-csrf)
9. **Credentials and tokens.** Passwords behind a slow salted KDF, never a fast digest; every value that
   grants access minted from the language's CSPRNG (`secrets`, `crypto.randomBytes`, `SecureRandom`),
   never its general-purpose PRNG. →
   [SENT-CRYPTO-01](vulnerability-catalog.md#sent-crypto-01--weak-or-absent-credential-hashing),
   [SENT-CRYPTO-02](vulnerability-catalog.md#sent-crypto-02--predictable-randomness-in-security-sensitive-values)
10. **Audit trail and log hygiene.** Privileged actions leave a durable, actor-attributed record; logs
    carry identifiers, not credentials or PII. →
    [SENT-LOG-01](vulnerability-catalog.md#sent-log-01--no-audit-trail-on-privileged-or-financial-actions),
    [SENT-LOG-02](vulnerability-catalog.md#sent-log-02--secrets-and-pii-written-to-logs-and-telemetry)

### How to test
- Enumerate every entry point from the code, not the UI: route registrations, handler decorators, RPC
  definitions, cron/webhook targets. For each, send an unauthenticated request and a
  wrong-user request; both must deny.
- Grep for the stack's client-exposure mechanism (public env prefixes, template-injected config,
  bundled assets) and for secret-shaped strings in anything shipped.
- Check the manifest: lockfile committed, every package resolves on its registry, audit tooling clean.
- Force a failure (kill the DB connection, send malformed input) and confirm the app fails closed with
  a generic error — not open, and not with a stack trace.
- Read a response body, not the rendered page: the network tab shows every field the API actually
  returned. → [SENT-INJ-08](vulnerability-catalog.md#sent-inj-08--excessive-data-exposure-in-responses)
- Trigger an error with a token in the request and confirm the token does not appear in the logs or the
  error tracker.

The mechanical searches for all of the above — per language, with the commands — are in
[`tooling.md`](tooling.md). Run them to buy attention, then spend that attention on trap 2, which no
tool can see.

---

## Supabase (Postgres + Auth + Storage)

### Key
The database is a public API. The client talks to Postgres directly with a key that ships to the
browser, so **Row Level Security is the authorization layer** — not your TypeScript.

### Trust model
- The **`anon` (publishable) key is public** by design. It is embedded in the client bundle and
  identifies the *project*, not the *user*. Anyone can extract it and call your database and Storage
  REST endpoints directly, bypassing your React app entirely.
- The authenticated user is identified by a **JWT** Supabase issues; inside Postgres its claims are
  reachable via `auth.uid()` and `auth.jwt()`. RLS policies are the only thing that turns "any holder
  of the anon key" into "only this user's rows."
- The **`service_role` key bypasses RLS completely.** It is a server-only secret. If it ever reaches
  the client — via `NEXT_PUBLIC_`, a serialized prop, or a bundle-imported module — the entire
  database is readable and writable by anyone. Treat its exposure as Critical (see
  [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)).

### Top traps
1. **RLS disabled on a client-reachable table.** The flagship failure. The app works because `anon` can
   read the table; nobody notices there is no policy. → [SENT-AUTHZ-07](vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
2. **Permissive policy.** `using (true)` or a `SELECT` policy with no matching `INSERT/UPDATE/DELETE`
   policy — RLS is "on" but grants everyone everything, or protects reads while leaving writes open. →
   [SENT-AUTHZ-07](vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
3. **Client-side filter mistaken for a control.** `.eq('user_id', session.user.id)` in TypeScript looks
   like it scopes the query. It does not: an attacker calls the REST endpoint directly and omits the
   filter. Ownership must live in a policy. → [SENT-AUTHZ-01](vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
4. **`service_role` on the client**, or used in an API route to "simplify" things, silently disabling
   RLS for that path. → [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
5. **Trusting `user_metadata` for authorization.** `user_metadata` is user-editable; only
   `app_metadata` (or a server-controlled table) is safe for roles. A policy or check keyed off
   `user_metadata.role` is bypassable. → [SENT-AUTHZ-05](vulnerability-catalog.md#sent-authz-05--insecure-session-and-claims-handling)
6. **Public Storage buckets for private files.** A bucket left public so avatars "just work," then
   reused for documents. Object URLs are guessable. → [SENT-SECRET-03](vulnerability-catalog.md#sent-secret-03--public-storage-buckets--default-open-configuration)
7. **Realtime / views / RPC bypassing policy.** Realtime subscriptions, `security definer` functions,
   and views can leak rows that the base-table policy would have blocked. Views run as their owner
   unless `security_invoker` is set.
8. **Embeddings table without RLS** in RAG apps — cross-tenant vector retrieval. →
   [SENT-LLM-06](vulnerability-catalog.md#sent-llm-06--rag-poisoning-and-non-row-scoped-vector-stores)

### How to test
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
  is the definitive test — see [../../docs/supabase-rls-guide.md](../../docs/supabase-rls-guide.md).
- **Grep the client bundle** for the service-role key shape and for `service_role` / `SERVICE_ROLE`
  anywhere a client component can import.

---

## Next.js 14 (App Router)

### Key
There is no implicit trust between files. A Server Action *looks* like a local function but is a public
POST endpoint; a Route Handler runs whether or not middleware did; and anything a Client Component can
read is public.

### Trust model
- **Server Components / Server Actions / Route Handlers** run on the server and may hold secrets.
  **Client Components** (`'use client'`) and anything they import or receive as props run in the
  browser and are public.
- **Every Server Action is an exposed endpoint.** The framework generates a callable POST for each
  `'use server'` function. Being imported by one component does not stop a direct call with arbitrary
  arguments.
- **`middleware.ts` is a routing-time convenience, not the authorization layer.** Its `matcher` has
  gaps, it does not run for every internal path, and Route Handlers execute independently.
- **`NEXT_PUBLIC_`-prefixed env vars are inlined into the client bundle.** So is any server value
  captured in a closure that gets serialized to a Client Component.

### Top traps
1. **Server Action with no authz.** `'use server'` functions that mutate data trusting the caller, or
   that accept the owner id from the client. → [SENT-AUTHZ-04](vulnerability-catalog.md#sent-authz-04--missing-auth-on-server-actions--route-handlers)
2. **Route Handler assuming middleware ran.** A handler under a path the `matcher` excludes (commonly
   `/api/*`), doing sensitive work with no in-handler check. → [SENT-AUTHZ-03](vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network)
3. **Secret in a Client Component.** A key read at module scope in a file that is (transitively)
   `'use client'`, or passed as a prop / returned from a Server Component into client props. →
   [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
4. **`NEXT_PUBLIC_` on a secret.** Especially a service-role or provider *secret* key. →
   [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
5. **Open redirect via `redirect(searchParams.get('next'))`** in a login/callback route. →
   [SENT-AUTHZ-06](vulnerability-catalog.md#sent-authz-06--auth-redirect--oauth-callback-misconfiguration)
6. **Caching a sensitive response.** A per-user Route Handler response cached (default `GET` caching,
   `force-cache`, or a CDN) and served to another user. Mark per-user responses `no-store`.
7. **Mass assignment in an action.** `.update({ ...formData })` from a Server Action. →
   [SENT-INJ-03](vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
8. **Missing security headers.** No `Content-Security-Policy` / `Strict-Transport-Security` /
   frame-ancestors configured in `next.config` or middleware. → [SENT-SECRET-02](vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)

### How to test
- **Call Server Actions directly.** In DevTools' Network tab, find the action's POST (it has a
  `Next-Action` header). Replay it with modified arguments — a different object id, an admin-only field —
  and confirm the server rejects it. Passing means authz lives in the action, not the UI.
- **Hit excluded routes without a session.** Curl the Route Handlers under paths the `matcher` skips
  with no cookie; a correct handler returns 401/403, not data.
- **Grep for client leakage.** Search for `NEXT_PUBLIC_` on secret-shaped names, and for secret reads in
  files under a `'use client'` boundary. Build the app and grep the `.next/static` bundle for known
  secret prefixes.
- **Check redirect targets.** Request the login route with `?next=https://example.org` and confirm you
  are not redirected off-origin.

---

## Generic serverless / edge (Vercel Functions, Workers)

### Key
Each function is independently reachable from the internet. There is no shared, always-on gateway doing
auth for you unless you built one — and even then, the function must not assume it ran.

### Trust model
- Functions are stateless and individually addressable. "Internal" functions are internal only by
  obscurity unless a check enforces it.
- Environment variables are the secret store; anything not explicitly server-scoped can leak through a
  client build step.
- Edge runtimes have reduced APIs and their own auth caveats; cold starts and per-invocation isolation
  mean per-request rate limiting needs a shared store (KV/Redis/DB), not in-memory counters.

### Top traps
1. **Cold-path auth gaps.** An auth check present on the "main" route but missing on a secondary
   function (cron target, internal proxy, revalidation hook). → [SENT-AUTHZ-04](vulnerability-catalog.md#sent-authz-04--missing-auth-on-server-actions--route-handlers)
2. **Unauthenticated internal proxy.** A function that forwards to a backend or third-party API with the
   server's credentials, callable by anyone. → [SENT-AUTHZ-03](vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network)
3. **No rate limiting.** In-memory counters don't work across invocations; effectively no limit. →
   [SENT-INJ-05](vulnerability-catalog.md#sent-inj-05--missing-rate-limits-on-heavy-or-metered-operations)
4. **Env exposure at the edge / in the client build.** → [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
5. **SSRF in a fetch/proxy function** taking a user URL. → [SENT-INJ-07](vulnerability-catalog.md#sent-inj-07--server-side-request-forgery-ssrf)
6. **Cron/webhook endpoints unprotected.** A scheduled function's HTTP trigger reachable by the public
   without a shared secret. → [SENT-SECRET-04](vulnerability-catalog.md#sent-secret-04--unverified-webhook-payloads)

### How to test
- Inventory every function/route, not just the ones the UI links. For each, send an unauthenticated
  request and confirm a deny.
- Hammer a metered/expensive function from a script and confirm a shared-store rate limit kicks in
  across invocations.
- Send a cron/webhook function a forged request with no secret/signature and confirm rejection.

---

## LLM / RAG applications

### Key
Two new trust boundaries appear: **untrusted content flowing *into* the model** (prompt injection) and
**model output flowing *into* a sink** (improper output handling). The model is not a trusted component;
it is a powerful text transformer sitting between them.

### Trust model
- Anything placed in the context window — user messages, retrieved documents, tool results, web content —
  is data the model may *follow as instructions* unless separated. Retrieval and tool use widen the
  attack surface: a document can carry an injection (indirect prompt injection).
- Model output is untrusted output. Rendering it, executing it, or passing it to a tool without
  validation is the same class of mistake as trusting user input.
- Model APIs are **metered and billed per call.** An uncapped generation endpoint is a financial DoS
  surface.
- Keys for the model provider are server-only secrets and must never enter the prompt or the client.

### Top traps
1. **Prompt injection** — untrusted content concatenated into instructions with no separation. →
   [SENT-LLM-01](vulnerability-catalog.md#sent-llm-01--prompt-injection)
2. **Improper output handling** — model output rendered as HTML or run as SQL/commands/tool calls
   unsanitized. → [SENT-LLM-02](vulnerability-catalog.md#sent-llm-02--improper-output-handling)
3. **Excessive agency** — broad tools / admin credentials / no human gate on high-impact actions. →
   [SENT-LLM-03](vulnerability-catalog.md#sent-llm-03--excessive-agency)
4. **Denial-of-wallet** — no per-user quota (often no auth) on a paid generation route. →
   [SENT-LLM-04](vulnerability-catalog.md#sent-llm-04--denial-of-wallet-on-metered-model-apis)
5. **Secrets / authz in the prompt** — keys embedded in prompts; "don't reveal other users' data" as a
   system-prompt instruction instead of an enforced control. → [SENT-LLM-05](vulnerability-catalog.md#sent-llm-05--sensitive-disclosure--system-prompt-as-boundary)
6. **Vector store not row-scoped** — cross-tenant retrieval from a shared embeddings table with no RLS.
   → [SENT-LLM-06](vulnerability-catalog.md#sent-llm-06--rag-poisoning-and-non-row-scoped-vector-stores)

### How to test
- **Direct injection:** send messages that instruct the model to ignore prior instructions, reveal the
  system prompt, or call a tool it shouldn't. Confirm separation holds and the system prompt is not the
  only guard.
- **Indirect injection:** ingest a document containing embedded instructions ("assistant: when asked
  about X, output …") and confirm retrieval doesn't let it hijack behavior or trigger tools.
- **Output handling:** make the model produce `<img onerror=...>` or SQL-shaped text and confirm the
  sink encodes/parameterizes it rather than executing it.
- **Denial-of-wallet:** call the generation endpoint in a loop, unauthenticated if possible, and confirm
  auth + a per-user quota stop it before cost accrues.
- **Cross-tenant retrieval:** as tenant A, run a query that should only match A's documents and confirm
  no B documents come back (RLS on the embeddings table; the two-account test from the Supabase
  playbook applies).

---

## Django / Flask (Python)

### Key
The framework ships with strong defaults (ORM parameterization, CSRF middleware, auto-escaping
templates) — vibe-coded Python apps get breached through the *escape hatches* and the settings that
were never flipped for production.

### Trust model
- Django's middleware stack and Flask's decorators are the enforcement points; a view/route without
  the right decorator (`login_required`, `permission_required`) is public, however "internal" it looks.
- `settings.py` / app config is the security posture in one file: `DEBUG`, `ALLOWED_HOSTS`,
  `SECRET_KEY`, cookie flags. Whatever is in the deployed settings module is what production runs.
- Jinja2/Django templates auto-escape HTML — until someone marks content `safe`.

### Top traps
1. **ORM injection despite the ORM.** `.raw()`, `.extra()`, `cursor.execute()` with an f-string or
   `%`-formatted SQL, or `text()` in SQLAlchemy with interpolated input — the ORM's safety only covers
   the queries that go through it. → [SENT-INJ-01](vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
2. **`DEBUG = True` in production.** Django's debug page dumps settings, environment, and stack traces
   to any visitor on an error. The single highest-leverage settings check. →
   [SENT-SECRET-02](vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
3. **CSRF protection disabled instead of configured.** `@csrf_exempt` sprinkled to make a failing POST
   work (or Flask apps with no CSRF extension at all on session-cookie-authenticated forms). →
   [SENT-AUTHZ-09](vulnerability-catalog.md#sent-authz-09--cross-site-request-forgery-csrf)
4. **Admin panel exposed.** Django admin at the default `/admin/` with weak or reused superuser
   credentials, no IP restriction or SSO, and `DEBUG`-era accounts still active. →
   [SENT-AUTHZ-02](vulnerability-catalog.md#sent-authz-02--broken-function-level-authorization)
5. **`SECRET_KEY` committed** (signs sessions — leaking it is session forgery), or loaded with an
   insecure fallback default. → [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
6. **Template escape hatches.** `|safe`, `mark_safe()`, `{% autoescape off %}`, `Markup()` on anything
   user-derived. → [SENT-INJ-02](vulnerability-catalog.md#sent-inj-02--cross-site-scripting-xss)
7. **Object access by pk with no owner filter.** `get_object_or_404(Invoice, pk=pk)` without
   `owner=request.user`. → [SENT-AUTHZ-01](vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)

### How to test
- `python manage.py check --deploy` — Django's own production checklist flags `DEBUG`, cookie flags,
  HSTS, and `SECRET_KEY` issues in one command.
- Grep for the escape hatches: `\.raw\(`, `\.extra\(`, `cursor.execute` with `f"`/`%`/`.format`,
  `@csrf_exempt`, `mark_safe`, `|safe`.
- Request `/admin/` unauthenticated; trigger an error page in the deployed configuration and confirm a
  generic error, not the debug page.
- Two-account IDOR probe on every pk/slug-addressed view, exactly as in the generic playbook.

---

## Rails

### Key
Rails' conventions do a lot of security work by default — the failures come from the idioms that
bypass convention: unfiltered params, `html_safe`, string-interpolated `where`, and skipped CSRF
callbacks.

### Trust model
- `params` is attacker-controlled, nested and mass-assignable by design; **strong parameters**
  (`require`/`permit`) are the write allow-list, and a model touched by any controller without them is
  writable wholesale.
- Session cookies are signed/encrypted with `secret_key_base` — leaking it is session forgery.
- ERB auto-escapes; `html_safe`, `raw`, and `render inline:` are the XSS escape hatches — Rails'
  equivalents of `dangerouslySetInnerHTML`.

### Top traps
1. **Mass assignment.** `Model.new(params[:model])` / `update(params.to_unsafe_h)` or a `permit!`
   (permit-everything) — attacker sets `admin`, `role`, `user_id`. →
   [SENT-INJ-03](vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
2. **CSRF handling skipped.** `skip_before_action :verify_authenticity_token` added to silence a
   failing form or API controller that still uses cookie sessions. →
   [SENT-AUTHZ-09](vulnerability-catalog.md#sent-authz-09--cross-site-request-forgery-csrf)
3. **`html_safe` / `raw` on user data** — the auto-escape bypass, often laundered through a helper. →
   [SENT-INJ-02](vulnerability-catalog.md#sent-inj-02--cross-site-scripting-xss)
4. **SQL injection via interpolated scopes.** `where("name = '#{params[:q]}'")` instead of the
   placeholder form. → [SENT-INJ-01](vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
5. **IDOR via `find`.** `Invoice.find(params[:id])` instead of `current_user.invoices.find(...)` —
   scope every lookup through the owner association. →
   [SENT-AUTHZ-01](vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
6. **Unscoped redirects** — `redirect_to params[:return_to]` (open redirect). →
   [SENT-AUTHZ-06](vulnerability-catalog.md#sent-authz-06--auth-redirect--oauth-callback-misconfiguration)

### How to test
- Run **Brakeman** — the Rails-native static scanner catches most of the above mechanically; treat its
  output as leads to verify, not a report to paste.
- Grep for `permit!`, `to_unsafe_h`, `html_safe`, `raw(`, `skip_before_action :verify_authenticity_token`,
  and `where(` / `order(` with `#{`.
- POST to a form endpoint without the CSRF token and confirm rejection; submit extra fields
  (`admin=true`) on every create/update and confirm they're dropped.
- Two-account probe on every `find(params[:id])` path.

---

## Go (net/http and common frameworks)

### Key
Go gives you almost no framework safety net — no default middleware, no ORM, no exceptions. The
vibe-coding failures are therefore *omissions the compiler tolerates*: ignored error returns, shared
state without a mutex, and requests without contexts.

### Trust model
- Every handler registered on a mux is public unless its own code checks auth — there is no
  framework-level session layer unless one was explicitly added.
- Goroutines are cheap and generated code spawns them freely; any variable reachable from two
  goroutines is shared state, and the memory model makes unsynchronized access undefined, not just racy.
- Errors are values: an ignored return *is* a swallowed error, silently.

### Top traps
1. **Goroutine races on shared state.** Handler closures writing package-level maps/slices/counters
   with no `sync.Mutex`; caches and "simple" in-memory sessions are the classic sites. →
   [SENT-ASYNC-02](vulnerability-catalog.md#sent-async-02--non-atomic-writes-to-shared-state)
2. **Error-swallowing via ignored returns.** `result, _ := doAuth(...)`, `val, _ := strconv.Atoi(...)`,
   or an `if err != nil` that logs and falls through to the success path — fail-open in the language's
   most idiomatic clothing. → [SENT-ASYNC-01](vulnerability-catalog.md#sent-async-01--swallowed-async-errors-and-silent-fallback-returns)
3. **Missing context cancellation.** Handlers ignoring `r.Context()`: DB queries and outbound calls
   with no deadline outlive the request, pile up under load, and turn a slow dependency into
   resource exhaustion. → [SENT-INJ-05](vulnerability-catalog.md#sent-inj-05--missing-rate-limits-on-heavy-or-metered-operations)
4. **SQL built with `fmt.Sprintf`.** `db.Query(fmt.Sprintf("... WHERE id = %s", id))` instead of
   placeholder args. → [SENT-INJ-01](vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template)
5. **Auth middleware wrapped per-route by hand** — and forgotten on the routes added later (the
   pattern-abandonment signature). → [SENT-ARCH-04](vulnerability-catalog.md#sent-arch-04--context-window-pattern-abandonment),
   [SENT-AUTHZ-03](vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network)

### How to test
- `go test -race ./...` and `go vet ./...` — the race detector is the definitive test for trap 1; run
  it with real concurrent load if tests don't exercise handlers.
- `errcheck ./...` (or `golangci-lint` with errcheck enabled) mechanically finds ignored error returns;
  review each hit on an auth/validation path as a potential fail-open.
- Grep for `fmt.Sprintf` feeding `Query`/`Exec`, for `go func` touching package-level vars, and for
  handlers that never read `r.Context()`.
- Diff the route table against the middleware wrapping: list every registered route and confirm each
  one passes through the auth chain.

---

## React Native / Flutter (mobile)

### Key
The binary ships to the attacker. Anything in the app package — strings, env "secrets," bundled JS or
Dart — is readable with free tooling, and anything the app can do, a reverse-engineered client can do
against your API directly.

### Trust model
- `EXPO_PUBLIC_`/bundled env vars, hardcoded constants, and asset files are **extracted, not
  protected** — an APK/IPA is a zip file. The only secrets a mobile app may hold are per-user,
  revocable tokens.
- The device offers a real secure store (iOS Keychain, Android Keystore) — but the default reach-for
  storage (`AsyncStorage`, `SharedPreferences`, `shared_preferences` in Flutter) is plaintext on disk.
- The API behind the app is the actual security boundary; every check must live there, because the
  client will be replayed with curl.

### Top traps
1. **Secrets bundled into the client binary.** Provider API keys (OpenAI/Anthropic, Stripe secret,
   Firebase service accounts) shipped in the app so it can call the service "directly" — extractable
   by anyone with the store listing. Proxy such calls through your server. →
   [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
2. **Tokens in insecure local storage.** Session/refresh tokens in `AsyncStorage` /
   `SharedPreferences` instead of Keychain/Keystore (`expo-secure-store`, `flutter_secure_storage`) —
   plaintext to any process with device/backup access. →
   [SENT-AUTHZ-05](vulnerability-catalog.md#sent-authz-05--insecure-session-and-claims-handling)
3. **No certificate pinning** on high-value APIs — a user-installed CA (trivial on a rooted or
   corporate device) lets a proxy read and rewrite every request, tokens included. Pin for financial
   and auth traffic; accept the rotation cost.
4. **Authorization decided in the app.** Role checks, feature gates, or price calculations client-side
   with the API trusting whatever arrives. → [SENT-AUTHZ-02](vulnerability-catalog.md#sent-authz-02--broken-function-level-authorization)
5. **Deep links / app links unvalidated** — another app on the device invokes your screens with
   attacker-chosen params; treat deep-link input like any other untrusted boundary. →
   [SENT-AUTHZ-06](vulnerability-catalog.md#sent-authz-06--auth-redirect--oauth-callback-misconfiguration)

### How to test
- Unpack the release artifact (`unzip app.apk`; `strings` / `apktool` / inspect the JS bundle or
  `libapp.so`) and grep for key prefixes (`sk_live`, `AKIA`, `AIza`, provider key shapes). Anything
  found is already leaked.
- Read the app's storage on a test device/emulator and confirm no token is on disk outside
  Keychain/Keystore.
- Proxy the app through mitmproxy/Burp with a user-installed CA: if traffic decrypts, pinning is
  absent — then replay the captured API calls without the app and confirm the server enforces every
  check itself.
- Fire crafted deep links at the app and confirm sensitive screens still demand auth.

---

## Adding a playbook

New stacks follow the same four-part shape: key, trust model, top traps (cross-linked to catalog IDs),
how to test. See the [playbook issue template](../../.github/ISSUE_TEMPLATE/playbook.md) and
[CONTRIBUTING.md](../../CONTRIBUTING.md).
