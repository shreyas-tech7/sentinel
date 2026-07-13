# Generic / Unknown Stack

Part of the [SENTINEL stack playbooks](../stack-playbooks.md). **This playbook is what makes SENTINEL
usable on any stack, not just the named ones** — read it whenever no named playbook matches, and skim
it even when one does: it is the invariant list the named playbooks specialize.

## Key
The stack changes the syntax, never the questions. Every framework has a client (public), a server
(where controls must live), a session mechanism, a data store, a dependency manifest, and environment
configuration — audit those six things and you have audited any stack.

## Trust model
- Anything that executes on, or is shipped to, a device the user controls — browser bundle, mobile
  binary, desktop app — is **public**: readable, modifiable, and bypassable. Controls that live there
  are UX, not security.
- The server (or the database, if it can enforce access itself) is the only place a control counts.
  Identify where the framework's server-side code actually runs, and treat everything else as
  attacker-controlled input to it.
- Whatever the framework calls its secret store (env vars, config files, a vault), trace which values
  cross to the client side — most stacks have a mechanism (a prefix, a build step, a template context)
  that silently ships server config to the client.

## Top traps
1. **Server-side validation missing at a boundary.** Regardless of framework: every route, handler,
   RPC, job, and webhook revalidates its input server-side, even when a client-side check exists. →
   [SENT-INJ-01](../vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template),
   [SENT-INJ-03](../vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
2. **Logged-in mistaken for authorized.** Object-level ownership checks on every read *and* write. →
   [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
3. **Session/token storage.** Tokens in JS-readable or world-readable storage; signatures unverified;
   user-editable claims trusted. → [SENT-AUTHZ-05](../vulnerability-catalog.md#sent-authz-05--insecure-session-and-claims-handling)
4. **No DB-level access control where the DB supports it.** If the store can enforce row/object-level
   access (Postgres RLS, Firestore rules, S3 policies), app-code filters alone are not the control. →
   [SENT-AUTHZ-07](../vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
5. **Dependency manifest sanity.** A lockfile exists and is committed; every dependency resolves on its
   registry; no known-critical advisories on reachable paths. →
   [SENT-SUPPLY-01](../vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies),
   [SENT-SUPPLY-02](../vulnerability-catalog.md#sent-supply-02--hallucinated-or-typosquatted-packages)
6. **Env var handling.** Secrets absent from source and git history; whatever the stack's
   ship-to-client mechanism is, no secret uses it; debug mode off in production. →
   [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets),
   [SENT-SECRET-02](../vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)
7. **Swallowed failures and races** — the async/structural classes apply to every language. →
   [SENT-ASYNC-01](../vulnerability-catalog.md#sent-async-01--swallowed-async-errors-and-silent-fallback-returns),
   [SENT-ASYNC-02](../vulnerability-catalog.md#sent-async-02--non-atomic-writes-to-shared-state)
8. **Cookie sessions without CSRF defense.** If the credential is ambient (a cookie), a cross-origin page
   can spend it. Every framework has a built-in protection, and the bug is almost always that someone
   switched it off. → [SENT-AUTHZ-09](../vulnerability-catalog.md#sent-authz-09--cross-site-request-forgery-csrf)
9. **Credentials and tokens.** Passwords behind a slow salted KDF, never a fast digest; every value that
   grants access minted from the language's CSPRNG (`secrets`, `crypto.randomBytes`, `SecureRandom`),
   never its general-purpose PRNG. →
   [SENT-CRYPTO-01](../vulnerability-catalog.md#sent-crypto-01--weak-or-absent-credential-hashing),
   [SENT-CRYPTO-02](../vulnerability-catalog.md#sent-crypto-02--predictable-randomness-in-security-sensitive-values)
10. **Audit trail and log hygiene.** Privileged actions leave a durable, actor-attributed record; logs
    carry identifiers, not credentials or PII. →
    [SENT-LOG-01](../vulnerability-catalog.md#sent-log-01--no-audit-trail-on-privileged-or-financial-actions),
    [SENT-LOG-02](../vulnerability-catalog.md#sent-log-02--secrets-and-pii-written-to-logs-and-telemetry)
11. **Files, paths, and parsers.** Every language has a deserializer that executes while parsing and a
    path API that joins without confining — check what the app feeds them. Webhook and queue handlers
    are idempotent, because every provider redelivers. →
    [SENT-INJ-09](../vulnerability-catalog.md#sent-inj-09--unsafe-deserialization-of-untrusted-data),
    [SENT-INJ-10](../vulnerability-catalog.md#sent-inj-10--path-traversal-and-unsafe-file-path-handling),
    [SENT-ASYNC-03](../vulnerability-catalog.md#sent-async-03--non-idempotent-webhook-and-queue-consumers)

## How to test
- Enumerate every entry point from the code, not the UI: route registrations, handler decorators, RPC
  definitions, cron/webhook targets. For each, send an unauthenticated request and a
  wrong-user request; both must deny.
- Grep for the stack's client-exposure mechanism (public env prefixes, template-injected config,
  bundled assets) and for secret-shaped strings in anything shipped.
- Check the manifest: lockfile committed, every package resolves on its registry, audit tooling clean.
- Force a failure (kill the DB connection, send malformed input) and confirm the app fails closed with
  a generic error — not open, and not with a stack trace.
- Read a response body, not the rendered page: the network tab shows every field the API actually
  returned. → [SENT-INJ-08](../vulnerability-catalog.md#sent-inj-08--excessive-data-exposure-in-responses)
- Trigger an error with a token in the request and confirm the token does not appear in the logs or the
  error tracker.
- Replay a webhook delivery byte-for-byte and confirm the side effect fires once, not twice.

The mechanical searches for all of the above — per language, with the commands — are in
[`tooling.md`](../tooling.md). Run them to buy attention, then spend that attention on trap 2, which no
tool can see.
