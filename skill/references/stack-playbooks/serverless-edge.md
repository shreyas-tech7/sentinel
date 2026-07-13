# Generic serverless / edge (Vercel Functions, Workers)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
Each function is independently reachable from the internet. There is no shared, always-on gateway doing
auth for you unless you built one — and even then, the function must not assume it ran.

## Trust model
- Functions are stateless and individually addressable. "Internal" functions are internal only by
  obscurity unless a check enforces it.
- Environment variables are the secret store; anything not explicitly server-scoped can leak through a
  client build step.
- Edge runtimes have reduced APIs and their own auth caveats; cold starts and per-invocation isolation
  mean per-request rate limiting needs a shared store (KV/Redis/DB), not in-memory counters.

## Top traps
1. **Cold-path auth gaps.** An auth check present on the "main" route but missing on a secondary
   function (cron target, internal proxy, revalidation hook). → [SENT-AUTHZ-04](../vulnerability-catalog.md#sent-authz-04--missing-auth-on-server-actions--route-handlers)
2. **Unauthenticated internal proxy.** A function that forwards to a backend or third-party API with the
   server's credentials, callable by anyone. → [SENT-AUTHZ-03](../vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network)
3. **No rate limiting.** In-memory counters don't work across invocations; effectively no limit. →
   [SENT-INJ-05](../vulnerability-catalog.md#sent-inj-05--missing-rate-limits-on-heavy-or-metered-operations)
4. **Env exposure at the edge / in the client build.** → [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
5. **SSRF in a fetch/proxy function** taking a user URL. → [SENT-INJ-07](../vulnerability-catalog.md#sent-inj-07--server-side-request-forgery-ssrf)
6. **Cron/webhook endpoints unprotected.** A scheduled function's HTTP trigger reachable by the public
   without a shared secret. → [SENT-SECRET-04](../vulnerability-catalog.md#sent-secret-04--unverified-webhook-payloads)
7. **Webhook handlers that aren't idempotent.** Providers redeliver; a replayed event double-fires the
   side effect, and per-invocation isolation means the dedupe must live in a shared store. →
   [SENT-ASYNC-03](../vulnerability-catalog.md#sent-async-03--non-idempotent-webhook-and-queue-consumers)

## How to test
- Inventory every function/route, not just the ones the UI links. For each, send an unauthenticated
  request and confirm a deny.
- Hammer a metered/expensive function from a script and confirm a shared-store rate limit kicks in
  across invocations.
- Send a cron/webhook function a forged request with no secret/signature and confirm rejection — then
  replay a *legitimate* delivery twice and confirm the side effect fires once.
