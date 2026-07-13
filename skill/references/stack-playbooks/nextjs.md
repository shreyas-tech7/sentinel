# Next.js (App Router)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md). Written against Next.js 14+; the trust
model holds for later App Router versions.

## Key
There is no implicit trust between files. A Server Action *looks* like a local function but is a public
POST endpoint; a Route Handler runs whether or not middleware did; and anything a Client Component can
read is public.

## Trust model
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

## Top traps
1. **Server Action with no authz.** `'use server'` functions that mutate data trusting the caller, or
   that accept the owner id from the client. → [SENT-AUTHZ-04](../vulnerability-catalog.md#sent-authz-04--missing-auth-on-server-actions--route-handlers)
2. **Route Handler assuming middleware ran.** A handler under a path the `matcher` excludes (commonly
   `/api/*`), doing sensitive work with no in-handler check. → [SENT-AUTHZ-03](../vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network)
3. **Secret in a Client Component.** A key read at module scope in a file that is (transitively)
   `'use client'`, or passed as a prop / returned from a Server Component into client props. →
   [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
4. **`NEXT_PUBLIC_` on a secret.** Especially a service-role or provider *secret* key. →
   [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)
5. **Open redirect via `redirect(searchParams.get('next'))`** in a login/callback route. →
   [SENT-AUTHZ-06](../vulnerability-catalog.md#sent-authz-06--auth-redirect--oauth-callback-misconfiguration)
6. **Caching a sensitive response.** A per-user Route Handler response cached (default `GET` caching,
   `force-cache`, or a CDN) and served to another user. Mark per-user responses `no-store`.
7. **Mass assignment in an action.** `.update({ ...formData })` from a Server Action. →
   [SENT-INJ-03](../vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
8. **Missing security headers.** No `Content-Security-Policy` / `Strict-Transport-Security` /
   frame-ancestors configured in `next.config` or middleware. → [SENT-SECRET-02](../vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode)

## How to test
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
