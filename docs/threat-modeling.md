# Threat Modeling with STRIDE

Phase 2 of the audit applies STRIDE to the trust boundaries found in Phase 1. This document shows STRIDE
mapped concretely to web, serverless, and LLM boundaries, and works through several trust-boundary maps
so the abstraction becomes something you can apply to real code.

## What a trust boundary is

A trust boundary is any line where data or control crosses from a **less-trusted** zone into a
**more-trusted** one. The classic mistake is to assume that because data arrived at a trusted component,
it is itself trustworthy. It is not. The value of drawing boundaries explicitly is that each one is a
place a control *must* exist — and STRIDE is the checklist of what could go wrong there.

The boundaries that matter most in vibe-coded web apps:

- **client → server** — the browser (fully attacker-controlled) to your handler.
- **edge/middleware → origin/data layer** — where "it was already checked upstream" assumptions break.
- **webhook/third-party → backend** — inbound events that arrive with authority you didn't grant.
- **user-content → interpreter** — untrusted data reaching SQL, a shell, HTML, a template, or a model.
- **app → database** (when the DB is a public API, as with Supabase) — the boundary *is* the database.

## STRIDE, mapped to real web/serverless/LLM manifestations

| Letter | Threat | Web / serverless manifestation | LLM manifestation |
|---|---|---|---|
| **S** — Spoofing | Pretending to be someone/something you're not | Forged `X-User-Id` header trusted from a proxy; unverified JWT; stolen token from `localStorage` | Impersonating the developer's instructions via prompt injection; spoofed tool identity |
| **T** — Tampering | Unauthorized modification | Mass assignment setting `role`/`price`; parameter tampering on an object id (IDOR write); modifying a webhook payload | Poisoning a retrieved document; altering tool arguments the model emits |
| **R** — Repudiation | Acting without a trace | No audit log on privileged/financial actions; no record of who changed what | No logging of prompts/tool calls; can't reconstruct what an agent did |
| **I** — Information disclosure | Leaking confidential data | IDOR read; over-broad API response; secret in the client bundle; RLS off | System-prompt leakage; secrets embedded in prompts; cross-tenant vector retrieval |
| **D** — Denial of service | Exhausting resources | No rate limit on a heavy endpoint; unbounded upload; brute-forceable login | **Denial-of-wallet**: uncapped metered model calls; unbounded context/token consumption |
| **E** — Elevation of privilege | Gaining rights you shouldn't have | Broken function-level authz on `/api/admin/*`; trusting a user-editable `role` claim | Excessive agency: an injected instruction reaching a high-impact tool with a broad key |

The point of running all six letters at each boundary is coverage: you look for the whole class of
threat, not only the one you thought of first. Then you rank by **blast radius** — auth, payment, and
data-layer boundaries first — to decide what to verify in the Phase 3 scan.

---

## Worked map 1 — client → server (a Route Handler that returns an object)

```
  ┌────────────────────────┐        trust boundary        ┌───────────────────────────┐
  │  Browser (UNTRUSTED)    │  ──────────────────────────▶ │  Route Handler (server)   │
  │  - can set any header   │   GET /api/invoices/:id      │  - has DB credentials     │
  │  - can change :id       │                              │  - returns invoice JSON   │
  │  - can replay requests  │ ◀────────────────────────── │                           │
  └────────────────────────┘        invoice payload        └───────────────────────────┘
                                                                     │
                                                                     ▼
                                                            ┌───────────────────┐
                                                            │  Database          │
                                                            └───────────────────┘
```

**Attacker-controlled:** the entire request — `:id`, all headers, the body, timing and repetition.

**STRIDE at this boundary:**
- **S** — Is the caller authenticated by a *verified* session, or by something forgeable (a header, an
  unverified token)?
- **T** — If this is also a write path (`POST /api/invoices/:id/refund`), can the caller tamper with an
  object they don't own?
- **I** — Does the handler return *this caller's* invoice, or any invoice whose id is supplied? (IDOR —
  the most likely finding here.)
- **E** — Does returning the object depend on a role the user can edit?
- **D** — Can the endpoint be called in a tight loop to exhaust the DB or a downstream cost?

**The control that must exist:** ownership is enforced server-side — ideally in the database (RLS), at
minimum in the handler by scoping the query to the authenticated user. See catalog
[SENT-AUTHZ-01](../skill/references/vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
and [SENT-AUTHZ-07](../skill/references/vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive).

---

## Worked map 2 — edge → data layer (the "middleware already checked it" trap)

```
                          matcher excludes /api/*  ✗ no check here
  ┌────────────┐   ┌───────────────────┐   ┌──────────────────────┐   ┌──────────────┐
  │  Browser   │──▶│  Edge middleware  │──▶│  Route Handler /api  │──▶│  Supabase DB │
  │ UNTRUSTED  │   │  auth check ✓     │   │  assumes auth ran ✗  │   │  RLS off? ✗  │
  └────────────┘   └───────────────────┘   └──────────────────────┘   └──────────────┘
        │                                                                     ▲
        └─────────────── direct request to /api/... bypasses the edge ───────┘
```

The middleware authenticates page routes, but its `matcher` excludes `/api/*`. A direct request to the
API route never passes the edge check, and the handler trusts that it did. If the database also has RLS
off, the request reaches data with **zero** enforcement between the internet and the rows.

**STRIDE highlights:**
- **S/E** — auth is enforced in exactly one place, and that place is bypassable by hitting the excluded
  path directly.
- **I/T** — the data layer is wide open behind the assumption.

**The controls that must exist:** auth is checked *in the handler* (defense-in-depth, not sole reliance
on middleware — [SENT-AUTHZ-03](../skill/references/vulnerability-catalog.md#sent-authz-03--authorization-enforced-only-in-middleware-or-network)),
**and** authorization is enforced at the database with RLS so even a bypassed handler cannot read across
tenants ([SENT-AUTHZ-07](../skill/references/vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)).
Two independent controls, because the whole failure here is single-point reliance.

---

## Worked map 3 — webhook → backend (inbound authority you didn't grant)

```
  ┌─────────────────────┐    trust boundary     ┌────────────────────────────┐
  │  Payment provider   │ ───────────────────▶  │  POST /api/webhooks/pay    │
  │  (or ANYONE who     │   event: checkout.paid │  - marks order paid        │
  │   knows the URL)    │                        │  - triggers fulfilment     │
  └─────────────────────┘                        └────────────────────────────┘
```

A webhook endpoint is public. The payload *claims* an order was paid — but a claim is not proof. Without
signature verification, anyone who learns the URL can forge the event and get free fulfilment.

**STRIDE highlights:**
- **S** — the sender is spoofable; the payload alone doesn't prove origin.
- **T** — payload fields (amount, order id, status) are attacker-controlled.
- **R** — without idempotency and logging, replays and forgeries leave no clean trail.

**The control that must exist:** verify the provider's signature against the **raw** request body before
acting, handle idempotently, and enforce a timestamp tolerance against replay. See
[SENT-SECRET-04](../skill/references/vulnerability-catalog.md#sent-secret-04--unverified-webhook-payloads).

---

## Worked map 4 — user-content → LLM → sink (two boundaries, one feature)

```
  ┌────────────┐   ┌──────────────────┐   ┌───────────────┐   ┌────────────────────┐
  │  User /    │──▶│  Prompt assembly │──▶│  Model (LLM)  │──▶│  Sink              │
  │  RAG docs  │ ① │  instructions +  │   │               │ ② │  HTML / DB / tool  │
  │  UNTRUSTED │   │  untrusted data  │   │               │   │  / paid API        │
  └────────────┘   └──────────────────┘   └───────────────┘   └────────────────────┘
        boundary ① : untrusted content INTO the model (prompt injection)
        boundary ② : model output INTO a sink (improper output handling)
```

An LLM feature introduces *two* trust boundaries where a traditional endpoint has one. At **①**, untrusted
content (user text, a retrieved document, a tool result) enters the prompt — if it's mixed into the
instruction channel, it can hijack behavior (prompt injection,
[SENT-LLM-01](../skill/references/vulnerability-catalog.md#sent-llm-01--prompt-injection)). At **②**, the
model's output leaves toward a sink — if it's rendered as HTML, run as SQL, or passed to a tool without
sanitization, the model becomes an injection vector
([SENT-LLM-02](../skill/references/vulnerability-catalog.md#sent-llm-02--improper-output-handling)).

**STRIDE highlights:**
- **S/E** — an injected instruction spoofs the developer's authority and, if tools are broad, elevates
  into real actions (excessive agency,
  [SENT-LLM-03](../skill/references/vulnerability-catalog.md#sent-llm-03--excessive-agency)).
- **I** — system-prompt leakage; cross-tenant retrieval from a vector store that isn't row-scoped
  ([SENT-LLM-06](../skill/references/vulnerability-catalog.md#sent-llm-06--rag-poisoning-and-non-row-scoped-vector-stores)).
- **D** — denial-of-wallet on the metered call
  ([SENT-LLM-04](../skill/references/vulnerability-catalog.md#sent-llm-04--denial-of-wallet-on-metered-model-apis)).

**The controls that must exist:** separate instructions from data and label untrusted content as data;
treat model output as untrusted before any sink; give the model least-privilege, per-user tools with
human gates on high-impact actions; authenticate and quota the metered call; and enforce authorization in
the data layer *before* the model sees anything — a system prompt cannot enforce it.

---

## From threat model to scan

The threat model's job is to hand Phase 3 a **ranked list of vectors to verify**, ordered by blast
radius. Auth, payment, and data-layer boundaries lead; a static marketing site's contact form trails.
That ranking is what makes the scan efficient — it reads the highest-consequence paths with the most
suspicion. The scan itself, and the catalog it runs against, are covered in
[methodology.md](methodology.md) and the
[vulnerability catalog](../skill/references/vulnerability-catalog.md).
