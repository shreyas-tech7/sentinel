# SENTINEL Stack Playbooks

Framework-specific manifestations of the [catalog](vulnerability-catalog.md) classes, and how to test
for them. The methodology in [`../SKILL.md`](../SKILL.md) generalizes to any stack — these playbooks
just encode the sharp edges of the stacks where vibe-coded apps bleed most.

**As of v3.0 each playbook is its own file** under [`stack-playbooks/`](stack-playbooks/), so an audit
loads only the one it needs. Read the file matching the stack you identified in Phase 1 — or the
**generic** one when nothing matches. Every playbook follows the same shape: **Key** (the one-sentence
mental model), **Trust model** (where the client/server line sits and which keys cross it), **Top
traps** (the recurring failures, each cross-linked to its catalog entry), and **How to test** (how to
prove a control holds).

Where an artifact isn't really a "stack" — a browser extension, a chat bot, a CLI or desktop tool —
route through [`artifact-playbooks.md`](artifact-playbooks.md) instead. Mobile is a stack, so it lives
here; a mobile app *plus* its backend is audited as both, sharing one trust-boundary map.

## The playbooks

| Stack | File | Read it when |
|---|---|---|
| **Generic / Unknown** | [`stack-playbooks/generic.md`](stack-playbooks/generic.md) | No named playbook matches — and skim it even when one does. The invariant list. |
| Supabase | [`stack-playbooks/supabase.md`](stack-playbooks/supabase.md) | Postgres + Auth + Storage; client talks to the DB directly. |
| Next.js | [`stack-playbooks/nextjs.md`](stack-playbooks/nextjs.md) | App Router; Server Actions, Route Handlers, `NEXT_PUBLIC_`. |
| Serverless / edge | [`stack-playbooks/serverless-edge.md`](stack-playbooks/serverless-edge.md) | Vercel Functions, Cloudflare Workers, individually-addressable functions. |
| LLM / RAG | [`stack-playbooks/llm-rag.md`](stack-playbooks/llm-rag.md) | **Only when Phase 0 detected an LLM/agent integration.** |
| Python | [`stack-playbooks/python.md`](stack-playbooks/python.md) | Django, Flask, FastAPI. |
| Firebase | [`stack-playbooks/firebase.md`](stack-playbooks/firebase.md) | Firestore / Realtime Database / Storage security rules. |
| Rails | [`stack-playbooks/rails.md`](stack-playbooks/rails.md) | Ruby on Rails. |
| PHP | [`stack-playbooks/php.md`](stack-playbooks/php.md) | Laravel, WordPress. |
| Node + Mongo | [`stack-playbooks/node-mongo.md`](stack-playbooks/node-mongo.md) | Express + MongoDB / Mongoose; NoSQL operator injection. |
| Go | [`stack-playbooks/go.md`](stack-playbooks/go.md) | `net/http` and common frameworks; races, ignored errors. |
| Java / Spring | [`stack-playbooks/java-spring.md`](stack-playbooks/java-spring.md) | Spring Boot, Spring Security, Spring MVC, Spring Data JPA. |
| .NET | [`stack-playbooks/dotnet.md`](stack-playbooks/dotnet.md) | ASP.NET Core MVC / Web API / Minimal APIs + EF Core. |
| Rust | [`stack-playbooks/rust.md`](stack-playbooks/rust.md) | Actix-web / Axum / Rocket + SQLx / Diesel; logic/config, not memory. |
| Mobile | [`stack-playbooks/mobile.md`](stack-playbooks/mobile.md) | React Native, Flutter, native iOS/Android. |

Each trap cross-links to its catalog entry in [`vulnerability-catalog.md`](vulnerability-catalog.md)
and its fix in [`remediation-patterns.md`](remediation-patterns.md). The mechanical searches that feed
every playbook's "How to test" are in [`tooling.md`](tooling.md).

## Adding a playbook

New stacks follow the same four-part shape: key, trust model, top traps (cross-linked to catalog IDs),
how to test. Add a new file under `stack-playbooks/`, add a row to the table above, and cross-link the
traps. See the [playbook issue template](../../.github/ISSUE_TEMPLATE/playbook.md) and
[CONTRIBUTING.md](../../CONTRIBUTING.md).
