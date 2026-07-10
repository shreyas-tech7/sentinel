---
name: Propose a stack playbook
about: Add a framework/stack-specific section to the SENTINEL playbooks
title: "[PLAYBOOK] <stack or framework name>"
labels: playbook, needs-triage
assignees: ''
---

<!--
Playbooks encode the sharp edges of a specific stack. The methodology already generalizes; a
playbook just tells the reviewer where THIS stack tends to bleed and how to test it.
Follow the four-part shape in stack-playbooks.md. See CONTRIBUTING.md → "How to add a stack
playbook".
-->

## Stack / framework
<!-- e.g. Django REST Framework, Cloudflare Workers, Firebase, tRPC + Prisma. -->

## Key
<!-- One sentence: the mental model for how this stack does authorization and trust. -->

## Trust model
<!-- Where the client/server boundary actually sits. Which keys/roles/tokens cross it, and which
     must never reach the client? What runs at the edge vs. the origin? -->

## Top traps
<!-- The specific, recurring ways vibe-coded apps on this stack get it wrong. Cross-link each to a
     catalog ID (e.g. SENT-AUTHZ-01) where one applies. -->
1.
2.
3.

## How to test / verify
<!-- Concrete steps to prove a control holds or fails — a command, a query, a two-account test. -->

## Why this belongs in SENTINEL
<!-- Is this stack common in vibe-coded apps? What makes its failure modes distinct from stacks
     already covered? -->

## Checklist
- [ ] I followed the key / trust-model / traps / test shape.
- [ ] Each trap cross-links to a catalog ID where one exists (or I proposed a new class).
- [ ] The "how to test" steps are runnable, not hand-wavy.
