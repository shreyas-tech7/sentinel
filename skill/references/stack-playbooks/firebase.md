# Firebase (Firestore / Realtime Database / Auth)

Part of the [SENTINEL stack playbooks](../stack-playbooks.md).

## Key
Firebase is Supabase's sibling failure: the client SDK talks to the database directly with a config
that ships to the browser, so **security rules are the authorization layer** — not your app code. The
rules file is the whole boundary, and the default a vibe-coded project reaches for opens it entirely.

## Trust model
- The **`firebaseConfig` (apiKey, projectId, etc.) is public** by design — it identifies the project,
  not a user, and belongs in the client bundle. Its exposure is *not* a finding; treating it as a
  secret is a category error. The user is identified by a **Firebase Auth ID token**, reachable inside
  rules as `request.auth.uid` and `request.auth.token`.
- **Security rules (`firestore.rules`, `database.rules.json`, `storage.rules`) are the only control.**
  Anyone can pull the public config, authenticate (or not), and hit the database's REST/gRPC API
  directly, bypassing every check written in your React/Flutter code. A client-side `where('uid','==',
  currentUser.uid)` is a query convenience, never authorization.
- The **Admin SDK bypasses all rules.** It is a server-only credential (a service-account JSON). If
  that file is committed, bundled, or shipped to a client, the entire project is wide open — treat it
  exactly like Supabase's `service_role` key ([SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)).

## Top traps
1. **Wide-open rules.** `allow read, write: if true;` — or the test-mode default that grants everything
   until a timestamp, left in place past launch. This is the flagship Firebase failure and the direct
   equivalent of RLS-disabled; rate it the same. → [SENT-AUTHZ-07](../vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
2. **Authenticated-but-not-authorized.** `allow read, write: if request.auth != null;` on per-user
   data — every logged-in user reads and writes every other user's documents. "Signed in" is not
   "owns this document." → [SENT-AUTHZ-01](../vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)
3. **Recursive wildcard grant.** A broad `match /{document=**}` block with a permissive condition that
   silently overrides the narrow, correct rules written below it. →
   [SENT-AUTHZ-07](../vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive)
4. **Privileged writes validated client-side only.** Role, plan, credit-balance, or price fields
   written from the client with no rule constraining them — a crafted SDK call sets `role: "admin"` or
   `credits: 999999`. Rules must pin these with `request.resource.data` checks (or forbid client writes
   to them entirely and route through a Cloud Function). →
   [SENT-INJ-03](../vulnerability-catalog.md#sent-inj-03--mass-assignment--over-allocation)
5. **Rules trusting user-editable token fields.** `request.auth.token` custom claims are safe only when
   set server-side via the Admin SDK; a `role` stored in the user's *profile document* and read back by
   a rule is attacker-writable unless the write path is itself locked. →
   [SENT-AUTHZ-05](../vulnerability-catalog.md#sent-authz-05--insecure-session-and-claims-handling)
6. **Storage rules left open.** `allow read, write: if request.auth != null;` on a bucket holding
   per-user files means any user downloads any other user's uploads. →
   [SENT-SECRET-03](../vulnerability-catalog.md#sent-secret-03--public-storage-buckets--default-open-configuration)
7. **Committed service-account key.** `serviceAccountKey.json` in the repo or bundled into a mobile
   app. → [SENT-SECRET-01](../vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)

## How to test
- **Read the rules file first — it is the audit.** Any `if true`, any bare `request.auth != null` on
  per-user data, and any broad `match /{document=**}` is a finding until proven scoped.
- **Prove cross-tenant isolation with the emulator.** The Firebase Local Emulator Suite plus
  `@firebase/rules-unit-testing` lets you assert that user A cannot read user B's document — write that
  test; it is the definitive proof, the Firebase analogue of the two-account curl test.
- **Attempt a privileged write from a plain client.** Signed in as an ordinary user, try to set
  `role`/`credits` on your own document via the SDK; a correct rule set rejects it.
- **Grep for the Admin SDK on the client** and for `serviceAccount`/`.json` credentials in the repo and
  in git history.
