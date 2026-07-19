# SENTINEL re-audit (regression) mode — worked example

**Date produced:** 2026-07-19
**Target:** OWASP Juice Shop v20.1.1 (same clone as `juice-shop-results.md`), four files.
**Purpose:** prove that Phase 4's re-audit delta buckets — **Resolved**, **Still open**, **Regressed**,
**Newly introduced** — each fire correctly against a *real* fix pass, with real before/after code and
real `git` evidence, not a description of what they would do.

This is a static exercise on a **local, uncommitted, never-pushed** working copy. Nothing was executed
or attacked; the working copy exists only to produce the diffs and history the re-audit reads.

## Setup

Starting from the original audit (`juice-shop-results.md`), four findings on the audited slice are
tracked here:

| # | Finding | File | Original severity |
|---|---|---|---|
| F1 | SQL injection in the login query | `routes/login.ts` | Critical |
| F2 | Broken object-level authorization (IDOR) on basket retrieval | `routes/basket.ts` | High |
| F3 | Passwords hashed with unsalted MD5 | `lib/insecurity.ts` | High |
| (new) | — | — | — |

A developer then does a two-commit "fix pass" in the working copy:

```
d6e830a  baseline: Juice Shop routes as audited in the original report
002e8aa  harden auth: parameterize login query, scope basket to owner; add debug user lookup
04b2c12  basket: simplify query for perf, drop redundant where clause
```

- **Commit `002e8aa`** fixes F1 (parameterizes the login query) and F2 (scopes the basket query to the
  owner), and — during the same pass — adds a new `routes/debugUser.ts` helper.
- **Commit `04b2c12`** "simplifies" the basket query for performance and, in doing so, silently removes
  the ownership check that `002e8aa` had just added.

The re-audit runs the full Phases 0–3 against the working copy's HEAD, with the original report
supplied, and presents the delta.

---

## Re-audit delta

### ✅ Resolved — F1: SQL injection in the login query
The interpolated query was replaced with a bound-parameter query. The control (parameterization) is
now present on the live path.

```diff
--- a/routes/login.ts
+++ b/routes/login.ts
-    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
+    models.sequelize.query('SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL', { replacements: { email: req.body.email || '', password: security.hash(req.body.password || '') }, model: UserModel, plain: true })
```

`email` is no longer concatenated into SQL; `' OR 1=1--` is now bound as a literal string. **Confirmed
closed** — not merely relocated. Confidence: High.

### ⛔ Still open — F3: passwords hashed with unsalted MD5
Untouched by the fix pass. The control (a slow salted KDF) is still absent on the live path.

```ts
// lib/insecurity.ts:41  (unchanged since baseline)
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

Retains its original **High** severity. This is "Still open," not "Regressed": no control was ever
added and then lost — it simply was never fixed.

### 🔁 Regressed — F2: broken object-level authorization (IDOR) on basket retrieval
This is the case the regression bucket exists for. F2 **was resolved** in `002e8aa` (an ownership
scope was added) and then **re-opened** in `04b2c12`. The live path is vulnerable again, exactly as in
the original report.

The mechanical detector is `git log -S` on the control identifier, which lists every commit that
changed how many times `UserId` appears in the file:

```
$ git log --oneline -S 'UserId' -- routes/basket.ts
04b2c12  basket: simplify query for perf, drop redundant where clause   <- removed it
002e8aa  harden auth: parameterize login query, scope basket to owner   <- added it
```

The added-then-removed pair is the SENT-ARCH-05 signature. The two diffs:

```diff
# 002e8aa — control ADDED (F2 resolved here)
-      const basket = await BasketModel.findOne({ where: { id }, include: [ ... ] })
+      const basket = await BasketModel.findOne({ where: { id, UserId: (req as any).user.id }, include: [ ... ] })
```
```diff
# 04b2c12 — control REMOVED (F2 regressed here), commit message says "perf", not "revert auth"
-      const basket = await BasketModel.findOne({ where: { id, UserId: (req as any).user.id }, include: [ ... ] })
+      const basket = await BasketModel.findOne({ where: { id }, include: [ ... ] })
```

The commit message ("simplify query for perf, drop redundant where clause") describes the intent, not
the security impact — the `UserId` clause was not redundant, it was the entire authorization control.
Restored to its original **High** severity, and flagged as **Regressed** rather than Still open,
because someone believed this was closed: that is the more dangerous state, and the one a plain
"still open" label would hide. Confidence: High.

### 🆕 Newly introduced — unauthenticated full-record user lookup (`routes/debugUser.ts`)
Created *by the fix pass itself* (commit `002e8aa`), absent from the original report:

```ts
// routes/debugUser.ts (new file)
export function debugUser () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = await UserModel.findByPk(req.params.id)
      res.json({ user }) // returns the whole row, no auth, no field filtering
    } catch (error) {
      next(error)
    }
  }
}
```

- **Analysis:** the handler loads any user by path id with no authentication and no object-level
  authorization, and serializes the entire `UserModel` row (including the password hash and TOTP
  secret) into the response.
- **Attack scenario:** `GET /rest/debug/user/1` returns the admin's full record to any unauthenticated
  caller.
- **Classification:** OWASP A01:2021 · API1:2023 (BOLA) / API3:2023 (excessive data exposure) ·
  CWE-306, CWE-639, CWE-201. **Severity: High. Confidence: High** (the missing auth and the full-row
  serialization are both visible in the new file).
- **Falsifier:** if this handler were never wired into the router, or were placed behind
  `isAuthorized()` and a field allow-list, it would not be exploitable — this walkthrough adds the file
  to demonstrate the bucket; a real re-audit would also confirm the route registration.

---

## Result

All four buckets fired against a single real fix pass, each on genuine code with genuine evidence:

| Bucket | Finding | Evidence |
|---|---|---|
| **Resolved** | F1 SQLi (login) | parameterized query now on the live path |
| **Still open** | F3 MD5 hashing | `createHash('md5')` unchanged since baseline |
| **Regressed** | F2 basket IDOR | `git log -S 'UserId'` shows control added (`002e8aa`) then removed (`04b2c12`) |
| **Newly introduced** | debug user endpoint | new unauthenticated full-row handler added in `002e8aa` |

The delta is a presentation layer over the standard report: every entry above still carries a
severity, a confidence, and (for the regression and the new finding) the source·sink·missing-control·
falsifier evidence standard. The regression bucket earns its keep here — F2 would read as an ordinary
"still open" without the history, hiding the fact that a control was added and then quietly lost, which
is precisely the failure mode Phase 4 is built to catch.

## Reproduce

The working copy is intentionally not committed to this repository. To recreate it, copy the four files
named above out of a Juice Shop v20.1.1 clone, `git init`, and apply the two commits described in
"Setup" (parameterize login; add `UserId` scope to basket + add `debugUser.ts`; then remove the
`UserId` scope). `git log -S 'UserId' -- routes/basket.ts` reproduces the regression signal.
