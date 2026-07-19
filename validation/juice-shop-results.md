# SENTINEL vs. OWASP Juice Shop — validation run

**Date produced:** 2026-07-19
**Target:** [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) v20.1.1, cloned at commit
`33518f5`.
**Method:** SENTINEL four-phase static methodology (Phases 0–3) applied by hand to a representative
slice of the Express/TypeScript backend. **Ground truth:** Juice Shop ships a documented catalogue of
intentional vulnerabilities ("challenges"); each finding below is cross-referenced to the challenge it
corresponds to, which is the externally checkable answer key.

Static-analysis-only. No route was called, no payload was sent, nothing was executed. The interpolated
strings shown as "attack scenario" exist to justify severity, per SENTINEL's evidence standard.

## Scope of this slice

Node.js 20 / Express 4 / TypeScript / Sequelize (SQLite). Audited entry points, each confirmed against
`server.ts` routing:

| Route | Handler | File |
|---|---|---|
| `POST /rest/user/login` | `login()` | `routes/login.ts` |
| `GET /rest/basket/:id` | `retrieveBasket()` | `routes/basket.ts` (behind `isAuthorized()`, `server.ts:356`) |
| `GET /rest/user/change-password` | `changePassword()` | `routes/changePassword.ts` |
| `POST /b2b/v2/orders` | `b2bOrder()` | `routes/b2bOrder.ts` |
| `GET /ftp/:file` | `servePublicFiles()` | `routes/fileServer.ts` |
| (shared) password hashing | `hash()` | `lib/insecurity.ts:41` |

This is a slice, not a full audit: Juice Shop has 60+ route modules. The point is to demonstrate that
SENTINEL's methodology surfaces the documented vulnerabilities in the code it is shown, with correct
severity and the authN-vs-authZ distinction intact — not to enumerate every challenge.

## Findings

### [CRITICAL] SQL injection in the login query
- **Severity:** Critical | **Confidence:** High
- **Classification:** OWASP A03:2021 (Injection) · CWE-89 · **maps to `loginAdminChallenge`,
  `loginBenderChallenge`, `loginJimChallenge`**
- **Location:** `routes/login.ts` — `models.sequelize.query(...)`
- **Analysis:** `req.body.email` is interpolated directly into a raw SQL string:
  ```ts
  models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, ...)
  ```
  The password side is hashed (still not parameterized), but `email` is entirely unsanitized.
- **Attack scenario:** email = `' OR 1=1--` collapses the `WHERE` clause and returns the first user
  (the admin), whom `afterLogin` then issues a token for — full authentication bypass.
- **Missing control / falsifier:** a parameterized query (`replacements`/bind params). There is no
  ORM-level escaping on this path because `sequelize.query` with a template string bypasses it. If a
  parameterized variant existed on the live path this would be void — it does not.
- **Remediation:** use bound parameters and never interpolate request data into SQL:
  ```ts
  models.sequelize.query(
    'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
    { replacements: { email: req.body.email || '', password: security.hash(req.body.password || '') },
      model: UserModel, plain: true })
  ```

### [HIGH] Broken object-level authorization (IDOR) on basket retrieval
- **Severity:** High | **Confidence:** High
- **Classification:** OWASP A01:2021 · API1:2023 (BOLA) · CWE-639 · **maps to `basketAccessChallenge`**
- **Location:** `routes/basket.ts` — `retrieveBasket()`
- **Analysis:** the route is authenticated (`app.use('/rest/basket', security.isAuthorized(), security.appendUserId())`, `server.ts:356`), but the handler loads the basket by the **path id alone**:
  ```ts
  const id = req.params.id
  const basket = await BasketModel.findOne({ where: { id }, include: [...] })
  ```
  `appendUserId()` attaches the caller's id to the request, but `retrieveBasket` never compares it to
  the basket's `UserId`. The `challengeUtils.solveIf(...)` block *detects* cross-user access for the
  CTF scoreboard; it does not *block* it.
- **Attack scenario:** logged-in user with basket 1 requests `GET /rest/basket/2` and reads another
  customer's basket contents. Authentication (who you are) passed; authorization (may you touch *this*
  object) was never checked — the canonical vibe-coding IDOR.
- **Missing control / falsifier:** a `where: { id, UserId: req.user.id }` scope, or a post-load
  ownership assertion. If the query were user-scoped this would be void; it is not.
- **Remediation:**
  ```ts
  const basket = await BasketModel.findOne({ where: { id, UserId: (req as any).user.id }, include: [...] })
  if (!basket) { res.status(404).json({ error: 'Basket not found' }); return }
  ```

### [HIGH] Password change without verified current password
- **Severity:** High | **Confidence:** High
- **Classification:** OWASP A07:2021 (Identification and Authentication Failures) · CWE-620 (Unverified
  Password Change) · **maps to `changePasswordBenderChallenge`**
- **Location:** `routes/changePassword.ts`
- **Analysis:** the current-password check is guarded by the *presence* of the parameter:
  ```ts
  if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password) {
    res.status(401).send(res.__('Current password is not correct.')); return
  }
  ```
  Omit `current` entirely and the whole check is skipped; the handler proceeds to
  `user.update({ password: newPasswordInString })`. Credentials also travel in the query string
  (`GET /rest/user/change-password?new=...&repeat=...`), so they land in access logs (see
  SENT-LOG-02) and are CSRF-reachable given the token is read from a header.
- **Attack scenario:** with any valid session token, `GET /rest/user/change-password?new=x&repeat=x`
  (no `current`) resets the account password with no knowledge of the old one.
- **Missing control / falsifier:** require `current`, verify it unconditionally, and move the operation
  off GET/query. If `current` were mandatory this would be void; the `currentPassword &&` short-circuit
  is exactly what makes it optional.
- **Remediation:**
  ```ts
  if (!currentPassword || security.hash(currentPassword) !== loggedInUser.data.password) {
    res.status(401).send(res.__('Current password is not correct.')); return
  }
  ```
  and expose the operation as `POST` with the body over TLS, not the query string.

### [HIGH] Server-side code execution via user-supplied `orderLinesData`
- **Severity:** High | **Confidence:** Medium
- **Classification:** OWASP A03:2021 · CWE-94 (Code Injection) · **maps to `rceChallenge`,
  `rceOccupyChallenge`**
- **Location:** `routes/b2bOrder.ts`
- **Analysis:** request body flows into an eval-family sink:
  ```ts
  const sandbox = { safeEval, orderLinesData: body.orderLinesData || '' }
  vm.createContext(sandbox)
  vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
  ```
  The 2-second `timeout` is a denial-of-service control (it catches the infinite-loop payload the CTF
  scores), not an execution-prevention control. `notevil`'s `safeEval` is the only barrier and is a
  known-bypassable JS sandbox.
- **Attack scenario:** a crafted `orderLinesData` expression that escapes `notevil` executes attacker
  JavaScript in the Node process; a trivial infinite loop instead exhausts the worker (denial of
  service), which is the `rceOccupyChallenge`.
- **Confidence / falsifier:** Medium because the exploit depends on a `notevil` sandbox-escape that is
  not visible in *this* file — the falsifier is "if `notevil` were an actually-sound sandbox, only the
  DoS leg would hold." Public bypasses for `notevil` exist, so the code-execution leg is credible, not
  proven from this snippet alone; the DoS leg is High-confidence on its own.
- **Remediation:** do not evaluate user input. Parse `orderLinesData` as data (`JSON.parse` with a
  schema check) rather than executing it; if expression evaluation is a genuine requirement, use a
  real out-of-process sandbox with a hard resource cap, not an in-process `vm` + `notevil`.

### [HIGH] Passwords hashed with unsalted MD5
- **Severity:** High | **Confidence:** High
- **Classification:** OWASP A02:2021 (Cryptographic Failures) · CWE-916 (Weak Password Hash) ·
  **relates to `weakPasswordChallenge` / general credential exposure**
- **Location:** `lib/insecurity.ts:41`
- **Analysis:** `export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')`
  is the function used to store and compare user passwords (see `login.ts`, `changePassword.ts`). MD5
  is fast, unsalted, and reversible by rainbow table.
- **Attack scenario:** any read of the `Users` table (e.g. via the SQLi above) yields MD5 digests that
  are trivially reversed for all common passwords, compromising every account and any password reused
  elsewhere.
- **Missing control / falsifier:** a slow salted KDF. If password storage were delegated to a provider
  or used bcrypt/Argon2 on the live path this would be void; it is `crypto.createHash('md5')`.
- **Remediation:** hash with Argon2id (or bcrypt/scrypt) and per-user salt; migrate existing digests on
  next successful login.

## Code Health Note (not a security severity on its own)

`routes/fileServer.ts` blocks classic path traversal correctly — it rejects any `params.file`
containing `/` and allowlists `.md`/`.pdf` — so `../` traversal does not reach `res.sendFile`. The
residual issue is `security.cutOffPoisonNullByte()` (`lib/insecurity.ts:44`), which *truncates* at a
literal `%00` and thereby enables the documented `nullByteChallenge` (request `foo.md%00.bak` to reach
a non-allowlisted backup file). This is a real, deliberate weakness, but it is narrow and file-read
only; noted here to show the slice distinguishes a working control (the `/` check) from a broken one
(the null-byte truncation) rather than flagging the whole handler.

## Verification / how to reproduce

```bash
git clone https://github.com/juice-shop/juice-shop.git   # commit 33518f5, v20.1.1
# Read the audited files and cross-check each finding against the named challenge in
# data/static/challenges.yml, which is Juice Shop's own vulnerability answer key.
```

Every High/Critical finding above corresponds to a named entry in Juice Shop's official challenge
catalogue, which is the external ground truth: the vulnerabilities are documented-by-design, and
SENTINEL's slice surfaced them with correct classification and severity, keeping authentication and
authorization separate on the basket route.
