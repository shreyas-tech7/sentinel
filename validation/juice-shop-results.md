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

---

# Scored coverage pass — 10 files, 40 documented challenges (2026-07-19)

**This section extends the five-finding slice above; that slice stands as recorded.** It addresses the
two things the earlier pass did not do: it scores against Juice Shop's own ground truth instead of
listing findings, and it covers the LLM/prompt-injection surface, which the earlier pass **did not
touch at all** — confirmed by grep: the words *LLM*, *prompt injection*, *chatbot*, and *section D*
appear nowhere in it.

**Date produced:** 2026-07-19
**Target:** OWASP Juice Shop v20.1.1, commit `33518f5`.
**Method:** SENTINEL Phases 0–3 applied by hand to a 10-file scope (2150 lines).
Static-analysis-only: nothing was started, called, or attacked. The app was never run.

## Read this first — the pass is not blind

The Benchmark runs in `owasp-benchmark-results.md` are blind: the sample is drawn without the truth
column and scored only afterwards. **This pass is not, and its recall figure is not comparable to
them.** The answer key was derived from Juice Shop's `vuln-code-snippet` markers *before* the audit,
which means the audited file list was chosen knowing which files carry documented vulnerabilities, and
the LLM challenges were read out of `challenges.yml` before `routes/chat.ts` was opened.

What this measures is therefore **coverage and finding quality on a known-vulnerable surface**: given
that a documented weakness is in this file, does the methodology produce a correct, evidence-backed
finding for it? That is a worthwhile question — it is the one the v4.0 ask posed — but it is not a
detection test, and a reader should not read 0.7750 recall here as comparable to 0.9358 F1 on
Benchmark. Making it blind would require choosing the scope without consulting the markers, which is
worth doing and is not what happened here.

## Ground truth

The answer key is derived mechanically from the target by `validation/score_juiceshop.py`, not written
by hand. Two independent signals locate each documented challenge's implementation:

1. `// vuln-code-snippet start <key>` markers, Juice Shop's own annotation of the intentionally
   vulnerable code behind each score-board challenge; and
2. `solveIf(challenges.<key>` / `solve(challenges.<key>` calls, where the app detects a solve.

Both are unioned, and every key is validated against `data/static/challenges.yml` (113 challenges).
Markers alone are too narrow — `routes/chat.ts` marks only the two coupon challenges even though it
also contains the `aiDebugging` detection. The union puts **40 documented challenges** inside the
audited scope.

### Scoring rules

- **TP** — a documented challenge located in an audited file that a finding covers.
- **FN** — a documented challenge located in an audited file that no finding covers.
- **FP** — a finding covering a key that is not a documented challenge anywhere.
- **Cross-file** — claimed, documented, but implemented outside the audited files. Neither TP nor FP.
- **Unscored** — a real finding with no corresponding challenge. Neither TP nor FP: the challenge list
  is a lower bound on what is wrong with this code, so penalising a correct finding for lacking a
  challenge id would punish correct work.

An important limit on what "recall" means here: a static audit can identify that account recovery
rests on guessable knowledge-based questions, but it cannot tell you Bender's pet's name. Several
challenges are *solved* by research or guessing rather than by reading code. Recall below measures
whether the audit found the underlying code weakness, not whether the auditor could solve the
challenge.

### Reproducing

```bash
git clone https://github.com/juice-shop/juice-shop.git   # commit 33518f5
python validation/score_juiceshop.py --juice-shop-root ../juice-shop \
    --findings validation/data/juice-shop-v6-findings.json --markdown
```

## Results (2026-07-19)

| File | Documented challenges | Found | Missed |
|---|---|---|---|
| `routes/chat.ts` | 3 | 3 | - |
| `routes/login.ts` | 12 | 4 | dlpPasswordSprayingChallenge, ephemeralAccountantChallenge, exposedCredentialsChallenge, ghostLoginChallenge, loginAmyChallenge, loginRapperChallenge, loginSupportChallenge, oauthUserPasswordChallenge |
| `routes/search.ts` | 2 | 2 | - |
| `routes/updateProductReviews.ts` | 2 | 2 | - |
| `lib/insecurity.ts` | 2 | 2 | - |
| `models/user.ts` | 2 | 1 | persistedXssUserChallenge |
| `server.ts` | 6 | 6 | - |
| `frontend/src/app/app.routing.ts` | 4 | 4 | - |
| `frontend/src/app/search-result/search-result.component.ts` | 3 | 3 | - |
| `data/static/securityQuestions.yml` | 5 | 5 | - |
| **total** | **40** | **31** | **9** |

| Metric | Value |
|---|---|
| True positives | 31 |
| False positives | 0 |
| False negatives | 9 |
| Precision | 1.0000 |
| Recall | 0.7750 |
| F1 | 0.8732 |
| Documented but detected outside scope (cross-file) | 1 |
| Findings outside the documented set (unscored) | 1 |

The 21 findings, each with source · sink · missing control · falsifier per the Phase 5 evidence
standard, are in [`data/juice-shop-v6-findings.json`](data/juice-shop-v6-findings.json).

## Phase 3 section D — the LLM surface

Section D is the hardest part of the catalog to test objectively, which is why it was the priority
here. `routes/chat.ts` is a real agentic surface: an `ai`-SDK `streamText` loop with four tools
(`searchProducts`, `getProductReviews`, `getOrderById`, `generateCoupon`), a ten-step cap, and a
system prompt carrying the business rules. **All three documented challenges implemented in that file
were found.**

- **JS6-01 · Excessive agency (High).** `generateCoupon` declares
  `discount: z.number().describe('The discount percentage for the coupon (maximum 10)')`. The bound
  lives in a *description string* — prose handed to the model — and `execute()` calls
  `security.generateCoupon(discount)` with no clamp and no check that the customer has the damaged
  order the policy requires. Every condition in the prompt's COUPON POLICY block is enforced only by
  the model's willingness to comply. This covers both `chatbotPromptInjectionChallenge`
  (fires at `discount >= 10`) and `chatbotGreedyInjectionChallenge` (`>= 50`), and it is the textbook
  instance of the rule section D already states: **system prompts are not security boundaries.**
- **JS6-02 · System prompt leakage (Medium).** `buildSystemPrompt()` ends with a block marked
  `CONFIDENTIAL - INTERNAL ONLY` describing a 15% escalation discount. Prompt text is model context,
  not a secret store. Juice Shop scores this as `systemPromptExtractionChallenge` from
  `routes/verify.ts`, outside the audited scope — hence the cross-file classification, not a TP.
- **JS6-03 · Broken function-level authorization (Medium).** Every `tool-call` event writes the tool
  name and full JSON arguments into the SSE stream unconditionally. The adjacent `solveIf` checks
  `req.cookies.show_tool_calls === 'true' && role !== admin`, which shows the exposure is meant to be
  admin-only — but the gate is a cookie the client sets on itself, and the server applies no role
  check before emitting. Covers `aiDebuggingChallenge`. This is an *enforcement location* failure
  (section A) surfacing on an LLM feature, not an LLM flaw as such.
- **JS6-04 · Indirect prompt injection (Medium, unscored).** `getProductReviews` returns review
  documents into model context, and review bodies are user-writable via
  `routes/updateProductReviews.ts` (which JS6-06/JS6-07 show is itself unguarded). Planted
  instruction-shaped text influences the model for *other* users asking about that product — a
  second-order path that needs no attacker presence in the conversation. No challenge covers this;
  it is reported as an unscored finding rather than counted.

**One thing section D correctly did not report.** `getProductReviews` executes
`db.reviewsCollection.find({ $where: 'this.product == ' + productId })` — string concatenation into a
MongoDB `$where` server-side JavaScript eval, reachable through a model-controlled tool argument. It
is not injectable: `productId = Number(id)` coerces any non-numeric payload to `NaN`, so the predicate
degrades to `this.product == NaN` and matches nothing. `Number()` is the control, and the falsifier
step is what surfaced it. Reporting it would have been a false positive; the fragility is worth a Low
note, since deleting one `Number()` call turns it into server-side code execution.

## Error analysis — the nine misses

All nine are false negatives; there were no false positives. They fall into exactly two findings the
audit failed to make.

**1. Hardcoded credentials in `routes/login.ts` — 8 missed challenges.**
`dlpPasswordSpraying`, `ephemeralAccountant`, `exposedCredentials`, `ghostLogin`, `loginAmy`,
`loginRapper`, `loginSupport`, `oauthUserPassword`.

`verifyPreLoginChallenges()` compares `req.body.password` against plaintext literals sitting in the
source file — `'Mr. N00dles'`, `'IamUsedForTesting'`, `'admin123'`, and a 30-character high-entropy
string for the password-spraying account (not reproduced here; it is a credential-shaped literal and
there is no reason to copy one into this repo). Phase 3 **section C** names this class outright
("Exposed credentials — hard-coded API keys, secrets"), and these are not subtle: they are quoted
string literals, greppable in one pass.

The audit read `login.ts`, produced the SQL injection finding (JS6-11), and stopped. That is the
failure mode: **finding the headline vulnerability in a file and treating the file as done.** One
finding — "production credentials for eight accounts are hardcoded in the login route" — would have
converted all eight. Recall would have been 0.9750 instead of 0.7750, and the difference is not
analytical difficulty, it is not finishing the file.

**2. Weak legacy sanitiser in `models/user.ts` — 1 missed challenge.** `persistedXssUserChallenge`.

The `username` setter branches to `security.sanitizeLegacy(username)` when the challenge is enabled,
and `sanitizeLegacy` is `input.replace(/<(?:\w+)\W+?[\w]/gi, '')` — a single-pass regex that strips
one tag-like shape and is trivially defeated by nesting or by markup the pattern does not match. The
branch was read during the audit and not flagged: a sanitiser was present, and its *quality* was not
interrogated. That is exactly the SENT-ARCH-05 signature the skill already documents — a control
structurally present but semantically incomplete — applied to a sanitiser rather than an auth check.

### What the two have in common

Neither is a limitation of the methodology and neither is a hard call. One is stopping a file early;
the other is accepting a control's existence as evidence of its adequacy. Both are the same failure
the Benchmark run surfaced in a different costume: **an assumption that was asserted rather than
verified.** Across all three of this release's error analyses — Java, Python, and Juice Shop — not one
miss came from failing to trace a dataflow. Every one came from not opening something.

## What this does and does not establish

- **Precision 1.0000 across 21 findings is the meaningful number here.** Every challenge claimed was
  real and in the right file; nothing was invented to inflate coverage. On a not-blind pass, precision
  is the figure that survives the caveat — recall is the one inflated by knowing where to look.
- **Recall 0.7750 is a coverage measure on a known surface**, not a detection rate, and not comparable
  to the Benchmark figures. See the caveat at the top.
- **The scope is 10 files of a 60+ route-module application.** It is the documented-vulnerable
  surface, deliberately, which is a favourable slice. Nothing here speaks to how the methodology
  performs on the ~90% of the codebase with no markers in it.
- **Section D is now genuinely exercised** — an agentic tool loop with a real excessive-agency finding,
  a real prompt-leakage finding, and a correctly-declined false positive — rather than untested, which
  is what it was after the five-finding slice.

## Files

- `validation/data/juice-shop-v6-findings.json` — the 21 findings with full evidence-standard fields
  and their challenge mappings.
- `validation/score_juiceshop.py` — derives the answer key from the target and scores against it.
