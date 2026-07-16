# SENTINEL Tool-Assisted Evidence

How to use static analysis, secret scanners, and git history to make the audit **faster and more
complete** — without letting a tool decide what goes in the report.

The governing rule, and the reason this file exists:

> **Tools produce leads. The audit produces findings.**
> A grep hit is a coordinate, not a conclusion. Nothing from a tool enters the report until you have
> opened the file, traced the data flow, and confirmed the missing control yourself. Conversely, a clean
> tool run is not evidence of safety — it is evidence that the tool's rules did not match.

## Why the methodology still leads

Static tools are pattern matchers, and the highest-impact vibe-coding class — broken authorization — is
**the absence of code**. There is no token to match on. `supabase.from('invoices').select('*').eq('id',
id)` is a cross-tenant data leak or a correct query depending on a policy in another system entirely, and
no linter can tell you which. That is [SENT-AUTHZ-01](vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor),
the single most common finding, and every scanner in the table below misses it.

So the split is:

| Tools are good at | The audit is good at |
|---|---|
| Committed secrets, known-vulnerable dependencies | Authorization gaps (the absence of a check) |
| Injection sinks with a recognizable shape | Whether a control is *reachable* on the live path |
| Ignored error returns, data races (Go) | Business logic, trust boundaries, blast radius |
| Enumerating a large codebase quickly | Deciding what the finding actually *means* |

Run the tools to buy attention, then spend that attention on authorization and logic.

---

## Where tools attach to the phases

**Phase 0 — Pre-audit inventory.** This is where tooling earns the most, because it is orientation, not
judgment. Get the shape of the codebase and the AI-authorship signal cheaply:

```bash
# Size and language mix — where is the code?
tokei .              # or: cloc .

# Entry points, which is what Phase 1 actually needs. (Note the trailing '.' — see the grep pack.)
rg -n --glob '!node_modules' "^(export )?(async )?function (GET|POST|PUT|PATCH|DELETE)\b|'use server'|@app\.route|def (get|post)\b" .

# Secrets across the FULL history, not just the working tree.
gitleaks detect --redact --log-opts="--all"

# Iteration depth: how many commits, how large, how AI-shaped?
git log --oneline | wc -l
git log --pretty='%h %an %s' --shortstat | head -50
```

**Phase 3 — Adversarial scan.** Tools generate the candidate list; the data-flow trace confirms or kills
each one. Semgrep with a stock ruleset plus the grep pack below covers the sink-shaped classes (B, C, G),
leaving your reading time for A, E, F, and H.

**Phase 4 — Iterative regression audit.** Git is the tool here, and it is the phase's whole engine. See
[Git archaeology](#git-archaeology-for-phase-4) below.

**Phase 5 — Remediation.** Nothing automated. A tool's suggested fix is a lead like any other.

---

## The toolchain, by ecosystem

Install nothing the project doesn't need. All of these are free and run locally.

| Purpose | Tool | Invocation | Catches |
|---|---|---|---|
| Secrets (all langs, full history) | **Gitleaks** | `gitleaks detect --redact --log-opts="--all"` | [SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets) |
| Secrets (alternative) | **TruffleHog** | `trufflehog git file://. --only-verified` | Same, with live-key verification |
| Multi-language SAST | **Semgrep** | `semgrep --config=auto` | [SENT-INJ-01](vulnerability-catalog.md#sent-inj-01--injection-sql--command--code--template), [-02](vulnerability-catalog.md#sent-inj-02--cross-site-scripting-xss), [-07](vulnerability-catalog.md#sent-inj-07--server-side-request-forgery-ssrf), [SENT-CRYPTO-01](vulnerability-catalog.md#sent-crypto-01--weak-or-absent-credential-hashing) |
| Deep dataflow SAST | **CodeQL** | `codeql database analyze --format=sarif-latest` | Cross-function taint; slow, worth it pre-launch |
| Dependencies (Node) | `npm audit` / **osv-scanner** | `npm audit --omit=dev --audit-level=high` | [SENT-SUPPLY-01](vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies) |
| Package existence | **registry check** | `npm view <pkg>` · `pip index versions <pkg>` | [SENT-SUPPLY-02](vulnerability-catalog.md#sent-supply-02--hallucinated-or-typosquatted-packages) — *no scanner does this* |
| Containers / OS packages | **Trivy** | `trivy fs --scanners vuln,secret,misconfig .` | Supply chain + misconfiguration |
| Python | **Bandit** · **pip-audit** | `bandit -r . -ll` | Injection, weak crypto, hard-coded secrets |
| Ruby / Rails | **Brakeman** | `brakeman -A` | Mass assignment, SQLi, CSRF skips, `html_safe` |
| Go | **race detector** · **errcheck** · **gosec** | `go test -race ./...` · `errcheck ./...` | [SENT-ASYNC-02](vulnerability-catalog.md#sent-async-02--non-atomic-writes-to-shared-state), [SENT-ASYNC-01](vulnerability-catalog.md#sent-async-01--swallowed-async-errors-and-silent-fallback-returns) |
| Django | **framework check** | `python manage.py check --deploy` | [SENT-SECRET-02](vulnerability-catalog.md#sent-secret-02--permissive-cors-missing-headers-debug-mode) |
| Supabase | **Security Advisor** | Dashboard, or the `pg_class` query in the playbook | [SENT-AUTHZ-07](vulnerability-catalog.md#sent-authz-07--missing-database-layer-access-control-rls-disabled-or-permissive) |
| Headers (deployed) | **Mozilla Observatory** | `observatory <host>` | Missing CSP / HSTS / frame-ancestors |

Two notes that matter more than the table:

- **`npm audit` cannot see a hallucinated package.** It reports advisories for packages that *exist*. A
  dependency that 404s on the registry is invisible to it and is the more dangerous finding. Check every
  unfamiliar name by hand — that is [SENT-SUPPLY-02](vulnerability-catalog.md#sent-supply-02--hallucinated-or-typosquatted-packages).
- **`semgrep --config=auto` uploads a project fingerprint** to Semgrep's registry to select rules. Use
  `--config=p/security-audit --metrics=off` on code you cannot send anywhere.

---

## The grep pack

Mechanical first-pass searches, keyed to catalog classes. Written for
[ripgrep](https://github.com/BurntSushi/ripgrep); each returns **candidates to read**, and a large fraction
of every result set will be benign. Run them, then open the hits.

> **Every command names its search path (`.`) explicitly, and you should keep it.** When ripgrep's stdin is
> not a terminal — inside a script, a CI step, a pipeline, or an agent's shell — a `rg PATTERN` with no path
> searches **stdin instead of the directory tree**. It silently reports nothing, or blocks waiting for input.
> A pattern that "found no issues" because it never read a file is the worst possible output from a security
> scan.

```bash
# ── A. Authorization ────────────────────────────────────────────────────────────
# Handlers that resolve a session and stop there (logged-in ≠ authorized). SENT-AUTHZ-01
rg -n "if \(!(session|user)\) return" -A 12 . | rg -n "\.(select|update|delete|findUnique|findOne)"

# Server Actions and route handlers — enumerate them all, then check each for an in-body authz check.
rg -n --glob '!node_modules' "'use server'|export async function (GET|POST|PUT|PATCH|DELETE)" .

# Trusted proxy headers — forgeable by a direct caller. SENT-AUTHZ-03
rg -ni "headers\.(get\()?['\"]?x-(user-id|authenticated|role|admin)" .

# Tokens in JS-reachable storage; unverified JWTs. SENT-AUTHZ-05
rg -n "localStorage\.(set|get)Item\(.*(token|jwt|session)|jwt\.decode\(|algorithms:\s*\[\s*['\"]none" .

# Open redirect. SENT-AUTHZ-06
rg -n "redirect\((req\.query|searchParams\.get|params\[)" .

# CSRF protection switched off. SENT-AUTHZ-09
rg -n "csrf_exempt|skip_before_action\s+:verify_authenticity_token|csrf:\s*false|sameSite:\s*['\"]none" .

# ── B. Injection & sinks ────────────────────────────────────────────────────────
# String-built SQL / shell / eval. SENT-INJ-01
rg -n "(query|execute|exec|raw|queryRawUnsafe)\s*\(\s*[\"'\`].*\\\$\{|fmt\.Sprintf\(.*(SELECT|INSERT|UPDATE|DELETE)" .
rg -n "\beval\(|new Function\(|child_process|os\.system\(|subprocess\..*shell\s*=\s*True" .

# XSS escape hatches. SENT-INJ-02
rg -n "dangerouslySetInnerHTML|\.innerHTML\s*=|v-html|mark_safe\(|\|\s*safe\b|\.html_safe\b|raw\(" .

# Mass assignment: untrusted spread into a write. SENT-INJ-03
rg -n "\.(update|insert|create)\(\s*\{?\s*\.\.\.(req\.body|body|formData|params)|permit!|to_unsafe_h" .

# SSRF: user-controlled outbound fetch. SENT-INJ-07
rg -n "(fetch|axios\.get|requests\.get|http\.Get)\(\s*(req\.|request\.|params|searchParams|url\b)" .

# Over-broad responses. SENT-INJ-08
rg -n "select\(\s*['\"]\*|SELECT \*|fields\s*=\s*['\"]__all__['\"]|res\.json\((user|profile|row)\)" .

# ── C. Secrets & config ─────────────────────────────────────────────────────────
# Secrets shipped to the client. SENT-SECRET-01  (then: build, and grep the bundle)
rg -n "(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|PUBLIC_)[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|SERVICE_ROLE)" .
rg -n "service_role|SERVICE_ROLE|sk_live_|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY" .

# Credentialed wildcard CORS; debug on. SENT-SECRET-02
rg -n "Access-Control-Allow-Origin.*\*|origin:\s*true|DEBUG\s*=\s*True|debug:\s*true" .

# Webhook handlers with no signature verification. SENT-SECRET-04
# (--files-without-match, NOT -L: in ripgrep -L means --follow.)
rg -l "webhook" . | xargs -r rg --files-without-match "constructEvent|createHmac|verify_signature|timingSafeEqual"

# ── F/G/H. Async, crypto, logging ───────────────────────────────────────────────
# Swallowed errors — the highest-yield line in this file. SENT-ASYNC-01
rg -n -U "catch\s*\([^)]*\)\s*\{[^}]*console\.(log|error)[^}]*\}" .
rg -n "catch\s*\([^)]*\)\s*\{\s*\}|, _ :?=|except.*:\s*pass" .

# Weak credential hashing. SENT-CRYPTO-01
rg -n "createHash\(['\"](md5|sha1|sha256)['\"]\)|hashlib\.(md5|sha1)\(|MODE_ECB|createCipher\(" .

# Predictable randomness where it authorizes something. SENT-CRYPTO-02
rg -n "Math\.random\(\)|random\.random\(\)|Date\.now\(\)" -C 2 . | rg -i "token|secret|key|code|nonce|id\b|session"

# Sensitive data into logs. SENT-LOG-02
rg -n "console\.(log|error)\(.*(req\.body|req\.headers|password|token|process\.env|user\b)" .
```

Three of these deserve a warning. The `Math.random()` search is deliberately over-broad — most hits are UI
keys and jitter, which are **not findings**; you are looking only for the ones that mint something which
grants access. The swallowed-error regexes will match legitimate top-level handlers that log and rethrow.
And the `createHash` pattern flags `sha256`, which is *correct* for hashing an already-high-entropy API key
and *wrong* only for a password — the regex cannot tell you which, and that distinction is the finding.

Read before reporting. That is the whole point of this file.

---

## Git archaeology for Phase 4

[Phase 4](../SKILL.md) asks whether successive iterations *removed* a control. Git can answer that
directly, and this is the only mechanical way to detect
[SENT-ARCH-05](vulnerability-catalog.md#sent-arch-05--security-focused-regression-trap).

```bash
# 1. When did a control identifier appear — and did it ever disappear?
#    -S is a pickaxe: it lists commits that changed the NUMBER of occurrences of the string.
git log -S 'requireUser' --oneline -- src/
git log -S 'enable row level security' --oneline
git log -S 'csrf' --oneline

# 2. Commits whose message promises security. Read their diffs with MORE suspicion, not less —
#    the message states the intent, never the diff. (SENT-ARCH-05)
git log --oneline --grep='secur\|auth\|harden\|fix.*vuln\|sanitiz' -i

# 3. Show only the REMOVED lines from security-sensitive files across history.
git log -p --follow -- middleware.ts | rg '^-' | rg -i 'auth|verify|check|role|policy|validate'

# 4. Which files changed together with auth code, and which auth files went quiet?
git log --format='' --name-only --since='6 months ago' | sort | uniq -c | sort -rn | head -30

# 5. Inter-session boundaries: files created in a burst, by one author, in one commit.
git log --pretty='%h %ad %s' --date=short --shortstat --diff-filter=A | rg -B1 'files? changed'

# 6. Was a secret ever committed and later "removed"? It is still in the history and still live.
gitleaks detect --redact --log-opts="--all"
git log --all --full-history -- '**/.env*'
```

Reading the output: a commit that *reduces* the occurrence count of `requireUser`, `verify`, `policy`, or
`enable row level security` is a lead of the highest quality this audit has. Open the diff. Ask whether
the control moved somewhere else or simply stopped existing — those look identical in the summary and are
opposite findings.

**Without git history**, say so explicitly in the report and run the same signatures statically: two
adjacent endpoints of the same shape where only one validates; a `verify()` on one path and a `decode()`
on another; a parameterized query beside a raw one. The phase degrades; it does not disappear.

---

## Machine-readable findings

When the audit feeds a dashboard, a CI gate, or a tracker rather than a human, emit each finding as JSON
alongside the Markdown report. Keep the same fields as the
[report format](../SKILL.md) so nothing is lost in translation.

```json
{
  "id": "SENT-AUTHZ-01",
  "title": "Invoice route returns any invoice by id",
  "severity": "critical",
  "confidence": "high",
  "classification": { "owasp": ["A01:2025"], "api": ["API1:2023"], "cwe": ["CWE-639", "CWE-284"] },
  "location": { "file": "app/api/invoices/[id]/route.ts", "line": 12, "symbol": "GET" },
  "evidence": {
    "source": "params.id (attacker-controlled)",
    "sink": "supabase.from('invoices').select('*').eq('id', params.id)",
    "missing_control": "no owner scope on the query and no RLS policy on `invoices`"
  },
  "falsifiable_by": "an RLS policy on `invoices` scoping select to auth.uid() = owner_id",
  "remediation_ref": "remediation-patterns.md#sent-authz-01--enforce-object-ownership-server-side"
}
```

`severity` ∈ `critical|high|medium|low`; `confidence` ∈ `high|medium|low`. The `evidence` and
`falsifiable_by` fields are not decoration — they are the [evidence standard](../SKILL.md) in serialized
form, and a finding that cannot fill them in is a finding that has not been verified.

To feed GitHub's code-scanning UI, map each object to a SARIF `result`: `ruleId` ← `id`, `level` ←
`critical|high → error`, `medium → warning`, `low → note`, and `locations[0].physicalLocation` ←
`location`. Upload with `github/codeql-action/upload-sarif`.

---

## Wiring the floor into CI

Two controls belong on every push, because they catch regressions of two classes with no human in the
loop. They are the *floor*, not a review — see the
[CI notes](../../.github/workflows/ci.md) for a ready-to-lift workflow.

1. **Secret scanning** on the full history, failing the build on any hit
   ([SENT-SECRET-01](vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)).
2. **Dependency audit** failing on High/Critical advisories
   ([SENT-SUPPLY-01](vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies)).

For a multi-tenant app, add a third: a **cross-tenant authorization test** — sign in as user A, request
user B's object, assert a deny. It is the only one of the three that tests the class that actually breaks
these apps, and no scanner will ever write it for you.

---

## Adding a tool

Keep the shape: what it catches, the exact invocation, which catalog IDs it maps to, and — the part most
tool documentation omits — **what it systematically misses**. A tool whose blind spots are undocumented
will be trusted past its competence, which is worse than not running it. See
[CONTRIBUTING.md](../../CONTRIBUTING.md).
