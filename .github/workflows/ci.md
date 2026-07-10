# CI notes — secret scanning and dependency audit

SENTINEL ships no runtime code, so this repo's own CI is deliberately small. It runs in
[`ci.yml`](ci.yml) and does two things:

1. **Structural integrity** — [`scripts/check_repo.py`](../../scripts/check_repo.py) resolves every
   intra-repo link and heading anchor, asserts that every `SENT-*` class exists in **both** the
   catalog and the remediation patterns (the invariant [CONTRIBUTING.md](../../CONTRIBUTING.md)
   states in prose), and greps for credential-shaped strings.
2. **Secret scanning** — Gitleaks over the full commit history.

Below is the *other* half: the reusable workflow this project recommends to every codebase it
audits. It demonstrates the two follow-through controls — **secret scanning** and **dependency
auditing** — and is meant to be lifted into any Next.js / Node project. The corresponding
methodology is in [`docs/how-to-use.md`](../../docs/how-to-use.md) under "Wire the follow-through
into CI," and the wider toolchain is in
[`skill/references/tooling.md`](../../skill/references/tooling.md).

To activate it in your project, save the YAML below as `.github/workflows/security.yml`.

## What it does

1. **Secret scan** — [Gitleaks](https://github.com/gitleaks/gitleaks) scans the full history and the
   current tree for credential-shaped strings (API keys, tokens, private keys, connection strings).
   It fails the build on any hit. This is the control that catches the single most common
   vibe-coding mistake: a `.env` or a hard-coded key committed by accident.
2. **Dependency audit** — `npm audit` (or `pnpm audit` / `yarn npm audit`) flags known-vulnerable
   and, indirectly, suspicious dependencies. Pair it with a lockfile so the audit is reproducible.
   Review new/renamed packages by hand — audit tools do not catch *hallucinated* package names
   (see catalog `SENT-SUPPLY-02`).

> Neither tool replaces the audit. They are the automated floor: they catch regressions of two
> specific classes so a human review can spend its attention on authorization and logic.

## Reference workflow (`.github/workflows/security.yml`)

```yaml
name: security

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history so the scan sees past commits, not just the diff
      - name: Gitleaks secret scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        # Fails the job on any finding. Tune with a committed .gitleaks.toml if you need
        # documented, reviewed allowlist entries (e.g. obvious placeholders in example reports).

  dependency-audit:
    runs-on: ubuntu-latest
    # Only meaningful in projects that have a package manifest; harmless no-op otherwise.
    if: ${{ hashFiles('**/package-lock.json', '**/pnpm-lock.yaml', '**/yarn.lock') != '' }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Audit production dependencies
        run: npm audit --omit=dev --audit-level=high
        # --audit-level=high fails the build on High/Critical advisories while letting Lows through
        # for triage. Drop to =moderate once the project is clean.
```

## Local pre-push equivalent

Run the same checks before pushing (see `CONTRIBUTING.md` step 3):

```bash
# this repo's own invariants: links, anchors, class parity, secret shapes
python scripts/check_repo.py

# secret-shaped strings in the staged diff
git diff --cached | grep -nE '(sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}\.|service_role|BEGIN [A-Z]+ PRIVATE KEY)' \
  && echo "Possible secret staged — review before committing" && exit 1 || echo "No secret-shaped strings staged"

# dependency advisories (in a project with a lockfile)
npm audit --omit=dev --audit-level=high
```

## Notes for maintainers of this repo

- Gitleaks runs against this repo in [`ci.yml`](ci.yml), over the full history.
- The example reports under `examples/` contain **intentional** placeholder strings
  (`<REDACTED_API_KEY>`, `sb-service-role-key-REDACTED`), and
  [`skill/references/tooling.md`](../../skill/references/tooling.md) contains regex *patterns* that
  describe secret shapes without being secrets. Neither is a credential, but a naive scanner may
  flag the surrounding shapes. If Gitleaks fires on one, add a reviewed allowlist in `.gitleaks.toml`
  scoped to that path rather than loosening the global rules. `scripts/check_repo.py` already
  distinguishes them: it exempts lines containing `REDACTED`/`EXAMPLE`/`<PLACEHOLDER>` and its
  patterns require literal high-entropy suffixes that a regex-as-text cannot satisfy.
- Never allowlist a real secret. If a scan ever fires on something that turns out to be real,
  rotate it immediately and follow [SECURITY.md](../../SECURITY.md).
