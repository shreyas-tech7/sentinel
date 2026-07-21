# Contributing to SENTINEL

Thanks for helping keep this useful. SENTINEL is a security *methodology* plus a reference corpus,
not a running service — so contributions are mostly knowledge: new vulnerability classes, sharper
detection guidance, better remediations, and additional stack playbooks. The bar is that every
addition be **defensible** (a technically literate reader should agree with it) and **defensive**
(oriented toward finding and fixing, never toward attacking systems you don't control).

Please read the [Code of Conduct](CODE_OF_CONDUCT.md) and the defensive-use terms in
[SECURITY.md](SECURITY.md) first.

## Ground rules

- **The six-phase workflow in [`skill/SKILL.md`](skill/SKILL.md) is fixed.** Improve wording and
  fix errors, but do not restructure the methodology (inventory → orient → model → scan → regress → fix) or the output
  format without opening a discussion issue first — consistency across the skill, the standalone
  prompts, and the example reports depends on it.
- **The catalog is the single source of truth.** Docs and the README link to it; they must not
  duplicate its content. If you change a classification or ID, update it in the catalog and let the
  links carry it.
- **No secrets, ever.** Do not commit `.env*`, keys, tokens, or realistic-looking fake credentials.
  Example reports use obvious placeholders only. See the redaction policy in
  [`examples/README.md`](examples/README.md).
- **Voice:** understated, precise, senior-engineer. No hype, no emoji spam. Let the substance
  carry it.

## How to add a vulnerability class

A class is not complete until it exists in **both** the catalog and the remediation patterns, and
is reachable from the scan. Follow the existing template in
[`skill/references/vulnerability-catalog.md`](skill/references/vulnerability-catalog.md):

1. **Assign an ID** in the right category namespace: `SENT-AUTHZ-*`, `SENT-INJ-*`, `SENT-SECRET-*`,
   `SENT-SUPPLY-*`, `SENT-LLM-*`, `SENT-ARCH-*`, `SENT-ASYNC-*`, `SENT-CRYPTO-*`, or `SENT-LOG-*`.
   Use the next free number.
2. **Write the entry** with every field: name, category, *what it is*, *why AI/vibe-coding tends to
   skip it*, *what to look for* (concrete sinks, patterns, missing controls), *classification*
   (OWASP / API / LLM ID + CWE ID from a current edition), *severity tendency*, and a *cross-link*
   to the fix.
3. **Add the matching fix** to
   [`skill/references/remediation-patterns.md`](skill/references/remediation-patterns.md), keyed to
   the same ID, with before/after code that **fails closed**. Every Critical/High class must have a
   drop-in fix.
4. **Wire it into the scan** if it introduces a genuinely new check category — add a line under the
   relevant Phase 3 group in `SKILL.md` and reflect it in the condensed class list inside
   [`prompts/sentinel-master-prompt.md`](prompts/sentinel-master-prompt.md).
5. **Bump the version** (see below) if you touched classifications or the mapping tables.

Prefer proposing the class first via the
[vulnerability-class issue template](.github/ISSUE_TEMPLATE/vulnerability-class.md) so the ID and
scope can be agreed before you write the full entry.

## How to add a stack playbook

Each stack playbook is its own file under
[`skill/references/stack-playbooks/`](skill/references/stack-playbooks/); add a new file there and a row
to the index table in
[`skill/references/stack-playbooks.md`](skill/references/stack-playbooks.md). For an artifact type whose
entry points aren't routes (a browser extension, bot, CLI, or desktop app), add to
[`skill/references/artifact-playbooks.md`](skill/references/artifact-playbooks.md) instead, leading with
its entry-point map. Each playbook has four parts and nothing more:

- **Key** — the one-sentence mental model for how this stack does authorization and trust.
- **Trust model** — where the client/server boundary actually sits, and which keys/roles cross it.
- **Top traps** — the specific, recurring ways vibe-coded apps on this stack bleed, each cross-linked
  to a catalog ID.
- **How to test / verify** — concrete steps to prove a control holds (or doesn't), preferably with a
  command or query.

State plainly that the methodology generalizes; the playbook only encodes the sharp edges. Propose
via the [playbook issue template](.github/ISSUE_TEMPLATE/playbook.md).

## How to improve a remediation

Fixes must be idiomatic for the stack, drop-in, and fail closed (deny by default; an error must not
grant access). If you add a language, keep the *shape* of the fix identical so the general pattern
stays legible. Note any version-specific API (e.g. a Next.js or Supabase client method that changed
between versions).

## How to add a tool

Scanners live in [`skill/references/tooling.md`](skill/references/tooling.md), and they are **advisory by
design**: they generate leads for the Phase 3 scan and never write findings. Keep the existing shape —
what it catches, the exact invocation, the catalog IDs it maps to, and the field most tool documentation
omits: **what it systematically misses.** A tool whose blind spots are undocumented gets trusted past its
competence, which is worse than not running it at all.

Do not propose changes that have SENTINEL run a scanner and transcribe its output into the report. That
inverts the discipline the project exists to enforce — that a finding requires a traced data flow and a
named falsifier.

## Versioning convention

The project version is the skill's `metadata.version` in `skill/SKILL.md`, following
[SemVer](https://semver.org/):

- **PATCH** (`1.0.x`) — wording fixes, new remediation languages, clarifications that change no
  classification.
- **MINOR** (`1.x.0`) — new vulnerability classes or playbooks; **any change to the OWASP / API /
  LLM / CWE mapping tables** (including refreshing to a new edition).
- **MAJOR** (`x.0.0`) — a change to the six-phase workflow or the report output format.

Every version bump gets a [CHANGELOG.md](CHANGELOG.md) entry under a new heading.

## Submitting

1. Fork and branch from `main` (`feat/ssrf-catalog-entry`, `docs/rls-guide-fix`).
2. Keep the change focused — one class, one playbook, or one doc per pull request.
3. Run the repo's own checks before pushing — all of them, since CI runs all of them:
   ```bash
   python scripts/check_repo.py                # links, anchors, class parity, secret shapes
   python scripts/check_standards_currency.py  # cited standards vs. latest editions
   python scripts/check_schema.py              # findings schema + its worked example
   python scripts/check_skill_package.py       # skill name, description limits, semver
   python scripts/check_encoding.py            # mojibake / lost bytes in tracked text
   python -m unittest discover -s validation -p 'test_*.py'   # scoring + schema conformance
   ```
   These are the same checks CI runs ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).
   `check_repo.py` will fail if you add a catalog class without a remediation, or vice versa — that
   invariant is enforced, not merely requested. Also confirm no `.env*` is staged.

   Everything except the last line is standard-library-only. The test suite's schema-conformance
   checks need `jsonschema` (`pip install 'jsonschema>=4.20'`); without it they skip locally, and CI
   sets `SENTINEL_REQUIRE_JSONSCHEMA=1` so a missing validator there is a failure rather than a
   silent pass.
4. Reference the issue you opened, and describe how you verified any code you added actually blocks
   the attack it claims to.

## Editing files on Windows

**Write files with a direct file-write, not a shell heredoc or a PowerShell here-string.**

This project has been bitten twice by the same platform quirk. In v7.0 a PowerShell here-string
mangled a commit message; in v8.0 a cp1252/UTF-8 round trip mojibaked PR bodies, turning every em
dash and curly quote into noise. Both took longer to repair than to cause, and neither was obvious on
review — the file still opened and the prose still read, only the punctuation was wrong.

The cause is that a Windows shell assumes cp1252 while this repo's content is UTF-8. Any text that
passes *through* the shell is at risk; text written straight to disk is not. Concretely:

- Prefer your editor, or a script that calls `Path.write_text(..., encoding="utf-8")`.
- If you must use PowerShell, pass `-Encoding utf8` explicitly — `Set-Content` and `Add-Content`
  default to the system ANSI codepage.
- Do not build multi-line prose (commit messages, PR bodies, docs) inside a `<<EOF` heredoc or a
  `@'...'@` here-string.

`scripts/check_encoding.py` catches the result if it happens anyway, and runs in CI. It reads file
bytes rather than terminal output on purpose: a Windows console renders a *correctly* encoded em dash
as a replacement glyph, so what you see in a terminal is not evidence either way.

Thank you — careful, defensible contributions are what keep this credible.
