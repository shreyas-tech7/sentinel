# How to Use SENTINEL

Three ways to run the audit, the different run modes, and how to wire the automatable follow-through into
CI. Pick the entry point that matches your tooling; all three produce the same report format.

## Option A — Install the skill into Claude Code

The skill is a drop-in [Agent Skill](https://code.claude.com/docs/en/skills). Claude invokes it
automatically when you ask about security, or you can name it.

1. Copy the `skill/` directory into your Claude Code skills location so it sits as a folder containing
   `SKILL.md` and its `references/`:
   - **Personal (all projects):** `~/.claude/skills/security-audit/`
   - **Project (shared with your repo):** `.claude/skills/security-audit/`

   ```bash
   # from the SENTINEL repo root, into your personal skills dir
   mkdir -p ~/.claude/skills/security-audit
   cp -r skill/SKILL.md skill/references ~/.claude/skills/security-audit/
   ```

   The result must look like:
   ```
   ~/.claude/skills/security-audit/
   ├── SKILL.md
   └── references/
       ├── vulnerability-catalog.md
       ├── stack-playbooks.md
       ├── remediation-patterns.md
       └── tooling.md
   ```

2. Start (or restart) Claude Code so it picks up the skill. Confirm it's loaded by asking
   `what skills are available?` or checking that a security request triggers it.

3. Invoke it by describing the task — the skill's description is tuned to trigger on audit-shaped
   requests even when you don't say "audit":
   > "Security-review `app/api/`, focus on the Supabase tables and the generate endpoint."

   Claude loads the references on demand as it works the phases.

## Option B — Install into Cursor

Cursor reads project rules from `.cursor/rules/`. Add the skill body as an always-available rule, and
keep the reference files in the repo for Claude/Cursor to open when needed.

1. Save the operating procedure as a rule:
   ```
   .cursor/rules/security-audit.mdc
   ```
   Paste the contents of [`skill/SKILL.md`](../skill/SKILL.md) into it (you can drop the YAML
   frontmatter, or convert it to an `.mdc` header). Set it to apply manually (invoke with `@security-audit`)
   or on-demand rather than always-on, so it only runs when you want a review.

2. Keep `skill/references/` in the repo. When the rule tells the model to "read
   `references/vulnerability-catalog.md`," point Cursor at the file (`@file`) so it has the detail.

3. Invoke in chat: `@security-audit review this file for authorization and secrets issues`, with the
   file(s) attached.

> Any assistant that can follow a system prompt and read attached files works the same way — the skill is
> just structured Markdown.

## Option C — Paste the standalone prompt into any chat model

No skill runtime required. Use the [master prompt](../prompts/sentinel-master-prompt.md) for a whole app
or multi-boundary system, or the [quick audit](../prompts/quick-audit.md) for one file, one diff, or one
endpoint.

1. Copy the fenced prompt block from the file.
2. Paste it into the model, then paste your code (or attach files) and name the entry points you care
   about most.
3. You get the same six-phase report. The standalone prompt inlines a condensed vulnerability list, so
   it's self-contained — though the skill's [references](../skill/references/) carry more detection and
   fix detail if you want to go deeper on a finding.

## Run modes

The methodology is the same; scope it to the situation:

| Mode | When | How |
|---|---|---|
| **Full audit** | A whole app, before a launch or a big change | Full skill or master prompt. Expect all six phases and a complete report. Give it the stack and the sensitive entry points up front. |
| **Quick / single-file** | A pull-request diff, one handler, one query | [`quick-audit.md`](../prompts/quick-audit.md). Collapses to a focused pass with the same finding format. |
| **Targeted** | "Just check authorization" / "just secrets" | Full skill, but tell it which classes to prioritize. It still orients and threat-models, just weights the scan. |
| **Regression pass** | "Did my last 20 commits weaken anything?" | Full skill on a repo *with git history* — Phase 4 is the point of the run. Without history it degrades to a static pass, and the report says so. |
| **Large codebase** | Too big for one pass | The skill flags global patterns, audits what it's given, and *names what it did not review*, then asks for the next files in sequence. Never assume silence means clean — see [methodology.md](methodology.md#handling-large-codebases). |

**Reading the report:** findings are ordered Critical → Low, each with a **severity** (how bad) and a
separate **confidence** (how sure). Fix Critical/High first; use confidence to decide what needs a second
look or runtime verification. Below-High-confidence findings name their own *falsifier* — the policy or
file that would close the item out — so start there.

*Code Health Notes* collects structural observations that are not security findings; it explains why the
codebase is hard to secure and never inflates the severity counts. The report then ends with *Residual
Risk* — the review's own blind spots, which are part of the deliverable, not an afterthought.

## Wire the follow-through into CI

An audit is a point-in-time review. Two of its recommendations are automatable and should run on every
change so regressions are caught without a human in the loop. These are the *floor*, not a replacement for
review — they catch two specific classes so a human can spend attention on authorization and logic.

1. **Secret scanning** — fail the build on any committed credential. This catches the most common
   vibe-coding mistake: a `.env` or hard-coded key committed by accident (catalog
   [SENT-SECRET-01](../skill/references/vulnerability-catalog.md#sent-secret-01--hard-coded-or-client-exposed-secrets)).
2. **Dependency audit** — flag known-vulnerable dependencies, and review new/renamed packages by hand for
   the ones audit tools miss — hallucinated or typosquatted names (catalog
   [SENT-SUPPLY-01](../skill/references/vulnerability-catalog.md#sent-supply-01--unpinned-or-unmaintained-dependencies),
   [SENT-SUPPLY-02](../skill/references/vulnerability-catalog.md#sent-supply-02--hallucinated-or-typosquatted-packages)).

A ready-to-use GitHub Actions workflow (Gitleaks + `npm audit`) and a local pre-push equivalent are in
[`.github/workflows/ci.md`](../.github/workflows/ci.md). For Supabase apps, add a **cross-tenant
authorization test** to CI as well — the two-account test in the
[RLS guide](supabase-rls-guide.md#how-to-test-that-a-policy-actually-blocks-cross-tenant-reads) —
so a future change can't silently reopen an RLS hole. That third check is the only one of the three that
tests the class which actually breaks these apps, and no scanner will write it for you.

The wider toolchain — per-ecosystem scanners, the grep pack, the git-archaeology commands behind Phase 4,
and a JSON/SARIF finding schema for feeding results into CI — is in
[`skill/references/tooling.md`](../skill/references/tooling.md). Its governing rule is worth repeating
before you wire anything up: **tools produce leads, the audit produces findings.** A clean scanner run is
not evidence of safety; it is evidence that the scanner's rules did not match.

## After the audit

- Fix Critical and High findings first; each ships with drop-in code. Apply the fix, then re-run the
  relevant [quick audit](../prompts/quick-audit.md) on the changed file to confirm it closed.
- Turn the *Systemic Recommendations* into tracked work (a Data Access Layer, centralized authz, schema
  validation at every boundary) — those prevent whole classes, not single findings.
- Re-audit after significant changes. Security is a property of the current code, not a certificate you
  earn once.
