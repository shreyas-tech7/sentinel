# Standards currency manifest

This file records **which edition of each external standard the SENTINEL vulnerability catalog is
currently grounded in.** It is the single source of truth that
[`scripts/check_standards_currency.py`](../../scripts/check_standards_currency.py) reads to flag when a
newer edition has been published and the catalog may be due for a review.

**This manifest does not migrate anything.** Adopting a new edition of a standard — re-checking every
`Classification:` line in `vulnerability-catalog.md`, remapping categories, updating the framework
tables — is a deliberate, reviewed project (it was Task 1 of the v4.0 line of work). The currency check
only raises a flag for a human; it must never rewrite the catalog on its own.

## How to read the table

- **`grounded_edition`** — the edition the catalog currently cites, as it appears in the catalog's
  framework-mapping table and its `Classification:` lines.
- **`latest_known_edition`** — the newest edition the maintainers were aware of *when this manifest was
  last reviewed* (see `last_reviewed`). The check compares the two and flags any row where they differ.
- Updating `latest_known_edition` (e.g. after OWASP publishes a new Top 10) is what *triggers* the flag;
  updating `grounded_edition` is what a maintainer does *after* completing the catalog migration.

<!-- check_standards_currency.py parses the table below. Keep the columns and the `key` values stable. -->

| key | standard | grounded_edition | latest_known_edition | last_reviewed | notes |
|---|---|---|---|---|---|
| owasp_top_10 | OWASP Top 10 | 2021 | 2021 | 2026-07-19 | A 2025 edition is in the OWASP pipeline but not finalized at review time; watch for the stable release. |
| owasp_api_top_10 | OWASP API Security Top 10 | 2023 | 2023 | 2026-07-19 | Current stable edition. |
| owasp_llm_top_10 | OWASP Top 10 for LLM Applications | 2025 | 2025 | 2026-07-19 | Current stable edition (2025). |
| cwe_top_25 | CWE Top 25 Most Dangerous Software Weaknesses | 2024 | 2024 | 2026-07-19 | MITRE publishes annually; expect a 2025 list. |
| cwe_list | MITRE CWE List | 2024 | 2024 | 2026-07-19 | The full CWE dictionary the catalog's CWE-IDs are drawn from. |
| asvs | OWASP ASVS | 4.0 | 4.0 | 2026-07-19 | Application Security Verification Standard; a 5.0 is in development — watch for the stable release. |

## When the check fires

`scripts/check_standards_currency.py` exits non-zero and names any row where `grounded_edition` !=
`latest_known_edition`. That is a **prompt for human review**, not a failure of the catalog: it means
someone bumped `latest_known_edition` to reflect a new publication, and a maintainer should now decide
whether to schedule the catalog migration. To resolve a flag, either complete the migration and update
`grounded_edition`, or (if the new edition is not yet stable) revert the premature
`latest_known_edition` bump.
