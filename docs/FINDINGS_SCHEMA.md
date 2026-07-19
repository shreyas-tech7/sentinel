# SENTINEL Findings Schema

SENTINEL's primary output is a prose security report (the format under "Output format" in
[`../skill/SKILL.md`](../skill/SKILL.md)). That report is written for a human and is never replaced by
anything here. This document describes an **additional, optional** machine-readable serialization of
the same findings, so that other tools can consume a SENTINEL finding without parsing Markdown.

The contract is [`../schema/finding.schema.json`](../schema/finding.schema.json) — a JSON Schema
(draft 2020-12).

## What this is, and what it is not

- **It is a stable, versioned contract.** `schema_version` starts at `"1.0"`. Additive, backward-
  compatible changes bump the minor version; a breaking change bumps the major, and a consumer that
  does not recognize the major version should reject the payload.
- **It is a view over the prose report, not a second analysis.** Every exported finding corresponds to
  one finding already written in the Phase 5 "Findings" section, with identical severity, confidence,
  classification, and wording. Serialization re-decides nothing.
- **It is consumed by others; SENTINEL does not call into them.** This schema exists so that
  **Gauntlet** (which has a "SENTINEL findings mapping" step, with a fallback fixture generator for
  when no schema exists — this is that schema) and **ReconBrief** (whose two-layer `NormalizedFinding`
  ingestion this is shaped to map cleanly onto) can ingest SENTINEL output. Writing the consumer side
  in either of those projects is **out of scope for SENTINEL** — SENTINEL only publishes the contract.
  SENTINEL performs no live execution and takes no action against any target as part of producing this
  export; it is the same static, report-only tool it always is.

## Shape

A SENTINEL export is a JSON **array** of finding objects. Each object has these fields (see the schema
for exact types, constraints, and per-field docs):

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | `"1.0"` today. |
| `id` | yes | Stable within a report; recommended `SENT-<CLASS>-NN-<counter>`. |
| `title` | yes | The finding heading, minus the severity tag. |
| `severity` | yes | `Critical` / `High` / `Medium` / `Low` — SENTINEL's rubric. |
| `confidence` | yes | `High` / `Medium` / `Low` — orthogonal to severity. |
| `classification` | yes | Structured: `sentinel_class`, `owasp[]`, **`cwe[]` (integers, ≥1)**. OWASP and CWE are **separate fields**, never one concatenated string. |
| `location` | yes | `file` (required), `line`, `function_or_endpoint`. |
| `analysis` | yes | What the flaw is and why it exists. |
| `attack_scenario` | yes | Concrete, minimal, defense-oriented — never weaponized. |
| `impact` | yes | What is lost/controlled and the blast radius. |
| `remediation_summary` | yes | The fix in prose. |
| `remediation_code` | no | `{ language, before, after }` — the drop-in fix for Critical/High. |
| `falsifier` | no | What, if present elsewhere, would void the finding. Populate below High confidence. |
| `references` | no | External URLs. |

### Why the fields are shaped this way

The field names are deliberately generic and self-explanatory so they map onto a normalized finding
model (such as ReconBrief's `NormalizedFinding`) without guessing at another project's internals:
`id`, `title`, `severity`, `confidence`, a nested `classification` with separate taxonomy axes, and a
nested `location` with `file` / `line`. Keeping `owasp` and `cwe` as distinct arrays — and `cwe` as
integers — lets a consumer filter or join on either taxonomy independently, which a single
`"A01:2021 · CWE-639"` string makes impossible.

## Worked example

A single finding — the basket IDOR from
[`../validation/juice-shop-results.md`](../validation/juice-shop-results.md) — serialized to the
contract:

```json
[
  {
    "schema_version": "1.0",
    "id": "SENT-AUTHZ-01-001",
    "title": "Broken object-level authorization on basket retrieval",
    "severity": "High",
    "confidence": "High",
    "classification": {
      "sentinel_class": "SENT-AUTHZ-01",
      "owasp": ["A01:2021", "API1:2023"],
      "cwe": [639]
    },
    "location": {
      "file": "routes/basket.ts",
      "line": 18,
      "function_or_endpoint": "GET /rest/basket/:id (retrieveBasket)"
    },
    "analysis": "The route is authenticated (isAuthorized on /rest/basket) but the handler loads the basket by the path id alone and never compares it to the caller's user id, so authentication passed while object-level authorization was never checked.",
    "attack_scenario": "A logged-in user whose own basket is 1 requests GET /rest/basket/2 and receives another customer's basket contents.",
    "impact": "Horizontal cross-tenant read of any basket by incrementing an id; every customer's basket is exposed to every authenticated user.",
    "remediation_summary": "Scope the lookup to the authenticated user's id and return 404 on miss, so ownership is enforced at the data layer.",
    "remediation_code": {
      "language": "typescript",
      "before": "const basket = await BasketModel.findOne({ where: { id }, include: [...] })",
      "after": "const basket = await BasketModel.findOne({ where: { id, UserId: (req as any).user.id }, include: [...] })\nif (!basket) { res.status(404).json({ error: 'Basket not found' }); return }"
    },
    "falsifier": "An upstream ownership middleware or a user-scoped where clause on the live path would make this a non-issue; neither is present.",
    "references": ["https://owasp.org/www-project-juice-shop/"]
  }
]
```

## Validating an export

Any draft-2020-12 validator works. For example, with Python's `jsonschema`:

```python
import json
from jsonschema import Draft202012Validator

schema = json.load(open("schema/finding.schema.json"))
findings = json.load(open("export.json"))      # a JSON array of findings

validator = Draft202012Validator(schema)
for i, finding in enumerate(findings):
    errors = sorted(validator.iter_errors(finding), key=lambda e: e.path)
    for e in errors:
        print(f"finding[{i}]: {list(e.path)}: {e.message}")
```

An empty error stream means the export conforms to the contract.
