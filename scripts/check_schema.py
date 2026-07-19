#!/usr/bin/env python3
"""Smoke-check the SENTINEL findings schema and its documented worked example.

Full JSON Schema validation belongs to a real draft-2020-12 validator (see
docs/FINDINGS_SCHEMA.md). This script is the stdlib-only guard that runs in CI:
it proves the schema file is well-formed and self-consistent, and that the worked
example embedded in docs/FINDINGS_SCHEMA.md still satisfies the schema's required
fields and enums — so the docs and the contract cannot silently drift apart.

Standard library only. Exit 0 = consistent, 1 = problem.

    python scripts/check_schema.py [--root .]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = Path("schema/finding.schema.json")
DOC = Path("docs/FINDINGS_SCHEMA.md")


def load_schema(path: Path) -> dict:
    schema = json.loads(path.read_text(encoding="utf-8"))
    for key in ("$schema", "type", "properties", "required"):
        if key not in schema:
            raise ValueError(f"schema missing top-level '{key}'")
    if schema["type"] != "object":
        raise ValueError("top-level schema type must be 'object'")
    # every required field must be described in properties
    undocumented = [f for f in schema["required"] if f not in schema["properties"]]
    if undocumented:
        raise ValueError(f"required fields not in properties: {undocumented}")
    return schema


def first_json_array(markdown: str) -> list:
    """Return the first ```json fenced block in the doc that parses as a list."""
    for block in re.findall(r"```json\s*(.*?)```", markdown, re.DOTALL):
        try:
            data = json.loads(block)
        except json.JSONDecodeError:
            continue
        if isinstance(data, list):
            return data
    raise ValueError("no ```json array block found in the doc")


def check_instance(finding: dict, schema: dict) -> list[str]:
    """Lightweight conformance check: required fields present, enums honored,
    classification.cwe is a non-empty list of ints. Not a full validator."""
    errors: list[str] = []
    for field in schema["required"]:
        if field not in finding:
            errors.append(f"missing required field '{field}'")

    def enum_of(field: str) -> list[str]:
        return schema["properties"].get(field, {}).get("enum", [])

    for field in ("severity", "confidence"):
        allowed = enum_of(field)
        if allowed and finding.get(field) not in allowed:
            errors.append(f"{field}='{finding.get(field)}' not in {allowed}")

    if finding.get("schema_version") != "1.0":
        errors.append(f"schema_version should be '1.0', got {finding.get('schema_version')!r}")

    classification = finding.get("classification", {})
    cwe = classification.get("cwe")
    if not isinstance(cwe, list) or not cwe:
        errors.append("classification.cwe must be a non-empty list")
    elif not all(isinstance(n, int) for n in cwe):
        errors.append("classification.cwe entries must be integers")

    location = finding.get("location", {})
    if "file" not in location:
        errors.append("location.file is required")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", type=Path)
    args = parser.parse_args()

    schema_path = args.root / SCHEMA
    doc_path = args.root / DOC
    if not schema_path.is_file():
        print(f"error: schema not found at {schema_path}", file=sys.stderr)
        return 1
    if not doc_path.is_file():
        print(f"error: doc not found at {doc_path}", file=sys.stderr)
        return 1

    try:
        schema = load_schema(schema_path)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"schema error: {exc}", file=sys.stderr)
        return 1

    try:
        examples = first_json_array(doc_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"doc error: {exc}", file=sys.stderr)
        return 1

    all_errors: list[str] = []
    for i, finding in enumerate(examples):
        for err in check_instance(finding, schema):
            all_errors.append(f"example[{i}]: {err}")

    if all_errors:
        print("Worked example does not conform to the schema:")
        for err in all_errors:
            print(f"  - {err}")
        return 1

    print(
        f"OK — schema well-formed ({len(schema['required'])} required fields); "
        f"{len(examples)} documented example finding(s) conform."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
