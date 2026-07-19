#!/usr/bin/env python3
"""Flag when a SENTINEL-cited standard has a newer published edition.

SENTINEL grounds its vulnerability catalog in public standards (OWASP Top 10,
OWASP API Security Top 10, OWASP Top 10 for LLM Applications, the CWE list and
CWE Top 25, ASVS). Those standards publish new editions on their own schedule,
and a catalog frozen against an old edition slowly loses credibility.

This check does NOT migrate the catalog. Migrating to a new edition — re-checking
every Classification line, remapping categories — is a deliberate, reviewed
project, never something to trigger automatically. This script only compares the
edition the catalog is *grounded in* against the *latest known* edition, both
recorded by hand in references/standards-versions.md, and flags any mismatch for
human review.

It also cross-checks that every standard the manifest tracks is actually cited in
references/vulnerability-catalog.md, so a standard cannot silently fall out of the
catalog while still being marked current in the manifest.

Standard library only. Exit code 0 = in sync, 1 = review needed / inconsistency.

    python scripts/check_standards_currency.py [--root .]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MANIFEST = Path("skill/references/standards-versions.md")
CATALOG = Path("skill/references/vulnerability-catalog.md")

# A manifest row: | key | standard | grounded | latest | last_reviewed | notes |
_ROW = re.compile(r"^\|\s*([a-z0-9_]+)\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|\s*$")

# Substrings we expect to find in the catalog for each tracked key, proving the
# standard is still actually cited there. Kept deliberately loose (edition-year
# agnostic) so this check tests *presence*, not currency — currency is the
# grounded-vs-latest comparison, which is the point of the script.
_CATALOG_MARKERS = {
    "owasp_top_10": ["OWASP Top 10"],
    "owasp_api_top_10": ["API Security Top 10", "API Security"],
    "owasp_llm_top_10": ["LLM Applications", "LLM Top 10", "Top 10 for LLM"],
    "cwe_top_25": ["CWE Top 25"],
    "cwe_list": ["CWE"],
    "asvs": ["ASVS"],
}


def parse_manifest(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        m = _ROW.match(line)
        if not m:
            continue
        key = m.group(1).strip()
        if key == "key":  # header row
            continue
        rows.append(
            {
                "key": key,
                "standard": m.group(2).strip(),
                "grounded": m.group(3).strip(),
                "latest": m.group(4).strip(),
                "last_reviewed": m.group(5).strip(),
                "notes": m.group(6).strip(),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", type=Path)
    args = parser.parse_args()

    manifest_path = args.root / MANIFEST
    catalog_path = args.root / CATALOG

    if not manifest_path.is_file():
        print(f"error: manifest not found at {manifest_path}", file=sys.stderr)
        return 1
    if not catalog_path.is_file():
        print(f"error: catalog not found at {catalog_path}", file=sys.stderr)
        return 1

    rows = parse_manifest(manifest_path.read_text(encoding="utf-8"))
    if not rows:
        print("error: no standard rows parsed from the manifest table", file=sys.stderr)
        return 1

    catalog_text = catalog_path.read_text(encoding="utf-8")

    drift: list[str] = []
    missing_citation: list[str] = []
    incomplete: list[str] = []

    for row in rows:
        if not (row["grounded"] and row["latest"]):
            incomplete.append(f"{row['key']}: grounded_edition/latest_known_edition must both be set")
            continue

        if row["grounded"] != row["latest"]:
            drift.append(
                f"{row['standard']} ({row['key']}): catalog grounded in "
                f"'{row['grounded']}' but latest known edition is '{row['latest']}' "
                f"(manifest last reviewed {row['last_reviewed'] or '?'})"
            )

        markers = _CATALOG_MARKERS.get(row["key"])
        if markers and not any(marker in catalog_text for marker in markers):
            missing_citation.append(
                f"{row['standard']} ({row['key']}): tracked in the manifest but no "
                f"citation found in {CATALOG.name} (looked for {markers})"
            )

    problems = incomplete + missing_citation + drift
    if not problems:
        print(
            f"OK — {len(rows)} standards tracked; every grounded edition matches its "
            f"latest known edition and is still cited in {CATALOG.name}."
        )
        return 0

    if incomplete:
        print("Manifest rows with missing editions:")
        for item in incomplete:
            print(f"  - {item}")
    if missing_citation:
        print("Standards tracked but not cited in the catalog:")
        for item in missing_citation:
            print(f"  - {item}")
    if drift:
        print("Standards with a newer edition than the catalog is grounded in "
              "(HUMAN REVIEW — do not auto-migrate):")
        for item in drift:
            print(f"  - {item}")
        print(
            "\nThis is a prompt to schedule a reviewed catalog migration, not a failure "
            "of the catalog. See skill/references/standards-versions.md."
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
