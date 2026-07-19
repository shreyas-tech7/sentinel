#!/usr/bin/env python3
"""Validate that the SENTINEL skill still satisfies the skill-package rules.

These are the packaging constraints the skill was originally published under, now
codified so a version bump or a description edit cannot quietly break them:

  1. Exactly one root SKILL.md (at skill/SKILL.md), and no stray SKILL.md elsewhere.
  2. `name` is kebab-case and is exactly 'security-audit' (invariant per the build spec).
  3. `description` is present, under 1024 characters, and contains no angle brackets.
  4. `metadata.version` is present and semver-shaped.

Standard library only. Exit 0 = valid, 1 = a rule is violated.

    python scripts/check_skill_package.py [--root .]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REQUIRED_NAME = "security-audit"
DESC_MAX = 1024
_KEBAB = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def frontmatter(text: str) -> str | None:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    return m.group(1) if m else None


def scalar(fm: str, key: str) -> str | None:
    # Tolerate indentation so nested keys (e.g. metadata.version) are found too.
    m = re.search(rf"^\s*{re.escape(key)}:\s*(.+)$", fm, re.M)
    if not m:
        return None
    return m.group(1).strip().strip('"')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", type=Path)
    args = parser.parse_args()
    root = args.root

    errors: list[str] = []

    skill_files = sorted(p.relative_to(root).as_posix() for p in root.rglob("SKILL.md"))
    if skill_files != ["skill/SKILL.md"]:
        errors.append(f"expected exactly one root SKILL.md at skill/SKILL.md, found {skill_files}")

    skill_path = root / "skill" / "SKILL.md"
    if not skill_path.is_file():
        print("error: skill/SKILL.md not found", file=sys.stderr)
        return 1

    fm = frontmatter(skill_path.read_text(encoding="utf-8"))
    if fm is None:
        print("error: skill/SKILL.md has no YAML frontmatter", file=sys.stderr)
        return 1

    name = scalar(fm, "name")
    if name is None:
        errors.append("frontmatter missing 'name'")
    else:
        if not _KEBAB.fullmatch(name):
            errors.append(f"name '{name}' is not kebab-case")
        if name != REQUIRED_NAME:
            errors.append(f"name must be '{REQUIRED_NAME}' (invariant), got '{name}'")

    desc = scalar(fm, "description")
    if desc is None:
        errors.append("frontmatter missing 'description'")
    else:
        if len(desc) >= DESC_MAX:
            errors.append(f"description is {len(desc)} chars, must be under {DESC_MAX}")
        if "<" in desc or ">" in desc:
            errors.append("description contains angle brackets")

    version = scalar(fm, "version")
    if version is None:
        errors.append("frontmatter missing 'metadata.version'")
    elif not _SEMVER.match(version):
        errors.append(f"version '{version}' is not semver (X.Y.Z)")

    if errors:
        print("Skill package validation failed:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(
        f"OK — skill package valid: name='{name}', version={version}, "
        f"description {len(desc)} chars, single root SKILL.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
