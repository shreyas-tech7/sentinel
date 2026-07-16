#!/usr/bin/env python3
"""Structural integrity checks for the SENTINEL repository.

SENTINEL ships no runtime code, so its correctness is the correctness of its
cross-references. This script enforces the invariants that CONTRIBUTING.md states
in prose, and that drifted once already:

  1. Every relative Markdown link resolves to a file that exists.
  2. Every "#anchor" resolves to a real heading in the target file.
  3. Every SENT-* class in the catalog has a remediation with the same ID,
     and every remediation has a catalog entry. (A class is not complete
     until it exists in both.)
  4. No credential-shaped strings are committed.

Standard library only. Exit code 0 = clean, 1 = findings.

    python scripts/check_repo.py [--root .]
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

# ── Slugification ───────────────────────────────────────────────────────────────
# Mirrors GitHub's algorithm: strip inline markdown, downcase, drop punctuation
# (keeping word chars, spaces, hyphens), then spaces -> hyphens. An em dash is
# punctuation, so "SENT-A-01 — Title" yields "sent-a-01--title" (two hyphens).

_INLINE_MD = re.compile(r"`|\*\*|\*|~~")
_MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_NOT_SLUG = re.compile(r"[^\w\- ]", re.UNICODE)


def slugify(heading: str) -> str:
    text = _MD_LINK.sub(r"\1", heading)
    text = _INLINE_MD.sub("", text)
    text = text.strip().lower()
    text = _NOT_SLUG.sub("", text)
    return text.replace(" ", "-")


# ── Markdown parsing (fence-aware) ──────────────────────────────────────────────

_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
# Matches the target of any ](...) construct, which also catches the outer link
# of a nested badge image: [![alt](img)](target)
_LINK_TARGET = re.compile(r"\]\(\s*([^)\s]+)")


def iter_lines(path: Path):
    """Yield (lineno, line, in_fence) for a Markdown file."""
    in_fence = False
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if _FENCE.match(line):
            in_fence = not in_fence
            yield i, line, True
            continue
        yield i, line, in_fence


def headings(path: Path) -> list[str]:
    return [
        m.group(2)
        for _, line, fenced in iter_lines(path)
        if not fenced and (m := _HEADING.match(line))
    ]


def anchors(path: Path) -> set[str]:
    """Heading slugs, with GitHub's -1/-2 disambiguation for duplicates."""
    seen: dict[str, int] = defaultdict(int)
    out: set[str] = set()
    for h in headings(path):
        base = slugify(h)
        n = seen[base]
        seen[base] += 1
        out.add(base if n == 0 else f"{base}-{n}")
    return out


def links(path: Path):
    for lineno, line, fenced in iter_lines(path):
        if fenced:
            continue
        for m in _LINK_TARGET.finditer(line):
            yield lineno, m.group(1)


# ── Checks ──────────────────────────────────────────────────────────────────────

SKIP_SCHEMES = ("http://", "https://", "mailto:", "tel:", "#!")


def check_links(root: Path, md_files: list[Path], errors: list[str]) -> None:
    anchor_cache: dict[Path, set[str]] = {}

    def anchors_for(p: Path) -> set[str]:
        if p not in anchor_cache:
            anchor_cache[p] = anchors(p)
        return anchor_cache[p]

    for md in md_files:
        rel = md.relative_to(root).as_posix()
        for lineno, target in links(md):
            if target.startswith(SKIP_SCHEMES):
                continue

            path_part, _, anchor = target.partition("#")

            if not path_part:  # same-file anchor
                if anchor and anchor not in anchors_for(md):
                    errors.append(f"{rel}:{lineno}: dead anchor '#{anchor}'")
                continue

            dest = (md.parent / path_part).resolve()
            if not dest.exists():
                errors.append(f"{rel}:{lineno}: dead link '{path_part}'")
                continue

            if anchor and dest.suffix == ".md":
                if anchor not in anchors_for(dest):
                    errors.append(
                        f"{rel}:{lineno}: dead anchor '{path_part}#{anchor}'"
                    )


_ID_IN_HEADING = re.compile(r"^(SENT-[A-Z]+-\d+)\b")


def ids_in(path: Path, level: int) -> dict[str, str]:
    """Map SENT-ID -> heading text, for headings at exactly `level`."""
    found: dict[str, str] = {}
    for _, line, fenced in iter_lines(path):
        if fenced:
            continue
        m = _HEADING.match(line)
        if not m or len(m.group(1)) != level:
            continue
        if hit := _ID_IN_HEADING.match(m.group(2)):
            found[hit.group(1)] = m.group(2)
    return found


def check_class_parity(root: Path, errors: list[str]) -> None:
    catalog = root / "skill" / "references" / "vulnerability-catalog.md"
    remedies = root / "skill" / "references" / "remediation-patterns.md"
    for p in (catalog, remedies):
        if not p.exists():
            errors.append(f"missing required file: {p.relative_to(root).as_posix()}")
            return

    cat_ids = set(ids_in(catalog, level=2))
    rem_ids = set(ids_in(remedies, level=3))

    for missing in sorted(cat_ids - rem_ids):
        errors.append(
            f"class parity: {missing} is in the catalog but has no remediation. "
            "A class is not complete until it exists in both."
        )
    for orphan in sorted(rem_ids - cat_ids):
        errors.append(
            f"class parity: {orphan} has a remediation but no catalog entry."
        )


SECRET_PATTERNS = [
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("Stripe live key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("PEM private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}"),
    ),
]

# Documentation legitimately names these shapes when teaching detection.
EXEMPT = re.compile(r"REDACTED|PLACEHOLDER|EXAMPLE|<[A-Z_]+>", re.IGNORECASE)


def check_secrets(root: Path, files: list[Path], errors: list[str]) -> None:
    for f in files:
        rel = f.relative_to(root).as_posix()
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable; gitleaks covers what we can't parse
        for i, line in enumerate(text.splitlines(), 1):
            if EXEMPT.search(line):
                continue
            for label, pat in SECRET_PATTERNS:
                if pat.search(line):
                    errors.append(f"{rel}:{i}: possible committed secret ({label})")


# ── Standards-edition sanity (guards the OWASP 2021→2025 migration) ──────────────
# The catalog classifies every class against a fixed set of standard editions. A
# half-finished edition migration (a stale 2021 code, a mis-paired 2025 name, a
# wrong CWE-Top-25 rank) is a factual error in a security tool — exactly the kind
# of thing the tool tells its users to catch. These checks make it CI-visible.
# The reference data is the OWASP Top 10:2025 and the 2025 CWE Top 25.

OWASP_2025_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# rank -> CWE, from https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
CWE_TOP25_2025 = {
    79: 1, 89: 2, 352: 3, 862: 4, 787: 5, 22: 6, 416: 7, 125: 8, 78: 9, 94: 10,
    120: 11, 434: 12, 476: 13, 121: 14, 502: 15, 122: 16, 863: 17, 20: 18,
    284: 19, 200: 20, 306: 21, 918: 22, 77: 23, 639: 24, 770: 25,
}

_CLASS_MARKER = re.compile(r"-\s+\*\*Classification:\*\*")
_OWASP_2021 = re.compile(r"\bA\d{2}:2021\b")
_OWASP_NAMED = re.compile(r"\bA(\d{2}):2025\s*\(([^)]+)\)")
_CWE_RANK = re.compile(r"\bCWE-(\d+)\b[^)]*?#(\d+)\s+on the 2025 CWE Top 25")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.replace("&", "and")).strip().lower()


def classification_blocks(path: Path):
    """Yield (lineno, joined_text) for each Classification field, joined across wraps."""
    lines = path.read_text(encoding="utf-8").splitlines()
    i, n = 0, len(lines)
    while i < n:
        if _CLASS_MARKER.search(lines[i]):
            buf = [lines[i].strip()]
            j = i + 1
            while (
                j < n
                and lines[j].strip()
                and not lines[j].lstrip().startswith("- **")
                and not lines[j].startswith("#")
            ):
                buf.append(lines[j].strip())
                j += 1
            yield i + 1, " ".join(buf)
            i = j
        else:
            i += 1


def check_catalog_editions(root: Path, errors: list[str]) -> None:
    catalog = root / "skill" / "references" / "vulnerability-catalog.md"
    if not catalog.exists():
        return
    rel = catalog.relative_to(root).as_posix()
    for lineno, text in classification_blocks(catalog):
        for m in _OWASP_2021.finditer(text):
            errors.append(
                f"{rel}:{lineno}: stale OWASP 2021 code '{m.group(0)}' on a "
                "Classification line — the catalog is on the 2025 editions."
            )
        for m in _OWASP_NAMED.finditer(text):
            code, name = "A" + m.group(1), m.group(2).strip()
            # A parenthetical that opens lowercase is a qualifier ("per the control"),
            # not a category name — OWASP category names are Title Case. Skip it.
            if not name[:1].isupper():
                continue
            official = OWASP_2025_NAMES.get(code)
            if official and not _norm(name).startswith(_norm(official)):
                errors.append(
                    f"{rel}:{lineno}: OWASP {code}:2025 is '{official}', "
                    f"but the catalog names it '({name})'."
                )
        for m in _CWE_RANK.finditer(text):
            cwe, rank = int(m.group(1)), int(m.group(2))
            actual = CWE_TOP25_2025.get(cwe)
            if actual is None:
                errors.append(
                    f"{rel}:{lineno}: CWE-{cwe} is annotated '#{rank} on the 2025 "
                    "CWE Top 25' but is not in the 2025 Top 25."
                )
            elif actual != rank:
                errors.append(
                    f"{rel}:{lineno}: CWE-{cwe} is #{actual} on the 2025 CWE Top 25, "
                    f"catalog says #{rank}."
                )


def check_validation_not_stub(root: Path, errors: list[str]) -> None:
    """The validation files must not ship as stubs once v4.0 claims them complete."""
    for name in ("METHODOLOGY.md", "owasp-benchmark-results.md", "juice-shop-results.md"):
        p = root / "validation" / name
        if p.exists() and "Stub —" in p.read_text(encoding="utf-8"):
            errors.append(
                f"validation/{name}: still a stub — the validation pass must fill it in."
            )


# ── Entry point ─────────────────────────────────────────────────────────────────

IGNORE_DIRS = {".git", "node_modules", ".next", "dist", "build", "__pycache__"}

# Everything text-shaped gets the secret scan, not just Markdown: a key in a
# workflow file or a script is exactly as leaked as one in a doc.
TEXT_SUFFIXES = {
    ".md", ".yml", ".yaml", ".py", ".sh", ".toml", ".json", ".txt",
    ".ts", ".js", ".sql", ".cfg", ".ini", ".env", "",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", type=Path)
    args = ap.parse_args()
    root = args.root.resolve()

    in_scope = [
        p
        for p in root.rglob("*")
        if p.is_file() and not IGNORE_DIRS & set(p.relative_to(root).parts)
    ]
    md_files = sorted(p for p in in_scope if p.suffix == ".md")
    text_files = sorted(p for p in in_scope if p.suffix.lower() in TEXT_SUFFIXES)

    if not md_files:
        print(f"no markdown found under {root}", file=sys.stderr)
        return 1

    errors: list[str] = []
    check_links(root, md_files, errors)
    check_class_parity(root, errors)
    check_catalog_editions(root, errors)
    check_validation_not_stub(root, errors)
    check_secrets(root, text_files, errors)

    if errors:
        print(f"FAIL — {len(errors)} problem(s):\n", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    catalog = root / "skill" / "references" / "vulnerability-catalog.md"
    n_classes = len(ids_in(catalog, level=2)) if catalog.exists() else 0
    n_links = sum(1 for md in md_files for _ in links(md))
    print(
        f"OK — {len(md_files)} markdown files, {n_links} links resolved, "
        f"{n_classes} classes with matching remediations, OWASP 2025 / CWE Top-25 "
        f"editions consistent, {len(text_files)} files scanned for secrets."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
