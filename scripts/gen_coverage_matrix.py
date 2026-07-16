#!/usr/bin/env python3
"""Generate ``skill/references/coverage-matrix.md`` from the vulnerability catalog.

The matrix is one table mapping every ``SENT-*`` class to its OWASP 2025 / CWE /
ASVS classification. It is *derived* from the catalog so it can never drift from
the source of truth — hand-editing it is a mistake the ``--check`` mode catches.

    python scripts/gen_coverage_matrix.py [--root .]          # (re)write the file
    python scripts/gen_coverage_matrix.py [--root .] --check   # CI drift gate: exit 1 if stale

Standard library only. Reuses ``check_repo.slugify`` so the anchors it emits are
the exact ones the link checker validates.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_repo import slugify  # noqa: E402  (same-dir sibling, canonical slug logic)

REL_CATALOG = Path("skill/references/vulnerability-catalog.md")
REL_OUT = Path("skill/references/coverage-matrix.md")

# `## SENT-AUTHZ-01 — Broken Object Level Authorization / IDOR`
_HEADING = re.compile(r"(?m)^##\s+((SENT-[A-Z]+-\d+)\s+—\s+(.*?))\s*$")
_OWASP_MAIN = re.compile(r"\bA\d{2}:20\d\d\b")
_API = re.compile(r"\bAPI\d{1,2}:20\d\d\b")
_LLM = re.compile(r"\bLLM\d{2}:20\d\d\b")
_CWE = re.compile(r"\bCWE-\d+\b")
_ASVS_CH = re.compile(r"ch\.\s*(\d+)")

_BANNER = (
    "<!-- GENERATED FILE — do not edit by hand.\n"
    "     Regenerate with: python scripts/gen_coverage_matrix.py\n"
    "     Source of truth: vulnerability-catalog.md -->\n"
)


def _uniq(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _classification_block(body: str) -> str:
    """The Classification field text, joined across its wrapped lines."""
    m = re.search(
        r"-\s+\*\*Classification:\*\*\s*(.*?)(?=\n\s*-\s+\*\*|\n##|\Z)",
        body,
        re.S,
    )
    return " ".join(m.group(1).split()) if m else ""


def build_matrix(catalog_text: str) -> str:
    rows: list[str] = []
    # Split into (heading, body) pairs so each class's Classification is scoped to it.
    parts = re.split(r"(?m)^(##\s+SENT-[A-Z]+-\d+\s+—\s+.*)$", catalog_text)
    for i in range(1, len(parts), 2):
        head_line, body = parts[i], parts[i + 1]
        hm = _HEADING.match(head_line)
        if not hm:
            continue
        full_heading, sent_id, title = hm.group(1), hm.group(2), hm.group(3)
        cls = _classification_block(body)

        owasp = _uniq(_OWASP_MAIN.findall(cls) + _API.findall(cls) + _LLM.findall(cls))
        cwes = _uniq(_CWE.findall(cls))
        asvs = _uniq(f"V{n}" for n in _ASVS_CH.findall(cls))

        anchor = slugify(full_heading)
        id_cell = f"[{sent_id}](vulnerability-catalog.md#{anchor})"
        rows.append(
            f"| {id_cell} | {title} | {', '.join(owasp) or '—'} "
            f"| {', '.join(cwes) or '—'} | {', '.join(asvs) or '—'} |"
        )

    header = (
        "# Coverage Matrix\n\n"
        f"{_BANNER}\n"
        "Every SENTINEL vulnerability class mapped to its standards classification, generated from the\n"
        "[catalog](vulnerability-catalog.md). OWASP uses the 2025 editions (API Security 2023, LLM 2025);\n"
        "CWE and ASVS (5.0) columns list the identifiers each class cites. Click a `SENT-*` id for the full\n"
        "entry — detection guidance, severity tendency, and the cross-linked fix.\n\n"
        f"**{len(rows)} classes.**\n\n"
        "| Class | Title | OWASP / API / LLM | CWE | ASVS 5.0 |\n"
        "|---|---|---|---|---|\n"
    )
    return header + "\n".join(rows) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--check", action="store_true", help="exit 1 if the file is stale; do not write")
    args = ap.parse_args()
    root = args.root.resolve()

    catalog = root / REL_CATALOG
    out = root / REL_OUT
    if not catalog.exists():
        print(f"catalog not found: {catalog}", file=sys.stderr)
        return 1

    generated = build_matrix(catalog.read_text(encoding="utf-8"))

    if args.check:
        current = out.read_text(encoding="utf-8") if out.exists() else ""
        if current != generated:
            print(
                f"FAIL — {REL_OUT.as_posix()} is stale. "
                "Run: python scripts/gen_coverage_matrix.py",
                file=sys.stderr,
            )
            return 1
        print(f"OK — {REL_OUT.as_posix()} is up to date.")
        return 0

    out.write_text(generated, encoding="utf-8")
    n = generated.count("\n| [SENT-")
    print(f"wrote {REL_OUT.as_posix()} — {n} classes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
