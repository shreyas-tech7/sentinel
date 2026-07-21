#!/usr/bin/env python3
"""Loud guards against silently scoring fewer cases than were asked for.

Three separate near-misses have now been caught by hand rather than by the
harness:

  * v7.0 — a guessed file path returned zero matches, and the scorer happily
    scored the empty set.
  * v8.0 — a file list written with CRLF line endings left a stray `\\r` on every
    path, so the scanner opened nothing and reported no findings.
  * v8.0 — 28 files failed to parse under the wrong interpreter version and were
    absent from the tool's report, which the converter would have turned into 28
    clean negatives.

Each one looked like a clean run: exit code 0, a plausible table, a number that
nobody could tell was wrong by reading it. Every one was caught because a human
thought a figure looked off, not because anything here objected.

The shared shape is a count. N cases go in, fewer than N come out, and nothing
says so. These helpers make that shape raise.

They are deliberately fatal rather than warning-level. A warning printed above a
results table is precisely what the last three incidents would have produced,
and precisely what would have been read past on the way to the F1 column.

Standard library only.
"""

from __future__ import annotations

__all__ = [
    "CaseCountMismatch",
    "require_count",
    "require_exact_cases",
    "require_clean_names",
]

# How many missing/unexpected names to name before truncating the message.
_SHOW = 10


class CaseCountMismatch(RuntimeError):
    """Raised when a harness step processed a different case set than it was given."""


def _listing(names: list[str]) -> str:
    head = ", ".join(names[:_SHOW])
    if len(names) > _SHOW:
        head += f", ... (+{len(names) - _SHOW} more)"
    return head


def require_count(processed: int, expected: int, what: str) -> None:
    """Assert a step handled exactly `expected` cases.

    Use where the identities are not available but the arithmetic is — a raw
    tool report, a row count, a file tally.
    """
    if processed != expected:
        raise CaseCountMismatch(
            f"{what}: processed {processed} case(s) but was asked for {expected}. "
            f"A short count means cases were skipped, not that they were clean; "
            f"scoring this run would understate the missing cases as negatives."
        )


def require_exact_cases(processed, expected, what: str) -> None:
    """Assert a step handled exactly the case set it was given, by name.

    Stronger than `require_count` and preferred wherever names exist: it catches
    a substitution (one case dropped, another duplicated) that leaves the total
    intact, and it names the specific cases that went missing so the cause is
    diagnosable rather than merely detected.
    """
    processed, expected = set(processed), set(expected)
    if processed == expected:
        return

    problems = []
    missing = sorted(expected - processed)
    unexpected = sorted(processed - expected)
    if missing:
        problems.append(f"{len(missing)} asked-for case(s) never processed: {_listing(missing)}")
    if unexpected:
        problems.append(f"{len(unexpected)} case(s) processed but not asked for: {_listing(unexpected)}")

    raise CaseCountMismatch(
        f"{what}: case set does not match. " + "; ".join(problems) + ". "
        f"Unprocessed cases must not be scored as negatives."
    )


def require_clean_names(names, source: str) -> None:
    """Reject case names carrying stray whitespace or control characters.

    The v8.0 CRLF incident produced names like `BenchmarkTest00042\\r`. Those are
    not equal to the real name, so every downstream lookup silently missed and
    the scan covered nothing. A name that differs from its stripped form is
    always a file-format bug upstream, never a real case id.
    """
    dirty = sorted(n for n in names if n != n.strip())
    if dirty:
        raise CaseCountMismatch(
            f"{source}: {len(dirty)} case name(s) carry stray whitespace — "
            f"{_listing([repr(n) for n in dirty])}. This is the signature of a file "
            f"written with the wrong line endings; every lookup on these names will "
            f"miss and the affected cases will score as silent negatives."
        )
