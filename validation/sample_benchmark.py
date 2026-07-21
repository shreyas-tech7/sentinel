#!/usr/bin/env python3
"""Draw a blind, stratified, reproducible sample of OWASP Benchmark test cases.

Reads only the test-case name and category columns of the expected-results CSV —
never the ground-truth flag — so the auditor who analyzes the sampled files is
blind to the expected answer. Scoring happens afterwards, in score.py, which is
the only place the truth column is read.

    python validation/sample_benchmark.py --benchmark-root ../BenchmarkJava \
        --per-category 6 --seed 42 --out validation/data/benchmark-sample.csv

Works against either OWASP Benchmark suite; they are separate repositories with
the same CSV schema but different filenames (BenchmarkJava ships
expectedresults-1.2.csv, BenchmarkPython ships expectedresults-0.1.csv). The
file is auto-discovered, or named explicitly with --expected-csv.

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

from score import find_expected_csv


def load_cases(expected_csv: Path) -> dict[str, list[str]]:
    """Return {category: [test names]} reading only columns 0-1 (name, category)."""
    by_category: dict[str, list[str]] = {}
    with expected_csv.open(newline="") as fh:
        reader = csv.reader(fh)
        next(reader)  # header
        for row in reader:
            if len(row) < 2:
                continue
            name, category = row[0].strip(), row[1].strip()
            by_category.setdefault(category, []).append(name)
    return by_category


def load_excluded(paths: list[Path]) -> set[str]:
    """Return the set of test names appearing in previously drawn sample CSVs.

    Reads only the test_name column, so excluding a prior sample never exposes
    the ground-truth flag; blindness is preserved.
    """
    excluded: set[str] = set()
    for path in paths:
        with path.open(newline="") as fh:
            reader = csv.reader(fh)
            next(reader, None)  # header
            for row in reader:
                if row:
                    excluded.add(row[0].strip())
    return excluded


def draw(
    by_category: dict[str, list[str]],
    per_category: int,
    seed: int,
    exclude: set[str] | None = None,
    categories: list[str] | None = None,
) -> list[tuple[str, str]]:
    rng = random.Random(seed)
    exclude = exclude or set()
    sample: list[tuple[str, str]] = []
    wanted = sorted(by_category) if categories is None else sorted(categories)
    for category in wanted:
        names = sorted(n for n in by_category.get(category, []) if n not in exclude)
        picked = rng.sample(names, min(per_category, len(names)))
        sample.extend((name, category) for name in sorted(picked))
    return sample


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-root", required=True, type=Path)
    parser.add_argument("--per-category", type=int, default=6)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--expected-csv",
        type=Path,
        default=None,
        help="ground-truth CSV; auto-discovered inside --benchmark-root when omitted",
    )
    parser.add_argument(
        "--exclude",
        type=Path,
        nargs="*",
        default=[],
        help="previously drawn sample CSVs whose cases must not be redrawn; "
        "reads only the test_name column, so blindness is preserved",
    )
    parser.add_argument(
        "--categories",
        nargs="*",
        default=None,
        help="restrict the draw to these categories (default: every category)",
    )
    args = parser.parse_args()

    try:
        expected_csv = find_expected_csv(args.benchmark_root, args.expected_csv)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        excluded = load_excluded(args.exclude)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    sample = draw(
        load_cases(expected_csv), args.per_category, args.seed, excluded, args.categories
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["test_name", "category"])
        writer.writerows(sample)

    if excluded:
        print(f"excluded {len(excluded)} previously drawn case(s)")
    print(f"wrote {len(sample)} sampled cases to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
