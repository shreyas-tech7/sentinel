#!/usr/bin/env python3
"""Draw a blind, stratified, reproducible sample of OWASP Benchmark test cases.

Reads only the test-case name and category columns of expectedresults-1.2.csv —
never the ground-truth flag — so the auditor who analyzes the sampled files is
blind to the expected answer. Scoring happens afterwards, in score.py, which is
the only place the truth column is read.

    python validation/sample_benchmark.py --benchmark-root ../BenchmarkJava \
        --per-category 6 --seed 42 --out validation/data/benchmark-sample.csv

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path


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


def draw(by_category: dict[str, list[str]], per_category: int, seed: int) -> list[tuple[str, str]]:
    rng = random.Random(seed)
    sample: list[tuple[str, str]] = []
    for category in sorted(by_category):
        names = sorted(by_category[category])
        picked = rng.sample(names, min(per_category, len(names)))
        sample.extend((name, category) for name in sorted(picked))
    return sample


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-root", required=True, type=Path)
    parser.add_argument("--per-category", type=int, default=6)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    expected_csv = args.benchmark_root / "expectedresults-1.2.csv"
    if not expected_csv.is_file():
        print(f"error: {expected_csv} not found", file=sys.stderr)
        return 1

    sample = draw(load_cases(expected_csv), args.per_category, args.seed)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["test_name", "category"])
        writer.writerows(sample)

    print(f"wrote {len(sample)} sampled cases to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
