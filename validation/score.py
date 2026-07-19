#!/usr/bin/env python3
"""Score a set of per-test-case verdicts against OWASP Benchmark ground truth.

Input verdicts are a JSON array of objects:

    [{"test_name": "BenchmarkTest00042", "category": "sqli", "vulnerable": true}, ...]

Only test cases present in the verdicts file are scored (the sampled subset).
The ground-truth flag is read here — and only here — from expectedresults-1.2.csv.

Definitions (per Benchmark convention, per category):
  TP = tool says vulnerable, ground truth says real vulnerability
  FP = tool says vulnerable, ground truth says not a real vulnerability
  FN = tool says not vulnerable (or is silent), ground truth says real
  TN = tool says not vulnerable (or is silent), ground truth says not real

Precision = TP/(TP+FP); Recall = TP/(TP+FN); F1 = harmonic mean. Division by
zero yields None, rendered as "n/a".

    python validation/score.py --benchmark-root ../BenchmarkJava \
        --verdicts validation/data/sentinel-benchmark-verdicts.json [--markdown]

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def load_truth(expected_csv: Path) -> dict[str, tuple[str, bool]]:
    """Return {test_name: (category, is_real_vulnerability)}."""
    truth: dict[str, tuple[str, bool]] = {}
    with expected_csv.open(newline="") as fh:
        reader = csv.reader(fh)
        next(reader)  # header
        for row in reader:
            if len(row) < 3:
                continue
            name = row[0].strip()
            category = row[1].strip()
            real = row[2].strip().lower() == "true"
            truth[name] = (category, real)
    return truth


def load_verdicts(path: Path) -> dict[str, bool]:
    """Return {test_name: tool_says_vulnerable}. Duplicate names are an error."""
    data = json.loads(path.read_text())
    verdicts: dict[str, bool] = {}
    for entry in data:
        name = entry["test_name"]
        if name in verdicts:
            raise ValueError(f"duplicate verdict for {name}")
        verdicts[name] = bool(entry["vulnerable"])
    return verdicts


def score(
    truth: dict[str, tuple[str, bool]], verdicts: dict[str, bool]
) -> dict[str, dict[str, int]]:
    """Per-category confusion counts over exactly the verdict set."""
    counts: dict[str, dict[str, int]] = {}
    for name, says_vulnerable in verdicts.items():
        if name not in truth:
            raise KeyError(f"{name} not present in ground truth")
        category, real = truth[name]
        cell = counts.setdefault(category, {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
        if says_vulnerable and real:
            cell["TP"] += 1
        elif says_vulnerable and not real:
            cell["FP"] += 1
        elif not says_vulnerable and real:
            cell["FN"] += 1
        else:
            cell["TN"] += 1
    return counts


def metrics(cell: dict[str, int]) -> dict[str, float | None]:
    tp, fp, fn = cell["TP"], cell["FP"], cell["FN"]
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def totals(counts: dict[str, dict[str, int]]) -> dict[str, int]:
    total = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for cell in counts.values():
        for key in total:
            total[key] += cell[key]
    return total


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def render_markdown(counts: dict[str, dict[str, int]], label: str) -> str:
    lines = [
        f"| Category | N | TP | FP | FN | TN | Precision | Recall | F1 |",
        f"|---|---|---|---|---|---|---|---|---|",
    ]
    for category in sorted(counts):
        cell = counts[category]
        m = metrics(cell)
        n = sum(cell.values())
        lines.append(
            f"| {category} | {n} | {cell['TP']} | {cell['FP']} | {cell['FN']} | {cell['TN']} "
            f"| {_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1'])} |"
        )
    total = totals(counts)
    m = metrics(total)
    n = sum(total.values())
    lines.append(
        f"| **all ({label})** | {n} | {total['TP']} | {total['FP']} | {total['FN']} | {total['TN']} "
        f"| {_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1'])} |"
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-root", required=True, type=Path)
    parser.add_argument("--verdicts", required=True, type=Path)
    parser.add_argument("--label", default="overall")
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()

    truth = load_truth(args.benchmark_root / "expectedresults-1.2.csv")
    verdicts = load_verdicts(args.verdicts)
    counts = score(truth, verdicts)

    if args.markdown:
        print(render_markdown(counts, args.label))
    else:
        out = {
            category: {**cell, **{k: v for k, v in metrics(cell).items()}}
            for category, cell in sorted(counts.items())
        }
        total = totals(counts)
        out["_total"] = {**total, **metrics(total)}
        json.dump(out, sys.stdout, indent=2)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
