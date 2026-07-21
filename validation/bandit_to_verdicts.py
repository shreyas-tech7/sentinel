#!/usr/bin/env python3
"""Convert a Bandit JSON report into the per-case verdict format `score.py` reads.

Bandit reports issues; the Benchmark asks a per-file question ("is this test case
a real vulnerability?"). The bridge is a flagging convention, and which one you
pick changes the score, so both are produced here rather than one being chosen
silently:

  * **any** -- a file is flagged if Bandit reports >=1 issue of any severity.
    This is the same ">=1 finding = flagged" convention used for the Semgrep Java
    run, and is the default.

  * **medium-plus** -- a file is flagged only on an issue of MEDIUM or HIGH
    severity. Bandit's LOW tier is dominated by `blacklist` import rules (B403
    `import pickle`, B404 `import subprocess`, B406/B408 XML parsers) that fire on
    the *presence of an import*, regardless of whether anything tainted reaches
    it. Counting an import as a vulnerability verdict overstates recall on cases
    the Benchmark marks safe.

Unlike Semgrep's Python run, no category filter is needed: every Bandit rule is a
security rule, so there is no maintainability rule to strip out.

    python validation/bandit_to_verdicts.py \
        --report validation/data/bandit-raw-python-v8.json \
        --sample validation/data/benchmark-sample-python-v6.csv \
        --convention any --out validation/data/bandit-benchmark-python-v8-verdicts.json

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

TEST_NAME_RE = re.compile(r"(BenchmarkTest\d+)\.py$")

CONVENTIONS = {
    "any": lambda issue: True,
    "medium-plus": lambda issue: issue["issue_severity"].upper() in {"MEDIUM", "HIGH"},
}


def load_sample(path: Path) -> list[tuple[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [(row["test_name"], row["category"]) for row in csv.DictReader(handle)]


def issues_by_test(report: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for issue in report["results"]:
        match = TEST_NAME_RE.search(issue["filename"].replace("\\", "/"))
        if not match:
            raise ValueError(f"cannot derive a test name from {issue['filename']!r}")
        grouped.setdefault(match.group(1), []).append(issue)
    return grouped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True, help="Bandit -f json output")
    parser.add_argument("--sample", type=Path, required=True, help="the sampled case list")
    parser.add_argument("--convention", choices=sorted(CONVENTIONS), default="any")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--annotated-out",
        type=Path,
        default=None,
        help="also write verdicts carrying the rule ids that fired",
    )
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))

    # A parse failure is not a clean negative -- it means the file was never
    # analyzed. Refuse to score a run that silently skipped cases.
    if report.get("errors"):
        names = sorted({e.get("filename", "?") for e in report["errors"]})
        print(
            f"error: Bandit reported {len(report['errors'])} file error(s); "
            f"those cases were not analyzed and must not be scored as negatives:\n  "
            + "\n  ".join(names[:10]),
            file=sys.stderr,
        )
        return 1

    sample = load_sample(args.sample)
    grouped = issues_by_test(report)

    unknown = set(grouped) - {name for name, _ in sample}
    if unknown:
        print(f"error: report covers cases not in the sample: {sorted(unknown)}", file=sys.stderr)
        return 1

    keep = CONVENTIONS[args.convention]
    verdicts, annotated = [], []
    for name, category in sample:
        firing = [i for i in grouped.get(name, []) if keep(i)]
        verdicts.append({"test_name": name, "category": category, "vulnerable": bool(firing)})
        rules = sorted({f"{i['test_id']} {i['test_name']}" for i in firing})
        annotated.append(
            {
                "test_name": name,
                "category": category,
                "vulnerable": bool(firing),
                "reason": ("rules fired: " + ", ".join(rules)) if rules else "no rule fired",
            }
        )

    args.out.write_text(json.dumps(verdicts, indent=2) + "\n", encoding="utf-8")
    flagged = sum(1 for v in verdicts if v["vulnerable"])
    print(f"wrote {len(verdicts)} verdicts ({flagged} flagged) to {args.out} [{args.convention}]")
    if args.annotated_out:
        args.annotated_out.write_text(json.dumps(annotated, indent=2) + "\n", encoding="utf-8")
        print(f"wrote annotated verdicts to {args.annotated_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
