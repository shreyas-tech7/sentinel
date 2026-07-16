#!/usr/bin/env python3
"""Score SENTINEL findings against public ground truth.

SENTINEL's accuracy claims are only worth as much as the ground truth they are
checked against. This scorer ingests a SENTINEL findings file (JSON, in the
schema defined under "Machine-readable findings" in
``skill/references/tooling.md``) and a ground-truth labels file, then reports a
confusion matrix (TP / FP / FN / TN) and the derived metrics: precision, recall,
specificity, F1, Youden's J, and — because this tool is deliberately
false-negative-averse — the false-negative rate.

Two ground-truth adapters, selected with ``--format``:

  benchmark    OWASP Benchmark ``expectedresults-*.csv``. Per-test-case labels
               (a real-vulnerability boolean and a CWE per ``BenchmarkTestNNNNN``).
               A finding matches a case by its test-case id, optionally also
               requiring a CWE match (``--match-cwe``). This is a true per-case
               TP/FP/FN/TN measurement.

  juice-shop   An OWASP Juice Shop challenge list (id / name / category / cwe).
               Juice Shop is app-shaped, not per-file-labeled, so this adapter
               measures RECALL OVER CHALLENGE CLASSES — which challenges'
               underlying weakness a static review surfaces — NOT a per-line
               TP/FP rate. FP and TN are therefore reported as n/a; see the
               module comment on ``score_juice_shop`` for why.

Standard library only. Exit code 0 on a successful scoring run, 1 on an input
error (missing file, unparseable truth, no usable label column).

    python validation/score.py --findings f.json --truth g.csv --format benchmark
    python validation/score.py --findings f.json --truth c.json --format juice-shop --json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

# A SENTINEL finding references a Benchmark case by carrying its id somewhere in
# a location/title field, e.g. ``.../testcode/BenchmarkTest00042.java``. Case is
# folded so "benchmarktest00042" and "BenchmarkTest00042" compare equal.
_TESTCASE = re.compile(r"benchmarktest0*\d+", re.IGNORECASE)
_CWE_NUM = re.compile(r"\d+")


# ── Findings ────────────────────────────────────────────────────────────────────


def load_findings(path: Path) -> list[dict[str, Any]]:
    """Load a findings file: a JSON array, or an object with a ``findings`` key."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if not isinstance(data, list):
        raise ValueError(
            "findings file must be a JSON array of findings, or an object with a "
            "'findings' array"
        )
    return [f for f in data if isinstance(f, dict)]


def _finding_strings(finding: dict[str, Any]) -> Iterable[str]:
    """Yield the string fields of a finding where a case id may legitimately live."""
    loc = finding.get("location") or {}
    if isinstance(loc, dict):
        for key in ("file", "symbol", "test_case", "case", "case_id"):
            val = loc.get(key)
            if isinstance(val, str):
                yield val
    for key in ("title", "test_case", "case", "case_id", "target"):
        val = finding.get(key)
        if isinstance(val, str):
            yield val


def finding_test_ids(finding: dict[str, Any]) -> set[str]:
    """Case-folded Benchmark test-case ids referenced by a finding."""
    ids: set[str] = set()
    for text in _finding_strings(finding):
        for m in _TESTCASE.finditer(text):
            ids.add(m.group(0).lower())
    return ids


def finding_cwes(finding: dict[str, Any]) -> set[int]:
    """Integer CWE ids from ``classification.cwe`` (e.g. 'CWE-89' -> 89)."""
    out: set[int] = set()
    classification = finding.get("classification") or {}
    raw = classification.get("cwe") if isinstance(classification, dict) else None
    if isinstance(raw, str):
        raw = [raw]
    for item in raw or []:
        m = _CWE_NUM.search(str(item))
        if m:
            out.add(int(m.group(0)))
    return out


# ── Metrics ─────────────────────────────────────────────────────────────────────


def _safe_div(numerator: float, denominator: float) -> float:
    """Division that returns 0.0 instead of raising on a zero denominator."""
    return numerator / denominator if denominator else 0.0


@dataclass
class Metrics:
    """Derived metrics. ``specificity``/``youden_j`` are None for coverage-only runs."""

    precision: float
    recall: float
    f1: float
    false_negative_rate: float
    specificity: Optional[float]
    youden_j: Optional[float]

    def as_dict(self) -> dict[str, Optional[float]]:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "specificity": None if self.specificity is None else round(self.specificity, 4),
            "youden_j": None if self.youden_j is None else round(self.youden_j, 4),
        }


@dataclass
class Result:
    """A scored confusion matrix plus context.

    ``fp`` and ``tn`` are None for the juice-shop adapter, which measures coverage
    (recall) only and has no per-line negative to score.
    """

    adapter: str
    tp: int
    fn: int
    fp: Optional[int]
    tn: Optional[int]
    cases_scored: int
    findings_total: int
    findings_matched: int
    findings_unmatched: int
    match_rule: str
    uncovered: list[str] = field(default_factory=list)

    def metrics(self) -> Metrics:
        fp = self.fp or 0
        tn = self.tn
        precision = _safe_div(self.tp, self.tp + fp)
        recall = _safe_div(self.tp, self.tp + self.fn)
        f1 = _safe_div(2 * precision * recall, precision + recall)
        fnr = _safe_div(self.fn, self.tp + self.fn)
        if tn is None:  # coverage-only adapter: specificity is undefined
            specificity: Optional[float] = None
            youden: Optional[float] = None
        else:
            specificity = _safe_div(tn, tn + fp)
            youden = recall + specificity - 1
        return Metrics(precision, recall, f1, fnr, specificity, youden)

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "match_rule": self.match_rule,
            "confusion_matrix": {
                "tp": self.tp,
                "fn": self.fn,
                "fp": self.fp,
                "tn": self.tn,
            },
            "cases_scored": self.cases_scored,
            "findings": {
                "total": self.findings_total,
                "matched": self.findings_matched,
                "unmatched": self.findings_unmatched,
            },
            "uncovered": self.uncovered,
            "metrics": self.metrics().as_dict(),
        }


# ── OWASP Benchmark adapter ──────────────────────────────────────────────────────


@dataclass
class BenchmarkCase:
    test_id: str  # canonical (as written in the truth file)
    category: str
    real: bool
    cwe: Optional[int]


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"true", "t", "1", "yes", "y"}


def parse_benchmark_truth(path: Path) -> dict[str, BenchmarkCase]:
    """Parse an OWASP Benchmark ``expectedresults-*.csv`` into case-folded rows.

    The file's first line is a comment header ("# test name, category, real
    vulnerability, cwe, ..."). Columns are located by name so column order and
    trailing metadata columns do not matter; if no header is recognised the
    parser falls back to positional columns (name, category, real, cwe).
    """
    rows = list(csv.reader(path.read_text(encoding="utf-8").splitlines()))
    rows = [r for r in rows if r and any(cell.strip() for cell in r)]
    if not rows:
        raise ValueError(f"{path.name}: no rows")

    header = list(rows[0])
    header[0] = header[0].lstrip("#").strip()
    lowered = [c.strip().lower() for c in header]

    def find(*needles: str) -> Optional[int]:
        for i, cell in enumerate(lowered):
            if any(n in cell for n in needles):
                return i
        return None

    is_header = any(
        n in " ".join(lowered) for n in ("test name", "category", "real vulnerability")
    )
    if is_header:
        i_name = find("test name", "name")
        i_cat = find("category")
        i_real = find("real vulnerability", "real")
        i_cwe = find("cwe")
        data = rows[1:]
    else:  # no header: assume the documented positional order
        i_name, i_cat, i_real, i_cwe = 0, 1, 2, 3
        data = rows

    if i_name is None or i_real is None:
        raise ValueError(
            f"{path.name}: could not locate the test-name and real-vulnerability "
            "columns; is this an OWASP Benchmark expectedresults CSV?"
        )

    truth: dict[str, BenchmarkCase] = {}
    for row in data:
        if len(row) <= max(i for i in (i_name, i_cat, i_real, i_cwe) if i is not None):
            continue
        test_id = row[i_name].strip()
        if not _TESTCASE.fullmatch(test_id):
            continue  # skip stray/comment lines
        cwe_val: Optional[int] = None
        if i_cwe is not None and i_cwe < len(row):
            m = _CWE_NUM.search(row[i_cwe])
            cwe_val = int(m.group(0)) if m else None
        truth[test_id.lower()] = BenchmarkCase(
            test_id=test_id,
            category=(row[i_cat].strip() if i_cat is not None and i_cat < len(row) else ""),
            real=_truthy(row[i_real]),
            cwe=cwe_val,
        )
    if not truth:
        raise ValueError(f"{path.name}: parsed zero BenchmarkTest cases")
    return truth


def score_benchmark(
    findings: list[dict[str, Any]],
    truth: dict[str, BenchmarkCase],
    match_cwe: bool = False,
) -> Result:
    """Confusion matrix over per-case Benchmark labels.

    A case is *flagged* if some finding references its test id (and, when
    ``match_cwe`` is set, also shares its CWE). Then per case:
    real & flagged -> TP, real & unflagged -> FN, !real & flagged -> FP,
    !real & unflagged -> TN. Findings whose test id is absent from the truth
    file are counted as unmatched and excluded from the matrix.
    """
    # Map every referenced test id to the CWEs the finding(s) asserted for it.
    flagged_cwes: dict[str, set[int]] = {}
    matched_findings = 0
    unmatched_findings = 0
    for finding in findings:
        ids = finding_test_ids(finding)
        if not ids:
            unmatched_findings += 1
            continue
        cwes = finding_cwes(finding)
        hit = False
        for tid in ids:
            if tid in truth:
                flagged_cwes.setdefault(tid, set()).update(cwes)
                hit = True
        if hit:
            matched_findings += 1
        else:
            unmatched_findings += 1

    def is_flagged(tid: str, case: BenchmarkCase) -> bool:
        if tid not in flagged_cwes:
            return False
        if not match_cwe or case.cwe is None:
            return True
        return case.cwe in flagged_cwes[tid]

    tp = fp = fn = tn = 0
    for tid, case in truth.items():
        flagged = is_flagged(tid, case)
        if case.real and flagged:
            tp += 1
        elif case.real and not flagged:
            fn += 1
        elif not case.real and flagged:
            fp += 1
        else:
            tn += 1

    return Result(
        adapter="benchmark",
        tp=tp,
        fn=fn,
        fp=fp,
        tn=tn,
        cases_scored=len(truth),
        findings_total=len(findings),
        findings_matched=matched_findings,
        findings_unmatched=unmatched_findings,
        match_rule="test-case id + CWE" if match_cwe else "test-case id",
    )


# ── OWASP Juice Shop adapter ─────────────────────────────────────────────────────
#
# Juice Shop is a running application, not a corpus of per-file-labelled test
# cases. There is no "line 12 is/ isn't a vulnerability" oracle to score against,
# so a per-line TP/FP/TN rate is not meaningful here. What the challenge list DOES
# give us is a class-level oracle: each challenge names a concrete weakness with a
# category and (usually) a CWE. So this adapter asks a narrower, honest question —
# for how many challenge classes does SENTINEL's static review surface the
# underlying weakness? That is RECALL over challenge classes. FP and TN are left
# as None: without a labelled negative set, any "false positive" count would be an
# artefact of the finding set, not a property of the target.


@dataclass
class Challenge:
    ident: str
    name: str
    category: str
    cwe: Optional[int]


def parse_juice_shop_truth(path: Path) -> list[Challenge]:
    """Parse a Juice Shop challenge list from JSON (array of objects) or CSV."""
    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and "challenges" in raw:
            raw = raw["challenges"]
        records = raw if isinstance(raw, list) else []
    else:
        records = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))

    challenges: list[Challenge] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        low = {str(k).strip().lower(): v for k, v in rec.items()}
        cwe_raw = low.get("cwe")
        cwe: Optional[int] = None
        if cwe_raw not in (None, ""):
            m = _CWE_NUM.search(str(cwe_raw))
            cwe = int(m.group(0)) if m else None
        challenges.append(
            Challenge(
                ident=str(low.get("id", low.get("key", ""))).strip(),
                name=str(low.get("name", "")).strip(),
                category=str(low.get("category", "")).strip(),
                cwe=cwe,
            )
        )
    if not challenges:
        raise ValueError(f"{path.name}: parsed zero challenges")
    return challenges


def _category_tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 3}


def score_juice_shop(
    findings: list[dict[str, Any]], challenges: list[Challenge]
) -> Result:
    """Recall over challenge classes: how many challenges' weakness is surfaced.

    A challenge is *covered* when some finding shares its CWE. When a challenge
    carries no CWE, the adapter falls back to a conservative category-keyword
    overlap against the findings' OWASP category strings and titles. This
    fallback is deliberately weak — CWE is the reliable signal; it exists only so
    a CWE-less challenge is not silently un-scorable.
    """
    all_cwes: set[int] = set()
    category_text: set[str] = set()
    for finding in findings:
        all_cwes |= finding_cwes(finding)
        classification = finding.get("classification") or {}
        for owasp in (classification.get("owasp") or []) if isinstance(classification, dict) else []:
            category_text |= _category_tokens(str(owasp))
        title = finding.get("title")
        if isinstance(title, str):
            category_text |= _category_tokens(title)

    covered = 0
    uncovered: list[str] = []
    for ch in challenges:
        hit = ch.cwe is not None and ch.cwe in all_cwes
        if not hit and ch.cwe is None:  # CWE-less: weak category fallback
            hit = bool(_category_tokens(ch.category) & category_text)
        if hit:
            covered += 1
        else:
            uncovered.append(ch.name or ch.ident)

    return Result(
        adapter="juice-shop",
        tp=covered,
        fn=len(challenges) - covered,
        fp=None,
        tn=None,
        cases_scored=len(challenges),
        findings_total=len(findings),
        findings_matched=covered,
        findings_unmatched=0,
        match_rule="CWE class coverage (category fallback)",
        uncovered=uncovered,
    )


# ── Presentation ─────────────────────────────────────────────────────────────────


def _fmt(value: Optional[float]) -> str:
    return "   n/a" if value is None else f"{value:6.4f}"


def _cell(value: Optional[int]) -> str:
    return " n/a" if value is None else f"{value:>4}"


def render(result: Result, findings_path: Path, truth_path: Path) -> str:
    m = result.metrics()
    line = "-" * 60
    out: list[str] = []
    out.append(f"SENTINEL validation - {result.adapter} adapter")
    out.append(f"findings file: {findings_path}")
    out.append(f"truth file:    {truth_path}")
    out.append(f"match rule:    {result.match_rule}")
    out.append(line)
    out.append("Confusion matrix")
    out.append("                    flagged   not flagged")
    out.append(f"  real vuln        {_cell(result.tp)}        {_cell(result.fn)}")
    out.append(f"  not vuln         {_cell(result.fp)}        {_cell(result.tn)}")
    if result.fp is None:
        out.append("  (coverage-only adapter: FP/TN not applicable - see METHODOLOGY.md)")
    out.append(line)
    out.append(f"cases scored:      {result.cases_scored}")
    out.append(
        f"findings:          {result.findings_total} total, "
        f"{result.findings_matched} matched, {result.findings_unmatched} unmatched"
    )
    out.append(line)
    out.append(f"precision            {_fmt(m.precision)}")
    out.append(f"recall (TPR)         {_fmt(m.recall)}")
    out.append(f"specificity (TNR)    {_fmt(m.specificity)}")
    out.append(f"F1                   {_fmt(m.f1)}")
    out.append(f"Youden's J           {_fmt(m.youden_j)}")
    out.append(f"false-negative rate  {_fmt(m.false_negative_rate)}")
    if result.uncovered:
        out.append(line)
        out.append("uncovered challenge classes:")
        for name in result.uncovered:
            out.append(f"  - {name}")
    return "\n".join(out)


# ── CLI ──────────────────────────────────────────────────────────────────────────


def run(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Score SENTINEL findings against public ground truth."
    )
    ap.add_argument("--findings", required=True, type=Path, help="SENTINEL findings JSON")
    ap.add_argument("--truth", required=True, type=Path, help="ground-truth labels file")
    ap.add_argument(
        "--format",
        required=True,
        choices=("benchmark", "juice-shop"),
        help="ground-truth adapter",
    )
    ap.add_argument(
        "--match-cwe",
        action="store_true",
        help="benchmark only: require a finding to also share the case CWE",
    )
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args(argv)

    for label, path in (("findings", args.findings), ("truth", args.truth)):
        if not path.exists():
            print(f"error: {label} file not found: {path}", file=sys.stderr)
            return 1

    try:
        findings = load_findings(args.findings)
        if args.format == "benchmark":
            truth = parse_benchmark_truth(args.truth)
            result = score_benchmark(findings, truth, match_cwe=args.match_cwe)
        else:
            challenges = parse_juice_shop_truth(args.truth)
            result = score_juice_shop(findings, challenges)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        payload = result.as_dict()
        payload["findings_file"] = str(args.findings)
        payload["truth_file"] = str(args.truth)
        print(json.dumps(payload, indent=2))
    else:
        print(render(result, args.findings, args.truth))
    return 0


if __name__ == "__main__":
    sys.exit(run())
