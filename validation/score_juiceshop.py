#!/usr/bin/env python3
"""Score a SENTINEL Juice Shop audit against Juice Shop's own documented challenges.

The answer key is derived mechanically from the target, not written by hand. Two
independent signals locate each documented challenge's implementation in a file:

  * `// vuln-code-snippet start <key> ...` markers, which Juice Shop uses to annotate
    the intentionally vulnerable code behind each score-board challenge, and
  * `solveIf(challenges.<key>` / `solve(challenges.<key>` calls, which are where the
    app actually detects that challenge being solved.

Markers alone are too narrow (routes/chat.ts marks only the two coupon challenges
though it also contains the aiDebugging detection), so the two are unioned. Every key
is validated against `data/static/challenges.yml`.

Definitions, over the audited file set:

  TP = documented challenge located in an audited file that a finding covers
  FN = documented challenge located in an audited file that no finding covers
  FP = a finding covering a key that is not a documented challenge anywhere

A claimed key that is documented but whose implementation sits in a file *outside*
the audited scope is neither TP nor FP -- it is reported as "cross-file". The
weakness may genuinely be in scope while the app's detection lives elsewhere
(systemPromptExtractionChallenge: the confidential prompt text is in routes/chat.ts,
but Juice Shop scores it from routes/verify.ts). Counting those as either would
misrepresent the result, so they are surfaced and excluded.

Findings with an empty `covers` list are real findings outside the documented
challenge set. They are reported separately as "unscored findings" and are neither
TP nor FP: Juice Shop's challenge list is a lower bound on what is wrong with the
code, so penalising a finding for lacking a challenge id would punish correct work.
Every such finding still carries the full Phase 5 evidence standard.

    python validation/score_juiceshop.py --juice-shop-root ../juice-shop \
        --findings validation/data/juice-shop-v6-findings.json [--markdown]

Requires PyYAML (Juice Shop ships challenges.yml as YAML). Otherwise stdlib only.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

from harness_guard import CaseCountMismatch, require_clean_names, require_count

SKIP_PREFIX = ("node_modules", "build/", "dist/", ".git/", "data/static/codefixes")
MARKER_RE = re.compile(r"vuln-code-snippet start ([ \t\w]+)")
SOLVE_RE = re.compile(r"(?:solveIf|solve)\s*\(\s*challenges\.(\w+)")
SUFFIXES = (".ts", ".js", ".yml", ".html")


def load_valid_keys(root: Path) -> set[str]:
    import yaml

    data = yaml.safe_load((root / "data/static/challenges.yml").read_text(encoding="utf-8"))
    return {c["key"] for c in data}


def build_answer_key(root: Path, valid: set[str]) -> dict[str, set[str]]:
    """Return {file: {challenge keys marked in it}} for the whole repo."""
    mapping: dict[str, set[str]] = collections.defaultdict(set)
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in SUFFIXES:
            continue
        rel = path.relative_to(root).as_posix()
        if any(rel.startswith(s) or f"/{s}" in rel for s in SKIP_PREFIX):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # [ \t] rather than \s: the key list ends at the newline. \s would run the
        # match into the following line of code and swallow identifiers.
        for match in MARKER_RE.finditer(text):
            for key in match.group(1).split():
                if key in valid:
                    mapping[rel].add(key)
        for match in SOLVE_RE.finditer(text):
            if match.group(1) in valid:
                mapping[rel].add(match.group(1))
    return mapping


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--juice-shop-root", required=True, type=Path)
    parser.add_argument("--findings", required=True, type=Path)
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()

    try:
        valid = load_valid_keys(args.juice_shop_root)
    except ImportError:
        print("error: PyYAML is required to read challenges.yml", file=sys.stderr)
        return 1

    answer_key = build_answer_key(args.juice_shop_root, valid)
    report = json.loads(args.findings.read_text(encoding="utf-8"))
    scope = report["scope_files"]

    # A scope path that does not resolve is the v7.0 failure mode: the audit
    # claims to have covered a file that was never there, and every challenge in
    # it scores as a clean miss instead of an error. Resolve before scoring.
    try:
        require_clean_names(scope, f"{args.findings.name}:scope_files")
        resolved = [f for f in scope if (args.juice_shop_root / f).is_file()]
        if len(resolved) != len(scope):
            missing = sorted(set(scope) - set(resolved))
            raise CaseCountMismatch(
                f"{args.findings.name}: {len(missing)} scope file(s) do not exist under "
                f"{args.juice_shop_root}: {', '.join(missing[:10])}. An audited file that "
                f"is not on disk was never read; its challenges must not score as misses."
            )
        require_count(len(resolved), len(scope), f"scoping {args.findings.name}")
    except CaseCountMismatch as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    in_scope: set[str] = set()
    per_file: dict[str, set[str]] = {}
    for f in scope:
        per_file[f] = answer_key.get(f, set())
        in_scope |= per_file[f]

    claimed: set[str] = set()
    unscored = []
    for finding in report["findings"]:
        if finding["covers"]:
            claimed |= set(finding["covers"])
        else:
            unscored.append(finding["id"])

    documented_anywhere: set[str] = set()
    for keys in answer_key.values():
        documented_anywhere |= keys

    tp = sorted(claimed & in_scope)
    fn = sorted(in_scope - claimed)
    # Documented, but its implementation lives outside the audited files.
    cross_file = sorted((claimed - in_scope) & documented_anywhere)
    fp = sorted(claimed - in_scope - documented_anywhere)

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else None
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision and recall and (precision + recall)
        else None
    )

    def fmt(v: float | None) -> str:
        return "n/a" if v is None else f"{v:.4f}"

    if args.markdown:
        print(f"| File | Documented challenges | Found | Missed |")
        print(f"|---|---|---|---|")
        for f in scope:
            keys = per_file[f]
            found = sorted(keys & claimed)
            missed = sorted(keys - claimed)
            print(
                f"| `{f}` | {len(keys)} | {len(found)} | "
                f"{', '.join(missed) if missed else '-'} |"
            )
        print(
            f"| **total** | **{len(in_scope)}** | **{len(tp)}** | **{len(fn)}** |"
        )
        print()
        print("| Metric | Value |")
        print("|---|---|")
        print(f"| True positives | {len(tp)} |")
        print(f"| False positives | {len(fp)} |")
        print(f"| False negatives | {len(fn)} |")
        print(f"| Precision | {fmt(precision)} |")
        print(f"| Recall | {fmt(recall)} |")
        print(f"| F1 | {fmt(f1)} |")
        print(f"| Documented but detected outside scope (cross-file) | {len(cross_file)} |")
        print(f"| Findings outside the documented set (unscored) | {len(unscored)} |")
    else:
        json.dump(
            {
                "documented_in_scope": len(in_scope),
                "TP": len(tp),
                "FP": len(fp),
                "FN": len(fn),
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "missed": fn,
                "spurious": fp,
                "cross_file": cross_file,
                "unscored_findings": unscored,
            },
            sys.stdout,
            indent=2,
        )
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
