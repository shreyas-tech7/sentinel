#!/usr/bin/env python3
"""SENTINEL benchmark harness.

Scans each evaluation target with the SENTINEL analyzer, matches findings
against the ground-truth label file, and computes per-class and overall
TP / FP / FN / precision / recall / F1 at the file level.

Metrics definition (stated precisely because it matters):
  * A "prediction" is a (file, class) pair produced by the scanner — duplicate
    findings of the same class in one file collapse to one prediction.
  * TP: predicted class is in the file's labeled classes.
  * FP: predicted class is not in the file's labeled classes (complete mode),
        or the file is labeled clean.
  * FN: a labeled (file, class) pair with no matching prediction.
  * Overall = micro-average over all (file, class) pairs of the target.
  * "complete" targets label every scanned file, so FP/FN/precision/recall/F1
    are fully measurable. "partial" targets label a verified subset; recall
    and raw TP/FN counts are measured, findings in unlabeled files are
    reported but NOT scored (they could be either kind), and precision is
    therefore not computed for them.

Usage:
    python bench/run_benchmark.py [--targets-dir DIR] [--out results/]
                                  [--only corpus,dvwa,juice-shop,webgoat]

Standard library only. Deterministic given the pinned target commits.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sentinel.scanner import scan_report  # noqa: E402
from sentinel import __version__  # noqa: E402

ALL_CLASSES = [
    "sql_injection", "xss", "command_injection", "path_traversal",
    "insecure_deserialization", "hardcoded_secrets", "ssrf",
]

TARGETS = {
    "corpus": {
        "path": "bench/corpus",
        "groundtruth": "bench/groundtruth/corpus.json",
        "mode": "complete",
    },
    "dvwa": {
        "path": "{targets_dir}/DVWA/vulnerabilities",
        "groundtruth": "bench/groundtruth/dvwa.json",
        "mode": "complete",
    },
    "juice-shop": {
        "path": "{targets_dir}/juice-shop",
        "groundtruth": "bench/groundtruth/juice-shop.json",
        "mode": "partial",
    },
    "webgoat": {
        "path": "{targets_dir}/WebGoat",
        "groundtruth": "bench/groundtruth/webgoat.json",
        "mode": "partial",
    },
}


def target_commit(targets_dir: Path, name: str) -> str | None:
    """Record the exact checkout a scan ran against (reproducibility metadata)."""
    root = {"dvwa": "DVWA", "juice-shop": "juice-shop", "webgoat": "WebGoat"}.get(name)
    if not root:
        return "vendored"
    d = targets_dir / root
    if not d.exists():
        return None
    try:
        return subprocess.run(
            ["git", "log", "-1", "--format=%H %cs"], cwd=d,
            capture_output=True, text=True, timeout=10,
        ).stdout.strip() or None
    except Exception:
        return None


def metrics(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
    }


def score_target(name: str, cfg: dict, targets_dir: Path) -> dict:
    gt_path = REPO_ROOT / cfg["groundtruth"]
    gt = json.loads(gt_path.read_text())
    scan_root = Path(cfg["path"].format(targets_dir=targets_dir))
    if not scan_root.exists():
        return {"target": name, "status": "missing",
                "error": f"target not present at {scan_root} — run bench/fetch_targets.sh"}

    include = tuple(gt.get("scan_scope", []))
    report = scan_report(scan_root, include)

    labels: dict[str, list[str]] = {k: v["classes"] for k, v in gt["labels"].items()}
    mode = cfg["mode"]

    # file -> predicted classes
    predicted: dict[str, set[str]] = {}
    for f in report["findings"]:
        predicted.setdefault(f["file"], set()).add(f["vuln_class"])

    if mode == "complete":
        scanned = {f["file"] for f in report["findings"]} | set()
        for f in report["stats"]["skipped"]:
            scanned.add(f["file"])
        unlabeled = sorted(
            p for p in predicted if p not in labels
        )
        if unlabeled:
            return {"target": name, "status": "groundtruth-error",
                    "error": f"scanned files missing from labels: {unlabeled[:10]}"}

    per_class = {c: {"tp": 0, "fp": 0, "fn": 0} for c in ALL_CLASSES}
    file_rows = []
    unscored_findings = 0
    for file, classes in sorted({**{k: [] for k in labels}, **{k: sorted(v) for k, v in predicted.items()}}.items()):
        labeled = set(labels.get(file, []))
        preds = predicted.get(file, set())
        if mode == "partial" and file not in labels:
            unscored_findings += len(preds)
            continue
        tp = preds & labeled
        fp = preds - labeled
        fn = labeled - preds
        for c in tp:
            per_class[c]["tp"] += 1
        for c in fp:
            per_class[c]["fp"] += 1
        for c in fn:
            per_class[c]["fn"] += 1
        file_rows.append({
            "file": file,
            "labeled": sorted(labeled),
            "predicted": sorted(preds),
            "tp": sorted(tp), "fp": sorted(fp), "fn": sorted(fn),
        })

    class_metrics = {}
    for c in ALL_CLASSES:
        m = per_class[c]
        if m == {"tp": 0, "fp": 0, "fn": 0}:
            class_metrics[c] = {"tp": 0, "fp": 0, "fn": 0,
                                "precision": None, "recall": None, "f1": None,
                                "n": 0}
            continue
        class_metrics[c] = {**metrics(m["tp"], m["fp"], m["fn"]), "n": m["tp"] + m["fn"]}

    total = metrics(sum(per_class[c]["tp"] for c in ALL_CLASSES),
                    sum(per_class[c]["fp"] for c in ALL_CLASSES),
                    sum(per_class[c]["fn"] for c in ALL_CLASSES))

    return {
        "target": name,
        "status": "ok",
        "mode": mode,
        "commit": gt.get("commit"),
        "actual_commit": target_commit(targets_dir, name),
        "match_mode": mode,
        "groundtruth_source": gt.get("source_of_truth"),
        "labels_file": str(gt_path.relative_to(REPO_ROOT)),
        "scan_stats": report["stats"],
        "overall": total,
        "per_class": class_metrics,
        "files": file_rows,
        "unscored_findings_in_unlabeled_files": unscored_findings,
        "raw_findings": report["findings"],
    }


def render_table(results: dict) -> str:
    lines = ["# SENTINEL benchmark results", ""]
    lines.append(f"Scanner version: {results['meta']['scanner_version']} · "
                 f"generated {results['meta']['generated']} · "
                 f"matching is file-level; see BENCHMARKS.md for the full methodology.")
    lines.append("")

    for name in results["order"]:
        r = results["targets"][name]
        lines.append(f"## Target: {name} ({r.get('match_mode', '?')} ground truth)")
        lines.append("")
        if r["status"] != "ok":
            lines.append(f"> **Not run:** {r['error']}")
            lines.append("")
            continue
        lines.append("| class | TP | FP | FN | precision | recall | F1 |")
        lines.append("|---|---|---|---|---|---|---|")
        for c in ALL_CLASSES:
            m = r["per_class"][c]
            if m["n"] == 0:
                continue
            p = f"{m['precision']:.2f}" if m["precision"] is not None else "—"
            rc = f"{m['recall']:.2f}" if m["recall"] is not None else "—"
            f1 = f"{m['f1']:.2f}" if m["f1"] is not None else "—"
            lines.append(f"| {c} | {m['tp']} | {m['fp']} | {m['fn']} | {p} | {rc} | {f1} |")
        o = r["overall"]
        lines.append(f"| **overall** | **{o['tp']}** | **{o['fp']}** | **{o['fn']}** "
                     f"| **{o['precision']:.2f}** | **{o['recall']:.2f}** | **{o['f1']:.2f}** |")
        if r["match_mode"] == "partial":
            lines.append("")
            lines.append(f"*Partial ground truth: recall is measured against the labeled subset; "
                         f"{r['unscored_findings_in_unlabeled_files']} findings in unlabeled files are reported but not scored. "
                         f"Precision is not computable without complete labels.*")
        lines.append("")

    # aggregated view over complete targets
    complete = [n for n in results["order"] if results["targets"][n]["status"] == "ok"
                and results["targets"][n]["match_mode"] == "complete"]
    if complete:
        agg = {c: {"tp": 0, "fp": 0, "fn": 0} for c in ALL_CLASSES}
        for n in complete:
            for c in ALL_CLASSES:
                m = results["targets"][n]["per_class"][c]
                agg[c]["tp"] += m["tp"]
                agg[c]["fp"] += m["fp"]
                agg[c]["fn"] += m["fn"]
        lines.append(f"## Aggregate — complete ground truth targets ({', '.join(complete)})")
        lines.append("")
        lines.append("| class | TP | FP | FN | precision | recall | F1 |")
        lines.append("|---|---|---|---|---|---|---|")
        for c in ALL_CLASSES:
            m = agg[c]
            if m["tp"] + m["fp"] + m["fn"] == 0:
                continue
            mm = metrics(m["tp"], m["fp"], m["fn"])
            p = f"{mm['precision']:.2f}" if mm["precision"] is not None else "—"
            rc = f"{mm['recall']:.2f}" if mm["recall"] is not None else "—"
            f1 = f"{mm['f1']:.2f}" if mm["f1"] is not None else "—"
            lines.append(f"| {c} | {m['tp']} | {m['fp']} | {m['fn']} | {p} | {rc} | {f1} |")
        tot = metrics(sum(m["tp"] for m in agg.values()),
                      sum(m["fp"] for m in agg.values()),
                      sum(m["fn"] for m in agg.values()))
        lines.append(f"| **overall** | **{tot['tp']}** | **{tot['fp']}** | **{tot['fn']}** "
                     f"| **{tot['precision']:.2f}** | **{tot['recall']:.2f}** | **{tot['f1']:.2f}** |")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--targets-dir", type=Path, default=Path("/tmp/bench-targets"),
                    help="directory containing the DVWA/, juice-shop/, WebGoat/ clones")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "results",
                    help="output directory for JSON + table")
    ap.add_argument("--only", default="corpus,dvwa,juice-shop,webgoat",
                    help="comma-separated subset of targets to run")
    args = ap.parse_args()

    import datetime
    wanted = [t.strip() for t in args.only.split(",") if t.strip()]
    results = {
        "meta": {
            "scanner_version": __version__,
            "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "matching": "file-level: (file, class) pairs; duplicates collapse",
        },
        "order": wanted,
        "targets": {},
    }

    for name in wanted:
        if name not in TARGETS:
            print(f"unknown target: {name}", file=sys.stderr)
            return 2
        cfg = TARGETS[name]
        print(f"[{name}] scanning…", file=sys.stderr)
        r = score_target(name, cfg, args.targets_dir)
        results["targets"][name] = r
        if r["status"] == "ok":
            o = r["overall"]
            print(f"[{name}] TP={o['tp']} FP={o['fp']} FN={o['fn']} "
                  f"P={o['precision']} R={o['recall']} F1={o['f1']}", file=sys.stderr)
        else:
            print(f"[{name}] {r['status']}: {r['error']}", file=sys.stderr)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "benchmark_results.json").write_text(json.dumps(results, indent=2) + "\n")
    table = render_table(results)
    (args.out / "tables.md").write_text(table + "\n")
    print(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
