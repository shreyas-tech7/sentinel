#!/usr/bin/env python3
"""Robustness harness: adversarial variants of the labeled corpus, scored.

Generates variants of every labeled vulnerable sample in bench/corpus/ using
the Gauntlet interface (a `gauntlet` CLI if one is installed, otherwise the
bundled local_mutator.py — the generator actually used is recorded in the
results), runs SENTINEL over every variant, and measures detection retention
per technique against the un-mutated baseline.

Framing: this is a defensive robustness test scoped to practice fixtures we
own. It answers "how much does detection degrade when the same flaw is
presented differently?" — nothing here is an attack recipe.

    python bench/run_robustness.py [--seed 42] [--out results/]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sentinel.scanner import scan_path  # noqa: E402
from sentinel import __version__  # noqa: E402

TECHNIQUES = ["source-indirection", "source-indirection-2",
              "dead-interlude", "identifier-rename", "comment-noise"]

# classes a variant must still be detected under (from the corpus ground truth)
import json as _json  # noqa: E402

CORPUS_GT = _json.loads((REPO_ROOT / "bench/groundtruth/corpus.json").read_text())


def corpus_vulnerable_files() -> dict[str, list[str]]:
    out = {}
    for rel, entry in CORPUS_GT["labels"].items():
        if entry["classes"]:
            out[rel] = entry["classes"]
    return out


def generate_variants(generator_cmd: str | None, seed: int) -> tuple[dict[str, list[Path]], str]:
    """Returns ({source_rel: [variant_paths]}, generator_description)."""
    files = corpus_vulnerable_files()
    tmp = Path(tempfile.mkdtemp(prefix="sentinel-variants-"))
    variants: dict[str, list[Path]] = {rel: [] for rel in files}

    if generator_cmd and shutil.which(generator_cmd.split()[0]):
        for rel in files:
            out_dir = tmp / Path(rel).stem
            r = subprocess.run(
                [*generator_cmd.split(), "mutate",
                 "--input", str(REPO_ROOT / "bench/corpus" / rel),
                 "--out", str(out_dir), "--seed", str(seed)],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode != 0:
                print(f"  gauntlet failed for {rel}: {r.stderr[:200]}", file=sys.stderr)
                continue
            for record in json.loads((out_dir / "manifest.json").read_text()):
                variants[rel].append(Path(record["variant"]))
        return variants, f"gauntlet CLI: {generator_cmd}"

    # local fallback — same contract
    from bench.gauntlet.local_mutator import mutate
    for rel in files:
        manifest = mutate(REPO_ROOT / "bench/corpus" / rel, tmp / Path(rel).stem, seed, TECHNIQUES)
        variants[rel] = [Path(record["variant"]) for record in manifest]
    return variants, f"local_mutator.py (bundled fallback; seed {seed})"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "results")
    ap.add_argument("--gauntlet-cmd", default="gauntlet",
                    help="Gauntlet CLI to prefer; falls back to local_mutator.py if absent")
    args = ap.parse_args()

    files = corpus_vulnerable_files()
    variants, generator = generate_variants(args.gauntlet_cmd, args.seed)
    print(f"generator: {generator}", file=sys.stderr)

    per_technique: dict[str, dict] = {t: {"variants": 0, "detected": 0, "baseline_detected": 0}
                                      for t in TECHNIQUES}
    per_file = []
    total_baseline = 0
    for rel, classes in sorted(files.items()):
        base_ctx = scan_path(REPO_ROOT / "bench/corpus", ())
        # baseline: scan just this file for speed and determinism
        base_findings, _ = scan_path(REPO_ROOT / "bench/corpus" / rel, ())
        base_classes = {f.vuln_class for f in base_findings}
        base_hit = bool(set(classes) & base_classes)
        total_baseline += 1 if base_hit else 0

        row = {"file": rel, "classes": classes, "baseline_detected": base_hit, "variants": []}
        stem = Path(rel).stem
        for vp in variants[rel]:
            technique = vp.name[len(stem) + 1:].rsplit(".", 1)[0]
            findings, _ = scan_path(vp, ())
            v_classes = {f.vuln_class for f in findings}
            detected = bool(set(classes) & v_classes)
            row["variants"].append({
                "variant": vp.name, "technique": technique, "detected": detected,
                "detected_classes": sorted(v_classes),
            })
            per_technique[technique]["variants"] += 1
            per_technique[technique]["detected"] += 1 if detected else 0
            per_technique[technique]["baseline_detected"] += 1 if base_hit else 0
        row["variants_detected"] = sum(1 for v in row["variants"] if v["detected"])
        row["variants_total"] = len(row["variants"])
        per_file.append(row)

    summary = {}
    for t, m in per_technique.items():
        summary[t] = {
            "baseline_detected": m["baseline_detected"],
            "variants": m["variants"],
            "detected": m["detected"],
            "retention": round(m["detected"] / m["baseline_detected"], 4) if m["baseline_detected"] else None,
            "missed": m["baseline_detected"] - m["detected"],
        }

    overall_baseline = sum(1 for r in per_file if r["baseline_detected"])
    overall_variants = sum(r["variants_total"] for r in per_file)
    overall_detected = sum(r["variants_detected"] for r in per_file)

    result = {
        "meta": {
            "scanner_version": __version__,
            "generator": generator,
            "seed": args.seed,
            "framing": "Defensive robustness: variants preserve the vulnerability and change its presentation.",
            "corpus_files": len(files),
        },
        "overall": {
            "baseline_detected": overall_baseline,
            "variants": overall_variants,
            "detected": overall_detected,
            "retention": round(overall_detected / overall_variants, 4) if overall_variants else None,
            "missed": overall_variants - overall_detected,
        },
        "per_technique": summary,
        "per_file": per_file,
    }

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "robustness_results.json").write_text(json.dumps(result, indent=2) + "\n")

    print(f"\nRobustness ({generator})")
    print(f"{'technique':<24} {'baseline':>9} {'detected':>9} {'missed':>7} {'retention':>10}")
    for t in TECHNIQUES:
        s = summary[t]
        r = f"{s['retention']:.0%}" if s["retention"] is not None else "—"
        print(f"{t:<24} {s['baseline_detected']:>9} {s['detected']:>9} {s['missed']:>7} {r:>10}")
    o = result["overall"]
    print(f"{'ALL':<24} {o['variants']:>9} {o['detected']:>9} {o['missed']:>7} {o['retention']:.0%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
