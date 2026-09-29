#!/usr/bin/env python3
"""Generate all benchmark charts as SVG from the results files.

Zero dependencies, deterministic output: the same results JSON always renders
byte-identical SVG. Read-only over results/; writes results/charts/*.svg.

    python bench/make_charts.py [--results results/]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CLASS_LABELS = {
    "sql_injection": "SQL injection",
    "xss": "XSS",
    "command_injection": "Command injection",
    "path_traversal": "Path traversal",
    "insecure_deserialization": "Deserialization",
    "hardcoded_secrets": "Hardcoded secrets",
    "ssrf": "SSRF",
}

W, H = 860, 420
MARGIN = {"left": 210, "right": 24, "top": 46, "bottom": 56}
PLOT_W = W - MARGIN["left"] - MARGIN["right"]
PLOT_H = H - MARGIN["top"] - MARGIN["bottom"]

COLORS = {"precision": "#2563eb", "recall": "#dc2626", "f1": "#059669",
          "value": "#2563eb"}


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _bar_chart_svg(title: str, groups: list[tuple[str, list[tuple[str, float | None]]]],
                   ymax: float = 1.0) -> str:
    """groups: [(group_label, [(bar_label, value), …]), …]"""
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
             f'viewBox="0 0 {W} {H}" font-family="Helvetica,Arial,sans-serif">']
    parts.append(f'<rect width="{W}" height="{H}" fill="white"/>')
    parts.append(f'<text x="{MARGIN["left"]}" y="26" font-size="16" font-weight="bold" '
                 f'fill="#111">{_esc(title)}</text>')

    # gridlines + y labels
    n_ticks = 5
    for t in range(n_ticks + 1):
        frac = t / n_ticks
        y = MARGIN["top"] + PLOT_H * (1 - frac)
        val = ymax * frac
        parts.append(f'<line x1="{MARGIN["left"]}" y1="{y:.1f}" x2="{W - MARGIN["right"]}" '
                     f'y2="{y:.1f}" stroke="#e5e7eb" stroke-width="1"/>')
        parts.append(f'<text x="{MARGIN["left"] - 8}" y="{y + 4:.1f}" font-size="11" '
                     f'text-anchor="end" fill="#555">{val:.2f}</text>')

    n_groups = len(groups)
    group_w = PLOT_W / max(n_groups, 1)
    for gi, (glabel, bars) in enumerate(groups):
        gx = MARGIN["left"] + gi * group_w
        n = len(bars)
        bar_w = min(34.0, group_w * 0.7 / max(n, 1))
        total_bars_w = bar_w * n
        start = gx + (group_w - total_bars_w) / 2
        for bi, (blabel, value) in enumerate(bars):
            if value is None:
                continue
            h = PLOT_H * min(value, ymax) / ymax
            x = start + bi * bar_w
            y = MARGIN["top"] + PLOT_H - h
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w - 3:.1f}" '
                         f'height="{h:.1f}" fill="{COLORS.get(blabel, COLORS["value"])}"/>')
            parts.append(f'<text x="{x + (bar_w - 3) / 2:.1f}" y="{y - 4:.1f}" font-size="10" '
                         f'text-anchor="middle" fill="#333">{value:.2f}</text>')
        parts.append(f'<text x="{gx + group_w / 2:.1f}" y="{H - MARGIN["bottom"] + 20}" '
                     f'font-size="11" text-anchor="middle" fill="#111">{_esc(glabel)}</text>')

    # legend
    legend_labels = sorted({b for _, bars in groups for b, _ in bars})
    lx = MARGIN["left"]
    for ll in legend_labels:
        parts.append(f'<rect x="{lx}" y="{H - 22}" width="11" height="11" '
                     f'fill="{COLORS.get(ll, COLORS["value"])}"/>')
        parts.append(f'<text x="{lx + 16}" y="{H - 12}" font-size="11" fill="#333">{_esc(ll)}</text>')
        lx += 16 + 7 * len(ll) + 28
    parts.append("</svg>")
    return "\n".join(parts)


def fmt(v: float | None) -> float | None:
    return v


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=REPO_ROOT / "results")
    args = ap.parse_args()

    bench = json.loads((args.results / "benchmark_results.json").read_text())
    robust = json.loads((args.results / "robustness_results.json").read_text())
    charts = args.results / "charts"
    charts.mkdir(parents=True, exist_ok=True)

    # 1) per-class precision/recall/F1 over complete ground truth targets
    complete = [n for n in bench["order"]
                if bench["targets"][n]["status"] == "ok"
                and bench["targets"][n]["match_mode"] == "complete"]
    agg: dict[str, dict[str, float | None]] = {}
    for c in CLASS_LABELS:
        tp = fp = fn = 0
        for n in complete:
            m = bench["targets"][n]["per_class"][c]
            tp += m["tp"]; fp += m["fp"]; fn += m["fn"]
        if tp + fp + fn == 0:
            continue
        p = tp / (tp + fp) if tp + fp else None
        r = tp / (tp + fn) if tp + fn else None
        f1 = 2 * p * r / (p + r) if p and r else None
        agg[c] = {"precision": p, "recall": r, "f1": f1}
    groups = [(CLASS_LABELS[c],
               [("precision", agg[c]["precision"]), ("recall", agg[c]["recall"]), ("f1", agg[c]["f1"])])
              for c in agg]
    (charts / "per_class_complete.svg").write_text(
        _bar_chart_svg("Per-class precision / recall / F1 — complete ground truth "
                       f"({', '.join(complete)})", groups))

    # 2) recall per target
    tgroups = []
    for n in bench["order"]:
        t = bench["targets"][n]
        if t["status"] == "ok":
            label = n + (" *" if t["match_mode"] == "partial" else "")
            tgroups.append((label, [("recall", t["overall"]["recall"])]))
    (charts / "target_recall.svg").write_text(
        _bar_chart_svg("Overall recall per target (* = partial ground truth)", tgroups))

    # 3) robustness retention per technique
    rgroups = [(t, [("retention", m["retention"])])
               for t, m in robust["per_technique"].items() if m["variants"]]
    (charts / "robustness.svg").write_text(
        _bar_chart_svg("Detection retention under adversarial variants (Gauntlet-style)", rgroups))

    print(f"wrote {len(list(charts.glob('*.svg')))} charts to {charts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
