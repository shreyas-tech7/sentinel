"""Command-line interface: `python -m sentinel scan …`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .scanner import scan_report

CLASSES = [
    "sql_injection", "xss", "command_injection", "path_traversal",
    "insecure_deserialization", "hardcoded_secrets", "ssrf",
]


def _table(report: dict) -> str:
    lines = []
    lines.append(f"SENTINEL {report['version']} — scanned {report['stats']['files_scanned']} files, "
                 f"{report['stats']['lines_scanned']} lines in {report['stats']['duration_seconds']}s")
    lines.append("")
    header = f"{'SEVERITY':<9} {'CLASS':<24} {'LOCATION':<46} RULE"
    lines.append(header)
    lines.append("-" * len(header))
    for f in report["findings"]:
        loc = f"{f['file']}:{f['line']}"
        lines.append(f"{f['severity'].upper():<9} {f['vuln_class']:<24} {loc:<46} {f['rule_id']}")
    lines.append("")
    lines.append(f"total findings: {len(report['findings'])}")
    for cls in CLASSES:
        n = report["findings_by_class"].get(cls, 0)
        if n:
            lines.append(f"  {cls:<24} {n}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL static-analysis core — defensive security scanning for code you own.",
    )
    ap.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a path for vulnerability classes")
    scan.add_argument("path", type=Path, help="file or directory to scan")
    scan.add_argument("--include", action="append", default=[],
                      help="glob(s) to restrict the scan (relative to PATH)")
    scan.add_argument("--json", dest="json_out", type=Path, help="write the full JSON report here")
    scan.add_argument("--table", action="store_true", help="print a human-readable table to stdout")
    scan.add_argument("--min-severity", choices=["critical", "high", "medium", "low"],
                      help="only report findings at or above this severity")

    args = ap.parse_args(argv)

    if args.command == "scan":
        report = scan_report(args.path, tuple(args.include))
        if args.min_severity:
            from .model import severity_at_least
            report["findings"] = [f for f in report["findings"]
                                  if severity_at_least(f["severity"], args.min_severity)]
            report["findings_by_class"] = {}
            for f in report["findings"]:
                report["findings_by_class"][f["vuln_class"]] = \
                    report["findings_by_class"].get(f["vuln_class"], 0) + 1
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if args.table or not args.json_out:
            print(_table(report))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
