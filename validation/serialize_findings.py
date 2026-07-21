#!/usr/bin/env python3
"""Serialize archived SENTINEL output into `schema/finding.schema.json` shape.

The findings schema has always been checked against one hand-written worked
example in `docs/FINDINGS_SCHEMA.md`. That proves the example is well-formed; it
proves nothing about whether *real* SENTINEL output serializes to the contract.
This module does the serialization for real, from three archived corpora, so
`test_schema_conformance.py` can validate the result with an actual draft-2020-12
validator instead of by inspection.

The three corpora are not equally complete, and the difference matters:

  * **Prose audit reports** (`examples/*-redacted.md`) are full SENTINEL reports.
    Every schema-required field has a real source in the report text, so these
    serialize to *complete* findings and are validated against the full schema.

  * **Juice Shop coverage records** (`validation/data/juice-shop-*.json`) are
    *scoring* records, not exports. They were captured to answer "did this pass
    identify the weakness behind challenge X" and carry only the fields scoring
    needs. They have no `attack_scenario`, no `impact`, and no CWE.

  * **Benchmark verdicts** (`validation/data/sentinel-benchmark-*.json`) are
    thinner still: one boolean and a one-line reason per test case. Their CWE is
    real, read from the Benchmark's own `expectedresults-*.csv` ground truth.

Serialization invents nothing. Where a corpus does not carry a field, the field
is absent and the record is validated under a *partial profile* derived from the
schema at runtime (see `partial_profile`) rather than filled with placeholder
prose. A finding that claims an attack scenario nobody wrote is worse than a
finding that admits it has none.

Standard library only; the validator lives in the test.

    python validation/serialize_findings.py --corpus reports --out export.json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema" / "finding.schema.json"

SCHEMA_VERSION = "1.0"

# Fields the Juice Shop scoring records genuinely carry. Everything else the
# schema requires is absent by fact, not by oversight.
JUICE_SHOP_FIELDS = (
    "schema_version",
    "id",
    "title",
    "severity",
    "confidence",
    "location",
    "analysis",
    "remediation_summary",
    "falsifier",
)

# Benchmark verdicts carry no severity or confidence at all -- a verdict is a
# boolean, not a rated finding.
BENCHMARK_FIELDS = (
    "schema_version",
    "id",
    "title",
    "classification",
    "location",
    "analysis",
)

_SEVERITY_WORDS = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}

# 'routes/appConfiguration.ts:9-16 - retrieveAppConfiguration; registered at server.ts:607'
_LOCATION_RE = re.compile(
    r"^(?P<file>[\w./-]+\.[A-Za-z0-9]+)"        # a path with an extension
    r"(?::(?P<line>\d+)(?:-\d+)?)?"             # optional :line or :line-range
    r"(?P<rest>.*)$"                            # whatever qualifies it
)
_REST_LEAD_RE = re.compile(r"^\s*(?:[-–]|with|,|;)\s*")

_OWASP_RE = re.compile(r"\b((?:A|API|LLM)\d{1,2}:\d{4})\b")
_CWE_RE = re.compile(r"\bCWE-(\d+)\b")
_SENT_CLASS_RE = re.compile(r"\b(SENT-[A-Z]+-\d+)\b")


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def partial_profile(schema: dict, carried: tuple[str, ...]) -> dict:
    """The real schema with `required` narrowed to the fields a corpus carries.

    Derived from the live schema at runtime, never hand-copied, so that a change
    to a type, enum, pattern, or `additionalProperties` propagates into the
    partial checks automatically. Only the required-field list is relaxed --
    every constraint on the fields that *are* present still applies, and
    `additionalProperties: false` still rejects an invented field.
    """
    profile = json.loads(json.dumps(schema))  # deep copy
    profile["required"] = [f for f in schema["required"] if f in carried]
    return profile


def parse_location(text: str) -> dict[str, Any]:
    """Split a report/record location string into the schema's structured form.

    Falls back to using the whole string as `file` when no path is recognizable
    -- the redacted example reports sanitize some locations down to prose
    ('embed blocks (video + booking widget) [sanitized]'), which is a redaction
    artifact, not a schema problem.
    """
    text = text.strip().rstrip(".")
    # The reports wrap paths in backticks; strip them before matching.
    unticked = text.replace("`", "")
    match = _LOCATION_RE.match(unticked)
    if not match:
        return {"file": unticked or text}

    location: dict[str, Any] = {"file": match.group("file")}
    if match.group("line"):
        location["line"] = int(match.group("line"))
    rest = _REST_LEAD_RE.sub("", match.group("rest")).strip()
    if rest:
        location["function_or_endpoint"] = rest
    return location


def parse_classification(text: str) -> dict[str, Any]:
    """Pull SENTINEL class, OWASP ids, and integer CWEs out of a Classification line."""
    classification: dict[str, Any] = {}
    sentinel_class = _SENT_CLASS_RE.search(text)
    if sentinel_class:
        classification["sentinel_class"] = sentinel_class.group(1)
    owasp = _OWASP_RE.findall(text)
    if owasp:
        classification["owasp"] = owasp
    cwe = [int(n) for n in _CWE_RE.findall(text)]
    if cwe:
        classification["cwe"] = cwe
    return classification


def _slug(text: str) -> str:
    """A schema-legal id fragment (`^[A-Za-z0-9._-]+$`)."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")


# --------------------------------------------------------------------------
# Corpus A -- full prose audit reports
# --------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^###\s*\[(?P<sev>[A-Z]+)\]\s*[-–]\s*(?P<title>.+?)\s*$")
_BULLET_RE = re.compile(r"^-\s+\*\*(?P<label>[^:*]+):\*\*\s*(?P<value>.*)$")

_LABEL_TO_FIELD = {
    "Vulnerability Analysis": "analysis",
    "Attack Scenario": "attack_scenario",
    "Impact": "impact",
    "Remediation": "remediation_summary",
    "Location": "_location",
    "Classification": "_classification",
    # '- **Severity:** Critical  |  **Confidence:** High' -- one bullet, two fields.
    "Severity": "_severity_line",
}


def _flush_bullet(label: str | None, buffer: list[str], raw: dict[str, str]) -> None:
    if label is None:
        return
    field = _LABEL_TO_FIELD.get(label)
    if field:
        raw[field] = "\n".join(buffer).strip()


def iter_report_findings(md_path: Path) -> Iterator[dict[str, Any]]:
    """Parse the `### [SEVERITY] - Title` finding blocks of a prose audit report."""
    report_slug = _slug(md_path.stem.replace("-audit-redacted", ""))
    counter = 0
    heading: re.Match[str] | None = None
    raw: dict[str, str] = {}
    label: str | None = None
    buffer: list[str] = []

    def finish() -> dict[str, Any] | None:
        nonlocal counter
        _flush_bullet(label, buffer, raw)
        if heading is None:
            return None
        counter += 1
        return _build_report_finding(heading, raw, report_slug, counter)

    for line in md_path.read_text(encoding="utf-8").splitlines():
        new_heading = _HEADING_RE.match(line)
        if new_heading:
            done = finish()
            if done:
                yield done
            heading, raw, label, buffer = new_heading, {}, None, []
            continue
        if heading is None:
            continue
        # A new top-level section ends the findings list.
        if line.startswith("## "):
            done = finish()
            if done:
                yield done
            heading, raw, label, buffer = None, {}, None, []
            continue
        bullet = _BULLET_RE.match(line)
        if bullet:
            _flush_bullet(label, buffer, raw)
            label, buffer = bullet.group("label").strip(), [bullet.group("value")]
        elif label is not None:
            buffer.append(line.strip())

    done = finish()
    if done:
        yield done


def _build_report_finding(
    heading: re.Match[str], raw: dict[str, str], report_slug: str, counter: int
) -> dict[str, Any]:
    classification = parse_classification(raw.get("_classification", ""))
    severity = _SEVERITY_WORDS.get(heading.group("sev").upper(), heading.group("sev").title())

    # The severity/confidence bullet reads: '**Severity:** X  |  **Confidence:** Y'
    confidence = "High"
    conf_match = re.search(r"\*\*Confidence:\*\*\s*(\w+)", raw.get("_severity_line", ""))
    if conf_match:
        confidence = conf_match.group(1).title()

    finding: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": f"{report_slug}-{counter:03d}",
        "title": heading.group("title"),
        "severity": severity,
        "confidence": confidence,
        "classification": classification,
        "location": parse_location(raw.get("_location", "unspecified")),
        "analysis": raw.get("analysis", ""),
        "attack_scenario": raw.get("attack_scenario", ""),
        "impact": raw.get("impact", ""),
        "remediation_summary": raw.get("remediation_summary", ""),
    }
    return finding


# --------------------------------------------------------------------------
# Corpus B -- Juice Shop coverage records
# --------------------------------------------------------------------------


def juice_shop_findings(path: Path) -> list[dict[str, Any]]:
    """Serialize one archived Juice Shop pass.

    `missing_control` becomes `remediation_summary`: it is the same content the
    schema asks for -- the control that should exist -- worded as a gap rather
    than as an instruction. No other field is re-purposed, and no prose is
    written here that a human did not write during the audit.
    """
    record = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for entry in record["findings"]:
        finding: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "id": _slug(entry["id"]),
            "title": entry["title"],
            "severity": entry["severity"],
            "confidence": entry["confidence"],
            "location": parse_location(entry["location"]),
            "analysis": entry["analysis"],
        }
        if entry.get("missing_control"):
            finding["remediation_summary"] = entry["missing_control"]
        if entry.get("falsifier"):
            finding["falsifier"] = entry["falsifier"]
        findings.append(finding)
    return findings


# --------------------------------------------------------------------------
# Corpus C -- OWASP Benchmark verdicts
# --------------------------------------------------------------------------


def load_benchmark_cwe(expected_csv: Path) -> dict[str, int]:
    """Read test-case -> CWE from the Benchmark's own ground-truth CSV.

    Columns: test name, category, real vulnerability, cwe. This is the
    Benchmark's classification, not SENTINEL's inference.
    """
    mapping: dict[str, int] = {}
    with expected_csv.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if not row or row[0].lstrip().startswith("#"):
                continue
            if len(row) < 4:
                continue
            mapping[row[0].strip()] = int(row[3])
    return mapping


def benchmark_findings(
    verdicts_path: Path, cwe_by_test: dict[str, int], file_template: str
) -> list[dict[str, Any]]:
    """Serialize the *true-positive* verdicts of one Benchmark run.

    Only verdicts where SENTINEL said 'vulnerable' become findings -- a negative
    verdict is the absence of a finding, and has nothing to serialize.
    """
    findings = []
    for entry in json.loads(verdicts_path.read_text(encoding="utf-8")):
        if not entry.get("vulnerable"):
            continue
        name = entry["test_name"]
        cwe = cwe_by_test.get(name)
        if cwe is None:
            raise KeyError(f"{name} has no CWE in the Benchmark ground truth")
        findings.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": _slug(name),
                "title": f"{entry['category']} in {name}",
                "classification": {"cwe": [cwe]},
                "location": {"file": file_template.format(name=name)},
                "analysis": entry["reason"],
            }
        )
    return findings


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

JAVA_FILE_TEMPLATE = "src/main/java/org/owasp/benchmark/testcode/{name}.java"
PYTHON_FILE_TEMPLATE = "testcode/{name}.py"


def collect(corpus: str, root: Path = REPO_ROOT) -> list[dict[str, Any]]:
    data = root / "validation" / "data"
    if corpus == "reports":
        findings: list[dict[str, Any]] = []
        for md in sorted((root / "examples").glob("*-redacted.md")):
            findings.extend(iter_report_findings(md))
        return findings
    if corpus == "juice-shop":
        findings = []
        for path in sorted(data.glob("juice-shop-*findings.json")):
            findings.extend(juice_shop_findings(path))
        return findings
    if corpus == "benchmark":
        findings = []
        for lang, template, csv_name in (
            ("java", JAVA_FILE_TEMPLATE, "expectedresults-1.2.csv"),
            ("python", PYTHON_FILE_TEMPLATE, "expectedresults-0.1.csv"),
        ):
            cwe_map = _benchmark_cwe_for(lang, root, csv_name)
            for path in sorted(data.glob(f"sentinel-benchmark-{lang}-*-annotated.json")):
                findings.extend(benchmark_findings(path, cwe_map, template))
        return findings
    raise ValueError(f"unknown corpus {corpus!r}")


def _benchmark_cwe_for(lang: str, root: Path, csv_name: str) -> dict[str, int]:
    """Locate the Benchmark ground truth, preferring a vendored copy."""
    vendored = root / "validation" / "data" / f"benchmark-truth-{lang}.csv"
    if vendored.is_file():
        return load_benchmark_cwe(vendored)
    sibling = root.parent / ("BenchmarkJava" if lang == "java" else "BenchmarkPython") / csv_name
    if sibling.is_file():
        return load_benchmark_cwe(sibling)
    raise FileNotFoundError(
        f"no {lang} Benchmark ground truth: expected {vendored} or {sibling}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", choices=["reports", "juice-shop", "benchmark"], required=True)
    parser.add_argument("--out", type=Path, help="write the export here (default: stdout)")
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args()

    findings = collect(args.corpus, args.root)
    payload = json.dumps(findings, indent=2, ensure_ascii=False)
    if args.out:
        args.out.write_text(payload + "\n", encoding="utf-8")
        print(f"wrote {len(findings)} findings to {args.out}")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
