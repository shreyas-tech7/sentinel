"""Finding model shared by the scanner, the benchmark, and the reports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict

SEVERITIES = ["critical", "high", "medium", "low"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    rule_id: str          # e.g. "SENT-INJ-01/SQLI" — stable, cites the catalog
    vuln_class: str       # benchmark class label, e.g. "sql_injection"
    cwe: str              # e.g. "CWE-89"
    severity: str         # critical | high | medium | low
    confidence: str       # firm | tentative  (reported separately from severity)
    file: str             # path as scanned (relative to scan root)
    line: int             # 1-based
    message: str
    snippet: str          # the matched source line, trimmed
    language: str

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    @property
    def fingerprint(self) -> str:
        """Stable identity for dedup and cross-run diffing."""
        raw = f"{self.rule_id}|{self.file}|{self.line}|{self.message}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)


def severity_at_least(severity: str, minimum: str) -> bool:
    return _SEV_RANK.get(severity, 99) <= _SEV_RANK.get(minimum, 99)


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)
