"""Rule registry — the deterministic core of the Phase-3 adversarial scan."""

from __future__ import annotations

from .base import Rule
from . import sqli, xss, cmdi, path_traversal, deserialization, secrets, ssrf

ALL_RULES: list[Rule] = [
    sqli.RULE,
    xss.RULE,
    cmdi.RULE,
    path_traversal.RULE,
    deserialization.RULE,
    secrets.RULE,
    ssrf.RULE,
]

VULN_CLASSES = sorted({r.vuln_class for r in ALL_RULES})


def rules_for_language(lang: str) -> list[Rule]:
    return [r for r in ALL_RULES if lang in r.languages]
