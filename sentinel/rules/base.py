"""Shared rule plumbing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..model import Finding
from ..taint import FileContext


def extract_call_args(ctx: FileContext, line_index0: int, open_paren_offset: int, max_lines: int = 6) -> str:
    """Return the text from an open paren to its matching close paren,
    spanning up to `max_lines` of the file. Line-oriented by design."""
    collected = ctx.lines[line_index0][open_paren_offset:]
    depth = collected.count("(") - collected.count(")")
    i = line_index0 + 1
    while depth > 0 and i < len(ctx.lines) and i - line_index0 <= max_lines:
        nxt = ctx.lines[i]
        collected += "\n" + nxt
        depth += nxt.count("(") - nxt.count(")")
        i += 1
    return collected


@dataclass
class Rule:
    rule_id: str
    vuln_class: str
    cwe: str
    severity: str
    confidence: str
    message: str
    languages: tuple[str, ...]
    check: Callable[[FileContext, int, str], Optional[Finding]]
    """check(ctx, line_index0, line) -> Finding | None"""


def make_finding(rule: Rule, ctx: FileContext, line_index0: int, detail: str) -> Finding:
    snippet = ctx.line(line_index0).strip()
    return Finding(
        rule_id=rule.rule_id,
        vuln_class=rule.vuln_class,
        cwe=rule.cwe,
        severity=rule.severity,
        confidence=rule.confidence,
        file=ctx.path,
        line=line_index0 + 1,
        message=f"{rule.message} ({detail})" if detail else rule.message,
        snippet=snippet[:300],
        language=ctx.language,
    )


_SINK_CACHE: dict[str, re.Pattern] = {}


def sink_pattern(regex: str) -> re.Pattern:
    compiled = _SINK_CACHE.get(regex)
    if compiled is None:
        compiled = re.compile(regex)
        _SINK_CACHE[regex] = compiled
    return compiled
