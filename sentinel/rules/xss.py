"""SENT-INJ-02 — Cross-site scripting.

Vulnerable shape: attacker-controlled data reaches an HTML/script sink
(`echo`, `innerHTML`, `dangerouslySetInnerHTML`, `th:utext`, …) without an
output encoder between source and sink. Encoders (htmlspecialchars,
DOMPurify, Angular sanitizers, bleach, th:text-by-construction) suppress.
"""

from __future__ import annotations

import re

from ..model import Finding
from ..taint import FileContext, has_direct_source, is_sanitized, taint_vars_in
from .base import Rule, make_finding, sink_pattern

XSS_SINKS: dict[str, str] = {
    "php": r"\b(?:echo|print)\b|\.\=",
    "js": r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write(?:ln)?\s*\(|\.html\s*\(|v-html\s*=|dangerouslySetInnerHTML|bypassSecurityTrustHtml\s*\(|\.insertAdjacentHTML\s*\(",
    "py": r"Markup\s*\(|\.innerHTML|write\s*\(\s*<|\bHTML\(",
    "java": r"th:utext|\.getWriter\s*\(\s*\)\s*\.\s*write|\.print(?:ln)?\s*\(",
    "go": r"template\.HTML\s*\(|\.InnerHtml",
}

SANITIZERS = (
    "htmlspecialchars", "htmlentities", "filter_var", "strip_tags",
    "DOMPurify", "sanitizeHtml", "sanitize-html", "sanitizer.sanitize",
    "escape_html", "escapeHtml", "bleach.clean", "striptags", "clean_html",
    "encodeURI", "encodeURIComponent", "textContent",
)

# echo of an untouched tainted var or tainted string, php: `echo $_GET[x] . '…'`
_PHP_ECHO_TAINT = re.compile(r"\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)\b")


def _check_xss(ctx: FileContext, i: int, line: str) -> Finding | None:
    lang = ctx.language
    pattern = sink_pattern(XSS_SINKS[lang])
    m = pattern.search(line)
    if not m:
        return None
    if is_sanitized(line, SANITIZERS):
        return None

    direct = has_direct_source(lang, line)
    tainted_vars = taint_vars_in(ctx, line)
    if not direct and not tainted_vars:
        return None

    # `dangerouslySetInnerHTML` needs the taint on the same line (the __html prop)
    detail = "attacker-controlled data written into HTML without output encoding"
    if lang == "php" and _PHP_ECHO_TAINT.search(line):
        return make_finding(RULE, ctx, i, detail)
    return make_finding(RULE, ctx, i, detail)


RULE = Rule(
    rule_id="SENT-INJ-02/XSS",
    vuln_class="xss",
    cwe="CWE-79",
    severity="high",
    confidence="firm",
    message="XSS: attacker-controlled data rendered into HTML/script without encoding",
    languages=("php", "js", "py", "java", "go"),
    check=_check_xss,
)
