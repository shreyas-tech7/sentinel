"""SENT-SECRET-01 — hard-coded secrets and credentials.

Two detectors:

  * name-based: an assignment of a string literal to a credential-shaped name
    (password, api_key, secret, token, …) whose value is not an environment
    lookup or an obvious placeholder;
  * shape-based: credential-shaped literals (AWS keys, GitHub tokens, PEM
    blocks, JWTs, Stripe keys) assigned or quoted anywhere in code.

Both exist in `scripts/check_repo.py` for this repository's own hygiene; these
are the same shapes applied to audited code.
"""

from __future__ import annotations

import re

from ..model import Finding
from ..taint import FileContext, strip_comments
from .base import Rule, make_finding, sink_pattern

SECRET_NAME = re.compile(
    r"(?i)[\"']?(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"auth[_-]?token|client[_-]?secret|private[_-]?key|secret[_-]?key|db[_-]?pass|aws[_-]?secret)[\"']?\s*[\"']?\s*[:=]\s*"
)
SECRET_VALUE = re.compile(r"[\"']([^\"'\n]{4,})[\"']")
ENV_LOOKUP = re.compile(r"process\.env\.|os\.environ|getenv|Getenv|System\.getenv|ENV\[|config\(|import\.meta\.env|Deno\.env")

PLACEHOLDER = re.compile(
    r"(?i)(changeme|change[-_]?me|example|placeholder|<[^>\n]+>|\$\{|%s|\{[{}0-9]\}|"
    r"xxx+|\*\*\*|dummy|sample|redacted|your[-_]?|insert[-_]?|replace[-_]?|default|todo|fixme|"
    r"password123?['\"]?\s*$|test|abc123|qwerty|letmein|secret123)"
)

# Credential-shaped literals
SHAPES = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]\{0,0\}")),
    ("Stripe live key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("PEM private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\b")),
]
SHAPES[2] = ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"))

# a "password = 'dave'" inside a SQL string is query text, not a committed secret
SQL_TEXT = re.compile(r"(?i)\b(select\s|insert\s+into|update\s+\w+\s+set|from\s+\w+\s+where|where\s+\w+\s*=)\b")

ASSIGN_LINE = re.compile(r"[\"']?[A-Za-z_][\w.-]*[\"']?\s*[:=]")


def _check_secrets(ctx: FileContext, i: int, raw_line: str) -> Finding | None:
    lang = ctx.language
    line = strip_comments(raw_line, lang)
    if line.strip() != raw_line.strip() and not line.strip():
        return None
    code = line.strip()
    if not code:
        return None

    # name-based
    nm = SECRET_NAME.search(code)
    if nm and not ENV_LOOKUP.search(code) and not SQL_TEXT.search(code):
        sep = nm.group(0)
        after = code[nm.end():].lstrip()[:1]
        is_eq_assign = sep.rstrip().endswith("=") or sep.rstrip().endswith(":")
        if ("==" in sep or "!=" in sep or ">=" in sep or "<=" in sep
                or (is_eq_assign and sep.rstrip().endswith("=") and after == "=")):
            return None   # a comparison, not an assignment
        vm = SECRET_VALUE.search(code[len(nm.group(0)):])
        if vm:
            value = vm.group(1)
            if not PLACEHOLDER.search(value) and not value.startswith("$"):
                detail = f"credential-shaped name assigned a literal value ({vm.group(0)[:40]}…)"
                return make_finding(RULE, ctx, i, detail)

    # shape-based
    for label, pattern in SHAPES:
        m = pattern.search(code)
        if m:
            if PLACEHOLDER.search(m.group(0)):
                continue
            detail = f"credential-shaped literal committed in source ({label})"
            return make_finding(RULE, ctx, i, detail)
    return None


RULE = Rule(
    rule_id="SENT-SECRET-01/KEY",
    vuln_class="hardcoded_secrets",
    cwe="CWE-798",
    severity="high",
    confidence="firm",
    message="Hard-coded secret: credential committed in source instead of a secret store",
    languages=("php", "js", "py", "java", "go"),
    check=_check_secrets,
)
