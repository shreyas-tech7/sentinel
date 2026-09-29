"""SENT-INJ-07 — server-side request forgery (SSRF).

Vulnerable shape: an HTTP client fetches a URL derived from request data
without an allowlist or host validation. Literal URLs are safe; allowlist
checks and dedicated validation calls suppress.
"""

from __future__ import annotations

import re

from ..model import Finding
from ..taint import FileContext, has_direct_source, is_sanitized, taint_vars_in
from .base import Rule, make_finding, sink_pattern

SSRF_SINKS: dict[str, str] = {
    "php": r"\bcurl_init\s*\(|curl_setopt\s*\([^,]+,\s*CURLOPT_URL",
    "js": r"\bfetch\s*\(|\baxios(?:\.(?:get|post|put|delete|request))?\s*\(|\bgot\s*\(|\bnodeFetch\s*\(|\brequest\s*\(",
    "py": r"\brequests\.(?:get|post|head|put|delete|request)\s*\(|\burllib\.request\.urlopen\s*\(|\burlopen\s*\(|\bhttpx\.(?:get|post)\s*\(",
    "java": r"new\s+URL\s*\(|restTemplate\.(?:getForObject|postForObject|exchange)\s*\(|url\s*\.\s*(?:openStream|openConnection)\s*\(",
    "go": r"http\.(?:Get|Post)\s*\(",
}

SSRF_CONTROLS = (
    "allowlist", "allowList", "whitelist", "whiteList", "allowed_hosts",
    "allowedHosts", "allowed_domains", "validateUrl", "validate_url",
    "isAllowed", "assertUrl", "checkHost", "safe_url", "safeUrl",
)

# obvious local-network / metadata payloads sometimes committed in fixtures
_LiteralUrl = re.compile(r"[\"']https?://")


def _check_ssrf(ctx: FileContext, i: int, line: str) -> Finding | None:
    lang = ctx.language
    m = sink_pattern(SSRF_SINKS[lang]).search(line)
    if not m:
        return None
    if is_sanitized(line, SSRF_CONTROLS):
        return None
    if ctx.has_allowlist_guard:
        return None   # outbound URLs pass an allowlist somewhere in this file

    direct = has_direct_source(lang, line)
    tainted_vars = taint_vars_in(ctx, line)
    if not direct and not tainted_vars:
        return None

    detail = "outbound request URL derived from attacker-controlled data without allowlist"
    return make_finding(RULE, ctx, i, detail)


RULE = Rule(
    rule_id="SENT-INJ-07/SSRF",
    vuln_class="ssrf",
    cwe="CWE-918",
    severity="high",
    confidence="firm",
    message="SSRF: attacker-controlled URL fetched server-side without allowlist validation",
    languages=("php", "js", "py", "java", "go"),
    check=_check_ssrf,
)
