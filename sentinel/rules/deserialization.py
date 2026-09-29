"""SENT-INJ-09 — insecure deserialization of untrusted data.

Vulnerable shape: a native object-deserialization primitive (pickle, Java
ObjectInputStream.readObject, PHP unserialize, node-serialize) consumes data
derived from a request. JSON parsing is the safe alternative and suppresses.
"""

from __future__ import annotations

import re

from ..model import Finding
from ..taint import FileContext, has_direct_source, is_sanitized, taint_vars_in
from .base import Rule, make_finding, sink_pattern

DESER_SINKS: dict[str, str] = {
    "php": r"\bunserialize\s*\(",
    "js": r"\bunserialize\s*\(|node_serialize| deserialize\s*\(",
    "py": r"\bpickle\.(?:loads|load)\s*\(|\bdill\.(?:loads|load)\s*\(|\bmarshal\.loads\s*\(|\byaml\.load\s*\(|\bcpickle\.loads\s*\(",
    "java": r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(|XMLDecoder\s*\(|\.fromXML\s*\(|\bYaml\s*\(\s*\)\s*\.\s*load\s*\(",
    "go": r"\byaml\.Unmarshal\b",
}

SAFE_LOADERS = (
    "json.loads", "json_decode", "json.loads", "JSON.parse",
    "yaml.safe_load", "yaml.dump", "SafeLoader", "CSafeLoader", "BaseLoader",
    "yaml.UnmarshalStrict",  # go yaml into typed struct is data-only
)


def _check_deser(ctx: FileContext, i: int, line: str) -> Finding | None:
    lang = ctx.language
    m = sink_pattern(DESER_SINKS[lang]).search(line)
    if not m:
        return None
    if is_sanitized(line, SAFE_LOADERS):
        return None

    # Python yaml.load: unsafe unless Loader= is a safe class (checked above)
    if lang == "py" and "yaml.load" in line and re.search(r"Loader\s*=", line):
        return None

    direct = has_direct_source(lang, line)
    tainted_vars = taint_vars_in(ctx, line)
    if not direct and not tainted_vars:
        return None

    detail = "native deserialization of attacker-controlled data"
    return make_finding(RULE, ctx, i, detail)


RULE = Rule(
    rule_id="SENT-INJ-09/DESER",
    vuln_class="insecure_deserialization",
    cwe="CWE-502",
    severity="critical",
    confidence="firm",
    message="Insecure deserialization: untrusted data passed to a native object-deserialization primitive",
    languages=("php", "js", "py", "java", "go"),
    check=_check_deser,
)
