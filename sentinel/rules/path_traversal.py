"""SENT-INJ-10 — path traversal and unsafe file-path handling.

Vulnerable shape: attacker-controlled data becomes (part of) a filesystem
path handed to include/require, a file reader, or an HTTP file-send sink,
with no canonicalization or containment check. Basename/realpath wrapping
and allowlist maps are the controls that suppress.
"""

from __future__ import annotations

import re

from ..model import Finding
from ..taint import FileContext, has_direct_source, is_sanitized, taint_vars_in
from .base import Rule, make_finding, sink_pattern

PATH_SINKS: dict[str, str] = {
    "php": r"\b(?:include|include_once|require|require_once|fopen|readfile|file_get_contents|unlink|fopen)\s*\(",
    "js": r"\.(?:readFile|readFileSync|createReadStream|sendFile|sendfile|download|unlink|appendFile|writeFile)\s*\(",
    "py": r"\bopen\s*\(|\.send_file\s*\(|\.send_from_directory\s*\(|shutil\.copy\s*\(",
    "java": r"new\s+File\s*\(|Files\.(?:read|copy|move|newInputStream|newOutputStream|walk)\w*\s*\(",
    "go": r"\.(?:ReadFile|Open|Create|WriteFile)\s*\(",
}

# allowlist-style controls
PATH_CONTROLS = (
    "basename", "realpath", "path.basename", "normalize",
    "os.path.basename", "os.path.abspath", "os.path.realpath", "secure_filename",
    "send_from_directory", "{ root:", "root:", "startsWith", "in_array",
)

_PHP_INCLUDE_TAINT = re.compile(
    r"\b(?:include|include_once|require|require_once)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)"
)


def _check_path(ctx: FileContext, i: int, line: str) -> Finding | None:
    lang = ctx.language
    m = sink_pattern(PATH_SINKS[lang]).search(line)
    if not m and lang == "php":
        if _PHP_INCLUDE_TAINT.search(line):
            return make_finding(RULE, ctx, i, "include/require of an attacker-controlled path")
        return None
    if not m:
        return None

    if is_sanitized(line, PATH_CONTROLS):
        return None
    if ctx.has_allowlist_guard:
        return None   # file gates paths through an allowlist / containment check

    direct = has_direct_source(lang, line)
    tainted_vars = taint_vars_in(ctx, line)
    if not direct and not tainted_vars:
        return None

    # A tainted var is only string-dangerous if it came from a source directly
    # or was built from one; both cases are covered by the checks above.
    detail = "filesystem path built from attacker-controlled data without containment check"
    return make_finding(RULE, ctx, i, detail)


RULE = Rule(
    rule_id="SENT-INJ-10/PATH",
    vuln_class="path_traversal",
    cwe="CWE-22",
    severity="high",
    confidence="firm",
    message="Path traversal: attacker-controlled data used as a filesystem path without containment",
    languages=("php", "js", "py", "java", "go"),
    check=_check_path,
)
