"""SENT-INJ-01/CMDI — command injection.

Vulnerable shape: attacker-controlled data is concatenated or formatted into
a string that a shell executes, or passed to a shell-enabled process API.
Quoting wrappers (escapeshellarg, shlex.quote) and argument-list executors
without a shell are the controls that suppress.
"""

from __future__ import annotations

import re

from ..model import Finding
from ..taint import FileContext, has_direct_source, is_sanitized, taint_vars_in
from .base import Rule, make_finding, sink_pattern

CMD_SINKS: dict[str, str] = {
    "php": r"\b(?:system|shell_exec|passthru|popen|proc_open|exec)\s*\(|`[^`]*\$\w",
    "js": r"\bchild_process\s*\.\s*(?:exec|execSync|execFile)?\s*\(|\bexec(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\(",
    "py": r"\bos\.(?:system|popen)\s*\(|\bsubprocess\.(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(|\bcommands\.getoutput\s*\(",
    "java": r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|new\s+ProcessBuilder\s*\(",
    "go": r"exec\.Command\s*\(",
}

SHELL_TRUE = re.compile(r"shell\s*=\s*True|shell\s*:\s*true|\"sh\"\s*,\s*\"-c\"|'-c'|\bcmd\s*/\s*c\b", re.IGNORECASE)
QUOTERS = ("escapeshellarg", "escapeshellcmd", "shlex.quote", "shlex_join", "shlex.join")

_PHP_BACKTICK = re.compile(r"`[^`]*\$[A-Za-z_]\w*[^`]*`")


def _check_cmdi(ctx: FileContext, i: int, line: str) -> Finding | None:
    lang = ctx.language
    m = sink_pattern(CMD_SINKS[lang]).search(line)
    if not m:
        if lang == "php" and _PHP_BACKTICK.search(line):
            pass  # backtick execution with an interpolated variable
        else:
            return None

    direct = has_direct_source(lang, line)
    tainted_vars = taint_vars_in(ctx, line)
    if not direct and not tainted_vars:
        return None

    if is_sanitized(line, QUOTERS):
        return None

    # Python: subprocess list-form without shell=True does not invoke a shell.
    if lang == "py":
        has_shell = SHELL_TRUE.search(line)
        if not has_shell and (not has_direct_source(lang, line)):
            return None
        if not has_shell and direct:
            # e.g. subprocess.run(["sh", "-c", txt]) — covered by SHELL_TRUE
            if re.search(r"\[\s*['\"]", line):
                return None

    # Go: exec.Command never spawns a shell by itself; only sh -c style is a
    # command injection sink.
    if lang == "go" and not SHELL_TRUE.search(line):
        return None

    detail = "shell command assembled from attacker-controlled data"
    return make_finding(RULE, ctx, i, detail)


RULE = Rule(
    rule_id="SENT-INJ-01/CMDI",
    vuln_class="command_injection",
    cwe="CWE-78",
    severity="critical",
    confidence="firm",
    message="Command injection: shell command built from attacker-controlled data",
    languages=("php", "js", "py", "java", "go"),
    check=_check_cmdi,
)
