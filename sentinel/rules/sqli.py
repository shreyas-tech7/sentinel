"""SENT-INJ-01/SQLI — SQL and NoSQL injection.

Vulnerable shape: attacker-controlled data reaches a query executor *inside*
the SQL text (string concatenation, template literal, f-string, or an
interpolated variable). Parameterized use — placeholders with a separate
params argument — is the control that makes it safe, so a tainted variable in
a params tuple/argument is *not* reported.
"""

from __future__ import annotations

import re

from ..model import Finding
from ..taint import (
    TAINT_SOURCES,
    FileContext,
    _occurrence_context,
    _taint_occurrences,
    has_direct_source,
    taint_vars_in,
)
from .base import Rule, extract_call_args, make_finding, sink_pattern

# query executors per language
SQL_SINKS: dict[str, str] = {
    "php": r"(?:->|::)\s*(?:query|exec|executeQuery)\s*\(|mysqli_query\s*\(|pg_query\s*\(|pg_exec\s*\(|sqlite_query\s*\(",
    "js": r"\.(?:query|raw)\s*\(",
    "py": r"\b(?:cursor|conn|db|session)\s*\.\s*execute\s*\(|\.executemany\s*\(",
    "java": r"\.(?:executeQuery|executeUpdate|execute|createQuery|createNativeQuery|createSQLQuery)\s*\(",
    "go": r"\.(?:Query|QueryRow|Exec)\s*\(",
}

# document-style (NoSQL) filters: request data as a filter value/operator
NOSQL_SINKS = re.compile(r"\.(?:findOne|find|findById|updateOne|updateMany|update|deleteOne|deleteMany|aggregate)\s*\(")
NOSQL_BODY = re.compile(r"\{\s*['\"]?\$(?:ne|gt|gte|lt|lte|regex|in|nin|where)['\"]?\s*:")
SQL_PLACEHOLDER = re.compile(r"\?\s*[,)\]]|\$\d\b|:\w+\b(?![\w'\"]*\s*\.concat)|@\w+|\$\{param")


def _check_sqli(ctx: FileContext, i: int, line: str) -> Finding | None:
    lang = ctx.language
    pattern = sink_pattern(SQL_SINKS[lang])
    m = pattern.search(line)

    paren_at = line.find("(", m.start()) if m else -1
    args = extract_call_args(ctx, i, paren_at) if m else ""

    direct = has_direct_source(lang, args)
    tainted_vars = taint_vars_in(ctx, args)

    # --- document-style (NoSQL) filters ---
    if not m:
        n = NOSQL_SINKS.search(line)
        if not n:
            return None
        n_args = extract_call_args(ctx, i, line.find("(", n.start()))
        if NOSQL_BODY.search(n_args) or has_direct_source(lang, n_args):
            return make_finding(RULE, ctx, i, "document filter built from request data")
        return None

    if not direct and not tainted_vars:
        return None

    # NoSQL operator injection: user-supplied operator object handed to a query
    if NOSQL_BODY.search(args) and (direct or tainted_vars):
        return make_finding(RULE, ctx, i, "operator-style filter built from request data")

    # "Direct" only counts when the source lands in string context; a source in
    # a separate parameters argument is the parameterized (safe) shape.
    direct_occ = [
        o for p in TAINT_SOURCES[lang]
        for o in p.finditer(args)
        if _occurrence_context(lang, args, o.start(), o.end()) is not None
    ]
    var_occ = _taint_occurrences(lang, args, tainted_vars)
    in_string = (
        bool(direct_occ)
        or bool(var_occ)
        or any(k in ctx.string_tainted_vars for k in tainted_vars)
    )
    if not in_string:
        # whole-query variable: query($sql) with tainted $sql
        bare = args.strip().rstrip(";").strip()
        if bare.startswith("(") and bare.endswith(")"):
            bare = bare[1:-1].strip()
        if not (tainted_vars and re.fullmatch(r"\$?[A-Za-z_]\w*", bare)):
            return None

    # The one safe shape: every tainted variable reaches the query quoted AND
    # charset-aware-escaped. Quoted-but-unescaped (LIKE '%${x}%') and
    # escaped-but-unquoted (user_id = $id) stay flagged. String-context raw
    # sources always stay flagged.
    if not direct_occ:
        safe = all(
            kind == "string_quoted" and var in ctx.escaped_vars
            for var, kind in tainted_vars.items()
        )
        if safe:
            return None

    return make_finding(RULE, ctx, i, "query text built from attacker-controlled data")


RULE = Rule(
    rule_id="SENT-INJ-01/SQLI",
    vuln_class="sql_injection",
    cwe="CWE-89",
    severity="high",
    confidence="firm",
    message="SQL/NoSQL injection: unparameterized query built from attacker-controlled data",
    languages=("php", "js", "py", "java", "go"),
    check=_check_sqli,
)
