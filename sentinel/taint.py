"""A deliberately small taint model.

The scanner is line-oriented and explainable on purpose: every finding must be
traceable to a source expression and a sink on a real line. We track:

  * taint *sources* per language (superglobals, request objects, params…),
  * a per-file variable map with last-assignment-wins semantics, propagated to
    a fixed point: a variable stays tainted unless a *defuser* (intval,
    escapeshellarg, htmlspecialchars, …) sits on its final value's path, or
    every tainted token it was built from is *validation-fenced*
    (is_numeric($octet[0]));
  * the *context* in which taint reaches a sink:
      - "source":  raw attacker data used directly,
      - "string":  inside or concatenated into a query/output/command string,
      - "quoted":  interpolated *directly between quote characters* — the one
        shape that, combined with a charset-aware *weak escaper*
        (mysqli_real_escape_string…), blocks exploitation. Quoted-but-unescaped
        (`LIKE '%${x}%'`) and escaped-but-unquoted (`user_id = $id`) both stay
        flagged, which is exactly the distinction DVWA's sqli lesson teaches.

This is not a dataflow analysis and does not pretend to be one. It is the
"lead generator" tier described in skill/references/tooling.md: cheap,
deterministic, and honest about what it cannot see.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Languages
# ---------------------------------------------------------------------------

LANG_BY_EXT = {
    ".php": "php",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js",
    ".ts": "js", ".tsx": "js",
    ".py": "py",
    ".java": "java",
    ".go": "go",
}

SIGIL_LANGS = {"php"}   # variables carry `$` and bare words are never variables

# ---------------------------------------------------------------------------
# Taint sources — a match means "this expression carries attacker data".
# ---------------------------------------------------------------------------

TAINT_SOURCES: dict[str, list[re.Pattern]] = {
    "php": [
        re.compile(r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION)\b"),
        re.compile(r"file_get_contents\s*\(\s*['\"]php://input"),
        re.compile(r"\$argv\b"),
    ],
    "js": [
        re.compile(r"\breq(uest)?\.(query|body|params|headers|cookies|files)\b"),
        re.compile(r"\b(?:params|query)\.[A-Za-z_]\w*"),   # express destructuring: ({ params }) => params.file
        re.compile(r"\bqueryParams?(?:Map)?\.[A-Za-z_]\w*"),  # angular route queries
        re.compile(r"\blocation\.(?:search|href)\b|\bdocument\.(?:URL|location)\b|\bwindow\.location\.(?:search|href)\b"),
        re.compile(r"\bprocess\.argv\b"),
    ],
    "py": [
        re.compile(r"\brequest\.(args|form|values|data|json|files|cookies|headers|GET|POST)\b"),
        re.compile(r"\brequest\.get_json\b"),
        re.compile(r"\bsys\.argv\b"),
        re.compile(r"\binput\s*\("),
    ],
    "java": [
        re.compile(r"@(RequestParam|PathVariable|PathParam|QueryParam|FormParam|CookieParam|HeaderParam|RequestBody)\b"),
        re.compile(r"\.getParameter\s*\("),
        re.compile(r"\.getHeader\s*\("),
        re.compile(r"\.getCookies\s*\("),
        re.compile(r"\.getInputStream\s*\("),
        re.compile(r"\.getReader\s*\("),
    ],
    "go": [
        re.compile(r"\br\.URL\.Query\b"),
        re.compile(r"\br\.(?:FormValue|PostFormValue)\b"),
        re.compile(r"\br\.Header\.Get\b"),
        re.compile(r"\bos\.Args\b"),
    ],
}

# ---------------------------------------------------------------------------
# Defusers and escapers
# ---------------------------------------------------------------------------

DEFUSER_CALLS = (
    "intval", "(int)", "(integer)", "escapeshellarg", "escapeshellcmd",
    "shlex.quote", "shlex.join", "htmlspecialchars", "htmlentities",
    "DOMPurify.sanitize", "sanitizeHtml", "bleach.clean", "strip_tags",
    "json_encode", "floatval", "(float)", "Number(", "parseInt", "parseFloat",
    "filter_var", "secure_filename", "realpath", "basename",
)

WEAK_ESCAPERS = (
    "mysqli_real_escape_string", "mysql_real_escape_string", "mysql_escape_string",
    "pg_escape_string", "sqlite_escape_string", "escape_string",
)

VALIDATION_CALLS = ("is_numeric", "ctype_digit", "is_int", "is_integer", "preg_match")

_ASSIGN = re.compile(
    r"^\s*(?:@?\w[\w.\[\]]*\s+)?"
    r"(?:const|let|var|final|private|public|protected|static|val|my\s+)*"
    r"\$?([A-Za-z_]\w*)\s*(?::\s*[\w<>,.\[\]|\s]+?)?\s*(?::=|=)\s*(.+?);?\s*$"
)

_ASSIGN_TRAILING = re.compile(
    r"^\s*(?:@?\w[\w.\[\]]*\s+)?"
    r"(?:const|let|var|final|private|public|protected|static|val|my\s+)*"
    r"\$?([A-Za-z_]\w*)\s*(?::\s*[\w<>,.\[\]|\s]+?)?=(?:\s*|//.*)$"
)

_MAX_PASSES = 3
_MAX_LINE_LEN = 4000


def _clean_rhs(rhs: str) -> str:
    rhs = rhs.strip()
    if rhs.startswith(("(", "[", "{")) and rhs.endswith((")", "]", "}")):
        rhs = rhs[1:-1].strip()
    return rhs


def _is_comment(line: str, lang: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if lang in ("php", "js", "java", "go"):
        return stripped.startswith(("//", "*", "/*", "#"))
    if lang == "py":
        return stripped.startswith("#")
    return False


def _source_match(lang: str, text: str) -> re.Match | None:
    for p in TAINT_SOURCES[lang]:
        m = p.search(text)
        if m:
            return m
    return None


# ---------------------------------------------------------------------------
# String spans and occurrence context
# ---------------------------------------------------------------------------

_QUOTES = "'\"`"


def _string_spans(line: str) -> list[tuple[int, int, str, bool]]:
    """Naive quote-span finder: (content_start, end_inclusive, quote, has_fstring_prefix).
    Escapes respected."""
    spans: list[tuple[int, int, str, bool]] = []
    i, n = 0, len(line)
    quote = None
    start = 0
    prefix = False
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                spans.append((start, i, quote, prefix))
                quote = None
        elif c in _QUOTES:
            prefix = i > 0 and line[i - 1] in "fF"
            start = i
            quote = c
        i += 1
    return spans


def _interpolates(lang: str, quote: str, has_fstring_prefix: bool) -> bool:
    """Can this literal interpolate a variable at its location?"""
    if lang == "php":
        return quote == '"'
    if lang == "js":
        return quote == "`"
    if lang == "py":
        return has_fstring_prefix
    return False


def _interp_brackets(lang: str, quote: str) -> tuple[str, str] | None:
    if lang == "js" and quote == "`":
        return "${", "}"
    if lang == "py" and quote in "'\"":
        return "{", "}"
    return None


def _adjacent_quotes(line: str, start: int, end: int) -> bool:
    before = line[:start].rstrip()
    after = line[end:].lstrip()
    return bool(before) and bool(after) and before[-1] in "'\"" and after[0] in "'\""


def _concat_adjacent(line: str, pos: int) -> bool:
    """True when taint sits right after a string-concat operator. A `.` preceded
    by an identifier is member access, not concat."""
    before = line[:pos].rstrip()
    if not before:
        return False
    ch = before[-1]
    if ch == ".":
        return not (len(before) >= 2 and (before[-2].isalnum() or before[-2] in "_)]"))
    return ch in "+%&|"


def _occurrence_context(lang: str, line: str, start: int, end: int) -> str | None:
    """Classify one taint occurrence on a line:
      "quoted" — interpolated directly between quote characters;
      "string" — inside a string via concat/other splicing;
      None     — plain code position (parameter context) or a literal that
                 cannot interpolate (the text there is just data).
    """
    spans = _string_spans(line)
    for s, e, q, fpre in spans:
        if s <= start <= e:
            if not _interpolates(lang, q, fpre):
                return None
            if lang == "php":
                if q == "'":
                    return None
                return "quoted" if _adjacent_quotes(line, start, end) else "string"
            brackets = _interp_brackets(lang, q)
            if brackets:
                open_t, close_t = brackets
                seg = line[s:e + 1]
                for m in re.finditer(re.escape(open_t) + r"[^{}]*" + re.escape(close_t), seg):
                    if s + m.start() <= start <= s + m.end():
                        return "quoted" if _adjacent_quotes(line, s + m.start(), s + m.end()) else "string"
            return None
    # not inside any literal: concatenated next to one?
    if _concat_adjacent(line, start) and any(q in line for q in _QUOTES):
        return "string"
    return None


def _var_pattern(lang: str, var: str) -> re.Pattern:
    if lang in SIGIL_LANGS:
        return re.compile(r"\$" + re.escape(var) + r"\b")
    return re.compile(r"\b" + re.escape(var) + r"\b")


def _taint_occurrences(lang: str, line: str, tainted_vars: dict[str, str]) -> list[tuple[int, int, str, str]]:
    """(start, end, taint-kind, context) for every in-string-context occurrence."""
    out: list[tuple[int, int, str, str]] = []
    for p in TAINT_SOURCES[lang]:
        for m in p.finditer(line):
            ctx_kind = _occurrence_context(lang, line, m.start(), m.end())
            if ctx_kind is not None:
                out.append((m.start(), m.end(), "source", ctx_kind))
    for var, kind in tainted_vars.items():
        for m in _var_pattern(lang, var).finditer(line):
            ctx_kind = _occurrence_context(lang, line, m.start(), m.end())
            if ctx_kind is not None:
                out.append((m.start(), m.end(), kind, ctx_kind))
    return out


def in_string_context(lang: str, line: str, tainted_vars: dict[str, str] | None = None) -> bool:
    return bool(_taint_occurrences(lang, line, tainted_vars or {}))


# ---------------------------------------------------------------------------
# FileContext
# ---------------------------------------------------------------------------

@dataclass
class FileContext:
    path: str
    language: str
    lines: list[str]
    string_tainted_vars: set[str] = field(default_factory=set)
    source_tainted_vars: set[str] = field(default_factory=set)
    defused_tokens: set[str] = field(default_factory=set)   # e.g. "$octet[0]"
    escaped_vars: set[str] = field(default_factory=set)     # weak-escaped on final path
    var_kinds: dict[str, str] = field(default_factory=dict)  # var -> source|string|string_quoted
    has_allowlist_guard: bool = False                        # file contains allowlist/containment check

    def line(self, index0: int) -> str:
        if 0 <= index0 < len(self.lines):
            return self.lines[index0]
        return ""


def build_context(path: str, language: str, text: str) -> FileContext:
    lines = [l[:_MAX_LINE_LEN] for l in text.splitlines()]
    ctx = FileContext(path=path, language=language, lines=lines)
    _propagate_taint(ctx)
    return ctx


def _collect_defused_tokens(ctx: FileContext) -> None:
    """Tokens wrapped in a validation call are fenced: is_numeric($octet[0])."""
    joined = "\n".join(ctx.lines)
    for call in VALIDATION_CALLS:
        for m in re.finditer(re.escape(call) + r"\s*\(([^()]*(?:\([^()]*\))?[^()]*)\)", joined):
            for token in re.finditer(r"\$\w+(?:\[\s*\d+\s*\])?", m.group(1)):
                ctx.defused_tokens.add(token.group(0))


def _rhs_defused(ctx: FileContext, rhs: str) -> bool:
    """True when every taint in the RHS is a validation-fenced token."""
    if _source_match(ctx.language, rhs):
        return False
    tokens = re.findall(r"\$\w+(?:\[\s*\d+\s*\])?", rhs)
    if not tokens:
        return False
    return all(t in ctx.defused_tokens for t in tokens)


def _rhs_tainted_refs(lang: str, rhs: str, state: dict[str, str]) -> dict[str, str]:
    refs: dict[str, str] = {}
    for var, kind in state.items():
        if _var_pattern(lang, var).search(rhs):
            refs[var] = kind
    return refs


JAVA_PARAM_DECL = re.compile(
    r"@(?:RequestParam|PathVariable|PathParam|QueryParam|FormParam|CookieParam|HeaderParam)"
    r"[^\n]*?\b([A-Za-z_.]+\s+)?([A-Za-z_]\w*)\s*[,)]"
)
_JAVA_LITERALS = {"true", "false", "null", "this"}
_JAVA_NUMERIC_TYPES = re.compile(
    r"(?i)^(long|integer|int|short|double|float|bigdecimal|number)$"
)


def _seed_declared_params(ctx: FileContext, state: dict[str, str], escaped: dict[str, bool]) -> None:
    """Spring/JAX-RS annotated parameters are request data by definition.
    Numeric-typed parameters are skipped: a bounded number cannot carry a
    path or a command (e.g. `@RequestParam Long id` used as an index)."""
    for raw in ctx.lines:
        if "@" not in raw:
            continue
        for m in JAVA_PARAM_DECL.finditer(raw):
            name = m.group(2)
            if name in _JAVA_LITERALS:
                continue
            type_part = (m.group(1) or "").strip()
            if _JAVA_NUMERIC_TYPES.match(type_part.split(".")[-1]):
                continue
            before = raw[max(0, m.start(2) - 8):m.start(2)]
            if "=" in before:   # an attribute value like required = false
                continue
            state.setdefault(name, "source")
            escaped[name] = False


_ALLOWLIST_GUARD = re.compile(
    r"(?i)(in_array\s*\([^)]*(allowed|whitelist|allowlist|config)|"
    r"\b(?:not\s+in|in)\s+[\w\.\[\]\"'\$\s]*(allowed|whitelist|allowlist)|"
    r"(?-i:[A-Z][A-Z_]{2,})\s*\.\s*includes\s*\(|"
    r"startsWith\s*\(|realpath\s*\(|.endsWith\s*\(\s*['\"])"
)


def _scan_allowlist_guard(ctx: FileContext) -> None:
    ctx.has_allowlist_guard = any(_ALLOWLIST_GUARD.search(l) for l in ctx.lines)


def _propagate_taint(ctx: FileContext) -> None:
    lang = ctx.language
    _collect_defused_tokens(ctx)
    _scan_allowlist_guard(ctx)

    assignments: list[tuple[str, str]] = []
    pending: tuple[str, str] | None = None   # name, partial-rhs (multi-line assignment)
    for raw in ctx.lines:
        if _is_comment(raw, lang):
            continue
        code = raw.split("//")[0] if lang != "py" else raw
        if pending is not None:
            merged = pending[1] + " " + code.strip()
            assignments.append((pending[0], _clean_rhs(merged)))
            pending = None
            if re.search(r"[(\[=+.|%&]\s*$", code):
                pending = (assignments.pop()[0], merged)
            continue
        m = _ASSIGN.match(code)
        if not m:
            tm = _ASSIGN_TRAILING.match(code)
            if tm:
                pending = (tm.group(1), "")
            continue
        if m and not re.search(r"[=!<>+\-*/%]=", m.group(0).split("=", 1)[0] + " ="):
            name, rhs = m.group(1), _clean_rhs(m.group(2))
            if re.search(r"[(\[=+.|%&]\s*$", rhs) and not rhs.endswith(")"):
                pending = (name, rhs)   # rhs continues on the next line
            else:
                assignments.append((name, rhs))

    state: dict[str, str] = {}
    escaped: dict[str, bool] = {}
    seeds: dict[str, str] = {}
    seed_escaped: dict[str, bool] = {}
    if lang == "java":
        _seed_declared_params(ctx, seeds, seed_escaped)
    for _ in range(_MAX_PASSES):
        prev = dict(state)
        state = dict(seeds)
        escaped = dict(seed_escaped)
        for name, rhs in assignments:
            weak = any(e in rhs for e in WEAK_ESCAPERS)
            if _rhs_defused(ctx, rhs):
                state.pop(name, None)          # last assignment wins: defused
                escaped[name] = False
                continue
            upstream_all = _rhs_tainted_refs(lang, rhs, state)   # includes self ($x = f($x))
            upstream = {k: v for k, v in upstream_all.items() if k != name}
            has_source = _source_match(lang, rhs) is not None
            if has_source or upstream_all:
                if any(d in rhs for d in DEFUSER_CALLS):
                    state.pop(name, None)      # defused on this assignment
                    escaped[name] = False
                    continue
                occ = _taint_occurrences(lang, rhs, upstream_all)
                if occ:
                    kind = "string_quoted" if all(c == "quoted" for _, _, _, c in occ) else "string"
                else:
                    kind = "source"
                state[name] = kind
                escaped[name] = weak or bool(upstream) and all(escaped.get(v, False) for v in upstream)
            else:
                escaped[name] = weak
        if state == prev:
            break

    ctx.var_kinds = state
    for name, kind in state.items():
        if kind in ("string", "string_quoted"):
            ctx.string_tainted_vars.add(name)
        ctx.source_tainted_vars.add(name)
    ctx.escaped_vars = {n for n, is_esc in escaped.items() if is_esc and n in state}


def taint_vars_in(ctx: FileContext, text: str) -> dict[str, str]:
    """Tainted variables referenced in `text`: {name: kind}.

    Sigil languages: `$var` is always a real reference. Elsewhere a bare word
    only counts at code positions or inside interpolating literals — never as
    prose inside a plain string."""
    found: dict[str, str] = {}
    spans = _string_spans(text)

    def in_plain_literal(pos: int) -> bool:
        return any(s <= pos <= e for s, e, _, _ in spans)

    for var in sorted(ctx.var_kinds, key=len, reverse=True):
        for m in _var_pattern(ctx.language, var).finditer(text):
            if m.group(0) in ctx.defused_tokens:
                continue
            if ctx.language in SIGIL_LANGS:
                found[var] = ctx.var_kinds[var]
                break
            if not in_plain_literal(m.start()):
                found[var] = ctx.var_kinds[var]
                break
            if _occurrence_context(ctx.language, text, m.start(), m.end()) is not None:
                found[var] = ctx.var_kinds[var]
                break
    return found


def has_direct_source(lang: str, text: str) -> bool:
    return _source_match(lang, text) is not None


def is_sanitized(text: str, sanitizers: tuple[str, ...]) -> bool:
    return any(name in text for name in sanitizers)


def strip_comments(line: str, lang: str) -> str:
    if lang == "py":
        return re.sub(r"(^|\s)#.*$", "", line)
    return re.sub(r"(/\*.*?\*/)|(^|\s)(?://|#).*$", "", line)
