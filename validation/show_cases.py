#!/usr/bin/env python3
"""Print the decision-relevant body of sampled OWASP Benchmark test cases.

This is a *presentation* aid, not an analyzer. It strips the GPL license header
and collapses blank-line runs so an auditor can read many sampled cases without
wading through ~18 lines of identical boilerplate per file. It makes no judgment
about any test case and never reads the ground-truth column — consistent with
SENTINEL's standing rule that tools produce leads while the audit produces
findings (skill/references/tooling.md).

    python validation/show_cases.py --benchmark-root ../BenchmarkJava \
        --sample validation/data/benchmark-sample-java-v6.csv \
        --lang java --start 0 --count 20

Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

JAVA_SUBDIR = Path("src/main/java/org/owasp/benchmark/testcode")
PYTHON_SUBDIR = Path("testcode")


def case_path(benchmark_root: Path, lang: str, test_name: str) -> Path:
    if lang == "java":
        return benchmark_root / JAVA_SUBDIR / f"{test_name}.java"
    return benchmark_root / PYTHON_SUBDIR / f"{test_name}.py"


def strip_license(text: str, lang: str) -> str:
    """Drop the leading license block: a /** ... */ javadoc or a ''' ... ''' docstring."""
    lines = text.splitlines()
    opener, closer = ("/**", "*/") if lang == "java" else ("'''", "'''")

    start = 0
    while start < len(lines) and not lines[start].strip():
        start += 1
    if start < len(lines) and lines[start].strip().startswith(opener):
        for idx in range(start + 1, len(lines)):
            if lines[idx].strip().endswith(closer):
                lines = lines[idx + 1 :]
                break

    kept: list[str] = []
    blank_run = 0
    for line in lines:
        if line.strip():
            blank_run = 0
            kept.append(line.rstrip())
        else:
            blank_run += 1
            if blank_run == 1:
                kept.append("")
    return "\n".join(kept).strip()


# Sink tokens used only to decide whether a Java doGet is inert boilerplate and may be
# elided from the printout. This gates *display*, never a verdict: when a doGet contains
# any of these, the method is printed in full so the auditor reads it. Empirically 8 of
# BenchmarkJava's 2740 cases have a live sink in doGet (all xpath); the rest either
# delegate to doPost or only set a cookie and forward.
JAVA_DOGET_SINK_TOKENS = (
    "exec(",
    "createQuery",
    "executeQuery",
    "executeUpdate",
    "FileInputStream",
    "FileOutputStream",
    "Cipher",
    "MessageDigest",
    "xpath",
    "XPath",
    "search(",
    "Random(",
)

_DOGET_RE = re.compile(r"[ \t]*(@Override\n)?[ \t]*public void doGet\(.*?\n    \}\n", re.S)


def elide_inert_doget(text: str) -> tuple[str, bool]:
    """Drop a Java doGet method when it contains no sink token.

    Returns (text, elided). The doGet in these test cases almost always just seeds a
    cookie and forwards, or delegates straight to doPost; the taint source and sink
    both live in doPost. Eliding it cuts ~20 lines of identical boilerplate per case.
    """
    match = _DOGET_RE.search(text)
    if not match:
        return text, False
    body = match.group(0)
    if any(token in body for token in JAVA_DOGET_SINK_TOKENS):
        return text, False
    marker = "    // [doGet elided by show_cases.py --terse: no sink token present]\n"
    return text[: match.start()] + marker + text[match.end() :], True


# The cookie-reading preamble is byte-identical across hundreds of Java cases: it walks
# request.getCookies() and assigns the matching value to `param`. Collapsing it to a one-line
# marker is faithful — the result is attacker-controlled either way, which is the only fact
# the taint trace needs — and every later *use* of `param` is preserved untouched.
_COOKIE_PREAMBLE_RE = re.compile(
    r"[ \t]*javax\.servlet\.http\.Cookie\[\] theCookies = request\.getCookies\(\);\n"
    r".*?\n {8}\}\n",
    re.S,
)


def collapse_cookie_preamble(text: str) -> str:
    return _COOKIE_PREAMBLE_RE.sub(
        "        // [param := attacker-controlled cookie value, URL-decoded]\n", text
    )


_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"')

_CATCH_RE = re.compile(
    r"[ \t]*\} catch \([^)]*(?:\n[^)]*)*?\) \{\n(?P<body>.*?)\n[ \t]*\}\n",
    re.S,
)


def collapse_inert_catches(text: str) -> str:
    """Collapse catch blocks that only report the error, keeping any that touch a sink.

    In these test cases the catch blocks are ~10 lines of identical
    response.getWriter().println(...) + throw. A catch body containing a sink token is
    left intact so the auditor still sees it.
    """

    def repl(match: re.Match[str]) -> str:
        # Strip string literals before looking for sink tokens: these catch blocks print
        # diagnostics like "...Cipher.getInstance... Test Case", and matching a sink token
        # inside a message would wrongly keep every block.
        body = _STRING_LITERAL_RE.sub('""', match.group("body"))
        if any(token in body for token in JAVA_DOGET_SINK_TOKENS):
            return match.group(0)
        return "        } catch (...) { /* [inert catch elided: reports the error, no sink] */ }\n"

    return _CATCH_RE.sub(repl, text)


def load_sample(path: Path) -> list[tuple[str, str]]:
    with path.open(newline="") as fh:
        reader = csv.reader(fh)
        next(reader)  # header
        return [(row[0].strip(), row[1].strip()) for row in reader if len(row) >= 2]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-root", required=True, type=Path)
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--lang", required=True, choices=["java", "python"])
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument(
        "--terse",
        action="store_true",
        help="also drop package/import lines, and any Java doGet with no sink token",
    )
    args = parser.parse_args()

    sample = load_sample(args.sample)
    window = sample[args.start : args.start + args.count]
    if not window:
        print(f"error: no cases in range [{args.start}, {args.start + args.count})", file=sys.stderr)
        return 1

    for test_name, category in window:
        path = case_path(args.benchmark_root, args.lang, test_name)
        if not path.is_file():
            print(f"\n{'=' * 78}\n### {test_name}  [{category}]\n{'=' * 78}")
            print(f"!! missing file: {path}")
            continue

        body = strip_license(path.read_text(encoding="utf-8", errors="replace"), args.lang)
        note = ""
        if args.terse:
            if args.lang == "java":
                body, elided = elide_inert_doget(body)
                if not elided and "doGet" in body:
                    note = "  (doGet KEPT — contains a sink token, read it)"
                body = collapse_inert_catches(collapse_cookie_preamble(body))
            body = "\n".join(
                line
                for line in body.splitlines()
                if not line.startswith(("package ", "import "))
                and "serialVersionUID" not in line
            ).strip()

        print(f"\n{'=' * 78}\n### {test_name}  [{category}]{note}\n{'=' * 78}")
        print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
