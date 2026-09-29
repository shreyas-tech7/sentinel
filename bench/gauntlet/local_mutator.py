#!/usr/bin/env python3
"""Local adversarial-variant generator implementing the Gauntlet contract.

See INTERFACE.md. Deterministic given --seed; produces variants of labeled
vulnerable samples that preserve the flaw while changing its presentation.

    python bench/gauntlet/local_mutator.py mutate \
        --input bench/corpus/sql_injection/sqli_php_mysqli_01.php \
        --out /tmp/variants --seed 42

Defensive scope: operate only on practice fixtures you own. See SECURITY.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sentinel.taint import (  # noqa: E402
    LANG_BY_EXT, TAINT_SOURCES, _string_spans, _interpolates,
)

TECHNIQUES = ["source-indirection", "dead-interlude", "identifier-rename", "comment-noise"]

RENAME_WORDS = [
    "record", "entry", "element", "payload", "candidate", "selection",
    "sample", "datum", "object", "holder", "packet", "parcel", "bundle",
    "token_item", "field", "buffer", "window", "marker", "pointer",
]

COMMENT_PHRASES = [
    "validated upstream", "sanitized by the framework", "trusted internal value",
    "input checked at the edge", "security: value verified",
]

SIGIL = {"php": "$", "js": "", "py": "", "java": "", "go": ""}
STMT_END = {"php": ";", "js": ";", "py": "", "java": ";", "go": ""}
COMMENT = {"php": "//", "js": "//", "py": "#", "java": "//", "go": "//"}


def _outside_strings(line: str, positions: list[tuple[int, int]]) -> list[tuple[int, int]]:
    spans = _string_spans(line)
    out = []
    for s, e in positions:
        if not any(a <= s <= b for a, b, _, _ in spans):
            out.append((s, e))
    return out


def _find_source(lang: str, lines: list[str]) -> tuple[int, re.Match] | None:
    """First in-code occurrence of a taint source, outside string literals."""
    for i, line in enumerate(lines):
        for pat in TAINT_SOURCES[lang]:
            for m in pat.finditer(line):
                if _outside_strings(line, [(m.start(), m.end())]):
                    return i, m
    return None


def _find_sink_line(lang: str, lines: list[str]) -> int:
    """Rough sink locator for interlude/noise placement (last code line)."""
    sink_words = {
        "php": r"\b(query|exec|echo|include|require|system|shell_exec|unserialize|readfile|curl_init)\b",
        "js": r"\b(query|innerHTML|sendFile|writeFile|exec|fetch|unserialize|dangerouslySetInnerHTML)\b",
        "py": r"\b(execute|open|system|loads|urlopen|requests|Markup)\b",
        "java": r"\b(executeQuery|executeUpdate|readObject|openStream|new File|getWriter)\b",
        "go": r"\b(Query|Exec|ReadFile|Command|http\.Get)\b",
    }[lang]
    last = None
    for i, line in enumerate(lines):
        if re.search(sink_words, line):
            last = i
    return last if last is not None else len(lines) - 1


def mutate_source_indirection(lang: str, lines: list[str], seed: int, hops: int = 1) -> list[str]:
    """Introduce temp variables between the taint source and its use.

    Replace-first, then insert declarations — the inserted lines must never be
    rewritten by their own transform.
    """
    found = _find_source(lang, lines)
    if not found:
        return lines
    i, m = found
    sig, end = SIGIL[lang], STMT_END[lang]
    lines = list(lines)

    if lang == "js":
        # declare the temp explicitly; no implicit globals
        pass

    if lang == "java":
        # The source match is an annotation; rewrite uses of the *parameter
        # name* on later lines instead of touching the declaration.
        decl_line = lines[i]
        pm = re.search(r"@\w+\s*(?:\([^)]*\)\s*)?[A-Za-z_.]+\s+([A-Za-z_]\w*)", decl_line)
        if not pm:
            return lines
        param = pm.group(1)
        last_tmp = "gauntletTmp"
        tmp_names = [f"gauntletTmp{h}" for h in range(hops)]
        # replace usages of the param name after the declaration line
        for j in range(i + 1, len(lines)):
            lines[j] = replace_word_outside_strings(lang, lines[j], param, tmp_names[-1])
        # chain the temps
        indent = line_indent(decl_line)
        chain = [f"{indent}String {tmp_names[0]} = {param};"]
        for h in range(1, hops):
            chain.append(f"{indent}String {tmp_names[h]} = {tmp_names[h-1]};")
        for off, decl in enumerate(chain):
            lines.insert(i + 1 + off, decl)
        return lines

    source_text = m.group(0)
    tmp_names = [f"{sig}gauntlet_tmp{h}" for h in range(hops)]
    # 1) replace every in-code occurrence of the source with the final temp
    lines = [replace_outside_strings(lang, l, source_text, tmp_names[-1]) for l in lines]
    # 2) insert the assignment chain right before the (now rewritten) source line,
    #    using the ORIGINAL source text for the first hop
    indent = line_indent(lines[i])
    prev = source_text
    chain = []
    if lang == "go":
        for h in range(hops):
            chain.append(f"{indent}{tmp_names[h].lstrip('$')} := {prev}")
            prev = tmp_names[h]
    else:
        keyword = "const " if lang == "js" else ""
        for h in range(hops):
            chain.append(f"{indent}{keyword}{tmp_names[h]} = {prev}{end}")
            prev = tmp_names[h]
    lines[i:i] = chain
    return lines


def line_indent(line: str) -> str:
    m = re.match(r"\s*", line)
    return m.group(0) if m else ""


def replace_outside_strings(lang: str, line: str, needle: str, repl: str) -> str:
    spans = _string_spans(line)
    out = []
    pos = 0
    for m in re.finditer(re.escape(needle), line):
        if any(a <= m.start() <= b for a, b, _, _ in spans):
            continue
        out.append(line[pos:m.start()])
        out.append(repl)
        pos = m.end()
    out.append(line[pos:])
    return "".join(out)


def mutate_dead_interlude(lang: str, lines: list[str], seed: int) -> list[str]:
    found = _find_source(lang, lines)
    if not found:
        return lines
    i, _ = found
    sig, end = SIGIL[lang], STMT_END[lang]
    if lang == "go":
        decl = "gauntletDead := 1 + 1"
    else:
        decl = f"{sig}gauntletDead = {seed % 97} + 1{end}"
    comment = f"{COMMENT[lang]} gauntlet: dead interlude (seed {seed})"
    insert_at = i + 1
    block = [comment, line_indent(lines[i]) + decl]
    lines = lines[:insert_at] + block + lines[insert_at:]
    return lines


def mutate_identifier_rename(lang: str, lines: list[str], seed: int) -> list[str]:
    # collect assigned variable names
    names = set()
    assign = re.compile(r"(?::=|=)\s")
    decl = re.compile(
        r"^\s*(?:@?\w[\w.\[\]]*\s+)?(?:const|let|var|final|private|public|static|val|my\s+)*"
        r"\$?([A-Za-z_]\w*)\s*(?::=|=)"
    )
    for line in lines:
        m = decl.match(line)
        if m:
            names.add(m.group(1))
    if not names:
        return lines
    mapping = {}
    for k, name in enumerate(sorted(names)):
        mapping[name] = RENAME_WORDS[(seed + k) % len(RENAME_WORDS)]
    out = []
    for line in lines:
        new = line
        for name, repl in mapping.items():
            if name == repl or name in RENAME_WORDS:
                continue
            new = replace_word_outside_strings(lang, new, name, repl)
        out.append(new)
    return out


def replace_word_outside_strings(lang: str, line: str, name: str, repl: str) -> str:
    pat = re.compile(r"\$" + re.escape(name) + r"\b") if lang == "php" \
        else re.compile(r"\b" + re.escape(name) + r"\b")
    spans = _string_spans(line)
    out = []
    pos = 0
    for m in pat.finditer(line):
        in_span = next(((a, b, q, f) for a, b, q, f in spans if a <= m.start() <= b), None)
        if in_span and not _interpolates(lang, in_span[2], in_span[3]):
            continue   # prose inside a plain literal — leave it alone
        out.append(line[pos:m.start()])
        out.append(("$" if lang == "php" else "") + repl)
        pos = m.end()
    out.append(line[pos:])
    return "".join(out)


def mutate_comment_noise(lang: str, lines: list[str], seed: int) -> list[str]:
    found = _find_source(lang, lines)
    if not found:
        return lines
    i, _ = found
    sink = _find_sink_line(lang, lines)
    c = COMMENT[lang]
    phrase_a = COMMENT_PHRASES[seed % len(COMMENT_PHRASES)]
    phrase_b = COMMENT_PHRASES[(seed + 1) % len(COMMENT_PHRASES)]
    lines = list(lines)
    lines.insert(sink + 1 if sink >= i else i, f"{line_indent(lines[min(i, len(lines)-1)])}{c} {phrase_b}")
    lines.insert(i, f"{line_indent(lines[i])}{c} {phrase_a}")
    return lines


TECHNIQUE_FNS = {
    "source-indirection": lambda lang, lines, seed: mutate_source_indirection(lang, lines, seed, hops=1),
    "source-indirection-2": lambda lang, lines, seed: mutate_source_indirection(lang, lines, seed, hops=2),
    "dead-interlude": mutate_dead_interlude,
    "identifier-rename": mutate_identifier_rename,
    "comment-noise": mutate_comment_noise,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mutate(input_path: Path, out_dir: Path, seed: int, techniques: list[str]) -> list[dict]:
    lang = LANG_BY_EXT[input_path.suffix.lower()]
    raw = input_path.read_bytes()
    text = raw.decode("utf-8")
    eol = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(eol)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for technique in techniques:
        fn = TECHNIQUE_FNS.get(technique)
        if fn is None:
            continue
        variant_lines = fn(lang, list(lines), seed)
        variant_text = eol.join(variant_lines)
        if variant_text == text:
            continue  # technique not applicable to this sample
        stem = input_path.stem
        variant_path = out_dir / f"{stem}.{technique}{input_path.suffix}"
        variant_path.write_bytes(variant_text.encode("utf-8"))
        manifest.append({
            "source": str(input_path),
            "variant": str(variant_path),
            "technique": technique,
            "seed": seed,
            "sha256_source": sha256(raw),
            "sha256_variant": sha256(variant_text.encode("utf-8")),
        })
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    m = sub.add_parser("mutate", help="generate adversarial variants of one file")
    m.add_argument("--input", type=Path, required=True)
    m.add_argument("--out", type=Path, required=True)
    m.add_argument("--seed", type=int, default=42)
    m.add_argument("--techniques", default=",".join(TECHNIQUES + ["source-indirection-2"]))
    args = ap.parse_args()
    if args.command == "mutate":
        manifest = mutate(args.input, args.out, args.seed,
                          [t for t in args.techniques.split(",") if t])
        print(json.dumps(manifest, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
