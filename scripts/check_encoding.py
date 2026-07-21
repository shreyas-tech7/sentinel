#!/usr/bin/env python3
"""Flag mojibake and encoding damage in tracked text files.

Two incidents motivate this check, both platform-specific and both self-inflicted:

  * v7.0 -- a PowerShell here-string mangled a commit message.
  * v8.0 -- a cp1252/UTF-8 round trip mojibaked PR bodies, turning every em dash
    and curly quote into noise before it was caught and repaired.

Both share a cause: text passing through a Windows shell that assumes cp1252
while the content is UTF-8. The damage is easy to miss -- the file still opens,
the prose still reads, and only the punctuation is wrong -- so it survives review
and lands.

What this flags:

  * **Mojibake signatures** -- the residue of UTF-8 bytes decoded as a
    single-byte charset and re-encoded.
  * **U+FFFD** -- the replacement character, meaning bytes were already lost.
  * **Undecodable bytes** -- a file that is not valid UTF-8 at all.
  * **A byte-order mark anywhere but the very start**, the signature of two
    differently-encoded fragments having been concatenated.

What it deliberately does *not* flag: correctly encoded non-ASCII. An em dash
stored as the proper UTF-8 e2 80 94 is right, and this repo's own scripts print
one. The check reads bytes rather than terminal output for exactly that reason --
a Windows console renders a valid em dash as a replacement glyph, and mistaking
that console artifact for file damage sends a reader chasing a bug that is not
there.

**This file is deliberately pure ASCII**, and its character classes are built
with `chr()` rather than written as literals. The first version spelled them out,
which made the checker flag its own source: the patterns it searches for are, by
construction, exactly the byte sequences it must reject. Building them numerically
removes the paradox and makes the file immune to the corruption it detects.

Standard library only. Exits non-zero when anything is flagged.
"""

from __future__ import annotations

import re
import subprocess
import sys
import unicodedata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

TEXT_SUFFIXES = {
    ".md", ".py", ".yml", ".yaml", ".json", ".csv", ".txt", ".toml",
    ".cfg", ".ini", ".sh", ".ps1",
}
TEXT_NAMES = {".gitattributes", ".gitignore"}

# The residue of a UTF-8 -> single-byte-charset -> UTF-8 round trip.
#
# Two variants exist and both must be caught -- an earlier version caught only
# one. A UTF-8 em dash is the bytes e2 80 94. Decoded as **cp1252** those become
# U+00E2, U+20AC (EURO SIGN), U+201D; decoded as **latin-1** the same bytes become
# U+00E2 and the raw C1 controls U+0080, U+0094. A pattern built around the
# Euro-sign form silently passes every latin-1 round trip -- and latin-1 is the
# more common one. That gap was found by the negative-control tests in
# validation/test_check_encoding.py, not by reading the regex.
#
# The reliable signature is a *pair*: a character in the range UTF-8 lead bytes
# occupy when misread as Latin-1, immediately followed by something only a
# continuation byte could have produced. Requiring the pair is what keeps
# legitimate accented text from tripping the check -- in real prose an accented
# letter is followed by a letter or a space, never by a C1 control or a stray
# Euro sign.
_LEAD_FIRST, _LEAD_LAST = 0xC2, 0xF4  # UTF-8 lead bytes, seen as Latin-1
_TAIL_FIRST, _TAIL_LAST = 0x80, 0xBF  # UTF-8 continuation bytes, seen as Latin-1
_CP1252_C1 = (  # the glyphs cp1252 maps bytes 80..9f onto
    0x20AC, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030,
    0x0160, 0x2039, 0x0152, 0x017D, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022,
    0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x017E, 0x0178,
)

_LEAD = f"{chr(_LEAD_FIRST)}-{chr(_LEAD_LAST)}"
_TAIL = f"{chr(_TAIL_FIRST)}-{chr(_TAIL_LAST)}" + "".join(chr(c) for c in _CP1252_C1)
MOJIBAKE = re.compile(f"[{_LEAD}][{_TAIL}]")

REPLACEMENT = chr(0xFFFD)
BOM = chr(0xFEFF)


def tracked_text_files() -> list[Path]:
    """Every tracked file that is meant to be human-readable text."""
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    files = []
    for rel in out.split("\0"):
        if not rel:
            continue
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            files.append(path)
    return files


def _describe(text: str, index: int) -> str:
    """Name the offending characters, since they are invisible in a terminal."""
    snippet = text[index : index + 3]
    names = " ".join(f"U+{ord(c):04X}({unicodedata.name(c, 'control')})" for c in snippet)
    return f"{ascii(snippet)} -- {names}"


def check(path: Path) -> list[str]:
    """Return a list of human-readable problems; empty means clean."""
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"not valid UTF-8 at byte {exc.start}: {exc.reason}"]

    problems = []
    for match in MOJIBAKE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        problems.append(f"line {line}: mojibake {_describe(text, match.start())}")
    for index, char in enumerate(text):
        if char == REPLACEMENT:
            line = text.count("\n", 0, index) + 1
            problems.append(
                f"line {line}: U+FFFD replacement character -- bytes already lost"
            )
    if BOM in text[1:]:
        index = text.index(BOM, 1)
        line = text.count("\n", 0, index) + 1
        problems.append(f"line {line}: byte-order mark mid-file -- concatenated encodings")
    return problems


def main() -> int:
    files = tracked_text_files()
    failures: list[str] = []
    for path in files:
        for problem in check(path):
            failures.append(f"{path.relative_to(REPO_ROOT).as_posix()}: {problem}")

    if failures:
        print(f"FAIL - {len(failures)} encoding problem(s):\n", file=sys.stderr)
        for line in failures[:40]:
            print(f"  {line}", file=sys.stderr)
        if len(failures) > 40:
            print(f"  ... and {len(failures) - 40} more", file=sys.stderr)
        print(
            "\nOn Windows, write files with a direct file-write rather than a shell\n"
            "heredoc or PowerShell here-string; those round-trip through cp1252.",
            file=sys.stderr,
        )
        return 1

    print(f"OK - {len(files)} tracked text files scanned, no mojibake or lost bytes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
