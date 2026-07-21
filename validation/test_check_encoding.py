#!/usr/bin/env python3
"""Negative controls for the mojibake checker.

A checker that never rejects anything proves nothing -- the same argument the
schema suite's NegativeControlTests makes. This one earned its keep immediately:
the first version of `MOJIBAKE` matched only the cp1252 round trip and silently
passed every latin-1 one, which is the *more* common form. These tests found
that; reading the regex did not.

Both real-world round trips are reconstructed here from real UTF-8 punctuation,
alongside legitimate accented prose that must NOT be flagged -- a check that
rejects correctly-spelled French would be worse than no check, because someone
would switch it off.

**Like the checker itself, this file is deliberately pure ASCII**, and builds its
fixtures with `chr()`. Spelling the characters out literally made both files trip
the very check they exist to support: their content *is* the byte sequence being
detected. Constructing the fixtures numerically keeps the repo clean while still
exercising the real characters at runtime.

Standard library only.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import check_encoding as ce  # noqa: E402

EM_DASH = chr(0x2014)
LEFT_QUOTE, RIGHT_QUOTE = chr(0x201C), chr(0x201D)
APOSTROPHE = chr(0x2019)
ELLIPSIS = chr(0x2026)
REPLACEMENT = chr(0xFFFD)
BOM = chr(0xFEFF)

# Real UTF-8 punctuation of the kind this repo's prose is full of.
CLEAN = (
    f"SENTINEL {EM_DASH} the numbers get scrutiny. "
    f"{LEFT_QUOTE}quoted{RIGHT_QUOTE}, it{APOSTROPHE}s fine{ELLIPSIS}"
)

# Legitimately accented prose: cafe, naive, resume, uber, Francois, strasse.
ACCENTED = (
    f"caf{chr(0xE9)} na{chr(0xEF)}ve r{chr(0xE9)}sum{chr(0xE9)} "
    f"{chr(0xFC)}ber Fran{chr(0xE7)}ois stra{chr(0xDF)}e"
)


def _roundtrip(text: str, charset: str) -> bytes:
    """Reproduce mojibake: UTF-8 bytes misread as `charset`, then re-encoded."""
    return text.encode("utf-8").decode(charset, errors="replace").encode("utf-8")


class MojibakeDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def _check(self, name: str, data: bytes) -> list[str]:
        path = self.tmp / name
        path.write_bytes(data)
        return ce.check(path)

    def test_clean_utf8_punctuation_is_not_flagged(self):
        """The control that matters most: correct em dashes must pass."""
        self.assertEqual(self._check("clean.md", CLEAN.encode("utf-8")), [])

    def test_latin1_roundtrip_is_flagged(self):
        """The variant the first implementation silently missed."""
        problems = self._check("latin1.md", _roundtrip(CLEAN, "latin-1"))
        self.assertTrue(problems, "latin-1 mojibake went undetected")
        self.assertTrue(any("mojibake" in p for p in problems))

    def test_cp1252_roundtrip_is_flagged(self):
        problems = self._check("cp1252.md", _roundtrip(CLEAN, "cp1252"))
        self.assertTrue(problems, "cp1252 mojibake went undetected")

    def test_legitimate_accented_prose_is_not_flagged(self):
        """Accented letters are followed by letters and spaces, never C1 controls."""
        self.assertEqual(self._check("accents.md", ACCENTED.encode("utf-8")), [])

    def test_replacement_character_is_flagged(self):
        data = f"text with {REPLACEMENT} here".encode("utf-8")
        problems = self._check("lost.md", data)
        self.assertTrue(any("U+FFFD" in p for p in problems))

    def test_undecodable_bytes_are_flagged(self):
        problems = self._check("binary.md", b"\xff\xfe\x00bad")
        self.assertTrue(any("not valid UTF-8" in p for p in problems))

    def test_midfile_bom_is_flagged(self):
        data = f"start\n{BOM}appended".encode("utf-8")
        problems = self._check("bom.md", data)
        self.assertTrue(any("byte-order mark" in p for p in problems))

    def test_leading_bom_alone_is_not_flagged(self):
        """A BOM at position 0 is legal; only a mid-file one signals splicing."""
        self.assertEqual(self._check("lead.md", f"{BOM}fine".encode("utf-8")), [])


class RepositoryIsCleanTests(unittest.TestCase):
    """The repo itself must stay free of encoding damage."""

    def test_no_tracked_file_has_mojibake(self):
        failures = []
        for path in ce.tracked_text_files():
            for problem in ce.check(path):
                failures.append(f"{path.name}: {problem}")
        self.assertEqual(failures, [], f"{len(failures)} encoding problem(s) in tracked files")

    def test_the_checker_and_its_tests_are_pure_ascii(self):
        """Neither file may contain the sequences it exists to reject.

        Spelling the patterns out as literals made both files fail the check.
        Building them with chr() is what resolves it -- assert that, so a later
        edit reintroducing literals fails here rather than in CI.
        """
        for name in ("scripts/check_encoding.py", "validation/test_check_encoding.py"):
            path = ce.REPO_ROOT / name
            self.assertTrue(
                path.read_bytes().isascii(),
                f"{name} must stay pure ASCII; build characters with chr()",
            )


if __name__ == "__main__":
    unittest.main()
