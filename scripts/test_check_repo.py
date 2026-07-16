#!/usr/bin/env python3
"""Tests for check_repo.py and gen_coverage_matrix.py.

Runs under pytest (`pytest scripts/`) or standalone (`python scripts/test_check_repo.py`).
Every case builds a tiny synthetic repo in a temp dir — the tests never depend on the
real catalog, so they assert the checks' behavior, not the current repo's state.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_repo as cr  # noqa: E402
import gen_coverage_matrix as gcm  # noqa: E402

CATALOG_GOOD = """# Catalog

## SENT-AUTHZ-01 — Broken Object Level Authorization / IDOR
- **Classification:** OWASP A01:2025 (Broken Access Control) · API1:2023 (Broken Object Level
  Authorization) · CWE-639 (Authorization Bypass Through User-Controlled Key — #24 on the 2025
  CWE Top 25), CWE-284 (Improper Access Control) · ASVS 5.0 ch. 8 (Authorization).
- **Severity tendency:** High.

## SENT-INJ-02 — Cross-Site Scripting (XSS)
- **Classification:** OWASP A05:2025 (Injection) · CWE-79 (Improper Neutralization — #1 on the 2025
  CWE Top 25) · ASVS 5.0 ch. 1 (Encoding and Sanitization).
- **Severity tendency:** High.

## SENT-ARCH-01 — Dead code masking a security control
- **Classification:** OWASP A06:2025 (Insecure Design) · CWE-561 (Dead Code).
- **Severity tendency:** Informational.

## SENT-ARCH-05 — Security-focused regression trap
- **Classification:** OWASP A06:2025 / A04:2025 (per the control) · CWE-358 (Improperly Implemented
  Security Check for Standard).
- **Severity tendency:** Medium.
"""

REMEDIATION_GOOD = """# Remedies

### SENT-AUTHZ-01 — Enforce object ownership server-side
code.

### SENT-INJ-02 — Encode on output
code.

### SENT-ARCH-01 — Remove or wire the dead control
code.

### SENT-ARCH-05 — Complete the half-present control
code.
"""


@contextmanager
def tmp_repo(catalog: str = CATALOG_GOOD, remediation: str = REMEDIATION_GOOD,
             validation: dict[str, str] | None = None):
    with TemporaryDirectory() as d:
        root = Path(d)
        refs = root / "skill" / "references"
        refs.mkdir(parents=True)
        (refs / "vulnerability-catalog.md").write_text(catalog, encoding="utf-8")
        (refs / "remediation-patterns.md").write_text(remediation, encoding="utf-8")
        val = root / "validation"
        val.mkdir()
        for name in ("METHODOLOGY.md", "owasp-benchmark-results.md", "juice-shop-results.md"):
            content = (validation or {}).get(name, f"# {name}\n\nReal content.\n")
            (val / name).write_text(content, encoding="utf-8")
        yield root


def _edition_errors(catalog: str) -> list[str]:
    with tmp_repo(catalog) as root:
        errs: list[str] = []
        cr.check_catalog_editions(root, errs)
        return errs


# ── slugify ──────────────────────────────────────────────────────────────────

def test_slugify_em_dash_yields_double_hyphen():
    got = cr.slugify("SENT-AUTHZ-01 — Broken Object Level Authorization / IDOR")
    assert got == "sent-authz-01--broken-object-level-authorization--idor", got


# ── edition sanity ───────────────────────────────────────────────────────────

def test_good_catalog_has_no_edition_errors():
    assert _edition_errors(CATALOG_GOOD) == []


def test_stale_2021_code_is_flagged():
    bad = CATALOG_GOOD.replace("A01:2025", "A01:2021")
    errs = _edition_errors(bad)
    assert any("stale OWASP 2021" in e for e in errs), errs


def test_owasp_code_name_swap_is_flagged():
    # A06 is Insecure Design; naming it Authentication Failures (A07's name) must fail.
    bad = CATALOG_GOOD.replace("A06:2025 (Insecure Design)", "A06:2025 (Authentication Failures)")
    errs = _edition_errors(bad)
    assert any("A06:2025 is 'Insecure Design'" in e for e in errs), errs


def test_qualifier_parenthetical_is_not_flagged():
    # "A04:2025 (per the control)" is a qualifier, not a name — must not trip the check.
    assert not any("A04:2025" in e for e in _edition_errors(CATALOG_GOOD))


def test_wrong_cwe_rank_is_flagged():
    # CWE-79 is #1; claiming #5 must fail.
    bad = CATALOG_GOOD.replace("#1 on the 2025", "#5 on the 2025")
    errs = _edition_errors(bad)
    assert any("CWE-79 is #1" in e for e in errs), errs


def test_cwe_not_in_top25_is_flagged():
    bad = CATALOG_GOOD.replace(
        "CWE-561 (Dead Code)", "CWE-561 (Dead Code — #7 on the 2025 CWE Top 25)"
    )
    errs = _edition_errors(bad)
    assert any("not in the 2025 Top 25" in e for e in errs), errs


# ── class parity ─────────────────────────────────────────────────────────────

def test_class_parity_mismatch_is_flagged():
    missing = REMEDIATION_GOOD.replace(
        "### SENT-ARCH-05 — Complete the half-present control\ncode.\n", ""
    )
    with tmp_repo(remediation=missing) as root:
        errs: list[str] = []
        cr.check_class_parity(root, errs)
        assert any("SENT-ARCH-05" in e and "no remediation" in e for e in errs), errs


def test_class_parity_clean_passes():
    with tmp_repo() as root:
        errs: list[str] = []
        cr.check_class_parity(root, errs)
        assert errs == [], errs


# ── validation stub guard ────────────────────────────────────────────────────

def test_validation_stub_is_flagged():
    stub = {"juice-shop-results.md": "# X\n\n*(Stub — written later.)*\n"}
    with tmp_repo(validation=stub) as root:
        errs: list[str] = []
        cr.check_validation_not_stub(root, errs)
        assert any("juice-shop-results.md" in e for e in errs), errs


def test_validation_complete_passes():
    with tmp_repo() as root:
        errs: list[str] = []
        cr.check_validation_not_stub(root, errs)
        assert errs == [], errs


# ── dead links ───────────────────────────────────────────────────────────────

def test_dead_link_is_flagged():
    with tmp_repo() as root:
        page = root / "page.md"
        page.write_text("See [gone](does-not-exist.md).\n", encoding="utf-8")
        errs: list[str] = []
        cr.check_links(root, [page], errs)
        assert any("dead link" in e for e in errs), errs


# ── coverage matrix generator ────────────────────────────────────────────────

def test_coverage_matrix_extracts_ids_and_classifications():
    out = gcm.build_matrix(CATALOG_GOOD)
    assert "**4 classes.**" in out, out
    assert "[SENT-AUTHZ-01](vulnerability-catalog.md#sent-authz-01--broken-object-level-authorization--idor)" in out
    assert "A01:2025" in out and "CWE-639" in out and "V8" in out
    # The qualifier-only class still lists its OWASP codes.
    assert "A06:2025, A04:2025" in out


# ── runner (no pytest required) ──────────────────────────────────────────────

def _run() -> int:
    tests = sorted(
        (name, fn)
        for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    )
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"ok    {name}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {name}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
