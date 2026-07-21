#!/usr/bin/env python3
"""Validate real serialized SENTINEL output against the findings schema.

`scripts/check_schema.py` is the stdlib-only CI guard: it proves the schema file
is well-formed and that the one worked example in `docs/FINDINGS_SCHEMA.md` still
satisfies it. What it cannot do -- deliberately, because it hand-rolls its checks
rather than depending on a package -- is run a real draft-2020-12 validator over
real output. That is this file's job.

It validates three archived corpora, serialized by `serialize_findings.py`:

  * 14 findings from the prose audit reports in `examples/` -- against the FULL
    schema, every required field included. These are real SENTINEL reports, so
    this is the test that actually answers "does SENTINEL output conform".
  * 41 Juice Shop coverage records -- against a partial profile, because scoring
    records carry no `attack_scenario`, `impact`, or CWE.
  * 117 Benchmark true-positive verdicts -- against a partial profile, with real
    CWEs read from the Benchmark's own ground-truth CSV.

The partial profiles are *derived from the live schema at runtime*, relaxing only
the required-field list. Every type, enum, pattern, and `additionalProperties`
rule still applies, so a schema change still breaks these tests.

`jsonschema` is not in the repo's stdlib-only default. Locally, absent it, the
validator-backed tests skip. In CI it is installed and `SENTINEL_REQUIRE_JSONSCHEMA=1`
is set, which turns a missing validator into a failure rather than a silent skip
-- otherwise "green CI" could mean "the real check never ran".
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import serialize_findings as sf  # noqa: E402

REQUIRE = os.environ.get("SENTINEL_REQUIRE_JSONSCHEMA") == "1"

try:
    from jsonschema import Draft202012Validator

    HAVE_JSONSCHEMA = True
    IMPORT_ERROR = ""
except ImportError as exc:  # pragma: no cover - environment-dependent
    Draft202012Validator = None  # type: ignore[assignment]
    HAVE_JSONSCHEMA = False
    IMPORT_ERROR = str(exc)


def _validator_guard(test: unittest.TestCase) -> None:
    """Fail in CI, skip locally, when the real validator is unavailable."""
    if HAVE_JSONSCHEMA:
        return
    message = (
        f"jsonschema is not installed ({IMPORT_ERROR}); "
        "schema conformance was NOT verified"
    )
    if REQUIRE:
        test.fail(message + " -- SENTINEL_REQUIRE_JSONSCHEMA=1 forbids skipping this")
    test.skipTest(message)


def _errors(validator, finding: dict) -> list[str]:
    return [
        f"{list(e.path)}: {e.message}"
        for e in sorted(validator.iter_errors(finding), key=lambda e: list(e.path))
    ]


class SchemaShapeTests(unittest.TestCase):
    """Guards that hold with or without the validator installed."""

    def test_schema_is_valid_draft_2020_12(self):
        _validator_guard(self)
        Draft202012Validator.check_schema(sf.load_schema())

    def test_partial_profile_relaxes_only_required(self):
        schema = sf.load_schema()
        profile = sf.partial_profile(schema, sf.JUICE_SHOP_FIELDS)
        self.assertLess(set(profile["required"]), set(schema["required"]))
        for key in ("properties", "additionalProperties", "type"):
            self.assertEqual(profile[key], schema[key], f"{key} must not be relaxed")

    def test_partial_profile_does_not_mutate_the_schema(self):
        schema = sf.load_schema()
        before = list(schema["required"])
        sf.partial_profile(schema, sf.BENCHMARK_FIELDS)
        self.assertEqual(schema["required"], before)


# Four archived findings omit the **Attack Scenario** and **Impact** bullets that
# SKILL.md's "Output format" marks as part of every finding block. This was found
# by running this test for the first time, not known beforehand.
#
# The schema is not what is wrong here: the report template mandates both fields,
# so these four deviate from SENTINEL's own contract rather than exposing an
# over-strict schema. All four are Low-severity defense-in-depth findings whose
# analysis says there is no active exploit path -- which explains the omission but
# does not license it, since a dependency-range finding still has a describable
# scenario ("a transitive advisory ships in a caret bump and reaches production").
#
# The example reports are frozen historical artifacts and are deliberately not
# edited to make a test pass. So the deviation is pinned here instead: the set is
# asserted to be exactly these four. A new report that drops the fields, or one of
# these gaining them, breaks this test and forces a fresh look.
KNOWN_INCOMPLETE = {
    "atlas-marketing-003",
    "atlas-marketing-004",
    "bjj-academy-005",
    "promptvault-005",
}
INCOMPLETE_FIELDS = ("attack_scenario", "impact")


class ReportExportConformanceTests(unittest.TestCase):
    """The headline check: real prose reports -> complete, conformant findings."""

    @classmethod
    def setUpClass(cls):
        cls.findings = sf.collect("reports")

    def test_every_report_finding_was_parsed(self):
        # Three redacted reports; each documents its findings under `###` headings.
        self.assertGreaterEqual(len(self.findings), 14)

    def test_full_schema_conformance(self):
        """Every complete finding validates against the unmodified schema."""
        _validator_guard(self)
        validator = Draft202012Validator(sf.load_schema())
        failures = []
        for finding in self.findings:
            if finding["id"] in KNOWN_INCOMPLETE:
                continue
            errors = _errors(validator, finding)
            if errors:
                failures.append(f"{finding['id']}: {'; '.join(errors)}")
        self.assertEqual(failures, [], f"{len(failures)} report finding(s) non-conformant")

    def test_incomplete_set_is_exactly_the_documented_four(self):
        """Pin the template deviation so it cannot grow or vanish unnoticed."""
        observed = {
            f["id"]
            for f in self.findings
            if any(not f.get(field) for field in INCOMPLETE_FIELDS)
        }
        self.assertEqual(observed, KNOWN_INCOMPLETE)

    def test_the_deviation_is_confined_to_low_severity(self):
        for finding in self.findings:
            if finding["id"] in KNOWN_INCOMPLETE:
                self.assertEqual(finding["severity"], "Low", finding["id"])

    def test_incomplete_findings_conform_apart_from_the_missing_bullets(self):
        """They are otherwise well-formed -- the gap is those two fields only."""
        _validator_guard(self)
        carried = tuple(
            f for f in sf.load_schema()["required"] if f not in INCOMPLETE_FIELDS
        )
        validator = Draft202012Validator(sf.partial_profile(sf.load_schema(), carried))
        for finding in self.findings:
            if finding["id"] not in KNOWN_INCOMPLETE:
                continue
            stripped = {k: v for k, v in finding.items() if v != ""}
            self.assertEqual(_errors(validator, stripped), [], finding["id"])

    def test_complete_findings_populate_every_required_field(self):
        schema = sf.load_schema()
        for finding in self.findings:
            if finding["id"] in KNOWN_INCOMPLETE:
                continue
            for field in schema["required"]:
                self.assertIn(field, finding, f"{finding['id']} missing {field}")
                self.assertTrue(finding[field], f"{finding['id']} has empty {field}")


class JuiceShopConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = sf.collect("juice-shop")

    def test_all_three_passes_are_covered(self):
        # v6 (21) + v7 blind (14) + v7 rescan (6)
        self.assertEqual(len(self.findings), 41)

    def test_partial_profile_conformance(self):
        _validator_guard(self)
        profile = sf.partial_profile(sf.load_schema(), sf.JUICE_SHOP_FIELDS)
        validator = Draft202012Validator(profile)
        failures = []
        for finding in self.findings:
            errors = _errors(validator, finding)
            if errors:
                failures.append(f"{finding.get('id')}: {'; '.join(errors)}")
        self.assertEqual(failures, [], f"{len(failures)} Juice Shop record(s) non-conformant")

    def test_locations_parse_to_a_real_file_path(self):
        for finding in self.findings:
            file = finding["location"]["file"]
            self.assertRegex(file, r"\.[A-Za-z0-9]+$", f"{finding['id']} location.file={file!r}")


class BenchmarkConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.findings = sf.collect("benchmark")
        except FileNotFoundError as exc:
            raise unittest.SkipTest(f"Benchmark ground truth unavailable: {exc}")

    def test_true_positives_were_serialized(self):
        self.assertGreater(len(self.findings), 100)

    def test_partial_profile_conformance(self):
        _validator_guard(self)
        profile = sf.partial_profile(sf.load_schema(), sf.BENCHMARK_FIELDS)
        validator = Draft202012Validator(profile)
        failures = []
        for finding in self.findings:
            errors = _errors(validator, finding)
            if errors:
                failures.append(f"{finding.get('id')}: {'; '.join(errors)}")
        self.assertEqual(failures, [], f"{len(failures)} Benchmark record(s) non-conformant")

    def test_cwes_come_from_ground_truth_as_integers(self):
        for finding in self.findings:
            cwe = finding["classification"]["cwe"]
            self.assertTrue(cwe and all(isinstance(n, int) for n in cwe), finding["id"])


class BenchmarkFixtureTests(unittest.TestCase):
    """The Benchmark corpus tests must run everywhere, not skip quietly in CI.

    Before 9.0.0 the three tests above skipped in CI, because the ground truth
    was only reachable through a sibling Benchmark clone that CI does not have.
    A skip is a silent pass: the suite stayed green while 117 records went
    unchecked. Vendoring a fixture fixed it -- and this asserts the fixture is
    still there, so deleting it fails loudly instead of quietly reopening the
    gap.
    """

    def test_vendored_ground_truth_is_committed(self):
        for lang in ("java", "python"):
            path = sf.REPO_ROOT / "validation" / "data" / f"benchmark-truth-{lang}.csv"
            self.assertTrue(
                path.is_file(),
                f"{path.name} missing -- BenchmarkConformanceTests will skip in CI, "
                f"which reads as a pass while checking nothing",
            )

    def test_fixture_covers_every_scored_case(self):
        """A partial fixture raises KeyError mid-run; catch it here instead."""
        try:
            findings = sf.collect("benchmark")
        except KeyError as exc:
            self.fail(f"vendored ground truth is missing a scored case: {exc}")
        self.assertGreater(len(findings), 100)


class NegativeControlTests(unittest.TestCase):
    """A validator that never rejects anything proves nothing."""

    def test_bad_severity_is_rejected(self):
        _validator_guard(self)
        validator = Draft202012Validator(sf.load_schema())
        finding = dict(sf.collect("reports")[0], severity="Catastrophic")
        self.assertTrue(_errors(validator, finding))

    def test_string_cwe_is_rejected(self):
        _validator_guard(self)
        profile = sf.partial_profile(sf.load_schema(), sf.BENCHMARK_FIELDS)
        validator = Draft202012Validator(profile)
        finding = sf.collect("juice-shop")[0]
        finding = dict(finding, classification={"cwe": ["89"]})
        self.assertTrue(_errors(validator, finding))

    def test_unknown_field_is_rejected(self):
        _validator_guard(self)
        profile = sf.partial_profile(sf.load_schema(), sf.JUICE_SHOP_FIELDS)
        validator = Draft202012Validator(profile)
        finding = dict(sf.collect("juice-shop")[0], invented_field="x")
        self.assertTrue(_errors(validator, finding))


if __name__ == "__main__":
    unittest.main()
