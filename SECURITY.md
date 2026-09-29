# Security Policy

## Intended use

SENTINEL is a **defensive** security-review tool. It exists to help engineers audit code they
own or are explicitly authorized to review, identify weaknesses, and fix them. Use it only for:

- code and infrastructure you own,
- systems you have written authorization to test (e.g. an engagement scope, a bug-bounty program
  that permits it, or your employer's assets), or
- educational study of your own deliberately vulnerable practice targets.

Do not use SENTINEL, its catalog, or its example payloads to probe or attack systems you do not
control. Findings are always paired with remediations; attack scenarios exist to justify severity
and motivate the fix, not to weaponize. If a request would orient the tool toward attacking a
third party, it is out of scope for this project.

## Benchmark targets: what they are and are not

The benchmark in [`bench/`](bench/) runs exclusively against **published, deliberately
vulnerable practice targets**: the labeled sample corpus vendored in `bench/corpus/`, OWASP
DVWA, OWASP Juice Shop, and OWASP WebGoat, cloned at pinned commits by
[`bench/fetch_targets.sh`](bench/fetch_targets.sh). The rules that govern this:

- **Source scanning only.** The targets are read as files. They are never installed, served,
  deployed, or run as applications by any script in this repository.
- **Nothing else is scanned by the benchmark.** The harness has no configuration to point it at
  arbitrary hosts, and the Gauntlet-style variant generator only rewrites files from the labeled
  corpus. If you extend the tooling, keep it that way.
- **Variants stay in the lab.** Adversarial variants are generated from labeled practice
  samples into temporary directories, scored, and deleted. They exist to measure detector
  robustness, not to distribute bypass techniques; the techniques themselves (renaming
  variables, inserting dead code) are trivial and documented in
  [`bench/gauntlet/INTERFACE.md`](bench/gauntlet/INTERFACE.md).

Using this project's tooling against systems without ownership or permission remains out of
scope, exactly as above.

## Reporting a vulnerability *in this repository*

This policy covers weaknesses in the SENTINEL project itself — for example, a documentation error
that would cause a reader to ship an insecure "fix," a remediation snippet with a bug, an example
report that leaks a real secret, or a supply-chain issue in anything this repo ships.

**Please do not open a public issue for a security problem.** Instead:

1. Use GitHub's **[Report a vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
   (Security → Advisories → *Report a vulnerability*) on this repository, **or**
2. Email the maintainer at the address listed on the GitHub profile that owns this repo, with
   `SENTINEL SECURITY` in the subject.

Include: what the problem is, where in the repo it lives (file and line), why it matters, and — if
you have one — a suggested fix. If you believe an example report contains an unredacted secret or a
detail that could aid a live attacker, flag that as **urgent** so it can be pulled immediately.

### What to expect

- **Acknowledgement** within 5 business days.
- An initial assessment (accepted / needs-info / declined, with reasoning) within 10 business days.
- Credit in the changelog for the fix, unless you ask to remain anonymous.

This is a volunteer-maintained open-source project, not a funded program; there is no bug bounty.
Good-faith reports made under this policy are welcome and will not be met with legal action.

## Redaction guarantee for example reports

Every file under [`examples/`](examples/) is redacted and educational. The vulnerabilities shown
were remediated before publication, secrets are replaced with obvious placeholders
(`<REDACTED_API_KEY>`, `sb-service-role-key-REDACTED`), and internal identifiers are sanitized. If
you find anything in an example that looks like a live secret or a real, unpatched internal detail,
report it under the process above and it will be treated as urgent. See
[`examples/README.md`](examples/README.md) for the full redaction policy.

## Supported versions

The methodology is stable; security-relevant updates (framework-mapping refreshes, remediation
corrections) are made on the latest version only. Pin a tag if you need reproducibility, but track
the latest release for current guidance.
