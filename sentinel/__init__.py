"""SENTINEL — runnable static-analysis core of the SENTINEL audit methodology.

This package implements the deterministic subset of the SENTINEL methodology:
the Phase-3 "adversarial code scan" as a set of explainable, line-oriented
rules with a small intra-file taint model. It is the component the benchmark
in `bench/` measures. The full six-phase workflow (context, STRIDE threat
modeling, regression audit, remediation) remains a review methodology — see
`skill/SKILL.md`.
"""

__version__ = "4.1.0"
