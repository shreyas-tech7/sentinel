# External Validation

SENTINEL's accuracy claims are checked against **public, purpose-built ground truth** that anyone can
clone and re-score — not against the maintainer's own projects.

| File | Target | What it proves |
|---|---|---|
| [METHODOLOGY.md](METHODOLOGY.md) | — | What was tested, how scoring worked, and how to reproduce it. |
| [owasp-benchmark-results.md](owasp-benchmark-results.md) | [OWASP Benchmark](https://owasp.org/www-project-benchmark/) | Scored true/false-positive accuracy against Benchmark's documented `expectedresults` labels. |
| [juice-shop-results.md](juice-shop-results.md) | [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | An app-shaped (not synthetic) check against Juice Shop's own challenge list, including its LLM/prompt-injection challenges. |

Ground rules: **static source review only** — no live attacks, no exploitation, no dynamic testing,
including against these targets. Misses are reported as misses and fed back into the
[vulnerability catalog](../skill/references/vulnerability-catalog.md) as gaps to close.
