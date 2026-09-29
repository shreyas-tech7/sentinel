# Gauntlet ⇄ SENTINEL interface

SENTINEL is the defensive scanner; **Gauntlet is its offensive counterpart**: a
generator of adversarial variants of known-vulnerable code samples. Variants
preserve the underlying vulnerability but change its surface presentation —
exactly the transformations real refactoring, obfuscation, and AI-assisted
rewrites produce. Running SENTINEL against them measures how well detection
holds up, which is a defensive robustness question, not an attack recipe.

**Scope rule:** Gauntlet is only ever pointed at the labeled practice samples
in `bench/corpus/` (all authored fixtures) and at the deliberately vulnerable
practice targets in `bench/targets/` (DVWA, Juice Shop, WebGoat). Never at
systems you do not own. See [SECURITY.md](../../SECURITY.md).

## Status

A separate Gauntlet implementation does not exist yet. Until it does, this
repository ships `local_mutator.py`, which implements the same contract below
with four lexical techniques. If/when a `gauntlet` CLI exists, the harness
(`bench/run_robustness.py --gauntlet-cmd gauntlet`) will drive it instead and
the results will say which generator produced the variants.

## Contract

Gauntlet must expose a CLI:

```
gauntlet mutate --input FILE --out DIR --seed N [--techniques t1,t2,…]
```

Behavior:

* Writes one variant file per technique into `DIR`, named
  `<input-stem>.<technique>.<ext>`.
* Every variant preserves the input's vulnerability class (same sink, same
  attacker-controlled data, different presentation).
* Writes `DIR/manifest.json`: a list of records, one per variant:

```json
{
  "source": "bench/corpus/sql_injection/sqli_php_mysqli_01.php",
  "variant": "/tmp/variants/sqli_php_mysqli_01.string-split.php",
  "technique": "string-split",
  "seed": 42,
  "sha256_source": "…",
  "sha256_variant": "…"
}
```

* The harness treats Gauntlet as a black box: any tool emitting this manifest
  plugs in. Variants the tool cannot produce for a given input are simply
  absent from the manifest.

## Techniques implemented by local_mutator.py

| Technique | What it does | Why it is a fair robustness probe |
|---|---|---|
| `source-indirection` | The taint source expression is assigned to a fresh temporary variable on the preceding line; the sink sees only the temp. Two-hop variant: temp → second temp → sink. | The most common real-world shape; defeats scanners that only match sources on the sink line. |
| `dead-interlude` | 1–3 benign statements are inserted between the source and the sink. | Defeats scanners that require source and sink within N lines. |
| `identifier-rename` | Every tracked local variable is renamed to an unrelated word (seeded choice). | Defeats scanners that key on variable names like `password`, `cmd`, `query`. |
| `comment-noise` | Security-themed comments ("validated upstream", "sanitized by the framework") are inserted around the flaw. | Detects scanners that suppress findings when code *claims* to be safe. |

All techniques are deterministic given `--seed` and change code lexically —
they do not alter the dataflow from source to sink.
