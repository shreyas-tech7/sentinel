#!/usr/bin/env python3
"""Run a comparison scanner inside a disposable virtualenv, then delete it.

Why this exists: installing Semgrep for the v5.0 and v6.0 comparison runs
downgraded `mcp`, `jsonschema`, and `opentelemetry-api` in the environment that
happened to be active, because Semgrep pins those transitively. The damage had
to be undone by hand afterwards, twice. A comparison run is a *measurement* --
it has no business mutating the machine it measures from.

This script makes that structural rather than remembered. The scanner is
installed into a throwaway venv under a temp directory, invoked from that
venv's own interpreter, and the whole tree is removed when the run ends --
including on failure or Ctrl-C. Nothing is ever installed into the interpreter
running this script, so the system environment cannot be reached even by a
dependency resolver that wants to.

    python validation/run_comparator.py --tool semgrep==1.170.0 \
        --out validation/data/semgrep-raw.json \
        -- scan --config semgrep-rules/java --json --quiet --metrics=off <files...>

Everything after `--` is passed through to the tool verbatim.

`--verify-isolation` records the versions of the packages Semgrep is known to
disturb before and after the run and fails loudly if any of them moved, so the
guarantee is checked rather than asserted. `--keep` leaves the venv in place
for debugging and prints its path.

Standard library only; needs network access for the install step.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

# Packages Semgrep has pinned-and-downgraded here before. Checked before and
# after the run when --verify-isolation is passed.
WITNESS_PACKAGES = ("mcp", "jsonschema", "opentelemetry-api")


def witness_versions() -> dict[str, str]:
    """Versions of the witness packages in the *calling* interpreter."""
    import importlib.metadata as md

    versions: dict[str, str] = {}
    for name in WITNESS_PACKAGES:
        try:
            versions[name] = md.version(name)
        except md.PackageNotFoundError:
            versions[name] = "<absent>"
    return versions


def venv_python(root: Path) -> Path:
    """Path to the interpreter inside a created venv, per platform layout."""
    candidate = root / ("Scripts" if sys.platform == "win32" else "bin") / (
        "python.exe" if sys.platform == "win32" else "python"
    )
    if not candidate.exists():
        raise FileNotFoundError(f"no interpreter at {candidate}")
    return candidate


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=False, text=True, capture_output=True, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tool",
        required=True,
        help="pip requirement to install, pinned (e.g. semgrep==1.170.0). "
        "Pin it: an unpinned comparator makes the run unreproducible.",
    )
    parser.add_argument(
        "--entrypoint",
        default=None,
        help="console script to invoke; defaults to the package name in --tool",
    )
    parser.add_argument("--out", type=Path, default=None, help="write tool stdout here")
    parser.add_argument("--keep", action="store_true", help="do not delete the venv")
    parser.add_argument(
        "--verify-isolation",
        action="store_true",
        help="fail if any witness package version changed across the run",
    )
    parser.add_argument("tool_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    tool_args = args.tool_args[1:] if args.tool_args[:1] == ["--"] else args.tool_args
    package = args.tool.split("==")[0].split("[")[0]
    entrypoint = args.entrypoint or package

    if "==" not in args.tool:
        print(f"warning: {args.tool} is unpinned; the run will not be reproducible", file=sys.stderr)

    before = witness_versions()
    print(f"host interpreter : {sys.executable}")
    print(f"witness packages : {before}")

    workdir = Path(tempfile.mkdtemp(prefix="sentinel-comparator-"))
    try:
        env_root = workdir / "venv"
        print(f"creating disposable venv at {env_root}")
        venv.EnvBuilder(with_pip=True, clear=True).create(env_root)
        python = venv_python(env_root)

        print(f"installing {args.tool} (isolated; the host environment is not a target)")
        proc = run([str(python), "-m", "pip", "install", "--quiet", args.tool])
        if proc.returncode != 0:
            print(proc.stdout, file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
            print(f"error: install of {args.tool} failed", file=sys.stderr)
            return 1

        installed = run(
            [str(python), "-c", f"import importlib.metadata as m; print(m.version({package!r}))"]
        )
        print(f"installed in venv: {package}=={installed.stdout.strip()}")

        script = env_root / ("Scripts" if sys.platform == "win32" else "bin") / entrypoint
        if sys.platform == "win32" and not script.exists():
            script = script.with_suffix(".exe")
        if not script.exists():
            print(f"error: no entrypoint {entrypoint!r} in the venv", file=sys.stderr)
            return 1

        print(f"running: {entrypoint} {' '.join(tool_args)}")
        result = run([str(script), *tool_args])
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(result.stdout, encoding="utf-8")
            print(f"wrote {len(result.stdout)} bytes to {args.out}")
        else:
            sys.stdout.write(result.stdout)
        if result.stderr.strip():
            print(result.stderr, file=sys.stderr)
        tool_rc = result.returncode
    finally:
        if args.keep:
            print(f"venv kept at {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
            print("disposable venv removed")

    after = witness_versions()
    if args.verify_isolation:
        drift = {k: (before[k], after[k]) for k in before if before[k] != after[k]}
        if drift:
            print(f"ISOLATION FAILED -- host packages moved: {json.dumps(drift)}", file=sys.stderr)
            return 2
        print(f"isolation verified: {list(before)} unchanged in the host environment")

    return tool_rc


if __name__ == "__main__":
    raise SystemExit(main())
