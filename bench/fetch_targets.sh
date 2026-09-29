#!/usr/bin/env bash
# Fetch the public practice targets used by the SENTINEL benchmark.
#
# These are deliberately vulnerable applications published for security
# training. They are cloned OUTSIDE the repository tree by default (or into a
# gitignored directory) and are never committed, never deployed, never run as
# services by this script — only their source code is scanned.
#
# Usage:
#   TARGETS_DIR=/tmp/bench-targets bash bench/fetch_targets.sh
#
# pins come from bench/groundtruth/*.json — keep them in sync.
set -euo pipefail

TARGETS_DIR="${TARGETS_DIR:-/tmp/bench-targets}"
mkdir -p "$TARGETS_DIR"

fetch() {
  local repo="$1" dir="$2" sha="$3"
  if [ -d "$TARGETS_DIR/$dir/.git" ]; then
    echo "✓ $dir already present"
    return
  fi
  echo "→ cloning $repo at pinned commit $sha"
  # Fetch the exact pinned commit; fall back to a branch clone + verification.
  if ! git init -q "$TARGETS_DIR/$dir" 2>/dev/null; then
    echo "  could not init $dir" >&2; exit 1
  fi
  git -C "$TARGETS_DIR/$dir" remote add origin "$repo"
  if git -C "$TARGETS_DIR/$dir" fetch -q --depth 1 origin "$sha" 2>/dev/null; then
    git -C "$TARGETS_DIR/$dir" checkout -q FETCH_HEAD
  else
    echo "  pinned-SHA fetch rejected; cloning default branch and verifying"
    git -C "$TARGETS_DIR/$dir" fetch -q --depth 1 origin
    actual="$(git -C "$TARGETS_DIR/$dir" log -1 --format=%H FETCH_HEAD)"
    if [ "$actual" != "$sha" ]; then
      echo "  WARNING: $dir moved — HEAD is $actual, benchmark pinned $sha" >&2
      echo "           results may differ from the published numbers." >&2
    fi
  fi
  echo "✓ $dir at $(git -C "$TARGETS_DIR/$dir" log -1 --format='%h %cs')"
}

mkdir -p "$TARGETS_DIR/.tmp"
fetch https://github.com/digininja/DVWA.git        DVWA        b496a5d3de6b967410155e1b7d3e51e9d035eb22
fetch https://github.com/juice-shop/juice-shop.git juice-shop  1618a611b173b4bf114028e6e02549950606e29d
fetch https://github.com/WebGoat/WebGoat.git       WebGoat     3284a8e466dfde083858f681e89aabb94e8b9c9e

echo
echo "Targets ready in $TARGETS_DIR. Run the benchmark with:"
echo "  python bench/run_benchmark.py --targets-dir $TARGETS_DIR"
