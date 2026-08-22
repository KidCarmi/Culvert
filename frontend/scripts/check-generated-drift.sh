#!/bin/sh
# Drift gate for committed generated artifacts (FE-1A qualification
# hardening). `git diff` alone misses a regenerated-but-untracked file (a
# committed deletion), so this uses `git status --porcelain`, which reports
# every tracked-state class — modified, deleted, untracked/recreated,
# renamed — plus an explicit is-tracked assertion for the canonical paths.
#
# Usage: check-generated-drift.sh types|dist
#   run AFTER regenerating (types) or rebuilding (dist); zero porcelain
#   output against the committed tree is the only PASS.
set -eu
cd "$(dirname "$0")/.."
scope="${1:?usage: check-generated-drift.sh types|dist}"

fail() {
  echo "DRIFT($scope): $1" >&2
  echo "Regenerate with the canonical scripts and commit the result;" >&2
  echo "never hand-edit or hand-delete generated artifacts." >&2
  exit 1
}

case "$scope" in
  types)
    git ls-files --error-unmatch src/api/types.gen.ts >/dev/null 2>&1 ||
      fail "src/api/types.gen.ts is not tracked by git (deleted or never committed)"
    status="$(git status --porcelain -- src/api/types.gen.ts)"
    ;;
  dist)
    [ -n "$(git ls-files -- dist)" ] ||
      fail "no tracked files under dist/ (committed output missing)"
    status="$(git status --porcelain -- dist)"
    ;;
  *)
    echo "check-generated-drift.sh: unknown scope '$scope'" >&2
    exit 2
    ;;
esac

if [ -n "$status" ]; then
  echo "$status" >&2
  fail "working tree differs from committed generated output (see porcelain above)"
fi
echo "drift($scope): committed generated output matches regeneration"
