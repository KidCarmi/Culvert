#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# mcp-doc-predicates.sh — run the MCP design-document structural predicates.
#
# Why this exists.  Board blocker #927 took three PRs and four verification
# rounds, and EVERY intermediate head passed the full CI pipeline while still
# carrying a real defect — including one where the config-surface matrix did
# not parse as a table at all, so every assertion quantified over it passed
# vacuously.  CI carried no signal because no CI job parsed these documents:
# the predicates existed, but ran only when a human remembered to run them.
# This script is the runner that closes that gap.
#
# EXPLICIT ALLOWLIST, not a glob.  `predicate-*.py` would make every future
# predicate blocking the moment it is checked in, with no review of whether it
# is fit to gate a merge.  Adding a predicate here is a deliberate act.
#
# predicate-25 is DELIBERATELY EXCLUDED.  It is remediation/provenance-specific:
# it diffs against a fixed historical base commit (`1203e04b`) to check that a
# particular remediation's provenance claims match its actual diff.  Run as a
# general gate it would fail an unrelated, perfectly valid PR merely for
# changing a requirement or decision after that historical point.  It stays
# manual — see docs/design/mcp/predicates/README.md.
#
# Contract: no network, no package installation, no document mutation, no
# generated output.  Python standard library only.  Fails on the FIRST
# non-zero predicate; prints the single success line only after all pass.
#
# Usage (from any working directory):
#     .github/scripts/mcp-doc-predicates.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Resolve the repository root from this script's own location, so the runner
# works from any working directory — the predicates read paths relative to the
# root and would otherwise fail confusingly on "file not found".
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

PREDICATE_DIR="docs/design/mcp/predicates"

# Fixed order, explicit membership. Keep numerically sorted for readability.
PREDICATES=(
  predicate-19.py
  predicate-21.py
  predicate-22.py
  predicate-23.py
  predicate-24.py
  predicate-26.py
)

echo "MCP design-document predicates"
echo "  repository root : $REPO_ROOT"
echo "  python          : $(python3 --version 2>&1)"
echo "  predicates      : ${#PREDICATES[@]} (explicit allowlist; predicate-25 excluded by design)"
echo

failed=""
for p in "${PREDICATES[@]}"; do
  path="$PREDICATE_DIR/$p"
  echo "───────────────────────────────────────────────────────────────────"
  echo "▶ $p"
  echo "───────────────────────────────────────────────────────────────────"
  if [ ! -f "$path" ]; then
    # A missing predicate is a failure, never a silent skip — an allowlist that
    # quietly tolerates absent members is the vacuity class these predicates
    # exist to catch.
    echo "::error::$path not found — the allowlist names a predicate that does not exist"
    failed="$p"
    break
  fi
  if ! python3 "$path"; then
    echo "::error::$p FAILED — see the violations printed above"
    failed="$p"
    break
  fi
  echo "✔ $p passed"
  echo
done

# Never leave build residue behind.
rm -rf "$PREDICATE_DIR/__pycache__"

if [ -n "$failed" ]; then
  echo
  echo "FAIL: $failed did not pass. Remaining predicates were not run."
  exit 1
fi

echo "PASS: all ${#PREDICATES[@]} MCP design-document predicates passed."
