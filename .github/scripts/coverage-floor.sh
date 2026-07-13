#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# coverage-floor.sh — the ONE implementation of both coverage contracts.
#
# Usage: coverage-floor.sh <coverage.out>
#
# Enforces:
#   1. the GLOBAL floor (whole-repo health metric), and
#   2. per-file floors on the security-sensitive surface — a drop below a
#      floor usually means a new branch was added without tests.
#
# Called from pr-fast-gate.yml (PRs) AND qa-gate.yml (main pushes). Before
# consolidation the floors table existed byte-for-byte in both workflows,
# which run on DIFFERENT events — a floor bump in one only surfaced as a
# confusing post-merge red on main (CI review, maintainability P0-3/P1-6).
# Edit floors HERE and only here.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

COVERAGE_OUT="${1:?usage: coverage-floor.sh <coverage.out>}"

GLOBAL_FLOOR=55

# file → floor%. Every file listed is security-sensitive.
FLOORS="
totp.go                85
security.go            70
session.go             75
lockout.go             80
policy.go              60
autoexclude.go         85
autoexclude_resolve.go 80
"

FUNC=$(go tool cover -func="$COVERAGE_OUT")
fail=0

TOTAL=$(echo "$FUNC" | awk '/^total:/ {gsub(/%/,"",$3); print $3}')
echo "── Global coverage ──"
echo "  total ... ${TOTAL}% (floor ${GLOBAL_FLOOR}%)"
awk -v p="$TOTAL" -v f="$GLOBAL_FLOOR" 'BEGIN { exit (p+0 < f+0) ? 1 : 0 }' || {
  echo "::error::total coverage ${TOTAL}% below the ${GLOBAL_FLOOR}% floor"
  fail=1
}

check () {
  local file="$1" floor="$2"
  local pct
  # Anchored match: require "/<file>:" so security.go doesn't also match
  # ui_security.go (and policy.go doesn't match cdrpolicy.go / ui_policy.go,
  # etc.). index() on a literal string keeps the check invariant to any
  # regex-special characters in the name.
  pct=$(echo "$FUNC" | awk -v f="$file" '
    index($1, "/" f ":") > 0 {
      match($NF, /[0-9.]+/); sum += substr($NF, RSTART, RLENGTH); n++
    }
    END { if (n>0) printf "%.1f", sum/n; else printf "0.0" }')
  echo "  $file ... ${pct}% (floor ${floor}%)"
  awk -v p="$pct" -v f="$floor" 'BEGIN { exit (p+0 < f+0) ? 1 : 0 }' || {
    echo "::error file=$file::coverage ${pct}% below floor ${floor}%"
    fail=1
  }
}

echo "── Gate-critical coverage ──"
while read -r file floor; do
  [ -z "$file" ] && continue
  check "$file" "$floor"
done <<< "$FLOORS"

exit $fail
