#!/bin/sh
# Drift-gate regression harness (FE-1A qualification hardening §4).
#
# Proves the generated-artifact drift gate itself cannot regress, by running
# the dangerous tamper classes against a SYNTHETIC repository built from the
# committed tree (git archive HEAD) — the real repository is never mutated:
#
#   A. one committed byte modified in types.gen.ts          -> gate FAILS
#   B. types.gen.ts committed-deleted, then regenerated      -> gate FAILS
#      (the class `git diff --exit-code` could not see)
#   C. unexpected committed file under dist/                 -> gate FAILS
#   D. committed dist asset deleted, then rebuilt            -> gate FAILS
#   E. clean canonical regeneration                          -> gate PASSES
#
# Requires the real workspace to have node_modules installed (run after
# `npm ci`); dependency trees are hardlink-copied into the synthetic repo so
# no per-case network install is needed.
set -eu
FRONTEND="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$FRONTEND/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
REPO="$WORK/repo"
mkdir -p "$REPO"

# Synthetic repo = the committed frontend + the OpenAPI document, re-inited
# so tamper commits never touch the real repository.
git -C "$ROOT" archive HEAD frontend api/openapi/openapi.json |
  tar -x -C "$REPO"
(
  cd "$REPO"
  git init -q
  git config user.email drift-harness@invalid
  git config user.name drift-harness
  git add -A
  git commit -qm base
  git tag base
)
cp -al "$FRONTEND/node_modules" "$REPO/frontend/node_modules"
cp -al "$FRONTEND/tools/openapi-gen/node_modules" \
  "$REPO/frontend/tools/openapi-gen/node_modules"

FE="$REPO/frontend"

regen() { (cd "$FE" && node tools/openapi-gen/generate.mjs >/dev/null); }
rebuild() { (cd "$FE" && npm run build >/dev/null 2>&1); }
gate() { (cd "$FE" && sh scripts/check-generated-drift.sh "$1" >/dev/null 2>&1); }
reset_base() {
  (
    cd "$REPO"
    git reset -q --hard base
    git clean -qfd -- frontend/dist frontend/src/api
  )
}

expect_fail() {
  case_id="$1"
  shift
  if "$@"; then
    echo "drift-harness: case $case_id — gate PASSED but must FAIL" >&2
    exit 1
  fi
  echo "drift-harness: case $case_id — gate failed as required"
}
expect_pass() {
  case_id="$1"
  shift
  if ! "$@"; then
    echo "drift-harness: case $case_id — gate FAILED but must PASS" >&2
    exit 1
  fi
  echo "drift-harness: case $case_id — gate passed as required"
}

# A. modified committed byte in types.gen.ts
printf '// tampered\n' >>"$FE/src/api/types.gen.ts"
(cd "$REPO" && git commit -qam "tamper A")
regen
expect_fail A gate types
reset_base

# B. committed deletion of types.gen.ts; regeneration recreates it UNTRACKED
(cd "$REPO" && git rm -q frontend/src/api/types.gen.ts && git commit -qm "tamper B")
regen
expect_fail B gate types
reset_base

# C. unexpected committed file under dist (build wipes it -> tracked deletion)
printf 'rogue\n' >"$FE/dist/rogue.txt"
(cd "$REPO" && git add frontend/dist/rogue.txt && git commit -qm "tamper C")
rebuild
expect_fail C gate dist
reset_base

# D. committed deletion of a generated dist asset; rebuild recreates UNTRACKED
css="$(cd "$FE/dist" && ls assets/*.css | head -1)"
(cd "$REPO" && git rm -q "frontend/dist/$css" && git commit -qm "tamper D")
rebuild
expect_fail D gate dist
reset_base

# E. clean canonical regeneration passes both gates
regen
rebuild
expect_pass E-types gate types
expect_pass E-dist gate dist

echo "drift-harness: all cases behaved correctly (A–D fail, E passes)"
