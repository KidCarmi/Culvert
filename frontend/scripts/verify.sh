#!/bin/sh
# Canonical FE-1A verification contract (docs/design/FRONTEND-MIGRATION-PLAN.md
# §1). CI runs exactly this script; developers run `npm run verify`. Order:
#   toolchain identity -> clean install + lifecycle-script policy proof ->
#   type generation + drift -> lint/format -> strict typecheck -> unit tests ->
#   production build + committed-dist drift -> bundle security scan ->
#   license policy -> vulnerability policy.
set -eu
cd "$(dirname "$0")/.."

echo "== [1/9] toolchain identity"
sh scripts/assert-toolchain.sh

echo "== [2/9] clean install + lifecycle-script policy (both npm trees)"
npm ci --ignore-scripts --no-audit --no-fund
# Prove the ignore-scripts posture is effective policy in BOTH package trees
# (frontend/.npmrc and tools/openapi-gen/.npmrc), not an accident of flags.
[ "$(npm config get ignore-scripts)" = "true" ] || {
  echo "POLICY: ignore-scripts is not true in the app tree" >&2
  exit 1
}
(
  cd tools/openapi-gen
  [ "$(npm config get ignore-scripts)" = "true" ] || {
    echo "POLICY: ignore-scripts is not true in tools/openapi-gen" >&2
    exit 1
  }
)
echo "ignore-scripts: true (app tree) / true (openapi-gen tree)"

echo "== [3/9] OpenAPI type generation + drift gate"
sh scripts/generate-types.sh
sh scripts/check-generated-drift.sh types

echo "== [4/9] lint + format"
npm run lint
npm run format:check

echo "== [5/9] strict typecheck"
npm run typecheck

echo "== [6/9] unit tests"
npm test

echo "== [7/9] production build + committed-dist drift gate"
npm run build
sh scripts/check-generated-drift.sh dist

echo "== [8/9] generated-bundle security scan"
node scripts/check-dist.mjs

echo "== [9/9] license + vulnerability policy"
sh scripts/check-licenses.sh
npm audit --audit-level=high
(cd tools/openapi-gen && npm audit --audit-level=high)

echo "frontend verify: ALL GATES PASSED"
