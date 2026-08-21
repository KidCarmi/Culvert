#!/bin/sh
# Canonical FE-1A verification contract (docs/design/FRONTEND-MIGRATION-PLAN.md
# §1). CI runs exactly this script; developers run `npm run verify`. Order:
#   toolchain identity -> clean install -> type generation + drift ->
#   lint/format -> strict typecheck -> unit tests -> production build +
#   committed-dist drift -> bundle security scan -> license policy ->
#   vulnerability policy.
set -eu
cd "$(dirname "$0")/.."

echo "== [1/9] toolchain identity"
sh scripts/assert-toolchain.sh

echo "== [2/9] clean install (npm ci; lifecycle scripts disabled via .npmrc)"
npm ci --no-audit --no-fund

echo "== [3/9] OpenAPI type generation + drift gate"
sh scripts/generate-types.sh
if ! git diff --exit-code -- src/api/types.gen.ts; then
  echo "DRIFT: src/api/types.gen.ts differs from regenerated output." >&2
  echo "Run 'npm run generate' and commit the result; never hand-edit it." >&2
  exit 1
fi

echo "== [4/9] lint + format"
npm run lint
npm run format:check

echo "== [5/9] strict typecheck"
npm run typecheck

echo "== [6/9] unit tests"
npm test

echo "== [7/9] production build + committed-dist drift gate"
npm run build
if [ -n "$(git status --porcelain -- dist)" ]; then
  git status --porcelain -- dist >&2
  git diff -- dist | head -50 >&2 || true
  echo "DRIFT: frontend/dist differs from the committed build output" >&2
  echo "(added/removed/renamed/changed file). Rebuild and commit; never" >&2
  echo "hand-edit dist." >&2
  exit 1
fi

echo "== [8/9] generated-bundle security scan"
node scripts/check-dist.mjs

echo "== [9/9] license + vulnerability policy"
sh scripts/check-licenses.sh
npm audit --audit-level=high
(cd tools/openapi-gen && npm audit --audit-level=high)

echo "frontend verify: ALL GATES PASSED"
