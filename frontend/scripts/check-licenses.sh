#!/bin/sh
# FE-1A license policy gate: every package in both dependency trees (app +
# generator workspace) must carry an allow-listed license. The allowlist is
# reviewed policy (ADR-FE-001 dependency policy) — extending it is a reviewed
# change to this file, never an ad-hoc CI edit.
set -eu
cd "$(dirname "$0")/.."

ALLOW="MIT;ISC;Apache-2.0;BSD-2-Clause;BSD-3-Clause;0BSD;CC0-1.0;BlueOak-1.0.0;CC-BY-4.0;CC-BY-3.0;Python-2.0;Unlicense;MPL-2.0"

echo "licenses: app tree"
./node_modules/.bin/license-checker-rseidelsohn \
  --onlyAllow "$ALLOW" \
  --excludePrivatePackages \
  --summary

echo "licenses: openapi-gen tree"
cd tools/openapi-gen
../../node_modules/.bin/license-checker-rseidelsohn \
  --onlyAllow "$ALLOW" \
  --excludePrivatePackages \
  --summary
