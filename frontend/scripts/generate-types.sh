#!/bin/sh
# Regenerates frontend/src/api/types.gen.ts from the committed
# api/openapi/openapi.json using the isolated, exactly-pinned generator
# workspace (frontend/tools/openapi-gen). Offline after `npm ci`.
set -eu
cd "$(dirname "$0")/.."
sh scripts/assert-toolchain.sh
cd tools/openapi-gen
npm ci --no-audit --no-fund
node generate.mjs
