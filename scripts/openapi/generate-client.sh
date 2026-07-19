#!/usr/bin/env bash
# Gate 9 — generate a typed Go client from the contract and compile it.
#
# Proves the contract is code-generation-safe. Generates into a throwaway module
# so the main build is never polluted by generated code. Deep/scheduled gate:
# skips gracefully when oapi-codegen cannot be installed (air-gap without mirror).
set -euo pipefail

OAPI_CODEGEN_VERSION="v2.4.1"  # PIN — verify against https://github.com/oapi-codegen/oapi-codegen/releases before bumping
SPEC="api/openapi/openapi.json"

root="$(git rev-parse --show-toplevel)"
cd "$root"

tools="$(pwd)/.tools"
if ! GOBIN="$tools" go install "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" 2>/dev/null; then
  echo "generate-client: oapi-codegen unavailable (offline?) — SKIPPING (deep/scheduled gate)."
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$SPEC" "$work/openapi.json"
cat > "$work/go.mod" <<GOMOD
module culvertapiclient

go 1.25

require github.com/oapi-codegen/runtime v1.1.1
GOMOD
cat > "$work/cfg.yaml" <<CFG
package: apiclient
generate:
  models: true
  client: true
output: client.gen.go
CFG
( cd "$work" && "$tools/oapi-codegen" -config cfg.yaml openapi.json && go mod tidy && go build ./... )
echo "generate-client: typed Go client generated and compiled OK."
