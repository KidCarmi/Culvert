#!/usr/bin/env bash
# Gate 9 — generate a typed Go client from the contract and compile it.
#
# Proves the contract is code-generation-safe. Generates into a throwaway module
# so the main build is never polluted by generated code.
#
# Strict mode: set CULVERT_CLIENTGEN_STRICT=1 (the CI job sets it). In strict mode
# an unavailable/uninstallable pinned generator, a generation failure, or a
# compile failure of the generated client is a HARD FAILURE — CI never silently
# succeeds because the tool was missing. Outside strict mode (local / air-gapped
# dev) an unavailable generator skips with a clear message.
set -euo pipefail

OAPI_CODEGEN_VERSION="v2.4.1"  # PIN — verify against https://github.com/oapi-codegen/oapi-codegen/releases before bumping
SPEC="api/openapi/openapi.json"
STRICT="${CULVERT_CLIENTGEN_STRICT:-0}"

root="$(git rev-parse --show-toplevel)"
cd "$root"

fail_or_skip() {
  # $1 = human message
  if [ "$STRICT" = "1" ]; then
    echo "generate-client: FATAL — $1 (strict CI mode)." >&2
    echo "generate-client: the client-generation gate must not pass without generating + compiling; failing hard." >&2
    exit 1
  fi
  echo "generate-client: $1 — SKIPPING (non-strict local/air-gapped dev)."
  exit 0
}

tools="$(pwd)/.tools"
# Reuse a cached binary (CI restores .tools) before reinstalling.
if [ ! -x "$tools/oapi-codegen" ]; then
  if ! GOBIN="$tools" go install "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" 2>/dev/null; then
    fail_or_skip "oapi-codegen ${OAPI_CODEGEN_VERSION} could not be installed"
  fi
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

# In strict CI a generation OR compile failure (type collisions, invalid schema,
# bad generated code) must fail the gate — not skip. In dev it degrades to a skip.
if [ "$STRICT" = "1" ]; then
  ( cd "$work" && "$tools/oapi-codegen" -config cfg.yaml openapi.json && go mod tidy && go build ./... )
  echo "generate-client: typed Go client generated and compiled OK (strict CI)."
else
  if ( cd "$work" && "$tools/oapi-codegen" -config cfg.yaml openapi.json && go mod tidy && go build ./... ); then
    echo "generate-client: typed Go client generated and compiled OK."
  else
    fail_or_skip "client generation/compile failed"
  fi
fi
