#!/usr/bin/env bash
# Run the full PR-safe, Go-native, offline API gate locally.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"; cd "$root"
go run ./cmd/apibundle -check
go test ./internal/apicontract/... -count=1
go test . -run 'TestOpenAPI_|TestConformance_' -count=1
echo "API contract verified."
