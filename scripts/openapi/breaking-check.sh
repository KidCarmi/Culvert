#!/usr/bin/env bash
# Gate 7 — breaking-change detection for the OpenAPI contract.
#
# Compares the working-tree contract against the merge base using oasdiff
# (Go-native, pinned). This is the BASELINE-ESTABLISHMENT-aware gate: if the
# base has no contract yet (first OpenAPI PR), it exits 0 — the gate becomes
# mandatory only after the baseline merges.
#
# Any breaking change fails the build. To intentionally ship one, follow the
# documented exception process (docs/api/API-VERSIONING-POLICY.md): a labelled,
# reviewed override with rationale + migration notes + named approver.
set -euo pipefail

OASDIFF_VERSION="v1.11.7"   # PIN — verify against https://github.com/oasdiff/oasdiff/releases before bumping
SPEC="api/openapi/openapi.yaml"
BASE_REF="${BASE_REF:-origin/main}"

root="$(git rev-parse --show-toplevel)"
cd "$root"

# Resolve oasdiff (already on PATH, else install the pin; skip gracefully offline).
if command -v oasdiff >/dev/null 2>&1; then
  OASDIFF=oasdiff
else
  if ! GOBIN="$(pwd)/.tools" go install "github.com/oasdiff/oasdiff@${OASDIFF_VERSION}" 2>/dev/null; then
    echo "breaking-check: oasdiff unavailable and could not be installed (offline?) — SKIPPING (deep/scheduled gate)."
    exit 0
  fi
  OASDIFF="$(pwd)/.tools/oasdiff"
fi

base_spec="$(mktemp)"
trap 'rm -f "$base_spec"' EXIT
if ! git show "${BASE_REF}:${SPEC}" > "$base_spec" 2>/dev/null; then
  echo "breaking-check: no contract on ${BASE_REF} — BASELINE ESTABLISHMENT, gate not yet mandatory."
  exit 0
fi

echo "breaking-check: diffing ${BASE_REF}:${SPEC} -> working tree with ${OASDIFF_VERSION}"
"$OASDIFF" breaking "$base_spec" "$SPEC" --fail-on ERR
echo "breaking-check: no breaking changes."
