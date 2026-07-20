#!/usr/bin/env bash
# Gate 7 — breaking-change detection for the OpenAPI contract.
#
# Compares the working-tree contract against the PR base (default origin/main)
# using oasdiff (Go-native, pinned). DETECTION ONLY — the intentional-breaking
# EXCEPTION is decided at the workflow level (a reviewed PR label + required
# sections + CODEOWNER approval), never by this script and never by an
# unreviewed environment variable.
#
# Exit codes (consumed by .github/workflows/pr-api-governance.yml):
#   0  no baseline yet, OR no breaking changes  -> gate passes
#   2  breaking changes detected                -> gate consults the exception
#   1  tool/other error (e.g. oasdiff unavailable in strict CI mode) -> HARD FAIL
#
# Strict mode: set CULVERT_BREAKING_STRICT=1 (the CI job sets it). In strict mode
# an unavailable/uninstallable oasdiff is a HARD FAILURE — the gate never silently
# succeeds because the tool could not be installed. Outside strict mode (local /
# air-gapped dev) an unavailable oasdiff skips with a clear message.
set -euo pipefail

OASDIFF_VERSION="v1.11.7"   # PIN — verify against https://github.com/oasdiff/oasdiff/releases before bumping
SPEC="api/openapi/openapi.yaml"
BASE_REF="${BASE_REF:-origin/main}"
STRICT="${CULVERT_BREAKING_STRICT:-0}"

root="$(git rev-parse --show-toplevel)"
cd "$root"

# Resolve oasdiff: prefer PATH, then a cached .tools binary (populated by the CI
# cache), else install the pin. In strict CI an install failure is fatal; in dev
# it is a graceful skip.
if command -v oasdiff >/dev/null 2>&1; then
  OASDIFF=oasdiff
elif [ -x "$(pwd)/.tools/oasdiff" ]; then
  OASDIFF="$(pwd)/.tools/oasdiff"
else
  if GOBIN="$(pwd)/.tools" go install "github.com/oasdiff/oasdiff@${OASDIFF_VERSION}" 2>/dev/null; then
    OASDIFF="$(pwd)/.tools/oasdiff"
  else
    if [ "$STRICT" = "1" ]; then
      echo "breaking-check: FATAL — oasdiff ${OASDIFF_VERSION} could not be installed in strict CI mode." >&2
      echo "breaking-check: the breaking-change gate must not pass without running; failing hard." >&2
      exit 1
    fi
    echo "breaking-check: oasdiff unavailable and could not be installed (offline dev?) — SKIPPING (non-strict)."
    exit 0
  fi
fi

base_spec="$(mktemp)"
trap 'rm -f "$base_spec"' EXIT
if ! git show "${BASE_REF}:${SPEC}" > "$base_spec" 2>/dev/null; then
  echo "breaking-check: no contract on ${BASE_REF} — BASELINE ESTABLISHMENT, gate not yet applicable."
  exit 0
fi

echo "breaking-check: diffing ${BASE_REF}:${SPEC} -> working tree with ${OASDIFF_VERSION}"
if "$OASDIFF" breaking "$base_spec" "$SPEC" --fail-on ERR; then
  echo "breaking-check: no breaking changes."
  exit 0
fi
echo "breaking-check: BREAKING changes detected against ${BASE_REF}." >&2
exit 2
