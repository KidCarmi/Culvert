#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# assert-release-ref.sh <ref-name>
#
# Release-identity fail-closed guard. An OFFICIAL signed release binary MUST carry
# a real vX.Y.Z tag, stamped into main.version (-X main.version=<tag>) and
# self-reported at runtime on /healthz. This guard refuses to build/sign when the
# release ref name is empty or not a semver tag. It NEVER lets the pipeline fall
# back to an empty / dev / latest / git-SHA version identity.
#
# Context: the first LIVE authoritative MCP Observe Acceptance failed its required
# `artifact.version` criterion because the signed v1.0.202 /healthz reported an
# empty version. This guard (plus assert-runtime-version.sh) makes an empty or
# non-tag release identity impossible to publish.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REF_NAME="${1:-}"

if [ -z "$REF_NAME" ]; then
  echo "::error::release ref_name is EMPTY; refusing to build an official signed binary without a version identity"
  exit 1
fi

if ! printf '%s' "$REF_NAME" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "::error::release ref_name '$REF_NAME' is not a vX.Y.Z tag; refusing to stamp a non-tag version into an official signed binary"
  exit 1
fi

echo "release version identity OK: $REF_NAME"
