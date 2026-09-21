#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# assert-release-complete.sh <tag>
#
# Refuses to publish a staged release that is missing any required asset.
#
# The needs-chain proves every producing job returned zero; this proves the
# ARTIFACTS actually landed. Those are different claims — `softprops/
# action-gh-release` and the SLSA generator upload as a side effect, and an
# upload that silently no-ops (wrong tag resolution against a draft, a matrix
# leg whose glob matched nothing) leaves a green pipeline and an incomplete
# public release.
#
# Required, derived from ci.yml's own matrix and steps:
#   • 5 proxy binaries + 2 culvert-maint binaries, each with .sigstore.json
#   • 2 CycloneDX SBOMs, each with .sigstore.json
#   • the complete signed catalog bundle culvert-release-catalog-<tag>.tar.gz
#   • SLSA provenance (*.intoto.jsonl)
#
# Fail-closed: an unreadable asset list, a zero-length asset, or any missing
# name refuses. ASSERT_RELEASE_ASSETS_FILE overrides the `gh` query with a
# newline-separated "<name> <size>" list (test seam).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

TAG="${1:?usage: assert-release-complete.sh <tag>}"

if [ -n "${ASSERT_RELEASE_ASSETS_FILE:-}" ]; then
  ASSETS="$(cat "$ASSERT_RELEASE_ASSETS_FILE")"
else
  REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY not set}"
  ASSETS="$(gh api "repos/${REPO}/releases/tags/${TAG}" \
    --jq '.assets[] | "\(.name) \(.size)"')" || {
      echo "::error::cannot read assets of release ${TAG} — refusing to publish"
      exit 1
    }
fi

if [ -z "$ASSETS" ]; then
  echo "::error::release ${TAG} has no assets — refusing to publish"
  exit 1
fi

missing=0
have() {
  # A present-but-EMPTY asset is missing: a 0-byte signature bundle is not a
  # signature. Match the name field exactly.
  awk -v want="$1" '$1 == want && $2 + 0 > 0 { found = 1 } END { exit found ? 0 : 1 }' <<<"$ASSETS"
}
need() {
  if have "$1"; then
    echo "ok: $1"
  else
    echo "::error::release ${TAG} is missing a non-empty asset: $1"
    missing=$((missing + 1))
  fi
}

for pair in "linux amd64" "linux arm64" "darwin amd64" "darwin arm64" "windows amd64"; do
  # Deliberate word split of the "<goos> <goarch>" pair.
  # shellcheck disable=SC2086
  set -- $pair
  ext=""
  [ "$1" = "windows" ] && ext=".exe"
  need "culvert-$1-$2${ext}"
  need "culvert-$1-$2${ext}.sigstore.json"
done

for arch in amd64 arm64; do
  need "culvert-maint-linux-${arch}"
  need "culvert-maint-linux-${arch}.sigstore.json"
done

for sbom in culvert.sbom.cdx.json culvert-maint.sbom.cdx.json; do
  need "$sbom"
  need "${sbom}.sigstore.json"
done

need "culvert-release-catalog-${TAG}.tar.gz"

# SLSA provenance: the generator names the file after the repository, so match
# by suffix rather than pinning a name this workflow does not choose.
if awk '$1 ~ /\.intoto\.jsonl$/ && $2 + 0 > 0 { found = 1 } END { exit found ? 0 : 1 }' <<<"$ASSETS"; then
  echo "ok: SLSA provenance (*.intoto.jsonl)"
else
  echo "::error::release ${TAG} carries no non-empty SLSA provenance (*.intoto.jsonl)"
  missing=$((missing + 1))
fi

if [ "$missing" -ne 0 ]; then
  echo "::error::${missing} required asset(s) missing from ${TAG} — refusing to publish; the release stays a draft"
  exit 1
fi

echo "release ${TAG} is complete (all required assets present and non-empty)"
