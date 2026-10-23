#!/usr/bin/env bash
# fetch-release-lineage.sh <target-version> <out-dir>
#
# Downloads the ORIGINAL signed catalog asset of every published release that
# is a supported upgrade source for <target-version> (version >= the transition
# floor releaseMinUpgradeFrom, strictly older than the target) into
# <out-dir>/v<version>/, and prints the comma-separated required-version list on
# stdout. The release catalog gate (TestReleaseCatalogGate, release_lineage.go)
# then VERIFIES each bundle with the baked Sigstore root + pinned identity
# before carrying a byte of it; this script is transport only and trusts
# nothing it downloads.
#
# Fail closed: a published supported release with no catalog asset, an asset of
# unexpected shape, or an archive member outside the expected set aborts — the
# alternative is a catalog that silently strands the appliances running that
# release (the agent refuses an upgrade whose running baseline has no signed
# evidence). Requires: gh (GH_TOKEN), jq, GITHUB_REPOSITORY.
set -euo pipefail

target="${1:?target version (X.Y.Z)}"
out="${2:?output directory}"
target="${target#v}"
semver='^[0-9]+\.[0-9]+\.[0-9]+$'
[[ "$target" =~ $semver ]] || { echo "fetch-release-lineage: target $target is not X.Y.Z" >&2; exit 2; }
: "${GITHUB_REPOSITORY:?}"

here="$(cd "$(dirname "$0")/../.." && pwd)"
floor="$(sed -n 's/^const releaseMinUpgradeFrom = "\([0-9.]*\)"$/\1/p' "$here/release_transition_policy.go")"
[[ "$floor" =~ $semver ]] || { echo "fetch-release-lineage: cannot read releaseMinUpgradeFrom" >&2; exit 2; }

# ver_lt A B — true when A < B (semver, numeric per component).
ver_lt() {
  local -a a b; local i
  IFS=. read -ra a <<<"$1"; IFS=. read -ra b <<<"$2"
  for i in 0 1 2; do
    ((10#${a[i]} < 10#${b[i]})) && return 0
    ((10#${a[i]} > 10#${b[i]})) && return 1
  done
  return 1
}

mkdir -p "$out"
releases=""
for page in $(seq 1 50); do
  chunk="$(gh api "repos/$GITHUB_REPOSITORY/releases?per_page=100&page=$page")"
  [ "$(jq 'length' <<<"$chunk")" -gt 0 ] || break
  releases+="$(jq -c '.[] | select(.draft == false) | {tag: .tag_name, assets: [.assets[] | {name, id, size}]}' <<<"$chunk")"$'\n'
done

required=()
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  tag="$(jq -r .tag <<<"$rel")"
  v="${tag#v}"
  [[ "$tag" == v* && "$v" =~ $semver ]] || continue
  ver_lt "$v" "$floor" && continue
  ver_lt "$v" "$target" || continue
  asset="culvert-release-catalog-$tag.tar.gz"
  id="$(jq -r --arg n "$asset" '[.assets[] | select(.name == $n)] | if length == 1 then .[0].id else "" end' <<<"$rel")"
  size="$(jq -r --arg n "$asset" '[.assets[] | select(.name == $n)][0].size // 0' <<<"$rel")"
  [ -n "$id" ] || { echo "fetch-release-lineage: published release $tag has no single $asset (fail closed)" >&2; exit 1; }
  ((size > 0 && size <= 8388608)) || { echo "fetch-release-lineage: $asset size $size out of bounds" >&2; exit 1; }
  tmp="$(mktemp)"
  gh api -H 'Accept: application/octet-stream' "repos/$GITHUB_REPOSITORY/releases/assets/$id" > "$tmp"
  # Only index.json, its signature sidecars and manifests/<file>.json may be
  # extracted; anything else (a path escape, a link, a stray file) aborts.
  while IFS= read -r m; do
    case "$m" in
      index.json|index.json.sigstore|index.json.sig|manifests/|./|./index.json|./index.json.sigstore|./index.json.sig|./manifests/) ;;
      manifests/*.json|./manifests/*.json) [[ "$m" != *..* && "$m" != */*/*/* ]] || { echo "fetch-release-lineage: $asset: unexpected member $m" >&2; exit 1; } ;;
      *) echo "fetch-release-lineage: $asset: unexpected member $m" >&2; exit 1 ;;
    esac
  done < <(tar -tzf "$tmp")
  if tar -tvzf "$tmp" | grep -qv '^[-d]'; then
    echo "fetch-release-lineage: $asset carries a non-regular member (fail closed)" >&2; exit 1
  fi
  mkdir -p "$out/$tag"
  tar -xzf "$tmp" -C "$out/$tag" --no-same-owner --no-same-permissions
  rm -f "$tmp"
  test -s "$out/$tag/index.json" || { echo "fetch-release-lineage: $asset has no index.json" >&2; exit 1; }
  required+=("$v")
  echo "fetch-release-lineage: $tag -> $out/$tag" >&2
done <<<"$releases"

(IFS=,; echo "${required[*]}")
