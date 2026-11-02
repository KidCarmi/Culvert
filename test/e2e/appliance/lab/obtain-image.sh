#!/usr/bin/env bash
# obtain-image.sh DEST_DIR — fetch the CI image tar the candidate OVA was built
# from, and VERIFY it. Source of truth: the Deep PR Gate's `deep-gate-image`
# artifact of $SOURCE_IMAGE_RUN_ID; once that artifact expires, the copy a
# previous lab run preserved (`lab-source-image-<run id>`). Either way the tar
# must hash to $SOURCE_IMAGE_TAR_SHA256 or nothing downstream runs.
# Prints the provenance ("source-run" | "lab-preserved:<artifact id>") on stdout.
set -euo pipefail
dest="${1:?DEST_DIR}"; mkdir -p "$dest"
: "${SOURCE_IMAGE_RUN_ID:?}" "${SOURCE_IMAGE_TAR_SHA256:?}" "${GITHUB_REPOSITORY:?}"
from=""
# The artifacts API (not `gh run download`) so a source run that is still in
# progress — its image job long finished — can be used.
for attempt in 1 2 3; do
  id="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$SOURCE_IMAGE_RUN_ID/artifacts" \
        --jq '.artifacts[] | select(.name == "deep-gate-image" and .expired == false) | .id' | head -1)"
  if [[ -n "$id" ]] && gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$id/zip" > "$dest/source.zip" \
     && unzip -q -o "$dest/source.zip" -d "$dest"; then rm -f "$dest/source.zip"; from=source-run; break; fi
  echo "source-run download failed (attempt $attempt)" >&2; sleep $((attempt * 5))
done
if [[ -z "$from" ]]; then
  id="$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts?name=lab-source-image-$SOURCE_IMAGE_RUN_ID&per_page=20" \
        --jq '[.artifacts[] | select(.expired == false)] | sort_by(.created_at) | last | .id // empty')"
  if [[ -n "$id" ]]; then
    gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$id/zip" > "$dest/preserved.zip"
    unzip -q -o "$dest/preserved.zip" -d "$dest"; rm -f "$dest/preserved.zip"; from="lab-preserved:$id"
  fi
fi
[[ -n "$from" ]] || { echo "::error::image tar unavailable: run $SOURCE_IMAGE_RUN_ID's artifact is gone and no lab copy is preserved — rebuild a SEPARATELY identified image" >&2; exit 1; }
echo "$SOURCE_IMAGE_TAR_SHA256  $dest/culvert-image.tar" | sha256sum -c - >&2
echo "$from"
