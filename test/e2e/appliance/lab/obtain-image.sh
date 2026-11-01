#!/usr/bin/env bash
# obtain-image.sh DEST_DIR — fetch the CI image tar the candidate OVA was built
# from, and VERIFY it. Source of truth: the Deep PR Gate's `deep-gate-image`
# artifact of $SOURCE_IMAGE_RUN_ID; once that artifact expires, the copy a
# previous lab run preserved (`lab-source-image-<run id>`). Either way the tar
# must hash to $SOURCE_IMAGE_TAR_SHA256 or nothing downstream runs.
# Prints the provenance ("source-run" | "lab-preserved:<artifact id>" |
# "pinned-artifact:<artifact id>") on stdout.
#
# SOURCE_IMAGE_ARTIFACT_ID (optional) pins ONE artifact: exactly that id is
# downloaded, it must be named deep-gate-image or lab-source-image-<run id>
# and be unexpired, and nothing else is tried. SOURCE_IMAGE_ARTIFACT_RUN
# (optional) also pins the run that uploaded it. Unset = the search below.
set -euo pipefail
dest="${1:?DEST_DIR}"; mkdir -p "$dest"
: "${SOURCE_IMAGE_RUN_ID:?}" "${SOURCE_IMAGE_TAR_SHA256:?}" "${GITHUB_REPOSITORY:?}"
from=""
if [[ -n "${SOURCE_IMAGE_ARTIFACT_ID:-}" ]]; then
  [[ "$SOURCE_IMAGE_ARTIFACT_ID" =~ ^[0-9]+$ ]] || { echo "::error::SOURCE_IMAGE_ARTIFACT_ID is not a number" >&2; exit 1; }
  meta="$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$SOURCE_IMAGE_ARTIFACT_ID" --jq '[.name, (.expired|tostring), (.workflow_run.id|tostring)] | @tsv')"
  IFS=$'\t' read -r name expired wrun <<<"$meta"
  echo "pinned artifact $SOURCE_IMAGE_ARTIFACT_ID: name=$name expired=$expired workflow_run=$wrun" >&2
  [[ "$expired" == false ]] || { echo "::error::pinned artifact $SOURCE_IMAGE_ARTIFACT_ID has expired" >&2; exit 1; }
  [[ "$name" == "lab-source-image-$SOURCE_IMAGE_RUN_ID" || ( "$name" == deep-gate-image && "$wrun" == "$SOURCE_IMAGE_RUN_ID" ) ]] \
    || { echo "::error::pinned artifact $SOURCE_IMAGE_ARTIFACT_ID is '$name' from run $wrun, not the image of run $SOURCE_IMAGE_RUN_ID" >&2; exit 1; }
  [[ -z "${SOURCE_IMAGE_ARTIFACT_RUN:-}" || "$wrun" == "$SOURCE_IMAGE_ARTIFACT_RUN" ]] \
    || { echo "::error::pinned artifact $SOURCE_IMAGE_ARTIFACT_ID was uploaded by run $wrun, not $SOURCE_IMAGE_ARTIFACT_RUN" >&2; exit 1; }
  gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$SOURCE_IMAGE_ARTIFACT_ID/zip" > "$dest/pinned.zip"
  unzip -q -o "$dest/pinned.zip" -d "$dest"; rm -f "$dest/pinned.zip"
  echo "$SOURCE_IMAGE_TAR_SHA256  $dest/culvert-image.tar" | sha256sum -c - >&2
  echo "pinned-artifact:$SOURCE_IMAGE_ARTIFACT_ID"
  exit 0
fi
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
