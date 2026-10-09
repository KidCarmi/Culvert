#!/usr/bin/env bash
# resolve-lab-pins.sh HEAD_SHA [--require-green]
# Derive every appliance-lab pin for a PR head from GitHub's own records:
#   Deep PR Gate run for that head_sha -> deep-gate-image artifact -> tar
#   sha256 + OCI image id (index.json manifests[0].digest, same rule as the
#   lab's own assertion) + both required gates' conclusions.
# Read-only (gh api GETs). Prints KEY=VALUE lines a sed/yq step (or a workflow
# resolve job) applies; it never edits anything itself.
set -euo pipefail
sha="${1:?HEAD_SHA (full 40-hex)}"; want_green="${2:-}"
repo="${GITHUB_REPOSITORY:-KidCarmi/Culvert}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "need the full 40-hex SHA" >&2; exit 2; }
run_for() {  # newest run of workflow file $1 at this exact head SHA
  gh api "repos/$repo/actions/workflows/$1/runs?head_sha=$sha&per_page=20" \
    --jq '[.workflow_runs[] | select(.event=="pull_request" or .event=="workflow_dispatch")] | sort_by(.run_number) | last | "\(.id) \(.status) \(.conclusion // "-")"'
}
read -r deep_id deep_status deep_concl <<<"$(run_for pr-deep-gate.yml)"
read -r fast_id fast_status fast_concl <<<"$(run_for pr-fast-gate.yml)"
[[ -n "$deep_id" && "$deep_id" != null ]] || { echo "no Deep PR Gate run for $sha" >&2; exit 1; }
if [[ "$want_green" == --require-green ]] && [[ "$deep_concl" != success || "$fast_concl" != success ]]; then
  echo "gates not green: deep=$deep_status/$deep_concl fast=$fast_status/$fast_concl" >&2; exit 1; fi
art="$(gh api "repos/$repo/actions/runs/$deep_id/artifacts" \
  --jq '.artifacts[] | select(.name=="deep-gate-image" and .expired==false) | "\(.id) \(.digest)"' | head -1)"
read -r art_id art_zip_digest <<<"$art"
[[ -n "$art_id" ]] || { echo "deep-gate-image not (yet) uploaded in run $deep_id" >&2; exit 1; }
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
gh api "repos/$repo/actions/artifacts/$art_id/zip" > "$w/a.zip"
# The zip digest GitHub recorded at upload must match what we downloaded.
[[ "sha256:$(sha256sum "$w/a.zip" | cut -d' ' -f1)" == "$art_zip_digest" ]] || { echo "artifact zip digest mismatch" >&2; exit 1; }
unzip -q "$w/a.zip" -d "$w"
tar_sha="$(sha256sum "$w/culvert-image.tar" | cut -d' ' -f1)"
img_id="$(tar -xOf "$w/culvert-image.tar" index.json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["manifests"][0]["digest"])')"
cat <<EOF
SOURCE_SHA=$sha
VARIANT=candidate-${sha:0:12}
IMAGE_RUN=$deep_id
IMAGE_ARTIFACT_ID=$art_id
IMAGE_ARTIFACT_ZIP_DIGEST=$art_zip_digest
IMAGE_TAR_SHA256=$tar_sha
IMAGE_ID=$img_id
DEEP_GATE=$deep_status/$deep_concl
FAST_GATE_RUN=$fast_id
FAST_GATE=$fast_status/$fast_concl
EOF
