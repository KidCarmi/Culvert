#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# candidate-platform-ref.sh <image> <index digest> <platform>
#
# Prints <image>@<manifest digest> for exactly one platform of the candidate
# index, read live from the registry. Anything that pulls or runs one platform
# of the candidate uses this reference: Docker's classic image store keeps one
# image per digest reference, so pulling <image>@<index digest> for a second
# platform fails with "cannot overwrite digest" (main run 36111817278).
#
# Seams: DOCKER_BIN, JQ_BIN.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE="${1:?usage: candidate-platform-ref.sh <image> <index digest> <platform>}"
DIGEST="${2:?index digest required}"
PLATFORM="${3:?platform required}"

HERE="$(dirname "$0")"
# lib/registry.sh reads DOCKER_BIN unguarded; set the default before sourcing it.
DOCKER_BIN="${DOCKER_BIN:-docker}"
# shellcheck source=.github/scripts/lib/registry.sh
. "$HERE/lib/registry.sh"
# shellcheck source=.github/scripts/lib/candidate.sh
. "$HERE/lib/candidate.sh"

valid_digest "$DIGEST" || { echo "::error::malformed index digest '${DIGEST}'" >&2; exit 1; }
LINES="" ; LRC=0
LINES="$(index_platforms "$IMAGE" "$DIGEST")" || LRC=$?
[ "$LRC" -eq 0 ] || { echo "::error::cannot read the index ${IMAGE}@${DIGEST}: ${LINES}" >&2; exit 1; }
PD="$(platform_digest "$LINES" "$PLATFORM")" || { echo "::error::${PLATFORM}: no single manifest digest in the index ${IMAGE}@${DIGEST}" >&2; exit 1; }
printf '%s@%s\n' "$IMAGE" "$PD"
