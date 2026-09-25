#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# candidate-record.sh record        <image> <digest> <sha> <version> <out.json>
# candidate-record.sh qualification <image> <digest> <sha> <version> <out.json>
# candidate-record.sh point         <image> <digest> <sha>
#
# Writes the predicates the main-push run signs over its candidate, and the
# discovery pointer. The caller signs with `cosign attest --type <type>`; the
# types and the producer identity live in lib/candidate.sh.
#
# `record` is written by the `docker` job right after the build: it binds the
# commit, repository/workflow/ref/event, producer run + attempt, the decided
# version, the index digest and EVERY required platform digest (read back from
# the registry, not from the build step's claim), and the build inputs.
#
# `qualification` is written by `qualify-candidate` only after the candidate
# ran, was scanned, and its embedded version/compiler/platforms checked. A
# candidate with a record but no qualification is not releasable: the tag run
# refuses it.
#
# `point` moves `candidate-commit-<sha>` onto the digest, LAST — after the
# record is signed — and reads it back. A present pointer therefore implies a
# signed record, which is what lets the next attempt treat "pointer present,
# record missing" as an anomaly instead of a half-finished run.
#
# Every mode refuses outside a main push of this repository's ci.yml: the
# record's signature would not verify anyway, and writing it elsewhere would
# only pollute the registry.
# Seams: DOCKER_BIN, JQ_BIN, SHA256_BIN.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

MODE="${1:?usage: candidate-record.sh record|qualification|point <image> <digest> <sha> [version out]}"
IMAGE="${2:?image required}"
DIGEST="${3:?digest required}"
SHA="${4:?sha required}"

HERE="$(dirname "$0")"
# lib/registry.sh reads DOCKER_BIN unguarded; set the default before sourcing it.
DOCKER_BIN="${DOCKER_BIN:-docker}"
ROOT="${CANDIDATE_REPO_ROOT:-$(cd "$HERE/../.." && pwd)}"
# shellcheck source=.github/scripts/lib/registry.sh
. "$HERE/lib/registry.sh"
# shellcheck source=.github/scripts/lib/candidate.sh
. "$HERE/lib/candidate.sh"
JQ="${JQ_BIN:-jq}"
SHA256="${SHA256_BIN:-sha256sum}"

refuse() { for l in "$@"; do echo "::error::$l"; done; exit 1; }

valid_digest "$DIGEST" || refuse "malformed digest '${DIGEST}' — refusing."
valid_sha "$SHA" || refuse "'${SHA}' is not a full commit id — refusing."

# The producer context. These are the facts the certificate will carry; a
# mismatch means the record would describe a run that did not make it.
[ "${GITHUB_REPOSITORY:-}" = "$CANDIDATE_REPOSITORY" ] || refuse "repository '${GITHUB_REPOSITORY:-}' is not ${CANDIDATE_REPOSITORY}."
[ "${GITHUB_EVENT_NAME:-}" = "$CANDIDATE_EVENT" ] || refuse "event '${GITHUB_EVENT_NAME:-}' is not a push — only a main push produces candidates."
[ "${GITHUB_REF:-}" = "$CANDIDATE_REF" ] || refuse "ref '${GITHUB_REF:-}' is not ${CANDIDATE_REF}."
case "${GITHUB_WORKFLOW_REF:-}" in
  "${CANDIDATE_REPOSITORY}/${CANDIDATE_WORKFLOW}@${CANDIDATE_REF}") ;;
  *) refuse "workflow '${GITHUB_WORKFLOW_REF:-}' is not ${CANDIDATE_REPOSITORY}/${CANDIDATE_WORKFLOW}@${CANDIDATE_REF}." ;;
esac
[ "${GITHUB_SHA:-}" = "$SHA" ] || refuse "this run is at ${GITHUB_SHA:-?}, not ${SHA}."

LINES="" ; LRC=0
LINES="$(index_platforms "$IMAGE" "$DIGEST")" || LRC=$?
[ "$LRC" -eq 0 ] || refuse "cannot read the index ${IMAGE}@${DIGEST} (${LINES})."
VIOL="$(platform_violations "$LINES")"
[ -z "$VIOL" ] || refuse "${IMAGE}@${DIGEST} is not a complete candidate:" "$VIOL"
LIVE="$(platforms_json "$LINES")"

producer() {
  "$JQ" -n --arg run "${GITHUB_RUN_ID:?}" --arg att "${GITHUB_RUN_ATTEMPT:?}" --arg job "${GITHUB_JOB:-}" \
    '{run_id: $run, run_attempt: $att, job: $job}'
}

case "$MODE" in
  record|qualification)
    VERSION="${5:?version required}"
    OUT="${6:?output file required}"
    valid_version "$VERSION" || refuse "'${VERSION}' is not vX.Y.Z."
    ;;
esac

case "$MODE" in
  record)
    TOOLCHAIN="$(sed -n 's/^toolchain //p' "$ROOT/go.mod")"
    [ -n "$TOOLCHAIN" ] || refuse "go.mod carries no toolchain line — the candidate's compiler would be unrecorded."
    BUILDER="$(sed -n 's/^FROM --platform=\$BUILDPLATFORM \([^ ]*\) AS builder$/\1/p' "$ROOT/Dockerfile")"
    [ -n "$BUILDER" ] || refuse "cannot read the builder image from the Dockerfile."
    h() { "$SHA256" "$ROOT/$1" | cut -d' ' -f1; }
    "$JQ" -n \
      --arg schema "culvert.release-candidate/v1" \
      --arg repo "$CANDIDATE_REPOSITORY" --arg wf "$CANDIDATE_WORKFLOW" \
      --arg ref "$CANDIDATE_REF" --arg ev "$CANDIDATE_EVENT" \
      --arg sha "$SHA" --arg version "$VERSION" --arg image "$IMAGE" --arg digest "$DIGEST" \
      --argjson platforms "$LIVE" --argjson producer "$(producer)" \
      --arg tc "$TOOLCHAIN" --arg builder "$BUILDER" \
      --arg df "$(h Dockerfile)" --arg gomod "$(h go.mod)" --arg gosum "$(h go.sum)" \
      --arg maintsum "$(h cmd/culvert-maint/go.sum)" \
      '{schema: $schema, repository: $repo, workflow: $wf, ref: $ref, event: $ev,
        source_sha: $sha, version: $version, image: $image, index_digest: $digest,
        platforms: $platforms, producer: $producer,
        build_inputs: {go_toolchain: $tc, builder_image: $builder,
          dockerfile_sha256: $df, go_mod_sha256: $gomod, go_sum_sha256: $gosum,
          maint_go_sum_sha256: $maintsum,
          note: "the runtime base (alpine:3.24) and the monthly GeoIP download are not pinned; the image bytes are not reproducible, which is why the version binds this digest rather than a rebuild"}}' > "$OUT"
    echo "candidate record for ${VERSION} → ${OUT}"
    ;;
  qualification)
    CHECKS="${QUALIFICATION_CHECKS:?QUALIFICATION_CHECKS (space-separated) required}"
    "$JQ" -n \
      --arg schema "culvert.release-candidate-qualification/v1" \
      --arg sha "$SHA" --arg version "$VERSION" --arg digest "$DIGEST" \
      --argjson platforms "$LIVE" --argjson producer "$(producer)" \
      --arg checks "$CHECKS" \
      '{schema: $schema, result: "pass", source_sha: $sha, version: $version,
        index_digest: $digest, platforms: $platforms, producer: $producer,
        checks: ($checks | split(" ") | map(select(length > 0)))}' > "$OUT"
    echo "qualification record for ${VERSION} → ${OUT}"
    ;;
  point)
    POINTER="${IMAGE}:$(candidate_pointer_tag "$SHA")"
    if [ -n "${DRY_RUN:-}" ]; then
      echo "DRY_RUN: would point ${POINTER} at ${DIGEST}"
      exit 0
    fi
    "${DOCKER_BIN:-docker}" buildx imagetools create --tag "$POINTER" "${IMAGE}@${DIGEST}"
    RB="" ; RB_RC=0
    RB="$(resolve_tag_digest "$POINTER")" || RB_RC=$?
    [ "$RB_RC" -eq 0 ] && [ "$RB" = "$DIGEST" ] || refuse "${POINTER} reads back as '${RB}', not ${DIGEST}." \
      "Another run moved the pointer; the tag run verifies whatever it names, so this is a refusal to" \
      "claim success, not a corruption. RECOVERY: re-run."
    echo "::notice::${POINTER} → ${DIGEST}"
    ;;
  *) refuse "unknown mode '${MODE}' (want record|qualification|point)." ;;
esac
