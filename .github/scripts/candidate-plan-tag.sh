#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# candidate-plan-tag.sh <image> <tag> <sha>
#
# Tag-run `docker` job, first decision: which EXISTING bytes this release is.
# A tag run does not build. It resolves, in this order, and takes the first
# source that exists:
#
#   1. binding        candidate-<tag>  — a previous attempt of THIS release
#                     already bound the version (resolve-release-candidate.sh).
#                     A retry resumes on exactly those bytes.
#   2. published      <X.Y.Z> / <vX.Y.Z> — the exact version aliases are
#                     write-once public tags. If one exists, the version's bytes
#                     are already distributed; the release adopts them.
#   3. main-candidate candidate-commit-<sha> — the candidate the main push built
#                     and qualified for this commit. Accepted only if its signed
#                     record AND its signed qualification verify against the
#                     main producer identity at this commit, name THIS version,
#                     and describe exactly the platforms the live index carries.
#   4. rebuild        only when an owner authorized it for this exact tag
#                     (RELEASE_REBUILD_AUTHORIZED_TAG == <tag>) and nothing
#                     above names bytes for the version. Never a silent fallback.
#
#   anything else     REFUSE, naming the recovery.
#
# 1 and 2 are checked BEFORE the main candidate on purpose: once bytes are bound
# or published under a version, nothing may substitute others, however well
# attested. An ambiguous registry answer at any step refuses — "could not tell"
# is never read as "absent", because that is how a rebuild would slip past an
# existing binding.
#
# Outputs ($GITHUB_OUTPUT): source=binding|published|main-candidate|rebuild,
#   build=true|false, digest (empty for rebuild), producer_run (main-candidate).
# Seams: DOCKER_BIN, COSIGN_BIN, JQ_BIN, CANDIDATE_PROBE_TAG.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE="${1:?usage: candidate-plan-tag.sh <image> <tag> <sha>}"
TAG="${2:?tag required}"
SHA="${3:?sha required}"
AUTHORIZED="${RELEASE_REBUILD_AUTHORIZED_TAG:-}"

HERE="$(dirname "$0")"
# lib/registry.sh reads DOCKER_BIN unguarded; set the default before sourcing it.
DOCKER_BIN="${DOCKER_BIN:-docker}"
# shellcheck source=.github/scripts/lib/registry.sh
. "$HERE/lib/registry.sh"
# shellcheck source=.github/scripts/lib/candidate.sh
. "$HERE/lib/candidate.sh"
JQ="${JQ_BIN:-jq}"

emit() { [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s\n' "$*" >> "$GITHUB_OUTPUT"; return 0; }
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"; return 0; }
refuse() { for l in "$@"; do echo "::error::$l"; done; exit 1; }
adopt() {
  echo "::notice::${TAG} → ${2} (source: ${1}${3:+, $3}) — reused, not rebuilt."
  emit "source=$1"; emit "build=false"; emit "digest=$2"; emit "producer_run=${4:-}"
  summary "### Release candidate source" "" "\`${TAG}\` reuses \`${2}\` (${1}${3:+; $3}). No image is built on this run."
  exit 0
}
lookup() { # lookup <ref> → sets L_RC and L_OUT; refuses on an ambiguous answer
  L_RC=0; L_OUT="$(resolve_tag_digest "$1")" || L_RC=$?
  [ "$L_RC" -ne 1 ] || refuse "could not determine whether $1 exists — the registry did not answer (${L_OUT})." \
    "An unreadable reference is not an absent one; reading it as absent is how new bytes would replace" \
    "bound ones. RECOVERY: re-run once the registry answers; nothing was written."
}

valid_version "$TAG" || refuse "'${TAG}' is not a vX.Y.Z release tag."
valid_sha "$SHA" || refuse "'${SHA}' is not a full commit id."
BARE="${TAG#v}"

PROBE="${CANDIDATE_PROBE_TAG:-latest}"
lookup "${IMAGE}:${PROBE}"
[ "$L_RC" -eq 0 ] || refuse "${IMAGE}:${PROBE} does not resolve — without a reference known to exist, a 404 cannot be told from a hidden or unreachable repository." \
  "RECOVERY: re-run once the registry answers."

# ── 1. an existing version binding ───────────────────────────────────────────
lookup "${IMAGE}:candidate-${TAG}"
[ "$L_RC" -eq 2 ] || adopt binding "$L_OUT" "candidate-${TAG}"

# ── 2. an already-published exact alias ──────────────────────────────────────
PUB=""
for a in "$BARE" "$TAG"; do
  lookup "${IMAGE}:${a}"
  if [ "$L_RC" -eq 0 ]; then
    [ -z "$PUB" ] || [ "$PUB" = "$L_OUT" ] || refuse "${IMAGE}:${BARE} and ${IMAGE}:${TAG} resolve to different digests (${PUB}, ${L_OUT})." \
      "Both exact aliases must name one image. RECOVERY: an owner decides which is the release; nothing is moved automatically."
    PUB="$L_OUT"
  fi
done
[ -z "$PUB" ] || adopt published "$PUB" "exact version alias already public"

# ── 3. the main-push candidate for this commit ───────────────────────────────
WHY=""
lookup "${IMAGE}:$(candidate_pointer_tag "$SHA")"
if [ "$L_RC" -eq 0 ]; then
  DIGEST="$L_OUT"
  LINES="" ; LRC=0
  LINES="$(index_platforms "$IMAGE" "$DIGEST")" || LRC=$?
  if [ "$LRC" -ne 0 ]; then
    refuse "the candidate for ${SHA} names ${DIGEST}, whose index cannot be read (${LINES}). RECOVERY: re-run once the registry answers."
  fi
  PV="$(platform_violations "$LINES")"
  LIVE="$(platforms_json "$LINES")"
  REC="" ; QUAL="" ; RRC=0 ; QRC=0
  REC="$(verify_statements "$CANDIDATE_RECORD_TYPE" "$IMAGE" "$DIGEST" "$SHA")" || RRC=$?
  QUAL="$(verify_statements "$CANDIDATE_QUALIFICATION_TYPE" "$IMAGE" "$DIGEST" "$SHA")" || QRC=$?
  if [ -n "$PV" ]; then
    WHY="the candidate ${DIGEST} is missing required platforms: ${PV//$'\n'/; }"
  elif [ "$RRC" -ne 0 ]; then
    WHY="$REC"
  else
    RV="$(record_violations "$REC" "$IMAGE" "$DIGEST" "$SHA" "$LIVE")"
    CV="$(printf '%s' "$REC" | "$JQ" -r '.[0].predicate.version')"
    TC="$(printf '%s' "$REC" | "$JQ" -r '.[0].predicate.build_inputs.go_toolchain')"
    WANT_TC="$(sed -n 's/^toolchain //p' "${CANDIDATE_REPO_ROOT:-$HERE/../..}/go.mod")"
    if [ -n "$RV" ]; then
      WHY="the candidate record does not match: ${RV//$'\n'/; }"
    elif [ "$CV" != "$TAG" ]; then
      WHY="the main candidate for ${SHA} was built as ${CV}, not ${TAG} (its embedded version would be wrong)"
    elif [ "$TC" != "$WANT_TC" ]; then
      WHY="the main candidate was built with ${TC}, but this commit pins ${WANT_TC}"
    elif [ "$QRC" -ne 0 ]; then
      WHY="the candidate was never qualified: ${QUAL}"
    else
      QV="$(qualification_violations "$QUAL" "$DIGEST" "$SHA" "$TAG" "$LIVE")"
      if [ -n "$QV" ]; then
        WHY="$QV"
      else
        RUN="$(printf '%s' "$REC" | "$JQ" -r '.[0].predicate.producer | "\(.run_id)/\(.run_attempt)"')"
        adopt main-candidate "$DIGEST" "record + qualification verified, producer run ${RUN}" "$RUN"
      fi
    fi
  fi
else
  WHY="no main-push candidate exists for ${SHA} (${IMAGE}:$(candidate_pointer_tag "$SHA") is absent)"
fi

# ── 4. an owner-authorized rebuild, or a refusal ─────────────────────────────
if [ -n "$AUTHORIZED" ] && [ "$AUTHORIZED" = "$TAG" ]; then
  echo "::warning::${WHY}."
  echo "::warning::RELEASE_REBUILD_AUTHORIZED_TAG=${TAG}: building ${TAG} from source on this tag run, as an owner authorized."
  emit "source=rebuild"; emit "build=true"; emit "digest="; emit "producer_run="
  summary "### Release candidate source" "" "\`${TAG}\` is being BUILT on the tag run: ${WHY}. An owner authorized this through \`RELEASE_REBUILD_AUTHORIZED_TAG\`."
  exit 0
fi
refuse "no reusable candidate for ${TAG} at ${SHA}: ${WHY}." \
  "A tag run never rebuilds silently: new bytes under a version must be an owner's decision." \
  "RECOVERY (pick one):" \
  "  • transient (registry/Sigstore unreachable): re-run this workflow." \
  "  • the tag was not created by auto-tag, or predates build-once promotion: set the repository" \
  "    variable RELEASE_REBUILD_AUTHORIZED_TAG=${TAG}, re-run, then clear the variable." \
  "  • the tag is on the wrong commit or version: delete the tag; auto-tag creates the right one." \
  "See docs/operator/release-publication-gating.md (build-once promotion)."
