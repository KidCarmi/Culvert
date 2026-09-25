#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# candidate-plan-main.sh <image> <sha>
#
# Main-push `docker` job, first decision: REUSE this commit's existing
# candidate, or BUILD one — and, either way, THE version the candidate carries.
# The version is decided here exactly once per commit; auto-tag consumes it
# (decide-release-version.sh) and never computes its own.
#
#   pointer candidate-commit-<sha> absent  → build. Version: the v* tag that
#                                            already names this commit, else
#                                            the highest v* tag + 1 patch.
#   pointer present, record verifies       → reuse its digest AND its version.
#                                            A re-run never rebuilds, so it can
#                                            never produce different bytes for a
#                                            version it already decided.
#   pointer present, record does not verify
#   or registry did not answer             → REFUSE. Unverifiable is not absent:
#                                            rebuilding would let a registry blip
#                                            substitute new bytes for a commit
#                                            whose version may already be bound.
#
# Why the main path writes the pointer LAST (candidate-record.sh): a present
# pointer then implies a written record, so "present but unverifiable" really
# is an anomaly worth a human, not a half-finished previous attempt.
#
# Outputs ($GITHUB_OUTPUT): mode=build|reuse, digest (reuse only), version,
#   version_bare, version_source=record|commit-tag|next-patch.
# Seams: DOCKER_BIN, COSIGN_BIN, JQ_BIN, GIT_BIN, CANDIDATE_PROBE_TAG.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE="${1:?usage: candidate-plan-main.sh <image> <sha>}"
SHA="${2:?sha required}"
GIT_BIN="${GIT_BIN:-git}"

HERE="$(dirname "$0")"
# lib/registry.sh reads DOCKER_BIN unguarded; set the default before sourcing it.
DOCKER_BIN="${DOCKER_BIN:-docker}"
# shellcheck source=.github/scripts/lib/registry.sh
. "$HERE/lib/registry.sh"
# shellcheck source=.github/scripts/lib/candidate.sh
. "$HERE/lib/candidate.sh"

emit() { [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s\n' "$*" >> "$GITHUB_OUTPUT"; return 0; }
refuse() { for l in "$@"; do echo "::error::$l"; done; exit 1; }

valid_sha "$SHA" || refuse "'${SHA}' is not a full 40-hex commit — a short SHA is never a candidate identity."

# v* tags already naming this commit. More than one means the commit was
# released twice under different numbers; which one the candidate carries is
# then an owner decision, not something to guess.
AT_SHA="$("$GIT_BIN" tag --points-at "$SHA" --list 'v*' | grep -E '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || true)"
AT_COUNT="$(printf '%s' "$AT_SHA" | grep -c . || true)"
[ "$AT_COUNT" -le 1 ] || refuse "commit ${SHA} carries ${AT_COUNT} version tags (${AT_SHA//$'\n'/ }) — refusing to choose one." \
  "RECOVERY: an owner deletes the unintended tag, then re-run."

# ── the precondition resolve_tag_digest's 404 rule depends on ────────────────
PROBE="${CANDIDATE_PROBE_TAG:-latest}"
PROBE_RC=0
PROBE_OUT="$(resolve_tag_digest "${IMAGE}:${PROBE}")" || PROBE_RC=$?
[ "$PROBE_RC" -eq 0 ] || refuse "cannot resolve ${IMAGE}:${PROBE} (${PROBE_OUT}) — the registry is unreachable or this run is not authorized, so an absent candidate pointer cannot be told from an unreadable one." \
  "RECOVERY: re-run once the registry answers; nothing was written."

POINTER="${IMAGE}:$(candidate_pointer_tag "$SHA")"
P_RC=0
DIGEST="$(resolve_tag_digest "$POINTER")" || P_RC=$?
case "$P_RC" in
  2)
    if [ -n "$AT_SHA" ]; then
      VERSION="$AT_SHA"; SOURCE="commit-tag"
    else
      HIGHEST="$("$GIT_BIN" tag --list 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
      HIGHEST="${HIGHEST%%$'\n'*}"
      [ -n "$HIGHEST" ] || HIGHEST="v0.0.0"
      B="${HIGHEST#v}"
      VERSION="v${B%%.*}.$(printf '%s' "$B" | cut -d. -f2).$(( $(printf '%s' "$B" | cut -d. -f3) + 1 ))"
      SOURCE="next-patch"
    fi
    valid_version "$VERSION" || refuse "computed version '${VERSION}' is not vX.Y.Z — refusing."
    echo "::notice::no candidate for ${SHA} yet — building one as ${VERSION} (${SOURCE})."
    emit "mode=build"
    emit "digest="
    ;;
  0)
    LINES="" ; LRC=0
    LINES="$(index_platforms "$IMAGE" "$DIGEST")" || LRC=$?
    [ "$LRC" -eq 0 ] || refuse "the candidate pointer names ${DIGEST}, whose index cannot be read (${LINES})." \
      "RECOVERY: re-run once the registry answers."
    LIVE="$(platforms_json "$LINES")"
    STMTS="" ; SRC=0
    STMTS="$(verify_statements "$CANDIDATE_RECORD_TYPE" "$IMAGE" "$DIGEST" "$SHA")" || SRC=$?
    [ "$SRC" -eq 0 ] || refuse "${POINTER} names ${DIGEST}, but ${STMTS}." \
      "A pointer is written only after its record, so this is not a half-finished attempt: the record is" \
      "missing, forged, or Sigstore/the registry did not answer. Rebuilding here could put new bytes under a" \
      "version that is already bound, so this refuses." \
      "RECOVERY: re-run once Sigstore and the registry answer. If it persists, an owner confirms no" \
      "candidate-v<version> binding names ${DIGEST}, deletes ${POINTER}, and re-runs to rebuild."
    VIOL="$(record_violations "$STMTS" "$IMAGE" "$DIGEST" "$SHA" "$LIVE")"
    [ -z "$VIOL" ] || refuse "the candidate record on ${DIGEST} does not match this commit:" "$VIOL" \
      "RECOVERY: an owner inspects ${POINTER}; nothing is rebuilt or overwritten automatically."
    VERSION="$(printf '%s' "$STMTS" | "${JQ_BIN:-jq}" -r '.[0].predicate.version')"
    if [ -n "$AT_SHA" ] && [ "$AT_SHA" != "$VERSION" ]; then
      refuse "the candidate for ${SHA} carries ${VERSION}, but the commit is tagged ${AT_SHA}." \
        "RECOVERY: an owner decides which version this commit is; nothing is retagged automatically."
    fi
    SOURCE="record"
    echo "::notice::reusing the verified candidate ${DIGEST} for ${SHA} as ${VERSION} — no rebuild."
    emit "mode=reuse"
    emit "digest=${DIGEST}"
    ;;
  *)
    refuse "could not determine whether ${POINTER} exists — the registry did not answer (${DIGEST})." \
      "An unreadable pointer is not an absent one. RECOVERY: re-run once the registry answers."
    ;;
esac

emit "version=${VERSION}"
emit "version_bare=${VERSION#v}"
emit "version_source=${SOURCE}"
