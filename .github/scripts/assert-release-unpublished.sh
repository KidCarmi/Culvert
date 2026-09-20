#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# assert-release-unpublished.sh <tag>
#
# Refuses before ANY job in this workflow mutates the GitHub Release for <tag>,
# unless that release is absent or still a DRAFT.
#
# ── Why a published release is write-once ────────────────────────────────────
# Every asset-carrying step in ci.yml stages with `draft: true`, and
# `softprops/action-gh-release` applies that to an EXISTING release too — so a
# re-run of an already-published v* workflow PATCHes the live release back to
# draft. That alone takes a public release offline, and the run cannot put it
# back: the image build is deliberately not reproducible over time, so the
# rebuild produces a different digest, promote-image-tags.sh refuses it against
# the write-once exact tag, and `publish-release` — which needs promote-image —
# is skipped. The release is then stranded: unpublished, its catalog asset
# replaced by one pinning a digest that was rejected (Codex review, PR #1441).
#
# The correct answer is to refuse BEFORE the first mutation, so the public
# release keeps its state and its assets untouched. A published release is
# finished; there is nothing a re-run can add to it. If its bytes must change,
# that is a new version.
#
# ── What each state means ────────────────────────────────────────────────────
#   no release for <tag>  → first run. Proceed.
#   draft == true         → a previous run staged and did not finish. Proceed:
#                           this is exactly the recoverable re-run the draft
#                           staging exists to allow.
#   draft == false        → REFUSE. Nothing is mutated.
#   any other API error   → REFUSE. "The API did not answer" is not "no release
#                           exists"; inferring absence from a failed lookup is
#                           the same mistake resolve_tag_digest exists to avoid.
#
# The resign path (`catalog-resign`) legitimately attaches an asset to a
# PUBLISHED release and is deliberately NOT guarded here: it is a
# workflow_dispatch job that skips `docker`, and therefore the whole
# catalog-pipeline/release/publish-release chain, and it uses `gh release
# upload`, which does not touch draft state.
#
# GH_BIN is a test seam.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

TAG="${1:?usage: assert-release-unpublished.sh <tag>}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY not set}"
GH_BIN="${GH_BIN:-gh}"

summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; return 0; }

RC=0
OUT="$("$GH_BIN" api "repos/${REPO}/releases/tags/${TAG}" --jq '.draft' 2>&1)" || RC=$?

if [ "$RC" -ne 0 ]; then
  case "$OUT" in
    *"Not Found"*|*"HTTP 404"*|*"404"*)
      echo "::notice::no existing release for ${TAG} — first run, nothing to protect."
      exit 0 ;;
  esac
  echo "::error::could not determine whether the release for ${TAG} is already published."
  echo "::error::gh said: ${OUT}"
  echo "::error::Refusing to stage release assets on an unknown release state."
  exit 1
fi

DRAFT="$(printf '%s' "$OUT" | tr -d '[:space:]')"
case "$DRAFT" in
  true)
    echo "::notice::release ${TAG} exists and is still a DRAFT — a re-run may continue staging."
    exit 0 ;;
  false)
    echo "::error::the release for ${TAG} is ALREADY PUBLISHED."
    echo "::error::Every asset step in this workflow stages with draft:true, which would take that public"
    echo "::error::release offline — and this run cannot put it back, because the rebuild's digest is"
    echo "::error::refused against the write-once ${TAG#v} image tag and publish-release is then skipped."
    echo "::error::Refusing before anything is mutated. The published release and its assets are untouched."
    echo "::error::If these bytes must ship, cut a new version. To re-sign the catalog of a published"
    echo "::error::release, use the catalog re-sign dispatch, which does not re-stage assets."
    summary "### Release publication refused"
    summary ""
    summary "\`${TAG}\` is already published. A published release is write-once; this run mutated nothing."
    exit 1 ;;
  *)
    echo "::error::unexpected draft state '${DRAFT}' for release ${TAG} — refusing"
    exit 1 ;;
esac
