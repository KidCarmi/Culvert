#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# decide-release-version.sh <sha> <version>
#
# auto-tag's only decision: may <version> — the version the candidate for
# <sha> was BUILT with, decided once by candidate-plan-main.sh — become the
# release tag now? auto-tag no longer computes a version of its own: the
# image already embeds one, and a tag that disagreed with it would ship a
# binary reporting the wrong version (or force a rebuild on the tag run).
#
# The remote is re-read here, inside auto-tag's cross-run concurrency group,
# never trusted from the checkout: the question is what is true NOW.
#
#   <version> already names <sha>             → nothing to do (a retry). exit 0
#   <sha> already carries another v* tag      → REFUSE: one version per commit.
#   <version> names another commit            → REFUSE: the version is taken.
#   a higher version already exists           → REFUSE: this candidate was
#                                               overtaken; tagging it now would
#                                               release an older commit under a
#                                               number that sorts below the
#                                               current release.
#   otherwise                                 → create + push the tag.
#
# `git push` of a new tag is the atomic step: the remote refuses a tag that
# already exists. If the push is refused, the remote is read once more — a
# concurrent retry of this same run may have won, which is success; anything
# else is a conflict and refuses.
#
# Outputs ($GITHUB_OUTPUT): tagged=created|existing.
# Seams: GIT_BIN, DRY_RUN.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SHA="${1:?usage: decide-release-version.sh <sha> <version>}"
VERSION="${2:?version required}"
GIT="${GIT_BIN:-git}"
REMOTE="${RELEASE_TAG_REMOTE:-origin}"

HERE="$(dirname "$0")"
# shellcheck source=.github/scripts/lib/candidate.sh
. "$HERE/lib/candidate.sh"

emit() { [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s\n' "$*" >> "$GITHUB_OUTPUT"; return 0; }
refuse() { for l in "$@"; do echo "::error::$l"; done; exit 1; }

valid_sha "$SHA" || refuse "'${SHA}' is not a full commit id."
valid_version "$VERSION" || refuse "'${VERSION}' is not vX.Y.Z — the candidate's version is malformed."

# state → AT_SHA (v* tags naming SHA), OWNER (commit VERSION names, or empty),
# HIGHEST (highest v* tag). Read from the remote, not the checkout.
read_state() {
  "$GIT" fetch --force --prune --prune-tags --tags "$REMOTE" >/dev/null 2>&1 \
    || refuse "cannot read tags from ${REMOTE} — refusing to decide a version blind. RECOVERY: re-run."
  AT_SHA="$("$GIT" tag --points-at "$SHA" --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
  OWNER="$("$GIT" rev-list -n1 "refs/tags/${VERSION}" 2>/dev/null || true)"
  HIGHEST="$("$GIT" tag --list 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
  HIGHEST="${HIGHEST%%$'\n'*}"
}

decide() {
  if [ "$OWNER" = "$SHA" ]; then
    echo "::notice::${VERSION} already names ${SHA} — nothing to do."
    emit "tagged=existing"
    exit 0
  fi
  if [ -n "$AT_SHA" ]; then
    refuse "${SHA} is already released as ${AT_SHA//$'\n'/ }; its candidate says ${VERSION}. One version per commit." \
      "RECOVERY: nothing to do if ${AT_SHA//$'\n'/ } is the intended release; otherwise an owner removes the wrong tag."
  fi
  if [ -n "$OWNER" ]; then
    refuse "${VERSION} already names ${OWNER}, not ${SHA} — the version this candidate was built with is taken." \
      "The image embeds ${VERSION}, so it cannot ship under another number. This commit is not released." \
      "RECOVERY: the next main push builds a fresh candidate with the next free version."
  fi
  if [ -n "$HIGHEST" ] && ! version_gt "$VERSION" "$HIGHEST"; then
    refuse "${VERSION} is not above the current highest release ${HIGHEST} — this candidate was overtaken." \
      "RECOVERY: none needed; a newer commit owns the release line. Its next main push releases it."
  fi
}

read_state
decide

if [ -n "${DRY_RUN:-}" ]; then
  echo "DRY_RUN: would tag ${SHA} as ${VERSION}"
  emit "tagged=created"
  exit 0
fi

"$GIT" tag -a "$VERSION" -m "Release ${VERSION}" "$SHA"
if "$GIT" push "$REMOTE" "refs/tags/${VERSION}"; then
  echo "::notice::tagged ${SHA} as ${VERSION}."
  emit "tagged=created"
  exit 0
fi

# The remote refused. Re-read: a concurrent attempt of this run may have
# created the same tag on the same commit (success); anything else refuses.
"$GIT" tag -d "$VERSION" >/dev/null 2>&1 || true
read_state
decide
refuse "pushing ${VERSION} failed and the remote still does not carry it — see the push error above." \
  "RECOVERY: re-run auto-tag; the decision is re-made from the remote."
