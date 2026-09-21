#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# promote-image-tags.sh <image> <digest> <candidate-tag> <tag>...
#
# Moves the PUBLIC release channels (latest, semver) onto an already-built,
# already-verified, IMMUTABLE digest. Nothing is rebuilt here: promotion is
# `docker buildx imagetools create --tag <public> <image>@<digest>`, so the
# bytes a consumer pulls from `:latest` are byte-identical to the bytes the
# evidence predicate approved.
#
# Preconditions the CALLER owns (this script does not re-check them):
#   • require-release-evidence.sh passed for the release SHA.
# Preconditions THIS script enforces (each a hard refusal):
#   1. <digest> is a well-formed sha256 reference.
#   2. <candidate-tag> exists in the registry and resolves to EXACTLY <digest>.
#      This binds the promotion to the digest this run actually built and the
#      catalog gate actually pinned — without it, a promote step could be handed
#      any digest string and would happily publish it.
#   3. RE-RUN SAFETY (see below).
#
# ── Two kinds of target, and only one of them can be superseded ─────────────
# IMMUTABLE_TAGS name THIS release and nothing else — the exact version
# (`1.2.3`). Nothing can supersede them: `1.2.3` can only ever mean the release
# at the `v1.2.3` tag, so promoting it is never a rollback and is ALWAYS done.
#
# FLOATING_TAGS are moving channels — `latest`, `main`, `1.2`, `1`. They name
# "the current thing", so an older run must never roll them backwards.
#
# The split matters because the first shipped version of this script had only
# one target list gated on supersession, so a tag run overtaken by a newer tag
# skipped EVERYTHING — including its own `X.Y.Z` — and `publish-release` still
# undrafted the release. The result was a public release whose exact version
# tag was absent, or pointed at the main run's digest rather than the one this
# release's catalog pins (Codex review, PR #1441).
#
# ── An immutable tag is WRITE-ONCE ───────────────────────────────────────────
# "Always promoted" is not the same as "repointed on every run". This image
# build is NOT reproducible over time — the Dockerfile rides a floating
# `alpine:3.24`, runs `apk upgrade`, and downloads a GeoIP database whose URL
# embeds `$(date +%Y-%m)`, so it changes every calendar month — so re-running an
# already-published tag's workflow produces a DIFFERENT digest for the same
# version. Repointing `X.Y.Z` at it would serve different bytes under a released
# version while that release's published catalog still pins the old digest
# (Codex review, PR #1441).
#
# So an immutable target is promoted only when it is ABSENT, or already resolves
# to exactly this digest (an idempotent re-run). Present-at-a-different-digest
# is a REFUSAL, not an overwrite: the correct answer to "this version's bytes
# changed" is a new version, never a quiet substitution under the old one. This
# is safe to enforce because the tag run is now the ONLY writer of the exact
# aliases — the main path stopped promoting them.
#
# "Absent" must be PROVEN, not inferred from a failed lookup: see
# resolve_tag_digest below. An ambiguous registry answer refuses.
#
# ── A retry RESUMES; it does not re-decide ──────────────────────────────────
# Write-once used to have no answer for "the first run promoted X.Y.Z and then a
# later job failed". An earlier revision of this script let the rebuild repoint
# the tag when the GitHub Release was still a Draft. That was WRONG: a GHCR tag
# is public the instant it is written, so Draft is not a visibility boundary for
# it, and the exception weakened exactly the immutability it was guarding.
#
# The answer is upstream instead. resolve-release-candidate.sh binds each
# version to ONE candidate digest before anything is published, and every
# downstream job — catalog generation, signing, this promotion — uses that
# digest. A retry therefore promotes the SAME digest and every already-written
# alias is an idempotent no-op, so partial publication is completed rather than
# re-decided. An exact tag pointing somewhere else is now a genuine
# inconsistency: it REFUSES, names the recovery, and deletes nothing.
#
# ── Re-run safety ────────────────────────────────────────────────────────────
# The channel's owner is the tip of the promoting ref. On the TAG path the tip
# is a TAG IDENTITY, not a commit: two version tags can name the same commit
# (a re-tag, or a second tag cut on an already-tagged commit), and comparing
# only SHAs then lets the LOWER tag believe it owns the channels and roll `X.Y`
# / `X` back to itself (Codex review, PR #1441). CHANNEL_TIP_TAG/RELEASE_TAG
# carry that identity; the commit comparison remains the main path's rule and
# the tag path's fallback for classifying superseded vs divergent.
#
#   CHANNEL_TIP == release SHA   → promote IMMUTABLE + FLOATING.
#   release SHA is an ANCESTOR of CHANNEL_TIP
#                                → promote IMMUTABLE, SKIP FLOATING. Exit 0 —
#                                  a newer run owns the moving channels, and on
#                                  a busy main branch the next merge lands
#                                  during this run's 40-minute build+gate
#                                  window, so failing would turn an ordinary
#                                  merge into a red release pipeline.
#   otherwise (divergent / force-push / unknown)
#                                → REFUSE, promote nothing. Exit 1.
#
# Re-running the SAME run is therefore idempotent. CHANNEL_TIP is supplied by
# the caller because how you name "the tip" differs by path: the default
# branch's head on the main path, the highest v* tag's commit on the tag path.
#
# The MAIN path deliberately declares NO immutable targets: the version it
# computes is speculative until auto-tag creates the tag, so a superseded main
# run must promote nothing. The tag run is what makes `X.Y.Z` authoritative.
#
# DRY_RUN=1 prints the promotion plan and touches no registry.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE="${1:?usage: promote-image-tags.sh <image> <digest> <candidate-tag>}"
DIGEST="${2:?digest required}"
CANDIDATE="${3:?candidate tag required}"

RELEASE_SHA="${RELEASE_SHA:?RELEASE_SHA not set}"
CHANNEL_TIP="${CHANNEL_TIP:?CHANNEL_TIP not set}"
# Tag identities. Set on the tag path only; empty on the main path, where the
# commit comparison is the whole rule.
RELEASE_TAG="${RELEASE_TAG:-}"
CHANNEL_TIP_TAG="${CHANNEL_TIP_TAG:-}"
# Space-separated; either may be empty, but not both.
read -r -a IMMUTABLE <<< "${IMMUTABLE_TAGS:-}"
read -r -a FLOATING <<< "${FLOATING_TAGS:-}"

DOCKER_BIN="${DOCKER_BIN:-docker}"
GIT_BIN="${GIT_BIN:-git}"

summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; return 0; }

# resolve_tag_digest + valid_digest live in lib/registry.sh, shared with
# resolve-release-candidate.sh: both decide whether to WRITE a public reference
# from what the registry answers, so they must classify a failed lookup
# identically. Do not re-inline this.
# shellcheck source=.github/scripts/lib/registry.sh
. "$(dirname "$0")/lib/registry.sh"

if [ "${#IMMUTABLE[@]}" -eq 0 ] && [ "${#FLOATING[@]}" -eq 0 ]; then
  echo "::error::neither IMMUTABLE_TAGS nor FLOATING_TAGS is set — a promotion that promotes nothing is a silent no-op; refusing"
  exit 1
fi

# ── 1. digest shape ──────────────────────────────────────────────────────────
valid_digest "$DIGEST" || { echo "::error::malformed digest '${DIGEST}' (want sha256:<64 hex>) — refusing"; exit 1; }

# ── 2. candidate-tag ↔ digest binding ────────────────────────────────────────
# `imagetools inspect --format {{.Manifest.Digest}}` resolves the tag through
# the registry and prints the manifest-LIST digest — the same value
# build-push-action reports as steps.build.outputs.digest.
if ! CAND_DIGEST="$("$DOCKER_BIN" buildx imagetools inspect "${IMAGE}:${CANDIDATE}" --format '{{.Manifest.Digest}}' 2>/dev/null)"; then
  echo "::error::candidate tag ${IMAGE}:${CANDIDATE} is not resolvable in the registry — refusing"
  exit 1
fi
CAND_DIGEST="$(printf '%s' "$CAND_DIGEST" | tr -d '[:space:]')"
if [ "$CAND_DIGEST" != "$DIGEST" ]; then
  echo "::error::candidate ${IMAGE}:${CANDIDATE} resolves to ${CAND_DIGEST} but this run built ${DIGEST} — refusing to promote a digest this run did not produce"
  exit 1
fi

# ── 3. supersession verdict ──────────────────────────────────────────────────
TARGETS=("${IMMUTABLE[@]}")
SUPERSEDED=0

# owns_channels: on the tag path the tip is a TAG IDENTITY — two tags can share
# a commit, and then the SHA comparison alone would hand ownership to both.
owns_channels() {
  if [ -n "$RELEASE_TAG" ] && [ -n "$CHANNEL_TIP_TAG" ]; then
    [ "$RELEASE_TAG" = "$CHANNEL_TIP_TAG" ]
    return
  fi
  [ "$RELEASE_SHA" = "$CHANNEL_TIP" ]
}

if owns_channels; then
  echo "promotion owner: ${RELEASE_TAG:-$RELEASE_SHA} is the channel tip."
  TARGETS+=("${FLOATING[@]}")
elif [ "$RELEASE_SHA" = "$CHANNEL_TIP" ] || "$GIT_BIN" merge-base --is-ancestor "$RELEASE_SHA" "$CHANNEL_TIP" 2>/dev/null; then
  # Superseded: either an ancestor commit, or the SAME commit carrying a higher
  # tag. Both mean a newer release owns the moving channels.
  SUPERSEDED=1
  echo "::notice::${RELEASE_TAG:-$RELEASE_SHA} is superseded by channel tip ${CHANNEL_TIP_TAG:-$CHANNEL_TIP} — a newer release owns the moving channels (${FLOATING[*]:-none}); they are NOT moved."
else
  echo "::error::${RELEASE_SHA} is neither the channel tip ${CHANNEL_TIP} nor an ancestor of it (divergent history / force-push) — refusing to promote"
  exit 1
fi

# ── immutable targets are WRITE-ONCE ─────────────────────────────────────────
KEEP=()
for t in "${TARGETS[@]}"; do
  [ -n "$t" ] || continue
  is_immutable=0
  for i in "${IMMUTABLE[@]}"; do [ "$i" = "$t" ] && is_immutable=1; done
  if [ "$is_immutable" -eq 0 ]; then
    KEEP+=("$t")
    continue
  fi
  INSPECT_RC=0
  EXISTING="$(resolve_tag_digest "${IMAGE}:${t}")" || INSPECT_RC=$?
  case "$INSPECT_RC" in
    2)
      # Positively absent — the only state in which an immutable tag may be
      # written.
      KEEP+=("$t") ;;
    0)
      if [ "$EXISTING" = "$DIGEST" ]; then
        echo "::notice::${IMAGE}:${t} already resolves to ${DIGEST} — idempotent re-run, nothing to move."
        continue
      fi
      echo "::error::${IMAGE}:${t} is ALREADY PUBLIC at ${EXISTING}, and this run is promoting ${DIGEST}."
      echo "::error::An exact version tag is WRITE-ONCE. A registry tag is public the moment it is written,"
      echo "::error::so repointing it changes what an already-distributed version means — the state of the"
      echo "::error::GitHub Release is irrelevant to that, and Draft is NOT a visibility boundary for GHCR."
      echo "::error::This should be unreachable: resolve-release-candidate.sh binds each version to ONE"
      echo "::error::candidate digest, so a retry promotes the SAME digest and lands on the no-op above."
      echo "::error::Reaching here means the exact tag and the candidate binding disagree."
      echo "::error::RECOVERY: nothing is deleted or overwritten automatically. Compare"
      echo "::error::${IMAGE}:candidate-${RELEASE_TAG:-<version>} against ${IMAGE}:${t} and have an owner"
      echo "::error::decide; if these bytes must ship, cut a new version."
      exit 1 ;;
    *)
      echo "::error::could not determine whether ${IMAGE}:${t} already exists — the registry did not answer."
      echo "::error::inspect said: ${EXISTING}"
      echo "::error::An exact version tag is write-once, and an ambiguous registry answer is NOT proof that"
      echo "::error::the tag is free. Refusing to promote. Re-run once the registry is reachable."
      exit 1 ;;
  esac
done
TARGETS=("${KEEP[@]}")

if [ "${#TARGETS[@]}" -eq 0 ]; then
  # Two ways to land here, both correct and both no-ops: superseded with no
  # immutable targets (the main path, whose computed version is speculative), or
  # every immutable target already resolving to this digest (an idempotent
  # re-run).
  echo "::notice::nothing to promote (superseded with no immutable targets, or every target already correct)."
  summary "### Image promotion — nothing to do"
  summary ""
  summary "\`${RELEASE_TAG:-$RELEASE_SHA}\` promoted nothing: either a newer release owns \`${FLOATING[*]:-the channels}\`, or every exact tag already resolves to \`${DIGEST}\`."
  exit 0
fi

# ── promote ──────────────────────────────────────────────────────────────────
ARGS=()
KEPT=()
for t in "${TARGETS[@]}"; do
  [ -n "$t" ] || continue
  ARGS+=(--tag "${IMAGE}:${t}")
  KEPT+=("$t")
done
if [ "${#ARGS[@]}" -eq 0 ]; then
  echo "::error::every target tag was empty — refusing"
  exit 1
fi

echo "promoting ${IMAGE}@${DIGEST} → ${KEPT[*]}"
if [ "${DRY_RUN:-}" = "1" ]; then
  echo "DRY_RUN: $DOCKER_BIN buildx imagetools create ${ARGS[*]} ${IMAGE}@${DIGEST}"
  exit 0
fi
"$DOCKER_BIN" buildx imagetools create "${ARGS[@]}" "${IMAGE}@${DIGEST}"

if [ "$SUPERSEDED" -eq 1 ]; then
  summary "### Image promotion — PARTIAL (superseded)"
  summary ""
  summary "Promoted the immutable tag(s) $(printf '`%s` ' "${KEPT[@]}") to \`${IMAGE}@${DIGEST}\`. The moving channels \`${FLOATING[*]:-none}\` were left to the newer run that owns them."
else
  summary "### Image promotion"
  summary ""
  summary "Promoted \`${IMAGE}@${DIGEST}\` (built from \`${RELEASE_SHA}\`) to: $(printf '`%s` ' "${KEPT[@]}")"
fi
