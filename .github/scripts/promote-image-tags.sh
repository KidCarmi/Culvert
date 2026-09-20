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
# ── Re-run safety ────────────────────────────────────────────────────────────
# The channel's owner is the tip of the promoting ref:
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
# Space-separated; either may be empty, but not both.
read -r -a IMMUTABLE <<< "${IMMUTABLE_TAGS:-}"
read -r -a FLOATING <<< "${FLOATING_TAGS:-}"

DOCKER_BIN="${DOCKER_BIN:-docker}"
GIT_BIN="${GIT_BIN:-git}"

summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; return 0; }

if [ "${#IMMUTABLE[@]}" -eq 0 ] && [ "${#FLOATING[@]}" -eq 0 ]; then
  echo "::error::neither IMMUTABLE_TAGS nor FLOATING_TAGS is set — a promotion that promotes nothing is a silent no-op; refusing"
  exit 1
fi

# ── 1. digest shape ──────────────────────────────────────────────────────────
case "$DIGEST" in
  sha256:[0-9a-f]*)
    # 7 chars of "sha256:" + 64 hex
    [ "${#DIGEST}" -eq 71 ] || { echo "::error::malformed digest '${DIGEST}' — refusing"; exit 1; } ;;
  *) echo "::error::malformed digest '${DIGEST}' (want sha256:<64 hex>) — refusing"; exit 1 ;;
esac

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
if [ "$RELEASE_SHA" = "$CHANNEL_TIP" ]; then
  echo "promotion owner: ${RELEASE_SHA} is the channel tip."
  TARGETS+=("${FLOATING[@]}")
elif "$GIT_BIN" merge-base --is-ancestor "$RELEASE_SHA" "$CHANNEL_TIP" 2>/dev/null; then
  SUPERSEDED=1
  echo "::notice::${RELEASE_SHA} is superseded by channel tip ${CHANNEL_TIP} — a newer run owns the moving channels (${FLOATING[*]:-none}); they are NOT moved."
else
  echo "::error::${RELEASE_SHA} is neither the channel tip ${CHANNEL_TIP} nor an ancestor of it (divergent history / force-push) — refusing to promote"
  exit 1
fi

if [ "${#TARGETS[@]}" -eq 0 ]; then
  # Superseded with no immutable targets: the main path, whose computed version
  # is speculative. Nothing to do, and that is the correct outcome.
  echo "::notice::nothing to promote (superseded, and this path declares no immutable targets)."
  summary "### Image promotion — SKIPPED"
  summary ""
  summary "\`${RELEASE_SHA}\` is an ancestor of the channel tip \`${CHANNEL_TIP}\`; a newer run owns \`${FLOATING[*]:-the channels}\`. Nothing was promoted."
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
