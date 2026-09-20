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
# ── Re-run safety ────────────────────────────────────────────────────────────
# A public channel must never be rolled BACKWARDS by re-running an older run.
# The channel's owner is the tip of the promoting ref, so:
#
#   CHANNEL_TIP == release SHA   → PROMOTE.
#   release SHA is an ANCESTOR of CHANNEL_TIP
#                                → SKIP (superseded: a newer run owns the
#                                  channel and has already promoted, or will).
#                                  Exit 0 — this is a normal outcome on a busy
#                                  main branch, where the next push lands
#                                  during this run's 40-minute build+gate
#                                  window; failing here would turn an ordinary
#                                  merge into a red release pipeline.
#   otherwise (divergent / force-push / unknown)
#                                → REFUSE. Exit 1.
#
# Re-running the SAME run is therefore idempotent, and re-running a superseded
# one is inert. CHANNEL_TIP is supplied by the caller (CHANNEL_TIP env) because
# how you name "the tip" differs by path: the default branch's head on the main
# path, the highest v* tag's commit on the tag path.
#
# DRY_RUN=1 prints the promotion plan and touches no registry.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE="${1:?usage: promote-image-tags.sh <image> <digest> <candidate-tag> <tag>...}"
DIGEST="${2:?digest required}"
CANDIDATE="${3:?candidate tag required}"
shift 3
TARGETS=("$@")

RELEASE_SHA="${RELEASE_SHA:?RELEASE_SHA not set}"
CHANNEL_TIP="${CHANNEL_TIP:?CHANNEL_TIP not set}"

DOCKER_BIN="${DOCKER_BIN:-docker}"
GIT_BIN="${GIT_BIN:-git}"

summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; return 0; }

if [ "${#TARGETS[@]}" -eq 0 ]; then
  echo "::error::no target tags given — a promotion that promotes nothing is a silent no-op; refusing"
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

# ── 3. re-run safety ─────────────────────────────────────────────────────────
if [ "$RELEASE_SHA" = "$CHANNEL_TIP" ]; then
  echo "promotion owner: ${RELEASE_SHA} is the channel tip."
elif "$GIT_BIN" merge-base --is-ancestor "$RELEASE_SHA" "$CHANNEL_TIP" 2>/dev/null; then
  echo "::notice::${RELEASE_SHA} is superseded by channel tip ${CHANNEL_TIP} — skipping promotion (a newer run owns these tags)."
  summary "### Image promotion — SKIPPED"
  summary ""
  summary "\`${RELEASE_SHA}\` is an ancestor of the channel tip \`${CHANNEL_TIP}\`; a newer run owns \`${TARGETS[*]}\`. Nothing was promoted."
  exit 0
else
  echo "::error::${RELEASE_SHA} is neither the channel tip ${CHANNEL_TIP} nor an ancestor of it (divergent history / force-push) — refusing to promote"
  exit 1
fi

# ── promote ──────────────────────────────────────────────────────────────────
ARGS=()
for t in "${TARGETS[@]}"; do
  [ -n "$t" ] || continue
  ARGS+=(--tag "${IMAGE}:${t}")
done
if [ "${#ARGS[@]}" -eq 0 ]; then
  echo "::error::every target tag was empty — refusing"
  exit 1
fi

echo "promoting ${IMAGE}@${DIGEST} → ${TARGETS[*]}"
if [ "${DRY_RUN:-}" = "1" ]; then
  echo "DRY_RUN: $DOCKER_BIN buildx imagetools create ${ARGS[*]} ${IMAGE}@${DIGEST}"
  exit 0
fi
"$DOCKER_BIN" buildx imagetools create "${ARGS[@]}" "${IMAGE}@${DIGEST}"

summary "### Image promotion"
summary ""
summary "Promoted \`${IMAGE}@${DIGEST}\` (built from \`${RELEASE_SHA}\`) to: $(printf '`%s` ' "${TARGETS[@]}")"
