#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# resolve-release-candidate.sh <image> <version-tag> <this-run-digest>
#
# Binds a version to ONE candidate digest, once, and hands that digest to every
# job downstream. On a retry it RECOVERS the binding instead of rebuilding.
#
# ── Why a binding exists at all ──────────────────────────────────────────────
# This image build is not reproducible over time (floating `alpine:3.24`, `apk
# upgrade`, a GeoIP URL embedding `$(date +%Y-%m)`), so re-running a tag
# produces DIFFERENT BYTES for the same version. Without a binding the release
# pipeline had no notion of "the candidate for vX.Y.Z" — only "whatever this run
# happened to build" — so a retry after a partial publication wanted to point
# public version tags at new bytes. A GHCR tag is public the moment it is
# written, so that is a real mutation of a released version, and the GitHub
# Release's Draft flag is NOT a visibility boundary for it.
#
# The binding turns a retry into a RESUME: the rebuilt bytes are discarded, and
# every remaining operation is completed against the digest this version was
# bound to the first time publication started.
#
# ── The binding is a write-once registry tag ─────────────────────────────────
# `<image>:candidate-vX.Y.Z`. It lives in the same registry as the artifact it
# names, is resolvable with the same tooling and the same credentials, and is
# durable across runs, re-runs and runner replacement — which an Actions output,
# a cache entry or a draft-release asset are not. It carries the `candidate-`
# prefix for the same reason `candidate-<run_id>` does: a candidate reference
# must never be mistakable for an approved release channel.
#
# It is created ONCE and never rewritten. If it already exists, this script
# adopts it; the only question then is whether it is trustworthy, which is the
# next section.
#
# ── An adopted binding must PROVE it belongs to this release ─────────────────
# A binding that cannot be verified is worse than none: it would hand a
# confidently-wrong digest to catalog generation, to signing and to public tag
# promotion. So the bound digest's own image config must name this commit
# (`org.opencontainers.image.revision`, stamped by the `docker` job). A binding
# that names another commit, names several, or names nothing REFUSES, and says
# what to do about it.
#
# The check runs on the FIRST run too, not only on retries. If the label
# mechanism is broken, the run that creates the binding is the cheapest possible
# place to find out — nothing has been published yet. Discovering it on the
# retry instead means discovering it after a partial publication.
#
# ── What this does NOT claim ─────────────────────────────────────────────────
# Nothing here is atomic across services. GHCR and the GitHub Releases API fail
# independently, and this script only makes the REGISTRY side resumable: it
# guarantees that every attempt at this version converges on one digest, so the
# operations that remain can be retried without changing what a released version
# means. Partial publication is handled by making each remaining step
# idempotent, not by pretending it cannot happen.
#
# Outputs (to $GITHUB_OUTPUT): digest, binding=created|reused|passthrough.
# Seams: DOCKER_BIN, JQ_BIN, PROMOTE_INSPECT_RETRY_DELAY.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE="${1:?usage: resolve-release-candidate.sh <image> <version-tag> <digest>}"
VERSION_TAG="${2-}"
RUN_DIGEST="${3:?digest built by this run required (arg 3)}"

RELEASE_SHA="${RELEASE_SHA:?RELEASE_SHA not set}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
JQ_BIN="${JQ_BIN:-jq}"
DRY_RUN="${DRY_RUN:-}"

# shellcheck source=.github/scripts/lib/registry.sh
. "$(dirname "$0")/lib/registry.sh"

emit() { [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s\n' "$*" >> "$GITHUB_OUTPUT"; return 0; }
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; return 0; }

valid_digest "$RUN_DIGEST" || { echo "::error::malformed digest '${RUN_DIGEST}' (want sha256:<64 hex>) — refusing"; exit 1; }

# ── main path: no version exists yet, so there is nothing to bind ────────────
# The version the main run computes is speculative until auto-tag creates the
# tag, and the main path promotes only moving channels, which are allowed to
# change. Pass this run's digest straight through.
if [ -z "$VERSION_TAG" ]; then
  echo "::notice::no version tag on this ref — no candidate binding; using this run's digest ${RUN_DIGEST}."
  emit "digest=${RUN_DIGEST}"
  emit "binding=passthrough"
  exit 0
fi

BINDING="${IMAGE}:candidate-${VERSION_TAG}"

# ── the precondition resolve_tag_digest's 404 rule depends on ────────────────
# Probe a reference this run KNOWS exists before reading a 404 as absence.
PROBE_RC=0
PROBE="$(resolve_tag_digest "${IMAGE}@${RUN_DIGEST}")" || PROBE_RC=$?
if [ "$PROBE_RC" -ne 0 ] || [ "$PROBE" != "$RUN_DIGEST" ]; then
  echo "::error::cannot resolve this run's own digest ${RUN_DIGEST} in ${IMAGE} (${PROBE})."
  echo "::error::The registry is unreachable or this run is not authorized for it, so no answer about"
  echo "::error::the candidate binding can be trusted. Refusing. Re-run once the registry is reachable."
  exit 1
fi

# ── resolve or create ────────────────────────────────────────────────────────
BOUND=""
RC=0
BOUND="$(resolve_tag_digest "$BINDING")" || RC=$?
case "$RC" in
  0)
    STATE="reused"
    echo "::notice::${VERSION_TAG} is already bound to ${BOUND} — recovering that candidate; this run's ${RUN_DIGEST} is discarded."
    ;;
  2)
    STATE="created"
    BOUND="$RUN_DIGEST"
    if [ -n "$DRY_RUN" ]; then
      echo "DRY_RUN: would bind ${VERSION_TAG} → ${BOUND} via ${BINDING}"
    else
      "$DOCKER_BIN" buildx imagetools create --tag "$BINDING" "${IMAGE}@${BOUND}"
      # Prove the write landed, and that WE are the writer. Two runs cannot
      # normally race one version tag, but adopting our own intent without
      # reading it back would turn a lost race into a split brain: this run
      # generating a catalog for one digest while the binding names another.
      READBACK=""
      RB_RC=0
      READBACK="$(resolve_tag_digest "$BINDING")" || RB_RC=$?
      if [ "$RB_RC" -ne 0 ]; then
        echo "::error::bound ${VERSION_TAG} → ${BOUND} but could not read ${BINDING} back (${READBACK}) — refusing."
        exit 1
      fi
      if [ "$READBACK" != "$BOUND" ]; then
        echo "::error::${BINDING} resolves to ${READBACK}, not the ${BOUND} this run wrote."
        echo "::error::Another run bound ${VERSION_TAG} first. Refusing rather than competing."
        echo "::error::RECOVERY: re-run this workflow; it will adopt ${READBACK} as the candidate."
        exit 1
      fi
    fi
    ;;
  *)
    echo "::error::could not determine whether ${VERSION_TAG} is already bound — the registry did not answer."
    echo "::error::inspect said: ${BOUND}"
    echo "::error::An unreadable binding is not an absent one, and guessing would either rebuild over a"
    echo "::error::released candidate or publish a digest nothing else agrees on. Refusing."
    echo "::error::RECOVERY: re-run once the registry is reachable; nothing was written."
    exit 1
    ;;
esac

# ── the adopted digest must name THIS commit ─────────────────────────────────
if [ -n "$DRY_RUN" ] && [ "$STATE" = "created" ]; then
  REVS="$RELEASE_SHA"
else
  CFG=""
  CFG_RC=0
  CFG="$("$DOCKER_BIN" buildx imagetools inspect "${IMAGE}@${BOUND}" --format '{{json .Image}}' 2>&1)" || CFG_RC=$?
  if [ "$CFG_RC" -ne 0 ]; then
    echo "::error::cannot read the image config of the bound candidate ${BOUND} (${CFG})."
    echo "::error::A binding whose provenance cannot be read must not drive catalog generation, signing"
    echo "::error::or public tag promotion. Refusing."
    echo "::error::RECOVERY: re-run once the registry is reachable; the binding is unchanged."
    exit 1
  fi
  # Walks both shapes `.Image` takes — a single config, or a platform→config map.
  REVS="$(printf '%s' "$CFG" | "$JQ_BIN" -r '
    [.. | objects | select(has("Labels")) | .Labels["org.opencontainers.image.revision"]? // empty]
    | map(select(. != "")) | unique | .[]' 2>/dev/null || true)"
fi

REV_COUNT="$(printf '%s' "$REVS" | grep -c . || true)"
if [ "$REV_COUNT" -ne 1 ]; then
  echo "::error::the candidate bound to ${VERSION_TAG} (${BOUND}) names ${REV_COUNT} source commits; want exactly 1."
  echo "::error::found: ${REVS:-<none>}"
  echo "::error::Without a single unambiguous source commit this candidate cannot be shown to be this"
  echo "::error::release's. Refusing to publish."
  echo "::error::RECOVERY: this binding is write-once and is NOT removed automatically. An owner must"
  echo "::error::decide — delete ${BINDING} to rebind, or cut a new version."
  exit 1
fi
if [ "$REVS" != "$RELEASE_SHA" ]; then
  echo "::error::the candidate bound to ${VERSION_TAG} (${BOUND}) was built from ${REVS}, not ${RELEASE_SHA}."
  echo "::error::Publishing it would ship one commit's bytes under another commit's tag. Refusing."
  echo "::error::RECOVERY: this binding is write-once and is NOT removed automatically. An owner must"
  echo "::error::decide — delete ${BINDING} to rebind, or cut a new version."
  exit 1
fi

echo "::notice::release candidate for ${VERSION_TAG}: ${BOUND} (${STATE}), source commit ${RELEASE_SHA}."
emit "digest=${BOUND}"
emit "binding=${STATE}"
summary "### Release candidate"
summary ""
summary "\`${VERSION_TAG}\` is bound to \`${BOUND}\` (${STATE}). Every downstream job — catalog, signing, promotion — uses this digest, so a retry resumes rather than rebuilds."
