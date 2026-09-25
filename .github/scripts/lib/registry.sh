#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# registry.sh — shared registry probes for the release publication path.
#
# Sourced, never executed. Consumers: promote-image-tags.sh (write-once check)
# and resolve-release-candidate.sh (the version→digest binding). Both decide
# whether to WRITE a public reference based on what the registry answers, so
# they must classify a failed lookup identically — a second copy of this
# classifier is how that agreement rots.
#
# Seams: DOCKER_BIN, PROMOTE_INSPECT_RETRY_DELAY.
# ─────────────────────────────────────────────────────────────────────────────

# resolve_tag_digest <ref>
#   0 → resolved; the manifest-list digest is on stdout.
#   2 → the tag is POSITIVELY ABSENT from the registry.
#   1 → AMBIGUOUS: the registry did not answer the question. The raw error is
#       on stdout so the caller can name it.
#
# The distinction is load-bearing. Reading every nonzero exit as "absent" makes
# a transient registry, auth or network failure indistinguishable from a free
# tag — and a caller would then write over a reference it was meant to protect.
#
# Classification is by MESSAGE because `imagetools inspect` exits 1 for every
# failure. The allowlist is deliberately NARROW and unrecognised output is
# AMBIGUOUS, because the two directions are not symmetric: a missed not-found
# refuses a legitimate first write (loud, recoverable by re-running), while a
# missed transient failure silently overwrites something released.
#
# `404 Not Found` is read as absence rather than as a hidden-authorization 404
# only because every caller probes a reference it KNOWS exists first (the
# candidate tag this run pushed), proving the registry is reachable and this run
# is authorized for this repository. Do not call this without that precondition.
resolve_tag_digest() {
  local ref="$1" out rc attempt
  for attempt in 1 2 3; do
    rc=0
    out="$("$DOCKER_BIN" buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>&1)" || rc=$?
    if [ "$rc" -eq 0 ]; then
      printf '%s' "$out" | tr -d '[:space:]'
      return 0
    fi
    case "$out" in
      *"not found"*|*"manifest unknown"*|*MANIFEST_UNKNOWN*|*NAME_UNKNOWN*|*"no such manifest"*|*"404 Not Found"*)
        return 2 ;;
    esac
    # Ambiguous. A single blip must not fail a release that has already spent
    # forty minutes building and gating, so retry a bounded number of times —
    # but only here, and never in the direction of assuming the tag is free.
    [ "$attempt" -eq 3 ] || sleep "${PROMOTE_INSPECT_RETRY_DELAY:-3}"
  done
  printf '%s' "$out"
  return 1
}

# valid_digest <ref> — sha256: plus exactly 64 lowercase hex.
valid_digest() {
  case "$1" in
    sha256:[0-9a-f]*) [ "${#1}" -eq 71 ] ;;
    *) return 1 ;;
  esac
}
