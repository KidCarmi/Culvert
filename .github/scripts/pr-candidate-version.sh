#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# pr-candidate-version.sh <commit-sha40> [<tags-file>]
#
# The version stamp for a PR-built (candidate) image: a SemVer PRERELEASE of
# the next patch after the latest published release, naming the commit it was
# built from —  vX.Y.(Z+1)-candidate.g<sha12>  (PR #1528 §3f L11).
#
# Why a prerelease and not "dev": the appliance's first boot installs the
# image-bundled maintenance agent only when it reports a release-shaped
# version (vX.Y.Z[-pre]); a "dev" agent was refused, so no candidate OVA ever
# had an agent and backup/restore/locking went unqualified. Why not a plain
# vX.Y.Z: a candidate must never look like a published release. A prerelease
# sorts BELOW the release it precedes, and the release-transition policy
# treats any non-bare version as unknown (release_dispatch.go
# effectiveCurrentVersion), so this stamp cannot satisfy a transition floor.
# The "g" keeps the commit identifier alphanumeric (a SemVer numeric
# identifier may not have a leading zero; a hex prefix can be all digits).
#
# Tags come from <tags-file> (one tag per line) or `git ls-remote origin`.
# Fails — never falls back to "dev" — when no release tag can be read.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
die() { echo "pr-candidate-version: $*" >&2; exit 1; }
sha="${1:-}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "want a full 40-hex commit sha, got '$sha'"
if [[ -n "${2:-}" ]]; then
  tags="$(cat "$2")"
else
  tags=""
  for i in 1 2 3; do
    tags="$(git ls-remote --tags --refs origin 'refs/tags/v*' | sed 's#.*refs/tags/##')" && [[ -n "$tags" ]] && break
    sleep $((i * 5))
  done
fi
latest="$(printf '%s\n' "$tags" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true)"
[[ -n "$latest" ]] || die "no release tag (vX.Y.Z) found"
IFS=. read -r major minor patch <<<"${latest#v}"
echo "v${major}.${minor}.$((patch + 1))-candidate.g${sha:0:12}"
