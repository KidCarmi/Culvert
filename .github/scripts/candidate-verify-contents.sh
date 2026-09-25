#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# candidate-verify-contents.sh <image> <digest> <sha> <version> <toolchain>
#
# Qualification of the ACTUAL candidate bytes, by digest, on every platform —
# the part of qualification that does not need to execute the image (the smoke
# run and the vulnerability scan are workflow steps in `qualify-candidate`).
#
# For the index <image>@<digest>:
#   • exactly the required platforms, each exactly once;
#   • every platform's config names <sha> as its source revision;
# and for each platform, from the files INSIDE that platform's image:
#   • the proxy and the maintenance agent were built by <toolchain> — the
#     root go.mod pin, not "whatever compiler happened to run";
#   • they were built for that platform (GOOS/GOARCH in the build info);
#   • /app/VERSION, written by the same RUN that links the proxy, says
#     <version>.
#
# The version the BINARIES embed is checked by executing them
# (candidate-run-check.sh), not here: `-trimpath` makes the Go toolchain omit
# `-ldflags` from the build info, so the `-X main.version=…` value is not
# readable statically (measured: `go version -m` on a -trimpath binary lists
# GOOS/GOARCH/CGO_ENABLED but no -ldflags line). Running the binary is also the
# stronger claim — it is what `/health` and `culvert-maint -version` report.
#
# Seams: DOCKER_BIN, GO_BIN, JQ_BIN.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE="${1:?usage: candidate-verify-contents.sh <image> <digest> <sha> <version> <toolchain>}"
DIGEST="${2:?digest required}"
SHA="${3:?sha required}"
VERSION="${4:?version required}"
TOOLCHAIN="${5:?toolchain required}"

HERE="$(dirname "$0")"
# lib/registry.sh reads DOCKER_BIN unguarded; set the default before sourcing it.
DOCKER_BIN="${DOCKER_BIN:-docker}"
# shellcheck source=.github/scripts/lib/registry.sh
. "$HERE/lib/registry.sh"
# shellcheck source=.github/scripts/lib/candidate.sh
. "$HERE/lib/candidate.sh"
DOCKER="${DOCKER_BIN:-docker}"
GO="${GO_BIN:-go}"
JQ="${JQ_BIN:-jq}"

valid_digest "$DIGEST" || { echo "::error::malformed digest '${DIGEST}'"; exit 1; }
valid_sha "$SHA" || { echo "::error::'${SHA}' is not a full commit id"; exit 1; }
valid_version "$VERSION" || { echo "::error::'${VERSION}' is not vX.Y.Z"; exit 1; }

REF="${IMAGE}@${DIGEST}"
FAIL=0
bad() { echo "::error::$*"; FAIL=1; }

LINES="" ; LRC=0
LINES="$(index_platforms "$IMAGE" "$DIGEST")" || LRC=$?
[ "$LRC" -eq 0 ] || { echo "::error::cannot read the index ${REF}: ${LINES}"; exit 1; }
PV="$(platform_violations "$LINES")"
if [ -n "$PV" ]; then
  while IFS= read -r l; do bad "$l"; done <<< "$PV"
  exit 1
fi
echo "platforms:"; printf '  %s\n' "$LINES"

CFG="" ; CRC=0
CFG="$("$DOCKER" buildx imagetools inspect "$REF" --format '{{json .Image}}' 2>&1)" || CRC=$?
[ "$CRC" -eq 0 ] || { echo "::error::cannot read the image configs of ${REF}: ${CFG}"; exit 1; }

# setting <buildinfo> <key> — the value of a `build <key>=<value>` line.
setting() { printf '%s\n' "$1" | awk -v k="$2" -F'\t' '$2 == "build" && index($3, k "=") == 1 { print substr($3, length(k) + 2); exit }'; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for P in $CANDIDATE_PLATFORMS; do
  OS="${P%%/*}"; ARCH="${P#*/}"
  REV="$(printf '%s' "$CFG" | "$JQ" -r --arg p "$P" '
    (if has($p) then .[$p] else . end) | .config.Labels["org.opencontainers.image.revision"] // ""' 2>/dev/null || true)"
  [ "$REV" = "$SHA" ] || bad "${P}: image config names revision '${REV}', want ${SHA}"

  D="$WORK/$OS-$ARCH"; mkdir -p "$D"
  "$DOCKER" pull --quiet --platform "$P" "$REF" >/dev/null
  CID="$("$DOCKER" create --platform "$P" "$REF")"
  for f in /app/culvert /app/VERSION /app/deploy/bin/culvert-maint; do
    "$DOCKER" cp "${CID}:${f}" "$D/$(basename "$f")" >/dev/null || bad "${P}: ${f} is missing from the image"
  done
  "$DOCKER" rm "$CID" >/dev/null || true

  if [ -f "$D/VERSION" ]; then
    GOT="$(tr -d '[:space:]' < "$D/VERSION")"
    [ "$GOT" = "$VERSION" ] || bad "${P}: /app/VERSION says '${GOT}', want ${VERSION}"
  fi
  for BIN in culvert culvert-maint; do
    [ -f "$D/$BIN" ] || continue
    INFO="$("$GO" version -m "$D/$BIN" 2>&1)" || { bad "${P}: cannot read the build info of ${BIN}: ${INFO}"; continue; }
    CC="$(printf '%s\n' "$INFO" | head -n1 | awk '{print $2}')"
    [ "$CC" = "$TOOLCHAIN" ] || bad "${P}: ${BIN} was built by '${CC}', but go.mod pins ${TOOLCHAIN}"
    [ "$(setting "$INFO" GOOS)" = "$OS" ] || bad "${P}: ${BIN} was built for GOOS=$(setting "$INFO" GOOS)"
    [ "$(setting "$INFO" GOARCH)" = "$ARCH" ] || bad "${P}: ${BIN} was built for GOARCH=$(setting "$INFO" GOARCH)"
    echo "  ${P} ${BIN}: ${CC}, $(setting "$INFO" GOOS)/$(setting "$INFO" GOARCH)"
  done
done

if [ "$FAIL" -ne 0 ]; then
  echo "::error::the candidate ${REF} does not carry what it claims — not qualified."
  exit 1
fi
echo "candidate contents verified: ${REF} is ${VERSION} at ${SHA}, built by ${TOOLCHAIN}, on ${CANDIDATE_PLATFORMS}."
