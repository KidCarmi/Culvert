#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# candidate-run-check.sh <image> <digest> <version> <platform>
#
# Executes the candidate — by digest, for one platform — and checks what the
# running binaries REPORT, which is what a release promises:
#   • the proxy starts, `/health` says "ok", and its `version` is <version>;
#   • `culvert-maint -version` prints <version>.
#
# A non-native platform runs under QEMU (the caller sets it up). That is slow,
# but it is the only way to observe the embedded version of an arm64 binary:
# `-trimpath` keeps `-ldflags` out of the Go build info (see
# candidate-verify-contents.sh). The deadline is generous for that reason.
#
# Seams: DOCKER_BIN, CURL_BIN, RUN_CHECK_PORT, RUN_CHECK_TRIES, RUN_CHECK_DELAY.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

IMAGE="${1:?usage: candidate-run-check.sh <image> <digest> <version> <platform>}"
DIGEST="${2:?digest required}"
VERSION="${3:?version required}"
PLATFORM="${4:?platform required}"
DOCKER="${DOCKER_BIN:-docker}"
CURL="${CURL_BIN:-curl}"
PORT="${RUN_CHECK_PORT:-18080}"
TRIES="${RUN_CHECK_TRIES:-90}"
DELAY="${RUN_CHECK_DELAY:-2}"
REF="${IMAGE}@${DIGEST}"

# Pull THIS platform first: the local store keeps one image per reference, and
# a run with --platform against a store holding the other platform's image is
# not guaranteed to re-pull — it could execute the wrong architecture.
"$DOCKER" pull --quiet --platform "$PLATFORM" "$REF" >/dev/null

AGENT="$("$DOCKER" run --rm --platform "$PLATFORM" --entrypoint /app/deploy/bin/culvert-maint "$REF" -version 2>&1 | tr -d '[:space:]')" || true
if [ "$AGENT" != "$VERSION" ]; then
  echo "::error::${PLATFORM}: culvert-maint -version reports '${AGENT}', want ${VERSION}"
  exit 1
fi
echo "${PLATFORM}: culvert-maint reports ${AGENT}"

CID="$("$DOCKER" run -d --platform "$PLATFORM" -p "127.0.0.1:${PORT}:8080" "$REF" \
  -port 8080 -ui-port 9090 -ui-no-tls)"
cleanup() { "$DOCKER" logs "$CID" 2>&1 | tail -n 40 || true; "$DOCKER" rm -f "$CID" >/dev/null 2>&1 || true; }
trap cleanup EXIT

BODY=""
for _ in $(seq 1 "$TRIES"); do
  if BODY="$("$CURL" -sf "http://127.0.0.1:${PORT}/health" 2>/dev/null)"; then
    break
  fi
  BODY=""
  sleep "$DELAY"
done
[ -n "$BODY" ] || { echo "::error::${PLATFORM}: /health never answered"; exit 1; }
STATUS="$(printf '%s' "$BODY" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
GOT="$(printf '%s' "$BODY" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ "$STATUS" = "ok" ] || { echo "::error::${PLATFORM}: /health status '${STATUS}', want ok"; exit 1; }
if [ "$GOT" != "$VERSION" ]; then
  echo "::error::${PLATFORM}: the running proxy reports version '${GOT}', want ${VERSION}"
  exit 1
fi
echo "${PLATFORM}: the running proxy reports ${GOT}"
