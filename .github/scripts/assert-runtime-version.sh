#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# assert-runtime-version.sh <binary> <expected-version>
#
# Runtime version-identity gate. Starts the EXACT built proxy binary that will be
# signed/published, probes its live /healthz endpoint, and asserts it self-reports
# <expected-version> (the release tag). This proves the bytes-under-signature
# actually surface their release identity at runtime: the check that would have
# caught the v1.0.202 defect, where a correctly-stamped main.version never reached
# /healthz (the endpoint omitted the field entirely).
#
# Runs only on the native leg (linux/amd64) since a foreign-platform binary cannot
# execute on the runner; the shared build composite guarantees every matrix leg
# uses the identical linker value.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BIN="${1:-}"
WANT="${2:-}"

[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "::error::binary not executable: $BIN"; exit 2; }
[ -n "$WANT" ] || { echo "::error::expected version is empty (guard misconfigured)"; exit 2; }

PORT=38080
LOG="$(mktemp)"
BODY="$(mktemp)"

# ui-no-tls so /healthz is plain HTTP on the admin listener (the LB-probe surface).
# Password satisfies the product complexity policy (upper+lower+digit).
"$BIN" -ui-no-tls -ui-port "$PORT" -port "$((PORT + 1))" \
  -user gate -pass GateProbe123 -metrics-token GateProbeToken123456 >"$LOG" 2>&1 &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }
trap cleanup EXIT

GOT=""
for _ in $(seq 1 60); do
  code="$(curl -s -o "$BODY" -w '%{http_code}' "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || echo 000)"
  if [ "$code" = "200" ]; then
    GOT="$(grep -oE '"version":"[^"]*"' "$BODY" | head -1 | sed 's/.*"version":"//; s/"$//')"
    break
  fi
  kill -0 "$PID" 2>/dev/null || { echo "::error::binary exited during startup"; cat "$LOG"; exit 1; }
  sleep 0.5
done

if [ -z "$GOT" ]; then
  echo "::error::/healthz did not surface a version field (release identity is unverifiable at runtime)"
  cat "$BODY" 2>/dev/null || true
  exit 1
fi
if [ "$GOT" != "$WANT" ]; then
  echo "::error::runtime /healthz version '$GOT' != release tag '$WANT' (release build-identity defect)"
  exit 1
fi

echo "runtime version identity OK: /healthz reports $GOT (== release tag)"
