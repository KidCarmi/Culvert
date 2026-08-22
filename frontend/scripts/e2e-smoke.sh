#!/bin/sh
# FE-1B real-binary browser smoke driver: builds the actual CULVERT binary
# (the committed frontend/dist is embedded by go:embed), starts it with the
# experimental UI enabled and plain-HTTP admin UI (headers identical; TLS
# termination is orthogonal to the serving contract), waits for readiness,
# then runs the Playwright spec against it. Never a dev server or a mock.
set -eu
FRONTEND="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$FRONTEND/.." && pwd)"
UI_PORT="${CULVERT_E2E_UI_PORT:-19090}"
PROXY_PORT="${CULVERT_E2E_PROXY_PORT:-19080}"
WORK="$(mktemp -d)"
BIN="$WORK/culvert"

cleanup() {
  [ -n "${CULVERT_PID:-}" ] && kill "$CULVERT_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "e2e-smoke: building CULVERT binary (embeds committed frontend/dist)"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN" .)

echo "e2e-smoke: starting binary (experimental UI enabled, ui-port $UI_PORT)"
(cd "$WORK" && CULVERT_EXPERIMENTAL_UI=1 "$BIN" \
  -port "$PROXY_PORT" -ui-port "$UI_PORT" -ui-no-tls \
  >"$WORK/culvert.log" 2>&1) &
CULVERT_PID=$!

i=0
until curl -fsS "http://127.0.0.1:$UI_PORT/api/setup/status" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "e2e-smoke: binary did not become ready; log tail:" >&2
    tail -30 "$WORK/culvert.log" >&2
    exit 1
  fi
  sleep 0.5
done
echo "e2e-smoke: binary ready"

cd "$FRONTEND"
CULVERT_E2E_BASE_URL="http://127.0.0.1:$UI_PORT" \
  npx playwright test --config e2e/playwright.config.ts
echo "e2e-smoke: PASS"
