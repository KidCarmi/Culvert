#!/bin/sh
# FE-1B/FE-3 real-binary browser driver: builds the actual CULVERT binary
# (the committed frontend/dist is embedded by go:embed) and starts THREE
# instances covering the FE-3 auth states — never a dev server or a mock:
#   AUTH      (:19090) — configured appliance, roster seeded via the
#               supported -ui-users-file mechanism (admin, operator, viewer,
#               and a TOTP-enrolled user with one backup code)
#   FRESH     (:19091) — fresh appliance (needsSetup=true)
#   SETUPFAIL (:19092) — ui-users-file parent is a regular FILE, so the
#               credential save fails durably (500 + server-side rollback)
# then runs the Playwright suites against them.
set -eu
FRONTEND="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$FRONTEND/.." && pwd)"
UI_PORT="${CULVERT_E2E_UI_PORT:-19090}"
FRESH_PORT="${CULVERT_E2E_FRESH_PORT:-19091}"
FAIL_PORT="${CULVERT_E2E_FAIL_PORT:-19092}"
PROXY_PORT="${CULVERT_E2E_PROXY_PORT:-19080}"
WORK="$(mktemp -d)"
BIN="$WORK/culvert"

cleanup() {
  [ -n "${AUTH_PID:-}" ] && kill "$AUTH_PID" 2>/dev/null || true
  [ -n "${FRESH_PID:-}" ] && kill "$FRESH_PID" 2>/dev/null || true
  [ -n "${FAIL_PID:-}" ] && kill "$FAIL_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

echo "e2e-smoke: building CULVERT binary (embeds committed frontend/dist)"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN" .)

# ── AUTH instance: seeded roster ─────────────────────────────────────────
# bcrypt hashes (hex, cost 10) for the fixture credentials in e2e/fixtures.ts;
# totp-user carries the base32 secret JBSWY3DPEHPK3PXP and one bcrypt-hashed
# backup code (RESCUE-CODE-7).
mkdir -p "$WORK/auth" "$WORK/fresh" "$WORK/failparent"
cat > "$WORK/auth/ui_users.json" <<'EOF'
{
  "default_auth_outcome": "Default",
  "users": [
    {
      "username": "admin",
      "pass_hash": "243261243130244144444944653830376a794b73614c37354a706c302e49544d69667451516e4d6e4f675a34546954723737506a6236754972634d71",
      "role": "admin"
    },
    {
      "username": "op-user",
      "pass_hash": "243261243130246e6f79492f476852757156497237472f4653332e6e2e57366d53525562304f515778336a7a4f6b325261574d674b55786a4d767557",
      "role": "operator"
    },
    {
      "username": "view-user",
      "pass_hash": "2432612431302442795a6736464466644f6e725362665038354b6c764f7770536776534e546f395a767577794f3254536550697a444d42564b4b7132",
      "role": "viewer"
    },
    {
      "username": "totp-user",
      "pass_hash": "24326124313024646268456746455a474b6777515a2e416e4767654c4f2f432f557634714e69326b4b74734c6530647538496a57376d2e714d6f5343",
      "role": "admin",
      "totp_secret": "JBSWY3DPEHPK3PXP",
      "backup_codes": ["$2a$10$RJzHx2XL9X9woIyg.vgPJu5eQ/HQGNWKprv2uuuX1BsiUO5t3pTw2"]
    }
  ]
}
EOF

# SETUPFAIL: the ui-users-file "directory" is a regular file, so the durable
# save inside apiSetupComplete fails with ENOTDIR even for root.
: > "$WORK/failparent/blocker"

start_instance() {
  # $1=name $2=ui-port $3=proxy-port $4=extra args...
  name="$1"; uiport="$2"; pport="$3"; shift 3
  d="$WORK/run-$name"
  mkdir -p "$d"
  (cd "$d" && CULVERT_EXPERIMENTAL_UI=1 "$BIN" \
    -port "$pport" -ui-port "$uiport" -ui-no-tls "$@" \
    >"$WORK/$name.log" 2>&1) &
  eval "${name}_PID=\$!"
}

start_instance AUTH "$UI_PORT" "$PROXY_PORT" -ui-users-file "$WORK/auth/ui_users.json"
start_instance FRESH "$FRESH_PORT" "$((PROXY_PORT + 1))" -ui-users-file "$WORK/fresh/ui_users.json"
start_instance FAIL "$FAIL_PORT" "$((PROXY_PORT + 2))" -ui-users-file "$WORK/failparent/blocker/ui_users.json"

wait_ready() {
  port="$1"; name="$2"
  i=0
  until curl -fsS "http://127.0.0.1:$port/api/setup/status" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
      echo "e2e-smoke: $name instance did not become ready; log tail:" >&2
      tail -30 "$WORK/$name.log" >&2
      exit 1
    fi
    sleep 0.5
  done
}
wait_ready "$UI_PORT" AUTH
wait_ready "$FRESH_PORT" FRESH
wait_ready "$FAIL_PORT" FAIL
echo "e2e-smoke: all three instances ready"

cd "$FRONTEND"
CULVERT_E2E_BASE_URL="http://127.0.0.1:$UI_PORT" \
CULVERT_E2E_FRESH_URL="http://127.0.0.1:$FRESH_PORT" \
CULVERT_E2E_SETUPFAIL_URL="http://127.0.0.1:$FAIL_PORT" \
  npx playwright test --config e2e/playwright.config.ts
echo "e2e-smoke: PASS"
