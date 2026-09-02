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
  [ -n "${SLUICE_PID:-}" ] && kill "$SLUICE_PID" 2>/dev/null || true
  [ -n "${AUTH_PID:-}" ] && kill "$AUTH_PID" 2>/dev/null || true
  [ -n "${FRESH_PID:-}" ] && kill "$FRESH_PID" 2>/dev/null || true
  [ -n "${FAIL_PID:-}" ] && kill "$FAIL_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

echo "e2e-smoke: building CULVERT binary (embeds committed frontend/dist)"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN" .)

# ── 2E-C real engine: the PINNED Sluice daemon (go.mod) runs as a real
# subprocess with real mTLS, so the browser enrollment journey exercises a
# genuine token exchange, a genuine definite refusal, and genuine receipts
# — never a mock. Tokens are per-process (first-boot token file); the
# daemon is per-run and lives in the harness tmp dir.
SLUICE_PORT="${CULVERT_E2E_SLUICE_PORT:-19443}"
SLUICE_BIN="$WORK/sluice"
echo "e2e-smoke: building the pinned Sluice daemon"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$SLUICE_BIN" github.com/KidCarmi/Sluice/cmd/sluice)
mkdir -p "$WORK/sl"
cat > "$WORK/sl/config.yaml" <<EOF2
server:
  grpc_addr: "127.0.0.1:$SLUICE_PORT"
  http_addr: "127.0.0.1:$((SLUICE_PORT + 1))"
  tls:
    cert_file: $WORK/sl/server.pem
    key_file: $WORK/sl/server-key.pem
    ca_file: $WORK/sl/ca.pem
enrollment:
  enabled: true
  token_file: $WORK/sl/enrollment_token
cli:
  socket_path: $WORK/sl/s.sock
logging:
  format: json
  level: warn
EOF2
("$SLUICE_BIN" -config "$WORK/sl/config.yaml" >"$WORK/sluice.log" 2>&1) &
SLUICE_PID=$!
i=0
until [ -s "$WORK/sl/enrollment_token" ] && [ -s "$WORK/sl/server.pem" ]; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then
    echo "e2e-smoke: Sluice daemon did not come up; log tail:" >&2
    tail -30 "$WORK/sluice.log" >&2
    exit 1
  fi
  sleep 0.5
done
SLUICE_TOKEN="$(cat "$WORK/sl/enrollment_token")"
SLUICE_FP="$(openssl x509 -in "$WORK/sl/server.pem" -noout -fingerprint -sha256 | sed 's/^.*=//; s/://g' | tr 'A-F' 'a-f')"
echo "e2e-smoke: Sluice daemon ready on 127.0.0.1:$SLUICE_PORT (pin ${SLUICE_FP%????????????????????????????????????????????????}…)"

# ── AUTH instance: seeded roster ─────────────────────────────────────────
# bcrypt hashes (hex, cost 10) for the fixture credentials in e2e/fixtures.ts;
# totp-user carries the base32 secret JBSWY3DPEHPK3PXP and one bcrypt-hashed
# backup code (RESCUE-CODE-7).
mkdir -p "$WORK/auth" "$WORK/fresh" "$WORK/failparent"
cat > "$WORK/auth/ui_users.json" <<'EOF'
{
  "default_auth_outcome": "Exempt",
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

# Zero-Trust posture for the seeded history: Stage-1 is Exempt (no proxy
# credentials needed) and Stage-2 default_action is deny, so each seeded
# request is refused at the policy default (POLICY_DEFAULT_DENY) with zero
# egress, and lands in the Badger history store at log_store_path.
cat > "$WORK/auth/config.yaml" <<EOF2
default_action: deny
log_store_path: $WORK/auth/logstore
EOF2

# ── 2A policy fixture: 503 rules loaded via the supported -policy file ────
# Priority 1  : "E2E Match Rule" — Block_Page on rule-hit.test (a matched
#               BLOCK logs the rule name + stable ULID with ZERO egress; the
#               ULID is minted by the server's load-time backfill, never
#               hardcoded in test code).
# Priority 5  : carries fileProfile/category references for the Where Used
#               browser proof.
# 10..509     : 500 Stage-2 access rules — the scale-qualification corpus.
#               None matches the fe4-seed-*.test or rule-hit.test seeds, so
#               the FE-4 default-deny history evidence is unchanged.
# 9001..9002  : two VALID Stage-1 auth rules (ruleType=auth), proving the
#               Access Rules surface excludes them.
{
  printf '[\n'
  printf '{"priority":1,"name":"E2E Match Rule","destFQDN":"rule-hit.test","action":"Block_Page","sslAction":"","fileFiltering":true,"fileProfile":"Executables","comment":"Deterministic 2A match target"},\n'
  printf '{"priority":5,"name":"E2E Reference Rule","destFQDN":"ref-probe.test","destCategory":"News","fileFiltering":true,"fileProfile":"Executables","action":"Allow","sslAction":"Inspect","comment":"Where-used fixture"},\n'
  i=1
  while [ "$i" -le 500 ]; do
    if [ $((i % 2)) -eq 0 ]; then act=Allow; ssl=Bypass; else act=Block_Page; ssl=Inspect; fi
    printf '{"priority":%d,"name":"Bulk rule %03d","destFQDN":"bulk-%d.example.test","action":"%s","sslAction":"%s"},\n' "$((i + 9))" "$i" "$i" "$act" "$ssl"
    i=$((i + 1))
  done
  printf '{"priority":9001,"name":"E2E Auth Exempt","ruleType":"auth","action":"Allow","destFQDN":"auth-fixture.test","subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.99.0.0/24"]}]},"auth":{"outcome":"Exempt","owner":"e2e-harness","reason":"Stage-1 exclusion fixture"}},\n'
  printf '{"priority":9002,"name":"E2E Auth Exempt B","ruleType":"auth","action":"Allow","destFQDN":"auth-fixture-b.test","subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.98.0.0/24"]}]},"auth":{"outcome":"Exempt","owner":"e2e-harness","reason":"Stage-1 exclusion fixture B"}}\n'
  printf ']\n'
} > "$WORK/auth/policy.json"

# FRESH/SETUPFAIL get their OWN log_store_path (recorded harness debt: the
# dataDir is a fixed absolute /data SHARED by all local instances, and the
# shared admin_settings.json can carry log_store_enabled from a previous
# run/instance — at boot every path-less instance then races for the ONE
# badger flock on /data/logstore, so whichever instance loses cannot enable
# history mid-suite: "cannot enable history store" on a coin flip). A
# per-instance path makes the FRESH history journeys deterministic; a config
# file does not affect the fresh appliance's needsSetup state (that is the
# ui-users roster).
cat > "$WORK/fresh/config.yaml" <<EOF2
log_store_path: $WORK/fresh/logstore
EOF2
cat > "$WORK/failcfg.yaml" <<EOF2
log_store_path: $WORK/faillogstore
EOF2

# 2E-A premise: a per-run LOCAL YARA rules directory so the Content Security
# YARA journey exercises the real engine deterministically (no external
# service; the dir starts empty and the spec cleans up what it creates).
mkdir -p "$WORK/auth/yara"
start_instance AUTH "$UI_PORT" "$PROXY_PORT" -ui-users-file "$WORK/auth/ui_users.json" -config "$WORK/auth/config.yaml" -policy "$WORK/auth/policy.json" -yara-rules-dir "$WORK/auth/yara"
start_instance FRESH "$FRESH_PORT" "$((PROXY_PORT + 1))" -ui-users-file "$WORK/fresh/ui_users.json" -config "$WORK/fresh/config.yaml"
start_instance FAIL "$FAIL_PORT" "$((PROXY_PORT + 2))" -ui-users-file "$WORK/failparent/blocker/ui_users.json" -config "$WORK/failcfg.yaml"

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

# API-establish the retained-history premise (§19): the AUTH instance's
# log-store boot state inherits the SHARED /data/admin_settings.json left by
# the PREVIOUS run (recorded harness debt — dataDir is a fixed absolute
# path), so if a prior run ended with the store disabled the seeds below
# would silently land only in the memory ring and every retained-history
# assertion would fail. Enable it through the supported admin API first.
# criticalDiskPct=99: on dev machines the session disk allowance makes
# statvfs read ~90%+ used permanently, and the default 90% threshold
# engages EMERGENCY minimal logging + retained-history cleanup mid-suite
# (a CORRECT product behavior that destroys the harness premise).
SEED_JAR="$WORK/auth/seed-cookies.txt"
curl -s -o /dev/null -c "$SEED_JAR" -X POST -H 'Content-Type: application/json' \
  -d '{"user":"admin","pass":"Password123"}' \
  "http://127.0.0.1:$UI_PORT/api/auth/login"
curl -s -o /dev/null -b "$SEED_JAR" -X PUT -H 'Content-Type: application/json' \
  -d '{"enabled":true,"retentionDays":7,"retentionMaxGB":1,"criticalDiskPct":99}' \
  "http://127.0.0.1:$UI_PORT/api/logs/retention"
# Trusted-proxy premise (supported admin API, RISK-019): the admin-plane
# per-IP rate limiter (60 mutations/min, hard-coded — a deliberate security
# posture) keys on realClientIP, and every suite client shares 127.0.0.1, so
# the budget is a SUITE-LENGTH shared resource — as specs accumulated, late
# tests started drawing 429s on legitimate mutations (first observed on the
# 2C post-accept lifecycle proof). Trusting loopback as a reverse proxy (the
# exact deployment shape the feature exists for) lets multi-client tests
# present distinct synthetic X-Forwarded-For identities and draw from their
# OWN per-IP budgets; clients that send no XFF still resolve to 127.0.0.1
# and the limiter stays fully armed for them.
curl -s -o /dev/null -b "$SEED_JAR" -X POST -H 'Content-Type: application/json' \
  -d '{"base_url":"","ui_sans":[],"trust_forwarded_headers":false,"trusted_proxy_cidrs":["127.0.0.1"]}' \
  "http://127.0.0.1:$UI_PORT/api/settings/network"
# Draft-mode hygiene: the SHARED /data admin_settings.json can carry
# require_commit=true (and /data/policy_draft state) from an interrupted
# previous run — e.g. a test's own cleanup drew a 429 — which breaks the 2A/2B
# live-write premises. Revert any inherited draft (tolerated 4xx when none is
# active), then disarm (the disarm refuses while a candidate is dirty, hence
# revert first).
curl -s -o /dev/null -b "$SEED_JAR" -X POST \
  "http://127.0.0.1:$UI_PORT/api/policy/draft/revert" || true
curl -s -o /dev/null -b "$SEED_JAR" -X PUT -H 'Content-Type: application/json' \
  -d '{"require_commit":false}' \
  "http://127.0.0.1:$UI_PORT/api/policy/draft"

echo "e2e-smoke: seeding traffic history through the AUTH proxy (default-deny)"
i=0
while [ "$i" -lt 150 ]; do
  curl -s -o /dev/null --max-time 2 -x "http://127.0.0.1:$PROXY_PORT" "http://fe4-seed-$i.test/" || true
  i=$((i + 1))
done
# 2A: ONE request matching "E2E Match Rule" (Block_Page — zero egress). The
# resulting newest history row carries the rule's real stable ULID for the
# Traffic → Policy deep-link proof. Total history: 151 entries.
curl -s -o /dev/null --max-time 2 -x "http://127.0.0.1:$PROXY_PORT" "http://rule-hit.test/" || true
sleep 2 # allow the async history writer to flush

cd "$FRONTEND"
CULVERT_E2E_BASE_URL="http://127.0.0.1:$UI_PORT" \
CULVERT_E2E_FRESH_URL="http://127.0.0.1:$FRESH_PORT" \
CULVERT_E2E_SETUPFAIL_URL="http://127.0.0.1:$FAIL_PORT" \
CULVERT_E2E_SLUICE_ADDR="127.0.0.1:$SLUICE_PORT" \
CULVERT_E2E_SLUICE_FP="$SLUICE_FP" \
CULVERT_E2E_SLUICE_TOKEN="$SLUICE_TOKEN" \
  npx playwright test --config e2e/playwright.config.ts "$@"
echo "e2e-smoke: PASS"
