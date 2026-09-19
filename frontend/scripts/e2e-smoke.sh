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
# 2F-G: a FOURTH appliance whose config.yaml seeds a read-only `yaml`
# upstream entry (the YAML read-only posture proof). It is a separate
# instance because a config.yaml parent proxy CHAINS every allowed
# plain-HTTP request of the appliance that carries it (PX-1), which would
# change the data-plane premise of every other journey on the AUTH
# instance. Nobody proxies traffic through it.
YAML_PORT="${CULVERT_E2E_YAML_PORT:-19093}"
# FE-6A.1: a FIFTH appliance whose IdP registry file is CORRUPT — quarantined
# at boot (auth_idp.go Load, R8) — and whose config.yaml carries a legacy
# `ldap:` block that stays present, active and NOT retired (its registry
# refuses writes, so no cutover can ever land on it). It exists because the
# corrupt/quarantined posture is a BOOT-TIME truth: no supported API can put
# a running appliance into it, and no other instance may carry it (a
# quarantined registry refuses every IdP write the other journeys need).
IDPQ_PORT="${CULVERT_E2E_IDPQ_PORT:-19094}"
# FE-6A.2 IDPW: the WRITE-journey appliance — boots on a corrupt registry
# (quarantined) with a legacy `ldap:` block, so one browser journey can run
# repair → legacy import → cutover ceremony → edit → delete end to end
# without consuming YAMLUP's once-ever cutover or IDPQ's read-only posture.
IDPW_PORT="${CULVERT_E2E_IDPW_PORT:-19095}"
# FE-6B.1 CERT: a persisted, passphrase-sealed inspection CA (-ca-path +
# CULVERT_CA_PASSPHRASE) and NO UI pair at boot — the fe6b1 spec seeds one
# through the supported admin API, so the read surface must report it
# persisted but NOT active (activation requires a restart). CERTDEG: a
# MALFORMED bundle at -ca-path (load failed, bundle_malformed, no Root CA),
# a persisted UI pair whose key does not match its certificate (corrupt at
# boot) and a pre-seeded operation ledger carrying one record per terminal
# state class — boot-time truths no API can produce on a running node.
CERT_PORT="${CULVERT_E2E_CERT_PORT:-19096}"
CERTDEG_PORT="${CULVERT_E2E_CERTDEG_PORT:-19097}"
WORK="$(mktemp -d)"
BIN="$WORK/culvert"

cleanup() {
  [ -n "${SLUICE_PID:-}" ] && kill "$SLUICE_PID" 2>/dev/null || true
  [ -n "${LDAP_STUB_PID:-}" ] && kill "$LDAP_STUB_PID" 2>/dev/null || true
  [ -n "${AUTH_PID:-}" ] && kill "$AUTH_PID" 2>/dev/null || true
  [ -n "${FRESH_PID:-}" ] && kill "$FRESH_PID" 2>/dev/null || true
  [ -n "${FAIL_PID:-}" ] && kill "$FAIL_PID" 2>/dev/null || true
  [ -n "${YAMLUP_PID:-}" ] && kill "$YAMLUP_PID" 2>/dev/null || true
  [ -n "${IDPQ_PID:-}" ] && kill "$IDPQ_PID" 2>/dev/null || true
  [ -n "${IDPW_PID:-}" ] && kill "$IDPW_PID" 2>/dev/null || true
  [ -n "${CERT_PID:-}" ] && kill "$CERT_PID" 2>/dev/null || true
  [ -n "${CERTDEG_PID:-}" ] && kill "$CERTDEG_PID" 2>/dev/null || true
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

# ── FE-6A.2 correction (Blocker 3): the appliance's enabled-LDAP writes cross
# the directory connection preflight at the write boundary UNCONDITIONALLY,
# so every journey that ENABLES an LDAP profile needs a directory that
# answers. cmd/ldapstub is the minimal in-repo responder (bind + base search);
# it is a harness fixture, never a production component. The YAMLUP/IDPW
# legacy blocks keep their `.invalid` directory so a journey can also prove
# the typed preflight refusal (zero mutation) before pointing at the stub.
LDAP_STUB_PORT="${CULVERT_E2E_LDAP_STUB_PORT:-19389}"
LDAP_STUB_BIN="$WORK/ldapstub"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$LDAP_STUB_BIN" ./cmd/ldapstub)
("$LDAP_STUB_BIN" -listen "127.0.0.1:$LDAP_STUB_PORT" >"$WORK/ldapstub.log" 2>&1) &
LDAP_STUB_PID=$!
LDAP_STUB_URL="ldap://127.0.0.1:$LDAP_STUB_PORT"
echo "e2e-smoke: LDAP stub directory on $LDAP_STUB_URL"

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
  # Every instance persists into its OWN data root (CULVERT_DATA_DIR, PR-C1):
  # the appliance's default is the fixed absolute /data, which (a) a CI
  # runner's unprivileged user cannot write — every /data-backed mutation
  # (admin settings, object stores, PAC profiles, CDR, drafts) then answered
  # persist_failed/503 while root-run qualification passed — and (b) was
  # SHARED by all four local instances, so state leaked across instances
  # and across runs. A per-instance root under the harness tmp dir makes
  # the suite hermetic on any host and for any user.
  name="$1"; uiport="$2"; pport="$3"; shift 3
  d="$WORK/run-$name"
  mkdir -p "$d"
  # exec: the recorded PID must be the APPLIANCE, not the subshell. With a
  # plain subshell `$!` names the subshell, cleanup's SIGTERM kills only
  # that, and the appliance is reparented to init and keeps its fixed ports
  # — the next run's readiness probes then hit the previous run's
  # instances and its seed login fails (FE-6A.0 correction requalification
  # finding: two consecutive runs collided deterministically).
  (cd "$d" && exec env CULVERT_EXPERIMENTAL_UI=1 CULVERT_DATA_DIR="$d" "$BIN" \
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

# FRESH/SETUPFAIL get their OWN log_store_path. (Historically this closed a
# harness debt: dataDir was a fixed absolute /data SHARED by all local
# instances, so a shared admin_settings.json could carry log_store_enabled
# and every path-less instance raced for the ONE badger flock on
# /data/logstore. Since PR-C1 every instance has its own data root, so the
# explicit path is now only the deterministic, self-describing premise.) A
# config file does not affect the fresh appliance's needsSetup state (that
# is the ui-users roster).
cat > "$WORK/fresh/config.yaml" <<EOF2
log_store_path: $WORK/fresh/logstore
EOF2
cat > "$WORK/failcfg.yaml" <<EOF2
log_store_path: $WORK/faillogstore
EOF2
# 2F-G YAML-seeded appliance: same roster as AUTH (a private copy — the
# roster file is written back on user changes), its own history path, and
# one config.yaml parent proxy under the `.invalid` TLD (RFC 6761: never
# resolves), so its periodic probe fails deterministically and nothing is
# ever dialled. Its only role in the suite is the read-only `yaml` row.
mkdir -p "$WORK/yamlup"
cp "$WORK/auth/ui_users.json" "$WORK/yamlup/ui_users.json"
# FE-6A.1: YAMLUP also carries a legacy YAML `ldap:` block (a `.invalid`
# directory — never dialled: Stage-1 is Exempt on every seeded roster) and an
# armed registry file, so fe6a1.spec.ts can commit the ONE operation-
# identified legacy-LDAP authority cutover through the supported admin API
# and the read surface can report the durable record. The bind_password is
# a canary the browser must never receive (bindCredentialConfigured only).
cat > "$WORK/yamlup/config.yaml" <<EOF2
log_store_path: $WORK/yamlup/logstore
upstream:
  proxies:
    - url: http://yaml-parent.invalid:3128
ldap:
  url: ldaps://legacy-dc.invalid:636
  base_dn: dc=legacy,dc=invalid
  bind_dn: cn=svc,dc=legacy,dc=invalid
  bind_password: YAMLBINDCANARY-legacy-ldap-never-in-browser
EOF2

# FE-6A.1 IDPQ: same roster (private copy), a legacy `ldap:` block that stays
# present/active/not-retired, and a registry file that is NOT valid JSON —
# quarantined at boot, registry EMPTY + degraded, writes refused.
mkdir -p "$WORK/idpq"
cp "$WORK/auth/ui_users.json" "$WORK/idpq/ui_users.json"
cat > "$WORK/idpq/config.yaml" <<EOF2
log_store_path: $WORK/idpq/logstore
ldap:
  url: ldaps://legacy-dc.invalid:636
  base_dn: dc=legacy,dc=invalid
  bind_dn: cn=svc,dc=legacy,dc=invalid
  bind_password: YAMLBINDCANARY-legacy-ldap-never-in-browser
EOF2
printf '[{"id":"torn","name":"torn"' > "$WORK/idpq/idp_profiles.json"

# FE-6A.2 IDPW: private roster copy, the same legacy `ldap:` block (present /
# active / not retired) and a corrupt registry file — the fe6a2 write journey
# repairs it through the T2 ceremony (confirm = the quarantine base name),
# imports the legacy block (disabled), retires the legacy authenticator via
# the cutover ceremony (confirm = the legacy directory URL), edits and deletes.
mkdir -p "$WORK/idpw"
cp "$WORK/auth/ui_users.json" "$WORK/idpw/ui_users.json"
cat > "$WORK/idpw/config.yaml" <<EOF2
log_store_path: $WORK/idpw/logstore
ldap:
  url: ldaps://legacy-dc.invalid:636
  base_dn: dc=legacy,dc=invalid
  bind_dn: cn=svc,dc=legacy,dc=invalid
  bind_password: YAMLBINDCANARY-legacy-ldap-never-in-browser
EOF2
printf '[{"id":"torn","name":"torn"' > "$WORK/idpw/idp_profiles.json"

# 2E-A premise: a per-run LOCAL YARA rules directory so the Content Security
# YARA journey exercises the real engine deterministically (no external
# service; the dir starts empty and the spec cleans up what it creates).
mkdir -p "$WORK/auth/yara"
# FE-6A.1: AUTH and YAMLUP arm a per-run IdP registry file (the supported
# -idp-profiles-file mechanism) so the registry is PERSISTED and the fe6a1
# spec can seed profiles through the admin API; the file starts absent
# (first run — empty registry).
start_instance AUTH "$UI_PORT" "$PROXY_PORT" -ui-users-file "$WORK/auth/ui_users.json" -config "$WORK/auth/config.yaml" -policy "$WORK/auth/policy.json" -yara-rules-dir "$WORK/auth/yara" -idp-profiles-file "$WORK/auth/idp_profiles.json"
start_instance FRESH "$FRESH_PORT" "$((PROXY_PORT + 1))" -ui-users-file "$WORK/fresh/ui_users.json" -config "$WORK/fresh/config.yaml"
start_instance FAIL "$FAIL_PORT" "$((PROXY_PORT + 2))" -ui-users-file "$WORK/failparent/blocker/ui_users.json" -config "$WORK/failcfg.yaml"
start_instance YAMLUP "$YAML_PORT" "$((PROXY_PORT + 3))" -ui-users-file "$WORK/yamlup/ui_users.json" -config "$WORK/yamlup/config.yaml" -idp-profiles-file "$WORK/yamlup/idp_profiles.json"
start_instance IDPQ "$IDPQ_PORT" "$((PROXY_PORT + 4))" -ui-users-file "$WORK/idpq/ui_users.json" -config "$WORK/idpq/config.yaml" -idp-profiles-file "$WORK/idpq/idp_profiles.json"
start_instance IDPW "$IDPW_PORT" "$((PROXY_PORT + 5))" -ui-users-file "$WORK/idpw/ui_users.json" -config "$WORK/idpw/config.yaml" -idp-profiles-file "$WORK/idpw/idp_profiles.json"

# ── FE-6B.1 CERT / CERTDEG ──────────────────────────────────────────────────
CA_PASSPHRASE_CANARY="E2E-CA-PASSPHRASE-never-in-browser"
mkdir -p "$WORK/cert" "$WORK/certdeg" "$WORK/run-CERTDEG"
cp "$WORK/auth/ui_users.json" "$WORK/cert/ui_users.json"
cp "$WORK/auth/ui_users.json" "$WORK/certdeg/ui_users.json"
printf 'log_store_path: %s/cert/logstore\n' "$WORK" > "$WORK/cert/config.yaml"
printf 'log_store_path: %s/certdeg/logstore\n' "$WORK" > "$WORK/certdeg/config.yaml"
# A UI leaf pair the spec uploads through the admin API (target=ui) — never
# through the surface under test. Generated here so the spec needs no X.509
# library; the private key never reaches the browser (leak needle).
openssl ecparam -genkey -name prime256v1 -noout -out "$WORK/cert/ui.key" 2>/dev/null
openssl req -x509 -new -key "$WORK/cert/ui.key" -subj "/CN=ui-fe6b1.e2e" -days 365 \
  -addext "subjectAltName=DNS:ui-fe6b1.e2e" -out "$WORK/cert/ui.crt" 2>/dev/null
# CERTDEG: the bundle is not a bundle; the persisted pair is a certificate
# beside a key from a DIFFERENT keypair (corrupt at boot: complete, invalid).
printf 'this is not a CA bundle' > "$WORK/certdeg/ca.bundle"
openssl ecparam -genkey -name prime256v1 -noout -out "$WORK/certdeg/other.key" 2>/dev/null
cp "$WORK/cert/ui.crt" "$WORK/run-CERTDEG/ui_tls_cert.pem"
cp "$WORK/certdeg/other.key" "$WORK/run-CERTDEG/ui_tls_key.pem"
chmod 600 "$WORK/run-CERTDEG/ui_tls_key.pem"
# The ledger: SUP (terminal superseded UNKNOWN), PEND (a pending import the
# boot settles against the malformed bundle: reconciled_evidence_invalid),
# ABT (aborted, persist_failed), CMT (committed + audited OCSP set).
FE6B1_HEX="$(printf 'fe6b1-candidate' | openssl dgst -sha256 | sed 's/^.*= *//')"
cat > "$WORK/run-CERTDEG/certificate_operations.json" <<EOF2
[
 {"operationId":"6b1e0000-fe6b-4e2e-9f00-000000000501","state":"outcome_unknown","action":"ca.import","actor":"admin@10.99.0.1","target":"root_ca","candidateDigest":"$FE6B1_HEX","fence":"car1:none","startedAt":"2026-09-18T10:00:00Z","finishedAt":"2026-09-18T10:00:02Z","code":"writer_evidence_superseded","supersededBy":"6b1e0000-fe6b-4e2e-9f00-0000000005aa","audited":false},
 {"operationId":"6b1e0000-fe6b-4e2e-9f00-000000000502","state":"pending","action":"ca.import","actor":"admin@10.99.0.1","target":"root_ca","candidateDigest":"$FE6B1_HEX","fence":"car1:none","startedAt":"2026-09-18T10:01:00Z","audited":false},
 {"operationId":"6b1e0000-fe6b-4e2e-9f00-000000000503","state":"aborted","action":"cert.ui.replace","actor":"admin@10.99.0.1","target":"ui_cert","candidateDigest":"$FE6B1_HEX","fence":"uic1:none","startedAt":"2026-09-18T10:02:00Z","finishedAt":"2026-09-18T10:02:01Z","code":"persist_failed","audited":false},
 {"operationId":"6b1e0000-fe6b-4e2e-9f00-000000000504","state":"committed","action":"ocsp.set","actor":"admin@10.99.0.1","target":"ocsp","candidateDigest":"disabled","fence":"ocr1:$FE6B1_HEX","expect":"1","startedAt":"2026-09-18T10:03:00Z","finishedAt":"2026-09-18T10:03:01Z","committedRevision":"ocr1:$FE6B1_HEX","result":{"ok":true,"enabled":false,"durable":true,"revision":"ocr1:$FE6B1_HEX","desired":{"enabled":false,"source":"admin"},"runtime":{"enabled":false}},"audited":true}
]
EOF2
# Exported explicitly (a prefix assignment on a FUNCTION call is not
# portably exported to the commands the function runs); unset right after so
# CERTDEG and nothing else inherits it.
CULVERT_CA_PASSPHRASE="$CA_PASSPHRASE_CANARY"; export CULVERT_CA_PASSPHRASE
start_instance CERT "$CERT_PORT" "$((PROXY_PORT + 6))" -ui-users-file "$WORK/cert/ui_users.json" -config "$WORK/cert/config.yaml" -ca-path "$WORK/cert/ca.bundle"
unset CULVERT_CA_PASSPHRASE
start_instance CERTDEG "$CERTDEG_PORT" "$((PROXY_PORT + 7))" -ui-users-file "$WORK/certdeg/ui_users.json" -config "$WORK/certdeg/config.yaml" -ca-path "$WORK/certdeg/ca.bundle"

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
wait_ready "$YAML_PORT" YAMLUP
wait_ready "$IDPQ_PORT" IDPQ
wait_ready "$IDPW_PORT" IDPW
wait_ready "$CERT_PORT" CERT
wait_ready "$CERTDEG_PORT" CERTDEG
echo "e2e-smoke: all eight instances ready"

# API-establish the retained-history premise (§19): the AUTH instance boots
# from a FRESH per-instance data root (PR-C1), so the retained-history store
# is off until the harness enables it through the supported admin API —
# otherwise the seeds below would land only in the memory ring and every
# retained-history assertion would fail.
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
# Disk-pressure PREFLIGHT (2F-F requalification finding): the appliance
# measures disk usage from statfs Bavail — the UNPRIVILEGED available space —
# and a session disk allowance on this class of runner can read >= 99%
# (the product's maximum configurable threshold) while df shows tens of GB
# free elsewhere. At or above the threshold the retention janitor's
# disk-critical cleanup deletes the appliance's own retained history
# (logguard.go handleDiskCritical — correct product behavior, it can only
# ever free its own logs), so the seed above is destroyed minutes into the
# run and the Traffic -> Policy deep-link journey fails on its
# newest-history premise with nothing in the harness naming the cause.
# Refuse to START within one point of the threshold instead of letting the
# premise decay mid-suite: free space on the runner, then rerun.
GUARD_JSON="$(curl -s -b "$SEED_JAR" "http://127.0.0.1:$UI_PORT/api/logs/retention")"
DISK_USED="$(printf '%s' "$GUARD_JSON" | sed -n 's/.*"diskUsedPct":\([0-9.]*\).*/\1/p')"
DISK_CRIT="$(printf '%s' "$GUARD_JSON" | sed -n 's/.*"criticalDiskPct":\([0-9]*\).*/\1/p')"
if [ -z "$DISK_USED" ] || [ -z "$DISK_CRIT" ]; then
  echo "e2e-smoke: could not read the disk-guard reading from /api/logs/retention; refusing to run (retained-history premise unverifiable)" >&2
  exit 1
fi
if awk -v u="$DISK_USED" -v c="$DISK_CRIT" 'BEGIN { exit !(u + 0 >= c - 1) }'; then
  echo "e2e-smoke: appliance disk-usage reading ${DISK_USED}% is within one point of the critical threshold ${DISK_CRIT}% — the seeded retained history would be deleted mid-suite; free space on this host and rerun" >&2
  exit 1
fi
echo "e2e-smoke: disk-guard preflight ok (used ${DISK_USED}%, critical ${DISK_CRIT}%)"
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
# Draft-mode hygiene: establish the 2A/2B live-write premise explicitly —
# no draft is open and commit mode is disarmed. (The data root is fresh per
# run since PR-C1; this used to also scrub require_commit/policy_draft state
# inherited through the shared /data.) Revert tolerates a 4xx when no draft
# is active; the disarm refuses while a candidate is dirty, hence revert
# first.
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
CULVERT_E2E_YAML_URL="http://127.0.0.1:$YAML_PORT" \
CULVERT_E2E_IDPQ_URL="http://127.0.0.1:$IDPQ_PORT" \
CULVERT_E2E_IDPW_URL="http://127.0.0.1:$IDPW_PORT" \
CULVERT_E2E_CERT_URL="http://127.0.0.1:$CERT_PORT" \
CULVERT_E2E_CERTDEG_URL="http://127.0.0.1:$CERTDEG_PORT" \
CULVERT_E2E_CERT_UI_PAIR_DIR="$WORK/cert" \
CULVERT_E2E_CERTDEG_DATA_DIR="$WORK/run-CERTDEG" \
CULVERT_E2E_CA_PASSPHRASE_CANARY="$CA_PASSPHRASE_CANARY" \
CULVERT_E2E_AUTH_DATA_DIR="$WORK/run-AUTH" \
CULVERT_E2E_SLUICE_ADDR="127.0.0.1:$SLUICE_PORT" \
CULVERT_E2E_SLUICE_FP="$SLUICE_FP" \
CULVERT_E2E_SLUICE_TOKEN="$SLUICE_TOKEN" \
CULVERT_E2E_LDAP_STUB_URL="$LDAP_STUB_URL" \
  npx playwright test --config e2e/playwright.config.ts "$@"
echo "e2e-smoke: PASS"
