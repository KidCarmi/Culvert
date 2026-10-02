#!/usr/bin/env bash
# predecessor-upgrade.sh — EXECUTED upgrade/downgrade qualification of two real
# Culvert release binaries against ONE persisted state root.
#
#   test/appliance/predecessor-upgrade.sh <FROM-binary> <TO-binary> <state-root> [evidence-dir]
#
# Legs (one state root, three boots):
#   A  boot FROM on a FRESH root, complete setup, log in, seed representative
#      state through the admin API, snapshot the root, verify enforcement
#   B  SIGTERM FROM, boot TO on the SAME root, assert the state survived the
#      upgrade and the SAME enforcement decisions hold
#   C  SIGTERM TO, boot FROM again on the SAME root (reverse leg = downgrade
#      tolerance; a failing check here is a FINDING about the predecessor, not
#      a script bug, and is recorded as such)
#
# Every process is started with its PID recorded and stopped by that exact PID.
# Admin-API calls use `--noproxy '*'`; proxied requests clear the *_proxy
# environment (`--noproxy` would also bypass the `-x` proxy under test).
#
# Environment knobs (all optional):
#   PORT_BASE        first of five consecutive TCP ports (default 20200):
#                    proxy, admin UI, allowed origin, parent proxy, unmatched origin
#   CULVERT_CA_PASSPHRASE  CA bundle passphrase (default test-passphrase)
#   ADMIN_PASS       admin password used for setup/login/proxy auth
#
# Exit status: 0 when every assertion passed, 1 otherwise. A machine-readable
# summary is written to <evidence-dir>/summary.json and a Markdown evidence
# report to <evidence-dir>/report.md.
#
# Dependencies: bash 4+, curl, python3 (JSON parsing), sha256sum, find.
set -uo pipefail

usage() {
  echo "usage: $0 <FROM-binary> <TO-binary> <state-root> [evidence-dir]" >&2
  exit 2
}
[ $# -ge 3 ] || usage
FROM_BIN=$(readlink -f "$1")
TO_BIN=$(readlink -f "$2")
ROOT=$3
OUT=${4:-"${ROOT%/}-evidence"}
PORT_BASE=${PORT_BASE:-20200}
PROXY_PORT=$PORT_BASE
UI_PORT=$((PORT_BASE + 1))
ORIGIN_PORT=$((PORT_BASE + 2))
PARENT_PORT=$((PORT_BASE + 3))
ORIGIN2_PORT=$((PORT_BASE + 4))
export CULVERT_CA_PASSPHRASE=${CULVERT_CA_PASSPHRASE:-test-passphrase}
ADMIN_USER="admin"
ADMIN_PASS=${ADMIN_PASS:-'Str0ng-Pilot-Pass!2026'}
PARENT_USER=parentuser
PARENT_PASS='parentpass-Xy9'
# Derived at run time (never a literal, so a secrets scanner has nothing to match);
# the value itself is irrelevant — only its survival across boots is asserted.
WEBHOOK_SECRET="pilot-webhook-signing-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
ALLOWED_HOST=localhost            # destFQDN of the one Allow rule
UNMATCHED_HOST=127.0.0.1          # a second local origin NOT covered by any rule
UI="https://127.0.0.1:$UI_PORT"
PX="http://127.0.0.1:$PROXY_PORT"

[ -x "$FROM_BIN" ] || { echo "FROM binary not executable: $FROM_BIN" >&2; exit 2; }
[ -x "$TO_BIN" ] || { echo "TO binary not executable: $TO_BIN" >&2; exit 2; }
case $ROOT in /*) ;; *) echo "state root must be absolute: $ROOT" >&2; exit 2;; esac
if [ -e "$ROOT" ] && [ -n "$(ls -A "$ROOT" 2>/dev/null)" ]; then
  echo "state root must not exist or must be empty (fresh root required): $ROOT" >&2
  exit 2
fi
mkdir -p "$ROOT" "$OUT"
OUT=$(readlink -f "$OUT")
ROOT=$(readlink -f "$ROOT")
JAR="$OUT/cookies.txt"
TRANSCRIPT="$OUT/transcript.log"
RESULTS="$OUT/results.jsonl"
: > "$TRANSCRIPT"; : > "$RESULTS"

# ── logging / assertions ─────────────────────────────────────────────────────
PHASE=A
FAILS=0
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$TRANSCRIPT"; }
rec() { printf '%s\n' "$*" >> "$TRANSCRIPT"; }
# result <status> <name> <detail>
result() {
  local st=$1 name=$2 detail=$3
  python3 - "$PHASE" "$st" "$name" "$detail" >> "$RESULTS" <<'PY'
import json, sys
print(json.dumps({"phase": sys.argv[1], "status": sys.argv[2], "name": sys.argv[3], "detail": sys.argv[4]}))
PY
  if [ "$st" = FAIL ]; then FAILS=$((FAILS + 1)); fi
  log "[$PHASE] $st  $name — $detail"
}
assert_eq() { # name expected actual
  if [ "$2" = "$3" ]; then result PASS "$1" "got $3"; else result FAIL "$1" "expected $2, got $3"; fi
}

# ── process control ──────────────────────────────────────────────────────────
PIDS=()
CULVERT_PID=""
cleanup() {
  local p
  if [ -n "$CULVERT_PID" ] && kill -0 "$CULVERT_PID" 2>/dev/null; then
    log "cleanup: SIGTERM culvert pid $CULVERT_PID"; kill -TERM "$CULVERT_PID" 2>/dev/null || true
    wait_gone "$CULVERT_PID" 60 || { log "cleanup: SIGKILL culvert pid $CULVERT_PID"; kill -KILL "$CULVERT_PID" 2>/dev/null || true; }
  fi
  for p in "${PIDS[@]:-}"; do
    [ -n "$p" ] || continue
    if kill -0 "$p" 2>/dev/null; then log "cleanup: SIGTERM helper pid $p"; kill -TERM "$p" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT
wait_gone() { # pid timeout-seconds
  local i
  for ((i = 0; i < $2 * 4; i++)); do kill -0 "$1" 2>/dev/null || return 0; sleep 0.25; done
  return 1
}
wait_http() { # url expected-code timeout-seconds
  local i code
  for ((i = 0; i < $3 * 4; i++)); do
    code=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 2 "$1" 2>/dev/null || true)
    [ "$code" = "$2" ] && return 0
    sleep 0.25
  done
  return 1
}

# start_culvert <binary> <label>
start_culvert() {
  local bin=$1 label=$2
  log "boot $label: CULVERT_DATA_DIR=$ROOT $bin -port $PROXY_PORT -ui-port $UI_PORT ... (compose-equivalent path flags)"
  CULVERT_DATA_DIR="$ROOT" "$bin" \
    -port "$PROXY_PORT" -ui-port "$UI_PORT" \
    -ca-path "$ROOT/ca.bundle" -policy "$ROOT/policy.json" \
    -ui-users-file "$ROOT/ui_users.json" -audit-log "$ROOT/audit.jsonl" \
    -request-log "$ROOT/requests.jsonl" -logfile "$ROOT/proxy.log" \
    -revocations-file "$ROOT/revocations.json" -idp-profiles-file "$ROOT/idp_profiles.json" \
    -fileprofiles-file "$ROOT/fileprofiles.json" \
    > "$OUT/culvert-$label.stdout" 2>&1 &
  CULVERT_PID=$!
  log "boot $label: pid $CULVERT_PID"
  if wait_http "http://127.0.0.1:$PROXY_PORT/ready" 200 60; then
    result PASS "$label.ready" "/ready answered 200 (pid $CULVERT_PID)"
  else
    result FAIL "$label.ready" "/ready never answered 200 within 60s (pid $CULVERT_PID); see culvert-$label.stdout"
  fi
}
stop_culvert() { # label
  local label=$1 pid=$CULVERT_PID
  log "stop $label: SIGTERM pid $pid"
  kill -TERM "$pid" 2>/dev/null || true
  if wait_gone "$pid" 60; then
    result PASS "$label.sigterm_exit" "pid $pid exited after SIGTERM"
  else
    kill -KILL "$pid" 2>/dev/null || true
    result FAIL "$label.sigterm_exit" "pid $pid did not exit within 60s of SIGTERM; SIGKILLed"
  fi
  CULVERT_PID=""
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
# api <curl args> : admin API with cookie jar; prints the body; the HTTP status
# is written to a file (api is normally called inside $(...), so a variable
# assignment would not reach the caller) and read back with api_code.
api() {
  local tmp; tmp=$(mktemp)
  curl -sk --noproxy '*' -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' \
    --max-time 15 -o "$tmp" -w '%{http_code}' "$@" > "$OUT/.api_code" 2>/dev/null || echo 000 > "$OUT/.api_code"
  cat "$tmp"; rm -f "$tmp"
}
api_code() { cat "$OUT/.api_code"; }
# through_proxy <label> <curl args> : request THROUGH the Culvert proxy under test;
# full headers+body recorded to $OUT/<phase>-<label>.txt; prints "<code>"
through_proxy() {
  local label=$1; shift
  local f="$OUT/$PHASE-$label.txt" code
  code=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u no_proxy -u NO_PROXY \
          -u ALL_PROXY -u all_proxy \
          curl -s --max-time 10 -x "$PX" -D "$f.hdr" -o "$f.body" -w '%{http_code}' "$@" 2>/dev/null || echo 000)
  { echo "\$ curl -s -x $PX ${*//$ADMIN_PASS/<ADMIN_PASS>}"; cat "$f.hdr" 2>/dev/null; echo; head -c 600 "$f.body" 2>/dev/null; echo; echo "[http_code=$code]"; } > "$f"
  rm -f "$f.hdr" "$f.body"
  rec "--- $PHASE $label"; rec "$(cat "$f")"
  echo "$code"
}
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); $1"; }

# ── helpers that run beside the proxy ────────────────────────────────────────
mkdir -p "$OUT/origin" "$OUT/origin2"
echo "hello-from-allowed-origin" > "$OUT/origin/index.html"
echo "hello-from-unmatched-origin" > "$OUT/origin2/index.html"
cat > "$OUT/parent_proxy.py" <<'PY'
#!/usr/bin/env python3
"""Minimal HTTP forward proxy that REQUIRES Proxy-Authorization: Basic user:pass.
It is the parent for the upstream v2 entry, so a 200 through Culvert proves the
sealed credential was unsealed and sent (X-Parent-Proxy: seen is added)."""
import base64, sys, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
HOST, PORT, USER, PASS = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
EXPECT = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *a):
        sys.stderr.write("parent: " + (fmt % a) + "\n"); sys.stderr.flush()
    def _reply(self, code, body, extra=None):
        self.send_response(code); self.send_header("Content-Type", "text/plain")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.headers.get("Proxy-Authorization", "") != EXPECT:
            self._reply(407, b"parent: proxy auth required\n", {"Proxy-Authenticate": 'Basic realm="parent"'}); return
        if not self.path.startswith("http://"):
            self._reply(400, b"parent: absolute-URI required\n"); return
        try:
            with urllib.request.urlopen(urllib.request.Request(self.path, headers={"User-Agent": "parent-proxy"}), timeout=5) as r:
                data, code = r.read(), r.status
        except urllib.error.HTTPError as e:
            data, code = e.read(), e.code
        except Exception as e:  # noqa: BLE001
            data, code = f"parent: upstream error {e}\n".encode(), 502
        self._reply(code, data, {"X-Parent-Proxy": "seen"})
ThreadingHTTPServer((HOST, PORT), H).serve_forever()
PY
python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 --directory "$OUT/origin" > "$OUT/origin.log" 2>&1 &
PIDS+=("$!"); ORIGIN_PID=$!
python3 -m http.server "$ORIGIN2_PORT" --bind 127.0.0.1 --directory "$OUT/origin2" > "$OUT/origin2.log" 2>&1 &
PIDS+=("$!"); ORIGIN2_PID=$!
python3 "$OUT/parent_proxy.py" 127.0.0.1 "$PARENT_PORT" "$PARENT_USER" "$PARENT_PASS" > "$OUT/parent.log" 2>&1 &
PIDS+=("$!"); PARENT_PID=$!
log "helpers: allowed origin pid $ORIGIN_PID (127.0.0.1:$ORIGIN_PORT), unmatched origin pid $ORIGIN2_PID (127.0.0.1:$ORIGIN2_PORT), parent proxy pid $PARENT_PID (127.0.0.1:$PARENT_PORT)"
wait_http "http://127.0.0.1:$ORIGIN_PORT/" 200 10 || { echo "allowed origin did not start" >&2; exit 2; }
wait_http "http://127.0.0.1:$ORIGIN2_PORT/" 200 10 || { echo "unmatched origin did not start" >&2; exit 2; }

# ── state-root inspection ────────────────────────────────────────────────────
snapshot_root() { # label → writes $OUT/sha-<label>.txt (relative path  sha256)
  (cd "$ROOT" && find . -type f | LC_ALL=C sort | while read -r f; do
     printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "${f#./}"; done) > "$OUT/sha-$1.txt"
  rec "--- sha256 of state root ($1)"; rec "$(cat "$OUT/sha-$1.txt")"
}
file_sha() { [ -f "$ROOT/$1" ] && sha256sum "$ROOT/$1" | cut -d' ' -f1 || echo MISSING; }
quarantine_files() { (cd "$ROOT" && find . \( -name '*.corrupt.*' -o -name '*corrupt*' -o -name '*quarantin*' -o -name '*.poison*' \) | sort); }

# ── per-boot checks shared by legs B and C ───────────────────────────────────
VERSION_A=""; VERSION_B=""; VERSION_C=""
SCHEMA_A=""; CA_SHA_A=""; READY_FAIL_A=""; DIAG_VERDICT_A=""; DIAG_ROWS_A=""
RULE_ID=""; ENTRY_ID=""; WEBHOOK_ID=""
rank() { case $1 in ok) echo 0;; warn) echo 1;; fail) echo 2;; *) echo 3;; esac; }

capture_health() { # label → sets VERSION_<label-ish> via echo; records /ready and /healthz
  local ready healthz
  ready=$(curl -s --noproxy '*' "http://127.0.0.1:$PROXY_PORT/ready")
  healthz=$(curl -sk --noproxy '*' "$UI/healthz")
  rec "--- $PHASE /ready"; rec "$ready"; rec "--- $PHASE /healthz"; rec "$healthz"
  echo "$ready" > "$OUT/$PHASE-ready.json"; echo "$healthz" > "$OUT/$PHASE-healthz.json"
  HEALTHZ_VERSION=$(echo "$healthz" | jq_ 'print(d.get("version",""))')
  READY_VERSION=$(echo "$ready" | jq_ 'print(d.get("version",""))')
  READY_FAILS=$(echo "$ready" | jq_ 'print(" ".join(sorted(k for k,v in d.get("checks",{}).items() if v.get("status")=="fail")))')
}
capture_diag() {
  local diag
  diag=$(api "$UI/api/diagnostics")
  echo "$diag" > "$OUT/$PHASE-diagnostics.json"
  DIAG_VERDICT=$(echo "$diag" | jq_ 'print(d.get("verdict",""))')
  DIAG_ROWS=$(echo "$diag" | jq_ 'print(" ".join(sorted(c["code"]+"="+c["status"] for c in d.get("checks",[]) if c.get("status")!="ok")))')
  rec "--- $PHASE /api/diagnostics verdict=$DIAG_VERDICT non-ok rows: $DIAG_ROWS"
}

enforcement_checks() { # the SAME three decisions on every leg
  local code
  code=$(through_proxy allowed-with-creds -U "$ADMIN_USER:$ADMIN_PASS" "http://$ALLOWED_HOST:$ORIGIN_PORT/")
  assert_eq "enforce.allowed_origin_with_credentials_200" 200 "$code"
  if grep -q '^X-Parent-Proxy: seen' "$OUT/$PHASE-allowed-with-creds.txt"; then
    result PASS "enforce.chained_via_credentialed_parent" "X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent"
  else
    result FAIL "enforce.chained_via_credentialed_parent" "response did not carry X-Parent-Proxy: seen (request did not traverse the credentialed parent)"
  fi
  code=$(through_proxy unmatched-with-creds -U "$ADMIN_USER:$ADMIN_PASS" "http://$UNMATCHED_HOST:$ORIGIN2_PORT/")
  assert_eq "enforce.unmatched_origin_default_deny_403" 403 "$code"
  code=$(through_proxy no-credentials "http://$ALLOWED_HOST:$ORIGIN_PORT/")
  assert_eq "enforce.no_credentials_407" 407 "$code"
}

post_boot_checks() { # label — run after booting a binary on the EXISTING root (legs B and C)
  local label=$1 q body st schema entries cs wh degraded da rules n sha
  q=$(quarantine_files)
  if [ -z "$q" ]; then result PASS "$label.no_quarantine_files" "no *.corrupt.* / quarantine artefacts in the state root"; else result FAIL "$label.no_quarantine_files" "found: $(echo "$q" | tr '\n' ' ')"; fi
  if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$ROOT/admin_settings.json" 2>/dev/null; then
    schema=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("admin_settings_schema",""))' "$ROOT/admin_settings.json")
    result PASS "$label.admin_settings_parses" "admin_settings.json parses (admin_settings_schema=$schema)"
    assert_eq "$label.admin_settings_schema_unchanged" "$SCHEMA_A" "$schema"
  else
    result FAIL "$label.admin_settings_parses" "admin_settings.json does not parse as JSON"
    result FAIL "$label.admin_settings_schema_unchanged" "unreadable"
  fi
  rm -f "$JAR"
  body=$(api -X POST "$UI/api/auth/login" -d "{\"user\":\"$ADMIN_USER\",\"pass\":\"$ADMIN_PASS\"}")
  rec "--- $PHASE POST /api/auth/login → $(api_code) $body"
  assert_eq "$label.login_same_password" 200 "$(api_code)"
  body=$(api "$UI/api/upstream"); rec "--- $PHASE GET /api/upstream → $(api_code) $body"
  entries=$(echo "$body" | jq_ 'print(len(d.get("entries") or []))')
  cs=$(echo "$body" | jq_ 'print(",".join(sorted(e["credentialState"] for e in (d.get("entries") or []))))')
  assert_eq "$label.upstream_entry_present" 1 "$entries"
  assert_eq "$label.upstream_credential_configured" configured "$cs"
  st=$(echo "$body" | jq_ 'print(d.get("key",{}).get("state",""), d.get("mode",""), d.get("migration",{}).get("state",""))')
  result INFO "$label.upstream_key_mode_migration" "key.state/mode/migration.state = $st"
  body=$(api "$UI/api/alerts/webhooks"); rec "--- $PHASE GET /api/alerts/webhooks → $(api_code) $body"
  wh=$(echo "$body" | jq_ 'print(",".join(w["id"] for w in d.get("webhooks") or []))')
  degraded=$(echo "$body" | jq_ 'print(any(w.get("signing_degraded") for w in d.get("webhooks") or []))')
  assert_eq "$label.webhook_still_listed" "$WEBHOOK_ID" "$wh"
  assert_eq "$label.webhook_not_signing_degraded" False "$degraded"
  body=$(api "$UI/api/default-action"); rec "--- $PHASE GET /api/default-action → $(api_code) $body"
  da=$(echo "$body" | jq_ 'print(d.get("defaultAction",""))')
  assert_eq "$label.default_action_deny" deny "$da"
  body=$(api "$UI/api/policy"); rec "--- $PHASE GET /api/policy → $(api_code) $body"
  rules=$(echo "$body" | jq_ 'print(",".join(r["id"]+":"+r["name"]+":"+r["action"] for r in d.get("rules") or []))')
  assert_eq "$label.allow_rule_present" "$RULE_ID:allow-local-origin:Allow" "$rules"
  enforcement_checks
  capture_health
  result INFO "$label.version" "/healthz version=$HEALTHZ_VERSION /ready version=$READY_VERSION"
  n=""
  for f in $READY_FAILS; do case " $READY_FAIL_A " in *" $f "*) ;; *) n="$n $f";; esac; done
  if [ -z "$n" ]; then result PASS "$label.ready_no_new_fail_rows" "fail rows now: [${READY_FAILS:-none}] ⊆ leg A: [${READY_FAIL_A:-none}]"; else result FAIL "$label.ready_no_new_fail_rows" "new fail rows:$n (leg A had: [${READY_FAIL_A:-none}])"; fi
  sha=$(file_sha ca.bundle)
  assert_eq "$label.ca_bundle_sha_unchanged" "$CA_SHA_A" "$sha"
  capture_diag
  if [ "$(rank "$DIAG_VERDICT")" -le "$(rank "$DIAG_VERDICT_A")" ]; then result PASS "$label.diagnostics_verdict_not_worse" "verdict $DIAG_VERDICT (leg A: $DIAG_VERDICT_A)"; else result FAIL "$label.diagnostics_verdict_not_worse" "verdict $DIAG_VERDICT is worse than leg A: $DIAG_VERDICT_A"; fi
  result INFO "$label.diagnostics_non_ok_rows" "now: [${DIAG_ROWS:-none}] ; leg A: [${DIAG_ROWS_A:-none}]"
  body=$(api "$UI/api/config/versions"); rec "--- $PHASE GET /api/config/versions → $(api_code) $body"
  result INFO "$label.config_versions" "$(echo "$body" | jq_ 'print(len(d), "version(s):", [(v["version"], v["action"]) for v in sorted(d, key=lambda v: v["version"])])')"
  body=$(api "$UI/api/audit?limit=8"); rec "--- $PHASE GET /api/audit?limit=8 → $(api_code) $body"
  echo "$body" > "$OUT/$PHASE-audit-tail.json"
}

# ═════════════════════════════════════════════════════════════════════════════
# LEG A — FROM on a fresh root
# ═════════════════════════════════════════════════════════════════════════════
PHASE=A
log "FROM=$FROM_BIN sha256=$(sha256sum "$FROM_BIN" | cut -d' ' -f1)"
log "TO=$TO_BIN sha256=$(sha256sum "$TO_BIN" | cut -d' ' -f1)"
log "state root=$ROOT evidence=$OUT ports: proxy=$PROXY_PORT ui=$UI_PORT origin=$ORIGIN_PORT parent=$PARENT_PORT origin2=$ORIGIN2_PORT"
start_culvert "$FROM_BIN" "A-from"
capture_health; VERSION_A=$HEALTHZ_VERSION
result INFO "A.version" "/healthz version=$HEALTHZ_VERSION /ready version=$READY_VERSION"

body=$(api "$UI/api/setup/status"); rec "--- A GET /api/setup/status → $(api_code) $body"
assert_eq "A.setup_status_needs_setup" true "$(echo "$body" | jq_ 'print(str(d.get("needsSetup")).lower())')"
body=$(api -X POST "$UI/api/setup/complete" -d "{\"user\":\"$ADMIN_USER\",\"pass\":\"$ADMIN_PASS\"}")
rec "--- A POST /api/setup/complete {user,pass} → $(api_code) $body"
assert_eq "A.setup_complete_200" 200 "$(api_code)"
body=$(api -X POST "$UI/api/auth/login" -d "{\"user\":\"$ADMIN_USER\",\"pass\":\"$ADMIN_PASS\"}")
rec "--- A POST /api/auth/login → $(api_code) $body"
assert_eq "A.login_200" 200 "$(api_code)"

# seed: explicit default-deny
body=$(api -X POST "$UI/api/default-action" -d '{"action":"deny"}'); rec "--- A POST /api/default-action {\"action\":\"deny\"} → $(api_code) $body"
assert_eq "A.default_action_set_deny" deny "$(echo "$body" | jq_ 'print(d.get("defaultAction",""))')"
# seed: one Allow rule for the local origin (action values are capitalised: Allow|Drop|Block_Page|Redirect)
body=$(api -X POST "$UI/api/policy" -d "{\"name\":\"allow-local-origin\",\"priority\":10,\"destFQDN\":\"$ALLOWED_HOST\",\"action\":\"Allow\",\"enabled\":true}")
rec "--- A POST /api/policy → $(api_code) $body"
RULE_ID=$(echo "$body" | jq_ 'print(d.get("id",""))' 2>/dev/null || true)
if [ "$(api_code)" = 200 ] && [ -n "$RULE_ID" ]; then result PASS "A.allow_rule_created" "id=$RULE_ID destFQDN=$ALLOWED_HOST action=Allow"; else result FAIL "A.allow_rule_created" "HTTP $(api_code): $body"; fi
# seed: upstream v2 entry (document revision 1 on a never-persisted document) + sealed credential (entry revision 1)
body=$(api -X POST "$UI/api/upstream/entries" -d "{\"scheme\":\"http\",\"host\":\"127.0.0.1\",\"port\":$PARENT_PORT,\"username\":\"$PARENT_USER\",\"revision\":1}")
rec "--- A POST /api/upstream/entries → $(api_code) $(echo "$body" | head -c 400)…"
ENTRY_ID=$(echo "$body" | jq_ 'print(d.get("entry",{}).get("id",""))' 2>/dev/null || true)
ENTRY_REV=$(echo "$body" | jq_ 'print(d.get("entry",{}).get("revision",""))' 2>/dev/null || true)
if [ "$(api_code)" = 201 ] && [ -n "$ENTRY_ID" ]; then result PASS "A.upstream_entry_created" "id=$ENTRY_ID authority=http://$PARENT_USER@127.0.0.1:$PARENT_PORT revision=$ENTRY_REV"; else result FAIL "A.upstream_entry_created" "HTTP $(api_code): $body"; fi
body=$(api -X POST "$UI/api/upstream/entries/$ENTRY_ID/credential" -d "{\"action\":\"replace\",\"password\":\"$PARENT_PASS\",\"revision\":${ENTRY_REV:-1}}")
rec "--- A POST /api/upstream/entries/$ENTRY_ID/credential {action:replace,password:<redacted>,revision:$ENTRY_REV} → $(api_code) $(echo "$body" | head -c 400)…"
cs=$(echo "$body" | jq_ 'print(d.get("entry",{}).get("credentialState",""))' 2>/dev/null || true)
assert_eq "A.upstream_credential_sealed" configured "$cs"
body=$(api "$UI/api/upstream"); rec "--- A GET /api/upstream → $(api_code) $body"
result INFO "A.upstream_health" "$(echo "$body" | jq_ 'e=(d.get("entries") or [{}])[0]; print("health=",e.get("health"),"eligible=",e.get("eligible"),"mode=",d.get("mode"),"key=",d.get("key"))')"
# seed: alert webhook with a signing secret
body=$(api -X POST "$UI/api/alerts/webhooks" -d "{\"name\":\"pilot-siem\",\"url\":\"https://siem.example.invalid/culvert-hook\",\"events\":[\"cert_expiry\",\"storage_write_failed\"],\"enabled\":true,\"secret\":\"$WEBHOOK_SECRET\"}")
rec "--- A POST /api/alerts/webhooks {…,secret:<redacted>} → $(api_code) $body"
WEBHOOK_ID=$(echo "$body" | jq_ 'print(d.get("id",""))' 2>/dev/null || true)
if [ "$(api_code)" = 200 ] && [ -n "$WEBHOOK_ID" ]; then result PASS "A.webhook_created" "id=$WEBHOOK_ID"; else result FAIL "A.webhook_created" "HTTP $(api_code): $body"; fi
body=$(api "$UI/api/alerts/webhooks"); rec "--- A GET /api/alerts/webhooks → $(api_code) $body"
assert_eq "A.webhook_not_signing_degraded" False "$(echo "$body" | jq_ 'print(any(w.get("signing_degraded") for w in d.get("webhooks") or []))')"
# auto-created config version snapshot
body=$(api "$UI/api/config/versions"); rec "--- A GET /api/config/versions → $(api_code) $body"
nver=$(echo "$body" | jq_ 'print(len(d))')
if [ "${nver:-0}" -ge 1 ]; then result PASS "A.config_version_autocreated" "$nver version(s): $(echo "$body" | jq_ 'print([v["action"] for v in d])')"; else result FAIL "A.config_version_autocreated" "no config versions listed"; fi

# baseline captured AFTER seeding
SCHEMA_A=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("admin_settings_schema",""))' "$ROOT/admin_settings.json" 2>/dev/null || echo UNREADABLE)
result INFO "A.admin_settings_schema" "admin_settings_schema=$SCHEMA_A keys=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$ROOT/admin_settings.json")"
CA_SHA_A=$(file_sha ca.bundle); result INFO "A.ca_bundle_sha" "$CA_SHA_A"
enforcement_checks
capture_health; READY_FAIL_A=$READY_FAILS
result INFO "A.ready_fail_rows" "[${READY_FAIL_A:-none}]"
capture_diag; DIAG_VERDICT_A=$DIAG_VERDICT; DIAG_ROWS_A=$DIAG_ROWS
result INFO "A.diagnostics" "verdict=$DIAG_VERDICT_A non-ok rows: [${DIAG_ROWS_A:-none}]"
body=$(api "$UI/api/audit?limit=12"); rec "--- A GET /api/audit?limit=12 → $(api_code) $body"; echo "$body" > "$OUT/A-audit-tail.json"
stop_culvert "A-from"
snapshot_root A
q=$(quarantine_files); if [ -z "$q" ]; then result PASS "A.no_quarantine_files" "clean after FROM shutdown"; else result FAIL "A.no_quarantine_files" "found: $q"; fi
tail -n 12 "$ROOT/audit.jsonl" > "$OUT/A-audit.jsonl.tail"; rec "--- A tail -n 12 audit.jsonl"; rec "$(cat "$OUT/A-audit.jsonl.tail")"

# ═════════════════════════════════════════════════════════════════════════════
# LEG B — TO on the SAME root (upgrade)
# ═════════════════════════════════════════════════════════════════════════════
PHASE=B
start_culvert "$TO_BIN" "B-to"
post_boot_checks B; VERSION_B=$HEALTHZ_VERSION
stop_culvert "B-to"
snapshot_root B

# ═════════════════════════════════════════════════════════════════════════════
# LEG C — FROM again on the SAME root (downgrade tolerance; failures are findings)
# ═════════════════════════════════════════════════════════════════════════════
PHASE=C
start_culvert "$FROM_BIN" "C-from-again"
post_boot_checks C; VERSION_C=$HEALTHZ_VERSION
stop_culvert "C-from-again"
snapshot_root C
cleanup; trap - EXIT

# ═════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
python3 - "$RESULTS" "$OUT" "$ROOT" "$FROM_BIN" "$TO_BIN" "$VERSION_A" "$VERSION_B" "$VERSION_C" "$PROXY_PORT" "$UI_PORT" "$ORIGIN_PORT" "$PARENT_PORT" "$ORIGIN2_PORT" <<'PY'
import hashlib, json, os, sys
res_path, out, root, frm, to, va, vb, vc = sys.argv[1:9]
ports = dict(zip(["proxy", "ui", "allowed_origin", "parent_proxy", "unmatched_origin"], map(int, sys.argv[9:14])))
rows = [json.loads(l) for l in open(res_path) if l.strip()]
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()
def shatab(label):
    p = os.path.join(out, f"sha-{label}.txt")
    return dict(l.split("  ", 1)[::-1] for l in open(p).read().splitlines() if "  " in l)
A, B, C = shatab("A"), shatab("B"), shatab("C")
fails = [r for r in rows if r["status"] == "FAIL"]
summary = {
    "from": {"binary": frm, "sha256": sha(frm), "version": va},
    "to": {"binary": to, "sha256": sha(to), "version": vb},
    "reverse_from_version": vc,
    "state_root": root, "ports": ports,
    "legs": {ph: {"pass": sum(1 for r in rows if r["phase"] == ph and r["status"] == "PASS"),
                  "fail": sum(1 for r in rows if r["phase"] == ph and r["status"] == "FAIL")} for ph in "ABC"},
    "verdict": "PASS" if not fails else "FAIL",
    "failures": fails, "results": rows,
    "state_files": {f: {"after_from": A.get(f), "after_to": B.get(f), "after_reverse": C.get(f),
                        "changed_by_upgrade": A.get(f) != B.get(f), "changed_by_downgrade": B.get(f) != C.get(f)}
                    for f in sorted(set(A) | set(B) | set(C))},
}
json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=2)
w = max(len(r["name"]) for r in rows) + 2
print()
print(f"{'LEG':<4}{'STATUS':<7}{'CHECK':<{w}}DETAIL")
for r in rows:
    print(f"{r['phase']:<4}{r['status']:<7}{r['name']:<{w}}{r['detail'][:120]}")
print()
print(f"FROM {va} ({os.path.basename(frm)})  →  TO {vb} ({os.path.basename(to)})  →  FROM again {vc}")
print("legs:", json.dumps(summary["legs"]), " verdict:", summary["verdict"])
# Markdown evidence report
md = [f"# Predecessor upgrade qualification — {va} → {vb} → {va}", "",
      f"- state root: `{root}`", f"- FROM: `{frm}` sha256 `{summary['from']['sha256']}` (reports `{va}`)",
      f"- TO: `{to}` sha256 `{summary['to']['sha256']}` (reports `{vb}`)",
      f"- ports: {json.dumps(ports)}", f"- verdict: **{summary['verdict']}** ({len(fails)} failing assertion(s))", "",
      "## Assertions", "", "| leg | status | check | detail |", "|---|---|---|---|"]
for r in rows:
    det = r["detail"].replace("|", "\\|")
    md.append(f"| {r['phase']} | {r['status']} | `{r['name']}` | {det} |")
md += ["", "## State-root sha256 (after leg A / after leg B / after leg C)", "", "| file | after FROM | after TO | after FROM-again | upgrade | downgrade |", "|---|---|---|---|---|---|"]
for f, v in summary["state_files"].items():
    s = lambda x: (x or "—")[:16]
    md.append(f"| `{f}` | `{s(v['after_from'])}` | `{s(v['after_to'])}` | `{s(v['after_reverse'])}` | {'changed' if v['changed_by_upgrade'] else 'same'} | {'changed' if v['changed_by_downgrade'] else 'same'} |")
open(os.path.join(out, "report.md"), "w").write("\n".join(md) + "\n")
sys.exit(1 if fails else 0)
PY
rc=$?
log "summary: $OUT/summary.json  report: $OUT/report.md  transcript: $TRANSCRIPT"
exit $rc
