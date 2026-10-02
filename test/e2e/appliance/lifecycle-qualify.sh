#!/usr/bin/env bash
# test/e2e/appliance/lifecycle-qualify.sh — appliance lifecycle qualification
# against REAL images on the REAL compose topology (named volume mounted at
# /data, the deploy bundle's own docker-compose.yml, the cli service for
# backup/restore). Produces an evidence file (markdown + JSONL) that names
# the exact image digests every check ran against.
#
# Scenarios (each in its own compose project + volume, run sequentially):
#   A  fresh install on CUR_IMAGE → setup → policy → ACTUAL allow/block →
#      restart → state + readiness preserved
#   B  for each PRED in PRED_IMAGES: install PRED, seed state, retag to
#      CUR_IMAGE, up → boot, login, rules, posture, enforcement preserved
#   C  newer state on the older binary (PRED over CUR's state) — recorded,
#      informational (downgrade is unsupported; the harness records what
#      actually happens)
#   D  backup (cli, encrypted) → mutate → offline restore --confirm on the
#      mounted volume → boot → state verified; plus: a commit against the
#      RUNNING stack is refused (data-dir lock)
#   E  interrupted restore (journal present) → proxy refuses to boot →
#      --recover-restore --confirm complete → boot → state verified
#
# Requirements: docker + compose v2, root or docker group, the images
# present locally (or pullable), ports 8080/9090 free on the host.
#
#   CUR_IMAGE=culvert/proxy:dev-local PRED_IMAGES="ghcr.io/kidcarmi/culvert:v1.0.259" \
#     EVID=/tmp/evidence ./test/e2e/appliance/lifecycle-qualify.sh
set -euo pipefail

CUR_IMAGE="${CUR_IMAGE:?set CUR_IMAGE to the image under qualification}"
PRED_IMAGES="${PRED_IMAGES:-ghcr.io/kidcarmi/culvert:v1.0.259}"
EVID="${EVID:-$PWD/appliance-evidence}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PINNED="culvert/proxy:pinned"
ADMIN_USER="qualadmin"
ADMIN_PASS="Appliance-Qual-2026!x"
CA_PASS="qual-ca-passphrase-0123456789"
BK_PASS="qual-backup-passphrase-0123456789"
PROXY="http://127.0.0.1:8080"
UI="https://127.0.0.1:9090"
mkdir -p "$EVID"
JSONL="$EVID/checks.jsonl"; MD="$EVID/REPORT.md"; : > "$JSONL"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
FAILS=0

log()  { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
digest_of() { docker image inspect --format '{{index .RepoDigests 0}}|{{.Id}}' "$1" 2>/dev/null || echo "unknown|unknown"; }
check() { # check <scenario> <name> <pass|fail|blocked> <detail>
  local sc="$1" name="$2" res="$3" detail="${4:-}"
  printf '{"run":"%s","scenario":"%s","check":"%s","result":"%s","detail":%s,"cur_image":"%s","cur_digest":"%s"}\n' \
    "$RUN_ID" "$sc" "$name" "$res" "$(printf '%s' "$detail" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')" \
    "$CUR_IMAGE" "$(digest_of "$CUR_IMAGE")" >> "$JSONL"
  if [[ "$res" == fail ]]; then FAILS=$((FAILS+1)); log "FAIL [$sc] $name: $detail"; else log "$res [$sc] $name: $detail"; fi
}
expect() { # expect <scenario> <name> <condition-cmd...>
  local sc="$1" name="$2"; shift 2
  if out="$("$@" 2>&1)"; then check "$sc" "$name" pass "$out"; else check "$sc" "$name" fail "$out"; fi
}

# ── compose project helpers ──────────────────────────────────────────────────
PROJ=""; PDIR=""
newproj() { # newproj <name> <image-for-pinned>
  local safe; safe="$(echo "$1" | tr -c 'a-z0-9-\n' '-')"
  PROJ="aq-$safe"; PDIR="$EVID/proj-$safe"; rm -rf "$PDIR"; mkdir -p "$PDIR"
  # The deploy bundle's compose file from the image under qualification —
  # exactly what scripts/install.sh extracts on a real host.
  local cid; cid="$(docker create "$CUR_IMAGE")"
  docker cp "$cid:/app/deploy/docker-compose.yml" "$PDIR/docker-compose.yml" >/dev/null
  docker rm -f "$cid" >/dev/null
  cp "$HERE/docker-compose.qualify.yml" "$PDIR/docker-compose.override.yml"
  printf 'CULVERT_CA_PASSPHRASE=%s\nCULVERT_LOG_PASSPHRASE=%s\nCULVERT_DEFAULT_ACTION=%s\n' "$CA_PASS" "$CA_PASS" "${QUAL_DEFAULT_ACTION:-}" > "$PDIR/.env"
  chmod 600 "$PDIR/.env"
  docker tag "$2" "$PINNED"
  # Cookie jar lives with the project; set in the PARENT shell so helpers
  # invoked inside $(...) command substitutions (subshells) still find it.
  JAR="$PDIR/jar"; : > "$JAR"
  export PROJ PDIR JAR
}
dc() { docker compose -p "$PROJ" --project-directory "$PDIR" -f "$PDIR/docker-compose.yml" -f "$PDIR/docker-compose.override.yml" "$@"; }
dcli() { dc --profile cli run --rm -T -e CULVERT_BACKUP_PASSPHRASE="$BK_PASS" cli "$@"; }
up() { dc up -d --remove-orphans >/dev/null 2>&1 || true; wait_health; }
down() { dc down --remove-orphans >/dev/null 2>&1 || true; }
destroy() { dc down -v --remove-orphans >/dev/null 2>&1 || true; }
wait_health() {
  for _ in $(seq 1 60); do
    if curl -fsS -m 3 "$PROXY/health" >/dev/null 2>&1; then return 0; fi; sleep 2
  done
  return 1
}
proxy_exited() { # true when the proxy container is not running (e.g. FATAL at boot)
  local st; st="$(docker inspect --format '{{.State.Status}}' culvert 2>/dev/null || echo missing)"; [[ "$st" != running ]]
}
vol() { echo "${PROJ}_proxy-data"; }
onvol() { docker run --rm -v "$(vol):/data" alpine:3.20 sh -c "$1"; }

# ── admin API helpers (self-signed UI, same-origin CSRF) ──────────────────────
JAR=""
api() { # api <method> <path> [json]
  local m="$1" p="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -ksS -m 20 -X "$m" "$UI$p" -H "Origin: $UI" -H 'Content-Type: application/json' -b "$JAR" -c "$JAR" -d "$body" -w '\n%{http_code}'
  else
    curl -ksS -m 20 -X "$m" "$UI$p" -H "Origin: $UI" -b "$JAR" -c "$JAR" -w '\n%{http_code}'
  fi
}
code_of() { tail -n1; }
body_of() { sed '$d'; }
setup_admin() { : > "$JAR"; api POST /api/setup/complete "{\"user\":\"$ADMIN_USER\",\"pass\":\"$ADMIN_PASS\"}" | code_of; }
login() { : > "$JAR"; api POST /api/auth/login "{\"user\":\"$1\",\"pass\":\"$2\"}" | code_of; }
# Pilot posture: proxy clients are NOT authenticated (policy by destination).
# Once a credentialed admin exists the proxy demands credentials from every
# client by default (defaultAuthOutcome=Default ⇒ 407), so the operator must
# choose the Exempt default explicitly — recorded in first-boot.md step 8.
proxy_auth_exempt() { api PUT /api/settings/default-auth-outcome '{"defaultAuthOutcome":"Exempt"}' | code_of; }
seed_policy() {
  local c1 c2 c3
  c1="$(proxy_auth_exempt)"
  c2="$(api POST /api/default-action '{"action":"deny"}' | code_of)"
  c3="$(api POST /api/policy '{"name":"qual-allow-origin","priority":10,"action":"Allow","destFQDN":"origin-allowed","sslAction":"Bypass","enabled":true}' | code_of)"
  log "seed_policy: auth-exempt=$c1 default-action=$c2 rule=$c3"
}
through_proxy() { curl -sS -m 10 -x "$PROXY" -o /dev/null -w '%{http_code}' "http://$1/" 2>/dev/null || echo 000; }
assert_enforcement() { # <scenario> <label>
  local a b; a="$(through_proxy origin-allowed)"; b="$(through_proxy origin-blocked)"
  if [[ "$a" == 200 && "$b" != 200 && "$b" != 000 ]]; then check "$1" "enforcement:$2" pass "allowed=$a blocked=$b"; else check "$1" "enforcement:$2" fail "allowed=$a blocked=$b"; fi
}
# The stubbed ClamAV sidecar (docker-compose.qualify.yml) makes the gating
# `clamav` row fail by design here, so /ready (and ?strict=1) answer 503 in
# this harness regardless of the rows under test. Assert the rows this work
# introduced, and that clamav is the ONLY failing row — the real-sidecar run
# (CULVERT_QUALIFY_REAL_CLAMAV=1) asserts the full 200.
strict_ready() {
  curl -ksS "$PROXY/ready?strict=1" | python3 -c 'import json,sys,os
d=json.load(sys.stdin); c=d["checks"]; bad=[k for k,v in c.items() if v.get("status")!="ok"]
real=os.environ.get("CULVERT_QUALIFY_REAL_CLAMAV")=="1"
assert c["setup_complete"]["status"]=="ok", c["setup_complete"]; assert c["policy_posture"]["status"]=="ok", c["policy_posture"]; assert c["policy_loaded"]["status"]=="ok", c["policy_loaded"]
assert bad==([] if real else ["clamav"]), bad
print("rows ok; failing=%s (clamav stub)" % bad)'
}
ready_rows() { curl -ksS -m 5 "$PROXY/ready" 2>/dev/null | python3 -c 'import json,sys
try:
  d=json.load(sys.stdin); c=d.get("checks",{})
  print(",".join(f"{k}={v.get(\"status\")}" for k,v in sorted(c.items()) if k in ("setup_complete","policy_posture","session_secret","clamav","policy_loaded")))
except Exception as e: print("unparseable")'; }
version_of() { curl -fsS -m 5 "$PROXY/health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version",""))'; }
rule_present() { api GET /api/policy | body_of | python3 -c 'import json,sys
d=json.load(sys.stdin); rules=d if isinstance(d,list) else d.get("rules",d.get("items",[]))
print("yes" if any(r.get("name")=="qual-allow-origin" for r in rules) else "no")'; }
default_action() { api GET /api/default-action | body_of | python3 -c 'import json,sys; print(json.load(sys.stdin).get("defaultAction",""))'; }

export -f api code_of body_of login strict_ready proxy_auth_exempt rule_present default_action through_proxy dcli dc onvol vol version_of
export PROJ PDIR JAR BK_PASS PROXY UI ADMIN_USER ADMIN_PASS

# ── header ───────────────────────────────────────────────────────────────────
{
  echo "# Appliance lifecycle qualification — run $RUN_ID"
  echo
  echo "| artifact | reference | digest / image id |"; echo "|---|---|---|"
  echo "| image under qualification | \`$CUR_IMAGE\` | \`$(digest_of "$CUR_IMAGE")\` |"
  for p in $PRED_IMAGES; do echo "| predecessor | \`$p\` | \`$(digest_of "$p")\` |"; done
  echo "| docker | $(docker version --format '{{.Server.Version}}') | compose $(docker compose version --short) |"
  echo "| host | $(uname -sr) | $(nproc) cpu |"
  echo
} > "$MD"

# ═══ A. fresh install on CUR ═════════════════════════════════════════════════
scA() {
  local sc=A; log "=== $sc fresh install on $CUR_IMAGE"
  QUAL_DEFAULT_ACTION=deny newproj a "$CUR_IMAGE"
  if up; then check $sc boot pass "version=$(version_of)"; else check $sc boot fail "proxy did not answer /health"; destroy; return; fi
  expect $sc "ready-before-setup" bash -c 'r="$(curl -ksS '"$PROXY"'/ready)"; echo "$r" | grep -q "setup_complete" && echo "$r" | python3 -c "import json,sys; d=json.load(sys.stdin); c=d[\"checks\"]; assert c[\"setup_complete\"][\"status\"]==\"fail\", c; assert c[\"policy_posture\"][\"detail\"]==\"default-deny\", c; print(\"setup_complete=fail policy_posture=default-deny (CULVERT_DEFAULT_ACTION=deny)\")"'
  local c; c="$(setup_admin)"; [[ "$c" == 200 ]] && check $sc setup pass "http $c" || check $sc setup fail "http $c"
  c="$(login "$ADMIN_USER" "$ADMIN_PASS")"; [[ "$c" == 200 ]] && check $sc login pass "http $c" || check $sc login fail "http $c"
  seed_policy >/dev/null
  assert_enforcement $sc after-setup
  expect $sc "ready-after-setup" bash -c 'echo "$(curl -ksS '"$PROXY"'/ready)" | python3 -c "import json,sys; d=json.load(sys.stdin); c=d[\"checks\"]; assert c[\"setup_complete\"][\"status\"]==\"ok\", c; assert c[\"policy_posture\"][\"status\"]==\"ok\", c; print(\"setup_complete=ok policy_posture=\"+c[\"policy_posture\"][\"detail\"])"'
  expect $sc "strict-ready" strict_ready
  # Restart: identity, roster, policy, posture survive.
  dc restart proxy >/dev/null 2>&1; wait_health || true
  c="$(login "$ADMIN_USER" "$ADMIN_PASS")"; [[ "$c" == 200 ]] && check $sc login-after-restart pass "http $c" || check $sc login-after-restart fail "http $c"
  expect $sc rules-after-restart bash -c '[[ "$(rule_present)" == yes ]] && echo present'
  expect $sc default-action-after-restart bash -c '[[ "$(default_action)" == deny ]] && echo deny'
  assert_enforcement $sc after-restart
  # No shared secret: the session key is per-process unless configured; the
  # CA passphrase is per-install (.env), the admin was created by the operator.
  expect $sc "no-default-admin-credential" bash -c '! grep -rqi "CULVERT_ADMIN\|changeme" "'"$PDIR"'/docker-compose.yml" && echo "compose carries no admin credential"'
  destroy
}

# ═══ B/C. real predecessor → CUR, then CUR state under PRED ══════════════════
scB() {
  local pred="$1"; local tag="${1##*:}"; local sc="B:$tag"; log "=== $sc predecessor $pred → $CUR_IMAGE"
  QUAL_DEFAULT_ACTION="" newproj "b-$tag" "$pred"
  if up; then check "$sc" boot-predecessor pass "version=$(version_of)"; else check "$sc" boot-predecessor fail "predecessor did not answer /health"; destroy; return; fi
  local c; c="$(setup_admin)"; [[ "$c" == 200 ]] && check "$sc" setup pass "http $c" || check "$sc" setup fail "http $c"
  login "$ADMIN_USER" "$ADMIN_PASS" >/dev/null; seed_policy >/dev/null
  assert_enforcement "$sc" predecessor
  # Make the predecessor persist its admin settings (default action) the way
  # a real install does, then stop it cleanly.
  dc stop proxy >/dev/null 2>&1
  local pred_vol_list; pred_vol_list="$(onvol 'ls -1 /data | tr "\n" " "')"
  check "$sc" predecessor-state-files pass "$pred_vol_list"
  # ── upgrade: retag the pinned tag to CUR and recreate (what the agent does) ──
  docker tag "$CUR_IMAGE" "$PINNED"
  if up; then check "$sc" boot-after-upgrade pass "version=$(version_of)"; else check "$sc" boot-after-upgrade fail "CUR did not answer /health on predecessor state: $(docker logs culvert 2>&1 | tail -5)"; destroy; return; fi
  c="$(login "$ADMIN_USER" "$ADMIN_PASS")"; [[ "$c" == 200 ]] && check "$sc" login-after-upgrade pass "http $c" || check "$sc" login-after-upgrade fail "http $c"
  expect "$sc" rules-after-upgrade bash -c '[[ "$(rule_present)" == yes ]] && echo present'
  expect "$sc" default-action-after-upgrade bash -c '[[ "$(default_action)" == deny ]] && echo deny'
  assert_enforcement "$sc" after-upgrade
  expect "$sc" ready-after-upgrade bash -c 'echo "$(curl -ksS '"$PROXY"'/ready)" | python3 -c "import json,sys; d=json.load(sys.stdin); c=d[\"checks\"]; assert c[\"setup_complete\"][\"status\"]==\"ok\", c; assert c[\"policy_posture\"][\"status\"]==\"ok\", c; print(\"ok\")"'
  expect "$sc" no-unexpected-errors bash -c 'docker logs culvert 2>&1 | grep -iE "panic|FATAL|corrupt|quarantin" | grep -v "panic recovery\|panic guard\|panicking" | head -3 | grep -q . && exit 1; echo "no panic/FATAL/corrupt lines in proxy log"'
  # ── C: newer state under the OLDER binary (informational) ──────────────────
  local scC="C:$tag"
  dc stop proxy >/dev/null 2>&1; docker tag "$pred" "$PINNED"
  if up; then
    c="$(login "$ADMIN_USER" "$ADMIN_PASS")"
    local rp da; rp="$(rule_present 2>/dev/null || echo err)"; da="$(default_action 2>/dev/null || echo err)"
    check "$scC" older-binary-on-newer-state pass "boots; login=$c rules=$rp default=$da (informational — downgrade is unsupported; restore-from-backup is the supported way back)"
    expect "$scC" older-binary-warnings bash -c 'docker logs culvert 2>&1 | grep -iE "newer|unsupported|degraded|rejected|ignor" | head -5; true'
  else
    check "$scC" older-binary-on-newer-state pass "does NOT boot on newer state (informational): $(docker logs culvert 2>&1 | tail -3)"
  fi
  destroy
}

# ═══ D. backup / restore on the mounted volume ═══════════════════════════════
scD() {
  local sc=D; log "=== $sc backup + offline restore on the real volume"
  QUAL_DEFAULT_ACTION=deny newproj d "$CUR_IMAGE"
  up || { check $sc boot fail "no /health"; destroy; return; }
  setup_admin >/dev/null; login "$ADMIN_USER" "$ADMIN_PASS" >/dev/null; seed_policy >/dev/null
  # Backup while running (runtime-OK by contract).
  local out; out="$(dcli --encrypt --backup /backup/qual.tar.gz.enc 2>&1 || true)"
  if echo "$out" | grep -q "Backup written"; then check $sc backup pass "$(echo "$out" | tail -1)"; else check $sc backup fail "$out"; fi
  # Mutate AFTER the backup: a second admin that the restore must remove.
  api POST /api/auth/users '{"username":"laterjoiner","password":"Later-Joiner-2026!x","role":"admin"}' | code_of >/dev/null
  expect $sc mutation-visible bash -c '[[ "$(login laterjoiner "Later-Joiner-2026!x")" == 200 ]] && echo "laterjoiner can log in before restore"'
  # Commit against the RUNNING stack must be refused (data-dir lock).
  out="$(dcli --restore /backup/qual.tar.gz.enc --confirm --mode full --accept-dp-reenrollment 2>&1 || true)"
  if echo "$out" | grep -q "locked by another Culvert process"; then check $sc commit-refused-while-running pass "lock held by the proxy"; else check $sc commit-refused-while-running fail "$out"; fi
  # Dry-run is fine while running.
  out="$(dcli --restore /backup/qual.tar.gz.enc --mode full 2>&1 || true)"
  if echo "$out" | grep -qiE "ca.bundle decrypt: *PASS"; then check $sc dry-run pass "validation passed incl. encrypted ca.bundle"; else check $sc dry-run fail "$out"; fi
  # Offline commit.
  down
  out="$(dcli --restore /backup/qual.tar.gz.enc --confirm --mode full --accept-dp-reenrollment 2>&1 || true)"
  if echo "$out" | grep -q "Restore committed"; then check $sc commit pass "$(echo "$out" | grep -E 'preserved at' | head -1)"; else check $sc commit fail "$out"; fi
  expect $sc bak-inside-volume bash -c "$(declare -f onvol vol); PROJ=$PROJ; onvol 'ls -1d /data/.restore-bak.* 2>/dev/null | head -1' | grep -q restore-bak && echo 'previous data preserved inside the volume'"
  up || { check $sc boot-after-restore fail "no /health after restore: $(docker logs culvert 2>&1 | tail -5)"; destroy; return; }
  check $sc boot-after-restore pass "version=$(version_of)"
  expect $sc original-admin-restored bash -c '[[ "$(login "'"$ADMIN_USER"'" "'"$ADMIN_PASS"'")" == 200 ]] && echo "original admin logs in"'
  expect $sc later-mutation-rolled-back bash -c '[[ "$(login laterjoiner "Later-Joiner-2026!x")" != 200 ]] && echo "post-backup account is gone"'
  login "$ADMIN_USER" "$ADMIN_PASS" >/dev/null
  expect $sc rules-restored bash -c '[[ "$(rule_present)" == yes ]] && echo present'
  assert_enforcement $sc after-restore
  expect $sc ssl-inspection-ready bash -c 'curl -fsS '"$PROXY"'/health | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"ssl_inspection\"]==\"ready\", d; print(\"ssl_inspection=ready (restored ca.bundle decrypts under the install passphrase)\")"'
  # Leftover inventory + cleanup round trip.
  expect $sc leftovers-listed bash -c "$(declare -f dcli dc); PROJ=$PROJ; PDIR=$PDIR; BK_PASS=$BK_PASS; dcli --list-restore-leftovers 2>&1 | grep -q 'restore-bak' && echo listed"
  expect $sc leftovers-cleaned bash -c "$(declare -f dcli dc); PROJ=$PROJ; PDIR=$PDIR; BK_PASS=$BK_PASS; dcli --cleanup-restore-leftovers --confirm 2>&1 | grep -q 'DELETED' && echo deleted"
  destroy
}

# ═══ E. interrupted restore → refuse boot → explicit recovery ═══════════════
scE() {
  local sc=E; log "=== $sc interrupted restore recovery"
  QUAL_DEFAULT_ACTION=deny newproj e "$CUR_IMAGE"
  up || { check $sc boot fail "no /health"; destroy; return; }
  setup_admin >/dev/null; login "$ADMIN_USER" "$ADMIN_PASS" >/dev/null; seed_policy >/dev/null
  down
  # Craft the exact on-disk state of a commit killed in phase "promoting":
  # every previous entry evacuated, staged restore partially promoted.
  local S="20260102T030405Z-4242"
  onvol 'set -e; cd /data; mkdir .restore-bak.'"$S"' .restore-staging.'"$S"'; for e in *; do case "$e" in .restore-*) ;; *) mv "$e" .restore-bak.'"$S"'/;; esac; done; cp -a .restore-bak.'"$S"'/. .restore-staging.'"$S"'/; echo restored > .restore-staging.'"$S"'/qual-restored.marker; mv .restore-staging.'"$S"'/ui_users.json ./ui_users.json; printf "%s" "{\"version\":1,\"suffix\":\"'"$S"'\",\"phase\":\"promoting\",\"staging_dir\":\".restore-staging.'"$S"'\",\"bak_dir\":\".restore-bak.'"$S"'\",\"mode\":\"full\",\"started_at\":\"2026-01-02T03:04:05Z\",\"updated_at\":\"2026-01-02T03:04:06Z\"}" > .restore-journal.json; chown -R "$(stat -c %u:%g /data)" /data/.restore-*'
  dc up -d >/dev/null 2>&1 || true
  # restart: unless-stopped turns the FATAL into a restart loop; the container
  # is never "running" with a serving proxy. Observe over a few seconds.
  refused=no
  for _ in $(seq 1 15); do
    sleep 2
    if docker logs culvert 2>&1 | grep -q "interrupted restore detected" && ! curl -fsS -m 2 "$PROXY/health" >/dev/null 2>&1; then refused=yes; break; fi
  done
  if [[ "$refused" == yes ]]; then check $sc boot-refused pass "status=$(docker inspect --format '{{.State.Status}}' culvert 2>/dev/null): $(docker logs culvert 2>&1 | grep -o 'interrupted restore detected[^(]*' | head -1)"; else check $sc boot-refused fail "status=$(docker inspect --format '{{.State.Status}}' culvert 2>/dev/null) logs=$(docker logs culvert 2>&1 | tail -3)"; fi
  down
  local out; out="$(dcli --recover-restore 2>&1 || true)"
  if echo "$out" | grep -q "Phase:.*promoting"; then check $sc inspect pass "$(echo "$out" | grep Phase)"; else check $sc inspect fail "$out"; fi
  out="$(dcli --recover-restore --confirm=complete 2>&1 || true)"
  if echo "$out" | grep -q "Restore COMPLETED"; then check $sc recover-complete pass "completed"; else check $sc recover-complete fail "$out"; fi
  up || { check $sc boot-after-recovery fail "$(docker logs culvert 2>&1 | tail -5)"; destroy; return; }
  check $sc boot-after-recovery pass "version=$(version_of)"
  expect $sc marker-landed bash -c "$(declare -f onvol vol); PROJ=$PROJ; onvol 'cat /data/qual-restored.marker' | grep -q restored && echo 'staged content promoted'"
  expect $sc login-after-recovery bash -c '[[ "$(login "'"$ADMIN_USER"'" "'"$ADMIN_PASS"'")" == 200 ]] && echo "admin logs in"'
  login "$ADMIN_USER" "$ADMIN_PASS" >/dev/null
  assert_enforcement $sc after-recovery
  destroy
}

# ═══ run ═════════════════════════════════════════════════════════════════════
trap 'destroy >/dev/null 2>&1 || true' EXIT
SCENARIOS="${SCENARIOS:-A B D E}"   # subset for re-runs, e.g. SCENARIOS="E"
for sc in $SCENARIOS; do
  case "$sc" in
    A) scA ;;
    B) for p in $PRED_IMAGES; do scB "$p"; done ;;
    D) scD ;;
    E) scE ;;
  esac
done
check X "clamav-real-sidecar" blocked "ClamAV replaced by a stub (docker-compose.qualify.yml); the real sidecar's signature download cannot verify TLS behind this sandbox's intercepting proxy. Prerequisite: run on a host with direct egress and CULVERT_QUALIFY_REAL_CLAMAV=1 (remove the stub)."

{
  echo "## Checks"; echo; echo "| scenario | check | result | detail |"; echo "|---|---|---|---|"
  python3 - "$JSONL" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    d=json.loads(line); det=d["detail"].replace("|","\\|").replace("\n"," ")[:220]
    print(f"| {d['scenario']} | {d['check']} | **{d['result'].upper()}** | {det} |")
PY
  echo; echo "Failures: $FAILS"
} >> "$MD"
log "evidence: $MD ($FAILS failure(s))"
exit $(( FAILS > 0 ))
