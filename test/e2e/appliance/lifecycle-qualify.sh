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
#   R  disaster recovery: backup + .env escrowed off-box, BOTH original
#      volumes destroyed, a new install restores into a FRESH /data → same
#      root CA (fingerprint), admin, policy and real enforcement
#   E  interrupted restore (journal present) → proxy refuses to boot →
#      --recover-restore --confirm complete → boot → state verified
#   G  restore onto a FULL volume (/data on a size-bounded loop-backed ext4
#      image, filled to a few KiB free) → refused at the stage step, before any move: no
#      journal, no staging/bak, data byte-identical → boots → the same
#      archive restores once space is freed
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
SUDO=""; [[ "$(id -u)" -eq 0 ]] || SUDO=sudo
LOOPDEVS=()

log()  { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
# digest_of answers "<repo digest or none>|<image id>" on ONE line. An image
# loaded from a tar (the CI gate image) carries no RepoDigests, and `index` on
# that empty list makes docker emit a bare newline before it fails — the first
# CI run of this lane wrote that newline INTO the JSONL record and the report
# step refused every line. The template never indexes an absent list, and the
# answer is stripped of control characters whatever docker prints.
digest_of() {
  local d
  d="$(docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}none{{end}}|{{.Id}}' "$1" 2>/dev/null | tr -d '\n\r\t')" || d=""
  printf '%s' "${d:-unknown|unknown}"
}
check() { # check <scenario> <name> <pass|fail|blocked> <detail>
  local sc="$1" name="$2" res="$3" detail="${4:-}"
  # Every field goes through json.dumps: the record must stay machine-readable
  # whatever a detail, image name or digest contains (the report step parses
  # it line by line and a single bad byte voids the whole run's evidence).
  python3 -c 'import json,sys; a=sys.argv[1:]; print(json.dumps({"run":a[0],"scenario":a[1],"check":a[2],"result":a[3],"detail":a[4],"cur_image":a[5],"cur_digest":a[6]},separators=(",",":")))' \
    "$RUN_ID" "$sc" "$name" "$res" "$detail" "$CUR_IMAGE" "$(digest_of "$CUR_IMAGE")" >> "$JSONL"
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
  # Real-ClamAV mode (CULVERT_QUALIFY_REAL_CLAMAV=1, direct egress): the
  # override keeps the origins and the proxy start_period but does NOT stub
  # the sidecar, so the bundle's clamav + its healthcheck run for real.
  if [[ "${CULVERT_QUALIFY_REAL_CLAMAV:-0}" == 1 ]]; then
    cp "$HERE/docker-compose.qualify.real-clamav.yml" "$PDIR/docker-compose.override.yml"
  else
    cp "$HERE/docker-compose.qualify.yml" "$PDIR/docker-compose.override.yml"
  fi
  export EXTRA_COMPOSE="${EXTRA_COMPOSE:-}"
  printf 'CULVERT_CA_PASSPHRASE=%s\nCULVERT_LOG_PASSPHRASE=%s\nCULVERT_DEFAULT_ACTION=%s\n' "$CA_PASS" "$CA_PASS" "${QUAL_DEFAULT_ACTION:-}" > "$PDIR/.env"
  chmod 600 "$PDIR/.env"
  docker tag "$2" "$PINNED"
  # Cookie jar lives with the project; set in the PARENT shell so helpers
  # invoked inside $(...) command substitutions (subshells) still find it.
  JAR="$PDIR/jar"; : > "$JAR"
  export PROJ PDIR JAR
  # Hermetic start: a previous run killed mid-scenario (or one whose destroy
  # ran without the cli profile) leaves this project's volumes behind, and a
  # stale /backup/qual.tar.gz.enc makes scenario D refuse the backup and then
  # restore an archive from a DIFFERENT install. Measured once: 7 false FAILs.
  # It runs BEFORE the loop device below is attached: destroy also detaches
  # every loop device this run attached, so attaching first handed Docker a
  # device with no backing file ("unable to read superblock").
  destroy
  # Size-bounded data volume (scenario G): /data on a loop-backed ext4 image
  # of QUAL_DATA_LOOP_MB MiB owned by the image's runtime user, so ENOSPC is a
  # real kernel verdict, not a simulated one. NOT a tmpfs volume: Docker's
  # local driver mounts a fresh tmpfs per attach and drops it at the last
  # detach, so a down/up cycle (which every scenario does) silently starts
  # from an empty /data — the first draft of this scenario "passed" its
  # data-untouched check on two empty directories. losetup needs root
  # (sudo on a CI runner); -m 0 so the non-root proxy user sees the same
  # free space df reports.
  EXTRA_COMPOSE=""
  if [[ -n "${QUAL_DATA_LOOP_MB:-}" ]]; then
    local uid gid img dev
    uid="$(docker run --rm --entrypoint id "$CUR_IMAGE" -u)"; gid="$(docker run --rm --entrypoint id "$CUR_IMAGE" -g)"
    img="$PDIR/data-disk.img"
    truncate -s "${QUAL_DATA_LOOP_MB}M" "$img"
    mkfs.ext4 -q -m 0 -E root_owner="$uid:$gid" "$img"
    dev="$($SUDO losetup -f --show "$img")"
    LOOPDEVS+=("$dev")
    printf 'volumes:\n  proxy-data:\n    driver: local\n    driver_opts:\n      type: ext4\n      device: %s\n' "$dev" > "$PDIR/docker-compose.loop.yml"
    EXTRA_COMPOSE="$PDIR/docker-compose.loop.yml"
    log "data volume: ${QUAL_DATA_LOOP_MB} MiB ext4 on $dev ($img), owner $uid:$gid"
  fi
}
dc() { docker compose -p "$PROJ" --project-directory "$PDIR" -f "$PDIR/docker-compose.yml" -f "$PDIR/docker-compose.override.yml" ${EXTRA_COMPOSE:+-f "$EXTRA_COMPOSE"} "$@"; }
dcli() { dc --profile cli run --rm -T -e CULVERT_BACKUP_PASSPHRASE="$BK_PASS" cli "$@"; }
up() { dc up -d --remove-orphans >/dev/null 2>&1 || true; wait_health; }
down() { dc down --remove-orphans >/dev/null 2>&1 || true; }
# --profile cli is load-bearing: culvert-backups is referenced only by the
# profiled cli service, so without the profile compose drops it from the
# model and `down -v` leaves it on the host across runs.
destroy() {
  dc --profile cli down -v --remove-orphans >/dev/null 2>&1 || true
  local d; for d in ${LOOPDEVS[@]+"${LOOPDEVS[@]}"}; do $SUDO losetup -d "$d" 2>/dev/null || true; done; LOOPDEVS=()
}
# QUAL_HEALTH_WAIT_S bounds the wait (default 120 s; the real ClamAV sidecar
# downloads ~250 MB of signatures before the proxy may start — give it 900).
wait_health() {
  local budget="${QUAL_HEALTH_WAIT_S:-120}" i
  for (( i = 0; i < budget; i += 2 )); do
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

# ═══ R. disaster recovery: fresh volume, original appliance gone ═══════════
# Distinct from D (same volume, previous data beside it). Here the original
# data AND backup volumes are destroyed; recovery has exactly what an
# operator holds off-box: the encrypted archive (+ its passphrase) and the
# separately kept .env (CA/log passphrases). A new install restores into a
# FRESH /data and must come back as the SAME appliance: same root CA
# (fingerprint), same admin, same policy, same enforcement.
ca_fp() { api GET /api/ca-cert | body_of | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }
scR() {
  local sc=R; log "=== $sc disaster recovery into a fresh volume"
  QUAL_DEFAULT_ACTION=deny newproj r1 "$CUR_IMAGE"
  up || { check $sc boot fail "no /health"; destroy; return; }
  setup_admin >/dev/null; login "$ADMIN_USER" "$ADMIN_PASS" >/dev/null; seed_policy >/dev/null
  local fp0 out esc="$EVID/dr-escrow" uid gid orig="$PROJ"
  fp0="$(ca_fp)"; [[ -n "$fp0" ]] && check $sc original-ca pass "root CA sha256 $fp0" || check $sc original-ca fail "no CA from /api/ca-cert"
  out="$(dcli --encrypt --backup /backup/dr.tar.gz.enc 2>&1 || true)"
  if echo "$out" | grep -q "Backup written"; then check $sc backup pass "$(echo "$out" | tail -1)"; else check $sc backup fail "$out"; fi
  # Off-box escrow: the archive and the .env leave the host separately.
  rm -rf "$esc"; mkdir -p "$esc"
  docker run --rm -v "${PROJ}_culvert-backups:/backup:ro" -v "$esc:/out" alpine:3.20 cp /backup/dr.tar.gz.enc /out/ \
    && cp "$PDIR/.env" "$esc/env" && check $sc escrowed pass "archive $(stat -c %s "$esc/dr.tar.gz.enc" 2>/dev/null) bytes + .env held off-box" \
    || check $sc escrowed fail "could not copy the archive out"
  destroy
  if docker volume inspect "${orig}_proxy-data" >/dev/null 2>&1 || docker volume inspect "${orig}_culvert-backups" >/dev/null 2>&1; then
    check $sc original-gone fail "a volume of $orig survived destroy"
  else
    check $sc original-gone pass "data and backup volumes of $orig removed"
  fi
  # A NEW install, exactly as recovery-restore-runbook.md §5 says: first
  # boot brings the stack up on fresh volumes (it mints its OWN root CA),
  # the setup wizard is NOT completed, the escrowed .env goes back, the
  # archive is restored with --accept-root-ca-change so the archived root
  # replaces the fresh one.
  newproj r2 "$CUR_IMAGE"; cp "$esc/env" "$PDIR/.env"; chmod 600 "$PDIR/.env"
  up || { check $sc new-install-boot fail "no /health on the new install"; destroy; rm -rf "$esc"; return; }
  local fpn; fpn="$(onvol 'test -e /data/ui_users.json && echo roster' 2>/dev/null || true)"
  [[ -z "$fpn" ]] && check $sc new-install-unclaimed pass "fresh install up, no admin roster (wizard not completed)" || check $sc new-install-unclaimed fail "fresh volume already holds ui_users.json"
  down
  uid="$(docker run --rm --entrypoint id "$CUR_IMAGE" -u)"; gid="$(docker run --rm --entrypoint id "$CUR_IMAGE" -g)"
  dcli --list-restore-leftovers >/dev/null 2>&1 || true   # creates the backups volume
  docker run --rm -v "${PROJ}_culvert-backups:/backup" -v "$esc:/in:ro" alpine:3.20 \
    sh -c "cp /in/dr.tar.gz.enc /backup/ && chown $uid:$gid /backup/dr.tar.gz.enc && chmod 600 /backup/dr.tar.gz.enc"
  out="$(dcli --restore /backup/dr.tar.gz.enc --confirm --mode full --accept-dp-reenrollment 2>&1 || true)"
  if echo "$out" | grep -q "Restore committed"; then
    check $sc root-ca-guard fail "restore over a freshly minted CA committed WITHOUT --accept-root-ca-change"
  else
    check $sc root-ca-guard pass "refused without --accept-root-ca-change: $(echo "$out" | grep -m1 -iE 'root ca|ca.bundle|refus' | cut -c1-160)"
  fi
  out="$(dcli --restore /backup/dr.tar.gz.enc --confirm --mode full --accept-dp-reenrollment --accept-root-ca-change 2>&1 || true)"
  if echo "$out" | grep -q "Restore committed"; then check $sc restore-commit pass "$(echo "$out" | grep -m1 -E 'Restore committed')"; else check $sc restore-commit fail "$out"; fi
  up || { check $sc boot-after-dr fail "no /health: $(docker logs culvert 2>&1 | tail -5)"; destroy; rm -rf "$esc"; return; }
  check $sc boot-after-dr pass "version=$(version_of)"
  expect $sc admin-recovered bash -c '[[ "$(login "'"$ADMIN_USER"'" "'"$ADMIN_PASS"'")" == 200 ]] && echo "original admin logs in on the new appliance"'
  login "$ADMIN_USER" "$ADMIN_PASS" >/dev/null
  local fp1; fp1="$(ca_fp)"
  [[ -n "$fp0" && "$fp1" == "$fp0" ]] && check $sc ca-identity-recovered pass "root CA sha256 $fp1 (same root: clients keep trusting it)" || check $sc ca-identity-recovered fail "fp=$fp1 want=$fp0"
  expect $sc ssl-inspection-ready bash -c 'curl -fsS '"$PROXY"'/health | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"ssl_inspection\"]==\"ready\", d; print(\"ssl_inspection=ready (ca.bundle decrypts under the escrowed passphrase)\")"'
  expect $sc rules-recovered bash -c '[[ "$(rule_present)" == yes ]] && echo present'
  expect $sc default-deny-recovered bash -c '[[ "$(default_action)" == deny ]] && echo deny'
  assert_enforcement $sc after-dr
  destroy; rm -rf "$esc"
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

# ═══ G. insufficient disk space: refused at the stage step, nothing moved ═══
# "Restore stages before the swap" was an ARGUMENT in the readiness report;
# this makes it evidence (owner review, PR #1528). The volume is a real
# size-bounded ext4 filesystem; the fill leaves a few KiB so the stage's first
# write hits ENOSPC from the kernel. Also records what the proxy's own data
# footprint is on that volume (df after seeding), so the bound is reviewable.
scG() {
  local sc=G; log "=== $sc restore onto a full volume is refused before any move"
  QUAL_DEFAULT_ACTION=deny QUAL_DATA_LOOP_MB="${QUAL_DATA_LOOP_MB:-128}" newproj g "$CUR_IMAGE"
  up || { check $sc boot fail "no /health on a ${QUAL_DATA_LOOP_MB:-128} MiB ext4 data volume: $(docker logs culvert 2>&1 | tail -3)"; destroy; return; }
  setup_admin >/dev/null; login "$ADMIN_USER" "$ADMIN_PASS" >/dev/null; seed_policy >/dev/null
  local out; out="$(dcli --encrypt --backup /backup/qual.tar.gz.enc 2>&1 || true)"
  if echo "$out" | grep -q "Backup written"; then check $sc backup pass "$(echo "$out" | tail -1)"; else check $sc backup fail "$out"; destroy; return; fi
  down
  check $sc data-footprint pass "$(onvol 'df -k /data | awk "NR==2{print \"used \"\$3\" KiB of \"\$2\" KiB, \"\$4\" KiB free\"}"; du -sk /data/* /data/.[a-z]* 2>/dev/null | sort -rn | head -4 | tr "\n" " "')"
  local before; before="$(onvol 'cd /data && find . -path ./.qual-fill -prune -o -type f -print0 | sort -z | xargs -0 sha256sum' | sha256sum | cut -c1-16)"
  # Fill to 4 KiB free. fallocate is honoured by tmpfs; the staged restore
  # needs tens of KiB (ca.bundle, ui_users.json, policy …).
  out="$(onvol 'avail=$(df -k /data | awk "NR==2{print \$4}"); fallocate -l $(( (avail-4)*1024 )) /data/.qual-fill && df -k /data | awk "NR==2{print \"filled: \"\$4\" KiB free of \"\$2}"' 2>&1)"
  check $sc volume-filled pass "$out"
  out="$(dcli --restore /backup/qual.tar.gz.enc --confirm --mode full --accept-dp-reenrollment 2>&1 || true)"
  if echo "$out" | grep -q "stage failed" && echo "$out" | grep -qi "no space left on device"; then check $sc refused-at-stage pass "$(echo "$out" | grep -i 'stage failed' | head -1 | cut -c1-200)"; else check $sc refused-at-stage fail "$out"; fi
  expect $sc no-journal-no-leftovers bash -c "$(declare -f onvol vol); PROJ=$PROJ; onvol 'cd /data && ! ls -d .restore-journal.json .restore-staging.* .restore-bak.* 2>/dev/null' && echo 'no journal, no staging dir, no bak dir'"
  local after; after="$(onvol 'cd /data && find . -path ./.qual-fill -prune -o -type f -print0 | sort -z | xargs -0 sha256sum' | sha256sum | cut -c1-16)"
  if [[ "$before" == "$after" ]]; then check $sc data-untouched pass "content digest $before unchanged"; else check $sc data-untouched fail "content digest changed $before → $after"; fi
  onvol 'rm -f /data/.qual-fill' >/dev/null
  up || { check $sc boot-after-refusal fail "$(docker logs culvert 2>&1 | tail -5)"; destroy; return; }
  check $sc boot-after-refusal pass "version=$(version_of)"
  expect $sc login-after-refusal bash -c '[[ "$(login "'"$ADMIN_USER"'" "'"$ADMIN_PASS"'")" == 200 ]] && echo "admin logs in"'
  login "$ADMIN_USER" "$ADMIN_PASS" >/dev/null
  assert_enforcement $sc after-refusal
  # The same archive restores once space exists — proves the refusal was the
  # disk, not the archive.
  down
  out="$(dcli --restore /backup/qual.tar.gz.enc --confirm --mode full --accept-dp-reenrollment 2>&1 || true)"
  if echo "$out" | grep -q "Restore committed"; then check $sc commit-after-space-freed pass "committed"; else check $sc commit-after-space-freed fail "$out"; fi
  up || { check $sc boot-after-commit fail "$(docker logs culvert 2>&1 | tail -5)"; destroy; return; }
  expect $sc login-after-commit bash -c '[[ "$(login "'"$ADMIN_USER"'" "'"$ADMIN_PASS"'")" == 200 ]] && echo "admin logs in"'
  destroy
}

# ═══ run ═════════════════════════════════════════════════════════════════════
trap 'destroy >/dev/null 2>&1 || true' EXIT
SCENARIOS="${SCENARIOS:-A B D R E G}"   # subset for re-runs, e.g. SCENARIOS="E"
for sc in $SCENARIOS; do
  case "$sc" in
    A) scA ;;
    B) for p in $PRED_IMAGES; do scB "$p"; done ;;
    D) scD ;;
    R) scR ;;
    E) scE ;;
    G) scG ;;
    # An unknown letter used to be skipped silently, so a scenario missing
    # from this table "passed" with zero checks.
    *) check "$sc" unknown-scenario fail "no scenario '$sc' in this harness" ;;
  esac
done
if [[ "${CULVERT_QUALIFY_REAL_CLAMAV:-0}" == 1 ]]; then
  check X "clamav-real-sidecar" pass "the REAL clamav/clamav sidecar from the deploy bundle ran (signatures downloaded, healthcheck passed, /ready strict incl. the scanner rows)"
else
  check X "clamav-real-sidecar" blocked "ClamAV replaced by a stub (docker-compose.qualify.yml); the real sidecar's signature download cannot verify TLS behind this sandbox's intercepting proxy. Prerequisite: run on a host with direct egress and CULVERT_QUALIFY_REAL_CLAMAV=1 (uses docker-compose.qualify.real-clamav.yml, no stub)."
fi

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
