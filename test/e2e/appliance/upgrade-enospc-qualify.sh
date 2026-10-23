#!/usr/bin/env bash
# test/e2e/appliance/upgrade-enospc-qualify.sh — upgrade under a FULL disk,
# on an isolated, size-bounded Docker host (PR #1528 closeout).
#
# The appliance keeps Docker's image store, the stack directory and the
# maintenance agent's state on ONE root filesystem. This harness reproduces
# that on a disposable host whose every byte lives in ONE fixed-size,
# loop-mounted ext4 file:
#
#   <EVID>/appliance-root.img  (QUAL_ENOSPC_DISK_MB, ext4, -m 0)
#     ├─ docker/       → the nested dockerd's data root (/var/lib/docker),
#     │                  which also holds its managed containerd (image
#     │                  content + snapshots) — verified at run time
#     ├─ containerd/   → /var/lib/containerd, bounded too in case a daemon
#     │                  version keeps containerd there
#     ├─ srv-culvert/  → /srv/culvert (deploy-bundle compose, .env)
#     └─ culvert-maint/→ /var/lib/culvert-maint (agent config + journal)
#
# The nested daemon runs in a privileged docker:dind container; the REAL
# agent (built from cmd/culvert-maint) runs inside it beside the REAL
# deploy-bundle stack. The registry stays on the outer host, outside the
# bounded space. The fill is a file INSIDE the loop filesystem, so the outer
# host's disk never fills — the image file is sparse and capped at
# QUAL_ENOSPC_DISK_MB.
#
# Scenarios:
#   E0  bounded host up; data root + containerd content proven on the loop fs;
#       PRED running with seeded state through the agent's own compose project
#   E1  boot-time category sync settled (see below), then the
#       disk filled to QUAL_ENOSPC_LEAVE_KB free; first, with NO upgrade,
#       the proxy must keep serving for 15 s; then apply PRED → CUR through
#       POST /v1/upgrades/apply ⇒ REFUSED at preflight_space before any
#       pull (the agent never fills the disk), the
#       running container, the pinned tag, /health, admin state, the CA
#       identity and TRAFFIC ENFORCEMENT are those of PRED, unchanged
#   E2  fill removed, a NEW apply ⇒ succeeds through the agent's real
#       /ready gate (baseline + preservation), running digest = CUR, admin
#       state, CA identity and enforcement preserved
#
# Enforcement is proven with traffic, not a status row: default-deny plus
# one allow rule, and two busybox origins from docker-compose.qualify.yml —
# origin-allowed must answer 200 through the proxy, origin-blocked must not.
#
# Requires root (losetup/mount, privileged container, /etc/docker/certs.d).
# Usage: CUR_IMAGE=<ref> PRED_IMAGE=<ref> EVID=<dir> upgrade-enospc-qualify.sh
set -euo pipefail
CUR_IMAGE="${CUR_IMAGE:?}"; PRED_IMAGE="${PRED_IMAGE:?}"; EVID="${EVID:?}"
DISK_MB="${QUAL_ENOSPC_DISK_MB:-2048}"; LEAVE_KB="${QUAL_ENOSPC_LEAVE_KB:-6144}"
DIND_IMAGE="${QUAL_DIND_IMAGE:-docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1}"; REG_PORT="${QUAL_ENOSPC_REG_PORT:-5056}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
# The convergence verdict is a PURE, locally-testable decision (ASTRA §2
# "mandatory convergence verdict"); its functions live in a sourced lib so
# convergence-oracle_test.sh can prove them red/green with no lab run.
. "$HERE/convergence-oracle.sh"
SCENARIO="${QUAL_ENOSPC_SCENARIO:-upgrade}"
# Convergence-verdict run state (ASTRA §2): CONV_PATH_RAN is set once a recovery
# scenario reaches its convergence decision; CONV_VERDICT holds the best class
# observed (proven > unproven_* ; a product failure is carried by FAILS).
CONV_PATH_RAN=0; CONV_VERDICT=none; CONV_LAST=none
mkdir -p "$EVID"; JSONL="$EVID/checks.jsonl"; MD="$EVID/REPORT.md"; : > "$JSONL"; FAILS=0
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"; DIND="eq-dind-$$"; REG="eq-registry-$$"
IMG="$EVID/appliance-root.img"; MNT="$EVID/mnt"; SOCKDIR="$(mktemp -d /tmp/eqsock.XXXXXX)"; SOCK="$SOCKDIR/agent.sock"
log(){ printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
check(){ local sc="$1" n="$2" r="$3" d="${4:-}"
  python3 -c 'import json,sys; print(json.dumps({"run":sys.argv[1],"scenario":sys.argv[2],"check":sys.argv[3],"result":sys.argv[4],"detail":sys.argv[5]},separators=(",",":")))' "$RUN_ID" "$sc" "$n" "$r" "$d" >> "$JSONL"
  if [[ "$r" == fail ]]; then FAILS=$((FAILS+1)); log "FAIL [$sc] $n: $d"; else log "$r [$sc] $n: $d"; fi; }
# conv_check <scenario> <check-name> <feedsync-outcome> <waited-s> [context] — the
# ONE convergence call path (ASTRA §2). classify_convergence (the sourced pure
# fn) decides the class; this records that the convergence path ran, keeps the
# run's best verdict, and emits the check: proven=pass, lab/network shortfall=
# info (UNPROVEN — not a pass; enforced at exit via convergence_exit_class),
# disk-side error or no outcome=fail. It never, on its own, lets a non-proven
# convergence exit 0 — write_report_and_exit does that.
conv_check(){ local sc="$1" name="$2" res="$3" waited="$4" ctx="${5:-}"
  CONV_PATH_RAN=1; CONV_LAST="$(classify_convergence "$res")"
  case "$CONV_LAST" in
    proven)       CONV_VERDICT=proven
      check "$sc" "$name" pass "convergence PROVEN: ${res#FeedSync: } (${waited}s)${ctx:+ — $ctx}" ;;
    unproven_lab) [[ "$CONV_VERDICT" == none ]] && CONV_VERDICT=unproven_lab || true
      check "$sc" "$name" info "convergence UNPROVEN — lab volume below the import footprint (${res#FeedSync: }); a lab dind-volume sizing limit, NOT a product fault${ctx:+; $ctx}" ;;
    unproven_net) [[ "$CONV_VERDICT" == none ]] && CONV_VERDICT=unproven_net || true
      check "$sc" "$name" info "convergence UNPROVEN — network download failure after ${waited}s (not disk)${ctx:+; $ctx}" ;;
    failed)       check "$sc" "$name" fail "convergence FAILED on the disk side: ${res:-no FeedSync outcome within ${conv:-?}s} (${waited}s)${ctx:+; $ctx}" ;;
  esac; }
# Bounded, enforced steps + quarantine custody (ASTRA item 5): sourced so
# recovery-custody_test.sh proves them red/green with no lab (stubbed docker).
# shellcheck disable=SC2034  # read by the sourced recovery-custody.sh
{ STEPLOG="$EVID/steps.log"; CUSTODY_NAMES=""; CUSTODY_TREE=none; }
# shellcheck source=recovery-custody.sh
. "$HERE/recovery-custody.sh"

CERTSD=""
# Teardown: harness_teardown (recovery-custody.sh) — bounded and enforced.
trap harness_teardown EXIT
[[ "$(id -u)" == 0 ]] || { echo "must run as root (losetup/mount, privileged dind, certs.d)" >&2; exit 2; }

# ── E0: the bounded host ─────────────────────────────────────────────────────
truncate -s "${DISK_MB}M" "$IMG"
mkfs.ext4 -q -F -m 0 "$IMG"   # -m 0: no root reserve, so root's free space is the free space we fill
mkdir -p "$MNT"; mount -o loop "$IMG" "$MNT"
mkdir -p "$MNT/docker" "$MNT/containerd" "$MNT/srv-culvert/culvert" "$MNT/culvert-maint/state"
check E0 bounded-fs pass "$(df -k --output=size,avail "$MNT" | tail -1 | awk '{printf "size=%dKiB avail=%dKiB", $1, $2}') image=$IMG (sparse, cap ${DISK_MB}MiB)"

GW="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
REGHOST="$GW:$REG_PORT"; REPO="$REGHOST/culvert"; PINNED="culvert/proxy:pinned"
CERTD="$EVID/registry-certs"; mkdir -p "$CERTD"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTD/tls.key" -out "$CERTD/tls.crt" \
  -subj "/CN=$GW" -addext "subjectAltName=IP:$GW" >/dev/null 2>&1
CERTSD="/etc/docker/certs.d/$REGHOST"; mkdir -p "$CERTSD"; cp "$CERTD/tls.crt" "$CERTSD/ca.crt"
docker run -d --name "$REG" -p "$REGHOST:5000" -v "$CERTD:/certs:ro" \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/tls.crt -e REGISTRY_HTTP_TLS_KEY=/certs/tls.key registry:2 >/dev/null
for _ in $(seq 1 20); do curl -fsS --cacert "$CERTD/tls.crt" "https://$REGHOST/v2/" >/dev/null 2>&1 && break; sleep 1; done
push_digest(){ docker tag "$1" "$REPO:$2" >/dev/null; docker push -q "$REPO:$2" >/dev/null
  local d; d="$(curl -sI -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' --cacert "$CERTD/tls.crt" "https://$REGHOST/v2/culvert/manifests/$2" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}')"
  [[ -n "$d" ]] || { echo "registry returned no digest for $REPO:$2" >&2; return 1; }
  echo "$REPO@$d"; }
PRED_REF="$(push_digest "$PRED_IMAGE" pred)"; CUR_REF="$(push_digest "$CUR_IMAGE" cur)"
log "pred=$PRED_REF cur=$CUR_REF"
# Content identity, not a version stamp. A push re-serializes the manifest, so
# the registry (and the nested daemon that pulls from it) names the image by a
# NEW manifest digest. What a push cannot change is the config blob, whose
# digest covers rootfs.diff_ids — the uncompressed layer content. When the
# caller states the config digest of the verified source tar, the pushed
# manifest's config is fetched, re-hashed here and required to match.
registry_config(){ local m; m="$(curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' --cacert "$CERTD/tls.crt" "https://$REGHOST/v2/culvert/manifests/${1##*@}")" || return 1
  local c; c="$(printf '%s' "$m" | python3 -c 'import json,sys;print(json.load(sys.stdin)["config"]["digest"])')" || return 1
  local h; h="sha256:$(curl -fsS --cacert "$CERTD/tls.crt" "https://$REGHOST/v2/culvert/blobs/$c" | sha256sum | cut -d' ' -f1)" || return 1
  [[ "$h" == "$c" ]] || { echo "config blob hashes to $h, manifest names $c" >&2; return 1; }
  echo "$c"; }
if [[ -n "${EXPECT_CONFIG_DIGEST:-}" ]]; then
  for pair in "cur:$CUR_REF" "pred:$PRED_REF"; do
    got="$(registry_config "${pair#*:}" 2>&1)" || got="error: $got"
    if [[ "$got" == "$EXPECT_CONFIG_DIGEST" ]]; then check E0 "image-content-${pair%%:*}" pass "pushed ${pair#*:} has config $got (re-hashed) = source tar config${EXPECT_SOURCE_NOTE:+; $EXPECT_SOURCE_NOTE}"
    else check E0 "image-content-${pair%%:*}" fail "pushed ${pair#*:} config=$got, expected $EXPECT_CONFIG_DIGEST"; fi
  done
fi

# The nested daemon: its own bridge range so the outer gateway (the registry)
# stays routable from inside; every state directory on the loop filesystem.
docker run -d --privileged --name "$DIND" -e DOCKER_TLS_CERTDIR= \
  -v "$MNT/docker:/var/lib/docker" -v "$MNT/containerd:/var/lib/containerd" \
  -v "$MNT/srv-culvert/culvert:/srv/culvert" -v "$MNT/culvert-maint:/var/lib/culvert-maint" \
  -v "$SOCKDIR:/run/culvert-maint" --mount "type=bind,src=$CERTSD,dst=/etc/docker/certs.d/$REGHOST,readonly" \
  -p 127.0.0.1:18080:8080 -p 127.0.0.1:19090:9090 \
  "$DIND_IMAGE" --bip 10.213.0.1/24 --default-address-pool base=10.214.0.0/16,size=24 >/dev/null
# IN: every command inside the bounded host is BOUNDED (ASTRA 6360307931 #3) —
# KILLed there at IN_BOUND, and locally 15 s later. No read can hang the run.
IN(){ local b="${IN_BOUND:-600}"; timeout --kill-after=5 "$((b + 15))" docker exec "$DIND" timeout -s KILL "$b" "$@"; }
for _ in $(seq 1 60); do IN docker info >/dev/null 2>&1 && break; sleep 1; done
info="$(IN docker info --format 'server={{.ServerVersion}} driver={{.Driver}} root={{.DockerRootDir}} containerd-store={{.DriverStatus}}')"
# Where the image CONTENT really lands: find the containerd content store and
# prove its filesystem is the loop device (same st_dev as the data root).
content="$(IN sh -c 'for d in /var/lib/docker/containerd/daemon/io.containerd.content.v1.content /var/lib/containerd/io.containerd.content.v1.content; do [ -d "$d" ] && echo "$d"; done; true' | head -1)"
devs="$(IN sh -c "stat -c %d /var/lib/docker /var/lib/containerd ${content:-/var/lib/docker} /srv/culvert /var/lib/culvert-maint" | sort -u | tr '\n' ' ')"
if [[ "$(echo "$devs" | wc -w)" == 1 && -n "$content" ]]; then
  check E0 image-store-bounded pass "$info; content store $content; every state dir on one device ($devs)"
else
  check E0 image-store-bounded fail "$info; content='$content' devices='$devs'"
fi
check E0 dind-image pass "$DIND_IMAGE = $(docker image inspect -f '{{index .RepoDigests 0}}' "$DIND_IMAGE" 2>/dev/null || echo unknown)"

timeout --kill-after=10 600 docker save busybox:stable | timeout --kill-after=10 600 docker exec -i "$DIND" timeout -s KILL 590 docker load -q >/dev/null
IN docker pull -q "$PRED_REF" >/dev/null; IN docker tag "$PRED_REF" "$PINNED"
PRED_ID="$(IN docker image inspect -f '{{.Id}}' "$PINNED")"
[[ "$PRED_ID" == "${PRED_REF##*@}" ]] && check E0 image-pulled pass "nested daemon runs $PRED_ID = the pushed manifest digest" \
  || check E0 image-pulled fail "nested daemon image $PRED_ID, pushed ${PRED_REF##*@}"
if [[ "$SCENARIO" == midwrite || "$SCENARIO" == midimport-kill ]]; then :
elif IN docker image inspect "$CUR_REF" >/dev/null 2>&1; then check E0 cur-absent fail "CUR already present inside the bounded host"; else check E0 cur-absent pass "CUR not present inside the bounded host — the apply must pull it"; fi

cid="$(docker create "$CUR_IMAGE")"; docker cp "$cid:/app/deploy/docker-compose.yml" "$MNT/srv-culvert/culvert/docker-compose.yml" >/dev/null; docker rm -f "$cid" >/dev/null
cp "$HERE/docker-compose.qualify.yml" "$MNT/srv-culvert/culvert/docker-compose.override.yml"
printf 'CULVERT_CA_PASSPHRASE=enospcqual-ca-0123456789\nCULVERT_LOG_PASSPHRASE=enospcqual-ca-0123456789\n' > "$MNT/srv-culvert/culvert/.env"; chmod 600 "$MNT/srv-culvert/culvert/.env"
IN sh -c 'cd /srv/culvert && docker compose up -d' >/dev/null 2>&1
for _ in $(seq 1 60); do curl -fsS -m 3 http://127.0.0.1:18080/health >/dev/null 2>&1 && break; sleep 2; done
UI=https://127.0.0.1:19090; JAR="$EVID/jar"; : > "$JAR"
api(){ curl -ksS -m 20 -X "$1" "$UI$2" -H "Origin: $UI" -H 'Content-Type: application/json' -b "$JAR" -c "$JAR" ${3:+-d "$3"} -w '\n%{http_code}'; }
api POST /api/setup/complete '{"user":"enospcadmin","pass":"Enospc-Qual-2026!x"}' | tail -n1 >/dev/null
# Pilot posture (first-boot.md step 8): clients unauthenticated, policy by
# destination, default-deny + one allow rule.
api PUT /api/settings/default-auth-outcome '{"defaultAuthOutcome":"Exempt"}' | tail -n1 >/dev/null
api POST /api/default-action '{"action":"deny"}' | tail -n1 >/dev/null
api POST /api/policy '{"name":"qual-allow-origin","priority":10,"action":"Allow","destFQDN":"origin-allowed","sslAction":"Bypass","enabled":true}' | tail -n1 >/dev/null
through_proxy(){ curl -sS -m 10 -x http://127.0.0.1:18080 -o /dev/null -w '%{http_code}' "http://$1/" 2>/dev/null || echo 000; }
# ASTRA 6359611097 #4: the blocked origin must answer EXACTLY 403 with Culvert's
# default-deny block page; a 5xx/000 is an outage and must never pass. The
# decision is enforcement_verdict (recovery-custody.sh), proven with negative
# controls in recovery-custody_test.sh.
assert_enforcement(){ local a b v f="$EVID/deny-body.$$.html"
  a="$(through_proxy origin-allowed)"
  b="$(curl -sS -m 10 -x http://127.0.0.1:18080 -o "$f" -w '%{http_code}' "http://origin-blocked/" 2>/dev/null || echo 000)"
  if v="$(enforcement_verdict "$a" "$b" "$f")"; then check "$1" "${2:-enforcement}" pass "${v#pass } (real traffic through the proxy)"
  else check "$1" "${2:-enforcement}" fail "${v#fail } — body: $(head -c 160 "$f" 2>/dev/null | tr -d '\r\n')"; fi
  rm -f "$f"; }
ca_fp(){ api GET /api/ca-cert | sed '$d' | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }
health_version(){ curl -fsS -m 5 http://127.0.0.1:18080/health | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])'; }
PRED_VER="$(health_version)"
# state_sum: a failed read is "error(rc)", never a digest of nothing.
state_sum(){ local o rc=0
  o="$(IN_BOUND=30 IN docker exec culvert sh -c 'cd /data && sha256sum ui_users.json ca.bundle')" || rc=$?
  if (( rc != 0 )) || [[ -z "$o" ]]; then echo "error(rc=$rc)"; return 1; fi
  printf '%s\n' "$o" | sha256sum | cut -c1-16; }
STATE0="$(state_sum)"
check E0 seeded-predecessor pass "running $PRED_VER image=$PRED_ID state=$STATE0"
RUN_IMG="$(IN docker inspect -f '{{.Image}}' culvert 2>/dev/null || true)"
[[ "$RUN_IMG" == "$PRED_ID" ]] && check E0 image-running pass "container culvert runs $RUN_IMG" || check E0 image-running fail "container culvert runs '$RUN_IMG', expected $PRED_ID"
FP0="$(ca_fp)"; [[ -n "$FP0" ]] && check E0 ca-identity pass "root CA sha256 $FP0" || check E0 ca-identity fail "no CA certificate from /api/ca-cert"
assert_enforcement E0

# The agent under test is the EXACT shipped binary when QUAL_AGENT_BIN is set
# (the f-disk job extracts /app/deploy/bin/culvert-maint from the candidate
# image), otherwise it is built from source (QUAL_AGENT_SRC / repo root). Using
# the shipped bytes is what binds F-DISK evidence to the agent the appliance
# actually runs, not a local dev rebuild (ASTRA finding on run 39140010708).
if [[ -n "${QUAL_AGENT_BIN:-}" ]]; then
  [[ -x "$QUAL_AGENT_BIN" ]] || { echo "QUAL_AGENT_BIN=$QUAL_AGENT_BIN is not an executable file"; exit 1; }
  cp "$QUAL_AGENT_BIN" "$EVID/culvert-maint"
  AGENT_PROVENANCE="shipped binary sha256 $(sha256sum "$EVID/culvert-maint" | cut -d' ' -f1), $("$EVID/culvert-maint" --version 2>/dev/null | head -1 | tr -d '\r' || echo 'version unavailable')"
else
  AGENT_SRC="${QUAL_AGENT_SRC:-$ROOT}"
  ( cd "$AGENT_SRC/cmd/culvert-maint" && CGO_ENABLED=0 go build -o "$EVID/culvert-maint" . )
  AGENT_PROVENANCE="built from cmd/culvert-maint at $(git -C "$AGENT_SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi
check E0 agent-identity pass "$AGENT_PROVENANCE"
docker cp "$EVID/culvert-maint" "$DIND:/usr/local/bin/culvert-maint" >/dev/null
esc_reg="$(printf '%s' "$REGHOST" | sed 's/\./\\\\./g')"
cat > "$MNT/culvert-maint/config.toml" <<CFG
privilege_mode = "docker_group_lab"
compose_project_dir = "/srv/culvert"
compose_file = "docker-compose.yml"
compose_override_file = "docker-compose.override.yml"
socket_path = "/run/culvert-maint/agent.sock"
state_dir = "/var/lib/culvert-maint/state"
proxy_repo = "$REPO"
image_allowlist = "^${esc_reg}/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})\$"
allow_peers = ["0"]
health_base_url = "http://127.0.0.1:8080"
health_path = "/health"
ready_path = "/ready"
operation_timeout = "20m"
stage_timeout = "8m"
reconcile_on_startup = true
CFG
IN sh -c 'nohup culvert-maint --config /var/lib/culvert-maint/config.toml >> /var/lib/culvert-maint/agent.log 2>&1 &'
ag(){ curl -sS --unix-socket "$SOCK" -H 'Content-Type: application/json' "$@"; }
for _ in $(seq 1 30); do ag http://unix/v1/health >/dev/null 2>&1 && break; sleep 1; done
if ag http://unix/v1/health >/dev/null 2>&1; then check E0 agent-start pass "$(ag http://unix/v1/health)"; else check E0 agent-start fail "$(tail -5 "$MNT/culvert-maint/agent.log")"; exit 1; fi
wait_op(){ for _ in $(seq 1 300); do local j st; j="$(ag "http://unix/v1/operations/$1" 2>/dev/null || true)"
  st="$(printf '%s' "$j" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("state",""))
except Exception: print("")')"; case "$st" in succeeded|failed) echo "$j"; return 0;; esac; sleep 2; done; echo '{"state":"timeout"}'; }
apply(){ ag -X POST http://unix/v1/upgrades/apply -d "{\"image_ref\":\"$1\",\"pre_backup\":false,\"rollback_on_failure\":true,\"idempotency_key\":\"$2\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("op_id",""))'; }
running_id(){ IN docker inspect -f '{{.Image}}' culvert; }

# diagnose: what the stack looks like when a probe fails (container state,
# restarts, OOM, recent logs of the proxy and of the bounded host's dockerd,
# free space). Evidence only — never changes the verdict.
# diagnose: recovery-custody.sh (bounded; ASTRA 6359611097 #1).

# fill_bounded: the ONLY fill in this harness — a file inside the loop mount,
# so the runner's own disk never fills. Leaves QUAL_ENOSPC_LEAVE_KB free.
fill_bounded(){ local avail fill
  avail="$(df -k --output=avail "$MNT" | tail -1 | tr -d ' ')"; fill=$(( avail - LEAVE_KB ))
  (( fill > 0 )) || { echo "only ${avail}KiB available"; return 1; }
  fallocate -l "$((fill * 1024))" "$MNT/.qual-fill"; }

write_report_and_exit(){
  timeout --kill-after=5 40 docker exec "$DIND" timeout -s KILL 30 cat /var/lib/culvert-maint/agent.log > "$EVID/agent.log" 2>/dev/null || true
  # ASTRA §2 mandatory convergence verdict. Emitted BEFORE the report is built so
  # the row appears and INCONCLUSIVE is set before the exit decision. A recovery
  # scenario that EXERCISED convergence but never PROVED it (only a lab-sizing or
  # network shortfall) is INCONCLUSIVE (exit 2) — NOT a pass; job SUCCESS can no
  # longer be read as convergence proof. A disk-side convergence failure already
  # set FAILS>0 (exit 1). The convergence path not being exercised at all (a
  # non-recovery scenario) is a pass here and decided by the scenario's own checks.
  if [[ "$CONV_PATH_RAN" == 1 ]]; then
    case "$(convergence_exit_class "$CONV_PATH_RAN" "$CONV_VERDICT" "$FAILS")" in
      pass)       check "$SCENARIO" convergence-verdict pass "convergence PROVEN (FeedSync sync complete observed) — the mandatory convergence verdict is satisfied" ;;
      incomplete) check "$SCENARIO" convergence-verdict info "convergence was EXERCISED but never PROVEN (best=$CONV_VERDICT): a lab-sizing/network shortfall is not product convergence — this run is INCONCLUSIVE for the convergence criterion, NOT a pass (exit 2)"
                  INCONCLUSIVE="${INCONCLUSIVE:-convergence-unproven}" ;;
      fail)       : ;;  # a disk-side convergence failure already set FAILS>0 (exit 1)
    esac
  fi
  local title="Upgrade-under-ENOSPC qualification"
  [[ "$SCENARIO" == midwrite ]] && title="Disk exhaustion during an active database write (F-DISK-1)"
  [[ "$SCENARIO" == midimport-kill ]] && title="Process kill during an active category import — interrupted-import recovery (F-DISK-RECOVERY-1 C1+C2)"
  { echo "# $title — run $RUN_ID"; echo
    echo "| artifact | reference |"; echo "|---|---|"
    echo "| image under qualification | \`$CUR_IMAGE\` → \`$CUR_REF\` |"; echo "| predecessor | \`$PRED_IMAGE\` → \`$PRED_REF\` |"
    echo "| bounded host | \`$DIND_IMAGE\`, data root + containerd + stack + agent state on one ${DISK_MB} MiB ext4 loop file (-m 0) |"
    echo "| agent | ${AGENT_PROVENANCE:-unknown}, privilege_mode=docker_group_lab, inside the bounded host |"
    echo; echo "| scenario | check | result | detail |"; echo "|---|---|---|---|"
    python3 - "$JSONL" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    d=json.loads(line); print(f"| {d['scenario']} | {d['check']} | **{d['result'].upper()}** | {d['detail'].replace('|','/').replace(chr(10),' ')[:260]} |")
PY
    echo; echo "Failures: $FAILS"; } > "$MD"
  [[ -s "$EVID/diagnose.log" ]] && { log "diagnostics:"; cat "$EVID/diagnose.log" >&2; }
  log "evidence: $MD ($FAILS failure(s))"
  (( FAILS > 0 )) && exit 1
  [[ -n "${INCONCLUSIVE:-}" ]] && exit 2   # never report a scenario that did not run as passed
  exit 0
}

# ── W: disk exhaustion DURING an active database write (F-DISK-1) ────────────
# QUAL_ENOSPC_SCENARIO=midwrite. A SEPARATE scenario from the upgrade path:
# fill the disk the moment the boot-time category sync starts its bulk
# BadgerDB write, record whether the known failure (SIGBUS in badger's sparse
# mmapped memtable) reproduces, then run the operator recovery procedure and
# the post-recovery integrity checks that must pass before F-DISK-1 can be
# closed. Needs egress to the category feed (the write is what is under
# test); without it the run is INCONCLUSIVE (exit 2), never a pass.
if [[ "$SCENARIO" == midwrite ]]; then
  # Poll fast: the write lasts seconds, and a coarse poll lands the fill
  # after it has finished — which then reads as "survived" when nothing was
  # tested (the first runner run polled at 5 s and could not tell).
  # Make the write happen UNDER OBSERVATION. On a fast host the predecessor's
  # boot-time feed write finishes during E0's setup checks, leaving nothing in
  # flight to fill against (appliance lab, runs 37138167013/37138298441:
  # inconclusive). Stop the proxy, remove ONLY the derived category cache
  # (re-downloadable by design, CHAOS-50), start it again: the boot-time sync
  # then runs while the poll below is already armed. Admin state, CA and
  # policy are untouched (state-intact compares them after recovery).
  IN sh -c 'cd /srv/culvert && docker compose stop proxy' >/dev/null 2>&1
  IN docker run --rm -v culvert_proxy-data:/data busybox:stable rm -rf /data/catfeeddb
  LOGS_SINCE="$(IN_BOUND=15 IN date -u +%Y-%m-%dT%H:%M:%SZ)" && [[ -n "$LOGS_SINCE" ]] \
    || { check "$SCENARIO" clock-read fail "could not read the bounded host's clock"; write_report_and_exit; }
  IN sh -c 'cd /srv/culvert && docker compose start proxy' >/dev/null 2>&1
  # Same container: read only what it logged since this start.
  wlogs() { IN docker logs --since "$LOGS_SINCE" culvert 2>&1; }
  wline=""
  for _ in $(seq 1 1200); do
    wline="$(wlogs | grep -m1 -oE 'FeedSync: (parsed [0-9]+ domain entries, writing to BadgerDB|download/parse failed|write REFUSED[^"]*)' || true)"
    [[ -n "$wline" ]] && break; sleep 0.5
  done
  if [[ "$wline" != *"writing to BadgerDB"* ]]; then
    check W write-started inconclusive "no bulk write observed (${wline:-nothing within 600 s}); this host cannot reproduce F-DISK-1"
    INCONCLUSIVE=1; write_report_and_exit; fi
  # The write must still be IN FLIGHT when the fill lands, or the scenario
  # tested nothing: checked immediately before the fill, and again after it.
  wdone='FeedSync: (sync complete|bulk write failed)[^"]*'
  if wlogs | grep -qE "$wdone"; then
    check W write-in-flight inconclusive "the write finished before the fill could land; nothing was tested"
    INCONCLUSIVE=1; write_report_and_exit; fi
  r0="$(IN_BOUND=15 IN docker inspect -f '{{.RestartCount}}' culvert 2>/dev/null)" || r0="unknown(read failed)"
  why="$(fill_bounded)" || { check W filled-during-write fail "$why"; write_report_and_exit; }
  if wlogs | grep -qE "$wdone"; then
    check W write-in-flight inconclusive "the write finished while the fill was being placed; nothing was tested"
    INCONCLUSIVE=1; write_report_and_exit; fi
  check W filled-during-write pass "$wline; write still in flight; filled to $(df -k --output=avail "$MNT" | tail -1 | tr -d ' ')KiB free"
  sleep 30
  after="$(wlogs | grep -m1 -oE "$wdone" || echo 'no completion line')"
  st="$(IN docker inspect -f 'status={{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}}' culvert 2>&1 || true)"
  # The verdict comes from the CONTAINER, not from its log: on a full disk
  # dockerd cannot write the crash trace ("Error writing log message"), so a
  # run that grepped only for SIGBUS read a crash as "survived" (Deep
  # 37126218486: exit=2 restarts=1, no trace). A crash is any exit, a non-zero
  # exit code, or a restart since the fill; the trace is reported if kept.
  read -r cst cex crs <<<"$(IN docker inspect -f '{{.State.Status}} {{.State.ExitCode}} {{.RestartCount}}' culvert 2>/dev/null || echo 'unknown 0 0')"
  trace=lost; wlogs | grep -q 'SIGBUS' && trace=SIGBUS
  if [[ "$cst" != running || "$cex" != 0 || "$crs" != "$r0" ]]; then
    check W known-failure-reproduced known-failure "F-DISK-1 reproduced: the proxy died during the write ($st; restarts before fill=$r0); crash trace: $trace"
    diagnose W-crash
  else
    v="$(health_version 2>/dev/null || echo unreachable)"
    if [[ "$v" == unreachable ]]; then
      check W known-failure-reproduced fail "container running but /health unreachable; $st"
    else
      check W known-failure-reproduced survived "no crash: still running, no restart since the fill; $st; /health version=$v; the write then reported: ${after}"
    fi
  fi
  # ASTRA Phase-3 rule 1: the ACCURATE DEGRADED OPERATOR STATE while the disk is
  # full — survival plus a bulk-write error log does not establish it. With the
  # fill STILL in place (free space bracketed before/after), send bounded
  # allow/deny traffic through the proxy and record what an operator observes:
  # enforcement must still hold under fill, and /health + the category-store
  # metrics must report the degradation truthfully. Only meaningful when the
  # container survived the fill; a crash is the known-failure path above.
  if [[ "$cst" == running && "${v:-unreachable}" != unreachable ]]; then
    freeA="$(df -k --output=avail "$MNT" | tail -1 | tr -d ' ')"
    ua="$(through_proxy origin-allowed)"; ub="$(through_proxy origin-blocked)"
    # Denial reason, retained: capture the blocked response's bounded body so the
    # record shows WHY the deny happened, not merely that a non-200 came back.
    ubody="$(curl -sS -m 10 -x http://127.0.0.1:18080 "http://origin-blocked/" 2>/dev/null | head -c 200 | tr -d '\r\n' || true)"
    freeB="$(df -k --output=avail "$MNT" | tail -1 | tr -d ' ')"
    # ASTRA hardening: the denial oracle must assert 403 SPECIFICALLY. A 5xx/502
    # is a crash or a backend failure wearing the clothes of a denial — accepting
    # "any non-200" let a broken proxy pass as "still enforcing". 403 is the
    # policy default-deny this run actually returns; anything else (incl. 000,
    # 407, 5xx) is a failure, not enforcement. Fresh requests + free-space
    # brackets + denial body retained.
    if [[ "$ua" == 200 && "$ub" == 403 ]]; then
      check W under-fill-enforcement pass "under fill (free ${freeA}->${freeB}KiB): allowed=$ua blocked=$ub (deny body: ${ubody:-none}) — default-deny enforced with the disk full, before any cleanup; 403 specifically (a 5xx would be a crash, not a policy denial)"
    else
      check W under-fill-enforcement fail "under fill (free ${freeA}->${freeB}KiB): allowed=$ua blocked=$ub (body: ${ubody:-none}) — expected allowed=200 blocked=403; a 000/407/5xx blocked code is a failure or crash, not policy enforcement"
    fi
    # ASTRA Phase-3 rule 1: assert the product TRUTHFULLY surfaces the incomplete
    # category import — free space, a serving /health and a write-error log do NOT
    # establish an accurate operator/agent incomplete-import state. The feed's own
    # completion contract is the oracle (F-FEED-1, internal/feedsync): a sync is
    # certified complete ONLY after the durable SyncRecord is written, and ONLY
    # then is culvert_category_feed_last_sync_timestamp_seconds set non-zero
    # (globalUT1FeedSyncer.Stats()). The boot import was still IN FLIGHT when the
    # fill landed (guarded above), so under ENOSPC it cannot certify. The
    # operator-observable truth MUST therefore be last_sync == 0 (NOT certified
    # complete) AND sync_failures_total >= 1 (the interrupted/refused import is
    # surfaced as a failure, not silently dropped — the CWE-778 direction). One
    # scrape, parsed; a product that reported last_sync > 0 here is falsely
    # certifying a completed sync and FAILS.
    hv="$(health_version 2>/dev/null || echo unreachable)"
    metrics="$(curl -fsS -m 5 http://127.0.0.1:18080/metrics 2>/dev/null || true)"
    feedm="$(printf '%s\n' "$metrics" | grep -E '^culvert_category_feed_(last_sync_timestamp_seconds|sync_failures_total|entries) ' | tr '\n' ' ')"
    mfull="$(printf '%s\n' "$metrics" | grep -E '^culvert_catfeeddb_(available|recovered|quarantined_copies) ' | tr '\n' ' ')"
    lastsync="$(printf '%s\n' "$metrics" | awk '/^culvert_category_feed_last_sync_timestamp_seconds /{print $2}')"
    failtot="$(printf '%s\n' "$metrics" | awk '/^culvert_category_feed_sync_failures_total /{print $2}')"
    werr="$(wlogs | grep -m1 -oE 'bulk write failed[^"]*|write REFUSED[^"]*' || echo 'no bulk-write-failed/refused line')"
    if [[ -z "${lastsync:-}" || -z "${failtot:-}" ]]; then
      check W degraded-state-truthful fail "category-feed metrics not exposed (last_sync='${lastsync:-}' sync_failures='${failtot:-}'): cannot verify the product surfaces the incomplete import — feed metrics: ${feedm:-none}; catfeeddb: ${mfull:-none}; write error: ${werr}"
    elif [[ "$lastsync" == 0 && "$failtot" =~ ^[0-9]+$ && "$failtot" -ge 1 ]]; then
      check W degraded-state-truthful pass "disk full, pre-cleanup (free ${freeB}KiB): import NOT certified complete (last_sync=0) AND the failed import is surfaced (sync_failures_total=$failtot); /health version=$hv; feed metrics: ${feedm:-none}; catfeeddb: ${mfull:-none}; write error: ${werr}"
    else
      check W degraded-state-truthful fail "product did NOT truthfully surface the incomplete import: last_sync=${lastsync} (expected 0 = not certified complete), sync_failures_total=${failtot} (expected >=1); /health version=$hv; feed metrics: ${feedm:-none}; catfeeddb: ${mfull:-none}; write error: ${werr}"
    fi
  fi
  # Recovery procedure (docs/appliance/readiness-report.md F-DISK-1): free
  # space on the data filesystem, then bring the stack back. The FIRST runner
  # run of this scenario (Deep 37125042106) found that `compose up -d` alone
  # left the proxy down: dockerd's restart attempt during the full disk failed
  # to save the container's state ("restartmanger wait error"). So the
  # procedure is ESCALATED in order and the run records which step brought the
  # proxy back — that, not an assumption, is what the runbook may document.
  # Every command's output is kept; nothing here may abort the run before the
  # report is written.
  rm -f "$MNT/.qual-fill"
  up_within(){ local i; for i in $(seq 1 "$1"); do curl -fsS -m 3 http://127.0.0.1:18080/health >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
  rstep(){ local label="$1"; shift
    { echo "== recovery step: $label $(date -u +%FT%TZ)"; "$@" 2>&1 | tail -20; } >> "$EVID/diagnose.log" 2>&1 || true; }
  recovered=""
  rstep "compose up -d" IN sh -c 'cd /srv/culvert && docker compose up -d'
  if up_within 60; then recovered="1: docker compose up -d"; else
    diagnose W-after-compose-up
    rstep "compose up -d --force-recreate proxy" IN sh -c 'cd /srv/culvert && docker compose up -d --force-recreate proxy'
    if up_within 60; then recovered="2: docker compose up -d --force-recreate proxy"; else
      diagnose W-after-recreate
      rstep "restart dockerd" docker restart "$DIND"
      for _ in $(seq 1 60); do IN docker info >/dev/null 2>&1 && break; sleep 1; done
      rstep "compose up -d after dockerd restart" IN sh -c 'cd /srv/culvert && docker compose up -d'
      if up_within 60; then recovered="3: restart dockerd, then docker compose up -d"; else diagnose W-after-dockerd-restart; fi
    fi
  fi
  if [[ -z "$recovered" ]]; then
    check W recovered-serving fail "proxy not serving after every escalation step (compose up; force-recreate; dockerd restart) — see diagnose.log"
    write_report_and_exit
  fi
  REC_AT="$(date -u +%FT%TZ)"
  v="$(health_version 2>/dev/null || echo unreachable)"
  [[ "$v" == "$PRED_VER" ]] && check W recovered-serving pass "/health 200 version=$v; recovered at step $recovered" || check W recovered-serving fail "version=$v after step $recovered"
  [[ "$recovered" == 1:* ]] && check W recovery-step-1-sufficient pass "free space + docker compose up -d" \
    || check W recovery-step-1-sufficient known-failure "free space + compose up -d did NOT restore the proxy; needed step $recovered (runbook must say so)"
  c="$(api POST /api/auth/login '{"user":"enospcadmin","pass":"Enospc-Qual-2026!x"}' | tail -n1 || true)"
  s1="$(state_sum || true)"
  [[ "$c" == 200 && "$s1" == "$STATE0" ]] && check W state-intact pass "admin login http $c; ui_users.json+ca.bundle digest $s1 unchanged" || check W state-intact fail "login=$c digest=$s1 want=$STATE0"
  fp="$(ca_fp || true)"; [[ "$fp" == "$FP0" ]] && check W ca-identity-intact pass "root CA sha256 $fp" || check W ca-identity-intact fail "fp=$fp want=$FP0"
  assert_enforcement W || true
  m="$(curl -fsS -m 5 http://127.0.0.1:18080/metrics 2>/dev/null | grep -E '^culvert_catfeeddb_(available|recovered|quarantined_copies) ' | tr '\n' ' ' || true)"
  [[ "$m" == *"culvert_catfeeddb_available 1"* ]] && check W category-store-opens pass "$m" || check W category-store-opens fail "category store not available after recovery: ${m:-no metric}"
  # A store torn mid-write reopens with only PART of the feed, and a non-empty
  # store does not trigger the boot-time sync — coverage stays partial until
  # the next scheduled round. Record what the reopened store reports.
  fl="$(wlogs | grep -oE 'FeedSync: [^"]{0,160}' | tail -3 | tr '\n' ' ' || true)"
  check W category-coverage-after-recovery info "post-recovery feed log: ${fl:-none}"
  # Convergence: the refused import is retried on the feed's failure backoff
  # (15 min floor, internal/feedsync syncRetryMin) — the process survived, so
  # no restart re-runs it sooner. With space back, that retry must complete
  # and certify the whole feed. A disk-side failure is a FAIL; a download
  # failure says nothing about the disk and is recorded as such.
  conv="${QUAL_FEED_CONVERGE_SECS:-1800}"; t0=$SECONDS; res=""
  while (( SECONDS - t0 < conv )); do
    res="$(IN docker logs --since "$REC_AT" culvert 2>&1 | grep -oE 'FeedSync: (sync complete[^"]*|bulk write failed|could not begin the import|import written but could not be certified|download/parse failed)' | tail -1 || true)"
    [[ -n "$res" ]] && break; sleep 15
  done
  waited=$((SECONDS - t0))
  conv_check W category-import-converges "$res" "$waited" "after recovery"
  write_report_and_exit
fi

# ── K: process kill DURING an active category import (F-DISK-RECOVERY-1 C1+C2) ─
# QUAL_ENOSPC_SCENARIO=midimport-kill. The midwrite scenario above proves the
# CLEAN-FAIL landing (badger returns ENOSPC, the store is not torn, recovery is a
# plain re-import — quarantined_copies stays 0). The ORIGINAL intermittent F-DISK
# failure was the STALLED landing: badger's mmap write faults, CHAOS-74 contains
# it, BulkWrite never returns, the store is torn+degraded and — because a RUNTIME
# fault is never quarantined (CHAOS-50 quarantines only at OPEN time) — re-faults
# on every restart forever. F-DISK-RECOVERY-1 closes that with a DURABLE
# import-pending marker written by BeginImport BEFORE the risky write (C1) and a
# startup quarantine+rebuild of an interrupted import (C2, TriggerInterruptedImport).
# This scenario proves that recovery at the APPLIANCE level, DETERMINISTICALLY and
# landing-independently: a SIGKILL mid-import (docker rm -f, which also prevents
# the restart-policy from racing the observation) leaves the SAME durable state
# the stall produces — the marker present and no completion record — so the next
# boot MUST quarantine+rebuild+re-converge instead of looping. It uses a kill, not
# a disk fill, because the recovery triggers on the marker, not on corruption, so
# no ENOSPC is needed to exercise it. Needs egress to the feed (the import is what
# is interrupted); without it the run is INCONCLUSIVE (exit 2), never a pass.
if [[ "$SCENARIO" == midimport-kill ]]; then
  MARKER=/data/catfeeddb.importing
  # Fast marker check straight on the dind's volume mountpoint — NOT a per-poll
  # `docker run busybox` (the first draft did that, ~1 s each: too coarse to
  # catch a short-lived import, and it also broke the loop on a "bulk write
  # failed" line before killing, even though the marker PERSISTS after a failed
  # import — no CompleteImport runs — so the interrupted state was there to catch;
  # run 39391241768 was inconclusive 3× for exactly that reason).
  # The volume path is OBSERVED, never assumed: a failed inspection ends the run.
  MP="$(IN_BOUND=30 IN docker volume inspect culvert_proxy-data -f '{{.Mountpoint}}')" && [[ "$MP" == /* ]] \
    || { check K volume-inspect fail "could not inspect the data volume (got '${MP:-}')"; write_report_and_exit; }
  # klog <since> <file>: the proxy log since <since>, read BOUNDED into <file>;
  # returns the read's status so a transport failure is never "no lines".
  klog(){ IN_BOUND=30 IN docker logs --since "$1" culvert > "$2" 2>&1; }
  # ASTRA 6359611097 #2: the marker is TRI-STATE. present/absent come only from a
  # check that itself ran; a failed transport, a missing volume or a timeout is
  # "error", which FAILS the run instead of reading as "absent".
  marker_state(){ local o
    o="$(rx 20 "if [ -e catfeeddb.importing ]; then echo present; else echo absent; fi" 2>/dev/null)" || { echo error; return 0; }
    case "$o" in present|absent) echo "$o" ;; *) echo error ;; esac; }
  marker_present(){ local m; m="$(marker_state)"
    case "$m" in present) return 0 ;; absent) return 1 ;; esac
    check K marker-observation fail "could not observe $MARKER (bounded check failed) — not treated as absent"; diagnose K-marker; write_report_and_exit; }
  # INB <secs> <cmd…>: a bounded read inside the bounded host (remote KILL at
  # <secs>, local bound <secs>+10) — the scenario's own reads must not hang it.
  INB(){ local b="$1"; shift; timeout --kill-after=5 "$((b + 10))" docker exec "$DIND" timeout -s KILL "$b" "$@"; }
  metric(){ curl -fsS -m 5 http://127.0.0.1:18080/metrics 2>/dev/null | awk -v k="$1" '$1==k{print $2}'; }
  # wait_serving <sc> <name> <secs>: /health must answer within the bound, else FAIL.
  wait_serving(){ local t=$((SECONDS + $3))
    while (( SECONDS < t )); do curl -fsS -m 3 http://127.0.0.1:18080/health >/dev/null 2>&1 && return 0; sleep 2; done
    check "$1" "$2-serving" fail "proxy not serving within $3 s"; diagnose "$1-$2"; write_report_and_exit; }
  # hist_sum: digest of the config-version history — the API listing (metadata of
  # every version) AND the on-disk version files byte-for-byte. A Layer-2 recovery
  # must not add, drop or rewrite config history. Non-200 is an error, not a value.
  hist_sum(){ local out code disk
    out="$(api GET /api/config/versions)" || return 1; code="$(tail -n1 <<<"$out")"; [[ "$code" == 200 ]] || return 1
    disk="$(INB 30 docker exec culvert sh -c 'cd /data || exit 3; for f in config_versions/*; do if [ -f "$f" ]; then sha256sum "$f" || exit 4; fi; done')" || return 1
    printf '%s\n%s\n' "$(sed '$d' <<<"$out")" "$disk" | sha256sum | cut -c1-16; }
  hist_count(){ api GET /api/config/versions | sed '$d' | python3 -c 'import json,sys;print(len(json.load(sys.stdin) or []))' 2>/dev/null || echo '?'; }
  # Probes come FROM THE FEED THE NODE DOWNLOADED (feed_probe_candidates): the
  # harness fetches the same URL the product logged and takes the first domains
  # of each mapped category present. Every lookup response is recorded raw in
  # probes.txt, so a miss is diagnosable from the evidence. A candidate that
  # resolves tier=admin is skipped (built-in taxonomy: proves nothing about
  # Layer 2); a pass names the domain AND the category the community store served.
  PROBE_CATS="gambling adult phishing malware social_networks games shopping dating streamingmedia news"
  PROBEFILE="$EVID/probes.txt"; PROBE_CANDIDATES=""
  derive_probes(){ local url tgz="$EVID/.feed-probe.tar.gz"
    url="$(INB 30 docker logs culvert 2>&1 | grep -oE 'FeedSync: starting UT1 sync from [^ "]+' | tail -1 | awk '{print $NF}')"
    [[ "$url" =~ ^https?:// ]] || { echo "no feed URL in the proxy log" >> "$PROBEFILE"; return 1; }
    timeout --kill-after=10 900 curl -fsSL -m 880 -o "$tgz" "$url" || { echo "feed download failed: $url" >> "$PROBEFILE"; return 1; }
    { echo "feed $url sha256 $(sha256sum "$tgz" | cut -d' ' -f1)"; } >> "$PROBEFILE"
    PROBE_CANDIDATES="$(feed_probe_candidates "$tgz" 5 $PROBE_CATS | tr '\n' ' ')"
    rm -f "$tgz"
    echo "candidates: ${PROBE_CANDIDATES:-none}" >> "$PROBEFILE"
    [[ -n "${PROBE_CANDIDATES// /}" ]]; }
  community_probe(){ local h raw t
    for h in ${1:-$PROBE_CANDIDATES}; do
      raw="$(api GET "/api/urlcat/lookup?host=$h" | tr '\n' ' ')"
      printf '%s lookup %s -> %s\n' "$(date -u +%FT%TZ)" "$h" "${raw:0:400}" >> "$PROBEFILE"
      t="$(sed 's/ [0-9]*[[:space:]]*$//' <<<"$raw" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("tier",""),d.get("category",""))' 2>/dev/null || true)"
      [[ "$t" == community\ * ]] && { echo "$h ${t#community }"; return 0; }
    done; return 1; }
  # final_integrity <sc> <phase>: the end-state contract. Admin/Layer-1 state, the
  # root CA, config history and real enforcement are what they were BEFORE the
  # kill; the Layer-2 store is available with no import-pending marker.
  final_integrity(){ local sc="$1" ph="$2" c st fp h av
    c="$(api POST /api/auth/login '{"user":"enospcadmin","pass":"Enospc-Qual-2026!x"}' | tail -n1 || true)"
    st="$(state_sum || true)"; fp="$(ca_fp || true)"; h="$(hist_sum || echo error)"
    if [[ "$c" == 200 && "$st" == "$STATE0" ]]; then check "$sc" "$ph-state" pass "admin login $c; ui_users.json+ca.bundle digest $st = pre-kill"
    else check "$sc" "$ph-state" fail "login=$c digest=$st want $STATE0"; fi
    if [[ -n "$fp" && "$fp" == "$FP0" ]]; then check "$sc" "$ph-ca" pass "root CA sha256 $fp = pre-kill"
    else check "$sc" "$ph-ca" fail "root CA fp='$fp' want $FP0"; fi
    if [[ "$h" == "$HIST0" ]]; then check "$sc" "$ph-config-history" pass "config version history digest $h = pre-kill ($(hist_count) version(s); API listing + on-disk files)"
    else check "$sc" "$ph-config-history" fail "config history digest $h, pre-kill $HIST0 ($HIST0_N version(s) before, $(hist_count) now)"; fi
    assert_enforcement "$sc" "$ph-enforcement"
    av="$(metric culvert_catfeeddb_available)"
    if [[ "$av" == 1 ]] && ! marker_present; then check "$sc" "$ph-layer2-durable" pass "community store available=1, no import-pending marker"
    else check "$sc" "$ph-layer2-durable" fail "available='$av' marker=$(marker_state)"; fi; }
  HIST0="$(hist_sum || echo error)"; HIST0_N="$(hist_count)"
  [[ "$HIST0" != error ]] && check K pre-kill-history pass "config history digest $HIST0 ($HIST0_N version(s))" \
    || { check K pre-kill-history fail "could not read the config history before the kill"; write_report_and_exit; }
  # Make the import happen under observation: stop, drop ONLY the derived cache
  # (re-downloadable, CHAOS-50) and any stale marker/quarantine, start again.
  # Every step below is bounded and enforced (step), and leftovers from earlier
  # incidents are inventoried and hashed BEFORE deletion (custody), never
  # globbed away unrecorded.
  dstep K compose-stop 180 'cd /srv/culvert && docker compose stop proxy'
  quarantine_custody K pre-run; delete_custodied K pre-run
  dstep K reset-cache 300 "cd '$MP' || exit 3; rm -rf -- catfeeddb catfeeddb.importing"
  rs="$(rx 20 'if [ -e catfeeddb ] || [ -e catfeeddb.importing ]; then echo present; else echo absent; fi' 2>/dev/null || echo error)"
  [[ "$rs" == absent ]] || { check K reset-cache fail "after the reset the derived cache/marker are '$rs' (want absent from a successful check)"; write_report_and_exit; }
  LOGS_SINCE="$(IN_BOUND=15 IN date -u +%Y-%m-%dT%H:%M:%SZ)" && [[ -n "$LOGS_SINCE" ]] \
    || { check "$SCENARIO" clock-read fail "could not read the bounded host's clock"; write_report_and_exit; }
  # ARM protection BEFORE the import starts writing (ASTRA 6360721903 #1): a
  # kill, compose or observation failure from here on exits with the image —
  # which holds whatever the import wrote — retained.
  arm_evidence "an import is writing to the data volume; any partial or quarantined data on it is not yet preserved"
  dstep K compose-start 180 'cd /srv/culvert && docker compose start proxy'
  wlogs(){ INB 30 docker logs --since "$LOGS_SINCE" culvert 2>&1; }
  done_re='FeedSync: sync complete'                               # the ONLY line that clears the marker
  beginfail='FeedSync: could not begin the import'                # BeginImport itself failed: no marker, nothing to interrupt
  r0="$(IN_BOUND=15 IN docker inspect -f '{{.RestartCount}}' culvert 2>/dev/null)" || r0="unknown(read failed)"
  # Kill the instant the durable marker is present and the import has NOT certified
  # complete — the deterministic interrupted-import state. The marker persists
  # through a FAILED BulkWrite too (no CompleteImport), so this catches both a slow
  # write (kill mid-write) and a fast failure (kill with the marker left behind).
  killed=""
  for _ in $(seq 1 2400); do
    if marker_present; then
      check K import-pending-marker pass "C1: $MARKER present and the import not yet certified — BeginImport wrote the durable intent BEFORE completing the bulk write; restarts=$r0"
      dstep K sigkill 60 'docker rm -f culvert'   # SIGKILL + no restart-policy race
      killed=1; break
    fi
    wlogs | grep -qE "$done_re" && break     # import completed → marker already cleared; window missed
    wlogs | grep -qE "$beginfail" && break   # could not begin (no egress / begin failed) → nothing to interrupt
    sleep 0.25
  done
  if [[ -z "$killed" ]]; then
    if wl="$(wlogs)"; then feedtail="$(grep -oE 'FeedSync: [^"]{0,120}' <<<"$wl" | tail -4 | tr '\n' '|' || true)"; else feedtail="(log read failed)"; fi
    check K import-pending-marker inconclusive "no interrupted-import window observed (marker never present before the import resolved); feed log: ${feedtail:-none}; this host completed or could-not-begin the import too fast/entirely to interrupt"
    INCONCLUSIVE=1; write_report_and_exit; fi
  # The kill leaves the interrupted end-state: marker present, no completion — the
  # same durable state the stalled landing produces, reached deterministically.
  # From here the volume holds an interrupted import the product will quarantine:
  # evidence that must be preserved before anything may delete it or its image.
  arm_evidence "interrupted import on the data volume (killed mid-write) — not yet preserved off the volume"
  if marker_present; then check K interrupted-state pass "proxy SIGKILLed mid-import; $MARKER still present and the import never certified — the stall's durable end-state, reached deterministically"
  else check K interrupted-state fail "marker gone after the kill — the import may have completed; nothing was interrupted"; INCONCLUSIVE=1; write_report_and_exit; fi
  # Recovery is a plain restart (no disk is full here). The next boot MUST
  # quarantine the interrupted store and rebuild — breaking the re-fault loop that
  # was the original failure.
  REC_AT="$(date -u +%FT%TZ)"
  dstep K compose-up 300 'cd /srv/culvert && docker compose up -d'
  wait_serving K recovered 120
  v="$(health_version 2>/dev/null || echo unreachable)"
  [[ "$v" == "$PRED_VER" ]] && check K recovered-serving pass "/health 200 version=$v after one restart (compose up -d)" || check K recovered-serving fail "version=$v after restart (want $PRED_VER)"
  # C2: the interrupted import is quarantined and the store rebuilt + serving.
  metrics="$(curl -fsS -m 5 http://127.0.0.1:18080/metrics 2>/dev/null)" \
    || { check K metrics-read fail "could not read /metrics after recovery"; write_report_and_exit; }
  qc="$(printf '%s\n' "$metrics" | awk '/^culvert_catfeeddb_quarantined_copies /{print $2}')"
  qt="$(printf '%s\n' "$metrics" | awk '/^culvert_catfeeddb_quarantines_total /{print $2}')"
  av="$(printf '%s\n' "$metrics" | awk '/^culvert_catfeeddb_available /{print $2}')"
  mfull="$(printf '%s\n' "$metrics" | grep -E '^culvert_catfeeddb_(available|recovered|quarantines_total|quarantined_copies) ' | tr '\n' ' ')"
  qmsg="$(wlogs | grep -m1 -oE 'community category store (was damaged and re-created|is healthy)[^"]{0,80}' || echo 'no catfeeddb health line')"
  if { [[ "${qc:-0}" -ge 1 ]] || [[ "${qt:-0}" -ge 1 ]]; } && [[ "$av" == 1 ]]; then
    check K interrupted-import-quarantined pass "C2: the interrupted import was quarantined and the store rebuilt + available (quarantined_copies=${qc:-?} quarantines_total=${qt:-?} available=$av) — breaks the re-fault loop; health='${qmsg}'; $mfull"
  else
    check K interrupted-import-quarantined fail "expected quarantine+rebuild of the interrupted store (quarantined_copies/quarantines_total >= 1 AND available=1): $mfull"
  fi
  if marker_present; then check K marker-cleared fail "$MARKER still present after the quarantine+rebuild"; else check K marker-cleared pass "import-pending marker cleared after quarantine+rebuild (no false re-quarantine on later clean boots)"; fi
  c="$(api POST /api/auth/login '{"user":"enospcadmin","pass":"Enospc-Qual-2026!x"}' | tail -n1 || true)"
  s1="$(state_sum || true)"
  [[ "$c" == 200 && "$s1" == "$STATE0" ]] && check K state-intact pass "admin login http $c; ui_users.json+ca.bundle digest $s1 unchanged (Layer-1/admin/CA untouched by the Layer-2 recovery)" || check K state-intact fail "login=$c digest=$s1 want=$STATE0"
  fp="$(ca_fp || true)"; [[ "$fp" == "$FP0" ]] && check K ca-identity-intact pass "root CA sha256 $fp" || check K ca-identity-intact fail "fp=$fp want=$FP0"
  assert_enforcement K || true
  # The rebuilt store is EMPTY, so the boot-time sync (RunNow: !ImportComplete)
  # re-runs. On a space-constrained node the quarantined PARTIAL (.corrupt,
  # preserved by CHAOS-50) still occupies the disk, so the F-DISK free-space
  # guard REFUSES the re-sync write — correct: it must not re-fill the disk that
  # was just recovered. The node then degrades to Layer-1-only, serving. This is
  # the owner's "restart-disk-full" case: the right outcome is GRACEFUL
  # DEGRADATION, not convergence. (A node with room converges outright; both are
  # accepted here.) Phase B below proves the "free-space recovery" case.
  conv="${QUAL_FEED_CONVERGE_SECS:-1800}"; t0=$SECONDS; res=""
  while (( SECONDS - t0 < conv )); do
    if klog "$REC_AT" "$EVID/k-recovery.log"; then
      res="$(grep -oE 'FeedSync: (sync complete[^"]*|write REFUSED \(disk_space\)[^"]*|bulk write failed|could not begin the import|import written but could not be certified|download/parse failed)' "$EVID/k-recovery.log" | tail -1 || true)"
    else res=""; KLOG_ERRORS=$(( ${KLOG_ERRORS:-0} + 1 )); fi
    [[ -n "$res" ]] && break; sleep 15
  done
  waited=$((SECONDS - t0))
  if klog "$REC_AT" "$EVID/k-recovery.log"; then feedlog="$(grep -oE 'FeedSync: [^"]{0,140}' "$EVID/k-recovery.log" | tail -6 | tr '\n' '|' || true)"
  else feedlog="(log read failed; ${KLOG_ERRORS:-0} failed reads during the wait)"; fi
  degraded_on_space=0
  # ASTRA §2: the convergence path is now EXERCISED. Whatever terminal outcome
  # this decision reaches (converge outright, degrade-then-recover below, a
  # network INFO that never converges, or a disk-side failure), the mandatory
  # verdict in write_report_and_exit refuses exit 0 unless convergence is PROVEN.
  CONV_PATH_RAN=1
  case "$res" in
    "FeedSync: sync complete"*) CONV_VERDICT=proven; check K restart-disk-full-degrades pass "rebuilt store re-synced outright (node had room): ${res#FeedSync: } (${waited}s) — no free-space step needed; feed: ${feedlog:-none}";;
    "FeedSync: write REFUSED (disk_space)"*)
        degraded_on_space=1
        hv="$(health_version 2>/dev/null || echo unreachable)"
        av2="$(curl -fsS -m 5 http://127.0.0.1:18080/metrics 2>/dev/null | awk '/^culvert_catfeeddb_available /{print $2}' || echo '?')"
        # Enforcement was already asserted above (line 531); here the graceful
        # proof is: proxy still serving its version + Layer-1 store available,
        # and the refusal is surfaced truthfully in the feed log (not a crash).
        if [[ "$hv" == "$PRED_VER" && "$av2" == 1 ]]; then
          check K restart-disk-full-degrades pass "the quarantined partial leaves too little room (${res#FeedSync: }); the F-DISK guard REFUSED the re-sync and the node degraded to Layer-1-only — /health $hv, catfeeddb available=$av2, no crash/loop (owner 'restart-disk-full'); feed: ${feedlog:-none}"
        else
          check K restart-disk-full-degrades fail "disk-space refusal did not stay graceful: /health=$hv catfeeddb_available=$av2; feed: ${feedlog:-none}"
        fi;;
    *"download/parse failed"*) check K restart-disk-full-degrades info "retry after ${waited}s hit a download failure (network, not disk); feed: ${feedlog:-none}";;
    "") if klog 1970-01-01T00:00:00Z "$EVID/k-all.log"; then allfeed="$(grep -oE 'FeedSync: [^"]{0,140}' "$EVID/k-all.log" | tail -8 | tr '\n' '|' || true)"; else allfeed="(log read failed)"; fi
        check K restart-disk-full-degrades fail "no FeedSync outcome within ${conv}s of recovery; since-recovery feed: ${feedlog:-NONE}; all-boots feed: ${allfeed:-NONE (FeedSync never logged — boot sync did not run on the rebuilt store)}"; diagnose K-no-converge;;
    *) check K restart-disk-full-degrades fail "unexpected re-sync outcome: $res (${waited}s); feed: ${feedlog:-none}";;
  esac
  # Bounded + idempotent (owner req 5): a SECOND clean restart must NOT re-quarantine.
  qc1="$(curl -fsS -m 5 http://127.0.0.1:18080/metrics 2>/dev/null | awk '/^culvert_catfeeddb_quarantined_copies /{print $2}')"
  dstep K restart-idempotence 180 'cd /srv/culvert && docker compose restart proxy'
  wait_serving K restart-idempotence 120
  qc2="$(curl -fsS -m 5 http://127.0.0.1:18080/metrics 2>/dev/null | awk '/^culvert_catfeeddb_quarantined_copies /{print $2}')"
  [[ -n "$qc2" && "$qc2" == "$qc1" ]] && check K idempotent-no-reloop pass "a second clean restart did not re-quarantine (quarantined_copies stayed ${qc1:-?}) — recovery is bounded, not a loop" || check K idempotent-no-reloop fail "quarantined_copies changed on a clean restart: ${qc1:-?} -> ${qc2:-?} (possible re-quarantine loop)"
  # Owner req 7 "free-space recovery": the degradation above was disk-space, so
  # free the blocker — the quarantined PARTIAL, a rebuildable cache's damaged
  # remnant (the operator action a space-constrained node needs after an
  # interrupted import) — restart, and prove the re-sync then CONVERGES.
  # Deterministic: the harness controls the disk, no external variable.
  if [[ "${degraded_on_space:-0}" == 1 ]]; then
    freeB4="$(IN_BOUND=15 IN df -k "$MP" | awk 'NR==2{print $4}')" && [[ "$freeB4" =~ ^[0-9]+$ ]] || freeB4="error"
    # Custody BEFORE deletion: inventory + hash + retain metadata of exactly
    # what the product quarantined, cross-checked against the product's own
    # count, then delete exactly that set by name (bounded, enforced).
    quarantine_custody K pre-free
    nq="$(printf '%s\n' $CUSTODY_NAMES | grep -c '^catfeeddb\.corrupt\.' || true)"; qcm="$(metric culvert_catfeeddb_quarantined_copies)"
    if [[ "$nq" == "$qcm" && "$nq" -ge 1 ]]; then check K custody-matches-product pass "inventory holds $nq quarantined cop(y/ies) = culvert_catfeeddb_quarantined_copies $qcm"
    else check K custody-matches-product fail "inventory holds $nq quarantined cop(y/ies), product reports $qcm"; write_report_and_exit; fi
    delete_custodied K pre-free
    freeAf="$(IN_BOUND=15 IN df -k "$MP" | awk 'NR==2{print $4}')" && [[ "$freeAf" =~ ^[0-9]+$ ]] || freeAf="error"
    REC_AT="$(date -u +%FT%TZ)"
    arm_evidence "a restart after freeing space may quarantine again"
    dstep K restart-after-free 180 'cd /srv/culvert && docker compose restart proxy'
    wait_serving K restart-after-free 120
    t0=$SECONDS; res2=""
    while (( SECONDS - t0 < conv )); do
      if klog "$REC_AT" "$EVID/k-free.log"; then
        res2="$(grep -oE 'FeedSync: (sync complete[^"]*|write REFUSED \(disk_space\)[^"]*|bulk write failed|download/parse failed)' "$EVID/k-free.log" | tail -1 || true)"
      else res2=""; KLOG_ERRORS=$(( ${KLOG_ERRORS:-0} + 1 )); fi
      [[ -n "$res2" ]] && break; sleep 15
    done
    waited2=$((SECONDS - t0))
    if klog "$REC_AT" "$EVID/k-free.log"; then feedlog2="$(grep -oE 'FeedSync: [^"]{0,140}' "$EVID/k-free.log" | tail -6 | tr '\n' '|' || true)"
    else feedlog2="(log read failed; ${KLOG_ERRORS:-0} failed reads)"; fi
    conv_check K free-space-recovery-converges "$res2" "$waited2" "after freeing the quarantined partial, avail ${freeB4}->${freeAf} KiB; feed: ${feedlog2:-none}"
    [[ -z "$res2" ]] && diagnose K-free-space || true
    quarantine_custody K post-free   # preserve anything the restart created; else verified clear
  else
    # Converged (or not) without a free-space step: the quarantined copy stays on
    # the volume. Record its custody anyway, so the evidence names what remains.
    quarantine_custody K retained
  fi
  # ── Final integrity, then a clean restart FROM the converged state (item 5) ─
  # Convergence is only worth something if the node it leaves is whole and stays
  # whole across a restart: state/CA/config history/enforcement exactly as before
  # the kill, the converged import actually serving, and a further boot that
  # neither re-quarantines, re-syncs nor loses the certified store.
  final_integrity K post-convergence
  if [[ "$CONV_VERDICT" == proven ]]; then
    probe=""
    if derive_probes; then probe="$(community_probe || true)"; fi
    if [[ -n "$probe" ]]; then check K converged-store-serves pass "/api/urlcat/lookup resolves ${probe%% *} (taken from the downloaded feed) -> tier=community category='${probe#* }' — the converged import is what serves; raw responses in probes.txt"
    else check K converged-store-serves fail "a sync completed, but no feed-derived candidate [${PROBE_CANDIDATES:-none derived}] resolves to the community tier (raw responses in probes.txt)"; fi
    qcF="$(metric culvert_catfeeddb_quarantined_copies)"; RS_AT="$(date -u +%FT%TZ)"
    arm_evidence "a clean restart may quarantine again"
    dstep K clean-restart 180 'cd /srv/culvert && docker compose restart proxy'
    wait_serving K clean-restart 120
    # Settle window: a boot that did NOT recognise the store as certified would
    # start a feed sync immediately (RunNow); a certified store waits a full
    # interval, so no "FeedSync: starting" may appear here.
    sleep "${QUAL_CLEAN_RESTART_SETTLE_SECS:-60}"
    # The raw log is captured WITH its read status before any filtering (ASTRA
    # 6360307931 #2): an unreadable log FAILS, it never reads as "quiet".
    lrc=0; klog "$RS_AT" "$EVID/clean-restart.log" || lrc=$?
    rlog="$(grep -oE 'FeedSync: [^"]{0,120}|community category store [^"]{0,100}' "$EVID/clean-restart.log" 2>/dev/null | tr '\n' '|' || true)"
    rec="$(metric culvert_catfeeddb_recovered)"; qcR="$(metric culvert_catfeeddb_quarantined_copies)"
    if v="$(clean_restart_verdict "$lrc" "$EVID/clean-restart.log" "$rec" "$qcF" "$qcR" "$(marker_state)")"; then
      check K clean-restart-after-convergence pass "${v#pass } (settle ${QUAL_CLEAN_RESTART_SETTLE_SECS:-60}s; raw log clean-restart.log); log: ${rlog:-quiet}"
    else
      check K clean-restart-after-convergence fail "${v#fail } (raw log clean-restart.log); log: ${rlog:-none}"
    fi
    # Fresh session after the restart, so a lookup failure can only mean the store.
    api POST /api/auth/login '{"user":"enospcadmin","pass":"Enospc-Qual-2026!x"}' >/dev/null || true
    probe2="$(community_probe "${probe%% *}" || true)"
    if [[ -n "$probe" && "$probe2" == "$probe" ]]; then check K converged-store-persists pass "after the clean restart ${probe%% *} still resolves tier=community '${probe#* }' — the certified store survived the restart"
    else check K converged-store-persists fail "after the clean restart '${probe%% *}' resolves '${probe2:-not community}' (before: '${probe:-none}')"; fi
    final_integrity K post-restart
    quarantine_custody K post-restart   # re-verify the volume after the last restart
  else
    check K clean-restart-after-convergence info "not run: convergence was not PROVEN (verdict=$CONV_VERDICT), so there is no converged state to restart from — the run stays INCONCLUSIVE for convergence (exit 2)"
  fi
  write_report_and_exit
fi

# ── E1: apply with the disk full ─────────────────────────────────────────────
# Wait out the boot-time category-feed sync before filling. On a fresh store
# it bulk-writes ~2.5M entries into BadgerDB, whose memtable and value log are
# sparse mmapped files: a disk that fills DURING that write SIGBUSes the proxy
# (measured on run 37119291924 — `fatal error: fault` in badger's
# logFile.writeEntry). That is a data-plane finding recorded in the readiness
# report, not something this harness qualifies; filling mid-sync would turn
# every E1 probe into a measurement of that race instead of the upgrade path.
# "Is a category feed store configured?" is read from what EVERY release
# shares — the container's own -cat-feed-db argument, or the FeedSync start
# line — never from a log line only newer builds print: E1 runs the
# PREDECESSOR, and keying on `CatFeedDB: BadgerDB at` (absent in v1.0.259)
# skipped this wait and filled the disk mid-sync (run 37121524210).
feed_idle=""
feed_cmd="$(IN docker inspect -f '{{json .Config.Cmd}} {{json .Config.Entrypoint}}' culvert 2>/dev/null || true)"
if [[ "$feed_cmd" == *cat-feed-db* ]] || IN docker logs culvert 2>&1 | grep -q 'FeedSync: starting'; then
  for _ in $(seq 1 120); do
    feed_idle="$(IN docker logs culvert 2>&1 | grep -m1 -oE 'FeedSync: (sync complete[^"]*|download/parse failed|bulk write failed|write REFUSED)' || true)"
    [[ -n "$feed_idle" ]] && break; sleep 5
  done
  if [[ -n "$feed_idle" ]]; then check E1 feed-sync-settled pass "boot-time category sync finished before the fill: ${feed_idle:0:120}"
  else check E1 feed-sync-settled fail "the boot-time category sync did not finish within 600 s; the fill would race it"; diagnose E1-feed-sync; exit 1; fi
else
  check E1 feed-sync-settled pass "no category feed store configured on this stack"
fi
need="$(docker image inspect -f '{{.Size}}' "$CUR_IMAGE")"
why="$(fill_bounded)" || { check E1 fill fail "$why"; exit 1; }
check E1 disk-filled pass "free $(df -k --output=avail "$MNT" | tail -1 | tr -d ' ')KiB on the bounded fs; CUR image size ~$((need/1024))KiB (docker image inspect .Size); outer host untouched (fill is a file inside $IMG)"
# Before any upgrade: does a nearly-full disk ALONE keep the proxy serving?
# (Separates a data-plane reaction to the full disk from anything the
# upgrade does.) The proxy keeps writing /data on the same filesystem; the
# category sync has settled above, so no bulk badger write is in flight.
sleep 15
v0="$(health_version 2>/dev/null || echo unreachable)"
if [[ "$v0" == "$PRED_VER" ]]; then check E1 full-disk-alone-proxy-serving pass "/health 200 version=$v0 15 s after the fill, no upgrade attempted"
else check E1 full-disk-alone-proxy-serving fail "version=$v0 15 s after the fill, BEFORE any upgrade (see diagnose.log)"; diagnose E1-full-disk-alone; fi
OP1="$(apply "$CUR_REF" "eq-full-$RUN_ID")"
j1="$(wait_op "$OP1")"; st1="$(printf '%s' "$j1" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("state"))')"
ag "http://unix/v1/operations/$OP1/logs" > "$EVID/op-full-disk.log" 2>&1 || true
# The agent must refuse BEFORE pulling (preflight_space); pulling onto the
# full disk is what took the running proxy down on the CI runner.
if [[ "$st1" == failed ]] && grep -q "preflight_space: REFUSED" "$EVID/op-full-disk.log" && ! grep -qE $'\tpull\t(START|out)' "$EVID/op-full-disk.log"; then
  check E1 refused-before-pull pass "op=$OP1 state=failed; $(grep -m1 'preflight_space: REFUSED' "$EVID/op-full-disk.log" | tr '\t' ' ' | cut -c1-260)"
else
  check E1 refused-before-pull fail "op=$OP1 state=$st1 (expected a preflight_space refusal with no pull stage); see op-full-disk.log"
fi
[[ "$(running_id)" == "$PRED_ID" ]] && check E1 running-unchanged pass "running image $PRED_ID" || check E1 running-unchanged fail "running=$(running_id) want=$PRED_ID"
[[ "$(IN docker image inspect -f '{{.Id}}' "$PINNED")" == "$PRED_ID" ]] && check E1 pinned-tag-unchanged pass "$PINNED → $PRED_ID" || check E1 pinned-tag-unchanged fail "$PINNED moved"
v="$(health_version 2>/dev/null || echo unreachable)"
if [[ "$v" == "$PRED_VER" ]]; then check E1 health-unchanged pass "/health 200 version=$v"
else
  check E1 health-unchanged fail "version=$v want=$PRED_VER (see diagnose.log)"; diagnose E1-health-failed
  back=none; for i in $(seq 1 45); do curl -fsS -m 3 http://127.0.0.1:18080/health >/dev/null 2>&1 && { back="${i}x2s"; break; }; sleep 2; done
  check E1 health-recovers-by-itself "$([[ $back == none ]] && echo fail || echo pass)" "proxy answered again after $back (still on the full disk)"; diagnose E1-after-wait
fi
c="$(api POST /api/auth/login '{"user":"enospcadmin","pass":"Enospc-Qual-2026!x"}' | tail -n1 || true)"; s="$(state_sum || true)"
[[ "$c" == 200 && "$s" == "$STATE0" ]] && check E1 state-preserved pass "admin login http $c; ui_users.json+ca.bundle digest $s unchanged" || check E1 state-preserved fail "login http $c state=$s want=$STATE0"
fp="$(ca_fp || true)"; [[ "$fp" == "$FP0" ]] && check E1 ca-identity-unchanged pass "root CA sha256 $fp" || check E1 ca-identity-unchanged fail "fp=$fp want=$FP0"
assert_enforcement E1
ag http://unix/v1/status > "$EVID/status-after-enospc.json" 2>&1 || true
check E1 agent-status pass "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print("attention_required=%s interrupted=%d"%(d.get("attention_required"),len(d.get("interrupted_operations") or [])))' "$EVID/status-after-enospc.json" 2>/dev/null || echo unreadable)"

# ── E2: space freed, retry ───────────────────────────────────────────────────
rm -f "${MNT:?}/.qual-fill"
check E2 space-freed pass "free $(df -k --output=avail "$MNT" | tail -1 | tr -d ' ')KiB"
# If the full disk took the proxy down, Docker cannot restart it while the
# disk is full and does not retry afterwards; an operator runs `up`. That
# is recorded (it is the data-plane finding, not the upgrade's), then the
# retry is qualified from a serving stack.
if ! curl -fsS -m 5 http://127.0.0.1:18080/health >/dev/null 2>&1; then
  IN sh -c 'cd /srv/culvert && docker compose up -d' >/dev/null 2>&1 || true
  for _ in $(seq 1 60); do curl -fsS -m 3 http://127.0.0.1:18080/health >/dev/null 2>&1 && break; sleep 2; done
  check E2 operator-up-after-free fail "the proxy was down after the full disk and came back only after a manual 'docker compose up -d' (data-plane finding; see diagnose.log)"
fi
OP2="$(apply "$CUR_REF" "eq-retry-$RUN_ID")"
j2="$(wait_op "$OP2")"; st2="$(printf '%s' "$j2" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("state"))')"
ag "http://unix/v1/operations/$OP2/logs" > "$EVID/op-retry.log" 2>&1 || true
[[ "$st2" == succeeded ]] && check E2 retry-succeeded pass "op=$OP2 state=$st2" || check E2 retry-succeeded fail "$j2"
CUR_ID="$(IN docker image inspect -f '{{.Id}}' "$CUR_REF" 2>/dev/null || echo none)"
[[ "$(running_id)" == "$CUR_ID" && "$CUR_ID" != none ]] && check E2 running-is-target pass "running $CUR_ID ($CUR_REF)" || check E2 running-is-target fail "running=$(running_id) want=$CUR_ID"
for _ in $(seq 1 30); do curl -fsS -m 3 http://127.0.0.1:18080/health >/dev/null 2>&1 && break; sleep 2; done
c="$(api POST /api/auth/login '{"user":"enospcadmin","pass":"Enospc-Qual-2026!x"}' | tail -n1 || true)"
[[ "$c" == 200 ]] && check E2 state-preserved pass "admin login http $c on $(health_version 2>/dev/null)" || check E2 state-preserved fail "http $c"
fp="$(ca_fp || true)"; [[ "$fp" == "$FP0" ]] && check E2 ca-identity-preserved pass "root CA sha256 $fp" || check E2 ca-identity-preserved fail "fp=$fp want=$FP0"
assert_enforcement E2
gate="$(grep -E -m2 'baseline:|health_gate' "$EVID/op-retry.log" | tr '\t\n' '  ' | cut -c1-400)"
grep -q 'baseline: ' "$EVID/op-retry.log" && check E2 agent-ready-gate pass "$gate" || check E2 agent-ready-gate fail "no /ready baseline in the op log: $gate"

write_report_and_exit
