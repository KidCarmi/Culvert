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
#   E1  disk filled to QUAL_ENOSPC_LEAVE_KB free, apply PRED → CUR through
#       POST /v1/upgrades/apply ⇒ the op FAILS at the pull with ENOSPC, the
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
mkdir -p "$EVID"; JSONL="$EVID/checks.jsonl"; MD="$EVID/REPORT.md"; : > "$JSONL"; FAILS=0
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"; DIND="eq-dind-$$"; REG="eq-registry-$$"
IMG="$EVID/appliance-root.img"; MNT="$EVID/mnt"; SOCKDIR="$(mktemp -d /tmp/eqsock.XXXXXX)"; SOCK="$SOCKDIR/agent.sock"
log(){ printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
check(){ local sc="$1" n="$2" r="$3" d="${4:-}"
  python3 -c 'import json,sys; print(json.dumps({"run":sys.argv[1],"scenario":sys.argv[2],"check":sys.argv[3],"result":sys.argv[4],"detail":sys.argv[5]},separators=(",",":")))' "$RUN_ID" "$sc" "$n" "$r" "$d" >> "$JSONL"
  if [[ "$r" == fail ]]; then FAILS=$((FAILS+1)); log "FAIL [$sc] $n: $d"; else log "$r [$sc] $n: $d"; fi; }
CERTSD=""
cleanup(){
  docker rm -f "$DIND" "$REG" >/dev/null 2>&1 || true
  if mountpoint -q "$MNT" 2>/dev/null; then umount "$MNT" || umount -l "$MNT" || true; fi
  rm -f "${IMG:?}"
  rm -f "${SOCKDIR:?}/agent.sock"; rmdir "${SOCKDIR:?}" 2>/dev/null || true
  [[ -n "$CERTSD" ]] && rm -f "${CERTSD:?}/ca.crt" && rmdir "${CERTSD:?}" 2>/dev/null || true
}
trap cleanup EXIT
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

# The nested daemon: its own bridge range so the outer gateway (the registry)
# stays routable from inside; every state directory on the loop filesystem.
docker run -d --privileged --name "$DIND" -e DOCKER_TLS_CERTDIR= \
  -v "$MNT/docker:/var/lib/docker" -v "$MNT/containerd:/var/lib/containerd" \
  -v "$MNT/srv-culvert/culvert:/srv/culvert" -v "$MNT/culvert-maint:/var/lib/culvert-maint" \
  -v "$SOCKDIR:/run/culvert-maint" --mount "type=bind,src=$CERTSD,dst=/etc/docker/certs.d/$REGHOST,readonly" \
  -p 127.0.0.1:18080:8080 -p 127.0.0.1:19090:9090 \
  "$DIND_IMAGE" --bip 10.213.0.1/24 --default-address-pool base=10.214.0.0/16,size=24 >/dev/null
IN(){ docker exec "$DIND" "$@"; }
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

docker save busybox:stable | docker exec -i "$DIND" docker load -q >/dev/null
IN docker pull -q "$PRED_REF" >/dev/null; IN docker tag "$PRED_REF" "$PINNED"
PRED_ID="$(IN docker image inspect -f '{{.Id}}' "$PINNED")"
if IN docker image inspect "$CUR_REF" >/dev/null 2>&1; then check E0 cur-absent fail "CUR already present inside the bounded host"; else check E0 cur-absent pass "CUR not present inside the bounded host — the apply must pull it"; fi

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
assert_enforcement(){ local a b; a="$(through_proxy origin-allowed)"; b="$(through_proxy origin-blocked)"
  if [[ "$a" == 200 && "$b" != 200 && "$b" != 000 ]]; then check "$1" enforcement pass "allowed=$a blocked=$b (default-deny + allow rule, real traffic through the proxy)"; else check "$1" enforcement fail "allowed=$a blocked=$b"; fi; }
ca_fp(){ api GET /api/ca-cert | sed '$d' | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }
health_version(){ curl -fsS -m 5 http://127.0.0.1:18080/health | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])'; }
PRED_VER="$(health_version)"
state_sum(){ IN docker exec culvert sh -c 'cd /data && sha256sum ui_users.json ca.bundle 2>/dev/null' | sha256sum | cut -c1-16; }
STATE0="$(state_sum)"
check E0 seeded-predecessor pass "running $PRED_VER image=$PRED_ID state=$STATE0"
FP0="$(ca_fp)"; [[ -n "$FP0" ]] && check E0 ca-identity pass "root CA sha256 $FP0" || check E0 ca-identity fail "no CA certificate from /api/ca-cert"
assert_enforcement E0

( cd "$ROOT/cmd/culvert-maint" && CGO_ENABLED=0 go build -o "$EVID/culvert-maint" . )
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

# ── E1: apply with the disk full ─────────────────────────────────────────────
need="$(docker image inspect -f '{{.Size}}' "$CUR_IMAGE")"
avail="$(df -k --output=avail "$MNT" | tail -1 | tr -d ' ')"
fill_kb=$(( avail - LEAVE_KB )); (( fill_kb > 0 )) || { check E1 fill fail "only ${avail}KiB available"; exit 1; }
fallocate -l "$((fill_kb * 1024))" "$MNT/.qual-fill"
check E1 disk-filled pass "free $(df -k --output=avail "$MNT" | tail -1 | tr -d ' ')KiB on the bounded fs; CUR image size ~$((need/1024))KiB (docker image inspect .Size); outer host untouched (fill is a file inside $IMG)"
OP1="$(apply "$CUR_REF" "eq-full-$RUN_ID")"
j1="$(wait_op "$OP1")"; st1="$(printf '%s' "$j1" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("state"))')"
ag "http://unix/v1/operations/$OP1/logs" > "$EVID/op-full-disk.log" 2>&1 || true
if [[ "$st1" == failed ]] && grep -qi "no space left on device" "$EVID/op-full-disk.log"; then
  check E1 pull-failed-enospc pass "op=$OP1 state=failed; $(grep -i -m1 'no space left on device' "$EVID/op-full-disk.log" | tr '\t' ' ' | cut -c1-220)"
else
  check E1 pull-failed-enospc fail "op=$OP1 state=$st1 (expected failed with ENOSPC); see op-full-disk.log"
fi
[[ "$(running_id)" == "$PRED_ID" ]] && check E1 running-unchanged pass "running image $PRED_ID" || check E1 running-unchanged fail "running=$(running_id) want=$PRED_ID"
[[ "$(IN docker image inspect -f '{{.Id}}' "$PINNED")" == "$PRED_ID" ]] && check E1 pinned-tag-unchanged pass "$PINNED → $PRED_ID" || check E1 pinned-tag-unchanged fail "$PINNED moved"
# diagnose: what the stack looks like when a probe fails (container state,
# restarts, OOM, recent logs of the proxy and of the bounded host's dockerd,
# free space). Evidence only — never changes the verdict.
diagnose(){ local tag="$1"; {
    echo "== $tag $(date -u +%FT%TZ)"; df -k "$MNT" | tail -1
    IN docker ps -a --format '{{.Names}} {{.Status}}' 2>&1
    IN docker inspect -f 'status={{.State.Status}} restarting={{.State.Restarting}} restarts={{.RestartCount}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}} err={{.State.Error}} started={{.State.StartedAt}}' culvert 2>&1
    echo "-- proxy log"; IN docker logs --tail 40 culvert 2>&1 | cut -c1-300
    echo "-- bounded dockerd log"; docker logs --tail 40 "$DIND" 2>&1 | cut -c1-300
  } >> "$EVID/diagnose.log" 2>&1 || true; }
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

IN cat /var/lib/culvert-maint/agent.log > "$EVID/agent.log" 2>/dev/null || true
{ echo "# Upgrade-under-ENOSPC qualification — run $RUN_ID"; echo
  echo "| artifact | reference |"; echo "|---|---|"
  echo "| image under qualification | \`$CUR_IMAGE\` → \`$CUR_REF\` |"; echo "| predecessor | \`$PRED_IMAGE\` → \`$PRED_REF\` |"
  echo "| bounded host | \`$DIND_IMAGE\`, data root + containerd + stack + agent state on one ${DISK_MB} MiB ext4 loop file (-m 0) |"
  echo "| agent | built from \`cmd/culvert-maint\` at $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown), privilege_mode=docker_group_lab, inside the bounded host |"
  echo; echo "| scenario | check | result | detail |"; echo "|---|---|---|---|"
  python3 - "$JSONL" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    d=json.loads(line); print(f"| {d['scenario']} | {d['check']} | **{d['result'].upper()}** | {d['detail'].replace('|','/').replace(chr(10),' ')[:260]} |")
PY
  echo; echo "Failures: $FAILS"; } > "$MD"
[[ -s "$EVID/diagnose.log" ]] && { log "diagnostics:"; cat "$EVID/diagnose.log" >&2; }
log "evidence: $MD ($FAILS failure(s))"; exit $(( FAILS > 0 ))
