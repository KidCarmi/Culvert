#!/usr/bin/env bash
# Workstream C real-docker end-to-end (sandbox dockerd 29.6.2, Compose 5.6.1
# from the signed deb). The sidecar bytes, archive and build-info are the
# FROZEN OVA's (culvert.1, ea362f9b…); the helper is the branch's
# appliance/provision/culvert-clamav-image, run unmodified. Every API call goes
# through a tap so a build/pull attempt is visible whether or not it succeeds;
# the ClamAV build context is replaced with one whose base does not exist, so
# an attempt fails fast instead of fetching.
set -u
W="$(cd "$(dirname "$0")" && pwd)"; S="$(dirname "$W")"
HELPER="$S/integ/appliance/provision/culvert-clamav-image"
P="$W/proj"; OUT="$W/e2e"; TAPLOG="$OUT/tap.log"
REF=culvert/clamav:1.5.4-culvert.1
VOLDIR="$W/dk/root/volumes/proj_clamav-db/_data"
rm -rf "$OUT"; mkdir -p "$OUT"; : > "$TAPLOG"
"$S/b6/tap/tap" /tmp/wscx/p.sock /tmp/wscx/d.sock "$TAPLOG" & TAPPID=$!
trap 'kill $TAPPID 2>/dev/null' EXIT; sleep 0.5
export DOCKER_HOST=unix:///tmp/wscx/p.sock
mkdir -p "$W/cfg561/cli-plugins"; ln -sf "$S/b6/x561/usr/libexec/docker/cli-plugins/docker-compose" "$W/cfg561/cli-plugins/docker-compose"
export DOCKER_CONFIG="$W/cfg561"
EXPECT_ID="$(sed -n 's/^CLAMAV_SIDECAR_ID=//p' "$W/realguest/manifest.env")"
SUM="$OUT/SUMMARY.txt"
echo "# $(date -u +%FT%TZ) dockerd $(docker version --format '{{.Server.Version}}') compose $(docker compose version --short) helper $(sha256sum "$HELPER" | cut -c1-16)" > "$SUM"
# The agent's compose.up argv on a no-build host with the override (pinned by
# TestBuildArgv_ComposeNoBuild), minus the sudo prefix.
AGENT_UP=(docker compose -f "$P/docker-compose.yml" -f "$P/docker-compose.maint-agent.yml" up -d --no-build)
compose() { ( cd "$P" && timeout -s KILL 180 docker compose -f docker-compose.yml -f docker-compose.maint-agent.yml "$@" ); }
q() { local o; o=$("$@" 2>/dev/null) && [[ -n "$o" ]] && printf '%s' "$o" || printf absent; }
calls() { tail -n +"$(( $1 + 1 ))" "$TAPLOG" | grep -cE "$2"; }
helper() { CULVERT_APPLIANCE_STATE_DIR="$1" CULVERT_DOCKER=docker "$HELPER" ensure; }
row() { # name rc off
  local b s p cid cimg pimg tag vol
  b=$(calls "$3" 'REQ POST /(v[0-9.]+/)?build'); s=$(calls "$3" 'REQ POST /(v[0-9.]+/)?(session|grpc)'); p=$(calls "$3" 'REQ POST /(v[0-9.]+/)?images/create')
  cimg=$(q docker inspect -f '{{.Image}}' culvert-clamav); [[ "$cimg" == "$EXPECT_ID" ]] && cimg=EXPECTED
  cid=$(q docker inspect -f '{{.State.Status}}' culvert-clamav)
  pimg=$(q docker inspect -f '{{.Image}}' culvert); pimg=${pimg:7:12}
  tag=$(q docker image inspect "$REF" --format '{{.Id}}'); [[ "$tag" == "$EXPECT_ID" ]] && tag=EXPECTED
  vol=$(cat "$VOLDIR/wsc-e2e-marker" 2>/dev/null || echo MISSING)
  printf '%-44s rc=%-3s build=%s session=%s pull=%s clamav=%s(%s) proxy_img=%s tag=%s volume=%s\n' "$1" "$2" "$b" "$s" "$p" "$cid" "$cimg" "$pimg" "$tag" "$vol" | tee -a "$SUM"
}
step() { # name -- cmd...
  local name="$1"; shift; local off rc=0; off=$(wc -l < "$TAPLOG")
  "$@" > "$OUT/$name.out" 2>&1 || rc=$?; sleep 1; row "$name" "$rc" "$off"
}

# Two distinct proxy images: the "current" and the "target" of an agent apply.
docker rmi -f culvert/proxy:pinned culvert/proxy:e2e-a culvert/proxy:e2e-b >/dev/null 2>&1
docker import --change 'ENTRYPOINT ["/stub"]' --change 'LABEL v=a' "$S/b6/stub/stub.tar" culvert/proxy:e2e-a >/dev/null
docker import --change 'ENTRYPOINT ["/stub"]' --change 'LABEL v=b' "$S/b6/stub/stub.tar" culvert/proxy:e2e-b >/dev/null
docker tag culvert/proxy:e2e-a culvert/proxy:pinned
echo "proxy a=$(docker image inspect -f '{{.Id}}' culvert/proxy:e2e-a | cut -c8-19) b=$(docker image inspect -f '{{.Id}}' culvert/proxy:e2e-b | cut -c8-19)" | tee -a "$SUM"

# Clean slate from the verified archive, then a volume marker.
compose down -v >/dev/null 2>&1
docker rmi -f "$REF" >/dev/null 2>&1; docker image prune -f >/dev/null 2>&1
step 00-helper-initial-load helper "$W/realguest"
step 01-agent-up-baseline "${AGENT_UP[@]}"
echo "e2e-$(date +%s)" > "$VOLDIR/wsc-e2e-marker"; MARK=$(cat "$VOLDIR/wsc-e2e-marker")
echo "marker=$MARK" | tee -a "$SUM"

# E1 apply then rollback through the agent argv, sidecar present.
docker tag culvert/proxy:e2e-b culvert/proxy:pinned
CL1=$(docker inspect -f '{{.Id}}' culvert-clamav)
step 10-apply-agent-up "${AGENT_UP[@]}"
[[ "$(docker inspect -f '{{.Id}}' culvert-clamav)" == "$CL1" ]] && echo "10: clamav container untouched by apply" | tee -a "$SUM"
docker tag culvert/proxy:e2e-a culvert/proxy:pinned
step 11-rollback-agent-up "${AGENT_UP[@]}"

# E2 the agent preflight's evidence: what the real daemon says for an absent tag.
docker rmi -f "$REF" >/dev/null 2>&1
docker image inspect "$REF" > "$OUT/20-inspect.out" 2> "$OUT/20-inspect.err"; echo "20-inspect-absent rc=$? stderr=$(head -c 120 "$OUT/20-inspect.err")" | tee -a "$SUM"
grep -qiE 'no such (image|object)' "$OUT/20-inspect.err" && echo "20: matches imageNotFoundRE" | tee -a "$SUM"
step 21-agent-up-while-tag-missing "${AGENT_UP[@]}"
step 22-helper-restores-running helper "$W/realguest"

# E3 maintenance path (culvert-os-update shape): stop, lose the tag, ensure, up --no-build.
step 30-stack-stop compose stop
docker rmi -f "$REF" >/dev/null 2>&1
step 31-helper-ensure-after-stop helper "$W/realguest"
step 32-up-no-build-after-stop compose up -d --no-build

# E4 whole image store lost (engine upgrade worst case): containers removed, images pruned, volumes kept.
step 40-down-keep-volumes compose down
docker rmi -f "$REF" >/dev/null 2>&1; docker image prune -af >/dev/null 2>&1
docker import --change 'ENTRYPOINT ["/stub"]' --change 'LABEL v=a' "$S/b6/stub/stub.tar" culvert/proxy:pinned >/dev/null
step 41-helper-ensure-after-loss helper "$W/realguest"
step 42-up-no-build-after-loss compose up -d --no-build

# E5 refusal: same loss, archive tampered -> helper refuses, up --no-build fails, nothing built, volume kept.
step 50-down-keep-volumes compose down
docker rmi -f "$REF" >/dev/null 2>&1; docker image prune -af >/dev/null 2>&1
docker import --change 'ENTRYPOINT ["/stub"]' --change 'LABEL v=a' "$S/b6/stub/stub.tar" culvert/proxy:pinned >/dev/null
T="$OUT/tampered"; mkdir -p "$T/images"; cp "$W/realguest/manifest.env" "$W/realguest/build-info.json" "$T/"
cp "$W/realguest/images/clamav.tar.gz" "$T/images/"; printf 'X' | dd of="$T/images/clamav.tar.gz" bs=1 seek=4096 conv=notrunc status=none
step 51-helper-refuses-tampered helper "$T"
cat "$T/clamav-image.state" | tee -a "$SUM"
step 52-up-no-build-refused compose up -d --no-build
rm -f "$T/images/clamav.tar.gz"
step 53-helper-refuses-missing-archive helper "$T"
grep reason "$T/clamav-image.state" | tee -a "$SUM"
step 54-recover-real-archive helper "$W/realguest"
step 55-up-after-recover compose up -d --no-build
echo "final marker expected=$MARK got=$(cat "$VOLDIR/wsc-e2e-marker" 2>/dev/null)" | tee -a "$SUM"
compose down -v >/dev/null 2>&1
echo done >> "$SUM"
