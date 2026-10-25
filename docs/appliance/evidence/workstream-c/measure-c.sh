#!/usr/bin/env bash
# Workstream C measurement: what Compose does when the baked ClamAV tag is
# missing, with and without --no-build, across the container states the
# appliance can be in (running, stopped by culvert-os-update, removed).
#
# The compose files are byte-identical to the integration tree's. Only the
# ClamAV BUILD CONTEXT is replaced with a Dockerfile naming a base that does
# not exist, so any build ATTEMPT fails fast instead of pulling. The tap relay
# in front of dockerd records every API call, so an attempt is visible
# whether or not it would have succeeded.
set -u
W="$(cd "$(dirname "$0")" && pwd)"
S="$(dirname "$W")"
COMPOSE_BIN="${COMPOSE_BIN:?COMPOSE_BIN=path to the docker-compose plugin}"
P="$W/proj"
OUT="${OUT:-$W/measure}"
TAPLOG="$OUT/tap.log"
REF=culvert/clamav:1.5.4-culvert.1
rm -rf "$OUT"; mkdir -p "$OUT"; : > "$TAPLOG"
"$S/b6/tap/tap" /tmp/wscx/p.sock /tmp/wscx/d.sock "$TAPLOG" & TAPPID=$!
trap 'kill $TAPPID 2>/dev/null' EXIT
sleep 0.5
export DOCKER_HOST=unix:///tmp/wscx/p.sock
mkdir -p "$W/cfg/cli-plugins"; ln -sf "$COMPOSE_BIN" "$W/cfg/cli-plugins/docker-compose"
export DOCKER_CONFIG="$W/cfg"
F=(-f "$P/docker-compose.yml" -f "$P/docker-compose.maint-agent.yml")
EXPECT_ID="$(sed -n 's/^CLAMAV_SIDECAR_ID=//p' "$W/guest/manifest.env")"
SUM="$OUT/SUMMARY.txt"
echo "# $(date -u +%FT%TZ) dockerd $(docker version --format '{{.Server.Version}}') compose $(docker compose version --short) ($(sha256sum "$COMPOSE_BIN" | cut -c1-16))" > "$SUM"

compose() { ( cd "$P" && timeout -s KILL 180 docker compose "${F[@]}" "$@" ); }

reset() { # clean slate: no containers, both images present, volume holds a marker
  compose down -v >/dev/null 2>&1
  docker image inspect "$REF" >/dev/null 2>&1 || docker load -q -i "$W/guest/images/clamav.tar.gz" >/dev/null
  compose up -d --no-build >/dev/null 2>&1 || { echo "reset: up failed" >&2; exit 1; }
  printf 'marker-%s\n' "$1" > "$OUT/marker"
  docker cp "$OUT/marker" culvert-clamav:/var/lib/clamav/wsc-marker
}

untag() { docker rmi -f "$REF" >/dev/null 2>&1 || true; }       # tag gone, image kept if a container uses it
purge() { untag; docker image prune -af >/dev/null 2>&1 || true; docker rmi -f culvert/proxy:pinned >/dev/null 2>&1; docker import --change 'ENTRYPOINT ["/stub"]' "$S/b6/stub/stub.tar" culvert/proxy:pinned >/dev/null; }

q() { local o; o=$("$@" 2>/dev/null) && [[ -n "$o" ]] && printf '%s' "$o" || printf absent; }
PROXY="${PROXY:-culvert}"

observe() { # name rc offset
  local name="$1" rc="$2" off="$3" tapcut="$OUT/$1.tap"
  tail -n +"$((off + 1))" "$TAPLOG" > "$tapcut"
  local builds sessions pulls
  builds=$(grep -cE 'REQ POST /v[0-9.]+/build|REQ POST /build' "$tapcut")
  sessions=$(grep -cE 'REQ POST /(v[0-9.]+/)?(session|grpc)' "$tapcut")
  pulls=$(grep -cE 'REQ POST /(v[0-9.]+/)?images/create' "$tapcut")
  local cimg cstate pstate tag vol
  cimg=$(q docker inspect -f '{{.Image}}' culvert-clamav)
  cstate=$(q docker inspect -f '{{.State.Status}}' culvert-clamav)
  pstate=$(q docker inspect -f '{{.State.Status}}' "$PROXY")
  tag=$(q docker image inspect "$REF" --format '{{.Id}}')
  if docker cp culvert-clamav:/var/lib/clamav/wsc-marker "$OUT/$1.marker" >/dev/null 2>&1; then vol=$(cat "$OUT/$1.marker"); else vol=unreadable; fi
  [[ "$cimg" == "$EXPECT_ID" ]] && cimg="EXPECTED" ; [[ "$tag" == "$EXPECT_ID" ]] && tag="EXPECTED"
  printf '%-34s rc=%-3s build_calls=%s session_calls=%s pull_calls=%s clamav=%s(%s) proxy=%s tag=%s volume=%s\n' \
    "$name" "$rc" "$builds" "$sessions" "$pulls" "$cstate" "$cimg" "$pstate" "$tag" "$vol" | tee -a "$SUM"
}

run() { # name -- compose args...
  local name="$1"; shift
  local off rc=0
  off=$(wc -l < "$TAPLOG")
  compose "$@" > "$OUT/$name.out" 2>&1 || rc=$?
  sleep 1
  observe "$name" "$rc" "$off"
}

for mode in plain nobuild; do
  args=(up -d); [[ $mode == nobuild ]] && args+=(--no-build)
  reset "A-$mode";                      run "A-$mode-tag-present"            "${args[@]}"
  reset "B-$mode"; untag;               run "B-$mode-running-tag-missing"    "${args[@]}"
  reset "C-$mode"; compose stop >/dev/null 2>&1; untag
                                        run "C-$mode-stopped-tag-missing"    "${args[@]}"
  reset "D-$mode"; compose down >/dev/null 2>&1; purge
                                        run "D-$mode-removed-image-gone"     "${args[@]}"
done
echo done >> "$SUM"
