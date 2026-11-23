#!/usr/bin/env bash
# Real-Docker probe of the lifecycle model's fake-exec assumptions (manual / scheduled;
# never a PR gate). Needs a running Docker daemon with the compose plugin, Go, curl and
# python3; pulls nothing from Docker Hub: the registry is built from source and both probe
# images are built FROM scratch.
#   usage: test/lifecycle-conformance/docker-probe.sh [registry port, default 5000]
#
# It reproduces the maintenance agent's own argv (internal/runner/templates_upgrade.go,
# templates_d16b.go) and reports, for each fault outcome the model injects, what real Docker
# does:
#   docker tag <repo>@sha256:<d> culvert/proxy:pinned
#   docker compose -f <compose> [-f <override>] up -d
#   docker inspect --format '{{json .Image}}' <container>     (identity the agent journals)
#   docker image inspect <image>                              (RepoDigests)
# Run it once per image store (containerd store: Docker 29 default for fresh installs;
# classic: daemon.json {"features":{"containerd-snapshotter":false}}).
set -uo pipefail
PORT="${1:-5000}"
REG="localhost:$PORT"; REPO="$REG/probe"
W="$(mktemp -d)"; P="$W/proj"; mkdir -p "$P" "$W/app" "$W/regdata"
REGPID=""; HOLDER=""
cleanup() {
  docker compose -f "$P/docker-compose.yml" down --remove-orphans >/dev/null 2>&1
  docker rm -f probe-sidecar >/dev/null 2>&1
  [ -n "$HOLDER" ] && kill "$HOLDER" 2>/dev/null
  [ -n "$REGPID" ] && kill "$REGPID" 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT
docker info >/dev/null 2>&1 || { echo "INCOMPLETE: no Docker daemon"; exit 2; }
echo "docker $(docker version --format '{{.Server.Version}}') / $(docker compose version --short) / storage $(docker info --format '{{.Driver}}')"

# ── registry (from source) and two distinct images (FROM scratch) ───────────────────────
GOBIN="$W/bin" CGO_ENABLED=0 GOFLAGS=-mod=mod go install github.com/distribution/distribution/v3/cmd/registry@v3.0.0 || exit 2
printf 'version: 0.1\nstorage:\n  filesystem:\n    rootdirectory: %s\nhttp:\n  addr: 127.0.0.1:%s\n' "$W/regdata" "$PORT" > "$W/registry.yml"
"$W/bin/registry" serve "$W/registry.yml" > "$W/registry.log" 2>&1 & REGPID=$!
for _ in $(seq 1 20); do curl -fs "http://127.0.0.1:$PORT/v2/" >/dev/null && break; sleep 0.5; done
cat > "$W/app/main.go" <<'EOF'
package main

import (
	"fmt"
	"net/http"
	"os"
)

var version = "dev"

func main() {
	h := func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, version) }
	http.HandleFunc("/health", h)
	http.HandleFunc("/ready", h)
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_ = http.ListenAndServe(addr, nil)
}
EOF
printf 'module probeapp\n\ngo 1.25\n' > "$W/app/go.mod"
printf 'FROM scratch\nCOPY app /app\nENTRYPOINT ["/app"]\n' > "$W/app/Dockerfile"
for v in v1 v2; do
  (cd "$W/app" && CGO_ENABLED=0 go build -ldflags "-X main.version=$v" -o app . && docker build -q -t "$REPO:$v" . >/dev/null) || exit 2
  docker push -q "$REPO:$v" >/dev/null || exit 2
done
digest() { curl -fsI -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
  "http://127.0.0.1:$PORT/v2/probe/manifests/$1" | awk 'tolower($1)=="docker-content-digest:"{print $2}' | tr -d '\r'; }
D1=$(digest v1); D2=$(digest v2)
docker rmi -f "$REPO:v1" "$REPO:v2" >/dev/null 2>&1   # re-pull by digest, as a customer host does
docker pull -q "$REPO@$D1" >/dev/null && docker pull -q "$REPO@$D2" >/dev/null || exit 2

# ── compose project mirroring the proxy service ─────────────────────────────────────────
cat > "$P/docker-compose.yml" <<'EOF'
name: probe
services:
  proxy:
    image: culvert/proxy:pinned
    container_name: probe-proxy
    restart: unless-stopped
EOF
# up fails BEFORE touching the proxy: a sibling service whose image cannot be pulled.
printf 'services:\n  sidecar:\n    image: %s/does-not-exist:1\n' "$REG" > "$P/override-unpullable.yml"
# up fails AFTER recreating the proxy: a sibling started after it cannot bind its port.
cat > "$P/override-portclash.yml" <<'EOF'
services:
  sidecar:
    image: culvert/proxy:pinned
    container_name: probe-sidecar
    depends_on: [proxy]
    environment: [ADDR=:9090]
    ports: ["127.0.0.1:18089:9090"]
EOF
printf 'services:\n  proxy: [unterminated\n' > "$P/override-broken.yml"

C=(docker compose -f "$P/docker-compose.yml")
cid()   { docker ps -aq --no-trunc --filter name=^probe-proxy$; }
cimg()  { local c; c=$(cid); if [ -n "$c" ]; then docker inspect --format '{{json .Image}}' "$c" | tr -d '"'; else echo none; fi; }
ID1=""; ID2=""
role()  { case "$1" in "$ID1") echo P;; "$ID2") echo T;; none|"") echo none;; *) echo "?";; esac; }
tagimg(){ docker image inspect --format '{{.Id}}' culvert/proxy:pinned 2>/dev/null || echo none; }
retag() { docker tag "$REPO@$1" culvert/proxy:pinned; }
reset() { "${C[@]}" down --remove-orphans >/dev/null 2>&1; docker rm -f probe-sidecar >/dev/null 2>&1; retag "$D1"; "${C[@]}" up -d >/dev/null 2>&1; }
row()   { printf '%-34s | rc=%-3s | container %-4s -> %-4s | recreated=%-3s | tag=%s\n' "$1" "$2" "$3" "$4" "$5" "$(role "$(tagimg)")"; }
ID1=$(docker image inspect --format '{{.Id}}' "$REPO@$D1"); ID2=$(docker image inspect --format '{{.Id}}' "$REPO@$D2")

echo; echo "== identity: what the agent journals =="
reset; img=$(cimg)
echo "container .Image  : $img"
echo "registry digest   : $D1"
if [ "$img" = "$D1" ]; then echo "=> .Image IS the registry (index) digest (containerd image store)"
else echo "=> .Image is the image CONFIG digest, distinct from the registry digest (classic store)"; fi
echo "RepoDigests       : $(docker image inspect --format '{{json .RepoDigests}}' "$img")"

echo; echo "== A. tag moved, up -d exits 0: is the container recreated? (model ok vs ok_stale) =="
stale=0; for i in $(seq 1 10); do
  reset; b=$(cid); retag "$D2"; "${C[@]}" up -d >/dev/null 2>&1; [ "$(cid)" = "$b" ] && stale=$((stale+1))
done; echo "ok_stale observed in $stale of 10 trials"

echo; echo "== B. tag unchanged, up -d =="
reset; b=$(cid); "${C[@]}" up -d >/dev/null 2>&1; rc=$?; [ "$(cid)" != "$b" ] && rec=yes || rec=no
row "B up -d, tag unchanged" "$rc" P "$(role "$(cimg)")" "$rec"

echo; echo "== C. up fails before touching the proxy (model up_fail_stale) =="
for o in unpullable broken; do
  reset; b=$(cid); retag "$D2"; "${C[@]}" -f "$P/override-$o.yml" up -d >/dev/null 2>&1; rc=$?
  [ "$(cid)" != "$b" ] && rec=yes || rec=no
  row "C-$o: tag P->T, up -d" "$rc" P "$(role "$(cimg)")" "$rec"
done

echo; echo "== D. up fails after recreating the proxy (model up_fail_recreated) =="
python3 -c 'import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",18089));s.listen();time.sleep(120)' &
HOLDER=$!; sleep 1
reset; b=$(cid); retag "$D2"; "${C[@]}" -f "$P/override-portclash.yml" up -d >/dev/null 2>&1; rc=$?
[ "$(cid)" != "$b" ] && rec=yes || rec=no
row "D portclash: tag P->T, up -d" "$rc" P "$(role "$(cimg)")" "$rec"

echo; echo "== E. a local tag whose registry reference is gone (model prior=nodigest) =="
docker tag "$REPO@$D1" culvert/local-only:x; docker rmi -f "$REPO@$D1" >/dev/null 2>&1
echo "RepoDigests: $(docker image inspect --format '{{json .RepoDigests}}' culvert/local-only:x)"
docker rmi -f culvert/local-only:x >/dev/null 2>&1
