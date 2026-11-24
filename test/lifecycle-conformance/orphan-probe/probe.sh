#!/usr/bin/env bash
# Real-Docker / real-systemd probe of the maintenance agent's crash behaviour (manual;
# never a PR gate). It answers the questions orphan_survival_crash_test.go could only
# model: when the agent is SIGKILLed with a docker command in flight, what do systemd,
# sudo, the docker CLI and dockerd really do, and can a later operation be overwritten?
#
#   usage: test/lifecycle-conformance/orphan-probe/probe.sh [--converge] [--quick] [agent binary]
#
#   --converge   also run the kill points with reconcile_on_startup = "converge". Needs an
#                agent that knows the key (#2039); with any other agent this is INCOMPLETE.
#   --only-converge  run nothing but the convergence part.
#   --quick      a reduced matrix (smoke run; not evidence).
#   ORPHAN_PROBE_OUT=<dir>  copy the per-trial records (JSONL) there.
#
# Needs root, a running Docker daemon with the compose plugin, Go, python3, curl, openssl,
# and a host with systemd and sudo installed under /usr (the systemd it runs is the host's
# own binary, inside a privileged container — no systemd on the host is touched and nothing
# is pulled from a registry). Verified on Ubuntu 24.04, systemd 255, sudo 1.9.15, Docker
# 29.10.0, Compose v5.7.1.
#
# What it changes on the host, and removes again: the fixed tag culvert/proxy:pinned, two
# probe images, containers of the compose project "orphanprobe", a registry certificate
# under /etc/docker/certs.d/127.0.0.1:<port>, one loopback port for the probe proxy, and a
# local image built from the host's /usr layout and a copy of /etc without password hashes and
# the usual private-key locations (best effort; the image is removed on exit, treat it as
# sensitive). With ORPHAN_PROBE_PROXY_BIN_* the real proxy and its plain-HTTP admin UI listen
# on ALL interfaces of this host (host network) while the probe runs: a disposable machine only. If the script is SIGKILLed, remove those by hand (the image is
# orphanprobe-sysd-base:1, the work directory /var/tmp/orphan-probe.*).
# It REFUSES to run where culvert/proxy:pinned already exists: that is somebody's Culvert.
#
# Exit: 0 every safety property held on every trial; 1 a property was violated;
#       2 incomplete (a prerequisite, a trial or a control did not run as intended).
set -uo pipefail
CONVERGE=0; ONLY_CONVERGE=0; QUICK=0; AGENT_BIN=""
for a in "$@"; do
  case "$a" in
    --converge) CONVERGE=1 ;;
    --only-converge) CONVERGE=1; ONLY_CONVERGE=1 ;;
    --quick) QUICK=1 ;;
    -*) echo "INCOMPLETE: unknown option $a"; exit 2 ;;
    *) AGENT_BIN="$a" ;;
  esac
done
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../../.." && pwd)"
REG_PORT="${ORPHAN_PROBE_REGISTRY_PORT:-5000}"; APP_PORT="${ORPHAN_PROBE_APP_PORT:-18080}"
# ORPHAN_PROBE_SETTLE: write interrupted_settle = <value> into the agent's config (only for an
# agent that knows the key; unset = the agent's own default, 75s). An agent with the settle
# wait holds every tag+recreate until that long after its start, so each trial costs up to
# twice the window. ORPHAN_PROBE_STOP_GRACE: the proxy's stop_grace_period (60s as shipped).
# To shorten a run, scale both and keep settle > stop grace > the proxy's drain, e.g.
# ORPHAN_PROBE_SETTLE=20s ORPHAN_PROBE_STOP_GRACE=15s: the relation the agent relies on is
# the same, the wall clock is not.
SETTLE="${ORPHAN_PROBE_SETTLE:-}"; STOP_GRACE="${ORPHAN_PROBE_STOP_GRACE:-60s}"
# ORPHAN_PROBE_PROXY_IMAGE_V1 / _V2: use two already-built Culvert RELEASE images (built by the
# repository's Dockerfile with --build-arg VERSION=probe-v1 / probe-v2) as the proxy, with the
# image's own user, entrypoint and default command. The proxy then listens where the release
# image listens: 8080 (proxy, /health, /ready) and 9090 (admin UI, HTTPS), on the host network.
IMG_V1="${ORPHAN_PROBE_PROXY_IMAGE_V1:-}"; IMG_V2="${ORPHAN_PROBE_PROXY_IMAGE_V2:-}"; UI_PORT=""; UI_TLS=0
if [ -n "$IMG_V1$IMG_V2" ]; then APP_PORT=8080; UI_PORT=9090; UI_TLS=1; fi
REAL_SOCK="${ORPHAN_PROBE_DOCKER_SOCK:-/var/run/docker.sock}"
SYSD=orphanprobe-sysd; PROJECT=orphanprobe; CNAME=orphanprobe-proxy; BASE=orphanprobe-sysd-base:1
CERT_DIR="/etc/docker/certs.d/127.0.0.1:$REG_PORT"
REPO_IMG="127.0.0.1:$REG_PORT/culvert"
export DOCKER_HOST="unix://$REAL_SOCK"
inc() { echo "INCOMPLETE: $*"; exit 2; }

[ "$(id -u)" -eq 0 ] || inc "must run as root"
case "$REG_PORT$APP_PORT" in *[!0-9]*|"") inc "ports must be numeric" ;; esac
for c in docker go python3 curl openssl sudo visudo tar; do command -v "$c" >/dev/null 2>&1 || inc "missing command: $c"; done
[ -x /lib/systemd/systemd ] || inc "no systemd binary at /lib/systemd/systemd"
docker info >/dev/null 2>&1 || inc "no Docker daemon"
docker compose version >/dev/null 2>&1 || inc "no compose plugin"
docker image inspect culvert/proxy:pinned >/dev/null 2>&1 && inc "culvert/proxy:pinned exists on this daemon; refusing to touch a real Culvert"
[ -e "$CERT_DIR" ] && inc "$CERT_DIR exists; choose another ORPHAN_PROBE_REGISTRY_PORT"
curl -s -m 1 "http://127.0.0.1:$APP_PORT/" >/dev/null 2>&1 && inc "port $APP_PORT is in use"
if [ -n "$UI_PORT" ]; then (exec 3<>"/dev/tcp/127.0.0.1/$UI_PORT") 2>/dev/null && inc "port $UI_PORT is in use"; fi
if [ -n "$IMG_V1$IMG_V2" ]; then
  docker image inspect "$IMG_V1" >/dev/null 2>&1 && docker image inspect "$IMG_V2" >/dev/null 2>&1 || inc "both ORPHAN_PROBE_PROXY_IMAGE_V1 and _V2 must name local images"
  docker volume inspect orphanprobe-data >/dev/null 2>&1 && inc "docker volume orphanprobe-data already exists"
fi
(exec 3<>"/dev/tcp/127.0.0.1/$REG_PORT") 2>/dev/null && inc "port $REG_PORT is in use; choose another ORPHAN_PROBE_REGISTRY_PORT"

# Ownership: this run removes only what this run created. Everything it is about to create
# must not exist yet (checked here), and each OWN_* flag is set at the moment of creation.
docker inspect "$SYSD" >/dev/null 2>&1 && inc "a container named $SYSD already exists; a previous run was killed? remove it by hand"
[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ] || inc "containers of compose project $PROJECT already exist"
for img in "$BASE" "$REPO_IMG:v1" "$REPO_IMG:v2"; do
  docker image inspect "$img" >/dev/null 2>&1 && inc "image $img already exists; refusing to overwrite or delete it"
done
W="$(mktemp -d /var/tmp/orphan-probe.XXXXXX)" || inc "mktemp failed"
case "$W" in /var/tmp/orphan-probe.??????) ;; *) inc "unexpected work directory: $W" ;; esac
REGPID=""; PROXYPID=""; OWN_CERT=0; OWN_TAG=0; OWN_BASE=0; OWN_SYSD=0; OWN_IMG=""; OWN_VOL=0
mkdir -p "$W"/{app,regdata,certs,root/etc,srv,ul,p,ev,bin}
cleanup() {
  trap - EXIT INT TERM
  if [ "$OWN_SYSD" = 1 ]; then
    # The agent first: while it lives it can recreate the proxy container.
    docker rm -f "$SYSD" >/dev/null 2>&1
    ids="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null)"
    [ -n "$ids" ] && docker rm -f $ids >/dev/null 2>&1
  fi
  [ -n "$PROXYPID" ] && kill "$PROXYPID" 2>/dev/null
  [ -n "$REGPID" ] && kill "$REGPID" 2>/dev/null
  [ "$OWN_VOL" = 1 ] && docker volume rm orphanprobe-data >/dev/null 2>&1
  [ "$OWN_TAG" = 1 ] && docker rmi culvert/proxy:pinned >/dev/null 2>&1
  for img in $OWN_IMG; do docker rmi "$img" >/dev/null 2>&1; done
  [ "$OWN_BASE" = 1 ] && docker rmi "$BASE" >/dev/null 2>&1
  [ "$OWN_CERT" = 1 ] && rm -f "$CERT_DIR/ca.crt" && rmdir "$CERT_DIR" 2>/dev/null
  rm -rf "$W/root"   # the /etc copy never outlives the run, kept or not
  if [ "${ORPHAN_PROBE_KEEP:-0}" = 1 ]; then echo "kept: $W"; else rm -rf "$W"; fi
  left=""
  docker inspect "$SYSD" >/dev/null 2>&1 && left="$left container:$SYSD"
  [ "$OWN_SYSD" = 1 ] && [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null)" ] && left="$left containers-of:$PROJECT"
  for img in $OWN_IMG; do docker image inspect "$img" >/dev/null 2>&1 && left="$left image:$img"; done
  docker image inspect culvert/proxy:pinned >/dev/null 2>&1 && [ "$OWN_TAG" = 1 ] && left="$left tag:culvert/proxy:pinned"
  docker image inspect "$BASE" >/dev/null 2>&1 && left="$left image:$BASE"
  [ -e "$CERT_DIR" ] && [ "$OWN_CERT" = 1 ] && left="$left $CERT_DIR"
  [ -n "$left" ] && echo "CLEANUP-INCOMPLETE:$left"
  return 0
}
trap cleanup EXIT
trap 'echo "INCOMPLETE: interrupted"; exit 2' INT TERM

echo "settle=${SETTLE:-agent default} stop_grace=$STOP_GRACE"
echo "docker $(docker version --format '{{.Server.Version}}') / compose $(docker compose version --short) / storage $(docker info --format '{{.Driver}}') / $(/lib/systemd/systemd --version | head -1) / $(sudo -V | head -1)"

# ── agent, registry (from source, TLS: `docker manifest inspect` insists), two images ────
if [ -z "$AGENT_BIN" ]; then
  AGENT_BIN="$W/bin/culvert-maint"
  (cd "$REPO/cmd/culvert-maint" && CGO_ENABLED=0 go build -o "$AGENT_BIN" .) || inc "agent build failed"
fi
[ -x "$AGENT_BIN" ] || inc "agent binary not executable: $AGENT_BIN"
# The registry is fetched and built from source; the Go module proxy and checksum server
# fail now and then (HTTP/2 stream errors). Three attempts, then the last error is shown.
registry_ok=0
for attempt in 1 2 3; do
  if GOBIN="$W/bin" CGO_ENABLED=0 GOFLAGS=-mod=mod go install github.com/distribution/distribution/v3/cmd/registry@v3.0.0 2>"$W/registry-build.log"; then
    registry_ok=1; break
  fi
  echo "registry build: attempt $attempt failed: $(tail -1 "$W/registry-build.log")"
  sleep $((attempt * 20))
done
[ "$registry_ok" = 1 ] || { tail -5 "$W/registry-build.log"; inc "registry build failed"; }
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/certs/r.key" -out "$W/certs/r.crt" -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null || inc "openssl failed"
printf 'version: 0.1\nstorage:\n  filesystem:\n    rootdirectory: %s\nhttp:\n  addr: 127.0.0.1:%s\n  tls:\n    certificate: %s\n    key: %s\n' \
  "$W/regdata" "$REG_PORT" "$W/certs/r.crt" "$W/certs/r.key" > "$W/registry.yml"
"$W/bin/registry" serve "$W/registry.yml" > "$W/registry.log" 2>&1 & REGPID=$!
mkdir -p "$(dirname "$CERT_DIR")" && mkdir "$CERT_DIR" || inc "could not create $CERT_DIR"
OWN_CERT=1; cp "$W/certs/r.crt" "$CERT_DIR/ca.crt"
for _ in $(seq 1 30); do curl -fs --cacert "$W/certs/r.crt" "https://127.0.0.1:$REG_PORT/v2/" >/dev/null && break; sleep 0.5; done
curl -fs --cacert "$W/certs/r.crt" "https://127.0.0.1:$REG_PORT/v2/" >/dev/null || inc "registry did not come up"

cat > "$W/app/main.go" <<'GO'
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

var version = "dev"

var stopping atomic.Bool

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:"+os.Getenv("APP_PORT"))
	if err != nil {
		os.Exit(1)
	}
	h := func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, version) }
	http.HandleFunc("/health", h)
	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if stopping.Load() && os.Getenv("STOP_SERVE") == "notready" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		h(w, r)
	})
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM)
		<-c
		stopping.Store(true)
		// A proxy draining for STOP_DELAY seconds. STOP_SERVE says what a probe
		// sees meanwhile: serving (200 everywhere), notready (/ready 503),
		// closed (the listener is gone).
		if os.Getenv("STOP_SERVE") == "closed" {
			_ = ln.Close()
		}
		d, _ := strconv.Atoi(os.Getenv("STOP_DELAY"))
		time.Sleep(time.Duration(d) * time.Second)
		os.Exit(0)
	}()
	_ = http.Serve(ln, nil)
	select {}
}
GO
printf 'module probeapp\n\ngo 1.25\n' > "$W/app/go.mod"
printf 'FROM scratch\nCOPY app /app\nENTRYPOINT ["/app"]\n' > "$W/Dockerfile"
# ORPHAN_PROBE_PROXY_BIN_V1 / _V2: use the real Culvert proxy instead of the stand-in. Each
# is a static culvert binary built with -ldflags "-X main.version=probe-v1" (resp. -v2).
# The image is that binary alone (FROM scratch), not the release image's Alpine layers.
REAL_PROXY=0
[ -n "$IMG_V1$IMG_V2" ] && REAL_PROXY=2
if [ "$REAL_PROXY" = 0 ] && { [ -n "${ORPHAN_PROBE_PROXY_BIN_V1:-}" ] || [ -n "${ORPHAN_PROBE_PROXY_BIN_V2:-}" ]; }; then
  [ -x "${ORPHAN_PROBE_PROXY_BIN_V1:-}" ] && [ -x "${ORPHAN_PROBE_PROXY_BIN_V2:-}" ] || inc "both ORPHAN_PROBE_PROXY_BIN_V1 and _V2 must be executable files"
  (exec 3<>"/dev/tcp/127.0.0.1/$((APP_PORT + 1))") 2>/dev/null && inc "port $((APP_PORT + 1)) (admin UI) is in use"
  REAL_PROXY=1
  printf 'FROM scratch\nCOPY app /app\nWORKDIR /data\nENTRYPOINT ["/app"]\n' > "$W/Dockerfile"
fi
for v in v1 v2; do
  if [ "$REAL_PROXY" = 2 ]; then
    # The release image as built: only re-tagged into the probe's registry.
    if [ "$v" = v1 ]; then src="$IMG_V1"; else src="$IMG_V2"; fi
    docker tag "$src" "$REPO_IMG:$v" || inc "could not tag $src"
    OWN_IMG="$OWN_IMG $REPO_IMG:$v"
    docker push -q "$REPO_IMG:$v" >/dev/null || inc "push failed"
    docker image inspect "$REPO_IMG:$v" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep "^$REPO_IMG@sha256:" | head -1 > "$W/ref-$v"
    [ -s "$W/ref-$v" ] || inc "no registry digest for $v"
    continue
  fi
  mkdir -p "$W/ctx-$v"; cp "$W/Dockerfile" "$W/ctx-$v/"
  if [ "$REAL_PROXY" = 1 ]; then
    if [ "$v" = v1 ]; then cp "$ORPHAN_PROBE_PROXY_BIN_V1" "$W/ctx-$v/app"; else cp "$ORPHAN_PROBE_PROXY_BIN_V2" "$W/ctx-$v/app"; fi
  else
    (cd "$W/app" && CGO_ENABLED=0 go build -ldflags "-X main.version=$v" -o "$W/ctx-$v/app" .) || inc "probe app build failed"
  fi
  docker build -q -t "$REPO_IMG:$v" "$W/ctx-$v" >/dev/null || inc "image build failed"
  OWN_IMG="$OWN_IMG $REPO_IMG:$v"
  docker push -q "$REPO_IMG:$v" >/dev/null || inc "push failed"
  docker image inspect "$REPO_IMG:$v" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep "^$REPO_IMG@sha256:" | head -1 > "$W/ref-$v"
  [ -s "$W/ref-$v" ] || inc "no registry digest for $v"
done
[ "$(cat "$W/ref-v1")" != "$(cat "$W/ref-v2")" ] || inc "v1 and v2 have the same digest"

# The production compose file gives the proxy stop_grace_period: 60s and
# restart: unless-stopped (docker-compose.yml); both matter here and are kept.
cat > "$W/srv/docker-compose.yml" <<YML
name: $PROJECT
services:
  proxy:
    image: culvert/proxy:pinned
    container_name: $CNAME
    restart: unless-stopped
    network_mode: host
    stop_grace_period: $STOP_GRACE
    environment:
      STOP_DELAY: "\${STOP_DELAY:-0}"
      APP_PORT: "\${APP_PORT:-$APP_PORT}"
      STOP_SERVE: "\${STOP_SERVE:-serving}"
YML
# ORPHAN_PROBE_CP=1 (real proxy only): run the proxy as a control plane (-cp-grpc-addr) and,
# in the slices that hold the shutdown open, hold it with a control-plane gRPC connection
# instead of an admin-UI request. That is the longest the proxy's listener stays up after
# SIGTERM (the gRPC graceful stop takes its 8 s budget), so an image whose /ready still says
# 200 while it drains says so for about 9 s, well past the unit's 5 s restart delay.
CP="${ORPHAN_PROBE_CP:-0}"; HOLD=uihold; CP_ARGS_YAML=""; IMAGE_COMMAND_YAML=""
if [ "$CP" = 1 ]; then
  [ "$REAL_PROXY" != 0 ] || inc "ORPHAN_PROBE_CP needs the real proxy (binary or image)"
  HOLD=cphold; CP_PORT=$((APP_PORT + 71)); export PROBE_CP_PORT="$CP_PORT"
  CP_ARGS_YAML=", \"-cp-grpc-addr\", \"127.0.0.1:$CP_PORT\", \"-cluster-insecure\", \"-cluster-db\", \"/data/cluster.json\""
  if [ "$REAL_PROXY" = 2 ]; then
    # The release image keeps its own command; the control-plane flags are added to it.
    base_cmd="$(docker image inspect --format '{{json .Config.Cmd}}' "$IMG_V1")" || inc "could not read the image's command"
    case "$base_cmd" in \[*\]) ;; *) inc "unexpected image command: $base_cmd" ;; esac
    IMAGE_COMMAND_YAML="    command: ${base_cmd%]}$CP_ARGS_YAML]"
  fi
fi
if [ "$REAL_PROXY" = 1 ]; then
  UI_PORT=$((APP_PORT + 1))
  # The real proxy: its own flags (as test/e2e/maint-agent/docker-compose.e2e.yml), plain-HTTP
  # admin UI on APP_PORT+1, state on a tmpfs. Same stop_grace_period and restart policy.
  cat > "$W/srv/docker-compose.yml" <<YML
name: $PROJECT
services:
  proxy:
    image: culvert/proxy:pinned
    container_name: $CNAME
    restart: unless-stopped
    network_mode: host
    stop_grace_period: $STOP_GRACE
    tmpfs: [/data, /tmp]
    environment:
      CULVERT_SESSION_SECRET: "$(openssl rand -hex 32)"
    command: ["-port", "$APP_PORT", "-ui-port", "$((APP_PORT + 1))", "-ui-no-tls",
      "-ca-path", "/data/ca.bundle", "-policy", "/data/policy.json", "-logfile", "/data/proxy.log",
      "-audit-log", "/data/audit.jsonl", "-request-log", "/data/requests.jsonl",
      "-threat-feed-db", "/data/threatfeeds.json", "-ui-users-file", "/data/ui_users.json"$CP_ARGS_YAML]
YML
fi
if [ "$REAL_PROXY" = 2 ]; then
  # The release image with its own default command (Dockerfile CMD) and a /data volume, as
  # docker-compose.yml runs it; same stop_grace_period and restart policy. No ClamAV sidecar.
  docker volume create orphanprobe-data >/dev/null && OWN_VOL=1 || inc "could not create the data volume"
  cat > "$W/srv/docker-compose.yml" <<YML
name: $PROJECT
services:
  proxy:
    image: culvert/proxy:pinned
    container_name: $CNAME
    restart: unless-stopped
    network_mode: host
    stop_grace_period: $STOP_GRACE
    volumes:
      - orphanprobe-data:/data
    environment:
      CULVERT_SESSION_SECRET: "$(openssl rand -hex 32)"
$IMAGE_COMMAND_YAML
volumes:
  orphanprobe-data:
    external: true
YML
fi
cat > "$W/config.toml" <<TOML
compose_project_dir = "/srv/culvert"
allow_peers = ["0"]
compose_file = "docker-compose.yml"
socket_path = "/run/culvert-maint/culvert-maint.sock"
state_dir = "/var/lib/culvert-maint"
privilege_mode = "sudoers"
health_base_url = "http://127.0.0.1:$APP_PORT"
health_path = "/health"
ready_path = "/ready"
operation_timeout = "30m"
stage_timeout = "5m"
allowed_backup_dir = "/backup"
image_allowlist = '^127\\.0\\.0\\.1:$REG_PORT/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})\$'
proxy_repo = "$REPO_IMG"
TOML

# ── a real systemd (the host's binary) as PID 1 of a privileged container ───────────────
# The container's /etc is a copy of the host's without password hashes, SSH host keys and the
# usual private-key locations (list below). That is a best effort, not a guarantee: anything
# else secret under /etc is copied. Treat $BASE as sensitive; it and $W/root are removed on
# exit (the directory right after the import). Use a disposable machine.
tar -C /etc --exclude='./systemd/system/*.wants' --exclude='./shadow*' --exclude='./gshadow*' --exclude='./ssh' \
  --exclude='./ssl/private' --exclude='./pki' --exclude='./letsencrypt' --exclude='./wireguard' --exclude='./NetworkManager' \
  --exclude='./netplan' --exclude='./docker' --exclude='*.key' --exclude='*.keytab' --exclude='privkey*.pem' \
  --exclude='./sudoers.d/*' --exclude='./fstab' --exclude='./crypttab' -c . | tar -C "$W/root/etc" -x || inc "could not copy /etc"
# The host's fstab names disks that do not exist in the container: systemd waits for them,
# local-fs.target fails and PID 1 drops to emergency mode ('maintenance'). The container
# mounts nothing of its own.
: > "$W/root/etc/fstab"
awk -F: '{print $1":*:19000:0:99999:7:::"}' "$W/root/etc/passwd" > "$W/root/etc/shadow"
awk -F: '{print $1":*::"}' "$W/root/etc/group" > "$W/root/etc/gshadow"
chmod 640 "$W/root/etc/shadow" "$W/root/etc/gshadow"
for l in bin sbin lib lib64; do ln -sfn "usr/$l" "$W/root/$l"; done
mkdir -p "$W"/root/{var/lib,var/log,run,tmp,proc,sys,dev,root,home,usr,srv,backup}
cat > "$W/root/init.sh" <<'SH'
#!/bin/sh
# systemd needs the unified hierarchy; on a cgroup-v1 host the container gets v1 mounts.
umount -R /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup || exit 9
exec /lib/systemd/systemd --system --log-target=console --show-status=0
SH
chmod +x "$W/root/init.sh"
tar -C "$W/root" -c . | docker import - "$BASE" >/dev/null || inc "could not build the systemd base image"
OWN_BASE=1
rm -rf "$W/root"
cp -r "$REPO/packaging" "$W/pkg"
# The container gets an empty writable /usr/local (the installer writes there). If the host's
# compose plugin lives under /usr/local, bring it along, or `docker compose` is gone inside.
for pd in /usr/local/lib/docker/cli-plugins /usr/local/libexec/docker/cli-plugins; do
  if [ -d "$pd" ]; then mkdir -p "$W/ul/${pd#/usr/local/}" && cp -a "$pd/." "$W/ul/${pd#/usr/local/}/"; fi
done

install_agent() { # $1 = extra config line (may be empty)
  [ "$OWN_SYSD" = 1 ] && docker rm -f "$SYSD" >/dev/null 2>&1
  OWN_SYSD=1
  docker run -d --name "$SYSD" --privileged --network host --tmpfs /run --tmpfs /tmp -v /usr:/usr:ro -v "$W/ul:/usr/local" \
    -v "$W/srv:/srv/culvert" -v "$W/pkg:/pkg:ro" -v "$AGENT_BIN:/culvert-maint.bin:ro" \
    -v "$REAL_SOCK:/dk/real.sock" -v "$W/p:/dk/p" -e container=docker "$BASE" /init.sh >/dev/null || inc "systemd container did not start"
  # The image carries the host's whole unit set, so on a general-purpose machine some unrelated
  # unit may fail inside a container and systemd reports 'degraded'. That is still a working
  # supervisor, which is all the probe needs; the failed units are printed so the run says what
  # it ran on. Anything else (still 'starting' after 3 minutes, no answer) is INCOMPLETE, with
  # the state shown instead of hidden.
  sysd_state=""
  for _ in $(seq 1 360); do
    sysd_state="$(docker exec "$SYSD" systemctl is-system-running 2>/dev/null)"
    case "$sysd_state" in running|degraded) break ;; esac
    sleep 0.5
  done
  case "$sysd_state" in
    running) ;;
    degraded) echo "systemd: degraded; failed units: $(docker exec "$SYSD" systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | tr '\n' ' ')" ;;
    *)
      echo "systemd state: '${sysd_state:-no answer}'"
      docker exec "$SYSD" systemctl list-jobs --no-pager 2>&1 | head -40
      docker exec "$SYSD" systemctl --failed --no-pager 2>&1 | head -40
      docker exec "$SYSD" systemctl list-units --all --no-pager --state=failed,activating 2>&1 | head -40
      docker exec "$SYSD" systemctl status --no-pager -n 0 local-fs.target emergency.target rescue.target 2>&1 | head -40
      docker exec "$SYSD" journalctl -b --no-pager -p warning 2>&1 | tail -60
      docker logs "$SYSD" 2>&1 | tail -60
      inc "systemd did not finish starting in the container" ;;
  esac
  # The unit Wants=docker.service; the host's unit files are in the image. The agent must
  # reach the HOST daemon through /run/docker.sock, so no second daemon may start here.
  docker exec "$SYSD" systemctl mask docker.service docker.socket containerd.service >/dev/null 2>&1
  docker exec "$SYSD" sh -c "ln -sfn /dk/real.sock /run/docker.sock; mkdir -p /etc/culvert-maint /etc/docker/certs.d/127.0.0.1:$REG_PORT /usr/local/bin /usr/local/libexec; chmod 755 /usr/local /usr/local/bin /usr/local/libexec"
  { cat "$W/config.toml"; [ -n "$SETTLE" ] && echo "interrupted_settle = \"$SETTLE\""; [ -n "$1" ] && echo "$1"; } > "$W/config.rendered.toml"
  docker cp "$W/config.rendered.toml" "$SYSD:/etc/culvert-maint/config.toml" >/dev/null
  docker cp "$W/certs/r.crt" "$SYSD:/etc/docker/certs.d/127.0.0.1:$REG_PORT/ca.crt" >/dev/null
  docker exec "$SYSD" sh -c "cat /etc/docker/certs.d/127.0.0.1:$REG_PORT/ca.crt >> /etc/ssl/certs/ca-certificates.crt"
  docker tag "$(cat "$W/ref-v1")" culvert/proxy:pinned && OWN_TAG=1
  docker exec -e CULVERT_MAINT_SKIP_VERIFY=1 "$SYSD" sh /pkg/culvert-maint/install.sh /culvert-maint.bin > "$W/install.log" 2>&1 || { tail -5 "$W/install.log"; inc "the installer failed"; }
  echo "unit: $(docker exec "$SYSD" systemctl show culvert-maint -p KillMode -p RestartUSec -p TimeoutStopUSec | tr '\n' ' ')"
}

export PROBE_UI_PORT="$UI_PORT" PROBE_UI_TLS="$UI_TLS"
export PROBE_DIR="$W" PROBE_SYSD="$SYSD" PROBE_REAL_SOCK="$REAL_SOCK" PROBE_APP_PORT="$APP_PORT" PROBE_PROJECT="$PROJECT" PROBE_CNAME="$CNAME"
python3 "$HERE/dkproxy.py" "$W/p" "$REAL_SOCK" "$SYSD" > "$W/dkproxy.log" 2>&1 & PROXYPID=$!
for _ in $(seq 1 20); do [ -S "$W/p/dk.sock" ] && break; sleep 0.2; done
[ -S "$W/p/dk.sock" ] || inc "kill proxy did not start"

ALL=-1,0,1,2,3,4,5,6,7,8,9,10,11,12; MID=7,8,9,10; SLOW=12   # SLOW: seconds the proxy drains; > RestartSec
[ "$QUICK" = 1 ] && { ALL=-1,0,9; MID=9; }
# ORPHAN_PROBE_POINTS / ORPHAN_PROBE_MID: run a chosen subset of kill points (not the full matrix).
ALL="${ORPHAN_PROBE_POINTS:-$ALL}"; MID="${ORPHAN_PROBE_MID-$MID}"
rc=0
worse() { [ "$1" -gt "$rc" ] && rc=$1; return 0; }
n() { echo "$1" | tr ',' '\n' | grep -c .; }   # how many kill points in a list
run() { [ -n "$4" ] || return 0; python3 "$HERE/rig.py" run "$@" || { echo "INCOMPLETE: slice $1 did not run"; worse 2; }; }
judge() { # $1 = label, rest = judge flags; moves the evidence aside
  python3 "$HERE/rig.py" judge "${@:2}"; local r=$?
  mkdir -p "$W/evidence/$1" && mv "$W"/ev/*.jsonl "$W/evidence/$1/" 2>/dev/null
  echo "PROBE-RESULT $1 exit=$r"; return $r
}

if [ "$ONLY_CONVERGE" = 0 ]; then
# ── 1. systemd semantics, with a child that ignores SIGTERM ──────────────────────────────
install_agent ""
docker cp "$HERE/stubctl.sh" "$SYSD:/stubctl.sh" >/dev/null
c1="$(docker exec "$SYSD" sh /stubctl.sh "TimeoutStopSec=15s" "sudo -n")"; echo "CONTROL shipped-shape $c1"
c3="$(docker exec "$SYSD" sh /stubctl.sh "TimeoutStopSec=15s" "setsid")"; echo "CONTROL shipped-shape $c3"
c2="$(docker exec "$SYSD" sh /stubctl.sh "KillMode=process" "")"; echo "CONTROL KillMode=process $c2"
case "$c1$c3" in *"old_child_alive_when_new_main_started=no"*"old_child_alive_when_new_main_started=no"*) ;; *) echo "VIOLATION: systemd started a new main process while an old child was alive"; worse 1 ;; esac
case "$c2" in *"old_child_alive_when_new_main_started=yes"*) ;; *) echo "INCOMPLETE: the KillMode=process control did not show an overlap"; worse 2 ;; esac

# ── 2. the shipped unit: every kill point, then the operator's next operation ────────────
if [ "$REAL_PROXY" != 0 ]; then
  # The real proxy exits in well under a second when idle, and after 5 s with an admin-UI
  # request pending ("uihold"). v1 is the image an upgrade leaves and a rollback returns to.
  run none-fast none 0 "$ALL"
  run rollback-fast rollback 0 "$ALL"
  PROBE_DRAIN=$HOLD run none-$HOLD none 6 "$MID"
  PROBE_DRAIN=$HOLD run rollback-$HOLD rollback 6 "$MID"
  PROBE_DRAIN=$HOLD run apply-$HOLD apply 6 "$MID"
  judge shipped-real-proxy --trials=$(( 2 * $(n "$ALL") + 3 * $(n "$MID") )); worse $?
else
# "fast": the proxy exits at once. "slow": it drains for $SLOW s, answering 200 meanwhile,
# as Culvert's proxy does today (the listener stays open until its proxy-server hook).
run none-fast none 0 "$ALL"
run rollback-fast rollback 0 "$ALL"
run none-slow none "$SLOW" "$MID"
run rollback-slow rollback "$SLOW" "$MID"
run apply-slow apply "$SLOW" "$MID"
judge shipped --trials=$(( 2 * $(n "$ALL") + 3 * $(n "$MID") )); worse $?

# ── 2b. the same slow drain with a proxy that answers /ready 503 once it has SIGTERM ────
PROBE_DRAIN=notready run rollback-slow-notready rollback "$SLOW" "$MID"
PROBE_DRAIN=notready judge ready-fails-on-shutdown --trials="$(n "$MID")"; worse $?
fi

# ── 3. sensitivity: the same agent with the fence removed must show the hazard ───────────
# (Stand-in proxy only: the control needs a stop that is still in flight when the agent
# restarts, and the real proxy's stop is over by then.)
if [ "$REAL_PROXY" = 0 ]; then
docker exec "$SYSD" sh -c 'mkdir -p /etc/systemd/system/culvert-maint.service.d && printf "[Service]\nKillMode=process\n" > /etc/systemd/system/culvert-maint.service.d/zz-probe.conf && systemctl daemon-reload'
run nofence-rollback-slow rollback "$SLOW" 9
judge no-fence-control --trials=1 --expect-fence-violation; [ $? -eq 0 ] || { echo "INCOMPLETE: with KillMode=process the probe did not see a docker command outlive the agent; it cannot see the hazard"; worse 2; }
fi

fi
# ── 4. optional: startup convergence (#2039) ─────────────────────────────────────────────
if [ "$CONVERGE" = 1 ]; then
  install_agent 'reconcile_on_startup = "converge"'
  docker exec "$SYSD" systemctl start culvert-maint; sleep 2
  [ "$(docker exec "$SYSD" systemctl is-active culvert-maint)" = active ] || inc "this agent does not start with reconcile_on_startup = \"converge\""
  run converge-fast converge 0 "$ALL"
  if [ "$REAL_PROXY" != 0 ]; then
    PROBE_DRAIN=$HOLD run converge-$HOLD converge 6 "$MID"
    judge converge-real-proxy --trials=$(( $(n "$ALL") + $(n "$MID") )); worse $?
  else
    run converge-slow converge "$SLOW" "$MID"
    PROBE_DRAIN=notready run converge-slow-notready converge "$SLOW" "$MID"
    judge converge --trials=$(( $(n "$ALL") + 2 * $(n "$MID") )); worse $?
  fi
fi

if [ -n "${ORPHAN_PROBE_OUT:-}" ]; then mkdir -p "$ORPHAN_PROBE_OUT" && cp -r "$W/evidence/." "$ORPHAN_PROBE_OUT/"; fi
echo "PROBE-EXIT $rc"
exit "$rc"
