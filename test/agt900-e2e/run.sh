#!/usr/bin/env bash
# AGT-900 real-Docker e2e: the maintenance agent's opt-in startup reconcile
# (reconcile_on_startup = "converge") against a REAL Docker daemon.
#
# Manual / evidence run; never a PR gate. Needs root, Go, the Docker engine
# binaries (dockerd, containerd, docker CLI with the compose plugin), openssl
# and curl. It pulls nothing from Docker Hub: the registry is built from source
# and the three proxy images are built FROM scratch.
#
#   usage: test/agt900-e2e/run.sh [--store containerd|classic|both]
#                                 [--mode root|sudoers|both]
#                                 [--cases <regex>] [--negative-control] [--keep]
#
# Each image store runs in its OWN private dockerd (own data-root, exec-root,
# socket and managed containerd), so the host's daemon, its images and its
# culvert/proxy:pinned tag are never touched, and the "Docker unavailable" case
# can stop a real daemon. The Go harness is
# cmd/culvert-maint/agt900_realdocker_e2e_test.go (build tag agt900_e2e).
#
# --mode root (the default) runs the agent as root, privilege_mode
# docker_group_lab, against a minimal compose file (docker-compose.yml here).
# --mode sudoers runs the PRODUCTION path: inside a private mount namespace
# (sudoers-env.sh) the real packaging/culvert-maint/install.sh creates the
# culvert-maint user and installs the rendered sudoers file and compose-cli
# wrapper; the agent runs as that user with privilege_mode sudoers against the
# SHIPPED docker-compose.yml + docker-compose.maint-agent.yml
# (render-shipped-compose.py; clamav is a FROM-scratch stub). Nothing of it
# leaves the namespace.
#
# --negative-control builds the agent from a COPY of cmd/culvert-maint once per
# mutant (see MUTANT_CASES), runs the cases that must catch each, and exits 0
# only if the harness FAILS every mutant. The checked-out source is never
# modified, and no mutant is ever written into it.
#
# Verdicts: PASS; FAIL (a contract check failed); ERROR (the harness could not
# evaluate the case: setup, crash or mutate step failed, or nothing was
# checked); GAP (only an owner-requested property stricter than the AGT-900
# contract failed). --negative-control counts only FAIL as a caught mutant.
# Exit: 0 all PASS (or, with --negative-control, every mutant was caught by a
#       failed contract check); 1 a FAIL or ERROR; 3 no FAIL/ERROR but a GAP;
#       2 incomplete (prerequisite, setup, no rows).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MAINT="$ROOT/cmd/culvert-maint"
STORES="containerd classic"
MODES="root"
CASES=""
NEGCTL=0
KEEP=0
REG_PORT="${AGT900_REGISTRY_PORT:-5443}"
PROXY_PORT="${AGT900_PROXY_PORT:-18480}"
export GOMAXPROCS="${GOMAXPROCS:-2}"   # the build/test machine OOMs with more

usage() { sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
  case "$1" in
    --store) case "$2" in both) STORES="containerd classic" ;; containerd|classic) STORES="$2" ;; *) echo "bad --store $2"; exit 2 ;; esac; shift 2 ;;
    --mode) case "$2" in both) MODES="root sudoers" ;; root|sudoers) MODES="$2" ;; *) echo "bad --mode $2"; exit 2 ;; esac; shift 2 ;;
    --cases) CASES="$2"; shift 2 ;;
    --negative-control) NEGCTL=1; shift ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1"; usage; exit 2 ;;
  esac
done
[ "$NEGCTL" = 1 ] && [ "$STORES" = "containerd classic" ] && STORES="containerd"

incomplete() { echo "INCOMPLETE: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || incomplete "must run as root (it starts private dockerd instances)"
for c in go docker dockerd containerd openssl curl chattr python3 strace nsenter; do
  command -v "$c" >/dev/null 2>&1 || incomplete "missing prerequisite: $c"
done
case " $MODES " in
  *" sudoers "*)
    for c in unshare setpriv sudo visudo useradd groupadd getent install; do
      command -v "$c" >/dev/null 2>&1 || incomplete "missing prerequisite for --mode sudoers: $c"
    done
    [ "$(command -v docker)" = /usr/bin/docker ] || incomplete "--mode sudoers needs the docker CLI at /usr/bin/docker (the path the sudoers rules name)"
    grep -qw overlay /proc/filesystems || incomplete "--mode sudoers needs overlayfs"
    ;;
esac
docker compose version >/dev/null 2>&1 || incomplete "missing the docker compose plugin"
RUNSH_PID=$$   # its mount namespace is the host's: every dockerd is started in it

W="$(mktemp -d /tmp/agt900.XXXXXX)"   # short: unix socket paths are limited to ~104 bytes
chmod 711 "$W"                          # the sudoers-mode agent user traverses it
mkdir -p "$W/bin"
# The harness and the shims use a copy of the real CLI: in sudoers mode
# /usr/bin/docker is the shim inside the private namespace.
cp "$(command -v docker)" "$W/bin/docker-real" || incomplete "copy the docker CLI"
REAL_DOCKER="$W/bin/docker-real"
REGPID=""
DAEMONS=()
down_projects() { # store: remove both modes' compose projects from its daemon
  local f
  for f in "$W/proj-$1/docker-compose.yml" "$W/s-$1/culvert/docker-compose.yml"; do
    [ -f "$f" ] && DOCKER_HOST="unix://$W/d-$1/docker.sock" "$REAL_DOCKER" compose -f "$f" down --remove-orphans >/dev/null 2>&1
  done
  return 0
}
cleanup() {
  for d in "${DAEMONS[@]}"; do
    down_projects "$(basename "$d" | sed 's/^d-//')"
    sh "$d/stop.sh" >/dev/null 2>&1
  done
  [ -n "$REGPID" ] && kill "$REGPID" 2>/dev/null
  # a daemon that did not stop cleanly can leave mounts under $W
  awk -v w="$W" '$2 ~ "^"w {print $2}' /proc/mounts | sort -r | while read -r m; do umount -l "$m" 2>/dev/null; done
  if [ "$KEEP" = 1 ]; then echo "kept work dir: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT

echo "== AGT-900 real-Docker e2e  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "   source: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)$(git -C "$ROOT" diff --quiet 2>/dev/null || echo ' (dirty)')"
echo "   docker: client $("$REAL_DOCKER" version --format '{{.Client.Version}}' 2>/dev/null) / compose $(docker compose version --short) / dockerd $(dockerd --version | awk '{print $3}' | tr -d ,)"
echo "   modes: $MODES   stores: $STORES"
echo "   work: $W"

# ── registry (from source, TLS: the agent's `docker manifest inspect` has no --insecure) ──
mkdir -p "$W/reg/data"
if [ -n "${AGT900_REGISTRY_BIN:-}" ] && [ -x "$AGT900_REGISTRY_BIN" ]; then
  cp "$AGT900_REGISTRY_BIN" "$W/bin/registry"
else
  (cd "$W" && GOBIN="$W/bin" CGO_ENABLED=0 GOFLAGS=-mod=mod go install github.com/distribution/distribution/v3/cmd/registry@v3.0.0) \
    || incomplete "could not build the registry (set AGT900_REGISTRY_BIN to a prebuilt distribution v3 registry)"
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$W/reg/key.pem" -out "$W/reg/cert.pem" >/dev/null 2>&1 || incomplete "openssl"
cat > "$W/reg/config.yml" <<EOF
version: 0.1
storage:
  filesystem:
    rootdirectory: $W/reg/data
http:
  addr: 127.0.0.1:$REG_PORT
  tls:
    certificate: $W/reg/cert.pem
    key: $W/reg/key.pem
EOF
"$W/bin/registry" serve "$W/reg/config.yml" > "$W/reg/registry.log" 2>&1 &
REGPID=$!
CURL=(curl -fs --noproxy '*' --cacert "$W/reg/cert.pem")
for _ in $(seq 1 40); do "${CURL[@]}" "https://localhost:$REG_PORT/v2/" >/dev/null && break; sleep 0.25; done
"${CURL[@]}" "https://localhost:$REG_PORT/v2/" >/dev/null || incomplete "registry did not come up (port $REG_PORT busy?)"

# ── the three fake proxy binaries ───────────────────────────────────────────────────────
for v in prior good bad; do
  mkdir -p "$W/img-$v"
  # drop the `ignore` build constraint in the scratch copy (it would also apply to the stdlib)
  sed '1{/^\/\/go:build ignore$/d}' "$HERE/fakeproxy/main.go" > "$W/img-$v/main.go"
  printf 'module fakeproxy\n\ngo 1.22\n' > "$W/img-$v/go.mod"
  # /usr/bin/wget: the shipped compose file's proxy healthcheck (multi-call binary)
  # The data-epoch labels (ADR-0062 slice 6a): every fake reads epoch 1 only, so
  # a data marker at epoch 2 is data none of them can read.
  printf 'FROM scratch\nLABEL io.culvert.data-epoch.min="1" io.culvert.data-epoch.max="1"\nCOPY app /app\nCOPY app /usr/bin/wget\nENTRYPOINT ["/app"]\n' > "$W/img-$v/Dockerfile"
  ready=ok; [ "$v" = bad ] && ready=fail
  (cd "$W/img-$v" && GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$v -X main.ready=$ready" -o app .) \
    || incomplete "building the fake proxy ($v)"
done
# The clamav sidecar of the shipped compose file (clamav/clamav:1.4 cannot be
# pulled here): a FROM-scratch stub of the same binary that idles until SIGTERM
# and answers the shipped healthcheck `clamdscan --ping 3`. Built locally under
# the shipped name in each PRIVATE daemon only.
mkdir -p "$W/img-clamav"
cp "$W/img-prior/app" "$W/img-clamav/app"
printf 'FROM scratch\nCOPY app /app\nCOPY app /usr/bin/clamdscan\nENTRYPOINT ["/app", "-idle"]\n' > "$W/img-clamav/Dockerfile"

# ── the agent(s) under test ──────────────────────────────────────────────────────────────
# A mutant is applied to a COPY of cmd/culvert-maint; the checked-out source is
# never touched. Each mutant names the cases that must catch it.
declare -A MUTANT_CASES=(
  [adopt_restarted]='^(restarted_at_health_gate|restarted_at_verify)$'
  [no_write_ahead]='^(rc_after_writeahead|repeat_tag_ahead_exhaust)$'
  [retire_before_audit]='^(audit_write_fails_keeps_record)$'
  # for the outstanding recovery cases
  [standalone_partial_noop]='^(standalone_rb_tag_moved|standalone_rb_up_done)$'
  [data_as_image]='^(data_rollback_record)$'
  [no_deadline_check]='^(reconcile_deadline_abandoned)$'
  [no_running_check]='^(container_paused)$'
  # runtime recovery (ADR-0062 slice 6, PR 4)
  [rr_compat_always_ok]='^(rr_incompatible)$'
  [rr_installed_any_image]='^(rr_hand_change)$'
  [rr_no_trigger]='^(rr_restore)$'
)
MUTANTS_ALL="adopt_restarted no_write_ahead retire_before_audit standalone_partial_noop data_as_image no_deadline_check no_running_check rr_compat_always_ok rr_installed_any_image rr_no_trigger"
apply_mutant() { # name dir
  local srv="$2/internal/server" f
  case "$1" in
    standalone_partial_noop) # a partially applied standalone rollback is not detected
      f="$srv/reconcile_decision_v2.go"
      sed -i 's/^\tif ids\.target != "" && (ids\.tag == ids\.target || ids\.run == ids\.target) {$/\tif false \&\& ids.target != "" \&\& (ids.tag == ids.target || ids.run == ids.target) { \/\/ NEGATIVE CONTROL: partial rollback not detected/' "$f" ;;
    data_as_image) # a data rollback record is reconciled like an image rollback
      f="$srv/reconcile_decision_v2.go"
      python3 - "$f" "$srv/startup_reconcile.go" <<'PY'
import sys
d, s = sys.argv[1], sys.argv[2]
t = open(d).read()
old = """	case in.Kind == ops.KindRollbackCreate && in.Mode == "data":
		// Never touches Docker; the existing manual data-recovery report applies.
		return rr("data_window_manual")
"""
img = '(in.Kind == ops.KindRollbackCreate && in.Mode == "image")'
if t.count(old) == 1 and t.count(img) == 1:
    t = t.replace(old, "").replace(img, "(in.Kind == ops.KindRollbackCreate) // NEGATIVE CONTROL: data treated as image")
    open(d, "w").write(t)
u = open(s).read()
if u.count(img) == 1:
    open(s, "w").write(u.replace(img, "(in.Kind == ops.KindRollbackCreate)"))
PY
      ;;
    no_deadline_check) # records after the deadline are still processed
      f="$srv/startup_reconcile.go"
      sed -i 's/^\t\tif ctx\.Err() != nil {$/\t\tif false \&\& ctx.Err() != nil { \/\/ NEGATIVE CONTROL: deadline ignored/' "$f" ;;
    no_running_check) # a stopped proxy container is treated as running
      f="$srv/reconcile_decision_v2.go"
      sed -i 's/^\tif ids\.run != "" && !in\.ContainerRunning {$/\tif false \&\& ids.run != "" \&\& !in.ContainerRunning { \/\/ NEGATIVE CONTROL: stopped container not detected/' "$f" ;;
    rr_compat_always_ok) # every restore image is taken as compatible with the data
      f="$srv/data_compat.go"
      sed -i 's/^\(func dataCompat(.*) (verdict compatVerdict, reason string) {\)$/\1\n\treturn compatOK, compatReasonCompatibleWithin \/\/ NEGATIVE CONTROL: compatibility never checked/' "$f" ;;
    rr_installed_any_image) # any running image counts as one this agent installed
      f="$srv/runtime_recovery_admit.go"
      sed -i 's/^\tif in != nil \&\& normID(in\.ImageID) == normID(x) {$/\tif in != nil { \/\/ NEGATIVE CONTROL: provenance not checked/' "$f" ;;
    rr_no_trigger) # the observer never hands its samples to the trigger
      f="$srv/runtime_observer.go"
      sed -i 's/^\ts\.noteRuntimeSample(\&smp)$/\t_ = smp \/\/ NEGATIVE CONTROL: the observer never triggers/' "$f" ;;
    adopt_restarted)
      f="$srv/reconcile_decision_v2.go"
      sed -i 's/^\tcase in\.Phase != journal\.PhaseVerified:$/\tcase in.Phase != journal.PhaseVerified \&\& in.Phase != journal.PhaseRestarted: \/\/ NEGATIVE CONTROL: adopts an ungated target/' "$f" ;;
    no_write_ahead)
      f="$srv/startup_reconcile.go"
      sed -i 's/^\tif err := s\.opts\.Journal\.Write(\*c\.rec); err != nil {$/\tif err := error(nil); err != nil { \/\/ NEGATIVE CONTROL: no write-ahead attempt record/' "$f" ;;
    retire_before_audit)
      f="$srv/startup_reconcile.go"
      python3 - "$f" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
old = """	c.out.Outcome = OutcomeConverged
	if err := s.auditReconciled(c, audit.OutcomeSucceeded); err != nil {
		return s.keepRecord(c, OutcomeConvergedNotRetired)
	}
	if err := s.opts.Journal.Remove(c.rec.OpID); err != nil {
		return s.keepRecord(c, OutcomeConvergedNotRetired)
	}
"""
new = """	c.out.Outcome = OutcomeConverged
	if err := s.opts.Journal.Remove(c.rec.OpID); err != nil {
		return s.keepRecord(c, OutcomeConvergedNotRetired)
	}
	_ = s.auditReconciled(c, audit.OutcomeSucceeded) // NEGATIVE CONTROL: retired before the audit, audit failure ignored
"""
if s.count(old) == 1:
    open(p, "w").write(s.replace(old, new))
PY
      ;;
  esac
  grep -q 'NEGATIVE CONTROL' "$f" || incomplete "mutant $1 did not apply"
  echo "   mutant $1:"
  diff -u "$MAINT/internal/server/$(basename "$f")" "$f" | sed 's/^/     /'
}
if [ "$NEGCTL" = 1 ]; then
  RUNS="${AGT900_MUTANTS:-$MUTANTS_ALL}"
  for m in $RUNS; do
    [ -n "${MUTANT_CASES[$m]:-}" ] || incomplete "unknown mutant $m"
    mkdir -p "$W/mut-$m" && cp -a "$MAINT" "$W/mut-$m/culvert-maint"
    apply_mutant "$m" "$W/mut-$m/culvert-maint"
    (cd "$W/mut-$m/culvert-maint" && go build -o "$W/bin/agent-$m" .) || incomplete "building mutant $m"
  done
else
  RUNS="current"
  (cd "$MAINT" && go build -o "$W/bin/agent-current" .) || incomplete "building the agent"
fi

# ── one private dockerd per image store ──────────────────────────────────────────────────
start_daemon() { # store
  local s="$1" d="$W/d-$1" feat pool
  mkdir -p "$d"
  if [ "$s" = classic ]; then feat=false; pool=10.231.0.0/16; else feat=true; pool=10.232.0.0/16; fi
  cat > "$d/start.sh" <<EOF
#!/bin/sh
# private dockerd for the AGT-900 e2e ($s image store); proxies unset: it only talks to localhost.
# Always started in run.sh's (the host's) mount namespace, also when the
# sudoers-mode harness calls this from its private namespace.
nsenter --mount=/proc/$RUNSH_PID/ns/mnt -- env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy -u NO_PROXY -u no_proxy \\
  dockerd --data-root "$d/data" --exec-root "$d/x" --pidfile "$d/pid" -H "unix://$d/docker.sock" \\
  --bridge=none --iptables=false --ip6tables=false --default-address-pool base=$pool,size=24 \\
  --feature containerd-snapshotter=$feat >> "$d/dockerd.log" 2>&1 &
i=0
while [ \$i -lt 120 ]; do
  DOCKER_HOST="unix://$d/docker.sock" "$REAL_DOCKER" info >/dev/null 2>&1 && exit 0
  i=\$((i+1)); sleep 0.5
done
echo "dockerd ($s) did not come up" >&2; exit 1
EOF
  cat > "$d/stop.sh" <<EOF
#!/bin/sh
p=\$(cat "$d/pid" 2>/dev/null) || exit 0
kill -TERM "\$p" 2>/dev/null || exit 0
i=0
while kill -0 "\$p" 2>/dev/null && [ \$i -lt 120 ]; do i=\$((i+1)); sleep 0.5; done
kill -0 "\$p" 2>/dev/null && { echo "dockerd did not stop" >&2; exit 1; }
exit 0
EOF
  chmod +x "$d/start.sh" "$d/stop.sh"
  DAEMONS+=("$d")
  sh "$d/start.sh"
}

digest() { # repo-path tag → registry digest (sha256:...)
  "${CURL[@]}" -I \
    -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json' \
    "https://localhost:$REG_PORT/v2/$1/manifests/$2" | awk 'tolower($1)=="docker-content-digest:"{print $2}' | tr -d '\r'
}

RESULTS="$W/results.tsv"; : > "$RESULTS"
HARNESS_RC=0
for s in $STORES; do
  echo; echo "== image store: $s"
  start_daemon "$s" || incomplete "private dockerd ($s)"
  export DOCKER_HOST="unix://$W/d-$s/docker.sock"
  drv="$("$REAL_DOCKER" info --format '{{.Driver}} {{json .DriverStatus}}')"
  echo "   daemon: $drv"
  case "$s:$drv" in
    containerd:*io.containerd.snapshotter*|classic:overlay2*|classic:vfs*|classic:fuse*) ;;
    *) incomplete "daemon for '$s' reports an unexpected store: $drv" ;;
  esac
  repo="localhost:$REG_PORT/culvert-$s"
  for v in prior good bad; do
    "$REAL_DOCKER" build -q -t "$repo:$v" "$W/img-$v" >/dev/null || incomplete "docker build $v ($s)"
    "$REAL_DOCKER" push -q "$repo:$v" >/dev/null || incomplete "docker push $v ($s)"
  done
  dp="$(digest "culvert-$s" prior)"; dg="$(digest "culvert-$s" good)"; db="$(digest "culvert-$s" bad)"
  [ -n "$dp" ] && [ -n "$dg" ] && [ -n "$db" ] || incomplete "registry digests ($s)"
  echo "   digests: prior=$dp good=$dg bad=$db"
  # a customer host has the release image only by its registry reference
  "$REAL_DOCKER" rmi -f "$repo:prior" "$repo:good" "$repo:bad" >/dev/null 2>&1
  "$REAL_DOCKER" pull -q "$repo@$dp" >/dev/null || incomplete "pull prior by digest ($s)"
  mkdir -p "$W/proj-$s/ctl" "$W/logs"
  case " $MODES " in
    *" sudoers "*)
      "$REAL_DOCKER" build -q -t clamav/clamav:1.4 "$W/img-clamav" >/dev/null || incomplete "build the clamav stub ($s)"
      # production layout: <compose_project_dir> named culvert => compose project "culvert"
      mkdir -p "$W/s-$s/culvert/ctl" "$W/run-culvert-maint"
      chmod 755 "$W/s-$s" "$W/s-$s/culvert" "$W/s-$s/culvert/ctl"
      python3 "$HERE/render-shipped-compose.py" "$ROOT" "$W/s-$s/culvert" "$PROXY_PORT" "$((PROXY_PORT + 1))" "$W/run-culvert-maint" \
        || incomplete "render the shipped compose files ($s)"
      ;;
  esac
  for mode in $MODES; do
  for run in $RUNS; do
    cases="$CASES"; label="$mode/$s"; tag="$mode-$s-$run"
    if [ "$run" != current ]; then cases="${MUTANT_CASES[$run]}"; label="$mode/$s/mutant:$run"; echo "   -- $mode mutant $run: cases $cases"; fi
    common=(AGT900_E2E=1 AGT900_STORE="$label" AGT900_DOCKER_HOST="$DOCKER_HOST"
      AGT900_REAL_DOCKER="$REAL_DOCKER" AGT900_REPO="$repo" AGT900_CA="$W/reg/cert.pem"
      AGT900_DIGEST_PRIOR="${dp#sha256:}" AGT900_DIGEST_GOOD="${dg#sha256:}" AGT900_DIGEST_BAD="${db#sha256:}"
      AGT900_PROXY_PORT="$PROXY_PORT" AGT900_DOCKERD_START="$W/d-$s/start.sh" AGT900_DOCKERD_STOP="$W/d-$s/stop.sh"
      AGT900_RESULTS="$RESULTS" AGT900_LOGS="$W/logs" AGT900_CASES="$cases" GOMAXPROCS="$GOMAXPROCS")
    gotest=(go test -tags agt900_e2e -count=1 -timeout 150m -run '^TestAGT900RealDocker$' -v .)
    if [ "$mode" = root ]; then
      (cd "$MAINT" && env "${common[@]}" AGT900_MODE=root AGT900_PROJECT="$W/proj-$s" \
          AGT900_COMPOSE_TEMPLATE="$HERE/docker-compose.yml" AGT900_AGENT_BIN="$W/bin/agent-$run" \
          "${gotest[@]}"; echo $? > "$W/logs/rc-$tag") 2>&1 \
        | tee "$W/logs/harness-$tag.log" | grep --line-buffered -E '^(=== |--- |    agt900|PASS|FAIL|ERROR|ok|panic)'
    else
      printf '#!/bin/sh\nexec %s "$@"\n' "$REAL_DOCKER" > "$W/bin/docker-shim-$tag"
      chmod 755 "$W/bin/docker-shim-$tag"
      (cd "$MAINT" && env "${common[@]}" AGT900_MODE=sudoers AGT900_PROJECT="$W/s-$s/culvert" AGT900_COMPOSE_PROJECT=culvert \
          AGT900_COMPOSE_OVERRIDE=docker-compose.maint-agent.yml AGT900_SHIM="$W/bin/docker-shim-$tag" \
          AGT900_W="$W" AGT900_SEED_REF="$repo@$dp" AGT900_AGENT_SRC="$W/bin/agent-$run" \
          unshare --mount --propagation private -- "$HERE/sudoers-env.sh" "$W/logs/sudoers-$tag" -- \
          "${gotest[@]}"; echo $? > "$W/logs/rc-$tag") 2>&1 \
        | tee "$W/logs/harness-$tag.log" | grep --line-buffered -E '^(=== |--- |    agt900|PASS|FAIL|ERROR|ok|panic|sudoers-env)'
      [ -f "$W/logs/sudoers-$tag/sudoers-evidence.txt" ] && sed 's/^/     /' "$W/logs/sudoers-$tag/sudoers-evidence.txt"
    fi
    [ "$(cat "$W/logs/rc-$tag" 2>/dev/null)" = 0 ] || HARNESS_RC=1
    down_projects "$s"
  done
  done
  sh "$W/d-$s/stop.sh"
  unset DOCKER_HOST
done

# ── results table ────────────────────────────────────────────────────────────────────────
echo
echo "== results ($(date -u +%Y-%m-%d), docker $(dockerd --version | awk '{print $3}' | tr -d ,))"
[ -s "$RESULTS" ] || incomplete "the harness produced no result rows (see $W/logs, rerun with --keep)"
awk -F'\t' 'BEGIN{printf "%-22s | %-34s | %-58s | %-58s | %s\n","store","case","expected","observed","verdict";
  printf "%s\n", "-----------------------+------------------------------------+------------------------------------------------------------+------------------------------------------------------------+--------"}
  {printf "%-22s | %-34s | %-58s | %-58s | %s\n",$1,$2,$3,$4,$5; if ($6!="") { n=split($6,a,";;"); for(i=1;i<=n;i++) printf "%-22s   %s\n","","  - " a[i] } }' "$RESULTS"
FAILS=$(awk -F'\t' '$5=="FAIL"' "$RESULTS" | wc -l)
GAPS=$(awk -F'\t' '$5=="GAP"' "$RESULTS" | wc -l)
ERRORS=$(awk -F'\t' '$5=="ERROR"' "$RESULTS" | wc -l)
TOTAL=$(wc -l < "$RESULTS")
echo
echo "rows: $TOTAL  FAIL: $FAILS  ERROR: $ERRORS  GAP: $GAPS  harness exit: $HARNESS_RC"
if [ "$NEGCTL" = 1 ]; then
  missed=0
  for m in $RUNS; do
    # Only a failed CONTRACT check (FAIL) counts as catching the mutant. An
    # ERROR row means the case was never evaluated (setup/harness failure), so
    # it can neither catch the mutant nor be ignored: it is reported.
    n=$(awk -F'\t' -v m="mutant:$m" 'index($1, m) && $5=="FAIL"' "$RESULTS" | wc -l)
    ne=$(awk -F'\t' -v m="mutant:$m" 'index($1, m) && $5=="ERROR"' "$RESULTS" | wc -l)
    if [ "$n" -gt 0 ]; then echo "NEGATIVE CONTROL $m: caught ($n FAIL row(s), $ne ERROR row(s))"
    else echo "NEGATIVE CONTROL $m: NOT caught ($ne ERROR row(s): harness errors never count as a catch)"; missed=1; fi
  done
  [ "$missed" = 0 ] && { echo "NEGATIVE CONTROL: every mutant was caught -> OK"; exit 0; }
  echo "NEGATIVE CONTROL: a mutant passed -> the harness cannot detect it"; exit 1
fi
if [ "$FAILS" -gt 0 ] || [ "$ERRORS" -gt 0 ] || [ "$HARNESS_RC" != 0 ]; then exit 1; fi
[ "$GAPS" -gt 0 ] && exit 3
exit 0
