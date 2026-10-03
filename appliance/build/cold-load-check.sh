#!/usr/bin/env bash
# cold-load-check.sh — prove a saved image archive runs from its OWN content.
#
# Loads the archive into an EMPTY, DISPOSABLE Docker/containerd store (a
# pinned docker:dind container with its own data root, removed afterwards),
# with registry fallback disabled, then:
#   1. the store is the containerd image store and starts empty;
#   2. a registry pull FAILS (so nothing below can be satisfied remotely);
#   3. `docker load` of the archive yields <ref> with ID <id> on linux/amd64;
#   4. a container is CREATED from <ref> with --pull=never (config + layers
#      usable) and <run-cmd> executes inside it (--network none);
#   5. --ready-clamav <seconds>: a real ClamAV container from <ref> reaches
#      `clamdscan --ping` within the bound. The daemon's registry access is
#      routed to a dead proxy; the container itself may reach the signature
#      mirror (freshclam), which is not a registry.
# A successful `docker load` proves nothing on its own: a 69,562-byte ClamAV
# archive with no config or layers "loaded" and broke first boot
# (F-OVA-CLAMAV-1, PR #1528).
#
# Usage: cold-load-check.sh --dind IMAGE@sha256:… --archive A.tar.gz --ref REF
#          --id sha256:… --run 'ENTRYPOINT [ARG…]' [--ready-clamav SECONDS]
set -euo pipefail

die() { echo "cold-load: FAIL: $*" >&2; exit 1; }
log() { echo "cold-load: $*"; }

DIND="" ARCHIVE="" REF="" ID="" RUN="" READY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dind) DIND="$2"; shift 2 ;;
    --archive) ARCHIVE="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    --id) ID="$2"; shift 2 ;;
    --run) RUN="$2"; shift 2 ;;
    --ready-clamav) READY="$2"; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done
[[ "$DIND" == *@sha256:* ]] || die "--dind must be pinned by digest"
[[ -f "$ARCHIVE" ]] || die "no archive $ARCHIVE"
[[ -n "$REF" && -n "$RUN" ]] || die "--ref and --run are required"
[[ "$ID" =~ ^sha256:[0-9a-f]{64}$ ]] || die "--id must be sha256:<64 hex>"
[[ -z "$READY" || "$READY" =~ ^[0-9]+$ ]] || die "--ready-clamav takes seconds"

name="culvert-coldload-$$-$RANDOM"
cleanup() { docker rm -f -v "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

net=(--network none)
proxy=()
if [[ -n "$READY" ]]; then
  # The ClamAV container needs egress for its signatures; the daemon must not
  # reach a registry: its proxy is a closed local port.
  net=()
  proxy=(-e HTTP_PROXY=http://127.0.0.1:9 -e HTTPS_PROXY=http://127.0.0.1:9 -e NO_PROXY=)
fi
docker pull -q "$DIND" >/dev/null
docker run -d --privileged --name "$name" "${net[@]}" "${proxy[@]}" -e DOCKER_TLS_CERTDIR= "$DIND" >/dev/null
dexec() { docker exec "$name" "$@"; }
for _ in $(seq 1 60); do dexec docker info >/dev/null 2>&1 && break; sleep 2; done
dexec docker info >/dev/null 2>&1 || { docker logs --tail 40 "$name" >&2 || true; die "disposable daemon did not start"; }
log "disposable store: $(dexec docker info --format '{{.ServerVersion}} {{.Driver}} {{.DriverStatus}}')"
dexec docker info --format '{{.DriverStatus}}' | grep -q 'io.containerd.snapshotter.v1' \
  || die "disposable daemon is not on the containerd image store (the guest is)"
[[ -z "$(dexec docker image ls -aq)" ]] || die "disposable store is not empty"

if timeout 60 docker exec "$name" docker pull -q busybox:latest >/dev/null 2>&1; then
  die "registry fallback is reachable from the disposable daemon"
fi
log "registry fallback disabled (a pull fails)"

docker cp "$ARCHIVE" "$name:/archive.tar.gz"
dexec docker load -i /archive.tar.gz | sed 's/^/cold-load: /'
got="$(dexec docker image inspect "$REF" --format '{{.Id}} {{.Os}}/{{.Architecture}}' 2>/dev/null)" \
  || die "$REF is not present after loading the archive"
[[ "$got" == "$ID linux/amd64" ]] || die "$REF is '$got', want '$ID linux/amd64'"
log "$REF = $got"

dexec docker create --pull=never --name coldload-create "$REF" >/dev/null \
  || die "cannot create a container from $REF using only the loaded content"
dexec docker rm coldload-create >/dev/null
read -r -a run <<<"$RUN"
out="$(dexec docker run --rm --pull=never --network none --entrypoint "${run[0]}" "$REF" "${run[@]:1}" 2>&1)" \
  || { echo "$out" >&2; die "$REF did not run '$RUN'"; }
log "ran '$RUN': $(echo "$out" | head -1)"

if [[ -n "$READY" ]]; then
  dexec docker run -d --pull=never --name coldload-clamav -e CLAMAV_NO_MILTERD=true "$REF" >/dev/null \
    || die "cannot start ClamAV from $REF"
  t0=$(date +%s)
  until dexec docker exec coldload-clamav clamdscan --ping 3 >/dev/null 2>&1; do
    if ! dexec docker inspect -f '{{.State.Running}}' coldload-clamav | grep -q true; then
      dexec docker logs --tail 60 coldload-clamav >&2 || true; die "ClamAV exited before it was ready"
    fi
    if (( $(date +%s) - t0 > READY )); then
      dexec docker logs --tail 60 coldload-clamav >&2 || true; die "ClamAV not ready (clamdscan --ping) within ${READY}s"
    fi
    sleep 10
  done
  log "ClamAV ready (clamdscan --ping) after $(( $(date +%s) - t0 ))s"
fi
log "PASS $REF"
