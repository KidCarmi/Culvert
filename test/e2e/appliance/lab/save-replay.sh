#!/usr/bin/env bash
# save-replay.sh — DIAGNOSTIC (F-OVA-CLAMAV-1): replay build-ova.sh's image
# sequence in a FRESH, DISPOSABLE Docker store and report whether each saved
# archive carries its image.
#
# The replay runs in a pinned docker:dind container with its own data root,
# never in the builder's daemon, so it can neither pre-populate nor repair the
# store the build uses. Variants (env), each in its own fresh store:
#   REPLAY_PRELOAD_TAR=<tar>  load the candidate image archive first, as the
#                             pre-fix build did before pulling ClamAV;
#   REPLAY_CREATE=1           also docker create/cp/rm the loaded image;
#   REPLAY_ORDER=save-first   pull, tag and SAVE ClamAV before the preload (the
#                             fixed build's order); the saves after the preload
#                             then show an image pulled BEFORE the load.
# Every archive is checked with archive_platform_closure against the pins.
# Observes only; never fails the job.
#
# Usage: save-replay.sh <repo> <tag> <index-digest> <amd64-digest> <dind-image@sha256:…> <out-dir>
set -uo pipefail
repo="$1" tag="$2" idx="$3" amd="$4" dind="$5" out="$6"
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=appliance/build/archive-identity.sh
. "$here/../../../../appliance/build/archive-identity.sh"
mkdir -p "$out"
name="culvert-save-replay-$$"
trap 'docker rm -f -v "$name" >/dev/null 2>&1 || true' EXIT
docker pull -q "$dind" >/dev/null
docker run -d --privileged --name "$name" -e DOCKER_TLS_CERTDIR= "$dind" >/dev/null
r() { docker exec "$name" "$@"; }
for _ in $(seq 1 60); do r docker info >/dev/null 2>&1 && break; sleep 2; done
echo "replay store: $(r docker info --format '{{.ServerVersion}} {{.Driver}} {{.DriverStatus}}') containerd=$(r containerd --version 2>/dev/null | awk '{print $3}')"
echo "images before replay: $(r docker image ls -aq | wc -l)"
ref="${repo}@${idx}" tagged="${repo}:${tag}"

save() { # label docker-save-args...
  local label="$1"; shift
  # Streamed out of the disposable daemon (docker cp could not reach its /tmp).
  docker exec "$name" docker save "$@" | gzip -n -1 > "$out/$label.tgz" \
    || { echo "$label: docker save FAILED"; return; }
  local size res; size="$(stat -c %s "$out/$label.tgz")"
  if res="$(archive_platform_closure "$out/$label.tgz" linux/amd64 "$idx" "$amd" 2>&1)"; then
    echo "$label: $size bytes — $res"
  else
    echo "$label: $size bytes — CLOSURE FAILED: $res"
    tar -tzvf "$out/$label.tgz" | sed "s/^/$label member: /"
  fi
}
pull_tag() {
  r docker pull -q "$ref" >/dev/null || { echo "REPLAY INCONCLUSIVE: the disposable store could not pull $ref"; exit 0; }
  r docker image inspect "$ref" --format 'after pull: {{.Id}} {{.Os}}/{{.Architecture}}'
  r docker tag "$ref" "$tagged"
}

if [[ "${REPLAY_ORDER:-}" == save-first ]]; then
  pull_tag
  save early-by-tag "$tagged"                 # the fixed build's save
fi
loaded=""
if [[ -n "${REPLAY_PRELOAD_TAR:-}" ]]; then
  docker cp "$REPLAY_PRELOAD_TAR" "$name:/preload.tar" >/dev/null
  loaded="$(r docker load -q -i /preload.tar | sed -n 's/^Loaded image: //p' | head -1)"
  echo "preloaded: $loaded"
fi
[[ "${REPLAY_ORDER:-}" == save-first ]] || pull_tag
if [[ "${REPLAY_CREATE:-0}" == 1 && -n "$loaded" ]]; then
  cid="$(r docker create "$loaded")" && r docker cp "$cid:/app/VERSION" /tmp/VERSION >/dev/null && r docker rm "$cid" >/dev/null && echo "create/cp/rm of $loaded done"
fi
r docker image ls --tree 2>&1 | sed 's/^/tree: /'
save by-tag "$tagged"                         # the save that produced F-OVA-CLAMAV-1
save by-digest "$ref"
save digest-and-tag "$ref" "$tagged"
rm -f "$out"/*.tgz
exit 0
