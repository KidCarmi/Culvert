#!/usr/bin/env bash
# save-replay.sh — DIAGNOSTIC (F-OVA-CLAMAV-1): replay build-ova.sh's exact
# image sequence in a FRESH, DISPOSABLE Docker store and report whether the
# saved archive carries its image.
#
# build-ova.sh: docker pull -q <repo>@<index digest>; docker tag <repo>@<index>
# <repo>:<tag>; docker save <repo>:<tag>. The replay runs those three in a
# pinned docker:dind container with its own data root, never in the
# builder's daemon, so it can neither pre-populate nor repair the store the
# build uses. For comparison it also saves by digest and by tag with
# --platform. Every archive is checked with archive_platform_closure against
# the pins. Observes only; never fails the job.
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
r docker pull -q "$ref" >/dev/null || { echo "REPLAY INCONCLUSIVE: the disposable store could not pull $ref"; exit 0; }
r docker image inspect "$ref" --format 'after pull: {{.Id}} {{.Os}}/{{.Architecture}}'
r docker tag "$ref" "$tagged"
r docker image ls --tree 2>&1 | sed 's/^/tree: /'
save() { # label docker-save-args...
  local label="$1"; shift
  r sh -c "set -o pipefail; docker save $* | gzip -n -1 > /tmp/$label.tgz" || { echo "$label: docker save FAILED"; return; }
  docker cp "$name:/tmp/$label.tgz" "$out/$label.tgz" >/dev/null || { echo "$label: copy-out FAILED"; return; }
  local size; size="$(stat -c %s "$out/$label.tgz")"
  if res="$(archive_platform_closure "$out/$label.tgz" linux/amd64 "$idx" "$amd" 2>&1)"; then
    echo "$label: $size bytes — $res"
  else
    echo "$label: $size bytes — CLOSURE FAILED: $res"
    tar -tzvf "$out/$label.tgz" | sed "s/^/$label member: /"
  fi
}
save by-tag "$tagged"                         # exactly build-ova.sh's save
save by-digest "$ref"
save by-tag-platform --platform linux/amd64 "$tagged"
rm -f "$out"/*.tgz
exit 0
