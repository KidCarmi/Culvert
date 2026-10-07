#!/usr/bin/env bash
# build-ova.sh — reproducible (input-pinned) Culvert appliance OVA build.
#
#   appliance/build/build-ova.sh [--out DIR] [--work DIR] [--skip-cosign]
#                                [--stop-after disk|vmdk] [--keep-work]
#                                [--candidate-image-tar FILE --candidate-source SHA
#                                 [--candidate-run-id ID] [--candidate-allow-provisioning-drift]]
#
# CANDIDATE mode (qualification of an UNPUBLISHED build, never for customers):
#   --candidate-image-tar takes a `docker save` tarball of the proxy image —
#   the Deep PR Gate's `deep-gate-image` artifact (culvert-image.tar) — instead
#   of pulling a signed release by digest. The OVA is then built from THAT
#   image's deploy bundle (compose files, agent binary, packaging) plus this
#   checkout's provisioning files, and is named/labelled "candidate": the
#   version carries "-candidate.<sha12>", the OVF product line says CANDIDATE,
#   build-info.json records the source SHA, the image tar's SHA-256 and the CI
#   run id, and the guest manifest carries CANDIDATE_BUILD=1. Signature
#   verification is NOT bypassed: the image has no signature to verify, and
#   that fact is recorded verbatim in build-info.json. The ONE candidate-scoped
#   trust decision is the maintenance agent: install.sh trusts the bundled
#   agent only for a cosign-verified image, so a candidate first boot passes
#   its break-glass CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1 — exported by
#   culvert-firstboot ONLY when the manifest says CANDIDATE_BUILD=1, logged on
#   every boot and on the console. A release OVA never sets it.
#   --candidate-source must equal this checkout's HEAD (the provisioning files
#   ride from HEAD, the application from the tar; one SHA ties them) unless
#   --candidate-allow-provisioning-drift is given, which records both SHAs.
#
# Pipeline (every input is a pin in manifest.env; nothing is resolved "latest"):
#   1. fetch + verify the base cloud image (SHA256 pin, GPG when the Ubuntu
#      cloud-image keyring is present on the build host)
#   2. pull the application images BY DIGEST, assert the amd64 platform digest,
#      cosign-verify the proxy image against the pinned release identity
#   3. stage the overlay: docker-saved image tars, scripts/install.sh from THIS
#      checkout, provisioning + maintenance files, build-info.json
#   4. virt-customize (libguestfs; works under TCG — no KVM needed) runs
#      prepare-guest.sh inside the disk: pinned Docker packages, units, firewall,
#      sshd/cloud-init config, identity strip
#   5. verify from OUTSIDE the guest that no build-host residue survived
#   6. qemu-img → streamOptimized VMDK → OVF (+ .mf SHA256) → tar → .ova
#
# Outputs (in --out): culvert-appliance-<ver>-<os>.ova, .ova.sha256,
#   build-info.json, dpkg-list.txt (guest package inventory for SBOM evidence),
#   host-components.txt, build-upgrades.txt (packages the pinned-snapshot
#   security upgrade moved), prepare-guest.log (the in-guest transcript).
#
# Requires: qemu-img, guestfish, virt-customize, virt-cat, virt-ls, docker (daemon access),
# curl, gzip, tar, sha256sum, python3, the root go.mod Go compiler;
# gpgv + ubuntu-cloudimage-keyring optional.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
MANIFEST="$HERE/manifest.env"
# shellcheck source=appliance/build/archive-identity.sh
. "$HERE/archive-identity.sh"
# shellcheck source=appliance/build/console-bundle.sh
. "$HERE/console-bundle.sh"
OUT="$REPO/appliance/build/out"
WORK="${TMPDIR:-/tmp}/culvert-ova-build"
SKIP_COSIGN=0
STOP_AFTER=""
KEEP_WORK=0
CANDIDATE_TAR=""
CANDIDATE_SOURCE=""
CANDIDATE_RUN_ID=""
CANDIDATE_ALLOW_DRIFT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --skip-cosign) SKIP_COSIGN=1; shift ;;
    --stop-after) STOP_AFTER="$2"; shift 2 ;;
    --keep-work) KEEP_WORK=1; shift ;;
    --candidate-image-tar) CANDIDATE_TAR="$2"; shift 2 ;;
    --candidate-source) CANDIDATE_SOURCE="$2"; shift 2 ;;
    --candidate-run-id) CANDIDATE_RUN_ID="$2"; shift 2 ;;
    --candidate-allow-provisioning-drift) CANDIDATE_ALLOW_DRIFT=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[0;36m[build]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[build] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

set -a
# shellcheck source=appliance/build/manifest.env
. "$MANIFEST"
set +a
for v in BASE_IMAGE_URL BASE_IMAGE_SHA256 APP_IMAGE_REPO APP_IMAGE_TAG APP_IMAGE_INDEX_DIGEST \
         APP_IMAGE_AMD64_DIGEST CLAMAV_IMAGE_REPO CLAMAV_IMAGE_TAG CLAMAV_IMAGE_INDEX_DIGEST \
         CLAMAV_IMAGE_AMD64_DIGEST CLAMAV_SIDECAR_REF COLDLOAD_DIND_IMAGE DOCKER_CE_VERSION VM_DISK_GB VM_VCPUS VM_MEMORY_MB VM_HW_VERSION; do
  [[ -n "${!v:-}" ]] || die "manifest.env: $v is not set"
done

for t in qemu-img guestfish virt-customize virt-cat virt-ls docker curl gzip tar sha256sum python3 go; do
  command -v "$t" >/dev/null 2>&1 || die "required tool missing: $t"
done
CONSOLE_GO_VERSION="$(console_go_version "$REPO")"
docker info >/dev/null 2>&1 || die "docker daemon not reachable"
[[ -f "$REPO/scripts/install.sh" ]] || die "scripts/install.sh not found at $REPO"

# SOURCE_DATE_EPOCH: the git commit time of this checkout unless the caller
# pins one. Used for every mtime the build controls (tar, gzip).
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || date +%s)"
fi
export SOURCE_DATE_EPOCH
GIT_COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="false"; [[ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ]] && GIT_DIRTY="true"

mkdir -p "$OUT" "$WORK/cache" "$WORK/overlay"
# One build per work dir: a second run would recreate disk.qcow2 under the
# first (measured: `virt-resize: guestfs_launch failed` when two builds were
# launched into the same --work a minute apart).
exec 9>"$WORK/.lock"
flock -n 9 || die "another build is already using $WORK"
cleanup() { if [[ "$KEEP_WORK" -eq 0 ]]; then rm -rf "$WORK/overlay" "$WORK/disk.qcow2" "$WORK/ova"; fi; }
trap cleanup EXIT

# ── 1. Base image ───────────────────────────────────────────────────────────
BASE_FILE="$WORK/cache/$(basename "$BASE_IMAGE_URL")"
if [[ ! -f "$BASE_FILE" ]]; then
  log "downloading base image $(basename "$BASE_IMAGE_URL")"
  curl -fsSL -o "$BASE_FILE.part" "$BASE_IMAGE_URL" && mv "$BASE_FILE.part" "$BASE_FILE"
fi
echo "${BASE_IMAGE_SHA256}  ${BASE_FILE}" | sha256sum -c --quiet - || die "base image SHA256 mismatch (manifest BASE_IMAGE_SHA256)"
log "base image SHA256 OK"
BASE_GPG="skipped (keyring or gpgv not available on build host)"
if command -v gpgv >/dev/null 2>&1 && [[ -f "${BASE_IMAGE_KEYRING:-/nonexistent}" ]]; then
  curl -fsSL -o "$WORK/cache/SHA256SUMS" "$BASE_IMAGE_SUMS_URL"
  curl -fsSL -o "$WORK/cache/SHA256SUMS.gpg" "$BASE_IMAGE_SUMS_SIG_URL"
  gpgv --keyring "$BASE_IMAGE_KEYRING" "$WORK/cache/SHA256SUMS.gpg" "$WORK/cache/SHA256SUMS" 2>"$WORK/cache/gpgv.log" \
    || die "GPG verification of SHA256SUMS failed: $(cat "$WORK/cache/gpgv.log")"
  grep -q "^${BASE_IMAGE_SHA256} \*$(basename "$BASE_IMAGE_URL")$" "$WORK/cache/SHA256SUMS" \
    || die "pinned SHA256 is not the one Ubuntu signed for this image"
  BASE_GPG="verified ($(grep -o 'using RSA key [0-9A-F]*' "$WORK/cache/gpgv.log" | head -1))"
  log "base image GPG: $BASE_GPG"
fi

# Recorded in build-info.json (provenance; not a gate).
HOST_CONTAINERD="$(docker version --format '{{range .Server.Components}}{{if eq .Name "containerd"}}{{.Version}}{{end}}{{end}}')"
log "build host containerd: $HOST_CONTAINERD"

# ── 2. Application images by digest ─────────────────────────────────────────
pull_by_digest() { # repo index_digest amd64_digest tag
  local repo="$1" idx="$2" amd="$3" tag="$4"
  log "pulling ${repo}@${idx}"
  docker pull -q "${repo}@${idx}" >/dev/null
  local arch
  arch="$(docker image inspect "${repo}@${idx}" --format '{{.Architecture}}/{{.Os}}')"
  [[ "$arch" == "amd64/linux" ]] || die "${repo}@${idx} resolved to $arch, want amd64/linux"
  local got
  got="$(docker manifest inspect "${repo}@${idx}" | python3 -c '
import json,sys
m=json.load(sys.stdin)
for e in m.get("manifests",[]):
    p=e.get("platform",{})
    if p.get("architecture")=="amd64" and p.get("os")=="linux":
        print(e["digest"]); break')"
  [[ "$got" == "$amd" ]] || die "${repo}: amd64 platform digest is $got, manifest pins $amd"
  docker tag "${repo}@${idx}" "${repo}:${tag}"
}
# ClamAV is pulled AND saved before the candidate image archive is loaded.
# Loading that archive into the store first made every later ClamAV save
# hollow — index and manifests only, no config or layers (69,562 bytes), by
# tag, by digest or both — while a store that never loaded it saves the full
# image (F-OVA-CLAMAV-1; bisected in fresh disposable stores, lab run
# 37154350794). The closure and cold-load checks below verify the result.
pull_by_digest "$CLAMAV_IMAGE_REPO" "$CLAMAV_IMAGE_INDEX_DIGEST" "$CLAMAV_IMAGE_AMD64_DIGEST" "$CLAMAV_IMAGE_TAG"
# The sidecar the appliance runs is the pinned base + pcre2 10.49
# (CVE-2026-103111), built here from appliance/clamav and never published.
# Its FROM is the base digest pulled above, so the build reuses those layers.
# The derived image's identity is its ID in this (containerd) store, the same
# identity model as a candidate application image: recorded in the guest
# manifest and re-checked by first boot.
log "building the ClamAV sidecar $CLAMAV_SIDECAR_REF from appliance/clamav (pinned base + pcre2 fix)"
docker build -q --platform linux/amd64 -t "$CLAMAV_SIDECAR_REF" "$REPO/appliance/clamav" >/dev/null
CLAMAV_SIDECAR_ID="$(docker image inspect "$CLAMAV_SIDECAR_REF" --format '{{.Id}}')"
CLAMAV_PCRE2="$(docker run --rm --network none --entrypoint sh "$CLAMAV_SIDECAR_REF" -c "apk info -v 2>/dev/null | grep '^pcre2-[0-9]'")"
[[ "$CLAMAV_PCRE2" == "pcre2-10.49-r0" ]] || die "ClamAV sidecar carries $CLAMAV_PCRE2, want pcre2-10.49-r0 (CVE-2026-103111)"
CLAMAV_FIXED="$(docker run --rm --network none --entrypoint sh "$CLAMAV_SIDECAR_REF" -c "apk info -v 2>/dev/null | grep -E '^(zlib|nghttp2-libs)-[0-9]' | sort | tr '\n' ' '")"
[[ "$CLAMAV_FIXED" == "nghttp2-libs-1.70.0-r0 zlib-1.3.2-r1 " ]] || die "ClamAV sidecar carries $CLAMAV_FIXED, want nghttp2-libs-1.70.0-r0 zlib-1.3.2-r1 (CVE-2026-58055, CVE-2026-85091)"
log "ClamAV sidecar $CLAMAV_SIDECAR_REF = $CLAMAV_SIDECAR_ID ($CLAMAV_PCRE2 ${CLAMAV_FIXED% })"
mkdir -p "$WORK"
log "docker save ${CLAMAV_SIDECAR_REF} (before any archive is loaded)"
docker save "${CLAMAV_SIDECAR_REF}" | gzip -n -6 > "$WORK/clamav.tar.gz"
CANDIDATE=0
CANDIDATE_TAR_SHA=""
if [[ -n "$CANDIDATE_TAR" ]]; then
  CANDIDATE=1
  [[ -f "$CANDIDATE_TAR" ]] || die "--candidate-image-tar: $CANDIDATE_TAR not found"
  [[ "$CANDIDATE_SOURCE" =~ ^[0-9a-f]{40}$ ]] || die "--candidate-source must be the full 40-hex source commit the image was built from"
  if [[ "$CANDIDATE_SOURCE" != "$GIT_COMMIT" ]]; then
    if [[ "$CANDIDATE_ALLOW_DRIFT" -eq 1 ]]; then
      log "WARNING: candidate image source $CANDIDATE_SOURCE != provisioning checkout $GIT_COMMIT (recorded as provisioning drift)"
    else
      die "candidate image source ($CANDIDATE_SOURCE) differs from this checkout ($GIT_COMMIT); build from the same SHA, or pass --candidate-allow-provisioning-drift to record the mismatch"
    fi
  fi
  CANDIDATE_TAR_SHA="$(sha256sum "$CANDIDATE_TAR" | cut -d' ' -f1)"
  log "CANDIDATE build: docker load $CANDIDATE_TAR (sha256:$CANDIDATE_TAR_SHA)"
  loaded="$(docker load -q -i "$CANDIDATE_TAR" | sed -n 's/^Loaded image: //p' | head -1)"
  [[ -n "$loaded" ]] || die "docker load reported no image tag for $CANDIDATE_TAR"
  APP_IMAGE_REPO="culvert/candidate"
  APP_IMAGE_TAG="sha-${CANDIDATE_SOURCE:0:12}"
  docker tag "$loaded" "${APP_IMAGE_REPO}:${APP_IMAGE_TAG}"
  arch="$(docker image inspect "${APP_IMAGE_REPO}:${APP_IMAGE_TAG}" --format '{{.Architecture}}/{{.Os}}')"
  [[ "$arch" == "amd64/linux" ]] || die "candidate image is $arch, want amd64/linux"
  # No registry: the image ID is the identity the guest's first boot re-checks
  # after `docker load`. On the containerd image store this build requires,
  # .Id is the OCI MANIFEST digest the saved archive's index.json lists (not
  # the config digest, which only the classic store reports as .Id — and the
  # classic store is refused by archive_names_digest below).
  APP_IMAGE_INDEX_DIGEST="$(docker image inspect "${APP_IMAGE_REPO}:${APP_IMAGE_TAG}" --format '{{.Id}}')"
  APP_IMAGE_AMD64_DIGEST="$APP_IMAGE_INDEX_DIGEST"
  APP_REF="${APP_IMAGE_REPO}:${APP_IMAGE_TAG}"
  COSIGN_RESULT="not applicable — CANDIDATE build from an unsigned CI artifact; provenance = image tar sha256:${CANDIDATE_TAR_SHA}, source ${CANDIDATE_SOURCE}, CI run ${CANDIDATE_RUN_ID:-unspecified}"
else
  pull_by_digest "$APP_IMAGE_REPO" "$APP_IMAGE_INDEX_DIGEST" "$APP_IMAGE_AMD64_DIGEST" "$APP_IMAGE_TAG"
  APP_REF="${APP_IMAGE_REPO}@${APP_IMAGE_INDEX_DIGEST}"
  COSIGN_RESULT="skipped (--skip-cosign)"
fi

if [[ "$CANDIDATE" -eq 0 && "$SKIP_COSIGN" -eq 0 ]]; then
  log "cosign-verifying ${APP_IMAGE_REPO}@${APP_IMAGE_INDEX_DIGEST} (keyless, pinned identity)"
  # Honour a build-host HTTPS proxy + CA bundle if present; nothing of it reaches the guest.
  cosign_env=(--network host)
  [[ -n "${HTTPS_PROXY:-}" ]] && cosign_env+=(-e "HTTPS_PROXY=$HTTPS_PROXY")
  [[ -n "${SSL_CERT_FILE:-}" && -f "${SSL_CERT_FILE:-}" ]] && cosign_env+=(-e SSL_CERT_FILE=/build-ca.crt -v "$SSL_CERT_FILE:/build-ca.crt:ro")
  docker run --rm "${cosign_env[@]}" "$COSIGN_IMAGE" verify --timeout=120s \
    --certificate-oidc-issuer="$SIGSTORE_ISSUER" \
    --certificate-identity-regexp="$SIGSTORE_SAN_REGEX" \
    "${APP_IMAGE_REPO}@${APP_IMAGE_INDEX_DIGEST}" >"$WORK/cosign.log" 2>&1 \
    || die "cosign verification FAILED: $(tail -3 "$WORK/cosign.log")"
  COSIGN_RESULT="verified (issuer=$SIGSTORE_ISSUER san=$SIGSTORE_SAN_REGEX)"
fi

# Versions carried by the image (the deploy bundle's maintenance agent is the
# host component install.sh installs at first boot).
cid="$(docker create "$APP_REF")"
docker cp "$cid:/app/VERSION" "$WORK/app-VERSION" >/dev/null
docker cp "$cid:/app/deploy/bin/culvert-maint" "$WORK/culvert-maint" >/dev/null
docker rm "$cid" >/dev/null
APP_VERSION="$(tr -d '[:space:]' < "$WORK/app-VERSION")"
MAINT_VERSION="$("$WORK/culvert-maint" --version 2>/dev/null || echo unknown)"
rm -f "$WORK/culvert-maint" "$WORK/app-VERSION"

if [[ "$CANDIDATE" -eq 1 ]]; then
  # The candidate image must carry the SemVer prerelease stamp naming THIS
  # source commit (.github/scripts/pr-candidate-version.sh), and its bundled
  # maintenance agent the same version: first boot installs that agent only
  # from a release-shaped stamp, and a "dev" or foreign-commit image would
  # build an OVA whose agent, labels and provenance disagree (PR #1528 §3f L11).
  want_pre="-candidate.g${CANDIDATE_SOURCE:0:12}"
  [[ "$APP_VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+-candidate\.g[0-9a-f]{12}$ && "$APP_VERSION" == *"$want_pre" ]] \
    || die "candidate image version '$APP_VERSION' is not the candidate stamp for source ${CANDIDATE_SOURCE:0:12} (want vX.Y.Z${want_pre}; build the image with VERSION from .github/scripts/pr-candidate-version.sh)"
  [[ "$MAINT_VERSION" == "v${APP_VERSION#v}" ]] \
    || die "bundled maintenance agent reports '$MAINT_VERSION', proxy '$APP_VERSION' — the two must carry one candidate version"
  VERSION="${APPLIANCE_VERSION:-${APP_VERSION#v}}"
  APPLIANCE_PRODUCT="$APPLIANCE_PRODUCT (CANDIDATE — qualification build, not for production)"
else
  VERSION="${APPLIANCE_VERSION:-${APP_IMAGE_TAG#v}}"
fi
OVA_BASENAME="${APPLIANCE_NAME}-${VERSION}-${GUEST_OS_ID}"

# ── 3. Overlay ──────────────────────────────────────────────────────────────
OV="$WORK/overlay"
rm -rf "$OV"; mkdir -p "$OV/opt/culvert-appliance" "$OV/var/lib/culvert-appliance/images"
# Copy only runtime inputs. Recursive directory copies also shipped host test
# scripts and could pick up ignored local material from a developer checkout.
mkdir -p "$OV/opt/culvert-appliance/provision" "$OV/opt/culvert-appliance/os-maintenance"
for runtime_file in 60-culvert-readahead.rules cloud-90-culvert.cfg culvert-appliance-reset-identity \
  culvert-firstboot.service culvert-firstboot.sh culvert-issue-update \
  culvert-issue.service culvert-issue.timer culvert-net culvert-status \
  culvert-sudo-policy nftables.conf sshd-50-culvert.conf; do
  [[ -f "$REPO/appliance/provision/$runtime_file" && ! -L "$REPO/appliance/provision/$runtime_file" ]] \
    || die "missing or symlinked provisioning input: $runtime_file"
  install -m 0644 "$REPO/appliance/provision/$runtime_file" "$OV/opt/culvert-appliance/provision/$runtime_file"
done
for runtime_file in 20auto-upgrades-culvert 50unattended-upgrades-culvert \
  culvert-os-update culvert-stack-resume.service; do
  [[ -f "$REPO/appliance/os-maintenance/$runtime_file" && ! -L "$REPO/appliance/os-maintenance/$runtime_file" ]] \
    || die "missing or symlinked maintenance input: $runtime_file"
  install -m 0644 "$REPO/appliance/os-maintenance/$runtime_file" "$OV/opt/culvert-appliance/os-maintenance/$runtime_file"
done
mkdir -p "$OV/opt/culvert-appliance/boot-splash"
for splash_file in install.sh install-lib.sh culvert.plymouth 99-culvert-splash.cfg \
  culvert-splash-message culvert-kernel-log-vt culvert-kernel-log-vt.service plymouthd.conf \
  culvert-has-display plymouth-start-headless.conf; do
  cp "$REPO/appliance/boot-splash/$splash_file" "$OV/opt/culvert-appliance/boot-splash/$splash_file"
done
build_console_bundle "$REPO" "$OV/opt/culvert-appliance/console"
CONSOLE_BINARY_SHA="$(sha256sum "$OV/opt/culvert-appliance/console/culvert-console" | cut -d' ' -f1)"
ACCESS_BINARY_SHA="$(sha256sum "$OV/opt/culvert-appliance/console/culvert-access" | cut -d' ' -f1)"
cp "$REPO/scripts/install.sh" "$OV/opt/culvert-appliance/install.sh"
cp "$MANIFEST" "$OV/var/lib/culvert-appliance/manifest.env"
# The built sidecar's identity (first boot refuses a loaded image without it).
printf '\n# ── ClamAV sidecar built by build-ova.sh ──\nCLAMAV_SIDECAR_ID=%s\n' "$CLAMAV_SIDECAR_ID" \
  >> "$OV/var/lib/culvert-appliance/manifest.env"
if [[ "$CANDIDATE" -eq 1 ]]; then
  # Later keys win when the guest sources the manifest: the application pins
  # now name the loaded candidate image, and CANDIDATE_BUILD=1 is what makes
  # culvert-firstboot export the agent's break-glass trust (nowhere else).
  {
    echo
    echo "# ── CANDIDATE build overrides (appended by build-ova.sh --candidate-image-tar) ──"
    echo "CANDIDATE_BUILD=1"
    echo "CANDIDATE_SOURCE_SHA=$CANDIDATE_SOURCE"
    echo "CANDIDATE_PROVISIONING_SHA=$GIT_COMMIT"
    echo "CANDIDATE_IMAGE_TAR_SHA256=$CANDIDATE_TAR_SHA"
    echo "CANDIDATE_CI_RUN_ID=${CANDIDATE_RUN_ID:-}"
    echo "APP_IMAGE_REPO=$APP_IMAGE_REPO"
    echo "APP_IMAGE_TAG=$APP_IMAGE_TAG"
    echo "APP_IMAGE_INDEX_DIGEST=$APP_IMAGE_INDEX_DIGEST"
    echo "APP_IMAGE_AMD64_DIGEST=$APP_IMAGE_AMD64_DIGEST"
  } >> "$OV/var/lib/culvert-appliance/manifest.env"
fi
mkdir -p "$OV/opt/culvert-appliance/bin"
# prepare-guest.sh rides in the overlay: virt-customize --run executes a script
# with /bin/sh (dash) regardless of its shebang, so it is invoked via bash.
cp "$HERE/prepare-guest.sh" "$OV/opt/culvert-appliance/prepare-guest.sh"

# ── BUILD-HOST-ONLY accommodation: an intercepting HTTPS proxy ──────────────
# A sandboxed build host may force outbound HTTPS through a local proxy
# (HTTPS_PROXY=http://127.0.0.1:PORT with its own CA). Inside the libguestfs
# appliance 127.0.0.1 is the GUEST; qemu user-mode networking (slirp) exposes
# the build host's loopback at the guest's DEFAULT GATEWAY (libguestfs uses
# 169.254.2.15/16, so that is 169.254.0.2 — NOT the generic 10.0.2.2). Only the
# PORT is handed over; prepare-guest.sh derives the host from its own default
# route. The CA bundle rides along, FOR THE BUILD ONLY.
# prepare-guest.sh consumes build-env.sh for curl/apt-over-https, then deletes
# every trace (apt conf, CA file, trust-store entry, build-env.sh); the
# outside-the-guest checks below refuse to package if any survived. An
# ordinary build host with direct egress writes nothing here.
BUILD_PROXY_CA_LINE=""
if [[ -n "${HTTPS_PROXY:-}" ]]; then
  pport="${HTTPS_PROXY##*:}"; pport="${pport%%/*}"
  [[ "$pport" =~ ^[0-9]+$ ]] || die "cannot parse a port from HTTPS_PROXY=$HTTPS_PROXY"
  log "build host uses an HTTPS proxy — handing port $pport to the guest (reached via its default gateway; build only, stripped afterwards)"
  printf 'BUILD_HTTPS_PROXY_PORT=%s\n' "$pport" > "$OV/var/lib/culvert-appliance/build-env.sh"
  if [[ -n "${SSL_CERT_FILE:-}" && -f "${SSL_CERT_FILE:-}" ]]; then
    cp "$SSL_CERT_FILE" "$OV/var/lib/culvert-appliance/build-ca.crt"
    # a distinctive line of the CA bundle, used to prove it left the guest trust store
    BUILD_PROXY_CA_LINE="$(awk '!/-----/ { print; exit }' "$SSL_CERT_FILE")"
  fi
fi

save_image() { # ref out.tar.gz
  log "docker save $1"
  docker save "$1" | gzip -n -6 > "$2"
}
save_image "${APP_IMAGE_REPO}:${APP_IMAGE_TAG}"       "$OV/var/lib/culvert-appliance/images/culvert.tar.gz"
mv "$WORK/clamav.tar.gz" "$OV/var/lib/culvert-appliance/images/clamav.tar.gz"  # saved before the candidate load (above)
# First boot checks the loaded image against APP_IMAGE_INDEX_DIGEST; prove the
# archive carries that identity before baking it (archive-identity.sh).
archive_names_digest "$OV/var/lib/culvert-appliance/images/culvert.tar.gz" "$APP_IMAGE_INDEX_DIGEST" \
  || die "the saved application archive does not carry $APP_IMAGE_INDEX_DIGEST — the first boot would refuse it. Build on a Docker daemon with the containerd image store (daemon.json: {\"features\":{\"containerd-snapshotter\":true}})"
# Both archives must CARRY a complete linux/amd64 image (manifest, config and
# every layer, size and digest checked), not merely name one: a 69 KB ClamAV
# archive with no layers loaded "successfully" and broke first boot
# (archive-identity.sh, F-OVA-CLAMAV-1).
archive_platform_closure "$OV/var/lib/culvert-appliance/images/culvert.tar.gz" linux/amd64 "$APP_IMAGE_INDEX_DIGEST" "$APP_IMAGE_AMD64_DIGEST" \
  || die "the saved application archive does not carry the complete pinned linux/amd64 image — refusing to bake it"
archive_platform_closure "$OV/var/lib/culvert-appliance/images/clamav.tar.gz" linux/amd64 "$CLAMAV_SIDECAR_ID" "$CLAMAV_SIDECAR_ID" \
  || die "the saved ClamAV archive does not carry the complete built linux/amd64 sidecar image — refusing to bake it"
# ...and must RUN from that content alone: load into an empty disposable
# containerd store with no registry, create a container, execute a binary.
"$HERE/cold-load-check.sh" --dind "$COLDLOAD_DIND_IMAGE" \
  --archive "$OV/var/lib/culvert-appliance/images/culvert.tar.gz" --ref "${APP_IMAGE_REPO}:${APP_IMAGE_TAG}" \
  --id "$APP_IMAGE_INDEX_DIGEST" --run "/app/deploy/bin/culvert-maint -version" \
  || die "the application archive does not run from its own content in an empty store — refusing to bake it"
"$HERE/cold-load-check.sh" --dind "$COLDLOAD_DIND_IMAGE" \
  --archive "$OV/var/lib/culvert-appliance/images/clamav.tar.gz" --ref "$CLAMAV_SIDECAR_REF" \
  --id "$CLAMAV_SIDECAR_ID" --run "clamd --version" \
  || die "the ClamAV archive does not run from its own content in an empty store — refusing to bake it"
APP_TAR_SHA="$(sha256sum "$OV/var/lib/culvert-appliance/images/culvert.tar.gz" | cut -d' ' -f1)"
CLAM_TAR_SHA="$(sha256sum "$OV/var/lib/culvert-appliance/images/clamav.tar.gz" | cut -d' ' -f1)"
INSTALL_SHA="$(sha256sum "$REPO/scripts/install.sh" | cut -d' ' -f1)"

BUILD_TS="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
BUILD_WALL="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BI_INSTALL_SHA="$INSTALL_SHA" BI_APP_VERSION="$APP_VERSION" BI_MAINT_VERSION="$MAINT_VERSION" \
BI_CLAM_SIDECAR_ID="$CLAMAV_SIDECAR_ID" BI_CLAM_PCRE2="$CLAMAV_PCRE2" \
BI_CONTAINERD="$HOST_CONTAINERD" BI_COSIGN="$COSIGN_RESULT" BI_BASE_GPG="$BASE_GPG" BI_APP_TAR_SHA="$APP_TAR_SHA" BI_CLAM_TAR_SHA="$CLAM_TAR_SHA" \
BI_VERSION="$VERSION" BI_OVA="$OVA_BASENAME.ova" BI_GIT_COMMIT="$GIT_COMMIT" BI_GIT_DIRTY="$GIT_DIRTY" \
BI_BUILD_TS="$BUILD_TS" BI_BUILD_WALL="$BUILD_WALL" \
BI_CONSOLE_GO_VERSION="$CONSOLE_GO_VERSION" BI_CONSOLE_BINARY_SHA="$CONSOLE_BINARY_SHA" \
BI_CANDIDATE="$CANDIDATE" BI_CANDIDATE_SOURCE="$CANDIDATE_SOURCE" BI_CANDIDATE_TAR_SHA="$CANDIDATE_TAR_SHA" BI_CANDIDATE_RUN_ID="$CANDIDATE_RUN_ID" \
python3 - "$OV/var/lib/culvert-appliance/build-info.json" <<'PY'
import json, os, subprocess, sys
E = os.environ
def v(cmd):
    try: return subprocess.check_output(cmd, shell=True, text=True).strip()
    except Exception: return "unknown"
info = {
  "schema": 1,
  "appliance": {"name": E["APPLIANCE_NAME"], "version": E["BI_VERSION"], "arch": E["APPLIANCE_ARCH"],
                "ova": E["BI_OVA"], "product": E["APPLIANCE_PRODUCT"]},
  "source": {"git_commit": E["BI_GIT_COMMIT"], "git_dirty": E["BI_GIT_DIRTY"] == "true",
             "source_date_epoch": int(E["SOURCE_DATE_EPOCH"]), "build_timestamp": E["BI_BUILD_TS"],
             "build_wallclock": E["BI_BUILD_WALL"], "install_sh_sha256": E["BI_INSTALL_SHA"]},
  "console": {"source_git_commit": E["BI_GIT_COMMIT"], "source_git_dirty": E["BI_GIT_DIRTY"] == "true",
              "go_compiler": E["BI_CONSOLE_GO_VERSION"], "binary_sha256": E["BI_CONSOLE_BINARY_SHA"],
              "target": "linux/amd64", "cgo_enabled": False,
              "origin": "built from this provisioning checkout; separate from the application image"},
  "guest_os": {"id": E["GUEST_OS_ID"], "name": E["GUEST_OS_NAME"], "codename": E["GUEST_OS_CODENAME"],
               "base_image_url": E["BASE_IMAGE_URL"], "base_image_sha256": E["BASE_IMAGE_SHA256"],
               "base_image_serial": E["BASE_IMAGE_SERIAL"], "base_image_gpg": E["BI_BASE_GPG"],
               "standard_support_until": E["GUEST_OS_STANDARD_SUPPORT_UNTIL"], "esm_support_until": E["GUEST_OS_ESM_SUPPORT_UNTIL"],
               "package_sources": [E["BASE_IMAGE_URL"] + " (preinstalled)",
                                   E["DOCKER_APT_URL"] + " " + E["GUEST_OS_CODENAME"] + " stable (key " + E["DOCKER_APT_KEY_FPR"] + ")"]},
  "host_components_pinned": {"docker-ce": E["DOCKER_CE_VERSION"], "docker-ce-cli": E["DOCKER_CE_CLI_VERSION"],
               "containerd.io": E["CONTAINERD_IO_VERSION"], "docker-compose-plugin": E["DOCKER_COMPOSE_PLUGIN_VERSION"],
               "culvert-maint (from image deploy bundle)": E["BI_MAINT_VERSION"]},
  "application": {"image": E["APP_IMAGE_REPO"], "tag": E["APP_IMAGE_TAG"], "index_digest": E["APP_IMAGE_INDEX_DIGEST"],
                  "amd64_digest": E["APP_IMAGE_AMD64_DIGEST"], "app_version_file": E["BI_APP_VERSION"],
                  "cosign": E["BI_COSIGN"], "baked_tar_sha256": E["BI_APP_TAR_SHA"],
                  "clamav_image": E["CLAMAV_IMAGE_REPO"], "clamav_tag": E["CLAMAV_IMAGE_TAG"],
                  "clamav_index_digest": E["CLAMAV_IMAGE_INDEX_DIGEST"], "clamav_amd64_digest": E["CLAMAV_IMAGE_AMD64_DIGEST"],
                  "clamav_baked_tar_sha256": E["BI_CLAM_TAR_SHA"],
                  "clamav_sidecar_ref": E["CLAMAV_SIDECAR_REF"], "clamav_sidecar_image_id": E["BI_CLAM_SIDECAR_ID"],
                  "clamav_sidecar_pcre2": E["BI_CLAM_PCRE2"]},
  "virtual_hardware": {"vcpus": int(E["VM_VCPUS"]), "memory_mb": int(E["VM_MEMORY_MB"]), "disk_gb": int(E["VM_DISK_GB"]),
                       "hw_version": E["VM_HW_VERSION"], "nic": "E1000 x1", "disk_format": "vmdk streamOptimized (thin)"},
  "build_tools": {"qemu-img": v("qemu-img --version | head -1"), "libguestfs": v("virt-customize --version"),
                  "docker": v("docker version --format '{{.Server.Version}}'"),
                  "containerd": E["BI_CONTAINERD"], "cosign_image": E["COSIGN_IMAGE"],
                  "build_host": v(". /etc/os-release && echo $PRETTY_NAME"), "kvm": v("test -e /dev/kvm && echo yes || echo 'no (TCG)'")}
}
if E["BI_CANDIDATE"] == "1":
    info["candidate"] = {
        "candidate": True,
        "not_for_production": True,
        "image_source_git_commit": E["BI_CANDIDATE_SOURCE"],
        "provisioning_git_commit": E["BI_GIT_COMMIT"],
        "provisioning_drift": E["BI_CANDIDATE_SOURCE"] != E["BI_GIT_COMMIT"],
        "image_tar_sha256": E["BI_CANDIDATE_TAR_SHA"],
        "ci_run_id": E["BI_CANDIDATE_RUN_ID"] or None,
        "image_signature": "none (unsigned CI artifact; release signature verification is not bypassed, it is inapplicable)",
        "agent_trust": "culvert-firstboot exports CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1 because the manifest carries CANDIDATE_BUILD=1 (candidate-scoped; a release OVA never sets it)",
    }
json.dump(info, open(sys.argv[1], "w"), indent=2); open(sys.argv[1], "a").write("\n")
PY
cp "$OV/var/lib/culvert-appliance/build-info.json" "$OUT/build-info.json"
log "build-info.json written"

# ── 4. Disk ─────────────────────────────────────────────────────────────────
DISK="$WORK/disk.qcow2"
log "preparing ${VM_DISK_GB}G qcow2 working disk (root partition grown IN PLACE at build time)"
# The cloud image's root partition is ~2.4 GB and cloud-init's growpart only
# runs at FIRST BOOT, so a plain `qemu-img resize` leaves the build with the
# original filesystem — measured: the Docker install hit ENOSPC at 100 %.
# The root partition (sda1) is the LAST one on the disk, so it is grown in
# place: GPT backup header moved to the new end, sda1's end extended, the
# filesystem checked and resized. NOT virt-resize: it copies partitions into a
# fresh table and RENUMBERS them (14,15,16,1 → 1,2,3,4), while the BIOS GRUB
# core image embedded in the BIOS-boot partition still names its /boot as
# partition 16 — every BIOS boot then stopped at "error: no such partition /
# grub rescue>" (appliance lab, test/appliance-lab; UEFI was unaffected
# because its grub.cfg finds /boot by UUID). The layout must stay the vendor's.
rm -f "$DISK"
qemu-img convert -q -O qcow2 "$BASE_FILE" "$DISK"
qemu-img resize -q "$DISK" "${VM_DISK_GB}G"
part_layout() { LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}" guestfish --ro -a "$1" run : part-list /dev/sda | awk '/part_num:/{n=$2} /part_start:/{print n":"$2}' | tr '\n' ' '; }
layout_before="$(part_layout "$DISK")"
LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}" guestfish -a "$DISK" <<'GF' || die "growing the root partition in place failed"
run
part-expand-gpt /dev/sda
part-resize /dev/sda 1 -34
e2fsck-f /dev/sda1
resize2fs /dev/sda1
GF
layout_after="$(part_layout "$DISK")"
# Same partition numbers at the same starts: only sda1's END may move.
[[ "$layout_before" == "$layout_after" ]] || die "partition layout changed while growing root (before: $layout_before; after: $layout_after) — BIOS GRUB would not find /boot"
log "root grown in place; partition numbers/starts unchanged: $layout_after"

log "virt-customize (libguestfs; this runs the guest under TCG when no KVM is present — expect 10-30 min)"
# The host's proxy variables must NOT reach the guest (libguestfs forwards
# them; 127.0.0.1 means the guest there) — the guest gets build-env.sh instead.
set +e
env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u NO_PROXY -u no_proxy \
virt-customize -a "$DISK" --smp 2 --memsize 2048 \
  --hostname culvert-appliance --timezone UTC \
  --copy-in "$OV/opt/culvert-appliance:/opt" \
  --copy-in "$OV/var/lib/culvert-appliance:/var/lib" \
  --run-command "bash /opt/culvert-appliance/prepare-guest.sh" \
  --no-logfile 2>&1 | tee "$WORK/virt-customize.log" | grep -v '^\[ *[0-9.]*\] Running: '
VC_RC="${PIPESTATUS[0]}"
set -e
# virt-customize shows a --run-command's output on the host ONLY when the
# command fails (it is redirected into the guest's /tmp/builder.log), so the
# host-side log cannot prove success. prepare-guest.sh writes its transcript
# and a completion marker inside the guest; both are read back here.
virt-cat -a "$DISK" /var/lib/culvert-appliance/prepare-guest.log > "$OUT/prepare-guest.log" 2>/dev/null || true
[[ "$VC_RC" -eq 0 ]] || die "virt-customize exited $VC_RC (see $WORK/virt-customize.log and $OUT/prepare-guest.log)"
PREP_DONE="$(virt-cat -a "$DISK" /var/lib/culvert-appliance/prepare-guest.done 2>/dev/null || true)"
[[ -n "$PREP_DONE" ]] || die "prepare-guest.sh did not finish: no completion marker in the guest (see $OUT/prepare-guest.log)"
grep -q '^prepare-guest: done$' "$OUT/prepare-guest.log" || die "prepare-guest.sh transcript is incomplete (see $OUT/prepare-guest.log)"
log "prepare-guest.sh completed in the guest at $PREP_DONE"

# ── 5. Outside-the-guest checks ─────────────────────────────────────────────
log "verifying guest contents"
CONSOLE_INSTALLED_SHA="$(virt-cat -a "$DISK" /opt/culvert-appliance/bin/culvert-console | sha256sum | cut -d' ' -f1)"
[[ "$CONSOLE_INSTALLED_SHA" == "$CONSOLE_BINARY_SHA" ]] || die "installed console binary does not match its recorded build hash"
ACCESS_INSTALLED_SHA="$(virt-cat -a "$DISK" /opt/culvert-appliance/bin/culvert-access | sha256sum | cut -d' ' -f1)"
[[ "$ACCESS_INSTALLED_SHA" == "$ACCESS_BINARY_SHA" ]] || die "installed access binary does not match its recorded build hash"
SPLASH_THEME_SHA="$(sha256sum "$REPO/appliance/boot-splash/culvert.plymouth" | cut -d' ' -f1)"
for splash_name in default.plymouth text.plymouth culvert/culvert.plymouth; do
  installed_splash_sha="$(virt-cat -a "$DISK" "/usr/share/plymouth/themes/$splash_name" | sha256sum | cut -d' ' -f1)"
  [[ "$installed_splash_sha" == "$SPLASH_THEME_SHA" ]] || die "boot theme differs from source: $splash_name"
done
SPLASH_GRUB_SHA="$(sha256sum "$REPO/appliance/boot-splash/99-culvert-splash.cfg" | cut -d' ' -f1)"
installed_splash_sha="$(virt-cat -a "$DISK" /etc/default/grub.d/99-culvert-splash.cfg | sha256sum | cut -d' ' -f1)"
[[ "$installed_splash_sha" == "$SPLASH_GRUB_SHA" ]] || die "boot presentation configuration differs from source"
for splash_pair in culvert-splash-message:/etc/initramfs-tools/scripts/init-premount/culvert-splash-message \
  culvert-kernel-log-vt:/opt/culvert-appliance/bin/culvert-kernel-log-vt \
  culvert-kernel-log-vt.service:/etc/systemd/system/culvert-kernel-log-vt.service \
  plymouthd.conf:/etc/plymouth/plymouthd.conf \
  culvert-has-display:/opt/culvert-appliance/bin/culvert-has-display \
  plymouth-start-headless.conf:/etc/systemd/system/plymouth-start.service.d/culvert-headless.conf; do
  installed_splash_sha="$(virt-cat -a "$DISK" "${splash_pair#*:}" | sha256sum | cut -d' ' -f1)"
  [[ "$installed_splash_sha" == "$(sha256sum "$REPO/appliance/boot-splash/${splash_pair%%:*}" | cut -d' ' -f1)" ]] \
    || die "boot console file differs from source: ${splash_pair#*:}"
done
virt-cat -a "$DISK" /var/lib/culvert-appliance/dpkg-list.txt       > "$OUT/dpkg-list.txt"
virt-cat -a "$DISK" /var/lib/culvert-appliance/host-components.txt > "$OUT/host-components.txt"
# Present only when manifest.env pins GUEST_APT_SNAPSHOT (prepare-guest.sh 1b).
virt-cat -a "$DISK" /var/lib/culvert-appliance/build-upgrades.txt > "$OUT/build-upgrades.txt" 2>/dev/null || rm -f "$OUT/build-upgrades.txt"
grep -q "^docker-ce	${DOCKER_CE_VERSION}	amd64$" "$OUT/dpkg-list.txt" || die "docker-ce is not the pinned version in the guest"
[[ "$(virt-cat -a "$DISK" /etc/machine-id | wc -c)" -eq 0 ]] || die "machine-id not empty"
if virt-ls -a "$DISK" /etc/ssh/ | grep -q '^ssh_host_'; then die "ssh host keys present in image"; fi
if virt-ls -a "$DISK" /etc/apt/apt.conf.d/ | grep -qi proxy; then die "apt proxy config leaked into image"; fi
if virt-ls -a "$DISK" /var/lib/culvert-appliance/ | grep -qE '^build-(env\.sh|ca\.crt)$'; then die "build proxy/CA material leaked into image"; fi
if virt-ls -a "$DISK" /usr/local/share/ca-certificates/ 2>/dev/null | grep -q .; then die "a build CA is still in /usr/local/share/ca-certificates"; fi
if [[ -n "$BUILD_PROXY_CA_LINE" ]] && virt-cat -a "$DISK" /etc/ssl/certs/ca-certificates.crt | grep -qF -- "$BUILD_PROXY_CA_LINE"; then die "build proxy CA still in the guest trust store"; fi
if virt-cat -a "$DISK" /etc/environment | grep -qi proxy; then die "proxy variables leaked into /etc/environment"; fi
if virt-ls -a "$DISK" /home/culvert/ 2>/dev/null | grep -q '^\.ssh$'; then die "authorized keys leaked into image"; fi
shadow_line="$(virt-cat -a "$DISK" /etc/shadow | grep '^culvert:' || true)"
[[ "$shadow_line" == culvert:!* ]] || die "console account is not locked in the image"
operator_shadow="$(virt-cat -a "$DISK" /etc/shadow | grep '^culvert-operator:' || true)"
[[ "$operator_shadow" == culvert-operator:!* ]] || die "operator password is not locked in the image"
if virt-ls -a "$DISK" /etc/ssh/culvert-authorized-keys/ | grep -q .; then die "operator keys leaked into image"; fi
log "guest checks OK (pinned docker, empty machine-id, no host keys, no proxy/CA residue, console account locked)"
[[ "$STOP_AFTER" == "disk" ]] && { cp "$DISK" "$OUT/$OVA_BASENAME.qcow2"; log "stopped after disk: $OUT/$OVA_BASENAME.qcow2"; KEEP_WORK=1; exit 0; }

# ── 6. VMDK + OVF + OVA ─────────────────────────────────────────────────────
OVADIR="$WORK/ova"; rm -rf "$OVADIR"; mkdir -p "$OVADIR"
VMDK="$OVADIR/$OVA_BASENAME-disk1.vmdk"
log "converting to streamOptimized VMDK"
qemu-img convert -p -f qcow2 -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "$DISK" "$VMDK" | tr '\r' '\n' | tail -1
VMDK_SIZE="$(stat -c %s "$VMDK")"
POPULATED="$(qemu-img info --output=json "$DISK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["actual-size"])')"
[[ "$STOP_AFTER" == "vmdk" ]] && { cp "$VMDK" "$OUT/"; log "stopped after vmdk: $OUT/$(basename "$VMDK")"; KEEP_WORK=1; exit 0; }

OVF="$OVADIR/$OVA_BASENAME.ovf"
python3 - "$HERE/culvert-appliance.ovf.tmpl" "$OVF" <<PY
import sys, html
t = open(sys.argv[1]).read()
subs = {
 "@@VMDK_NAME@@": "$(basename "$VMDK")", "@@VMDK_SIZE@@": "$VMDK_SIZE", "@@VMDK_POPULATED@@": "$POPULATED",
 "@@DISK_GB@@": "$VM_DISK_GB", "@@VM_NAME@@": "$OVA_BASENAME", "@@HW_VERSION@@": "$VM_HW_VERSION",
 "@@VCPUS@@": "$VM_VCPUS", "@@MEMORY_MB@@": "$VM_MEMORY_MB",
 "@@PRODUCT@@": html.escape("$APPLIANCE_PRODUCT"), "@@VENDOR@@": "$APPLIANCE_VENDOR",
 "@@VERSION@@": "$VERSION", "@@FULL_VERSION@@": html.escape("$VERSION ($GUEST_OS_NAME, app $APP_IMAGE_TAG, commit ${GIT_COMMIT:0:12})" + (" — CANDIDATE qualification build from source ${CANDIDATE_SOURCE:0:12}, NOT FOR PRODUCTION" if "$CANDIDATE" == "1" else "")),
}
for k, v in subs.items(): t = t.replace(k, v)
assert "@@" not in t, "unsubstituted token in OVF"
open(sys.argv[2], "w").write(t)
PY
python3 -c "import xml.dom.minidom,sys; xml.dom.minidom.parse(sys.argv[1])" "$OVF"

MF="$OVADIR/$OVA_BASENAME.mf"
( cd "$OVADIR" && {
    printf 'SHA256(%s)= %s\n' "$(basename "$OVF")"  "$(sha256sum "$(basename "$OVF")"  | cut -d' ' -f1)"
    printf 'SHA256(%s)= %s\n' "$(basename "$VMDK")" "$(sha256sum "$(basename "$VMDK")" | cut -d' ' -f1)"
  } > "$MF" )

OVA="$OUT/$OVA_BASENAME.ova"
log "packing $OVA"
# OVF spec: descriptor first, then disks, then the manifest. ustar, fixed
# owner and mtime so the archive layout is deterministic for identical inputs.
( cd "$OVADIR" && tar --format=ustar --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" -cf "$OVA" \
    "$(basename "$OVF")" "$(basename "$VMDK")" "$(basename "$MF")" )
( cd "$OUT" && sha256sum "$(basename "$OVA")" > "$(basename "$OVA").sha256" )
python3 - "$OUT/build-info.json" "$OVA" <<PY
import json, sys, hashlib, os
p=sys.argv[1]; d=json.load(open(p))
d["artifact"]={"ova": os.path.basename(sys.argv[2]), "size_bytes": os.path.getsize(sys.argv[2]),
               "sha256": hashlib.sha256(open(sys.argv[2],"rb").read()).hexdigest()}
json.dump(d, open(p,"w"), indent=2); open(p,"a").write("\n")
PY
log "done: $OVA ($(du -h "$OVA" | cut -f1))"
log "build-info: $OUT/build-info.json"
