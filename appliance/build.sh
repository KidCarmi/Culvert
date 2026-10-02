#!/usr/bin/env bash
# build.sh — reproducible Culvert appliance (OVA) build. Host side.
#
#   appliance/build.sh [--out DIR] [--work DIR] [--accel auto|kvm|tcg]
#                      [--skip-fetch] [--skip-bake]
#
# Inputs are pinned in appliance/manifest.env; every digest actually consumed
# is written to <out>/<name>.build-record.json. Stages:
#   fetch   guest cloud image (sha256-verified), application image (pulled by
#           digest, cosign-verified against release_identity.env), clamav image
#           (digest-verified), pinned docker-ce .debs (resolved in a throwaway
#           ubuntu container, Packages index generated)
#   payload one ISO9660 disk with all of the above + appliance/guest + vendored
#           scripts/install.sh — the bake VM has NO network
#   bake    boot the cloud image under QEMU with a NoCloud seed that runs
#           appliance/bake/bake.sh (installs docker, preloads images, installs
#           first-boot units, scrubs identity, powers off)
#   package qcow2 → streamOptimized VMDK, OVF from template, manifest, OVA, sums
#
# Tools: bash, docker (daemon), cosign, qemu-img, qemu-system-x86_64,
#        cloud-localds, genisoimage, curl, sha256sum, tar, git.
# shellcheck disable=SC1091  # manifest.env / release_identity.env / os-release are data files, not scripts to follow
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

. "$HERE/manifest.env"

OUT="$REPO/appliance-out"; WORK=""; ACCEL=auto; SKIP_FETCH=0; SKIP_BAKE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$(mkdir -p "$2" && cd "$2" && pwd)"; shift ;;
    --work) WORK="$(mkdir -p "$2" && cd "$2" && pwd)"; shift ;;
    --accel) ACCEL="$2"; shift ;;
    --skip-fetch) SKIP_FETCH=1 ;;
    --skip-bake) SKIP_BAKE=1 ;;
    -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ -n "$WORK" ]] || WORK="$OUT/work"
mkdir -p "$OUT" "$WORK"
PAYLOAD="$WORK/payload"
NAME="${APPLIANCE_NAME:?}-${APPLIANCE_VERSION:?}"
OUT_DIR="${OUT:?}/${NAME:?}"

log() { printf '\033[1;34m[build]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[build] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
json_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

for t in docker cosign qemu-img qemu-system-x86_64 cloud-localds genisoimage curl sha256sum tar git; do need "$t"; done
docker info >/dev/null 2>&1 || die "docker daemon not reachable"
[[ "$(uname -m)" == "x86_64" ]] || die "x86_64 build host required (guest is ${APPLIANCE_ARCH})"
if [[ "$ACCEL" == auto ]]; then if [[ -w /dev/kvm ]]; then ACCEL=kvm; else ACCEL=tcg; fi; fi
case "$ACCEL" in kvm) CPU=host ;; tcg) CPU=max ;; *) die "--accel must be auto|kvm|tcg" ;; esac
GIT_SHA="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY=false; if git -C "$REPO" status --porcelain 2>/dev/null | grep -q .; then GIT_DIRTY=true; fi
log "building ${NAME} from ${GIT_SHA} (dirty=${GIT_DIRTY}) accel=${ACCEL} out=${OUT}"

# ── fetch ────────────────────────────────────────────────────────────────────
GUEST_IMG="$WORK/guest-base.img"
if [[ ! -f "$GUEST_IMG" ]] || [[ "$(sha "$GUEST_IMG")" != "$GUEST_IMAGE_SHA256" ]]; then
  [[ "$SKIP_FETCH" == 0 ]] || die "--skip-fetch but ${GUEST_IMG} is missing/stale"
  log "fetch: guest image ${GUEST_IMAGE_URL}"
  curl -fsSL -o "$GUEST_IMG" "$GUEST_IMAGE_URL"
fi
[[ "$(sha "$GUEST_IMG")" == "$GUEST_IMAGE_SHA256" ]] || die "guest image sha256 mismatch (expected ${GUEST_IMAGE_SHA256})"
GUEST_MANIFEST="$WORK/guest-base.manifest"
if [[ ! -f "$GUEST_MANIFEST" ]]; then curl -fsSL -o "$GUEST_MANIFEST" "$GUEST_IMAGE_MANIFEST_URL" || die "cannot fetch guest package manifest"; fi

mkdir -p "$PAYLOAD/images" "$PAYLOAD/debs"
APP_REF="${APP_IMAGE_REPO}@${APP_IMAGE_DIGEST}"

. "$REPO/release_identity.env"
if [[ "$SKIP_FETCH" == 0 || ! -f "$PAYLOAD/images/culvert.tar" ]]; then
  log "fetch: application image ${APP_REF}"
  docker pull -q "$APP_REF" >/dev/null
  log "fetch: cosign verify (issuer ${CULVERT_RELEASE_SIGSTORE_ISSUER})"
  cosign verify --certificate-oidc-issuer "$CULVERT_RELEASE_SIGSTORE_ISSUER" \
    --certificate-identity-regexp "$CULVERT_RELEASE_SIGSTORE_SAN_REGEX" "$APP_REF" > "$WORK/cosign-verify.json" 2> "$WORK/cosign-verify.log" \
    || die "cosign verify FAILED for ${APP_REF} — refusing to build (see ${WORK}/cosign-verify.log)"
  docker tag "$APP_REF" "$APP_IMAGE_LOCAL_TAG"
  docker save -o "$PAYLOAD/images/culvert.tar" "$APP_IMAGE_LOCAL_TAG"
  log "fetch: clamav image ${CLAMAV_IMAGE}"
  docker pull -q "$CLAMAV_IMAGE" >/dev/null
  clam_id="$(docker image inspect "$CLAMAV_IMAGE" --format '{{.Id}}')"
  [[ "$clam_id" == "$CLAMAV_IMAGE_DIGEST" ]] || die "${CLAMAV_IMAGE} resolved to ${clam_id}, manifest pins ${CLAMAV_IMAGE_DIGEST} — update manifest.env deliberately"
  docker save -o "$PAYLOAD/images/clamav.tar" "$CLAMAV_IMAGE"
fi
[[ -s "$WORK/cosign-verify.json" ]] || die "cosign verification record missing (${WORK}/cosign-verify.json)"
APP_SIGNERS="$(grep -o '"critical"' "$WORK/cosign-verify.json" | wc -l | tr -d ' ')"

if [[ "$SKIP_FETCH" == 0 || ! -f "$PAYLOAD/debs/Packages.gz" ]]; then
  log "fetch: docker-ce ${DOCKER_CE_VERSION} .debs via ${DEB_RESOLVER_IMAGE}"
  find "${PAYLOAD:?}/debs" -mindepth 1 -delete
  proxy_args=()
  for v in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do [[ -n "${!v:-}" ]] && proxy_args+=(-e "$v=${!v}"); done
  ca_args=()
  if [[ -n "${BUILD_PROXY_CA_BUNDLE:-}" ]]; then ca_args+=(-v "${BUILD_PROXY_CA_BUNDLE}:/usr/local/share/ca-certificates/build-proxy.crt:ro"); fi
  docker run --rm --network host -v "$PAYLOAD/debs:/out" "${proxy_args[@]}" "${ca_args[@]}" \
    -e DOCKER_APT_URL="$DOCKER_APT_URL" -e DOCKER_APT_SUITE="$DOCKER_APT_SUITE" \
    -e V_CE="$DOCKER_CE_VERSION" -e V_CTR="$CONTAINERD_IO_VERSION" -e V_COMPOSE="$DOCKER_COMPOSE_PLUGIN_VERSION" \
    "$DEB_RESOLVER_IMAGE" bash -euo pipefail -c '
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null; apt-get install -y -qq ca-certificates curl gnupg dpkg-dev >/dev/null 2>&1
      update-ca-certificates >/dev/null 2>&1 || true
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL "$DOCKER_APT_URL/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] $DOCKER_APT_URL $DOCKER_APT_SUITE stable" > /etc/apt/sources.list.d/docker.list
      apt-get update -qq >/dev/null
      cd /out
      apt-get install -y -qq --download-only --no-install-recommends -o Dir::Cache::archives=/out \
        "docker-ce=$V_CE" "docker-ce-cli=$V_CE" "containerd.io=$V_CTR" "docker-compose-plugin=$V_COMPOSE" >/dev/null
      rm -rf /out/partial /out/lock
      dpkg-scanpackages . /dev/null 2>/dev/null > Packages && gzip -kf Packages
      cp /etc/apt/keyrings/docker.gpg /out/docker-archive-keyring.gpg
      chmod -R a+rX /out' || die "deb payload resolution failed"
fi
ls "$PAYLOAD"/debs/docker-ce_*.deb >/dev/null 2>&1 || die "docker-ce .deb missing from payload"

# ── payload ──────────────────────────────────────────────────────────────────
log "payload: assembling"
rm -rf "${PAYLOAD:?}/appliance" "${PAYLOAD:?}/vendor"; mkdir -p "$PAYLOAD/appliance" "$PAYLOAD/vendor"
cp -a "$HERE/guest" "$HERE/bake" "$HERE/manifest.env" "$PAYLOAD/appliance/"
cp "$REPO/scripts/install.sh" "$PAYLOAD/vendor/install.sh"
cp "$REPO/release_identity.env" "$PAYLOAD/vendor/release_identity.env"
# build-inputs.json: every input digest, written BEFORE the bake so the guest
# carries it (/etc/culvert-appliance/build-inputs.json).
{
  echo "{"
  echo "  \"schema\": 1,"
  echo "  \"appliance\": {\"name\": \"$(json_str "$APPLIANCE_NAME")\", \"version\": \"$(json_str "$APPLIANCE_VERSION")\", \"arch\": \"$(json_str "$APPLIANCE_ARCH")\"},"
  echo "  \"source\": {\"repo_commit\": \"$GIT_SHA\", \"repo_dirty\": $GIT_DIRTY, \"install_sh_sha256\": \"$(sha "$REPO/scripts/install.sh")\", \"release_identity_env_sha256\": \"$(sha "$REPO/release_identity.env")\"},"
  echo "  \"guest\": {\"os\": \"$(json_str "$GUEST_OS_NAME")\", \"image_url\": \"$(json_str "$GUEST_IMAGE_URL")\", \"image_sha256\": \"$GUEST_IMAGE_SHA256\", \"manifest_url\": \"$(json_str "$GUEST_IMAGE_MANIFEST_URL")\", \"manifest_sha256\": \"$(sha "$GUEST_MANIFEST")\"},"
  echo "  \"application\": {\"version\": \"$APP_VERSION\", \"image_repo\": \"$APP_IMAGE_REPO\", \"image_digest\": \"$APP_IMAGE_DIGEST\", \"local_tag\": \"$APP_IMAGE_LOCAL_TAG\", \"oci_archive_sha256\": \"$(sha "$PAYLOAD/images/culvert.tar")\", \"cosign_verified\": true, \"cosign_signatures\": $APP_SIGNERS, \"cosign_issuer\": \"$(json_str "$CULVERT_RELEASE_SIGSTORE_ISSUER")\", \"cosign_identity_regex\": \"$(json_str "$CULVERT_RELEASE_SIGSTORE_SAN_REGEX")\"},"
  echo "  \"clamav\": {\"image\": \"$CLAMAV_IMAGE\", \"image_digest\": \"$CLAMAV_IMAGE_DIGEST\", \"oci_archive_sha256\": \"$(sha "$PAYLOAD/images/clamav.tar")\"},"
  echo "  \"docker\": {\"apt_url\": \"$DOCKER_APT_URL\", \"apt_suite\": \"$DOCKER_APT_SUITE\", \"docker_ce\": \"$DOCKER_CE_VERSION\", \"containerd_io\": \"$CONTAINERD_IO_VERSION\", \"compose_plugin\": \"$DOCKER_COMPOSE_PLUGIN_VERSION\", \"debs\": ["
  first=1
  for f in "$PAYLOAD"/debs/*.deb; do
    [[ $first == 1 ]] || echo ","; first=0
    printf '    {"file": "%s", "sha256": "%s"}' "$(basename "$f")" "$(sha "$f")"
  done
  echo; echo "  ]},"
  echo "  \"tools\": {\"docker\": \"$(docker version --format '{{.Server.Version}}')\", \"cosign\": \"$(cosign version 2>&1 | awk '/GitVersion/{print $2}')\", \"qemu_img\": \"$(qemu-img --version | head -n1)\", \"qemu_system\": \"$(qemu-system-x86_64 --version | head -n1)\", \"accel\": \"$ACCEL\", \"build_host\": \"$(json_str "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"') $(uname -r)")\"},"
  echo "  \"started_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\""
  echo "}"
} > "$PAYLOAD/build-inputs.json"
genisoimage -quiet -r -l -V CULVERT_PAYLOAD -o "$WORK/payload.iso" "$PAYLOAD" || die "payload ISO failed"
log "payload: $(du -h "$WORK/payload.iso" | cut -f1) ISO"

# ── bake ─────────────────────────────────────────────────────────────────────
DISK="$WORK/disk.qcow2"
SERIAL="$WORK/bake-serial.log"
if [[ "$SKIP_BAKE" == 0 || ! -f "$DISK" ]]; then
  log "bake: creating ${DISK_SIZE_GB}G disk from the guest image"
  rm -f "$DISK"
  qemu-img create -q -f qcow2 -F qcow2 -b "$GUEST_IMG" "$DISK" "${DISK_SIZE_GB}G"
  cloud-localds "$WORK/bake-seed.iso" "$HERE/bake/user-data" "$HERE/bake/meta-data"
  : > "$SERIAL"
  log "bake: booting (accel=${ACCEL}, ${BAKE_VCPU} vCPU, ${BAKE_MEMORY_MB} MiB, timeout ${BAKE_TIMEOUT_SECONDS}s, NO network) — serial: ${SERIAL}"
  set +e
  timeout "$BAKE_TIMEOUT_SECONDS" qemu-system-x86_64 \
    -machine q35,accel="$ACCEL" -cpu "$CPU" -smp "$BAKE_VCPU" -m "$BAKE_MEMORY_MB" \
    -display none -monitor none -serial "file:${SERIAL}" -no-reboot \
    -drive "file=${DISK},if=virtio,format=qcow2,cache=unsafe" \
    -drive "file=${WORK}/bake-seed.iso,if=virtio,format=raw,readonly=on" \
    -drive "file=${WORK}/payload.iso,if=virtio,format=raw,readonly=on" \
    -netdev user,id=n0,restrict=on -device virtio-net-pci,netdev=n0 \
    -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
    > "$WORK/qemu.log" 2>&1
  rc=$?
  set -e
  [[ $rc -eq 0 ]] || { tail -n 30 "$SERIAL" >&2; die "qemu exited rc=${rc} (124 = timeout)"; }
  grep -aq 'CULVERT_BAKE_OK' "$SERIAL" || { grep -a '\[bake\]' "$SERIAL" | tail -n 30 >&2; die "bake did not report CULVERT_BAKE_OK — see ${SERIAL}"; }
  log "bake: OK"
fi

# ── package ──────────────────────────────────────────────────────────────────
log "package: flattening to streamOptimized VMDK + qcow2"
rm -rf "${OUT_DIR:?}"; mkdir -p "$OUT_DIR"
VMDK="$OUT_DIR/$NAME-disk1.vmdk"; QCOW="$OUT_DIR/$NAME.qcow2"; OVF="$OUT_DIR/$NAME.ovf"; MF="$OUT_DIR/$NAME.mf"; OVA="$OUT/$NAME.ova"
qemu-img convert -O qcow2 -c "$DISK" "$QCOW"
qemu-img convert -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "$DISK" "$VMDK"
VMDK_SIZE="$(stat -c %s "$VMDK")"
DISK_CAPACITY="$(qemu-img info --output=json "$VMDK" | sed -n 's/.*"virtual-size": *\([0-9]*\).*/\1/p' | head -n1)"
sed -e "s|@@NAME@@|${APPLIANCE_NAME}|g" -e "s|@@VERSION@@|${APPLIANCE_VERSION}|g" \
    -e "s|@@VMDK_FILE@@|$(basename "$VMDK")|g" -e "s|@@VMDK_SIZE@@|${VMDK_SIZE}|g" \
    -e "s|@@DISK_CAPACITY@@|${DISK_CAPACITY}|g" -e "s|@@VCPU@@|${VM_VCPU}|g" -e "s|@@MEM_MB@@|${VM_MEMORY_MB}|g" \
    -e "s|@@APP_VERSION@@|${APP_VERSION}|g" -e "s|@@APP_IMAGE_DIGEST@@|${APP_IMAGE_DIGEST}|g" \
    "$HERE/ovf/culvert-appliance.ovf.tmpl" > "$OVF"
if grep -q '@@' "$OVF"; then die "unexpanded placeholder in OVF"; fi
{ printf 'SHA256(%s)= %s\n' "$(basename "$OVF")" "$(sha "$OVF")"; printf 'SHA256(%s)= %s\n' "$(basename "$VMDK")" "$(sha "$VMDK")"; } > "$MF"
# OVF 1.1 §5: descriptor first, manifest second, then referenced files. ustar for old importers.
tar --format=ustar -C "$OUT_DIR" -cf "$OVA" "$(basename "$OVF")" "$(basename "$MF")" "$(basename "$VMDK")"
( cd "$OUT" && sha256sum "$(basename "$OVA")" "$NAME/$(basename "$OVF")" "$NAME/$(basename "$MF")" "$NAME/$(basename "$VMDK")" "$NAME/$(basename "$QCOW")" > "$NAME.sha256" )
cp "$SERIAL" "$OUT/$NAME.bake-serial.log" 2>/dev/null || true
cp "$WORK/cosign-verify.json" "$OUT/$NAME.cosign-verify.json" 2>/dev/null || true

# build-record.json = build-inputs.json + bake + outputs
{
  sed '$d' "$PAYLOAD/build-inputs.json" | sed '$ s/$/,/'
  echo "  \"finished_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"bake\": {\"serial_log\": \"$(basename "$OUT/$NAME.bake-serial.log")\", \"ok\": true, \"accel\": \"$ACCEL\"},"
  echo "  \"outputs\": {"
  echo "    \"ova\": {\"file\": \"$(basename "$OVA")\", \"sha256\": \"$(sha "$OVA")\", \"size\": $(stat -c %s "$OVA")},"
  echo "    \"ovf\": {\"file\": \"$NAME/$(basename "$OVF")\", \"sha256\": \"$(sha "$OVF")\"},"
  echo "    \"manifest\": {\"file\": \"$NAME/$(basename "$MF")\", \"sha256\": \"$(sha "$MF")\"},"
  echo "    \"vmdk\": {\"file\": \"$NAME/$(basename "$VMDK")\", \"sha256\": \"$(sha "$VMDK")\", \"size\": $VMDK_SIZE, \"virtual_size\": $DISK_CAPACITY, \"format\": \"vmdk/streamOptimized\"},"
  echo "    \"qcow2\": {\"file\": \"$NAME/$(basename "$QCOW")\", \"sha256\": \"$(sha "$QCOW")\", \"size\": $(stat -c %s "$QCOW")},"
  echo "    \"vm\": {\"vcpu\": $VM_VCPU, \"memory_mb\": $VM_MEMORY_MB, \"disk_gb\": $DISK_SIZE_GB, \"hardware\": \"vmx-10\", \"firmware\": \"bios\"}"
  echo "  }"
  echo "}"
} > "$OUT/$NAME.build-record.json"
log "work dir kept at ${WORK} (re-run with --skip-fetch/--skip-bake to reuse; delete it to reclaim space)"
log "done:"; cat "$OUT/$NAME.sha256" >&2
