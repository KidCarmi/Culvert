#!/usr/bin/env bash
# firstboot.sh — Culvert appliance first-boot provisioning (runs as root from
# culvert-appliance-firstboot.service; idempotent and interruption-safe).
#
# Every step records a marker under /var/lib/culvert-appliance/steps/ and is
# skipped on a re-run; a failure leaves /var/lib/culvert-appliance/error for the
# console and exits non-zero (the unit fails; `systemctl restart
# culvert-appliance-firstboot` resumes at the failed step). Nothing here writes
# application state under /data or mints application keys — the application
# mints its own identity (CA, session secret, ...) when it starts.
set -euo pipefail

STATE=/var/lib/culvert-appliance
STEPS=$STATE/steps
RUN=/run/culvert-appliance
LIB=/usr/local/lib/culvert-appliance
ETC=/etc/culvert-appliance
INSTALL_DIR=/srv/culvert
mkdir -p "$STEPS" "$RUN"
chmod 0700 "$RUN"

log() { printf '%s firstboot: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
set_phase() { printf '%s\n' "$*" > "$STATE/phase"; }
fail() {
  log "ERROR: $*"
  printf '%s\n' "$*" > "$STATE/error"
  set_phase "failed"
  exit 1
}
on_exit() {
  local rc=$?
  if [[ $rc -ne 0 && ! -s "$STATE/error" ]]; then
    printf 'step failed (rc=%s) — see /var/log/culvert-appliance/firstboot.log\n' "$rc" > "$STATE/error"
    set_phase failed
  fi
}
trap on_exit EXIT
done_step() { touch "$STEPS/$1"; }
need_step() { [[ ! -e "$STEPS/$1" ]]; }

# shellcheck source=/dev/null
. "$ETC/manifest.env"
rm -f "$STATE/error"
set_phase "starting"
log "Culvert appliance ${APPLIANCE_VERSION} first boot (app ${APP_VERSION}, image ${APP_IMAGE_REPO}@${APP_IMAGE_DIGEST})"

# ── 1. Docker must be up ────────────────────────────────────────────────────
set_phase "waiting for docker"
for _ in $(seq 1 90); do docker info >/dev/null 2>&1 && break; sleep 2; done
docker info >/dev/null 2>&1 || fail "docker daemon did not come up (journalctl -u docker)"

# ── 2. Offline integrity check of the preloaded images against the build record
if need_step verify-images; then
  set_phase "verifying preloaded images"
  app_id="$(docker image inspect "${APP_IMAGE_REPO}@${APP_IMAGE_DIGEST}" --format '{{.Id}}' 2>/dev/null || true)"
  [[ "$app_id" == "$APP_IMAGE_DIGEST" ]] || fail "preloaded application image missing or altered (Id='${app_id}', expected ${APP_IMAGE_DIGEST})"
  clam_id="$(docker image inspect "$CLAMAV_IMAGE" --format '{{.Id}}' 2>/dev/null || true)"
  [[ "$clam_id" == "$CLAMAV_IMAGE_DIGEST" ]] || fail "preloaded clamav image missing or altered (Id='${clam_id}', expected ${CLAMAV_IMAGE_DIGEST})"
  log "preloaded images verified: app ${app_id}, clamav ${clam_id}"
  done_step verify-images
fi

# ── 3. One-time console password for the operator user (console-only; SSH is
#      key-only). Skipped when a datasource already set a password. The value
#      is shown on tty1 by console-status until it is changed at first login.
if need_step console-password; then
  set_phase "minting console password"
  if id culvert >/dev/null 2>&1; then
    shadow_hash="$(getent shadow culvert | cut -d: -f2)"
    if [[ -z "$shadow_hash" || "$shadow_hash" == '!'* || "$shadow_hash" == '*' ]]; then
      pw="$(tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | head -c 16)"
      echo "culvert:${pw}" | chpasswd
      passwd -e culvert >/dev/null
      ( umask 077; printf '%s\n' "$pw" > "$RUN/console-password" )
      log "one-time console password minted for user culvert (change forced at first login)"
    else
      log "user culvert already has a password (set by the datasource) — not overriding"
    fi
  else
    log "user culvert does not exist yet (cloud-init did not create it) — no console password"
  fi
  done_step console-password
fi

# ── 4. Run the standard quick-start installer, OFFLINE, against the preloaded
#      image. Trust posture: the image's cosign verification happened at OVA
#      build time (build-inputs.json carries the verified identity) and step 2
#      re-checked the digest; the registry/Sigstore round trip the installer
#      would do is not possible without egress, so the agent install is told
#      to trust the preloaded image (CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1).
if need_step install; then
  set_phase "installing application stack (scripts/install.sh)"
  export HOME=/root
  env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root \
    CULVERT_INSTALL_OFFLINE=1 \
    CULVERT_DIR="$INSTALL_DIR" \
    CULVERT_PROXY_SEED_REF="${APP_IMAGE_REPO}@${APP_IMAGE_DIGEST}" \
    CULVERT_PROXY_REPO="$APP_IMAGE_REPO" \
    CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1 \
    bash "$LIB/install.sh" < /dev/null || fail "scripts/install.sh failed — see /var/log/culvert-appliance/firstboot.log; retry with: systemctl restart culvert-appliance-firstboot"
  done_step install
fi

# ── 5. Post-install facts for the console / support ─────────────────────────
set_phase "finalising"
{
  echo "PROVISIONED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "INSTALL_DIR=$INSTALL_DIR"
  echo "PINNED_IMAGE_ID=$(docker image inspect culvert/proxy:pinned --format '{{.Id}}' 2>/dev/null || echo unknown)"
  echo "MAINT_AGENT_VERSION=$(/usr/local/bin/culvert-maint --version 2>/dev/null || echo not-installed)"
} > "$STATE/provisioned.env"
touch "$STATE/provisioned"
set_phase "provisioned"
log "first boot complete"
