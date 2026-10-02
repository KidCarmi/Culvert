#!/usr/bin/env bash
# bake.sh — runs as root INSIDE the build VM (invoked by the bake cloud-init
# seed) with the payload disk mounted read-only at $1. The VM has NO network
# (QEMU user-mode net is started with restrict=on): every input is on the
# payload, every input digest is in payload/build-inputs.json.
#
# Steps are ordered so a failure leaves a diagnosable serial log; on any error
# the trap prints CULVERT_BAKE_FAIL and powers off, and build.sh refuses the
# disk. Success ends with CULVERT_BAKE_OK and a power-off.
# shellcheck disable=SC1091  # manifest.env is sourced from the payload mount
set -euo pipefail

PAYLOAD="${1:?payload mount point}"
CONSOLE=/dev/ttyS0
LOG=/var/log/culvert-appliance-bake.log

say() { printf '[bake] %s\n' "$*" | tee -a "$LOG" > "$CONSOLE" 2>/dev/null || printf '[bake] %s\n' "$*"; }
fail_trap() {
  local rc=$?
  say "FAILED (rc=$rc) at line ${BASH_LINENO[0]}: ${BASH_COMMAND}"
  tail -n 40 "$LOG" > "$CONSOLE" 2>/dev/null || true
  echo "CULVERT_BAKE_FAIL rc=$rc" > "$CONSOLE"
  sync
  systemctl poweroff
}
trap fail_trap ERR

mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

. "$PAYLOAD/appliance/manifest.env"
say "bake start — ${APPLIANCE_NAME} ${APPLIANCE_VERSION} on $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"') kernel $(uname -r)"
[[ -f "$PAYLOAD/build-inputs.json" ]] || { say "payload incomplete: build-inputs.json missing"; false; }

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT_OFFLINE=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/culvert-payload.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0)

# ── 1. Docker Engine + Compose from the OFFLINE payload repository ───────────
say "1/8 installing Docker Engine ${DOCKER_CE_VERSION} from the payload"
echo "deb [trusted=yes] file:${PAYLOAD}/debs ./" > /etc/apt/sources.list.d/culvert-payload.list
apt-get "${APT_OFFLINE[@]}" -qq update
apt-get "${APT_OFFLINE[@]}" -y -qq --no-install-recommends \
  -o Dpkg::Options::=--force-confold install \
  "docker-ce=${DOCKER_CE_VERSION}" "docker-ce-cli=${DOCKER_CE_VERSION}" \
  "containerd.io=${CONTAINERD_IO_VERSION}" "docker-compose-plugin=${DOCKER_COMPOSE_PLUGIN_VERSION}"
rm -f /etc/apt/sources.list.d/culvert-payload.list
# Future maintenance uses Docker's real repository (same layout install.sh
# writes, so a later install.sh run sees "Docker present" and leaves it alone).
install -m 0755 -d /etc/apt/keyrings
install -m 0644 "$PAYLOAD/debs/docker-archive-keyring.gpg" /etc/apt/keyrings/docker.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] ${DOCKER_APT_URL} ${DOCKER_APT_SUITE} stable" > /etc/apt/sources.list.d/docker.list
docker --version; docker compose version

# ── 2. Daemon configuration (BEFORE the first start, so the image store is
#      containerd-backed from the beginning — a preloaded image only keeps its
#      registry digest under that store) ──────────────────────────────────────
say "2/8 configuring dockerd"
install -m 0755 -d /etc/docker
install -m 0644 "$PAYLOAD/appliance/guest/etc/docker-daemon.json" /etc/docker/daemon.json
systemctl enable containerd docker >/dev/null
systemctl restart docker
for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 2; done
docker info --format 'store={{json .DriverStatus}} fw={{.FirewallBackend.Driver}}'
docker info --format '{{json .DriverStatus}}' | grep -q 'io.containerd.snapshotter' || { say "containerd image store NOT active"; false; }

# ── 3. Preload the application + clamav images and VERIFY their identity ────
say "3/8 preloading container images"
docker load -i "$PAYLOAD/images/culvert.tar"
docker load -i "$PAYLOAD/images/clamav.tar"
app_id="$(docker image inspect "$APP_IMAGE_LOCAL_TAG" --format '{{.Id}}')"
app_digests="$(docker image inspect "$APP_IMAGE_LOCAL_TAG" --format '{{json .RepoDigests}}')"
[[ "$app_id" == "$APP_IMAGE_DIGEST" ]] || { say "app image Id $app_id != manifest digest $APP_IMAGE_DIGEST"; false; }
[[ "$app_digests" == *"${APP_IMAGE_REPO}@${APP_IMAGE_DIGEST}"* ]] || { say "app image lost its RepoDigest: $app_digests"; false; }
clam_id="$(docker image inspect "$CLAMAV_IMAGE" --format '{{.Id}}')"
[[ "$clam_id" == "$CLAMAV_IMAGE_DIGEST" ]] || { say "clamav image Id $clam_id != manifest digest $CLAMAV_IMAGE_DIGEST"; false; }
docker images --digests --format '{{.Repository}}:{{.Tag}} {{.Digest}} {{.ID}}'

# ── 4. Appliance files ──────────────────────────────────────────────────────
say "4/8 installing appliance files"
install -m 0755 -d /usr/local/lib/culvert-appliance /etc/culvert-appliance /var/lib/culvert-appliance /var/log/culvert-appliance
install -m 0755 "$PAYLOAD/appliance/guest/bin/firstboot.sh" /usr/local/lib/culvert-appliance/firstboot.sh
install -m 0755 "$PAYLOAD/appliance/guest/bin/console-status.sh" /usr/local/lib/culvert-appliance/console-status.sh
install -m 0755 "$PAYLOAD/appliance/guest/bin/culvert-appliance" /usr/local/sbin/culvert-appliance
install -m 0755 "$PAYLOAD/vendor/install.sh" /usr/local/lib/culvert-appliance/install.sh
install -m 0644 "$PAYLOAD/vendor/release_identity.env" /etc/culvert-appliance/release_identity.env
install -m 0644 "$PAYLOAD/appliance/manifest.env" /etc/culvert-appliance/manifest.env
install -m 0644 "$PAYLOAD/build-inputs.json" /etc/culvert-appliance/build-inputs.json
install -m 0644 "$PAYLOAD/appliance/guest/systemd/"*.service "$PAYLOAD/appliance/guest/systemd/"*.timer /etc/systemd/system/
install -m 0644 "$PAYLOAD/appliance/guest/etc/90-culvert-appliance.cfg" /etc/cloud/cloud.cfg.d/90-culvert-appliance.cfg
install -m 0644 "$PAYLOAD/appliance/guest/etc/52culvert-appliance-unattended" /etc/apt/apt.conf.d/52culvert-appliance-unattended
install -m 0644 "$PAYLOAD/appliance/guest/etc/20auto-upgrades" /etc/apt/apt.conf.d/20auto-upgrades
install -m 0644 -D "$PAYLOAD/appliance/guest/etc/needrestart-culvert.conf" /etc/needrestart/conf.d/culvert-appliance.conf
install -m 0644 "$PAYLOAD/appliance/guest/etc/sshd-culvert-appliance.conf" /etc/ssh/sshd_config.d/60-culvert-appliance.conf
install -m 0644 "$PAYLOAD/appliance/guest/etc/journald-culvert.conf" /etc/systemd/journald.conf.d/culvert-appliance.conf 2>/dev/null || {
  install -d /etc/systemd/journald.conf.d; install -m 0644 "$PAYLOAD/appliance/guest/etc/journald-culvert.conf" /etc/systemd/journald.conf.d/culvert-appliance.conf; }
systemctl daemon-reload
systemctl enable culvert-appliance-firstboot.service culvert-appliance-console.timer culvert-appliance-mgmt.service >/dev/null
# Console: the appliance owns /etc/issue; the stock one is kept for reference.
cp -a /etc/issue /etc/issue.dist 2>/dev/null || true
printf 'Culvert Appliance %s — status not yet collected (first boot in progress)\n\n' "$APPLIANCE_VERSION" > /etc/issue

# ── 5. Minimise the guest ───────────────────────────────────────────────────
say "5/8 removing snapd / lxd installer stubs, disabling motd news"
apt-get -y -qq purge snapd lxd-installer lxd-agent-loader >/dev/null 2>&1 || true
rm -rf /var/cache/snapd /root/snap /snap
sed -i 's/^ENABLED=1/ENABLED=0/' /etc/default/motd-news 2>/dev/null || true
apt-get -y -qq autoremove --purge >/dev/null 2>&1 || true
apt-get clean

# ── 6. Record the bake ──────────────────────────────────────────────────────
say "6/8 recording bake facts"
{
  echo "APPLIANCE_BAKED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "APPLIANCE_GUEST_KERNEL=$(uname -r)"
  echo "APPLIANCE_DOCKER_VERSION=$(docker version --format '{{.Server.Version}}')"
  echo "APPLIANCE_COMPOSE_VERSION=$(docker compose version --short)"
  echo "APPLIANCE_INSTALL_SH_SHA256=$(sha256sum /usr/local/lib/culvert-appliance/install.sh | cut -d' ' -f1)"
} > /etc/culvert-appliance/bake.env
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' | sort > /etc/culvert-appliance/dpkg-list.tsv
cp /etc/culvert-appliance/dpkg-list.tsv /var/log/culvert-appliance/bake-dpkg-list.tsv

# ── 7. Strip EVERY per-instance identity so each deployed VM mints its own ──
say "7/8 scrubbing instance identity (ssh host keys, machine-id, cloud-init state, logs, bake user)"
systemctl stop docker containerd >/dev/null 2>&1 || true
rm -f /etc/ssh/ssh_host_*
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id
# The bake seed created cloud-init's default user; the appliance's default user
# (culvert) is created by cloud-init on the FIRST real boot.
userdel -r ubuntu >/dev/null 2>&1 || true
rm -f /etc/sudoers.d/90-cloud-init-users
rm -rf /var/lib/cloud/instances /var/lib/cloud/instance /var/lib/cloud/data /var/lib/cloud/sem /var/lib/cloud/scripts/per-instance/*
rm -f /etc/netplan/50-cloud-init.yaml /etc/ssh/sshd_config.d/50-cloud-init.conf
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.bash_history /home/*/.bash_history
find /var/log -type f -name '*.gz' -delete
find /var/log -type f ! -path '/var/log/culvert-appliance*' -exec truncate -s 0 {} +
journalctl --rotate >/dev/null 2>&1 || true; journalctl --vacuum-time=1s >/dev/null 2>&1 || true
cp "$LOG" /var/log/culvert-appliance/bake.log 2>/dev/null || true

# ── 8. Done ─────────────────────────────────────────────────────────────────
say "8/8 trimming and powering off"
fstrim -v / || true
sync
echo "CULVERT_BAKE_OK" > "$CONSOLE"
systemctl poweroff
