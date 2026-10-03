#!/usr/bin/env bash
# prepare-guest.sh — runs INSIDE the guest disk during `virt-customize --run`
# (libguestfs appliance, guest root mounted at /, network via the build host).
#
# It installs the pinned Docker packages, lays down the appliance provisioning
# files from /opt/culvert-appliance, creates the console administrator account
# (LOCKED — no password, no key: see docs/appliance/first-boot.md), and strips
# every per-instance identity so the disk is safe to clone. It is the ONLY place
# that installs software into the guest; build-ova.sh never runs commands in it.
#
# Inputs (copied in by build-ova.sh before this runs):
#   /var/lib/culvert-appliance/manifest.env   the build pins
#   /opt/culvert-appliance/{provision,os-maintenance,bin,install.sh}
#
# No systemd is running here: `systemctl enable` works (it edits symlinks);
# `systemctl start` must not be used.
set -euo pipefail

MANIFEST=/var/lib/culvert-appliance/manifest.env
# shellcheck source=/dev/null
. "$MANIFEST"

export DEBIAN_FRONTEND=noninteractive
APPL=/opt/culvert-appliance
STATE=/var/lib/culvert-appliance
log() { printf 'prepare-guest: %s\n' "$*"; }

# virt-customize redirects a --run-command's output into the guest's
# /tmp/builder.log and shows it on the HOST only when the command FAILS
# (measured, build run 8: the script completed but build-ova.sh, grepping the
# host-side log for the final line, reported "did not finish"). So this script
# keeps its own transcript next to the other build provenance and writes a
# completion marker as its very last act; build-ova.sh reads both from outside
# the guest with virt-cat. The transcript survives the step-5 /var/log wipe
# because it lives under $STATE, not /var/log.
LOG="$STATE/prepare-guest.log"
DONE="$STATE/prepare-guest.done"
rm -f "$LOG" "$DONE"
exec > >(tee -a "$LOG") 2>&1
TEE_PID=$!

[[ "$(dpkg --print-architecture)" == "amd64" ]] || { echo "unsupported guest arch" >&2; exit 1; }
[[ "$(. /etc/os-release; echo "$VERSION_CODENAME")" == "$GUEST_OS_CODENAME" ]] \
  || { echo "base image codename does not match manifest GUEST_OS_CODENAME=$GUEST_OS_CODENAME" >&2; exit 1; }

# ── 0. BUILD-HOST-ONLY: intercepting HTTPS proxy handed in by build-ova.sh ──
# Present only when the build host itself sits behind such a proxy (sandbox
# CI). Everything installed here is removed again in step 5 and re-checked by
# build-ova.sh from outside the guest. Plain-HTTP apt sources (archive/security
# .ubuntu.com) go direct through qemu's user-mode NAT; only HTTPS uses the proxy.
BUILD_PROXY_ACTIVE=0
if [[ -f "$STATE/build-env.sh" ]]; then
  # shellcheck source=/dev/null
  . "$STATE/build-env.sh"
  BUILD_PROXY_ACTIVE=1
  # The build host's loopback is reachable at the appliance's default gateway
  # (slirp host alias). Derived, never hard-coded: libguestfs picks the subnet.
  gw="$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')"
  [[ -n "$gw" ]] || { echo "BUILD-ONLY proxy requested but the guest has no default route (DHCP client missing on the build host?)" >&2; exit 1; }
  BUILD_HTTPS_PROXY="http://${gw}:${BUILD_HTTPS_PROXY_PORT}"
  # The transcript is shipped in the image, so it names neither the gateway
  # nor the port — only that the sandbox-only accommodation was active.
  log "BUILD-ONLY: routing HTTPS through the build host's proxy via the guest's default gateway (removed in step 5)"
  export https_proxy="$BUILD_HTTPS_PROXY" HTTPS_PROXY="$BUILD_HTTPS_PROXY"
  printf 'Acquire::https::Proxy "%s";\n' "$BUILD_HTTPS_PROXY" > /etc/apt/apt.conf.d/99-culvert-build-proxy
  if [[ -f "$STATE/build-ca.crt" ]]; then
    install -d -m 0755 /usr/local/share/ca-certificates
    install -m 0644 "$STATE/build-ca.crt" /usr/local/share/ca-certificates/culvert-build-proxy-ca.crt
    update-ca-certificates >/dev/null 2>&1
  fi
fi

# ── 1. Docker Engine + Compose plugin, pinned, from Docker's official repo ──
log "configuring Docker apt repository"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL "$DOCKER_APT_GPG_URL" -o /tmp/docker.gpg.asc
got_fpr="$(gpg --batch --with-colons --show-keys /tmp/docker.gpg.asc 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
if [[ "$got_fpr" != "$DOCKER_APT_KEY_FPR" ]]; then
  echo "Docker apt key fingerprint mismatch: got '$got_fpr' want '$DOCKER_APT_KEY_FPR'" >&2
  exit 1
fi
gpg --batch --dearmor -o /etc/apt/keyrings/docker.gpg /tmp/docker.gpg.asc
chmod a+r /etc/apt/keyrings/docker.gpg
rm -f /tmp/docker.gpg.asc
# snapshot=no: Docker's repository has no snapshot service; without the
# option the pinned-snapshot apt run below would refuse the whole update.
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg snapshot=no] ${DOCKER_APT_URL} ${GUEST_OS_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

log "apt-get update"
apt-get update -qq
log "installing pinned Docker packages"
apt-get install -y -qq --no-install-recommends \
  "docker-ce=${DOCKER_CE_VERSION}" \
  "docker-ce-cli=${DOCKER_CE_CLI_VERSION}" \
  "containerd.io=${CONTAINERD_IO_VERSION}" \
  "docker-compose-plugin=${DOCKER_COMPOSE_PLUGIN_VERSION}"
# install.sh's quick-start path also wants these on the host (pigz speeds image
# loads; psmisc provides fuser for its apt-lock wait). Both are tiny.
apt-get install -y -qq --no-install-recommends pigz psmisc
# Keep the pinned engine from drifting via an operator's casual `apt upgrade`;
# culvert-os-update --docker is the deliberate, stack-aware upgrade path.
apt-mark hold docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null

# ── 1b. Guest security updates, pinned to an Ubuntu archive SNAPSHOT ───────
# The base cloud image serial is weeks old by the time it is built into an
# appliance: the run-9 guest scan found 33 findings Ubuntu had already fixed
# (2 HIGH in openssl/libssl3t64). They are applied at BUILD time — a customer
# must not boot a known-vulnerable OpenSSL and wait for unattended-upgrades on
# their own network — but from an archive snapshot pinned in manifest.env
# (GUEST_APT_SNAPSHOT, snapshot.ubuntu.com), so the input-pinning contract
# holds: same manifest ⇒ same package versions, and the SBOM/CVE evidence
# describes exactly what shipped. `upgrade` (not dist-upgrade) never installs
# new packages, so a new kernel ABI is NOT pulled in here — the kernel moves
# only through culvert-os-update os (+ reboot) after deployment, which is a
# deliberate, documented operator step. Docker is held above and cannot move.
if [[ -n "${GUEST_APT_SNAPSHOT:-}" ]]; then
  log "applying guest security updates from the Ubuntu archive snapshot ${GUEST_APT_SNAPSHOT}"
  apt-get -qq -o Acquire::Snapshot="${GUEST_APT_SNAPSHOT}" update
  before="$(dpkg-query -W -f='${binary:Package}=${Version}\n' | sort)"
  DEBIAN_FRONTEND=noninteractive apt-get -y -qq -o Acquire::Snapshot="${GUEST_APT_SNAPSHOT}" \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade
  after="$(dpkg-query -W -f='${binary:Package}=${Version}\n' | sort)"
  # Shipped as evidence: exactly which packages the snapshot upgrade moved.
  # comm, not diff: diff exits 1 whenever the lists differ, which under
  # `set -o pipefail` aborted the whole first candidate build right after the
  # upgrade had succeeded (measured). comm exits 0 on differences.
  { echo "# guest packages upgraded at build time from snapshot ${GUEST_APT_SNAPSHOT} (old -> new)"
    comm -3 <(echo "$before") <(echo "$after") | tr -d '\t' | sort | awk -F= '{v[$1]=v[$1] (v[$1]?" -> ":"") $2} END{for (p in v) print p " " v[p]}' | sort
  } > "$STATE/build-upgrades.txt"
  moved="$(grep -vc '^#' "$STATE/build-upgrades.txt" || true)"
  log "build-time upgrades: ${moved:-0} package(s) moved"
  # Leave the snapshot behind: the deployed appliance updates from the live
  # archive (unattended-upgrades + culvert-os-update), never from a snapshot.
  apt-get -qq update
fi

# Docker daemon defaults for the appliance: containerd image store (the
# default on a fresh 29.x install, pinned explicitly so a pre-baked image keeps
# its registry digest across save/load), bounded json logs, live-restore so an
# engine restart during OS maintenance does not kill the proxy.
install -d -m 0755 /etc/docker
cat > /etc/docker/daemon.json <<'JSON'
{
  "features": { "containerd-snapshotter": true },
  "log-driver": "json-file",
  "log-opts": { "max-size": "50m", "max-file": "3" },
  "live-restore": true
}
JSON

systemctl enable docker.service containerd.service >/dev/null 2>&1

# ── 2. Appliance provisioning files ─────────────────────────────────────────
log "installing provisioning files"
install -d -m 0755 /etc/culvert-appliance "$STATE/state" "$STATE/images" /usr/local/sbin
install -m 0755 "$APPL/provision/culvert-firstboot.sh"            "$APPL/bin/culvert-firstboot"
install -m 0755 "$APPL/provision/culvert-status"                  "$APPL/bin/culvert-status"
install -m 0755 "$APPL/provision/culvert-net"                     "$APPL/bin/culvert-net"
install -m 0755 "$APPL/provision/culvert-issue-update"            "$APPL/bin/culvert-issue-update"
install -m 0755 "$APPL/provision/culvert-appliance-reset-identity" "$APPL/bin/culvert-appliance-reset-identity"
install -m 0755 "$APPL/provision/culvert-sudo-policy"             "$APPL/bin/culvert-sudo-policy"
install -m 0755 "$APPL/os-maintenance/culvert-os-update"          "$APPL/bin/culvert-os-update"
install -m 0755 "$APPL/install.sh"                                "$APPL/bin/culvert-install.sh"
# culvert-firstboot is on PATH for its explicit repair verb only
# (`sudo culvert-firstboot --repair-agent`); the unit still runs it by path.
for b in culvert-status culvert-net culvert-os-update culvert-appliance-reset-identity culvert-sudo-policy culvert-firstboot; do
  ln -sf "$APPL/bin/$b" "/usr/local/sbin/$b"
done

install -m 0644 "$APPL/provision/culvert-firstboot.service" /etc/systemd/system/culvert-firstboot.service
install -m 0644 "$APPL/provision/culvert-issue.service"     /etc/systemd/system/culvert-issue.service
install -m 0644 "$APPL/provision/culvert-issue.timer"       /etc/systemd/system/culvert-issue.timer
systemctl enable culvert-firstboot.service culvert-issue.timer >/dev/null 2>&1

# Firewall: nftables with an input-drop policy (22/8080/9090 only). ufw stays
# installed but inactive; Docker's own tables coexist (see nftables.conf).
install -m 0644 "$APPL/provision/nftables.conf" /etc/nftables.conf
systemctl enable nftables.service >/dev/null 2>&1
systemctl disable ufw.service >/dev/null 2>&1 || true

# SSH: key-only, no root, no passwords (drop-in, so Ubuntu's sshd_config stays
# package-owned and keeps receiving security updates).
install -d -m 0755 /etc/ssh/sshd_config.d
install -m 0644 "$APPL/provision/sshd-50-culvert.conf" /etc/ssh/sshd_config.d/50-culvert.conf

# cloud-init: default (console) user is `culvert`, datasources limited to the
# ones an appliance import can present, password SSH disabled.
install -m 0644 "$APPL/provision/cloud-90-culvert.cfg" /etc/cloud/cloud.cfg.d/90-culvert-appliance.cfg

# OS maintenance: security pocket only, no automatic reboot.
install -m 0644 "$APPL/os-maintenance/50unattended-upgrades-culvert" /etc/apt/apt.conf.d/50unattended-upgrades-culvert
install -m 0644 "$APPL/os-maintenance/20auto-upgrades-culvert"       /etc/apt/apt.conf.d/20auto-upgrades-culvert

# Console banner (agetty reads /etc/issue.d/*.issue on util-linux >= 2.35).
install -d -m 0755 /etc/issue.d
printf 'Culvert appliance — provisioning has not run yet.\n\n' > /etc/issue.d/50-culvert.issue

# ── 3. Console administrator account (LOCKED at build time) ─────────────────
# No password and no key are shipped. cloud-init (OVF `password` / `public-keys`)
# or the first-boot fallback (one-time random console password printed to the
# VM console, change forced at first login) unlocks it per instance.
if ! id culvert >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --comment "Culvert appliance administrator" culvert
fi
usermod -aG sudo,adm culvert
passwd -l culvert >/dev/null
printf 'culvert ALL=(ALL:ALL) ALL\n' > /etc/sudoers.d/50-culvert-console
chmod 0440 /etc/sudoers.d/50-culvert-console
visudo -c -q -f /etc/sudoers.d/50-culvert-console

# ── 4. Evidence captured into the image for the SBOM/CVE record ─────────────
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' | sort > "$STATE/dpkg-list.txt"
{
  echo "docker-ce=$(dpkg-query -W -f='${Version}' docker-ce)"
  echo "docker-ce-cli=$(dpkg-query -W -f='${Version}' docker-ce-cli)"
  echo "containerd.io=$(dpkg-query -W -f='${Version}' containerd.io)"
  echo "docker-compose-plugin=$(dpkg-query -W -f='${Version}' docker-compose-plugin)"
  echo "cloud-init=$(dpkg-query -W -f='${Version}' cloud-init)"
  echo "open-vm-tools=$(dpkg-query -W -f='${Version}' open-vm-tools)"
  echo "unattended-upgrades=$(dpkg-query -W -f='${Version}' unattended-upgrades)"
  echo "openssh-server=$(dpkg-query -W -f='${Version}' openssh-server)"
  echo "nftables=$(dpkg-query -W -f='${Version}' nftables)"
  echo "kernel=$(find /boot -maxdepth 1 -name "vmlinuz-*" -printf "%f\n" | sed "s/^vmlinuz-//" | sort -V | tail -1)"
} > "$STATE/host-components.txt"

# ── 5. Strip per-instance identity + build residue (clone-safe disk) ────────
log "cleaning"
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
rm -f /etc/ssh/ssh_host_*            # regenerated by cloud-init at first boot
truncate -s 0 /etc/machine-id        # regenerated by systemd at first boot
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true
rm -f /root/.bash_history /home/*/.bash_history
find /var/log -type f -exec truncate -s 0 {} +
rm -rf /var/lib/cloud/instances /var/lib/cloud/instance /var/lib/cloud/data 2>/dev/null || true
# Nothing from the BUILD host may survive: no proxy config, no apt proxy, no
# authorized keys. build-ova.sh re-checks these from outside the guest.
rm -f /etc/apt/apt.conf.d/*proxy* /etc/environment.d/*proxy* /root/.docker/config.json
if [[ "$BUILD_PROXY_ACTIVE" -eq 1 ]]; then
  log "BUILD-ONLY: removing the build host proxy + CA from the guest"
  unset https_proxy HTTPS_PROXY
  rm -f /etc/apt/apt.conf.d/99-culvert-build-proxy /usr/local/share/ca-certificates/culvert-build-proxy-ca.crt
  update-ca-certificates --fresh >/dev/null 2>&1
  rm -f "$STATE/build-env.sh" "$STATE/build-ca.crt"
fi
rm -rf /root/.ssh /home/culvert/.ssh
log "done"
date -u +%Y-%m-%dT%H:%M:%SZ > "$DONE"   # the ONLY success signal build-ova.sh trusts
exec 1>&- 2>&-
wait "$TEE_PID" 2>/dev/null || true
