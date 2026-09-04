#!/usr/bin/env bash
# install.sh — One-command Culvert setup for a fresh Linux server.
#
# Usage (fresh server):
#   curl -fsSL https://raw.githubusercontent.com/KidCarmi/Culvert/main/scripts/install.sh | bash
#
# Or if you already cloned:
#   bash scripts/install.sh
#
# What this script does:
#   1. Detects your Linux distro (Ubuntu, Debian, RHEL, CentOS, Fedora, Amazon Linux, Arch)
#   2. Removes conflicting Docker packages (snap, old docker-compose v1, distro packages)
#   3. Installs Docker Engine + Compose v2 from Docker's official repo
#   4. Adds the current user to the docker group
#   5. Provisions /srv/culvert (no source checkout needed): pulls the public
#      proxy image from ghcr.io and extracts the deployment files (compose
#      files + maintenance-agent packaging) from its /app/deploy bundle.
#      Running from inside a source checkout uses the checkout instead;
#      images without the bundle fall back to a git clone.
#   6. Starts all services with docker compose up -d
#   7. (Optional, best-effort) Installs the host-side maintenance agent
#      (culvert-maint systemd service) from the image deploy bundle — falling
#      back to the cosign-verified signed-release download, then to a local
#      source build (host Go toolchain or a throwaway golang container).
#      Skip entirely with CULVERT_SKIP_MAINT_AGENT=1.
#
# Supported distros:
#   Ubuntu 20.04+, Debian 11+, RHEL/CentOS/Rocky/Alma 8+, Fedora 38+,
#   Amazon Linux 2023+, Arch Linux
#
# Cloud platforms (all use standard distros, fully supported):
#   AWS EC2, Azure VM, GCP Compute Engine, Oracle Cloud, DigitalOcean,
#   Linode/Akamai, Hetzner, Vultr, OVH
#
# Requirements: sudo access, internet connection

set -euo pipefail

###############################################################################
# Helpers
###############################################################################
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }
step()  { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# wait_for_apt_lock — block until any other apt/dpkg process releases its lock.
# Cloud VMs (Ubuntu especially) often run unattended-upgrades on first boot,
# which holds /var/lib/dpkg/lock-frontend and causes apt-get to fail with
# "Could not get lock /var/lib/dpkg/lock-frontend" if we run too soon.
wait_for_apt_lock() {
  local waited=0
  local max=300  # 5 minutes
  while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || sudo fuser /var/lib/dpkg/lock          >/dev/null 2>&1 \
     || sudo fuser /var/lib/apt/lists/lock     >/dev/null 2>&1; do
    if (( waited == 0 )); then
      warn "Another apt/dpkg process is running (likely unattended-upgrades). Waiting..."
    fi
    sleep 3
    waited=$((waited + 3))
    if (( waited >= max )); then
      warn "Still waiting for apt lock after ${max}s. Giving up and trying anyway."
      break
    fi
  done
}

# apt_install_with_repair — run apt-get install with auto-repair on dpkg failure.
# Usage: apt_install_with_repair pkg1 pkg2 ...
# On failure: dumps the last 30 lines of output, runs `dpkg --configure -a`
# and `apt-get install -f -y` to fix half-configured packages, then retries once.
# This is the #1 cause of "E: Sub-process /usr/bin/dpkg returned an error code (1)"
# being unrecoverable from the user's perspective.
apt_install_with_repair() {
  local log
  log=$(mktemp 2>/dev/null || echo "/tmp/culvert-apt-$$.log")

  wait_for_apt_lock

  if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >"$log" 2>&1; then
    rm -f "$log"
    return 0
  fi

  warn "apt-get install failed. Last 30 lines of output:"
  tail -n 30 "$log" >&2 || true
  rm -f "$log"

  warn "Attempting to repair dpkg state (dpkg --configure -a)..."
  wait_for_apt_lock
  sudo dpkg --configure -a 2>&1 | tail -n 20 >&2 || true
  warn "Attempting to fix broken dependencies (apt-get install -f -y)..."
  wait_for_apt_lock
  sudo apt-get install -f -y 2>&1 | tail -n 20 >&2 || true

  info "Retrying installation of: $*"
  wait_for_apt_lock
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

# dump_docker_diagnostics — print docker.service status and recent journal lines.
# Called when docker.service fails to start so the user sees the actual error
# without having to manually run systemctl status / journalctl.
dump_docker_diagnostics() {
  echo "" >&2
  warn "── docker.service status ──"
  sudo systemctl status docker.service --no-pager -l 2>&1 | sed 's/^/    /' >&2 || true
  echo "" >&2
  warn "── docker.service journal (last 30 lines) ──"
  sudo journalctl -xeu docker.service --no-pager -n 30 2>&1 | sed 's/^/    /' >&2 || true
  echo "" >&2
  warn "── containerd.service journal (last 20 lines) ──"
  sudo journalctl -xeu containerd.service --no-pager -n 20 2>&1 | sed 's/^/    /' >&2 || true
  echo "" >&2
}

# Source repo — used ONLY by the legacy clone fallback in §6b (images built
# before the /app/deploy bundle). Everything a normal install needs comes from
# the public proxy image on ghcr.io.
# Where to run the stack. Honor CULVERT_DIR if set; default /srv/culvert for
# EVERY user — it matches the maintenance-agent config's compose_project_dir
# default, and its ancestors (/, /srv) are world-searchable, so the
# unprivileged culvert-maint service user can chdir into the stack and Release
# Management wires up out of the box. A home-dir stack (the old non-root
# default ~/Culvert) sits under a 0700/0750 home on most cloud images
# (ec2-user, modern Ubuntu), which forces the installer to skip the agent
# fail-closed and leaves the Release panel at "Agent unreachable".
INSTALL_DIR="${CULVERT_DIR:-/srv/culvert}"

###############################################################################
# Detect distro family
###############################################################################
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID}"
    DISTRO_VERSION="${VERSION_ID:-}"
    DISTRO_CODENAME="${VERSION_CODENAME:-}"
    DISTRO_LIKE="${ID_LIKE:-}"
  else
    error "Cannot detect distro — /etc/os-release not found."
  fi

  # Normalize to a family
  case "$DISTRO_ID" in
    ubuntu|debian|linuxmint|pop)
      DISTRO_FAMILY="debian"
      # Mint and Pop use Ubuntu repos
      if [[ "$DISTRO_ID" == "linuxmint" || "$DISTRO_ID" == "pop" ]]; then
        DISTRO_ID="ubuntu"
        # Map to Ubuntu codename
        DISTRO_CODENAME="${UBUNTU_CODENAME:-$DISTRO_CODENAME}"
      fi
      ;;
    rhel|centos|rocky|almalinux|ol)
      DISTRO_FAMILY="rhel"
      # Docker's repo uses "rhel" or "centos" depending on version
      if [[ "$DISTRO_ID" != "rhel" ]]; then
        DISTRO_ID="centos"
      fi
      ;;
    fedora)
      DISTRO_FAMILY="fedora"
      ;;
    amzn)
      DISTRO_FAMILY="amzn"
      ;;
    arch|manjaro|endeavouros)
      DISTRO_FAMILY="arch"
      ;;
    *)
      # Try ID_LIKE as fallback
      if [[ "$DISTRO_LIKE" == *"debian"* || "$DISTRO_LIKE" == *"ubuntu"* ]]; then
        DISTRO_FAMILY="debian"
        DISTRO_ID="ubuntu"
      elif [[ "$DISTRO_LIKE" == *"rhel"* || "$DISTRO_LIKE" == *"centos"* || "$DISTRO_LIKE" == *"fedora"* ]]; then
        DISTRO_FAMILY="rhel"
        DISTRO_ID="centos"
      else
        error "Unsupported distro: $DISTRO_ID. Supported: Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora, Amazon Linux, Arch."
      fi
      ;;
  esac

  info "Detected: $DISTRO_ID ($DISTRO_FAMILY family)"
}

###############################################################################
# Pre-flight checks
###############################################################################
step "Pre-flight checks"

[[ "$(uname -s)" == "Linux" ]] || error "This script is for Linux only."

if ! sudo -n true 2>/dev/null; then
  warn "sudo access required. You may be prompted for your password."
fi

# Check internet
if curl -fsSL --connect-timeout 5 https://download.docker.com > /dev/null 2>&1 || \
   wget -q --timeout=5 -O /dev/null https://download.docker.com 2>/dev/null; then
  info "Internet connectivity OK"
else
  error "No internet connection. Cannot reach download.docker.com"
fi

# Memory check — Culvert + ClamAV need ~1.5 GB to run comfortably.
# ClamAV alone keeps ~600 MB of virus signatures resident in RAM.
if command -v free &>/dev/null; then
  TOTAL_MEM_MB=$(free -m | awk '/^Mem:/{print $2}')
  if [[ -n "$TOTAL_MEM_MB" && "$TOTAL_MEM_MB" -lt 1500 ]]; then
    warn "Detected ${TOTAL_MEM_MB} MB RAM. Culvert + ClamAV want ~1.5 GB to run comfortably."
    warn "Consider adding swap or disabling the clamav service in docker-compose.yml."
  fi
fi

# Disk space check — Docker engine + Culvert images need ~3 GB free in /var.
# Low disk space is a frequent cause of dpkg postinst failures during install.
if command -v df &>/dev/null; then
  DISK_AVAIL_MB=$(df -m /var 2>/dev/null | awk 'NR==2 {print $4}')
  if [[ -n "$DISK_AVAIL_MB" && "$DISK_AVAIL_MB" =~ ^[0-9]+$ && "$DISK_AVAIL_MB" -lt 3000 ]]; then
    warn "Only ${DISK_AVAIL_MB} MB free in /var. Docker engine + Culvert images need ~3 GB."
    warn "Low disk space is a common cause of dpkg install failures."
  fi
fi

# Corporate proxy detection — Docker daemon does NOT inherit shell env vars.
# If the user is behind an HTTP proxy, image pulls will hang or fail unless
# /etc/systemd/system/docker.service.d/http-proxy.conf is configured.
if [[ -n "${HTTPS_PROXY:-}${https_proxy:-}${HTTP_PROXY:-}${http_proxy:-}" ]]; then
  warn "HTTP/HTTPS proxy environment variables detected."
  warn "Docker daemon does NOT inherit these — image pulls may fail."
  warn "Configure: https://docs.docker.com/engine/daemon/proxy/"
fi

detect_distro

###############################################################################
# 1. Clean up conflicting Docker installations
###############################################################################
step "Cleaning up old Docker installations"

# Remove snap Docker (Ubuntu-specific, causes permission errors)
if command -v snap &>/dev/null && snap list docker 2>/dev/null | grep -q docker; then
  info "Removing snap Docker (known to cause permission issues)..."
  sudo snap remove docker 2>/dev/null || true
  hash -r
fi

# Cloud VM pre-installed Docker cleanup
# Azure, GCP, and some AWS AMIs ship with outdated Docker or Moby packages.
if dpkg -l moby-engine 2>/dev/null | grep -q "^ii"; then
  info "Removing Azure-provided Moby engine (replacing with Docker CE)..."
  sudo apt-get remove -y moby-engine moby-cli moby-containerd moby-runc moby-compose 2>/dev/null || true
fi

case "$DISTRO_FAMILY" in
  debian)
    # Remove old docker-compose v1 (Python-based, incompatible with newer engines)
    if dpkg -l docker-compose 2>/dev/null | grep -q "^ii"; then
      info "Removing old docker-compose v1..."
      sudo apt-get remove -y docker-compose 2>/dev/null || true
    fi
    # Remove distro-packaged Docker.
    # Note: we deliberately do NOT remove `runc` here. Modern containerd.io
    # declares `Conflicts: runc` and apt resolves the swap automatically.
    # Pre-removing `runc` can break unrelated dependents (kubeadm, crun-based
    # tools) and was the trigger for an earlier dpkg-failure report.
    for pkg in docker.io containerd podman-docker; do
      if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        info "Removing $pkg..."
        wait_for_apt_lock
        sudo apt-get remove -y "$pkg" 2>/dev/null || true
      fi
    done
    ;;
  rhel|fedora)
    # Remove distro-packaged Docker/Podman
    for pkg in docker podman-docker containerd.io runc; do
      if rpm -q "$pkg" &>/dev/null; then
        info "Removing $pkg..."
        sudo dnf remove -y "$pkg" 2>/dev/null || sudo yum remove -y "$pkg" 2>/dev/null || true
      fi
    done
    ;;
  amzn)
    if rpm -q docker &>/dev/null; then
      info "Removing Amazon Linux docker package..."
      sudo yum remove -y docker 2>/dev/null || true
    fi
    ;;
  arch)
    info "Arch Linux — skipping package removal (pacman handles conflicts)"
    ;;
esac

info "Cleanup complete"

###############################################################################
# 2. Install Docker Engine
###############################################################################
step "Installing Docker Engine"

if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
  info "Docker with Compose v2 already installed: $(docker --version)"
  if ! sudo systemctl is-active --quiet docker 2>/dev/null; then
    warn "Docker daemon is not currently running — will repair it in the next step."
  fi
else
  case "$DISTRO_FAMILY" in
    debian)
      info "Installing from Docker's official apt repository..."
      sudo apt-get update -qq
      apt_install_with_repair ca-certificates curl gnupg

      sudo install -m 0755 -d /etc/apt/keyrings
      if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
        curl -fsSL "https://download.docker.com/linux/${DISTRO_ID}/gpg" | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
      fi

      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO_ID} ${DISTRO_CODENAME} stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

      sudo apt-get update -qq
      apt_install_with_repair docker-ce docker-ce-cli containerd.io docker-compose-plugin
      ;;

    rhel)
      info "Installing from Docker's official yum/dnf repository..."
      sudo dnf install -y yum-utils 2>/dev/null || sudo yum install -y yum-utils 2>/dev/null
      sudo yum-config-manager --add-repo "https://download.docker.com/linux/${DISTRO_ID}/docker-ce.repo"
      sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin 2>/dev/null || \
        sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      ;;

    fedora)
      info "Installing from Docker's official dnf repository..."
      sudo dnf install -y dnf-plugins-core
      sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
      sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
      ;;

    amzn)
      info "Installing Docker on Amazon Linux..."
      sudo yum install -y docker
      # Amazon Linux doesn't have docker-compose-plugin in its repo — install manually
      COMPOSE_VERSION=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
      sudo mkdir -p /usr/local/lib/docker/cli-plugins
      sudo curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" \
        -o /usr/local/lib/docker/cli-plugins/docker-compose
      sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
      ;;

    arch)
      info "Installing Docker via pacman..."
      sudo pacman -Sy --noconfirm docker docker-compose
      ;;

    *)
      error "Unsupported distro family: $DISTRO_FAMILY"
      ;;
  esac

  info "Docker installed: $(docker --version)"
  info "Compose installed: $(docker compose version)"
fi

###############################################################################
# 3. Start Docker and add user to group
###############################################################################
step "Configuring Docker"

# Reload systemd in case the install added or changed unit files mid-run.
sudo systemctl daemon-reload >/dev/null 2>&1 || true

# Start containerd FIRST — docker.service depends on it. If containerd is
# wedged, docker will refuse to start with a generic "control process exited
# with error code" message, which is exactly the failure the user reported.
sudo systemctl enable containerd >/dev/null 2>&1 || true
if ! sudo systemctl start containerd 2>/dev/null; then
  warn "containerd failed to start on first attempt — retrying..."
  sleep 2
  sudo systemctl restart containerd 2>/dev/null || true
fi

sudo systemctl enable docker >/dev/null 2>&1 || true

# Start docker — with auto-recovery on failure.
if ! sudo systemctl start docker 2>/dev/null; then
  warn "docker.service failed to start on first attempt."
  dump_docker_diagnostics

  warn "Recovery attempt 1: reloading systemd and restarting containerd..."
  sudo systemctl daemon-reload || true
  sudo systemctl restart containerd 2>/dev/null || true
  sleep 2

  if ! sudo systemctl start docker 2>/dev/null; then
    case "$DISTRO_FAMILY" in
      debian)
        warn "Recovery attempt 2: reinstalling docker-ce + containerd.io..."
        sudo apt-get install --reinstall -y docker-ce docker-ce-cli containerd.io 2>&1 | tail -n 20 >&2 || true
        ;;
      rhel|fedora)
        warn "Recovery attempt 2: reinstalling docker-ce + containerd.io..."
        sudo dnf reinstall -y docker-ce docker-ce-cli containerd.io 2>&1 | tail -n 20 >&2 || \
          sudo yum reinstall -y docker-ce docker-ce-cli containerd.io 2>&1 | tail -n 20 >&2 || true
        ;;
    esac
    sudo systemctl daemon-reload || true
    sudo systemctl restart containerd 2>/dev/null || true
    sleep 2

    if ! sudo systemctl start docker 2>/dev/null; then
      dump_docker_diagnostics
      error "Docker daemon could not be started after recovery attempts.

  Common causes and fixes:
    1. Reboot — kernel module / cgroup state may need refresh after install
    2. Invalid /etc/docker/daemon.json — check JSON syntax
    3. Disk full — check: df -h /var/lib/docker
    4. Conflicting iptables backend — try: sudo update-alternatives --config iptables
    5. cgroup v1/v2 mismatch — check: stat -fc %T /sys/fs/cgroup

  Manual diagnostic commands:
    sudo systemctl status docker.service
    sudo journalctl -xeu docker.service
    sudo journalctl -xeu containerd.service"
    fi
  fi
fi

CURRENT_USER="$(id -un)"
if [[ "$CURRENT_USER" != "root" ]]; then
  if ! groups "$CURRENT_USER" | grep -qw docker; then
    info "Adding '$CURRENT_USER' to the docker group..."
    sudo usermod -aG docker "$CURRENT_USER"
    warn "Group change takes effect after re-login. Using sudo for now."
  fi
fi

if sudo docker info &>/dev/null; then
  info "Docker engine is running"
else
  dump_docker_diagnostics
  error "Docker engine started but is not responding. See diagnostics above."
fi

# NOTE: the git-install helper (ensure_git) was removed alongside the source-clone
# fallback — a source-free, build-free install never needs git.

###############################################################################
# 5. Provision the install dir (no source checkout required)
###############################################################################

# carry_forward_prior_secrets — a re-run that lands in a NEW stack dir must not
# strand the encryption passphrases in the OLD .env. Every Culvert stack dir
# basename resolves to the SAME compose project ('culvert'), so all stack dirs
# SHARE the named volumes (proxy-data etc.); the new dir's `docker compose up`
# reuses the existing, still-ENCRYPTED /data/ca.bundle. If the new .env lacks
# CULVERT_CA_PASSPHRASE the proxy recreates with an empty passphrase and — since
# CA load is non-fatal by design — SILENTLY disables SSL inspection (TLS becomes
# tunnel-only: no scanning/DLP/CDR). Copy the prior .env forward so the existing
# CA/log passphrases survive the move. Best-effort; never fatal.
carry_forward_prior_secrets() {
  [[ -f "$INSTALL_DIR/.env" ]] && return 0   # a .env already here — never overwrite
  local prior=""
  # 1. The dir the currently/most-recently deployed proxy container ran from.
  prior="$(sudo docker inspect culvert \
    --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' 2>/dev/null || true)"
  # 2. The legacy home-dir default of the INVOKING user (sudo resets $HOME to
  #    root's, so resolve the real user's home explicitly).
  if [[ -z "$prior" || ! -f "$prior/.env" ]]; then
    local real_user real_home
    real_user="${SUDO_USER:-$(id -un)}"
    real_home="$(getent passwd "$real_user" 2>/dev/null | cut -d: -f6 || true)"
    if [[ -n "$real_home" && -f "$real_home/Culvert/.env" ]]; then
      prior="$real_home/Culvert"
    fi
  fi
  if [[ -n "$prior" && "$prior" != "$INSTALL_DIR" && -f "$prior/.env" ]]; then
    info "Carrying encryption secrets forward from the existing deployment at $prior"
    info "(shared compose project + volumes — preserves the SSL-inspection CA passphrase)."
    sudo install -m 600 -o "$(id -un)" "$prior/.env" "$INSTALL_DIR/.env"
  fi
}

step "Setting up Culvert"

# Deployment needs only the compose files + the maintenance-agent packaging.
# Those ship INSIDE the public proxy image at /app/deploy and are extracted in
# §6b after the image is pulled — a fresh install never clones the source
# repo (which may not be publicly readable). Running from inside an existing
# checkout / deployment dir uses its files directly.
if [[ -f "./docker-compose.yml" ]] && grep -q "culvert" ./docker-compose.yml 2>/dev/null; then
  info "Already inside a Culvert checkout/deployment dir: $(pwd)"
  INSTALL_DIR="$(pwd)"
elif [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
  info "Culvert deployment already exists at $INSTALL_DIR"
else
  info "Provisioning $INSTALL_DIR..."
  sudo mkdir -p "$INSTALL_DIR"
  # Owned by the invoking user so later non-sudo writes (.env via env_put)
  # work; the maintenance agent gets group traversal separately
  # (ensure_agent_traversal), and ancestors of /srv/culvert are already
  # world-searchable.
  sudo chown "$(id -un)" "$INSTALL_DIR"
  carry_forward_prior_secrets
fi

cd "$INSTALL_DIR"
# Canonicalize to the absolute path `cd` just resolved. INSTALL_DIR can still
# hold a relative CULVERT_DIR override (e.g. "culvert-stack") at this point,
# and every later use of $INSTALL_DIR — including agent_ancestors_traversable,
# which walks dirname($INSTALL_DIR) upward — assumes an absolute path. Passing
# a relative one there would resolve to "$PWD/$INSTALL_DIR", double-counting
# the leaf we already cd'd into instead of naming it once.
INSTALL_DIR="$PWD"

###############################################################################
# 6. Seed the pinned proxy image tag (P1.4)
###############################################################################
step "Seeding proxy image"

# docker-compose.yml resolves the FIXED local tag `culvert/proxy:pinned`
# (P1.4 — the proxy image is selected at the sudo boundary, not via env
# vars). The tag is LOCAL-ONLY and never published to a registry, so it must
# exist before `docker compose up`, or compose tries to pull
# docker.io/culvert/proxy:pinned and fails with "pull access denied".
# See roadmap/D1.6c-pin-value-binding-plan.md §8 (migration strategy).
PINNED_TAG="culvert/proxy:pinned"
PROXY_REPO="${CULVERT_PROXY_REPO:-ghcr.io/kidcarmi/culvert}"

# ── Signed release catalog: the release AUTHORITY for a fresh install ─────────
# The signed catalog (not GHCR tag enumeration) decides which immutable image
# digest a fresh install deploys — the SAME authority that governs day-2 updates.
# The installer runs the `culvert bootstrap-resolve` verifier (baked trust roots:
# signature + freshness + rollback) to resolve the channel to a repo@sha256 digest;
# the shell performs NO cryptography or JSON trust parsing. Origin and trust are
# independent: overriding the URL never changes the trusted signing identity.
#   CULVERT_RELEASE_CATALOG_URL  unset ⇒ the baked canonical origin; an explicit
#     URL ⇒ operator mirror/staging; off/none/disabled ⇒ NO catalog fetch (never
#     a silent downgrade to tag discovery — an explicit seed is then required).
#   CULVERT_INSTALL_CHANNEL      install channel (default: stable ⇒ the catalog
#     "recommended" mainline). stable | lts | critical.
CATALOG_URL="${CULVERT_RELEASE_CATALOG_URL:-}"
INSTALL_CHANNEL="${CULVERT_INSTALL_CHANNEL:-stable}"
# GH_REPO is the source/release repository the signed `culvert-linux-<arch>`
# verifier asset is published to (distinct from PROXY_REPO, the ghcr.io image).
GH_REPO="${CULVERT_GITHUB_REPO:-KidCarmi/Culvert}"

# Pinned release-signing identity (PUBLIC — mirrors release_identity.env, kept
# byte-equal by TestReleaseIdentitySSOT). Used to cosign-verify the proxy image
# BEFORE we trust the host-root maintenance-agent binary extracted from its
# /app/deploy bundle. Hardcoded here — NOT read from the image — on purpose:
# the trust identity must come from a source the image cannot forge (this
# script arrives over TLS from a trusted origin; the image does not).
# NOTE: the SAN is pinned to TAGGED releases (…@refs/tags/v.*$) — only a
# version-tagged signed image verifies; a main-tracking :latest or a locally
# built image does not, and the agent then falls back to the signed-release
# download (fail-closed) rather than trusting an unverified binary.
MAINT_SIGSTORE_ISSUER="https://token.actions.githubusercontent.com"
MAINT_SIGSTORE_SAN_REGEX='^https://github\.com/KidCarmi/Culvert/\.github/workflows/ci\.yml@refs/tags/v.*$'
# Pinned cosign verifier image (the root of trust for the check). A bare tag is
# mutable; high-assurance operators should override with a digest-pinned ref.
# MUST be cosign v3.x (new-format Sigstore bundles). Mirrors the agent
# installer's COSIGN_IMAGE default.
MAINT_COSIGN_IMAGE="${CULVERT_MAINT_COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v3.0.6}"

# verify_pinned_image_signature — cosign-verify (keyless) the registry image
# behind $PINNED_TAG against the pinned tag identity. No host cosign needed;
# runs the pinned cosign container (docker is already up). Return codes:
#   0 = VERIFIED (a keyless signature present AND the pinned tag identity matched)
#   1 = NOT VERIFIED, for ANY reason (image has no registry digest — e.g.
#       locally built; unsigned/main-only image; private image the cosign
#       container has no credentials for; identity mismatch; or cosign/registry/
#       Rekor unreachable). The reasons are deliberately NOT distinguished:
#       cosign's "no matching signatures" text cannot reliably tell an absent
#       signature from a present-but-mismatched one, so claiming "tampering"
#       would cry wolf on a normal :latest. Fail-closed callers trust the
#       bundle ONLY on return 0; every 1 falls through to the self-verifying
#       signed-release download.
verify_pinned_image_signature() {
  local digest_ref
  # RepoDigests carries the source-registry digest of the pulled image; a
  # locally built (never-pushed) image has none → unverifiable.
  digest_ref="$(sudo docker image inspect "$PINNED_TAG" \
    --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' 2>/dev/null || true)"
  if [[ "$digest_ref" != *@sha256:* ]]; then
    return 1
  fi
  # Best-effort registry auth for the cosign container: it fetches the signature
  # artifact from the SAME repo as the image, so a PRIVATE image needs the same
  # credentials the earlier `sudo docker pull` used (root's docker config under
  # sudo). Public images (the default posture) need none. Plaintext-auth entries
  # transfer; external credential helpers do not (documented limitation).
  local -a cred_args=()
  if sudo test -f /root/.docker/config.json 2>/dev/null; then
    cred_args=(-v /root/.docker:/root/.docker:ro)
  fi
  # --timeout bounds the Sigstore/Rekor network call so an egress-filtered
  # appliance (sigstore.dev blackholed) fails closed instead of hanging.
  local rc=0
  sudo docker run --rm "${cred_args[@]}" "$MAINT_COSIGN_IMAGE" verify \
    --timeout=60s \
    --certificate-oidc-issuer="$MAINT_SIGSTORE_ISSUER" \
    --certificate-identity-regexp="$MAINT_SIGSTORE_SAN_REGEX" \
    "$digest_ref" >/dev/null 2>&1 || rc=$?
  [[ "$rc" -eq 0 ]]
}

# NOTE: the historical source-clone-then-build helper has been REMOVED. Culvert
# only ever deploys a SIGNED PUBLISHED image and takes its docker-compose.yml from
# that same image's /app/deploy bundle, so the binary and its compose command are
# always the same release. Cloning HEAD + building is exactly how the compose
# drifted a release ahead of the binary and crash-looped the proxy; there is no
# longer a build path. Offline hosts preload an image and set CULVERT_PROXY_SEED_REF.

# resolve_latest_signed_release_ref — BREAK-GLASS ONLY (gated on
# CULVERT_INSTALL_ALLOW_TAG_DISCOVERY=1; never runs on a normal install). This is
# the LEGACY GHCR tag-enumeration path that the signed catalog replaces: it picks
# a MUTABLE tag by a naive version sort, which is exactly how a stale legacy
# `0.0.238` image (predating the /app/deploy bundle) was selected on a fresh host.
# It is retained solely as a consciously-named operator escape hatch and is NOT a
# trusted catalog decision.
#
# echo "<PROXY_REPO>:vX.Y.Z" for the newest vMAJOR.MINOR.PATCH tag published to the
# (public) GHCR proxy repo. A default install should seed a SIGNED RELEASE digest:
# only a release-tag image
# cosign-verifies against the pinned identity (verify_pinned_image_signature),
# which is what lets the host maintenance agent install from a trusted image.
# `:latest` is a main build and can NEVER verify (the pinned SAN anchors to
# refs/tags/v*), so seeding it left the agent SKIPPED on every default
# source-free install. Uses the anonymous GHCR pull-token flow: works for a
# PUBLIC image with no credentials (the stated distribution posture even after
# the source repo goes private). Echoes nothing on ANY failure — the caller then
# falls back to :latest, so this only ever IMPROVES the default, never worsens it.
resolve_latest_signed_release_ref() {
  command -v curl >/dev/null 2>&1 || return 0
  local reg repo_path token tags latest
  reg="${PROXY_REPO%%/*}"        # ghcr.io
  repo_path="${PROXY_REPO#*/}"   # kidcarmi/culvert
  # The anonymous tag-list flow is GHCR-specific and needs a host/path split; a
  # custom/private registry (CULVERT_PROXY_REPO override) falls back to :latest.
  [[ "$reg" == "ghcr.io" && "$repo_path" != "$PROXY_REPO" ]] || return 0
  # Each command-substitution assignment is explicitly `|| return 0` guarded so
  # the fallback does not depend on bash's non-POSIX `set -e`-in-$() suppression
  # (RHEL-family / Amazon Linux 2 ship bash 4.x where that quirk differs).
  token="$(curl -fsS --max-time 15 "https://ghcr.io/token?scope=repository:${repo_path}:pull" 2>/dev/null \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')" || return 0
  [[ -n "$token" ]] || return 0
  tags="$(curl -fsS --max-time 15 -H "Authorization: Bearer $token" \
    "https://ghcr.io/v2/${repo_path}/tags/list?n=1000" 2>/dev/null)" || return 0
  # Newest final MAJOR.MINOR.PATCH by version sort. The proxy image tags are
  # produced by docker/metadata-action `type=semver,pattern={{version}}` (ci.yml),
  # which emits the semver WITHOUT a leading "v" (git tag v1.0.79 → image tag
  # 1.0.79). Match THAT shape and deliberately IGNORE any legacy "v"-prefixed
  # tags: the opening-quote-then-digit pattern "[0-9]... never matches "v0.0.238",
  # so a stray old tag can no longer win the sort. (The historical `"v[0-9]...`
  # pattern matched none of the real {{version}} tags and picked up a year-old
  # "v0.0.238" leftover instead — the crash-loop-inducing wrong-version pull.)
  # Pre-releases (1.2.3-rc1) are excluded — the closing quote only follows bare
  # X.Y.Z, and the pinned identity/pipeline sign final release tags.
  latest="$(printf '%s' "$tags" | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' | tr -d '"' | sort -V -u | tail -n1)" || return 0
  [[ -n "$latest" ]] || return 0
  printf '%s:%s\n' "$PROXY_REPO" "$latest"
}

# catalog_fetch_disabled — true when CULVERT_RELEASE_CATALOG_URL is an explicit
# off/none/disabled sentinel. A disabled origin must NEVER silently downgrade to
# tag discovery; the caller then requires an explicit verified seed instead.
catalog_fetch_disabled() {
  case "$(printf '%s' "${CATALOG_URL:-}" | tr '[:upper:]' '[:lower:]')" in
    off|none|disabled) return 0 ;;
    *) return 1 ;;
  esac
}

# acquire_bootstrap_verifier — echo the path to a `culvert` binary that carries
# the `bootstrap-resolve` subcommand, or return 1. The binary is the verifier
# whose baked trust roots perform the catalog signature/freshness/rollback checks
# — that verification is the trust gate and is NOT deferred.
#
# STAGE NOTE: this stage downloads the signed `culvert-linux-<arch>` release asset
# over HTTPS from github.com. Hardening the ACQUISITION with a cosign verify-blob
# of the verifier binary itself (against the pinned release identity) is a
# deliberately DEFERRED follow-up stage; it does not change what the binary then
# verifies about the catalog.
# resolve_verifier_version — echo the release tag to fetch the verifier from.
# CULVERT_BOOTSTRAP_VERIFIER_VERSION pins it; otherwise the MAINTAINER-DESIGNATED
# latest release (NOT a tag sort — this is why it can never resurrect a legacy
# 0.0.238-style tag). The verifier version is decoupled from the appliance version
# it resolves (the CATALOG picks the appliance image). Two independent lookups so a
# rate-limited api.github.com (60 req/hr/IP, unauthenticated) does not hard-fail the
# install: the JSON API first, then the non-rate-limited releases/latest HTML
# redirect whose Location carries the tag.
# safe_release_tag — accept only a conservative release-tag charset. This is a
# HARD injection guard: `ver` flows into the download URL, and GitHub applies
# RFC-3986 dot-segment normalization, so a tag containing `/` or `..` could escape
# to a DIFFERENT repo's asset (e.g. ver="../../attacker/evilrepo/releases/download/v1").
# Reject anything but [alnum . _ -] with an optional leading `v` and no `..`.
safe_release_tag() {
  [[ "$1" =~ ^v?[0-9A-Za-z][0-9A-Za-z._-]*$ && "$1" != *".."* ]]
}

resolve_verifier_version() {
  local v
  v="${CULVERT_BOOTSTRAP_VERIFIER_VERSION:-}"
  if [[ -n "$v" ]]; then
    safe_release_tag "$v" || { warn "CULVERT_BOOTSTRAP_VERIFIER_VERSION=$v is not a valid release tag"; return 1; }
    printf '%s\n' "$v"; return 0
  fi
  v="$(curl -fsS --max-time 15 "https://api.github.com/repos/${GH_REPO}/releases/latest" 2>/dev/null \
    | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | head -n1 | sed -E 's/.*"([^"]+)"[[:space:]]*$/\1/')" || true
  if [[ -z "$v" ]]; then
    # Fallback: the HTML redirect from /releases/latest → /releases/tag/<tag> is not
    # API-rate-limited. Extract the tag from the Location header.
    v="$(curl -fsSI --max-time 15 "https://github.com/${GH_REPO}/releases/latest" 2>/dev/null \
      | tr -d '\r' | grep -iE '^location:' | sed -E 's#.*/releases/tag/([^/[:space:]]+).*#\1#' | head -n1)" || true
  fi
  [[ -n "$v" ]] || return 1
  # Validate even the network-derived tag: a MITM-poisoned tag_name/Location must not
  # be able to path-traverse the download URL to another repo.
  safe_release_tag "$v" || { warn "resolved verifier tag '$v' is not a valid release tag"; return 1; }
  printf '%s\n' "$v"
}

# acquire_bootstrap_verifier — download a `culvert` binary that carries the
# `bootstrap-resolve` subcommand and set BOOTSTRAP_VERIFIER_BIN (+ _DIR for
# cleanup). Returns 1 on any failure. The binary's baked trust roots perform the
# catalog signature/freshness/rollback checks — that verification is the trust gate.
#
# TRUST: the verifier binary is the ROOT OF TRUST for the entire fresh install (it
# selects the proxy image, whose /app/deploy provides the root-run maintenance-agent
# packaging). A TLS-only download is NOT sufficient on a host behind a TLS-inspection
# proxy with a trusted org CA — the product's own deployment reality — so the binary
# is cosign verify-blob'd against the PINNED release identity (MAINT_SIGSTORE_*) BEFORE
# it is executed. Fail closed on any verification failure. Break-glass:
# CULVERT_BOOTSTRAP_SKIP_VERIFY=1 (loud) for air-gapped / egress-filtered hosts that
# cannot reach the signature bundle or Sigstore endpoints.
BOOTSTRAP_VERIFIER_BIN=""
BOOTSTRAP_VERIFIER_DIR=""
acquire_bootstrap_verifier() {
  if [[ -n "$BOOTSTRAP_VERIFIER_BIN" && -x "$BOOTSTRAP_VERIFIER_BIN" ]]; then
    return 0 # already fetched this run
  fi
  command -v curl >/dev/null 2>&1 || { warn "curl is required to fetch the catalog verifier"; return 1; }
  # GH_REPO is interpolated into the download URL; constrain it to owner/name so a
  # CULVERT_GITHUB_REPO override cannot inject path segments or a different host.
  if [[ ! "$GH_REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ || "$GH_REPO" == *".."* ]]; then
    warn "CULVERT_GITHUB_REPO='$GH_REPO' is not a valid owner/name repository"; return 1
  fi
  local arch
  case "$(uname -m)" in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) warn "unsupported architecture '$(uname -m)' — the catalog verifier ships linux/amd64 and linux/arm64 only"; return 1 ;;
  esac
  local ver
  if ! ver="$(resolve_verifier_version)"; then
    warn "could not determine the release tag for the catalog verifier (api.github.com may be rate-limited);"
    warn "pin one explicitly with CULVERT_BOOTSTRAP_VERIFIER_VERSION=vX.Y.Z, or preload an image and use CULVERT_PROXY_SEED_REF."
    return 1
  fi
  local dir asset base
  # Stage under an EXEC-CAPABLE dir: the verifier is downloaded THEN executed, so a
  # /tmp mounted `noexec` (CIS-hardened / hardened-EC2 posture) would block the
  # trusted install. Prefer the install dir (root fs, owned by us); fall back to
  # $TMPDIR/mktemp default only if that fails. cleanup_bootstrap_verifier removes it.
  dir="$(mktemp -d "${INSTALL_DIR}/.verifier.XXXXXX" 2>/dev/null)" || dir="$(mktemp -d)" || return 1
  asset="culvert-linux-${arch}"
  base="https://github.com/${GH_REPO}/releases/download/${ver}"
  # Download into the dir under the ASSET name so cosign resolves the sibling
  # <asset>.sigstore.json by basename.
  if ! curl -fsSL --max-time 90 -o "$dir/$asset" "$base/$asset"; then
    warn "could not download the catalog verifier ($asset $ver)"
    rm -rf "$dir"; return 1
  fi
  if ! verify_bootstrap_verifier "$dir" "$asset" "$ver"; then
    rm -rf "$dir"; return 1
  fi
  chmod 0755 "$dir/$asset"
  # Capability probe WITHOUT executing: a `culvert` binary predating this feature
  # lacks the `bootstrap-resolve` subcommand and would instead treat it as a stray
  # positional arg and START THE PROXY SERVER — hanging the installer and binding
  # ports. A static string check (never executing an unknown-capability binary)
  # avoids that entirely; the timeout in seed_from_catalog is a second backstop.
  if ! grep -qa 'bootstrap-resolve' "$dir/$asset"; then
    warn "the downloaded verifier ($asset $ver) does not support 'bootstrap-resolve' (release predates the catalog installer);"
    warn "pin a newer release with CULVERT_BOOTSTRAP_VERIFIER_VERSION=vX.Y.Z, or preload an image and use CULVERT_PROXY_SEED_REF."
    rm -rf "$dir"; return 1
  fi
  BOOTSTRAP_VERIFIER_BIN="$dir/$asset"
  BOOTSTRAP_VERIFIER_DIR="$dir"
  return 0
}

# verify_bootstrap_verifier DIR ASSET VER — cosign verify-blob the downloaded
# verifier against the pinned release identity, in the pinned cosign container (no
# host cosign needed; docker is already up). Fail-closed. $1=dir $2=asset $3=version.
verify_bootstrap_verifier() {
  local dir=$1 asset=$2 ver=$3
  if [[ "${CULVERT_BOOTSTRAP_SKIP_VERIFY:-}" == "1" ]]; then
    warn "CULVERT_BOOTSTRAP_SKIP_VERIFY=1 — trusting the catalog verifier WITHOUT cosign verification (BREAK-GLASS; air-gapped/egress-filtered only)."
    return 0
  fi
  if ! curl -fsSL --max-time 60 -o "$dir/$asset.sigstore.json" "https://github.com/${GH_REPO}/releases/download/${ver}/$asset.sigstore.json"; then
    warn "could not download the verifier signature bundle ($asset.sigstore.json $ver) — refusing to trust an unverified verifier."
    warn "Preload an image and use CULVERT_PROXY_SEED_REF, or set CULVERT_BOOTSTRAP_SKIP_VERIFY=1 (break-glass)."
    return 1
  fi
  # --user 0:0: the staging dir is mktemp -d (0700, invoking-user-owned); the cosign
  # image's default nonroot user could not traverse it. Mount read-only.
  # --certificate-identity-regexp against the PINNED SAN (tagged releases of this
  # repo's ci.yml) — the SAME identity that gates the proxy image + the maint agent.
  # --timeout bounds the Sigstore/Rekor/TUF network calls so an egress-filtered
  # appliance fails CLOSED fast (matching verify_pinned_image_signature) instead of
  # hanging until the operator reaches for CULVERT_BOOTSTRAP_SKIP_VERIFY. Locked-down
  # networks must allow the Sigstore endpoints (Fulcio, Rekor, the TUF CDN) or use
  # the offline path (CULVERT_PROXY_SEED_REF); see docs/operator/*.
  if ! sudo docker run --rm --user 0:0 -v "$dir:/work:ro" -w /work "$MAINT_COSIGN_IMAGE" \
      verify-blob \
      --timeout=60s \
      --bundle "$asset.sigstore.json" \
      --new-bundle-format \
      --certificate-identity-regexp "$MAINT_SIGSTORE_SAN_REGEX" \
      --certificate-oidc-issuer "$MAINT_SIGSTORE_ISSUER" \
      "$asset" >/dev/null 2>&1; then
    warn "cosign verification FAILED for the catalog verifier ($asset $ver) against the pinned release identity — refusing to run it."
    warn "If this host cannot reach the Sigstore endpoints (Fulcio/Rekor/TUF CDN), preload an image and use CULVERT_PROXY_SEED_REF, or CULVERT_BOOTSTRAP_SKIP_VERIFY=1 (break-glass)."
    return 1
  fi
  info "Catalog verifier cosign-verified against the pinned release identity ($ver)."
  return 0
}

# cleanup_bootstrap_verifier — remove the throwaway verifier download + floor dirs.
cleanup_bootstrap_verifier() {
  [[ -n "$BOOTSTRAP_VERIFIER_DIR" && -d "$BOOTSTRAP_VERIFIER_DIR" ]] && rm -rf "$BOOTSTRAP_VERIFIER_DIR"
  [[ -n "$BOOTSTRAP_FLOOR_DIR" && -d "$BOOTSTRAP_FLOOR_DIR" ]] && rm -rf "$BOOTSTRAP_FLOOR_DIR"
  BOOTSTRAP_VERIFIER_BIN=""
  BOOTSTRAP_VERIFIER_DIR=""
  BOOTSTRAP_FLOOR_DIR=""
}

# stage_rollback_floor — if a PRIOR install's proxy-data volume survived (reinstall
# where the container + stack dir were removed but the /data volume was kept), copy
# its persisted rollback floor (release_catalog_state.json) into a readable staging
# dir and echo that dir, so bootstrap-resolve enforces anti-rollback/replay and a
# reinstall cannot be silently downgraded below the version this host last accepted.
#
# Best-effort and CONSERVATIVE: the floor lives inside a ROOT-OWNED named volume, so
# the copy needs sudo; and we require EXACTLY ONE matching proxy-data volume with a
# floor file (ambiguity ⇒ skip rather than guess a floor). Does nothing on a
# first-ever install (no volume ⇒ no floor ⇒ bootstrap-resolve uses floor 0, which is
# correct for a fresh host). A wrong/unrelated floor can only cause a fail-CLOSED
# rejection (never a downgrade), so erring toward enforcement is safe.
BOOTSTRAP_FLOOR_DIR=""

# proxy_data_volume_mountpoint — echo the host mountpoint of the SINGLE proxy-data
# named volume, or return 1 if absent/ambiguous. Root-owned; callers use sudo to
# read/write. Conservative single-match so we never touch an unrelated project's
# volume (ambiguity ⇒ skip).
proxy_data_volume_mountpoint() {
  command -v docker >/dev/null 2>&1 || return 1
  local vols n vol
  vols="$(sudo docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E '(^|_)proxy-data$' || true)"
  [[ -n "$vols" ]] || return 1
  n="$(printf '%s\n' "$vols" | grep -c . || true)"
  [[ "$n" == "1" ]] || return 1
  vol="$vols"
  sudo docker volume inspect "$vol" --format '{{.Mountpoint}}' 2>/dev/null
}

stage_rollback_floor() {
  local mp fdir
  mp="$(proxy_data_volume_mountpoint)" || return 1
  { [[ -n "$mp" ]] && sudo test -f "$mp/release_catalog_state.json"; } || return 1
  fdir="$(mktemp -d "${INSTALL_DIR}/.floor.XXXXXX" 2>/dev/null)" || fdir="$(mktemp -d)" || return 1
  if ! sudo cp "$mp/release_catalog_state.json" "$fdir/release_catalog_state.json" 2>/dev/null; then
    rm -rf "$fdir"; return 1
  fi
  sudo chown "$(id -u):$(id -g)" "$fdir/release_catalog_state.json" 2>/dev/null || true
  BOOTSTRAP_FLOOR_DIR="$fdir"
  printf '%s\n' "$fdir"
}

# persist_bootstrap_decision — after the stack is up (so the proxy-data volume
# exists), copy the host-side catalog decision record into /data so the RUNNING
# appliance can read it and surface it read-only on /api/releases (provenance /
# incident forensics: which digest + catalog_version + trust scheme provisioned this
# host). Best-effort: no record (SEED_REF / break-glass install) or no resolvable
# volume ⇒ silently skip; never fail the install. World-readable (0644) — the record
# is non-secret metadata and the container runs as a non-root user.
persist_bootstrap_decision() {
  local src mp rec_ref cur_ref
  src="$INSTALL_DIR/.catalog-bootstrap.json"
  [[ -f "$src" ]] || return 0
  # Publish ONLY a record that matches the ACTUALLY-seeded image. A stale record from
  # a prior failed catalog attempt (followed by a break-glass/SEED_REF reseed) must
  # not misreport /api/releases as a catalog-authorized digest that was never
  # deployed. Compare the record's image_ref to the pinned image's registry digest.
  rec_ref="$(grep -oE '"image_ref"[[:space:]]*:[[:space:]]*"[^"]+"' "$src" 2>/dev/null \
    | head -n1 | sed -E 's/.*"([^"]+)"[[:space:]]*$/\1/')" || true
  cur_ref="$(sudo docker image inspect "$PINNED_TAG" \
    --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' 2>/dev/null || true)"
  if [[ -z "$rec_ref" || "$rec_ref" != "$cur_ref" ]]; then
    return 0 # record does not match the running image (stale / non-catalog seed) — skip
  fi
  mp="$(proxy_data_volume_mountpoint)" || return 0
  [[ -n "$mp" ]] || return 0
  if sudo cp "$src" "$mp/bootstrap_decision.json" 2>/dev/null; then
    sudo chmod 0644 "$mp/bootstrap_decision.json" 2>/dev/null || true
    info "Recorded the bootstrap catalog decision to /data (provenance on /api/releases)."
  fi
}

# seed_from_catalog — the TRUSTED fresh-install default: resolve the image digest
# from the signed catalog and seed $PINNED_TAG from that exact immutable digest.
# Returns 0 on success (tag seeded), 1 otherwise. Never falls back to a mutable
# tag; a failure lets the caller apply its own fail-closed policy.
# warn_if_clock_skewed — a badly-wrong host clock is the sharp edge of catalog
# freshness: the signature is clock-independent, but expires_at is checked against
# the LOCAL clock, so a host that thinks it is months in the past can accept a
# long-expired (genuinely-signed) catalog — a real pre-NTP cloud-first-boot footgun.
# Compare the host clock to TLS-fetched network time (the Date header from an HTTPS
# HEAD) and warn if they diverge by more than an hour. Advisory only (the catalog
# freshness gate remains the hard control); this just tells the operator to sync NTP.
warn_if_clock_skewed() {
  command -v curl >/dev/null 2>&1 || return 0
  command -v date >/dev/null 2>&1 || return 0
  local hdr server_epoch host_epoch skew
  hdr="$(curl -fsSI --max-time 10 "https://github.com" 2>/dev/null | tr -d '\r' \
    | awk -F': ' 'tolower($1)=="date"{print $2; exit}')" || true
  [[ -n "$hdr" ]] || return 0
  server_epoch="$(date -u -d "$hdr" +%s 2>/dev/null)" || return 0
  [[ -n "$server_epoch" ]] || return 0
  host_epoch="$(date -u +%s)"
  skew=$(( host_epoch - server_epoch )); [[ "$skew" -lt 0 ]] && skew=$(( -skew ))
  if [[ "$skew" -gt 3600 ]]; then
    warn "Host clock differs from network time by ~${skew}s. A wrong clock can make the"
    warn "signed-catalog freshness check accept a STALE catalog (or reject a fresh one)."
    warn "Sync time before installing:  sudo timedatectl set-ntp true   (or: sudo chronyc makestep)"
  fi
}

seed_from_catalog() {
  if catalog_fetch_disabled; then
    warn "CULVERT_RELEASE_CATALOG_URL=$CATALOG_URL — catalog fetch is disabled; not auto-seeding from the catalog."
    return 1
  fi
  # Advisory: a pre-NTP / mis-set clock is the main way a fresh install accepts a
  # stale signed catalog. Warn (non-fatal) before we resolve.
  warn_if_clock_skewed
  # A plaintext override origin leaves the catalog fetch confidential-only-broken and,
  # worse, leaks any presigned mirror credentials to on-path observers. The signature
  # still protects INTEGRITY over http, but warn loudly — prefer https for mirrors.
  case "$(printf '%s' "${CATALOG_URL:-}" | tr '[:upper:]' '[:lower:]')" in
    http://*) warn "CULVERT_RELEASE_CATALOG_URL uses plaintext http:// — prefer https:// for an operator mirror (a presigned URL would leak on-path)." ;;
  esac
  acquire_bootstrap_verifier || return 1
  # Cleanup the throwaway verifier download when this function returns (any path).
  trap cleanup_bootstrap_verifier RETURN
  local decision image_ref errf rc
  decision="$INSTALL_DIR/.catalog-bootstrap.json"
  info "Resolving the install image from the signed release catalog (channel=$INSTALL_CHANNEL) ..."
  # bootstrap-resolve performs the FULL verified resolution (signature + freshness,
  # plus best-effort anti-rollback/replay) against the baked trust roots and prints
  # ONLY the repo@sha256 image_ref; --out records the decision so the appliance can
  # prove which catalog decision bootstrapped it. No crypto/JSON parsing in shell.
  # The catalog origin is passed via the ENVIRONMENT (owner-readable /proc/pid/environ),
  # never argv (world-readable /proc/pid/cmdline), since a mirror URL may be presigned.
  local -a cmd=("$BOOTSTRAP_VERIFIER_BIN" bootstrap-resolve --channel "$INSTALL_CHANNEL" \
    --proxy-repo "$PROXY_REPO" --print image_ref --out "$decision")
  # Enforce a surviving rollback floor on a reinstall (no-op on a fresh host). The
  # verifier reads <data-dir>/release_catalog_state.json and refuses a catalog below
  # the version this host last accepted — closing the mirror-replay downgrade for the
  # volume-kept reinstall case.
  local floordir
  if floordir="$(stage_rollback_floor)"; then
    info "Enforcing the anti-rollback floor from the surviving proxy-data volume."
    cmd+=(--data-dir "$floordir")
  fi
  # timeout is a second backstop against a hung/old binary (the capability probe is
  # the primary guard); tolerate hosts without coreutils `timeout`. Fold everything
  # into one non-empty array so "${cmd[@]}" is set-u-safe on bash 4.2 (Amazon Linux 2).
  command -v timeout >/dev/null 2>&1 && cmd=(timeout 120 "${cmd[@]}")
  errf="$(mktemp)" || return 1
  rc=0
  image_ref="$(CULVERT_RELEASE_CATALOG_URL="$CATALOG_URL" "${cmd[@]}" 2>"$errf")" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    warn "Signed-catalog resolution failed (fail-closed; NOT falling back to tag discovery):"
    # Read line-by-line, but also emit a final line that lacks a trailing newline
    # (a bare exec error like "…/culvert: Permission denied" may not end in \n).
    while IFS= read -r line || [[ -n "$line" ]]; do warn "  $line"; done <"$errf"
    [[ "$rc" -eq 124 ]] && warn "  (verifier timed out — the release may predate 'bootstrap-resolve'; pin CULVERT_BOOTSTRAP_VERIFIER_VERSION)"
    # 126 = the downloaded verifier could not be executed; the usual cause is a
    # noexec staging filesystem. We stage under $INSTALL_DIR to avoid /tmp noexec,
    # but surface the actionable hint if it still bites.
    [[ "$rc" -eq 126 ]] && warn "  (verifier not executable — the staging filesystem may be mounted noexec; set TMPDIR to an exec-capable dir, or use CULVERT_PROXY_SEED_REF)"
    rm -f "$errf"
    return 1
  fi
  rm -f "$errf"
  image_ref="$(printf '%s' "$image_ref" | tr -d '[:space:]')"
  # Strict shape gate: repo@sha256:<64 lowercase hex>. Tighter than a glob so a
  # compromised verifier's stdout cannot smuggle metacharacters past this point
  # (docker's quoted argv already neutralizes them; this is defense-in-depth).
  if [[ ! "$image_ref" =~ ^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$ ]]; then
    warn "catalog resolver returned an unexpected image ref; refusing to seed."
    return 1
  fi
  info "Catalog authorized $image_ref — pulling the exact immutable digest ..."
  if sudo docker pull "$image_ref" && sudo docker tag "$image_ref" "$PINNED_TAG"; then
    info "Seeded $PINNED_TAG from the signed catalog ($image_ref)"
    return 0
  fi
  # Resolution succeeded but the pull/tag failed: drop the decision record so a later
  # break-glass reseed cannot publish a catalog digest that was never deployed. (The
  # persist step also digest-matches against the running image as a second guard.)
  rm -f "$decision"
  warn "Could not pull the catalog-authorized digest $image_ref"
  return 1
}

seed_pinned_tag() {
  local had_stale=0
  if sudo docker image inspect "$PINNED_TAG" >/dev/null 2>&1; then
    # Keep the existing tag when it tracks a LIVE/current deployment: a proxy
    # container (culvert, or culvert-dp on an HA data-plane node — running OR
    # stopped, the P1.4 §8.2 stability rule that the pinned tag matches the live
    # daemon), or a populated stack dir at $INSTALL_DIR (a source checkout with a
    # locally-built tag, or an existing install). When NONE is present the tag is
    # a stale leftover from a previously-removed install (dir + volumes gone,
    # image kept); reusing it would silently deploy a year-old image + compose +
    # agent (#7). Fall through to refresh it.
    #
    # KNOWN NARROWING: `docker compose down -v` that leaves the dir on disk still
    # keeps the tag (compose file present) even though the data volume is gone —
    # closing that fully would refresh a dev's locally-built pinned tag on a
    # never-deployed checkout, so the tradeoff favours the checkout case. The
    # operator escape hatch (CULVERT_PROXY_SEED_REF, named in the warning below)
    # covers the rare stale-after-down-v reinstall.
    if sudo docker inspect culvert >/dev/null 2>&1 \
       || sudo docker inspect culvert-dp >/dev/null 2>&1 \
       || [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
      info "$PINNED_TAG already present; not reseeding (tracking the current deployment)"
      return 0
    fi
    warn "$PINNED_TAG is present but no running or existing deployment was found — treating it"
    warn "as a stale leftover and refreshing it (a removed-then-reinstalled host must not deploy"
    warn "an old image). The registry-down path below keeps the leftover rather than failing."
    had_stale=1
  fi

  # Seed source precedence:
  #   1. CULVERT_PROXY_SEED_REF — operator-supplied, explicit break-glass (offline
  #      / migration: the currently-running repo@sha256 digest). Loud + recorded.
  #   2. The image of an already-running `culvert` container (auto-captured,
  #      keeps the pinned tag identical to the live daemon — §8.2; a healthy
  #      existing deployment is NOT replaced merely because the installer re-ran).
  #   3. The SIGNED RELEASE CATALOG (seed_from_catalog) — the TRUSTED default. The
  #      catalog is the release authority for both fresh install and day-2 updates;
  #      it resolves the channel to an immutable repo@sha256 digest, verified.
  #   4. (NO tag enumeration, NO :latest, NO local build in the trusted path.)
  #      Legacy GHCR tag discovery survives ONLY as a consciously-named break-glass
  #      (CULVERT_INSTALL_ALLOW_TAG_DISCOVERY=1), disabled by default and never
  #      represented as a trusted catalog selection.
  if [[ -n "${CULVERT_PROXY_SEED_REF:-}" ]]; then
    info "Seeding $PINNED_TAG from CULVERT_PROXY_SEED_REF=$CULVERT_PROXY_SEED_REF ..."
    # Prefer an image ALREADY PRESENT locally (a `docker load`-ed tarball on an
    # air-gapped host, or an out-of-band mirror pull) so the documented offline
    # path never touches the registry — the local-build/clone fallback is gone, so
    # a pull-only seed would strand an air-gapped host with a loaded image. Only
    # reach for a registry pull when the ref is not already on this host.
    if sudo docker image inspect "$CULVERT_PROXY_SEED_REF" >/dev/null 2>&1; then
      if sudo docker tag "$CULVERT_PROXY_SEED_REF" "$PINNED_TAG"; then
        info "Seeded $PINNED_TAG from the locally present image (no pull)"
        return 0
      fi
    elif sudo docker pull "$CULVERT_PROXY_SEED_REF" && sudo docker tag "$CULVERT_PROXY_SEED_REF" "$PINNED_TAG"; then
      info "Seeded $PINNED_TAG"
      return 0
    fi
    warn "Could not seed from CULVERT_PROXY_SEED_REF — trying the next source..."
  fi

  local running_image
  running_image=$(sudo docker inspect culvert --format '{{.Image}}' 2>/dev/null || true)
  if [[ -n "$running_image" ]]; then
    info "Seeding $PINNED_TAG from the running culvert container ($running_image)..."
    if sudo docker tag "$running_image" "$PINNED_TAG"; then
      return 0
    fi
    warn "Could not tag the running container's image — trying the next source..."
  fi

  # The TRUSTED default: resolve the image from the SIGNED CATALOG and seed the
  # pinned tag from that exact immutable digest. The catalog — not a mutable tag —
  # is the release authority, identically to day-2 updates.
  if seed_from_catalog; then
    return 0
  fi

  # BREAK-GLASS ONLY: legacy GHCR tag discovery. Disabled by default; it is NOT a
  # trusted catalog selection (it picks a mutable tag by naive version sort — the
  # exact mechanism that installed the stale pre-/app/deploy image 0.0.238). It
  # runs solely when an operator consciously opts in, and says so loudly.
  if [[ "${CULVERT_INSTALL_ALLOW_TAG_DISCOVERY:-}" == "1" ]]; then
    warn "CULVERT_INSTALL_ALLOW_TAG_DISCOVERY=1 — BREAK-GLASS: selecting the image by GHCR tag"
    warn "discovery instead of the signed catalog. This is NOT a trusted catalog decision and"
    warn "may pick a stale tag; prefer fixing catalog reachability or an explicit CULVERT_PROXY_SEED_REF."
    local signed_ref
    signed_ref="$(resolve_latest_signed_release_ref)"
    if [[ -n "$signed_ref" ]]; then
      info "Seeding $PINNED_TAG from tag discovery $signed_ref (break-glass) ..."
      if sudo docker pull "$signed_ref" && sudo docker tag "$signed_ref" "$PINNED_TAG"; then
        info "Seeded $PINNED_TAG from $signed_ref (break-glass tag discovery)"
        return 0
      fi
      warn "Could not seed from $signed_ref — trying :latest (break-glass) ..."
    fi
    info "Seeding $PINNED_TAG from $PROXY_REPO:latest (break-glass, unsigned main build) ..."
    if sudo docker pull "$PROXY_REPO:latest" && sudo docker tag "$PROXY_REPO:latest" "$PINNED_TAG"; then
      info "Seeded $PINNED_TAG (break-glass :latest)"
      return 0
    fi
  fi

  # NO local build. Culvert is a signed-release product: the deployed binary and
  # the docker-compose.yml it is launched with MUST come from the SAME published
  # image, or the compose can pass a CLI flag the binary does not define and the
  # proxy crash-loops on "flag provided but not defined". A local `docker build`
  # from an arbitrary checkout (whose source may be a release ahead of the pulled
  # image) is exactly how that skew was introduced, so it is deliberately NOT a
  # seed source. A registry-unreachable host must preload an image and point the
  # installer at it via CULVERT_PROXY_SEED_REF (see the caller's error message).
  warn "Registry pull failed and no seedable image is available (local build is disabled)."

  # Every refresh source failed. If we were only trying to REFRESH a stale
  # leftover (the tag still exists), keep it rather than failing — a possibly-old
  # image is better than no install when the registry is unreachable. A genuine
  # fresh seed with no leftover still returns 1 so the caller fails closed with the
  # preload-an-image guidance (there is no build/clone fallback). The §6c preflight
  # still runs on the kept leftover and re-aligns the compose to it if they differ.
  if [[ "$had_stale" -eq 1 ]] && sudo docker image inspect "$PINNED_TAG" >/dev/null 2>&1; then
    warn "Could not refresh $PINNED_TAG — keeping the existing (possibly STALE) leftover image."
    warn "If this host previously ran a different Culvert version, seed a current image explicitly:"
    warn "  CULVERT_PROXY_SEED_REF=$PROXY_REPO:<X.Y.Z> sudo bash scripts/install.sh"
    return 0
  fi

  return 1
}

if ! seed_pinned_tag; then
  # NO local build, NO source clone. Culvert deploys a SIGNED PUBLISHED image and
  # takes its docker-compose.yml from that same image's /app/deploy bundle, so the
  # binary and the compose command it is launched with are always the same release.
  # Building from an arbitrary checkout (or a HEAD clone) is what let the compose
  # drift a release ahead of the binary and crash-loop the proxy; that path is gone.
  # A registry-unreachable / air-gapped host must preload the image and point the
  # installer at it — the ONLY supported offline path.
  error "Could not obtain $PINNED_TAG from the signed release catalog, and no explicit
  image seed was provided. The installer never enumerates GHCR tags and never builds
  from source — the signed catalog is the release authority.

  Fix one of the following, then re-run:

  1) Catalog reachable? The default origin is the canonical Culvert catalog. If this
     host uses a mirror/staging origin, set it (trust is unchanged by the origin):
       CULVERT_RELEASE_CATALOG_URL=https://mirror.example/release-catalog sudo bash scripts/install.sh

  2) Offline / air-gapped, or catalog fetch disabled? Preload a signed image and seed it
     explicitly (this is the supported break-glass; it is loud and recorded):
       # on a connected host:  docker pull $PROXY_REPO:<X.Y.Z> && docker save $PROXY_REPO:<X.Y.Z> -o culvert.tar
       # copy culvert.tar over, then on THIS host:
       docker load -i culvert.tar
       CULVERT_PROXY_SEED_REF=$PROXY_REPO:<X.Y.Z> sudo bash scripts/install.sh
     (CULVERT_PROXY_SEED_REF may name any image tag/digest already present on this host
     or in a private/mirror registry it can reach.)"
fi

###############################################################################
# 6b. Deployment files — extracted from the image (no git clone)
###############################################################################

# copy_bundle_file SRC DST MODE — install one extracted (root-owned, from
# `sudo docker cp`) bundle file into the stack dir, owned by the invoking user.
copy_bundle_file() {
  sudo install -m "$3" -o "$(id -un)" "$1" "$2"
}

# extract_deploy_bundle — pull the deployment files out of the pinned proxy
# image's /app/deploy bundle into $INSTALL_DIR: the compose files and the
# maintenance-agent packaging/ tree (installer, config example, systemd unit,
# sudoers template). The agent BINARY in the bundle is deliberately NOT left
# in the stack dir — install_maint_agent extracts it into a throwaway temp dir
# when it needs it (extract_bundled_maint_bin). Fails cleanly (nothing written)
# when the image predates the bundle, so the caller can fall back to git.
extract_deploy_bundle() {
  local tmp cid
  tmp="$(mktemp -d)" || return 1
  cid="$(sudo docker create "$PINNED_TAG" 2>/dev/null)" || { rm -rf "$tmp"; return 1; }
  if ! sudo docker cp "$cid:/app/deploy/." "$tmp/" >/dev/null 2>&1; then
    sudo docker rm -f "$cid" >/dev/null 2>&1 || true
    sudo rm -rf "$tmp"
    return 1
  fi
  sudo docker rm -f "$cid" >/dev/null 2>&1 || true
  if [[ ! -f "$tmp/docker-compose.yml" || ! -f "$tmp/docker-compose.maint-agent.yml" \
     || ! -f "$tmp/packaging/culvert-maint/install.sh" ]]; then
    sudo rm -rf "$tmp"
    return 1
  fi
  # Install order matters for crash-safety: the packaging/ tree and the override
  # compose file go in FIRST, and docker-compose.yml — the re-extraction sentinel
  # that §6b and §5's reuse check key on — goes in LAST. So a copy that fails
  # partway leaves NO sentinel (or we remove it below), and the next run
  # re-extracts instead of treating an incomplete tree as a finished deployment.
  # Every copy is checked; the previous version ignored the loop's failures and
  # unconditionally returned 0, which permanently stranded a partial extract.
  local ok=1 f rel
  while IFS= read -r -d '' f; do
    rel="${f#"$tmp"/}"
    sudo mkdir -p "$INSTALL_DIR/$(dirname "$rel")" || { ok=0; break; }
    case "$rel" in
      */install.sh) copy_bundle_file "$f" "$INSTALL_DIR/$rel" 0755 || { ok=0; break; } ;;
      *)            copy_bundle_file "$f" "$INSTALL_DIR/$rel" 0644 || { ok=0; break; } ;;
    esac
  done < <(sudo find "$tmp/packaging" -type f -print0)
  if [[ "$ok" -eq 1 ]]; then
    copy_bundle_file "$tmp/docker-compose.maint-agent.yml" \
      "$INSTALL_DIR/docker-compose.maint-agent.yml" 0644 || ok=0
  fi
  if [[ "$ok" -eq 1 ]]; then
    # LAST — the sentinel. Only now is the deployment considered complete.
    copy_bundle_file "$tmp/docker-compose.yml" "$INSTALL_DIR/docker-compose.yml" 0644 || ok=0
  fi
  sudo rm -rf "$tmp"
  if [[ "$ok" -ne 1 ]]; then
    # Remove the sentinel so a partial extract can't be mistaken for a complete
    # one on the next run (it may not have been written, but be certain).
    sudo rm -f "$INSTALL_DIR/docker-compose.yml" 2>/dev/null || true
    # Return 2 = the bundle WAS present but writing it into $INSTALL_DIR failed
    # (disk full / permissions), distinct from return 1 = no bundle in the image
    # (older release). The caller errors directly on 2 instead of attempting a
    # git clone that would fail the same way.
    return 2
  fi
  return 0
}

# extract_bundled_maint_bin DEST — copy the agent binary shipped in the pinned
# proxy image (/app/deploy/bin/culvert-maint) to DEST. The TLS image pull from
# the pinned repo is the trust channel — the same channel that delivers the
# proxy binary that handles all the traffic — so this grants nothing the stack
# does not already trust. Primary agent source: unlike the GitHub release
# assets and the source repo, the image stays publicly pullable.
extract_bundled_maint_bin() {
  local dest="$1" cid
  cid="$(sudo docker create "$PINNED_TAG" 2>/dev/null)" || return 1
  if ! sudo docker cp "$cid:/app/deploy/bin/culvert-maint" "$dest" >/dev/null 2>&1; then
    sudo docker rm -f "$cid" >/dev/null 2>&1 || true
    return 1
  fi
  sudo docker rm -f "$cid" >/dev/null 2>&1 || true
  sudo chmod 0755 "$dest" 2>/dev/null || true
  [[ -x "$dest" ]]
}

# Re-extract when the deployment is missing OR incomplete. Keying on
# docker-compose.yml alone would treat a partial extract (compose present, the
# maint-agent installer missing) as finished and never self-heal; also require
# the packaging installer that install_maint_agent depends on. A complete source
# checkout / clone has both, so this never spuriously re-extracts over one.
if [[ ! -f "$INSTALL_DIR/docker-compose.yml" \
   || ! -f "$INSTALL_DIR/packaging/culvert-maint/install.sh" ]]; then
  step "Extracting deployment files"
  info "Extracting compose files + agent packaging from $PINNED_TAG (/app/deploy)..."
  if extract_deploy_bundle; then
    info "Deployment files installed to $INSTALL_DIR (no source checkout needed)."
  else
    extract_rc=$?
    if [[ "$extract_rc" -eq 2 ]]; then
      # The bundle was present but writing it failed (disk full / permissions).
      # A git clone would fail the same way — error directly with the real cause.
      error "Failed to write the deployment files to $INSTALL_DIR — likely out of disk space
  or a permissions problem (not a missing image bundle). Free space / fix permissions and
  re-run; the installer re-extracts automatically."
    fi
    # The pinned image predates the /app/deploy bundle (a very old release). We no
    # longer fall back to a git clone: a bundle-less image cannot supply a compose
    # file guaranteed to match its binary, which is the whole failure mode we are
    # closing. Fail closed and tell the operator to seed a current release.
    error "The pulled image ($PINNED_TAG) has no /app/deploy bundle — it is older than the
  source-free deployment format and cannot supply a matching docker-compose.yml. Seed a
  current signed release instead and re-run:
    CULVERT_PROXY_SEED_REF=$PROXY_REPO:<X.Y.Z> sudo bash scripts/install.sh"
  fi
fi

###############################################################################
# 6c. Compose ↔ image compatibility preflight
###############################################################################
# The proxy is launched with the flags in docker-compose.yml's `command:`. If the
# seeded image's binary does not DEFINE one of those flags, Go's flag parser exits
# non-zero on startup ("flag provided but not defined: -X") and the container
# crash-loops. This happens when the on-disk compose is NEWER than the image — e.g.
# the installer ran inside a source checkout (§5 keeps that dir's HEAD compose) or
# an operator left a hand-edited/previously-extracted compose in place while the
# pulled image is an older release. §6b only extracts when compose is ABSENT, so it
# does not catch this. Detect the mismatch and heal by re-extracting the compose
# from THIS image's own /app/deploy bundle — the copy that matches the binary by
# construction. (Fresh source-free installs are already safe: their compose came
# from the bundle in §6b; this is the belt-and-suspenders guard for every other
# path, and the direct fix for the -idp-profiles-file crash loop.)

# compose_command_flags — culvert flags from the proxy service's `command:` array.
# Scoped to the `proxy:` service block (top-level 2-space-indented key) so a
# flow-style "command: [ ... ]" array on any OTHER service (e.g. `cli`, whose
# flags are normally passed at `docker compose run --rm cli <flags>` time but
# which the compose file's own comments show operators DO hand-edit) is never
# misread as a culvert proxy flag — that previously made
# preflight_compose_image_compat() falsely conclude the compose/image were
# incompatible and silently overwrite an operator's hand-edited
# docker-compose.yml. Healthcheck test tokens (wget -qO-, clamav --ping) are
# also excluded, being outside the proxy service's command array. Comment
# lines are dropped so a commented-out "-flag" example never counts.
compose_command_flags() {
  # `|| true`: grep -o exits 1 on a (hypothetical) flagless command block; under
  # `set -o pipefail` that would surface as a function failure — degrade to empty.
  # Single-line awk program (no embedded "}"-only lines) so a simple
  # line-based function extractor (used by this repo's install_script_*_test.go
  # suite) can still find this function's own closing brace unambiguously.
  # Entering/exiting the proxy block: `/^  proxy:/` matches the header
  # regardless of what follows the colon (a bare mapping, a YAML anchor like
  # "proxy: &proxy", or a trailing comment) so an anchored service header
  # doesn't fall out of scope; a DIFFERENT top-level 2-space-indented key
  # (matched only on lines that are not the proxy header itself) closes it.
  { awk '/^  proxy:/{inproxy=1} !/^  proxy:/ && /^  [a-zA-Z0-9_-]+:/{inproxy=0} inproxy && /command:[ \t]*\[/{inblk=1} inproxy && inblk{print} inproxy && inblk && /\]/{inblk=0}' \
      "$INSTALL_DIR/docker-compose.yml" 2>/dev/null \
    | grep -vE '^[[:space:]]*#' \
    | grep -oE '"-[a-zA-Z0-9-]+"' | tr -d '"' | sort -u; } || true
}

# image_supported_flags — flag names the seeded binary DEFINES, scraped from its
# -help usage. `culvert -help` prints the usage block and exits 2; we only need the
# flag list, so the non-zero exit is ignored. Args are appended to the image's
# `./culvert` entrypoint, matching how compose launches it. Leading whitespace is
# stripped PER LINE (sed, not `tr -d [:space:]`) so each flag stays on its own line.
image_supported_flags() {
  # `culvert -help` exits 2 (and grep exits 1 if it somehow prints no flags); under
  # `set -euo pipefail` an unguarded pipeline failure here would abort the whole
  # install at the `supported="$(image_supported_flags)"` assignment. `|| true`
  # degrades any failure to empty output, which the caller treats as "skip".
  { sudo docker run --rm "$PINNED_TAG" -help 2>&1 \
    | grep -oE '^[[:space:]]+-[a-zA-Z0-9-]+' | sed -E 's/^[[:space:]]+//' | sort -u; } || true
}

# missing_compose_flags SUPPORTED — echo the compose flags absent from SUPPORTED.
# `grep -- "$f"` terminates option parsing so a leading-dash flag ("-audit-log")
# is treated as a pattern, not a grep option.
missing_compose_flags() {
  local supported="$1" f missing=""
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    grep -qxF -- "$f" <<<"$supported" || missing+="$f "
  done < <(compose_command_flags)
  printf '%s' "$missing"
}

preflight_compose_image_compat() {
  local supported missing
  supported="$(image_supported_flags)"
  # If the flag list could not be read, do NOT guess — skip rather than block a
  # healthy install on a transient scrape failure.
  if [[ -z "$supported" ]]; then
    info "Skipping compose/image flag preflight (could not enumerate image flags)."
    return 0
  fi
  missing="$(missing_compose_flags "$supported")"
  [[ -z "$missing" ]] && return 0

  warn "docker-compose.yml passes flags the seeded image does not define: $missing"
  warn "As-is this crash-loops the proxy (\"flag provided but not defined\"). Re-extracting"
  warn "the compose file from the image's own /app/deploy bundle so it matches the binary."
  sudo cp -a "$INSTALL_DIR/docker-compose.yml" "$INSTALL_DIR/docker-compose.yml.bak" 2>/dev/null || true
  sudo rm -f "$INSTALL_DIR/docker-compose.yml"
  local ex_rc=0
  extract_deploy_bundle || ex_rc=$?  # capture the REAL rc (1=no bundle, 2=write failed)
  if [[ "$ex_rc" -ne 0 ]]; then
    # Restore the backup so `up` at least attempts the (still-broken) stack and the
    # diagnostics surface the real cause, rather than leaving no compose at all.
    [[ -f "$INSTALL_DIR/docker-compose.yml.bak" ]] \
      && sudo cp -a "$INSTALL_DIR/docker-compose.yml.bak" "$INSTALL_DIR/docker-compose.yml"
    if [[ "$ex_rc" -eq 2 ]]; then
      error "Could not re-extract the compose file from $PINNED_TAG — writing to $INSTALL_DIR
  failed (likely out of disk space or a permissions problem). Free space / fix permissions
  and re-run."
    fi
    error "The seeded image ($PINNED_TAG) has no /app/deploy bundle to re-extract a matching
  compose from — it is older than the source-free deployment format. Seed a current signed
  release and re-run:
    CULVERT_PROXY_SEED_REF=$PROXY_REPO:<X.Y.Z> sudo bash scripts/install.sh"
  fi

  # Confirm the refreshed compose is actually compatible now; fail loudly rather
  # than deploy a still-broken stack (the bundle should match, but never assume).
  missing="$(missing_compose_flags "$supported")"
  if [[ -n "$missing" ]]; then
    error "Compose still references flags the image does not define after refreshing from the
  bundle: $missing. This indicates a compose/binary mismatch inside the image itself — seed a
  different signed release: CULVERT_PROXY_SEED_REF=$PROXY_REPO:<X.Y.Z> sudo bash scripts/install.sh"
  fi
  info "Compose file refreshed from $PINNED_TAG (previous saved as docker-compose.yml.bak)."
}
preflight_compose_image_compat

###############################################################################
# 7. Pull and start
###############################################################################
step "Starting Culvert"

# dump_compose_diagnostics — print container state and recent logs on failure.
dump_compose_diagnostics() {
  echo "" >&2
  warn "── docker compose ps -a ──"
  sudo docker compose ps -a 2>&1 | sed 's/^/    /' >&2 || true
  echo "" >&2
  warn "── docker compose logs (last 100 lines per service) ──"
  sudo docker compose logs --tail=100 --no-color 2>&1 | sed 's/^/    /' >&2 || true
  echo "" >&2
}

###############################################################################
# Encryption-at-rest passphrase
###############################################################################
# is_fresh_deployment — true when this looks like a first-time install: THIS
# install directory's own proxy-data Docker volume does not exist yet (Docker
# creates it on the first `docker compose up`). Resolves the REAL volume name
# via `docker compose config` (run from $INSTALL_DIR, our cwd since the `cd`
# above) instead of guessing it — Compose only labels volumes it creates with
# com.docker.compose.project/.volume (NOT a working-directory label), so
# matching by label alone can't distinguish this project from another compose
# project on the same host that also declares a "proxy-data" volume. Asking
# Compose for the resolved name applies whatever project-naming it would
# actually use (directory basename, COMPOSE_PROJECT_NAME, or an explicit
# `name:`) and lets us check that exact volume for existence. Any docker/
# compose error => treat as NOT fresh (conservative).
is_fresh_deployment() {
  local resolved_name
  resolved_name="$(sudo docker compose config 2>/dev/null | awk '
    /^volumes:/ { invol=1; next }
    invol && /^  proxy-data:/ { inpd=1; next }
    inpd && /^    name:/ { print $2; exit }
  ')"
  [[ -n "$resolved_name" ]] || return 1
  ! sudo docker volume inspect "$resolved_name" >/dev/null 2>&1
}

# secret_already_set VAR — true if VAR is non-empty in the host env or in .env.
secret_already_set() {
  local var="$1" envfile="$2"
  [[ -n "${!var:-}" ]] && return 0
  [[ -f "$envfile" ]] && grep -Eq "^${var}=.+" "$envfile" 2>/dev/null
}

# env_put VAR VALUE FILE — set/replace VAR=VALUE in FILE (mode 600).
env_put() {
  local var="$1" val="$2" file="$3"
  # The shared /srv/culvert .env can be owned by a different user across runs
  # (a prior `sudo` install → root-owned 0600, then an unprivileged re-run, or
  # vice versa). Without this, the `touch`/writes below hit EACCES and abort the
  # whole install under `set -euo pipefail`. Take ownership via sudo when we
  # can't write it (no-op — and no sudo call — when we already can, so the
  # extracted-function tests on a user-owned temp file are unaffected).
  if [[ -e "$file" && ! -w "$file" ]]; then
    sudo chown "$(id -un)" "$file" 2>/dev/null || true
  elif [[ ! -e "$file" && ! -w "$(dirname "$file")" ]]; then
    sudo touch "$file" 2>/dev/null && sudo chown "$(id -un)" "$file" 2>/dev/null || true
  fi
  # If ownership still can't be taken (sudo genuinely denied), DEGRADE — warn
  # and skip rather than let the unguarded touch/append below abort the whole
  # install under `set -euo pipefail`. The normal path (writable, or sudo chown
  # succeeded) falls straight through with no behavior change.
  if [[ -e "$file" && ! -w "$file" ]]; then
    warn "Cannot write $file (owned by another user and sudo could not take it) — leaving it unchanged."
    warn "Set $var manually in $file if you need it, then restart the stack."
    return 0
  fi
  # The full read (grep) / write (mv|rm) / append sequence below must run as
  # ONE atomic transaction — install.sh is designed to be safely re-run
  # against an existing deployment (e.g. an automation retry racing a
  # still-running instance, or two admins running it at once), and two
  # concurrent env_put calls both reading "$file" before either has written
  # it back can otherwise interleave: whichever "mv" runs LAST wins
  # unconditionally, silently discarding the other invocation's already-
  # applied update (a lost-update race — unique-per-invocation staging files
  # alone stop the two calls' writes from colliding, but not their reads
  # and writes from interleaving with each other). A dedicated lock file
  # (not $file itself, which gets replaced out from under an flock held on
  # its old inode by the very "mv" below) held for the whole transaction
  # serializes concurrent env_put calls against the same $file into a strict
  # queue, so this reasons about $file exactly as a sequential caller would.
  (
    flock -x 9
    touch "$file"; chmod 600 "$file"
    sed -i 's/\r$//' "$file" 2>/dev/null || true # normalize to LF so compose parses cleanly
    # grep -v exits 1 (not just erroring) whenever EVERY line matched the
    # pattern being dropped — including the common case where $file contains
    # only this one VAR=... line. Treat ONLY that "no lines survived" case (1)
    # as benign and promote the filtered file; a real error (e.g. ENOSPC
    # while writing $tmp) gets a higher exit code and must NOT clobber the
    # existing $file with a truncated/empty temp file.
    tmp="$(mktemp "${file}.XXXXXX" 2>/dev/null)" || tmp="${file}.tmp.$$"
    rc=0
    grep -vE "^${var}=" "$file" > "$tmp" 2>/dev/null && rc=0 || rc=$?
    if [[ $rc -eq 0 || $rc -eq 1 ]]; then
      mv "$tmp" "$file"
    else
      rm -f "$tmp"
    fi
    printf '%s=%s\n' "$var" "$val" >> "$file"
    chmod 600 "$file"
  ) 9>"$file.lock"
}

gen_passphrase() {
  local p
  p="$(openssl rand -base64 48 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 40 || true)"
  [[ -n "$p" ]] || p="$(head -c 48 /dev/urandom 2>/dev/null | base64 | tr -dc 'A-Za-z0-9' | head -c 40 || true)"
  [[ -n "$p" ]] || error "Could not generate a passphrase (openssl and /dev/urandom both unavailable)."
  printf '%s' "$p"
}

# validate_passphrase_for_env_file LABEL PASS — enforces the same length +
# character-safety contract on a passphrase regardless of where it came from
# (operator-typed or host-env-supplied) before it is ever written to .env.
# Exits via error() on failure; returns silently on success.
validate_passphrase_for_env_file() {
  local label="$1" pass="$2"
  # This passphrase is PBKDF2-SHA256'd (600k iterations, internal/ca/ca.go)
  # straight into the AES-256-GCM key that protects the SSL-inspection Root
  # CA private key and saved request logs — a short passphrase is brute-
  # forceable regardless of the iteration count. gen_passphrase's
  # auto-generated default is 40 characters; require anything else supplied
  # to be long enough to meaningfully resist an offline attack.
  if [[ "${#pass}" -lt 12 ]]; then
    error "$label too short (${#pass} characters) — must be at least 12. This encrypts the SSL-inspection CA key and saved logs at rest, so it must resist offline brute-force."
  fi
  # The passphrase is stored in .env, which docker compose interpolates
  # ($VAR), treats # as a comment, etc. Restrict to characters that survive
  # that round-trip intact so the value reaching the container is exact — a
  # raw "$" is the sharpest edge here: Compose treats "$Foo" in a .env value
  # as ITS OWN variable reference and can resolve it to something else
  # entirely (often empty, under the very same sudo-reset environment this
  # whole function works around), silently storing a different passphrase
  # than the one supplied.
  # -z/--null-data makes grep match the WHOLE value as one record: without it
  # a value with an embedded newline whose individual lines are each charset-
  # clean would pass, and env_put would then append it as a second, malformed
  # .env line, silently corrupting the persisted passphrase (Codex, PR #1156).
  if printf '%s' "$pass" | LC_ALL=C grep -qz '[^A-Za-z0-9._@%^!*()+=:,-]'; then
    error "$label has characters unsafe for the .env file. Use letters, digits, and simple punctuation (no \$, quotes, backslash, #, /, newlines, or spaces)."
  fi
}

# persist_host_env_session_secret — docs/OPERATIONS.md §3 tells an operator
# setting up a multi-node deployment to "set CULVERT_SESSION_SECRET ... on
# every node" before bringing the stack up, and exporting it as a host
# environment variable is the natural way to do that non-interactively. That
# hits the exact same failure shape setup_at_rest_encryption() below already
# guards against for CULVERT_LOG_PASSPHRASE/CULVERT_CA_PASSPHRASE: §7 starts
# the stack with plain `sudo docker compose up` (no `-E`), which does NOT
# forward this shell's environment to the child process, and
# docker-compose.yml resolves CULVERT_SESSION_SECRET only via compose's own
# process env or $INSTALL_DIR/.env. A host-env-only value therefore never
# reaches the container: every node falls back to its own random per-process
# signing key (session.InitRandomKey, session.go) instead of the shared
# cluster key the operator asked for, and admin sessions silently stop being
# valid across nodes — no error, no log line, just cluster-wide logouts.
# Never overwrite an existing .env value (same "never overwrite" contract as
# env_put/setup_at_rest_encryption), and validate before persisting — the
# same 64-hex-char / >=32-byte contract session.go's initSessionSecret()
# enforces at boot (hex.DecodeString + len(key) < 32 => panic), so a bad
# value fails the install with a clear message instead of persisting a key
# that will make the container panic/crash-loop on every node.
persist_host_env_session_secret() {
  local envfile="$INSTALL_DIR/.env"
  [[ -n "${CULVERT_SESSION_SECRET:-}" ]] || return 0
  grep -Eq '^CULVERT_SESSION_SECRET=.+' "$envfile" 2>/dev/null && return 0
  local trimmed
  trimmed="$(printf '%s' "$CULVERT_SESSION_SECRET" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  if [[ ! "$trimmed" =~ ^[0-9a-fA-F]{64,}$ || $(( ${#trimmed} % 2 )) -ne 0 ]]; then
    error "CULVERT_SESSION_SECRET (host environment) must be at least 64 hex characters (32 bytes) — got ${#trimmed}. Fix it before the stack starts, or every node will fall back to its own random signing key."
  fi
  env_put CULVERT_SESSION_SECRET "$trimmed" "$envfile"
  info "Persisted CULVERT_SESSION_SECRET from the host environment into $envfile so the running container can use it."
}

# Encrypts data at rest (AES-256), value(s) stored in $INSTALL_DIR/.env which
# docker-compose.yml reads as ${CULVERT_*_PASSPHRASE:-}. We never overwrite an
# existing value. On a FRESH deployment (no data volume yet) we can safely also
# encrypt the SSL-inspection CA key, because there's no existing CA bundle to
# clash with; on an EXISTING deployment we only set the saved-log passphrase and
# leave the CA passphrase to the operator.
setup_at_rest_encryption() {
  local envfile="$INSTALL_DIR/.env"

  # A host-environment-only CULVERT_LOG_PASSPHRASE (exported by an automated,
  # non-interactive install) has the same failure shape the CA branch below
  # guards against: secret_already_set() counts it as "configured", but §7
  # starts the stack with plain `sudo docker compose up` (no `-E`), which does
  # not forward this shell's environment — so the value never reaches compose's
  # ${VAR:-} substitution and saved-log encryption silently runs with an empty
  # passphrase. Persist it into .env FIRST (env_put never overwrites an
  # existing .env value, so an on-disk operator value still wins), with the
  # same whole-value charset guard (grep -z: an embedded newline must not
  # split into per-line checks and then corrupt .env — Codex review, PR #1156).
  # Fail-closed via the shared validator — the same floor and charset contract
  # the interactive choice-2 path enforces on an operator-typed passphrase; a
  # host-env value is equally operator-supplied, and warn-and-continue here
  # would run the install with the operator's encryption intent silently
  # dropped.
  if [[ -n "${CULVERT_LOG_PASSPHRASE:-}" ]] && ! grep -Eq '^CULVERT_LOG_PASSPHRASE=.+' "$envfile" 2>/dev/null; then
    validate_passphrase_for_env_file "CULVERT_LOG_PASSPHRASE" "$CULVERT_LOG_PASSPHRASE"
    env_put CULVERT_LOG_PASSPHRASE "$CULVERT_LOG_PASSPHRASE" "$envfile"
  fi

  local log_set=0 ca_set=0
  secret_already_set CULVERT_LOG_PASSPHRASE "$envfile" && log_set=1
  secret_already_set CULVERT_CA_PASSPHRASE "$envfile" && ca_set=1

  # CA passphrase already set: nothing left for this function to do (we never
  # overwrite an existing value, and a set CA passphrase means at-rest
  # encryption was already decided one way or another).
  if [[ "$ca_set" == 1 ]]; then
    # secret_already_set() treats a host-environment-only value (e.g.
    # exported by an automated, non-interactive install before running this
    # script) as "already configured" too — but §7 below starts the stack
    # with plain `sudo docker compose up` (no `-E`), which does NOT forward
    # this shell's environment to the child process. A CULVERT_CA_PASSPHRASE
    # that lives only here and never makes it into .env is silently dropped:
    # docker compose resolves it to empty and the proxy persists its Root CA
    # private key UNENCRYPTED — the same "proxy recreates with an empty
    # passphrase" failure carry_forward_prior_secrets() above guards against
    # for a different trigger. Persist it now (same $-interpolation safety
    # guard as the reuse-for-CA branch below) so it actually survives.
    # Fail-closed via the shared validator (12-char floor + whole-value charset
    # check) — the same contract the interactive choice-2 path enforces, so an
    # operator's explicit encryption intent is never silently dropped into an
    # unencrypted-CA install (the earlier warn-and-skip posture contradicted
    # the interactive path's error on the identical input).
    if [[ -n "${CULVERT_CA_PASSPHRASE:-}" ]] && ! grep -Eq '^CULVERT_CA_PASSPHRASE=.+' "$envfile" 2>/dev/null; then
      validate_passphrase_for_env_file "CULVERT_CA_PASSPHRASE" "$CULVERT_CA_PASSPHRASE"
      env_put CULVERT_CA_PASSPHRASE "$CULVERT_CA_PASSPHRASE" "$envfile"
    fi
    info "Encryption passphrase already configured — keeping existing values."
    return
  fi

  local fresh=0; is_fresh_deployment && fresh=1

  # On an EXISTING deployment, a pre-set log passphrase is the full contract
  # (the CA passphrase is deliberately left to the operator — see above).
  if [[ "$log_set" == 1 && "$fresh" != 1 ]]; then
    info "Encryption passphrase already configured — keeping existing values."
    return
  fi

  # Fresh deployment with a log passphrase already set (e.g. exported in the
  # host env by an automated install, or left over from an interrupted prior
  # run) but no CA passphrase yet: reuse the existing log passphrase for the
  # CA key rather than silently leaving the SSL-inspection CA private key
  # unencrypted with no warning at all.
  if [[ "$log_set" == 1 && "$ca_set" != 1 ]]; then
    local existing_pass="${CULVERT_LOG_PASSPHRASE:-}"
    if [[ -z "$existing_pass" && -f "$envfile" ]]; then
      existing_pass="$(grep -E '^CULVERT_LOG_PASSPHRASE=' "$envfile" | tail -1 | cut -d= -f2-)"
    fi
    # .env values round-trip through docker compose's own interpolation (it
    # expands $-references when resolving .env, same as the interactive
    # choice=2 path guards against below) — writing a value containing those
    # characters here could silently persist a DIFFERENT string than the one
    # actually used as CULVERT_LOG_PASSPHRASE, so CA and log encryption keys
    # would diverge instead of matching as intended.
    if [[ -n "$existing_pass" ]] && ! printf '%s' "$existing_pass" | LC_ALL=C grep -q '[^A-Za-z0-9._@%^!*()+=:,-]'; then
      env_put CULVERT_CA_PASSPHRASE "$existing_pass" "$envfile"
      info "Fresh deployment — also encrypting the SSL-inspection CA key with the existing CULVERT_LOG_PASSPHRASE."
    elif [[ -n "$existing_pass" ]]; then
      warn "CULVERT_LOG_PASSPHRASE contains characters that are not safe to persist verbatim in $envfile"
      warn "(docker compose re-interpolates \$-references when reading .env) — leaving"
      warn "CULVERT_CA_PASSPHRASE unset rather than risk a silently mismatched key. Set it yourself in"
      warn "$envfile if you need the CA key encrypted."
    else
      warn "CULVERT_LOG_PASSPHRASE is configured but its value could not be read to also encrypt the"
      warn "SSL-inspection CA key — set CULVERT_CA_PASSPHRASE yourself in $envfile if you need it encrypted."
    fi
    return
  fi

  local choice="1"
  if [[ -t 0 ]]; then
    echo ""
    if [[ "$fresh" == 1 ]]; then
      echo "First-time install — encrypt data at rest? (SSL-inspection CA key + saved logs, AES-256)"
    else
      echo "Encrypt saved request logs at rest? (AES-256; applies when you enable 'Save logs to disk')"
    fi
    echo "  [1] Auto-generate a strong passphrase  (recommended)"
    echo "  [2] Enter my own passphrase"
    echo "  [3] Skip — store unencrypted"
    read -rp "Choose [1/2/3] (default 1): " choice || true
    [[ -z "$choice" ]] && choice="1"
  else
    info "Non-interactive install: auto-generating an encryption passphrase (saved to .env)."
  fi

  local pass=""
  case "$choice" in
    2)
      read -rsp "Enter passphrase: " pass; echo ""
      local pass2=""; read -rsp "Confirm passphrase: " pass2; echo ""
      [[ -n "$pass" ]] || error "Empty passphrase."
      [[ "$pass" == "$pass2" ]] || error "Passphrases did not match."
      validate_passphrase_for_env_file "Passphrase" "$pass"
      ;;
    3)
      warn "Skipping encryption at rest. Enable later by setting CULVERT_LOG_PASSPHRASE"
      warn "(and, on a clean setup, CULVERT_CA_PASSPHRASE) in $envfile, then restart."
      return
      ;;
    *)
      pass="$(gen_passphrase)"
      info "Generated a random 40-character passphrase."
      ;;
  esac

  env_put CULVERT_LOG_PASSPHRASE "$pass" "$envfile"
  if [[ "$fresh" == 1 ]]; then
    env_put CULVERT_CA_PASSPHRASE "$pass" "$envfile"
    info "Fresh deployment — also encrypting the SSL-inspection CA key with this passphrase."
  else
    info "Existing deployment — set the saved-log passphrase only (left the CA key untouched to"
    info "avoid disturbing an existing CA bundle; set CULVERT_CA_PASSPHRASE yourself if needed)."
  fi

  if [[ "$choice" == "2" ]]; then
    # The admin chose their own passphrase — don't echo it; just remind them.
    info "Keep your passphrase safe. It's required to read encrypted data and is not recoverable if lost."
  else
    # Auto-generated: the admin must save it. Show it prominently so they can
    # copy it to a password manager — but only when stdout is a real terminal,
    # so it never lands in a redirected install log / CI output.
    echo ""
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  IMPORTANT — SAVE YOUR ENCRYPTION PASSPHRASE${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    if [[ -t 1 ]]; then
      echo -e "  Passphrase: ${GREEN}${pass}${NC}"
    else
      echo    "  (passphrase hidden — output is redirected; read it from the file below)"
    fi
    echo    "  Stored in:  $envfile  (chmod 600)"
    echo    "  → Copy it into a password manager / secrets vault now."
    echo    "  → If this passphrase is lost, data encrypted with it CANNOT be recovered."
    echo -e "${YELLOW}════════════════════════════════════════════════════════════${NC}"
    echo ""
  fi
}

step "Encryption at rest"
setup_at_rest_encryption
persist_host_env_session_secret

# Persist the catalog config so the appliance's OWN runtime auto-seed (and every
# later `docker compose up`, reboot, or agent-driven recreate) uses the SAME origin
# the installer resolved from — not just this one invocation's environment. Only a
# non-default override is written; an unset URL keeps the baked canonical default.
# The origin never changes trust (baked roots + pinned identity are independent of
# where bytes are fetched), and the runtime still verifies on-disk catalogs even
# when the fetch is disabled. INSTALL_CHANNEL is recorded for the operator + the
# future verifier-acquisition stage (the runtime resolves catalog channels itself).
if [[ -n "$CATALOG_URL" ]]; then
  env_put CULVERT_RELEASE_CATALOG_URL "$CATALOG_URL" "$INSTALL_DIR/.env"
fi
env_put CULVERT_INSTALL_CHANNEL "$INSTALL_CHANNEL" "$INSTALL_DIR/.env"

info "Pulling images and starting services (first run may take a few minutes — ClamAV downloads ~250 MB of virus signatures)..."

# `docker compose up -d --wait` (Compose v2.17+) blocks until containers are
# either healthy or exited, and returns non-zero on failure. Much more
# reliable than the old "sleep + grep healthy" loop, which silently passed
# even when services crash-looped.
#
# --wait-timeout must cover clamav's healthcheck start_period (300s in
# docker-compose.yml — first boot downloads ~250 MB of virus signatures, which
# alone can take longer than that on a modest-bandwidth host). --wait blocks on
# EVERY service with a healthcheck, including clamav, even though the proxy
# only depends_on it for start order and tolerates it being unreachable at
# runtime. A shorter timeout here reports a false install failure while
# ClamAV is still downloading signatures. Keep in sync with docker-compose.yml
# (pinned by TestInstallScript_ComposeWaitTimeout_CoversClamAVStartPeriod).
COMPOSE_UP_OK=0
if sudo docker compose up -d --wait --wait-timeout 330; then
  COMPOSE_UP_OK=1
else
  # Fallback for older Compose versions that don't support --wait.
  warn "'docker compose up --wait' failed or is unsupported. Falling back to manual health check."
  if sudo docker compose up -d; then
    info "Waiting up to 90s for services to become healthy..."
    for i in $(seq 1 45); do
      # Treat any exited container as a hard failure
      if sudo docker compose ps -a --format '{{.State}}' 2>/dev/null | grep -qw exited; then
        break
      fi
      if sudo docker compose ps --format '{{.Health}}' 2>/dev/null | grep -qw healthy; then
        COMPOSE_UP_OK=1
        break
      fi
      sleep 2
    done
  fi
fi

if [[ "$COMPOSE_UP_OK" != "1" ]]; then
  warn "Culvert services did not reach a healthy state."
  dump_compose_diagnostics
  error "Culvert failed to start. See diagnostics above.

  Common causes:
    1. Port conflict — another process is using 8080 or 9090
       Check: sudo ss -tlnp | grep -E ':(8080|9090)'
    2. Image pull failed — corporate proxy or Docker Hub rate limit
    3. Insufficient memory — ClamAV needs ~600 MB on its own
    4. Build failure — check the logs above for compile errors

  Manual diagnostics:
    cd $INSTALL_DIR
    sudo docker compose ps -a
    sudo docker compose logs"
fi

# The stack is up and the proxy-data volume now exists — record the signed-catalog
# decision that provisioned this host into /data so the appliance can prove its
# provenance on /api/releases (best-effort; no-op for a non-catalog seed).
persist_bootstrap_decision

# Backstop for the silent-SSL-inspection-loss class: a CA that fails to load is
# non-fatal (the proxy serves TLS tunnel-only), so `docker compose up --wait`
# reports HEALTHY even when SSL inspection is OFF — e.g. after a stack move that
# stranded the CA passphrase. Surface it here instead of printing a clean
# success banner over a degraded security posture. Best-effort; never fatal.
SSL_INSPECTION_BROKEN=0
warn_if_ssl_inspection_broken() {
  command -v curl >/dev/null 2>&1 || return 0
  local body
  body="$(curl -fsS --max-time 5 http://localhost:8080/health 2>/dev/null || true)"
  [[ -n "$body" ]] || return 0
  # handleHealth reports "ssl_inspection":"load_failed" when a CONFIGURED CA
  # bundle could not be loaded/decrypted (distinct from "unavailable" = no CA
  # configured, which is a normal choice and NOT flagged here).
  if grep -q '"ssl_inspection":"load_failed"' <<<"$body"; then
    SSL_INSPECTION_BROKEN=1
    warn "SSL inspection is DISABLED — the Root CA could not be loaded/decrypted."
    warn "Most common cause: the CA passphrase (CULVERT_CA_PASSPHRASE) does not match the"
    warn "existing encrypted /data/ca.bundle — e.g. the stack was moved without carrying"
    warn "the original .env forward. TLS is being tunneled with NO scanning / DLP / CDR."
    warn "Fix: put the ORIGINAL CULVERT_CA_PASSPHRASE in $INSTALL_DIR/.env, then run"
    warn "     'cd $INSTALL_DIR && sudo docker compose up -d'  (or rotate the CA in the admin UI)."
  fi
}
if [[ "$COMPOSE_UP_OK" == "1" ]]; then
  warn_if_ssl_inspection_broken
fi

###############################################################################
# 8. Maintenance agent (optional, best-effort)
###############################################################################
step "Maintenance agent (optional)"

# The host-side Maintenance Agent (culvert-maint) is a systemd service that
# runs backup / restore / cleanup / Docker-image-update operations against THIS
# compose stack over a local Unix socket — the host-side half of day-2
# automation for unattended (e.g. OVA / first-boot) deployments.
#
# It is reached on the host via its UDS by a local operator or the control
# plane. The installer attempts to wire that socket into the proxy container
# automatically (wire_release_agent_for_compose) — fail-closed: any safety
# check that does not pass leaves Release Management unwired ("Agent
# unreachable" in the UI) with a warning. Mounting the AGENT's UDS (NOT
# /var/run/docker.sock) is the supported, isolation-preserving mechanism — the
# agent's SO_PEERCRED + allow_peers + sudoers allowlist remain the privilege
# boundary, so a compromised proxy still cannot exceed the agent's narrow
# allowlisted surface. See docker-compose.maint-agent.yml
# and docs/operator/release-management-agent.md.
#
# Optional + best-effort: a failure NEVER fails the Culvert install — we warn
# and move on. Opt out entirely with CULVERT_SKIP_MAINT_AGENT=1.
#
# TRUST: the agent is host-root, and its installer + templates come from the
# proxy image's /app/deploy bundle in a source-free deploy. We root-exec that
# bundle installer ONLY when the image cosign-verifies against the pinned
# release identity, or a source checkout is present, or the operator sets the
# break-glass CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1 (dev/private image, at their
# own risk). An unverified image with no source and no override skips the agent
# (the proxy is unaffected). See the trust gate in install_maint_agent.
MAINT_AGENT_INSTALLED=0
MAINT_AGENT_WIRED=0

# agent_ancestors_traversable — true when every ANCESTOR above $1 (its parent
# up to /) is world-searchable. The agent runs as the unprivileged culvert-maint
# user and the runner does chdir(compose_project_dir) BEFORE sudo, so the path
# must be reachable by that user. We grant the LEAF dir group traversal
# post-install (0750 root:culvert-maint via ensure_agent_traversal), so the leaf
# itself has no world requirement and the compose file is read by root (no
# world-read needed) — but ancestors we will not modify must already be
# searchable, or the agent could never chdir in. A system path like /srv/culvert
# passes (/, /srv are 0755); a 0700 home or /root is rejected at an ancestor.
agent_ancestors_traversable() {
  local target="$1" p mode
  # $1 (INSTALL_DIR) can be a relative CULVERT_DIR override with no leading
  # "/". dirname() on a relative, single-segment path (e.g. "culvert-stack")
  # returns ".", and dirname(".") is ALSO "." forever — the walk below would
  # never reach "/" and spin forever. Anchor to an absolute path first so the
  # loop terminates exactly like it does for an already-absolute $1.
  [[ "$target" == /* ]] || target="${PWD}/${target}"
  p="$(dirname "$target")"
  while :; do
    [[ -d "$p" ]] || return 1
    mode="$(stat -c '%a' "$p" 2>/dev/null)" || return 1
    case "${mode: -1}" in 1|3|5|7) : ;; *) return 1 ;; esac
    [[ "$p" == "/" ]] && break
    p="$(dirname "$p")"
  done
  return 0
}

# resolve_maint_version — the release tag to pin the agent to. Tracks the
# running proxy so the agent matches the stack it operates: CULVERT_MAINT_VERSION
# wins, else the proxy image's org.opencontainers.image.version label (bare
# semver from docker/metadata-action, normalized to vX.Y.Z). Empty output means
# "unknown" — the caller then falls back to the image-bundled binary's own
# version stamp, and past that installs without a version pin (bundled binary
# as-is, or a source build).
resolve_maint_version() {
  # Explicit env pin wins — but normalize + semver-gate it exactly like the
  # image-label path below. Without this, a bare `CULVERT_MAINT_VERSION=1.4.0`
  # would be compared verbatim against the ALWAYS v-prefixed bundled stamp
  # ("v1.4.0"), spuriously refusing the matching verified bundle, and the
  # downstream agent installer (which requires vX.Y.Z) would reject it too. A
  # non-semver env value is ignored (warn to STDERR so it can't pollute the
  # command-substitution capture) and resolution falls through to the label.
  if [[ -n "${CULVERT_MAINT_VERSION:-}" ]]; then
    local ev="${CULVERT_MAINT_VERSION}"
    [[ "$ev" != v* ]] && ev="v$ev"
    if [[ "$ev" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
      echo "$ev"
      return 0
    fi
    warn "CULVERT_MAINT_VERSION='${CULVERT_MAINT_VERSION}' is not a release version (vX.Y.Z) — ignoring it." >&2
  fi
  local v
  v="$(sudo docker inspect culvert --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null || true)"
  if [[ -z "$v" || "$v" == "<no value>" ]]; then
    v="$(sudo docker image inspect "$PINNED_TAG" --format '{{index .Config.Labels "org.opencontainers.image.version"}}' 2>/dev/null || true)"
  fi
  [[ "$v" == "<no value>" ]] && v=""
  # Normalize a leading v, then accept ONLY a real release semver (vX.Y.Z[-pre]).
  # main-branch / dev images carry a non-release label (e.g. "main" → "vmain")
  # for which no signed release asset exists; returning it would make the
  # installer 404 on the download and then fall back anyway. Emit empty instead
  # so the caller goes straight to the build fallback.
  [[ -n "$v" && "$v" != v* ]] && v="v$v"
  if [[ "$v" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
    echo "$v"
    return 0
  fi
  echo ""
}

# ensure_agent_traversal — grant the culvert-maint service group traversal of
# the stack dir without world bits (least-privilege 0750 root:culvert-maint),
# now that the installer has created the culvert-maint user/group. Only ADDS
# access (chgrp + g+rx); never removes any. Probes with the real identity.
ensure_agent_traversal() {
  if sudo -u culvert-maint test -x "$INSTALL_DIR" 2>/dev/null; then
    return 0
  fi
  info "Granting culvert-maint group traversal of $INSTALL_DIR (0750 root:culvert-maint)..."
  sudo chgrp culvert-maint "$INSTALL_DIR" 2>/dev/null || true
  # Group SEARCH only (chdir), not read — the agent never lists the dir; docker
  # (under sudo, as root) reads the compose file. Matches the X_OK probe intent.
  sudo chmod g+x "$INSTALL_DIR" 2>/dev/null || true
  if sudo -u culvert-maint test -x "$INSTALL_DIR" 2>/dev/null; then
    return 0
  fi
  warn "culvert-maint still cannot traverse $INSTALL_DIR — operations will fail at chdir."
  warn "An ancestor directory is likely not searchable; move the stack under a system path (e.g. /srv/culvert)."
  return 1
}

maint_toml_string() {
  local key="$1" file="${2:-/etc/culvert-maint/config.toml}"
  # Strip from the first quote onward (rather than requiring the closing
  # quote to be the last non-blank character on the line) so a normal
  # trailing inline TOML comment — e.g. `key = "value"  # comment` — doesn't
  # leak into the extracted value. Mirrors extract_toml_string() in
  # packaging/culvert-maint/install.sh.
  sudo awk -v k="$key" '
    /^[[:space:]]*#/ { next }
    $0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
      line=$0
      sub("^[[:space:]]*"k"[[:space:]]*=[[:space:]]*", "", line)
      sub(/^"/, "", line)
      sub(/".*$/, "", line)
      print line
      exit
    }
  ' "$file" 2>/dev/null
}

docker_security_options() {
  sudo docker info --format '{{range .SecurityOptions}}{{println .}}{{end}}' 2>/dev/null || true
}

proxy_mounts_docker_socket() {
  local cid="$1"
  sudo docker inspect "$cid" --format '{{range .Mounts}}{{println .Source " " .Destination}}{{end}}' 2>/dev/null |
    grep -Eq '(^|[[:space:]])(/var/run/docker\.sock|/run/docker\.sock)([[:space:]]|$)'
}

patch_allow_peers_numeric_uid() {
  local uid="$1" cfg="/etc/culvert-maint/config.toml" tmp
  case "$uid" in
    ''|*[!0-9]*|0) return 1 ;;
  esac
  tmp="$(mktemp)" || return 1
  if ! sudo awk -v uid="$uid" '
    # find_comment_start returns the index of the first "#" that lies OUTSIDE
    # a double-quoted TOML string, or 0 if none. A naive regex split at the
    # first "#" would misfire on a legitimate quoted peer value that itself
    # contains "#" (TOML allows it, and the maint-agent config loader accepts
    # any username user.Lookup resolves, e.g. allow_peers = ["svc#prod"]) —
    # that "#" is not a comment marker and must not truncate the array. Walks
    # back over any whitespace immediately preceding the "#" so that
    # whitespace is treated as part of the comment (preserved on reattach).
    # Does not handle escaped quotes inside a TOML string (\"); not a concern
    # for the usernames/UIDs this array holds.
    function find_comment_start(s,    i, n, inquote, ch) {
      n = length(s)
      inquote = 0
      for (i = 1; i <= n; i++) {
        ch = substr(s, i, 1)
        if (ch == "\"") {
          inquote = !inquote
        } else if (ch == "#" && !inquote) {
          while (i > 1 && substr(s, i - 1, 1) ~ /[[:space:]]/) i--
          return i
        }
      }
      return 0
    }
    BEGIN { patched=0 }
    /^[[:space:]]*allow_peers[[:space:]]*=/ && patched == 0 {
      line=$0
      # Split off a trailing inline TOML comment before classifying the line,
      # so an operator-added "  # ..." note on the allow_peers line (a normal
      # TOML habit) is not mistaken for the array spilling onto later lines —
      # the array-closing checks below must see the actual code, not comment
      # text. code is what gets rewritten; comment (if any) is reattached
      # unchanged on every branch that prints a modified line.
      code=line; comment=""
      cstart=find_comment_start(line)
      if (cstart > 0) {
        comment=substr(line, cstart)
        code=substr(line, 1, cstart-1)
      }
      if (code ~ /^[[:space:]]*allow_peers[[:space:]]*=[[:space:]]*\["culvert-cp"\][[:space:]]*$/) {
        print "allow_peers = [\"" uid "\"]" comment
        patched=1
        next
      }
      if (code ~ "\"" uid "\"") {
        print line
        patched=1
        next
      }
      if (code !~ /\][[:space:]]*$/) {
        print line
        patched=2
        next
      }
      if (code ~ /\[[[:space:]]*\][[:space:]]*$/) {
        # Empty array (e.g. "allow_peers = []"): the generic append below
        # always prepends a comma, which would leave a leading ", " with no
        # preceding element ("[, \"uid\"]") — invalid TOML.
        sub(/\[[[:space:]]*\][[:space:]]*$/, "[\"" uid "\"]", code)
        print code comment
        patched=1
        next
      }
      sub(/[[:space:]]*\][[:space:]]*$/, ", \"" uid "\"]", code)
      print code comment
      patched=1
      next
    }
    { print }
    END { if (patched == 0 || patched == 2) exit 42 }
  ' "$cfg" > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  sudo install -m 0640 -o root -g culvert-maint "$tmp" "$cfg"
  rm -f "$tmp"
}

verify_maint_agent_health_as_proxy_uid() {
  local uid="$1" gid="$2" sock="$3"
  command -v curl >/dev/null 2>&1 || return 1
  # Preferred: impersonate the proxy UID via sudo. But the container UID
  # usually has NO passwd entry on the host (e.g. UID 100 on Amazon Linux),
  # and sudo rejects unknown numeric run-as users unless the sudoers option
  # allow_unknown_runas_id is enabled — probe with `true` first so a sudo
  # limitation is never misread as the agent denying the UID. Fall back to
  # setpriv (util-linux), which switches to arbitrary numeric IDs without a
  # passwd entry; the agent itself only ever sees the numeric SO_PEERCRED
  # UID, exactly like the real in-container caller.
  if sudo -n -u "#$uid" -g "#$gid" true 2>/dev/null; then
    sudo -n -u "#$uid" -g "#$gid" curl -fsS --unix-socket "$sock" http://unix/v1/health >/dev/null 2>&1
    return
  fi
  if command -v setpriv >/dev/null 2>&1; then
    sudo -n setpriv --reuid "$uid" --regid "$gid" --clear-groups \
      curl -fsS --unix-socket "$sock" http://unix/v1/health >/dev/null 2>&1
    return
  fi
  warn "Cannot impersonate UID $uid for the health probe (no passwd entry for sudo, and setpriv is unavailable)."
  return 1
}

# heal_maint_proxy_repo CFG WANTED — repoint a freshly-seeded config.toml's
# proxy_repo (and its paired image_allowlist) at WANTED when both are still
# the packaging example's untouched default for ghcr.io/kidcarmi/culvert.
# CULVERT_PROXY_REPO / CULVERT_RELEASE_PROXY_REPO is the documented override
# for a custom/private registry (§6 above), but unlike compose_project_dir and
# socket_path — which DO get self-healed elsewhere in install_maint_agent —
# nothing ever propagated that override into config.toml's proxy_repo. Left
# unhealed, wire_release_agent_for_compose's cfg_repo != release_repo check
# PERMANENTLY skips Release-Management wiring on every custom-registry
# install, since nothing else ever brings the two back into agreement.
# Rewrites ONLY the byte-identical untouched default (mirrors the
# compose_project_dir self-heal's "never touch an operator edit" rule) —
# an already-customized proxy_repo OR image_allowlist is left alone, and the
# caller's existing mismatch warning still fires. The replacement
# image_allowlist keeps the same shape the packaging installer's own
# proxy_repo/image_allowlist consistency check expects (dots in the repo
# literal escaped, so they match literally rather than as a regex wildcard).
#
# Deliberately does NOT build the replacement lines with awk -v: awk's -v
# (and command-line var=value) assignments are escape-processed per POSIX,
# and an unrecognized escape like the "\." this function needs is handled
# inconsistently across awk implementations — some silently DROP the
# backslash, which would turn a literal dot back into a regex wildcard (CI
# caught exactly this: passed on a local gawk, failed on the runner's awk).
# A plain bash line-for-line comparison + printf never reinterprets the
# value, so the escaping survives on every awk/sed/shell combination.
heal_maint_proxy_repo() {
  local cfg="$1" wanted="$2"
  local default_repo="ghcr.io/kidcarmi/culvert"
  local old_proxy_line="proxy_repo = \"$default_repo\""
  local old_allow_line="image_allowlist = '^ghcr\\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})\$'"

  [[ "$wanted" != "$default_repo" ]] || return 1
  sudo grep -qxF "$old_proxy_line" "$cfg" 2>/dev/null || return 1
  sudo grep -qxF "$old_allow_line" "$cfg" 2>/dev/null || return 1

  local escaped new_proxy_line new_allow_line tmp line
  escaped="$(printf '%s' "$wanted" | sed 's/\./\\./g')"
  new_proxy_line="proxy_repo = \"$wanted\""
  new_allow_line="image_allowlist = '^${escaped}(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})\$'"

  tmp="$(mktemp)" || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "$old_proxy_line" ]]; then
      printf '%s\n' "$new_proxy_line"
    elif [[ "$line" == "$old_allow_line" ]]; then
      printf '%s\n' "$new_allow_line"
    else
      printf '%s\n' "$line"
    fi
  done < <(sudo cat "$cfg" 2>/dev/null) > "$tmp"
  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    return 1
  fi
  sudo install -m 0640 -o root -g culvert-maint "$tmp" "$cfg"
  rm -f "$tmp"
  return 0
}

wire_release_agent_for_compose() {
  local maint_installer="$1"
  local cfg="/etc/culvert-maint/config.toml"
  local sudoers="/etc/sudoers.d/culvert-maint"
  local socket_path="/run/culvert-maint/culvert-maint.sock"
  local default_repo="ghcr.io/kidcarmi/culvert"

  if [[ -n "${CULVERT_SKIP_RELEASE_AGENT_WIRING:-}" ]]; then
    info "CULVERT_SKIP_RELEASE_AGENT_WIRING set - leaving Release Management agent wiring disabled"
    return 0
  fi

  local sec_opts
  sec_opts="$(docker_security_options)"
  if [[ -z "$sec_opts" ]] || grep -Eqi 'rootless|userns' <<<"$sec_opts"; then
    warn "Release Management auto-wiring skipped: Docker is rootless/userns-remapped or security options could not be read."
    warn "Use docs/operator/release-management-agent.md for a custom, explicit wiring."
    return 0
  fi

  local proxy_cid
  proxy_cid="$(sudo docker compose ps -q proxy 2>/dev/null || true)"
  if [[ -z "$proxy_cid" ]] || [[ "$(sudo docker inspect "$proxy_cid" --format '{{.State.Running}}' 2>/dev/null || true)" != "true" ]]; then
    warn "Release Management auto-wiring skipped: proxy container is not running."
    return 0
  fi
  if proxy_mounts_docker_socket "$proxy_cid"; then
    warn "Release Management auto-wiring skipped: proxy container has a Docker socket mount."
    warn "Remove the Docker socket from the proxy before enabling Release Management."
    return 0
  fi

  local proxy_uid
  proxy_uid="$(sudo docker compose exec -T proxy id -u 2>/dev/null | tr -d '\r\n' || true)"
  if [[ ! "$proxy_uid" =~ ^[0-9]+$ ]] || [[ "$proxy_uid" == "0" ]]; then
    warn "Release Management auto-wiring skipped: proxy UID is not a non-root numeric UID (got '$proxy_uid')."
    return 0
  fi

  local maint_gid
  maint_gid="$(getent group culvert-maint | awk -F: '{print $3}' | head -n1)"
  if [[ ! "$maint_gid" =~ ^[0-9]+$ ]]; then
    warn "Release Management auto-wiring skipped: culvert-maint group/GID not found."
    return 0
  fi
  if ! sudo test -f "$cfg" || ! sudo test -f "$sudoers"; then
    warn "Release Management auto-wiring skipped: maintenance-agent config or sudoers file is missing."
    return 0
  fi

  local cfg_project cfg_socket cfg_repo release_repo
  cfg_project="$(maint_toml_string compose_project_dir "$cfg")"
  cfg_socket="$(maint_toml_string socket_path "$cfg")"
  cfg_repo="$(maint_toml_string proxy_repo "$cfg")"
  [[ -n "$cfg_socket" ]] || cfg_socket="$socket_path"
  [[ -n "$cfg_repo" ]] || cfg_repo="$default_repo"
  release_repo="${CULVERT_RELEASE_PROXY_REPO:-${CULVERT_PROXY_REPO:-$default_repo}}"

  if [[ "$cfg_project" != "$INSTALL_DIR" ]]; then
    warn "Release Management auto-wiring skipped: maint-agent compose_project_dir ($cfg_project) does not match install dir ($INSTALL_DIR)."
    return 0
  fi
  if [[ "$cfg_repo" != "$release_repo" ]]; then
    warn "Release Management auto-wiring skipped: maint-agent proxy_repo ($cfg_repo) does not match release proxy repo ($release_repo)."
    return 0
  fi
  if [[ "$cfg_socket" != "$socket_path" ]]; then
    warn "Release Management auto-wiring skipped: maint-agent socket_path is not the default ($cfg_socket)."
    return 0
  fi

  info "Authorizing proxy UID $proxy_uid for the local maintenance agent..."
  if ! patch_allow_peers_numeric_uid "$proxy_uid"; then
    warn "Release Management auto-wiring skipped: could not safely patch allow_peers."
    return 0
  fi
  env_put CULVERT_MAINT_GID "$maint_gid" "$INSTALL_DIR/.env"
  env_put CULVERT_RELEASE_PROXY_REPO "$release_repo" "$INSTALL_DIR/.env"

  # Persist the maintenance-socket override so AGENT-DRIVEN recreates keep the
  # socket. Without this, the agent recreates the proxy with a single `-f`
  # (sudoers-bound) and drops the override's socket mount — after the first
  # update the CP can no longer reach the agent. compose_override_file carries
  # docker-compose.maint-agent.yml as a second `-f` on the recreate ONLY. The
  # ${CULVERT_MAINT_GID} it needs is resolved from $INSTALL_DIR/.env (written
  # above) because the agent runs compose with a scrubbed env. Only when the
  # override file is actually present. Set BEFORE the sudoers re-render so the
  # override allowlist line is rendered too.
  if [[ -f "$INSTALL_DIR/docker-compose.maint-agent.yml" ]]; then
    # Delete ANY existing form (TOML allows `key=v` and `key = v`) then append the
    # canonical line. A grep(prefix)+sed(` = ` only) pair would MISS a spaceless
    # `compose_override_file="old"`: grep matches so the append is skipped, but the
    # spaced sed does not replace it, leaving the stale value — the socket would
    # then be dropped on the next update, the exact failure this persists against.
    sudo sed -i '/^[[:space:]]*compose_override_file[[:space:]]*=/d' "$cfg"
    # Ensure the file ends in a newline BEFORE appending — but only add one when
    # it does not already (tail -c1 is empty iff the last byte is a newline, since
    # $() strips a trailing newline). This is idempotent (no blank-line buildup on
    # re-runs) AND safe against a hand-edited config.toml whose last line lacks a
    # trailing newline (without this, the key would glue onto that line and the
    # maint installer would not render the two-`-f` sudoers rule).
    if [[ -n "$(sudo tail -c1 "$cfg" 2>/dev/null)" ]]; then
      printf '\n' | sudo tee -a "$cfg" >/dev/null
    fi
    printf 'compose_override_file = "docker-compose.maint-agent.yml"\n' | sudo tee -a "$cfg" >/dev/null
    info "Maintenance agent will carry docker-compose.maint-agent.yml on recreate (socket survives updates)."
  fi

  # Re-render sudoers after the config patch, then start the service.
  if ! sudo CULVERT_MAINT_SKIP_VERIFY=1 bash "$maint_installer" /usr/local/bin/culvert-maint; then
    warn "Release Management auto-wiring skipped: maint-agent sudoers/config re-render failed."
    return 0
  fi
  # enable (idempotent) + RESTART, not `enable --now`: on a re-run/upgrade where
  # the agent is ALREADY running, `--now` only starts a stopped unit — it does
  # NOT reload the config.toml this function just patched. The agent reads its
  # config ONCE at startup, so both the allow_peers patch AND compose_override_file
  # would be ignored by the running process, and it would keep recreating with a
  # single `-f` (dropping the socket) until a manual restart. `restart` also
  # starts a stopped unit, so it is correct for first-install and upgrade alike.
  if ! sudo systemctl enable culvert-maint >/dev/null 2>&1; then
    warn "Release Management auto-wiring skipped: could not enable culvert-maint."
    return 0
  fi
  if ! sudo systemctl restart culvert-maint >/dev/null 2>&1; then
    warn "Release Management auto-wiring skipped: could not (re)start culvert-maint."
    return 0
  fi

  local i
  for i in $(seq 1 20); do
    [[ -S "$socket_path" ]] && break
    sleep 1
  done
  if [[ ! -S "$socket_path" ]]; then
    warn "Release Management auto-wiring skipped: maint-agent socket did not appear at $socket_path."
    return 0
  fi
  if ! verify_maint_agent_health_as_proxy_uid "$proxy_uid" "$maint_gid" "$socket_path"; then
    warn "Release Management auto-wiring skipped: /v1/health did not authorize the proxy UID."
    return 0
  fi

  info "Mounting the maint-agent UDS into the proxy with the safe override..."
  if ! sudo docker compose -f docker-compose.yml -f docker-compose.maint-agent.yml up -d; then
    warn "Release Management auto-wiring skipped: compose override failed."
    return 0
  fi
  if ! sudo docker compose exec -T proxy test -S "$socket_path" >/dev/null 2>&1; then
    warn "Release Management auto-wiring skipped: proxy cannot see the maint-agent socket after override."
    return 0
  fi
  proxy_cid="$(sudo docker compose ps -q proxy 2>/dev/null || true)"
  if [[ -n "$proxy_cid" ]] && proxy_mounts_docker_socket "$proxy_cid"; then
    warn "Release Management auto-wiring skipped: proxy gained a Docker socket mount after override."
    return 0
  fi

  MAINT_AGENT_WIRED=1
  info "Release Management wired to local culvert-maint over the UDS (no Docker socket mounted)."
}

install_maint_agent() {
  local maint_installer="packaging/culvert-maint/install.sh"

  if [[ -n "${CULVERT_SKIP_MAINT_AGENT:-}" ]]; then
    info "CULVERT_SKIP_MAINT_AGENT set — skipping maintenance agent"
    return 0
  fi

  # The installer script is required for every path (it installs binary,
  # sudoers, and unit). It arrives via the image deploy bundle (§6b) or a
  # source checkout; the Go sources are only needed for the BUILD fallback.
  if [[ ! -f "$maint_installer" ]]; then
    warn "Maintenance agent installer not found in $INSTALL_DIR — skipping"
    return 0
  fi

  # It is a systemd service, so systemd is the one hard requirement.
  if ! command -v systemctl &>/dev/null; then
    warn "systemd not detected — the maintenance agent is a systemd service; skipping"
    return 0
  fi

  # One scratch dir + one RETURN trap for every temp artifact this function
  # creates (bash keeps a single RETURN trap per function; the bundled-binary
  # extract and the build fallback below both live under it). sudo rm: files
  # written via `sudo docker cp` / container builds come out root-owned.
  local scratch
  scratch="$(mktemp -d)" || { warn "mktemp failed — skipping maintenance agent"; return 0; }
  # shellcheck disable=SC2064 -- expand $scratch now; it is function-local
  trap "sudo rm -rf '$scratch'" RETURN

  # Version we WANT installed (env → running proxy image label). Empty = take
  # the bundled binary as-is / build from source.
  local target_version
  target_version="$(resolve_maint_version)"

  # ── Guards (apply to EVERY path below, INCLUDING the already-installed wiring
  #    fast-path — a wired agent that can't chdir into the stack is worse than
  #    an unwired one, so these must gate the wiring, not just fresh installs
  #    (#6)). Cheap + dependency-free, so run them BEFORE the network cosign
  #    verify + bundle extract. ─────────────────────────────────────────────────
  #
  # (1) The agent's sudoers allowlist is path-bound to this stack's directory. A
  # path with whitespace/quotes/shell-or-sed metacharacters can't be rendered
  # safely into the sudoers grammar, so skip cleanly rather than half-bind it.
  case "$INSTALL_DIR" in
    *[[:space:]\"\'\\\&\|\$\`\(\)]*)
      warn "Install path '$INSTALL_DIR' has characters that can't be bound in the agent's sudoers allowlist."
      warn "Skipping the maintenance agent. Move the checkout to a plain path and re-run, or install it manually."
      return 0 ;;
  esac
  # (2) The unprivileged culvert-maint service must be able to chdir into the
  # stack (the runner sets cmd.Dir before sudo). We grant the LEAF group
  # traversal post-install, but an ANCESTOR we won't modify that is unsearchable
  # (a 0700 home, /root) means the agent could never reach the stack.
  if ! agent_ancestors_traversable "$INSTALL_DIR"; then
    warn "An ancestor of '$INSTALL_DIR' is not searchable by an unprivileged service user."
    warn "The maintenance agent runs as 'culvert-maint' and could not chdir into the stack; skipping."
    warn "This happens for stacks under a 0700/0750 home directory (CULVERT_DIR override or a"
    warn "home-dir checkout). Use the default system path instead — re-run from a neutral cwd:"
    warn "  cd / && sudo bash /path/to/install.sh          # deploys to /srv/culvert"
    return 0
  fi

  # ── Installer-script trust gate (Codex P1) ──────────────────────────────────
  # EVERY install/wiring path below root-execs "$maint_installer"
  # (packaging/culvert-maint/install.sh) — which also renders the sudoers and
  # systemd-unit templates. In a source-free deploy that script was extracted
  # from the proxy image's /app/deploy bundle by extract_deploy_bundle, BEFORE
  # any signature check. Running an UNVERIFIED image's installer as root would
  # hand a tampered/typosquatted image host-root — worse than fix #1, which only
  # gated the bundled BINARY. So establish trust for the SCRIPT itself, ONCE,
  # here (it gates the fast-path re-wire too):
  #   1. A real source checkout — cmd/culvert-maint/go.mod is NEVER shipped in
  #      the image bundle (only the compiled binary + packaging/), so its
  #      presence positively identifies the operator's own tree (a git checkout
  #      the operator populated themselves). Trusted; cheap.
  #   2. Otherwise the installer is image-derived: trust it (and the bundled
  #      binary, via trust_image_bundle) ONLY when the pinned proxy image
  #      cosign-verifies against the pinned release identity.
  #   3. Break-glass: CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1 for a dev/private
  #      image the operator knowingly trusts.
  # No trust ⇒ skip the agent entirely (the proxy is unaffected). The go.mod
  # check runs first so source deploys keep the fast-path's no-network property;
  # only a pure-bundle deploy pays the one cosign verify.
  #
  # trust_image_bundle is the SEPARATE decision of whether to install the image's
  # BUNDLED BINARY (fix #1): true only when we are trusting the IMAGE (cosign OK
  # or break-glass). A source checkout trusts the SCRIPT but not the image binary
  # (it builds from source / downloads the signed release instead).
  local installer_trusted=0 trust_image_bundle=0
  if [[ -f cmd/culvert-maint/go.mod ]]; then
    installer_trusted=1
  elif [[ -z "${CULVERT_MAINT_FORCE_BUILD:-}" ]] && verify_pinned_image_signature; then
    installer_trusted=1
    trust_image_bundle=1
  elif [[ -n "${CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE:-}" ]]; then
    warn "CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE set — root-executing the image-bundle agent"
    warn "installer AND its bundled binary despite an unverified proxy image (break-glass;"
    warn "you accept the risk of a tampered image gaining host-root)."
    installer_trusted=1
    trust_image_bundle=1
  fi
  if [[ "$installer_trusted" -ne 1 ]]; then
    warn "Maintenance agent skipped: the proxy image did not cosign-verify against the pinned"
    warn "release identity (unsigned/main :latest, private image without credentials, locally"
    warn "built, or cosign/registry unreachable) and no source checkout is present — so the"
    warn "bundled packaging/culvert-maint/install.sh cannot be trusted to run as ROOT."
    warn "Culvert's proxy is unaffected; Release Management / day-2 upgrades stay unwired."
    warn "Wire it by installing from a signed release tag or a source checkout, or re-run with"
    warn "  CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1   # dev/private image, at your own risk"
    return 0
  fi

  # Repoint proxy_repo (+ its paired image_allowlist) at a custom/private
  # registry requested via CULVERT_RELEASE_PROXY_REPO / CULVERT_PROXY_REPO, the
  # same override wire_release_agent_for_compose resolves as release_repo.
  # Runs here, BEFORE the "already installed" fast paths below, because those
  # paths wire_release_agent_for_compose and return WITHOUT ever reaching the
  # self-heal blocks near the end of this function — a re-run against an
  # already-installed agent (the common case: adding CULVERT_PROXY_REPO to an
  # existing deployment, no version change) would otherwise never get healed.
  # A truly fresh host has no config.toml yet at this point, so this is a
  # harmless no-op here; the matching call near the end of this function
  # (alongside the compose_project_dir/socket_path self-heals) catches that
  # case once the packaging installer has created it. heal_maint_proxy_repo
  # only rewrites the untouched packaging default (see its own doc comment);
  # an operator-edited proxy_repo/image_allowlist is left alone and the
  # existing mismatch warning in wire_release_agent_for_compose still applies.
  local wanted_proxy_repo="${CULVERT_RELEASE_PROXY_REPO:-${CULVERT_PROXY_REPO:-ghcr.io/kidcarmi/culvert}}"
  if heal_maint_proxy_repo /etc/culvert-maint/config.toml "$wanted_proxy_repo"; then
    info "Pointing maintenance agent at the custom proxy registry ($wanted_proxy_repo)..."
    if ! sudo CULVERT_MAINT_SKIP_VERIFY=1 bash "$maint_installer" /usr/local/bin/culvert-maint; then
      warn "Re-rendering after pointing the agent at $wanted_proxy_repo failed."
      warn "Fix proxy_repo/image_allowlist in /etc/culvert-maint/config.toml and re-run the installer."
      return 0
    fi
  fi

  # ── Fast path: already installed AND at a KNOWN target version → just ensure
  #    traversal + wiring, skipping the (network) cosign verify + bundle extract
  #    entirely. The guards above already ran, so wiring here cannot create a
  #    broken-chdir state. Only when the target is known pre-extract (env/label);
  #    an unknown target still needs the bundle to derive its version (the
  #    idempotence block after the bundle handles that). ─────────────────────────
  if [[ -f /etc/systemd/system/culvert-maint.service && -n "$target_version" ]]; then
    local installed_now=""
    if command -v culvert-maint &>/dev/null; then
      installed_now="$(culvert-maint --version 2>/dev/null || true)"
    fi
    if [[ "$installed_now" == "$target_version" ]]; then
      info "Maintenance agent already at $target_version — leaving it unchanged."
      ensure_agent_traversal || true
      MAINT_AGENT_INSTALLED=1
      wire_release_agent_for_compose "$maint_installer"
      return 0
    fi
  fi

  # Bundled agent binary: shipped inside the pinned proxy image at
  # /app/deploy/bin/culvert-maint, so it exists wherever the image can be
  # pulled — GitHub release assets and the source repo may not be publicly
  # readable. It also tracks the EXACT image the stack runs.
  #
  # TRUST (fix — finding #1): the agent is a HOST-ROOT systemd service (sudoers
  # docker allowlist), so we must NOT install its BINARY from an unverified
  # image. trust_image_bundle (computed once in the trust gate above) is set only
  # when we are trusting the IMAGE — either it cosign-verified against the pinned
  # tag identity, or the operator set the CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE
  # break-glass. Only then do we extract + trust the bundled binary — SKIP_VERIFY
  # at install time is then legitimate because the SOURCE image is (or was
  # explicitly) trusted. Otherwise (a source checkout where we build instead, or
  # an image we don't trust) trust_image_bundle is 0 and we fall through to the
  # signed-release download (which self-verifies) or the source build.
  local bundled_bin=""
  if [[ -z "${CULVERT_MAINT_FORCE_BUILD:-}" ]]; then
    if [[ "$trust_image_bundle" -eq 1 ]]; then
      if extract_bundled_maint_bin "$scratch/culvert-maint-bundled"; then
        local cand="$scratch/culvert-maint-bundled" bundled_version=""
        # Probe the extracted binary before trusting it. A FAILED exec means it
        # cannot run on THIS host — e.g. a foreign-arch image seeded via
        # CULVERT_PROXY_SEED_REF with no matching binfmt/qemu — so discard it
        # rather than install a crash-looping systemd unit (#10). (If binfmt IS
        # registered the foreign binary runs emulated and --version succeeds,
        # which is degraded-but-functional and acceptable.)
        if bundled_version="$("$cand" --version 2>/dev/null)" \
           && [[ "$bundled_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
          if [[ -z "$target_version" ]]; then
            # No explicit target — adopt the verified image's bundled version.
            target_version="$bundled_version"
            bundled_bin="$cand"
            info "Proxy image verified — using its bundled agent $bundled_version."
          elif [[ "$bundled_version" == "$target_version" ]]; then
            bundled_bin="$cand"
            info "Proxy image verified — using its bundled agent $bundled_version (matches target)."
          else
            # The image bundles a DIFFERENT version than requested. Installing
            # the bundle would install the WRONG version and loop forever on
            # every re-run (installed != target); use the signed-release
            # download of the requested target instead (#4).
            info "Proxy image bundles agent $bundled_version but the target is $target_version —"
            info "using the signed-release download for $target_version instead of the image bundle."
          fi
        else
          info "Bundled agent binary is not runnable on this host (architecture mismatch or"
          info "corrupt) — falling back to the signed-release download / source build."
        fi
      fi
    else
      # Reached only for a source checkout (an untrusted image already returned
      # at the trust gate). We trust the SCRIPT (from source) but not the image's
      # bundled binary — build it from source / download the signed release.
      info "Not using the image's bundled agent binary (source checkout present) —"
      info "installing from the signed-release download or a local source build."
    fi
  fi

  # Upgrade-aware: the systemd unit is the "fully installed" marker (written
  # last). If it exists AND the installed agent already reports the target
  # version, leave it. If versions differ, fall through to the idempotent
  # (re)install to UPGRADE. A bare binary with no unit is a PARTIAL install —
  # also fall through and let the installer finish.
  if [[ -f /etc/systemd/system/culvert-maint.service ]]; then
    local installed_version=""
    if command -v culvert-maint &>/dev/null; then
      installed_version="$(culvert-maint --version 2>/dev/null || true)"
    fi
    # When the installed agent is already the target (or no target can be
    # resolved), skip the reinstall but STILL run the wiring below — it is
    # idempotent, and a previous run may have installed the agent yet failed
    # (or been skipped) at the Release Management wiring step.
    # (Guards already ran before the bundle block above, so wiring on these
    # already-installed early-returns cannot create a broken-chdir state.)
    if [[ -z "$target_version" ]]; then
      info "Maintenance agent installed ($installed_version); cannot resolve a target version — leaving it unchanged"
      ensure_agent_traversal || true
      MAINT_AGENT_INSTALLED=1
      wire_release_agent_for_compose "$maint_installer"
      return 0
    fi
    if [[ "$installed_version" == "$target_version" ]]; then
      info "Maintenance agent already at $target_version — leaving it unchanged"
      ensure_agent_traversal || true
      MAINT_AGENT_INSTALLED=1
      wire_release_agent_for_compose "$maint_installer"
      return 0
    fi
    info "Upgrading maintenance agent ($installed_version → $target_version)..."
  fi

  # ── Install: verified bundled binary → signed release → local build. ────────
  # $bundled_bin is set ONLY when verify_pinned_image_signature passed above, so
  # CULVERT_MAINT_SKIP_VERIFY=1 here is trusting an ALREADY-VERIFIED source (the
  # cosign-verified proxy image), not an unverified download. The image carries
  # no sidecar cosign bundle for the binary itself; the image signature is the
  # anchor. If the image was not verified, $bundled_bin is empty and this branch
  # is skipped in favour of the self-verifying signed-release download below.
  local installed_ok=0
  if [[ -n "$bundled_bin" ]]; then
    info "Installing maintenance agent from the (verified) image deploy bundle..."
    if sudo CULVERT_MAINT_SKIP_VERIFY=1 bash "$maint_installer" "$bundled_bin"; then
      installed_ok=1
    else
      warn "Bundled-agent install failed — trying the signed-release download..."
    fi
  fi
  if [[ "$installed_ok" -ne 1 && -n "$target_version" && -z "${CULVERT_MAINT_FORCE_BUILD:-}" ]]; then
    info "Installing maintenance agent from the signed release ($target_version)..."
    # No positional binary → the agent installer downloads + cosign-verifies the
    # release asset itself (fail-closed). Pass the resolved version through.
    if sudo CULVERT_MAINT_VERSION="$target_version" bash "$maint_installer"; then
      installed_ok=1
    else
      warn "Signed-release install failed (network/registry/verify) — falling back to a local build."
    fi
  fi

  if [[ "$installed_ok" -ne 1 ]]; then
    # Build fallback (air-gap / registry-down / unknown version). Build into a
    # throwaway temp dir so we never leave a (possibly root-owned) binary in the
    # working tree; cleaned up on every return path. Prefer the host Go
    # toolchain (fast), else a throwaway golang container — Docker is already up.
    #
    # libc / glibc strategy (the two builds differ ON PURPOSE):
    #  - Host build: default toolchain (cgo on). os/user honors NSS (LDAP/SSSD)
    #    when resolving allow_peers usernames; no glibc-version mismatch.
    #  - Container fallback: CGO_ENABLED=0 (static). Runs anywhere, but os/user
    #    falls back to pure-Go /etc/passwd parsing, so on a host whose
    #    allow_peers come from NSS the operator must use numeric UIDs (warned).
    if [[ ! -f cmd/culvert-maint/go.mod ]]; then
      warn "No bundled/release agent installed and sources not present for a build fallback — skipping (Culvert is unaffected)."
      return 0
    fi
    local build_dir maint_bin go_image
    go_image="${CULVERT_GO_IMAGE:-golang:1.25}"
    build_dir="$scratch/build"
    mkdir -p "$build_dir" || { warn "mkdir failed — skipping maintenance agent"; return 0; }
    maint_bin="$build_dir/culvert-maint"

    if command -v go &>/dev/null; then
      info "Building culvert-maint with the host Go toolchain..."
      ( cd cmd/culvert-maint && go build -o "$maint_bin" . ) \
        || warn "Host 'go build' failed — falling back to a Go build container..."
    fi
    if [[ ! -x "$maint_bin" ]]; then
      info "Building culvert-maint in a Go container ($go_image; static, no host Go required)..."
      if ! sudo docker run --rm -e CGO_ENABLED=0 \
             -v "$INSTALL_DIR/cmd/culvert-maint":/src:ro,z \
             -v "$build_dir":/out:z \
             -w /src "$go_image" go build -o /out/culvert-maint . ; then
        warn "Could not build culvert-maint (host Go and container build both failed)."
        warn "Culvert is unaffected. Re-run later from $INSTALL_DIR:"
        warn "  (cd cmd/culvert-maint && go build -o culvert-maint .) \\"
        warn "    && sudo CULVERT_MAINT_SKIP_VERIFY=1 bash $maint_installer cmd/culvert-maint/culvert-maint"
        return 0
      fi
      warn "Built a static (CGO_ENABLED=0) binary: allow_peers must be local"
      warn "/etc/passwd users or numeric UIDs — NSS/LDAP usernames won't resolve."
    fi
    if [[ ! -x "$maint_bin" ]]; then
      warn "culvert-maint binary missing after build — skipping (Culvert is unaffected)."
      return 0
    fi

    info "Running maintenance agent installer (local build)..."
    # A freshly built binary has no signature; trust it explicitly.
    if ! sudo CULVERT_MAINT_SKIP_VERIFY=1 bash "$maint_installer" "$maint_bin"; then
      warn "Maintenance agent install did not complete — Culvert is unaffected."
      return 0
    fi
  fi

  # The installer seeds /etc/culvert-maint/config.toml from the example, whose
  # compose_project_dir default is /srv/culvert. This stack lives at
  # $INSTALL_DIR and the sudoers allowlist is path-bound to compose_project_dir,
  # so when the value is still the example default and we are elsewhere, point
  # it at this stack and re-render the binding. We only ever rewrite the
  # untouched default — never an operator-edited path. Re-render reuses the
  # already-installed binary (skip-verify) so we never download twice.
  if [[ "$INSTALL_DIR" != "/srv/culvert" ]] \
     && sudo grep -q '^compose_project_dir = "/srv/culvert"' /etc/culvert-maint/config.toml 2>/dev/null; then
    info "Pointing maintenance agent at this stack (compose_project_dir=$INSTALL_DIR)..."
    sudo sed -i "s|^compose_project_dir = .*|compose_project_dir = \"$INSTALL_DIR\"|" /etc/culvert-maint/config.toml
    if ! sudo CULVERT_MAINT_SKIP_VERIFY=1 bash "$maint_installer" /usr/local/bin/culvert-maint; then
      warn "Re-rendering the sudoers binding for $INSTALL_DIR failed."
      warn "Fix compose_project_dir in /etc/culvert-maint/config.toml and re-run the installer."
      return 0
    fi
  fi

  # Same proxy_repo repointing as above, for the FRESH-install case: the
  # earlier call (before the fast-path returns) no-ops when config.toml
  # doesn't exist yet — it does now, freshly seeded by the installer call(s)
  # above. Idempotent: a re-run where the earlier call already healed it
  # finds proxy_repo no longer at the default and no-ops here too.
  if heal_maint_proxy_repo /etc/culvert-maint/config.toml "$wanted_proxy_repo"; then
    info "Pointing maintenance agent at the custom proxy registry ($wanted_proxy_repo)..."
    if ! sudo CULVERT_MAINT_SKIP_VERIFY=1 bash "$maint_installer" /usr/local/bin/culvert-maint; then
      warn "Re-rendering after pointing the agent at $wanted_proxy_repo failed."
      warn "Fix proxy_repo/image_allowlist in /etc/culvert-maint/config.toml and re-run the installer."
      return 0
    fi
  fi

  # Migrate the pre-RuntimeDirectory socket default. Installs seeded before the
  # /run/culvert-maint/ move have socket_path = "/run/culvert-maint.sock", which
  # the unprivileged agent cannot bind directly in root-owned /run. Rewrite ONLY
  # the untouched old default to the managed-runtime-dir path; never touch a
  # customized value. socket_path is not sudoers-bound, so no re-render needed.
  if sudo grep -q '^socket_path = "/run/culvert-maint.sock"' /etc/culvert-maint/config.toml 2>/dev/null; then
    info "Migrating socket_path to the managed runtime dir (/run/culvert-maint/culvert-maint.sock)..."
    sudo sed -i 's|^socket_path = "/run/culvert-maint.sock"|socket_path = "/run/culvert-maint/culvert-maint.sock"|' /etc/culvert-maint/config.toml
  fi

  # Grant the unprivileged agent group traversal of the stack dir (least-
  # privilege 0750 root:culvert-maint), now that the user/group exist.
  # Non-fatal: a warning here means operations would fail at chdir.
  ensure_agent_traversal || true

  MAINT_AGENT_INSTALLED=1
  info "Maintenance agent installed."
  wire_release_agent_for_compose "$maint_installer"
}

install_maint_agent || true

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Culvert is running!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
if [[ "${SSL_INSPECTION_BROKEN:-0}" == "1" ]]; then
  echo -e "${YELLOW}  ⚠ SSL inspection is DISABLED — the Root CA failed to load (see the${NC}"
  echo -e "${YELLOW}    warning above). HTTPS is tunneled without scanning/DLP/CDR until the${NC}"
  echo -e "${YELLOW}    CA passphrase in $INSTALL_DIR/.env matches the encrypted ca.bundle.${NC}"
  echo ""
fi
echo "  Proxy:    http://<your-ip>:8080  (configure browsers to use this)"
echo "  Admin UI: https://<your-ip>:9090 (accept the self-signed cert)"
echo ""
echo "  First visit: the setup wizard will create your admin account."
echo ""
echo "  Verify readiness:"
echo "    curl http://<your-ip>:8080/ready"
echo ""
echo "  Operator health checks:"
echo "    Admin UI → Infrastructure → Diagnostics"
echo ""
echo "  Useful commands:"
echo "    cd $INSTALL_DIR"
echo "    docker compose logs -f          # watch all logs"
echo "    docker compose logs -f proxy    # watch proxy logs"
echo "    docker compose ps               # check service status"
echo "    docker compose down             # stop everything"
echo "    docker compose up -d            # (re)start everything"
echo ""
if [[ "$CURRENT_USER" != "root" ]] && ! groups "$CURRENT_USER" | grep -qw docker; then
  echo -e "${YELLOW}  NOTE: Log out and back in to use 'docker' without sudo.${NC}"
  echo ""
fi
if [[ "${MAINT_AGENT_INSTALLED:-0}" == "1" ]]; then
  echo "  Maintenance agent installed (systemd: culvert-maint)."
  if [[ "${MAINT_AGENT_WIRED:-0}" == "1" ]]; then
    echo "  Release Management is wired locally over /run/culvert-maint/culvert-maint.sock."
    echo "  No Docker socket is mounted into the proxy."
    echo "  Note: /api/releases may still report available:false until a trusted"
    echo "  release catalog is published into /data/release_catalog."
  else
    echo "  Release Management auto-wiring was not enabled. This is fail-closed;"
    echo "  see the warnings above and docs/operator/release-management-agent.md"
    echo "  for custom Docker, userns-remap, rootless, or remote-agent setups."
  fi
  echo ""
fi
