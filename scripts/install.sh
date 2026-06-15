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
#   5. Clones Culvert (if not already in the repo)
#   6. Starts all services with docker compose up -d --build
#   7. (Optional, best-effort) Builds + installs the host-side maintenance
#      agent (culvert-maint systemd service). Builds with the host Go
#      toolchain if present, else in a throwaway golang container (no host
#      Go required). Skip entirely with CULVERT_SKIP_MAINT_AGENT=1.
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

REPO_URL="https://github.com/KidCarmi/Culvert.git"
INSTALL_DIR="${CULVERT_DIR:-$HOME/Culvert}"

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

###############################################################################
# 4. Install git if missing
###############################################################################
if ! command -v git &>/dev/null; then
  step "Installing git"
  case "$DISTRO_FAMILY" in
    debian) apt_install_with_repair git ;;
    rhel|fedora) sudo dnf install -y git 2>/dev/null || sudo yum install -y git ;;
    amzn) sudo yum install -y git ;;
    arch) sudo pacman -Sy --noconfirm git ;;
  esac
  info "git installed"
fi

###############################################################################
# 5. Clone Culvert (if not already in the repo)
###############################################################################
step "Setting up Culvert"

if [[ -f "./docker-compose.yml" ]] && grep -q "culvert" ./docker-compose.yml 2>/dev/null; then
  info "Already inside Culvert repo: $(pwd)"
  INSTALL_DIR="$(pwd)"
elif [[ -d "$INSTALL_DIR" ]] && [[ -f "$INSTALL_DIR/docker-compose.yml" ]]; then
  info "Culvert repo already exists at $INSTALL_DIR"
else
  info "Cloning Culvert..."
  git clone "$REPO_URL" "$INSTALL_DIR"
  info "Cloned to $INSTALL_DIR"
fi

cd "$INSTALL_DIR"

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

seed_pinned_tag() {
  if sudo docker image inspect "$PINNED_TAG" >/dev/null 2>&1; then
    info "$PINNED_TAG already present; not reseeding"
    return 0
  fi

  # Seed source precedence (mirrors packaging/culvert-maint/install.sh):
  #   1. CULVERT_PROXY_SEED_REF — operator-supplied (existing-install
  #      migration: the currently-running repo@sha256 digest).
  #   2. The image of an already-running `culvert` container (auto-captured,
  #      keeps the pinned tag identical to the live daemon — §8.2).
  #   3. ${PROXY_REPO}:latest — fresh-install bootstrap.
  #   4. Local build from this checkout — air-gapped / registry-down fallback.
  if [[ -n "${CULVERT_PROXY_SEED_REF:-}" ]]; then
    info "Seeding $PINNED_TAG from CULVERT_PROXY_SEED_REF=$CULVERT_PROXY_SEED_REF ..."
    if sudo docker pull "$CULVERT_PROXY_SEED_REF" && sudo docker tag "$CULVERT_PROXY_SEED_REF" "$PINNED_TAG"; then
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

  info "Seeding $PINNED_TAG from $PROXY_REPO:latest ..."
  if sudo docker pull "$PROXY_REPO:latest" && sudo docker tag "$PROXY_REPO:latest" "$PINNED_TAG"; then
    info "Seeded $PINNED_TAG"
    return 0
  fi

  warn "Registry pull failed. Building $PINNED_TAG locally from this checkout (slower)..."
  if sudo docker build -t "$PINNED_TAG" .; then
    info "Built and seeded $PINNED_TAG locally"
    return 0
  fi

  return 1
}

if ! seed_pinned_tag; then
  error "Could not seed $PINNED_TAG from any source (seed ref, running container, $PROXY_REPO:latest, local build).

  Seed it manually, then re-run this script:
    docker pull $PROXY_REPO:latest && docker tag $PROXY_REPO:latest $PINNED_TAG
  or build from source:
    docker build -t $PINNED_TAG ."
fi

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

info "Pulling images and starting services (first run may take 1-2 minutes)..."

# `docker compose up -d --wait` (Compose v2.17+) blocks until containers are
# either healthy or exited, and returns non-zero on failure. Much more
# reliable than the old "sleep + grep healthy" loop, which silently passed
# even when services crash-looped.
COMPOSE_UP_OK=0
if sudo docker compose up -d --wait --wait-timeout 180; then
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

###############################################################################
# 8. Maintenance agent (optional, best-effort)
###############################################################################
step "Maintenance agent (optional)"

# The host-side Maintenance Agent (culvert-maint) is a systemd service that
# lets the admin UI drive backup / restore / cleanup / upgrade against THIS
# compose stack over a local Unix socket. It is optional day-2 tooling, so a
# failure here NEVER fails the Culvert install — we warn and move on. Opt out
# entirely with CULVERT_SKIP_MAINT_AGENT=1.
MAINT_AGENT_INSTALLED=0

install_maint_agent() {
  if [[ -n "${CULVERT_SKIP_MAINT_AGENT:-}" ]]; then
    info "CULVERT_SKIP_MAINT_AGENT set — skipping maintenance agent"
    return 0
  fi

  # Already installed? Leave it untouched (idempotent, never clobber config).
  if command -v culvert-maint &>/dev/null || [[ -f /etc/systemd/system/culvert-maint.service ]]; then
    info "Maintenance agent already installed — leaving it unchanged"
    return 0
  fi

  local maint_installer="packaging/culvert-maint/install.sh"
  if [[ ! -f "$maint_installer" ]]; then
    warn "Maintenance agent installer not found ($maint_installer) — skipping"
    return 0
  fi

  # It is a systemd service, so systemd is the one hard requirement.
  if ! command -v systemctl &>/dev/null; then
    warn "systemd not detected — the maintenance agent is a systemd service; skipping"
    return 0
  fi

  # Build the binary. Prefer the host Go toolchain (fast); otherwise fall back
  # to a throwaway golang container — Docker is already up at this point, so no
  # host Go is required. The module is self-contained (its own go.mod).
  local maint_bin="$INSTALL_DIR/cmd/culvert-maint/culvert-maint"
  rm -f "$maint_bin"
  if command -v go &>/dev/null; then
    info "Building culvert-maint with the host Go toolchain..."
    if ! ( cd cmd/culvert-maint && go build -o culvert-maint . ); then
      warn "Host 'go build' failed — falling back to a Go build container..."
      rm -f "$maint_bin"
    fi
  fi
  if [[ ! -x "$maint_bin" ]]; then
    info "Building culvert-maint in a Go container (no host Go required)..."
    if ! sudo docker run --rm \
           -v "$INSTALL_DIR/cmd/culvert-maint":/src:z -w /src \
           golang:1.25 go build -o culvert-maint . ; then
      warn "Could not build culvert-maint (host Go and container build both failed)."
      warn "Culvert is unaffected. Re-run later with Go installed:"
      warn "  (cd cmd/culvert-maint && go build -o culvert-maint .) \\"
      warn "    && sudo bash $maint_installer cmd/culvert-maint/culvert-maint"
      return 0
    fi
  fi
  if [[ ! -x "$maint_bin" ]]; then
    warn "culvert-maint binary missing after build — skipping (Culvert is unaffected)."
    return 0
  fi

  info "Running maintenance agent installer..."
  if ! sudo bash "$maint_installer" "$maint_bin"; then
    warn "Maintenance agent install did not complete — Culvert is unaffected."
    warn "Re-run later with: sudo bash $maint_installer $maint_bin"
    return 0
  fi

  # The installer seeds /etc/culvert-maint/config.toml from the example, whose
  # compose_project_dir default is /srv/culvert. This stack lives at
  # $INSTALL_DIR, and the sudoers allowlist is path-bound to compose_project_dir
  # — so if it still holds the example default and we are elsewhere, point it at
  # this stack and re-run the installer to re-render the sudoers binding. We
  # only touch the still-default value, never an operator-edited path.
  if [[ "$INSTALL_DIR" != "/srv/culvert" ]] \
     && grep -q '^compose_project_dir = "/srv/culvert"' /etc/culvert-maint/config.toml 2>/dev/null; then
    info "Pointing maintenance agent at this stack (compose_project_dir=$INSTALL_DIR)..."
    sudo sed -i "s|^compose_project_dir = .*|compose_project_dir = \"$INSTALL_DIR\"|" /etc/culvert-maint/config.toml
    if ! sudo bash "$maint_installer" "$maint_bin"; then
      warn "Re-rendering the sudoers binding for $INSTALL_DIR failed."
      warn "Fix compose_project_dir in /etc/culvert-maint/config.toml and re-run the installer."
      return 0
    fi
  fi

  MAINT_AGENT_INSTALLED=1
  info "Maintenance agent installed (not started)."
}

install_maint_agent || true

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Culvert is running!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
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
echo "    docker compose up -d --build    # rebuild and restart"
echo ""
if [[ "$CURRENT_USER" != "root" ]] && ! groups "$CURRENT_USER" | grep -qw docker; then
  echo -e "${YELLOW}  NOTE: Log out and back in to use 'docker' without sudo.${NC}"
  echo ""
fi
if [[ "${MAINT_AGENT_INSTALLED:-0}" == "1" ]]; then
  echo "  Maintenance agent installed (systemd: culvert-maint), not yet started."
  echo "  Before starting it, set the allowed caller(s):"
  echo "    sudo \$EDITOR /etc/culvert-maint/config.toml   # set allow_peers"
  echo "    sudo systemctl enable --now culvert-maint"
  echo ""
fi
