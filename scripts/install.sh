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
# Where to clone/run the stack. Honor CULVERT_DIR if set. Otherwise: root (the
# appliance / first-boot / OVA case) gets the system path /srv/culvert — it
# matches the agent config's compose_project_dir default, and the maintenance
# agent reaches it via the culvert-maint group (0750 root:culvert-maint, granted
# post-install) rather than world bits. Non-root keeps the familiar ~/Culvert.
if [[ -n "${CULVERT_DIR:-}" ]]; then
  INSTALL_DIR="$CULVERT_DIR"
elif [[ "$(id -u)" -eq 0 ]]; then
  INSTALL_DIR="/srv/culvert"
else
  INSTALL_DIR="$HOME/Culvert"
fi

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
  touch "$file"; chmod 600 "$file"
  sed -i 's/\r$//' "$file" 2>/dev/null || true # normalize to LF so compose parses cleanly
  # grep -v exits 1 (not just erroring) whenever EVERY line matched the
  # pattern being dropped — including the common case where $file contains
  # only this one VAR=... line. Treat ONLY that "no lines survived" case (1)
  # as benign and promote the filtered file; a real error (e.g. ENOSPC while
  # writing $file.tmp) gets a higher exit code and must NOT clobber the
  # existing $file with a truncated/empty temp file.
  local rc=0
  grep -vE "^${var}=" "$file" > "$file.tmp" 2>/dev/null && rc=0 || rc=$?
  if [[ $rc -eq 0 || $rc -eq 1 ]]; then
    mv "$file.tmp" "$file"
  else
    rm -f "$file.tmp"
  fi
  printf '%s=%s\n' "$var" "$val" >> "$file"
  chmod 600 "$file"
}

gen_passphrase() {
  local p
  p="$(openssl rand -base64 48 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 40 || true)"
  [[ -n "$p" ]] || p="$(head -c 48 /dev/urandom 2>/dev/null | base64 | tr -dc 'A-Za-z0-9' | head -c 40 || true)"
  [[ -n "$p" ]] || error "Could not generate a passphrase (openssl and /dev/urandom both unavailable)."
  printf '%s' "$p"
}

# Encrypts data at rest (AES-256), value(s) stored in $INSTALL_DIR/.env which
# docker-compose.yml reads as ${CULVERT_*_PASSPHRASE:-}. We never overwrite an
# existing value. On a FRESH deployment (no data volume yet) we can safely also
# encrypt the SSL-inspection CA key, because there's no existing CA bundle to
# clash with; on an EXISTING deployment we only set the saved-log passphrase and
# leave the CA passphrase to the operator.
setup_at_rest_encryption() {
  local envfile="$INSTALL_DIR/.env"
  if secret_already_set CULVERT_LOG_PASSPHRASE "$envfile" || secret_already_set CULVERT_CA_PASSPHRASE "$envfile"; then
    info "Encryption passphrase already configured — keeping existing values."
    return
  fi

  local fresh=0; is_fresh_deployment && fresh=1

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
      # The passphrase is stored in .env, which docker compose interpolates
      # ($VAR), treats # as a comment, etc. Restrict to characters that survive
      # that round-trip intact so the value reaching the container is exact.
      if printf '%s' "$pass" | LC_ALL=C grep -q '[^A-Za-z0-9._@%^!*()+=:,-]'; then
        error "Passphrase has characters unsafe for the .env file. Use letters, digits, and simple punctuation (no \$, quotes, backslash, #, /, or spaces)."
      fi
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
# runs backup / restore / cleanup / Docker-image-update operations against THIS
# compose stack over a local Unix socket — the host-side half of day-2
# automation for unattended (e.g. OVA / first-boot) deployments.
#
# It is reached on the host via its UDS by a local operator or the control
# plane. By default we do NOT wire that socket into the proxy container, so the
# in-container Release Management UI reports the agent as "unreachable" until you
# opt in. Mounting the AGENT's UDS (NOT /var/run/docker.sock) is the supported,
# isolation-preserving opt-in — the agent's SO_PEERCRED + allow_peers + sudoers
# allowlist remain the privilege boundary, so a compromised proxy still cannot
# exceed the agent's narrow allowlisted surface. See docker-compose.maint-agent.yml
# and docs/operator/release-management-agent.md.
#
# Optional + best-effort: a failure NEVER fails the Culvert install — we warn
# and move on. Opt out entirely with CULVERT_SKIP_MAINT_AGENT=1.
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
  local p mode
  p="$(dirname "$1")"
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
# "unknown" — the caller then BUILDS from source instead of downloading.
resolve_maint_version() {
  if [[ -n "${CULVERT_MAINT_VERSION:-}" ]]; then
    echo "${CULVERT_MAINT_VERSION}"
    return 0
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
    BEGIN { patched=0 }
    /^[[:space:]]*allow_peers[[:space:]]*=/ && patched == 0 {
      line=$0
      if (line ~ /^[[:space:]]*allow_peers[[:space:]]*=[[:space:]]*\["culvert-cp"\][[:space:]]*$/) {
        print "allow_peers = [\"" uid "\"]"
        patched=1
        next
      }
      if (line ~ "\"" uid "\"") {
        print line
        patched=1
        next
      }
      if (line !~ /\][[:space:]]*$/) {
        print line
        patched=2
        next
      }
      sub(/[[:space:]]*\][[:space:]]*$/, ", \"" uid "\"]", line)
      print line
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
  sudo -n -u "#$uid" -g "#$gid" curl -fsS --unix-socket "$sock" http://unix/v1/health >/dev/null 2>&1
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
  if [[ ! -f "$cfg" || ! -f "$sudoers" ]]; then
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
    if [[ -n "$(tail -c1 "$cfg" 2>/dev/null)" ]]; then
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
  # sudoers, and unit). The Go sources are only needed for the BUILD fallback —
  # the signed-release download path does not need them.
  if [[ ! -f "$maint_installer" ]]; then
    warn "Maintenance agent installer not found in this checkout — skipping"
    return 0
  fi

  # It is a systemd service, so systemd is the one hard requirement.
  if ! command -v systemctl &>/dev/null; then
    warn "systemd not detected — the maintenance agent is a systemd service; skipping"
    return 0
  fi

  # Version we WANT installed (env → running proxy). Empty = build from source.
  local target_version
  target_version="$(resolve_maint_version)"

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
    if [[ -n "$target_version" && "$installed_version" == "$target_version" ]]; then
      info "Maintenance agent already at $target_version — leaving it unchanged"
      return 0
    fi
    if [[ -z "$target_version" ]]; then
      info "Maintenance agent installed ($installed_version); cannot resolve a target version — leaving it unchanged"
      return 0
    fi
    info "Upgrading maintenance agent ($installed_version → $target_version)..."
  fi

  # The agent's sudoers allowlist is path-bound to this stack's directory. A
  # path with whitespace/quotes/shell-or-sed metacharacters can't be rendered
  # safely into the sudoers grammar (the agent installer rejects it), so skip
  # the whole step cleanly rather than leave a half-bound install behind.
  case "$INSTALL_DIR" in
    *[[:space:]\"\'\\\&\|\$\`\(\)]*)
      warn "Install path '$INSTALL_DIR' has characters that can't be bound in the agent's sudoers allowlist."
      warn "Skipping the maintenance agent. Move the checkout to a plain path and re-run, or install it manually."
      return 0 ;;
  esac

  # The unprivileged culvert-maint service must be able to chdir into the stack
  # (the runner sets cmd.Dir = compose_project_dir before sudo). We grant the
  # LEAF group traversal post-install (0750 root:culvert-maint), so it has no
  # world requirement — but an ANCESTOR we will not modify that is unsearchable
  # (e.g. a 0700 home, or /root) means the agent could never reach the stack.
  # Skip cleanly instead of binding a guaranteed-broken path.
  if ! agent_ancestors_traversable "$INSTALL_DIR"; then
    warn "An ancestor of '$INSTALL_DIR' is not searchable by an unprivileged service user."
    warn "The maintenance agent runs as 'culvert-maint' and could not chdir into the stack; skipping."
    warn "For unattended/appliance installs, place the stack under a system path, e.g.:"
    warn "  sudo CULVERT_DIR=/srv/culvert bash scripts/install.sh"
    return 0
  fi

  # ── Install: prefer the signed release, fall back to a local build. ─────────
  local installed_ok=0
  if [[ -n "$target_version" && -z "${CULVERT_MAINT_FORCE_BUILD:-}" ]]; then
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
      warn "No release installed and agent sources not present for a build fallback — skipping (Culvert is unaffected)."
      return 0
    fi
    local build_dir maint_bin go_image
    go_image="${CULVERT_GO_IMAGE:-golang:1.25}"
    build_dir="$(mktemp -d)" || { warn "mktemp failed — skipping maintenance agent"; return 0; }
    trap "rm -rf '$build_dir'" RETURN
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
     && grep -q '^compose_project_dir = "/srv/culvert"' /etc/culvert-maint/config.toml 2>/dev/null; then
    info "Pointing maintenance agent at this stack (compose_project_dir=$INSTALL_DIR)..."
    sudo sed -i "s|^compose_project_dir = .*|compose_project_dir = \"$INSTALL_DIR\"|" /etc/culvert-maint/config.toml
    if ! sudo CULVERT_MAINT_SKIP_VERIFY=1 bash "$maint_installer" /usr/local/bin/culvert-maint; then
      warn "Re-rendering the sudoers binding for $INSTALL_DIR failed."
      warn "Fix compose_project_dir in /etc/culvert-maint/config.toml and re-run the installer."
      return 0
    fi
  fi

  # Migrate the pre-RuntimeDirectory socket default. Installs seeded before the
  # /run/culvert-maint/ move have socket_path = "/run/culvert-maint.sock", which
  # the unprivileged agent cannot bind directly in root-owned /run. Rewrite ONLY
  # the untouched old default to the managed-runtime-dir path; never touch a
  # customized value. socket_path is not sudoers-bound, so no re-render needed.
  if grep -q '^socket_path = "/run/culvert-maint.sock"' /etc/culvert-maint/config.toml 2>/dev/null; then
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
