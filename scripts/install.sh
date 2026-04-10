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
    # Remove distro-packaged Docker
    for pkg in docker.io containerd runc podman-docker; do
      if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        info "Removing $pkg..."
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
else
  case "$DISTRO_FAMILY" in
    debian)
      info "Installing from Docker's official apt repository..."
      sudo apt-get update -qq
      sudo apt-get install -y -qq ca-certificates curl gnupg >/dev/null

      sudo install -m 0755 -d /etc/apt/keyrings
      if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
        curl -fsSL "https://download.docker.com/linux/${DISTRO_ID}/gpg" | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
      fi

      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO_ID} ${DISTRO_CODENAME} stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

      sudo apt-get update -qq
      sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
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

sudo systemctl enable docker >/dev/null 2>&1
sudo systemctl start docker

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
  error "Docker engine failed to start. Check: sudo systemctl status docker"
fi

###############################################################################
# 4. Install git if missing
###############################################################################
if ! command -v git &>/dev/null; then
  step "Installing git"
  case "$DISTRO_FAMILY" in
    debian) sudo apt-get install -y -qq git >/dev/null ;;
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
# 6. Build and start
###############################################################################
step "Building and starting Culvert"

info "This will take a few minutes on first run (downloading Go, compiling, GeoIP DB)..."
sudo docker compose up -d --build

###############################################################################
# 7. Wait for health checks
###############################################################################
step "Waiting for services to start"

info "Waiting for proxy to become healthy..."
for i in $(seq 1 30); do
  if sudo docker compose ps --format json 2>/dev/null | grep -q '"healthy"'; then
    break
  fi
  sleep 2
done

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
