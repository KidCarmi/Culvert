#!/usr/bin/env bash
# install.sh — One-command Culvert setup for a fresh Ubuntu/Debian server.
#
# Usage (fresh server):
#   curl -fsSL https://raw.githubusercontent.com/KidCarmi/Culvert/main/scripts/install.sh | bash
#
# Or if you already cloned:
#   bash scripts/install.sh
#
# What this script does:
#   1. Removes snap Docker and old docker-compose v1 (if present)
#   2. Installs Docker Engine from Docker's official repo
#   3. Installs Docker Compose v2 plugin
#   4. Adds the current user to the docker group
#   5. Clones Culvert (if not already in the repo)
#   6. Starts all services with docker compose up -d --build
#
# Requirements: Ubuntu 20.04+ or Debian 11+, sudo access, internet connection
# Tested on: Ubuntu 22.04, 24.04

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
# Pre-flight checks
###############################################################################
step "Pre-flight checks"

# Must be Linux
[[ "$(uname -s)" == "Linux" ]] || error "This script is for Linux only."

# Must have sudo
if ! sudo -n true 2>/dev/null; then
  warn "sudo access required. You may be prompted for your password."
fi

# Check internet
if ! curl -fsSL --connect-timeout 5 https://download.docker.com > /dev/null 2>&1; then
  if ! wget -q --timeout=5 -O /dev/null https://download.docker.com 2>/dev/null; then
    error "No internet connection. Cannot reach download.docker.com"
  fi
fi
info "Internet connectivity OK"

###############################################################################
# 1. Clean up conflicting Docker installations
###############################################################################
step "Cleaning up old Docker installations"

# Remove snap Docker (causes permission errors and no-new-privileges bugs)
if snap list docker 2>/dev/null | grep -q docker; then
  info "Removing snap Docker (known to cause permission issues)..."
  sudo snap remove docker 2>/dev/null || true
  hash -r
else
  info "No snap Docker found"
fi

# Remove old docker-compose v1 (Python-based, incompatible with newer engines)
if dpkg -l docker-compose 2>/dev/null | grep -q "^ii"; then
  info "Removing old docker-compose v1..."
  sudo apt-get remove -y docker-compose 2>/dev/null || true
fi

# Remove Ubuntu's docker.io if present (we'll install Docker's official packages)
for pkg in docker.io containerd runc; do
  if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
    info "Removing $pkg..."
    sudo apt-get remove -y "$pkg" 2>/dev/null || true
  fi
done

###############################################################################
# 2. Install Docker Engine (official repo)
###############################################################################
step "Installing Docker Engine"

if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
  info "Docker with Compose v2 already installed: $(docker --version)"
else
  info "Installing from Docker's official repository..."

  # Install prerequisites
  sudo apt-get update -qq
  sudo apt-get install -y -qq ca-certificates curl gnupg >/dev/null

  # Add Docker's GPG key
  sudo install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
  fi

  # Detect distro (Ubuntu or Debian)
  . /etc/os-release
  DISTRO="${ID}"
  if [[ "$DISTRO" != "ubuntu" && "$DISTRO" != "debian" ]]; then
    warn "Detected $DISTRO — trying Ubuntu repo as fallback"
    DISTRO="ubuntu"
  fi

  # Add Docker's apt repo
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO} ${VERSION_CODENAME} stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  # Install Docker + Compose plugin
  sudo apt-get update -qq
  sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null

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

# Verify Docker works
if sudo docker info &>/dev/null; then
  info "Docker engine is running"
else
  error "Docker engine failed to start. Check: sudo systemctl status docker"
fi

###############################################################################
# 4. Clone Culvert (if not already in the repo)
###############################################################################
step "Setting up Culvert"

# Check if we're already inside the Culvert repo
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
# 5. Build and start
###############################################################################
step "Building and starting Culvert"

info "This will take a few minutes on first run (downloading Go, compiling, GeoIP DB)..."
sudo docker compose up -d --build

###############################################################################
# 6. Wait for health checks
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
echo "  Default login: admin / admin (change this immediately!)"
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
