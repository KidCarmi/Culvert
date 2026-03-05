#!/usr/bin/env bash
# install-runner.sh — set up a GitHub Actions self-hosted runner for ProxyShield CI
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/KidCarmi/Claude-Test/main/scripts/install-runner.sh | bash
#   # or clone the repo and run:
#   bash scripts/install-runner.sh
#
# What this script does:
#   1. Installs Docker (if not already present)
#   2. Adds the current user to the docker group (fixes socket permission errors)
#   3. Downloads and configures the GitHub Actions runner
#   4. Installs the runner as a systemd service
#
# Requirements: Ubuntu/Debian 20.04+, sudo access
# After running: log out and back in (or run `newgrp docker`) to apply group changes.

set -euo pipefail

###############################################################################
# Config — edit these before running, or pass as env vars
###############################################################################
GITHUB_OWNER="${GITHUB_OWNER:-KidCarmi}"
GITHUB_REPO="${GITHUB_REPO:-Claude-Test}"
RUNNER_TOKEN="${RUNNER_TOKEN:-}"          # required: get from Settings → Actions → Runners → New
RUNNER_NAME="${RUNNER_NAME:-$(hostname)}"
RUNNER_LABELS="${RUNNER_LABELS:-self-hosted,linux,x64}"
RUNNER_VERSION="${RUNNER_VERSION:-2.322.0}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/actions-runner}"

###############################################################################
# Helpers
###############################################################################
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

require_cmd() { command -v "$1" &>/dev/null || error "'$1' not found. Install it first."; }

###############################################################################
# 0. Validate runner token
###############################################################################
if [[ -z "$RUNNER_TOKEN" ]]; then
  echo ""
  echo "  A runner registration token is required."
  echo ""
  echo "  Get one at:"
  echo "    https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/settings/actions/runners/new"
  echo ""
  read -rp "  Paste the token here: " RUNNER_TOKEN
  [[ -z "$RUNNER_TOKEN" ]] && error "Token cannot be empty."
fi

###############################################################################
# 1. Install Docker (skip if already installed)
###############################################################################
if command -v docker &>/dev/null; then
  info "Docker already installed: $(docker --version)"
else
  info "Installing Docker..."
  require_cmd curl
  curl -fsSL https://get.docker.com | sudo sh
  info "Docker installed: $(docker --version)"
fi

###############################################################################
# 2. Add current user to the docker group
#    This is the most common cause of CI failures on self-hosted runners:
#    "permission denied while trying to connect to the Docker daemon socket"
###############################################################################
CURRENT_USER="$(id -un)"
if groups "$CURRENT_USER" | grep -qw docker; then
  info "User '$CURRENT_USER' is already in the docker group."
else
  info "Adding user '$CURRENT_USER' to the docker group..."
  sudo usermod -aG docker "$CURRENT_USER"
  warn "Group change will take effect after you log out and back in."
  warn "To apply immediately in this session, run: newgrp docker"
fi

###############################################################################
# 3. Download the GitHub Actions runner
###############################################################################
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  RUNNER_ARCH="x64"   ;;
  aarch64) RUNNER_ARCH="arm64" ;;
  armv7l)  RUNNER_ARCH="arm"   ;;
  *)       error "Unsupported architecture: $ARCH" ;;
esac

RUNNER_PKG="actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_PKG}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [[ -f "./config.sh" ]]; then
  info "Runner binary already present in $INSTALL_DIR, skipping download."
else
  info "Downloading GitHub Actions runner ${RUNNER_VERSION} (${RUNNER_ARCH})..."
  curl -fsSL -o "$RUNNER_PKG" "$RUNNER_URL"
  tar xzf "$RUNNER_PKG"
  rm -f "$RUNNER_PKG"
  info "Runner extracted to $INSTALL_DIR"
fi

###############################################################################
# 4. Configure the runner
###############################################################################
REPO_URL="https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}"

info "Configuring runner '${RUNNER_NAME}' for ${REPO_URL}..."
./config.sh \
  --url "$REPO_URL" \
  --token "$RUNNER_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "$RUNNER_LABELS" \
  --work "_work" \
  --unattended \
  --replace

###############################################################################
# 5. Install as a systemd service (runs as current user)
###############################################################################
if systemctl is-enabled "actions.runner.${GITHUB_OWNER}-${GITHUB_REPO}.${RUNNER_NAME}.service" &>/dev/null 2>&1; then
  info "Systemd service already installed."
else
  info "Installing runner as a systemd service..."
  sudo ./svc.sh install "$CURRENT_USER"
fi

info "Starting the runner service..."
sudo ./svc.sh start

###############################################################################
# 6. Verify Docker access
###############################################################################
info "Verifying Docker access..."
# Use sg to run docker in the new group without requiring re-login
if sg docker -c "docker info" &>/dev/null; then
  info "Docker access confirmed."
else
  warn "Docker access check failed. You may need to log out and back in."
  warn "After re-login, restart the runner service:"
  warn "  cd ${INSTALL_DIR} && sudo ./svc.sh restart"
fi

###############################################################################
# Done
###############################################################################
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  Runner '${RUNNER_NAME}' installed and running!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  Repo:    ${REPO_URL}"
echo "  Labels:  ${RUNNER_LABELS}"
echo "  Dir:     ${INSTALL_DIR}"
echo ""
echo "  Useful commands:"
echo "    sudo ${INSTALL_DIR}/svc.sh status   # check service status"
echo "    sudo ${INSTALL_DIR}/svc.sh stop     # stop the runner"
echo "    sudo ${INSTALL_DIR}/svc.sh start    # start the runner"
echo "    sudo ${INSTALL_DIR}/svc.sh uninstall # remove the service"
echo ""
if ! groups "$CURRENT_USER" | grep -qw docker || ! docker info &>/dev/null 2>&1; then
  echo -e "${YELLOW}  ACTION REQUIRED:${NC}"
  echo "    Log out and back in (or open a new terminal) to apply"
  echo "    the docker group membership, then restart the service:"
  echo "      sudo ${INSTALL_DIR}/svc.sh restart"
  echo ""
fi
