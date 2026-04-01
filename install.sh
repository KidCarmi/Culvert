#!/usr/bin/env bash
# Culvert — one-shot installer
# Usage: curl -sSL <url>/install.sh | bash
#        or: bash install.sh [--port 8080] [--ui-port 9090] [--config /etc/culvert/config.yaml]
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[Culvert]${NC} $*"; }
warn()  { echo -e "${YELLOW}[Culvert]${NC} $*"; }
die()   { echo -e "${RED}[Culvert] ERROR:${NC} $*" >&2; exit 1; }

# ── Defaults ─────────────────────────────────────────────────────────────────
PROXY_PORT=8080
UI_PORT=9090
INSTALL_DIR="/opt/culvert"
DATA_DIR="/var/lib/culvert"
CONFIG_FILE="$INSTALL_DIR/config.yaml"
SERVICE_NAME="culvert"
BINARY="$INSTALL_DIR/culvert"

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)      PROXY_PORT="$2";   shift 2 ;;
    --ui-port)   UI_PORT="$2";      shift 2 ;;
    --config)    CONFIG_FILE="$2";  shift 2 ;;
    --dir)       INSTALL_DIR="$2";  shift 2 ;;
    --data)      DATA_DIR="$2";     shift 2 ;;
    *) die "Unknown option: $1" ;;
  esac
done

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"

# ── OS / arch detection ───────────────────────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac
[[ "$OS" == "linux" ]] || die "Unsupported OS: $OS (Linux only)"

# ── Detect init system ────────────────────────────────────────────────────────
INIT_SYSTEM=""
if command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
  INIT_SYSTEM="systemd"
elif [[ -f /etc/init.d/cron ]] || command -v service &>/dev/null; then
  INIT_SYSTEM="sysv"
fi

# ── Directories ───────────────────────────────────────────────────────────────
info "Creating directories..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR"

# ── Build or download binary ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/main.go" ]]; then
  info "Building from source..."
  command -v go &>/dev/null || die "Go not found. Install from https://golang.org/dl/"
  (cd "$SCRIPT_DIR" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BINARY" .) \
    || die "Build failed"
  info "Binary built: $BINARY"
else
  die "Source not found. Clone the repository first:\n  git clone https://github.com/KidCarmi/Claude-Test.git && cd Claude-Test && sudo bash install.sh"
fi

# ── Passphrase management (fully automatic — user never sees this) ────────────
# A random 32-byte passphrase is generated once and stored in a root-only file.
# It is loaded from there on every start — no manual export needed.
PASSPHRASE_FILE="$DATA_DIR/.ca_passphrase"
CA_BUNDLE="$DATA_DIR/ca.bundle"

if [[ ! -f "$PASSPHRASE_FILE" ]]; then
  info "Generating CA encryption passphrase..."
  # 32 random bytes → hex string (64 chars) — stored at 0600
  head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n' > "$PASSPHRASE_FILE"
  chmod 0600 "$PASSPHRASE_FILE"
  info "Passphrase stored at $PASSPHRASE_FILE (root-only, never shown)"
fi

# ── Default config ────────────────────────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
  info "Writing default config to $CONFIG_FILE..."
  cat > "$CONFIG_FILE" <<EOF
proxy:
  port: $PROXY_PORT
  ui_port: $UI_PORT
  ca_path: $CA_BUNDLE
  # IMPORTANT: policy_file persists your policy rules across restarts.
  # Without this, all rules are lost when the process restarts.
  policy_file: $DATA_DIR/policy.json
  log_file: /var/log/culvert/access.log
  log_max_mb: 100

# Admin credentials are set via the first-time setup wizard in the Web UI.
# Alternatively, uncomment and set them here:
# auth:
#   user: admin
#   pass: changeme

# Uncomment to enable IP allowlist:
# security:
#   ip_filter_mode: allow
#   ip_list:
#     - 10.0.0.0/8
#     - 192.168.0.0/16

log_format: json
EOF
fi

mkdir -p /var/log/culvert
chmod 755 /var/log/culvert

# ── systemd service ───────────────────────────────────────────────────────────
if [[ "$INIT_SYSTEM" == "systemd" ]]; then
  info "Installing systemd service..."
  cat > /etc/systemd/system/"$SERVICE_NAME".service <<EOF
[Unit]
Description=Culvert Secure Web Gateway
After=network.target
Documentation=https://github.com/KidCarmi/Claude-Test

[Service]
Type=simple
User=root
EnvironmentFile=-$PASSPHRASE_FILE
# The passphrase is loaded from $PASSPHRASE_FILE and passed via env var.
# It is never visible in 'ps' output or shell history.
ExecStartPre=/bin/bash -c 'export CULVERT_CA_PASSPHRASE=\$(cat $PASSPHRASE_FILE)'
ExecStart=/bin/bash -c 'CULVERT_CA_PASSPHRASE=\$(cat $PASSPHRASE_FILE) exec $BINARY -config $CONFIG_FILE'
Restart=on-failure
RestartSec=5
# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$DATA_DIR /var/log/culvert
PrivateTmp=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"

  sleep 2
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "Service started successfully ✓"
  else
    warn "Service may not have started. Check: journalctl -u $SERVICE_NAME -n 50"
  fi

# ── SysV / manual start ───────────────────────────────────────────────────────
else
  warn "systemd not detected — creating start/stop scripts..."
  cat > "$INSTALL_DIR/start.sh" <<EOF
#!/bin/bash
CULVERT_CA_PASSPHRASE=\$(cat $PASSPHRASE_FILE) \\
  $BINARY -config $CONFIG_FILE &
echo \$! > $DATA_DIR/culvert.pid
echo "Culvert started (PID \$(cat $DATA_DIR/culvert.pid))"
EOF
  cat > "$INSTALL_DIR/stop.sh" <<EOF
#!/bin/bash
kill \$(cat $DATA_DIR/culvert.pid 2>/dev/null) 2>/dev/null && echo "Stopped" || echo "Not running"
EOF
  chmod +x "$INSTALL_DIR/start.sh" "$INSTALL_DIR/stop.sh"
  bash "$INSTALL_DIR/start.sh"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
info ""
info "╔══════════════════════════════════════════════════════╗"
info "║           Culvert installed successfully          ║"
info "╠══════════════════════════════════════════════════════╣"
info "║  Proxy  → http://$(hostname -I | awk '{print $1}'):$PROXY_PORT                    ║"
info "║  Web UI → https://$(hostname -I | awk '{print $1}'):$UI_PORT                   ║"
info "║  Config → $CONFIG_FILE"
info "║  Logs   → /var/log/culvert/access.log            ║"
info "╚══════════════════════════════════════════════════════╝"
info ""
info "First-time setup:"
info "  Open the Web UI — you will be prompted to set an admin password."
info ""
info "Configure your browser/system proxy:"
info "  HTTP/HTTPS Proxy: $(hostname -I | awk '{print $1}'):$PROXY_PORT"
info ""
info "Download the CA cert (for HTTPS inspection):"
info "  https://$(hostname -I | awk '{print $1}'):$UI_PORT/api/ca-cert"
