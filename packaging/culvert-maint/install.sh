#!/bin/sh
# Culvert Maintenance Agent — manual install (D1.6a)
#
# This is the documented manual install path for D1.6a. Packaging
# (.deb / .rpm) is deferred until the agent contract has stabilized
# through D1.6b/c. See roadmap/D1.6-maintenance-agent-implementation-
# plan.md § 1.1.
#
# Run as root. Idempotent: re-running upgrades the binary and unit
# in place; will not clobber a hand-edited /etc/culvert-maint/config.toml
# or /etc/sudoers.d/culvert-maint.
#
# Usage:
#   sudo ./install.sh /path/to/culvert-maint
#
# Where the argument is the path to the freshly-built `culvert-maint`
# binary. Build it with:
#   (cd cmd/culvert-maint && go build -o culvert-maint .)

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must be run as root" >&2
    exit 1
fi

if [ "${1:-}" = "" ]; then
    echo "usage: $0 /path/to/culvert-maint-binary" >&2
    exit 1
fi

BIN_SRC=$1
if [ ! -x "$BIN_SRC" ]; then
    echo "install.sh: binary $BIN_SRC is not executable" >&2
    exit 1
fi

# Resolve the directory of this script so we can locate the sibling
# packaging files regardless of where the operator runs us from.
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
SYSTEMD_UNIT="$SCRIPT_DIR/../systemd/culvert-maint.service"
SUDOERS_TEMPLATE="$SCRIPT_DIR/../sudoers/culvert-maint"
CONFIG_TEMPLATE="$SCRIPT_DIR/config.example.toml"

for f in "$SYSTEMD_UNIT" "$SUDOERS_TEMPLATE" "$CONFIG_TEMPLATE"; do
    if [ ! -f "$f" ]; then
        echo "install.sh: missing packaging file: $f" >&2
        exit 1
    fi
done

# 1. Service account (idempotent — getent gates).
if ! getent group culvert-maint >/dev/null; then
    groupadd --system culvert-maint
    echo "install.sh: created group culvert-maint"
fi
if ! getent passwd culvert-maint >/dev/null; then
    useradd --system --gid culvert-maint \
            --home-dir /var/lib/culvert-maint \
            --shell /sbin/nologin \
            culvert-maint
    echo "install.sh: created user culvert-maint"
fi

# 2. Binary.
install -m 0755 -o root -g root "$BIN_SRC" /usr/local/bin/culvert-maint
echo "install.sh: installed /usr/local/bin/culvert-maint"

# 3. Config (do not clobber an existing one).
mkdir -p /etc/culvert-maint
chown root:culvert-maint /etc/culvert-maint
chmod 0750 /etc/culvert-maint
if [ ! -f /etc/culvert-maint/config.toml ]; then
    install -m 0640 -o root -g culvert-maint \
        "$CONFIG_TEMPLATE" /etc/culvert-maint/config.toml
    echo "install.sh: installed default /etc/culvert-maint/config.toml — review before starting"
else
    echo "install.sh: /etc/culvert-maint/config.toml already exists; left unchanged"
fi

# 4. Sudoers (do not clobber). Caller is expected to edit
# {compose_project_dir} / {compose_file} placeholders before installing
# in production.
if [ ! -f /etc/sudoers.d/culvert-maint ]; then
    install -m 0440 -o root -g root \
        "$SUDOERS_TEMPLATE" /etc/sudoers.d/culvert-maint
    echo "install.sh: installed /etc/sudoers.d/culvert-maint — edit placeholders, then 'visudo -c'"
else
    echo "install.sh: /etc/sudoers.d/culvert-maint already exists; left unchanged"
fi

# 5. State dir.
install -m 0750 -o culvert-maint -g culvert-maint -d /var/lib/culvert-maint
install -m 0750 -o culvert-maint -g culvert-maint -d /var/lib/culvert-maint/operations
echo "install.sh: prepared /var/lib/culvert-maint"

# 6. Systemd unit.
install -m 0644 -o root -g root "$SYSTEMD_UNIT" /etc/systemd/system/culvert-maint.service
systemctl daemon-reload
echo "install.sh: installed /etc/systemd/system/culvert-maint.service"

cat <<EOF
install.sh: install complete.

Next steps:
  1. Review /etc/culvert-maint/config.toml (especially compose_project_dir).
  2. Edit /etc/sudoers.d/culvert-maint and replace {compose_file} with
     your actual compose filename (typically docker-compose.yml).
  3. Validate the sudoers file:    visudo -c -f /etc/sudoers.d/culvert-maint
  4. Edit /etc/systemd/system/culvert-maint.service to set --allow-peers
     to the CP service-account UID or username.
  5. Start the agent:                systemctl start culvert-maint
  6. Tail the journal for errors:    journalctl -u culvert-maint -f
  7. Smoke test (as the allowed CP user):
        curl --unix-socket /run/culvert-maint.sock http://localhost/v1/health
EOF
