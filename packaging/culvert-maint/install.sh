#!/bin/sh
# Culvert Maintenance Agent — manual install (D1.6a)
#
# This is the documented manual install path for D1.6a. Packaging
# (.deb / .rpm) is deferred until the agent contract has stabilized
# through D1.6b/c. See roadmap/D1.6-maintenance-agent-implementation-
# plan.md § 1.1.
#
# Run as root. Idempotent: re-running upgrades the binary and unit
# in place; will not clobber a hand-edited /etc/culvert-maint/config.toml.
#
# Usage:
#   sudo ./install.sh /path/to/culvert-maint
#
# Where the argument is the path to the freshly-built `culvert-maint`
# binary. Build it with:
#   (cd cmd/culvert-maint && go build -o culvert-maint .)
#
# What this script does (in order):
#   1. Creates the culvert-maint system user and group (idempotent).
#   2. Installs the binary at /usr/local/bin/culvert-maint.
#   3. Installs /etc/culvert-maint/config.toml from the example
#      (only if not already present — operator edits survive).
#   4. RENDERS /etc/sudoers.d/culvert-maint with the FULL compose
#      path resolved from compose_project_dir + compose_file in
#      config.toml. The shipped template uses a {compose_path}
#      placeholder; this script substitutes it. Refuses to install
#      a sudoers file that still contains placeholders.
#   5. Validates the rendered sudoers with `visudo -c`. Fails the
#      install if validation fails.
#   6. Prepares /var/lib/culvert-maint and operations/ subdir.
#   7. Installs the systemd unit and reloads systemd.
#
# The sudoers file MUST be path-bound to the absolute compose path —
# sudo's exact-arg matching does not honor cwd. This script enforces
# that by reading compose_project_dir + compose_file from config.toml
# at install time and rendering the path into the allowlist line.

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

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
SYSTEMD_UNIT="$SCRIPT_DIR/../systemd/culvert-maint.service"
SUDOERS_TEMPLATE="$SCRIPT_DIR/../sudoers/culvert-maint"
CONFIG_TEMPLATE="$SCRIPT_DIR/config.example.toml"
CONFIG_DEST=/etc/culvert-maint/config.toml
SUDOERS_DEST=/etc/sudoers.d/culvert-maint

for f in "$SYSTEMD_UNIT" "$SUDOERS_TEMPLATE" "$CONFIG_TEMPLATE"; do
    if [ ! -f "$f" ]; then
        echo "install.sh: missing packaging file: $f" >&2
        exit 1
    fi
done

# 1. Service account.
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
if [ ! -f "$CONFIG_DEST" ]; then
    install -m 0640 -o root -g culvert-maint "$CONFIG_TEMPLATE" "$CONFIG_DEST"
    echo "install.sh: installed default $CONFIG_DEST — edit before starting (especially compose_project_dir + allow_peers)"
else
    echo "install.sh: $CONFIG_DEST already exists; left unchanged"
fi

# 4. Resolve compose path from config.toml and render sudoers.
extract_toml_string() {
    # Reads /etc/culvert-maint/config.toml and prints the value of the
    # given basic-string key. Strips quotes and surrounding whitespace.
    # Accepts:    key = "value"      key   =   "value"
    # Tolerates leading whitespace; ignores commented lines.
    key=$1
    awk -v k="$key" '
        BEGIN { FS="=" }
        /^[[:space:]]*#/ { next }
        $0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
            v=$2
            sub(/^[[:space:]]*"/,"",v)
            sub(/"[[:space:]]*$/,"",v)
            print v
            exit
        }
    ' "$CONFIG_DEST"
}

PROJECT_DIR=$(extract_toml_string compose_project_dir || true)
COMPOSE_FILE=$(extract_toml_string compose_file || true)
[ -z "$COMPOSE_FILE" ] && COMPOSE_FILE=docker-compose.yml

if [ -z "$PROJECT_DIR" ]; then
    echo "install.sh: ERROR — compose_project_dir not found in $CONFIG_DEST" >&2
    echo "install.sh: edit $CONFIG_DEST first, then re-run install.sh" >&2
    exit 1
fi
case "$PROJECT_DIR" in
    /*) : ;;
    *)
        echo "install.sh: ERROR — compose_project_dir must be absolute, got '$PROJECT_DIR'" >&2
        exit 1
        ;;
esac

COMPOSE_PATH="$PROJECT_DIR/$COMPOSE_FILE"
RENDERED_SUDOERS=$(mktemp)
trap 'rm -f "$RENDERED_SUDOERS"' EXIT

# Substitute {compose_path} with the resolved absolute path.
# `sed` with a non-/ delimiter accommodates path slashes.
sed "s|{compose_path}|$COMPOSE_PATH|g" "$SUDOERS_TEMPLATE" > "$RENDERED_SUDOERS"

# Refuse to install a sudoers file with leftover placeholders.
if grep -q '{compose_path}\|{compose_file}\|{compose_project_dir}' "$RENDERED_SUDOERS"; then
    echo "install.sh: ERROR — rendered sudoers file still contains placeholders:" >&2
    grep -n '{compose_' "$RENDERED_SUDOERS" >&2
    exit 1
fi

# Validate the rendered sudoers grammar BEFORE moving it into /etc.
if ! visudo -c -f "$RENDERED_SUDOERS" >/dev/null; then
    echo "install.sh: ERROR — rendered sudoers failed visudo -c validation" >&2
    cat "$RENDERED_SUDOERS" >&2
    exit 1
fi

install -m 0440 -o root -g root "$RENDERED_SUDOERS" "$SUDOERS_DEST"
echo "install.sh: rendered + installed $SUDOERS_DEST (compose_path=$COMPOSE_PATH)"

# Re-validate the file in its installed location for good measure.
if ! visudo -c -f "$SUDOERS_DEST" >/dev/null; then
    echo "install.sh: ERROR — installed $SUDOERS_DEST failed visudo -c (rolling back)" >&2
    rm -f "$SUDOERS_DEST"
    exit 1
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

Compose path bound in sudoers allowlist:
  $COMPOSE_PATH

Next steps:
  1. Review /etc/culvert-maint/config.toml — particularly:
     - compose_project_dir
     - compose_file
     - allow_peers           (the CP UID or username allowlist)
     - privilege_mode        (sudoers is the production default)
  2. Confirm the user(s) in allow_peers exist on the host — the agent
     will fail to start otherwise.
  3. Start the agent:                systemctl start culvert-maint
  4. Tail the journal for errors:    journalctl -u culvert-maint -f
  5. Smoke test (as the allowed CP user):
        curl --unix-socket /run/culvert-maint.sock http://localhost/v1/health

If you change compose_project_dir or compose_file later, re-run this
script — it will re-render and re-install the sudoers file with the
new path.
EOF
