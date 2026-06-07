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

# proxy_repo (P1.4): the repository the sudoers `docker pull`/`docker tag`
# entries bind to. Rendered into {proxy_repo} below, exactly like
# {compose_path}. Default mirrors the Go config default + the canonical
# image_allowlist repo.
PROXY_REPO=$(extract_toml_string proxy_repo || true)
[ -z "$PROXY_REPO" ] && PROXY_REPO=ghcr.io/kidcarmi/culvert
IMAGE_ALLOWLIST=$(extract_toml_string image_allowlist || true)

# --- Validate proxy_repo ------------------------------------------------
# Bare repository only: no @digest, no whitespace/quotes/control chars. It
# is substituted into the sudoers allowlist pattern, so a malformed value
# must never reach the rendered file.
case "$PROXY_REPO" in
    *@* | *'sha256:'* )
        echo "install.sh: ERROR — proxy_repo must be a bare repository (no @digest/tag), got '$PROXY_REPO'" >&2
        exit 1
        ;;
esac
case "$PROXY_REPO" in
    *[[:cntrl:]]* | *' '* | *'	'* | *'"'* | *"'"* | *'|'* )
        echo "install.sh: ERROR — proxy_repo contains whitespace/quotes/control chars: '$PROXY_REPO'" >&2
        exit 1
        ;;
esac
# Consistency with image_allowlist (P1.4 §3.1): proxy_repo and the allowlist
# MUST describe the same repository. Heuristic: the allowlist regex (with its
# backslash escapes stripped) must contain the proxy_repo literal. Only
# enforced when image_allowlist is explicitly set; an empty value means the
# Go default is used, which already matches the proxy_repo default.
if [ -n "$IMAGE_ALLOWLIST" ]; then
    AL_NORM=$(printf '%s' "$IMAGE_ALLOWLIST" | sed 's/\\//g')
    case "$AL_NORM" in
        *"$PROXY_REPO"*) : ;;
        *)
            echo "install.sh: ERROR — proxy_repo '$PROXY_REPO' is not referenced by image_allowlist." >&2
            echo "install.sh: they MUST describe the same repository (P1.4). Reconcile config.toml and re-run." >&2
            exit 1
            ;;
    esac
fi

# --- Validate compose_project_dir ---------------------------------------
# The Go side (internal/config) already enforces these on agent start;
# we re-validate here because the sudoers entry is rendered BEFORE the
# agent runs. A malformed value at this stage would either fail visudo -c
# or produce an allowlist line that does not match real invocations.
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
# Reject control characters / whitespace / quotes that would break sudoers
# grammar or sed substitution. POSIX [:cntrl:] covers \0..\x1f and \x7f.
case "$PROJECT_DIR" in
    *[[:cntrl:]]* | *' '* | *'	'* | *'"'* | *"'"* )
        echo "install.sh: ERROR — compose_project_dir contains whitespace/quotes/control chars: '$PROJECT_DIR'" >&2
        exit 1
        ;;
esac

# --- Validate compose_file ---------------------------------------------
# Must be a bare filename (no slashes, no backslash, not "." or "..").
# This is the same shape the Go config validator enforces; we mirror it
# here so the rendered sudoers line can never contain a path-traversal
# component or a directory prefix.
case "$COMPOSE_FILE" in
    "." | ".." )
        echo "install.sh: ERROR — compose_file must not be '.' or '..', got '$COMPOSE_FILE'" >&2
        exit 1
        ;;
    */* | *\\* )
        echo "install.sh: ERROR — compose_file must be a bare filename (no slash or backslash), got '$COMPOSE_FILE'" >&2
        exit 1
        ;;
esac
case "$COMPOSE_FILE" in
    *[[:cntrl:]]* | *' '* | *'	'* | *'"'* | *"'"* )
        echo "install.sh: ERROR — compose_file contains whitespace/quotes/control chars: '$COMPOSE_FILE'" >&2
        exit 1
        ;;
esac

# --- Seed the fixed pinned image tag (P1.4) — BEFORE flipping the boundary --
# The compose file resolves `image: culvert/proxy:pinned` (no env var). That
# LOCAL tag must exist before the next `docker compose up`, or the stack
# fails with "no such image". We seed it FIRST — before the new sudoers
# (which drops the old `pull proxy`/CULVERT_PROXY_IMAGE env_keep path) is
# installed — so a seed failure aborts the install with the OLD, working
# sudo path still in place (the reviewer's "keep the old path until the swap
# succeeds"). An existing install MUST seed from the CURRENTLY-RUNNING digest
# (so the pinned tag matches the live daemon) via CULVERT_PROXY_SEED_REF; see
# roadmap/D1.6c-pin-value-binding-plan.md §8 for the full ordering.
PINNED_TAG="culvert/proxy:pinned"
if docker image inspect "$PINNED_TAG" >/dev/null 2>&1; then
    echo "install.sh: $PINNED_TAG already present; not reseeding"
else
    # Seed source precedence:
    #   1. CULVERT_PROXY_SEED_REF — operator-supplied (e.g. the running
    #      digest captured during an existing-install migration).
    #   2. ${PROXY_REPO}:latest    — fresh-install bootstrap.
    SEED_REF="${CULVERT_PROXY_SEED_REF:-$PROXY_REPO:latest}"
    echo "install.sh: seeding $PINNED_TAG from $SEED_REF ..."
    if docker pull "$SEED_REF" && docker tag "$SEED_REF" "$PINNED_TAG"; then
        echo "install.sh: seeded $PINNED_TAG"
    else
        echo "install.sh: ERROR — could not seed $PINNED_TAG from $SEED_REF." >&2
        echo "install.sh: aborting BEFORE installing the new sudoers, so the existing" >&2
        echo "install.sh: image apply/rollback path keeps working. Seed it, then re-run:" >&2
        echo "install.sh:   docker tag <repo>@sha256:<running-digest> $PINNED_TAG   # existing install" >&2
        echo "install.sh: or set CULVERT_PROXY_SEED_REF and re-run. See the migration plan §8." >&2
        exit 1
    fi
fi

COMPOSE_PATH="$PROJECT_DIR/$COMPOSE_FILE"
RENDERED_SUDOERS=$(mktemp)
trap 'rm -f "$RENDERED_SUDOERS"' EXIT

# Escape characters that are special on the REPLACEMENT side of `sed s|…|…|`:
#   \   — literal backslash
#   &   — replaced with the entire match
#   |   — our chosen delimiter
# Order matters: backslash MUST be escaped first so we don't double-escape
# the escapes we add for & and |. We deliberately do NOT escape `/` because
# the delimiter is `|`, not `/`.
ESCAPED_PATH=$(printf '%s' "$COMPOSE_PATH" \
    | sed -e 's/\\/\\\\/g' -e 's/&/\\&/g' -e 's/|/\\|/g')
ESCAPED_REPO=$(printf '%s' "$PROXY_REPO" \
    | sed -e 's/\\/\\\\/g' -e 's/&/\\&/g' -e 's/|/\\|/g')

# Substitute {compose_path} and {proxy_repo}. `sed` with a non-/ delimiter
# accommodates path/registry slashes.
sed -e "s|{compose_path}|$ESCAPED_PATH|g" \
    -e "s|{proxy_repo}|$ESCAPED_REPO|g" \
    "$SUDOERS_TEMPLATE" > "$RENDERED_SUDOERS"

# Refuse to install a sudoers file with leftover placeholders.
if grep -q '{compose_path}\|{compose_file}\|{compose_project_dir}\|{proxy_repo}' "$RENDERED_SUDOERS"; then
    echo "install.sh: ERROR — rendered sudoers file still contains placeholders:" >&2
    grep -nE '\{compose_|\{proxy_repo\}' "$RENDERED_SUDOERS" >&2
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
Proxy repo bound in sudoers pull/tag allowlist (P1.4):
  $PROXY_REPO   →  retagged locally as culvert/proxy:pinned

Next steps:
  1. Review /etc/culvert-maint/config.toml — particularly:
     - compose_project_dir
     - compose_file
     - proxy_repo            (MUST match image_allowlist's repository)
     - allow_peers           (the CP UID or username allowlist)
     - privilege_mode        (sudoers is the production default)
     Ensure docker-compose.yml uses 'image: culvert/proxy:pinned' for the
     proxy and cli services (P1.4); this install seeded that local tag.
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
