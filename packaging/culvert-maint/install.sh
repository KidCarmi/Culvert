#!/bin/sh
# Culvert Maintenance Agent — manual install (D1.6a)
#
# Documented manual install path for D1.6a. Packaging (.deb / .rpm) is
# deferred until the agent contract stabilizes through D1.6b/c. See
# roadmap/D1.6-maintenance-agent-implementation-plan.md § 1.1.
#
# Run as root. Idempotent: re-running upgrades the binary, sudoers, and
# unit in place; a hand-edited /etc/culvert-maint/config.toml is never
# clobbered.
#
# Usage:
#   sudo ./install.sh /path/to/culvert-maint
#
# The argument is the freshly-built `culvert-maint` binary. Build it with:
#   (cd cmd/culvert-maint && go build -o culvert-maint .)
#
# Steps, in order:
#   1. Pre-flight: root check, required commands, docker daemon reachable.
#   2. Create the culvert-maint system user and group (idempotent).
#   3. Install the binary at /usr/local/bin/culvert-maint.
#   4. Install /etc/culvert-maint/config.toml from the example (only if
#      absent — operator edits survive).
#   5. Read compose_project_dir / compose_file / proxy_repo from the
#      config, validate them, and (P1.4) seed the fixed local image tag
#      culvert/proxy:pinned BEFORE touching sudoers.
#   6. Render /etc/sudoers.d/culvert-maint from the template, reject any
#      leftover placeholder, and validate with `visudo -c` before install.
#   7. Prepare /var/lib/culvert-maint and operations/ subdir.
#   8. Install the systemd unit and reload systemd.
#
# The sudoers file MUST be path-bound to the absolute compose path —
# sudo's exact-arg matching does not honor cwd. This script enforces that
# by rendering compose_project_dir + compose_file into the allowlist line.

set -eu

# ── Helpers ────────────────────────────────────────────────────────────────

log()  { printf 'install.sh: %s\n' "$*"; }
warn() { printf 'install.sh: %s\n' "$*" >&2; }
die()  { printf 'install.sh: ERROR — %s\n' "$*" >&2; exit 1; }

usage() {
    cat >&2 <<EOF
usage: sudo $0 [/path/to/culvert-maint-binary]

Installs the Culvert Maintenance Agent (binary, config, sudoers, systemd
unit). Idempotent. Must run as root.

Binary source (in precedence order):
  1. positional argument          a prebuilt local binary
  2. \$CULVERT_MAINT_BIN            same, via env
  3. signed release download       requires \$CULVERT_MAINT_VERSION=vX.Y.Z
                                   (cosign-verified, fail-closed)

Env knobs:
  CULVERT_MAINT_VERSION        release tag to download (e.g. v1.2.3)
  CULVERT_MAINT_GITHUB_REPO    owner/repo for the release + cosign identity
                               (default KidCarmi/Culvert)
  CULVERT_MAINT_RELEASE_BASE   override the asset base URL
  CULVERT_MAINT_BUNDLE         cosign Sigstore bundle (*.sigstore.json) for
                               verifying a local binary
  CULVERT_MAINT_CERT_IDENTITY  override the expected cosign cert identity
  CULVERT_MAINT_COSIGN_IMAGE   pinned cosign image (default ghcr.io/sigstore/cosign/cosign:v3.0.6;
                               MUST be cosign v3.x to read the new-format bundle —
                               operators who pinned a v2.x DIGEST must re-pin to v3)
  CULVERT_MAINT_SKIP_VERIFY=1  trust a hand-supplied LOCAL binary without
                               verification (never honored on the download path)
EOF
    exit "${1:-1}"
}

# Reject characters that would break sudoers grammar or our sed
# substitution: control chars (\0..\x1f, \x7f), whitespace, quotes, pipe.
reject_unsafe() {
    # $1 = human label, $2 = value
    case "$2" in
        *[[:cntrl:]]* | *' '* | *'	'* | *'"'* | *"'"* | *'|'* )
            die "$1 contains whitespace/quotes/pipe/control chars: '$2'" ;;
    esac
}

# Escape a value for the REPLACEMENT side of `sed s|…|…|`:
#   \  literal backslash   &  whole match   |  our delimiter
# Backslash MUST be escaped first so we don't double-escape what follows.
sed_escape_replacement() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/&/\\&/g' -e 's/|/\\|/g'
}

# Escape sudoers-special colons and commas in a value destined to be a
# LITERAL inside a sudoers command (Cmnd) — sudo treats a bare ':' as the
# Runas/Host separator and a bare ',' as the Cmnd-list separator, so a
# proxy_repo with a registry port (e.g. 127.0.0.1:5000/culvert) or a
# compose_project_dir with a comma (e.g. /srv/culvert,backup — legal on
# Linux) renders an unescaped ':' or ',' that visudo -c rejects with a syntax
# error. The template already hand-escapes its own literal colons (sha256\:,
# culvert/proxy\:pinned); the substituted values must get the same treatment.
# Run this BEFORE sed_escape_replacement so the backslashes it adds are then
# sed-escaped correctly.
sudoers_escape_colon() {
    printf '%s' "$1" | sed -e 's/:/\\:/g' -e 's/,/\\,/g'
}

# Read a TOML basic-string value:  key = "value"  (any leading whitespace,
# any spacing around =). Ignores commented lines. Prints empty if absent.
# Strips everything from the FIRST "=" (not FS="="'s second field) so an "="
# embedded in the value itself is not truncated, and cuts the value at its
# closing quote so a trailing inline "# comment" after the string does not
# leak into the extracted value.
extract_toml_string() {
    awk -v k="$1" '
        /^[[:space:]]*#/ { next }
        $0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
            line=$0
            sub("^[[:space:]]*"k"[[:space:]]*=[[:space:]]*", "", line)
            sub(/^"/, "", line)
            sub(/".*$/, "", line)
            print line
            exit
        }
    ' "$CONFIG_DEST"
}

# check_proxy_repo_matches_allowlist REPO ALLOWLIST — proxy_repo and
# image_allowlist MUST describe the same repository (P1.4 §3.1): a mismatch
# lets install.sh complete successfully while the agent's OWN image_allowlist
# gate (cmd/culvert-maint/internal/config) then rejects every upgrade/rollback
# dispatch forever, silently, because the requested <proxy_repo>@sha256:...
# ref never matches. An empty ALLOWLIST previously SKIPPED this check
# entirely, on the assumption that "empty means the Go default, which matches
# the proxy_repo default" — but that assumption only holds when proxy_repo is
# ALSO left at its default. The common real-world case is the opposite: an
# operator customizes proxy_repo (e.g. a private mirror) and never touches
# image_allowlist, so it silently defaults to a pattern anchored to
# ghcr.io/kidcarmi/culvert that can never match the custom repo. Default an
# empty ALLOWLIST to that same Go-side pattern (config.go's
# defaultImageAllowlist) so the comparison always runs, catching exactly that
# case at install time instead of at every future dispatch.
check_proxy_repo_matches_allowlist() {
    _repo=$1; _allowlist=$2
    if [ -z "$_allowlist" ]; then
        _allowlist='^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$'
    fi
    _al_norm=$(printf '%s' "$_allowlist" | sed 's/\\//g')
    case "$_al_norm" in
        *"$_repo"*) return 0 ;;
    esac
    die "proxy_repo '$_repo' is not referenced by image_allowlist — they MUST describe the same repository (P1.4). Set image_allowlist in config.toml to a pattern matching '$_repo' (an unset image_allowlist defaults to a pattern anchored to ghcr.io/kidcarmi/culvert, which will never match a custom proxy_repo) and re-run."
}

# ── 1. Pre-flight ────────────────────────────────────────────────────────────

case "${1:-}" in
    -h|--help) usage 0 ;;
esac

[ "$(id -u)" -eq 0 ] || die "must be run as root"

# Binary source is OPTIONAL: a positional path takes precedence over the env
# var; when neither is set, the agent is downloaded from the signed release
# (resolved + verified in §1b below, after the temp-cleanup trap is armed).
BIN_ARG=${1:-${CULVERT_MAINT_BIN:-}}

for c in id install useradd groupadd getent awk sed grep mktemp visudo systemctl docker; do
    command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
done

# The image-tag seed (step 5) and any later docker call need a live daemon.
docker info >/dev/null 2>&1 || die "docker daemon is not reachable (is it running, and can root use it?)"

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
SYSTEMD_UNIT="$SCRIPT_DIR/../systemd/culvert-maint.service"
SUDOERS_TEMPLATE="$SCRIPT_DIR/../sudoers/culvert-maint"
CONFIG_TEMPLATE="$SCRIPT_DIR/config.example.toml"
CONFIG_DEST=/etc/culvert-maint/config.toml
SUDOERS_DEST=/etc/sudoers.d/culvert-maint

for f in "$SYSTEMD_UNIT" "$SUDOERS_TEMPLATE" "$CONFIG_TEMPLATE"; do
    [ -f "$f" ] || die "missing packaging file: $f"
done

# Temp paths cleaned up on any exit: the rendered sudoers file and the
# download/verify scratch dirs from §1b. Declared before the trap so `set -u`
# never trips on an unset name inside the handler.
RENDERED_SUDOERS=""
RENDERED_SUDOERS_TMP=""
CLEAN_DL_DIR=""
CLEAN_VERIFY_DIR=""
cleanup() {
    [ -n "$RENDERED_SUDOERS" ] && rm -f "$RENDERED_SUDOERS"
    [ -n "$RENDERED_SUDOERS_TMP" ] && rm -f "$RENDERED_SUDOERS_TMP"
    [ -n "$CLEAN_DL_DIR" ] && rm -rf "$CLEAN_DL_DIR"
    [ -n "$CLEAN_VERIFY_DIR" ] && rm -rf "$CLEAN_VERIFY_DIR"
    return 0
}
trap cleanup EXIT

# ── 1b. Resolve the agent binary: local (positional/env) or download+verify ──
#
# Runs in pre-flight, BEFORE any host mutation (the binary install at §3 and
# the P1.4 pinned-image seed at §5). A download/verify failure therefore aborts
# with the OLD install untouched — never a half-installed state. The download
# path ALWAYS cosign-verifies and FAILS CLOSED; an unverified download is worse
# than a host build, so verification is non-optional there. A locally supplied
# binary is the operator's own artifact: verified against a sibling cosign
# Sigstore bundle (*.sigstore.json, or $CULVERT_MAINT_BUNDLE) when present, or
# trusted with $CULVERT_MAINT_SKIP_VERIFY=1.

CERT_OIDC_ISSUER=${CULVERT_MAINT_CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}
# The cosign verifier image IS the root of trust for the download path. A bare
# tag is mutable; high-assurance / air-gapped operators should override this
# with a digest-pinned ref (ghcr.io/sigstore/cosign/cosign:v3.0.6@sha256:<digest>).
# MUST be cosign v3.x: the release signs with cosign 3.x new-format Sigstore
# bundles, which a v2.x verifier cannot parse — operators who pinned a v2.x
# digest must re-pin to v3.0.6.
COSIGN_IMAGE=${CULVERT_MAINT_COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v3.0.6}
GH_REPO=${CULVERT_MAINT_GITHUB_REPO:-KidCarmi/Culvert}

# Map host arch → release asset arch (matches ci.yml's linux-only legs).
case "$(uname -m)" in
    x86_64|amd64)  ASSET_ARCH=amd64 ;;
    aarch64|arm64) ASSET_ARCH=arm64 ;;
    *) die "unsupported architecture '$(uname -m)' — culvert-maint ships linux/amd64 and linux/arm64 only" ;;
esac

# Default keyless cert identity = the ci.yml release workflow at a given tag.
cert_identity_for() {
    printf 'https://github.com/%s/.github/workflows/ci.yml@refs/tags/%s' "$GH_REPO" "$1"
}

# cosign verify-blob in a pinned container — no host cosign dependency (docker
# is already required for the seed step). $1=dir $2=binary basename $3=identity.
verify_cosign() {
    _dir=$1; _bin=$2; _ident=$3
    [ -f "$_dir/$_bin.sigstore.json" ] || die "missing signature bundle: $_bin.sigstore.json"
    log "verifying $_bin with cosign (identity=$_ident) ..."
    # --user 0:0: the scratch dir is mktemp -d (0700 root); the cosign image
    # defaults to USER nonroot (65532), which could not traverse/read the
    # root-owned mount. The files are root-owned, so run cosign as root.
    # --new-bundle-format is cosign v3's default; passed explicitly to self-
    # document and stay correct if the default ever flips.
    docker run --rm --user 0:0 -v "$_dir:/work:ro" -w /work "$COSIGN_IMAGE" \
        verify-blob \
        --bundle "$_bin.sigstore.json" \
        --new-bundle-format \
        --certificate-identity "$_ident" \
        --certificate-oidc-issuer "$CERT_OIDC_ISSUER" \
        "$_bin" \
        || die "cosign verification FAILED for $_bin — refusing to install"
    log "cosign verification OK for $_bin"
}

if [ -n "${BIN_ARG:-}" ]; then
    # ── Local binary (positional arg or $CULVERT_MAINT_BIN) ───────────────────
    BIN_SRC=$BIN_ARG
    [ -f "$BIN_SRC" ] || die "binary not found: $BIN_SRC"
    [ -x "$BIN_SRC" ] || die "binary is not executable: $BIN_SRC"

    if [ "${CULVERT_MAINT_SKIP_VERIFY:-}" = "1" ]; then
        warn "CULVERT_MAINT_SKIP_VERIFY=1 — installing local binary WITHOUT signature verification"
    else
        _bundle=${CULVERT_MAINT_BUNDLE:-$BIN_SRC.sigstore.json}
        if [ ! -f "$_bundle" ]; then
            die "no signature bundle for '$BIN_SRC' (looked for $_bundle). Supply it, set CULVERT_MAINT_BUNDLE, or set CULVERT_MAINT_SKIP_VERIFY=1 to trust a hand-supplied binary."
        fi
        if [ -n "${CULVERT_MAINT_CERT_IDENTITY:-}" ]; then
            _ident=$CULVERT_MAINT_CERT_IDENTITY
        elif [ -n "${CULVERT_MAINT_VERSION:-}" ]; then
            _ident=$(cert_identity_for "$CULVERT_MAINT_VERSION")
        else
            die "to verify a local binary set CULVERT_MAINT_CERT_IDENTITY (or CULVERT_MAINT_VERSION to derive it), or CULVERT_MAINT_SKIP_VERIFY=1 to trust it"
        fi
        # Stage into a temp dir so cosign resolves the sibling bundle by basename.
        CLEAN_VERIFY_DIR=$(mktemp -d)
        cp "$BIN_SRC"  "$CLEAN_VERIFY_DIR/culvert-maint"
        cp "$_bundle"  "$CLEAN_VERIFY_DIR/culvert-maint.sigstore.json"
        verify_cosign "$CLEAN_VERIFY_DIR" culvert-maint "$_ident"
        # Install the EXACT bytes that just passed cosign, not the original
        # path (which a racing process could swap post-verification).
        BIN_SRC="$CLEAN_VERIFY_DIR/culvert-maint"
    fi
    log "using local agent binary: $BIN_SRC"
else
    # ── Download the signed release asset (always verified, fail-closed) ──────
    VERSION=${CULVERT_MAINT_VERSION:-}
    [ -n "$VERSION" ] || die "no binary given and CULVERT_MAINT_VERSION is unset.
  Pass a prebuilt binary:    sudo $0 /path/to/culvert-maint
  or pin a release to fetch: CULVERT_MAINT_VERSION=vX.Y.Z sudo $0
  (the quick-start scripts/install.sh derives the version from the running proxy.)"
    case "$VERSION" in
        v*) : ;;
        *)  die "CULVERT_MAINT_VERSION must be a release tag like 'v1.2.3', got '$VERSION'" ;;
    esac
    reject_unsafe "CULVERT_MAINT_VERSION" "$VERSION"

    # Pick a download tool (only required on this path — not for local/offline).
    if command -v curl >/dev/null 2>&1; then DL_TOOL=curl
    elif command -v wget >/dev/null 2>&1; then DL_TOOL=wget
    else die "need curl or wget to download the release asset"; fi

    ASSET="culvert-maint-linux-$ASSET_ARCH"
    BASE=${CULVERT_MAINT_RELEASE_BASE:-https://github.com/$GH_REPO/releases/download/$VERSION}
    CLEAN_DL_DIR=$(mktemp -d)
    log "downloading $ASSET ($VERSION) from $BASE ..."
    for f in "$ASSET" "$ASSET.sigstore.json"; do
        if [ "$DL_TOOL" = curl ]; then
            curl -fsSL -o "$CLEAN_DL_DIR/$f" "$BASE/$f" || die "download failed: $BASE/$f"
        else
            wget -q -O "$CLEAN_DL_DIR/$f" "$BASE/$f" || die "download failed: $BASE/$f"
        fi
    done

    _ident=${CULVERT_MAINT_CERT_IDENTITY:-$(cert_identity_for "$VERSION")}
    verify_cosign "$CLEAN_DL_DIR" "$ASSET" "$_ident"

    chmod 0755 "$CLEAN_DL_DIR/$ASSET"
    BIN_SRC="$CLEAN_DL_DIR/$ASSET"
    log "downloaded + verified agent binary: $BIN_SRC"
fi

# ── 2. Service account ───────────────────────────────────────────────────────

if ! getent group culvert-maint >/dev/null; then
    groupadd --system culvert-maint
    log "created group culvert-maint"
fi
if ! getent passwd culvert-maint >/dev/null; then
    useradd --system --gid culvert-maint \
            --home-dir /var/lib/culvert-maint \
            --shell /sbin/nologin \
            culvert-maint
    log "created user culvert-maint"
fi

# ── 3. Binary ────────────────────────────────────────────────────────────────

# Skip the copy when re-running with the already-installed binary as the source
# (the quick-start re-render path passes /usr/local/bin/culvert-maint) — GNU
# `install` errors "are the same file" and would abort under set -e.
if [ "$(readlink -f "$BIN_SRC")" = "$(readlink -f /usr/local/bin/culvert-maint 2>/dev/null)" ]; then
    log "binary source is already the installed binary; skipping copy"
else
    install -m 0755 -o root -g root "$BIN_SRC" /usr/local/bin/culvert-maint
fi
log "installed /usr/local/bin/culvert-maint"

# ── 4. Config (never clobber an existing one) ────────────────────────────────

install -m 0750 -o root -g culvert-maint -d /etc/culvert-maint
if [ ! -f "$CONFIG_DEST" ]; then
    install -m 0640 -o root -g culvert-maint "$CONFIG_TEMPLATE" "$CONFIG_DEST"
    log "installed default $CONFIG_DEST — edit before starting (especially compose_project_dir + allow_peers)"
else
    log "$CONFIG_DEST already exists; left unchanged"
fi

# Migrate the pre-RuntimeDirectory socket default. The systemd unit now makes
# only /run/culvert-maint writable (RuntimeDirectory) — not /run — so an existing
# config still pointing at /run/culvert-maint.sock would fail to bind at startup.
# Rewrite ONLY the untouched old default; never touch a customized value. This is
# a bug-fix exception to "never clobber an existing config" (the old value cannot
# work under the new unit). socket_path is not sudoers-bound, so no re-render.
if grep -q '^socket_path = "/run/culvert-maint.sock"' "$CONFIG_DEST" 2>/dev/null; then
    sed -i 's|^socket_path = "/run/culvert-maint.sock"|socket_path = "/run/culvert-maint/culvert-maint.sock"|' "$CONFIG_DEST"
    log "migrated socket_path to /run/culvert-maint/culvert-maint.sock (managed RuntimeDirectory)"
fi

# ── 5. Resolve + validate config, then seed the pinned image tag ─────────────

PROJECT_DIR=$(extract_toml_string compose_project_dir)
COMPOSE_FILE=$(extract_toml_string compose_file)
[ -n "$COMPOSE_FILE" ] || COMPOSE_FILE=docker-compose.yml

# proxy_repo (P1.4): the repo the sudoers `docker pull`/`docker tag` entries
# bind to. Rendered into {proxy_repo} below, like {compose_path}.
PROXY_REPO=$(extract_toml_string proxy_repo)
[ -n "$PROXY_REPO" ] || PROXY_REPO=ghcr.io/kidcarmi/culvert
IMAGE_ALLOWLIST=$(extract_toml_string image_allowlist)

# Validate proxy_repo: bare repository only (no @digest/tag), no unsafe chars.
case "$PROXY_REPO" in
    *@* | *'sha256:'* )
        die "proxy_repo must be a bare repository (no @digest/tag), got '$PROXY_REPO'" ;;
esac
reject_unsafe "proxy_repo" "$PROXY_REPO"

# proxy_repo and image_allowlist MUST describe the same repository (P1.4 §3.1).
# Heuristic: the allowlist regex (backslashes stripped) must contain the
# proxy_repo literal. Runs even when image_allowlist is left unset — see
# check_proxy_repo_matches_allowlist's doc comment for why that case matters most.
check_proxy_repo_matches_allowlist "$PROXY_REPO" "$IMAGE_ALLOWLIST"

# Validate compose_project_dir: present, absolute, no unsafe chars.
[ -n "$PROJECT_DIR" ] || die "compose_project_dir not found in $CONFIG_DEST — edit it first, then re-run"
case "$PROJECT_DIR" in
    /*) : ;;
    *)  die "compose_project_dir must be absolute, got '$PROJECT_DIR'" ;;
esac
reject_unsafe "compose_project_dir" "$PROJECT_DIR"

# Validate compose_file: bare filename, not "." / "..", no unsafe chars.
case "$COMPOSE_FILE" in
    "." | "..")   die "compose_file must not be '.' or '..', got '$COMPOSE_FILE'" ;;
    */* | *\\* )  die "compose_file must be a bare filename (no slash or backslash), got '$COMPOSE_FILE'" ;;
esac
reject_unsafe "compose_file" "$COMPOSE_FILE"

# compose_override_file (optional, socket-persist): a second `-f` merged onto the
# proxy-recreate ONLY, so an opt-in override (the maintenance-agent socket wiring)
# survives an agent-driven recreate. When set it flows into a sudoers literal, so
# validate it STRICTER than compose_file: bare filename, not "." / "..", no unsafe
# chars, and distinct from compose_file. Empty ⇒ single-`-f` recreate; the
# {compose_override_path} sudoers line is DELETED (see the render step below).
COMPOSE_OVERRIDE_FILE=$(extract_toml_string compose_override_file)
if [ -n "$COMPOSE_OVERRIDE_FILE" ]; then
    case "$COMPOSE_OVERRIDE_FILE" in
        "." | "..")   die "compose_override_file must not be '.' or '..', got '$COMPOSE_OVERRIDE_FILE'" ;;
        */* | *\\* )  die "compose_override_file must be a bare filename (no slash or backslash), got '$COMPOSE_OVERRIDE_FILE'" ;;
    esac
    [ "$COMPOSE_OVERRIDE_FILE" != "$COMPOSE_FILE" ] || \
        die "compose_override_file must differ from compose_file, got '$COMPOSE_OVERRIDE_FILE'"
    reject_unsafe "compose_override_file" "$COMPOSE_OVERRIDE_FILE"
    # reject_unsafe covers whitespace/quotes/pipe/control; the override name also
    # becomes a sudoers literal + an argv token, so reject the remaining shell
    # metacharacters too. This matches the Go agent's config.Load/runner.New set
    # exactly, so a value that installs here also starts the agent (fail FAST at
    # install rather than at agent startup).
    case "$COMPOSE_OVERRIDE_FILE" in
        *';'* | *'&'* | *'$'* | *'`'* | *'<'* | *'>'* | *'*'* | *'?'* | *'('* | *')'* | *'{'* | *'}'* )
            die "compose_override_file must not contain shell metacharacters, got '$COMPOSE_OVERRIDE_FILE'" ;;
    esac
    # The override FILE must exist in the project dir. If it is configured but
    # absent, every agent-driven recreate runs `docker compose -f <base> -f
    # <missing> up -d`, which docker rejects with "no such file or directory" —
    # so an update/rollback would hard-fail (worse than not configuring it at
    # all). Warn loudly; the file is operator-managed (may be added before the
    # first dispatch), so this does not hard-fail the install.
    if [ ! -f "$PROJECT_DIR/$COMPOSE_OVERRIDE_FILE" ]; then
        warn "compose_override_file is set ($COMPOSE_OVERRIDE_FILE) but"
        warn "$PROJECT_DIR/$COMPOSE_OVERRIDE_FILE does not exist. Every agent-driven"
        warn "recreate will hard-fail (docker: no such file) until it is present."
    fi
    # The agent runs `docker compose` with a SCRUBBED environment, so any
    # ${VAR} / ${VAR:?...} the override interpolates (e.g. the socket override's
    # ${CULVERT_MAINT_GID}) MUST be resolvable from <compose_project_dir>/.env —
    # compose auto-loads that file. A required-but-unset var makes every
    # agent-driven recreate hard-fail. The ${VAR:?} colon form also trips on an
    # EMPTY value, so check for the KEY, not just the file. Warn loudly; the
    # operator owns the .env.
    if [ ! -f "$PROJECT_DIR/.env" ] || ! grep -Eq '^CULVERT_MAINT_GID=.+' "$PROJECT_DIR/.env" 2>/dev/null; then
        warn "compose_override_file is set ($COMPOSE_OVERRIDE_FILE) but CULVERT_MAINT_GID"
        warn "is not present in $PROJECT_DIR/.env. The agent runs compose with a scrubbed"
        warn "env, so the socket override's \${CULVERT_MAINT_GID:?...} must be in that .env"
        warn "or every agent-driven recreate will hard-fail. Set it before dispatching:"
        warn "  echo \"CULVERT_MAINT_GID=\$(getent group culvert-maint | cut -d: -f3)\" >> $PROJECT_DIR/.env"
    fi
fi

# Seed the fixed pinned image tag (P1.4) BEFORE flipping the sudo boundary.
# docker-compose.yml resolves `image: culvert/proxy:pinned` (no env var). That
# LOCAL tag must exist before the next `docker compose up` or the stack fails
# with "no such image". Seeding first means a seed failure aborts the install
# with the OLD, working sudo path still in place. An existing install MUST seed
# from the CURRENTLY-RUNNING digest via CULVERT_PROXY_SEED_REF so the pinned tag
# matches the live daemon; see roadmap/D1.6c-pin-value-binding-plan.md §8.
PINNED_TAG="culvert/proxy:pinned"
if docker image inspect "$PINNED_TAG" >/dev/null 2>&1; then
    log "$PINNED_TAG already present; not reseeding"
else
    # Seed source precedence:
    #   1. CULVERT_PROXY_SEED_REF — operator-supplied (e.g. the running digest
    #      captured during an existing-install migration).
    #   2. ${PROXY_REPO}:latest    — fresh-install bootstrap.
    SEED_REF="${CULVERT_PROXY_SEED_REF:-$PROXY_REPO:latest}"
    log "seeding $PINNED_TAG from $SEED_REF ..."
    if docker pull "$SEED_REF" && docker tag "$SEED_REF" "$PINNED_TAG"; then
        log "seeded $PINNED_TAG"
    else
        warn "could not seed $PINNED_TAG from $SEED_REF."
        warn "aborting BEFORE installing the new sudoers, so the existing image"
        warn "apply/rollback path keeps working. Seed it, then re-run:"
        warn "  docker tag <repo>@sha256:<running-digest> $PINNED_TAG   # existing install"
        die  "or set CULVERT_PROXY_SEED_REF and re-run. See the migration plan §8."
    fi
fi

# ── 6. Render + validate + install sudoers ───────────────────────────────────

COMPOSE_PATH="$PROJECT_DIR/$COMPOSE_FILE"
RENDERED_SUDOERS=$(mktemp)
RENDERED_SUDOERS_TMP=$(mktemp)

# Pass 1 — substitute {compose_path} and {proxy_repo}. A non-/ delimiter (|) lets
# the path/registry slashes pass through unescaped. Both values are
# colon-escaped for sudoers FIRST (compose_project_dir may legally contain a
# ':' — e.g. a path with a timestamp or mount label — and a registry port
# like 127.0.0.1:5000 would otherwise render a bare ':' that visudo rejects),
# THEN sed-escaped so the added backslash survives.
sed -e "s|{compose_path}|$(sed_escape_replacement "$(sudoers_escape_colon "$COMPOSE_PATH")")|g" \
    -e "s|{proxy_repo}|$(sed_escape_replacement "$(sudoers_escape_colon "$PROXY_REPO")")|g" \
    "$SUDOERS_TEMPLATE" > "$RENDERED_SUDOERS_TMP"

# Pass 2 — the compose.up allowlist has a second, override-carrying form bound to
# {compose_override_path}. When an override is configured, render that placeholder
# to its absolute path; when it is NOT, DELETE the line entirely — otherwise the
# unresolved placeholder would trip the leftover-placeholder guard below (and a
# host with no override must never carry that extra allowlisted form). POSIX sh:
# no arrays, so this is a plain if/else over two one-line sed programs.
if [ -n "$COMPOSE_OVERRIDE_FILE" ]; then
    COMPOSE_OVERRIDE_PATH="$PROJECT_DIR/$COMPOSE_OVERRIDE_FILE"
    sed "s|{compose_override_path}|$(sed_escape_replacement "$(sudoers_escape_colon "$COMPOSE_OVERRIDE_PATH")")|g" \
        "$RENDERED_SUDOERS_TMP" > "$RENDERED_SUDOERS"
else
    sed '/{compose_override_path}/d' "$RENDERED_SUDOERS_TMP" > "$RENDERED_SUDOERS"
fi
rm -f "$RENDERED_SUDOERS_TMP"

# Refuse to install a sudoers file with any leftover placeholder.
if grep -qE '\{compose_path\}|\{compose_file\}|\{compose_project_dir\}|\{compose_override_path\}|\{proxy_repo\}' "$RENDERED_SUDOERS"; then
    warn "rendered sudoers file still contains placeholders:"
    grep -nE '\{compose_|\{proxy_repo\}' "$RENDERED_SUDOERS" >&2
    die "refusing to install an unrendered sudoers file"
fi

# Validate grammar BEFORE moving it into /etc.
if ! visudo -c -f "$RENDERED_SUDOERS" >/dev/null; then
    warn "rendered sudoers failed visudo -c validation:"
    cat "$RENDERED_SUDOERS" >&2
    die "refusing to install an invalid sudoers file"
fi

install -m 0440 -o root -g root "$RENDERED_SUDOERS" "$SUDOERS_DEST"
log "rendered + installed $SUDOERS_DEST (compose_path=$COMPOSE_PATH)"

# Re-validate in place; roll back if the installed copy is somehow invalid.
if ! visudo -c -f "$SUDOERS_DEST" >/dev/null; then
    rm -f "$SUDOERS_DEST"
    die "installed $SUDOERS_DEST failed visudo -c (rolled back)"
fi

# ── 7. State directory ───────────────────────────────────────────────────────

install -m 0750 -o culvert-maint -g culvert-maint -d /var/lib/culvert-maint
install -m 0750 -o culvert-maint -g culvert-maint -d /var/lib/culvert-maint/operations
log "prepared /var/lib/culvert-maint"

# ── 8. Systemd unit ──────────────────────────────────────────────────────────

install -m 0644 -o root -g root "$SYSTEMD_UNIT" /etc/systemd/system/culvert-maint.service
systemctl daemon-reload
log "installed /etc/systemd/system/culvert-maint.service"

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
        curl --unix-socket /run/culvert-maint/culvert-maint.sock http://localhost/v1/health

If you change compose_project_dir or compose_file later, re-run this
script — it will re-render and re-install the sudoers file with the
new path.
EOF
