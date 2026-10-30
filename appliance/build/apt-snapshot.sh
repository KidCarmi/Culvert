# shellcheck shell=bash
# apt-snapshot.sh — the ONE way the appliance build talks to APT while the
# Ubuntu archive is pinned to a snapshot (FB-1,
# docs/appliance/evidence/combined/future-build/FB-1-APT-SNAPSHOT.md).
#
# Sourced by prepare-guest.sh (inside the guest) and by
# snapshot-pin-check.sh (the network regression lane, in an isolated APT
# root), so that lane exercises these exact functions. Requires
# GUEST_APT_SNAPSHOT and the four GUEST_APT_SNAPSHOT_INRELEASE_SHA256_* pins
# from manifest.env.
#
# Measured on APT 2.8.3 (the guest's version), which is why each rule exists:
#   - `-o Acquire::Snapshot=…` is NOT an APT option; it is silently ignored and
#     every call resolves against the live archive (E1). The selector is
#     `--snapshot ID` (APT::Snapshot), and EVERY apt-get/apt-cache call needs
#     it: a call without it resolves live again (E3).
#   - A source without snapshot support is silently used LIVE under
#     `--snapshot` (E4). `Snapshot: yes` on a source makes an unsupported
#     source a hard error instead (rc 100, E5), so the Ubuntu sources carry it
#     for the duration of the pinned section.
#   - A future or wrong snapshot ID silently means "now" (E6): the ID alone
#     proves nothing, so the InRelease bytes are pinned by SHA-256.
#   - An unreachable index is only a warning to a plain `update` (E7);
#     `--error-on=any` makes it rc 100. APT accepts that option on `update`
#     only ("not understood in combination with the other options" on
#     install), hence the separate update helper.
#
# APT_SNAP_OPTS (array, default empty) and APT_SNAP_ROOT (default "") exist
# for the isolated-root regression lane only; the guest never sets them.

APT_SNAP_SUITES=(noble noble-updates noble-security noble-backports)
APT_SNAP_ROOT="${APT_SNAP_ROOT:-}"
if [[ -z "${APT_SNAP_OPTS+x}" ]]; then APT_SNAP_OPTS=(); fi

apt_snap_die() { echo "apt-snapshot: $*" >&2; exit 1; }

# The manifest pin variable for one suite.
apt_snap_pin_var() {
  case "$1" in
    noble)           echo GUEST_APT_SNAPSHOT_INRELEASE_SHA256_NOBLE ;;
    noble-updates)   echo GUEST_APT_SNAPSHOT_INRELEASE_SHA256_UPDATES ;;
    noble-security)  echo GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY ;;
    noble-backports) echo GUEST_APT_SNAPSHOT_INRELEASE_SHA256_BACKPORTS ;;
    *) apt_snap_die "no InRelease pin is defined for suite $1" ;;
  esac
}

# Validate the snapshot ID and the four pins BEFORE any network access. The ID
# must be a well-formed snapshot timestamp strictly earlier than now: a future
# ID is served as the archive's current state (E6).
apt_snap_require_pins() {
  local now suite var
  [[ "${GUEST_APT_SNAPSHOT:-}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] \
    || apt_snap_die "GUEST_APT_SNAPSHOT='${GUEST_APT_SNAPSHOT:-}' is not a snapshot ID (YYYYMMDDTHHMMSSZ)"
  now="$(date -u +%Y%m%dT%H%M%SZ)"
  [[ "$GUEST_APT_SNAPSHOT" < "$now" ]] \
    || apt_snap_die "GUEST_APT_SNAPSHOT=$GUEST_APT_SNAPSHOT is not earlier than the build start ($now)"
  for suite in "${APT_SNAP_SUITES[@]}"; do
    var="$(apt_snap_pin_var "$suite")"
    [[ "${!var:-}" =~ ^[0-9a-f]{64}$ ]] || apt_snap_die "manifest.env: $var is not a SHA-256"
  done
}

# Every apt-get call of the pinned section. Never `update` (see below).
apt_snap() {
  [[ "${1:-}" != update ]] || apt_snap_die "use apt_snap_update for update"
  apt-get "${APT_SNAP_OPTS[@]}" --snapshot "$GUEST_APT_SNAPSHOT" "$@"
}

# The pinned update: fails on any index it cannot fetch (E7).
apt_snap_update() {
  apt-get "${APT_SNAP_OPTS[@]}" --snapshot "$GUEST_APT_SNAPSHOT" --error-on=any "$@" update
}

# apt-cache resolves the candidate from the SNAPSHOT lists, not the live ones
# fetched alongside them (E3/E9).
apt_cache_snap() {
  apt-cache "${APT_SNAP_OPTS[@]}" --snapshot "$GUEST_APT_SNAPSHOT" "$@"
}

# Opt the Ubuntu sources into snapshots (E5) and refuse any other source APT
# would silently resolve live (E4). The image's file is kept and restored by
# apt_snap_sources_restore: the deployed appliance updates from the live
# archive by design. $1: path of a non-Ubuntu one-line source that is allowed
# (Docker's, which carries snapshot=no and is pinned by exact versions plus
# the build-ova.sh reconciliation).
apt_snap_sources_enable() {
  local allowed="${1:-}" src="$APT_SNAP_ROOT/etc/apt/sources.list.d/ubuntu.sources" f stray="" types
  [[ -s "$src" ]] || apt_snap_die "$src is missing or empty"
  for f in "$APT_SNAP_ROOT"/etc/apt/sources.list "$APT_SNAP_ROOT"/etc/apt/sources.list.d/*; do
    [[ -e "$f" && "$f" != "$src" && "$f" != "$allowed" ]] || continue
    case "$f" in
      *.list) grep -qE '^[[:space:]]*deb(-src)?[[:space:]]' "$f" || continue ;;
      *.sources) ;;
      *) continue ;;
    esac
    stray="$stray${stray:+ }$f"
  done
  [[ -z "$stray" ]] || apt_snap_die "APT source(s) outside the pinned set would be resolved from the live archive: $stray"
  if [[ -n "$allowed" ]] && ! grep -qE '^deb \[[^]]*snapshot=no[^]]*\] ' "$allowed"; then
    apt_snap_die "$allowed must carry snapshot=no"
  fi
  cp -p "$src" "$src.culvert-pre-snapshot"
  # Every stanza gets exactly one `Snapshot: yes` (an existing Snapshot: line
  # is replaced, never duplicated). deb822 field names are case-insensitive;
  # tolower, not IGNORECASE, because the guest's awk is mawk.
  awk 'tolower($0) ~ /^snapshot:/ {next}
       {print}
       tolower($0) ~ /^types:/ {print "Snapshot: yes"}' "$src.culvert-pre-snapshot" > "$src"
  types="$(grep -ci '^types:' "$src" || true)"
  [[ "$types" -ge 1 && "$types" == "$(grep -c '^Snapshot: yes$' "$src")" ]] \
    || apt_snap_die "could not opt every Ubuntu source stanza into snapshots"
}

apt_snap_sources_restore() {
  local src="$APT_SNAP_ROOT/etc/apt/sources.list.d/ubuntu.sources"
  [[ -f "$src.culvert-pre-snapshot" ]] || apt_snap_die "no saved Ubuntu sources to restore"
  mv -f "$src.culvert-pre-snapshot" "$src"
}

# The InRelease APT just fetched for each suite must be byte-identical to the
# reviewed pin (E6/E8). A missing file is a failure, never a skip.
apt_snap_verify_inrelease() {
  local lists="$APT_SNAP_ROOT/var/lib/apt/lists" suite var file got
  for suite in "${APT_SNAP_SUITES[@]}"; do
    var="$(apt_snap_pin_var "$suite")"
    file="$lists/snapshot.ubuntu.com_ubuntu_${GUEST_APT_SNAPSHOT}_dists_${suite}_InRelease"
    [[ -s "$file" ]] || apt_snap_die "snapshot InRelease for $suite was not fetched ($file)"
    got="$(sha256sum "$file" | cut -d' ' -f1)"
    [[ "$got" == "${!var}" ]] \
      || apt_snap_die "snapshot $GUEST_APT_SNAPSHOT $suite InRelease is $got, manifest pins ${!var} ($var)"
  done
}

# One line naming the snapshot and its verified InRelease hashes, for the
# build log and build-upgrades.txt.
apt_snap_label() {
  local suite var out="Ubuntu archive snapshot $GUEST_APT_SNAPSHOT, InRelease SHA-256 verified:"
  for suite in "${APT_SNAP_SUITES[@]}"; do
    var="$(apt_snap_pin_var "$suite")"
    out="$out $suite=${!var}"
  done
  echo "$out"
}
