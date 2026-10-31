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

# apt_snap_utc_instant VALUE: true only for a REAL UTC calendar instant written
# YYYYMMDDTHHMMSSZ. The shape alone is not enough (ASTRA, 31 Oct: the first
# version accepted 20260230T120000Z and 20251340T256199Z): the value must
# round-trip unchanged through GNU date, which rejects impossible dates and
# times and would otherwise normalize them (Feb 30 -> Mar 2, second 60).
apt_snap_utc_instant() {
  local v="${1:-}" iso back
  [[ "$v" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})Z$ ]] || return 1
  iso="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]} UTC"
  back="$(LC_ALL=C TZ=UTC date -u -d "$iso" +%Y%m%dT%H%M%SZ 2>/dev/null)" || return 1
  [[ "$back" == "$v" ]]
}

# Validate the snapshot ID, the build-start instant and the four pins BEFORE
# any network access. GUEST_APT_BUILD_START is recorded ONCE by build-ova.sh
# (host) and handed to the guest in its manifest, so host and guest judge the
# ID against the same instant rather than each reading a moving clock. The ID
# must be strictly earlier than it: a future ID is served as the archive's
# current state (E6).
apt_snap_require_pins() {
  local suite var
  apt_snap_utc_instant "${GUEST_APT_SNAPSHOT:-}" \
    || apt_snap_die "GUEST_APT_SNAPSHOT='${GUEST_APT_SNAPSHOT:-}' is not a real UTC instant (YYYYMMDDTHHMMSSZ)"
  apt_snap_utc_instant "${GUEST_APT_BUILD_START:-}" \
    || apt_snap_die "GUEST_APT_BUILD_START='${GUEST_APT_BUILD_START:-}' is not a recorded build-start instant (YYYYMMDDTHHMMSSZ)"
  [[ "$GUEST_APT_SNAPSHOT" < "$GUEST_APT_BUILD_START" ]] \
    || apt_snap_die "GUEST_APT_SNAPSHOT=$GUEST_APT_SNAPSHOT is not earlier than the build start $GUEST_APT_BUILD_START"
  for suite in "${APT_SNAP_SUITES[@]}"; do
    var="$(apt_snap_pin_var "$suite")"
    [[ "${!var:-}" =~ ^[0-9a-f]{64}$ ]] || apt_snap_die "manifest.env: $var is not a SHA-256"
  done
}

# Every apt-get call of the pinned section. Never `update` (see below).
# Always-Include-Phased-Updates: phasing picks a machine-dependent subset of
# an update, so "same snapshot => same versions" would not hold; the pinned
# snapshot is the reviewed set, so all of it applies. Keep-Downloaded-Packages:
# the acquired .debs stay in the cache until the acquisition receipt is taken.
apt_snap() {
  [[ "${1:-}" != update ]] || apt_snap_die "use apt_snap_update for update"
  apt-get "${APT_SNAP_OPTS[@]}" --snapshot "$GUEST_APT_SNAPSHOT" \
    -o APT::Get::Always-Include-Phased-Updates=true -o APT::Keep-Downloaded-Packages=true "$@"
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

# apt_snap_acquisition_receipt CACHE_DIR OUT: one row per .deb the build
# acquired — package, version, architecture (read from the .deb itself, not
# its file name), SHA-256 of the bytes, file name. build-ova.sh reconciles
# every row against the authenticated indexes and the Docker byte pins.
apt_snap_acquisition_receipt() {
  local dir="$1" out="$2" f
  : > "$out.tmp"
  for f in "$dir"/*.deb; do
    [[ -e "$f" ]] || continue
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$(dpkg-deb -f "$f" Package)" "$(dpkg-deb -f "$f" Version)" "$(dpkg-deb -f "$f" Architecture)" \
      "$(sha256sum "$f" | cut -d' ' -f1)" "${f##*/}" >> "$out.tmp"
  done
  sort "$out.tmp" > "$out"; rm -f "$out.tmp"
  [[ -s "$out" ]] || apt_snap_die "no acquired packages in $dir (cache emptied before the receipt?)"
}

# apt_snap_verify_docker_debs RECEIPT: each pinned Docker package was acquired
# exactly once, at its pinned version, with its reviewed SHA-256. Docker's
# repository is not snapshotted, so these four byte pins are what binds them.
apt_snap_verify_docker_debs() {
  local receipt="$1" spec name ver shavar want rows
  for spec in "docker-ce DOCKER_CE_VERSION DOCKER_CE_DEB_SHA256" \
              "docker-ce-cli DOCKER_CE_CLI_VERSION DOCKER_CE_CLI_DEB_SHA256" \
              "containerd.io CONTAINERD_IO_VERSION CONTAINERD_IO_DEB_SHA256" \
              "docker-compose-plugin DOCKER_COMPOSE_PLUGIN_VERSION DOCKER_COMPOSE_PLUGIN_DEB_SHA256"; do
    read -r name ver shavar <<<"$spec"
    want="${!shavar:-}"
    [[ "$want" =~ ^[0-9a-f]{64}$ ]] || apt_snap_die "manifest.env: $shavar is not a SHA-256"
    rows="$(awk -F'\t' -v n="$name" '$1==n' "$receipt")"
    [[ -n "$rows" && "$(wc -l <<<"$rows")" == 1 ]] || apt_snap_die "$name: expected exactly one acquired .deb, receipt has: ${rows:-none}"
    [[ "$(cut -f2 <<<"$rows")" == "${!ver}" && "$(cut -f3 <<<"$rows")" == amd64 ]] \
      || apt_snap_die "$name: acquired $(cut -f2,3 <<<"$rows" | tr '\t' ' '), manifest pins ${!ver} amd64"
    [[ "$(cut -f4 <<<"$rows")" == "$want" ]] \
      || apt_snap_die "$name ${!ver}: acquired .deb is $(cut -f4 <<<"$rows"), manifest pins $want ($shavar)"
  done
}

