#!/usr/bin/env bash
# fb1-c5.sh BUILD_DIR WORK — LAB ONLY. FB-1 T4 case C5: the guest's section-1
# source set (Ubuntu `Snapshot: yes` + Docker's one-line `snapshot=no`
# source) under the production library, then a simulated install of what
# prepare-guest.sh installs. Asserts the Docker pins are selected and every
# Ubuntu package the simulation installs is a version the SNAPSHOT lists.
set -euo pipefail
B="$1"; R="$2"
set -a; . "$B/manifest.env"; set +a
. "$B/apt-snapshot.sh"
mkdir -p "$R/etc/apt/sources.list.d" "$R/etc/apt/apt.conf.d" "$R/etc/apt/preferences.d" "$R/etc/apt/keyrings" \
  "$R/var/lib/apt/lists/partial" "$R/var/cache/apt/archives/partial" "$R/var/lib/dpkg"
: > "$R/var/lib/dpkg/status"
K=/usr/share/keyrings/ubuntu-archive-keyring.gpg
printf 'Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble noble-updates noble-backports\nComponents: main restricted universe multiverse\nSigned-By: %s\n\nTypes: deb\nURIs: http://security.ubuntu.com/ubuntu/\nSuites: noble-security\nComponents: main restricted universe multiverse\nSigned-By: %s\n' "$K" "$K" \
  > "$R/etc/apt/sources.list.d/ubuntu.sources"
curl -fsSL --retry 3 "$DOCKER_APT_GPG_URL" -o "$R/d.asc"
fpr="$(GNUPGHOME="$(mktemp -d)" gpg --batch --with-colons --show-keys "$R/d.asc" | awk -F: '$1=="fpr"{print $10; exit}')"
[[ "$fpr" == "$DOCKER_APT_KEY_FPR" ]] || { echo "FAIL C5 Docker key fingerprint $fpr"; exit 1; }
GNUPGHOME="$(mktemp -d)" gpg --batch --dearmor -o "$R/etc/apt/keyrings/docker.gpg" "$R/d.asc"
# The line prepare-guest.sh writes, with the keyring inside this root.
echo "deb [arch=amd64 signed-by=$R/etc/apt/keyrings/docker.gpg snapshot=no] ${DOCKER_APT_URL} ${GUEST_OS_CODENAME} stable" \
  > "$R/etc/apt/sources.list.d/docker.list"
# shellcheck disable=SC2034 # read by apt-snapshot.sh
APT_SNAP_ROOT="$R"
# shellcheck disable=SC2034 # read by apt-snapshot.sh
APT_SNAP_OPTS=(-o "Dir=$R" -o "Dir::State::status=$R/var/lib/dpkg/status" -o Dir::Etc::trusted=/dev/null
  -o Dir::Etc::TrustedParts=/usr/share/keyrings -o APT::Architecture=amd64 -o Debug::NoLocking=1
  -o Acquire::Languages=none -o APT::Sandbox::User=root)

# c5_check ROOT: simulate the installs, then attribute each installed version.
c5_check() {
  local r="$1" n p v
  apt_snap -s install --no-install-recommends "docker-ce=${DOCKER_CE_VERSION}" "docker-ce-cli=${DOCKER_CE_CLI_VERSION}" \
    "containerd.io=${CONTAINERD_IO_VERSION}" "docker-compose-plugin=${DOCKER_COMPOSE_PLUGIN_VERSION}" pigz psmisc \
    "${GUEST_KERNEL_META}" plymouth plymouth-theme-ubuntu-text plymouth-label fontconfig > "$r.sim"
  grep '^Inst ' "$r.sim" | awk '{v=$3; gsub(/[()]/,"",v); print $2, v}' > "$r.inst"
  n="$(wc -l < "$r.inst")"
  [[ "$n" -gt 0 ]] || { echo "FAIL C5 the simulation installs nothing"; cat "$r.sim"; exit 1; }
  for pv in "docker-ce ${DOCKER_CE_VERSION}" "docker-ce-cli ${DOCKER_CE_CLI_VERSION}" "containerd.io ${CONTAINERD_IO_VERSION}" "docker-compose-plugin ${DOCKER_COMPOSE_PLUGIN_VERSION}"; do
    grep -qxF "$pv" "$r.inst" || { echo "FAIL C5 $pv is not what the simulation selects"; exit 1; }
  done
  while read -r p v; do
    case "$p" in docker-ce|docker-ce-cli|containerd.io|docker-compose-plugin) continue ;; esac
    # The version table lists each version followed by its sources; the
    # selected version must have a SNAPSHOT source (a live list may list the
    # same version too, which proves nothing either way).
    apt_cache_snap policy "$p" | awk -v v="$v" -v u="https://snapshot.ubuntu.com/ubuntu/${GUEST_APT_SNAPSHOT}" '
      /^     [^ ]/ || /^ \*\*\* / { cur = ($1 == "***") ? $2 : $1; next }
      cur == v && index($0, u) { found = 1 }
      END { exit !found }' || { echo "FAIL C5 $p $v is not a version the snapshot lists"; exit 1; }
  done < "$r.inst"
  echo "PASS C5 simulated install (4 Docker pins + pigz psmisc + kernel meta + boot packages): $n packages; Docker at the pins; every Ubuntu one a snapshot ${GUEST_APT_SNAPSHOT} version"
}

apt_snap_require_pins
apt_snap_sources_enable "$R/etc/apt/sources.list.d/docker.list"
apt_snap_update -qq
apt_snap_verify_inrelease
echo "PASS C5 pinned update + InRelease pins with the guest source set (Docker snapshot=no beside Snapshot: yes)"
c5_check "$R"
