#!/usr/bin/env bash
# sim.sh REPO ROOT STATUS: the FB-1 pin-selection resolution (README.md).
# An isolated APT root under ROOT loads the 325c142a dpkg STATUS, takes the
# guest's section-1 source set and the production apt-snapshot.sh helpers,
# and writes ROOT.upgrade-default.txt / .upgrade-allphased.txt / .kmeta*.txt.
# The candidate pins are set explicitly below; they now equal manifest.env.
set -euo pipefail
M="$1"; R="$2"; STATUS="$3"
set -a; . "$M/appliance/build/manifest.env"; set +a
# shellcheck disable=SC2034 # read by apt-snapshot.sh
GUEST_APT_SNAPSHOT=20261105T000000Z
# shellcheck disable=SC2034 # read by apt-snapshot.sh
GUEST_APT_SNAPSHOT_INRELEASE_SHA256_NOBLE=cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0
# shellcheck disable=SC2034 # read by apt-snapshot.sh
GUEST_APT_SNAPSHOT_INRELEASE_SHA256_UPDATES=b82fcb2734d8a7a04efe6a7a19f8eb16692d3c64a5884fb2755ba6fd647aaa78
# shellcheck disable=SC2034 # read by apt-snapshot.sh
GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY=9798467b11460fac5c1015fc5b297c9b05d125d24a77b6953e8675de774cb866
# shellcheck disable=SC2034 # read by apt-snapshot.sh
GUEST_APT_SNAPSHOT_INRELEASE_SHA256_BACKPORTS=53907c41dd1f5f1ab0465119ee5175ca916a1dc2c64f1762097c5049c6ff7e6b
. "$M/appliance/build/apt-snapshot.sh"
mkdir -p "$R/etc/apt/sources.list.d" "$R/etc/apt/apt.conf.d" "$R/etc/apt/preferences.d" "$R/etc/apt/keyrings" "$R/var/lib/apt/lists/partial" "$R/var/cache/apt/archives/partial" "$R/var/lib/dpkg"
cp "$STATUS" "$R/var/lib/dpkg/status"
K=/usr/share/keyrings/ubuntu-archive-keyring.gpg
printf 'Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble noble-updates noble-backports\nComponents: main restricted universe multiverse\nSigned-By: %s\n\nTypes: deb\nURIs: http://security.ubuntu.com/ubuntu/\nSuites: noble-security\nComponents: main restricted universe multiverse\nSigned-By: %s\n' "$K" "$K" > "$R/etc/apt/sources.list.d/ubuntu.sources"
curl -fsSL --retry 3 "$DOCKER_APT_GPG_URL" | GNUPGHOME="$(mktemp -d)" gpg --batch --dearmor -o "$R/etc/apt/keyrings/docker.gpg"
echo "deb [arch=amd64 signed-by=$R/etc/apt/keyrings/docker.gpg snapshot=no] ${DOCKER_APT_URL} ${GUEST_OS_CODENAME} stable" > "$R/etc/apt/sources.list.d/docker.list"
printf 'Package: snapd\nPin: release *\nPin-Priority: -1\n' > "$R/etc/apt/preferences.d/culvert-no-snapd"
APT_SNAP_ROOT="$R"
APT_SNAP_OPTS=(-o "Dir=$R" -o "Dir::State::status=$R/var/lib/dpkg/status" -o Dir::Etc::trusted=/dev/null -o Dir::Etc::TrustedParts=/usr/share/keyrings -o APT::Architecture=amd64 -o Debug::NoLocking=1 -o Acquire::Languages=none -o APT::Sandbox::User=root)
apt_snap_sources_enable "$R/etc/apt/sources.list.d/docker.list"
apt_snap_update -qq
apt_snap_verify_inrelease && echo "pins verified"
apt_snap -s -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade > "$R.upgrade-default.txt"
apt_snap -s -o APT::Get::Always-Include-Phased-Updates=true -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade > "$R.upgrade-allphased.txt"
apt_snap -s install --no-install-recommends "$GUEST_KERNEL_META" > "$R.kmeta.txt"
apt_cache_snap policy "$GUEST_KERNEL_META" > "$R.kmeta-policy.txt"
apt_cache_snap depends "$GUEST_KERNEL_META" > "$R.kmeta-depends.txt"
