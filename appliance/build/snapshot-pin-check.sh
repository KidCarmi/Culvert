#!/usr/bin/env bash
# snapshot-pin-check.sh — FB-1 T4: the network regression lane for the guest's
# snapshot-pinned APT section. NOT a PR gate (it needs snapshot.ubuntu.com and
# download.docker.com); run it on a build/lab host before a candidate build.
#
#   appliance/build/snapshot-pin-check.sh [WORKDIR]
#
# Each case runs in its own isolated APT root (Dir=…, no dpkg database, no
# root needed) on the host's APT, which must be 2.8.x like the guest's. It
# drives the SAME functions prepare-guest.sh uses (apt-snapshot.sh) with the
# SAME manifest pins, and checks the behaviour FB-1 measured (E2/E5/E6/E7):
#   C1  pinned update + InRelease verification pass; the snapshot candidate
#       of a canary (systemd) is the snapshot's, and differs from the live one
#   C2  a future snapshot ID and calendar-impossible IDs are refused by the
#       guard (against the recorded build start); with the guard bypassed
#       APT returns the archive's CURRENT state with rc 0 (E6) and the
#       InRelease pin check is what fails
#   C3  `Snapshot: yes` on a source with no snapshot service: update rc 100
#   C4  an unreachable index: plain update rc 0 (E7), pinned update rc 100
# Exit 0 only when every case behaves as stated.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK"
set -a
# shellcheck source=appliance/build/manifest.env
. "$HERE/manifest.env"
set +a
# shellcheck source=appliance/build/apt-snapshot.sh
. "$HERE/apt-snapshot.sh"
# One recorded build-start instant, as build-ova.sh records it.
GUEST_APT_BUILD_START="$(date -u +%Y%m%dT%H%M%SZ)"

KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg
[[ -f "$KEYRING" ]] || { echo "missing $KEYRING (ubuntu-keyring)" >&2; exit 2; }
apt_version="$(apt-get --version | awk 'NR==1{print $2}')"
case "$apt_version" in 2.8.*) ;; *) echo "APT $apt_version: this lane reproduces the guest's APT 2.8.x" >&2; exit 2 ;; esac

FAILED=0
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILED=1; }

# mkroot NAME SOURCES-BODY -> sets APT_SNAP_ROOT/APT_SNAP_OPTS for that root.
mkroot() {
  local r="$WORK/$1"
  rm -rf "$r"
  mkdir -p "$r/etc/apt/sources.list.d" "$r/etc/apt/apt.conf.d" "$r/etc/apt/preferences.d" \
    "$r/var/lib/apt/lists/partial" "$r/var/cache/apt/archives/partial" "$r/var/lib/dpkg"
  : > "$r/var/lib/dpkg/status"
  printf '%s\n' "$2" > "$r/etc/apt/sources.list.d/ubuntu.sources"
  APT_SNAP_ROOT="$r"
  APT_SNAP_OPTS=(-o "Dir=$r" -o "Dir::State::status=$r/var/lib/dpkg/status" -o Dir::Etc::trusted=/dev/null
    -o Dir::Etc::TrustedParts=/usr/share/keyrings -o APT::Architecture=amd64 -o Debug::NoLocking=1
    -o Acquire::Languages=none -o APT::Sandbox::User=root)
}

# The image's Ubuntu sources, main only (the cases need no other component).
ubuntu_sources() {
  printf 'Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble noble-updates noble-backports\nComponents: main\nSigned-By: %s\n\n' "$KEYRING"
  printf 'Types: deb\nURIs: http://security.ubuntu.com/ubuntu/\nSuites: noble-security\nComponents: main\nSigned-By: %s\n' "$KEYRING"
}

echo "snapshot-pin-check: APT $apt_version, $(apt_snap_label), recorded build start $GUEST_APT_BUILD_START"

# ── C1: the production path ─────────────────────────────────────────────────
mkroot c1 "$(ubuntu_sources)"
apt_snap_require_pins
apt_snap_sources_enable
if apt_snap_update -qq >"$WORK/c1.log" 2>&1; then
  if (apt_snap_verify_inrelease) 2>>"$WORK/c1.log"; then pass "C1 pinned update; all four InRelease files equal the manifest pins"
  else fail "C1 InRelease verification failed on the manifest snapshot ($(tail -1 "$WORK/c1.log"))"; fi
  snap_cand="$(apt_cache_snap policy systemd | awk '/Candidate:/{print $2}')"
  live_cand="$(apt-cache "${APT_SNAP_OPTS[@]}" policy systemd | awk '/Candidate:/{print $2}')"
  snap_from="$(apt_cache_snap policy systemd | awk -v c="$snap_cand" '$1==c{getline; print $2; exit}')"
  if [[ "$snap_from" == "https://snapshot.ubuntu.com/ubuntu/$GUEST_APT_SNAPSHOT" ]]; then
    pass "C1 snapshot candidate systemd $snap_cand comes from $snap_from (live candidate: $live_cand)"
  else
    fail "C1 snapshot candidate systemd $snap_cand comes from '${snap_from:-?}', not the snapshot"
  fi
else
  fail "C1 pinned update failed: $(tail -3 "$WORK/c1.log" | tr '\n' ' ')"
fi
apt_snap_sources_restore

# ── C2: a future ID (E6) ────────────────────────────────────────────────────
real_id="$GUEST_APT_SNAPSHOT"
GUEST_APT_SNAPSHOT=20991231T000000Z
if (apt_snap_require_pins) 2>"$WORK/c2-guard.log"; then fail "C2 the guard accepted future ID $GUEST_APT_SNAPSHOT"
else pass "C2 guard refuses: $(tail -1 "$WORK/c2-guard.log")"; fi
for bad in 20260230T120000Z 20251340T256199Z 20260229T000000Z 20261029T240000Z; do
  if (GUEST_APT_SNAPSHOT="$bad" apt_snap_require_pins) 2>>"$WORK/c2-guard.log"; then fail "C2 the guard accepted impossible ID $bad"
  else pass "C2 guard refuses impossible ID $bad"; fi
done
mkroot c2 "$(ubuntu_sources)"
apt_snap_sources_enable
if apt_snap_update -qq >"$WORK/c2.log" 2>&1; then
  if (apt_snap_verify_inrelease) 2>>"$WORK/c2.log"; then fail "C2 a future ID's InRelease matched the pins"
  else pass "C2 APT accepted the future ID (rc 0, E6); the pin check refuses it: $(tail -1 "$WORK/c2.log")"; fi
else
  # The service may also refuse it outright; either way nothing is installed.
  pass "C2 the snapshot service refused the future ID ($(grep -m1 -E '^(E|Err):' "$WORK/c2.log" || tail -1 "$WORK/c2.log"))"
fi
GUEST_APT_SNAPSHOT="$real_id"

# ── C3: Snapshot: yes on a source without snapshot support (E5) ────────────
mkroot c3 "$(ubuntu_sources)
$(printf '\nTypes: deb\nURIs: %s\nSuites: %s\nComponents: stable\nArchitectures: amd64\nSigned-By: /dev/null\nSnapshot: yes\n' "$DOCKER_APT_URL" "$GUEST_OS_CODENAME")"
set +e; apt_snap_update -qq >"$WORK/c3.log" 2>&1; rc=$?; set -e
# rc 100 alone could be any error (the stanza is deliberately unsigned): the
# refusal must be APT's snapshot-support error.
c3_err="$(grep -m1 -iE '^E: .*snapshot' "$WORK/c3.log" || true)"
if [[ "$rc" == 100 && -n "$c3_err" ]]; then pass "C3 Snapshot: yes on Docker's repository: rc 100 ($c3_err)"
else fail "C3 Snapshot: yes on Docker's repository: rc $rc, '${c3_err:-no snapshot error}' (expected rc 100 + a snapshot-support error)"; fi

# A host that does not resolve: APT reports a FETCH failure, which a plain
# update downgrades to a warning. (A reachable host with a missing Release
# file is already an error without the option, so it would prove nothing.)
# No Snapshot: yes here, so the case isolates --error-on from E5.
unreachable_src="$(printf 'Types: deb\nURIs: http://culvert-fb1-unreachable.invalid/ubuntu/\nSuites: noble\nComponents: main\nSigned-By: %s\n' "$KEYRING")"
mkroot c4plain "$unreachable_src"
set +e; apt-get "${APT_SNAP_OPTS[@]}" -qq update >"$WORK/c4-plain.log" 2>&1; rc_plain=$?; set -e
mkroot c4pinned "$unreachable_src"
set +e; apt_snap_update -qq >"$WORK/c4-pinned.log" 2>&1; rc_pinned=$?; set -e
if [[ "$rc_plain" == 0 && "$rc_pinned" == 100 ]]; then pass "C4 unreachable index: plain update rc 0 (warning only), pinned update rc 100"
else fail "C4 unreachable index: plain rc $rc_plain (expected 0), pinned rc $rc_pinned (expected 100)"; fi

echo "snapshot-pin-check: logs in $WORK"
exit "$FAILED"
