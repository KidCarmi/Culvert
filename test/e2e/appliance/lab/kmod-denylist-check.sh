#!/usr/bin/env bash
# kmod-denylist-check.sh MODPROBE_CONF SNAPSHOT [ABI]
#
# Offline proof, in seconds and without building or booting an OVA, that every
# module in the appliance's modprobe denylist resolves to `install /bin/false`
# as its FINAL modprobe step against the REAL module tree of the kernel the OVA
# installs. Same predicate as prepare-guest.sh's build check and the booted
# guest probe; it exists to catch a broken denylist before a ~40 min lab cycle
# (the ksmbd softdep hole, the kvm-amd file-name mistake and a probe-parser bug
# all reproduce here).
#
# Trust chain (fail closed at every link): snapshot InRelease signature checked
# with Ubuntu's archive keyring -> Packages.gz sha256 from InRelease -> the
# linux-modules deb's sha256 from Packages. The kernel ABI is the snapshot's
# own linux-image-virtual candidate (the metapackage the OVA keeps), unless
# given explicitly. Prints one line per module; exits 1 if any still loads.
set -euo pipefail
conf="${1:?MODPROBE_CONF}"; snap="${2:?SNAPSHOT e.g. 20261002T120000Z}"; abi="${3:-}"
keyring="${UBUNTU_KEYRING:-/usr/share/keyrings/ubuntu-archive-keyring.gpg}"
[[ -s "$keyring" ]] || { echo "no Ubuntu archive keyring at $keyring" >&2; exit 2; }
base="https://snapshot.ubuntu.com/ubuntu/$snap"
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
python3 -I - "$base" "$keyring" "$w" "$abi" > "$w/plan" <<'PY'
import gzip, hashlib, re, subprocess, sys, urllib.request
base, keyring, w, abi = sys.argv[1:5]
def get(u):
    with urllib.request.urlopen(u, timeout=120) as r: return r.read()
best = {}   # package -> (version, filename, sha256) across the three pockets
for suite in ("noble", "noble-updates", "noble-security"):
    inrel = get(f"{base}/dists/{suite}/InRelease")
    open(f"{w}/InRelease", "wb").write(inrel)
    v = subprocess.run(["gpgv", "--keyring", keyring, "--output", f"{w}/Release", f"{w}/InRelease"], capture_output=True)
    if v.returncode != 0: sys.exit(f"{suite}: InRelease signature check failed: {v.stderr.decode()[-300:]}")
    rel = open(f"{w}/Release").read()
    m = re.search(r"^ ([0-9a-f]{64})\s+\d+\s+main/binary-amd64/Packages\.gz$", rel, re.M)
    if not m: sys.exit(f"{suite}: Release lists no main/binary-amd64/Packages.gz")
    pk = get(f"{base}/dists/{suite}/main/binary-amd64/Packages.gz")
    if hashlib.sha256(pk).hexdigest() != m.group(1): sys.exit(f"{suite}: Packages.gz sha256 mismatch")
    for stanza in gzip.decompress(pk).decode().split("\n\n"):
        f = dict(re.findall(r"^([A-Za-z0-9-]+): (.*)$", stanza, re.M))
        n = f.get("Package", "")
        if n == "linux-image-virtual" or n.startswith("linux-modules-"):
            cur = best.get(n)
            if cur is None or subprocess.run(["dpkg", "--compare-versions", f["Version"], "gt", cur[0]]).returncode == 0:
                best[n] = (f["Version"], f["Filename"], f["SHA256"], f.get("Depends", ""))
if not abi:
    meta = best.get("linux-image-virtual") or sys.exit("snapshot has no linux-image-virtual")
    m = re.search(r"linux-image-(\d+\.\d+\.\d+-\d+-generic)", meta[3]) or sys.exit("cannot derive ABI from linux-image-virtual Depends")
    abi = m.group(1)
mod = best.get(f"linux-modules-{abi}") or sys.exit(f"snapshot has no linux-modules-{abi}")
print(f"ABI={abi}\nURL={base}/{mod[1]}\nSHA256={mod[2]}\nVERSION={mod[0]}")
PY
plan() { sed -n "s/^$1=//p" "$w/plan"; }
abi="$(plan ABI)"
curl -fsS -o "$w/m.deb" "$(plan URL)"
echo "$(plan SHA256)  $w/m.deb" | sha256sum -c --quiet - || { echo "linux-modules deb sha256 mismatch" >&2; exit 1; }
dpkg-deb -x "$w/m.deb" "$w/root"
depmod -b "$w/root" "$abi"
mkdir "$w/conf"; cp "$conf" "$w/conf/culvert.conf"
echo "kernel $abi (linux-modules $(plan VERSION), snapshot $snap; signature, index and package hashes verified)"
# modprobe -n prints NOTHING for a module already loaded on the machine running
# it (it reads /sys/module/<m>/initstate), so on a host that has kvm, kvm_amd,
# ib_core or ib_uverbs loaded -- a GitHub runner on an Azure AMD host has all
# four -- the check would read the RUNNER's state, not the OVA's. The loop runs
# in a private mount namespace with an empty tmpfs over /sys/module, so only
# the OVA's module tree and the conf decide the verdict.
mods="$(awk '$1=="install" && $3=="/bin/false"{print $2}' "$conf")"
as_root=(); [[ "$(id -u)" == 0 ]] || as_root=(sudo -n)
"${as_root[@]}" unshare -m --propagation private bash -s "$w/root" "$abi" "$w/conf" "$mods" <<'NS'
set -uo pipefail
root="$1" abi="$2" conf="$3" mods="$4"
mount -t tmpfs none /sys/module || { echo "cannot hide /sys/module" >&2; exit 2; }
[[ -z "$(ls -A /sys/module)" ]] || { echo "/sys/module is not empty inside the namespace" >&2; exit 2; }
fail=0
for m in $mods; do
  last="$(modprobe -d "$root" -S "$abi" -C "$conf" -n -v "$m" 2>&1 | tail -n1)"
  if [[ "$last" =~ ^install\ /bin/false[[:space:]]*$ ]]; then echo "denied  $m"
  elif [[ "$last" == *"not found"* ]]; then echo "absent  $m (not in linux-modules)"
  elif [[ -z "$last" ]]; then echo "ERROR   $m -> modprobe printed nothing (treated as a failure, never as denied)"; fail=1
  else echo "LOADS   $m -> $last"; fail=1; fi
done
exit "$fail"
NS
