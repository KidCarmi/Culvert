#!/bin/bash
# fetch.sh BASEURL OUTDIR — signed InRelease for noble{,-updates,-security,-backports},
# gpgv-verified with the Ubuntu archive keyring; Packages.xz hash-verified against it.
set -euo pipefail
base="$1"; out="$2"; mkdir -p "$out"
for suite in noble noble-updates noble-security noble-backports; do
  curl -fsS -m 120 -o "$out/$suite.InRelease" "$base/dists/$suite/InRelease"
  gpgv --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg "$out/$suite.InRelease" 2>"$out/$suite.gpgv" || { echo "SIGNATURE FAIL $suite"; cat "$out/$suite.gpgv"; exit 1; }
  echo "sig-ok $suite $(grep -o 'using RSA key [0-9A-F]*' "$out/$suite.gpgv" | head -1) $(grep -m1 '^Date:' "$out/$suite.InRelease")"
  for comp in main restricted universe multiverse; do
    f="$comp/binary-amd64/Packages.xz"
    want="$(awk -v f="$f" '/^SHA256:/{s=1;next} /^[A-Za-z]/{s=0} s && $3==f {print $1}' "$out/$suite.InRelease")"
    curl -fsS -m 300 -o "$out/$suite-$comp.Packages.xz" "$base/dists/$suite/$f"
    got="$(sha256sum "$out/$suite-$comp.Packages.xz" | cut -c1-64)"
    [ "$got" = "$want" ] || { echo "HASH FAIL $suite $f"; exit 1; }
    xz -dc "$out/$suite-$comp.Packages.xz" > "$out/$suite-$comp.Packages"
  done
done
echo done
