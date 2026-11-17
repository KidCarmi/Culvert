#!/bin/bash
# window-probe.sh SNAPSHOT_ID -> one TSV line: id, updates InRelease date+sha,
# security InRelease date+sha, linux-image-virtual-hwe-24.04 version(s), and how
# many of the 13 R10-F1 fixed versions noble-security/main lists.
# Derived from ../fb1-snapshot-20261105/tools/window-probe.sh (only the fix list changed).
set -euo pipefail
id=$1; d=raw/$id; mkdir -p $d; B=https://snapshot.ubuntu.com/ubuntu/$id/dists
for s in noble-updates noble-security; do
  [ -s $d/$s.InRelease ] || curl -sSf --max-time 60 -o $d/$s.InRelease $B/$s/InRelease
  [ -s $d/$s.main.xz ] || curl -sSf --max-time 180 -o $d/$s.main.xz $B/$s/main/binary-amd64/Packages.xz
  want=$(awk '/^SHA256:/{f=1;next} /^[A-Za-z]/{f=0} f && $3=="main/binary-amd64/Packages.xz"{print $1}' $d/$s.InRelease)
  got=$(sha256sum $d/$s.main.xz | cut -d' ' -f1); [ "$want" = "$got" ] || { echo "$id $s Packages.xz hash mismatch"; exit 1; }
done
for s in noble-updates noble-security; do [ -s $d/$s.main ] || xz -dc $d/$s.main.xz > $d/$s.main; done
hwe=$(cat $d/noble-updates.main $d/noble-security.main | awk 'BEGIN{RS="";FS="\n"} /\nPackage: linux-image-virtual-hwe-24.04\n|^Package: linux-image-virtual-hwe-24.04\n/{for(i=1;i<=NF;i++) if($i ~ /^Version:/) print substr($i,10)}' | sort -uV | tr '\n' ',')
fix=0; for pv in "libc6 2.39-0ubuntu8.12" "libc-bin 2.39-0ubuntu8.12" "libc-dev-bin 2.39-0ubuntu8.12" "libc-devtools 2.39-0ubuntu8.12" "libc6-dev 2.39-0ubuntu8.12" "locales 2.39-0ubuntu8.12" "perl 5.38.2-3.2ubuntu0.7" "perl-base 5.38.2-3.2ubuntu0.7" "perl-modules-5.38 5.38.2-3.2ubuntu0.7" "libperl5.38t64 5.38.2-3.2ubuntu0.7" "python3-pyasn1 0.4.8-4ubuntu0.4" "linux-image-7.0.0-43-generic 7.0.0-43.43~24.04.1" "linux-modules-7.0.0-43-generic 7.0.0-43.43~24.04.1"; do
  set -- $pv; awk -v p="$1" -v v="$2" 'BEGIN{RS="";FS="\n";r=1} {a=0;b=0;for(i=1;i<=NF;i++){if($i=="Package: "p)a=1;if($i=="Version: "v)b=1} if(a&&b){r=0;exit}} END{exit r}' $d/noble-security.main && fix=$((fix+1)); done
ud=$(grep -m1 '^Date:' $d/noble-updates.InRelease | cut -c7-); sd=$(grep -m1 '^Date:' $d/noble-security.InRelease | cut -c7-)
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s/13\n' $id "$ud" $(sha256sum $d/noble-updates.InRelease | cut -c1-64) "$sd" $(sha256sum $d/noble-security.InRelease | cut -c1-64) "$hwe" $fix
