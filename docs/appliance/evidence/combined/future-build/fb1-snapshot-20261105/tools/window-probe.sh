#!/bin/bash
# probe.sh SNAPSHOT_ID -> one TSV line: id, updates InRelease date+sha, security InRelease date+sha, hwe meta version(s), 9-fix presence
set -euo pipefail
id=$1; d=raw/$id; mkdir -p $d; B=https://snapshot.ubuntu.com/ubuntu/$id/dists
for s in noble-updates noble-security; do
  [ -s $d/$s.InRelease ] || curl -sSf --max-time 60 -o $d/$s.InRelease $B/$s/InRelease
  [ -s $d/$s.main.xz ] || curl -sSf --max-time 120 -o $d/$s.main.xz $B/$s/main/binary-amd64/Packages.xz
  want=$(awk '/^SHA256:/{f=1;next} /^[A-Za-z]/{f=0} f && $3=="main/binary-amd64/Packages.xz"{print $1}' $d/$s.InRelease)
  got=$(sha256sum $d/$s.main.xz | cut -d' ' -f1); [ "$want" = "$got" ] || { echo "$id $s Packages.xz hash mismatch"; exit 1; }
done
for s in noble-updates noble-security; do [ -s $d/$s.main ] || xz -dc $d/$s.main.xz > $d/$s.main; done
hwe=$(cat $d/noble-updates.main $d/noble-security.main | awk 'BEGIN{RS="";FS="\n"} /\nPackage: linux-image-virtual-hwe-24.04\n|^Package: linux-image-virtual-hwe-24.04\n/{for(i=1;i<=NF;i++) if($i ~ /^Version:/) print substr($i,10)}' | sort -uV | tr '\n' ',')
fix=0; for pv in "apt 2.8.4ubuntu0.1" "apt-utils 2.8.4ubuntu0.1" "libapt-pkg6.0t64 2.8.4ubuntu0.1" "bind9-dnsutils 1:9.18.39-0ubuntu0.24.04.9" "bind9-host 1:9.18.39-0ubuntu0.24.04.9" "bind9-libs 1:9.18.39-0ubuntu0.24.04.9" "libmspack0t64 0.11-1.1ubuntu0.24.04.1" "libpcre2-8-0 10.42-4ubuntu2.2" "python3-twisted 24.3.0-1ubuntu0.3"; do
  set -- $pv; awk -v p="$1" -v v="$2" 'BEGIN{RS="";FS="\n";r=1} {a=0;b=0;for(i=1;i<=NF;i++){if($i=="Package: "p)a=1;if($i=="Version: "v)b=1} if(a&&b){r=0;exit}} END{exit r}' $d/noble-security.main && fix=$((fix+1)); done
ud=$(grep -m1 '^Date:' $d/noble-updates.InRelease | cut -c7-); sd=$(grep -m1 '^Date:' $d/noble-security.InRelease | cut -c7-)
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s/9\n' $id "$ud" $(sha256sum $d/noble-updates.InRelease | cut -c1-64) "$sd" $(sha256sum $d/noble-security.InRelease | cut -c1-64) "$hwe" $fix
