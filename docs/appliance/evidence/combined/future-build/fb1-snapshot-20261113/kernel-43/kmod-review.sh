#!/bin/bash
# kmod-review.sh KDIR KVER PROVISION_DIR: the prepare-guest.sh section-2 module
# checks run OFFLINE on the extracted kernel module packages of KVER.
set -euo pipefail
K=$1; v=$2; P=$3; R=$K/root-$v
mkdir -p $R/etc/modprobe.d
for d in $K/linux-modules-$v-generic_*.deb $K/linux-main-modules-*-$v-generic_*.deb; do dpkg-deb -x "$d" $R; done
kv=$v-generic; MD=$R/lib/modules/$kv; [ -d $MD ] || MD=$R/usr/lib/modules/$kv
base=$(dirname $(dirname $MD)); base=$(dirname $base)
depmod -b "$base" $kv
install -m 0644 $P/modprobe-culvert-unused.conf $R/etc/modprobe.d/culvert-unused.conf
denied_mods="$(awk '$1=="install" && $3=="/bin/false"{print $2}' $R/etc/modprobe.d/culvert-unused.conf)"
echo "denied: $(wc -w <<<"$denied_mods")"
fail=0
for m in $denied_mods kvm-amd can-raw; do
  modprobe -d "$base" -S $kv -C $R/etc/modprobe.d -n -v "$m" 2>&1 | tail -n 1 | grep -qE '^install /bin/false[[:space:]]*$' || { echo "modprobe would still load $m"; fail=1; }
done
netload="$(awk '$1=="alias" && $2 ~ /^(net-pf-[0-9]+$|net-pf-[0-9]+-proto-|tcp-ulp-)/ {print $3}' $MD/modules.alias | tr - _ | sort -u)"
reviewed="$(awk '!/^#/ && NF {print $1}' $P/net-autoload-reviewed.txt | tr - _ | sort -u)"
denied_norm="$(tr ' -' '\n_' <<<"$denied_mods" | awk NF | sort -u)"
unreviewed="$(comm -23 <(printf '%s\n' "$netload") <(sort -u <(printf '%s\n' "$denied_norm" "$reviewed")))"
stale="$(comm -13 <(printf '%s\n' "$netload") <(printf '%s\n' "$reviewed"))"
echo "unreviewed: [$(tr '\n' ' ' <<<"$unreviewed")]"; echo "stale: [$(tr '\n' ' ' <<<"$stale")]"
echo "net autoload surface: $(wc -l <<<"$netload") modules, $(comm -12 <(printf '%s\n' "$netload") <(printf '%s\n' "$denied_norm") | wc -l) denied, $(wc -l <<<"$reviewed") reviewed"
printf '%s\n' "$netload" > $K/netload-$v.txt
(cd $MD && find . -name '*.ko*' | sed -E 's/\.ko(\.(zst|xz|gz))?$//' | sort) > $K/modules-$v.txt
echo "modules: $(wc -l < $K/modules-$v.txt)"
[[ -z "$unreviewed" && -z "$stale" && $fail -eq 0 ]] && echo "RESULT PASS" || echo "RESULT FAIL"
