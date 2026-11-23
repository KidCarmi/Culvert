#!/bin/sh
# $1: extra unit line; $2: launcher prefix for the child ("" | setsid | "sudo -n")
cat > /tmp/stubchild.sh <<'C'
#!/bin/sh
trap '' TERM
while :; do sleep 0.05; done
C
printf '#!/bin/sh\n%s sh /tmp/stubchild.sh &\nexec sleep 100000\n' "$2" > /tmp/stubmain.sh
printf '[Service]\nType=simple\nExecStart=/bin/sh /tmp/stubmain.sh\nRestart=on-failure\nRestartSec=5s\n%s\n' "$1" > /etc/systemd/system/stubctl.service
systemctl daemon-reload; systemctl reset-failed stubctl 2>/dev/null; systemctl start stubctl; sleep 1
M=$(systemctl show stubctl -p MainPID --value); [ "$M" -gt 1 ] || { echo "unit did not start"; exit 2; }
CG=/sys/fs/cgroup$(grep "^0::" /proc/$M/cgroup | cut -c4-)
OLD=$(grep -v "^$M\$" $CG/cgroup.procs | tr '\n' ' ')
t0=$(date +%s%N); kill -9 "$M"; newat=""; overlap=""; goneat=""
i=0; while [ $i -lt 1200 ]; do i=$((i+1))
  alive=no; for p in $OLD; do [ -d /proc/$p ] && alive=yes; done
  [ -z "$goneat" ] && [ $alive = no ] && goneat=$(( ($(date +%s%N) - t0) / 1000000 ))
  N=$(systemctl show stubctl -p MainPID --value)
  if [ "$N" -gt 1 ] && [ "$N" != "$M" ]; then newat=$(( ($(date +%s%N) - t0) / 1000000 )); overlap=$alive; break; fi
  sleep 0.1
done
echo "unit='$1' launcher='$2' old_children_gone_ms=${goneat:-never} new_main_ms=${newat:-none} old_child_alive_when_new_main_started=${overlap:-n/a}"
systemctl kill -s KILL stubctl 2>/dev/null; systemctl stop stubctl 2>/dev/null; for p in $OLD; do kill -9 $p 2>/dev/null; done; true
