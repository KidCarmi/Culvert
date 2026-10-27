# shellcheck shell=bash
# m2-guest.sh — guest side of the #1528 M2 hardening checkpoint (run as root,
# through gpriv, with M2SUM and M2URL prepended by the harness).
#
# Every observation goes through `obs`, which records the command's exit
# status and line count beside its stdout and stderr:
#   m2-obs <ctx> <name> rc=<n> lines=<n>
#   m2-out <ctx> <name>| <stdout line>
#   m2-err <ctx> <name>| <stderr line>
# The verdicts live in m2-verdict.py on the runner and refuse anything that
# was not acquired with rc=0 and parsed: a failed read is never an empty one.
# The last line is "m2-end"; without it the transcript is incomplete.
# Temporary files: /run/culvert-lab-m2.err and /run/culvert-lab-m2probe
# (tmpfs), both removed before the end marker.
E=/run/culvert-lab-m2.err
obs() { local ctx="$1" name="$2" out rc; shift 2
  out="$("$@" 2>"$E")"; rc=$?
  echo "m2-obs $ctx $name rc=$rc lines=$(printf '%s' "$out" | grep -c '')"
  [ -n "$out" ] && printf '%s\n' "$out" | sed "s/^/m2-out $ctx $name| /"
  [ -s "$E" ] && sed "s/^/m2-err $ctx $name| /" "$E"
  return 0; }
# emit CTX NAME RC OUT — record an observation whose command already ran, so
# the SAME output can be both recorded and used (no second, unchecked read).
emit() { local ctx="$1" name="$2" rc="$3" out="$4"
  echo "m2-obs $ctx $name rc=$rc lines=$(printf '%s' "$out" | grep -c '')"
  [ -n "$out" ] && printf '%s\n' "$out" | sed "s/^/m2-out $ctx $name| /"
  [ -s "$E" ] && sed "s/^/m2-err $ctx $name| /" "$E"
  return 0; }
# alive PID — the process still exists and is not a zombie. A process whose
# status cannot be read but whose /proc entry exists counts as alive, so an
# unverifiable case is never mistaken for a disappearance.
alive() { [ -d "/proc/$1" ] || return 1
  ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null; }
echo "m2-begin boot_id=$(cat /proc/sys/kernel/random/boot_id)"

# ── host: settings, ordering, io_uring ──────────────────────────────────────
obs host sysctl sysctl -n kernel.io_uring_disabled kernel.unprivileged_bpf_disabled net.ipv4.ip_forward
obs host sysctl-file sha256sum /etc/sysctl.d/99-culvert-hardening.conf
obs host io_uring-setup python3 -c 'import ctypes,errno
l=ctypes.CDLL(None,use_errno=True); p=ctypes.create_string_buffer(120)
r=l.syscall(425,1,p); e=ctypes.get_errno()
print("opened" if r>=0 else "errno:"+errno.errorcode.get(e,str(e)))'
# The sysctl refuses NEW rings; one created before it applied would survive.
# Ordering evidence for THIS boot: systemd-sysctl (which applies
# /etc/sysctl.d) must have finished before containerd and dockerd started.
obs host ordering systemctl show -p Id -p ActiveEnterTimestampMonotonic -p ExecMainStartTimestampMonotonic systemd-sysctl.service containerd.service docker.service
obs host sysctl-journal journalctl -b -u systemd-sysctl.service --no-pager -o cat
# Census of io_uring descriptors. Every failed read is resolved before it is
# counted: an fd directory that cannot be listed is "exited" only if the
# process is gone, otherwise "unreadable-alive" (fails). A descriptor whose
# readlink fails is read once more; then it is "fd-vanished" only if its
# /proc entry is gone, otherwise "fd-unreadable" (fails). Each non-success
# outcome is recorded individually; successful reads are counted.
fd_census() { local p pid fds fd f t procs=0 alive_bad=0 exited=0 seen=0 rings=0 vanished=0 unread=0
  for p in /proc/[0-9]*; do pid="${p#/proc/}"; procs=$((procs+1))
    if ! fds="$(ls -A "$p/fd" 2>/dev/null)"; then
      if alive "$pid"; then alive_bad=$((alive_bad+1)); echo "unreadable-alive $pid $(cat "$p/comm" 2>/dev/null)"
      else exited=$((exited+1)); echo "exited $pid"; fi
      continue; fi
    for fd in $fds; do f="$p/fd/$fd"
      if t="$(readlink "$f" 2>/dev/null)" || t="$(readlink "$f" 2>/dev/null)"; then
        seen=$((seen+1))
        [ "$t" = "anon_inode:[io_uring]" ] && { rings=$((rings+1)); echo "ring $pid $(cat "$p/comm" 2>/dev/null) $f"; }
      elif [ -L "$f" ]; then unread=$((unread+1)); echo "fd-unreadable $pid $fd $(cat "$p/comm" 2>/dev/null)"
      else vanished=$((vanished+1)); echo "fd-vanished $pid $fd"; fi
    done
  done
  echo "summary procs=$procs fds=$seen rings=$rings unreadable_alive=$alive_bad exited=$exited fd_vanished=$vanished fd_unreadable=$unread"; }
obs host io_uring-fds fd_census
obs host modules cat /proc/modules
obs host nics sh -c 'for i in /sys/class/net/*/device/driver; do [ -e "$i" ] && echo "${i%/device/driver}" "$(basename "$(readlink -f "$i")")"; done; true'
obs host mdb bridge mdb show

# ── network contexts: the host namespace and each container's ──────────────
# The bounded argument depends on exactly these three namespaces; any other
# network namespace on the guest fails the check (census below).
# One line per process: "ns <netns> <pid>", or, when the read fails,
# "exited <pid>" (confirmed gone) or "unreadable-alive <pid> <comm>" (fails).
# The verdict reconciles the namespaces seen here with the three expected
# contexts acquired separately below: a missing one fails, an extra one fails.
netns_census() { local p pid n procs=0 read=0 bad=0 exited=0
  for p in /proc/[0-9]*; do pid="${p#/proc/}"; procs=$((procs+1))
    if n="$(readlink "$p/ns/net" 2>/dev/null)"; then read=$((read+1)); echo "ns $n $pid"
    elif alive "$pid"; then bad=$((bad+1)); echo "unreadable-alive $pid $(cat "$p/comm" 2>/dev/null)"
    else exited=$((exited+1)); echo "exited $pid"; fi
  done
  echo "summary procs=$procs read=$read unreadable_alive=$bad exited=$exited"; }
obs host netns-census netns_census
ctxs="host:$$"
for c in culvert culvert-clamav; do
  pid="$(docker inspect -f '{{.State.Pid}}' "$c" 2>"$E")"; rc=$?
  emit "$c" pid "$rc" "$pid"
  case "$pid" in ''|0|*[!0-9]*) ;; *) [ "$rc" = 0 ] && ctxs="$ctxs $c:$pid" ;; esac
done
for cp in $ctxs; do ctx="${cp%%:*}"; pid="${cp#*:}"; N="nsenter --net=/proc/$pid/ns/net"
  obs "$ctx" netns readlink "/proc/$pid/ns/net"
  obs "$ctx" links $N ip -d -o link show
  obs "$ctx" routes4 $N ip -o -4 route show table all
  obs "$ctx" routes6 $N ip -o -6 route show table all
  obs "$ctx" qdisc $N tc qdisc show
  obs "$ctx" nft-json $N nft -j list ruleset
  obs "$ctx" nft-text $N nft list ruleset
  # Per interface, in this namespace (/proc/sys/net is resolved in the
  # reader's network namespace): IPv6 forwarding, seg6 and ioam6 ingress.
  obs "$ctx" ipv6-conf $N sh -c 'for d in /proc/sys/net/ipv6/conf/*; do [ -d "$d" ] || exit 3
    echo "${d##*/} forwarding=$(cat $d/forwarding) seg6=$(cat $d/seg6_enabled) ioam6=$(cat $d/ioam6_enabled) disable=$(cat $d/disable_ipv6)"; done'
done

# ── containers: processes, then the in-container probe ──────────────────────
curl -fsS -m 30 -o /run/culvert-lab-m2probe "$M2URL" || echo "m2-probe-fetch-failed"
got="$(sha256sum /run/culvert-lab-m2probe 2>/dev/null | cut -c1-64)"
echo "m2-probe-sha256 want=$M2SUM got=${got:-none}"
chmod 0755 /run/culvert-lab-m2probe 2>/dev/null || true
for c in culvert culvert-clamav; do
  echo "m2-container $c $(docker inspect -f 'id={{printf "%.12s" .Id}} started={{.State.StartedAt}} restarts={{.RestartCount}} user={{.Config.User}} capdrop={{.HostConfig.CapDrop}} capadd={{.HostConfig.CapAdd}} privileged={{.HostConfig.Privileged}} secopt={{.HostConfig.SecurityOpt}}' "$c" 2>&1)"
  # The capability reads below iterate over EXACTLY this recorded list; the
  # verdict reconciles every listed pid with one outcome line.
  top="$(docker top "$c" -eo pid 2>"$E")"; rc=$?
  emit "$c" top "$rc" "$top"
  [ "$rc" = 0 ] || top=""
  for p in $(printf '%s\n' "$top" | tail -n +2); do
    python3 -c 'import sys
c,p=sys.argv[1:3]; d={}
for l in open("/proc/%s/status" % p):
    k,_,v=l.partition(":"); d[k]=v.strip()
e=int(d["CapEff"],16); b=int(d["CapBnd"],16)
print("m2-proc %s %s comm=%s uid=%s capeff=%s capbnd=%s netraw-eff=%d netraw-bnd=%d netadmin-bnd=%d sysadmin-bnd=%d seccomp=%s" % (c,p,open("/proc/%s/comm" % p).read().strip().replace(" ","_"),d["Uid"].split()[1],d["CapEff"],d["CapBnd"],(e>>13)&1,(b>>13)&1,(b>>12)&1,(b>>21)&1,d.get("Seccomp")))' "$c" "$p" 2>/dev/null \
      || { if alive "$p"; then echo "m2-proc-unreadable $c $p"; else echo "m2-proc-exited $c $p"; fi; }
  done
  if [ "$got" = "$M2SUM" ] && docker cp /run/culvert-lab-m2probe "$c:/tmp/.culvert-m2probe" >/dev/null 2>&1; then
    o="$(docker exec -u 0 "$c" /tmp/.culvert-m2probe 2>&1)"; echo "m2-probe $c as=root rc=$? $o"
    o="$(docker exec "$c" /tmp/.culvert-m2probe 2>&1)"; echo "m2-probe $c as=default rc=$? $o"
    docker exec -u 0 "$c" rm -f /tmp/.culvert-m2probe; echo "m2-probe-removed $c rc=$?"
  else echo "m2-probe-not-run $c"; fi
done
rm -f /run/culvert-lab-m2probe

# ── ClamAV still scans in this state ─────────────────────────────────────────
obs clamav version docker exec culvert-clamav clamdscan --version
# Built at run time (no file in the repository carries the signature).
# clamdscan exits 1 when it finds something; the verdict requires rc=1 + FOUND.
eicar_scan() { printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | docker exec -i culvert-clamav clamdscan --no-summary --stream -; }
obs clamav eicar eicar_scan
obs clamav freshclam docker exec culvert-clamav sh -c 'tail -n 200 /var/log/clamav/freshclam.log | grep -E "up.to.date|updated|ERROR|WARNING" | tail -3'
rm -f "$E"
echo "m2-end"
