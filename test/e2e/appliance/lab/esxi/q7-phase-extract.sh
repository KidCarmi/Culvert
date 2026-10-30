#!/bin/bash
# q7-phase-extract.sh — READ-ONLY phase timeline of recent maintenance reboots.
#
# Purpose: locate where a Q7 recovery spent its time WITHOUT a new reboot.
# The Q7 clock starts at the authenticated acceptance of
# `culvert-os-update reboot`, so it covers BOTH halves:
#   A. the old boot's shutdown: stack stop (proxy stop_grace_period 60 s,
#      in-process shutdown envelope up to ~51 s), then systemd shutdown;
#   B. the new boot: firmware/kernel, docker, culvert-stack-resume,
#      ClamAV start→healthy (the proxy container does not START before
#      ClamAV is healthy: docker-compose.yml depends_on service_healthy),
#      then the proxy's own startup.
# Every published port answers "connection refused" from the moment the
# containers stop in A until the proxy container starts in B, so an external
# "refused" sample cannot tell A from B. Only the guest journal can.
#
# Run as root on the authenticated VM console of the test VM:
#   bash q7-phase-extract.sh [BOOTS]  > q7-phases.txt     (BOOTS default 6)
# It changes nothing: journalctl/docker reads only. It prints only fixed
# grep patterns from Culvert units and container logs (no request bodies,
# headers, tokens or credentials are matched), in UTC with microseconds.
set -uo pipefail
BOOTS="${1:-6}"
[[ "$BOOTS" =~ ^[0-9]+$ ]] || { echo "BOOTS must be a number" >&2; exit 2; }
export LC_ALL=C TZ=UTC
J=(journalctl --no-pager -q -o short-iso-precise)

echo "# q7-phase-extract v1  host=$(hostname)  now=$(date -u +%FT%T.%6NZ)  kernel=$(uname -r)"
echo "# journald storage: $(ls -d /var/log/journal 2>/dev/null || echo 'VOLATILE (no /var/log/journal): previous boots unavailable')"
echo "## boots (index, boot id, first entry, last entry)"
journalctl --no-pager --list-boots 2>&1 | tail -n "$((BOOTS + 1))"

# Fixed, product-owned patterns. Each line is one phase marker.
PAT_SYS='culvert-os-update\[|culvert-stack-resume|Starting docker\.service|Started docker\.service|Stopping docker\.service|Stopped docker\.service|Starting containerd\.service|Started containerd\.service|Stopped containerd\.service|Reached target (network-online|multi-user|shutdown|reboot|final)\.target|systemd-networkd-wait-online|Finished culvert-firstboot|culvert-maint\.service|Linux version|systemd-shutdown|Stopping culvert-|kernel: (EXT4-fs \(.*\): mounted|Run /init)'

for ((b = -BOOTS + 1; b <= 0; b++)); do
  id="$(journalctl --no-pager --list-boots 2>/dev/null | awk -v b="$b" '$1==b{print $2}')"
  [[ -n "$id" ]] || continue
  echo
  echo "## boot $b  id=$id"
  echo "### first / last journal entry (wall clock)"
  "${J[@]}" -b "$b" -n 1 --reverse 2>/dev/null | head -n 1 || true
  "${J[@]}" -b "$b" -n 1 2>/dev/null | tail -n 1 || true
  echo "### phase markers (wall clock)"
  "${J[@]}" -b "$b" 2>/dev/null | grep -E "$PAT_SYS" | grep -v -E 'password|token|secret' | head -n 200
  echo "### same markers, monotonic (seconds since this boot's kernel start)"
  journalctl --no-pager -q -o short-monotonic -b "$b" 2>/dev/null | grep -E "$PAT_SYS" | grep -v -E 'password|token|secret' | head -n 200
done

echo
echo "## container lifecycle as Docker records it (current container objects)"
for c in culvert culvert-clamav; do
  docker inspect -f "$c created={{.Created}} started={{.State.StartedAt}} finished={{.State.FinishedAt}} restarts={{.RestartCount}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}" "$c" 2>&1 | head -n 1
done

# Container logs persist across `compose stop`/`up -d` (no recreate), so they
# cover the failed boot too. Only lifecycle lines are printed.
SINCE="$(journalctl --no-pager --list-boots 2>/dev/null | awk '$1 ~ /^-?[0-9]+$/' | tail -n "$BOOTS" | head -n 1 | awk '{print $4"T"$5}')"
[[ "$SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}$ ]] || SINCE=""
echo
echo "## culvert-clamav lifecycle lines since ${SINCE:-unknown}"
docker logs --timestamps ${SINCE:+--since "$SINCE"} culvert-clamav 2>&1 \
  | grep -E 'Starting ClamAV|Socket for clamd not found yet, retrying \((0|10|20|30|60|90|120)/|Set stacksize|Loaded [0-9]+ signatures|Database correctly|clamd.*(started|listening|Listening)|Received (SIGTERM|signal)|Stopping|exit|Exit|Shutting|shutdown' \
  | head -n 300
echo
echo "## culvert (proxy) lifecycle lines since ${SINCE:-unknown}"
docker logs --timestamps ${SINCE:+--since "$SINCE"} culvert 2>&1 \
  | grep -E 'Shutdown|Draining [0-9]+ active tunnel|Drain (budget exhausted|timeout)|All tunnels drained|abandon|SecurityScan: ClamAV (connected|unreachable)|Proxy (listening|started)|listening on|Listening on|Admin UI|starting Culvert|Culvert v|signal' \
  | grep -v -E 'password|token|secret' | head -n 300
echo
echo "# end"
