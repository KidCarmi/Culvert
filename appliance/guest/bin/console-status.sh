#!/usr/bin/env bash
# console-status.sh — renders the Culvert appliance status banner.
#   render  → write /etc/issue (tty1 login banner) and refresh the idle getty
#   print   → print the same text to stdout (used by `culvert-appliance status`)
# Readiness is read GENERICALLY from the proxy port's /ready JSON (status +
# every entry under .checks); it never invents its own notion of readiness.
set -uo pipefail

MODE="${1:-print}"
STATE=/var/lib/culvert-appliance
RUN=/run/culvert-appliance
ETC=/etc/culvert-appliance
# shellcheck source=/dev/null
[[ -f "$ETC/manifest.env" ]] && . "$ETC/manifest.env"
APPLIANCE_VERSION="${APPLIANCE_VERSION:-unknown}"

ips() { ip -4 -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $2 "=" $4}' | tr '\n' ' '; }
primary_ip() { ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' | head -n1; }

render() {
  local ip; ip="$(primary_ip)"; [[ -z "$ip" ]] && ip="<no-address>"
  local phase="not started"; [[ -f "$STATE/phase" ]] && phase="$(cat "$STATE/phase")"
  echo "────────────────────────────────────────────────────────────────────────"
  echo " Culvert Appliance ${APPLIANCE_VERSION}   host: $(hostname)   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "────────────────────────────────────────────────────────────────────────"
  echo " Addresses : $(ips)"
  echo " Admin UI  : https://${ip}:9090      Proxy: http://${ip}:8080"
  echo " First boot: ${phase}"
  if [[ -f "$STATE/error" ]]; then
    echo " ERROR     : $(head -c 300 "$STATE/error")"
    echo "             log: /var/log/culvert-appliance/firstboot.log   retry: sudo systemctl restart culvert-appliance-firstboot"
  fi
  # ── readiness, straight from the application ──
  local body code
  body="$(curl -sS -m 3 -o /dev/stdout -w '\n%{http_code}' http://127.0.0.1:8080/ready 2>/dev/null)" || body=$'\n000'
  code="${body##*$'\n'}"; body="${body%$'\n'*}"
  if [[ "$code" == "000" ]]; then
    echo " Readiness : proxy not answering on 127.0.0.1:8080 yet"
  elif command -v jq >/dev/null 2>&1 && jq -e . >/dev/null 2>&1 <<<"$body"; then
    echo " Readiness : $(jq -r '[.status // "?", (.version // empty)] | join("  app ")' <<<"$body")   (HTTP ${code}; /ready?strict=1 → $(curl -sS -m 3 -o /dev/null -w '%{http_code}' 'http://127.0.0.1:8080/ready?strict=1' 2>/dev/null || echo 000))"
    jq -r '(.checks // {}) | to_entries[] | "   " + .key + ": " + (.value.status // "?") + (if .value.detail then " (" + (.value.detail|tostring) + ")" else "" end)' <<<"$body" 2>/dev/null | fold -s -w 78
  else
    echo " Readiness : HTTP ${code} (non-JSON body)"
  fi
  local setup
  setup="$(curl -sk -m 3 https://127.0.0.1:9090/api/setup/status 2>/dev/null | jq -r '.needsSetup // empty' 2>/dev/null)"
  [[ "$setup" == "true" ]] && echo " Setup     : NOT DONE — open https://${ip}:9090 to create the first admin (do this from a trusted network)"
  [[ "$setup" == "false" ]] && echo " Setup     : complete"
  # ── console access ──
  if [[ -s "$RUN/console-password" ]] && id culvert >/dev/null 2>&1; then
    local lastchg; lastchg="$(getent shadow culvert | cut -d: -f3)"
    if [[ "$lastchg" == "0" ]]; then
      echo " Console   : user 'culvert'  one-time password: $(cat "$RUN/console-password")   (you must change it at first login)"
    else
      rm -f "$RUN/console-password"
    fi
  fi
  if [[ -f "$ETC/mgmt-allow.conf" ]] && [[ -s "$ETC/mgmt-allow.conf" ]]; then
    echo " Mgmt ACL  : ssh/admin UI limited to $(tr '\n' ' ' < "$ETC/mgmt-allow.conf")"
  fi
  echo " Network   : $(if [[ -f /etc/netplan/60-culvert-appliance.yaml ]]; then echo "static (/etc/netplan/60-culvert-appliance.yaml)"; else echo "DHCP"; fi) — change: sudo culvert-appliance netconfig --help"
  echo "────────────────────────────────────────────────────────────────────────"
  echo
}

case "$MODE" in
  print) render ;;
  render)
    tmp="$(mktemp)"; render > "$tmp"
    if ! cmp -s "$tmp" /etc/issue; then
      cat "$tmp" > /etc/issue
      # Redisplay the banner on an idle tty1 (never kick a logged-in session).
      if ! who 2>/dev/null | awk '$2=="tty1"{f=1} END{exit !f}'; then
        systemctl try-restart getty@tty1.service >/dev/null 2>&1 || true
      fi
    fi
    rm -f "$tmp" ;;
  *) echo "usage: $0 render|print" >&2; exit 2 ;;
esac
