#!/usr/bin/env bash
# Loaded once, before cmd_qualify; all referenced sources belong to the freeze.
: "${ESXI_BIND:?controller LAN address required}"

esxi_p1_stage() {
  local extra=()
  if [[ $1 == network-before && ${ESXI_CONTINUE_UNDISPATCHED:-0} == 1 ]]; then
    extra=(--continue-undispatched --continuation-proof "$SEC/confirmation-dispatch-observation-v2.json")
  fi
  python3 "$ADAPTER_HERE/p1-regressions.py" --scope "$ESXI_SCOPE" --bind "$ESXI_BIND" \
    --campaign "${ESXI_P1_CAMPAIGN:-initial}" "${extra[@]}" "$1"
}

lab_before_reboot() {
  local suffix=''
  [[ ${ESXI_CONTINUE_UNDISPATCHED:-0} != 1 ]] || suffix='-continuation'
  esxi_p1_stage network-before > "$EV/p1-${ESXI_P1_CAMPAIGN:-initial}-network-before-controller$suffix.txt" 2>&1
  python3 "$ADAPTER_HERE/timing-diagnostic.py" observe --scope "$ESXI_SCOPE" \
    --label maintenance --host "$LAB_HOST" --seconds 1800 --interval 5 \
    > "$EV/timing-observer-controller.txt" 2>&1 &
  ESXI_TIMING_PID=$!
  local n
  for n in {1..30}; do
    [[ -s $EV/timing-maintenance.jsonl ]] && break
    kill -0 "$ESXI_TIMING_PID" 2>/dev/null || return 90
    sleep 1
  done
  [[ -s $EV/timing-maintenance.jsonl ]] || return 90
  python3 "$ADAPTER_HERE/timing-diagnostic.py" mark --scope "$ESXI_SCOPE" --label maintenance
}

lab_after_reboot_observation() {
  local rc=0
  wait "$ESXI_TIMING_PID" || rc=$?
  if [[ $rc == 0 ]] && python3 - "$EV/timing-maintenance.jsonl" <<'PY'
import json,sys
rows=[json.loads(x) for x in open(sys.argv[1],encoding='utf-8')]
assert any(r['event']=='all_services_returned_after_failure' for r in rows)
PY
  then check ESXi independent-reboot-timing pass 'TCP, proxy health and ready operator status returned after independently observed failures; timestamped samples retained.'
  else check ESXi independent-reboot-timing fail 'Independent readiness timing incomplete; preserve all observations.'; fi
  if [[ $STOP == 0 ]]; then
    esxi_p1_stage network-after > "$EV/p1-${ESXI_P1_CAMPAIGN:-initial}-network-after-controller.txt" 2>&1
  fi
}

# Preserve API stdout unchanged. Record only timing, never arguments, cookies,
# response bodies or credentials. Subshell callers get unique evidence names.
eval "$(declare -f api | sed '1s/^api /esxi_original_api /')"
api() {
  if [[ ${1:-} == GET && ${2:-} == /api/backups ]]; then
    local timer="$EV/backup-api-$(date +%s)-$RANDOM" rc=0
    python3 "$ADAPTER_HERE/request-timestamp.py" "$timer-start.json"
    esxi_original_api "$@" || rc=$?
    python3 "$ADAPTER_HERE/request-timestamp.py" "$timer-end.json" "$rc"
    return "$rc"
  fi
  esxi_original_api "$@"
}
