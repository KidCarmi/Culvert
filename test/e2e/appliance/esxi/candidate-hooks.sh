#!/usr/bin/env bash
# Loaded once, before cmd_qualify; all referenced sources belong to the freeze.
: "${ESXI_BIND:?controller LAN address required}"

# Bind both lifecycle hooks to the exact candidate before any reboot dispatch.
ESXI_SHUTDOWN_HELPER=''
case ${ESXI_ENGINE_SOURCE:-} in
  6248daf72a5312e75062e2c2823438911604af7f) ESXI_SHUTDOWN_HELPER=lifecycle-shutdown.py ;;
  246cb73d4b62d7a4baf2fcb8558ad8622657529a) ESXI_SHUTDOWN_HELPER=lifecycle-shutdown-246.py ;;
esac
readonly ESXI_SHUTDOWN_HELPER

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
  if [[ -n $ESXI_SHUTDOWN_HELPER ]]; then
    # Observe the actual authenticated ancestor chain. Do not replace the
    # shared lifecycle's nested sudo/bash maintenance command with execv.
    ( set -o noclobber
      python3 "$ADAPTER_HERE/$ESXI_SHUTDOWN_HELPER" before | gpriv --timeout 60 > "$SEC/lifecycle-shutdown-before.json"
    )
  fi
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
  if [[ -n $ESXI_SHUTDOWN_HELPER ]]; then
    if ! ( set -o noclobber
      python3 "$ADAPTER_HERE/$ESXI_SHUTDOWN_HELPER" after --before "$SEC/lifecycle-shutdown-before.json" \
        | gpriv --timeout 60 > "$SEC/lifecycle-shutdown-after.json"
    ) || ! python3 "$ADAPTER_HERE/$ESXI_SHUTDOWN_HELPER" verify \
      --before "$SEC/lifecycle-shutdown-before.json" --after "$SEC/lifecycle-shutdown-after.json" \
      --timing "$EV/timing-maintenance.jsonl" --output "$EV/lifecycle-shutdown-verdict.json"; then
      check ESXi original-console-shutdown fail 'Original local session teardown or120s observed recovery unproven; no retry.'
      STOP=1
      return 90
    fi
    check ESXi original-console-shutdown pass 'Original PAM/console session stopped within10s without timeout/SIGKILL; observed recovery within120s. Separate traffic readiness gate still required.'
  fi
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
