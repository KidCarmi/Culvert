#!/usr/bin/env bash
# test/e2e/appliance/recovery-custody.sh — bounded, enforced harness steps and
# the quarantine chain of custody for the F-DISK recovery scenario (ASTRA item 5).
# Sourced by upgrade-enospc-qualify.sh; proven red/green with no lab by
# recovery-custody_test.sh (which stubs `docker`). Expects from the caller:
# check, diagnose, write_report_and_exit, DIND, MP, EVID, STEPLOG,
# CUSTODY_NAMES, CUSTODY_TREE.
# shellcheck disable=SC2034  # CUSTODY_* are read by the caller

# Every mutating step of the recovery scenario (compose stop/start/up/restart,
# the cache reset, the quarantine deletion) runs under a hard deadline and its
# exit status DECIDES: a timeout or non-zero exit is a FAIL check and ends the
# run (exit 1). Before, these ran as `... >/dev/null 2>&1 || true`, so a
# deletion that failed or a restart that never happened was invisible, and every
# verdict after it was measured against a state nobody had established.
# `timeout` cannot run a shell function, so steps call `docker exec "$DIND"`.
run_bounded(){ local secs="$1" label="$2"; shift 2; local rc=0 out
  out="$(timeout --kill-after=10 "$secs" "$@" 2>&1)" || rc=$?
  printf '%s %s rc=%d bound=%ss\n%s\n' "$(date -u +%FT%TZ)" "$label" "$rc" "$secs" "${out:0:4000}" >> "$STEPLOG"
  return "$rc"; }
step(){ local sc="$1" name="$2" secs="$3"; shift 3; local rc=0 why
  run_bounded "$secs" "$sc/$name" "$@" || rc=$?
  (( rc == 0 )) && return 0
  why="exit $rc"; if (( rc == 124 || rc == 137 )); then why="timed out after ${secs}s"; fi
  check "$sc" "step-$name" fail "required harness step '$name' $why (output in steps.log)"
  diagnose "step-$name"; write_report_and_exit; }
# quarantine_custody <sc> <tag> — the chain of custody for every quarantined
# copy (catfeeddb.corrupt.*) and import scratch dir (catfeeddb.importingtmp.*)
# on the data volume, taken BEFORE anything deletes them. Under
# $EVID/custody/<tag>/: inventory.txt (name, file count, bytes per entry),
# manifest.sha256 (sha256 of every file, sorted — the content record) and
# meta.tar (every file under 1 MiB byte-for-byte: MANIFEST, KEYREGISTRY, …).
# Sets CUSTODY_NAMES (exact top-level names, for delete-by-name) and
# CUSTODY_TREE (sha256 of manifest.sha256). Any failure FAILS the run: a copy
# that cannot be recorded is never deleted.
quarantine_custody(){ local sc="$1" tag="$2" d="$EVID/custody/$2" n files=0 bytes=0 f b lines sz
  mkdir -p "$d"; : > "$d/inventory.txt"
  CUSTODY_NAMES="$(timeout 60 docker exec "$DIND" sh -c "cd '$MP' && for e in catfeeddb.corrupt.* catfeeddb.importingtmp.*; do [ -e \"\$e\" ] && echo \"\$e\"; done; true")" \
    || { check "$sc" "custody-$tag" fail "could not list the data volume ($MP)"; write_report_and_exit; }
  CUSTODY_NAMES="$(printf '%s\n' "$CUSTODY_NAMES" | sed '/^$/d' | LC_ALL=C sort | tr '\n' ' ')"; CUSTODY_NAMES="${CUSTODY_NAMES% }"
  if [[ -z "$CUSTODY_NAMES" ]]; then CUSTODY_TREE=none; : > "$d/manifest.sha256"
    check "$sc" "custody-$tag" pass "inventory: nothing quarantined on the volume — nothing to hash or delete"; return 0; fi
  for n in $CUSTODY_NAMES; do
    [[ "$n" =~ ^catfeeddb\.(corrupt|importingtmp)\.[A-Za-z0-9._-]+$ ]] \
      || { check "$sc" "custody-$tag" fail "unexpected entry name '$n' — refusing to inventory/delete it"; write_report_and_exit; }
    sz="$(timeout 120 docker exec "$DIND" sh -c "cd '$MP' && find '$n' -type f | wc -l; find '$n' -type f -exec stat -c %s {} + | awk '{s+=\$1} END{print s+0}'")" \
      || { check "$sc" "custody-$tag" fail "could not size $n"; write_report_and_exit; }
    f="$(sed -n 1p <<<"$sz" | tr -d ' ')"; b="$(sed -n 2p <<<"$sz" | tr -d ' ')"
    [[ "${f:-}" =~ ^[0-9]+$ && "${b:-}" =~ ^[0-9]+$ ]] || { check "$sc" "custody-$tag" fail "could not size $n (files='${f:-}' bytes='${b:-}')"; write_report_and_exit; }
    printf '%s files=%s bytes=%s\n' "$n" "$f" "$b" >> "$d/inventory.txt"; files=$((files+f)); bytes=$((bytes+b))
  done
  timeout 900 docker exec "$DIND" sh -c "cd '$MP' && find $CUSTODY_NAMES -type f | LC_ALL=C sort | xargs -r sha256sum" > "$d/manifest.sha256" \
    || { check "$sc" "custody-$tag" fail "hashing the quarantined copies failed or exceeded 900 s"; write_report_and_exit; }
  # Portable across busybox and GNU tar (no -T): the names are validated above
  # and badger file names carry no whitespace.
  timeout 300 docker exec "$DIND" sh -c "cd '$MP' && set -- \$(find $CUSTODY_NAMES -type f -size -1024k | LC_ALL=C sort); [ \$# -eq 0 ] || tar -cf - \"\$@\"" > "$d/meta.tar" \
    || { check "$sc" "custody-$tag" fail "could not retain the small metadata files"; write_report_and_exit; }
  if [[ -s "$d/meta.tar" ]]; then tar -tf "$d/meta.tar" > "$d/meta.list" \
    || { check "$sc" "custody-$tag" fail "the retained metadata archive is unreadable"; write_report_and_exit; }
  else : > "$d/meta.list"; fi
  lines="$(wc -l < "$d/manifest.sha256")"
  if (( lines != files )); then check "$sc" "custody-$tag" fail "manifest has $lines hashes for $files files — the inventory is incomplete"; write_report_and_exit; fi
  CUSTODY_TREE="$(sha256sum "$d/manifest.sha256" | cut -d' ' -f1)"
  check "$sc" "custody-$tag" pass "inventoried BEFORE deletion: $(wc -l < "$d/inventory.txt") entr(y/ies) [$CUSTODY_NAMES], $files files, $bytes bytes; manifest sha256 $CUSTODY_TREE; $(wc -l < "$d/meta.list") metadata file(s) retained (custody/$tag/)"; }
# delete_custodied <sc> <tag> — delete EXACTLY what quarantine_custody recorded,
# by name (never a glob: a copy that appears after the inventory is never
# destroyed unrecorded), bounded and enforced; then prove every inventoried name
# is gone and report anything that appeared during the custody window.
delete_custodied(){ local sc="$1" tag="$2" args="" n left after
  [[ -z "$CUSTODY_NAMES" ]] && return 0
  for n in $CUSTODY_NAMES; do args+=" '$MP/$n'"; done
  step "$sc" "delete-$tag" 300 docker exec "$DIND" sh -c "rm -rf --$args"
  left="$(timeout 60 docker exec "$DIND" sh -c "for e in $args; do [ -e \"\$e\" ] && echo \"\$e\"; done; true")" || left="(listing failed)"
  after="$(timeout 60 docker exec "$DIND" sh -c "cd '$MP' && for e in catfeeddb.corrupt.* catfeeddb.importingtmp.*; do [ -e \"\$e\" ] && echo \"\$e\"; done; true" | tr '\n' ' ')" || after="(listing failed)"
  if [[ -n "$left" ]]; then check "$sc" "delete-$tag" fail "inventoried entries still present after deletion: $left"; write_report_and_exit
  elif [[ -n "${after// /}" ]]; then check "$sc" "delete-$tag" fail "deleted exactly the inventoried set (manifest $CUSTODY_TREE), but un-inventoried entries appeared meanwhile: $after"
  else check "$sc" "delete-$tag" pass "deleted exactly the inventoried set [$CUSTODY_NAMES] (manifest $CUSTODY_TREE); none remain and nothing else appeared"; fi; }


# Teardown is bounded (each step under a deadline) and its failures are
# ENFORCED: every step's outcome is recorded in cleanup.log, and a run that
# otherwise passed exits 3 if teardown failed — a leaked loop mount, privileged
# dind or certs.d entry is never silent. A run that already failed or was
# inconclusive keeps its own exit code (teardown cannot upgrade or mask it).
harness_teardown(){ local st=$? cf=0 rc
  ct(){ rc=0; timeout --kill-after=10 "$1" "${@:2}" >> "$EVID/cleanup.log" 2>&1 || rc=$?
    printf 'cleanup rc=%d bound=%ss: %s\n' "$rc" "$1" "${*:2}" >> "$EVID/cleanup.log"; (( rc == 0 )) || cf=$((cf+1)); }
  # The presence probe is bounded too, and a probe that TIMES OUT is a failure,
  # never read as "absent" — a wedged daemon must not look like a clean teardown.
  local ins="${TEARDOWN_PROBE_SECS:-30}"
  for c in "$DIND" "$REG"; do
    rc=0; timeout --kill-after=5 "$ins" docker inspect "$c" >/dev/null 2>&1 || rc=$?
    if (( rc == 0 )); then ct 120 docker rm -f "$c"
    elif (( rc == 124 || rc == 137 )); then echo "cleanup: docker inspect $c timed out after ${ins}s" >> "$EVID/cleanup.log"; cf=$((cf+1)); fi
  done
  # A plain umount that fails but a lazy one that succeeds is a clean teardown;
  # only a mount that is STILL present afterwards counts as a failure.
  if mountpoint -q "$MNT" 2>/dev/null; then
    timeout 60 umount "$MNT" >> "$EVID/cleanup.log" 2>&1 || timeout 60 umount -l "$MNT" >> "$EVID/cleanup.log" 2>&1 || true
    if mountpoint -q "$MNT" 2>/dev/null; then echo "cleanup: $MNT still mounted" >> "$EVID/cleanup.log"; cf=$((cf+1)); fi
  fi
  ct 30 rm -f "${IMG:?}"
  ct 30 rm -f "${SOCKDIR:?}/agent.sock"; [[ -d "$SOCKDIR" ]] && ct 30 rmdir "${SOCKDIR:?}"
  if [[ -n "$CERTSD" && -d "$CERTSD" ]]; then ct 30 rm -f "${CERTSD:?}/ca.crt"; ct 30 rmdir "${CERTSD:?}"; fi
  if (( cf > 0 )); then
    echo "TEARDOWN: $cf cleanup step(s) failed — see cleanup.log" >&2
    [[ -f "$MD" ]] && printf '\nTeardown: **%d cleanup step(s) FAILED** (cleanup.log)\n' "$cf" >> "$MD"
    (( st == 0 )) && exit 3
  fi
  exit "$st"
}
