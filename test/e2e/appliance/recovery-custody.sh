#!/usr/bin/env bash
# test/e2e/appliance/recovery-custody.sh — bounded, enforced harness steps, the
# quarantine chain of custody, the enforcement verdict and the enforced teardown
# for the F-DISK recovery scenario (ASTRA item 5; audit 6359611097).
# Sourced by upgrade-enospc-qualify.sh; proven red/green with no lab by
# recovery-custody_test.sh (which stubs `docker`). Expects from the caller:
# check, write_report_and_exit, DIND, MP, MNT, EVID, STEPLOG,
# CUSTODY_NAMES, CUSTODY_TREE.
# shellcheck disable=SC2034  # CUSTODY_* are read by the caller
#
# Three rules hold throughout:
#   1. Bounded on BOTH ends. Every remote command runs as
#      `docker exec <dind> timeout -s KILL <n> …` inside an outer, slightly longer
#      local `timeout`, so the remote process dies on its own deadline; killing
#      the local docker CLI alone would not stop it.
#   2. An observation that fails is an ERROR, never "absent". A listing reports
#      absence only when the listing itself succeeded (rc 0); a missing volume, a
#      failed `cd`, a daemon or transport error or a timeout is rc != 0 and FAILS.
#   3. Nothing is deleted that is not recoverable: the COMPLETE quarantined bytes
#      are copied off the pressure volume and re-verified against the manifest
#      before the deletion is attempted.

# rx <secs> <shell> — run <shell> on the data volume inside the bounded host,
# bounded remotely (KILL at <secs>) and locally (<secs>+15). `cd` failure is an
# error (rc 3), never an empty result. No remote pipelines: busybox/dash may lack
# pipefail, so anything that needs one is done on the runner side.
rx(){ local secs="$1"; shift
  timeout --kill-after=5 "$((secs + 15))" docker exec "$DIND" timeout -s KILL "$secs" sh -c "cd '$MP' || exit 3; $*"; }

run_bounded(){ local secs="$1" label="$2"; shift 2; local rc=0 out
  out="$(timeout --kill-after=10 "$secs" "$@" 2>&1)" || rc=$?
  printf '%s %s rc=%d bound=%ss\n%s\n' "$(date -u +%FT%TZ)" "$label" "$rc" "$secs" "${out:0:4000}" >> "$STEPLOG"
  return "$rc"; }
# step <sc> <name> <secs> <cmd…> — a REQUIRED step: a timeout or non-zero exit
# FAILS the check and ends the run. The FAIL is recorded first, so the verdict
# survives even if the (bounded) diagnostics after it collect nothing.
step(){ local sc="$1" name="$2" secs="$3"; shift 3; local rc=0 why
  run_bounded "$secs" "$sc/$name" "$@" || rc=$?
  (( rc == 0 )) && return 0
  why="exit $rc"
  if (( rc == 124 )); then why="timed out at its local bound (${secs}s)"
  elif (( rc == 137 )); then why="was KILLed at its deadline (rc 137)"; fi
  check "$sc" "step-$name" fail "required harness step '$name' $why (output in steps.log)"
  # Remote-completion evidence for a timed-out step: what is still running.
  if (( rc == 124 || rc == 137 )); then
    { echo "-- processes in the bounded host after '$name' timed out"
      timeout --kill-after=5 "$(( ${DIAG_BOUND:-20} + ${DIAG_SLACK:-10} ))" docker exec "$DIND" ps 2>&1 || echo "(process listing unavailable: rc=$?)"; } >> "$STEPLOG"
  fi
  diagnose "step-$name"; write_report_and_exit; }
# dstep <sc> <name> <secs> <shell> — step for a shell command inside the bounded
# host, with the remote side KILLed at <secs> (rule 1).
dstep(){ local sc="$1" name="$2" secs="$3"; shift 3
  step "$sc" "$name" "$((secs + 15))" docker exec "$DIND" timeout -s KILL "$secs" sh -c "$*"; }

# diagnose <tag> — evidence only, and BOUNDED (ASTRA 6359611097 #1): every call carries its own
# deadline — the remote side is KILLed inside the bounded host too — so a wedged
# daemon or transport costs at most ~3 minutes here and the FAIL verdict that
# called diagnose always reaches the report and teardown.
diagnose(){ local tag="$1" B="${DIAG_BOUND:-20}" S="${DIAG_SLACK:-10}" o
  bx(){ timeout --kill-after=5 "$((B + S))" "$@" 2>&1 || echo "(diagnostic unavailable: rc=$? — $*)"; }
  bi(){ bx docker exec "$DIND" timeout -s KILL "$B" "$@"; }
  { echo "== $tag $(date -u +%FT%TZ)"; bx df -k "$MNT" | tail -1
    bi docker ps -a --format '{{.Names}} {{.Status}}'
    bi docker inspect -f 'status={{.State.Status}} restarting={{.State.Restarting}} restarts={{.RestartCount}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}} err={{.State.Error}} started={{.State.StartedAt}}' culvert
    echo "-- proxy crash head (first panic/fatal/signal line + 30)"
    o="$(bi docker logs culvert)"
    if [[ "$o" == "(diagnostic unavailable"* ]]; then echo "$o"
    else grep -m1 -A30 -E '^(panic:|fatal error:|SIG[A-Z]+:|runtime: |\[signal )' <<<"$o" | cut -c1-300 || true; fi
    echo "-- proxy log"; bi docker logs --tail 40 culvert | cut -c1-300
    # The glob must expand INSIDE the bounded host's volume, not on the runner.
    echo "-- /data usage"; bi docker run --rm -v culvert_proxy-data:/data:ro busybox:stable sh -c 'du -sk /data/*' | sort -n | tail -8
    echo "-- bounded dockerd log"; bx docker logs --tail 40 "$DIND" | cut -c1-300
  } >> "$EVID/diagnose.log" 2>&1 || true; }

# Evidence state (ASTRA 6360307931 #1). $EVID/.evidence-state records whether
# the data volume — inside the loop image — may hold quarantine evidence that has
# NOT been preserved off it:
#   absent / none            nothing to protect yet
#   unpreserved:<reason>     the image holds (or may hold) evidence not yet
#                            preserved — set BEFORE any operation that can create
#                            it (arm_evidence), and on any custody failure, new
#                            un-inventoried entry or failed observation
#   preserved:<tag>          the complete bytes of the CURRENT set were preserved
#                            and verified (custody/<tag>)
#   clear:<tag>              a SUCCESSFUL listing found nothing to preserve
# Every exit path goes through harness_teardown, which RETAINS the image while
# the state is unpreserved — a clean container teardown never erases evidence
# that was never copied out. It is a file, not a variable, so subshells and the
# EXIT trap all see the same state.
evidence_state(){ printf '%s\n' "$1" > "$EVID/.evidence-state"; }
evidence_state_get(){ if [[ -f "$EVID/.evidence-state" ]]; then cat "$EVID/.evidence-state"; else echo none; fi; }
# arm_evidence <reason> — call BEFORE an operation that may create quarantine
# evidence or leave partial data (an import starting, a kill, a restart). A
# failure or timeout of that operation then exits with the image retained,
# because the protection was already in place (ASTRA 6360721903 #1).
arm_evidence(){ evidence_state "unpreserved:$1"; }

# custody_fail <sc> <tag> <msg> — FAIL and end the run; nothing is deleted, and
# the evidence is marked unpreserved so teardown retains the image holding it.
custody_fail(){ evidence_state "unpreserved:custody-$2 failed: $3"
  check "$1" "custody-$2" fail "$3 — nothing was deleted; the loop image holding it is RETAINED"; write_report_and_exit; }

# quarantine_custody <sc> <tag> — chain of custody for every quarantined copy
# (catfeeddb.corrupt.*) and import scratch dir (catfeeddb.importingtmp.*), taken
# BEFORE anything deletes them. Under $EVID/custody/<tag>/:
#   inventory.txt        name, file count and bytes per entry
#   manifest.sha256      sha256 of every file, sorted by path
#   quarantine.tar.gz    the COMPLETE bytes of every inventoried entry, off the
#                        pressure volume, verified by extracting it and checking
#                        every file against manifest.sha256 (rule 3)
#   quarantine.tar.gz.sha256
# Sets CUSTODY_NAMES (exact names, for delete-by-name) and CUSTODY_TREE (sha256
# of manifest.sha256). Every failure FAILS the run before any deletion.
quarantine_custody(){ local sc="$1" tag="$2" d="$EVID/custody/$2" n files=0 bytes=0 f b lines out need avail
  mkdir -p "$d"; : > "$d/inventory.txt"; : > "$d/manifest.sha256"
  out="$(rx 60 'for e in catfeeddb.corrupt.* catfeeddb.importingtmp.*; do if [ -e "$e" ]; then echo "$e"; fi; done')" \
    || custody_fail "$sc" "$tag" "could not observe the data volume ($MP): the listing failed (rc=$?), which is not the same as nothing there"
  CUSTODY_NAMES="$(printf '%s\n' "$out" | sed '/^$/d' | LC_ALL=C sort | tr '\n' ' ')"; CUSTODY_NAMES="${CUSTODY_NAMES% }"
  printf '%s\n' "$CUSTODY_NAMES" > "$d/names.txt"
  if [[ -z "$CUSTODY_NAMES" ]]; then CUSTODY_TREE=none; evidence_state "clear:$tag"
    check "$sc" "custody-$tag" pass "inventory (listing succeeded): nothing quarantined on the volume — nothing to preserve or delete"; return 0; fi
  for n in $CUSTODY_NAMES; do
    [[ "$n" =~ ^catfeeddb\.(corrupt|importingtmp)\.[A-Za-z0-9._-]+$ ]] \
      || custody_fail "$sc" "$tag" "unexpected entry name '$n' — refusing to inventory/delete it"
    out="$(rx 120 "find '$n' -type f -exec stat -c '%s' {} +")" || custody_fail "$sc" "$tag" "could not size $n (rc=$?)"
    f="$(printf '%s\n' "$out" | sed '/^$/d' | wc -l | tr -d ' ')"; b="$(printf '%s\n' "$out" | awk '{s+=$1} END{print s+0}')"
    [[ "$f" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || custody_fail "$sc" "$tag" "could not size $n (files='$f' bytes='$b')"
    printf '%s files=%s bytes=%s\n' "$n" "$f" "$b" >> "$d/inventory.txt"; files=$((files+f)); bytes=$((bytes+b))
  done
  out="$(rx 900 "find $CUSTODY_NAMES -type f -exec sha256sum {} +")" || custody_fail "$sc" "$tag" "hashing the quarantined copies failed or exceeded 900 s (rc=$?)"
  printf '%s\n' "$out" | sed '/^$/d' | LC_ALL=C sort -k2 > "$d/manifest.sha256"
  lines="$(wc -l < "$d/manifest.sha256" | tr -d ' ')"
  (( lines == files )) || custody_fail "$sc" "$tag" "manifest has $lines hashes for $files files — the inventory is incomplete"
  CUSTODY_TREE="$(sha256sum "$d/manifest.sha256" | cut -d' ' -f1)"
  # Same generation already preserved? (identical names AND identical content
  # hashes in an earlier verified custody) — reuse it rather than copy again.
  local o
  for o in "$EVID"/custody/*/; do o="${o%/}"
    [[ "$o" == "$d" || ! -s "$o/quarantine.tar.gz.sha256" ]] && continue
    if cmp -s "$o/names.txt" "$d/names.txt" && cmp -s "$o/manifest.sha256" "$d/manifest.sha256"; then
      basename "$o" > "$d/preserved-by"; evidence_state "preserved:$tag"
      check "$sc" "custody-$tag" pass "this exact set [$CUSTODY_NAMES] (manifest $CUSTODY_TREE) is already preserved and verified in custody/$(basename "$o")/ — no second copy"
      return 0
    fi
  done
  # Rule 3: the complete bytes, off the pressure volume, BEFORE any deletion.
  # Room for the archive plus the verification extract (worst case: no
  # compression) and 64 MiB headroom; refusing is better than a partial copy.
  need=$(( (2 * bytes) / 1024 + 65536 )); avail="$(df -Pk "$d" | awk 'NR==2{print $4}')"
  [[ "$avail" =~ ^[0-9]+$ ]] && (( avail >= need )) \
    || custody_fail "$sc" "$tag" "not enough room off the volume to preserve ${bytes} bytes (need ${need} KiB, have ${avail:-?} KiB at $d)"
  ( set -o pipefail; rx 1800 "tar -cf - $CUSTODY_NAMES" | gzip -1 > "$d/quarantine.tar.gz" ) \
    || custody_fail "$sc" "$tag" "copying the complete quarantined bytes off the volume failed (rc=$?)"
  rm -rf "$d/verify"; mkdir -p "$d/verify"
  tar -xzf "$d/quarantine.tar.gz" -C "$d/verify" || custody_fail "$sc" "$tag" "the preserved archive does not extract"
  [[ "$(find "$d/verify" -type f | wc -l | tr -d ' ')" == "$files" ]] \
    || custody_fail "$sc" "$tag" "the preserved archive holds $(find "$d/verify" -type f | wc -l | tr -d ' ') files, the inventory $files"
  ( cd "$d/verify" && sha256sum -c --quiet "$d/manifest.sha256" ) >> "$d/verify.log" 2>&1 \
    || custody_fail "$sc" "$tag" "the preserved archive does not match the manifest (see custody/$tag/verify.log)"
  rm -rf "$d/verify"
  sha256sum "$d/quarantine.tar.gz" | sed "s|$d/||" > "$d/quarantine.tar.gz.sha256"
  evidence_state "preserved:$tag"
  check "$sc" "custody-$tag" pass "BEFORE deletion: $(wc -l < "$d/inventory.txt" | tr -d ' ') entr(y/ies) [$CUSTODY_NAMES], $files files, $bytes bytes; manifest sha256 $CUSTODY_TREE; complete bytes preserved off-volume as quarantine.tar.gz (sha256 $(cut -d' ' -f1 < "$d/quarantine.tar.gz.sha256")) and re-verified file-by-file against the manifest"; }

# delete_custodied <sc> <tag> — delete EXACTLY what quarantine_custody recorded
# and preserved, by name (never a glob: a copy that appears after the inventory
# is never destroyed unrecorded), bounded and enforced; then prove, with
# listings that themselves succeeded, that every inventoried name is gone and
# report anything that appeared during the custody window.
# A preserved archive authorizes deletion ONLY of the generation it preserves
# (ASTRA 6360721903 #2): the state must be preserved:<tag>, the names must be
# exactly custody/<tag>/names.txt, and the bytes on the volume are RE-HASHED and
# must still equal custody/<tag>/manifest.sha256 immediately before deletion.
# Any new entry, or any listing that fails, re-arms the protection (unpreserved).
delete_custodied(){ local sc="$1" tag="$2" args="" n left after d="$EVID/custody/$2" now
  [[ -z "$CUSTODY_NAMES" ]] && return 0
  { [[ -s "$d/quarantine.tar.gz.sha256" || -s "$d/preserved-by" ]] && [[ "$(evidence_state_get)" == "preserved:$tag" ]]; } \
    || { check "$sc" "delete-$tag" fail "refusing to delete: no verified off-volume copy authorizes custody '$tag' (state '$(evidence_state_get)')"; write_report_and_exit; }
  [[ "$(cat "$d/names.txt" 2>/dev/null)" == "$CUSTODY_NAMES" ]] \
    || { arm_evidence "deletion refused: the set to delete [$CUSTODY_NAMES] is not the preserved set"; check "$sc" "delete-$tag" fail "refusing to delete: [$CUSTODY_NAMES] is not the set preserved in custody/$tag"; write_report_and_exit; }
  now="$(rx 900 "find $CUSTODY_NAMES -type f -exec sha256sum {} +")" \
    || { arm_evidence "pre-delete re-hash failed"; check "$sc" "delete-$tag" fail "refusing to delete: could not re-hash the set before deletion (rc=$?)"; write_report_and_exit; }
  printf '%s\n' "$now" | sed '/^$/d' | LC_ALL=C sort -k2 | cmp -s - "$d/manifest.sha256" \
    || { arm_evidence "the set changed since it was preserved"; check "$sc" "delete-$tag" fail "refusing to delete: the bytes on the volume no longer match the preserved manifest $CUSTODY_TREE"; write_report_and_exit; }
  for n in $CUSTODY_NAMES; do args+=" '$n'"; done
  dstep "$sc" "delete-$tag" 300 "cd '$MP' || exit 3; rm -rf --$args"
  left="$(rx 60 "for e in $args; do if [ -e \"\$e\" ]; then echo \"\$e\"; fi; done")" \
    || { arm_evidence "post-delete listing failed; the volume's content is unknown"; check "$sc" "delete-$tag" fail "could not verify the deletion: the post-delete listing failed (rc=$?)"; write_report_and_exit; }
  after="$(rx 60 'for e in catfeeddb.corrupt.* catfeeddb.importingtmp.*; do if [ -e "$e" ]; then echo "$e"; fi; done')" \
    || { arm_evidence "post-delete volume listing failed; the volume's content is unknown"; check "$sc" "delete-$tag" fail "could not verify the volume after deletion: listing failed (rc=$?)"; write_report_and_exit; }
  after="$(printf '%s' "$after" | tr '\n' ' ')"
  if [[ -n "$left" ]]; then check "$sc" "delete-$tag" fail "inventoried entries still present after deletion: $left"; write_report_and_exit
  elif [[ -n "${after// /}" ]]; then
    # New, un-inventoried entries: the old archive does not cover them.
    arm_evidence "un-inventoried entries appeared during custody '$tag': $after"
    check "$sc" "delete-$tag" fail "deleted exactly the inventoried set (manifest $CUSTODY_TREE), but un-inventoried entries appeared meanwhile: $after — protection re-armed; the image is retained unless they are preserved"
  else evidence_state "clear:$tag"
    check "$sc" "delete-$tag" pass "deleted exactly the inventoried, preserved set [$CUSTODY_NAMES] (manifest $CUSTODY_TREE, re-hashed unchanged before deletion); verified gone by a successful listing; nothing else appeared"; fi; }

# enforcement_verdict <allowed-code> <blocked-code> <blocked-body-file> — the
# default-deny contract, as a pure decision: the allowed origin answers 200 AND
# the unmatched origin answers exactly 403 with Culvert's default-deny block page
# (category "Default Deny"). A 5xx, a 000, a 407, a bare 403 from something else,
# or a 200 for the blocked origin is NOT enforcement — an outage must never pass.
# Prints "pass <why>" or "fail <why>"; returns 0 only on pass.
enforcement_verdict(){ local a="$1" b="$2" body="$3"
  if [[ "$a" != 200 ]]; then echo "fail allowed origin answered $a (want 200)"; return 1; fi
  if [[ "$b" != 403 ]]; then echo "fail blocked origin answered $b (want 403: a 5xx/000 is an outage, not a denial)"; return 1; fi
  if ! grep -q 'Access Denied' "$body" 2>/dev/null || ! grep -q 'Default Deny' "$body" 2>/dev/null; then
    echo "fail blocked origin answered 403 without Culvert's default-deny block page"; return 1; fi
  echo "pass allowed=200 blocked=403 with the default-deny block page"; }

# clean_restart_verdict <log-rc> <log-file> <recovered> <qc-before> <qc-after> <marker-state>
# — the clean-restart-after-convergence decision as a pure function (ASTRA
# 6360307931 #2). The restart log must have been READ (rc 0) for "no re-sync"
# to mean anything: an unreadable log is an error, never "quiet". Prints
# "pass <why>" or "fail <why>"; returns 0 only on pass.
clean_restart_verdict(){ local lrc="$1" lf="$2" rec="$3" qb="$4" qa="$5" mk="$6"
  if [[ "$lrc" != 0 ]]; then echo "fail the restart log could not be read (rc=$lrc) — absence of a re-sync is unproven"; return 1; fi
  if [[ "$mk" != absent ]]; then echo "fail import-pending marker is '$mk' (want absent)"; return 1; fi
  if [[ "$rec" != 0 ]]; then echo "fail culvert_catfeeddb_recovered='$rec' (want 0: the restart re-quarantined)"; return 1; fi
  if [[ -z "$qa" || "$qa" != "$qb" ]]; then echo "fail quarantined_copies '$qb' -> '$qa' (want unchanged)"; return 1; fi
  if grep -q 'FeedSync: starting' "$lf"; then echo "fail a feed sync started after the restart (the store was not recognised as certified)"; return 1; fi
  echo "pass no quarantine (recovered=0, quarantined_copies $qb->$qa), no marker, no re-sync in a log that was read"; }

# Teardown is bounded (each step under a deadline) and its failures are
# ENFORCED: every step's outcome is recorded in cleanup.log, and a run that
# otherwise passed exits 3 if teardown failed. A run that already failed or was
# inconclusive keeps its own exit code (teardown cannot upgrade or mask it).
# Container presence is TRI-STATE: present (rc 0), absent (rc 1 AND the daemon
# said "No such object"), or unknown (anything else — daemon down, timeout).
# Unknown is a failure, and the loop image is only removed once the containers
# are verified gone and the mount is verified released.
harness_teardown(){ local st=$? cf=0 rc out uncertain=0
  ct(){ rc=0; timeout --kill-after=10 "$1" "${@:2}" >> "$EVID/cleanup.log" 2>&1 || rc=$?
    printf 'cleanup rc=%d bound=%ss: %s\n' "$rc" "$1" "${*:2}" >> "$EVID/cleanup.log"; (( rc == 0 )) || cf=$((cf+1)); return "$rc"; }
  local ins="${TEARDOWN_PROBE_SECS:-30}"
  for c in "$DIND" "$REG"; do
    rc=0; out="$(timeout --kill-after=5 "$ins" docker inspect "$c" 2>&1 >/dev/null)" || rc=$?
    if (( rc == 0 )); then
      ct 120 docker rm -f "$c" || uncertain=1
    elif (( rc == 1 )) && grep -qi 'no such object' <<<"$out"; then
      echo "cleanup: $c absent (daemon confirmed)" >> "$EVID/cleanup.log"
    else
      printf 'cleanup: presence of %s UNKNOWN (rc=%d, bound %ss): %s\n' "$c" "$rc" "$ins" "${out:0:300}" >> "$EVID/cleanup.log"; cf=$((cf+1)); uncertain=1
    fi
  done
  # A plain umount that fails but a lazy one that succeeds is a clean teardown;
  # only a mount that is STILL present afterwards counts as a failure.
  if mountpoint -q "$MNT" 2>/dev/null; then
    timeout 60 umount "$MNT" >> "$EVID/cleanup.log" 2>&1 || timeout 60 umount -l "$MNT" >> "$EVID/cleanup.log" 2>&1 || true
    if mountpoint -q "$MNT" 2>/dev/null; then echo "cleanup: $MNT still mounted" >> "$EVID/cleanup.log"; cf=$((cf+1)); uncertain=1; fi
  fi
  local es; es="$(evidence_state_get)"
  if [[ "$es" == unpreserved:* ]]; then
    printf 'cleanup: RETAINED %s — it holds evidence that was NOT preserved off the volume (%s)\n' "$IMG" "${es#unpreserved:}" >> "$EVID/cleanup.log"
    if [[ -f "$MD" ]]; then printf '\nEvidence: **loop image RETAINED** at `%s` — %s\n' "$IMG" "${es#unpreserved:}" >> "$MD"; fi
    # A run that otherwise passed must never leave evidence unpreserved.
    (( st == 0 )) && cf=$((cf+1))
  elif (( uncertain )); then
    echo "cleanup: RETAINED $IMG — container/mount state not verified released" >> "$EVID/cleanup.log"
  else ct 30 rm -f "${IMG:?}" || true; fi
  ct 30 rm -f "${SOCKDIR:?}/agent.sock" || true; if [[ -d "$SOCKDIR" ]]; then ct 30 rmdir "${SOCKDIR:?}" || true; fi
  if [[ -n "$CERTSD" && -d "$CERTSD" ]]; then ct 30 rm -f "${CERTSD:?}/ca.crt" || true; ct 30 rmdir "${CERTSD:?}" || true; fi
  if (( cf > 0 )); then
    echo "TEARDOWN: $cf cleanup step(s) failed — see cleanup.log" >&2
    if [[ -f "$MD" ]]; then printf '\nTeardown: **%d cleanup step(s) FAILED** (cleanup.log)\n' "$cf" >> "$MD"; fi
    (( st == 0 )) && exit 3
  fi
  exit "$st"
}

# feed_probe_candidates <feed.tar.gz> <per-category> <category…> — probe domains
# TAKEN FROM THE FEED THE NODE DOWNLOADED, never guessed. Run 39916602574 used a
# guessed adult-domain list and the lab's mirror carries no adult category, so
# the probe proved nothing either way. Prints up to <per-category> domains from
# each blacklists/<category>/domains member that exists, keeping only plain DNS
# names (they go into a query string). Order is the feed's own, so it is stable.
feed_probe_candidates(){ local tgz="$1" per="$2" c m; shift 2
  local members; members="$(tar -tzf "$tgz" 2>/dev/null)" || return 1
  for c in "$@"; do
    m="$(grep -E "(^|/)blacklists/$c/domains$" <<<"$members" | head -n1)"; [[ -n "$m" ]] || continue
    { tar -xzOf "$tgz" "$m" 2>/dev/null || true; } | tr -d '\r' | grep -E '^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$' | head -n "$per" || true
  done; }
