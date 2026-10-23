#!/usr/bin/env bash
# shellcheck disable=SC2034  # case variables are read by the sourced library or via eval
# test/e2e/appliance/recovery-custody_test.sh — LOCAL red/green proof of
# recovery-custody.sh (ASTRA item 5; audit 6359611097): bounded and enforced
# steps, tri-state observation, complete off-volume custody before deletion,
# the strict enforcement verdict, feed-derived probes and the enforced teardown.
# No lab, no Docker daemon, no network: a stub `docker` on PATH runs
# `docker exec <c> <cmd…>` locally against a temp directory standing in for the
# data volume, and can be told to fail, hang or report the daemon down. Each
# case runs in a subshell because a FAIL ends the run (write_report_and_exit),
# exactly as in the real harness.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; if [[ -n "${KEEP:-}" ]]; then echo "keeping $T"; else trap 'rm -rf "$T"' EXIT; fi
mkdir -p "$T/bin"
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
[ -n "${STUB_SLEEP:-}" ] && sleep "$STUB_SLEEP"
case "$1" in
  exec) shift 2
    if [ -n "${STUB_FAIL_MATCH:-}" ] && [[ "$*" == *"$STUB_FAIL_MATCH"* ]]; then echo "stub: forced failure" >&2; exit 1; fi
    if [[ "$*" == *"tar -cf"* ]]; then
      # The archive stream arrives, but is not a tar: extraction must fail.
      if [ -n "${STUB_TAR_GARBAGE:-}" ]; then echo "not a tar stream"; exit 0; fi
      # The bytes change between hashing and archiving: verification must fail.
      if [ -n "${STUB_TAR_TAMPER:-}" ]; then find "$STUB_TAR_TAMPER" -name MANIFEST -exec sh -c 'printf x >> "$1"' _ {} \; ; fi
    fi
    exec "$@" ;;
  inspect)
    if [ -n "${STUB_DAEMON_DOWN:-}" ]; then echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock" >&2; exit 1; fi
    if [ -n "${STUB_PRESENT:-}" ]; then exit 0; fi
    echo "Error: No such object: $2" >&2; exit 1 ;;
  rm) [ -z "${STUB_RM_CONTAINER_FAIL:-}" ] ;;
  *) echo "stub docker: unsupported $*" >&2; exit 2 ;;
esac
STUB
chmod +x "$T/bin/docker"; export PATH="$T/bin:$PATH"

fails=0; n=0; unsupported=0
# proc_state <exact-args>: present | absent | unsupported. Absence counts ONLY
# when the process table was actually enumerated (ASTRA 6360307931): a ps that
# fails or prints nothing is "unsupported", never "absent".
proc_state(){ local out
  if ! out="$(ps -eo args= 2>/dev/null)" || [[ -z "$out" ]]; then echo unsupported; return 0; fi
  if grep -qxF "$1" <<<"$out"; then echo present; else echo absent; fi; }
# unsupported_or_fail <what>: report an unproven assertion explicitly. With
# REQUIRE_PROCESS_PROOF=1 (the Linux lab job) it is a FAILURE.
unsupported_or_fail(){ if [[ -n "${REQUIRE_PROCESS_PROOF:-}" ]]; then bad "$1 — process enumeration unsupported here, and proof is required"
  else unsupported=$((unsupported+1)); printf 'UNSUPPORTED %s — process enumeration unavailable; NOT proven on this platform\n' "$1"; fi; }
ok(){ n=$((n+1)); printf 'ok   %s\n' "$1"; }
bad(){ n=$((n+1)); printf 'FAIL %s\n' "$1"; fails=$((fails+1)); }
expect(){ if eval "$2"; then ok "$1"; else bad "$1 (assertion: $2)"; fi; }

# run_case <name> <body>: fresh evidence dir + volume, harness hooks stubbed,
# library sourced; prints the case's exit code (99 = the run was ended by a FAIL).
run_case(){ local name="$1" body="$2"
  C="$T/$name"; mkdir -p "$C/evid" "$C/vol"
  ( set -euo pipefail
    EVID="$C/evid"; STEPLOG="$EVID/steps.log"; MP="${CASE_MP:-$C/vol}"; MNT="$C"; DIND=stub-dind
    CUSTODY_NAMES=""; CUSTODY_TREE=none; export DIAG_BOUND="${DIAG_BOUND:-1}" DIAG_SLACK="${DIAG_SLACK:-1}"
    check(){ printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >> "$EVID/checks.txt"; }
    write_report_and_exit(){ echo "REPORT-REACHED" >> "$EVID/checks.txt"; exit 99; }
    # shellcheck source=recovery-custody.sh
    . "$HERE/recovery-custody.sh"
    eval "$body"
    printf 'CUSTODY_NAMES=%s\nCUSTODY_TREE=%s\n' "$CUSTODY_NAMES" "$CUSTODY_TREE" > "$EVID/vars.txt"
  ) > "$C/out.txt" 2>&1 && echo 0 || echo $?
}
checks(){ cat "$T/$1/evid/checks.txt" 2>/dev/null || true; }
mkq(){ local d="$T/$1/vol/$2"; mkdir -p "$d"; printf 'manifest-%s' "$2" > "$d/MANIFEST"; printf 'k' > "$d/KEYREGISTRY"
  head -c 2097152 /dev/urandom > "$d/000001.vlog"; }   # a 2 MiB database file: must be preserved, not just hashed

echo "== step / dstep: bounded on both ends, enforced =="
rc="$(run_case step-ok 'step K s 5 docker exec x true')"
expect "step: success returns 0 and records no failure" '[[ $rc == 0 && -z "$(checks step-ok)" ]]'
rc="$(run_case step-fail 'step K s 5 docker exec x false')"
expect "step: a non-zero exit FAILS the check and ends the run" '[[ $rc == 99 ]] && checks step-fail | grep -q "step-s fail required harness step .s. exit 1"'
rc="$(STUB_SLEEP=5 run_case step-hang 'step K s 1 docker exec x true')"
expect "step: a hang is cut at the bound and FAILS" '[[ $rc == 99 ]] && checks step-hang | grep -q "step-s fail required harness step .s. \(timed out\|was KILLed\)"'
expect "step: a timed-out step records remote-process evidence" 'grep -q "processes in the bounded host after" "$T/step-hang/evid/steps.log"'
t0=$SECONDS; rc="$(run_case dstep-remote 'dstep K r 1 "sleep 29.517"')"; took=$((SECONDS - t0))
expect "dstep: the REMOTE command is KILLed at its own 1 s deadline (outer 16 s bound not reached; took ${took}s)" '[[ $rc == 99 && $took -lt 10 ]] && checks dstep-remote | grep -q "step-r fail required harness step .r. was KILLed at its deadline"'
ps_after="$(proc_state "sleep 29.517")"
case "$ps_after" in
  absent) ok "dstep: no remote process outlives the KILL (process table enumerated)" ;;
  present) bad "dstep: the remote process OUTLIVED the KILL" ;;
  *) unsupported_or_fail "dstep: no remote process outlives the KILL" ;;
esac
expect "proc_state: a process that IS running is reported present (the check can see processes)" '( sleep 30.731 & p=$!; sleep 0.2; r="$(proc_state "sleep 30.731")"; kill "$p"; [[ $r == present || $r == unsupported ]] )'

t0=$SECONDS; rc="$(STUB_SLEEP=60 run_case diag-stall 'step K s 1 docker exec x true')"; took=$((SECONDS - t0))
expect "step: with the diagnostic transport STALLED too, the FAIL still reaches the report, bounded (took ${took}s)" '[[ $rc == 99 && $took -lt 60 ]] && checks diag-stall | grep -q "step-s fail" && checks diag-stall | grep -q REPORT-REACHED'
expect "step: every stalled diagnostic (6 remote calls) is cut and recorded as unavailable" '[[ $(grep -c "diagnostic unavailable" "$T/diag-stall/evid/diagnose.log") -eq 6 ]]'
expect "diagnose: the /data glob is sent to the bounded host unexpanded" 'grep -q "sh -c du -sk /data/\*" "$T/diag-stall/evid/diagnose.log"'

echo "== observation failures are errors, never absence (ASTRA #2) =="
rc="$(CASE_MP=/nonexistent/volume run_case obs-novol 'quarantine_custody K t')"
expect "custody: a missing volume FAILS (was: PASS with an empty inventory)" '[[ $rc == 99 ]] && checks obs-novol | grep -q "could not observe the data volume"'
rc="$(STUB_FAIL_MATCH=catfeeddb.corrupt run_case obs-transport 'quarantine_custody K t')"
expect "custody: a transport failure on the listing FAILS" '[[ $rc == 99 ]] && checks obs-transport | grep -q "could not observe"'
rc="$(run_case obs-empty 'quarantine_custody K t')"
expect "custody: an empty volume PASSES only from a listing that succeeded" '[[ $rc == 0 ]] && checks obs-empty | grep -q "custody-t pass inventory (listing succeeded): nothing quarantined"'

echo "== custody: complete bytes preserved off-volume and verified BEFORE deletion (ASTRA #3) =="
mkdir -p "$T/cust-two/vol"; mkq cust-two catfeeddb.corrupt.1700000000000000001; mkq cust-two catfeeddb.importingtmp.42
cp -a "$T/cust-two/vol" "$T/cust-two-orig"
rc="$(run_case cust-two 'quarantine_custody K t')"
d="$T/cust-two/evid/custody/t"
expect "custody: two entries PASS with the archive verified" '[[ $rc == 0 ]] && checks cust-two | grep -q "complete bytes preserved off-volume as quarantine.tar.gz.*re-verified file-by-file"'
expect "custody: the manifest hashes every file (6) and verifies against the volume" '[[ $(wc -l < "$d/manifest.sha256") == 6 ]] && (cd "$T/cust-two/vol" && sha256sum -c --quiet "$d/manifest.sha256")'
expect "custody: the 2 MiB database file IS in the preserved archive, byte-identical" 'mkdir -p "$T/x2" && tar -xzf "$d/quarantine.tar.gz" -C "$T/x2" && cmp -s "$T/x2/catfeeddb.corrupt.1700000000000000001/000001.vlog" "$T/cust-two-orig/catfeeddb.corrupt.1700000000000000001/000001.vlog"'
expect "custody: the archive digest is recorded and correct" '(cd "$d" && sha256sum -c --quiet quarantine.tar.gz.sha256)'
expect "custody: inventory is NOT deletion — every entry is still on the volume" '[[ -d "$T/cust-two/vol/catfeeddb.corrupt.1700000000000000001" && -d "$T/cust-two/vol/catfeeddb.importingtmp.42" ]]'
mkdir -p "$T/cust-copyfail/vol"; mkq cust-copyfail catfeeddb.corrupt.8
rc="$(STUB_FAIL_MATCH='tar -cf' run_case cust-copyfail 'quarantine_custody K t; delete_custodied K t')"
expect "custody: a failed off-volume copy FAILS and nothing is deleted" '[[ $rc == 99 ]] && checks cust-copyfail | grep -q "copying the complete quarantined bytes off the volume failed" && [[ -d "$T/cust-copyfail/vol/catfeeddb.corrupt.8" ]]'
mkdir -p "$T/cust-badname/vol"; mkq cust-badname 'catfeeddb.corrupt.1;x'
rc="$(run_case cust-badname 'quarantine_custody K t')"
expect "custody: an unexpected entry name is REFUSED (never preserved or deleted)" '[[ $rc == 99 ]] && checks cust-badname | grep -q "refusing to inventory/delete" && [[ -d "$T/cust-badname/vol/catfeeddb.corrupt.1;x" ]]'
mkdir -p "$T/cust-hashfail/vol"; mkq cust-hashfail catfeeddb.corrupt.7
rc="$(STUB_FAIL_MATCH=sha256sum run_case cust-hashfail 'quarantine_custody K t; delete_custodied K t')"
expect "custody: a hashing failure FAILS before anything is deleted" '[[ $rc == 99 ]] && checks cust-hashfail | grep -q "hashing the quarantined copies failed" && [[ -d "$T/cust-hashfail/vol/catfeeddb.corrupt.7" ]]'

echo "== delete_custodied: exactly the preserved set, verified gone =="
mkdir -p "$T/del-ok/vol/catfeeddb"; mkq del-ok catfeeddb.corrupt.11; mkq del-ok catfeeddb.importingtmp.12
rc="$(run_case del-ok 'quarantine_custody K t; delete_custodied K t')"
expect "delete: removes exactly the inventoried, preserved entries and PASSES" '[[ $rc == 0 ]] && checks del-ok | grep -q "delete-t pass deleted exactly the inventoried, preserved set" && [[ ! -e "$T/del-ok/vol/catfeeddb.corrupt.11" && ! -e "$T/del-ok/vol/catfeeddb.importingtmp.12" ]]'
expect "delete: the live store beside them is untouched" '[[ -d "$T/del-ok/vol/catfeeddb" ]]'
mkdir -p "$T/del-nocustody/vol"; mkq del-nocustody catfeeddb.corrupt.13
rc="$(run_case del-nocustody 'CUSTODY_NAMES=catfeeddb.corrupt.13; delete_custodied K t')"
expect "delete: REFUSED without a verified off-volume copy" '[[ $rc == 99 ]] && checks del-nocustody | grep -q "refusing to delete: no verified off-volume copy" && [[ -d "$T/del-nocustody/vol/catfeeddb.corrupt.13" ]]'
mkdir -p "$T/del-late/vol"; mkq del-late catfeeddb.corrupt.21
rc="$(run_case del-late 'quarantine_custody K t; mkdir "$MP/catfeeddb.corrupt.22"; delete_custodied K t')"
expect "delete: a copy that appears AFTER the inventory is never destroyed unrecorded" '[[ -d "$T/del-late/vol/catfeeddb.corrupt.22" && ! -e "$T/del-late/vol/catfeeddb.corrupt.21" ]]'
expect "delete: and its appearance FAILS the check" 'checks del-late | grep -q "delete-t fail .*appeared meanwhile: catfeeddb.corrupt.22"'
mkdir -p "$T/del-fail/vol"; mkq del-fail catfeeddb.corrupt.31
rc="$(STUB_FAIL_MATCH='rm -rf' run_case del-fail 'quarantine_custody K t; delete_custodied K t')"
expect "delete: a failed deletion FAILS the run (was: rm … || true)" '[[ $rc == 99 ]] && checks del-fail | grep -q "step-delete-t fail" && [[ -d "$T/del-fail/vol/catfeeddb.corrupt.31" ]]'
mkdir -p "$T/del-verifyfail/vol"; mkq del-verifyfail catfeeddb.corrupt.41
rc="$(STUB_FAIL_MATCH="for e in  '" run_case del-verifyfail 'quarantine_custody K t; delete_custodied K t')"
expect "delete: an unverifiable post-delete listing FAILS (not read as gone)" '[[ $rc == 99 ]] && checks del-verifyfail | grep -q "could not verify the deletion"'

echo "== enforcement_verdict: an outage never passes (ASTRA #4) =="
page="$T/page.html"; printf '<h1>Access Denied</h1><span class="val">Default Deny</span>' > "$page"
other="$T/other.html"; printf 'Forbidden' > "$other"
ev(){ enforcement_verdict "$@" >/dev/null 2>&1; }
( fails=0; . "$HERE/recovery-custody.sh"
  expect "enforcement: 200 / 403 + default-deny page passes"           'ev 200 403 "$page"'
  expect "enforcement: 200 / 503 FAILS (outage)"                       '! ev 200 503 "$page"'
  expect "enforcement: 200 / 500 FAILS (crash)"                        '! ev 200 500 "$page"'
  expect "enforcement: 200 / 000 FAILS (no answer)"                    '! ev 200 000 "$page"'
  expect "enforcement: 200 / 407 FAILS (auth, not policy)"             '! ev 200 407 "$page"'
  expect "enforcement: 200 / 403 without the block page FAILS"         '! ev 200 403 "$other"'
  expect "enforcement: 200 / 200 FAILS (nothing blocked)"              '! ev 200 200 "$page"'
  expect "enforcement: 503 / 403 FAILS (allowed origin down)"          '! ev 503 403 "$page"'
  exit "$fails" ) || fails=$((fails + $?))
n=$((n + 8))

echo "== feed_probe_candidates: probes come from the downloaded feed =="
mkdir -p "$T/feed/blacklists/gambling" "$T/feed/blacklists/hacking"
printf 'casino-one.example\n# comment\n1.2.3.4\nCASINO.example\ncasino-two.example\nbad host.example\n' > "$T/feed/blacklists/gambling/domains"
printf 'hack.example\n' > "$T/feed/blacklists/hacking/domains"
(cd "$T/feed" && tar -czf ../feed.tar.gz blacklists)
got="$( . "$HERE/recovery-custody.sh"; feed_probe_candidates "$T/feed.tar.gz" 5 gambling adult | tr '\n' ' ')"
expect "probes: domains are taken from the feed, in feed order, only plain DNS names" '[[ "$got" == "casino-one.example casino-two.example " ]]'
expect "probes: a category absent from the feed (adult) contributes nothing"          '[[ "$got" != *adult* ]]'
expect "probes: an unreadable feed is an error, not an empty probe list"              '! ( . "$HERE/recovery-custody.sh"; feed_probe_candidates /nonexistent.tgz 5 gambling )'

echo "== harness_teardown: bounded, tri-state, never masks the verdict =="
teardown_case(){ local name="$1" st="$2"; shift 2; local D="$T/$name"; mkdir -p "$D/evid" "$D/sock"; : > "$D/img"
  env "$@" bash -c '
    set -euo pipefail; EVID="$1"; MD="$EVID/REPORT.md"; : > "$MD"
    DIND=d; REG=r; MNT="$1/not-mounted"; IMG="$2"; SOCKDIR="$3"; CERTSD=""
    . "$4"; trap harness_teardown EXIT; exit "$5"' _ "$D/evid" "$D/img" "$D/sock" "$HERE/recovery-custody.sh" "$st" \
    >/dev/null 2>&1 && echo 0 || echo $?; }
expect "teardown: containers confirmed absent keep a passing exit 0"        '[[ $(teardown_case td-ok 0) == 0 ]]'
expect "teardown: and the loop image is removed"                             '[[ ! -e "$T/td-ok/img" && ! -d "$T/td-ok/sock" ]]'
expect "teardown: daemon DOWN is not absence — a PASS becomes exit 3"        '[[ $(teardown_case td-down 0 STUB_DAEMON_DOWN=1) == 3 ]]'
expect "teardown: and the loop image is RETAINED (state not verified)"       '[[ -e "$T/td-down/img" ]] && grep -q "UNKNOWN" "$T/td-down/evid/cleanup.log" && grep -q "RETAINED" "$T/td-down/evid/cleanup.log"'
expect "teardown: a failed container removal turns a PASS into exit 3"       '[[ $(teardown_case td-fail 0 STUB_PRESENT=1 STUB_RM_CONTAINER_FAIL=1) == 3 ]]'
expect "teardown: the failure is recorded in cleanup.log and REPORT.md"      'grep -q "cleanup rc=1" "$T/td-fail/evid/cleanup.log" && grep -q "cleanup step(s) FAILED" "$T/td-fail/evid/REPORT.md"'
expect "teardown: a failed run keeps exit 1 (teardown cannot mask it)"       '[[ $(teardown_case td-f1 1 STUB_DAEMON_DOWN=1) == 1 ]]'
expect "teardown: an inconclusive run keeps exit 2"                          '[[ $(teardown_case td-f2 2 STUB_DAEMON_DOWN=1) == 2 ]]'
expect "teardown: a hung daemon probe is cut at its bound and counted"       '[[ $(teardown_case td-hang 0 STUB_PRESENT=1 STUB_SLEEP=200 TEARDOWN_PROBE_SECS=1) == 3 ]] && grep -q "UNKNOWN (rc=124" "$T/td-hang/evid/cleanup.log"'

echo "== clean_restart_verdict: an unreadable log never reads as quiet (ASTRA 6360307931 #2) =="
quiet="$T/quiet.log"; printf 'POLICY_ALLOW ...\n' > "$quiet"; resync="$T/resync.log"; printf 'FeedSync: starting UT1 sync from x\n' > "$resync"
( fails=0; . "$HERE/recovery-custody.sh"; cr(){ clean_restart_verdict "$@" >/dev/null 2>&1; }
  expect "clean restart: read log, nothing changed -> pass"              'cr 0 "$quiet" 0 1 1 absent'
  expect "clean restart: log read FAILED (rc 1) -> fail, not quiet"      '! cr 1 "$quiet" 0 1 1 absent'
  expect "clean restart: log read TIMED OUT (rc 124) -> fail"            '! cr 124 "$quiet" 0 1 1 absent'
  expect "clean restart: marker check ERROR -> fail"                     '! cr 0 "$quiet" 0 1 1 error'
  expect "clean restart: re-quarantined (recovered=1) -> fail"           '! cr 0 "$quiet" 1 1 1 absent'
  expect "clean restart: quarantined copies unreadable -> fail"          '! cr 0 "$quiet" 0 1 "" absent'
  expect "clean restart: quarantined copies changed -> fail"             '! cr 0 "$quiet" 0 1 2 absent'
  expect "clean restart: a feed sync started -> fail"                    '! cr 0 "$resync" 0 1 1 absent'
  exit "$fails" ) || fails=$((fails + $?))
n=$((n + 8))

echo "== evidence custody through the ACTUAL report + EXIT path (ASTRA 6360307931 #1) =="
# exit_case <name> <body> [env…]: a real script with `trap harness_teardown EXIT`
# whose write_report_and_exit exits 1 on any FAIL — the production shape.
# Prints the process exit code.
exit_case(){ local name="$1" body="$2"; shift 2; local D="$T/$name"; mkdir -p "$D/evid" "$D/vol" "$D/sock"; head -c 4096 /dev/zero > "$D/img"
  env "$@" bash -c '
    set -euo pipefail
    EVID="$1"; MD="$EVID/REPORT.md"; : > "$MD"; STEPLOG="$EVID/steps.log"; MP="$2"; MNT="$EVID/not-mounted"
    DIND=d; REG=r; IMG="$3"; SOCKDIR="$4"; CERTSD=""; CUSTODY_NAMES=""; CUSTODY_TREE=none; FAILS=0
    export DIAG_BOUND=1 DIAG_SLACK=1
    check(){ printf "%s %s %s %s\n" "$1" "$2" "$3" "$4" >> "$EVID/checks.txt"; if [[ "$3" == fail ]]; then FAILS=$((FAILS+1)); fi; }
    write_report_and_exit(){ echo REPORT-WRITTEN >> "$EVID/checks.txt"; (( FAILS > 0 )) && exit 1; exit 0; }
    . "$5"; trap harness_teardown EXIT
    eval "$6"
    write_report_and_exit' _ "$D/evid" "$D/vol" "$D/img" "$D/sock" "$HERE/recovery-custody.sh" "$body" >/dev/null 2>&1 && echo 0 || echo $?; }
xq(){ local d="$T/$1/vol/$2"; mkdir -p "$d"; printf 'manifest' > "$d/MANIFEST"; head -c 2097152 /dev/urandom > "$d/000001.vlog"; }
UNP='evidence_state "unpreserved:interrupted import on the volume"'
mkdir -p "$T/ex-copy/vol"; xq ex-copy catfeeddb.corrupt.51
rc="$(exit_case ex-copy "$UNP; quarantine_custody K t; delete_custodied K t" STUB_FAIL_MATCH='tar -cf')"
expect "EXIT path: a failed copy exits 1 and the image holding the evidence is RETAINED" '[[ $rc == 1 && -e "$T/ex-copy/img" ]] && grep -q "RETAINED .*custody-t failed" "$T/ex-copy/evid/cleanup.log" && grep -q "loop image RETAINED" "$T/ex-copy/evid/REPORT.md"'
mkdir -p "$T/ex-extract/vol"; xq ex-extract catfeeddb.corrupt.52
rc="$(exit_case ex-extract "$UNP; quarantine_custody K t; delete_custodied K t" STUB_TAR_GARBAGE=1)"
expect "EXIT path: a non-archive stream fails verification (extract or file count), exits 1, image RETAINED, nothing deleted" '[[ $rc == 1 && -e "$T/ex-extract/img" && -d "$T/ex-extract/vol/catfeeddb.corrupt.52" ]] && grep -Eq "custody-t fail the preserved archive failed verification: .*(does not extract|holds 0 files)" "$T/ex-extract/evid/checks.txt"'
mkdir -p "$T/ex-tamper/vol"; xq ex-tamper catfeeddb.corrupt.53
rc="$(exit_case ex-tamper "$UNP; quarantine_custody K t; delete_custodied K t" STUB_TAR_TAMPER="$T/ex-tamper/vol")"
expect "EXIT path: bytes that changed after hashing fail verification, image RETAINED" '[[ $rc == 1 && -e "$T/ex-tamper/img" ]] && grep -q "does not match the manifest" "$T/ex-tamper/evid/checks.txt"'
rc="$(exit_case ex-early "$UNP; dstep K compose-up 2 false")"
expect "EXIT path: an early abort (a failed step before custody) RETAINS the image" '[[ $rc == 1 && -e "$T/ex-early/img" ]] && grep -q "RETAINED .*interrupted import on the volume" "$T/ex-early/evid/cleanup.log"'
mkdir -p "$T/ex-ok/vol"; xq ex-ok catfeeddb.corrupt.54
rc="$(exit_case ex-ok "$UNP; quarantine_custody K t; delete_custodied K t")"
expect "EXIT path CONTROL: preserved + verified + deleted -> exit 0, state clear, the image is removed" '[[ $rc == 0 && ! -e "$T/ex-ok/img" ]] && [[ "$(cat "$T/ex-ok/evid/.evidence-state")" == clear:t ]]'
rc="$(exit_case ex-unpres-pass "$UNP")"
expect "EXIT path: a run that 'passes' with evidence still unpreserved exits 3, image RETAINED" '[[ $rc == 3 && -e "$T/ex-unpres-pass/img" ]]'

echo "== evidence lifecycle: arm BEFORE the risky step, invalidate on new entries (ASTRA 6360721903) =="
# The REAL caller ordering: pre-run custody leaves the state clear/preserved,
# then the import window is armed BEFORE the kill. A kill that fails must keep
# the image (it holds the partial import).
rc="$(exit_case lc-killfail 'quarantine_custody K pre-run; delete_custodied K pre-run; arm_evidence "an import is writing"; dstep K sigkill 2 false')"
expect "lifecycle: a FAILED kill after arming exits 1 and RETAINS the image" '[[ $rc == 1 && -e "$T/lc-killfail/img" ]] && grep -q "RETAINED .*an import is writing" "$T/lc-killfail/evid/cleanup.log"'
rc="$(exit_case lc-killhang 'quarantine_custody K pre-run; arm_evidence "an import is writing"; dstep K sigkill 1 "sleep 30"')"
expect "lifecycle: a kill that TIMES OUT after arming RETAINS the image" '[[ $rc == 1 && -e "$T/lc-killhang/img" ]]'
mkdir -p "$T/lc-newentry/vol"; xq lc-newentry catfeeddb.corrupt.61
rc="$(exit_case lc-newentry "$UNP; quarantine_custody K t; mkdir \"\$MP/catfeeddb.corrupt.62\"; printf x > \"\$MP/catfeeddb.corrupt.62/MANIFEST\"; delete_custodied K t")"
expect "lifecycle: a NEW entry after the inventory invalidates 'preserved' — exit 1, image RETAINED" '[[ $rc == 1 && -e "$T/lc-newentry/img" ]] && grep -q "RETAINED .*un-inventoried entries appeared" "$T/lc-newentry/evid/cleanup.log"'
expect "lifecycle: and the new entry itself is never deleted" '[[ -d "$T/lc-newentry/vol/catfeeddb.corrupt.62" && ! -e "$T/lc-newentry/vol/catfeeddb.corrupt.61" ]]'
mkdir -p "$T/lc-obserr/vol"; xq lc-obserr catfeeddb.corrupt.63
rc="$(exit_case lc-obserr "$UNP; quarantine_custody K t; delete_custodied K t" STUB_FAIL_MATCH="for e in  '")"
expect "lifecycle: an uncertain post-delete listing re-arms protection — exit 1, image RETAINED" '[[ $rc == 1 && -e "$T/lc-obserr/img" ]] && grep -q "RETAINED .*post-delete listing failed" "$T/lc-obserr/evid/cleanup.log"'
mkdir -p "$T/lc-changed/vol"; xq lc-changed catfeeddb.corrupt.64
rc="$(exit_case lc-changed "$UNP; quarantine_custody K t; printf y >> \"\$MP/catfeeddb.corrupt.64/MANIFEST\"; delete_custodied K t")"
expect "lifecycle: bytes changed after preservation — deletion REFUSED, image RETAINED, nothing deleted" '[[ $rc == 1 && -e "$T/lc-changed/img" && -d "$T/lc-changed/vol/catfeeddb.corrupt.64" ]] && grep -q "no longer match the preserved manifest" "$T/lc-changed/evid/checks.txt"'
mkdir -p "$T/lc-otherset/vol"; xq lc-otherset catfeeddb.corrupt.65; xq lc-otherset catfeeddb.corrupt.66
rc="$(exit_case lc-otherset "$UNP; quarantine_custody K t; CUSTODY_NAMES=catfeeddb.corrupt.65; delete_custodied K t")"
expect "lifecycle: an archive authorizes only the set it preserved — a different set is REFUSED" '[[ $rc == 1 && -e "$T/lc-otherset/img" && -d "$T/lc-otherset/vol/catfeeddb.corrupt.65" ]] && grep -q "is not the set preserved" "$T/lc-otherset/evid/checks.txt"'
mkdir -p "$T/lc-reuse/vol"; xq lc-reuse catfeeddb.corrupt.67
rc="$(exit_case lc-reuse "$UNP; quarantine_custody K a; arm_evidence restart; quarantine_custody K b")"
expect "lifecycle: re-custody of the SAME generation reuses the verified archive (no second copy) and clears the arm" '[[ $rc == 0 && ! -e "$T/lc-reuse/evid/custody/b/quarantine.tar.gz" && "$(cat "$T/lc-reuse/evid/custody/b/preserved-by")" == a ]] && grep -q "already preserved" "$T/lc-reuse/evid/checks.txt"'
mkdir -p "$T/lc-rearm/vol"; xq lc-rearm catfeeddb.corrupt.68
rc="$(exit_case lc-rearm "$UNP; quarantine_custody K t; delete_custodied K t; arm_evidence \"a restart may quarantine again\"; mkdir \"\$MP/catfeeddb.corrupt.69\"; printf z > \"\$MP/catfeeddb.corrupt.69/MANIFEST\"; dstep K restart 2 false")"
expect "lifecycle: a restart re-armed after deletion that then fails RETAINS the image holding its fresh quarantine" '[[ $rc == 1 && -e "$T/lc-rearm/img" ]] && grep -q "RETAINED .*a restart may quarantine again" "$T/lc-rearm/evid/cleanup.log"'

echo "== archive reuse/deletion requires RECOVERABLE bytes, never metadata (ASTRA 6361214485) =="
mkdir -p "$T/ar-ok/vol"; xq ar-ok catfeeddb.corrupt.71
rc="$(exit_case ar-ok "$UNP; quarantine_custody K a; arm_evidence restart; quarantine_custody K b; delete_custodied K b")"
expect "reuse CONTROL: an intact archive is re-verified and reused; delete -> exit 0, image removed, archive kept" '[[ $rc == 0 && ! -e "$T/ar-ok/img" && -s "$T/ar-ok/evid/custody/a/quarantine.tar.gz" && ! -e "$T/ar-ok/vol/catfeeddb.corrupt.71" ]] && grep -q "re-verified now" "$T/ar-ok/evid/checks.txt"'
mkdir -p "$T/ar-trunc/vol"; xq ar-trunc catfeeddb.corrupt.72
rc="$(exit_case ar-trunc "$UNP; quarantine_custody K a; : > \"\$EVID/custody/a/quarantine.tar.gz\"; arm_evidence restart; quarantine_custody K b; delete_custodied K b")"
expect "reuse: a TRUNCATED earlier archive is rejected and a FRESH verified copy is made before deletion" '[[ $rc == 0 && ! -e "$T/ar-trunc/evid/custody/b/preserved-by" ]] && (cd "$T/ar-trunc/evid/custody/b" && sha256sum -c --quiet quarantine.tar.gz.sha256) && grep -q "rejected: .*does not match its recorded digest" "$T/ar-trunc/evid/custody/b/verify.log"'
mkdir -p "$T/ar-missing/vol"; xq ar-missing catfeeddb.corrupt.73
rc="$(exit_case ar-missing "$UNP; quarantine_custody K a; mv \"\$EVID/custody/a/quarantine.tar.gz\" \"\$EVID/moved.tgz\"; arm_evidence restart; quarantine_custody K b; delete_custodied K b")"
expect "reuse: a MISSING earlier archive is rejected and a FRESH verified copy is made before deletion" '[[ $rc == 0 && ! -e "$T/ar-missing/evid/custody/b/preserved-by" ]] && (cd "$T/ar-missing/evid/custody/b" && sha256sum -c --quiet quarantine.tar.gz.sha256) && grep -q "rejected: archive missing" "$T/ar-missing/evid/custody/b/verify.log"'
mkdir -p "$T/ar-postreuse/vol"; xq ar-postreuse catfeeddb.corrupt.74
rc="$(exit_case ar-postreuse "$UNP; quarantine_custody K a; arm_evidence restart; quarantine_custody K b; : > \"\$EVID/custody/a/quarantine.tar.gz\"; delete_custodied K b")"
expect "delete: archive corrupted AFTER reuse, BEFORE delete -> REFUSED, exit 1, image RETAINED, source kept" '[[ $rc == 1 && -e "$T/ar-postreuse/img" && -d "$T/ar-postreuse/vol/catfeeddb.corrupt.74" ]] && grep -q "RETAINED .*authorizing archive is not recoverable" "$T/ar-postreuse/evid/cleanup.log"'
mkdir -p "$T/ar-postreuse-mv/vol"; xq ar-postreuse-mv catfeeddb.corrupt.75
rc="$(exit_case ar-postreuse-mv "$UNP; quarantine_custody K a; arm_evidence restart; quarantine_custody K b; mv \"\$EVID/custody/a/quarantine.tar.gz\" \"\$EVID/moved.tgz\"; delete_custodied K b")"
expect "delete: archive MISSING after reuse, before delete -> REFUSED, image RETAINED, source kept" '[[ $rc == 1 && -e "$T/ar-postreuse-mv/img" && -d "$T/ar-postreuse-mv/vol/catfeeddb.corrupt.75" ]] && grep -q "refusing to delete: archive missing" "$T/ar-postreuse-mv/evid/checks.txt"'
mkdir -p "$T/ar-own/vol"; xq ar-own catfeeddb.corrupt.76
rc="$(exit_case ar-own "$UNP; quarantine_custody K t; printf junk >> \"\$EVID/custody/t/quarantine.tar.gz\"; delete_custodied K t")"
expect "delete: its OWN archive altered between custody and delete -> REFUSED, image RETAINED" '[[ $rc == 1 && -e "$T/ar-own/img" && -d "$T/ar-own/vol/catfeeddb.corrupt.76" ]]'
mkdir -p "$T/ar-sidecar/vol"; xq ar-sidecar catfeeddb.corrupt.77
rc="$(exit_case ar-sidecar "$UNP; quarantine_custody K t; ( cd \"\$EVID/custody/t\" && sha256sum quarantine.tar.gz >/dev/null && : > quarantine.tar.gz && sha256sum quarantine.tar.gz > quarantine.tar.gz.sha256 ); delete_custodied K t")"
expect "delete: an empty archive whose digest was RE-RECORDED still fails the manifest check -> REFUSED" '[[ $rc == 1 && -e "$T/ar-sidecar/img" && -d "$T/ar-sidecar/vol/catfeeddb.corrupt.77" ]]'

echo "== structural: the REAL scenario arms protection before every risky step (ASTRA 6360721903) =="
# In the K scenario, from the import onward, the nearest evidence-state change
# before every dstep must be arm_evidence (never a stale preserved/clear state).
order="$(awk '
  /^if \[\[ "\$SCENARIO" == midimport-kill \]\]; then/ {k=1}
  k && /^fi$/ {k=0}
  !k {next}
  /arm_evidence /                  {last="arm"; armed=1; next}
  /quarantine_custody K|delete_custodied K/ {last="custody"; next}
  armed && /dstep K / { match($0, /dstep K [a-z-]+/); s=substr($0, RSTART+8, RLENGTH-8); print s "=" last }
' "$HERE/upgrade-enospc-qualify.sh" | tr '\n' ' ')"
expect "structural: every risky K step after the import starts is preceded by arm_evidence [$order]" '[[ -n "$order" && "$order" != *"=custody"* ]] && [[ "$order" == *"compose-start=arm"* && "$order" == *"sigkill=arm"* && "$order" == *"restart-after-free=arm"* && "$order" == *"clean-restart=arm"* ]]'

echo "== structural: no unbounded docker exec in the harness (ASTRA 6360307931 #3) =="
unb="$(grep -nE 'docker exec' "$HERE/upgrade-enospc-qualify.sh" "$HERE/recovery-custody.sh" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' | grep -v 'timeout' | grep -vE '(^|[^A-Za-z_])INB? ' || true)"
expect "structural: every docker exec is bounded (timeout, IN or INB) — offenders: ${unb:-none}" '[[ -z "$unb" ]]'
expect "structural: IN itself is bounded on both ends" 'grep -qE "^IN\(\)\{ .*timeout --kill-after=.*docker exec \"\\\$DIND\" timeout -s KILL" "$HERE/upgrade-enospc-qualify.sh"'

echo
if (( unsupported > 0 )); then echo "NOTE: $unsupported assertion(s) UNSUPPORTED on this platform (not counted as proven)"; fi
if (( fails == 0 )); then echo "PASS: recovery custody + enforced steps + verdicts + teardown — $n assertions, $unsupported unsupported"; exit 0
else echo "FAILED: $fails/$n assertions"; exit 1; fi
