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

fails=0; n=0
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
expect "dstep: no remote process outlives the KILL" '! ps -eo args= | grep -qx "sleep 29.517"'

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

echo
if (( fails == 0 )); then echo "PASS: recovery custody + enforced steps + verdicts + teardown — $n assertions"; exit 0
else echo "FAILED: $fails/$n assertions"; exit 1; fi
