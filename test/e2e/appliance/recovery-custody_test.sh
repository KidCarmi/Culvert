#!/usr/bin/env bash
# shellcheck disable=SC2034  # case variables are read by the sourced library or via eval
# test/e2e/appliance/recovery-custody_test.sh — LOCAL red/green proof of the
# bounded/enforced steps, the quarantine chain of custody and the enforced
# teardown in recovery-custody.sh (ASTRA item 5). No lab, no Docker daemon, no
# network: a stub `docker` on PATH runs `docker exec <c> <cmd…>` locally against
# a temp directory standing in for the data volume, and can be told to fail or
# hang. Each case runs in a subshell because a FAIL ends the run
# (write_report_and_exit), exactly as in the real harness.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; [[ -n "${KEEP:-}" ]] && echo "keeping $T" || trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
[ -n "${STUB_SLEEP:-}" ] && sleep "$STUB_SLEEP"
case "$1" in
  exec) shift 2
    if [ -n "${STUB_FAIL_MATCH:-}" ] && [[ "$*" == *"$STUB_FAIL_MATCH"* ]]; then echo "stub: forced failure" >&2; exit 1; fi
    exec "$@" ;;
  inspect) [ -n "${STUB_PRESENT:-}" ] ;;
  rm) [ -z "${STUB_RM_CONTAINER_FAIL:-}" ] ;;
  *) echo "stub docker: unsupported $*" >&2; exit 2 ;;
esac
STUB
chmod +x "$T/bin/docker"; export PATH="$T/bin:$PATH"

fails=0; n=0
ok(){ n=$((n+1)); printf 'ok   %s\n' "$1"; }
bad(){ n=$((n+1)); printf 'FAIL %s\n' "$1"; fails=$((fails+1)); }
expect(){ if eval "$2"; then ok "$1"; else bad "$1 (assertion: $2)"; fi; }

# run_case <name> <body>: a fresh evidence dir + volume, the harness hooks
# stubbed, the library sourced; prints the case's exit code.
run_case(){ local name="$1" body="$2"
  C="$T/$name"; mkdir -p "$C/evid" "$C/vol"
  ( set -euo pipefail
    EVID="$C/evid"; STEPLOG="$EVID/steps.log"; MP="$C/vol"; DIND=stub-dind
    CUSTODY_NAMES=""; CUSTODY_TREE=none
    check(){ printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >> "$EVID/checks.txt"; }
    diagnose(){ :; }
    write_report_and_exit(){ exit 99; }
    # shellcheck source=recovery-custody.sh
    . "$HERE/recovery-custody.sh"
    eval "$body"
    printf 'CUSTODY_NAMES=%s\nCUSTODY_TREE=%s\n' "$CUSTODY_NAMES" "$CUSTODY_TREE" > "$EVID/vars.txt"
  ) > "$C/out.txt" 2>&1 && echo 0 || echo $?
}
checks(){ cat "$T/$1/evid/checks.txt" 2>/dev/null || true; }
mkq(){ local d="$T/$1/vol/$2"; mkdir -p "$d"; printf 'manifest-%s' "$2" > "$d/MANIFEST"; printf 'k' > "$d/KEYREGISTRY"
  head -c 2097152 /dev/zero > "$d/000001.vlog"; }   # one file over the 1 MiB metadata limit

echo "== step: bounded + enforced =="
rc="$(run_case step-ok 'step K s 5 docker exec x true')"
expect "step: success returns 0 and records no failure" '[[ $rc == 0 && -z "$(checks step-ok)" ]]'
expect "step: success is logged with rc=0" 'grep -q "K/s rc=0" "$T/step-ok/evid/steps.log"'
rc="$(run_case step-fail 'step K s 5 docker exec x false')"
expect "step: a non-zero exit FAILS the check and ends the run" '[[ $rc == 99 ]] && checks step-fail | grep -q "step-s fail required harness step .s. exit 1"'
rc="$(STUB_SLEEP=5 run_case step-hang 'step K s 1 docker exec x true')"
expect "step: a hang is cut at the bound and FAILS as timed out" '[[ $rc == 99 ]] && checks step-hang | grep -q "timed out after 1s"'

echo "== quarantine_custody: inventory + hash + retained metadata BEFORE deletion =="
rc="$(run_case cust-empty 'quarantine_custody K t')"
expect "custody: an empty volume passes with nothing to delete" '[[ $rc == 0 ]] && checks cust-empty | grep -q "custody-t pass inventory: nothing quarantined"'
mkdir -p "$T/cust-two/vol"; mkq cust-two catfeeddb.corrupt.1700000000000000001; mkq cust-two catfeeddb.importingtmp.42
rc="$(run_case cust-two 'quarantine_custody K t')"
d="$T/cust-two/evid/custody/t"
expect "custody: two entries inventoried and PASS" '[[ $rc == 0 ]] && checks cust-two | grep -q "custody-t pass inventoried BEFORE deletion: 2 entr"'
expect "custody: inventory records file count and bytes per entry" 'grep -q "^catfeeddb.corrupt.1700000000000000001 files=3 bytes=$((2097152+1+$(printf manifest-catfeeddb.corrupt.1700000000000000001 | wc -c)))$" "$d/inventory.txt"'
expect "custody: the manifest hashes every file (6) and verifies against the volume" '[[ $(wc -l < "$d/manifest.sha256") == 6 ]] && (cd "$T/cust-two/vol" && sha256sum -c --quiet "$d/manifest.sha256")'
expect "custody: CUSTODY_TREE is the sha256 of the manifest" 'grep -q "CUSTODY_TREE=$(sha256sum "$d/manifest.sha256" | cut -d" " -f1)" "$T/cust-two/evid/vars.txt"'
expect "custody: small metadata files are retained byte-for-byte, the 2 MiB vlog is not" 'grep -q "MANIFEST" "$d/meta.list" && ! grep -q "000001.vlog" "$d/meta.list" && [[ $(wc -l < "$d/meta.list") == 4 ]]'
expect "custody: inventory is NOT deletion — every entry is still on the volume" '[[ -d "$T/cust-two/vol/catfeeddb.corrupt.1700000000000000001" && -d "$T/cust-two/vol/catfeeddb.importingtmp.42" ]]'
mkdir -p "$T/cust-badname/vol"; mkq cust-badname 'catfeeddb.corrupt.1;x'
rc="$(run_case cust-badname 'quarantine_custody K t')"
expect "custody: an unexpected entry name is REFUSED (never hashed or deleted)" '[[ $rc == 99 ]] && checks cust-badname | grep -q "refusing to inventory/delete" && [[ -d "$T/cust-badname/vol/catfeeddb.corrupt.1;x" ]]'
mkdir -p "$T/cust-hashfail/vol"; mkq cust-hashfail catfeeddb.corrupt.7
rc="$(STUB_FAIL_MATCH=sha256sum run_case cust-hashfail 'quarantine_custody K t; delete_custodied K t')"
expect "custody: a hashing failure FAILS before anything is deleted" '[[ $rc == 99 ]] && checks cust-hashfail | grep -q "hashing the quarantined copies failed" && [[ -d "$T/cust-hashfail/vol/catfeeddb.corrupt.7" ]]'

echo "== delete_custodied: exactly the inventoried set, enforced =="
mkdir -p "$T/del-ok/vol/catfeeddb"; mkq del-ok catfeeddb.corrupt.11; mkq del-ok catfeeddb.importingtmp.12
rc="$(run_case del-ok 'quarantine_custody K t; delete_custodied K t')"
expect "delete: removes exactly the inventoried entries and PASSES" '[[ $rc == 0 ]] && checks del-ok | grep -q "delete-t pass deleted exactly the inventoried set" && [[ ! -e "$T/del-ok/vol/catfeeddb.corrupt.11" && ! -e "$T/del-ok/vol/catfeeddb.importingtmp.12" ]]'
expect "delete: the live store beside them is untouched" '[[ -d "$T/del-ok/vol/catfeeddb" ]]'
mkdir -p "$T/del-late/vol"; mkq del-late catfeeddb.corrupt.21
rc="$(run_case del-late 'quarantine_custody K t; mkdir "$MP/catfeeddb.corrupt.22"; delete_custodied K t')"
expect "delete: a copy that appears AFTER the inventory is never destroyed unrecorded" '[[ -d "$T/del-late/vol/catfeeddb.corrupt.22" && ! -e "$T/del-late/vol/catfeeddb.corrupt.21" ]]'
expect "delete: and its appearance FAILS the check" 'checks del-late | grep -q "delete-t fail .*appeared meanwhile: catfeeddb.corrupt.22"'
mkdir -p "$T/del-fail/vol"; mkq del-fail catfeeddb.corrupt.31
rc="$(STUB_FAIL_MATCH='rm -rf' run_case del-fail 'quarantine_custody K t; delete_custodied K t')"
expect "delete: a failed deletion FAILS the run (was: rm … || true)" '[[ $rc == 99 ]] && checks del-fail | grep -q "step-delete-t fail" && [[ -d "$T/del-fail/vol/catfeeddb.corrupt.31" ]]'

echo "== harness_teardown: bounded, enforced, never masks the verdict =="
# teardown_case <name> <script-exit> [stub env…]: runs a script whose EXIT trap
# is harness_teardown; prints the process exit code.
teardown_case(){ local name="$1" st="$2"; shift 2; local D="$T/$name"; mkdir -p "$D/evid" "$D/sock"; : > "$D/img"
  env "$@" bash -c '
    set -euo pipefail; EVID="$1"; MD="$EVID/REPORT.md"; : > "$MD"
    DIND=d; REG=r; MNT="$1/not-mounted"; IMG="$2"; SOCKDIR="$3"; CERTSD=""
    . "$4"; trap harness_teardown EXIT; exit "$5"' _ "$D/evid" "$D/img" "$D/sock" "$HERE/recovery-custody.sh" "$st" \
    >/dev/null 2>&1 && echo 0 || echo $?; }
expect "teardown: clean teardown keeps a passing exit 0"            '[[ $(teardown_case td-ok 0) == 0 ]]'
expect "teardown: clean teardown removes the image and socket dir"  '[[ ! -e "$T/td-ok/img" && ! -d "$T/td-ok/sock" ]]'
expect "teardown: a failed step turns a PASS into exit 3 (not silent)" '[[ $(teardown_case td-fail 0 STUB_PRESENT=1 STUB_RM_CONTAINER_FAIL=1) == 3 ]]'
expect "teardown: the failure is recorded in cleanup.log and REPORT.md" 'grep -q "cleanup rc=1" "$T/td-fail/evid/cleanup.log" && grep -q "cleanup step(s) FAILED" "$T/td-fail/evid/REPORT.md"'
expect "teardown: a failed run keeps exit 1 (teardown cannot mask it)"  '[[ $(teardown_case td-f1 1 STUB_PRESENT=1 STUB_RM_CONTAINER_FAIL=1) == 1 ]]'
expect "teardown: an inconclusive run keeps exit 2"                     '[[ $(teardown_case td-f2 2 STUB_PRESENT=1 STUB_RM_CONTAINER_FAIL=1) == 2 ]]'
expect "teardown: a hung daemon probe is cut at its bound and counted (not read as absent)" '[[ $(teardown_case td-hang 0 STUB_PRESENT=1 STUB_SLEEP=200 TEARDOWN_PROBE_SECS=1) == 3 ]] && grep -q "timed out after 1s" "$T/td-hang/evid/cleanup.log"'

echo
if (( fails == 0 )); then echo "PASS: recovery custody + enforced steps + teardown — $n assertions"; exit 0
else echo "FAILED: $fails/$n assertions"; exit 1; fi
