#!/usr/bin/env bash
# test/e2e/appliance/convergence-oracle_test.sh — LOCAL red/green proof of the
# F-DISK recovery convergence verdict (ASTRA 2026-10-20 §2 "Require negative
# propagation tests and a mandatory convergence verdict"). No lab, no Docker, no
# network: it sources the SAME pure functions upgrade-enospc-qualify.sh uses and
# asserts the decision directly — the way ASTRA independently executed the
# operator-capture classifier against a synthetic input.
#
# The defect being pinned: the old harness counted only `fail` toward the exit
# code, so a recovery run that EXERCISED convergence and only ever hit a
# lab-sizing ("write REFUSED (disk_space)") or network ("download/parse failed")
# INFO still exited 0 — and job SUCCESS was then read as convergence proof when
# none was observed. The NEGATIVE-PROPAGATION assertions below require every such
# exercised-but-unproven case to map to `incomplete` (exit 2), never `pass`.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/convergence-oracle.sh"

fails=0; n=0
eq(){ n=$((n+1)); local got="$1" want="$2" what="$3"
  if [[ "$got" == "$want" ]]; then printf 'ok   %-58s = %s\n' "$what" "$got"
  else printf 'FAIL %-58s = %s (want %s)\n' "$what" "$got" "$want"; fails=$((fails+1)); fi; }

echo "== classify_convergence: outcome -> class =="
eq "$(classify_convergence 'FeedSync: sync complete (2581463 domains)')" proven        'sync complete -> proven'
eq "$(classify_convergence 'FeedSync: sync complete')"                   proven        'sync complete (bare) -> proven'
eq "$(classify_convergence 'FeedSync: write REFUSED (disk_space)')"      unproven_lab  'disk_space refusal -> unproven_lab'
eq "$(classify_convergence 'FeedSync: write REFUSED (disk_space) 1142MiB')" unproven_lab 'disk_space refusal w/ detail -> unproven_lab'
eq "$(classify_convergence 'FeedSync: download/parse failed: dial tcp')"  unproven_net  'download/parse failed -> unproven_net'
eq "$(classify_convergence '')"                                          failed        'empty (no outcome) -> failed'
eq "$(classify_convergence 'FeedSync: bulk write failed')"               failed        'bulk write failed -> failed'
eq "$(classify_convergence 'FeedSync: could not begin the import')"      failed        'could not begin import -> failed'
eq "$(classify_convergence 'FeedSync: import written but could not be certified')" failed 'uncertified import -> failed'
eq "$(classify_convergence 'FeedSync: something unrecognised')"          failed        'unrecognised outcome -> failed (fail-closed)'

echo "== convergence_exit_class: (ran, verdict, fails) -> exit class =="
# Not a recovery scenario (path not exercised): a pass, decided by other checks.
eq "$(convergence_exit_class 0 none 0)"          pass        'ran=0                 -> pass (path not exercised)'
eq "$(convergence_exit_class 0 none 3)"          fail        'ran=0 but fails>0     -> fail'
# Convergence PROVEN: the only way an exercised recovery run passes.
eq "$(convergence_exit_class 1 proven 0)"        pass        'ran=1 proven          -> pass'
# NEGATIVE PROPAGATION — the defect. Each of these exited 0 before the fix.
eq "$(convergence_exit_class 1 unproven_lab 0)"  incomplete  'ran=1 unproven_lab    -> incomplete (NOT pass)'
eq "$(convergence_exit_class 1 unproven_net 0)"  incomplete  'ran=1 unproven_net    -> incomplete (NOT pass)'
eq "$(convergence_exit_class 1 none 0)"          incomplete  'ran=1 none (never converged) -> incomplete (NOT pass)'
# A product disk-side failure fails outright (exit 1), ahead of INCONCLUSIVE.
eq "$(convergence_exit_class 1 none 1)"          fail        'ran=1 w/ fails>0      -> fail'
eq "$(convergence_exit_class 1 proven 2)"        fail        'ran=1 proven w/ fails>0 -> fail (a fail elsewhere still fails)'

echo "== invariant: an EXERCISED run can never PASS without a PROVEN convergence =="
for v in none unproven_lab unproven_net failed; do
  cls="$(convergence_exit_class 1 "$v" 0)"
  n=$((n+1))
  if [[ "$cls" != pass ]]; then printf 'ok   exercised+%-13s never passes (=%s)\n' "$v" "$cls"
  else printf 'FAIL exercised+%-13s mapped to PASS — the defect\n' "$v"; fails=$((fails+1)); fi
done
# ...and the one that MUST pass does.
n=$((n+1)); [[ "$(convergence_exit_class 1 proven 0)" == pass ]] \
  && echo 'ok   exercised+proven       passes' \
  || { echo 'FAIL exercised+proven did NOT pass — the oracle is vacuous'; fails=$((fails+1)); }

echo
if (( fails == 0 )); then echo "PASS: convergence oracle — $n assertions (mandatory verdict + negative propagation)"; exit 0
else echo "FAILED: $fails/$n assertions"; exit 1; fi
