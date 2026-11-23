#!/usr/bin/env bash
# Model-to-implementation conformance for the maintenance agent (shadow, non-blocking).
#   usage: test/lifecycle-conformance/run.sh [report dir]
# Exit 0 only if the model check completed, all three conformance suites RAN and passed, and
# every orphan-survival vector and control flow ran to its end and passed.
# Exit 1 = a conformance vector mismatched, an orphan-survival finding no longer matches its
# pinned expectation, or an owner-approved property failed.
# Exit 2 = incomplete (budget hit, vacuous property, a suite skipped or missing, an orphan
# run that failed for any reason other than a pinned expectation or the reaped control):
# never reported as a pass, and never downgraded by anything below.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REPORT="${1:-$(mktemp -d)}"; mkdir -p "$REPORT"; REPORT="$(cd "$REPORT" && pwd)"
BIN="$(mktemp -d)"; trap 'rm -rf "$BIN"' EXIT
TAG=lifecycle_conformance
status=0
cd "$ROOT/cmd/culvert-maint" || exit 2

echo "== model check (abstraction only: says nothing about the Go code by itself) =="
# Built, then executed, instead of `go run`: `go run` reports every non-zero exit as 1,
# which would turn "incomplete" (2) into "failed" (1).
go build -tags "$TAG" -o "$BIN/lifecyclecheck" ./internal/lifecyclemodel/cmd/lifecyclecheck || exit 2
# The policy lives in the checker: 2 = budget hit / vacuous property (wins over everything);
# 1 = an owner-APPROVED property fails. A failing PROPOSED or OPEN property is printed with
# its trace for the owner and is not a verdict on the pull request.
"$BIN/lifecyclecheck" -include-proposed -fail-only-approved -max-states 200000 -max-seconds 60 -report "$REPORT"
mc=$?
case "$mc" in 0) ;; 1) status=1 ;; *) status=2 ;; esac

echo "== conformance: model-derived sequences against the real maintenance-agent code =="
CULVERT_CONFORMANCE_REPORT="$REPORT" \
  timeout 300 go test -tags "$TAG" ./internal/server/ -run 'TestModelConformance' -count=1 -timeout 240s -v \
  > "$REPORT/conformance.log" 2>&1
rc=$?
grep -E '^(--- (PASS|FAIL|SKIP): TestModelConformance|ok|FAIL|PASS)|MISMATCH|PROPERTY|VACUOUS|never reached' "$REPORT/conformance.log" | head -60 || true
passed=$(grep -c '^--- PASS: TestModelConformance' "$REPORT/conformance.log" || true)
if [ "$rc" -ne 0 ]; then
  echo "CONFORMANCE FAILED (go test exit $rc); see $REPORT/conformance.log"; [ "$status" -lt 1 ] && status=1
elif [ "$passed" -ne 3 ] || grep -q '^--- SKIP' "$REPORT/conformance.log"; then
  echo "INCOMPLETE: expected 3 conformance suites to run and pass, saw $passed -- refusing to report a pass"; status=2
else
  echo "conformance: 3/3 suites ran and passed"
fi

echo "== orphan survival: real agent binary, the in-flight docker command outlives the agent =="
# Findings are pinned as `open` in orphanExpectations; a finding is not a failure, a change
# in one is. Exit 0 or 1 needs POSITIVE evidence that every vector and control flow ran to
# its end; 1 additionally needs every failed subtest to be explained by its own EXPECTATION
# MISMATCH or A3 line. Anything else non-zero is INCOMPLETE (2).
OLOG="$REPORT/orphan-survival.log"
OVEC=7                # kill points with a docker command in flight: killPoints() minus "health"
OFLOWS=$((2 * OVEC))  # report + later-operation flow per vector; the reaped control runs the same 14
timeout 300 go test -tags "$TAG" . -run '^TestOrphan(Survival|Classifier)_' -count=1 -timeout 240s -v > "$OLOG" 2>&1
orc=$?
grep -E '^(--- (PASS|FAIL|SKIP): TestOrphan|ok|FAIL|PASS)|CLASSIFY|ORPHAN-SUMMARY' "$OLOG" | head -40 || true
# Never truncated: every line that decides the verdict.
grep -E 'EXPECTATION MISMATCH|INVALID|A3:|panic:|test timed out|--- FAIL' "$OLOG" || true
ocv=$(grep -cE "ORPHAN-COMPLETE TestOrphanSurvival_CrashVectors/[^ ]+ flow=(report|later)\$" "$OLOG" || true)
occ=$(grep -cE "ORPHAN-COMPLETE TestOrphanSurvival_ReapedControl/[^ ]+ flow=control-later=(true|false)\$" "$OLOG" || true)
osum=$(grep -cE "ORPHAN-SUMMARY TestOrphanSurvival_(CrashVectors|ReapedControl) kill_points=$OVEC flows_expected=$OFLOWS\$" "$OLOG" || true)
otop=$(grep -cE '^--- (PASS|FAIL): TestOrphan(Survival_CrashVectors|Survival_ReapedControl|Classifier_Later) ' "$OLOG" || true)
ocomplete=0
if [ "$ocv" -eq "$OFLOWS" ] && [ "$occ" -eq "$OFLOWS" ] && [ "$osum" -eq 2 ] && [ "$otop" -eq 3 ] && ! grep -q -- '--- SKIP' "$OLOG"; then
  ocomplete=1
fi
obroken=0
grep -qE 'INVALID|panic:|test timed out' "$OLOG" && obroken=1
# Every failed subtest must carry its own explanation; a failed top-level test must be one of
# the two vector suites and must have a failed subtest.
ofsub=0; ounexplained=0
for n in $(grep -oE '^ +--- FAIL: TestOrphanSurvival_(CrashVectors|ReapedControl)/[^ ]+' "$OLOG" | awk '{print $3}'); do
  ofsub=$((ofsub + 1))
  grep -qF -e "EXPECTATION MISMATCH $n:" -e "A3: $n:" "$OLOG" || ounexplained=$((ounexplained + 1))
done
for top in $(grep -oE '^--- FAIL: TestOrphan[A-Za-z_]+' "$OLOG" | awk '{print $3}'); do
  case "$top" in
    TestOrphanSurvival_CrashVectors|TestOrphanSurvival_ReapedControl)
      grep -qE "^ +--- FAIL: $top/" "$OLOG" || ounexplained=$((ounexplained + 1)) ;;
    *) ounexplained=$((ounexplained + 1)) ;;
  esac
done
echo "orphan survival evidence: complete flows $ocv+$occ of $OFLOWS+$OFLOWS, summaries $osum/2, suite results $otop/3, failed subtests $ofsub (unexplained $ounexplained), invalid/panic/timeout=$obroken, go test exit $orc"
if [ "$orc" -eq 0 ] && [ "$ocomplete" -eq 1 ] && ! grep -q -- '--- FAIL' "$OLOG"; then
  echo "orphan survival: all suites ran to completion and passed (findings pinned as open; see the CLASSIFY lines)"
elif [ "$orc" -ne 0 ] && [ "$ocomplete" -eq 1 ] && [ "$obroken" -eq 0 ] && [ "$ofsub" -ge 1 ] && [ "$ounexplained" -eq 0 ]; then
  echo "ORPHAN SURVIVAL MISMATCH: only pinned findings or the reaped control changed; see $OLOG"; [ "$status" -lt 1 ] && status=1
else
  echo "INCOMPLETE: orphan-survival run is not provably complete, or failed for a reason other than a pinned finding; see $OLOG"; status=2
fi
echo "model check exit=$mc  overall exit=$status  reports: $REPORT"
exit "$status"
