#!/usr/bin/env bash
# Model-to-implementation conformance for the maintenance agent (shadow, non-blocking).
#   usage: test/lifecycle-conformance/run.sh [report dir]
# Exit 0 only if the model check completed, all three conformance suites RAN and passed, and
# both orphan-survival suites RAN and passed.
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
# in one is. Any non-zero go test exit is INCOMPLETE (2) unless the run is provably complete
# and only a pinned expectation or the reaped control disagreed (1).
OLOG="$REPORT/orphan-survival.log"
timeout 300 go test -tags "$TAG" . -run '^TestOrphanSurvival_' -count=1 -timeout 240s -v > "$OLOG" 2>&1
orc=$?
grep -E '^(--- (PASS|FAIL|SKIP): TestOrphanSurvival|ok|FAIL|PASS)|CLASSIFY' "$OLOG" | head -40 || true
# Never truncated: every line that decides the verdict.
grep -E 'EXPECTATION MISMATCH|INVALID|A3:|panic:|test timed out' "$OLOG" || true
opassed=$(grep -cE '^--- PASS: TestOrphanSurvival_(CrashVectors|ReapedControl) ' "$OLOG" || true)
oresults=$(grep -cE '^--- (PASS|FAIL): TestOrphanSurvival_(CrashVectors|ReapedControl) ' "$OLOG" || true)
if [ "$orc" -eq 0 ]; then
  if [ "$opassed" -ne 2 ] || grep -q -- '--- SKIP' "$OLOG"; then
    echo "INCOMPLETE: expected 2 orphan-survival suites to run and pass with no skipped vector, saw $opassed passing -- refusing to report a pass"; status=2
  else
    echo "orphan survival: 2/2 suites ran and passed (findings pinned as open; see the CLASSIFY lines)"
  fi
elif grep -qE 'EXPECTATION MISMATCH|A3:' "$OLOG" && ! grep -qE 'panic:|test timed out|INVALID' "$OLOG" && [ "$oresults" -eq 2 ]; then
  echo "ORPHAN SURVIVAL MISMATCH (go test exit $orc): a pinned finding or the reaped control changed; see $OLOG"; [ "$status" -lt 1 ] && status=1
else
  echo "INCOMPLETE: orphan-survival run did not complete or did not exercise orphan survival (go test exit $orc); see $OLOG"; status=2
fi
echo "model check exit=$mc  overall exit=$status  reports: $REPORT"
exit "$status"
