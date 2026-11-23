#!/usr/bin/env bash
# Model-to-implementation conformance for the maintenance agent (shadow, non-blocking).
#   usage: test/lifecycle-conformance/run.sh [report dir]
# Exit 0 only if the model check completed, all three conformance suites RAN and passed, and
# both orphan-survival suites RAN and passed.
# Exit 1 = a conformance vector mismatched, an orphan-survival finding no longer matches its
# pinned expectation, or an owner-approved property failed.
# Exit 2 = incomplete (budget hit, vacuous property, a suite skipped or missing, an orphan
# vector that did not exercise orphan survival): never reported as a pass, and never
# downgraded by anything below.
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
# in one is. INVALID = the vector did not exercise the hazard (A1/A2/A5): incomplete, not a pass.
timeout 300 go test -tags "$TAG" . -run '^TestOrphanSurvival_' -count=1 -timeout 240s -v \
  > "$REPORT/orphan-survival.log" 2>&1
orc=$?
grep -E '^(--- (PASS|FAIL|SKIP): TestOrphanSurvival|ok|FAIL|PASS)|CLASSIFY|MISMATCH|INVALID|A3:' "$REPORT/orphan-survival.log" | head -60 || true
opassed=$(grep -cE '^--- PASS: TestOrphanSurvival_(CrashVectors|ReapedControl) ' "$REPORT/orphan-survival.log" || true)
if [ "$orc" -ne 0 ] && { grep -q 'INVALID' "$REPORT/orphan-survival.log" || ! grep -q -- '--- FAIL' "$REPORT/orphan-survival.log"; }; then
  echo "INCOMPLETE: orphan-survival vectors did not run or did not exercise orphan survival (go test exit $orc); see $REPORT/orphan-survival.log"; status=2
elif [ "$orc" -ne 0 ]; then
  echo "ORPHAN SURVIVAL MISMATCH (go test exit $orc); see $REPORT/orphan-survival.log"; [ "$status" -lt 1 ] && status=1
elif [ "$opassed" -ne 2 ] || grep -q -- '--- SKIP' "$REPORT/orphan-survival.log"; then
  echo "INCOMPLETE: expected 2 orphan-survival suites to run and pass with no skipped vector, saw $opassed passing -- refusing to report a pass"; status=2
else
  echo "orphan survival: 2/2 suites ran and passed (findings pinned as open; see the CLASSIFY lines)"
fi
echo "model check exit=$mc  overall exit=$status  reports: $REPORT"
exit "$status"
