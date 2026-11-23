#!/usr/bin/env bash
# Model-to-implementation conformance for the maintenance agent (shadow, non-blocking).
#   usage: test/lifecycle-conformance/run.sh [report dir]
# Exit 0 only if the model check completed and all three conformance suites RAN and passed.
# Exit 1 = a conformance vector mismatched, an owner-approved property failed, or the model
#          or the real code's observations drifted from the reviewed baseline (baseline.json,
#          observed.json; regenerate with update-baseline.sh after an intended change).
# Exit 2 = incomplete (budget hit, vacuous property, a suite skipped or missing): never
# reported as a pass, and never downgraded by anything below.
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
# 1 = an owner-APPROVED property fails; 3 = drift from the reviewed baseline (reported as 1
# overall). A failing PROPOSED or OPEN property is printed with its trace for the owner and is
# not a verdict on the pull request -- but a CHANGE in its verdict is drift.
"$BIN/lifecyclecheck" -include-proposed -fail-only-approved -max-states 200000 -max-seconds 60 -report "$REPORT"
mc=$?
case "$mc" in 0) ;; 1|3) status=1 ;; *) status=2 ;; esac

echo "== conformance: model-derived sequences against the real maintenance-agent code =="
CULVERT_CONFORMANCE_REPORT="$REPORT" \
  timeout 300 go test -tags "$TAG" ./internal/server/ -run 'TestModelConformance' -count=1 -timeout 240s -v \
  > "$REPORT/conformance.log" 2>&1
rc=$?
grep -E '^(--- (PASS|FAIL|SKIP): TestModelConformance|ok|FAIL|PASS)|MISMATCH|PROPERTY|VACUOUS|DRIFT|INCOMPLETE|never reached' "$REPORT/conformance.log" | head -60 || true
passed=$(grep -c '^--- PASS: TestModelConformance' "$REPORT/conformance.log" || true)
if [ "$rc" -ne 0 ]; then
  echo "CONFORMANCE FAILED (go test exit $rc); see $REPORT/conformance.log"; [ "$status" -lt 1 ] && status=1
# A skipped SUBTEST is indented ("    --- SKIP: ..."); match it as well as a skipped suite.
elif [ "$passed" -ne 3 ] || grep -qE '^[[:space:]]*--- SKIP' "$REPORT/conformance.log"; then
  echo "INCOMPLETE: expected 3 conformance suites to run and pass, saw $passed -- refusing to report a pass"; status=2
else
  echo "conformance: 3/3 suites ran and passed"
fi
echo "model check exit=$mc  overall exit=$status  reports: $REPORT"
exit "$status"
