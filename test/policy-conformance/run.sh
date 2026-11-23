#!/usr/bin/env bash
# Policy-engine differential conformance (shadow, non-blocking).
#   usage: test/policy-conformance/run.sh [report dir]
# Exit 0 only if the reference model's own tests and all five differential suites RAN
# and passed. 1 = a mismatch or a torn snapshot. 2 = a suite missing or skipped (never
# reported as a pass).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REPORT="${1:-$(mktemp -d)}"; mkdir -p "$REPORT"; REPORT="$(cd "$REPORT" && pwd)"
cd "$ROOT" || exit 2
SUITES="SingleConditionGrid RandomRuleSets PublicationSequence SnapshotAtomicity StartupDefault"

go test -tags policy_conformance -count=1 ./internal/policyref/ > "$REPORT/model.log" 2>&1
mrc=$?
CULVERT_POLICY_CONFORMANCE_REPORT="$REPORT" \
  go test -tags policy_conformance -race -count=1 -timeout 15m -v -run '^TestPolicyReference_' . > "$REPORT/conformance.log" 2>&1
rc=$?
grep -E '^(--- (PASS|FAIL|SKIP)|ok|FAIL)|MISMATCH|VACUOUS|OPEN QUESTION|torn|compared=' "$REPORT/conformance.log" | cut -c1-400 | head -80 || true
status=0
if [ "$mrc" -ne 0 ] || [ "$rc" -ne 0 ]; then
  echo "POLICY CONFORMANCE FAILED (model tests exit $mrc, differential exit $rc); see $REPORT"; status=1
fi
for s in $SUITES; do
  if ! grep -q "^--- PASS: TestPolicyReference_$s " "$REPORT/conformance.log"; then
    [ "$status" -eq 0 ] && { echo "INCOMPLETE: suite $s did not run and pass -- refusing to report a pass"; status=2; }
  fi
done
if grep -qE '^[[:space:]]*--- SKIP' "$REPORT/conformance.log"; then
  echo "INCOMPLETE: a suite or subtest was skipped -- refusing to report a pass"; [ "$status" -eq 0 ] && status=2
fi
[ "$status" -eq 0 ] && echo "policy conformance: model tests + 5/5 suites ran and passed"
exit "$status"
