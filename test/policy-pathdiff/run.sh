#!/usr/bin/env bash
# Cross-path policy differential (shadow, non-blocking).
#   usage: test/policy-pathdiff/run.sh [report dir]
# Exit 0 only if the generator's own tests and all five suites RAN and matched the
# reviewed baselines. 1 = behaviour drift, a vacuous stratum or a dead comparator.
# 2 = a suite missing or skipped (never reported as a pass).
# To re-record the baselines after a reviewed change: PATHDIFF_WRITE_BASELINE=1 run.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REPORT="${1:-$(mktemp -d)}"; mkdir -p "$REPORT"; REPORT="$(cd "$REPORT" && pwd)"
cd "$ROOT" || exit 2
SUITES="Generated Controls ActionDispatch DialAlias Review"

go test -tags policy_pathdiff -count=1 ./internal/pathdiffgen/ > "$REPORT/generator.log" 2>&1
grc=$?
# CGO_ENABLED=0 matches the shipped binary, so the dial-alias suite sees its resolver.
CGO_ENABLED=0 \
PATHDIFF_SEED="${PATHDIFF_SEED:-heldout-1}" PATHDIFF_SCALE="${PATHDIFF_SCALE:-1}" \
PATHDIFF_OUT="$REPORT/report.json" PATHDIFF_REVIEW_OUT="$REPORT/review.json" \
PATHDIFF_BASELINE="$HERE/baseline.json" \
PATHDIFF_DISPATCH_BASELINE="$HERE/baseline-dispatch.json" \
PATHDIFF_DIAL_BASELINE="$HERE/baseline-dial.json" \
PATHDIFF_REVIEW="$HERE/review_predictions.jsonl" \
  go test -tags policy_pathdiff -count=1 -timeout 15m -v -run '^TestPathDiff_' . > "$REPORT/pathdiff.log" 2>&1
rc=$?
grep -E '^(--- (PASS|FAIL|SKIP)|ok|FAIL)|behaviour drift|vacuous|not live|not deterministic|verifier changed|seed=|LEAD ' "$REPORT/pathdiff.log" | cut -c1-300 | head -80 || true
status=0
if [ "$grc" -ne 0 ] || [ "$rc" -ne 0 ]; then
  echo "POLICY PATHDIFF FAILED (generator tests exit $grc, differential exit $rc); see $REPORT"; status=1
fi
for s in $SUITES; do
  if ! grep -q "^--- PASS: TestPathDiff_$s " "$REPORT/pathdiff.log"; then
    [ "$status" -eq 0 ] && { echo "INCOMPLETE: suite $s did not run and pass -- refusing to report a pass"; status=2; }
  fi
done
if grep -qE '^[[:space:]]*--- SKIP' "$REPORT/pathdiff.log"; then
  echo "INCOMPLETE: a suite was skipped -- refusing to report a pass"; [ "$status" -eq 0 ] && status=2
fi
[ "$status" -eq 0 ] && echo "policy pathdiff: generator tests + 5/5 suites ran and matched the reviewed baselines"
exit "$status"
