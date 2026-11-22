#!/usr/bin/env bash
# Model-to-implementation conformance for the maintenance agent (shadow, non-blocking).
#   usage: test/lifecycle-conformance/run.sh [report dir]
# Exit 0 only if the model check completed and all three conformance suites RAN and passed.
# Exit 1 = a property or a conformance vector failed.  Exit 2 = incomplete (budget hit, vacuous
# property, a suite skipped or missing): never reported as a pass.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
REPORT="${1:-$(mktemp -d)}"; mkdir -p "$REPORT"; REPORT="$(cd "$REPORT" && pwd)"
VEC="$(mktemp -d)"; trap 'rm -rf "$VEC"' EXIT
status=0

echo "== model check (abstraction only: says nothing about the Go code by itself) =="
python3 -B "$HERE/verify/check.py" --model "$HERE/model/culvert_apply.py" --props "$HERE/model/properties.json" \
  --include-proposed --max-states 200000 --max-seconds 60 --json "$REPORT/model_check.json"
mc=$?
# Exit 2 (budget hit / vacuous property / contract file changed under us) always fails the run.
# Exit 1 fails the run only for an owner-APPROVED property. A failing PROPOSED property is a
# report for the owner, not a verdict on the pull request: this tool does not define the contract.
if [ "$mc" -eq 2 ]; then status=2
elif [ "$mc" -eq 1 ]; then
  if python3 -B - "$REPORT/model_check.json" <<'PY'
import json, sys
bad = [x for x in json.load(open(sys.argv[1]))["results"] if x["verdict"] == "FAIL" and x.get("status") == "approved"]
sys.exit(1 if bad else 0)
PY
  then echo "NOTE: only PROPOSED (not owner-approved) properties fail; reported, not counted as a failure"
  else status=1; fi
elif [ "$mc" -ne 0 ]; then status=2; fi

echo "== conformance: model-derived sequences against the real maintenance-agent code =="
python3 -B "$HERE/gen_vectors.py" "$VEC" || exit 2
cd "$ROOT/cmd/culvert-maint" || exit 2
CULVERT_CONFORMANCE_VECTORS="$VEC" CULVERT_CONFORMANCE_REPORT="$REPORT" \
  timeout 300 go test -tags lifecycle_conformance ./internal/server/ -run 'TestModelConformance' -count=1 -timeout 240s -v \
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
echo "model check exit=$mc  overall exit=$status  reports: $REPORT"
exit "$status"
