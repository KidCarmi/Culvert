#!/usr/bin/env bash
# Regenerate the reviewed lifecycle baselines after an INTENDED change to the model or to
# the maintenance agent's modelled behaviour:
#   cmd/culvert-maint/internal/lifecyclemodel/baseline.json  (model: verdicts, traces, vectors)
#   cmd/culvert-maint/internal/lifecyclemodel/observed.json  (real code: what the model does not predict)
#
# REGENERATING IS NOT PROOF OF CORRECTNESS. It records whatever the code and the model now
# do. Before regenerating, this script captures every difference from the reviewed baseline
# and prints it at the end as a block for the pull request description. A reviewer must
# accept each line explicitly. A property verdict that moved is the most important line:
#   PASS -> FAIL  a regression candidate (the lifecycle no longer holds what it held)
#   FAIL -> PASS  verify the improvement is real: removing a safety capture once turned C2
#                 from FAIL to PASS, so a run can look better while protecting less
# CI never runs this script; the shadow workflow fails if a run modified either file.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MODEL="$ROOT/cmd/culvert-maint/internal/lifecyclemodel"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$ROOT/cmd/culvert-maint"

# 1. What changed relative to the reviewed baseline (the binary embeds the OLD files).
before_rc=0
"$HERE/run.sh" "$TMP/before" > "$TMP/before.log" 2>&1 || before_rc=$?
grep -E '^DRIFT   |DRIFT \(real code\)|newly differing|no longer differing|MISMATCH' "$TMP/before.log" > "$TMP/drift.txt" || true

# 2. Record the new baselines.
go build -tags lifecycle_conformance -o "$TMP/lifecyclecheck" ./internal/lifecyclemodel/cmd/lifecyclecheck
"$TMP/lifecyclecheck" -include-proposed -fail-only-approved -max-states 200000 -max-seconds 60 \
  -write-baseline "$MODEL/baseline.json"
CULVERT_CONFORMANCE_WRITE_OBSERVED="$MODEL/observed.json" \
  go test -tags lifecycle_conformance ./internal/server/ -run 'TestModelConformance_ApplyFlow$' -count=1 -timeout 240s

# 3. The embedded files changed: rebuild and confirm a clean run against them. (run.sh
#    unsets CULVERT_CONFORMANCE_WRITE_OBSERVED itself.)
"$HERE/run.sh" "$TMP/after"
git -C "$ROOT" --no-pager diff --stat -- "$MODEL/baseline.json" "$MODEL/observed.json"

# 4. The review block.
echo
echo "================ BEHAVIOUR CHANGES TO REVIEW (paste into the pull request) ================"
if grep -q MISMATCH "$TMP/drift.txt"; then
  echo "NOTE: the old baseline also saw conformance MISMATCHES, i.e. model and code disagreed."
  echo "      Make sure model.go was changed on purpose, not to silence them."
fi
if [ "$before_rc" -eq 2 ] || { [ "$before_rc" -ne 0 ] && [ ! -s "$TMP/drift.txt" ]; }; then
  # Never "nothing to review" when the comparison itself did not complete: an old baseline the
  # new code cannot read (e.g. a changed file layout) hides every drift line.
  echo "COMPARISON AGAINST THE OLD BASELINE DID NOT COMPLETE (run.sh exit $before_rc); the drift below is"
  echo "partial or empty. Review the full diff of baseline.json and observed.json by hand:"
  grep -E 'INCOMPLETE|FAILED' "$TMP/before.log" | head -5 | sed 's/^/  > /'
  git -C "$ROOT" --no-pager diff --stat -- "$MODEL/baseline.json" "$MODEL/observed.json" | sed 's/^/  /'
fi
if [ ! -s "$TMP/drift.txt" ] && [ "$before_rc" -eq 0 ]; then
  echo "(no drift from the reviewed baseline: nothing to review)"
elif [ -s "$TMP/drift.txt" ]; then
  sed -E -e 's/^DRIFT   //' \
    -e 's/^(property [A-Z][0-9]+ verdict PASS -> FAIL.*)$/[REGRESSION CANDIDATE] \1/' \
    -e 's/^(property [A-Z][0-9]+ verdict FAIL -> PASS.*)$/[VERIFY THE IMPROVEMENT IS REAL] \1/' "$TMP/drift.txt"
  echo
  echo "Reviewer: accept each line explicitly. A regenerated baseline records behaviour; it does"
  echo "not show the behaviour is correct. Security-relevant properties (rollback preservation S2,"
  echo "write-ahead barrier S7, journal retirement S4, reconcile C1/C2, recovery B1/B2) need owner sign-off."
fi
echo "==========================================================================================="
