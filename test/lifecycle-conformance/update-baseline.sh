#!/usr/bin/env bash
# Regenerate the reviewed lifecycle baselines after an INTENDED change to the model or to
# the maintenance agent's modelled behaviour:
#   cmd/culvert-maint/internal/lifecyclemodel/baseline.json  (model: verdicts, traces, vectors)
#   cmd/culvert-maint/internal/lifecyclemodel/observed.json  (real code: what the model does not predict)
# Commit both in the same pull request as the change and review their diff line by line:
# every changed line is a behaviour change. CI never runs this script; the shadow workflow
# fails if a run modified either file.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
MODEL="$ROOT/cmd/culvert-maint/internal/lifecyclemodel"
BIN="$(mktemp -d)"; trap 'rm -rf "$BIN"' EXIT
cd "$ROOT/cmd/culvert-maint"
go build -tags lifecycle_conformance -o "$BIN/lifecyclecheck" ./internal/lifecyclemodel/cmd/lifecyclecheck
"$BIN/lifecyclecheck" -include-proposed -fail-only-approved -max-states 200000 -max-seconds 60 \
  -write-baseline "$MODEL/baseline.json"
CULVERT_CONFORMANCE_WRITE_OBSERVED="$MODEL/observed.json" \
  go test -tags lifecycle_conformance ./internal/server/ -run 'TestModelConformance_ApplyFlow$' -count=1 -timeout 240s
# The embedded files changed: rebuild and confirm a clean run against them.
"$HERE/run.sh"
git -C "$ROOT" --no-pager diff --stat -- "$MODEL/baseline.json" "$MODEL/observed.json"
