#!/usr/bin/env bash
# Regenerate api/route-classification.yaml SKELETON from the live uiRoutes table.
# NEVER blindly overwrites the reviewed manifest — writes to a .new file for a
# hand-reviewed diff. The route-coverage gate names exactly what changed.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"; cd "$root"
echo "This helper is intentionally manual. The authoritative route source is the"
echo "live uiRoutes table; the coverage gate (TestOpenAPI_Gate3) reports every"
echo "route missing a classification row. Add rows for reported UNCLASSIFIED"
echo "routes to api/route-classification.yaml and remove STALE ones."
