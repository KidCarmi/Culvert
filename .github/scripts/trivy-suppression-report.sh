#!/usr/bin/env bash
# Same artifact/DB as the blocking scan; findings advisory, scan errors fatal.
set -euo pipefail
REF="${1:?image reference required}"
PLATFORM="${2:?platform required}"
OUT="${3:?output directory required}"
SOURCE="${4:-docker}"
mkdir -p "$OUT"
NAME="${PLATFORM//\//-}"
trivy image --image-src "$SOURCE" --platform "$PLATFORM" --scanners vuln \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --show-suppressed \
  --list-all-pkgs --exit-code 0 --format json --output "$OUT/$NAME.json" "$REF"
trivy convert --show-suppressed --format table "$OUT/$NAME.json" > "$OUT/$NAME.txt"
cat "$OUT/$NAME.txt"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Trivy advisory: $PLATFORM · $REF"
    echo 'All severities, unfixed and suppressed findings; JSON artifact includes installed packages.'
    echo '```'
    cat "$OUT/$NAME.txt"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi
