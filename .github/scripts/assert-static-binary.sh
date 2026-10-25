#!/usr/bin/env bash
# Inspect actual ELF bytes, never execute the inspected binary. A failing ldd
# (including a missing loader/tool) is not evidence of static linkage.
set -euo pipefail
BIN="${1:?usage: assert-static-binary.sh <ELF binary>}"
INFO="$("${GO_BIN:-go}" version -m "$BIN")"
printf '%s\n' "$INFO" | awk -F '\t' '$2 == "build" && $3 == "CGO_ENABLED=0" { found=1 } END { exit !found }' || {
  echo "::error::${BIN}: missing CGO_ENABLED=0 build evidence"; exit 1;
}
HEADERS="$(LC_ALL=C readelf --program-headers --wide "$BIN")"
if printf '%s\n' "$HEADERS" | grep -Eq '^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]'; then
  echo "::error::${BIN}: ELF carries an interpreter or dynamic segment"; exit 1
fi
sha256sum "$BIN"
echo "${BIN}: CGO_ENABLED=0, no ELF interpreter/dynamic segment; applies only to this binary."
