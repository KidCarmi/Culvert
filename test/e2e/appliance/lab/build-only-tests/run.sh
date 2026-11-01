#!/usr/bin/env bash
# run.sh — offline tests for the build-only route (no network, no build, no VM).
#   test/e2e/appliance/lab/build-only-tests/run.sh [BASE_REV]
# Needs python3 + PyYAML, gpg/gpgv, and the frozen source commit 0981ff3d in
# this clone (git fetch origin review/1528-m1-engine-pins). BASE_REV (optional)
# compares non-build-only routing with an earlier lab commit.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; lab="$(cd "$here/.." && pwd)"; top="$(git -C "$here" rev-parse --show-toplevel)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
git -C "$top" show 0981ff3d037dedcf08cf7686474c65ba6b3784bf:appliance/build/manifest.env > "$work/manifest.env" \
  || { echo "frozen source 0981ff3d is not in this clone: git fetch origin review/1528-m1-engine-pins" >&2; exit 2; }
# gpg-agent sockets: a deep $TMPDIR exceeds the 108-byte socket limit; gpg uses /run/user/<uid> when it exists.
[ -d "/run/user/$(id -u)" ] || { mkdir -p /run/user && mkdir -m 700 "/run/user/$(id -u)"; } 2>/dev/null || true
rc=0
echo "== routing (every workflow a push to test/appliance-lab fires)"
base=()
if [ -n "${1:-}" ]; then mkdir -p "$work/base"; for f in $(git -C "$top" ls-tree --name-only "$1" .github/workflows/); do git -C "$top" show "$1:$f" > "$work/base/$(basename "$f")"; done; base=("$work/base"); fi
python3 -I -B "$here/route_matrix.py" "$top/.github/workflows" "$(git -C "$top" log -1 --format=%B)" "${base[@]}" || rc=1
echo "== route guard";       python3 -I -B "$here/guard_test.py" "$lab/build-only-route-guard.py" || rc=1
echo "== base signature";    bash "$here/signature_test.sh" "$lab/base-signature-check.sh" "$work" || rc=1
echo "== identity";          python3 -I -B "$here/identity_test.py" "$work" "$lab/build-only-identity.py" "$work/manifest.env" || rc=1
echo "== overall: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"; exit $rc
