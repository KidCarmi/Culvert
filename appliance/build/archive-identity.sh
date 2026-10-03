#!/usr/bin/env bash
# archive-identity.sh — sourced by build-ova.sh.
#
# archive_names_digest <image.tar.gz> <sha256:…>
#   succeeds only when the `docker save` archive's OCI index.json lists the
#   given digest as a top-level manifest AND carries that blob. First boot
#   verifies the loaded image against the pinned digest; a build host on the
#   classic (non-containerd) image store saves a RE-CREATED manifest instead
#   — the registry digest is gone and RepoDigests is empty after `docker
#   load` (moby/moby#51934) — so the OVA would abort its own first boot. The
#   build checks the archive it ships, not the host it ran on (Codex P1,
#   PR #1528).
archive_names_digest() {
  local tar="$1" want="$2"
  [[ "$want" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "archive_names_digest: bad digest '$want'" >&2; return 2; }
  tar -xzOf "$tar" index.json 2>/dev/null | python3 -c '
import json, sys
want = sys.argv[1]
try:
    idx = json.load(sys.stdin)
except Exception:
    sys.exit("archive has no readable OCI index.json (pre-OCI docker save?)")
got = [m.get("digest") for m in idx.get("manifests", [])]
if want not in got:
    sys.exit("index.json lists %s, not the pinned %s" % (got, want))
' "$want" || return 1
  tar -tzf "$tar" "blobs/sha256/${want#sha256:}" >/dev/null 2>&1 \
    || { echo "archive lacks blob ${want}" >&2; return 1; }
}
