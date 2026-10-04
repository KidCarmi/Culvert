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

# archive_platform_closure <image.tar.gz> <os/arch> <pinned-digest> [pinned-platform-manifest]
#   succeeds only when the `docker save` archive carries the PINNED image and
#   every blob its selected platform needs: index.json must list
#   <pinned-digest> (an image index or a single manifest); from THAT descriptor
#   only, the <os/arch> manifest (equal to [pinned-platform-manifest] when
#   given), its config and each layer must be present with the size and
#   sha256 their descriptors declare. A complete but different image does not
#   satisfy it: the walk starts at the pin, and a pin covers everything below
#   it by digest. An archive can name an image without carrying it: the
#   runner-built OVAs baked a 69,562-byte ClamAV archive whose amd64 manifest
#   referenced a config and seven layers that were not in it; `docker load`
#   reported success and first boot then failed to create the container
#   (LOCAL-ESXI F-OVA-CLAMAV-1, PR #1528).
archive_platform_closure() {
  local tar="$1" want="${2:-}" pin="${3:-}" plat="${4:-}"
  [[ -f "$tar" ]] || { echo "archive_platform_closure: no archive $tar" >&2; return 2; }
  [[ "$want" == */* ]] || { echo "archive_platform_closure: platform must be os/arch" >&2; return 2; }
  [[ "$pin" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "archive_platform_closure: bad pinned digest '$pin'" >&2; return 2; }
  [[ -z "$plat" || "$plat" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "archive_platform_closure: bad platform manifest digest '$plat'" >&2; return 2; }
  python3 - "$tar" "$want" "$pin" "$plat" <<'PY'
import hashlib, json, sys, tarfile
path, want, pin, plat = sys.argv[1:5]
want_os, want_arch = want.split("/", 1)
INDEX = {"application/vnd.oci.image.index.v1+json",
         "application/vnd.docker.distribution.manifest.list.v2+json"}
with tarfile.open(path, "r:gz") as tf:
    # Member names may carry a leading "./" (tar run from inside the layout).
    members = {m.name[2:] if m.name.startswith("./") else m.name: m for m in tf.getmembers() if m.isfile()}
    def blob(desc, what):
        d = desc.get("digest", "")
        if not d.startswith("sha256:") or len(d) != 71:
            sys.exit("%s has an unusable digest %r" % (what, d))
        m = members.get("blobs/sha256/" + d[7:])
        if m is None:
            sys.exit("archive lacks %s %s" % (what, d))
        if "size" in desc and m.size != desc["size"]:
            sys.exit("%s %s is %d bytes, descriptor says %d" % (what, d, m.size, desc["size"]))
        data = tf.extractfile(m).read()
        if hashlib.sha256(data).hexdigest() != d[7:]:
            sys.exit("%s %s does not hash to its digest" % (what, d))
        return data
    try:
        top = json.loads(tf.extractfile(members["index.json"]).read())
    except Exception:
        sys.exit("archive has no readable OCI index.json")
    root = [d for d in top.get("manifests", []) if d.get("digest") == pin]
    if not root:
        sys.exit("index.json does not list the pinned %s (lists %s)" % (pin, [d.get("digest") for d in top.get("manifests", [])]))
    found = []
    def walk(descs, depth):
        if depth > 3:
            sys.exit("index nesting too deep")
        for desc in descs:
            p = desc.get("platform") or {}
            if p and (p.get("os"), p.get("architecture")) != (want_os, want_arch):
                continue  # another platform or an attestation: not needed
            doc = json.loads(blob(desc, "manifest"))
            if desc.get("mediaType", "") in INDEX or "manifests" in doc:
                walk(doc.get("manifests", []), depth + 1)
                continue
            if "config" not in doc:
                continue
            cfg = json.loads(blob(doc["config"], "config"))
            if (cfg.get("os"), cfg.get("architecture")) != (want_os, want_arch):
                continue
            for i, layer in enumerate(doc.get("layers", [])):
                blob(layer, "layer %d" % i)
            found.append(desc["digest"])
    walk(root[:1], 0)
    if not found:
        sys.exit("pinned %s carries no complete %s image" % (pin, want))
    if plat and plat != pin and plat not in found:  # plat == pin: the pin IS the manifest
        sys.exit("pinned %s resolves %s to %s, not the pinned %s" % (pin, want, found, plat))
    print("closure ok: %s %s -> %s" % (pin, want, " ".join(found)))
PY
}
