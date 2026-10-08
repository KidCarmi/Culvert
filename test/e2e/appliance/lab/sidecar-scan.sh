#!/usr/bin/env bash
# sidecar-scan.sh — ONE scan pipeline for every ClamAV sidecar archive the lab
# qualifies (ASTRA, #1528): the archive baked into a candidate OVA, and the
# image an appliance ADOPTED by building it on the host during a component
# refresh. Both are scanned by these exact steps, so a result for one is never
# transferred to the other — each is bound to its own bytes.
#
#   bind  ARCHIVE.tar EXPECT_ID ID_KIND OUT.json
#       Bind archive → top entry → (index → linux/amd64) manifest → config,
#       re-hashing every blob against its name. ID_KIND says what EXPECT_ID
#       names: "top" (the archive's single index.json entry — the OCI index
#       the OVA build recorded) or "either" (top entry OR config: a guest's
#       `docker inspect .Image` is the top digest under the containerd image
#       store and the config digest under the classic store; which one matched
#       is recorded). Prints the bound config digest.
#   reach ARCHIVE.tar BINDING.json ROOTFS_DIR EVIDENCE_DIR
#       Unpack the bound amd64 layers and record reachability of the MEDIUM
#       findings (zlib gz write path importers, nghttpx presence).
#   trivy ARCHIVE.tar EXPECT_CONFIG EVIDENCE_DIR
#       Full all-severity record + CycloneDX SBOM + the Deep gate's sidecar
#       policy (no fixable HIGH/CRITICAL), with Trivy's ImageID required to
#       equal the bound config. Exits with the policy gate's code.
set -euo pipefail

cmd_bind() {
  local tar="$1" expect="$2" kind="$3" out="$4"
  python3 -I - "$tar" "$expect" "$kind" "$out" <<'PY'
import hashlib, json, sys, tarfile
tar, expect, kind, out = sys.argv[1:5]
assert kind in ("top", "either"), f"bad ID_KIND {kind}"
t = tarfile.open(tar)
def blob(d):
    b = t.extractfile("blobs/sha256/" + d.split(":")[1]).read()
    assert "sha256:" + hashlib.sha256(b).hexdigest() == d, f"blob {d} does not hash to its name"
    return b
INDEX = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
top = json.load(t.extractfile("index.json"))
assert len(top["manifests"]) == 1, f"index.json has {len(top['manifests'])} entries, expected exactly one image"
entry = top["manifests"][0]
doc = json.loads(blob(entry["digest"]))
mt = doc.get("mediaType") or entry.get("mediaType", "")
if mt in INDEX or "manifests" in doc:
    amd = [m for m in doc["manifests"] if m.get("platform", {}).get("os") == "linux" and m["platform"].get("architecture") == "amd64"]
    assert len(amd) == 1, f"{len(amd)} linux/amd64 manifests"
    man_digest, others = amd[0]["digest"], len(doc["manifests"]) - 1
    man = json.loads(blob(man_digest))
else:
    man_digest, others, man = entry["digest"], 0, doc
config = man["config"]["digest"]
cfg = json.loads(blob(config))
assert cfg.get("os") == "linux" and cfg.get("architecture") == "amd64", f"config is {cfg.get('os')}/{cfg.get('architecture')}"
for l in man["layers"]:
    blob(l["digest"])
names = set(t.getnames())
if "manifest.json" in names:  # docker save archive: cross-check its legacy manifest
    legacy = json.load(t.extractfile("manifest.json"))
    assert len(legacy) == 1 and legacy[0]["Config"].endswith(config.split(":")[1]), "manifest.json names another config"
    repo_tags, layout = legacy[0].get("RepoTags"), "docker-save"
else:  # a pure OCI layout (the reproducible sidecar build exports one)
    assert "oci-layout" in names, "archive has neither manifest.json nor an oci-layout marker"
    assert json.load(t.extractfile("oci-layout")).get("imageLayoutVersion") == "1.0.0", "unexpected oci-layout version"
    ann = entry.get("annotations", {})
    repo_tags, layout = [ann["io.containerd.image.name"]] if "io.containerd.image.name" in ann else [], "oci"
matched = "top" if expect == entry["digest"] else ("config" if expect == config else "")
assert matched == "top" or (kind == "either" and matched == "config"), \
    f"expected id {expect} is neither the top entry {entry['digest']} nor (allowed: {kind == 'either'}) the config {config}"
res = {"archive_sha256": hashlib.sha256(open(tar, "rb").read()).hexdigest(),
       "expected_id": expect, "id_matched": matched, "top": entry["digest"], "top_is_index": man_digest != entry["digest"],
       "amd64_manifest": man_digest, "config": config,
       "layers": [l["digest"] for l in man["layers"]], "diff_ids": cfg["rootfs"]["diff_ids"],
       "repo_tags": repo_tags, "archive_layout": layout, "other_platform_entries": others}
json.dump(res, open(out, "w"), indent=2)
print(config)
PY
}

cmd_reach() {
  local tar="$1" binding="$2" root="$3" ev="$4" n=0 hits=0 f s nx
  mkdir -p "$root"
  python3 -I - "$tar" "$binding" "$root" <<'PY'
import io, json, sys, tarfile
t = tarfile.open(sys.argv[1]); b = json.load(open(sys.argv[2])); root = sys.argv[3]
for d in b["layers"]:
    raw = t.extractfile("blobs/sha256/" + d.split(":")[1]).read()
    with tarfile.open(fileobj=io.BytesIO(raw)) as lt:   # gzip/plain auto-detected
        members = [m for m in lt.getmembers() if not m.isdev() and ".wh." not in m.name]
        lt.extractall(root, members=members, filter="tar")
PY
  : > "$ev/reachability.txt"
  while IFS= read -r -d '' f; do
    file -b "$f" | grep -q '^ELF' || continue
    n=$((n+1))
    s="$(readelf --dyn-syms -W "$f" 2>/dev/null | awk '$7=="UND"{print $8}' | sed 's/@.*//' | grep -E '^(gzprintf|gzvprintf|gzwrite|gzputs|gzputc|gzdopen|gzbuffer)$' | sort -u | tr '\n' ' ' || true)"
    if [ -n "$s" ]; then hits=$((hits+1)); echo "IMPORTS ${f#"$root"}: $s" | tee -a "$ev/reachability.txt"; fi
  done < <(find "$root" -type f -print0)
  echo "elf_files_scanned=$n gz_write_importers=$hits" | tee -a "$ev/reachability.txt"
  nx="$(find "$root" \( -name nghttpx -o -name 'nghttp2*' \) | sed "s#^$root##" | sort | tr '\n' ' ')"
  echo "nghttp2 files: ${nx:-none}" | tee -a "$ev/reachability.txt"
  if find "$root" -name nghttpx | grep -q .; then echo "nghttpx_present=yes"; else echo "nghttpx_present=no"; fi | tee -a "$ev/reachability.txt"
  [ "$n" -gt 10 ] || { echo "::error::only $n ELF files found — rootfs extraction failed"; return 1; }
}

cmd_trivy() {
  local tar="$1" config="$2" ev="$3" img gate
  trivy image --download-db-only --db-repository mirror.gcr.io/aquasec/trivy-db:2
  trivy --version > "$ev/trivy-version.txt"
  trivy image --skip-db-update --input "$tar" --scanners vuln --format json --output "$ev/trivy-all.json"
  img="$(jq -r '.Metadata.ImageID' "$ev/trivy-all.json")"
  [ "$img" = "$config" ] || { echo "::error::Trivy scanned ImageID $img, expected $config"; return 1; }
  trivy image --skip-db-update --input "$tar" --format cyclonedx --output "$ev/sbom.cdx.json"
  jq -r '[.Results[]?.Vulnerabilities[]? | {s: .Severity, f: ((.FixedVersion // "") != "")}]
         | group_by(.s) | map({severity: .[0].s, total: length, fixable: map(select(.f)) | length})' \
    "$ev/trivy-all.json" | tee "$ev/severity-summary.json"
  echo "components: $(jq '.components | length' "$ev/sbom.cdx.json")" | tee "$ev/sbom-summary.txt"
  # The Deep gate's sidecar policy, unchanged: no fixable HIGH/CRITICAL.
  set +e
  trivy image --skip-db-update --input "$tar" --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed \
    --format table --exit-code 1 | tee "$ev/trivy-gate.txt"
  gate="${PIPESTATUS[0]}"
  set -e
  echo "gate_exit=$gate" | tee -a "$ev/trivy-gate.txt"
  return "$gate"
}

case "${1:-}" in
  bind)  shift; cmd_bind "$@" ;;
  reach) shift; cmd_reach "$@" ;;
  trivy) shift; cmd_trivy "$@" ;;
  *) echo "usage: $0 bind|reach|trivy ..." >&2; exit 2 ;;
esac
