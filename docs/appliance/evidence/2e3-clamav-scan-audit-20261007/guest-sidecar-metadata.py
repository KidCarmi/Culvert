#!/usr/bin/env python3
"""Read only the retained 2e3 ClamAV archive; print non-secret identity metadata."""
import gzip
import hashlib
import json
import os
import re
import stat
import tarfile

PATH = "/var/lib/culvert-appliance/images/clamav.tar.gz"
ARCHIVE_SHA = "603c165c35141aed67667dffbc09132664feadd74dfcabbfc7e109b4dbecffa6"
INDEX = "sha256:f3fcbf45d0a50da7e1880e498a030e38b1cd31d792a2737a881ebe8391b13ec3"
MANIFEST = "sha256:be3827e2327c5e51c695c7fe934133f0433c8baa9a7b3ea03e2cdb9ea5d1331c"
MAX_COMPRESSED, MAX_EXPANDED = 2 << 30, 4 << 30
MAX_META, MAX_TOTAL_META, MAX_MEMBERS = 256 << 10, 8 << 20, 256

def require(ok, message):
    if not ok:
        raise ValueError(message)

class BoundedReader:
    def __init__(self, source):
        self.source, self.used = source, 0
    def read(self, n=-1):
        require(n >= 0, "unbounded decompressed read refused")
        require(self.used + n <= MAX_EXPANDED, "expanded archive bound exceeded")
        data = self.source.read(n)
        self.used += len(data)
        return data


def inspect():
    fd = os.open(PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode), "archive is not regular")
        require(before.st_uid == 0, "archive is not root-owned")
        require(not before.st_mode & 0o022, "archive is group/world writable")
        require(0 < before.st_size <= MAX_COMPRESSED, "compressed archive size refused")
        digest = hashlib.sha256()
        seen_bytes = 0
        while True:
            chunk = source.read(4 << 20)
            if not chunk:
                break
            seen_bytes += len(chunk)
            require(seen_bytes <= MAX_COMPRESSED, "compressed archive grew past bound")
            digest.update(chunk)
        require(digest.hexdigest() == ARCHIVE_SHA, "archive SHA256 mismatch")
        source.seek(0)
        blobs, sizes, total, count = {}, {}, 0, 0
        with gzip.GzipFile(fileobj=source) as decoded:
            bounded = BoundedReader(decoded)
            with tarfile.open(fileobj=bounded, mode="r|") as archive:
                for member in archive:
                    count += 1
                    require(count <= MAX_MEMBERS, "too many archive members")
                    name = member.name.removeprefix("./").rstrip("/")
                    require(len(name) <= 256 and not name.startswith("/") and ".." not in name.split("/"), "unsafe member name")
                    if member.isdir():
                        require(name in (".", "blobs", "blobs/sha256"), "unexpected directory")
                        continue
                    require(member.isfile(), "non-regular archive member refused")
                    require(name not in sizes, "duplicate archive member")
                    require(name in ("index.json", "manifest.json", "oci-layout", "repositories") or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name), "unexpected archive member")
                    require(0 <= member.size <= MAX_EXPANDED, "member size refused")
                    sizes[name] = member.size
                    if member.size <= MAX_META:
                        total += member.size
                        require(total <= MAX_TOTAL_META, "metadata memory bound exceeded")
                        data = archive.extractfile(member).read(MAX_META + 1)
                        require(len(data) == member.size, "short metadata member")
                        blobs[name] = data
        after = os.fstat(source.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "archive changed during read")
    def blob(desc):
        d = desc.get("digest", "")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", d), "bad metadata digest")
        name = "blobs/sha256/" + d[7:]
        require(name in blobs, "metadata blob missing or exceeds bound")
        data = blobs[name]
        require(len(data) == desc.get("size"), "metadata descriptor size mismatch")
        require(hashlib.sha256(data).hexdigest() == d[7:], "metadata digest mismatch")
        return json.loads(data)
    top = json.loads(blobs["index.json"])
    roots = [d for d in top.get("manifests", []) if d.get("digest") == INDEX]
    require(len(roots) == 1, "expected index not unique")
    idx = blob(roots[0])
    selected = [d for d in idx.get("manifests", []) if d.get("platform", {}).get("os") == "linux" and d.get("platform", {}).get("architecture") == "amd64"]
    require(len(selected) == 1 and selected[0].get("digest") == MANIFEST, "unexpected amd64 manifest")
    manifest = blob(selected[0])
    cfg = blob(manifest["config"])
    require(cfg.get("os") == "linux" and cfg.get("architecture") == "amd64", "wrong config platform")
    layers = manifest.get("layers", [])
    diff_ids = cfg.get("rootfs", {}).get("diff_ids", [])
    require(0 < len(layers) == len(diff_ids) <= 64, "unexpected layer count")
    for layer, diff in zip(layers, diff_ids):
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", layer.get("digest", "")) and re.fullmatch(r"sha256:[0-9a-f]{64}", diff), "bad layer digest")
        require(sizes.get("blobs/sha256/" + layer["digest"][7:]) == layer.get("size"), "layer missing or size differs")
    print(json.dumps({"schema": 1, "archive_path": PATH, "archive_sha256": ARCHIVE_SHA, "archive_bytes": before.st_size, "index_digest": INDEX, "manifest_digest": MANIFEST, "config_digest": manifest["config"]["digest"], "config_raw_sha256": manifest["config"]["digest"][7:], "os": cfg["os"], "architecture": cfg["architecture"], "rootfs_diff_ids": diff_ids, "layer_descriptors": layers, "member_count": count, "expanded_bytes_read": bounded.used, "scope": "metadata hashes and member presence/size verified; compressed archive hash verified; individual layer payloads not rehashed; no extraction, Docker, network or mutation"}, sort_keys=True))

if __name__ == "__main__":
    try:
        inspect()
    except Exception as error:
        print(json.dumps({"ok": False, "error_type": type(error).__name__, "detail": str(error)}))
        raise SystemExit(1)
