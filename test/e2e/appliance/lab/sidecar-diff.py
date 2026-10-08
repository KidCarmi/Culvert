#!/usr/bin/env python3
"""Diff two baked ClamAV sidecar archives (OCI/docker-archive tars).

Usage: sidecar-diff.py A.tar B.tar OUT_DIR

Answers one question for a reviewer: when two OVA builds of the SAME source
bake sidecars with different image IDs, what actually differs?

  * image config (created, history, env, entrypoint, labels)
  * layer list (diff_ids) — identical layers are reported, not expanded
  * for each differing layer position: every file's content hash, mode,
    owner and size, so CONTENT changes are separated from METADATA-only
    changes (timestamps, apk db install times)
  * the apk package set (name=version from lib/apk/db/installed)

Stdlib only; the archives are data and are never executed.
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile


def blob(t, digest):
    algo, hx = digest.split(":", 1)
    for name in (f"blobs/{algo}/{hx}", f"{hx}/layer.tar", f"{hx}.json"):
        try:
            return t.extractfile(name).read()
        except KeyError:
            continue
    raise KeyError(digest)


def open_layer(raw):
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return tarfile.open(fileobj=io.BytesIO(raw))


def image(path):
    t = tarfile.open(path)
    names = set(t.getnames())
    if "index.json" in names:
        idx = json.loads(t.extractfile("index.json").read())
        desc = idx["manifests"][0]
        top = json.loads(blob(t, desc["digest"]))
        if "manifests" in top:  # an index: pick linux/amd64
            desc = next(m for m in top["manifests"]
                        if m.get("platform", {}).get("architecture") == "amd64")
            man = json.loads(blob(t, desc["digest"]))
        else:
            man = top
        cfg_raw = blob(t, man["config"]["digest"])
        layers = [blob(t, l["digest"]) for l in man["layers"]]
    else:  # legacy docker save
        m = json.loads(t.extractfile("manifest.json").read())[0]
        cfg_raw = t.extractfile(m["Config"]).read()
        layers = [t.extractfile(l).read() for l in m["Layers"]]
    cfg = json.loads(cfg_raw)
    return t, cfg, "sha256:" + hashlib.sha256(cfg_raw).hexdigest(), layers


def listing(raw):
    out = {}
    with open_layer(raw) as lt:
        for m in lt.getmembers():
            h = ""
            if m.isfile():
                h = hashlib.sha256(lt.extractfile(m).read()).hexdigest()[:16]
            out[m.name] = {"type": m.type.decode() if isinstance(m.type, bytes) else str(m.type),
                           "mode": oct(m.mode), "uid": m.uid, "gid": m.gid,
                           "size": m.size, "sha": h, "link": m.linkname, "mtime": m.mtime}
    return out


def apk_db(raws):
    pkgs = {}
    for raw in raws:
        with open_layer(raw) as lt:
            try:
                data = lt.extractfile("lib/apk/db/installed").read().decode()
            except (KeyError, AttributeError):
                continue
        cur = {}
        pkgs = {}  # the top-most layer that carries the db wins
        for line in data.splitlines() + [""]:
            if not line:
                if "P" in cur:
                    pkgs[cur["P"]] = cur.get("V", "?")
                cur = {}
            elif line[1:2] == ":":
                cur[line[0]] = line[2:]
    return pkgs


def main():
    a_path, b_path, out = sys.argv[1:4]
    os.makedirs(out, exist_ok=True)
    _, ca, ida, la = image(a_path)
    _, cb, idb, lb = image(b_path)
    rep = [f"A config {ida}", f"B config {idb}"]
    da, db = ca["rootfs"]["diff_ids"], cb["rootfs"]["diff_ids"]
    rep.append(f"layers: A={len(da)} B={len(db)}")
    content_changed = 0
    for i in range(max(len(da), len(db))):
        x = da[i] if i < len(da) else None
        y = db[i] if i < len(db) else None
        if x == y:
            rep.append(f"  layer {i}: identical {x}")
            continue
        rep.append(f"  layer {i}: DIFFERS A={x} B={y}")
        if i >= len(la) or i >= len(lb):
            continue
        fa, fb = listing(la[i]), listing(lb[i])
        for name in sorted(set(fa) | set(fb)):
            p, q = fa.get(name), fb.get(name)
            if p is None or q is None:
                rep.append(f"    {'ONLY-B' if p is None else 'ONLY-A'} {name}")
                content_changed += 1
                continue
            keys = [k for k in p if p[k] != q[k]]
            if not keys:
                continue
            kind = "CONTENT" if set(keys) - {"mtime"} else "mtime-only"
            if kind == "CONTENT":
                content_changed += 1
            rep.append(f"    {kind:10} {name} " + " ".join(f"{k}:{p[k]}->{q[k]}" for k in keys))
    hist_a = [h.get("created_by", "") for h in ca.get("history", [])]
    hist_b = [h.get("created_by", "") for h in cb.get("history", [])]
    rep.append("history (created_by) identical" if hist_a == hist_b else "history DIFFERS")
    for k in ("Env", "Entrypoint", "Cmd", "Labels", "User", "WorkingDir"):
        if ca.get("config", {}).get(k) != cb.get("config", {}).get(k):
            rep.append(f"config.{k} DIFFERS: {ca['config'].get(k)} -> {cb['config'].get(k)}")
    rep.append(f"created: A={ca.get('created')} B={cb.get('created')}")
    pa, pb = apk_db(la), apk_db(lb)
    pkg_diff = sorted(f"{n}: {pa.get(n)} -> {pb.get(n)}" for n in set(pa) | set(pb) if pa.get(n) != pb.get(n))
    rep.append(f"apk packages: A={len(pa)} B={len(pb)}; differing={len(pkg_diff)}")
    rep += ["  " + d for d in pkg_diff]
    rep.append(f"VERDICT files_with_content_change={content_changed} packages_changed={len(pkg_diff)}")
    open(os.path.join(out, "sidecar-diff.txt"), "w").write("\n".join(rep) + "\n")
    json.dump({"a": pa, "b": pb}, open(os.path.join(out, "apk-packages.json"), "w"), indent=1, sort_keys=True)
    print("\n".join(rep[:60]))
    print(rep[-1])


if __name__ == "__main__":
    main()
