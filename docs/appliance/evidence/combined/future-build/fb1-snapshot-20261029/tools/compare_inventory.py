#!/usr/bin/env python3
"""Predict the replacement build's package set under a snapshot and compare it,
row by row, with the retained OVA 325c142a inventory (FB-1 pin selection).

  compare_inventory.py INVENTORY SNAPSHOT_DIR UPGRADE_SIM DOCKER_PINS OUT_TSV

INVENTORY     325c142a exact-byte inventory (package\\tversion\\tarch, 680 rows)
SNAPSHOT_DIR  verified <suite>-<component>.Packages of the candidate snapshot
UPGRADE_SIM   `apt-get -s --with-new-pkgs upgrade` against the 325c status
              under that snapshot (the build's section 1b step)
DOCKER_PINS   name=version lines (manifest.env Docker pins)

Prediction, stated so it can be checked: every Ubuntu package ends at the
snapshot's CANDIDATE (highest version listed for its architecture, Debian
ordering via `dpkg --compare-versions`), because the build runs
`upgrade --with-new-pkgs` against the snapshot; packages the simulation newly
installs are added; kernel packages of an older ABI than the newest image are
purged (prepare-guest.sh "exactly one kernel ships"); Docker packages stay at
their pins. The actual disk (T5) is the authority; this is a prediction.

Classes: unchanged | upgrade | DOWNGRADE | removed-kernel | added |
docker-pinned | NOT-IN-SNAPSHOT. "security" = the 325c version is listed in
noble-security of this snapshot. Exit 1 if any DOWNGRADE, NOT-IN-SNAPSHOT, a
Docker version off its pin, or an unexplained removal.
"""
import glob
import os
import re
import subprocess
import sys
from functools import cmp_to_key


def dpkg_cmp(a, b):
    if a == b:
        return 0
    if subprocess.run(["dpkg", "--compare-versions", a, "lt", b]).returncode == 0:
        return -1
    if subprocess.run(["dpkg", "--compare-versions", a, "gt", b]).returncode == 0:
        return 1
    return 0


def load_snapshot(d):
    idx = {}  # (name, arch) -> {version: set(pockets)}
    for f in sorted(glob.glob(os.path.join(d, "*.Packages"))):
        pocket = os.path.basename(f)[: -len(".Packages")]
        for st in open(f, encoding="utf-8", errors="replace").read().split("\n\n"):
            m = re.search(r"^Package: (.+)$", st, re.M)
            v = re.search(r"^Version: (.+)$", st, re.M)
            a = re.search(r"^Architecture: (.+)$", st, re.M)
            if m and v and a:
                idx.setdefault((m.group(1), a.group(1)), {}).setdefault(v.group(1), set()).add(pocket)
    return idx


def main(inv_path, snap_dir, sim_path, pins_path, out_path):
    inv = [l.rstrip("\n").split("\t") for l in open(inv_path) if l.strip()]
    pins = dict(l.strip().split("=", 1) for l in open(pins_path) if "=" in l)
    idx = load_snapshot(snap_dir)
    sim_inst = {}
    for l in open(sim_path):
        m = re.match(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+) ", l)
        if m:
            sim_inst[m.group(1)] = m.group(3)
    images = [n for n, _, _ in inv if re.match(r"^linux-image-\d", n)] + [n for n in sim_inst if re.match(r"^linux-image-\d", n)]
    abis = sorted({re.match(r"^linux-image-(\d[\d.]*-\d+)-", n).group(1) for n in images},
                  key=cmp_to_key(dpkg_cmp))
    newest = abis[-1]
    rows, bad = [], []
    seen = set()
    for name, ver, arch in inv:
        seen.add(name)
        vers = idx.get((name, arch), {})
        sec = "security" if any("noble-security" in p for p in vers.get(ver, ())) else ""
        if name in pins:
            new = pins[name]
            cls = "docker-pinned" if new == ver else "DOCKER-PIN-MISMATCH"
            rows.append((name, arch, ver, new, cls, sec, "docker (pinned)"))
            if cls != "docker-pinned":
                bad.append(name)
            continue
        kabi = re.match(r"^linux-(?!libc-dev$|base$|tools-common$).*-(\d+\.\d+\.\d+-\d+)(?:-generic)?$", name)
        if kabi and kabi.group(1) != newest:
            rows.append((name, arch, ver, "", "removed-kernel", sec, f"superseded ABI {kabi.group(1)} purged; newest {newest}"))
            continue
        if not vers:
            rows.append((name, arch, ver, "", "NOT-IN-SNAPSHOT", sec, "no stanza for this name/arch"))
            bad.append(name)
            continue
        cand = sorted(vers, key=cmp_to_key(dpkg_cmp))[-1]
        new = sim_inst.get(name, cand)
        c = dpkg_cmp(new, ver)
        cls = "unchanged" if c == 0 else ("upgrade" if c > 0 else "DOWNGRADE")
        if cls == "DOWNGRADE":
            bad.append(name)
        if new not in vers:
            cls, note = "NOT-IN-SNAPSHOT", "predicted version not listed"
            bad.append(name)
        else:
            note = ",".join(sorted(vers[new]))
        rows.append((name, arch, ver, new, cls, sec, note))
    for name, new in sorted(sim_inst.items()):
        if name not in seen:
            arch = "amd64"
            vers = idx.get((name, arch), {})
            rows.append((name, arch, "", new, "added", "", ",".join(sorted(vers.get(new, {"?"})))))
    with open(out_path, "w") as f:
        f.write("package\tarch\tversion_325c\tversion_predicted\tclass\t325c_in_security\tpredicted_origin_or_note\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    counts = {}
    for r in rows:
        counts[r[4]] = counts.get(r[4], 0) + 1
    print("rows=%d " % len(rows) + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print("security rows (325c version in noble-security): %d" % sum(1 for r in rows if r[5]))
    print("newest kernel ABI: " + newest)
    if bad:
        print("CONFLICTS: " + " ".join(sorted(set(bad))))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:6]))
