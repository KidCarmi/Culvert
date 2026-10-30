#!/usr/bin/env python3
"""Reconcile an appliance guest's installed packages against pinned indexes (FB-1).

build-ova.sh runs this after prepare-guest.sh, against the guest's
dpkg-list.txt. Every installed (package, version, architecture) must be
accounted for, or the build fails:

  * an Ubuntu package must be in the Packages index of the PINNED archive
    snapshot. The chain is: manifest pin -> InRelease bytes (SHA-256) ->
    Packages bytes (the SHA-256 that InRelease lists) -> the package stanza;
  * one of the Docker packages must be at its manifest pin, and present in
    Docker's index (Docker InRelease, whose signature build-ova.sh verified
    against the fingerprint-checked key -> Packages SHA-256 listed there).

Anything else fails: a version only the live archive carries (the 57 of OVA
325c142a), an unknown or local origin, a Docker package off its pin, a
missing index, an index whose bytes do not match its InRelease, an InRelease
that does not match its pin. All failures are reported, not just the first.

The output (package-provenance.tsv) records, per package, the origin, the
pockets that list it, the pool path and the SHA-256 of the .deb as the
verified index states it. Offline: it never touches the network.

Layout of --snapshot-dir: <suite>.InRelease and <suite>-<component>.Packages
(uncompressed). Layout of --docker-dir: InRelease and Packages.
"""

import argparse
import hashlib
import os
import re
import sys

SUITES = ("noble", "noble-updates", "noble-security", "noble-backports")
COMPONENTS = ("main", "restricted", "universe", "multiverse")
ARCH = "amd64"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Failure(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def inrelease_sha256(path):
    """Map of index path -> SHA-256 from the SHA256: section of an InRelease."""
    out = {}
    section = False
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("SHA256:"):
                section = True
                continue
            if section:
                if not line.startswith(" "):
                    section = False
                    continue
                parts = line.split()
                if len(parts) == 3 and HEX64.match(parts[0]):
                    out[parts[2]] = parts[0]
    return out


def parse_packages(path):
    """Yield (package, version, arch, filename, sha256) for each stanza."""
    def emit(st):
        return (st.get("Package"), st.get("Version"), st.get("Architecture"),
                st.get("Filename"), st.get("SHA256"))

    stanza = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                if stanza:
                    yield emit(stanza)
                stanza = {}
                continue
            if line[0] in " \t":
                continue
            key, _, value = line.partition(":")
            stanza[key] = value.strip()
    if stanza:
        yield emit(stanza)


def verified_index(packages, inrelease_map, entry, label, problems):
    """The Packages file, if it exists and its bytes are the ones InRelease lists."""
    want = inrelease_map.get(entry)
    if want is None:
        problems.append(f"index\t{label}\tInRelease lists no {entry}")
        return None
    if not os.path.isfile(packages):
        problems.append(f"index\t{label}\tmissing {os.path.basename(packages)}")
        return None
    got = sha256_file(packages)
    if got != want:
        problems.append(f"index\t{label}\t{os.path.basename(packages)} is {got}, InRelease lists {want}")
        return None
    return packages


def load_snapshot(snapshot_dir, pins, problems):
    """(package, version, arch) -> {"pockets": [...], "filename", "sha256"}."""
    found = {}
    for suite in SUITES:
        inrel = os.path.join(snapshot_dir, f"{suite}.InRelease")
        if not os.path.isfile(inrel) or os.path.getsize(inrel) == 0:
            problems.append(f"index\t{suite}\tmissing or empty InRelease")
            continue
        got = sha256_file(inrel)
        if got != pins[suite]:
            problems.append(f"index\t{suite}\tInRelease is {got}, manifest pins {pins[suite]}")
            continue
        listed = inrelease_sha256(inrel)
        for comp in COMPONENTS:
            path = verified_index(os.path.join(snapshot_dir, f"{suite}-{comp}.Packages"), listed,
                                  f"{comp}/binary-{ARCH}/Packages", f"{suite}/{comp}", problems)
            if path is None:
                continue
            for pkg, ver, arch, filename, sha in parse_packages(path):
                if not (pkg and ver and arch and filename and sha):
                    problems.append(f"index\t{suite}/{comp}\tincomplete stanza for {pkg or '?'}")
                    continue
                # The .deb's identity is its SHA-256. The archive may list the
                # same file under two pool paths (a component move: e.g.
                # ocl-icd 2.3.2-1build1 is pool/universe in noble and
                # pool/main in noble-updates, same SHA-256), so paths are
                # collected; two DIFFERENT hashes for one (package, version,
                # arch) are a conflict, reported if that package is installed.
                rec = found.setdefault((pkg, ver, arch), {"pockets": [], "filenames": [], "sha256": sha})
                if rec["sha256"] != sha:
                    rec["conflict"] = True
                pocket = f"{suite}/{comp}"
                if pocket not in rec["pockets"]:
                    rec["pockets"].append(pocket)
                if filename not in rec["filenames"]:
                    rec["filenames"].append(filename)
    return found


def load_docker(docker_dir, problems):
    inrel = os.path.join(docker_dir, "InRelease")
    if not os.path.isfile(inrel) or os.path.getsize(inrel) == 0:
        problems.append("index\tdocker\tmissing or empty InRelease")
        return {}, None
    path = verified_index(os.path.join(docker_dir, "Packages"), inrelease_sha256(inrel),
                          f"stable/binary-{ARCH}/Packages", "docker/stable", problems)
    found = {}
    if path is not None:
        for pkg, ver, arch, filename, sha in parse_packages(path):
            if pkg and ver and arch and filename and sha:
                found[(pkg, ver, arch)] = {"filename": filename, "sha256": sha}
    return found, sha256_file(inrel)


def read_inventory(path, problems):
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 3 or not all(parts):
                problems.append(f"inventory\tline {n}\tnot <package>TAB<version>TAB<arch>")
                continue
            name, ver, arch = parts
            rows.append((name.split(":", 1)[0], ver, arch))
    if not rows:
        problems.append("inventory\t-\tno installed packages")
    return rows


def parse_pairs(values, what, problems, check=None):
    out = {}
    for v in values or []:
        key, sep, val = v.partition("=")
        if not sep or not key or not val:
            problems.append(f"argument\t{what}\t{v!r} is not KEY=VALUE")
            continue
        if check and not check(val):
            problems.append(f"argument\t{what}\t{key} has an invalid value")
            continue
        out[key] = val
    return out


def reconcile(args):
    problems = []
    pins = parse_pairs(args.pin, "--pin", problems, HEX64.match)
    for suite in SUITES:
        if suite not in pins:
            problems.append(f"argument\t--pin\tno pin for {suite}")
    docker_pins = parse_pairs(args.docker_pin, "--docker-pin", problems)
    if not docker_pins:
        problems.append("argument\t--docker-pin\tno Docker package pins")
    if not re.match(r"^[0-9]{8}T[0-9]{6}Z$", args.snapshot_id or ""):
        problems.append("argument\t--snapshot-id\tnot a snapshot ID")
    if problems:
        return problems, []

    snapshot = load_snapshot(args.snapshot_dir, pins, problems)
    docker, docker_inrelease = load_docker(args.docker_dir, problems)
    inventory = read_inventory(args.dpkg_list, problems)
    if problems:
        # A broken index would turn every package into a false "not found";
        # report the index problems alone.
        return problems, []

    snap_uri = f"https://snapshot.ubuntu.com/ubuntu/{args.snapshot_id}"
    installed = {}
    rows = []
    for name, ver, arch in inventory:
        installed[name] = ver
        if name in docker_pins:
            if ver != docker_pins[name]:
                problems.append(f"package\t{name}\t{ver} {arch} is not the manifest pin {docker_pins[name]}")
                continue
            rec = docker.get((name, ver, arch))
            if rec is None:
                problems.append(f"package\t{name}\t{ver} {arch} is not in Docker's verified index")
                continue
            rows.append((name, ver, arch, "docker", args.docker_uri, "stable", rec["filename"], rec["sha256"]))
            continue
        rec = snapshot.get((name, ver, arch))
        if rec is None:
            problems.append(f"package\t{name}\t{ver} {arch} is not in snapshot {args.snapshot_id}")
            continue
        if rec.get("conflict"):
            problems.append(f"package\t{name}\t{ver} {arch} is listed with two different .deb hashes in the snapshot")
            continue
        rows.append((name, ver, arch, "ubuntu-snapshot", snap_uri, ",".join(rec["pockets"]),
                     ",".join(rec["filenames"]), rec["sha256"]))
    for name, ver in sorted(docker_pins.items()):
        if name not in installed:
            problems.append(f"package\t{name}\tpinned {ver} is not installed")
    header = [
        f"# FB-1 package provenance: every installed package of this guest, reconciled offline.",
        f"# ubuntu-snapshot = {snap_uri} ; InRelease SHA-256 " +
        " ".join(f"{s}={pins[s]}" for s in SUITES),
        f"# docker = {args.docker_uri} (InRelease SHA-256 {docker_inrelease}, signature verified by build-ova.sh)",
        "package\tversion\tarch\torigin\turi\tpockets\tpool_path\tsha256",
    ]
    return problems, header + ["\t".join(r) for r in sorted(rows)]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dpkg-list", required=True)
    p.add_argument("--snapshot-dir", required=True)
    p.add_argument("--snapshot-id", required=True)
    p.add_argument("--pin", action="append", help="SUITE=INRELEASE_SHA256 (one per suite)")
    p.add_argument("--docker-dir", required=True)
    p.add_argument("--docker-uri", required=True)
    p.add_argument("--docker-pin", action="append", help="PACKAGE=VERSION (one per pinned Docker package)")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)

    problems, lines = reconcile(args)
    if problems:
        print(f"package provenance: {len(problems)} problem(s); nothing written", file=sys.stderr)
        for line in sorted(problems):
            print(f"  {line}", file=sys.stderr)
        return 1
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, args.out)
    print(f"package provenance: {len(lines) - 4} package(s) reconciled -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
