#!/usr/bin/env python3
"""Reconcile an appliance guest's installed packages against pinned indexes (FB-1).

build-ova.sh runs this after prepare-guest.sh, against the guest's
dpkg-list.txt. Every installed (package, version, architecture) must be
accounted for, or the build fails:

  * an Ubuntu package must be in the Packages index of the PINNED archive
    snapshot. The chain is: manifest pin -> InRelease bytes (SHA-256) ->
    Packages bytes (the SHA-256 that InRelease lists) -> the package stanza;
  * one of the Docker packages must be at its manifest pin, listed in
    Docker's index (Docker InRelease, whose signature build-ova.sh verified
    against the fingerprint-checked key -> Packages SHA-256 listed there)
    with the REVIEWED .deb SHA-256 (--docker-deb-sha256), and acquired by
    this build with exactly those bytes.

Package BYTES are bound independently of the index (--acquired, the guest's
acquisition receipt: each .deb it downloaded, by the file's own control
fields and its SHA-256): every acquired file must equal what the
authenticated index (or the Docker byte pin) names for that
package/version/architecture. An index that is merely self-consistent is not
enough: a Docker index listing another hash for the pinned version fails.

Anything else fails: a version only the live archive carries (the 57 of OVA
325c142a), an unknown or local origin, a Docker package off its pin or its
bytes, an acquired file whose hash differs from its authenticated index
entry, a missing index, an index whose bytes do not match its InRelease, an
InRelease that does not match its pin. All failures are reported.

The output (package-provenance.tsv) records, per package, the origin, the
pockets, the pool path, the .deb SHA-256 the verified index states, and the
binding: acquired-verified (bytes this build downloaded and checked) or
inherited-base-image. A package without a verified acquisition is accepted
ONLY when the exact package/version/architecture is in the base image's
pre-transaction dpkg status (--base-status, read by build-ova.sh on the build
host from the verified base image file before any guest step): an upgraded
or newly installed package with no acquisition receipt fails. Inherited bytes
are bound only by BASE_IMAGE_SHA256, not per package — the explicit limit.
Offline: it never touches the network.

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


def read_base_status(path, problems):
    """The base image's pre-transaction /var/lib/dpkg/status: the set of
    installed (package, version, architecture) and its SHA-256."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        problems.append(f"base-status\t{path}\tunreadable: {e.strerror}")
        return set(), {}, ""
    installed, by_name = set(), {}
    for stanza in raw.decode("utf-8", "replace").split("\n\n"):
        fields = {}
        for line in stanza.split("\n"):
            k, sep, v = line.partition(": ")
            if sep and not line.startswith((" ", "\t")):
                fields[k] = v.strip()
        if not fields.get("Package"):
            continue
        if not fields.get("Status", "").endswith(" installed"):
            continue
        name, ver, arch = fields["Package"], fields.get("Version", ""), fields.get("Architecture", "")
        if not ver or not arch:
            problems.append(f"base-status\t{name}\tinstalled stanza without Version/Architecture")
            continue
        installed.add((name, ver, arch))
        by_name.setdefault((name, arch), set()).add(ver)
    if not installed:
        problems.append("base-status\t-\tno installed packages (not a dpkg status file?)")
    return installed, by_name, hashlib.sha256(raw).hexdigest()


def read_acquired(path, problems):
    """The guest's acquisition receipt: package, version, arch, sha256, file."""
    rows = []
    if not path or not os.path.isfile(path):
        problems.append("acquired\t-\tno acquisition receipt")
        return rows
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 5 or not all(parts) or not HEX64.match(parts[3]):
                problems.append(f"acquired\tline {n}\tnot <package>TAB<version>TAB<arch>TAB<sha256>TAB<file>")
                continue
            rows.append(tuple(parts))
    if not rows:
        problems.append("acquired\t-\tthe acquisition receipt is empty")
    return rows


def check_arguments(args, problems):
    pins = parse_pairs(args.pin, "--pin", problems, HEX64.match)
    for suite in SUITES:
        if suite not in pins:
            problems.append(f"argument\t--pin\tno pin for {suite}")
    docker_pins = parse_pairs(args.docker_pin, "--docker-pin", problems)
    if not docker_pins:
        problems.append("argument\t--docker-pin\tno Docker package pins")
    docker_shas = parse_pairs(args.docker_deb_sha256, "--docker-deb-sha256", problems, HEX64.match)
    for name in docker_pins:
        if name not in docker_shas:
            problems.append(f"argument\t--docker-deb-sha256\tno reviewed .deb SHA-256 for {name}")
    for name in docker_shas:
        if name not in docker_pins:
            problems.append(f"argument\t--docker-deb-sha256\t{name} has no version pin")
    if not re.match(r"^[0-9]{8}T[0-9]{6}Z$", args.snapshot_id or ""):
        problems.append("argument\t--snapshot-id\tnot a snapshot ID")
    return pins, docker_pins, docker_shas


def bind_docker_index(docker, docker_pins, docker_shas, problems):
    """The pinned Docker versions must be listed with the REVIEWED bytes. A
    self-consistent index (InRelease -> Packages) that lists another hash for
    the pinned version is refused: a version pin alone does not bind bytes."""
    for name, ver in sorted(docker_pins.items()):
        rec = docker.get((name, ver, ARCH))
        if rec is None:
            problems.append(f"index\tdocker/stable\t{name} {ver} {ARCH} is not in Docker's verified index")
        elif rec["sha256"] != docker_shas[name]:
            problems.append(f"index\tdocker/stable\t{name} {ver} {ARCH} is listed as {rec['sha256']}, "
                            f"the reviewed pin is {docker_shas[name]}")


def bind_acquired(acquired, snapshot, docker_pins, docker_shas, snapshot_id, problems):
    """Every .deb the guest acquired must be the bytes the authenticated
    metadata names for that package/version/architecture. Returns the set of
    (package, version, arch) whose acquired bytes verified."""
    verified, seen = set(), {}
    for pkg, ver, arch, sha, fname in acquired:
        key = (pkg, ver, arch)
        if seen.get(key, sha) != sha:
            problems.append(f"acquired\t{pkg}\t{ver} {arch} was acquired as two different files")
            continue
        seen[key] = sha
        if pkg in docker_pins:
            if ver != docker_pins[pkg] or arch != ARCH:
                problems.append(f"acquired\t{pkg}\t{ver} {arch} is not the manifest pin {docker_pins[pkg]} {ARCH}")
            elif sha != docker_shas[pkg]:
                problems.append(f"acquired\t{pkg}\t{ver} {arch} ({fname}) is {sha}, the reviewed pin is {docker_shas[pkg]}")
            else:
                verified.add(key)
            continue
        rec = snapshot.get(key)
        if rec is None:
            problems.append(f"acquired\t{pkg}\t{ver} {arch} ({fname}) is not in snapshot {snapshot_id}")
        elif rec.get("conflict"):
            problems.append(f"acquired\t{pkg}\t{ver} {arch} is listed with two different .deb hashes in the snapshot")
        elif sha != rec["sha256"]:
            problems.append(f"acquired\t{pkg}\t{ver} {arch} ({fname}) is {sha}, the authenticated snapshot index lists {rec['sha256']}")
        else:
            verified.add(key)
    return verified


def reconcile(args):
    problems = []
    pins, docker_pins, docker_shas = check_arguments(args, problems)
    if problems:
        return problems, [], {}

    snapshot = load_snapshot(args.snapshot_dir, pins, problems)
    docker, docker_inrelease = load_docker(args.docker_dir, problems)
    inventory = read_inventory(args.dpkg_list, problems)
    acquired = read_acquired(args.acquired, problems)
    base, base_by_name, base_sha = read_base_status(args.base_status, problems)
    if problems:
        # A broken index would turn every package into a false "not found";
        # report the index problems alone.
        return problems, [], {}
    bind_docker_index(docker, docker_pins, docker_shas, problems)
    verified = bind_acquired(acquired, snapshot, docker_pins, docker_shas, args.snapshot_id, problems)

    snap_uri = f"https://snapshot.ubuntu.com/ubuntu/{args.snapshot_id}"
    installed = {}
    rows = []
    for name, ver, arch in inventory:
        installed[name] = ver
        key = (name, ver, arch)
        if key in verified:
            binding = "acquired-verified"
        elif key in base:
            binding = "inherited-base-image"
        else:
            binding = None  # neither acquired nor in the base image: refused below
        if name in docker_pins:
            if ver != docker_pins[name]:
                problems.append(f"package\t{name}\t{ver} {arch} is not the manifest pin {docker_pins[name]}")
                continue
            rec = docker.get(key)
            if rec is None:
                problems.append(f"package\t{name}\t{ver} {arch} is not in Docker's verified index")
                continue
            if binding != "acquired-verified":
                problems.append(f"package\t{name}\t{ver} {arch} is installed but no verified acquisition of its bytes exists")
                continue
            rows.append((name, ver, arch, "docker", args.docker_uri, "stable", rec["filename"], rec["sha256"], binding))
            continue
        rec = snapshot.get(key)
        if rec is None:
            problems.append(f"package\t{name}\t{ver} {arch} is not in snapshot {args.snapshot_id}")
            continue
        if rec.get("conflict"):
            problems.append(f"package\t{name}\t{ver} {arch} is listed with two different .deb hashes in the snapshot")
            continue
        if binding is None:
            had = sorted(base_by_name.get((name, arch), ()))
            was = f"the base image had {', '.join(had)}" if had else "it is not in the base image"
            problems.append(f"package\t{name}\t{ver} {arch} has no verified acquisition and {was}")
            continue
        rows.append((name, ver, arch, "ubuntu-snapshot", snap_uri, ",".join(rec["pockets"]),
                     ",".join(rec["filenames"]), rec["sha256"], binding))
    for name, ver in sorted(docker_pins.items()):
        if name not in installed:
            problems.append(f"package\t{name}\tpinned {ver} is not installed")
    counts = {"acquired-verified": sum(1 for r in rows if r[8] == "acquired-verified"),
              "inherited-base-image": sum(1 for r in rows if r[8] == "inherited-base-image"),
              "acquired-not-installed": sum(1 for k in verified if installed.get(k[0]) != k[1])}
    header = [
        "# FB-1 package provenance: every installed package of this guest, reconciled offline.",
        f"# ubuntu-snapshot = {snap_uri} ; InRelease SHA-256 " +
        " ".join(f"{s}={pins[s]}" for s in SUITES),
        f"# docker = {args.docker_uri} (InRelease SHA-256 {docker_inrelease}, signature verified by build-ova.sh); "
        "reviewed .deb SHA-256 " + " ".join(f"{n}={docker_shas[n]}" for n in sorted(docker_shas)),
        "# binding: acquired-verified = this build downloaded the .deb and its bytes equal the authenticated index "
        "(Docker: also the reviewed pin); inherited-base-image = shipped in the base cloud image and not re-acquired: "
        "this exact package/version/architecture is in the base image's pre-transaction dpkg status "
        f"(SHA-256 {base_sha}); its VERSION is in the pinned snapshot, its BYTES are bound only by "
        "BASE_IMAGE_SHA256, not per package.",
        "package\tversion\tarch\torigin\turi\tpockets\tpool_path\tsha256\tbinding",
    ]
    return problems, header + ["\t".join(r) for r in sorted(rows)], counts


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dpkg-list", required=True)
    p.add_argument("--snapshot-dir", required=True)
    p.add_argument("--snapshot-id", required=True)
    p.add_argument("--pin", action="append", help="SUITE=INRELEASE_SHA256 (one per suite)")
    p.add_argument("--docker-dir", required=True)
    p.add_argument("--docker-uri", required=True)
    p.add_argument("--docker-pin", action="append", help="PACKAGE=VERSION (one per pinned Docker package)")
    p.add_argument("--docker-deb-sha256", action="append", help="PACKAGE=SHA256 (reviewed .deb hash per Docker pin)")
    p.add_argument("--acquired", required=True, help="the guest's acquisition receipt (acquired-debs.tsv)")
    p.add_argument("--base-status", required=True,
                   help="the base image's pre-transaction /var/lib/dpkg/status (base-dpkg-status.txt)")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)

    problems, lines, counts = reconcile(args)
    if problems:
        print(f"package provenance: {len(problems)} problem(s); nothing written", file=sys.stderr)
        for line in sorted(problems):
            print(f"  {line}", file=sys.stderr)
        return 1
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, args.out)
    print(f"package provenance: {sum(1 for l in lines if not l.startswith('#')) - 1} package(s) reconciled -> {args.out}; "
          + " ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
