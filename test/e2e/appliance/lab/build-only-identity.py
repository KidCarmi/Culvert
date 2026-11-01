#!/usr/bin/env python3
"""build-only-identity.py OUT_DIR MANIFEST_ENV CONSOLE_DIR

The identity step of the build-only route (frozen BOM, section 7), run on the
outputs of ONE build-ova.sh invocation before anything could boot them. It
re-checks, from the retained files, what the BOM requires of the build:

  build-info.json        source commit (clean), SOURCE_DATE_EPOCH, snapshot ID,
                         build start later than the snapshot, candidate image
                         source/provisioning commit (no drift), image tar,
                         CI run, application image ID and VERSION, ClamAV
                         sidecar ID and archive, base status hash, OVA hash
  package-provenance.tsv only ubuntu-snapshot / docker origins, only the two
                         bindings, the 4 Docker rows acquired-verified at the
                         manifest pins and .deb SHA-256 values
  acquired-debs.tsv      present; every acquired-verified row has a receipt
                         row with the same SHA-256
  base-dpkg-status.txt   SHA-256 equals the pin and build-info's record
  build-upgrades.txt     names the snapshot ID and the four InRelease hashes
  dpkg-list.txt          exactly one linux-image-<abi>, the approved kernel
  console binaries       culvert-console / culvert-access SHA-256 recorded and
                         compared with the producer-reported expectations

Expected values come from the environment (EXPECT_*, APPLIANCE_SOURCE_SHA, …)
and from the frozen source's own manifest.env. The 94/586 split is printed as
an observation, never checked: the prediction is not T5, and T5 belongs to
ASTRA. Exit 1 on any mismatch, after printing every check.
"""
import hashlib
import json
import os
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def rows(path):
    """Data rows of a TSV, without comment lines and the column header."""
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if parts[0] == "package":
            continue
        out.append(parts)
    return out


def main():
    out_dir, manifest_env, console_dir = sys.argv[1:4]
    env = os.environ
    m = manifest(manifest_env)
    results = []

    def check(name, got, want):
        ok = got == want
        results.append(ok)
        print(f"{'OK  ' if ok else 'FAIL'} {name}: got={got!r} want={want!r}")

    def need(name, path):
        ok = os.path.isfile(path) and os.path.getsize(path) > 0
        results.append(ok)
        print(f"{'OK  ' if ok else 'FAIL'} {name}: {'present' if ok else 'missing or empty'} ({os.path.basename(path)})")
        return ok

    p = lambda name: os.path.join(out_dir, name)  # noqa: E731
    sha = env["APPLIANCE_SOURCE_SHA"]

    # build-info.json
    bi = {}
    if need("build-info.json", p("build-info.json")):
        bi = json.load(open(p("build-info.json"), encoding="utf-8"))
    src, cand, app, gos, art = (bi.get(k, {}) for k in ("source", "candidate", "application", "guest_os", "artifact"))
    check("source.git_commit", src.get("git_commit"), sha)
    check("source.git_dirty", src.get("git_dirty"), False)
    check("source.source_date_epoch", src.get("source_date_epoch"), int(env["SOURCE_DATE_EPOCH_PIN"]))
    check("source.apt_snapshot", src.get("apt_snapshot"), env["EXPECT_APT_SNAPSHOT"])
    start = src.get("apt_build_start") or ""
    check("source.apt_build_start is later than the snapshot",
          len(start) == 16 and start > env["EXPECT_APT_SNAPSHOT"], True)
    check("candidate.image_source_git_commit", cand.get("image_source_git_commit"), sha)
    check("candidate.provisioning_git_commit", cand.get("provisioning_git_commit"), sha)
    check("candidate.provisioning_drift", cand.get("provisioning_drift"), False)
    check("candidate.image_tar_sha256", cand.get("image_tar_sha256"), env["SOURCE_IMAGE_TAR_SHA256"])
    check("candidate.ci_run_id", str(cand.get("ci_run_id")), env["SOURCE_IMAGE_RUN_ID"])
    check("application.index_digest", app.get("index_digest"), env["EXPECT_IMAGE_ID"])
    check("application.app_version_file", (app.get("app_version_file") or "").strip(), env["EXPECT_APP_VERSION"])
    check("application.clamav_sidecar_image_id", app.get("clamav_sidecar_image_id"), env["EXPECT_SIDECAR_ID"])
    check("application.clamav_baked_tar_sha256", app.get("clamav_baked_tar_sha256"), env["EXPECT_SIDECAR_ARCHIVE_SHA256"])
    check("guest_os.base_image_sha256", gos.get("base_image_sha256"), m.get("BASE_IMAGE_SHA256"))
    check("guest_os.base_dpkg_status_sha256", gos.get("base_dpkg_status_sha256"), env["EXPECT_BASE_STATUS_SHA256"])

    # The OVA and its recorded hash
    ovas = sorted(f for f in os.listdir(out_dir) if f.endswith(".ova"))
    check("exactly one .ova", len(ovas), 1)
    if len(ovas) == 1:
        ova_sha = sha256(p(ovas[0]))
        rec = open(p(ovas[0] + ".sha256"), encoding="utf-8").read().split()[0] if os.path.isfile(p(ovas[0] + ".sha256")) else None
        check(".ova.sha256 matches the file", rec, ova_sha)
        check("build-info artifact.sha256 matches the file", art.get("sha256"), ova_sha)
        print(f"     OVA {ovas[0]} sha256 {ova_sha}")

    # base-dpkg-status.txt
    if need("base-dpkg-status.txt", p("base-dpkg-status.txt")):
        check("base-dpkg-status.txt sha256", sha256(p("base-dpkg-status.txt")), env["EXPECT_BASE_STATUS_SHA256"])

    # package-provenance.tsv
    pins = {"docker-ce": ("DOCKER_CE_VERSION", "DOCKER_CE_DEB_SHA256"),
            "docker-ce-cli": ("DOCKER_CE_CLI_VERSION", "DOCKER_CE_CLI_DEB_SHA256"),
            "containerd.io": ("CONTAINERD_IO_VERSION", "CONTAINERD_IO_DEB_SHA256"),
            "docker-compose-plugin": ("DOCKER_COMPOSE_PLUGIN_VERSION", "DOCKER_COMPOSE_PLUGIN_DEB_SHA256")}
    prov = rows(p("package-provenance.tsv")) if need("package-provenance.tsv", p("package-provenance.tsv")) else []
    check("package-provenance rows have 9 columns", all(len(r) == 9 for r in prov), True)
    prov = [r for r in prov if len(r) == 9]
    check("origins outside ubuntu-snapshot/docker", sorted({r[3] for r in prov} - {"ubuntu-snapshot", "docker"}), [])
    check("bindings outside acquired-verified/inherited-base-image",
          sorted({r[8] for r in prov} - {"acquired-verified", "inherited-base-image"}), [])
    docker = {r[0]: r for r in prov if r[3] == "docker"}
    check("docker rows", sorted(docker), sorted(pins))
    for name, (vk, sk) in pins.items():
        r = docker.get(name, [""] * 9)
        check(f"{name} version", r[1], m.get(vk))
        check(f"{name} .deb sha256", r[7], m.get(sk))
        check(f"{name} binding", r[8], "acquired-verified")
    acquired = [r for r in prov if r[8] == "acquired-verified"]
    inherited = [r for r in prov if r[8] == "inherited-base-image"]
    print(f"     observation (not checked; T5 decides): {len(prov)} packages, "
          f"acquired-verified={len(acquired)} inherited-base-image={len(inherited)} (prediction 680: 94 / 586)")

    # acquired-debs.tsv
    receipts = {}
    if need("acquired-debs.tsv", p("acquired-debs.tsv")):
        for r in rows(p("acquired-debs.tsv")):
            if len(r) >= 4:
                receipts.setdefault((r[0], r[1], r[2]), set()).add(r[3])
    missing = [f"{r[0]}={r[1]}/{r[2]}" for r in acquired if r[7] not in receipts.get((r[0], r[1], r[2]), ())]
    check("acquired-verified rows without a matching receipt", missing, [])

    # build-upgrades.txt
    if need("build-upgrades.txt", p("build-upgrades.txt")):
        head = open(p("build-upgrades.txt"), encoding="utf-8").readline()
        check("build-upgrades names the snapshot", env["EXPECT_APT_SNAPSHOT"] in head, True)
        for k in ("NOBLE", "UPDATES", "SECURITY", "BACKPORTS"):
            v = m.get(f"GUEST_APT_SNAPSHOT_INRELEASE_SHA256_{k}", "<unset>")
            check(f"build-upgrades names InRelease {k.lower()}", v in head, True)

    # dpkg-list.txt: exactly one kernel image, the approved one
    if need("dpkg-list.txt", p("dpkg-list.txt")):
        kern = [r for r in rows(p("dpkg-list.txt")) if r[0].startswith("linux-image-") and r[0][12:13].isdigit()]
        check("linux-image-<abi> packages", [(r[0], r[1] if len(r) > 1 else None) for r in kern],
              [(env["EXPECT_KERNEL"], env["EXPECT_KERNEL_VERSION"])])

    # Console binaries, measured from the overlay the build installed
    for name, var in (("culvert-console", "EXPECT_CONSOLE_SHA256"), ("culvert-access", "EXPECT_ACCESS_SHA256")):
        path = os.path.join(console_dir, name)
        got = sha256(path) if os.path.isfile(path) else None
        print(f"     measured {name} sha256 {got}")
        check(f"{name} sha256 (producer-reported expectation)", got, env[var])
    check("build-info console.binary_sha256 is the measured console", bi.get("console", {}).get("binary_sha256"),
          sha256(os.path.join(console_dir, "culvert-console")) if os.path.isfile(os.path.join(console_dir, "culvert-console")) else None)

    bad = results.count(False)
    print(f"identity: {len(results) - bad}/{len(results)} checks passed")
    if bad:
        print("::error::build-only identity mismatch; the OVA is retained as FAILED evidence and must not be booted")
        sys.exit(1)


if __name__ == "__main__":
    main()
