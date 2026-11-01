"""Offline tests for build-only-identity.py: a correct fixture must pass and each
single fault must be refused. Usage: identity_test.py WORKDIR SCRIPT MANIFEST_ENV."""
import hashlib, json, os, shutil, subprocess, sys, tempfile
S = sys.argv[1]; script = sys.argv[2]; manifest = sys.argv[3]
BASE = b"Package: base-files\nStatus: install ok installed\nVersion: 13ubuntu10\n"
m = {}
for l in open(manifest):
    l = l.split("#", 1)[0].strip()
    if "=" in l:
        k, v = l.split("=", 1); m[k] = v
H = lambda b: hashlib.sha256(b).hexdigest()
SHA = "0981ff3d037dedcf08cf7686474c65ba6b3784bf"
env = dict(os.environ, APPLIANCE_SOURCE_SHA=SHA, SOURCE_IMAGE_RUN_ID="41208642365",
  SOURCE_IMAGE_TAR_SHA256="c98564d4d86d99e61a0e86541aeea5331a6ecce704e7f146b507d8e818484a52",
  SOURCE_DATE_EPOCH_PIN="1793096442", EXPECT_IMAGE_ID="sha256:d2ce15f1f7a99c2875579d0cf55f1fe51f0c6e993071eed4bc201eccba732d79",
  EXPECT_APP_VERSION="v1.0.375-candidate.g0981ff3d037d",
  EXPECT_SIDECAR_ID="sha256:91eae57526b246da28cb370bd824c45af51e245be0093afcc316bc3fbe941f9d",
  EXPECT_SIDECAR_ARCHIVE_SHA256="6482ae8c2774b30913b69d3d26778da8005817bdfb4df051f324e74c93c3c8ad",
  EXPECT_APT_SNAPSHOT="20261029T180000Z",
  EXPECT_BASE_STATUS_SHA256=hashlib.sha256(BASE).hexdigest(),
  EXPECT_BASE_SIGNER="D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81", EXPECT_KERNEL="linux-image-7.0.0-42-generic", EXPECT_KERNEL_VERSION="7.0.0-42.42~24.04.1",
  EXPECT_CONSOLE_SHA256=H(b"console"), EXPECT_ACCESS_SHA256=H(b"access"))
ova = b"fake-ova"
docker = {"docker-ce": ("DOCKER_CE_VERSION","DOCKER_CE_DEB_SHA256"), "docker-ce-cli": ("DOCKER_CE_CLI_VERSION","DOCKER_CE_CLI_DEB_SHA256"),
          "containerd.io": ("CONTAINERD_IO_VERSION","CONTAINERD_IO_DEB_SHA256"), "docker-compose-plugin": ("DOCKER_COMPOSE_PLUGIN_VERSION","DOCKER_COMPOSE_PLUGIN_DEB_SHA256")}
def good():
    bi = {"source": {"git_commit": SHA, "git_dirty": False, "source_date_epoch": 1793096442,
                     "apt_build_start": "20261102T101500Z", "apt_snapshot": "20261029T180000Z"},
          "candidate": {"image_source_git_commit": SHA, "provisioning_git_commit": SHA, "provisioning_drift": False,
                        "image_tar_sha256": env["SOURCE_IMAGE_TAR_SHA256"], "ci_run_id": "41208642365"},
          "application": {"index_digest": env["EXPECT_IMAGE_ID"], "app_version_file": env["EXPECT_APP_VERSION"],
                          "clamav_sidecar_image_id": env["EXPECT_SIDECAR_ID"], "clamav_baked_tar_sha256": env["EXPECT_SIDECAR_ARCHIVE_SHA256"]},
          "guest_os": {"base_image_sha256": m["BASE_IMAGE_SHA256"], "base_image_gpg": "verified (using RSA key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81)", "base_dpkg_status_sha256": env["EXPECT_BASE_STATUS_SHA256"]},
          "console": {"binary_sha256": H(b"console")},
          "artifact": {"sha256": H(ova)}}
    prov = ["# header", "package\tversion\tarch\torigin\turi\tpockets\tpool_path\tsha256\tbinding"]
    acq = []
    for n,(vk,sk) in docker.items():
        prov.append(f"{n}\t{m[vk]}\tamd64\tdocker\turi\tstable\tpool/{n}.deb\t{m[sk]}\tacquired-verified")
        acq.append(f"{n}\t{m[vk]}\tamd64\t{m[sk]}\t{n}.deb")
    prov.append("pigz\t2.8-1\tamd64\tubuntu-snapshot\turi\tnoble\tpool/p.deb\t" + "a"*64 + "\tacquired-verified")
    acq.append("pigz\t2.8-1\tamd64\t" + "a"*64 + "\tpigz.deb")
    prov.append("bash\t5.2\tamd64\tubuntu-snapshot\turi\tnoble\tpool/b.deb\t" + "b"*64 + "\tinherited-base-image")
    label = (f"# guest packages upgraded at build time from the Ubuntu archive snapshot 20261029T180000Z, InRelease SHA-256 verified: "
             f"noble={m['GUEST_APT_SNAPSHOT_INRELEASE_SHA256_NOBLE']} noble-updates={m['GUEST_APT_SNAPSHOT_INRELEASE_SHA256_UPDATES']} "
             f"noble-security={m['GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY']} noble-backports={m['GUEST_APT_SNAPSHOT_INRELEASE_SHA256_BACKPORTS']} (old -> new)\n")
    dl = ["linux-image-7.0.0-42-generic\t7.0.0-42.42~24.04.1\tamd64", "linux-image-virtual-hwe-24.04\t7.0.0-42.42~24.04.1\tamd64",
          "linux-modules-7.0.0-42-generic\t7.0.0-42.42~24.04.1\tamd64", "bash\t5.2\tamd64"]
    return {"bi": bi, "prov": prov, "acq": acq, "label": label, "dl": dl, "ova": ova, "ovasha": H(ova),
            "console": b"console", "access": b"access", "base": BASE}
def write(d, f):
    os.makedirs(d + "/out"); os.makedirs(d + "/con")
    if f["bi"] is not None: json.dump(f["bi"], open(d + "/out/build-info.json", "w"))
    open(d + "/out/package-provenance.tsv", "w").write("\n".join(f["prov"]) + "\n")
    open(d + "/out/acquired-debs.tsv", "w").write("\n".join(f["acq"]) + "\n")
    open(d + "/out/build-upgrades.txt", "w").write(f["label"] + "bash 5.1 -> 5.2\n")
    open(d + "/out/dpkg-list.txt", "w").write("\n".join(f["dl"]) + "\n")
    open(d + "/out/base-dpkg-status.txt", "wb").write(f["base"])
    open(d + "/out/c.ova", "wb").write(f["ova"]); open(d + "/out/c.ova.sha256", "w").write(f"{f['ovasha']}  c.ova\n")
    if f["console"] is not None: open(d + "/con/culvert-console", "wb").write(f["console"])
    open(d + "/con/culvert-access", "wb").write(f["access"])
def run(f):
    d = tempfile.mkdtemp(dir=S); write(d, f)
    r = subprocess.run([sys.executable, "-I", script, d + "/out", manifest, d + "/con"], env=env, capture_output=True, text=True)
    shutil.rmtree(d); return r
def mut(fn):
    f = good(); fn(f); return f
cases = [
 ("control: good outputs", lambda f: None, 0),
 ("dirty source", lambda f: f["bi"]["source"].update(git_dirty=True), 1),
 ("other commit", lambda f: f["bi"]["source"].update(git_commit="0"*40), 1),
 ("other SOURCE_DATE_EPOCH", lambda f: f["bi"]["source"].update(source_date_epoch=1), 1),
 ("other snapshot", lambda f: f["bi"]["source"].update(apt_snapshot="20261002T120000Z"), 1),
 ("build start not later", lambda f: f["bi"]["source"].update(apt_build_start="20261029T180000Z"), 1),
 ("provisioning drift", lambda f: f["bi"]["candidate"].update(provisioning_drift=True), 1),
 ("other image tar", lambda f: f["bi"]["candidate"].update(image_tar_sha256="0"*64), 1),
 ("other app image", lambda f: f["bi"]["application"].update(index_digest="sha256:" + "0"*64), 1),
 ("other app VERSION", lambda f: f["bi"]["application"].update(app_version_file="v1.0.360-candidate.g0648adeba52e"), 1),
 ("other sidecar id", lambda f: f["bi"]["application"].update(clamav_sidecar_image_id="sha256:" + "0"*64), 1),
 ("other sidecar archive", lambda f: f["bi"]["application"].update(clamav_baked_tar_sha256="0"*64), 1),
 ("base gpg field missing", lambda f: f["bi"]["guest_os"].pop("base_image_gpg"), 1),
 ("base gpg skipped (no keyring/gpgv)", lambda f: f["bi"]["guest_os"].update(base_image_gpg="skipped (keyring or gpgv not available on build host)"), 1),
 ("base gpg wrong signer", lambda f: f["bi"]["guest_os"].update(base_image_gpg="verified (using RSA key 1A5D6C4C7DB87C81D2EB44626FDDC30B513D5BB7)"), 1),
 ("base gpg empty", lambda f: f["bi"]["guest_os"].update(base_image_gpg=""), 1),
 ("other base status (build-info)", lambda f: f["bi"]["guest_os"].update(base_dpkg_status_sha256="0"*64), 1),
 ("other base status (file)", lambda f: f.update(base=f["base"] + b"\n"), 1),
 ("ova hash file mismatch", lambda f: f.update(ovasha="0"*64), 1),
 ("build-info artifact mismatch", lambda f: f["bi"]["artifact"].update(sha256="0"*64), 1),
 ("no build-info", lambda f: f.update(bi=None), 1),
 ("docker row inherited", lambda f: f["prov"].__setitem__(2, f["prov"][2].replace("acquired-verified", "inherited-base-image")), 1),
 ("docker deb sha differs", lambda f: f["prov"].__setitem__(2, f["prov"][2].replace(m["DOCKER_CE_DEB_SHA256"], "0"*64)), 1),
 ("docker row missing", lambda f: f["prov"].pop(5), 1),
 ("unknown origin", lambda f: f["prov"].append("x\t1\tamd64\tlive\turi\tnoble\tp\t" + "c"*64 + "\tacquired-verified"), 1),
 ("unknown binding", lambda f: f["prov"].append("x\t1\tamd64\tubuntu-snapshot\turi\tnoble\tp\t" + "c"*64 + "\tunverified"), 1),
 ("receipt deleted (new pkg)", lambda f: f["acq"].pop(4), 1),
 ("receipt sha differs", lambda f: f["acq"].__setitem__(4, f["acq"][4].replace("a"*64, "d"*64)), 1),
 ("receipt file empty", lambda f: f.update(acq=[]), 1),
 ("upgrades miss snapshot", lambda f: f.update(label=f["label"].replace("20261029T180000Z", "X")), 1),
 ("upgrades miss a pin", lambda f: f.update(label=f["label"].replace(m["GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY"], "X")), 1),
 ("two kernels", lambda f: f["dl"].append("linux-image-7.0.0-38-generic\t7.0.0-38.38~24.04.4\tamd64"), 1),
 ("kernel 38 only", lambda f: f.update(dl=[l.replace("7.0.0-42", "7.0.0-38") for l in f["dl"]]), 1),
 ("console differs", lambda f: f.update(console=b"other"), 1),
 ("console missing", lambda f: f.update(console=None), 1),
 ("access differs", lambda f: f.update(access=b"other"), 1),
]
bad = 0
for name, fn, want in cases:
    r = run(mut(fn)); ok = r.returncode == want
    bad += not ok
    fails = [l for l in r.stdout.splitlines() if l.startswith("FAIL")]
    print(f"{'PASS' if ok else 'WRONG'} {name}: exit={r.returncode} " + (f"[{fails[0][:90]}]" if fails else r.stdout.splitlines()[-1] if r.stdout else r.stderr[-200:]))
print(f"{len(cases)-bad}/{len(cases)} cases as expected"); sys.exit(1 if bad else 0)
