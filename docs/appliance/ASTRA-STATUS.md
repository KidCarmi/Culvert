# ASTRA status — on-prem appliance pilot (appliance engineer)

Owner: Astra (appliance engineer). Reader: Fable (coordinator/integrator).
Branch: `claude/onprem-appliance-astra` (push-only by Astra). Baseline: `origin/main` = `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`.

Evidence vocabulary used below: **SRC** = source inspection only; **TEST** = existing repo test;
**RAN** = command I executed in this container, output quoted; **VM** = executed inside a built guest VM;
**UNTESTED** / **BLOCKED** = not executed, with the exact command that would run it.

Latest push: _(filled in at the bottom, "Push log")_.

---

## Milestone 1 — environment capability verification (RAN, 2026-10-02)

Container: Ubuntu 24.04.4 LTS, kernel `6.18.44-fc-v51`, x86_64, 4 vCPU, 15 GiB RAM, no swap.
Disk: `/` 252 GiB virtual, **30 GiB available** (`df -h /`). Outbound HTTPS via the session agent proxy.

| Capability | Result | Evidence |
|---|---|---|
| Docker daemon | **YES (self-started)**. Client 29.6.2 was present but no daemon; `dockerd` + `containerd` binaries exist and I started one. cgroup v1, overlayfs via containerd snapshotter, nftables. | RAN below |
| `docker pull` of the v1.0.259 catalog digest | **YES**, 6.0 s, 109 MB image. `docker save` tarball = 32,929,280 bytes, sha256 `edc43b63183fd0362b6f221d7c4f6b8fc03ecf7e2a80d33cba5375d4cbef0cfc`. | RAN |
| `cosign verify` with `release_identity.env` identity | **YES** (cosign v3.1.3, 5 signatures, claims + tlog + CA chain verified). The catalog `index.json.sigstore` bundle also verifies (`verify-blob` → `Verified OK`). | RAN |
| `https://catalog.culvertlabs.com/release-catalog/index.json` | **YES**, HTTP 200, 360 bytes, `catalog_version` 1001000259, recommended `culvert-1.0.259`; manifest is at `release-catalog/manifests/culvert-1.0.259.json` and pins `list_digest sha256:238ba9…347e`, platforms linux/amd64 + linux/arm64. | RAN |
| `/dev/kvm` | **NO** (`ls: cannot access '/dev/kvm': No such file or directory`). QEMU binary lists `tcg` and `kvm` accelerators; only **TCG** (software emulation) is usable here. | RAN |
| qemu-img / qemu-system-x86_64 | **YES via apt**: `qemu-utils`, `qemu-system-x86` 1:8.2.2+ds-0ubuntu1.18 (QEMU 8.2.2); OVMF 2024.02 present (`/usr/share/OVMF/OVMF_CODE_4M.fd`). | RAN |
| cloud-image-utils (`cloud-localds`), genisoimage | **YES via apt** (cloud-image-utils 0.33-1). | RAN |
| virt-customize (libguestfs) | **YES via apt** (`libguestfs-tools` 1.52.0). Needs a kernel it can boot an appliance with; without KVM it runs under TCG (slow, but works). UNTESTED beyond `command -v`. | RAN |
| packer | **NO apt candidate** (`apt-cache policy packer` → `Candidate: (none)`); HashiCorp apt repo not configured. Not needed: build is bash + cloud-init + qemu-img (decision in Track A). | RAN |
| shellcheck | **YES via apt**, 0.9.0 (same major as the Deep PR Gate's). | RAN |
| Ubuntu 24.04 cloud image | **YES**: `noble-server-cloudimg-amd64.img` 625,612,288 bytes, qcow2 3.5 GiB virtual, `sha256sum -c` against upstream `SHA256SUMS` → `OK`; sha256 `6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2` (upstream "current" as of 2026-09-26 build; Track A will pin a dated release URL, not `current`). | RAN |
| trivy / syft / grype | **YES**: the upstream `install.sh` scripts fail here (they resolve `latest` through the GitHub HTML/API, which the session proxy answers with 403); fetching the explicit release tarballs works. trivy 0.75.0 (vuln DB `UpdatedAt 2026-10-02 06:55:51Z`), syft 1.54.0, grype 0.119.0. | RAN |
| ovftool (VMware) | **NO** (proprietary download, not installable here). OVF/OVA will be produced from a template + `tar` + manifest, validated structurally only — see hypervisor-qualification.md. | RAN |
| QEMU TCG boot of the cloud image + NoCloud seed | _see "TCG boot smoke" below_ | RAN |

### What this means for qualification in THIS environment

- I can **build** the OVA artefacts (qcow2 → streamOptimized VMDK via `qemu-img`, OVF + manifest + sha256) end to end.
- I can **boot and provision** the built image only under **TCG** (no KVM): expect ~10–20× slower than native. Enough for a first-boot provisioning + reboot + OS-update qualification, with generous timeouts; not representative for performance.
- I **cannot** test on ESXi/vSphere, VirtualBox or Hyper-V here. The OVF will be written to the ESXi-compatible subset (VirtualSCSI/lsilogic, E1000/vmxnet3, VMX-21 hardware) but import into vSphere is **UNTESTED** and documented as such.
- Registry access and the signed catalog are reachable, so a "registry-connected update" path can be exercised from the host; inside a TCG guest, network goes through QEMU user-mode networking (slirp) which also reaches the proxy-fronted internet — to be confirmed during Track B.
- Scanners (trivy/syft/grype) work with fresh DBs; cosign works; so Track D (SBOM/CVE) can run fully.

### Exact commands and outputs (RAN)

```text
$ ls -la /dev/kvm
ls: cannot access '/dev/kvm': No such file or directory
$ nproc; free -h | head -2; df -h / | tail -1
4
Mem: 15Gi total, 14Gi free
/dev/vda 252G 8.5G 30G 22% /
$ uname -a
Linux vm 6.18.44-fc-v51 #1 SMP PREEMPT_DYNAMIC @0 x86_64 x86_64 x86_64 GNU/Linux

$ docker version        # before starting a daemon
Client: Docker Engine - Community Version 29.6.2 ... compose v5.3.1, buildx v0.35.0
failed to connect to the docker API at unix:///var/run/docker.sock ... no such file or directory
$ setsid nohup dockerd --host=unix:///var/run/docker.sock --data-root=/var/lib/docker >/tmp/dockerd.log 2>&1 &
$ docker info | grep -E 'Server Version|Storage Driver|Cgroup Version|Kernel'
 Server Version: 29.6.2
 Storage Driver: overlayfs
 Cgroup Version: 1
 Kernel Version: 6.18.44-fc-v51

$ time docker pull ghcr.io/kidcarmi/culvert@sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e
Digest: sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e
Status: Downloaded newer image for ghcr.io/kidcarmi/culvert@sha256:238ba9…
real 0m6.018s
$ docker images --digests
ghcr.io/kidcarmi/culvert <none> sha256:238ba9…347e 238ba99b61e1 38 hours ago 109MB
$ docker inspect <digest> --format '{{.Config.User}} {{json .Config.Entrypoint}} {{json .Config.Cmd}}'
proxy ["./culvert"] ["-port","8080","-ui-port","9090","-ca-path","/data/ca.bundle","-policy","/data/policy.json","-logfile","/data/proxy.log","-audit-log","/data/audit.jsonl","-geoip-db","/app/GeoLite2-Country.mmdb","-yara-rules-dir","/app/yara","-threat-feed-db","/data/threatfeeds.json"]
$ docker run --rm --entrypoint sh <digest> -c 'id; ls /app/deploy; ls -ld /data'
uid=100(proxy) gid=101(proxy) groups=101(proxy)
bin  docker-compose.maint-agent.yml  docker-compose.yml  packaging
drwxr-xr-x 2 proxy proxy 4096 Sep 30 19:08 /data
  → runtime user is uid 100 / gid 101 ("proxy"); /data must be owned 100:101 on the host volume.

$ curl -sSL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 && chmod +x /usr/local/bin/cosign
$ cosign version | grep GitVersion
GitVersion:    v3.1.3
$ source release_identity.env && cosign verify \
    --certificate-oidc-issuer "$CULVERT_RELEASE_SIGSTORE_ISSUER" \
    --certificate-identity-regexp "$CULVERT_RELEASE_SIGSTORE_SAN_REGEX" \
    ghcr.io/kidcarmi/culvert@sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e
Verification for ghcr.io/kidcarmi/culvert@sha256:238ba9… --
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
cosign exit=0   (5 signatures in the -o json output)

$ curl -sS -o /tmp/index.json -w 'http=%{http_code} size=%{size_download}\n' https://catalog.culvertlabs.com/release-catalog/index.json
http=200 size=360
{"schema_version":1,"generated_at":"2026-09-30T19:05:50Z","expires_at":"2027-03-29T19:05:50Z","catalog_version":1001000259,"channels":{"recommended":"culvert-1.0.259"},"releases":[{"release_id":"culvert-1.0.259","version_id":"1.0.259","manifest_ref":"culvert-1.0.259.json","manifest_sha256":"3e726de1dc2c00e6e5c07acb9c066963282d299ac23b2db131cae869552c1dc8"}]}
$ curl -sS -o /tmp/index.json.sigstore -w 'http=%{http_code}\n' https://catalog.culvertlabs.com/release-catalog/index.json.sigstore
http=200
$ cosign verify-blob --bundle /tmp/index.json.sigstore --certificate-oidc-issuer "$CULVERT_RELEASE_SIGSTORE_ISSUER" --certificate-identity-regexp "$CULVERT_RELEASE_SIGSTORE_SAN_REGEX" /tmp/index.json
Verified OK
$ curl -sS https://catalog.culvertlabs.com/release-catalog/manifests/culvert-1.0.259.json
{"schema_version":1,"release_id":"culvert-1.0.259","version_id":"1.0.259","severity":"normal","created_at":"2026-09-30T19:05:50Z","image":{"repo":"ghcr.io/kidcarmi/culvert","list_digest":"sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e","platforms":["linux/amd64","linux/arm64"]},"min_upgrade_from":"","changelog_url":"","notes":""}

$ apt-get install -y qemu-utils qemu-system-x86 cloud-image-utils genisoimage shellcheck libguestfs-tools   # exit=0
$ qemu-img --version | head -1 ; qemu-system-x86_64 --version | head -1 ; qemu-system-x86_64 -accel help
qemu-img version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)
QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)
Accelerators supported in QEMU binary: tcg kvm
$ shellcheck --version | grep version:
version: 0.9.0
$ apt-cache policy packer
packer: Installed: (none)  Candidate: (none)

$ curl -sS https://cloud-images.ubuntu.com/noble/current/SHA256SUMS | grep 'amd64.img$'
6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2 *noble-server-cloudimg-amd64.img
$ curl -sSL -o noble-server-cloudimg-amd64.img https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img && sha256sum -c --ignore-missing SHA256SUMS
noble-server-cloudimg-amd64.img: OK      (625,612,288 bytes; qcow2, virtual size 3.5 GiB)

$ curl -sSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
aquasecurity/trivy crit unable to find '' - use 'latest' ...         ← proxy returns 403 for github.com/<repo>/releases/latest and api.github.com
$ git ls-remote --tags https://github.com/aquasecurity/trivy | ... | sort -V | tail -1     → v0.75.0   (git transport works)
$ curl -sSL -o trivy.tgz https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz && tar xzf trivy.tgz trivy && mv trivy /usr/local/bin/
$ trivy --version | head -1 ; syft version | grep ^Version ; grype version | grep ^Version
Version: 0.75.0
Version: 1.54.0
Version: 0.119.0
$ trivy image --quiet --severity HIGH,CRITICAL --scanners vuln ghcr.io/kidcarmi/culvert@sha256:238ba9…347e
│ … (alpine 3.24.2)                 │ alpine   │ 0 │
│ app/culvert                       │ gobinary │ 0 │
│ app/deploy/bin/culvert-maint      │ gobinary │ 0 │
  Vulnerability DB UpdatedAt: 2026-10-02 06:55:51Z   (a 0 here means "no HIGH/CRITICAL findings in this DB today", not "no vulnerabilities" — full triage is Track D)

$ docker save -o culvert-1.0.259.tar ghcr.io/kidcarmi/culvert@sha256:238ba9…347e && ls -l culvert-1.0.259.tar && sha256sum culvert-1.0.259.tar
32929280 culvert-1.0.259.tar
edc43b63183fd0362b6f221d7c4f6b8fc03ecf7e2a80d33cba5375d4cbef0cfc
```


### Image preload finding (RAN) — decides the offline-first-boot design

Under Docker's **containerd image store** (the default this daemon came up with: `DriverStatus [["driver-type","io.containerd.snapshotter.v1"]]`), an image pulled by digest and then saved **without a tag** loses its registry reference on `docker load`:

```text
$ docker save -o culvert-1.0.259.tar ghcr.io/kidcarmi/culvert@sha256:238ba9…   # 32,929,280 B
$ docker rmi … ; docker load -i culvert-1.0.259.tar
Loaded image ID: sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e
$ docker image inspect ghcr.io/kidcarmi/culvert@sha256:238ba9…
Error response from daemon: No such image
```

but saved **with a local tag** the OCI archive carries the digest annotation and `docker load` restores BOTH the tag AND the registry RepoDigest, and the image **ID equals the catalog list digest**:

```text
$ docker tag sha256:238ba9… ghcr.io/kidcarmi/culvert:v1.0.259
$ docker save -o culvert-v1.0.259-tagged.tar ghcr.io/kidcarmi/culvert:v1.0.259   # 32,929,792 B, OCI layout (blobs/, index.json, manifest.json)
$ docker rmi … ; docker load -i culvert-v1.0.259-tagged.tar
Loaded image: ghcr.io/kidcarmi/culvert:v1.0.259
$ docker image inspect ghcr.io/kidcarmi/culvert:v1.0.259 --format 'Id={{.Id}} RepoDigests={{json .RepoDigests}}'
Id=sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e RepoDigests=["ghcr.io/kidcarmi/culvert@sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e"]
$ docker tag ghcr.io/kidcarmi/culvert:v1.0.259 ghcr.io/kidcarmi/culvert@sha256:…
refusing to create a tag with a digest reference
```

Consequences for Track B: the OVA preloads the **tagged** OCI archive; the guest Docker is pinned to the containerd image store at build time (`/etc/docker/daemon.json` → `features.containerd-snapshotter=true`, so the behaviour does not depend on docker-ce's install-time default); first boot sets `CULVERT_PROXY_SEED_REF=ghcr.io/kidcarmi/culvert@sha256:<digest>` so `scripts/install.sh`'s existing `docker image inspect "$CULVERT_PROXY_SEED_REF"` succeeds and it tags `culvert/proxy:pinned` **without a pull**; and the first-boot unit can check `.Id == <digest from build-record.json>` as an offline integrity check before invoking the installer. `verify_pinned_image_signature` (cosign against ghcr.io) still needs registry + Sigstore egress; offline it cannot pass, so the maintenance-agent trust gate must rest on the build-time `cosign verify` recorded in the build record (details and the proposed guarded bypass in Track B).

### TCG boot smoke (RAN)

Booted the pinned Ubuntu 24.04 cloud image under QEMU **TCG** (no KVM) with a NoCloud seed, 2 vCPU / 2 GiB, q35, virtio disk + net, serial console:

```text
$ qemu-img create -f qcow2 -F qcow2 -b ../guest/noble-server-cloudimg-amd64.img disk.qcow2 8G
$ cloud-localds seed.iso user-data meta-data          # user-data: runcmd echoes a marker to /dev/ttyS0 then poweroff
$ qemu-system-x86_64 -machine q35,accel=tcg -cpu max -smp 2 -m 2048 -nographic -no-reboot \
    -drive file=disk.qcow2,if=virtio,format=qcow2 -drive file=seed.iso,if=virtio,format=raw,readonly=on \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 > serial.log 2>&1
$ grep -aE 'TCG_SMOKE_OK|Cloud-init v' serial.log
[  131.197907] cloud-init[620]: Cloud-init v. 26.1-0ubuntu1~24.04.1 running 'init-local' ... Up 130.68 seconds.
[  161.989364] cloud-init[687]: Cloud-init v. 26.1-0ubuntu1~24.04.1 running 'init' ... Up 161.47 seconds.
[  226.347774] cloud-init[981]: Cloud-init v. 26.1-0ubuntu1~24.04.1 running 'modules:config' ... Up 224.71 seconds.
[  242.609702] cloud-init[1023]: Cloud-init v. 26.1-0ubuntu1~24.04.1 running 'modules:final' ... Up 241.32 seconds.
TCG_SMOKE_OK 6.8.0-142-generic VERSION_ID="24.04"
```

Guest kernel `6.8.0-142-generic`, cloud-init 26.1. ~4 min of guest uptime to reach `modules:final` under TCG (a KVM host does this in ~20 s). So VM qualification here is **feasible but slow**: budget 30–60 min per full first-boot + reboot cycle, and treat timings as non-representative.

---

## Track status (updated 2026-10-02, after the Track A–E pushes; the TCG bake is running)

| Track | State | Where | Evidence class |
|---|---|---|---|
| A. Guest OS decision + `ova-build.md` | **done** | `docs/appliance/ova-build.md`, `appliance/manifest.env` | SRC + RAN (inputs fetched/verified) |
| B. `appliance/` build + first-boot provisioning | **implemented; qualification in progress** | `appliance/build.sh`, `appliance/bake/`, `appliance/guest/`, `appliance/ovf/`, `appliance/qualify/qemu-qualify.sh`, `scripts/install.sh` (offline opt-in) | shellcheck clean (RAN); installer contract tests `go test -run 'Install|Deploy|ReleaseManagementInstall|CatalogBootstrap|ReleaseIdentity|PinnedSeed|DeployBundle' .` → `ok` (RAN, 2m14s); bake + first-boot: see Track F |
| C. `os-maintenance-runbook.md` + OS update/reboot qualification | **doc done; qualification pending the bake** (TCG) | `docs/appliance/os-maintenance-runbook.md`; phase 2 of `qemu-qualify.sh` | — |
| D. `sbom-cve/` | **done for the two images + inventories; guest-disk scan pending the bake** | `docs/appliance/sbom-cve/README.md` + artifacts | RAN (trivy 0.75.0, grype 0.119.0, syft 1.54.0, cosign 3.1.3; DB timestamps in the README) |
| E. `install-runbook.md` + `hypervisor-qualification.md` | **drafts pushed; §1/§3/§4 of the qualification doc filled after the runs** | `docs/appliance/` | SRC; vSphere import UNTESTED by construction |
| F. OVA build | **running** (`appliance/build.sh --accel tcg`, started 10:03Z from `bd4ceea`) | `<scratch>/out/` | RAN when it completes |
| extra | manual-dispatch CI workflow `.github/workflows/appliance-build.yml` (new file, not a gate) | — | UNTESTED in CI (cannot dispatch from here) |

### Design summary (what Fable should know)

* **Build = boot the stock Ubuntu cloud image once under QEMU with a NoCloud seed and an OFFLINE payload ISO** (docker-ce .debs with a local apt index, the two OCI image archives, the appliance guest files, vendored `scripts/install.sh`), then flatten to streamOptimized VMDK + OVF + manifest + OVA (+ qcow2). No packer, no libguestfs, no network in the bake VM. `appliance/manifest.env` pins every input; `<name>.build-record.json` records every digest consumed and produced.
* **Preload**: the application image is saved with a local tag (`ghcr.io/kidcarmi/culvert:v1.0.259`) so `docker load` restores the registry RepoDigest and `.Id == catalog list digest`; the guest daemon is pinned to the containerd image store. `clamav/clamav:1.4` is preloaded too (pinned digest; the image bundles the signature DB, so clamd is healthy with no egress — verified by reading the image: `main.cvd`/`daily.cvd`/`bytecode.cvd` present, `/init` only runs freshclam when `main.cvd` is missing).
* **First boot** (`culvert-appliance-firstboot.service`, after cloud-final + docker): verify preloaded image Ids against `/etc/culvert-appliance/build-inputs.json` → mint a one-time console password for user `culvert` unless a datasource set one (SSH stays key-only) → run the vendored `scripts/install.sh` with `CULVERT_INSTALL_OFFLINE=1 CULVERT_PROXY_SEED_REF=<repo>@<digest> CULVERT_DIR=/srv/culvert CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1`, cwd `/`, stdin null → marker. Idempotent per step; failure is shown on the console with the retry command.
* **Console** (`/etc/issue`, 15 s timer): addresses, admin/proxy URLs, first-boot phase/error, `/ready` status + every `.checks` row verbatim, setup-needed line from `/api/setup/status`, one-time password while unchanged, mgmt allowlist, DHCP/static.
* **Host CLI** `culvert-appliance`: `status`, `netconfig --static/--dhcp` (netplan, validated before apply), `mgmt-allow` (nftables: NEW connections to 22 and the DNAT'd 9090 only from listed CIDRs — the host-level mitigation for the app's TOFU setup), `auto-reboot on|off`, `reidentify --yes` (host keys + machine-id, never `/data`), `firstboot-retry`, `logs`.
* **Identity**: the bake strips ssh host keys, machine-id, cloud-init state and the bake user; nothing under `/data` is ever written by provisioning.

### `scripts/install.sh` change (host-side, my path) — please review

One addition, before the internet pre-flight: `offline_install_ok()` honours `CULVERT_INSTALL_OFFLINE=1` only when docker is installed, `docker compose version` works, `CULVERT_PROXY_SEED_REF` is set AND `docker image inspect` finds it locally; otherwise it warns and the normal fatal check runs. No other line of the installer changed. All contract tests that scan the file pass (`deploy_pinned_seed_test.go`, `deploy_bundle_contract_test.go`, `install_catalog_bootstrap_contract_test.go`, `release_management_install_contract_test.go`, `release_identity_test.go`, the `install_script_*` tests). Pre-existing: shellcheck 0.9.0 (apt on 24.04) cannot parse the `# shellcheck disable=SC2064 -- reason` directive at L~2490 — present on `main` too, not introduced here.

### Trust posture of the offline first boot (please confirm you are comfortable with it)

The maintenance-agent trust gate in `install_maint_agent` needs `cosign verify` against ghcr.io + Sigstore, impossible offline. The appliance therefore passes `CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1` (the existing break-glass) **after** its own offline check that the preloaded image Id equals the digest recorded at build time — and the build refuses to produce an OVA unless `cosign verify` of that digest passed (the verification output ships as `<name>.cosign-verify.json`). The residual is that the guest trusts its own build record, whose integrity rests on the OVA's sha256/manifest the operator verifies at import. Alternative if you prefer: an online-when-possible mode (try cosign first, fall back) — easy to add in `firstboot.sh`; I did not add it because an appliance that behaves differently depending on egress at first boot is harder to support.

## Open questions / proposals for Fable (not blocking)

1. **ClamAV image has two fixable CVEs** (`pcre2` 10.48→10.49-r0 HIGH, `nghttp2-libs` 1.69→1.70 MEDIUM; Alpine secdb confirms the fixes). `docker-compose.yml` pins `clamav/clamav:1.4` by tag; the appliance pins the digest that tag resolved to today (`sha256:57deb108…`). When Docker Hub republishes `1.4`, bump `CLAMAV_IMAGE_DIGEST` in `appliance/manifest.env` (my side) — or consider a digest-pinned tag in compose (your side).
2. **Setup TOFU**: the host-level `mgmt-allow` restricts 9090 by source CIDR, but the honest fix is app-side: a one-time setup token printed on the console (I can show anything the app writes to a well-known file in `/data`… which provisioning cannot read — the volume is 100:101; the console renderer runs as root so it *can* read `/var/lib/docker/volumes/culvert_proxy-data/_data/<file>` if you want to define one). Your call.
3. **Agent self-update signal**: after `/v1/upgrades/apply`, the agent binary/sudoers/compose on the host stay at the OLD version until `install.sh` is re-run (documented in `os-maintenance-runbook.md` §6). Proposal (Go, your side): the agent compares `server.Version` with the running image's `org.opencontainers.image.version` and surfaces `agent_update_pending` in `/v1/status` + the Release panel. I deliberately do not propose in-place self-replacement.
4. **`docs/operator/*`**: nothing needs editing for the appliance. I'd suggest one line in `docs/operator/catalog-bootstrap-install-runbook.md`'s env table for `CULVERT_INSTALL_OFFLINE` once you accept the installer change.
5. **A `/ready` row for "setup complete"** would let the console drop its separate `/api/setup/status` call — optional; the renderer already prints every `.checks` row generically.

## Push log

_(appended after each push)_

- 2026-10-02 — `72ce0984c1add911142db489c69f949a7ade1574` — M1 environment capability report.
