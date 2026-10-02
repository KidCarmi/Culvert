# Culvert appliance — OVA build

Owner: appliance engineering (Astra). Status: build path implemented in `appliance/`; see
`docs/appliance/ASTRA-STATUS.md` for what has actually been executed and `hypervisor-qualification.md`
for what has been tested where.

## 1. Guest OS decision

**Ubuntu 24.04 LTS (noble) server cloud image, x86_64, dated release `20260926`** (`appliance/manifest.env`).

| Topic | Decision | Why |
|---|---|---|
| Distribution | Ubuntu 24.04 LTS server **cloud image** (not the ISO installer, not "minimal") | Already cloud-init + open-vm-tools + netplan + unattended-upgrades; the `.img` is a ready root filesystem (no installer automation to maintain); Canonical publishes it as an ESXi OVA too, so the virtual-hardware shape is a known-importable reference. `scripts/install.sh` supports Ubuntu natively. |
| Support horizon | Standard security maintenance to **April 2029**; ESM to 2034 (Ubuntu Pro, not assumed). | Longest horizon of the supported distro families without a paid subscription. |
| Kernel | `linux-image-virtual` 6.8 GA series (what the cloud image ships; HWE kernel deliberately NOT enabled). | GA kernel gets the longest, most conservative security stream; the appliance has no hardware needing newer drivers. |
| Package sources | `archive.ubuntu.com` / `security.ubuntu.com` (noble, noble-updates, noble-security) + **Docker's apt repo** `download.docker.com/linux/ubuntu noble stable` (the same source `scripts/install.sh` uses). No snaps: `snapd`, `lxd-installer`, `lxd-agent-loader` are purged at bake. | One OS package stream and one engine package stream, both signed and both scriptable for maintenance; snaps would add a third auto-updating channel the runbook could not govern. |
| Pinned, not "current" | The dated `release-20260926` URL + sha256, never `noble/current/`. | `current` moves; a rebuild must be byte-for-byte reproducible from the manifest. |

## 2. Inputs (all pinned in `appliance/manifest.env`)

| Input | Value | Verified by |
|---|---|---|
| Guest image | `https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img` | sha256 `6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2` (build refuses otherwise) |
| Guest package manifest | `…/ubuntu-24.04-server-cloudimg-amd64.manifest` | sha256 recorded in the build record (inventory for `sbom-cve/`) |
| Application image | `ghcr.io/kidcarmi/culvert@sha256:238ba99b61e1903485c4e86a2dbac33e12aa2bbc52a2861ee499f1825610347e` = catalog `culvert-1.0.259` `image.list_digest` | pulled **by digest**; `cosign verify` against `release_identity.env` (issuer + SAN regex) — build **refuses** on failure; verification output kept as `<name>.cosign-verify.json` |
| ClamAV image | `clamav/clamav:1.4` (the tag `docker-compose.yml` uses) pinned to `sha256:57deb108fc4c72778aa83eafbca7bb7153e28c3f57c005afd38d31f16da86f23` | image Id compared to the pin; a drifted tag fails the build until the manifest is bumped deliberately |
| Docker Engine | `docker-ce` / `docker-ce-cli` `5:29.8.2-1~ubuntu.24.04~noble`, `containerd.io` `2.3.6-1~ubuntu.24.04~noble`, `docker-compose-plugin` `5.5.1-1~ubuntu.24.04~noble` | apt-resolved at exact versions inside a throwaway `ubuntu:24.04` container; every `.deb` sha256 in the build record; Docker's apt signing key shipped to the guest |
| Deploy bundle + agent | come out of the application image (`/app/deploy`, `/app/deploy/bin/culvert-maint`) — **not** a separate input | identity = the image digest |
| `scripts/install.sh`, `release_identity.env` | vendored from the repo commit the build runs at | git commit + sha256 in the build record |
| Virtual hardware | 2 vCPU, 4096 MB, 40 GiB thin disk, VMX-10, BIOS, pvscsi, vmxnet3 | `manifest.env` (`VM_*`, `DISK_SIZE_GB`) |

## 3. Outputs (`appliance/build.sh --out DIR`)

```
<out>/culvert-appliance-<ver>.ova                      ustar: .ovf, .mf, -disk1.vmdk (OVF 1.1 order)
<out>/culvert-appliance-<ver>/culvert-appliance-<ver>.ovf
<out>/culvert-appliance-<ver>/culvert-appliance-<ver>.mf          SHA256(<file>)= <hex> lines
<out>/culvert-appliance-<ver>/culvert-appliance-<ver>-disk1.vmdk  streamOptimized, lsilogic descriptor
<out>/culvert-appliance-<ver>/culvert-appliance-<ver>.qcow2       compressed qcow2 for KVM/QEMU users
<out>/culvert-appliance-<ver>.sha256                   sha256sum of every output
<out>/culvert-appliance-<ver>.build-record.json        EVERY input digest/version + tool versions + output digests
<out>/culvert-appliance-<ver>.bake-serial.log          serial console of the bake VM (audit trail)
<out>/culvert-appliance-<ver>.cosign-verify.json       the cosign verification of the application image
```

The guest itself carries `/etc/culvert-appliance/build-inputs.json` (the input half of the build record),
`manifest.env`, `bake.env` (engine/compose/kernel versions as installed) and `dpkg-list.tsv`.

## 4. Build pipeline

Script-based, bash + cloud-init NoCloud + QEMU. No packer (no apt candidate on the build host, and it would
add nothing: the whole build is "boot the stock image once with a seed and a payload disk, then flatten").

```
fetch    guest .img ──sha256──┐
         app image ──digest+cosign──► docker save (locally tagged ⇒ RepoDigest survives load)
         clamav image ──digest──►      docker save
         docker-ce .debs ──apt pin──►  Packages.gz index (+ Docker apt key)
payload  genisoimage -r -l -V CULVERT_PAYLOAD  (images/, debs/, appliance/{guest,bake,manifest.env}, vendor/install.sh, build-inputs.json)
bake     qemu-system-x86_64 -machine q35 -smp 2 -m 3072 -netdev user,restrict=on   ← NO network
           disk   = qcow2 overlay (40G) on the guest image
           cdrom1 = NoCloud seed (appliance/bake/{user-data,meta-data})  → runs appliance/bake/bake.sh
           cdrom2 = payload ISO
         bake.sh: apt install docker-ce from the payload repo → daemon.json (containerd image store, live-restore,
           log rotation) → docker load + verify Ids == manifest digests → install first-boot/console/CLI/units →
           purge snapd → record versions/dpkg list → scrub ssh host keys, machine-id, cloud-init state, bake user,
           logs → fstrim → "CULVERT_BAKE_OK" on serial → poweroff
package  qemu-img convert -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic
         qemu-img convert -O qcow2 -c
         OVF from appliance/ovf/culvert-appliance.ovf.tmpl (placeholders: name, version, vmdk file/size,
           disk capacity, vCPU, MiB, app version/digest) → .mf → tar --format=ustar → sha256 → build record
```

Why an **offline** bake: the build VM gets every input from the payload disk, so (a) the build is reproducible
from the manifest alone, (b) it runs identically on a laptop, a CI runner or behind a corporate proxy (only
the host-side `fetch` stage talks to the network, and it honours `HTTP(S)_PROXY` / `BUILD_PROXY_CA_BUNDLE`),
and (c) no proxy CA or credential can leak into the image because the guest never had any.

Why images are loaded **at bake** rather than at first boot: the preloaded images are then part of the
disk image the OVA manifest/sha256 covers, and first boot only has to verify `docker image inspect … .Id`
against `build-inputs.json` (an offline integrity check) before handing over to `scripts/install.sh`.

### Exact commands

```bash
# Build host prerequisites (Ubuntu 24.04 shown): a docker daemon, cosign, qemu, cloud-image-utils, genisoimage.
sudo apt-get install -y qemu-utils qemu-system-x86 cloud-image-utils genisoimage
curl -sSL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 && chmod +x /usr/local/bin/cosign

# Full build (auto-picks KVM when /dev/kvm is writable, else TCG — TCG works, ~20–40 min bake on 4 cores)
appliance/build.sh --out /var/tmp/culvert-appliance-out
# Rebuild only the packaging stage from an existing bake / reuse fetched inputs:
appliance/build.sh --out /var/tmp/culvert-appliance-out --skip-fetch --skip-bake

# Verify a delivered OVA
sha256sum -c culvert-appliance-<ver>.sha256
tar -xf culvert-appliance-<ver>.ova && sha256sum -c <(sed -E 's/^SHA256\((.*)\)= (.*)$/\2  \1/' culvert-appliance-<ver>.mf)
```

CI: a workflow can run exactly `appliance/build.sh` on an x86_64 runner (KVM-enabled runners make the bake
fast; without KVM it still completes under TCG). Not added in this slice — see ASTRA-STATUS.md.

## 5. Reproducibility notes

* Everything that enters the guest is pinned by digest/version in `manifest.env` and recorded in the build
  record; a rebuild from the same manifest installs the same package set and the same images.
* Byte-identical disk images are **not** claimed: timestamps inside the guest (apt/dpkg logs, journal, file
  mtimes, `bake.env`), ext4 metadata and qcow2/VMDK compression make two bakes differ at the byte level.
  Equivalence is asserted at the **inventory** level: `/etc/culvert-appliance/dpkg-list.tsv` and the preloaded
  image Ids must match between two builds of the same manifest.
* `repo_dirty: true` in the build record means the vendored `install.sh`/guest files came from an uncommitted
  tree; a release build must show `false`.

## 6. Size expectations

Guest image 597 MiB (qcow2) + docker-ce payload 131 MiB (.debs, only the needed subset installs) + application
image OCI archive 31.4 MiB + ClamAV image 146 MiB (includes the signature DB) → VMDK (streamOptimized,
compressed) on the order of 1.3–1.8 GiB. Measured figures: `docs/appliance/ASTRA-STATUS.md`, Track F.
