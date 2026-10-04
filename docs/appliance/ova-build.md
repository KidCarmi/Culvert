# Culvert appliance — reproducible OVA build record

**Status (2026-10-02):** build path implemented and executed on a KVM-less
build host (libguestfs under TCG). What was actually produced and what was
blocked is in [`astra-evidence.md`](astra-evidence.md); this page is the build
contract.

## What the OVA is

A single-disk x86_64 virtual machine (`vmx-13`, 2 vCPU, 4 GB RAM, 40 GB thin
disk, one E1000 NIC) whose guest OS is **Ubuntu 24.04 LTS** (standard security
maintenance until **2029-04**, Ubuntu Pro ESM until 2034-04). Pre-baked into the
disk, all pinned in [`appliance/build/manifest.env`](../../appliance/build/manifest.env):

| Layer | Content | Pin |
|-------|---------|-----|
| Guest OS | Ubuntu `noble` cloud image, serial `20260926` | SHA256 + Ubuntu's GPG signature on `SHA256SUMS` |
| Container engine | `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-compose-plugin` from `download.docker.com` (`apt-mark hold`) | exact `.deb` versions + repo key fingerprint |
| Application | `ghcr.io/kidcarmi/culvert:v1.0.259` as a `docker save` tar, loaded at first boot | OCI **index digest** + asserted amd64 manifest digest; cosign keyless verification against the pinned release identity **at build time** |
| AV sidecar | `clamav/clamav:1.4` (as `docker-compose.yml` names it) as a tar | index + amd64 digests |
| Installer | `scripts/install.sh` from the building checkout (SHA256 recorded) | git commit in `build-info.json` |
| Provisioning | `appliance/provision/*`, `appliance/os-maintenance/*` | git commit |

Nothing per-instance ships in the image: no SSH host keys, empty
`/etc/machine-id`, the `culvert` console account is **locked** (no password, no
key), no proxy/apt residue from the build host. `build-ova.sh` re-checks each of
these from outside the guest before packaging and refuses to package otherwise.

The ClamAV **signature database** (~250 MB) is NOT pre-baked — it would be
stale by import time; the sidecar downloads it on first start (see first-boot).

## Build host requirements

* Linux, `qemu-img`, libguestfs (`virt-customize`, `virt-cat`, `virt-ls`),
  `docker` with daemon access, `curl`, `tar`, `gzip`, `sha256sum`, `python3`.
  Optional: `gpgv` + `/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg`
  (present on Ubuntu hosts) for base-image signature verification.
* The Docker daemon must use the **containerd image store**
  (`{"features":{"containerd-snapshotter":true}}`, the default on a fresh
  Docker 29 install). A classic store saves a re-created manifest without the
  registry digest, and the guest's first boot — which verifies the loaded
  image against the pinned digest — would refuse it. The build checks the
  archive it is about to bake (`archive-identity.sh`) and stops with that
  message instead of producing an OVA that cannot boot.
* The build must be able to run a **privileged container**: each saved image
  archive is cold-loaded into a disposable `docker:dind` store (pinned by
  digest, `COLDLOAD_DIND_IMAGE` in `manifest.env`) with no registry access,
  and a container is created and run from it before the archive is baked
  (`cold-load-check.sh`). A host that cannot run privileged containers cannot
  build the OVA.
* **No KVM required.** libguestfs falls back to TCG (`accel=kvm:tcg`); the
  in-guest package install then takes 10–30 minutes instead of ~2.
* A host **kernel package** must be installed (`/boot/vmlinuz-*` +
  `/lib/modules/*`) — supermin builds the libguestfs appliance from it. In a
  container that lacks one: `apt-get install linux-image-virtual` (that is what
  the 2026-10-02 build did).
* Outbound HTTPS to `cloud-images.ubuntu.com`, `download.docker.com`,
  `archive.ubuntu.com`/`security.ubuntu.com` (in-guest apt), `ghcr.io`,
  `registry-1.docker.io`, and the Sigstore endpoints
  (`fulcio.sigstore.dev`, `rekor.sigstore.dev`, `tuf-repo-cdn.sigstore.dev`)
  for cosign. The build honours `HTTPS_PROXY`/`SSL_CERT_FILE` for its own
  pulls/cosign only; nothing from them reaches the guest.
* `--work` is held by an `flock` for the whole run: a second build into the
  same directory is refused (two runs would recreate the working disk under
  each other); use a different `--work` to build in parallel.
* ~12 GB free in `--work` (base image, the working qcow2, VMDK).

## Running it

```bash
# from the repository root, on the commit being released
appliance/build/build-ova.sh --out appliance/build/out --work /var/tmp/culvert-ova
#   --skip-cosign        do not cosign-verify the proxy image (dev only; recorded in build-info)
#   --candidate-image-tar FILE --candidate-source SHA [--candidate-run-id ID]
#                        CANDIDATE build from a CI image tar (see below)
#   --stop-after disk    stop at the customized qcow2 (boot/test it; no VMDK/OVA)
#   --stop-after vmdk    stop after the streamOptimized VMDK
#   --keep-work          keep the working directory for inspection
```

Outputs in `--out`:

* `culvert-appliance-<version>-ubuntu-24.04.ova` and `.ova.sha256`
* `build-info.json` — guest OS + package sources, architecture, tool versions
  (qemu-img, libguestfs, docker, cosign image), application image digests and
  cosign result, host component versions (pinned Docker versions,
  `culvert-maint --version` taken from the image's deploy bundle), git commit
  + dirty flag, `SOURCE_DATE_EPOCH`, build timestamp, final OVA SHA256
* `dpkg-list.txt` and `host-components.txt` — the guest package inventory,
  captured inside the guest during the build (input for the SBOM evidence)
* `prepare-guest.log` — the in-guest customization transcript, read back out
  of the disk with `virt-cat` (libguestfs shows a `--run-command`'s output on
  the host only when the command fails, so this is the record of a build that
  succeeded; the same file ships in the image at
  `/var/lib/culvert-appliance/prepare-guest.log` beside `build-info.json`)

The OVA is a ustar archive in OVF order (descriptor, disk, manifest) with fixed
owner/mtime (`SOURCE_DATE_EPOCH`, default: the git commit time). The `.mf`
carries `SHA256(...)` lines for the descriptor and the VMDK, which vSphere
verifies on import.

## Pipeline (what `build-ova.sh` does, in order)

1. Source `manifest.env`; refuse to run if any pin is missing; check tools.
2. Download the base image into the work cache (or reuse it); verify the SHA256
   pin; when the keyring is present, `gpgv` the upstream `SHA256SUMS` and assert
   the pin is the signed value.
3. `docker pull <repo>@<index digest>` for both images; assert the resolved
   platform is `linux/amd64` and that the index's amd64 entry equals the pinned
   amd64 digest; tag `repo:tag` locally. ClamAV is pulled AND `docker save`d
   first, before any image archive is loaded: in a candidate build, loading the
   candidate tar into the same store made every later ClamAV save hollow
   (index and manifests, no config or layers — 69,562 bytes), whether saved by
   tag, digest or both (F-OVA-CLAMAV-1, `readiness-report.md` §3f; bisected in
   fresh disposable stores). Pinned by
   `TestBuildOVA_SavesClamAVBeforeLoadingTheCandidate`.
4. `cosign verify` (pinned `ghcr.io/sigstore/cosign/cosign:v3.0.6`, issuer +
   SAN regex identical to `scripts/install.sh` / `release_identity.env`) of the
   proxy image. Failure aborts the build.
5. Stage the overlay: the `docker save | gzip -n` archives of both images,
   `scripts/install.sh`, provisioning + maintenance files, `manifest.env`,
   `build-info.json`. Before either archive is recorded or baked, each must
   (a) carry the COMPLETE pinned image — `archive_platform_closure` walks from
   the pinned digest in `index.json` to the linux/amd64 manifest and requires
   its config and every layer with the declared size and sha256, so a complete
   but different image does not pass — and (b) RUN from its own content:
   `cold-load-check.sh` loads it into an empty disposable containerd store whose
   registry pull fails, checks the reference's ID and platform, creates a
   container with `--pull=never` and runs a binary from it
   (`culvert-maint -version`, `clamd --version`). A successful `docker load`
   alone proves nothing: the hollow archive "loaded" and first boot then could
   not create ClamAV.
6. Convert the base image to a 40 GB qcow2 and grow the root partition IN
   PLACE (`part-expand-gpt`, `part-resize /dev/sda 1`, `e2fsck`, `resize2fs`):
   the cloud image's root is 2.4 GB and cloud-init's `growpart` only runs at
   first boot, while the Docker install needs the space during the build. The
   build refuses to continue if any partition number or start changed. NOT
   `virt-resize`: it renumbers the partitions (14, 15, 16, 1 → 1, 2, 3, 4)
   while the BIOS GRUB core image still names `/boot` as partition 16, so the
   OVA stopped at `grub rescue>` under BIOS (found by the QEMU appliance lab;
   `readiness-report.md` §3f). Pinned by `TestBuildOVA_RootGrownInPlace`.
7. `virt-customize`: copy the overlay in, run
   [`prepare-guest.sh`](../../appliance/build/prepare-guest.sh) inside the guest
   (Docker repo key fingerprint check → pinned package install → hold →
   `daemon.json` with the containerd image store + live-restore → units,
   firewall, sshd/cloud-init drop-ins, locked `culvert` account → package
   inventory → identity strip). The script's LAST act is to write
   `/var/lib/culvert-appliance/prepare-guest.done`; that marker, read back with
   `virt-cat`, is the only success signal the driver trusts — never the
   host-side virt-customize output.
8. Outside-the-guest assertions (pinned `docker-ce` present, empty machine-id,
   no host keys, no proxy config, no authorized keys, console account locked).
9. `qemu-img convert -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic`,
   render the OVF from `culvert-appliance.ovf.tmpl`, write the `.mf`, tar.

## Reproducibility — what is and is not claimed

* **Input-pinned reproducibility (claimed):** two builds of the same
  `manifest.env` + commit install identical package versions, embed byte-identical
  image tars (same digests, `gzip -n`) and identical provisioning files, and
  their `build-info.json` differ only in `build_wallclock`, `build_tools`
  versions and the OVA checksum. The pins are the verification surface.
* **Bit-for-bit reproducibility (not claimed):** `apt-get install` inside the
  guest writes timestamps (`/var/lib/dpkg/*`, apt caches), so the VMDK — and
  therefore the OVA checksum — differs run to run. Verify an OVA against its
  `.ova.sha256`/`build-info.json` from the release, not by rebuilding it.
* The base image serial is pinned, so a newer Ubuntu cloud image is a manifest
  change, never a silent drift.
* **Guest security updates are pinned too.** `prepare-guest.sh` step 1b runs
  `apt-get upgrade` against the Ubuntu archive SNAPSHOT named by
  `GUEST_APT_SNAPSHOT` in `manifest.env` (`apt -o Acquire::Snapshot`,
  snapshot.ubuntu.com), so the base image's packages ship at a reviewed,
  dated state instead of the serial's — same manifest, same versions — and
  `build-upgrades.txt` next to the OVA lists what moved. `upgrade`, never
  `dist-upgrade`: no new kernel ABI is installed at build time; the kernel
  moves through `culvert-os-update os` after deployment. Raising the
  snapshot is a pin change like any other.

## Candidate builds (qualification of an unpublished image — never for customers)

`--candidate-image-tar FILE --candidate-source SHA [--candidate-run-id ID]`
builds the OVA from a `docker save` tarball instead of a signed release
pulled by digest — the Deep PR Gate's `deep-gate-image` artifact
(`culvert-image.tar`) is the intended input, so the OVA carries the
application, deploy bundle (compose, agent binary, packaging) **and** this
checkout's provisioning files from one source SHA. `--candidate-source` must
equal `HEAD` unless `--candidate-allow-provisioning-drift` is given, which
records both SHAs. What makes it a candidate and not a release:

* the image must carry the candidate stamp `vX.Y.Z-candidate.g<sha12>` naming
  `--candidate-source` (`.github/scripts/pr-candidate-version.sh`, set by the
  PR image build for the proxy AND the bundled agent); `build-ova.sh` refuses
  any other stamp, or an agent whose version differs, so the first boot can
  install that agent (§3f L11 of the readiness report). The OVA version is
  that stamp; the OVF product line and
  annotation say CANDIDATE / NOT FOR PRODUCTION, `build-info.json` carries a
  `candidate` object (image source SHA, provisioning SHA, drift flag, image
  tar SHA-256, CI run id) and `culvert-status` prints a banner on the guest;
* **signature verification is not bypassed** — an unsigned CI artifact has no
  signature to verify, and `build-info.json` records exactly that
  (`application.cosign: not applicable — CANDIDATE …`) instead of a skipped
  check;
* the only candidate-scoped trust decision is the maintenance agent:
  `install.sh` admits the bundled agent only for a cosign-verified image, so
  `culvert-firstboot` exports its break-glass
  `CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1` **only** when the guest manifest
  carries `CANDIDATE_BUILD=1`, logs it on every run and prints it on the
  console. A release OVA never sets it (`appliance_firstboot_test.go` pins
  both halves).

```bash
# from the preserved Deep gate artifact of PR head <sha>
unzip deep-gate-image.zip            # → culvert-image.tar
appliance/build/build-ova.sh --candidate-image-tar culvert-image.tar \
  --candidate-source <sha> --candidate-run-id <run id> --out out/
```

## Why Ubuntu 24.04 and not Debian 12 / Ubuntu 26.04

Debian 12 "bookworm" moved to LTS-only maintenance in 2026-06 (release
2023-06 + 3 years), so at pin time it no longer receives security-team updates.
Ubuntu 24.04 LTS has free security maintenance to 2029-04 and is the
release Docker's repository, `open-vm-tools` and cloud-init are all current on.
Ubuntu 26.04 LTS (2026-04) would extend the horizon by two years; it was not
chosen for the pilot because `scripts/install.sh`'s host-side testing and the
project CI run on 24.04. Moving is a manifest change plus a re-qualification.

## Updating the pins

| Pin | How to find the new value |
|-----|---------------------------|
| Base image | `https://cloud-images.ubuntu.com/releases/noble/` → newest `release-YYYYMMDD` → `SHA256SUMS` line for `ubuntu-24.04-server-cloudimg-amd64.img` |
| Docker packages | `https://download.docker.com/linux/ubuntu/dists/noble/stable/binary-amd64/Packages` (the build script's own `pull`/`apt` steps fail loudly on a typo) |
| Proxy image | the signed release catalog's `recommended` digest for the channel (`docs/operator/catalog-bootstrap-install-runbook.md`); `docker manifest inspect ghcr.io/kidcarmi/culvert:vX.Y.Z` for the amd64 entry |
| ClamAV | `docker manifest inspect clamav/clamav:1.4` |

A pin change is a reviewed commit; `build-info.json` of the resulting OVA is
the release record.
