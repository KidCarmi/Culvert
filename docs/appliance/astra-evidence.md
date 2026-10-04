# Appliance track — executed vs blocked evidence (Astra, 2026-10-02)

Honest record of what was actually run on the build host for this track, with
results, and what could not be run, with the exact command and prerequisite.
Nothing documented-but-not-executed is reported as passed.

Build host: Ubuntu 24.04.4 container, 4 vCPU, 15 GB RAM, Docker 29.6.2
(containerd image store), **no `/dev/kvm`** (libguestfs/qemu run under TCG),
outbound HTTPS through a policy proxy (CA bundle honoured; GitHub release
pages/API are policy-blocked, ghcr.io / Docker Hub / cloud-images.ubuntu.com /
download.docker.com / Sigstore are reachable). Repo HEAD during the work moved
from `3fcc07e` to `2ee72ac` (coordinator commits); all paths below are relative
to the repo root.

## Files created (all inside the owned paths)

| File | Purpose |
|------|---------|
| `appliance/README.md` | index |
| `appliance/build/manifest.env` | every pinned input (base image SHA256/serial/GPG key, Docker .deb versions + repo key, image index/amd64 digests, cosign identity, VM sizing) |
| `appliance/build/build-ova.sh` | the reproducible build driver (shellcheck-clean) |
| `appliance/build/prepare-guest.sh` | in-guest customization run by libguestfs (shellcheck-clean) |
| `appliance/build/culvert-appliance.ovf.tmpl` | OVF descriptor template (vmx-13, 2 vCPU/4 GB/40 GB thin, E1000, OVF properties, guestInfo+iso transport) |
| `appliance/provision/culvert-firstboot.sh` + `.service` | idempotent, resumable first boot (ovf → console → images → install → complete) |
| `appliance/provision/culvert-status`, `culvert-issue-update`, `culvert-issue.service/.timer` | console readiness status + `/etc/issue.d` banner |
| `appliance/provision/culvert-net` | DHCP/static netplan helper for the console |
| `appliance/provision/culvert-appliance-reset-identity` | pre-clone identity reset |
| `appliance/provision/nftables.conf`, `sshd-50-culvert.conf`, `cloud-90-culvert.cfg` | firewall (22/8080/9090), key-only SSH, cloud-init policy (default user `culvert`, OVF/NoCloud/VMware datasources) |
| `appliance/os-maintenance/50unattended-upgrades-culvert`, `20auto-upgrades-culvert`, `culvert-os-update` | security-only auto-updates, no auto-reboot; operator update/reboot tool |
| `appliance/sbom/README.md`, `appliance/sbom/evidence/*` | 2 CycloneDX SBOMs, 2 trivy JSON + 2 table reports, `tool-versions.txt`, `summary.txt` (916 KB total) |
| `docs/appliance/ova-build.md`, `hypervisor-install.md`, `first-boot.md`, `os-maintenance.md`, `sbom-cve-evidence.md`, `astra-evidence.md` | documentation |

No file outside `appliance/**` and `docs/appliance/*` was modified.

## Design choices and assumptions

* **Guest OS: Ubuntu 24.04 LTS** (standard security maintenance to 2029-04,
  ESM to 2034-04). Debian 12 was rejected because it entered LTS-only
  maintenance in 2026-06. x86_64 only.
* **Pre-bake strategy:** Docker CE 29.8.2 + compose 5.5.1 installed from
  Docker's repo at build time (pinned, `apt-mark hold`); the proxy image
  (`v1.0.259`, by index digest, cosign-verified at build) and `clamav/clamav:1.4`
  are `docker save`d into `/var/lib/culvert-appliance/images/` and
  `docker load`ed at first boot. **Measured:** with the containerd image store
  a save/load round-trip keeps the image's index digest *and* `RepoDigests`
  (`ghcr.io/kidcarmi/culvert@sha256:238ba99…`), so `scripts/install.sh`'s own
  `verify_pinned_image_signature` cosign gate works unchanged on the loaded
  image — the appliance passes **no** `CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE`
  break-glass. The guest daemon is pinned to that store in `daemon.json`.
* **First boot reuses `scripts/install.sh` verbatim** (copied into the image at
  build; SHA256 recorded). Environment it is run with (from `/`, stdin
  `/dev/null`, `HOME=/root`):
  `CULVERT_DIR=/srv/culvert`,
  `CULVERT_PROXY_SEED_REF=ghcr.io/kidcarmi/culvert:v1.0.259` (tag restored by
  `docker load`; install.sh takes the local image, no registry pull),
  `CULVERT_INSTALL_ASSUME_DOCKER=1` (**depends on Fable's install.sh change**;
  until it lands the preflight simply requires `download.docker.com` to be
  reachable, which an online appliance satisfies), `CULVERT_INSTALL_CHANNEL=stable`.
  Non-interactive install.sh auto-generates the CA/log passphrases into
  `/srv/culvert/.env`; `env_put` never overwrites an existing value (verified
  by reading `setup_at_rest_encryption`/`env_put`), so re-runs are safe.
* **No shared secrets:** console user `culvert` is locked in the image (verified
  from outside the guest by the build: `/etc/shadow` entry begins `culvert:!`);
  per-instance credential via OVF `password`/`public-keys` (cloud-init), else a
  one-time random console password printed to `/dev/console` with forced
  change (only when no key either). SSH key-only, `AllowUsers culvert`, no root.
* **Readiness semantics in `culvert-status`:** `/health` 200 ⇒ "services
  running"; `GET https://127.0.0.1:9090/api/setup/status` `needsSetup=false`
  ⇒ "setup complete"; `/ready` 200 + `policy_loaded=ok` + (`ca` row absent or
  `ok`) ⇒ "ready to enforce". Parses the `checks` map when present.
* **Firewall:** nftables `inet culvert` input-drop table; Docker's own tables
  untouched (published ports traverse FORWARD/NAT). ufw left installed/inactive.
* **Admin UI TLS replacement:** documented via the existing Certificates panel
  upload (`POST /api/certs/upload` target `ui`, persisted in `/data`,
  `ui_tls_custom.go`) as preferred; `-tls-cert/-tls-key` (flags read in
  `main.go` lines 287-288, `proxy.tls_cert/tls_key` YAML) as the alternative.
* **Reproducibility claim:** input-pinned, not bit-for-bit (apt writes
  timestamps inside the guest). Documented in `ova-build.md`.
* **Build environment accommodation:** supermin needs a kernel in
  `/boot` + `/lib/modules`; this container had none, so
  `apt-get install linux-image-virtual` was run on the build host (documented
  prerequisite, not part of the image).

## EXECUTED (commands actually run, with results)

| # | Command (abridged) | Result |
|---|--------------------|--------|
| 1 | `apt-get install qemu-utils libguestfs-tools qemu-system-x86 shellcheck genisoimage` | OK (qemu-img 8.2.2, virt-customize 1.52.0, shellcheck installed) |
| 2 | `libguestfs-test-tool` (first run) | FAILED: `supermin: failed to find a suitable kernel` (container has no `/boot`, `/lib/modules`) |
| 3 | `apt-get install linux-image-virtual` → `libguestfs-test-tool` | **TEST FINISHED OK**, 33 s, `accel=kvm:tcg` (TCG in use) |
| 4 | `curl …/release-20260926/SHA256SUMS{,.gpg}`; `sha256sum -c`; `gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg` | image `ubuntu-24.04-server-cloudimg-amd64.img` (625 MB) **SHA256 OK**; **Good signature** from "UEC Image Automatic Signing Key", RSA key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81 |
| 5 | `curl download.docker.com/linux/ubuntu/dists/noble/stable/binary-amd64/Packages` + `gpg --show-keys` of the repo key | pins: docker-ce/cli 5:29.8.2, containerd.io 2.3.6, compose-plugin 5.5.1 (`…-1~ubuntu.24.04~noble`); key fpr 9DC8…CD88 |
| 6 | `docker manifest inspect ghcr.io/kidcarmi/culvert:v1.0.259`; `docker image inspect` | index `sha256:238ba99b…`, amd64 `sha256:f714e55b…` (matches Fable's digest), arm64 present; image labels `org.opencontainers.image.revision=31a7562f…`, created 2026-09-30 |
| 7 | `docker create/cp` of `/app/deploy`; `./culvert-maint -version` | bundle = compose files + packaging/ + bin/culvert-maint; agent reports **v1.0.259**; `/app/VERSION` = v1.0.259 |
| 8 | `docker pull clamav/clamav:1.4`; manifest inspect | index `sha256:57deb108…`, amd64 `sha256:da8463f6…`, 152 MB |
| 9 | `cosign verify` (ghcr.io/sigstore/cosign/cosign:v3.0.6, keyless, pinned issuer + SAN regex) of the proxy image by digest | **Verified** (claims validated, Rekor inclusion verified offline, cert chain to trusted CA) — Sigstore endpoints reachable through the proxy |
| 10 | `docker save` → `docker rmi` → `docker load` of the proxy image | loaded `Id` = index digest, **`RepoDigests` preserved** (`ghcr.io/kidcarmi/culvert@sha256:238ba99…`), tag restored |
| 11 | `syft docker:<proxy@digest> -o cyclonedx-json`; same for clamav | 934 and 789 components (`appliance/sbom/evidence/*.cdx.json`) |
| 12 | `trivy image --download-db-only` (via proxy) | DB v2 UpdatedAt 2026-10-02T06:55:51Z |
| 13 | `trivy image --scanners vuln,secret --format json` and `--format table` on both images | proxy image: alpine 0, Go binary 1 (GO-2026-5932, UNKNOWN, unfixed), culvert-maint 0, secrets 0; clamav: CVE-2026-103111 HIGH pcre2 (fix 10.49-r0), CVE-2026-58055 MEDIUM nghttp2 (fix 1.70.0-r0), secrets 0 |
| 14 | `shellcheck -x` on all 8 shell files; `bash -n`; `nft -c -f nftables.conf`; YAML parse of the cloud-init cfg; XML parse of the OVF template | all clean / parse |
| 15 | unit run of the OVF property parser against a sample `ovf-env.xml` | hostname, mode, address, gateway, dns extracted; absent key → empty |
| 16 | `culvert-status --json/--brief`, `culvert-net show` on the build host (no proxy) | correct "provisioning (incomplete)" state, HTTP code `000`, default-route interface selected |
| 17 | `virt-copy-out`/`virt-cat`/`virt-ls` of the base image | cloud-init 26.1 `DataSourceOVF` keys confirmed (`instance-id`, `hostname`, `public-keys`, `password`, `user-data`, `network-config`; transport `guestinfo.ovfEnv` or ISO); base image ships **no** SSH host keys, empty machine-id, ships iptables/nftables/open-vm-tools/unattended-upgrades/ufw |
| 18 | `appliance/build/build-ova.sh --work … --out … --keep-work` (run 1) | failed at `build-info.json` (shell `true` in Python) → fixed (env-passed values) |
| 19 | run 2 | failed: `virt-customize --run` executes the script with `/bin/sh` (dash): `set: Illegal option -o pipefail` → fixed (`--run-command "bash …"`); steps 1–6 of the pipeline (base SHA256+GPG, pulls, amd64 assertion, cosign, saves, build-info, 40 G qcow2) all succeeded in ~2 min |
| 20 | run 3 (after fix) | see "Build run status" below |

## Build run status

Every run is `build-ova.sh --work … --out … --keep-work` on the sandbox build
host (no KVM — the guest customization runs under TCG, ~8 min per attempt
once the base image, pulls and cosign verification are cached). Steps 1–3
(base SHA256 + GPG, image pulls by digest, amd64 assertion, cosign-verified
proxy image, `docker save`, `build-info.json`) succeeded on every run from
run 2 onward; the history below is the in-guest customization step.

| Run | Outcome | Cause → fix |
|-----|---------|-------------|
| 3–6 | failed inside `prepare-guest.sh` (apt/curl could not reach HTTPS origins) | the sandbox forces an intercepting HTTPS proxy on the build host; the guest first tried the proxy at the QEMU-documented `10.0.2.2`, but libguestfs' slirp uses `169.254.x.x` with the host at the guest's default gateway → the guest now DERIVES the gateway from `ip -4 route show default`, and the build CA is passed through for the build only (both stripped in step 5 and re-checked from outside the guest) |
| 7 | failed: `No space left on device` during the Docker install | `qemu-img resize` grows the virtual disk but the cloud image's 2.4 GB root partition is only grown by cloud-init at FIRST BOOT → `virt-resize --expand /dev/sda1` grows it at build time |
| 8 | the customization COMPLETED (verified from outside the guest: Docker pinned packages present in `dpkg-list.txt`, both image tarballs saved, `/var/log` truncated, no proxy/CA residue, empty `machine-id`) but `build-ova.sh` reported "did not finish" | the driver grepped the HOST-side virt-customize log for the script's last line, and virt-customize shows a `--run-command`'s output on the host only when the command FAILS → the script now writes its own transcript (`prepare-guest.log`) and a completion marker (`prepare-guest.done`) under `/var/lib/culvert-appliance`, and the driver reads both back with `virt-cat` (the only success signal it trusts) |
| 8 → 9 (pre-validation, no new run) | stages 5–6 (outside-the-guest residue checks, streamOptimized VMDK, OVF render, `.mf`, tar) were exercised against a COPY of the run-8 disk with the marker + a minimal transcript injected via `guestfish` | every guest check passed (pinned docker-ce, empty machine-id, no host keys, no proxy/CA residue, locked console account); the VMDK conversion took 8 min; the OVF render then FAILED its own `assert "@@" not in t` because the template's leading XML comment literally said `@@TOKENS@@` → comment reworded (the guard is kept: it is what caught this); the fixed template was in place before run 9 reached stage 6 |
| 9 | **SUCCEEDED — the first complete end-to-end OVA build of the track.** `culvert-appliance-1.0.259-ubuntu-24.04.ova`, 1,137,305,600 bytes, SHA256 `87c9b32f28686d200522859c07d86e75e128ed6daa9b3b33f348728f51e81382` (equal in `.ova.sha256` and `build-info.json` → `artifact.sha256`); `real 20m58s` under TCG, `BUILD_EXIT=0` (`build-ova9.log`). Milestones: base SHA256 + GPG → pulls by digest + amd64 assert → cosign verified (keyless, pinned identity) → `docker save` ×2 → `virt-resize` → `prepare-guest.sh completed in the guest at 2026-10-02T20:44:51Z` (marker read back by `virt-cat`) → outside-the-guest checks OK → streamOptimized VMDK → OVF → `.mf` → tar. The first attempt at run 9 (`build-ova.log`, 20:31) died at `virt-resize: guestfs_launch failed` because two builds had been launched into the SAME `--work` dir a minute apart (the second `rm -f`/`qemu-img create` pulled the disk from under the first) — `build-ova.sh` now takes an `flock` on the work dir and refuses a second run. | Acceptance checklist run against the artefact (`ova-verify/acceptance.txt`): exactly `.ovf`, `-disk1.vmdk`, `.mf` in that order, owner 0/0, mtimes = `SOURCE_DATE_EPOCH`; `.mf` digests equal `sha256sum` of the extracted members; VMDK `createType="streamOptimized"`, `ddb.adapterType = "lsilogic"`, 1,137,288,192 bytes = `ovf:size`; OVF `ovf:capacity="40"` (`byte * 2^30`), `populatedSize` set, `vmx-13`, `ovf:transport="com.vmware.guestInfo iso"`, 2 vCPU / 4096 MB, zero `@@`, minidom-clean; `prepare-guest.log` ends `prepare-guest: done`, no `E: ` lines, no build-host address or port; inside the disk `prepare-guest.{done,log}`, `images/`, `build-info.json`, `dpkg-list.txt`, `host-components.txt` present and `state/` EMPTY (first boot must run), no `/home/culvert/.ssh`. Still NOT done: booting it (no KVM) and the vSphere import. |

## Candidate build from the PR-head CI image (round 3, 2026-10-03)

`build-ova.sh --candidate-image-tar` (see `ova-build.md` §Candidate builds)
was run on this host against the preserved Deep PR Gate artifact
`deep-gate-image` of run 37065478520 (head `6b26b34`; `culvert-image.tar`
sha256 `ddb59654ec6ce0e9c388fbb26b0a05a665407769175c739aed88c8ea8935a2eb`),
with `--candidate-allow-provisioning-drift` because the provisioning files
come from the round-3 checkout (the CI lane builds both from one SHA; here
the image predates the round-3 commits). The guest layer additionally
exercised the new pinned-snapshot security upgrade (`GUEST_APT_SNAPSHOT=20261002T120000Z`).

| Run | Outcome | Cause → fix |
|-----|---------|-------------|
| c1 | virt-customize completed its work (`Finishing off` at 614 s) and the driver then died with `line 366: …/virt-customize.log: Permission denied`, exit 126 | **operator error, not a product defect**: `build-ova.sh` was edited (header comment + evidence extraction) while this run was executing it, and bash reads a script incrementally — the shifted offsets made it execute a fragment. The run was discarded; the standing rule is the one the script's own flock already implies: never edit a build script while a build runs |
| c2 | the snapshot upgrade **succeeded** inside the guest — 36 packages unpacked/set up from `snapshot.ubuntu.com` at `20261002T120000Z`, including `openssl`/`libssl3t64` 3.0.13-0ubuntu3.15 → **3.0.13-0ubuntu3.16** (the two HIGH findings), `dracut-install`, `libevent-core`, `libheif*`, `libxpm4`, `python3-jwt`, `python3-requests`, and `linux-libc-dev`/`linux-tools-common` 6.8.0-142 → 6.8.0-146 (header/tooling packages; **no new kernel image**, as designed) — then `prepare-guest.sh` exited non-zero in the evidence step: `diff` exits 1 when the lists differ, which `set -o pipefail` turned into an abort | `comm` instead of `diff` (exit 0 on differences), moved-count grep guarded (`184edfe`) |
| c3 | **SUCCEEDED** — `culvert-appliance-dev-candidate.6b26b3402253-ubuntu-24.04.ova`, 1,180,559,360 bytes, SHA256 `a51f231686bf837a78e332fe8866cbc5bcd12e06e7a44e7fad9f17c26154f076` (`cand-build3.log`, ~26 min under TCG). Provenance in `build-info.json` (`appliance/sbom/evidence/candidate-6b26b34.build-info.json`): `candidate: true`, image source `6b26b34…`, provisioning `184edfe…` (`provisioning_drift: true`, allowed explicitly), image tar sha256 `ddb59654…`, CI run 37065478520, `application.cosign: "not applicable — CANDIDATE build from an unsigned CI artifact…"`. Read back from the disk with `virt-cat`/`virt-ls`: the guest manifest carries `CANDIDATE_BUILD=1` and the candidate image pins AFTER the release pins (later keys win), `/opt/culvert-appliance/bin` + `/usr/local/sbin` carry `culvert-sudo-policy` and `culvert-firstboot`, the shipped `install.sh` handles `CULVERT_INSTALL_SETUP_TOKEN`. The pinned-snapshot upgrade moved 13 packages (`guest-os-candidate-6b26b34.build-upgrades.txt`): `openssl`/`libssl3t64` → 3.0.13-0ubuntu3.16 (the two HIGHs), `dracut-install`, `libevent-core`, `libheif*`, `libxpm4`, `python3-jwt`, `python3-requests`, `sosreport`, `linux-libc-dev`/`linux-tools-common` → 6.8.0-146 (no new kernel image). **Still NOT done: booting it** (no KVM) — the artefact exists to be booted on the pilot hypervisor, not to be shipped | — |

## Final candidate build (closeout, 2026-10-03) — image and provisioning from ONE commit

The round-3 candidate (`6b26b34`) predates the restore, agent and feed-sync
fixes, so it was superseded. `build-ova.sh --candidate-image-tar` was run
against the Deep PR Gate artifact `deep-gate-image` of run **37124197333**
(head `4c4b772`; `culvert-image.tar` sha256
`bb8a2c75369ca3397aaf84566eeee6222f30ca5c3b791de7d60bfecac9a8c3a4`, artifact
zip digest `4900e510…`), from a clean worktree checked out at the SAME commit,
so `provisioning_drift: false` — no drift flag was needed.

| Run | Outcome |
|-----|---------|
| c4 | **SUCCEEDED** — `culvert-appliance-dev-candidate.4c4b7728c0e6-ubuntu-24.04.ova`, 1,223,895,040 bytes, SHA256 `e24eb542f973fb70360bad5124ef81fdab8b6f8d67af601720613cbcca3700a4` (equal in `.ova.sha256` and `build-info.json` → `artifact.sha256`), ~26 min under TCG. Provenance (`appliance/sbom/evidence/candidate-4c4b772.build-info.json`): `candidate: true`, image source AND provisioning `4c4b7728c0e6a1746e968d935b635fc652647e6f`, `git_dirty: false`, image tar sha256 `bb8a2c75…`, CI run 37124197333, application image id inside the guest `sha256:384f4c4b1bad91be93dc8b78adb974b6c57dd9b4c8f534bfdbafc2c1e4f1ab04` (containerd store: the OCI manifest digest), ClamAV pinned `clamav/clamav:1.4@sha256:57deb108…` (unchanged), Docker 5:29.8.2 / containerd 2.3.6 / compose 5.5.1 (pins unchanged). Snapshot `20261002T120000Z` moved the same 13 packages as c3 (`guest-os-candidate-4c4b772.build-upgrades.txt`); the kernel image stays `6.8.0-142` (`/boot` read back with `virt-ls`). Guest re-scan of THIS artefact: `sbom-cve-evidence.md` §Final candidate. **Still NOT done: booting it** — `vsphere-qualification.md` is the procedure. |

**Superseded: c4 does not boot under BIOS (historical record, kept).** The
QEMU appliance lab (`test/appliance-lab`) booted c4's own disk under SeaBIOS
and it stopped at `error: no such partition. Entering rescue mode... grub
rescue>`; under UEFI the same disk reaches the kernel. Cause: the build's
`virt-resize` renumbered the partitions under the BIOS GRUB core image. Its
ESXi result is BLOCKED and stays so: the file exists only on the host that
built it, with no permitted transfer route. The replacement candidate is
built from the corrected source with its own identity (`readiness-report.md`
§3f).

**Superseded: `60a73475…` (source `78e1bc56`) never runs first boot
(historical record, kept).** It boots under BIOS (the fix above holds), then
systemd deletes `culvert-firstboot.service`'s start job to break an ordering
cycle with cloud-init's `cloud-final.service`; c4 carries the same unit, so it
would have stopped there too once booted. Fixed in the unit's ordering
(`readiness-report.md` §3f L5–L6); the replacement is built from the head that
carries the fix.

**Superseded: `e85e3640…` (lab variant, 78e1bc56 image + the first-boot fix)
cannot start ClamAV (historical record, kept).** First boot runs, then Compose
cannot create ClamAV: the baked `clamav.tar.gz` held only the image's index and
manifests (69,562 bytes). Loading the candidate image archive before pulling
ClamAV made every later ClamAV save hollow; the build now saves ClamAV first
and refuses any archive that does not carry and run its pinned image
(`readiness-report.md` §3f L8–L10). c4's archive was complete (152,380,114
bytes).

Commits after `4c4b772` change only the qualification harness, evidence and
documentation (verified with `git diff --stat 4c4b772 HEAD` at the closeout
commit: no Go source, Dockerfile, compose file, `appliance/build/`,
`appliance/provision/`, `appliance/os-maintenance/`, `packaging/` or
`scripts/` path), so the artefact's source identity remains `4c4b772` and it
was not rebuilt.

## BLOCKED (exact command + prerequisite)

| Item | Command that would do it | Prerequisite missing here |
|------|--------------------------|---------------------------|
| Boot the built disk at native speed / in the target hypervisor | `qemu-system-x86_64 -enable-kvm -m 4096 -smp 2 -cpu host -drive file=culvert-appliance-1.0.259-ubuntu-24.04.qcow2,if=virtio -cdrom seed.iso -nic user,hostfwd=tcp::2222-:22,hostfwd=tcp::9090-:9090 -nographic` | `/dev/kvm` (no hypervisor in this container) |
| Import + first boot on vSphere (the declared supported platform) | `ovftool --acceptAllEulas --diskMode=thin --prop:public-keys="$(cat key.pub)" culvert-appliance-1.0.259-ubuntu-24.04.ova vi://user@vcenter/DC/host/Cluster` then console/`culvert-status` | an ESXi 7+/vCenter target; `ovftool` |
| End-to-end first-boot run of `install.sh` inside the appliance (ClamAV ~250 MB download, compose `--wait`, maintenance-agent cosign gate) | implied by the two rows above | a booted guest (KVM or hypervisor); install.sh's `CULVERT_INSTALL_ASSUME_DOCKER` support (Fable) |
| ~~Guest-OS CVE scan of the built disk~~ — DONE on run 9 (`sbom-cve-evidence.md` §(c)); note `trivy vm` cannot walk the streamOptimized VMDK, scan the raw-converted qcow2 | `trivy vm --scanners vuln --format json --output guest-os.trivy.json <disk.vmdk>` (trivy `vm` is experimental; raw/VMDK input) | a finished build artefact (see build status) |
| trivy/syft as native binaries | GitHub release download | github.com `/releases/*` and api.github.com are policy-blocked (403) — used the official container images instead (versions recorded) |
| VirtualBox/KVM import qualification | — | out of pilot scope; documented as unqualified |

## Requests to Fable (changes outside my paths)

1. **`scripts/install.sh`** — add `CULVERT_INSTALL_ASSUME_DOCKER=1` (or
   equivalent): when set and `docker` + `docker compose version` work, skip the
   `download.docker.com` reachability preflight (lines ~202-207) and the Docker
   repo/install step (§2). The first-boot service already exports it. Without
   it the appliance still installs as long as `download.docker.com` is
   reachable, but an egress-restricted site would fail the preflight for a
   package the image already has.
2. **`scripts/install.sh` (nice-to-have)** — print the resolved
   `verify_pinned_image_signature` reason class (verified / no-digest /
   unreachable / mismatch) in the agent-skipped warning so an appliance
   operator can tell a Sigstore egress block from a tampered image. Currently
   deliberately undifferentiated (documented in the script); for an appliance
   the egress case is the common one.
3. **Release process** — when a new appliance is cut, publish `build-info.json`
   and the `.ova.sha256` with the OVA, and re-run `appliance/sbom` evidence
   (the trivy DB date is the dated part). No code change; ownership note.
4. **`docker-compose.yml` (observation, no change requested)** — ClamAV's
   `start_period: 300s` and install.sh's `--wait-timeout 330` bound the first
   boot; on a slow link the first `install` step fails and is retried by the
   unit (2-min backoff, 5/h). Documented in `first-boot.md`.

## Things the integration must know

* The provisioning does **not** need any new install.sh flag to run except
  request 1; everything else is existing behaviour (`CULVERT_PROXY_SEED_REF`
  local-image path, non-interactive passphrase generation, `/app/deploy`
  extraction, maintenance-agent cosign gate).
* First-boot state lives in `/var/lib/culvert-appliance/state/*.done`; the
  service has `ConditionPathExists=!…/complete.done`, so it never re-runs
  after completion, and `culvert-appliance-reset-identity` re-arms only the
  `console`/`access`/`ovf` steps and drops the source VM's operator keys
  (application state kept).
* The OVF declares `ovf:transport="com.vmware.guestInfo iso"`; cloud-init's
  OVF datasource and `culvert-firstboot` both read `guestinfo.ovfEnv`
  (`vmtoolsd`) or the `ovf-env.xml` ISO.
* `culvert-status` probes `https://127.0.0.1:9090/api/setup/status` with `-k`
  (self-signed admin cert) — read-only, loopback.
