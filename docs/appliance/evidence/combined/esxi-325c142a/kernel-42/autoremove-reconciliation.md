# The 34 `autoremove --purge` removals: reconciliation (read-only)

This answers the owner's reconciliation request (comment 6506229963). It **corrects** my "0 removals" in `DISPOSITION.md` §1: that claim came from a simulation that marked every non-kernel package as manually installed, so it tested kernel protection only.

## 1. What the 34 are, and that the 42 upgrade adds none

**List:** `autoremove-34.txt`, with shipped versions. It equals ASTRA's retained count and named packages: bpftrace, bpfcc-tools, linux-tools-common, development headers/libraries, ubuntu-kernel-accessories.

**Simulation:**
- Same isolated APT 2.8.3 root and signed indexes as `apt-indexes.txt`.
- Exact inventory.
- Realistic auto-marks: every package automatic, except the cloud-image seed metapackages (`ubuntu-minimal/standard/server`, cloud-init, openssh-server, grub/shim) and what the build installs explicitly (Docker ×4, pigz, psmisc, the HWE kernel meta, plymouth ×3, fontconfig). This marking is an assumption; it reproduces ASTRA's retained 34 and the QEMU run's actual 34 exactly.

| State | Removals |
|---|---|
| As shipped (38), before the upgrade | **34** |
| After the 42 upgrade | **34, identical set** |

**The 42 transaction contributes 0 removals.**

**Why they are orphans.** The build (`prepare-guest.sh` l.135–141) purges the GA kernel metapackage `linux-virtual` and then the stale 6.8 kernel packages. Nothing re-anchors what they held (installed reverse dependencies shown):

| Chain | Packages |
|---|---|
| `linux-virtual` (purged) used to Recommend `ubuntu-kernel-accessories`, which Recommends bpftrace and bpfcc-tools | ubuntu-kernel-accessories, bpftrace, bpfcc-tools, python3-bpfcc, libbpfcc, python3-netaddr, ieee-data, libllvm18, libclang1-18, libclang-cpp18 |
| bpftrace's Recommends `libc6-dev` | libc6-dev, libc-dev-bin, libc-devtools, libcrypt-dev, linux-libc-dev, rpcsvc-proto, manpages-dev; plus the image libraries pulled by `libc-devtools` → `libgd3`: libtiff6, libwebp7, libjpeg8, libjpeg-turbo8, libheif1 (+ aom plugins), libaom3, libxpm4, libdeflate0, libjbig0, liblerc4, libsharpyuv0 |
| `linux-tools-6.8.0-*` (purged as stale) | linux-tools-common, then hwdata |
| `snapd` (purged) | squashfs-tools (no installed reverse dependency) |

**Already exercised on these exact bytes.** In QEMU run 40555901182, step 7 ran `culvert-os-update os` on OVA 325c142a (`07-os-update.txt`, sha256 `7655550e…f0cc`, evidence artifact 12760932320):
- `0 upgraded` (42 was not yet in the archive), then autoremove: **`34 to remove`**;
- the removed names **equal this list exactly** (checked by script, symmetric difference empty).

Every later check in that run passed:

| Check | Result |
|---|---|
| reboot | 31 s |
| docker-held | engine 29.9.2 |
| stack-resumed | pass |
| enforcement | 200 / 403 |
| `/ready` | 200 |
| image-identity | pass |
| M2H `reboot-*` and `final-*` | pass |

**Harness wording defect (minor, recorded only):** that run's `os-update` check detail says "(0 package actions)". It counted the upgrade step only and undercounts the 34 removals. The verdict is unaffected.

## 2. Effect on guest tools and security

- **Function: no product dependency.**
  - None of the 34 is referenced by appliance provisioning, OS maintenance, boot splash, `scripts/install.sh`, the maintenance agent or packaging (source search at 0648adeb).
  - The appliance stack runs in containers and ships no build toolchain need.
  - QEMU step 8 confirms the product still works with them removed.
- **Operator diagnostics lost:**
  - the BPF tracing tools (`bpftrace`, the `bcc` tools);
  - `perf` support files (`linux-tools-common`);
  - C headers and man pages.

  These are root-only diagnostics. None is used by the Culvert runbooks.
- **Security: attack surface only shrinks; there is no new exposure.**
  - It removes LLVM/clang and the BPF tooling (root-only, but large).
  - It removes a C toolchain's headers.
  - It removes seven image-parsing libraries: libtiff, libwebp, libjpeg, libheif, libaom, libxpm, libgd. They are pulled in only by `libc-devtools`.
  - It removes `linux-libc-dev` and `linux-tools-common`. The exact scan attributes Linux kernel-source CVE rows to these two userspace packages (`findings.tsv`: 14 CRITICAL / 372 HIGH rows each; not the running kernel), so after `os` those rows disappear from a guest scan.
  - It removes nothing on the M2 path. The kernel's BPF settings (`unprivileged_bpf_disabled=2`, BPF LSM) are kernel configuration, not these userspace tools.
- **Postures:**

| Posture | Carries the 34? |
|---|---|
| As shipped (38) | Yes. The 34 are present at first boot. |
| After maintenance (38 or 42) | No. The first `culvert-os-update os` removes them, whether or not a kernel update is pending. |

  unattended-upgrades does not remove them: `Remove-New-Unused-Dependencies` only covers packages that become unused during its own run.

## 3. Corrected pre-`os` rule (replaces "0 removals")

Before `os`, on the console, read-only:
- `apt-get -s upgrade --with-new-pkgs` must show exactly the 5 kernel actions;
- `apt-get -s autoremove --purge` must show exactly the 34 of `autoremove-34.txt`.

**Any other set: STOP and report.**

## 4. Future-build items (recorded, nothing changed now)

1. **Snapshot pin** (`DISPOSITION.md` §6). Required for any future build:
   - use `APT::Snapshot` / `--snapshot`;
   - prove that the index URLs actually fetched are `snapshot.ubuntu.com/…/<id>/`;
   - fail closed when the snapshot is unavailable;
   - reconcile every shipped package version and hash against the pinned indexes, including the non-Ubuntu source (Docker) against its own pinned versions.
2. **Ship the maintained state** (owner decision). Run `autoremove --purge` at build after the metapackage purge, so the shipped image does not carry 34 orphans that the first `os` removes. This would make the first-boot and post-maintenance package sets equal, and drop the attributed scan rows from the shipped image.
