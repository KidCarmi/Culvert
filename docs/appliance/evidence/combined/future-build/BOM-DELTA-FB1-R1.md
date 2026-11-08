# BOM delta FB1-R1: perf/BPF diagnostic tooling removed, inventory gate added

INTERNAL-ONLY replacement candidate after QEMU campaign 2. Owner direction of 8 Nov 2026: OPUS owns the remediation, the builds and the tests; ASTRA accepts the candidate and route before any qualification. MERGE, PILOT and RELEASE remain NO-GO.

**Why.** Campaign 2 (lab run 42402656551, OVA `f9d68540…`) stopped at `E/kernel-cve-assumptions`, "perf tool installed". The image shipped `/usr/bin/perf`, the version-dispatch wrapper of `linux-tools-common`, together with the BPF tracing tools. No versioned perf build was installed, but the criterion forbids the command. The only earlier pass of this check (0648 OVA) came after that campaign's real OS update had autoremoved these packages.

**Scope.** Everything in `BUILD-BOM.md` still holds, except the rows below. The three values that cannot live in this file are recorded in the PR #1528 handoff, as for `BUILD-BOM.md`:
- the commit SHA;
- the commit's Deep gate image;
- the commit-stamped console.

## Changed rows

| BOM row | `BUILD-BOM.md` | FB1-R1 |
|---|---|---|
| §1 Build commit | the commit that adds `BUILD-BOM.md` (`0981ff3d`) | the `review/1528-m1-engine-pins` commit that adds this file. It is a fast-forward of `0981ff3d`. |
| §1 Line content | M1 + Q7 console + CI closure + FB-1 | the same, plus this delta: build scripts and their tests only. No application, console, sidecar, harness or dependency change. |
| §4 Package set | 680 | **668** = 680 − the 12 packages of `appliance/build/diagnostic-tooling-purge.txt`, at the versions below |
| §3 Inherited / acquired | 586 / 94 | **575 / 93** installed. The acquisition receipt still lists the `linux-tools-common 6.8.0-147.147` `.deb`, because the snapshot upgrade downloads it before the purge. Its bytes are verified like every other row. |
| §7 Outputs | the list in §7 | §7, plus the new outputs in the next section |

The application image, the bundled `culvert-maint`, the console and the sidecar are rebuilt from the new commit under the unchanged §2 and §5 requirements:
- **The stamp-free console** must still equal the hashes of `c88c0e76`, because the console source is unchanged.
- **The sidecar ID and the baked archive** must still equal §5, because `appliance/clamav/` is unchanged.

### Removed packages (all auto-installed from the base image except the first, which the snapshot upgrade raised to `-147`)

| Package | Version on `f9d68540` | Installed reverse dependencies outside the list |
|---|---|---|
| linux-tools-common | 6.8.0-147.147 | none |
| bpftrace | 0.20.2-1ubuntu4.3 | none |
| bpfcc-tools | 0.29.1+ds-1ubuntu7 | none |
| python3-bpfcc | 0.29.1+ds-1ubuntu7 | none (bpfcc-tools only) |
| libbpfcc | 0.29.1+ds-1ubuntu7 | none (bpftrace, python3-bpfcc only) |
| ubuntu-kernel-accessories | 1.539.2 | none |
| hwdata | 0.379-1 | none (linux-tools-common only) |
| python3-netaddr | 0.8.0-2ubuntu1 | none (bpfcc-tools only) |
| ieee-data | 20220827.1 | none (python3-netaddr only) |
| libclang-cpp18 | 1:18.1.3-1ubuntu1 | none (libbpfcc only) |
| libclang1-18 | 1:18.1.3-1ubuntu1 | none (bpftrace only) |
| libllvm18 | 1:18.1.3-1ubuntu1 | none (bpftrace, libbpfcc, libclang-cpp18, libclang1-18 only) |

**How the removal set was verified, on the exact retained `f9d68540` disk:**
- **Dependency graph.** The disk's own `/var/lib/dpkg/status` and `/var/lib/apt/extended_states` were read offline: 680 installed packages, 632 of them auto-marked. "Reverse dependencies" counts Depends, Pre-Depends and Recommends, with Provides resolved.
- **apt simulation.** `apt-get -s purge` of exactly these 12, against that status, removes exactly these 12.
- **Command coverage.** On that disk the inventory gate fails 11 rules. On the same inventory with the 12 packages and every file they own removed, it passes: 668 packages, 1,388 PATH entries.

**What the build enforces** (`prepare-guest.sh`, after the last pinned install):
- every listed package must be installed, so a stale list stops the build;
- the simulated purge must remove exactly the list;
- the purge is never an autoremove;
- these packages must still be installed afterwards:
  - the kernel metapackage, image and modules;
  - `ubuntu-server`, `open-vm-tools`, `cloud-init`, `unattended-upgrades`;
  - `openssh-server`, `nftables`, `apt`, `python3`;
  - the four Docker packages, `plymouth` and `plymouth-theme-ubuntu-text`;
- `/etc/apt/preferences.d/culvert-no-diagnostic-tooling` pins `linux-tools-* bpftrace bpfcc-tools python3-bpfcc libbpfcc ubuntu-kernel-accessories` at −1, verified to leave no candidate, so a later OS update cannot bring them back.

## New required outputs (§7 additions, identity step before any boot)

| Output | Requirement |
|---|---|
| `removed-diagnostic-tooling.txt` | exactly the 12 packages above |
| `inventory-gate-guest.txt` | `inventory gate: PASS`, written by the in-guest gate |
| `inventory-gate.txt` | `inventory gate: PASS`, written by the gate `build-ova.sh` runs from outside the guest on the finished disk, before the VMDK |
| `dpkg-list.txt` | 668 rows; none of the 12; no `linux-tools-*` |

The gate's rules are in `appliance/build/forbidden-inventory.txt`:
- **`E/kernel-cve-assumptions`:** the `perf` command, every `linux-tools-*` package, and `/usr/lib/linux-tools`;
- **the BPF tooling:** its packages, `bpftrace*`, `*.bt` and `*-bpfcc`;
- **snapd.**

Tests: `appliance_inventory_gate_test.go`.
