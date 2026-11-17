# R10-F1: raising the snapshot pin to `20261113T000000Z` (17 Nov 2026)

**Owner decision (17 Nov 2026, PR #1528).** The exact-byte scan of the R10 candidate OVA `9e31f226` (lab run 43964288041, Trivy DB 16 Nov) reported new fix-available Ubuntu rows. ASTRA held campaign 10 on them (R10-F1). They are:
- glibc 2.39-0ubuntu8.12, including CVE-2026-86805 (dynamic-loader TOCTOU, local privilege escalation) and CVE-2026-84243 (`LANGUAGE` traversal, code execution);
- perl 5.38.2-3.2ubuntu0.7;
- python3-pyasn1 0.4.8-4ubuntu0.4;
- kernel `7.0.0-43.43~24.04.1`, which fixes all 4 CRITICAL and 50 of 59 HIGH rows of `7.0.0-42`.

The owner was asked: "Does the same replacement build also move the Ubuntu apt snapshot to 20261116 — fixing the glibc privilege-escalation/code-execution flaws, perl and pyasn1 — which also moves the kernel 7.0.0-42 → 7.0.0-43?" The answer was **"Yes, include it."**

This raise is limited to:
- the guest apt snapshot pin;
- the fixtures and expectations derived from it.

The Docker pin change of the same decision is recorded separately (`../../r10-engine-pins/`).

## Constraints

1. **Kernel.** The snapshot resolves `linux-image-virtual-hwe-24.04` to exactly **7.0.0-43.43~24.04.1**, the kernel the owner approved. The kernel is not version-pinned (`manifest.env`: `upgrade --with-new-pkgs` takes the snapshot's newest ABI), so the snapshot itself must hold it.
2. **The thirteen fixes.** `noble-security` lists all 13 fixed versions `tools/window-probe.sh` checks: `libc6`, `libc-bin`, `libc-dev-bin`, `libc-devtools`, `libc6-dev`, `locales` 2.39-0ubuntu8.12; `perl`, `perl-base`, `perl-modules-5.38`, `libperl5.38t64` 5.38.2-3.2ubuntu0.7; `python3-pyasn1` 0.4.8-4ubuntu0.4; `linux-image-` / `linux-modules-7.0.0-43-generic` 7.0.0-43.43~24.04.1.
3. **Smallest change.** Among snapshots that satisfy 1–2, take the earliest, so that the fewest unreviewed packages move. This is the rule of the `20261029T180000Z` and `20261105T000000Z` selections.

**Why not 20261116, the snapshot named to the owner.** `20261113T000000Z` is the earliest qualifying snapshot, and against the `9e31f226` disk it predicts the **identical** transaction as `20261116T000000Z` (same 20 `Inst` lines, below). It is therefore the same decision with the smaller published window.

## Kernel and fix window (`kernel-window-scan.tsv`, `tools/window-probe.sh`)

This continues `../fb1-snapshot-20261105/kernel-window-scan.tsv` from `20261109T180000Z` to `20261117T000000Z`, every 6 hours. The tool is the FB1-R2 `window-probe.sh` with only the fix list changed. Each `Packages.xz` is checked against its InRelease.

| Snapshots | HWE meta | 13 fixes |
|---|---|---|
| to `20261111T180000Z` | 7.0.0-42 | 1–5/13 |
| `20261112T000000Z` | 7.0.0-42 **and** 7.0.0-43 | 5/13 |
| `20261112T060000Z`–`20261112T180000Z` | 7.0.0-43 | 7/13 |
| **`20261113T000000Z`** – `20261117T000000Z` | **7.0.0-43 only** | **13/13** |

**Selected:** `20261113T000000Z`.

## Authenticated metadata (`authn.tsv`, `inrelease/`)

| Suite | InRelease SHA-256 | `Date:` |
|---|---|---|
| noble | `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` (unchanged) | 25 Apr 2024 15:10:33 UTC |
| noble-updates | `bb3362859b0a0285bc8f2d4a23b026f1780e96a21b4c695df0a999c505b2c461` | 12 Nov 2026 23:49:05 UTC |
| noble-security | `32a96f18660f01f41f46a13555f0b546b917f24c92216db86bec1f1fe478e8e1` | 12 Nov 2026 21:24:19 UTC |
| noble-backports | `78a500b79a5e1da2e2a75a912cbe4692baeecede6bdafa2223e26d23b0869b27` | 11 Nov 2026 17:24:26 UTC |

How each file was checked:
- fetched twice from `snapshot.ubuntu.com/ubuntu/20261113T000000Z/dists/<suite>/InRelease`; the two fetches were byte-identical;
- `gpgv` against `/usr/share/keyrings/ubuntu-archive-keyring.gpg` reports a Good signature from RSA key `F6ECB3762474EDA9D21B7022871920D1991BC93C` (`inrelease/gpgv-*.txt`);
- all 16 `Packages.xz` files (4 suites × 4 components) were fetched and each matched its InRelease SHA-256.

The Packages files are not committed; they can be re-fetched by hash.

## Resolution against the R10 candidate disk (`sim/`, `compare-9e31f226.tsv`)

**Inputs** (`inputs/`):
- the exact-byte installed inventory of OVA `9e31f226`, i.e. `rootfs-dpkg.tsv` from scan artifact 14274504988 (668 rows);
- that disk's own `/var/lib/dpkg/status`, read offline from the OVA (`inputs/9e31f226-dpkg-status.sha256`; not committed):
  - the OVA member of artifact 14260839269 was range-read and its sha256 recomputed as `9e31f226…`;
  - the VMDK was exported read-only with `qemu-storage-daemon`;
  - the file was dumped with `debugfs -c` from GPT partition 1;
- the Docker pins the disk carries (`inputs/docker-pins.txt`). They are held at the disk's own values, so the comparison isolates the snapshot's effect; the owner's Docker change is `../../r10-engine-pins/`.

**Method:**
- `tools/sim.sh` is FB1-R2's `sim.sh` with the snapshot ID and the four pins passed as arguments;
- the unchanged `../fb1-snapshot-20261029/tools/compare_inventory.py` classifies every row.

| Class | Rows | Packages |
|---|---|---|
| unchanged | 644 | |
| docker-pinned | 4 | unchanged by the snapshot |
| upgrade | 16 | below |
| removed-kernel / added | 4 / 4 | `linux-image`, `linux-modules`, `linux-main-modules-zfs`, `linux-main-modules-v4l2loopback`: `-7.0.0-42-generic` purged, `-7.0.0-43-generic` added (the same four packages at the new ABI) |
| **DOWNGRADE / not in snapshot / other** | **0** | |

The 16 upgrades:

| Package | Before → after | Origin |
|---|---|---|
| `libc6`, `libc-bin`, `libc-dev-bin`, `libc-devtools`, `libc6-dev`, `locales` | 2.39-0ubuntu8.9 → 8.12 | noble-security |
| `perl`, `perl-base`, `perl-modules-5.38`, `libperl5.38t64` | 5.38.2-3.2ubuntu0.6 → 0.7 | noble-security |
| `python3-pyasn1` | 0.4.8-4ubuntu0.3 → 0.4 | noble-security |
| `linux-libc-dev` | 6.8.0-147.147 → 6.8.0-149.149 | noble-security (headers only) |
| `linux-image-virtual-hwe-24.04` | 7.0.0-42.42~24.04.1 → 7.0.0-43.43~24.04.1 | noble-security (the approved kernel) |
| `ca-certificates` | 20260816ubuntu0.24.04.1 → .2 | noble-security |
| **`distro-info`, `python3-distro-info`** | 1.7build1 → 1.7ubuntu0.1 | **noble-updates only.** These are the non-security changes, already published at the earliest qualifying snapshot, as `libsqlite3-0` was in FB1-R2. |

Further results:
- **Phasing.** `sim/upgrade-allphased.txt` is byte-identical to `sim/upgrade-default.txt`, and the comparison over it is identical.
- **Same transaction at 16 Nov.** The same simulation at `20261116T000000Z` gives the identical 20 `Inst` lines.
- **Kernel meta.** `sim/kernel-meta-install.txt` and `sim/kernel-meta-policy.txt` resolve `linux-image-virtual-hwe-24.04` to 7.0.0-43.43~24.04.1. Newest kernel ABI: 7.0.0-43.

## Kernel 7.0.0-43 against the appliance's module policy (`kernel-43/`)

`prepare-guest.sh` section 2 stops the build if the kernel's module set no longer matches the reviewed policy:
- every module in `modprobe-culvert-unused.conf` (plus `kvm-amd`, `can-raw`) must resolve to `install /bin/false`;
- every module a socket family, genetlink family, sock_diag request or TCP ULP can autoload must be denied or listed in `net-autoload-reviewed.txt`;
- the reviewed list may not name a module the kernel no longer ships.

`kernel-43/kmod-review.sh` runs those exact checks offline:
- on the extracted `linux-modules`, `linux-main-modules-zfs` and `linux-main-modules-v4l2loopback` packages (`kernel-43/debs.sha256`, each checked against the snapshot's Packages SHA-256);
- after `depmod`, with `modprobe -n -v`.

| Kernel | Denied → `/bin/false` | Net-autoload surface | Unreviewed / stale | Result |
|---|---|---|---|---|
| 7.0.0-42 (control) | 67 + 2 | 61 modules, 29 denied, 32 reviewed | none / none | PASS |
| **7.0.0-43** | 67 + 2 | 61 modules, 29 denied, 32 reviewed | none / none | **PASS** |

**Control.** The 42 result equals the line the real `9e31f226` build printed (`net autoload surface: 61 modules, 29 denied, 32 reviewed`, `prepare-guest.log`).

**What differs between 42 and 43:**
- **Module set.** The 6900 module paths are identical (`kernel-43/sets.txt`). The package file lists differ only in two vDSO `.build-id` debug files.
- **Config.** The kernel configs differ only in `CONFIG_VERSION_SIGNATURE`; both are upstream 7.0.14 (`kernel-43/config-diff.txt`).

The appliance's module policy files therefore need no change.

**Scope of this evidence.** It is a prediction. The built disk is the authority: its `build-upgrades.txt`, `package-provenance.tsv`, `dpkg-list.txt`, `prepare-guest.log` and the exact-byte scan.
