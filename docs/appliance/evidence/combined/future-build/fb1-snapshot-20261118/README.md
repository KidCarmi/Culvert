# R11-F1: raising the snapshot pin to `20261118T000000Z` (19 Nov 2026)

**Owner direction (19 Nov 2026, PR #1528).** This fixes the two pre-pilot blockers left after QEMU Campaign 10 on OVA `aea0845a`. Both packages are updated; neither is removed or reconfigured.

| Package | aea0845a | Fixed version | Finding |
|---|---|---|---|
| `needrestart` | 3.6-7ubuntu4.5 | **3.6-7ubuntu4.6** (noble-security) | CVE-2026-124757 HIGH: local privilege escalation through the root apt/dpkg hook (process names, cgroup paths) |
| `sosreport` | 4.11.2-0ubuntu0~24.04.1 | **4.11.2-0ubuntu0~24.04.2** (noble-security) | CVE-2026-79655 MEDIUM: `sos clean` follows out-of-tree tar members (symlink/hardlink) |

The proposal and its review are on PR #1528:
- OPUS 7014118861: update both; removal of needrestart deferred to the OS-upgrade gate as R11-H1.
- ASTRA 16:02Z on 19 Nov: authenticated review of the same delta.

**Why update and not remove:**
- `sosreport` is a **Depends** of `ubuntu-server`, so a purge would also remove the metapackage the build keeps.
- Removing `needrestart` changes run-time restart behaviour on the OS-update path, which is not qualified.
- No configuration closes either flaw.

This raise is limited to the guest apt snapshot pin and the fixtures and expectations derived from it. The Docker pins, kernel, scripts and every other input are unchanged.

## Constraints

1. **Kernel.** `linux-image-virtual-hwe-24.04` must still resolve to exactly **7.0.0-43.43~24.04.1**, the kernel the owner approved on 17 Nov. No kernel change is part of this raise.
2. **The two fixes.** `noble-security` must list both fixed versions (`tools/window-probe.sh`).
3. **Smallest change.** Among snapshots that satisfy 1–2, take the earliest. This is the rule of every earlier selection (`20261029T180000Z`, `20261105T000000Z`, `20261113T000000Z`).

## Window (`kernel-window-scan.tsv`, `tools/window-probe.sh`)

The tool is the R10-F1 `window-probe.sh` with only the fix list and its count changed. Each `Packages.xz` is checked against its InRelease.

| Snapshots | HWE meta | 2 fixes |
|---|---|---|
| `20261116T180000Z`–`20261117T180000Z` | 7.0.0-43 | 1/2 (sosreport only) |
| **`20261118T000000Z`** – `20261119T120000Z` | **7.0.0-43** | **2/2** |

**Selected:** `20261118T000000Z`, the first 6-hour snapshot after Ubuntu published needrestart 3.6-7ubuntu4.6.

## Authenticated metadata (`authn.tsv`, `inrelease/`)

| Suite | InRelease SHA-256 | `Date:` |
|---|---|---|
| noble | `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` (unchanged) | 25 Apr 2024 15:10:33 UTC |
| noble-updates | `95fabe7ae86391dc2d76d40d06e0d248862f5997b99fd100bd736a8ca82273a4` | 17 Nov 2026 23:37:10 UTC |
| noble-security | `0dcbc7c8460be3ecec2578aa1cb8d22cebe2d5d4e70b8bf069dc61315724e649` | 17 Nov 2026 21:40:30 UTC |
| noble-backports | `a853769b1583a20dfbc2a5488f3c7ba80cad91fdca180ce9555c979177a1023d` | 17 Nov 2026 02:04:59 UTC |

How each file was checked:
- fetched twice from `snapshot.ubuntu.com/ubuntu/20261118T000000Z/dists/<suite>/InRelease`; the two fetches were byte-identical;
- `gpgv` against `/usr/share/keyrings/ubuntu-archive-keyring.gpg` reports a Good signature from RSA key `F6ECB3762474EDA9D21B7022871920D1991BC93C` (`inrelease/gpgv-*.txt`);
- all 16 `Packages.xz` files (4 suites × 4 components) were fetched, and each matched its InRelease SHA-256 and size.

The Packages files are not committed; they can be re-fetched by hash.

**Fixed packages** (`fixed-debs.tsv`): the `.deb` SHA-256 values are read from the verified index. Both files were downloaded and hash-matched. Their `changelog.Debian` entries name the fixes: needrestart `CVE-2026-124757` (three patches); sosreport `CVE-2026-79655` (LP: #2168552).

## Resolution against the exact candidate disk (`sim/`, `compare-aea0845a.tsv`)

**Inputs** (`inputs/`):
- **Inventory:** the exact-byte installed inventory of OVA `aea0845a`, i.e. `rootfs-dpkg.tsv` from scan artifact 14453767402 (668 rows).
- **Status file:** that disk's own `/var/lib/dpkg/status`, read offline from the OVA (`inputs/aea0845a-dpkg-status.sha256`; not committed):
  - the OVA member of build artifact 14442199990 was range-read and its sha256 recomputed as `aea0845a…`;
  - the VMDK was exported read-only with `qemu-storage-daemon` (FUSE);
  - the file was dumped with `debugfs -c` from GPT partition 1.
  - It holds 664 `install ok installed` packages plus the 4 Docker packages in `hold` state, i.e. the 668 rows of the scan inventory, equal row for row.
- **APT policy:** the disk's own `/etc/apt/preferences.d` (`inputs/apt-preferences/`: `culvert-no-snapd`, `culvert-no-diagnostic-tooling`, `ubuntu-pro-esm-apps`, `ubuntu-pro-esm-infra`). These replace the single snapd pin the earlier `sim.sh` wrote (`tools/sim.sh` takes them as its 9th argument).
- **Docker pins** the disk carries (`inputs/docker-pins.txt`). They are held at the disk's own values, which are the manifest's.

**Method:**
- `tools/sim.sh` is R10-F1's `sim.sh` plus the preferences argument;
- the unchanged `../fb1-snapshot-20261029/tools/compare_inventory.py` classifies every row.

**Control.** The same simulation at the current pin `20261113T000000Z` gives 0 upgrades (`sim/control-20261113/`). The disk is current at its own snapshot.

| Class | Rows | Packages |
|---|---|---|
| unchanged | 662 | |
| docker-pinned | 4 | unchanged |
| upgrade | **2** | `needrestart` 3.6-7ubuntu4.5 → 3.6-7ubuntu4.6; `sosreport` 4.11.2-0ubuntu0~24.04.1 → 4.11.2-0ubuntu0~24.04.2 (both noble-security) |
| added / removed / **DOWNGRADE / not in snapshot / other** | **0** | |

Further results:
- **Phasing.** `sim/upgrade-allphased.txt` is byte-identical to `sim/upgrade-default.txt`.
- **Kernel meta.** `sim/kernel-meta-install.txt`: "linux-image-virtual-hwe-24.04 is already the newest version (7.0.0-43.43~24.04.1)".
- **docker-compose-plugin "kept back".** It appears in both the control and the 20261118 resolution: it is held on the disk, and the simulation reads Docker's live index. It is not a snapshot effect.

## Clean-base build transaction (`sim/clean-base/`)

The build starts from the Ubuntu cloud image, not from `aea0845a`. The same `sim.sh` was run against the build's own `base-dpkg-status.txt`, a member of build artifact 14442199990 (ZIP CRC `0x5997da31` verified; `inputs/aea0845a-base-dpkg-status.sha256`). It was run under both pins, with the snapd pin the build sets before its `upgrade --with-new-pkgs` step.

| Pin | Result |
|---|---|
| `20261113T000000Z` | 91 upgraded, 6 newly installed, 0 removed |
| `20261118T000000Z` | 92 upgraded, 6 newly installed, 0 removed |

The two transactions are identical except for:
- `+ Inst needrestart [3.6-7ubuntu4.5] (3.6-7ubuntu4.6 …)`. The base image already carries 4.5, which 20261113 left in place.
- `sosreport [4.10.2-0ubuntu0~24.04.1]`, whose target moves from `4.11.2-0ubuntu0~24.04.1` to `4.11.2-0ubuntu0~24.04.2`.

The kernel-meta resolutions are identical (7.0.0-43). Default and all-phased resolutions are byte-identical under both pins.

**Scope of this evidence.** It is a prediction. The built disk is the authority: its `build-upgrades.txt` (BASE → candidate, so it lists every base upgrade, not only these two), `package-provenance.tsv`, `dpkg-list.txt`, `prepare-guest.log` and the exact-byte scan. The acceptance criterion for the new disk is the **final** `aea0845a` → new delta: exactly these two packages plus the enumerated generated identity and provenance records. Its `package-provenance.tsv` must have 0 unexplained origins; the 4 signed Docker packages and inherited base-image limits are explained origins.
