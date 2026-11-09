# FB1-R2: raising the snapshot pin to `20261105T000000Z` (9 Nov 2026)

**Owner decision (9 Nov 2026, D4 on PR #1528).** The exact-byte scan of the FB1-R1 candidate OVA `f76b6e82` (built from `6eead9a1` on pin `20261029T180000Z`) reported 24 fix-available Ubuntu rows: 14 CVEs across 9 binary packages (3 HIGH rows, apt CVE-2026-109518; 21 MEDIUM rows). The owner chose to refresh the snapshot instead of accepting them as campaign residuals.

The exception is limited to:
- moving the guest apt snapshot pin;
- the fixtures and expectations derived from it.

No other dependency, engine, kernel or criterion change is part of it.

## Constraints

1. **Kernel.** The snapshot resolves `linux-image-virtual-hwe-24.04` to exactly **7.0.0-42.42~24.04.1**, the owner-approved kernel-42 identity. The kernel is not version-pinned (`manifest.env`: `upgrade --with-new-pkgs` takes the snapshot's newest ABI), so the snapshot itself must hold it.
2. **The nine fixes.** `noble-security` lists all nine fixed versions.
3. **Docker.** The four Docker pins do not change.
4. **Smallest change.** Among snapshots that satisfy 1–3, take the earliest, so that the fewest unreviewed packages move. This is the same principle as the `20261029T180000Z` selection.

## Kernel and fix window (`kernel-window-scan.tsv`, `tools/window-probe.sh`)

This continues `../fb1-snapshot-20261029/kernel-window-scan.tsv`. It covers every 6-hour snapshot from `20261031T120000Z` to `20261109T120000Z`.

For each snapshot, `window-probe.sh`:
- fetches the noble-updates and noble-security InRelease and `main/binary-amd64/Packages.xz`;
- checks each `Packages.xz` against its InRelease SHA-256 entry;
- records the `linux-image-virtual-hwe-24.04` versions and how many of the nine fixed versions noble-security/main lists.

| Snapshots | HWE meta | Nine fixes |
|---|---|---|
| to `20261103T120000Z` | 7.0.0-42 (and the superseded 38 entry until `20261102T120000Z`) | 0/9 |
| `20261103T180000Z`–`20261104T120000Z` | 7.0.0-42 | 5/9 |
| `20261104T180000Z` | 7.0.0-42 | 8/9 |
| **`20261105T000000Z`** – `20261109T120000Z` | **7.0.0-42 only** | **9/9** |

No snapshot in the window offers a kernel newer than 7.0.0-42.

**Selected:** `20261105T000000Z`, the earliest snapshot meeting constraints 1–3.

## Authenticated metadata (`authn.tsv`, `inrelease/`)

| Suite | InRelease SHA-256 | `Date:` |
|---|---|---|
| noble | `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` (unchanged) | 25 Apr 2024 15:10:33 UTC |
| noble-updates | `b82fcb2734d8a7a04efe6a7a19f8eb16692d3c64a5884fb2755ba6fd647aaa78` | 04 Nov 2026 22:21:27 UTC |
| noble-security | `9798467b11460fac5c1015fc5b297c9b05d125d24a77b6953e8675de774cb866` | 04 Nov 2026 20:00:17 UTC |
| noble-backports | `53907c41dd1f5f1ab0465119ee5175ca916a1dc2c64f1762097c5049c6ff7e6b` | 04 Nov 2026 18:22:27 UTC |

How each file was checked:
- It was fetched twice from `snapshot.ubuntu.com/ubuntu/20261105T000000Z/dists/<suite>/InRelease`, and the two fetches were byte-identical.
- `gpgv` against `/usr/share/keyrings/ubuntu-archive-keyring.gpg` reports a Good signature from RSA key `F6ECB3762474EDA9D21B7022871920D1991BC93C` (`inrelease/gpgv-*.txt`).
- All 16 `Packages.xz` files (4 suites × 4 components) were fetched, and each matched its InRelease SHA-256 entry.

The Packages files (about 131 MB uncompressed) are not committed. They can be re-fetched by hash.

## Resolution against the FB1-R1 inventory (`sim/`, `compare-f76b6e82.tsv`)

**Inputs** (`inputs/`):
- The exact-byte installed inventory of the FB1-R1 OVA `f76b6e82`, which is `rootfs-dpkg.tsv` from scan artifact `13651862819` (668 rows).
- That disk's own `/var/lib/dpkg/status`, read offline from the retained VMDK. Its SHA-256 is in `f76b6e82-dpkg-status.sha256`; the file is not committed.
- The manifest's Docker pins.

**Method.** `tools/sim.sh` is `../fb1-snapshot-20261029/tools/sim.sh`, unchanged apart from the four new pin values (`noble` is unchanged). It loads that status into an isolated APT root with the guest's section-1 sources, then simulates the build's `upgrade --with-new-pkgs` under the new pin. The unchanged `../fb1-snapshot-20261029/tools/compare_inventory.py` classifies every inventory row.

| Class | Rows | Packages |
|---|---|---|
| unchanged | 654 | |
| docker-pinned | 4 | `docker-ce`, `docker-ce-cli` 5:29.9.2-1, `containerd.io` 2.4.2-3, `docker-compose-plugin` 5.6.1-1 (held; unchanged) |
| upgrade | 10 | see below |
| **added / removed / DOWNGRADE / not in snapshot** | **0** | |

The 10 upgrades:

| Package | Before → after | Origin |
|---|---|---|
| `apt`, `apt-utils`, `libapt-pkg6.0t64` | 2.8.3 → 2.8.4ubuntu0.1 | noble-security (CVE-2026-109518) |
| `bind9-dnsutils`, `bind9-host`, `bind9-libs` | `…24.04.8` → `…24.04.9` | noble-security + noble-updates |
| `libmspack0t64` | 0.11-1.1build1 → 0.11-1.1ubuntu0.24.04.1 | noble-security + noble-updates |
| `libpcre2-8-0` | 10.42-4ubuntu2.1 → 10.42-4ubuntu2.2 | noble-security + noble-updates |
| `python3-twisted` | 24.3.0-1ubuntu0.2 → 24.3.0-1ubuntu0.3 | noble-security |
| **`libsqlite3-0`** | 3.45.1-1ubuntu2.8 → 3.45.1-1ubuntu2.9 | **noble-updates only.** The one non-security change. It is already published at the earliest qualifying snapshot. |

Further results:
- **Kernel.** `sim/kernel-meta-install.txt` reports that `linux-image-virtual-hwe-24.04` is already the newest version (7.0.0-42.42~24.04.1). The policy shows the same version Installed and Candidate. Newest kernel ABI: 7.0.0-42.
- **Phasing.** `sim/upgrade-allphased.txt` is byte-identical to `sim/upgrade-default.txt`, and the comparison over it is identical.

**Scope of this evidence.** It is a prediction. The built disk is the authority: its `build-upgrades.txt`, `package-provenance.tsv`, `dpkg-list.txt` and the exact-byte scan.
