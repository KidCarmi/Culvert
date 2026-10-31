# FB-1: selecting the snapshot pin `20261029T180000Z` (31 Oct 2026)

The owner authorized raising the pin, within three constraints:

1. The snapshot resolves the approved kernel transition, 7.0.0-38 to **7.0.0-42.42~24.04.1**, and no other kernel transition.
2. It regresses no package version present in the retained OVA 325c142a, including its security-pocket updates.
3. The four Docker pins do not change.

**Selected:** `20261029T180000Z`. Its four InRelease files are byte-identical to the indexes the approved kernel-42 transaction was resolved against (`../../esxi-325c142a/kernel-42/apt-indexes.txt`, lines 2–5). This pin is not a new choice of archive state. It is the archive state the kernel-42 disposition already reviewed, now made reproducible.

## Authenticated metadata (`authn.tsv`, `inrelease/`)

| Suite | InRelease SHA-256 | `Date:` |
|---|---|---|
| noble | `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` | 25 Apr 2024 15:10:33 UTC |
| noble-updates | `1af76bea40c6b8ddbc51a51046c5a3e7912c9611536e97afc673a4b1c39d1886` | 29 Oct 2026 13:22:21 UTC |
| noble-security | `d90e89008640e66a6eacc13ffaad0fbbd205877cc51acdd8d4f99f9d21fcfee0` | 29 Oct 2026 16:38:05 UTC |
| noble-backports | `b6a0b10bb67d8da7ecb72a3f62dda5f408091d5a1abe8cbda2380f4af6b705cd` | 28 Oct 2026 21:24:20 UTC |

How each file was checked:

- It was fetched from `snapshot.ubuntu.com/ubuntu/20261029T180000Z/dists/<suite>/InRelease` twice, and the two fetches were byte-identical.
- `gpgv` against `/usr/share/keyrings/ubuntu-archive-keyring.gpg` reports a Good signature from RSA key `F6ECB3762474EDA9D21B7022871920D1991BC93C` (`inrelease/gpgv-*.txt`).
- All 16 `Packages.xz` files (4 suites × 4 components) were fetched, and each matched its InRelease SHA-256 entry.

The InRelease files themselves are committed, so the hashes can be re-checked offline. The Packages files (about 134 MB) are not committed. They can be re-fetched by hash from the committed InRelease files.

## Kernel window (`kernel-window-scan.tsv`)

For every 6-hour snapshot from 26 to 31 Oct, the scan records the noble-updates InRelease hash and the `linux-image-virtual-hwe-24.04` version.

| Snapshots | `linux-image-virtual-hwe-24.04` |
|---|---|
| up to `20261028T000000Z` | 7.0.0-38.38~24.04.4 |
| `20261028T060000Z` to `20261031T060000Z` | 7.0.0-42.42~24.04.1, with no newer image |

So any snapshot in the second window would satisfy constraint 1.

The selected one is the only one in that window whose indexes the approved transaction was actually resolved against. A later snapshot would bring package changes nobody reviewed. For example, noble-updates `3e30429b…` at `20261030T180000Z` is the "live" file T4/C2 observed.

## Resolution against the 325c142a inventory (`sim/`, `compare-325c142a.tsv`)

**Method.** `tools/sim.sh` sets up an isolated APT root:

- it loads the real 325c142a dpkg status (sha256 `ebec9a70…`, recorded in `../../esxi-325c142a/kernel-42/apt-indexes.txt` line 7);
- it uses the guest's section-1 source set (Ubuntu `Snapshot: yes`, Docker `snapshot=no`, snapd pinned out);
- it uses the production `apt-snapshot.sh` helpers.

It then simulates the build's `upgrade --with-new-pkgs`. `tools/compare_inventory.py` compares each of the 680 inventory rows against the result, using Debian version ordering (`dpkg --compare-versions`).

| Class | Rows | Meaning |
|---|---|---|
| unchanged | 671 | same version as 325c142a |
| docker-pinned | 4 | `docker-ce`, `docker-ce-cli` 5:29.9.2-1, `containerd.io` 2.4.2-3, `docker-compose-plugin` 5.6.1-1, all unchanged |
| upgrade | 1 | `linux-image-virtual-hwe-24.04` 7.0.0-38.38~24.04.4 → 7.0.0-42.42~24.04.1 |
| added | 4 | `linux-image`, `linux-modules`, `linux-main-modules-zfs` and `linux-main-modules-v4l2loopback`, all `-7.0.0-42-generic` 7.0.0-42.42~24.04.1 (noble-updates) |
| removed-kernel | 4 | the same four packages for `-7.0.0-38-generic`, purged by prepare-guest.sh's "exactly one kernel ships" step and superseded by the 42 set |
| **DOWNGRADE** | **0** | |
| **not in snapshot / unknown origin** | **0** | |

**Security rows.** 209 rows carry a 325c142a version that is listed in noble-security. Of these:

- 204 are unchanged;
- 1 is the kernel meta, which moves up to 7.0.0-42;
- 4 are the 7.0.0-38 kernel packages, replaced by their 7.0.0-42 versions per the approved disposition.

No security-update version is lost.

**The previous pin.** The `20261002T120000Z` pin would have regressed exactly the recorded 57 rows (`provenance-nonsnapshot-57.tsv`), 44 of them security-pocket updates.

**The `upgrade` Inst lines** (`sim/upgrade-default.txt`) are the four `-42-generic` packages plus the meta. They are the same as the approved transaction's (`../../esxi-325c142a/kernel-42/`).

**Phasing.**

- `sim/upgrade-allphased.txt` is identical, with the same 5 Inst lines.
- None of these packages are phased.
- The only packages kept back are the four held Docker packages.
- The build now sets `APT::Get::Always-Include-Phased-Updates=true` anyway, so a phased package can never make the resolution depend on the build machine's phasing hash.

**Kernel meta.** `sim/kernel-meta-install.txt`, `-policy.txt` and `-depends.txt` show `linux-image-virtual-hwe-24.04` resolving to the same 7.0.0-42 set when installed directly.

**Regeneration.** Running `compare_inventory.py` again on the same inputs gives byte-identical output, with either simulation.

## Docker packages (`docker/docker-deb-pins.tsv`)

How the index was checked:

- Docker's `noble stable` InRelease (sha256 `c6462b3f…`) has a gpgv Good signature from key `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` (manifest `DOCKER_APT_KEY_FPR`).
- Its `stable/binary-amd64/Packages` (sha256 `2fc6d42b…`) matches the InRelease entry.

That index lists the four pinned versions with these SHA-256 values:

| Package | Version | `.deb` SHA-256 (now `manifest.env` `*_DEB_SHA256`) |
|---|---|---|
| docker-ce | 5:29.9.2-1~ubuntu.24.04~noble | `95ddf7a2d8b8c0eb82d8597d4d604e294dcf741081f2e228524d5ab9bfd7c8ae` |
| docker-ce-cli | 5:29.9.2-1~ubuntu.24.04~noble | `74747b5c99000279b9b2c7eb82543b4121d8436a58aa3be7e78ac6681d74794f` |
| containerd.io | 2.4.2-3~ubuntu.24.04~noble | `f811ab57d1f4bb0cce19df7d526da8c711d8ebea0447cc83da1999188e664122` |
| docker-compose-plugin | 5.6.1-1~ubuntu.24.04~noble | `9725be1df7fd5ccc6b21ac24112885896c8d134345e3f4aa20b3c2064ef4620e` |

The downloaded files hash to the same values. The engine three equal M1's verified identities (`../../m1-engine-pins/`).

## Limits

- **This is a prediction.** It starts from 325c142a's status. The replacement build starts from the cloud image and installs the same set. The authority is T5: the built disk's own `package-provenance.tsv` and `acquired-debs.tsv`.
- **Base-image packages.** Packages already present in the base image at the version the snapshot lists are bound by version, plus the base image's own SHA-256 (`BASE_IMAGE_SHA256`). Their bytes were not acquired during the build, so the reconciler marks them `inherited-base-image` and does not claim byte identity for them.
