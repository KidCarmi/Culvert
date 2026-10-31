# FB-1: the guest APT snapshot pin is not applied; future-build blocker

| | |
|---|---|
| **Status** | **Source/test closure on `review/1528-m1-engine-pins` (§6). Artifact closure OPEN:** T5 needs an actual replacement OVA. Until then FB-1 is not lifted. |
| **Scope** | §1–§5 are the original specification (owner 6506229963), unchanged. §6 records the implementation the owner then authorized (fix + isolated verification + CI; no OVA build). |
| **This OVA** | 325c142a's identity, exact-byte scans and qualification evidence remain valid **for its bytes**. Its provenance is not rewritten. Its build was **not** snapshot-locked: it was built from the live archive of its build day. The fix does not change that, and nothing here may be read as making 325c142a snapshot-reproducible. |

## 1. Defect

`appliance/build/prepare-guest.sh` @ 0648adeb passes `-o Acquire::Snapshot="$GUEST_APT_SNAPSHOT"` at six call sites:

| Line | Call |
|---|---|
| 122 | `update` |
| 124 | `upgrade --with-new-pkgs` |
| 133 | kernel meta `install` |
| 162 | candidate check (`apt-cache policy`) |
| 165 | `apt-cache depends` |
| 202 | plymouth/fontconfig `install` |

**APT 2.8.3 has no such key.** Its snapshot selector is `APT::Snapshot`, exposed as `--snapshot` (Canonical: https://ubuntu.com/server/docs/how-to/software/snapshot-service/). The library's strings contain only `APT::Snapshot` and `Acquire::Snapshots::URI…`.

**So every call resolved against the live archive of the build day:**
- **57 of the 680 shipped versions do not exist in snapshot `20261002T120000Z`** (`../esxi-325c142a/kernel-42/provenance-nonsnapshot-57.tsv`).
- The guard at l.162 compared the installed kernel meta against the **live** candidate, so it could not detect this.

**Two documentation claims at 0648adeb are false and must be corrected with the fix:**
- `manifest.env` l.43 ("apt -o Acquire::Snapshot");
- `prepare-guest.sh` l.85–86, which says a source without `snapshot=no` "would refuse the whole update". Measured in E4 below: by default it is silently used **live**.

## 2. Measured APT 2.8.3 behaviour (isolated roots, 29 Oct 2026)

These are the facts the fix has to be built on. Each is a reason a naive fix would still fail open.

| # | Setup | Result | Consequence |
|---|---|---|---|
| E1 | `-o Acquire::Snapshot=ID` | 0 snapshot lists fetched; systemd candidate 8.18 (live) | **The defect.** |
| E2 | `--snapshot ID` (or `-o APT::Snapshot=ID`) | 19 snapshot lists fetched; candidate 8.17 (snapshot) | Correct selector. |
| E3 | Snapshot lists present, **next call without** `--snapshot` | Candidate live again | **Every** apt-get/apt-cache call needs the selector. |
| E4 | `--snapshot`, a source without snapshot support (Docker), default options | rc 0; that source used **live** | Must opt in per source. |
| E5 | Same source with `snapshot=yes` / deb822 `Snapshot: yes` | **rc 100**, "Snapshots not supported" | Fail-closed switch for sources that must be snapshotted. |
| E6 | `--snapshot 20991231T000000Z` (a future ID) | **rc 0**; the server served its latest state (InRelease `Date` 29 Oct 18:58Z) | **A wrong ID silently means "now".** The ID alone proves nothing. |
| E7 | Unreachable index, plain `update` | rc 0 with `W:` | Needs `--error-on=any`, which gives **rc 100**. |
| E8 | The snapshot InRelease fetched twice, ~1.5 h apart | **Byte-identical** (noble-updates `6e43c599…`, noble-security `3b358f74…`) | InRelease hashes can be pinned. |
| E9 | Live lists are fetched alongside, even with `--snapshot` | Candidate selection still uses the snapshot lists | Absence of live lists cannot be the check; candidate origin must be. |

## 3. Minimal fix (`prepare-guest.sh`, `manifest.env`, `build-ova.sh` only)

1. **One helper, used for every apt call in §1b.** For example:
   `apt_snap() { apt-get --snapshot "$GUEST_APT_SNAPSHOT" --error-on=any "$@"; }`, plus an `apt-cache --snapshot` twin.
   - Replace all six call sites.
   - The kernel candidate check (l.162/165) uses the twin, so it compares against the **snapshot** candidate.
   - *Why:* closes E1/E3, and fixes the guard that hid the defect.
2. **Opt Ubuntu sources in, Docker explicitly out.**
   - During the snapshot section, the build's Ubuntu sources carry `Snapshot: yes`.
   - Docker keeps `snapshot=no`; it is pinned by exact versions plus a hash check (step 5).
   - Restore the image's original sources afterwards (the deployed appliance updates live by design).
   - *Why:* closes E4. An Ubuntu source that cannot be snapshotted now fails the build.
3. **Pin the snapshot content, not just its name.** `manifest.env` gains `GUEST_APT_SNAPSHOT_INRELEASE_SHA256_{NOBLE,UPDATES,SECURITY,BACKPORTS}`. After the update, the build:
   - hashes `/var/lib/apt/lists/snapshot.ubuntu.com_ubuntu_${ID}_dists_<suite>_InRelease`;
   - **fails** on any mismatch, on a missing file, and on an ID that is not strictly earlier than the build start.
   - *Why:* closes E6 and makes "same manifest ⇒ same indexes" checkable. Raising the pin becomes a reviewed change of five values.
4. **Fail closed on transport:** `--error-on=any` on every update.
   - *Why:* closes E7.
5. **Post-build reconciliation in `build-ova.sh`, against the disk's `dpkg-list.txt` and the pinned indexes.** For every installed `(package, version, arch)`:
   - it is found in the snapshot `Packages` of a pinned InRelease; record the pocket, pool path and SHA256;
   - **or** it is one of the 4 Docker packages: version equals the manifest pin, found in Docker's signed index; record the SHA256;
   - **anything else fails the build.** That covers live-only versions (the 57), local or unknown origins, and a missing index.
   - It also writes `package-provenance.tsv` (name, version, arch, origin URI, pool path, SHA256) as build evidence. This replaces the unverifiable "from snapshot" label.
   - *Why:* this is the backstop that would have failed the 325c142a build. It covers anything steps 1–4 miss, including base-image packages that were never upgraded.
6. **Correct the evidence labels.** The `build-upgrades.txt` header and the build log state the snapshot ID **and** the verified InRelease hashes, or say "LIVE ARCHIVE — not snapshot-pinned" if the pin is disabled.

**Not part of the fix** (separate owner decision, already recorded): running `autoremove` at build time (`../esxi-325c142a/kernel-42/autoremove-reconciliation.md` §4).

## 4. Regression tests required before the next release build

| ID | Kind / where | Asserts | Red today? |
|---|---|---|---|
| T1 | Static Go test beside `appliance_build_layout_test.go` | `prepare-guest.sh` contains no `Acquire::Snapshot`; inside §1b every `apt-get`/`apt-cache` goes through `apt_snap`/twin; `update` carries `--error-on=any`; the l.85–86 and manifest l.43 comments no longer make the false claims | **Yes** (6 occurrences) |
| T2 | Static Go test | `manifest.env` has the four InRelease pins (64-hex); the snapshot section writes `Snapshot: yes` for Ubuntu and keeps `snapshot=no` for Docker; `build-ova.sh` invokes the reconciliation and fails on it | **Yes** |
| T3 | Offline unit test of the reconciler (fixture `Packages` + `dpkg-list`; no network) | (a) the **real 325c142a inventory against the 20261002 snapshot fails, naming exactly the 57** (red case from existing evidence); (b) an all-in-snapshot fixture passes; (c) a Docker version ≠ pin fails; (d) an unknown-origin package fails; (e) a missing or empty index fails; (f) an InRelease hash mismatch fails | New tool |
| T4 | Network lane (lab/build workflow, not the PR gate), isolated APT root as in §2 | E2 candidate = snapshot version for a canary (systemd); E6 future ID → **InRelease pin mismatch fails**; E5 `Snapshot: yes` on an unsupported source → rc 100; E7 `--error-on=any` → rc 100 | New |
| T5 | The next candidate build itself | `package-provenance.tsv` present; reconciliation reports 0 non-snapshot versions; InRelease hashes equal the manifest | — |

**Acceptance for lifting FB-1:**
- T1–T4 green on the fix commit;
- T5 green on the next built OVA;
- the reconciliation output is attached to its evidence.

**Until then, every OVA must be described as "built from the live archive at build time".** Its exact-byte inventory and scans stay its only authoritative package record.

## 5. Reference values for the current pin (observed, not yet adopted)

These are the snapshot `20261002T120000Z` InRelease files. Each was fetched and checked with `gpgv` against the Ubuntu archive key F6EC…C93C, on two fetches (E8).

| Suite | InRelease SHA-256 | `Date:` |
|---|---|---|
| noble | `cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0` | 25 Apr 2024 15:10:33 UTC |
| noble-updates | `6e43c5996bd6cf1d1fe7389a3d6ec383761635cdad2dfb58c020bded199235af` | 02 Oct 2026 08:01:33 UTC |
| noble-security | `3b358f744efb789bab437ac77209ac20be2c8665197ce274f65c5f812bd4d519` | 02 Oct 2026 06:20:59 UTC |
| noble-backports | `dc4d31dc0a8897dbecfd0375a4041b4aeb4a6fae00c688cf923daec3c4a258f8` | 02 Oct 2026 06:22:59 UTC |

**Prototype check of T3(a)**, read-only, using the existing evidence:
- the reconciliation rule from §3 step 5;
- applied to 325c142a's exact inventory (680 packages) against these indexes.

Result: **57 failures**, and the 4 Docker packages at their manifest pins. That is the expected red case.

A future pin bump may choose a newer snapshot. These values only illustrate the format.

## 6. Implementation (source/test closure, 30 Oct 2026)

Commit `d452d50dda9943bafaa4e03d3f77e542dd6d97dd` on `review/1528-m1-engine-pins` (PR #1528's frozen branch is unchanged).

| §3 step | Where | What |
|---|---|---|
| 1 | `appliance/build/apt-snapshot.sh` (new; sourced by `prepare-guest.sh`) | `apt_snap` / `apt_snap_update` / `apt_cache_snap` put `--snapshot ID` on every call. All six old sites and the purges now use them. The kernel guard compares against the **snapshot** candidate. |
| 1 (scope widened) | `prepare-guest.sh` §1 | The pinned update and InRelease check now run **before** the Docker install. So Docker's Ubuntu dependencies and `pigz`/`psmisc` also resolve from the snapshot; at 0648adeb they came from the live archive. The only raw APT calls left are the live update after the sources are restored, and `apt-get clean`. |
| 2 | `apt_snap_sources_enable` / `_restore` | Every `ubuntu.sources` stanza gets exactly one `Snapshot: yes`; the original is restored after the section. Any other source is refused, and Docker's must declare `snapshot=no`. |
| 3 | `manifest.env` + `apt_snap_require_pins` / `apt_snap_verify_inrelease` | The four §5 hashes are now pins. Build refusal cases: the ID is malformed or not earlier than the build start; an InRelease is missing; an InRelease differs from its pin. |
| 4 | `apt_snap_update` | `--error-on=any`. APT 2.8.3 accepts it on `update` only; on `install` it is rc 100 "not understood", which is why there are two helpers. |
| 5 | `build-ova.sh` §1b + §5, `reconcile-package-provenance.py` (new) | **Before the guest step, the build host fetches the indexes independently.** The chain is pin → InRelease → `Packages.xz` SHA-256 → `Packages`. Docker's InRelease is checked with `gpgv` against the fingerprint-pinned key. **After the guest step, every `dpkg-list.txt` row is reconciled.** A row passes only if it is either in the pinned snapshot, or one of the four Docker packages at its pin found in Docker's index. Anything else fails the build. The result is `package-provenance.tsv`. Package identity is the `.deb` SHA-256: the archive can list one file under two pool paths (`ocl-icd` 2.3.2-1build1 is in `pool/universe` in noble and `pool/main` in noble-updates). |
| 6 | `build-upgrades.txt` header, build log | These now name the snapshot ID **and** the four verified InRelease hashes. There is no live-archive mode: a build without the pins is refused. |

**Regression evidence**

| Test | Result |
|---|---|
| T1/T2: `appliance_fb1_snapshot_provenance_test.go`, static | **Red on the pre-fix scripts:** 49 failures, including all six ignored-option sites. Green on the fix. |
| Guest library behaviour (offline) | The checks refuse each of the following: a future ID, a malformed ID, a missing pin, a short pin, a changed InRelease, a missing InRelease, and a live list standing in for the snapshot one. The source checks refuse a stray `.list`, a stray `.sources`, and a Docker source without `snapshot=no`. The restore returns the original bytes, and the helper argv is exact. |
| T3 (offline; real stanzas from snapshot 20261002T120000Z restricted to the inventory's names; the real 325c142a inventory, sha256 `675a0773…`) | (a) **refused on exactly the recorded 57** (the list is byte-identical to `provenance-nonsnapshot-57.tsv`). (b) Without the 57: 623 rows (619 snapshot + 4 Docker). Each of the following fails: (c) a Docker package off its pin, a pin absent from Docker's index, or a pinned package not installed; (d) an unknown package, a live-only version, or the wrong architecture; (e) a missing index, an emptied index, or a missing InRelease; (f) an InRelease off its pin. A tampered `Packages` under a valid InRelease, a tampered Docker index, and two different `.deb` hashes for one version also fail. |
| T3(a) on the **full** real indexes (local, 30 Oct) | 57 refused, identical list. The 623 reconcile. All four Docker `.deb` hashes equal those M1 verified (`m1-engine-pins/`, `r6-r7-security-dispositions.md`). |
| Mutation check | Ten mutations of the reconciler and library are each caught by at least one test. |
| T4: `appliance/build/snapshot-pin-check.sh`, network, isolated APT roots, on a hosted runner (APT 2.8.3) | **All PASS**, lab run 41111194290 (`fb1-t4/`). E2, E5, E6 and E7 are reproduced against the fix. A future ID is refused by the guard and, with the guard bypassed, by the pin check. build-ova.sh's own fetch block stops on a wrong pin. On the fetched real indexes, 325c142a is refused on exactly the 57. |
| T5: the next built OVA | **Pending:** it needs an owner-approved replacement build. |

**Before the next build, raise the pin.** 44 of the 57 live-only versions are security-pocket updates. A build correctly pinned to `20261002T120000Z` would ship older versions than 325c142a. The readiness report §0-FB1 has the prerequisite list.


## 7. Corrections and pin raise (31 Oct 2026)

This section covers ASTRA's two findings on §6 and the owner-authorized pin raise. §1–§6 are unchanged as the record of 30 Oct.

### 7.1 The snapshot ID is a real UTC instant, earlier than one recorded build start

**Finding.**
- The ID check was a regex followed by a lexical comparison against `date -u` read at the point of the check.
- So `20260230T120000Z` and `20251340T256199Z` passed.
- The "now" it compared against was read inside the guest, after host downloads had already happened.

**Fix.**
- `apt_snap_utc_instant` passes an ID only if `date -u -d` parses it as a UTC instant **and** formatting that instant reproduces the input byte for byte.
- The round trip does not rely on `date` refusing an impossible date: GNU date refuses one, but a normalizing `date` (busybox, BSD `-j`) would roll it over to another day.
- `build-ova.sh` records **one** build start (`GUEST_APT_BUILD_START`) before the base-image download. It validates the pins against that instant at that point, before any network fetch.
- The same value goes to the guest through the overlay manifest, and into `build-info.json` as `apt_build_start`.
- The guest re-checks the ID against that recorded instant, never against its own clock.

**Tests** (`RequirePinsRefusesBadIDsAndPins`, `RequirePinsUsesTheRecordedInstantNotTheClock`). Each of the following is refused:
- 30 Feb, ASTRA's `20251340T256199Z`, 29 Feb 2026, hour 24, minute 60, second 60, a leading space, a missing `Z`;
- an ID equal to, or later than, the build start;
- a missing or impossible build start;
- an impossible ID under a normalizing `date` stub.

Two controls show the recorded instant decides, not the clock:
- IDs in 2020, long before now, are refused when they are after the recorded start;
- a clock stub reading 1970 is ignored.

T4 C2 adds the impossible IDs on the hosted runner.

### 7.2 Package bytes are bound to authenticated metadata, not just versions

**Finding.**
- The reconciler compared versions only.
- Docker's repository has no snapshots, so a self-consistent Docker index listing another `.deb` hash for the pinned version passed (ASTRA's reproduction).

**Fix: three layers.**

1. **Reviewed Docker `.deb` pins.** `manifest.env` now carries `*_DEB_SHA256` for the four Docker packages. Each value was read from Docker's gpgv-verified index and hashed from the downloaded file. The engine three equal M1's verified identities (`fb1-snapshot-20261029/docker/`).
2. **Guest acquisition receipt.**
   - `prepare-guest.sh` records `acquired-debs.tsv` from the `.deb` files themselves: `dpkg-deb -f` for package/version/architecture, plus `sha256sum`.
   - It records the receipt once after the Docker install and again before `apt-get clean`.
   - It refuses a Docker `.deb` whose version, architecture or SHA-256 is not the pin, and a missing or duplicate Docker file.
   - Phased updates are always included (`Always-Include-Phased-Updates`), so resolution never depends on the build machine's phasing hash.
3. **Host reconciliation.** `reconcile-package-provenance.py --acquired` refuses all of the following:
   - an acquired file whose SHA-256 differs from the **authenticated snapshot index** entry for the same package/version/architecture;
   - an acquired Docker file that differs from the reviewed pin;
   - a Docker index listing another hash for a pinned version;
   - one package/version acquired as two different files;
   - an acquired `.deb` the snapshot does not list;
   - a Docker package installed without a verified acquisition;
   - an empty or malformed receipt;
   - a missing byte pin.

   Each `package-provenance.tsv` row now carries **binding**:
   - `acquired-verified`: this build downloaded the bytes and they matched;
   - `inherited-base-image`: the package was already in the base image at the snapshot's version.

**Limit, stated so it is not overread.** Inherited packages were not downloaded. Their bytes are bound only by `BASE_IMAGE_SHA256`, the signed cloud-image file, not package by package. The reconciler reports their count separately and never claims byte identity for them. (*§7.4 below: in `4f56bdfc` the inherited label was a fallback for any package without a receipt; it is now bound to the recorded base inventory.*)

**Tests:**
- `DockerByteBindingRefusesASelfConsistentIndex` (ASTRA's reproduction);
- `AcquisitionReceiptFailsClosed`: same name/version/architecture with different bytes, for Ubuntu and for Docker, plus each refusal above;
- `GuestReceiptAndDockerByteCheck`: real `.deb` files built with `dpkg-deb`: control, different bytes, wrong version, missing file, duplicate file, empty cache.

**Mutation check: 14 of 14 caught.** Two lines were each disabled and caught separately:
- the round-trip compare (caught only by the normalizing-`date` case, which was added for that reason);
- the build-start order.

The others:
- build-start validation;
- the guest Docker SHA check;
- the empty-receipt refusal;
- the Docker index pin;
- Ubuntu and Docker acquired-byte comparisons;
- the Docker-must-be-acquired rule;
- the duplicate-file rule;
- `--acquired` being required;
- unknown acquired files;
- the build-ova pin call;
- the guest verify call.

### 7.3 The pin: `20261029T180000Z`

Selection, authenticated metadata, kernel window, full comparison against 325c142a, and Docker index evidence: `fb1-snapshot-20261029/README.md`.

**Summary.** The four InRelease files are byte-identical to the indexes the owner-approved kernel-42 transaction was resolved against.

Against the 325c142a inventory, using Debian ordering:

| Class | Rows |
|---|---|
| unchanged | 671 |
| Docker, unchanged at the pins | 4 |
| kernel meta upgrade, 7.0.0-38 → 7.0.0-42.42~24.04.1 | 1 |
| 7.0.0-42 kernel packages added | 4 |
| superseded 7.0.0-38 kernel packages purged | 4 |
| downgrades | **0** |
| versions outside the snapshot | **0** |

All 209 rows whose 325c142a version is in noble-security are kept or superseded by the approved kernel. There is no conflict between the owner's three constraints at this snapshot, so no alternative is proposed.

**Network checks** (lab, `.github/lab/fb1-c5.sh`, hosted runner, APT 2.8.3). C6 adds a real acquisition under the pin:
- the four Docker `.deb` files equal their manifest pins, through the production receipt and check;
- the five kernel `.deb` files are 7.0.0-42.42~24.04.1;
- each kernel file equals its authenticated snapshot index entry **and** the approved kernel-42 identity (`esxi-325c142a/kernel-42/kernel-debs.tsv`).

The run IDs and the checkout SHA are in the PR #1528 handoff and in the readiness report §0-FB1b.

**T5 remains pending.** On the replacement OVA it requires:
- its own `package-provenance.tsv`: 0 non-snapshot rows, every Docker row `acquired-verified`;
- `acquired-debs.tsv`;
- InRelease hashes equal to the manifest.

### 7.4 A missing receipt is not an inheritance (ASTRA, review of `4f56bdfc`)

**Finding.** In `4f56bdfc`, any installed Ubuntu package without a receipt row was labelled `inherited-base-image`, without checking that the base image carried it. Deleting a row from `acquired-debs.tsv` therefore passed. This was confirmed on real data. Against the base image of serial 20260926, 94 of the 680 predicted rows are not in the base at that exact version/architecture: 67 upgraded, 27 new. Any of the 90 Ubuntu ones could have lost its receipt and still passed.

**Fix.**
- `build-ova.sh` reads `/var/lib/dpkg/status` from the verified base image file **on the build host, before any guest step** (`virt-cat -a "$BASE_FILE"`). The file is never modified and the guest never writes it, so the record is pre-transaction by construction.
- The record is written to `base-dpkg-status.txt`, and its SHA-256 goes into `build-info.json`.
- The reconciler requires `--base-status`. A package without a verified acquisition is accepted only when that exact installed package/version/architecture is in that status. Otherwise the build fails with `has no verified acquisition and the base image had <version>` or `… and it is not in the base image`.
- The provenance header records the base status SHA-256.

**Tests.**

`MissingReceiptNeedsTheBaseInventory` runs on real data: the real 325c142a rows, the **real** base status (fixture sha256 `3fde68c0…`) and a receipt holding exactly what the base lacks. Each of the following is refused:
- an upgraded package with its receipt deleted (`dracut-install`, base `060+5-1ubuntu3.3`);
- a newly installed package with its receipt deleted (`fontconfig`);
- every Ubuntu receipt row deleted: exactly the 33 such rows of that fixture population.

Synthetic cases (`MissingReceiptBaseInventoryIsExact`):
- refused: an older base version, the same version on another architecture, only config files left, an empty status;
- refused: a missing `--base-status` argument;
- controls that pass: an exact base row, and an older base version that was acquired.

`T3b` now uses the real base status, and checks the 4 + 33 acquired-verified and remaining inherited bindings.

`T2` pins three things: the read from `$BASE_FILE` after verification and before the disk and the guest step; the `--base-status` argument; and the empty-status refusal.

**Mutations: 8 of 8 caught**, including the `4f56bdfc` fallback itself, a name-only match, counting config-file stanzas, and reading the status from the customised disk.

**Network check** (lab). The lab re-reads the base status from the freshly downloaded and verified image, with the same `virt-cat` command, and requires it to equal the fixture. It then downloads all 94 packages the base lacks (C7). Every Ubuntu file must equal its authenticated index entry, and every Docker file its pin. The predicted inventory then reconciles to `acquired-verified=94 inherited-base-image=586`. Three receipt deletions are refused:
- `openssh-server` (upgraded: the base had `…13.19`);
- `pigz` (new);
- all 90 Ubuntu rows.
