# FB-1: the guest APT snapshot pin is not applied; future-build blocker

| | |
|---|---|
| **Status** | **OPEN. Blocks the next release/candidate OVA build.** |
| **Scope** | Specification only. No source, build or OVA change is authorized now (owner 6506229963). |
| **This OVA** | 325c142a's identity, exact-byte scans and qualification evidence remain valid **for its bytes**. Its provenance is not rewritten. Its build was **not** snapshot-locked. |

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
