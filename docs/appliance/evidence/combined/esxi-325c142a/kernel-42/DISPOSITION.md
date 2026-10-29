# Kernel 7.0.0-42 disposition for the ESXi resume (OVA 325c142a)

**Producer:** OPUS. **Decision:** ASTRA checks this independently, then resumes on `culvert-esxi-325c142a` under owner approval 6505106369 (option 1).

**Scope:**
- This file is evidence only. It changes no frozen input: not the OVA, not source `0648adeb`, not `freeze-0648adeb/BOM.md`, not the M2 residual (revision 3).
- Every item below was produced in an isolated producer sandbox. Nothing touched ESXi.

## 1. The transaction `culvert-os-update os` will run

**Method:**
- Start from the **exact OVA inventory**: 680 packages from the exact-byte scan, run 40579.
- Evaluate it with **APT 2.8.3**, the guest's version, against the **signed live archive**. Index details: `apt-indexes.txt`. The archive key is F6EC…C93C and every InRelease returned "Good signature". Index dates:
  - noble-updates: 29 Oct 13:22Z
  - noble-security: 29 Oct 16:38Z
- Keep the shipped snapd pin and the four Docker holds.

**Result** (`apt-transaction.txt`): 1 upgraded, 4 newly installed, 0 removed, 0 kept back. Kernel only.

| Package | Change | SHA-256 (signed index, re-hashed after download) |
|---|---|---|
| `linux-image-virtual-hwe-24.04` | 7.0.0-38.38~24.04.4 → 7.0.0-42.42~24.04.1 | `ce9dba0a…3c0a` |
| `linux-image-7.0.0-42-generic` | new | `92a0665c…d72c` |
| `linux-modules-7.0.0-42-generic` | new | `c59cd391…d3a0` |
| `linux-main-modules-zfs-7.0.0-42-generic` | new (like-for-like with the shipped 38 package) | `11dda212…5832` |
| `linux-main-modules-v4l2loopback-7.0.0-42-generic` | new (like-for-like) | `34eefa09…69df` |

**Notes:**
- **Same set ASTRA observed.** These are exactly the 5 packages ASTRA reported from the VM on 28 Oct.
- **Pockets:** all five come from **noble-updates only**. They are not in noble-security, so unattended-upgrades (security pocket only) cannot install them by itself.
- **Not phased.** No `Phased-Update-Percentage` is set on any of them. Simulating with `Always-Include-Phased-Updates` gives identical lines.
- **Only one dependency changes.** The metapackage's `Depends` moves from `linux-image-7.0.0-38-generic` to `-42-generic`.
- **`autoremove --purge` removes no kernel** (`autoremove-kernel-protection.txt`):
  - APT 2.8.3 protects the booted kernel (38 during `os`) and the newest two (42, 38).
  - So 38 stays installed as a GRUB fallback after the reboot.
- **Non-kernel autoremove** depends on the guest's `extended_states`, which the inventory does not carry. The transaction cannot make a non-kernel package newly removable.
- **Pending-transaction rule for ASTRA, before `os`:** run read-only on the console:
  - `apt-get -s upgrade --with-new-pkgs`
  - `apt-get -s autoremove --purge`
  
  **STOP and report** if either differs from the 5 packages above / 0 removals. A different set is a transaction nobody reviewed.

## 2. Module and configuration delta, 38 → 42

Source file: `module-config-delta.txt`. The 38 config is byte-identical to the shipped `/boot/config-7.0.0-38-generic`.

**`.ko` set:** 6903 files in each kernel, with one change each way:
- **Removed:** `platform_profile`. It became built-in: `ACPI_PLATFORM_PROFILE` m→y.
- **Added:** `i2c-hid-acpi-prp0001`. It loads only on a matching ACPI device.
- Neither name is on the denylist.

**ZFS and v4l2loopback** (the owner asked about these packages): each 42 package carries the same module names as its 38 predecessor (`spl`, `zfs`; `v4l2loopback`). Neither is denylisted, and neither appears in any earlier M2 loaded-module list. They are installed, not loaded: autoloading needs a root-only action (a ZFS pool import, or a v4l2 user).

**Shipped denylist:** 66 of its 67 names are loadable modules in both kernels. `dccp` has been removed upstream in both, so its entry is inert. No denylisted module became built-in.

**M2 precondition modules:** availability is identical in 38 and 42.

**Configuration:** 9 options differ. Only one matters for security:

| Change | Effect | M2 relevance |
|---|---|---|
| `CONFIG_LSM` gains `bpf` | **BPF LSM is active by default on 42.** No `lsm=` override is on the command line. | Attaching an LSM program needs at least `CAP_BPF` and `CAP_MAC_ADMIN`. Docker's default capability set grants neither (each container's raw CapBnd is recorded at every M2 checkpoint). Docker's seccomp allows `bpf()` only with `CAP_BPF`/`CAP_SYS_ADMIN`. `unprivileged_bpf_disabled=2` is unchanged. **Net effect:** a new root-only kernel surface; no change for containers or restricted principals. Recorded, not mitigated. |

**Unchanged** in both kernels: `IO_URING=y`, `BPF_UNPRIV_DEFAULT_OFF=y`, `BPF_LSM=y`, `FUTEX_PRIVATE_HASH=y`, `PAGE_POOL_STATS=y`.

## 3. CVE mapping with patch inclusion

**Method**, per CVE (three independent sources):
1. The Ubuntu tracker status (`ubuntu-status-20261029.txt`, retrieved 29 Oct ~18:50Z).
2. The fix subject in the **42 changelog entry** versus the 38-and-older entries.
3. **Source:** the added lines of the upstream fix commit (Ubuntu's `break-fix`, from the torvalds tree), matched file by file in Ubuntu's `linux-hwe-7.0` diff.gz.
   - 38 diff: `cd099699…30ff`
   - 42 diff: `ab5b2722…b076`
   - Both were verified against the signed Sources index.

**Limits of the method:**
- It verifies the **source package**. The binaries are Ubuntu's build of that same version, signed in the same archive; I did not disassemble them.
- A "pending" tracker status means the fix is committed in that version but **Ubuntu has not marked it released**. This is why the tracker still shows these as open.

### 3a. The M2-named findings (`cve-source-inclusion.tsv`)

| CVE | Area | Tracker (hwe-7.0, noble) | 42 changelog | Fix lines 38 → 42 | 42 verdict |
|---|---|---|---|---|---|
| **98532** | `ipv6_find_hdr` past end | pending 42 | yes | 0/2 → 2/2 | **fixed (source)** |
| **98573** | `skb_checksum_setup_ipv6` underflow | pending 42 | yes | 0/3 → 3/3 | **fixed (source)** |
| **98503** | AF_PACKET TX_RING | pending 42 | yes | 0/42 → 42/42 | **fixed (source)** |
| 98570 / 98526 / 98487 / 98588 / 98567 | lwtunnel headroom, llc, bridge mdb, sockmap, xps | pending 42 | yes | 0 → all | fixed (source) |
| 98441 / 98442 | act_ct | pending 42 | yes | 0 → 8/8, 4/5 | fixed (source)¹ |
| 98624 / 98625 | nfnetlink_queue, flowtable HW_DEAD | pending 42 | yes | 0 → all | fixed (source) |
| **98788** | futex private-hash UAF on resize | **needed** | **no** | 0/2 → 0/2 | **NOT fixed** |
| **98858** | io_uring SQPOLL | **needed** | no | 0 → 0 | **NOT fixed** |
| **98804** | page_pool recycle | **needed** | no | 0 → 0 | **NOT fixed** |
| **98792** | flowtable pending bit | **needed** | no | 0 → 2/10² | **NOT fixed** |
| **98797** | skbedit/mirred queue_mapping | **needed** | no | 0 → 0/26 | **NOT fixed** |

¹ 98442's one unmatched line is present in 42 in its 7.0-stable form, which adds an `add_helper` clause.

² The 2 matching lines also occur in the 98625 fix.

**98788 is not fixed.** The 42 entry carries three *other* futex private-hash fixes:
- "Avoid private hash use-after-free on final put"
- "Fix race in futex_pivot_pending() during private hash resize"
- "Also allocate private hash on vfork()"

None of them is the 98788 fix. Do not read them as closing it.

### 3b. All 185 CRITICAL/HIGH "present" findings on 38 (`kernel-cves-38-vs-42.tsv`)

The exact-byte scan classed 185 CRITICAL/HIGH kernel findings as "present" on the shipped 38 (6 CRITICAL, 179 HIGH):

| Outcome on 42 | Count | Notes |
|---|---|---|
| Fix in the 42 source, absent from 38 (tracker "pending" in 39 or 42) | **127** | Includes **5 of the 6 CRITICAL**: 89530, 89652, 98365, 98571, 98621 |
| Tracker "pending", but **not verified** by line match (partial match, no match, or no comparable lines) | **17** | Probably context-adapted backports. **Not claimed.** |
| **No Ubuntu fix** (tracker "needed") | **41** | Includes **CRITICAL 98725** (nvmet-auth: `nvmet.ko` is not loaded; ASTRA already credits its non-reachability) and **98788** |

**Not claimed:** "all fixed". **41 findings (plus 17 unverified) remain** after the upgrade.

## 4. Two postures, reported separately

| | **As shipped: 7.0.0-38**, first boot (Q2–Q5 done on ESXi; QEMU run 40555) | **After maintenance: 7.0.0-42** (the state from Q6 onward) |
|---|---|---|
| Kernel findings | 185 present, as in the exact scan and M2 revision 3 | 127 fixed in source; 41 open; 17 unverified |
| 98532 / 98573 / 98503 | **Open.** The M2 mitigations and checks apply (§1, §3 of the residual). | **Fixed in source.** The mitigations stay as defence in depth. The checks still run because they also cover the other rows. |
| 98788 (futex) | Open: the core residual (§2) | **Open, unchanged.** The bounds of §2 and §4–§7 still apply in full. |
| 98858 / 98804 / 98792 / 98797 | Open, each with its M2 check | **Open, same checks.** |
| New surface | — | BPF LSM active (root only, §2) |
| What qualified it | Q2–Q5 on ESXi; full QEMU | Q6–Q11 on ESXi (below). QEMU never ran 42. |

**The as-shipped posture is what a fresh deployment of this OVA boots.** It stays 38 until the operator runs `os`. The 42 posture is not a property of the OVA; it belongs to an appliance maintained through the product path.

## 5. Revised M2 change-to-test map for the resume

| Check (lab `e6bb0ff0`, unchanged) | Why it is sensitive to the kernel | When on ESXi |
|---|---|---|
| `<tag>-hardening`: io_uring sysctl value, ring census, container capabilities and seccomp, AF_PACKET / io_uring in-container probes | Sysctl and seccomp semantics come from the new kernel | **`reboot` (new: first boot on 42)** and `final` |
| `<tag>-ordering`: systemd-sysctl before containerd/dockerd | New initramfs and boot | `reboot`, `final` |
| `<tag>-preconditions`: module census, unprivileged BPF, NIC driver, namespaces, links/routes/qdiscs | Different `.ko` set and autoload | `reboot`, `final` |
| `<tag>-ruleset`: nft JSON expression gate | The new kernel's nf_tables reports the ruleset | `reboot`, `final` |

**What changes in the procedure:**
- Use the M2 tag **`reboot`** after the OS-update reboot, as in the QEMU checkpoint map (BOM §5).
- On ESXi this is the **first M2 evidence on 42**. In QEMU, `os` did not change the kernel.

**Add five read-only console observations after the reboot.** These need no harness change:
- `uname -r` = `7.0.0-42-generic`
- `cat /sys/kernel/security/lsm` contains `bpf` (records §2)
- `dpkg -l 'linux-image-7.0.0-*'` lists both 38 and 42
- `sysctl kernel.unprivileged_bpf_disabled` = 2 (also covered inside `preconditions`)
- `grep -E '^(zfs|spl|v4l2loopback) ' /proc/modules` returns nothing (installed, not loaded)

**The rest is unchanged:**
- Q7: three timed recoveries of ≤120 s each.
- Q8: encrypted restore.
- Q9: VGA, scoped **post-maintenance (42)**. The as-shipped 38 display remains qualified on QEMU SVGA only.
- Q10: `final`.
- Q11: sealed evidence.

## 6. Provenance finding: the build's snapshot pin did not take effect

**What happened:**
- `prepare-guest.sh` (0648adeb, lines 122/124/133/162/165/202) passes `-o Acquire::Snapshot=<id>`. **APT 2.8.3 has no such key.**
  - Its snapshot option is `APT::Snapshot` (`--snapshot`). The library's strings contain `APT::Snapshot` and `Acquire::Snapshots::URI…`, and nothing else.
  - Clean-room test: `-o Acquire::Snapshot=…` fetches **zero** lists from snapshot.ubuntu.com, and `apt-cache policy systemd` gives the live candidate 8.18. With `--snapshot`, the candidate is the snapshot's 8.17.
- So the build-time upgrade, the kernel-metapackage install and the "snapshot candidate" kernel check all ran against the **live archive of the build day**.

**Evidence in the shipped bytes** (`provenance-nonsnapshot-57.tsv`):
- **57 of the 680 shipped versions do not exist in snapshot 20261002T120000Z.**
- All 57 are in the live archive: 44 in -security and -updates, 13 in -updates only. Examples: systemd 255.4-1ubuntu8.18, tzdata 2026e.
- The build log line "applying guest security updates from the Ubuntu archive snapshot…" and the header of `build-upgrades.txt` are therefore **inaccurate labels**.
- The kernel (7.0.0-38) is the same version in the snapshot and in live, so the kernel is unaffected.

**Impact:**
- **Not a vulnerability.** The OVA received newer packages than the pin allowed.
- **The SBOM/CVE evidence stays valid.** It came from scanning the exact shipped bytes (run 40579), not from the manifest.
- **What is broken is reproducibility.** The documented contract "same manifest ⇒ same package versions" was **not upheld** for this build: a rebuild from 0648adeb would install different versions.
- **Not changed now:** no source, OVA or BOM edit, per the owner's instruction.
- **Recommended for any future build** (owner decision): switch to `APT::Snapshot`, and assert that every shipped version exists in the pinned snapshot.

## Files (`SHA256SUMS`)

| File | Contents |
|---|---|
| `apt-indexes.txt` | Signed InRelease dates, signature results and hashes; status-file provenance |
| `apt-transaction.txt` | Simulated `os` upgrade: default phasing and all-phased |
| `autoremove-kernel-protection.txt` | Post-upgrade autoremove simulation with APT's kernel-protection debug output |
| `kernel-debs.tsv` | Signed-index SHA-256 and size of the 38 and 42 kernel packages; downloaded and re-hashed OK |
| `module-config-delta.txt` | `.ko` sets, denylist, precondition modules and config diff, 38 vs 42 |
| `cve-source-inclusion.tsv` | The 17 M2-named findings: tracker, changelog, fix commit, source lines |
| `kernel-cves-38-vs-42.tsv` | All 185 present findings: tracker and source verdict |
| `ubuntu-status-20261029.txt` | Raw tracker values |
| `provenance-nonsnapshot-57.tsv` | The 57 shipped versions absent from the snapshot |
| `tools/` | `fetch.sh` (signed-index fetch), `mkstatus.py` (status file from the inventory), `srccheck.py` (fix lines against the Ubuntu diffs) |
