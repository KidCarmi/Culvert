# ESXi custody, rollback, risks and owner-authorized operations (OVA 325c142a)

The producer prepared this; ASTRA verifies the live state in PLAN.md Q0 before anything changes. **Nothing in this file has been executed.**

## 1. Existing VM custody, as last recorded by ASTRA

Source: review 5592731454 and the ASTRA shared ruling of 27 October.

| Item | Value |
|---|---|
| ESXi host | ESXi 8.0.1 build 21813344; designated datastore and network; one test VM at a time |
| Current VM | `culvert-esxi-b4f5d6ed9cc5`, UUID `564d26f1-1bef-ab61-7274-013aa2c30f09`, IP **192.168.1.141**, 2 vCPU / 4 GiB / 40 GiB, E1000 |
| What it runs | The superseded candidate OVA `27006cf4…` (source `4524311b`), restored with its state and history after a source-absent restore. It carries the ESXi failed-service display **FAIL** and the R1 writer defect; the old engine 29.9.0 and the old sidecar. **Not** a qualification target for 325c142a. |
| Retired earlier | Baseline `culvert-esxi-fa07985246e9` (UUID `564dda03-…`) and source VM `culvert-esxi-1a92064ce02c` (UUID `564d3a09-…`), both removed under explicit authorization. Their custody archives are sealed by ASTRA (DPAPI-encrypted, hash-verified). |
| Standing instruction | "Preserve one current VM/custody and broad NIC support. No VM action now." |

## 2. Proposed VM arrangement for qualification

**Recommended: leave the existing VM exactly as it is.** Import the new OVA as a **separate** VM named `culvert-esxi-325c142a`, on a free IP (not .141), only after Q0 confirms both conditions below.

| Condition (from Q0) | Requirement |
|---|---|
| Host headroom | 2 vCPU + 4 GiB RAM free for a second VM |
| Datastore | ≥ 48 GiB free |

- **Why:** the existing VM stays the untouched rollback baseline and custody object. Nothing about it changes, so no snapshot is needed.
- **If the host cannot run two VMs** (the earlier campaign's "one test VM at a time" rule): power the existing VM **off** before the import. Do not delete or snapshot it. Powering off is reversible and leaves its disks and registration intact.

Either way, the existing VM is never deleted, re-IP'd, upgraded or restored into during this campaign.

## 3. Rollback procedure

Abort at any step, for any reason, including any STOP trigger:

1. **Power off** `culvert-esxi-325c142a`. Do not delete it: it is evidence. Record the time and the reason on #1528.
2. If the existing VM was powered off (§2 fallback):
   - power it on;
   - wait for `http://192.168.1.141:8080/health` to return 200;
   - log in as its admin;
   - confirm `/ready` returns 200 and one allowed and one denied request return 200/403.
3. **IP conflict at any point:** power off the new VM first, then check that .141 answers as before.
4. **Datastore pressure** (free space under 10 % while the campaign runs): power off the new VM; no deletion without approval.
5. **No other rollback exists or is needed:**
   - no host-level setting, vSwitch, port group, datastore or other VM is changed by this plan;
   - all guest changes stay inside the new VM.

**Removing the new VM's disks afterwards** is a separate destructive decision (§4, O9), never part of rollback.

## 4. Operations that need the owner's authorization

One approval can cover O1–O8 as a bundle. **O9 and O10 stay separate decisions.**

| ID | Operation | Reversible? | Notes |
|---|---|---|---|
| O1 | Make **one private, checksum-verified custody copy** of the OVA artifact before 2026-11-10 (`RETENTION-PROPOSAL.md`) | yes (delete the copy) | Needed regardless of ESXi; the only copy the plan makes |
| O2 | Use that custody copy as the import source on the ESXi admin workstation (ovftool reads it; ESXi writes the VM's own disk) | yes | Creating the VM disk is inherent to import; no second file copy is retained outside custody |
| O3 | Read-only inventory of the ESXi host (Q0) | n/a | Read-only, but on the owner's infrastructure |
| O4 | Create and power on VM `culvert-esxi-325c142a` (2 vCPU / 4 GiB / 40 GiB thin, E1000, designated port group, free static IP) | yes (power off) | — |
| O5 | §2 fallback only: power off the existing VM `culvert-esxi-b4f5d6ed9cc5` for the campaign, then power it back on | yes | Skipped when the host has headroom |
| O6 | Guest-level test mutations inside the new VM only, all recorded and cleaned up | inside the new VM | setup + first admin; policy rules; Exempt posture; ClamAV stop/start; backup; restore commit; temporary failing/slow systemd units; temporary HTTP serving of the M2 probe |
| O7 | `culvert-os-update os` + reboots inside the new VM | inside the new VM | Proceeds **only** if `check` shows no newer `linux-image` (otherwise STOP) |
| O8 | Retain the evidence tarball in ASTRA's sealed custody; publish only its SHA-256 and the redacted results on #1528 | yes | Excludes the setup token, the admin password and recovery secrets |
| O9 | **Separate:** delete the new VM's disks, or retire the existing VM, after the campaign | **no** | Decided after the report; default is keep both, powered as left |
| O10 | **Separate:** any access change to the public Actions artifact (for example deleting it early to end public availability) | **no** | Not proposed (see the retention proposal) |

**Not requested, and not done by this plan:**
- rebuild, merge, release, pilot, customer or production use;
- a second OVA;
- host, vSwitch or datastore changes;
- snapshots of the existing VM;
- any change to the existing VM other than O5.

## 5. Risks

| Risk | Likelihood | Effect | Control |
|---|---|---|---|
| Live failed-service display fails again on real ESXi VGA (historical FAIL) | low–medium: the fix is in these bytes and passed QEMU SVGA, but ESXi VGA was the failing medium | Q9 fails; qualification incomplete | Exact expected lines in PLAN Q9; report as FAIL with frames. No rebuild without a new decision. |
| ESXi storage latency pushes recovery over 120 s (historical 141.218 s on 6248) | low–medium (27006cf4 ESXi: 67–79 s) | Q7 fails | Record per-phase timing (`recovery-time.md`); report, do not retry into a pass |
| A released HWE kernel (98532/98573 work in progress in 7.0.0-42) lands during the window | medium | `os` would install a different kernel | Q0 and Q6 `check` guard: STOP before `os` (trigger 2) |
| The OVA artifact expires on 2026-11-10 before custody is made | high if nothing is done | the qualified bytes become unobtainable; a rebuild would be a new artifact | O1 by **2026-11-07** (`RETENTION-PROPOSAL.md`) |
| The residual window ends 2026-11-26T17:53:38Z | certain | qualification must be complete and reported before then | Schedule: custody ≤ 11-07, ESXi run ≤ 11-20, report ≤ 11-24 |
| IP conflict with the existing VM | low | network disruption to the baseline | Q0 picks a free IP; rollback §3 step 3 |
| Host has no headroom for a second VM | unknown | needs O5 | §2 fallback; reversible |
| Evidence leaks secrets | low | credential exposure | Q11 redaction rule; raw tarball stays private |
| Unsigned candidate image (`CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1`) | certain, by design | none inside the internal scope | Internal-only; never for customers |
| Live IdP still unqualified | certain | an open gate outside this plan | Stays BLOCKED, declared |
| Datastore fills (thin 40 GiB) | low | VM I/O errors | Q0 ≥ 48 GiB; rollback §3 step 4 |
