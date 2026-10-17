# Maintenance-reboot recovery time

**Budget:** each of at least three consecutive maintenance reboots (`sudo culvert-os-update reboot`) must recover within **120 s**.

- **Start of the clock:** the authenticated acceptance of the reboot.
- **End of the clock:** the third consecutive 5-second sample in which all four of these hold:
  - `/ready` is ok with ClamAV;
  - allowed and blocked traffic are both enforced;
  - a fresh EICAR body is blocked by ClamAV;
  - the operator phase reports `ready`.

First-install time is measured separately.

## Why it is slow

Recovery time depends on read latency, not CPU or throughput.

Every maintenance reboot reads the same data:

- about 3,400 small reads before the kernel starts, as firmware and GRUB load the kernel and initrd;
- about 15,000 reads after that, roughly 750 MiB, for systemd, the container engine, container layers and the ClamAV database.

The time therefore grows by about 9 s for every millisecond of disk read latency. ESXi E0 measured 114–162 s with the unchanged OS, which corresponds to roughly 9–14 ms of read latency. ASTRA also measured shared-device read latency as high as 90 ms during the slowest runs.

## Controlled comparison

**Setup:**
- QEMU lab, run 37389977929.
- The retained b579 OVA.
- The disk delayed by 12 ms per read and 3 ms per write through device-mapper. This profile reproduces the ESXi baseline.
- Three maintenance reboots per variant.

| Variant (cumulative) | Recovery (s, ×3) | Δ | Kernel start |
|---|---|---|---|
| unchanged | 146.8 / 146.6 / 146.5 | | +47.1 s |
| read-ahead 4 MiB | 116.4 / 116.4 / 116.4 | −30 s | +47.1 s |
| + snapd/ModemManager/udisks2/multipathd/apport masked | 116.4 ×3 | 0 | +47.1 s |
| + cloud-init disabled after first boot | 103.1 ×3 | −13 s | +47.1 s |
| + `MODULES=dep` initrd (37.3 → 25.1 MB) | 95.3 ×3 | −8 s | +38.9 s |

In every case:
- state persisted (admin, policy, CA, image, agent);
- the first post-reboot backup listing passed (about 1.7 s);
- traffic was enforced.

## What ships

**4 MiB read-ahead** for whole disks: `appliance/provision/60-culvert-readahead.rules`.
- Installed into the image by `prepare-guest.sh`.
- It does not depend on the hypervisor.

**cloud-init disabled once first boot completes**: `culvert-firstboot` `step_finish` writes `/etc/cloud/cloud-init.disabled` after its completion marker.
- Its per-instance work (users, keys, password, hostname, network) is done by then.
- `culvert-appliance-reset-identity` removes the marker, so a reset or cloned appliance regenerates its identity through cloud-init on its next boot.
- An unwritable marker is logged and never fails provisioning.

**Periodic root fsck disabled**: `build-ova.sh` runs `tune2fs -c 0 -i 0` on the
root ext4 (guestfish `maxmountcount:0 intervalbetweenchecks:0`) right after the
in-place grow, and the build then re-reads `tune2fs -l` and refuses any ext4
with a mount-count or time-based check still armed (`$OUT/root-fsck-policy.txt`
records the base and final policy).
- A periodic check fires a FULL root fsck on some later maintenance reboot; on
  slow ESXi-like storage that adds ~20-30 s to local-fs and can push the
  recovery over the 120 s budget. `tune2fs -c 0 -i 0` disables ONLY the
  mount-count and time-based schedules; error-triggered checking and the ext4
  journal recovery are untouched, and the on-boot check of a cleanly-unmounted
  fs stays instant. This is not a free integrity win: with no scheduled sweep,
  latent on-disk corruption is surfaced only on an error or journal-replay
  trigger, so a necessary repair must never be suppressed to meet the timing
  budget. The operator path for a suspected-corruption case is an OFFLINE check
  — stop the stack, boot the recovery shell (or attach the disk to another
  host) and run `e2fsck -f /dev/sda1` against the unmounted root before
  returning it to service.
- Motivated by ASTRA's 141.218 s ESXi reboot showing local-fs at ~32 s with a
  suspected fsck transition, vs a clean 8.9 s local-fs in the calibrated 12 ms
  lab run (recovery-ab run 38989972928, 6248daf7: 107.69 / 107.53 / 107.52 s,
  under budget). That ~23 s local-fs delta is only part of the full
  141.218 − 107.5 ≈ 33.7 s recovery gap; the remaining ~11 s sits in other
  stages (firmware/kernel/initrd read time at higher latency) and is NOT
  attributed to fsck. A `local-fs` milestone or a journal-replay line does not
  by itself prove a periodic full check — the real-ESXi capture must carry the
  initramfs/systemd fsck output, `tune2fs -l` policy/state, and concurrent
  datastore latency to separate a scheduled fsck from pure latency. The
  build-time report makes the shipped base policy visible for that comparison.

**`e2scrub_all.timer` masked**: `prepare-guest.sh`. The appliance root is a
plain partition with no LVM snapshot target, so the periodic online scrub has
nothing to scrub. Masking it is housekeeping — it removes a no-op timer, not a
measured recovery gain. `e2scrub_reap` (stale-snapshot cleanup) is left alone —
it is instant.

## What does not ship, and why

**Service masking** gave no measurable gain, so it is not worth the change.

**`MODULES=dep`** builds the initrd with only the drivers of the machine that builds it.
- The OVA is built on QEMU (virtio) and deployed to ESXi (`vmw_pvscsi` / LSI), VirtualBox, Proxmox VE / KVM and other hypervisors. An initrd without their storage drivers would not boot.
- The −8 s / 37.3→25.1 MB in the table above is the MEASURED figure for `MODULES=dep` on the b579 payload. A curated `MODULES=list` covering every supported controller is the safe form of it, but its size and gain on the CURRENT payload are an ESTIMATE until measured — do not transfer the `dep` number to it.
- It is a separately-qualified optimization, not part of the fsck-policy change. Before it can ship it needs, per supported profile (hypervisor/version, disk controller + transport, firmware mode, NIC — ESXi AND Proxmox VE/KVM AND VirtualBox explicitly): cold boot, maintenance reboot, kernel-update/initramfs-regeneration boot, and the supported recovery path. Generic QEMU success is not Proxmox qualification.

## How this is proven

The candidate OVA built from this source is qualified in two places:
- the QEMU lab, on the same profile;
- ESXi, independently by ASTRA, with at least three reboots.

Storage latency on a shared device is infrastructure. The changes above lower the number of seconds paid per millisecond of latency. They do not set that latency.
