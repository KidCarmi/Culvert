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

## Two-latency comparison (candidate 6248daf7, retained bytes)

After ASTRA's capture ruled out fsck, the same retained 6248 OVA was run at two
injected latencies (lab run 39012697264, dm-delay): the calibrated `esxi12`
(12 ms read / 3 ms write) and a diagnostic `esxi30` (30 ms / 15 ms ≈ ASTRA's
device-read mean). 3 reboots each, same bytes, one runner.

| Phase | esxi12 (s) | esxi30 (s) | ×, for a ×2.5 latency step |
|---|---|---|---|
| recovery (total) | 107.7 | 226.9 | 2.11 |
| firmware_gap (pre-kernel: kernel + initrd reads) | 46.6 | 114.3 | 2.45 |
| kernel (initramfs) | 6.8 | 12.9 | 1.90 |
| apparmor | 2.1 | 5.1 | 2.47 |
| dbus | 0.6 | 1.4 | 2.37 |
| containerd | 1.9 | 4.6 | 2.45 |
| containerd metadata→next-plugin gap | 1.40 | 3.50 | 2.50 |
| docker | 2.8 | 6.3 | 2.26 |
| stack resume (compose up → ClamAV ready) | 16.7 | 26.8 | 1.60 |
| boot fsck (UEFI + BOOT only; root skipped) | 1.1 | 2.6 | 2.48 |
| containerd read volume (MiB) | 51.2 | 51.2 | 1.00 |
| docker read volume (MiB) | 116.3 | 116.3 | 1.00 |

Every phase grows with latency and the bytes read stay constant, so recovery is
latency-sensitive. **This step changed read AND write delay together (12→30 ms
read, 3→15 ms write), so it does NOT by itself isolate read cost or rule out
CPU/scheduling/metadata work** — see the read/write isolation below, which does.
Caveat: the dm-delay lab is cache=none + direct-I/O, so every read pays the full
injected latency (a pessimistic bound, not a demonstrated model of ESXi
caching); it proves latency-sensitivity and phase distribution, not an absolute
ESXi number or the original stall's cause.

## Read/write isolation (candidate 6248daf7, retained bytes)

To separate read cost from write cost, the same OVA was run holding one delay
fixed while varying the other (lab run 39037503405, 3 reboots per profile):

| Profile | read / write (ms) | recovery (s, ×3 avg) | effect vs baseline |
|---|---|---|---|
| r12w3 (baseline, 120 s gate) | 12 / 3 | 107.6 | — |
| r30w3 (read varied, write held 3) | 30 / 3 | 217.9 | +110 s / +18 ms read ≈ **6.1 s/ms** |
| r12w15 (write varied, read held 12) | 12 / 15 | 115.6 | +8 s / +12 ms write ≈ **0.67 s/ms** |

**Read latency dominates write by ~9× per ms** (110 s vs 8 s total effect). By
phase, the read arm vs the write arm: pre-kernel +66.5 s / +1.1 s; kernel
+5.9 / +0.3; containerd metadata→plugin gap +2.0 / +0.04 (a read burst, shown
by its own split — not by matching ESXi's 11.5 s); docker +2.5 / +0.9; stack
resume +5.0 / +0.8. The early-boot `/proc/diskstats` sampler recorded
**~774 MiB read / ~28 MiB written per boot (≈27:1)**, consistent with the read
dominance. This isolates read vs write IN THE LAB; it does not establish the
ESXi stall's cause. The product-side read levers are initrd size (pre-kernel —
`MODULES=list`, deferred) and read-ahead/batching + container-layer reads for
the engine/stack phases; per-read latency is infrastructure.

## What ships

**4 MiB read-ahead** for whole disks: `appliance/provision/60-culvert-readahead.rules`.
- Installed into the image by `prepare-guest.sh`.
- It does not depend on the hypervisor.

**cloud-init disabled once first boot completes**: `culvert-firstboot` `step_finish` writes `/etc/cloud/cloud-init.disabled` after its completion marker.
- Its per-instance work (users, keys, password, hostname, network) is done by then.
- `culvert-appliance-reset-identity` removes the marker, so a reset or cloned appliance regenerates its identity through cloud-init on its next boot.
- An unwritable marker is logged and never fails provisioning.

**Periodic root fsck guaranteed off + reported** — policy/reporting hardening,
**NOT the fix for the 141.218 s failure** (ruled out below): `build-ova.sh` runs
`tune2fs -c 0 -i 0` on the root ext4 (guestfish
`maxmountcount:0 intervalbetweenchecks:0`) right after the in-place grow, then
re-reads `tune2fs -l` and refuses any ext4 with a mount-count or time-based
check still armed (`$OUT/root-fsck-policy.txt` records the base and final
policy).
- It disables ONLY the mount-count and time-based schedules; error-triggered
  checking and the ext4 journal recovery are untouched, and the on-boot check of
  a cleanly-unmounted fs stays instant. This is not a free integrity win: with
  no scheduled sweep, latent on-disk corruption is surfaced only on an error or
  journal-replay trigger, so a necessary repair must never be suppressed to meet
  the timing budget. The operator path for a suspected-corruption case is an
  OFFLINE check — stop the stack, boot the recovery shell (or attach the disk to
  another host) and run `e2fsck -f /dev/sda1` against the unmounted root before
  returning it to service.
- **fsck is RULED OUT as the cause of the 141.218 s failure** (ASTRA
  original-path ESXi capture, 17 Oct 2026, retained 6248 boot `13b52b23-…`): the
  root was ALREADY `Maximum mount count -1` / `Check interval 0`, the initramfs
  check reported `cloudimg-rootfs: clean` and was condition-skipped at 22.181 s,
  the journal shows no full root check, and `e2scrub_all` never executed. So
  this change only GUARANTEES and REPORTS a state the retained image already
  had — it does not recover the lost seconds. The earlier "suspected fsck
  transition" hypothesis is retired by that capture.

**`e2scrub_all.timer` masked**: `prepare-guest.sh`. The appliance root is a
plain partition with no LVM snapshot target, so the periodic online scrub has
nothing to scrub. Masking it is housekeeping — it removes a no-op timer, not a
measured recovery gain. NOTE: `e2scrub_reap` is NOT instant — ASTRA observed it
running 35.379→61.084 s (≈25.7 s) CONCURRENTLY with the container-engine phase
on the 141 s boot; ASTRA records it as "not a demonstrated ordering/I/O cause,"
so it is a candidate contributor to investigate, not a proven one, and is left
unmasked pending that evidence.

## Measured recovery phases (ESXi 141.218 s boot)

ASTRA's original-path capture (new-kernel uptime, seconds) localises where the
time goes — latency-bound reads, not fsck:

| Phase | Window (s) | Span |
|---|---|---|
| kernel start → local-fs | 0 → 32.375 | ~32 s (kernel + initramfs + mounts) |
| AppArmor + DBus | 32.65 → 37.95 | ~5 s |
| containerd | 38.65 → 54.68 | 16.0 s (incl. one gap 43.02→54.53 = **11.5 s**) |
| Docker | 54.69 → 68.16 | 13.5 s (container load 60.39→65.56) |
| stack resume | 68.16 → 90.79 | 22.6 s (compose up → ClamAV ready) |

ESXi storage latency on that VM: device read mean ~30 ms / max 67 ms, VM read
mean ~53 ms / max 156 ms — well above the 12 ms lab calibration (which recovers
in 107.5 s). The dominant, latency-sensitive phases are the **pre-local-fs
reads** and the **container-engine + stack** phases; the single largest
identified item is the 11.5 s containerd metadata→next-plugin gap. ASTRA is
explicit that sampled latency is not yet demonstrated causation and that no
guest boot-I/O sampler existed for this reboot — closing that is the next
controlled comparison (per-phase timing + a guest `/proc/diskstats` sampler at
two injected latencies, retained bytes, before any engine/provisioning change).

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
