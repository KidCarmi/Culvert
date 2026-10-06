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

## What does not ship, and why

**Service masking** gave no measurable gain, so it is not worth the change.

**`MODULES=dep`** builds the initrd with only the drivers of the machine that builds it.
- The OVA is built on QEMU (virtio) and deployed to ESXi (`vmw_pvscsi` / LSI), VirtualBox and other hypervisors. An initrd without their storage drivers would not boot.
- A curated `MODULES=list` covering every supported controller is the safe form of this −8 s. It needs boot proof on each supported hypervisor before it can ship.

## How this is proven

The candidate OVA built from this source is qualified in two places:
- the QEMU lab, on the same profile;
- ESXi, independently by ASTRA, with at least three reboots.

Storage latency on a shared device is infrastructure. The changes above lower the number of seconds paid per millisecond of latency. They do not set that latency.
