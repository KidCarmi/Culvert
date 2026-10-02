# Culvert appliance — hypervisor qualification

What was tested, on what, with which artifacts; and what is explicitly **unsupported / untested**. Evidence
vocabulary: **RAN** = executed in the build environment (QEMU, no KVM — TCG software emulation);
**UNTESTED** = not executed anywhere by us; **SRC** = reasoning from the descriptor/image only.

Artifact under test: see §1 (digests from `culvert-appliance-<ver>.build-record.json`).

## 1. Artifact

_(filled from the build record once the build completes — see ASTRA-STATUS.md Track F)_

## 2. Qualification matrix

| Hypervisor | Import path | Status | Notes |
|---|---|---|---|
| **QEMU 8.2.2 / TCG** (Ubuntu 24.04 host, no `/dev/kvm`) | qcow2 output, virtio disk + virtio-net, NoCloud seed | **RAN** — see §3 | Software emulation only; timings are 10–20× slower than KVM and are not performance evidence. |
| QEMU/KVM, libvirt, Proxmox | same qcow2, VirtIO | **UNTESTED** (no KVM in the build environment) | Same guest/kernel/drivers as the TCG run; the only difference is the accelerator. Command: `appliance/qualify/qemu-qualify.sh --image <qcow2> --work <dir> --accel kvm`. |
| **VMware vSphere / ESXi** (primary target) | `.ova` (OVF 1.1, VMX-10, VirtualSCSI/pvscsi, VmxNet3, BIOS, vApp properties for cloud-init OVF datasource) | **UNTESTED** — no ESXi host and no `ovftool` in the build environment | Descriptor is shaped after Canonical's own ESXi OVA for the same guest image (`ubuntu-24.04-server-cloudimg-amd64.ova`, release 20260926), the guest ships `open-vm-tools` 13.0.10 and the `vmw_pvscsi`/`vmxnet3` kernel modules (GA kernel 6.8). The VMDK is `qemu-img`'s streamOptimized output with an `lsilogic` descriptor, which is the same `ddb.adapterType` Canonical's VMDK carries. **Must be imported and booted on a real ESXi host before any customer use**: `ovftool --schemaValidate culvert-appliance-<ver>.ova` then Deploy OVF Template, check (a) vApp properties appear, (b) console banner appears, (c) `ip link` shows `ens192`, (d) first boot provisions. |
| VMware Workstation / Fusion | `.ova` | **UNTESTED** | Same OVF; Workstation ignores vApp properties unless OVF environment transport is supported — cloud-init then runs with no datasource (DHCP, no keys) and the console one-time password is the way in. |
| Microsoft Hyper-V | — | **Unsupported in this slice** | No VHDX output produced (`qemu-img convert -O vhdx` would be trivial; cloud-init would need the NoCloud/`None` path; Gen2 would need UEFI + the image's `grub-efi`). Not qualified. |
| VirtualBox | `.ova` | **UNTESTED** | VirtualBox imports OVF 1.1 but maps pvscsi/vmxnet3 to its own controllers; expect to swap to AHCI/virtio-net at import. |
| Nutanix AHV, KVM-based clouds | qcow2 | **UNTESTED** | Should behave like QEMU/KVM; cloud-init datasource would be ConfigDrive/NoCloud. |

## 3. QEMU/TCG qualification runs (RAN)

_(filled from `appliance/qualify/qemu-qualify.sh` evidence — RESULT.txt and the per-check files — once the
run completes; see ASTRA-STATUS.md)_

## 4. OS update + reboot (Track C qualification)

_(filled from the phase-2 evidence)_

## 5. Known limitations of the qualification environment

* No KVM: everything ran under TCG. First boot, provisioning logic, systemd units, docker, compose, the
  agent, the enforcement path and the reboot cycle were exercised for real; **performance was not**.
* No direct egress: the build environment reaches the internet only through an HTTP proxy with a host
  allowlist. The phase-2 "allowed request" and the apt update therefore went through that proxy as a
  *parent proxy* configured in the appliance (`/api/upstream/entries`) and as an apt proxy — test wiring,
  recorded in the evidence; a customer appliance talks to the internet directly or through its own parent
  proxy.
* No ESXi, no ovftool: OVF validity is asserted structurally (manifest hashes, OVF 1.1 ordering, XML
  well-formedness) and by provenance (Canonical's descriptor for the same guest image), not by import.
