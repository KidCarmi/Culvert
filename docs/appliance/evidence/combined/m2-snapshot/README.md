# M2 read-only kernel-exposure snapshot (owner 6400728126; ASTRA 27 Oct)

**These are observations only. The dispositions are ASTRA's.**

**Run:** lab run [40472951974](https://github.com/KidCarmi/Culvert/actions/runs/40472951974), lab commit `0071fc13` (harness `m2`).

**Method.** It boots the retained **OVA 61c46d6d** (sha256 and `.mf` verified) to first-boot steady state, takes the snapshot, and stops. There is no build and no qualify campaign. It ran on two disks:

| Variant | Disk | boot_id |
|---|---|---|
| `m2-ova61c46d6d` | **unmodified** OVA disk | `01e9f070-c5e0-405d-8aeb-927319d80a07` |
| `m2-engine-b9105086` | same OVA, M1 engine pins installed into the disposable copy before first boot | `114bf55f-c432-494c-ac9e-c709da01b4a2` |

Both disks report `build-info` `git_commit` b9105086 and kernel 7.0.0-38-generic.

**Strictly read-only:**
- No module is loaded, nothing is mounted, no traffic is injected, and no configuration is changed.
- Commands that can autoload a module (`ip fou`, `ss` sock_diag, `ip tunnel`) are not used. Sockets come from `/proc/PID/net/*`, links from a netlink dump, and FOU is queried only if it is already loaded.
- Module policy comes from `modprobe --showconfig` and `modprobe -n` (dry run, with real exit codes).
- **The loaded-module set is identical before and after the snapshot on both disks** (check `snapshot-loaded-nothing` PASS).
- **The two disks load the identical 72-module set.**
- The only guest change is the normal first console login: one-time password, then the forced change.

Raw output: `M2-snapshot-*.txt`, `checks-*.jsonl`, `identities-*.txt`, `evidence-*.tar.gz`.

## CVE-2026-98621: GUE REMCSUM (fou)

- **`fou`/`fou6` are not loaded on either disk.** No FOU/GUE receive port can therefore exist, and `ip fou` was not run.
- **They are not denied.** There is no `blacklist`/`install` line; `modprobe -n fou` resolves to `udp_tunnel` + `ip6_udp_tunnel` + `fou`. Configuring a GUE port needs `GENL_ADMIN_PERM`, i.e. CAP_NET_ADMIN in the netns.
- **No tunnel interfaces exist** in any of the 3 network namespaces: only `lo`, `ens4`, `docker0`, one compose bridge, and veth/eth0 pairs.
- **UDP sockets in all namespaces are only:**
  - systemd-resolved at `127.0.0.53:53` and `127.0.0.54:53`;
  - the DHCP client on `10.0.2.15:68`;
  - Docker's embedded DNS at `127.0.0.11:<ephemeral>` inside each container namespace.
- **Forwarding:** `ip_forward=1` (Docker); IPv6 is enabled with forwarding 0; `rp_filter=2`.
- **NIC offload** (`ens4`, e1000): rx-checksumming off, tx-checksumming on, TSO on (full list in the snapshot).
- **Neither container holds CAP_NET_ADMIN:**
  - `culvert` runs as user `proxy` with CapEff=0.
  - `culvert-clamav` uses Docker's default set `a80425fb`: NET_RAW and NET_BIND_SERVICE yes; NET_ADMIN, SYS_ADMIN, SYS_MODULE, BPF, PERFMON and SYS_PTRACE no.
  - Both have Seccomp=2 and are unprivileged, with no added caps or devices.

## CVE-2026-98571: stmmac

- **No stmmac/dwmac driver is bound.** No PCI device's modalias resolves to stmmac.
- **The PCI inventory** (QEMU i440FX + the OVF's E1000):

| PCI address | Device | Driver |
|---|---|---|
| 00.0 | host bridge | — (alias `intel_agp`) |
| 01.0 | ISA | — |
| 01.1 | IDE | `ata_piix` |
| 01.3 | SMBus | `piix4_smbus` |
| 02.0 | VMware SVGA | **unbound**: `nomodeset`; alias `vmwgfx` |
| 03.0 | virtio-scsi | `virtio-pci` |
| 04.0 | **Intel 82540EM (8086:100e)** | **`e1000`**, bound to `ens4` |

- **The modules are not denied.** `stmmac`, `stmmac_pci`, `stmmac_platform` and `dwmac_generic` would load, resolving phylink, pcs_xpcs and so on, if a matching device appeared.
- **Limits:** this is QEMU hardware. It says nothing about real ESXi or other hypervisors, and nothing about passthrough NICs.

## CVE-2026-98725: nvmet-auth

- **No `nvmet*` / `nvme_loop` module is loaded.**
- **`nvmet` and `nvmet_tcp` are denied** with `blacklist` + `install /bin/false` in the effective configuration.
- **`nvmet_rdma` and `nvmet_fc` have no line of their own,** but each dry-run dependency chain hits `install /bin/false`: `nvmet_fc` through its denied `nvmet` dependency, and `nvmet_rdma` through `nvmet` and the denied RDMA core. Both chains are in the snapshot.
- **configfs is mounted** at `/sys/kernel/config` (the systemd default), and `/sys/kernel/config/nvmet` is **absent**.
- **Listeners:** no TCP listener on 4420 or 8009 in the root namespace.

## Inputs for the prioritized HIGH clusters

- **BPF and kernel sysctls:**
  - `kernel.unprivileged_bpf_disabled=2`, `perf_event_paranoid=4`, `bpf_jit_harden=0`;
  - **`kernel.io_uring_disabled=0`** (io_uring is available to all users; containers run with Docker's default seccomp);
  - `apparmor_restrict_unprivileged_userns=1`, `max_user_namespaces=12274`;
  - `yama.ptrace_scope=1`, `kptr_restrict=1`, `dmesg_restrict=1`, `kexec_load_disabled=0`.
- **Filesystems registered:** configfs, debugfs, tracefs, bpf, squashfs, fuse/fuseblk, overlay. `binder_linux` is not denied and is not loaded.
- **Logins:** `root`, `culvert`, `sync`, and `culvert-operator` (forced command `culvert-access`). The `docker` group has no members.
- **Packages present at first boot** (before any OS update):
  - `bpftrace` 0.20.2-1ubuntu4.3, `bpfcc-tools` 0.29.1, `linux-tools-common` 6.8.0-147;
  - `ubuntu-kernel-accessories` 1.539.2.

  The first `culvert-os-update` autoremoves these (34 packages; identical on the baseline run). This is an observation for the BOM, not a change made here.
- **Network-autoload denials recorded:** `ip_vs` and `vxlan`. The full effective blacklist/install set has its line count and sha256 in the snapshot.
