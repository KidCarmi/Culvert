# `culvert-os-update os` on OVA 325c142a: complete transaction (read-only)

This is a reconciliation for the owner directive 6506229963 and the user directive of 29 Oct.

**Sources:**
- source `0648adeb`, `appliance/os-maintenance/culvert-os-update` l.313–327;
- the signed simulation (`apt-transaction.txt`, `autoremove-34.txt`);
- the QEMU transcript `07-os-update.txt` (run 40555901182);
- the verified `needrestart` deb (sha256 `0fafb623…d174`).

**Nothing was executed on ESXi.** The kernel 38→42 CVE mapping (`DISPOSITION.md` §3) is unchanged.

## 1. Every step, in order

| # | Step | What it does on 325c142a | Evidence |
|---|---|---|---|
| 1 | `guard_maintenance` | Takes the os-update lock and the maintenance-agent lock, and checks the shutdown fence and interrupted-journal guards. **The stack is not stopped.** | source l.66 |
| 2 | `heal_interrupted_dpkg` | Runs `dpkg --configure -a` only if dpkg's journal is dirty. Expected: no-op. | source l.113 |
| 3 | `apt-get update` | Fetches the **live** archive. This is intended: the deployed appliance updates from the archive, not a snapshot. | — |
| 4 | `upgrade --with-new-pkgs` | **1 upgraded + 4 new**, all kernel: `linux-image-virtual-hwe-24.04` → 42, plus `linux-image-`, `linux-modules-`, `-zfs-` and `-v4l2loopback-` `7.0.0-42`. Docker ×4 stays held and is not in the transaction. | `apt-transaction.txt` |
| 4a | Kernel `postinst.d` | `initramfs-tools` builds the **42 initramfs** through the same hooks: `zz-culvert-trim` (version-agnostic; it drops `drivers/{net,infiniband,thunderbolt,usb/typec,mmc}`), plymouth, and the modprobe denylist. `zz-update-grub` applies `99-culvert-splash.cfg`; the GRUB default becomes 42, with 38 under "Advanced options". `/run/reboot-required` is written. | hook source |
| 4b | `needrestart` (APT `Post-Invoke`) | Runs in Ubuntu mode: restart mode `a`, `NeedRestart::UI::Ubuntu`. **It does not prompt**, even on the console TTY: the Ubuntu UI only prints "Pending kernel upgrade!". `docker*` units are listed under `override_rc => 0`, so they are never restarted. No library a running process maps is upgraded, so no service restart is expected. | verified deb: `needrestart` l.263–274 and 950–975; `UI/Ubuntu.pm`; `needrestart.conf` l.119 |
| 5 | `autoremove --purge` | **34 removals, all non-kernel and pre-existing.** The kernel is protected: 38 stays installed as the fallback. | `autoremove-34.txt`, `autoremove-reconciliation.md` |
| 6 | `finish` | Prints `REBOOT REQUIRED: …`. **It does not reboot** unless `--reboot-if-required` is given. The reboot is a separate, deliberate `culvert-os-update reboot`, which does a graceful stack stop, sets the resume marker, and lets `culvert-stack-resume` start the stack at boot. | source l.273–276 |

**Net disk effect:**

| | Size |
|---|---|
| 4 new kernel packages | +175.6 MiB |
| 34 removed packages | −270.8 MiB |
| **Net** | **about 95 MiB freed** |

## 2. Actual functional impact

| Area | Impact | Basis |
|---|---|---|
| Proxy and ClamAV stack | **None during `os`.** The stack keeps running. The new kernel takes effect only after the separate reboot. | steps 1, 4b, 6 |
| Docker / Compose | **None.** Held, not in the transaction, and needrestart is blacklisted for `docker*`. | step 4, `override_rc` |
| Operator console during `os` | **No interactive prompt** from needrestart or the kernel postinst: `--force-confold`/`confdef`, no grub-pc upgrade, Ubuntu-mode UI. | step 4b |
| The 34 removals | **None for the product.** No appliance, provisioning, agent, installer or packaging code uses them. QEMU already ran this exact removal on these bytes, and every later check passed. **Lost:** root-only diagnostics (bpftrace/bcc, perf support, C headers and man pages). | `autoremove-reconciliation.md` |
| First boot on 42 | **Not yet exercised anywhere.** QEMU's `os` had no kernel update (27 Oct). The 42 initramfs, the GRUB entry, the splash and the M2 controls get their first test at the ESXi reboot. That is already the planned `reboot` M2 checkpoint plus the five console observations (`DISPOSITION.md` §5). | — |
| Rollback | **38 stays bootable** from GRUB's "Advanced options" until a later maintenance cycle installs a newer kernel (APT keeps the booted kernel and the newest two). | `autoremove-kernel-protection.txt` |

## 3. Actual security impact

| Change | Effect |
|---|---|
| Kernel 38 → 42 | 127 of the 185 CRITICAL/HIGH "present" findings fixed in the 42 source; 41 still open (incl. CRITICAL 98725 and 98788); 17 unverified (`DISPOSITION.md` §3, unchanged). **The new surface is BPF LSM, active by default; root-only.** |
| The 34 removals | **Attack surface only shrinks:** LLVM/clang, the BPF tooling, a C toolchain's headers, 7 image-parsing libraries, and `linux-libc-dev`/`linux-tools-common` (which carry the scan's attributed kernel-source rows). Nothing on the M2 path is removed. |
| 38 kept as a fallback | The vulnerable 38 stays **selectable at the GRUB menu** (console / root only) until a later cycle. This is a residual: record it, do not mitigate it. |

## 4. Two wording defects (recorded; no code change)

1. **`culvert-os-update` l.321 says "Holds are still honoured … and nothing is removed".** That is true of the upgrade step and false for `os` as a whole: the next line's autoremove removes the 34.
2. **The QEMU harness check `os-update` reports "(0 package actions)".** It counted the upgrade step only.

**Pre-`os` STOP rule** (unchanged from `autoremove-reconciliation.md` §3): the simulation must show exactly the 5 kernel actions and the 34 listed removals.
