# First-boot experience and boot-time work

This is design rationale, not a claim that boot-time optimizations or a host
self-updater have shipped. Source review is pinned to
`36b5407e5bd3ff3c883bf855c269b8b7675013ed`; the measured ESXi candidate used
2 vCPUs and 4 GiB configured RAM. Runtime `nproc`/`MemTotal` were not retained.

## Early boot presentation

The next-candidate builder installs a Culvert cyan-on-black Plymouth text
theme before exporting the OVA. The sequence is firmware/bootloader, Culvert
early boot, then the existing Go console with management URL and setup
guidance. Hypervisor firmware and emergency output are still visible when
appropriate. The splash is presentation, not an application-readiness signal
or a boot-speed optimization; its native activity indicator is not a measured
appliance completion percentage.

The theme uses Ubuntu's packaged `ubuntu-text` renderer, including its existing
system-prompt and Escape-to-details handling. Both the default and text
fallback alternatives select the Culvert theme; package-owned themes and
`/etc/os-release` remain unchanged. Ubuntu's packaged Plymouth quit/panic hooks
and getty ordering control the handoff, with no new dependency on Docker,
network availability or provisioning completion.

The screen is `C U L V E R T`, the renderer's activity dots, and one line
under them in the theme colour: "Starting system services - Esc: boot
messages" (an initramfs script, `culvert-splash-message`, sends it once
Plymouth is up). It is deliberately not a `keys:` message, which ubuntu-text
draws four rows from the bottom in the theme's `white`; a plain message sits
under the title, with the activity dots, in the theme's `blue`. It is true for
the whole time the splash is shown: the splash ends when the console menu
starts, and the menu reports provisioning and readiness itself. The title is 13
characters because ubuntu-text draws it at column `(width-12)/2`; the first
candidate's 50-character title therefore wrapped off-centre on every screen
(owner report on #1528, reproduced in QEMU frames).

Three things are owned explicitly so that nothing else is left on the screen:

* **One display mode.** `nomodeset` keeps the console in the firmware's mode
  (VGA text 80x25 on a BIOS VM) from GRUB to the menu. Without it, ESXi's
  `vmwgfx` took the console over about a second after the splash started
  (journal: `vmwgfx … deactivate vga console` at 5.2 s, Plymouth started at
  4.6 s) and the earlier text stayed in the corner of a larger screen. The
  console menu is an 80x25 text UI; nothing on the guest uses accelerated
  graphics.
* **Text mode on tty1.** Plymouth waits `DeviceTimeout` (Ubuntu default 8 s)
  for a graphics device before it draws the text splash, holding tty1 in
  graphics mode meanwhile. With `nomodeset` on BIOS no such device ever
  appears, so
  the first eight seconds were blank, and a boot that reached the console menu
  inside that window left tty1 in graphics mode: the kernel then ignores
  every write to it, and the menu ran behind a screen frozen on early boot
  text (lab probe: `KDGETMODE` = graphics from 4.2 s to 37 s, Plymouth already
  gone). Two independent fixes: `/etc/plymouth/plymouthd.conf` sets
  `DeviceTimeout=0.1` (read before `plymouthd.defaults`, first value wins;
  Ubuntu's initramfs hook copies it and the build checks it is there), and
  `culvert-console --login` puts its VT back in text mode before every menu
  frame, whatever left it in graphics mode. systemd's `TTYReset=yes` on
  `getty@tty1` would normally do this, but it skips its whole terminal reset
  when it cannot open `/dev/console` (ttyS0, see below), which is the ESXi
  case; the console's own repair does not depend on it.
  `DeviceTimeout=0.1` also means a graphics device that appears later (a boot
  entry without `nomodeset`) is ignored by the splash, which stays text.
* **No splash without a display.** On a machine with no display controller (a
  serial-only VM) nobody can see the splash, but Plymouth would still cost the
  serial console: it captures `/dev/console` (systemd's status lines) from the
  moment it starts, and holds kernel messages back from every console while
  its splash is shown. The initramfs message script ends Plymouth there, and
  `plymouth-start`, `-reboot`, `-poweroff`, `-halt` and `-kexec` carry
  `ExecCondition=culvert-has-display`, so neither the real root nor a shutdown
  starts it again; the serial console then carries the whole boot and the
  whole shutdown (when a hung shutdown is diagnosed). "Display" means a PCI
  VGA-compatible or other display controller (class `0x0300` or `0x0380`):
  the kernel registers its VGA text console even with no adapter, so the
  console driver cannot tell the two apart; 3D controllers (compute GPUs)
  drive no console and do not count. Found in the lab: with the 0.1 s wait the
  splash also appeared on the serial-only boot, and serial lost every
  `[ OK ]` line and the kernel log after 2.8 s.
* **Kernel messages on their own console.** `culvert-kernel-log-vt.service`
  runs before the splash ends and routes the kernel's VT output to tty12
  (`setlogcons 12`), seeding it with the kernel log so far. Alt+F12 shows it,
  Alt+F1 returns. Nothing is suppressed: the log level is unchanged, the serial
  console and the journal (`journalctl -k`) receive every message. Without it,
  every kernel message after the splash is drawn over the console menu. The
  residual: a kernel panic message is on tty12, serial and the hypervisor's
  log, not on tty1. tty12 shows the boot kernel log (command line, hardware
  identifiers, MAC addresses) to anyone at the hypervisor console without an
  appliance login, while `dmesg` on the box is root-only; that is the same
  audience that already saw these lines on tty1 before this console existed.
* **Kernel messages during the splash.** ubuntu-text holds kernel messages
  back from all consoles while it is shown (`klogctl` console-off on show,
  console-on on hide; noble `ubuntu-text.patch`), serial included. Messages
  emitted meanwhile are not replayed on the consoles afterwards; they stay in
  the kernel log and journal, and Esc shows the boot messages Plymouth has
  captured. Plymouth also captures `/dev/console` for as long as it runs, so
  systemd's status lines reach serial only after it quits. Both are the
  packaged behaviour, not Culvert settings, and so is the one-way toggle: a
  second Esc does not return to the splash (the details view stays until the
  splash ends). On a machine with a display and a serial port, serial
  therefore carries the kernel log up to the splash and systemd's lines after
  it; a serial-only machine has no Plymouth at all (see "No splash without a
  display").

`/dev/console`: the kernel command line keeps the cloud image's
`console=tty1 console=ttyS0`, so `/dev/console` is ttyS0. That holds on ESXi
too, where the VM has no serial port: the 8250 driver registers the legacy
port anyway (lab `/proc/consoles` with no serial device attached), so systemd
status lines and unit console output are not drawn on tty1. Emergency and
rescue shells use `sulogin`, which prompts on every console in
`/proc/consoles`, tty1 included.

Packages come from the existing pinned Ubuntu snapshot and enter the guest
SBOM before cloning. A custom theme name makes Noble's initramfs hook include
font support even for the native text renderer, so the build explicitly
installs `plymouth-label` and `fontconfig` too. The installer rebuilds every
installed initramfs and rejects one missing the Culvert theme, the native
renderer, the message script or `plymouthd.conf` (presence: Ubuntu's hook
copies the file verbatim). The outer build independently compares the
selected themes, the GRUB drop-in and every installed console file (ten
paths) with source hashes.

Normal boot adds `splash plymouth.ignore-serial-consoles nomodeset` to the
existing GRUB default arguments: the Culvert screen appears on the VGA console
only. `quiet` is never added, and an inherited `quiet` is removed, because it
lowers the kernel log level on every console including ttyS0, where boot
failures are diagnosed. `GRUB_DISTRIBUTOR` is not changed: `grub-install`
derives the UEFI bootloader directory from it and the signed shim/GRUB chain
expects `/EFI/ubuntu`, so a routine GRUB package update must keep installing
there. Existing root and serial-console arguments remain present. For
recovery, use Escape for details, or edit the GRUB kernel entry to remove
`splash` and add `plymouth.enable=0`. Normal recovery entries do not inherit
`GRUB_CMDLINE_LINUX_DEFAULT`. Do not remove the serial console or suppress
error reporting to hide boot failures.

Before calling this visually qualified, build a new OVA and verify BIOS and
UEFI VGA startup, Escape details, serial login, a boot failure/emergency path,
handoff to the Go console and PAM, and retention after a kernel update.
Mocked build tests establish packaging and failure handling only. The prior
36b5407e ESXi measurements do not qualify this new presentation.

Primary implementation references: [Noble packaging and ubuntu-text patch](https://archive.ubuntu.com/ubuntu/pool/main/p/plymouth/plymouth_24.004.60-1ubuntu7.2.debian.tar.xz),
[Plymouth renderer and console handling](https://archive.ubuntu.com/ubuntu/pool/main/p/plymouth/plymouth_24.004.60.orig.tar.xz),
[Ubuntu Plymouth controls](https://manpages.ubuntu.com/manpages/noble/man1/plymouth.1.html)
and [systemd boot-status options](https://github.com/systemd/systemd/blob/v255/man/systemd.xml).

## What the measured reboot tells us

The retained `esxi-run-36b5407e/evidence/post-reboot-observation.json` records
monotonic timestamps since guest boot:

| Observation | Time since boot | Meaning |
|---|---:|---|
| Console worker process started | 202.95 s | Process launch, not first visible console frame |
| Docker main process started | 302.08 s | Docker **started at** 302 s; this is not its startup duration |
| Maintenance agent process started | 367.02 s | Does not establish when its socket became usable |
| Stack-resume command started / finished | 367.02 / 476.28 s | About 109 s executing the resume command |
| First-boot unit | Never started | Condition false, start timestamp zero; no completed provisioning steps in the full current-boot journal |

The harness reported SSH and proxy `/health` reachable 552 s after the reboot
command. That interval includes shutdown, boot, forwarding recovery and polling;
it is neither first-boot installation time nor an exact proxy-ready timestamp.

Retained `08-stack-resume.txt` narrows the resume interval: command start
11:54:30, both maintenance locks held 11:54:31, Compose start 11:54:33,
ClamAV starting 11:54:54, started/waiting 11:55:06, healthy 11:56:11,
proxy starting 11:56:11, started and resume finished 11:56:19. The reboot
request was logged at 11:47:56. ClamAV therefore accounts for a measured
65-second health wait in this sequence; it does not explain the entire
552 seconds. Proxy creation completed 503 seconds after the request; its exact
subsequent health transition was not captured. This VM has been deleted, so
missing timing evidence requires another controlled run.

Preinstalling more first-boot components cannot by itself remove this reboot's
delay: provisioning did not run. Before changing dependency ordering, collect
`systemd-analyze time`, `critical-chain`, `plot`, unit activation timestamps and
monotonic journals for Docker/containerd, network-online, cloud-init and resume.
Also record ESXi CPU scheduling and datastore latency, Docker container
start/health transitions, and timestamps for management versus enforcement
readiness. These distinguish queued dependencies, resource contention and
application initialization. `blame` alone omits queued jobs and `Type=simple`
initialization; critical-chain also has parallelism and activation limitations.
See the [upstream systemd analysis manual](https://github.com/systemd/systemd/blob/v255/man/systemd-analyze.xml).

## What is already baked, and what first boot still does

| Component | Current artifact / first-boot behavior |
|---|---|
| Docker, Compose and OS packages | Installed in the guest disk during build; Docker versions pinned and held. |
| Go console and local recovery worker | One static `culvert-console` executable, built before disk customization; console units and helpers already installed. |
| Culvert proxy and CLI | Same precompiled image, shipped as a compressed image archive; first boot imports it into Docker. |
| Maintenance agent | Static Go binary already compiled into the proxy image's deploy bundle. First boot verifies its source, extracts and installs its host files, then configures access and starts it. This candidate did not need an on-guest Go build. |
| ClamAV | Image archive shipped; first boot imports it and waits for service health. Actual signature download/initialization costs need phase measurements. |
| Instance state | Network/hostname, login credentials, setup token, CA/session material and application state are initialized for each VM. They must not be cloned from a running template. |

The implementation is in
[guest preparation](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/appliance/build/prepare-guest.sh),
[first-boot image/install steps](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/appliance/provision/culvert-firstboot.sh#L219),
and the [compiled deploy bundle](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/Dockerfile#L93).

## Incremental changes with the lowest risk

1. **Show observed progress first.** Keep the console available independently
   of Docker. Distinguish management access, provisioning and traffic readiness;
   use actual completed steps and current observations, with elapsed time and a
   recovery action when blocked. Do not manufacture percentages or treat a
   usable setup URL as enforcement readiness.
2. **Measure, then separate agent packaging from activation.** Stage the
   verified host binary, unit and templates during OVA build. Add an explicit
   offline installation mode: the current packaging installer performs Docker
   checks and `daemon-reload`, while `prepare-guest.sh` has no running systemd.
   Finalize per-instance configuration and verify the pinned image's proxy UID,
   group/socket access and sudoers binding before starting services. Keep the
   privileged-operation smoke test and version checks.
3. **Avoid a second proxy creation where evidence justifies it.** Today
   `wire_release_agent_for_compose` observes the running proxy UID, configures
   the agent and recreates the proxy with its socket override. Prepare that
   binding before the first proxy start, preserving the same authorization
   checks. This can avoid repeated application initialization, but its saving
   has not been measured. See [installer wiring](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/scripts/install.sh#L2326).
4. **Evaluate image-store seeding separately.** Shipping image tars already
   removes registry pulls, but still requires decompression/import on the VM.
   Docker supports loading compressed archives and restores their tags;
   it does not promise zero startup work. A later builder could import into a
   disposable guest using the pinned engine, then shut it down cleanly and
   scrub identities. Do not copy a developer's live Docker data directory.
   Compare disk/OVA size, load time and clone correctness before adopting this.
   See [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/).

Follow existing Go boundaries for new runtime logic: the root module owns
`cmd/culvert-console` and `internal/applianceconsole`; `cmd/culvert-maint` is a
separate module. Use the compiler pinned by root `go.mod`, static Linux/amd64
appliance builds, typed operations with bounded inputs, and deterministic
failure/recovery tests. Keep privileged command templates aligned with their
sudoers rules. Moving lifecycle logic to Go does not require moving the proxy
out of its container or creating another daemon.

## Three different meanings of “fence”

**HA write fencing is already inside the Go proxy binary.** It uses
`ha_fencing.go`, `ha_lease.go` and `internal/halease`; `armHALease` runs before
HA role selection. There is no separate Culvert HA-fencing executable to bake.

**etcd is the external lease authority.** Compose includes an optional `ha`
profile with a single-member etcd container, explicitly marked for a local lab.
Both control planes must use the same authority; automatically enabling an
independent local witness on every cloned appliance would not provide shared
arbitration. Production needs separately managed failure domains, TLS and
durable etcd state. Three etcd members can tolerate one member failure; one
cannot tolerate any. This is a witness deployment choice, not three Culvert
control planes. See [Culvert's Compose contract](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/docker-compose.yml#L191)
and [etcd's quorum/failure-domain guidance](https://etcd.io/docs/v3.6/faq/#what-is-failure-tolerance).

**The host maintenance shutdown fence is local coordination.** The console,
OS-maintenance helper and maintenance agent share locks and a durable
`host-shutdown.pending` protocol. This prevents maintenance overlapping a
shutdown or bypassing interrupted work; it does not arbitrate HA leadership.
Faster startup must preserve both protocols. Witness state must not be
reset/cloned during a host update, and HA failover still has the documented
[bounded replication-loss window](../adr/0005-ha-lease-witness-failover.md).

## Upgrade gap and qualification prerequisites

The agent currently upgrades the pinned **proxy image**, with preflight,
backup, health verification and rollback. It does not update its own host
binary or the host console. Rerunning the installer can replace the agent,
but that is not a transactional host self-update API. See the
[current upgrade operation](https://github.com/KidCarmi/Culvert/blob/36b5407e5bd3ff3c883bf855c269b8b7675013ed/cmd/culvert-maint/internal/server/handlers_upgrade_apply.go#L1).

Such an API needs a separately reviewed, signed and versioned compatible host
bundle: agent, console, helpers, units and protocol requirements. Stage and
verify it before mutation; publish atomically, retain the previous version,
and recover interrupted transitions from a durable journal. A bounded
privileged helper must own activation and rollback across the agent's own
restart. Preserve operator configuration, instance secrets, socket directory
identity and both maintenance locks/fences. An unsigned candidate exception
must not become the production trust path. These are requirements, not
implemented capabilities.

| Qualification slice | Evidence required before claiming improvement |
|---|---|
| Boot progress only | Fresh default/key/static-network imports; unavailable network; interrupted provisioning; management and enforcement states remain distinct. |
| Agent preinstallation / initial wiring | Signed artifact and exact versions; wrong-architecture/tamper rejection before mutation; real socket-authorized privileged operation; no proxy restart needed solely to add wiring. |
| Preloaded images / boot tuning | Fresh clones have distinct credentials/IDs; cold first boot, ordinary reboot and maintenance reboot measured separately; slow DNS/network/storage cases stay recoverable. |
| Host bundle updates | Old/new compatibility, failure before/after activation, lost power, failed health check, rollback, concurrent maintenance and same-boot shutdown refusal. |
| HA changes | Separate multi-node lab: witness loss, partition, paused leader, rolling restart and retained epochs; the single-VM ESXi run provides no HA qualification. |

Prerequisites for speed claims are a phase-timed baseline on the same VM
resources and a separate disposable candidate. HA work additionally requires
two control planes and an approved witness topology. Publish measured changes
for each boot scenario; do not infer a saving from upstream examples or the
presence of a prebuilt binary.
