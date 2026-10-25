# Appliance lab — guest boot qualification (run 20261025T113738Z)

| identity | value |
|---|---|
| lab/harness commit | `521fe5c246c0ad095340407c5768c8fc7bfa2ba0` |
| OVA | `culvert-appliance-1.0.327-candidate.gb910508629e9-ubuntu-24.04.ova` sha256 `61c46d6db6603d76edbb0d64327bed85e76bea86d24457e9f3ae36e71bd5854a` |
| appliance source (guest build-info) | `?` |
| application image in the guest | `?` |
| accelerator | kvm (preflight: `preflight.json`) |
| access | read-only `culvert-operator` SSH (imported key) + authenticated local console (`culvert`, PAM + sudo) |

| step | check | result | detail |
|---|---|---|---|
| P | tools | **PASS** | qemu, qemu-img, ssh, curl, python3, openssl, iso tool present |
| P | memory | **PASS** | 14619 MiB available (need 6144) |
| P | disk | **PASS** | 83 GiB free at //culvert-lab/console (need 15: OVA + VMDK + base + overlay growth) |
| P | accel | **PASS** | accel=kvm (kvm usable: yes) |
| V | ova-sha256 | **PASS** | culvert-appliance-1.0.327-candidate.gb910508629e9-ubuntu-24.04.ova sha256 61c46d6db6603d76edbb0d64327bed85e76bea86d24457e9f3ae36e71bd5854a (= the pinned candidate) |
| V | ova-manifest | **PASS** | every file digest in the OVA's .mf verified |
| V1 | console-topology | **INFO** | ttyS0 -W- (EC Np a) 4:64;tty1 -WU (E p ) 4:1; printk=3 4 1 7 |
| V1 | tty1-after-first-boot | **PASS** | tty1 (25 80) holds only the console UI |
| V1 | tty1-text-mode | **PASS** | tty1 KD_TEXT; 1 kdmode-tty1 0 (0=text 1=graphics) |
| V1 | splash-on-display | **PASS** | plymouth-start Result=success (has-display rc=0) |
| V1 | getty-tty-reset | **INFO** | TTYReset=yes TTYVHangup=yes open-rc=0 seconds=0.00 (V1-ttyreset.txt) |
| V2 | tty1-after-reboot-with-failures | **PASS** | tty1 (25 80) holds only the console UI |
| V2 | tty1-text-mode | **PASS** | tty1 KD_TEXT; 1 kdmode-tty1 0 (0=text 1=graphics) |
| V2 | splash-before-esc | **PASS** | title on tty1 before the first Esc: ok (pre=11 mid=15 post=40 mid_status_max=3) |
| V2 | esc-shows-boot-messages | **PASS** | after the first Esc, with the splash still running, tty1 shows the boot messages, not the title: ok (pre=11 mid=15 post=40 mid_status_max=3; V2-vcs-probe.txt) |
| V2 | esc-one-way | **PASS** | after the second Esc the splash title does not come back while Plymouth runs: ok (pre=11 mid=15 post=40 mid_status_max=3) |
| V2 | splash-healthy-control | **PASS** | clean first boot: the live splash displayed 'Starting system services' and NO failure warning (OCR; V1-splash-ocr.txt) |
| V2 | splash-names-failed-unit | **PASS** | the LIVE splash displayed a failed-unit warning while a unit was failed (OCR of [116.03,124.03) s; V2-splash-ocr.txt): Service failed: lab-console-fail.service - Esc or Alt+F |
| V3 | tty1-after-postboot-writes | **PASS** | tty1 (25 80) holds only the console UI |
| V4 | tty1-after-clean-reboot | **PASS** | tty1 (25 80) holds only the console UI |
| V4 | tty1-text-mode | **PASS** | tty1 KD_TEXT; 1 kdmode-tty1 0 (0=text 1=graphics) |
| V4 | vt-probe | **INFO** | 120 samples; 1 kdmode-tty1 0 (0=text 1=graphics); first: LAB-PROBE up=3.80 fg=1 kdmode=0 plymouth=up; last: LAB-PROBE up=36.33 fg=1 kdmode=0 plymouth=down |
| V4 | no-graphics-after-splash | **PASS** | 119 samples after plymouth exited, all kdmode=0 |
| V4 | splash-graphics-window | **INFO** | 0 samples (x0.25 s) in graphics mode while plymouth was up |
| V4 | console-build-identity | **PASS** | the guest's console banner and tty1 Build line name 1.0.327-candidate.gb910508629e9, the version of the booted OVA 61c46d6db6603d76edbb0d64327bed85e76bea86d24457e9f3ae36e71bd5854a |
| V | frames | **INFO** | 153 distinct frames, 17 events (V-frames/, V*-*.png contact sheets) |
| V5 | no-splash-without-display | **PASS** | plymouth-start Result=exec-condition (has-display rc=1) |
| V5 | serial-only-boot | **PASS** | serial carries the kernel log (536 lines), systemd status and a login prompt |
| V5 | serial-shutdown | **PASS** | serial carries 79 systemd stop lines and the kernel's power-down line |
| C | guest-reachable | **INFO** | guest not reachable at collect time; console log only |

Totals: info=6, pass=24

Not qualified by this lab: vSphere/ESXi import (ovftool), the guestinfo OVF transport, VMware Tools, LSI Logic SCSI, the hypervisor's tty1 console (ttyS0 here), datastore/thin-provisioning behaviour, the proxy's Release Management dispatch (6c calls the agent socket as its peer, with TEST-ONLY trust), and F-DISK-1 (owned by the bounded nested-Docker harness; still OPEN).
