# ASTRA ESXi handoff — candidate 6248daf7 (console-shutdown P1 + boot-UX, on the a80be4b6 base)

**This candidate SUPERSEDES a80be4b6 (OVA 394788af…) for the console / boot-UX
scope.** It is a strict superset of a80be4b6's source: head `e7535ed9` has
a80be4b6's head `99e25cec` as an ancestor, so 6248daf7 carries everything
a80be4b6 did — the F-P2 1.5.4 sidecar bump (`6aa900cd`) and the admin-allowlist
fresh-recovery fix (`99e25cec`) — PLUS the two ASTRA findings on a80be4b6:

1. **Console-shutdown P1** (`100f5cf2` + `54ce0619`): `culvert-console` was the
   cause of the ~90s session-scope stall. On SIGTERM/SIGINT/SIGHUP a cosmetic
   tty1 write (plymouth owns the VT during shutdown) blocked in `write(2)` —
   not ctx-interruptible — so systemd waited `DefaultTimeoutStopSec` (90s) then
   SIGKILLed the PAM session. Fix: a watchdog (`armShutdownExit`,
   `consoleShutdownGrace` 5s) guarantees process exit within 5s of the signal
   regardless of a wedged syscall, and the interactive menu/confirm paths gate
   their cosmetic ANSI writes on `ctx.Err()==nil` while the termios restore
   ioctl always runs. Proven by a PTY reproduction with a non-vacuous control
   (`cmd/culvert-console/shutdown_exit_linux_test.go`: watchdog-on exits within
   grace+2s; watchdog-off stays blocked).

2. **Boot-UX** (`e7535ed9`): ~50s of brand/dots with no status or Esc hint
   during the delayed-service interval. Fix: `culvert-splash-status(.service)`
   re-asserts, under the real root after `switch_root`, a plymouth status line
   + Esc hint for the whole service-start window — the healthy
   `Starting system services  -  Esc: boot messages` and, once any unit fails
   (`systemctl is-system-running` = degraded), the failure warning
   `A service failed to start  -  Esc: boot messages, Alt+F12: kernel log`.

**The baked sidecar is an INDEPENDENT 1.5 rebuild, not a80be4b6's or
9e344526's bytes.** Image id `8af92aa4` (≠ a80be4b6 `b11e29c5`, ≠ 9e344526
`dc96d2f2`), baked archive `7fefc79c` (≠ `9404b981`), ref
`culvert/clamav:1.5.4-culvert.1`, off the same upstream `clamav/clamav:1.5`
index `638d9020` and `pcre2-10.49-r0`. The reproducible build pins byte-identity
*within* a run, not *across* builds — so F-P2 and the CVE scan are re-proven on
6248daf7's own bytes below, never inherited (a third independent 1.5 build, same
all-zero result).

## Artifact to qualify

| field | value |
|---|---|
| OVA | `culvert-appliance-1.0.263-candidate.g6248daf72a53-ubuntu-24.04.ova` |
| OVA sha256 | `59d4d371b46b69ec2a992009c76ba0a72d96c30dabb1a51847f9ea8edccbfd61` |
| OVA artifact | `appliance-lab-ova-candidate-6248daf7`, id 12074562532, lab run 38964077956 |
| source | `6248daf72a53…` = PR #1528 head `e7535ed9` merged into base main `dec66e1b` (the commit the deep-gate image was built + version-stamped from; what ships when #1528 merges) |
| app image id (manifest) | `sha256:20a547edd3e9db83cd1fa65f734bdeec5fc8f6d077f6f73344a38798a5d9692d` |
| app image tar sha256 | `d05f2c1d39db4223b9549fb312ba3c4ae0ac5761f7175218926e7f021bb65dfd` (CI image run 38961525689) |
| sidecar | `culvert/clamav:1.5.4-culvert.1`, image id `sha256:8af92aa4da736583ede38a5565a11cc57b30fb91bdcb2b31374dd81848382413`, baked archive `sha256:7fefc79c82e4febdd59377e3689f042d0d77a17120e0a4959d9bde63e20db95e` |

## Already proven in the QEMU/Docker lab (no ESXi needed)

- **Full qualify PASS** (lab run 38964077956, failures 0): boot, operator SSH,
  first-boot, setup-with-token, RBAC demotion, `/ready` ca+policy+clamav,
  category enforcement, agent + backup + offline restore, encrypted history
  recovery, and the admin-allowlist SURVIVAL assertions ([6b] same-volume,
  [H] fresh-volume).
- **F-DISK-1 PASS, bound to 6248daf7's EXACT app + agent** (lab run 38990080517,
  0 failures): the bounded ENOSPC-midwrite campaign built the maintenance agent
  from `6248daf` and ran it against 6248daf7's app image (config re-hashed from
  source tar `d05f2c1d`, runtime `v1.0.263-candidate.g6248daf72a53` — NOT
  bad788e). The ClamAV feed write filled the disk mid-write; the proxy SURVIVED
  (no crash, no restart), recovered on `docker compose up -d`, state + CA
  identity intact, category store opens, the feed import converges on retry.
  This REPLACES the earlier F-DISK claim, whose evidence (artifact 12073939869)
  named bad788e source/agent/image (ASTRA 23:00Z correction).
- **Console-shutdown P1 bounded** (Phase-2 boot-console, lab run 38968007999,
  22 PASS / 0 FAIL): clean maintenance reboot (V4) and the failing-unit reboot
  (V2) both complete; no stuck graphics after the splash; tty1 returns to the
  console UI in text mode. Unit-level bound proven by the PTY reproduction
  above.
- **Boot-UX hint VISIBLE through the service-start window** (same boot-console
  run, frames bound to OVA `59d4d371`): on first boot the splash shows
  `Starting system services  -  Esc: boot messages` by ~11s
  (`V-frames/00014_00011.00.png`) and throughout the reboot service-start
  window (`V-frames/00044_00121.53.png`); the bare brand/dots window is now
  ~10s, then an informative console menu (build/network/setup status +
  `L/F2 Sign in`) takes over by ~13s. The Esc contract is intact:
  `splash-before-esc`, `esc-shows-boot-messages`, `esc-one-way` all PASS.
- **F-P2 CLOSED on 6248daf7's OWN sidecar** (Phase-2 fp2-isolated, same run):
  isolated reproduction under a hard verdict — control `ClamAV 1.4.6/28136` =
  **58** EICAR-to-bare-clean (bug reproduces, harness is biting), candidate
  `ClamAV 1.5.4/28150` (image id `8af92aa4`) = **0** wrong-cleans. A third
  independent 1.5 build answering zero — the direct answer to "a future rebuild
  is not guaranteed byte-identical."
- **Sidecar CVE scan CLEAN** (Phase-2 ova-sidecar-scan, same run): exact-byte
  Trivy of the 1.5 archive `7fefc79c` baked in THIS OVA, every link re-hashed
  (OVA `59d4d371` → archive `7fefc79c` → image id `8af92aa4`, Trivy ImageID
  matched) — `severity-summary.json` = `[]` (0 findings, gate_exit=0; Deep-gate
  policy: no fixable HIGH/CRITICAL). 42 SBOM components; nghttpx absent.
- **Console-shutdown P1 CONFIRMED FIXED on real ESXi** (ASTRA 22:22Z): the exact
  original PAM → console → recovery-shell → sudo lifecycle teardown
  (`session-1.scope`, 243 journal entries, no truncation) completed in
  **0.340147 s**, no timeout/SIGKILL — the old 90.011826 s stall is gone.
- **Recovery is latency-bound and WITHIN budget at the calibrated profile**
  (lab recovery-ab run 38989972928, esxi12 = dm-delay 12 ms read / 3 ms write):
  three maintenance reboots recovered in **107.69 / 107.53 / 107.52 s**, under
  the 120 s budget; split ≈ **46 s pre-kernel** (firmware reads kernel 17 MB +
  initrd 41 MB) + ≈ **46 s kernel→ready** (local-fs @8.9 s with a CLEAN root, no
  periodic fsck; 798 MiB / ~104 s host read-wait). Matches the shipped b579
  baseline (`docs/appliance/recovery-time.md`, 103.1 s), so the newer payload
  (HWE 7.0.0-38, Docker 29.9.0, ClamAV 1.5.4) did NOT regress recovery at the
  calibration latency.

## Recovery: the one OPEN item on real ESXi — fsck RULED OUT

ASTRA measured **141.218 s** original-path recovery on real ESXi (over the
120 s budget) — the console-shutdown P1 is NOT the cause (teardown 0.34 s).

**ASTRA's original-path filesystem capture is COMPLETE (17 Oct 2026, PR comment
6230967268 / 5978949299), and it RULES OUT fsck** on the retained 6248 boot
`13b52b23-…`: root `/dev/sda1` was ALREADY `Maximum mount count -1` /
`Check interval 0`, the initramfs check reported `cloudimg-rootfs: clean` and
was condition-skipped at 22.181 s, the journal shows no full root check, and
`e2scrub_all` never executed. So the proposed fsck-policy change validates
policy/reporting but is **not** the demonstrated fix for this failure — its two
triggers were already disabled on the shipped image. (`e2scrub_reap` DID run
35.379→61.084 s ≈ 25.7 s concurrently; ASTRA records it as "not a demonstrated
ordering/I/O cause" — a candidate to investigate, not proven.)

**Measured recovery phases (new-kernel uptime, s)** — where the time actually
goes, latency-bound reads not fsck:

| Phase | Window (s) | Span |
|---|---|---|
| kernel start → local-fs | 0 → 32.375 | ~32 s (kernel + initramfs + mounts) |
| AppArmor + DBus | 32.65 → 37.95 | ~5 s |
| containerd | 38.65 → 54.68 | 16.0 s (gap 43.02→54.53 = **11.5 s**) |
| Docker | 54.69 → 68.16 | 13.5 s (container load 60.39→65.56) |
| stack resume | 68.16 → 90.79 | 22.6 s (compose up → ClamAV ready) |

ESXi latency on that VM: device read mean ~30 ms / max 67 ms, VM read mean
~53 ms / max 156 ms — well above the 12 ms lab calibration (107.5 s). Dominant,
latency-sensitive phases: the **pre-local-fs reads** and the **container-engine
+ stack** phases; single largest identified item is the 11.5 s containerd
metadata→next-plugin gap. ASTRA is explicit: sampled latency is not yet
demonstrated causation, and no guest boot-I/O sampler existed for this reboot.

**Owner-advisor decision (PR comment 6230751701) still holds:** keep broad
storage-driver coverage; DEFER `MODULES=list` (its −8 s is an ESTIMATE measured
for `MODULES=dep` on b579 only; needs per-profile boot proof incl. **Proxmox
VE/KVM** before shipping). The `tune2fs -c 0 -i 0` + masked `e2scrub_all.timer`
+ build-time report stays as reporting/guarantee hardening (error-triggered +
journal checks preserved; offline `e2fsck -f /dev/sda1` is the repair path) —
NOT the recovery fix. **141.218 s stays OPEN; no closure as "probably storage."**

**Selected next controlled comparison (in-lab, retained 6248 bytes, no new OVA):**
1. **Per-phase breakdown in the recovery-ab job** matching ASTRA's boundaries
   (local-fs / AppArmor / DBus / containerd / Docker / stack resume + the
   containerd metadata→next-plugin gap), so lab and ESXi phases are comparable.
2. **A guest boot-I/O sampler** over the recovery window (per-phase
   `/proc/diskstats` sectors-read deltas) — the specific MISSING INPUT ASTRA
   named; proves which phase pays the latency.
3. **Two injected latencies** — the calibrated `esxi12` and a new `esxi30`
   (~30 ms read / 15 ms write, matching ASTRA's device-read mean) — to see which
   phases scale with latency (the latency-bound ones) vs which are fixed.
4. Only then, a focused engine/provisioning A/B on the dominant phase. Exact
   replacement bytes still require independent ESXi qualification.

**Same-bytes note:** OVA `59d4d371` (artifact 12074562532) is the bytes ASTRA
already tested — not a new import. A provisioning fix (initramfs / tune2fs /
e2scrub) changes the OVA disk but KEEPS the same app image (20a547ed) + agent,
so F-DISK / console / F-P2 / sidecar carry over; only recovery is re-measured.
ASTRA's frozen controllers / retained OVAs / guests for the earlier rounds are
untouched.
