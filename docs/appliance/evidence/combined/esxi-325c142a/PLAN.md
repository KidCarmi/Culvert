# ESXi qualification plan: OVA 325c142a (finish qualification of THIS appliance)

**Status:**
- This is a producer proposal. Nothing on ESXi has been touched.
- Execution needs the single owner approval listed in `CUSTODY-AND-AUTHORIZATION.md` §4.
- ASTRA executes the plan and owns the verdicts.

**Goal:** prove on real ESXi the behaviours that QEMU cannot prove, on the exact OVA ASTRA accepted for internal QEMU qualification. Everything already proven elsewhere is reused, not repeated.

**Not in scope:**
- a rebuild, merge, release, pilot or customer use;
- a second OVA;
- touching the existing ESXi VM beyond what §4 of the custody document lists.

## 1. Artifact under qualification (do not substitute)

| | |
|---|---|
| OVA | `culvert-appliance-1.0.360-candidate.g0648adeba52e-ubuntu-24.04.ova` |
| OVA SHA-256 | `325c142a7df441eb97dd5a5e688e0fb89979b8ee29680175d627fcf8556df96f` (every `.mf` digest must match) |
| Source | Actions artifact `12756793569` (run 40555901182). ZIP: 2,079,718,929 bytes, SHA-256 `124fcc372cfa1953f05be8e3c640504a4b546b8abd1a532e89d819cce9ebf903`. **Expires 2026-11-10T18:12:40Z**; see `RETENTION-PROPOSAL.md`. |
| Source commit | `0648adeba52e09f15505095ba1ff556304b9fcef`, epoch `1793096442`, VERSION `v1.0.360-candidate.g0648adeba52e` |
| App image | index/manifest `sha256:20b6abcbc17028e50aa7db1871dd3e6175a61d533afd961302cc7558dc5a8ed0`; baked archive `4536f0572f6b940929bcdd16a193b1ff8698fdc70608f9d69463bf7be0ff35f6` |
| ClamAV sidecar | `culvert/clamav:1.5.4-culvert.4`, image ID `sha256:91eae57526b246da28cb370bd824c45af51e245be0093afcc316bc3fbe941f9d`; archive `6482ae8c2774b30913b69d3d26778da8005817bdfb4df051f324e74c93c3c8ad` |
| Installed binaries (ASTRA-verified) | app `bc6e4f7f…8312c`; maintenance agent `2631f25c…34372`; console `c4a24736…a3b69`; access `cae9748b…12821` |
| Guest | Ubuntu 24.04 (cloud image serial 20260926); kernel `7.0.0-38-generic`; docker-ce `5:29.9.2-1~ubuntu.24.04~noble`; containerd.io `2.4.2-3~ubuntu.24.04~noble`; compose `5.6.1` |
| Virtual hardware (OVF) | `vmx-13`; 2 vCPU / 4 GiB / 40 GiB thin; **1 × E1000** |
| Candidate posture | Unsigned CI image. First boot logs `CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1`. Never for customers. |

**Residual window:** 2026-10-27T17:53:38Z → **2026-11-26T17:53:38Z** at most, ending earlier on any STOP trigger. ESXi qualification and its report must finish inside it.

## 2. What is reused, and why it is not repeated

Each row is reused because nothing in its scope changed for this OVA, or because ESXi adds no information beyond it. Change set `b9105086..0648adeb` (non-docs):
- `manifest.env` pins, `build-ova.sh`, `prepare-guest.sh`;
- the sidecar Dockerfile;
- the M2 sysctl drop-in and the `cap_drop` changes in the compose files;
- tests only.

Restore and backup code is unchanged since the last ESXi-qualified OVA (`4524311b`).

| Evidence | Where | Reused for | Repeat on ESXi? |
|---|---|---|---|
| Full CI, Fast/Deep, F-P2 (sidecar 91eae575), exact sidecar scan | ASTRA shared review | build/test, sidecar false-clean defect, sidecar CVEs | No |
| Exact-byte scans of THIS OVA (run 40579477744) | ASTRA 27 Oct ruling | guest/host/app/sidecar vulnerability state, installed-binary identity | No |
| QEMU qualification of THIS OVA (run 40555901182): 148 pass, 0 fail; M2 28/28; recovery 39 s ×3; history fresh-volume restore; signed update/rollback fixture; operator SSH refusals; recovery-secret custody | ASTRA 27 Oct ruling | functional behaviour independent of the hypervisor | No; the ESXi spot checks in §3 are smaller |
| F-DISK-1 (nested Docker, run 40555901182) | same | full-disk write safety | No. It is a data-path property, and ESXi adds a datastore alarm only, which is a pilot gate (vsphere-qualification.md §9). |
| Boot console on QEMU VMware-SVGA (61c46d6d, same console source as `0648adeb`) | ASTRA ruling, 24 pass | console UX in QEMU | Reused as a source baseline only. **Real ESXi VGA is NOT inherited** (Q9 below). |
| Exact 27006cf4 ESXi campaign (review 5592731454) | ESXi 8.0.1 | ESXi import, guestinfo, source-absent cross-VM restore, history recovery, P1 lifecycle regressions | Cross-VM source-absent restore is **not** repeated: restore code is unchanged, and fresh-volume restore passed on THIS OVA in QEMU. Import, boot, recovery, maintenance, ClamAV and the display ARE repeated, because those paths changed (Q2–Q9). |
| Live IdP | none (blocked) | — | Stays BLOCKED; out of scope |

## 3. ESXi qualification steps

**Base procedure:** `docs/appliance/vsphere-qualification.md`, retargeted to §1 by this commit. ASTRA's frozen ESXi controller from the 27006cf4 campaign may drive the steps and capture VGA frames; only the identity pins change.

**Conventions:**
- Every step writes to `$EV/` (one tarball at the end).
- `$SSH` is the `culvert` admin over the OVF-injected key.
- **STOP** means report and reassess: no rerun, rebuild, patch or retry campaign.

| ID | Step | ESXi-only reason | Pass criteria |
|---|---|---|---|
| Q0 | Read-only preflight on the host: ESXi version/build, free space on the designated datastore, port group, CPU/RAM headroom, the existing VM's power state and IP (`culvert-esxi-b4f5d6ed9cc5`, 192.168.1.141). Re-read the Ubuntu linux-hwe-7.0/noble status of 98532/98573/98788. | host state | ≥ 48 GiB free on the datastore (40 GiB thin + 20 %); a free IP that is not .141; no released HWE fix (else STOP, trigger 2) |
| Q1 | Verify the artifact (vsphere-qualification.md §1) | — | ZIP and OVA SHA-256 as §1; every `.mf` digest matches; OVF says CANDIDATE and `1.0.360-candidate.g0648adeba52e` |
| Q2 | Import and first boot (§2–§3): ovftool with guestinfo key and static address, E1000 left as shipped | real OVF/guestinfo transport, VMware hardware | Provisioning `complete` with all `.done` files. Setup token 32 characters. `culvert` runs `20b6abcb…`. `culvert-clamav` runs `91eae575…`. Kernel `7.0.0-38-generic`, engine 29.9.2, Docker packages held. First-boot time recorded (info). |
| Q3 | Networking and the M2 firstboot checkpoint: `ethtool -i` on the NIC; reachability of 8080/9090/22 from the client; then run `m2-guest.sh` + `m2-verdict.py` from lab `e6bb0ff0` (§5) | real NIC/driver; namespaces and ruleset on ESXi hardware | NIC driver `e1000` (STOP trigger 6 if not e1000/vmxnet3). All 7 `firstboot-*` M2 checks PASS. |
| Q4 | Enforcement (§4–§5): setup without token 403 / with token 200; login; `Exempt`; default deny 403; allow rule 200; other host 403; one category-block rule; `/ready` | the data path through the ESXi NIC | 403/200/200; 403/200/403; category block 403; `/ready` 200 with `policy_loaded`, `policy_posture`, `ca` ok |
| Q5 | ClamAV, same oracle as the 27006cf4 gate: clean object and EICAR before; `docker stop culvert-clamav`; same requests; start; same requests | the 1.5.4-culvert.4 sidecar and the image helper have never run on ESXi | before 200/403; sidecar down **403/403** (fail closed) and `/ready` 503; recovered 200/403 and `/ready` 200; sidecar image ID still `91eae575…` |
| Q6 | Maintenance (§6–§8): agent status; product backup; restore dry run; **`culvert-os-update check` first**; then `os`; then `reboot` | agent, sudoers and os-update changed since 27006cf4; real ESXi reboot | Agent reachable; backup `succeeded` and listed; dry run `validation passed`. **If `check` lists any newer `linux-image`: STOP before `os`** (a released HWE kernel is trigger 2, and installing it would change the qualified kernel). After the reboot: kernel unchanged, engine 29.9.2, packages held, state persists, no first-boot step reran. |
| Q7 | Recovery: three consecutive `culvert-os-update reboot`, measured as in `recovery-time.md` (three consecutive joint-ready samples: operator/agent, admin login + CA, real 200/403 traffic, ClamAV ready); then the first post-recovery backup | ESXi storage latency is the historical failure (141.218 s on 6248) | **Each recovery ≤ 120 s**; distinct boot IDs; post-recovery backup succeeds. Recorded beside 27006cf4's 78.969 / 67.844 / 71.328 s and this OVA's QEMU 39.1 / 39.4 / 39.2 s. |
| Q8 | Backup/restore on this VM only, per `recovery-restore-runbook.md` lines 65–68: encrypted backup → post-backup mutation (add a rule) → dry run → `docker compose down` → `--profile cli run --rm -e CULVERT_BACKUP_PASSPHRASE cli --restore /backup/<archive> --mode full --confirm` → `docker compose -f docker-compose.yml -f docker-compose.maint-agent.yml up -d` (BOTH files, or the agent is unreachable) → verify | restore on ESXi storage with the new engine | The mutation is gone. Rules, CA fingerprint, categories, allowlist and admin login are as at backup. 200/403. Agent reachable. `/ready` 200. |
| Q9 | **Failed-service display on the live ESXi console** (§4 fixture): (a) one short failing unit; (b) one long-named plus one more failing unit; (c) fixtures removed, clean reboot as the healthy control. Capture the VGA frames during the splash; press Esc once, then again. | **Historical ESXi FAIL** (27006cf4, frame-0033). Only real ESXi VGA can close it. | (a) the splash shows exactly `Service failed: culvert-qual-a-fail.service  -  Esc or Alt+F12: boot log` (72 cols). (b) It shows exactly `Service failed: culvert-qual-a-deliberate (+1 more)  -  Esc or Alt+F12: boot log` (80 cols, no wrap). (c) It shows `Starting system services  -  Esc: boot messages` and **no** failure warning. In each case Esc shows boot messages and is one-way, and the console menu holds tty1 after boot. Fixtures are removed and verified absent. |
| Q10 | Final checkpoint: M2 `final` (§5); identity readback (app image, sidecar ID, kernel, engine); `sudo culvert-status` | state after all faults and reboots | All 7 `final-*` M2 checks PASS; identities unchanged from Q2 |
| Q11 | Evidence: `tar -czf` plus SHA-256; exclude the setup token, the admin password and recovery secrets (`03e`-style "shown-and-matches" only) | — | Tarball hash published on #1528; raw tarball kept in ASTRA's sealed custody |

**Reboots** in Q9 carry deliberate slow and failing units, so they do not count toward Q7 timing.

**Order:** Q0 → Q1 → Q2 → Q3 → Q4 → Q5 → Q6 → Q7 → Q8 → Q9 → Q10 → Q11. Q8 runs before Q9 so the display fixtures never sit in a backup.

**Not in this plan (and why):**
- **Data-disk alarm delivery (vsphere-qualification.md §9):** a pilot gate.
- **Source-absent cross-VM restore:** see §2.
- **Signed update/rollback with test trust:** covered by QEMU and CI. Installing test trust on ESXi adds risk and no ESXi-specific information.
- **IdP:** blocked.
- **Uninterruptible-writer or power-loss shutdown:** never claimed.

## 4. Display fixture for Q9 (ESXi variant of the lab's boot-console fixture)

The QEMU fixture writes markers to `/dev/hvc0`, which does not exist on ESXi; this variant writes to the journal only. Install it as root on the new VM for (a), reboot, capture; for (b) add the long unit; then remove everything for (c).

```bash
# (a) one short failing unit + a slow unit that holds the splash open ~45 s
sudo tee /etc/systemd/system/culvert-qual-delay.service >/dev/null <<'U'
[Unit]
Description=ESXi qualification: hold the splash open
DefaultDependencies=no
After=local-fs.target systemd-udevd.service
Before=systemd-user-sessions.service plymouth-quit.service plymouth-quit-wait.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'echo CULVERT-QUAL-SPLASH-START; sleep 45; echo CULVERT-QUAL-SPLASH-END'
[Install]
WantedBy=sysinit.target
U
sudo tee /etc/systemd/system/culvert-qual-a-fail.service >/dev/null <<'U'
[Unit]
Description=ESXi qualification: a unit that fails during boot
Before=systemd-user-sessions.service
[Service]
Type=oneshot
ExecStart=/bin/false
[Install]
WantedBy=multi-user.target
U
sudo systemctl daemon-reload && sudo systemctl enable culvert-qual-delay.service culvert-qual-a-fail.service
sudo culvert-os-update reboot            # capture frames from power-on to the console menu

# (b) replace the short unit with a 58-char name + one more failing unit
sudo systemctl disable culvert-qual-a-fail.service; sudo rm -f /etc/systemd/system/culvert-qual-a-fail.service
for u in culvert-qual-a-deliberately-long-failing-unit-name.service culvert-qual-z-fail.service; do
  sudo cp /dev/stdin /etc/systemd/system/$u <<'U'
[Unit]
Description=ESXi qualification: a unit that fails during boot
Before=systemd-user-sessions.service
[Service]
Type=oneshot
ExecStart=/bin/false
[Install]
WantedBy=multi-user.target
U
done
sudo systemctl daemon-reload && sudo systemctl enable culvert-qual-a-deliberately-long-failing-unit-name.service culvert-qual-z-fail.service
sudo culvert-os-update reboot

# (c) remove every fixture, verify absence, clean reboot (healthy control)
sudo systemctl disable culvert-qual-delay.service culvert-qual-a-deliberately-long-failing-unit-name.service culvert-qual-z-fail.service
sudo rm -f /etc/systemd/system/culvert-qual-*.service && sudo systemctl daemon-reload && sudo systemctl reset-failed
ls /etc/systemd/system/culvert-qual-* 2>&1; systemctl list-units --state=failed --no-legend   # expect: no such file; no failed units
sudo culvert-os-update reboot
```

**Expected lines:** derived from the shipped `culvert-splash-status`, which budgets the whole line to 80 columns (prefix 16 + body ≤ 35 + hint 29). The first failed unit is the alphabetically first one, which is why the fixture names start with `a-` and `z-`.

## 5. M2 checkpoints on ESXi (Q3 firstboot, Q10 final)

Use lab `e6bb0ff0` exactly: `m2-guest.sh` `d21f8ebf…`, `m2-verdict.py` `f8201229…`.

**The in-container probe:**
- Build it reproducibly: `cd test/e2e/appliance/lab/m2probe && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o m2probe .` with go1.27.3.
- The QEMU run's probe SHA-256 was `5961d86f6a335ed2692624a2372b82c5d54541ff4ef1715e3d3ffeafd83afc13`. Record your own; a different value is recorded, not fatal.
- Serve it from the workstation over HTTP, on a port the guest can reach.

```bash
SUM=$(sha256sum m2probe | cut -c1-64)
{ printf 'M2SUM=%q\nM2URL=%q\n' "$SUM" "http://<workstation-ip>:<port>/m2probe"; cat m2-guest.sh; } \
  | $SSH 'sudo bash -s' > "$EV/M2H-firstboot.txt"; echo "transport rc=$?" >> "$EV/M2H-firstboot.rc"
python3 -I m2-verdict.py "$EV/M2H-firstboot.txt" firstboot "$(tail -1 "$EV/M2H-firstboot.rc" | cut -d= -f2)"
```

**Pass:** all 7 checks pass (transcript, hardening, ordering, preconditions, ruleset, clamav, clamav-ready).
- **On fail:** any failed check is a STOP (trigger 1). The guest script reads state and creates or removes only its two temporary files under `/run`.
- **Scope:** this is the bounded residual's per-boot evidence on ESXi hardware. It does not widen the residual.

## 6. STOP triggers (unchanged, from the accepted residual disposition)

1. a failed required check;
2. a released applicable HWE kernel fix (Q0 and Q6 guard it);
3. priority above High, CVSS ≥ 9, KEV listing or a public exploit;
4. a new relevant RCE;
5. compromise or unexpected state;
6. a prohibited configuration (for example a NIC other than e1000/vmxnet3, or Xen);
7. out-of-scope use;
8. expiry of the residual window.

**STOP means:** report on #1528 and wait. No automatic kernel patch, rerun, rebuild or new test series.
