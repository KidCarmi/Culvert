# Appliance lab — guest boot qualification (run 20261025T104429Z)

| identity | value |
|---|---|
| lab/harness commit | `735f1a24c72624e6fc361c2cb5a7d667d4bc22a0` |
| OVA | `culvert-appliance-1.0.327-candidate.gb910508629e9-ubuntu-24.04.ova` sha256 `61c46d6db6603d76edbb0d64327bed85e76bea86d24457e9f3ae36e71bd5854a` |
| appliance source (guest build-info) | `b910508629e9d80352067bc8ec608753ddf0924e` |
| application image in the guest | `sha256:ca27cf9a645431ed77255efa0897daabb63bbed9c6b4acd6ac574820422d186c` |
| accelerator | kvm (preflight: `preflight.json`) |
| access | read-only `culvert-operator` SSH (imported key) + authenticated local console (`culvert`, PAM + sudo) |

| step | check | result | detail |
|---|---|---|---|
| P | tools | **PASS** | qemu, qemu-img, ssh, curl, python3, openssl, iso tool present |
| P | memory | **PASS** | 14725 MiB available (need 6144) |
| P | disk | **PASS** | 73 GiB free at //culvert-lab/lab (need 20: OVA + VMDK + base + overlay growth) |
| P | accel | **PASS** | accel=kvm (kvm usable: yes) |
| 1 | ova-sha256 | **PASS** | culvert-appliance-1.0.327-candidate.gb910508629e9-ubuntu-24.04.ova sha256 61c46d6db6603d76edbb0d64327bed85e76bea86d24457e9f3ae36e71bd5854a |
| 1 | ova-manifest | **PASS** | every .mf digest matches |
| 1 | disk-chain | **PASS** | disk.raw (disposable copy of the OVA's own VMDK) → direct-I/O loop /dev/loop0 → dm culvert-lab-4bb99689 (linear; latency injectable); QEMU cache=none |
| 2 | boot-started | **PASS** | qemu pid 30765 accel=kvm |
| 2 | kernel-started | **PASS** | [    0.000000] Linux version 7.0.0-38-generic (buildd@lcy02-amd64-063) (x86_64-linux-gnu-g after 5s |
| 2 | operator-ssh-up | **PASS** | culvert-operator SSH (OVF-delivered key, status-json) after 23s |
| 2 | firstboot-complete | **PASS** | status-json: complete recorded, phase provisioned, 54s from power-on |
| 3 | operator-observe | **PASS** | culvert-operator: help, status, status-json (valid JSON, version 1.0.327-candidate.gb910508629e9), diagnostics |
| 3 | status-setup-pending | **PASS** | status-json setup_status=pending, phase=provisioned |
| 3 | firstboot-steps | **PASS** | access agent complete console images install ovf |
| 3a | console-onetime-printed | **PASS** | first boot printed a one-time console password on the VM console (ttyS0) |
| 3a | console-login | **PASS** | PAM login as culvert with the one-time password → forced change → sudo with the new password → root |
| 3a | password-changed | **PASS** | chage: no change pending after the forced change |
| 3 | culvert-status-setup-pending | **PASS** |   STATE:              services running — setup pending (create the first admin at https://10.0.2.15:9090) |
| 3 | image-identity | **PASS** | culvert runs sha256:ca27cf9a645431ed77255efa0897daabb63bbed9c6b4acd6ac574820422d186c |
| 3 | setup-token | **PASS** | 32 characters, from culvert-status via the authenticated console; identical to the token first boot printed on the VM console |
| 3c | operator-commands-refused | **PASS** | 'bash'→2 'status; id'→2 'sudo -n id'→2 '/bin/sh -c id'→2 'status-json --help'→2 'reboot'→2 |
| 3c | forwarding-refused | **PASS** | local-forward:refused remote-forward:255 stdio-forward:255 |
| 3c | file-transfer-refused | **PASS** | scp-legacy:1 scp-sftp:255 sftp:255 |
| 3c | local-admin-ssh-refused | **PASS** | culvert@ with the imported key: exit 255 |
| 3c | sshd-effective | **PASS** | AllowUsers culvert-operator, PasswordAuthentication no, DisableForwarding yes, ForceCommand culvert-access; operator has no sudo |
| 3c | local-admin-sudo-needs-password | **PASS** | culvert: sudo -n refused (a password is required) |
| 3d | boot-timing | **INFO** | Startup finished in 3.013s (kernel) + 46.358s (userspace) = 49.371s ; slowest: 39.324s culvert-firstboot.service 1.757s systemd-networkd-wait-online.service 1.518s cloud-init-local.service |
| 3e | recovery-secrets | **PASS** | root reveal shows both .env passphrases exactly, no setup token, with custody guidance; unprivileged invocation refused |
| 4a | bootstrap-api-needs-token | **PASS** | POST /api/auth/users 403, PUT default-auth-outcome 403 without the token; status-json still setup_status=pending |
| 4 | setup-without-token | **PASS** | 403 |
| 4 | setup-with-token | **PASS** | 200 |
| 4 | admin-login | **PASS** | 200 |
| 4 | status-setup-complete | **PASS** | culvert-status: setup complete |
| 4 | operator-setup-complete | **PASS** | status-json setup_status=completed, administrator_enrolled=True |
| 4b | demotion-immediate | **PASS** | labop admin session: GET /api/auth/users 200 → demoted to viewer → the same session 403 |
| 4b | portal-cookie-replay | **BLOCKED** | needs an identity provider (none in this lab); covered by TestUISessionRole_RejectsReplayedPortalCookie and the proxy cookie-boundary tests in CI |
| 5 | auth-exempt | **PASS** | 200 |
| 5 | default-deny | **PASS** | {"defaultAction":"deny"} |
| 5 | traffic | **PASS** | example.com 403 → rule → 200; example.org 403 (real egress through the guest proxy) |
| 5 | ready-rows | **PASS** | ca ok;policy_loaded ok;policy_posture ok; |
| 5 | clamav-real | **PASS** | /ready clamav ok — the REAL clamav/clamav sidecar from the OVA, signatures fetched by the guest |
| 5 | status-ready-to-enforce | **PASS** | culvert-status: ready to enforce |
| 5 | ca-identity | **PASS** | root CA sha256 C8:28:DB:B1:0F:F5:08:5C:B2:99:63:F3:6B:40:0C:E5:FB:0A:22:70:F2:04:10:66:6F:38:11:0D:C8:8A:C2:38 |
| 5b | category-data | **PASS** | UT1 sync complete (lastSync entries: 2026-10-25T10:46:00Z 2601320); 2 of 5 probe hosts resolve via the community tier |
| 5c | category-enforcement | **PASS** | thepiratebay.org (Malicious via UT1): category rule → 403; without it → 301 |
| 6 | agent-installed | **PASS** | culvert-maint active, version v1.0.327-candidate.gb910508629e9 = proxy v1.0.327-candidate.gb910508629e9, no agent.pending |
| 6 | agent-reachable | **PASS** | agent v1.0.327-candidate.gb910508629e9 reachable over its socket, privilege_mode=sudoers, compose stack up |
| 6 | agent-backup | **PASS** | op 01M5SATBBSVMGWP3QJCAX8CKD8 → culvert-backup-20261025-104834-424771.tar.gz succeeded (proxy → agent socket → sudoers → cli container) |
| 6 | backup-listed | **PASS** | culvert-backup-20261025-104834-424771.tar.gz listed by /api/backups (available=true, one entry) |
| 6 | restore-dry-run | **PASS** | Validation: PASS; dry run, no files written (Culvert version: v1.0.327-candidate.gb910508629e9) |
| 6b | restore-refused-while-running | **PASS** | commit against the running stack refused (Restore commit error: restore: data directory is locked by another Culvert process (is the proxy still running? stop the stack first)); the post-backup rule is untouched |
| 6b | allowlist-survived-restore | **PASS** | admin marker allowlist-survives-marker.example present after restore (not re-added) — the saved allowlist survived the backup |
| 6b | restore-commit | **PASS** | down → restore --confirm → up: login 200, backup rules back (lab-allow-example), post-backup rule gone, example.com 200 / example.net 403 |
| 6c | test-only-trust | **PASS** | registry CA, hosts entry, fixture keyring (public) installed; agent restarted; running image sha256:ca27cf9a645431ed77255efa0897daabb63bbed9c6b4acd6ac574820422d186c now carries ghcr.io/kidcarmi/culvert@sha256:ca27cf9a645431ed77255efa0897daabb63bbed9c6b4acd6ac574820422d186c |
| 6c | unsigned-apply-refused | **PASS** | apply without release evidence: 403 ("error":"release trust: signed release proof required"); still running the baseline |
| 6c | signed-apply | **PASS** | agent apply with signed target + baseline evidence: succeeded; running sha256:27a35951fb338402b2c21e086f5a5d54e7a16bbc50e8cb9f7354fcbcf083d4a7 (lab-target label); enforcement after the swap: example.com 200, example.org 403 |
| 6c | signed-rollback | **PASS** | agent image rollback to the signed baseline: succeeded; running sha256:ca27cf9a645431ed77255efa0897daabb63bbed9c6b4acd6ac574820422d186c again; example.com 200, example.org 403; admin login 200 |
| 6d | support-bundle | **FAIL** | approve http 204 |
| 7 | os-update | **PASS** | culvert-os-update os exit 0 (0 package actions) |
| 7 | reboot | **PASS** | proxy /health and operator SSH back 31s after the reboot command |
| 7 | kernel | **INFO** | kernel unchanged (7.0.0-38-generic): no newer linux-image was installed |
| 7 | docker-held | **PASS** | Docker packages still held; engine 29.9.0 |
| 8 | stack-resumed | **PASS** | culvert-stack-resume.service took the os-update + agent locks, started the stack and cleared its marker |
| 8 | admin-login | **PASS** | 200 after reboot |
| 8 | policy-persisted | **PASS** | rules: lab-allow-example |
| 8 | enforcement | **PASS** | example.com 200, example.org 403 (also proves Exempt auth survived) |
| 8 | ready | **PASS** | /ready 200 |
| 8 | ca-identity | **PASS** | unchanged C8:28:DB:B1:0F:F5:08:5C:B2:99:63:F3:6B:40:0C:E5:FB:0A:22:70:F2:04:10:66:6F:38:11:0D:C8:8A:C2:38 |
| 8 | ca-encrypted-at-rest | **PASS** | /data/ca.bundle starts PSCA, no PEM private key, .env CULVERT_CA_PASSPHRASE non-empty |
| 8 | support-persisted | **PASS** | csb_e5jiqw4sdsyt4bd4gpaixkzpm3 listed after the reboot: state=ready, case=lab-persist |
| 8 | category-data | **PASS** | category lookups identical before/after reboot |
| 8 | backup-listed | **PASS** | culvert-backup-20261025-104834-424771.tar.gz still listed (available=true, one entry) |
| 8 | agent-reachable | **PASS** | agent v1.0.327-candidate.gb910508629e9 reachable over its socket, privilege_mode=sudoers, compose stack up (after the maintenance reboot) |
| 8 | firstboot-not-rerun | **PASS** | no first-boot step ran on the second boot |
| 8 | state-files | **PASS** | first-boot state files unchanged |
| 8 | restore-persisted | **PASS** | the restored policy (no lab-post-backup) survived the reboot |
| 8 | image-identity | **PASS** | culvert runs sha256:ca27cf9a645431ed77255efa0897daabb63bbed9c6b4acd6ac574820422d186c after the reboot (the signed rollback target) |
| 8 | operator-status | **PASS** | status-json after the reboot: setup_status=completed, phase=ready |
| 8 | boot-timing | **INFO** | Startup finished in 3.095s (kernel) + 16.488s (userspace) = 19.584s ; slowest: 13.251s culvert-stack-resume.service 839ms docker.service 832ms dev-sda1.device |
| R | io-accounting | **INFO** | LAB-ONLY guest change for attribution: systemd DefaultIOAccounting=yes (DefaultIOAccounting=yes) |
| R | clamav-evidence | **PASS** | a fresh EICAR body is answered '403 Blocked by CLAMAV scan' with clamd up, NOT with clamd stopped (403:Blocked: antivirus scanning is currently unavailable, so thi), and again after clamd restarts |
| R | variant-base | **INFO** | LAB-ONLY guest change set 'base' applied: base: no change  |
| R | readahead-base | **PASS** | effective read_ahead_kb=4096 == expected 4096 before measurement |
| R | profile-fast | **INFO** | disk: read +0ms, write +0ms per I/O (0 83886080 linear 7:0 0 ); budget 60s; 3 maintenance reboots |
| R | backup-list-fast-1 | **PASS** | first listing http 200: culvert-backup-20261025-104834-424771.tar.gz (11609 bytes, encrypted=False) in 0.658s, count=1 (login 0.103s, not counted) |
| R | operator-capture-integrity-fast-1 | **PASS** | 6 sanitized records, all complete and reparse (overflow=0 unparseable=0) |
| R | recovery-fast-1 | **PASS** | recovered in 36.8s (budget 60s; unrounded 36.754547999999886): kernel=+6.3s first_ready_clamav_ok=+26.2s first_traffic_allow_block=+26.3s first_eicar_blocked_by_clamav=+26.4s first_operator_phase_ready=+26.8s first_joint_sample=+26.8s third_consecutive_joint_sample=+36.8s; samples=6; host disk: 8634 |
| R | readahead-fast-1 | **PASS** | effective read_ahead_kb=4096 == expected 4096 (post-reboot, stack up) |
| R | state-fast-1 | **PASS** | admin login, normalized policy (persisted, not draft) + valid default action, CA, image and agent availability equal the pre-reboot baseline |
| R | backup-list-fast-2 | **PASS** | first listing http 200: culvert-backup-20261025-104834-424771.tar.gz (11609 bytes, encrypted=False) in 0.594s, count=1 (login 0.102s, not counted) |
| R | operator-capture-integrity-fast-2 | **PASS** | 7 sanitized records, all complete and reparse (overflow=0 unparseable=0) |
| R | recovery-fast-2 | **PASS** | recovered in 41.5s (budget 60s; unrounded 41.52149200000008): kernel=+6.3s first_ready_clamav_ok=+31.0s first_traffic_allow_block=+31.1s first_eicar_blocked_by_clamav=+26.1s first_operator_phase_ready=+26.5s first_joint_sample=+31.6s third_consecutive_joint_sample=+41.5s; samples=7; host disk: 8701  |
| R | readahead-fast-2 | **PASS** | effective read_ahead_kb=4096 == expected 4096 (post-reboot, stack up) |
| R | state-fast-2 | **PASS** | admin login, normalized policy (persisted, not draft) + valid default action, CA, image and agent availability equal the pre-reboot baseline |
| R | backup-list-fast-3 | **PASS** | first listing http 200: culvert-backup-20261025-104834-424771.tar.gz (11609 bytes, encrypted=False) in 0.587s, count=1 (login 0.110s, not counted) |
| R | operator-capture-integrity-fast-3 | **PASS** | 7 sanitized records, all complete and reparse (overflow=0 unparseable=0) |
| R | recovery-fast-3 | **PASS** | recovered in 41.6s (budget 60s; unrounded 41.621354999999994): kernel=+6.3s first_ready_clamav_ok=+31.1s first_traffic_allow_block=+26.2s first_eicar_blocked_by_clamav=+26.2s first_operator_phase_ready=+26.7s first_joint_sample=+31.6s third_consecutive_joint_sample=+41.6s; samples=7; host disk: 8678 |
| R | readahead-fast-3 | **PASS** | effective read_ahead_kb=4096 == expected 4096 (post-reboot, stack up) |
| R | state-fast-3 | **PASS** | admin login, normalized policy (persisted, not draft) + valid default action, CA, image and agent availability equal the pre-reboot baseline |
| R | recovery-cases | **PASS** | 3 of 3 profile x reboot cases ran |
| H | history-recorded | **PASS** | 12 marker requests (hist0389f4d96da1-*) in the history store |
| H | history-export | **PASS** | POST /api/logs/history/export → 3445 bytes, encrypted stream (CVRTST01), sha256 50179467fd62e6c8…, held on the runner |
| H | history-export-opaque | **PASS** | no marker host is readable in the archive bytes |
| H | history-backup | **PASS** | culvert-backup-20261025-110339-868800.tar.gz |
| H | history-source-destroyed | **PASS** | data volume deleted (volume=culvert_proxy-data), restored from culvert-backup-20261025-110339-868800.tar.gz into a fresh volume, CULVERT_LOG_PASSPHRASE rotated |
| H | history-gone-after-restore | **PASS** | after the restore the history store is ON (new key) and holds 0 marker records — the backup does not carry history |
| H | history-import-refused-while-running | **PASS** | refused against the running proxy: History import error: data directory is locked by another Culvert process (is the proxy still running? stop the stack first) |
| H | history-wrong-passphrase | **PASS** | wrong archive passphrase refused (backup decrypt failed (invalid passphrase or tampered backup)), nothing imported |
| H | history-import-dry-run | **PASS** | history archive OK: 12 records, 0 skipped at export, created 2026-10-25T11:03:39Z |
| H | history-recovered | **PASS** | imported=12 duplicate=0 rekeyed=0 expired=0 invalid=0; the 12 marker records read back identical (ts, host, status, method) under the ROTATED log key |
| H | allowlist-survived-recovery | **PASS** | admin marker allowlist-survives-marker.example present after fresh-volume recovery (not re-added) |
| H | history-enforcement | **PASS** | example.com 200 through the proxy after the recovery |

Totals: blocked=1, fail=1, info=6, pass=104

Not qualified by this lab: vSphere/ESXi import (ovftool), the guestinfo OVF transport, VMware Tools, LSI Logic SCSI, the hypervisor's tty1 console (ttyS0 here), datastore/thin-provisioning behaviour, the proxy's Release Management dispatch (6c calls the agent socket as its peer, with TEST-ONLY trust), and F-DISK-1 (owned by the bounded nested-Docker harness; still OPEN).
