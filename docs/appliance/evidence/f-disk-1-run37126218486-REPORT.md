# Disk exhaustion during an active database write (F-DISK-1) — run 20261003T133245Z

| artifact | reference |
|---|---|
| image under qualification | `culvert:ci-smoke` → `172.17.0.1:5056/culvert@sha256:7ce1d643bef2f910f0dea237b5b6aec1327fd4dd107b06cd29bdb80f786073a4` |
| predecessor | `culvert:ci-smoke` → `172.17.0.1:5056/culvert@sha256:7ce1d643bef2f910f0dea237b5b6aec1327fd4dd107b06cd29bdb80f786073a4` |
| bounded host | `docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1`, data root + containerd + stack + agent state on one 2048 MiB ext4 loop file (-m 0) |
| agent | built from `cmd/culvert-maint` at f29f08b, privilege_mode=docker_group_lab, inside the bounded host |

| scenario | check | result | detail |
|---|---|---|---|
| E0 | bounded-fs | **PASS** | size=1992552KiB avail=1976120KiB image=/home/runner/work/_temp/appliance-fdisk1/appliance-root.img (sparse, cap 2048MiB) |
| E0 | image-store-bounded | **PASS** | server=29.8.2 driver=overlayfs root=/var/lib/docker containerd-store=[[driver-type io.containerd.snapshotter.v1]]; content store /var/lib/docker/containerd/daemon/io.containerd.content.v1.content; every state dir on one device (1792 ) |
| E0 | dind-image | **PASS** | docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 = docker@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 |
| E0 | seeded-predecessor | **PASS** | running dev image=sha256:7ce1d643bef2f910f0dea237b5b6aec1327fd4dd107b06cd29bdb80f786073a4 state=26e8608d8243b353 |
| E0 | ca-identity | **PASS** | root CA sha256 31:C8:F2:2B:59:A7:83:3D:DD:66:21:17:20:A4:E7:68:87:DD:22:72:98:82:4F:36:FF:AB:53:4E:11:F8:1D:0C |
| E0 | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| E0 | agent-start | **PASS** | {"agent_version":"dev","status":"ok"} |
| W | filled-during-write | **PASS** | FeedSync: parsed 2570579 domain entries, writing to BadgerDB; write still in flight; filled to 5116KiB free |
| W | known-failure-reproduced | **SURVIVED** | no SIGBUS; status=exited exit=2 restarts=1; /health version=unreachable; the write then reported: no completion line |
| W | recovered-serving | **PASS** | /health 200 version=dev; recovered at step 2: docker compose up -d --force-recreate proxy |
| W | recovery-step-1-sufficient | **KNOWN-FAILURE** | free space + compose up -d did NOT restore the proxy; needed step 2: docker compose up -d --force-recreate proxy (runbook must say so) |
| W | state-intact | **PASS** | admin login http 200; ui_users.json+ca.bundle digest 26e8608d8243b353 unchanged |
| W | ca-identity-intact | **PASS** | root CA sha256 31:C8:F2:2B:59:A7:83:3D:DD:66:21:17:20:A4:E7:68:87:DD:22:72:98:82:4F:36:FF:AB:53:4E:11:F8:1D:0C |
| W | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| W | category-store-opens | **PASS** | culvert_catfeeddb_available 1 culvert_catfeeddb_recovered 0 culvert_catfeeddb_quarantined_copies 0  |
| W | category-coverage-after-recovery | **INFO** | post-recovery feed log: FeedSync: starting UT1 sync from https://raw.githubusercontent.com/NethServer/toulouse-bl-mirror/master/blacklists.tar.gz FeedSync: parsed 2570579 domain entries, writing to BadgerDB…  |

Failures: 0
