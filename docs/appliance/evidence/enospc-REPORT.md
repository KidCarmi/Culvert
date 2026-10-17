# Upgrade-under-ENOSPC qualification — run 20261003T111724Z

| artifact | reference |
|---|---|
| image under qualification | `culvert/proxy:dev-r3b` → `172.17.0.1:5056/culvert@sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` → `172.17.0.1:5056/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f` |
| bounded host | `docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1`, data root + containerd + stack + agent state on one 2048 MiB ext4 loop file (-m 0) |
| agent | built from `cmd/culvert-maint` at a1ddc1c, privilege_mode=docker_group_lab, inside the bounded host |

| scenario | check | result | detail |
|---|---|---|---|
| E0 | bounded-fs | **PASS** | size=1992552KiB avail=1976120KiB image=/tmp/claude-0/-home-user-Culvert/9f0490a9-b6a6-5cfb-9bef-3520e8817f2e/scratchpad/enospc-g5/appliance-root.img (sparse, cap 2048MiB) |
| E0 | image-store-bounded | **PASS** | server=29.8.2 driver=overlayfs root=/var/lib/docker containerd-store=[[driver-type io.containerd.snapshotter.v1]]; content store /var/lib/docker/containerd/daemon/io.containerd.content.v1.content; every state dir on one device (1792 ) |
| E0 | dind-image | **PASS** | docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 = docker@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 |
| E0 | cur-absent | **PASS** | CUR not present inside the bounded host — the apply must pull it |
| E0 | seeded-predecessor | **PASS** | running v1.0.259 image=sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f state=847e37ee019e3285 |
| E0 | ca-identity | **PASS** | root CA sha256 25:1E:85:2D:B4:D2:3D:42:32:5E:D0:A0:78:73:8D:06:3B:6C:55:10:CD:11:7F:0F:28:A3:78:A4:C4:C9:5B:AE |
| E0 | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| E0 | agent-start | **PASS** | {"agent_version":"dev","status":"ok"} |
| E1 | disk-filled | **PASS** | free 6140KiB on the bounded fs; CUR image size ~31749KiB (docker image inspect .Size); outer host untouched (fill is a file inside /tmp/claude-0/-home-user-Culvert/9f0490a9-b6a6-5cfb-9bef-3520e8817f2e/scratchpad/enospc-g5/appliance-root.img) |
| E1 | full-disk-alone-proxy-serving | **PASS** | /health 200 version=v1.0.259 15 s after the fill, no upgrade attempted |
| E1 | refused-before-pull | **PASS** | op=01M40QRQGR3D648Z3DXE0JPQ6E state=failed; 2026-10-03T11:18:10.611066301Z preflight_space out preflight_space: REFUSED — /var/lib/docker has 5 MiB free; pulling the target (31 MiB compressed) needs about 349 MiB. Nothing was pulled or changed. Free space (e.g |
| E1 | running-unchanged | **PASS** | running image sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| E1 | pinned-tag-unchanged | **PASS** | culvert/proxy:pinned → sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| E1 | health-unchanged | **PASS** | /health 200 version=v1.0.259 |
| E1 | state-preserved | **PASS** | admin login http 200; ui_users.json+ca.bundle digest 847e37ee019e3285 unchanged |
| E1 | ca-identity-unchanged | **PASS** | root CA sha256 25:1E:85:2D:B4:D2:3D:42:32:5E:D0:A0:78:73:8D:06:3B:6C:55:10:CD:11:7F:0F:28:A3:78:A4:C4:C9:5B:AE |
| E1 | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| E1 | agent-status | **PASS** | attention_required=False interrupted=0 |
| E2 | space-freed | **PASS** | free 1861700KiB |
| E2 | retry-succeeded | **PASS** | op=01M40QRTMQNP599QF1R3DKY0GG state=succeeded |
| E2 | running-is-target | **PASS** | running sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1 (172.17.0.1:5056/culvert@sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1) |
| E2 | state-preserved | **PASS** | admin login http 200 on dev |
| E2 | ca-identity-preserved | **PASS** | root CA sha256 25:1E:85:2D:B4:D2:3D:42:32:5E:D0:A0:78:73:8D:06:3B:6C:55:10:CD:11:7F:0F:28:A3:78:A4:C4:C9:5B:AE |
| E2 | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| E2 | agent-ready-gate | **PASS** | 2026-10-03T11:18:13.602652225Z capture_before out capture_before: running_image_id=sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f prior_digests=sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f,sha256:f714e55b7b67 |

Failures: 0
