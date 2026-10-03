# Upgrade-under-ENOSPC qualification — run 20261003T103439Z

| artifact | reference |
|---|---|
| image under qualification | `culvert/proxy:dev-r3b` → `172.17.0.1:5056/culvert@sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` → `172.17.0.1:5056/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f` |
| bounded host | `docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1`, data root + containerd + stack + agent state on one 2048 MiB ext4 loop file (-m 0) |
| agent | built from `cmd/culvert-maint` at ee858e1, privilege_mode=docker_group_lab, inside the bounded host |

| scenario | check | result | detail |
|---|---|---|---|
| E0 | bounded-fs | **PASS** | size=1992552KiB avail=1976120KiB image=/tmp/claude-0/-home-user-Culvert/9f0490a9-b6a6-5cfb-9bef-3520e8817f2e/scratchpad/enospc-g4/appliance-root.img (sparse, cap 2048MiB) |
| E0 | image-store-bounded | **PASS** | server=29.8.2 driver=overlayfs root=/var/lib/docker containerd-store=[[driver-type io.containerd.snapshotter.v1]]; content store /var/lib/docker/containerd/daemon/io.containerd.content.v1.content; every state dir on one device (1792 ) |
| E0 | dind-image | **PASS** | docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 = docker@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 |
| E0 | cur-absent | **PASS** | CUR not present inside the bounded host — the apply must pull it |
| E0 | seeded-predecessor | **PASS** | running v1.0.259 image=sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f state=c0fed3da4f6c10e9 |
| E0 | ca-identity | **PASS** | root CA sha256 D0:92:2E:23:8A:B2:03:51:5A:80:65:E4:90:86:F7:6F:45:04:DE:07:C8:67:59:28:25:7E:66:4F:B7:95:F2:14 |
| E0 | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| E0 | agent-start | **PASS** | {"agent_version":"dev","status":"ok"} |
| E1 | disk-filled | **PASS** | free 6140KiB on the bounded fs; CUR image size ~31749KiB (docker image inspect .Size); outer host untouched (fill is a file inside /tmp/claude-0/-home-user-Culvert/9f0490a9-b6a6-5cfb-9bef-3520e8817f2e/scratchpad/enospc-g4/appliance-root.img) |
| E1 | pull-failed-enospc | **PASS** | op=01M40NA2MFQW9CCZN85KRQB6MC state=failed; 2026-10-03T10:35:13.576515438Z pull err failed to copy: failed to send write: write /var/lib/docker/containerd/daemon/io.containerd.content.v1.content/ingest/12408e4098bbac350409e7a73d9a92d6c7a6aef4636784ceba7a090c5c |
| E1 | running-unchanged | **PASS** | running image sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| E1 | pinned-tag-unchanged | **PASS** | culvert/proxy:pinned → sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| E1 | health-unchanged | **PASS** | /health 200 version=v1.0.259 |
| E1 | state-preserved | **PASS** | admin login http 200; ui_users.json+ca.bundle digest c0fed3da4f6c10e9 unchanged |
| E1 | ca-identity-unchanged | **PASS** | root CA sha256 D0:92:2E:23:8A:B2:03:51:5A:80:65:E4:90:86:F7:6F:45:04:DE:07:C8:67:59:28:25:7E:66:4F:B7:95:F2:14 |
| E1 | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| E1 | agent-status | **PASS** | attention_required=False interrupted=0 |
| E2 | space-freed | **PASS** | free 1861592KiB |
| E2 | retry-succeeded | **PASS** | op=01M40NA5VB398N8YFN2X5CPVBQ state=succeeded |
| E2 | running-is-target | **PASS** | running sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1 (172.17.0.1:5056/culvert@sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1) |
| E2 | state-preserved | **PASS** | admin login http 200 on dev |
| E2 | ca-identity-preserved | **PASS** | root CA sha256 D0:92:2E:23:8A:B2:03:51:5A:80:65:E4:90:86:F7:6F:45:04:DE:07:C8:67:59:28:25:7E:66:4F:B7:95:F2:14 |
| E2 | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| E2 | agent-ready-gate | **PASS** | 2026-10-03T10:35:16.403292335Z capture_before out capture_before: running_image_id=sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f prior_digests=sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f,sha256:f714e55b7b67 |

Failures: 0
