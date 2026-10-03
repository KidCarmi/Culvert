# Upgrade-under-ENOSPC qualification — run 20261003T092433Z

| artifact | reference |
|---|---|
| image under qualification | `culvert/proxy:dev-r3b` → `172.17.0.1:5056/culvert@sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` → `172.17.0.1:5056/culvert@sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f` |
| bounded host | `docker:29-dind`, data root + containerd + stack + agent state on one 2048 MiB ext4 loop file (-m 0) |
| agent | built from `cmd/culvert-maint` at c64119b, privilege_mode=docker_group_lab, inside the bounded host |

| scenario | check | result | detail |
|---|---|---|---|
| E0 | bounded-fs | **PASS** | size=1992552KiB avail=1976120KiB image=<EVID>/appliance-root.img (sparse, cap 2048MiB) |
| E0 | image-store-bounded | **PASS** | server=29.8.2 driver=overlayfs root=/var/lib/docker containerd-store=[[driver-type io.containerd.snapshotter.v1]]; content store /var/lib/docker/containerd/daemon/io.containerd.content.v1.content; every state dir on one device (1792 ) |
| E0 | dind-image | **PASS** | docker:29-dind = docker@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 |
| E0 | cur-absent | **PASS** | CUR not present inside the bounded host — the apply must pull it |
| E0 | seeded-predecessor | **PASS** | running v1.0.259 image=sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f state=ca90bb25ac431f45 |
| E0 | agent-start | **PASS** | {"agent_version":"dev","status":"ok"} |
| E1 | disk-filled | **PASS** | free 6140KiB on the bounded fs; CUR needs ~31749KiB unpacked; outer host untouched (fill is a file inside <EVID>/appliance-root.img) |
| E1 | pull-failed-enospc | **PASS** | op=01M40HA1G6DKSY86VAS241J299 state=failed; 2026-10-03T09:25:18.086411707Z pull err failed to copy: failed to send write: write /var/lib/docker/containerd/daemon/io.containerd.content.v1.content/ingest/ac30f9867fa950a9fe9b74ab8d595aaa0bb311d8f01e22a4100287f713 |
| E1 | running-unchanged | **PASS** | running image sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| E1 | pinned-tag-unchanged | **PASS** | culvert/proxy:pinned → sha256:f714e55b7b6708442af164accb082a3c3c89a79ecd37934931af3b166a4f448f |
| E1 | health-unchanged | **PASS** | /health 200 version=v1.0.259 |
| E1 | state-preserved | **PASS** | admin login http 200; ui_users.json+ca.bundle digest ca90bb25ac431f45 unchanged |
| E1 | agent-status | **PASS** | attention_required=False interrupted=0 |
| E2 | space-freed | **PASS** | free 1861656KiB |
| E2 | retry-succeeded | **PASS** | op=01M40HA4JSAE188A9V4V6VYEQW state=succeeded |
| E2 | running-is-target | **PASS** | running sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1 (172.17.0.1:5056/culvert@sha256:ad2d417e65575e4056c66f14427e6d2ad98f3287f69840c35e3b290b3cc805c1) |
| E2 | state-preserved | **PASS** | admin login http 200 on dev |

Failures: 0
