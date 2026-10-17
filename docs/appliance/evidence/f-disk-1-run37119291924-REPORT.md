# Upgrade-under-ENOSPC qualification — run 20261003T112350Z

| artifact | reference |
|---|---|
| image under qualification | `culvert:ci-smoke` → `172.17.0.1:5056/culvert@sha256:1367803313de15b08d48be474e6fcff29c245d14cd8cccd40d773d538ca512e2` |
| predecessor | `ghcr.io/kidcarmi/culvert:v1.0.259` → `172.17.0.1:5056/culvert@sha256:e5d42c47dd4d7da824ec923f8940ff314ad78566115312ba379a6c4f11af6208` |
| bounded host | `docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1`, data root + containerd + stack + agent state on one 2048 MiB ext4 loop file (-m 0) |
| agent | built from `cmd/culvert-maint` at 43f6664, privilege_mode=docker_group_lab, inside the bounded host |

| scenario | check | result | detail |
|---|---|---|---|
| E0 | bounded-fs | **PASS** | size=1992552KiB avail=1976120KiB image=/home/runner/work/_temp/appliance-enospc/appliance-root.img (sparse, cap 2048MiB) |
| E0 | image-store-bounded | **PASS** | server=29.8.2 driver=overlayfs root=/var/lib/docker containerd-store=[[driver-type io.containerd.snapshotter.v1]]; content store /var/lib/docker/containerd/daemon/io.containerd.content.v1.content; every state dir on one device (1792 ) |
| E0 | dind-image | **PASS** | docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 = docker@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 |
| E0 | cur-absent | **PASS** | CUR not present inside the bounded host — the apply must pull it |
| E0 | seeded-predecessor | **PASS** | running v1.0.259 image=sha256:e5d42c47dd4d7da824ec923f8940ff314ad78566115312ba379a6c4f11af6208 state=efbeba2d4558cb28 |
| E0 | ca-identity | **PASS** | root CA sha256 94:23:00:28:B3:73:94:3E:47:2A:60:59:E7:4C:D3:D3:FE:8F:53:D2:68:05:EE:1A:B0:CD:4A:16:08:A0:58:38 |
| E0 | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| E0 | agent-start | **PASS** | {"agent_version":"dev","status":"ok"} |
| E1 | disk-filled | **PASS** | free 6140KiB on the bounded fs; CUR image size ~72258KiB (docker image inspect .Size); outer host untouched (fill is a file inside /home/runner/work/_temp/appliance-enospc/appliance-root.img) |
| E1 | full-disk-alone-proxy-serving | **FAIL** | version=unreachable 15 s after the fill, BEFORE any upgrade (see diagnose.log) |
| E1 | refused-before-pull | **FAIL** | op=01M40R4PDZ1NQVRXNVS4EZRMBB state=failed (expected a preflight_space refusal with no pull stage); see op-full-disk.log |
| E1 | running-unchanged | **PASS** | running image sha256:e5d42c47dd4d7da824ec923f8940ff314ad78566115312ba379a6c4f11af6208 |
| E1 | pinned-tag-unchanged | **PASS** | culvert/proxy:pinned → sha256:e5d42c47dd4d7da824ec923f8940ff314ad78566115312ba379a6c4f11af6208 |
| E1 | health-unchanged | **FAIL** | version=unreachable want=v1.0.259 (see diagnose.log) |
| E1 | health-recovers-by-itself | **FAIL** | proxy answered again after none (still on the full disk) |
| E1 | state-preserved | **FAIL** | login http 000 state=e3b0c44298fc1c14 want=efbeba2d4558cb28 |
| E1 | ca-identity-unchanged | **FAIL** | fp= want=94:23:00:28:B3:73:94:3E:47:2A:60:59:E7:4C:D3:D3:FE:8F:53:D2:68:05:EE:1A:B0:CD:4A:16:08:A0:58:38 |
| E1 | enforcement | **FAIL** | allowed=000000 blocked=000000 |
| E1 | agent-status | **PASS** | attention_required=False interrupted=0 |
| E2 | space-freed | **PASS** | free 1811508KiB |
| E2 | operator-up-after-free | **FAIL** | the proxy was down after the full disk and came back only after a manual 'docker compose up -d' (data-plane finding; see diagnose.log) |
| E2 | retry-succeeded | **FAIL** | {"op_id":"01M40RB8BMNCJEGXR3VR95SY2E","kind":"upgrades.apply","state":"failed","actor":"uid=0,user=root","idempotency_key":"eq-retry-20261003T112350Z","lock_held_by":"01M40RB8BMNCJEGXR3VR95SY2E","started_at":"2026-10-03T11:28:17.268643969Z","finished_at":"2026 |
| E2 | running-is-target | **FAIL** | running=sha256:e5d42c47dd4d7da824ec923f8940ff314ad78566115312ba379a6c4f11af6208 want=sha256:1367803313de15b08d48be474e6fcff29c245d14cd8cccd40d773d538ca512e2 |
| E2 | state-preserved | **PASS** | admin login http 200 on v1.0.259 |
| E2 | ca-identity-preserved | **PASS** | root CA sha256 94:23:00:28:B3:73:94:3E:47:2A:60:59:E7:4C:D3:D3:FE:8F:53:D2:68:05:EE:1A:B0:CD:4A:16:08:A0:58:38 |
| E2 | enforcement | **PASS** | allowed=200 blocked=403 (default-deny + allow rule, real traffic through the proxy) |
| E2 | agent-ready-gate | **PASS** | 2026-10-03T11:28:17.394067881Z capture_before out capture_before: running_image_id=sha256:e5d42c47dd4d7da824ec923f8940ff314ad78566115312ba379a6c4f11af6208 prior_digests=sha256:e5d42c47dd4d7da824ec923f8940ff314ad78566115312ba379a6c4f11af6208,sha256:e5d42c47dd4d |

Failures: 10
