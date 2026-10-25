# Disk exhaustion during an active database write (F-DISK-1) — run 20261025T103406Z

| artifact | reference |
|---|---|
| image under qualification | `culvert:ci-smoke` → `172.17.0.1:5056/culvert@sha256:7aef494381724759485a2c334beb723390b91d850a3b453e0c23a85ad3921556` |
| predecessor | `culvert:ci-smoke` → `172.17.0.1:5056/culvert@sha256:7aef494381724759485a2c334beb723390b91d850a3b453e0c23a85ad3921556` |
| bounded host | `docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1`, data root + containerd + stack + agent state on one 2048 MiB ext4 loop file (-m 0) |
| agent | shipped binary sha256 81e4214d98f3cf9b1fffc3e41a2e5576f643c9865e7a49f908d700fd105ce64e, v1.0.327-candidate.gb910508629e9, privilege_mode=docker_group_lab, inside the bounded host |

| scenario | check | result | detail |
|---|---|---|---|
| E0 | bounded-fs | **PASS** | size=1992552KiB avail=1976120KiB image=/home/runner/work/_temp/fdisk1/attempt-2/appliance-root.img (sparse, cap 2048MiB) |
| E0 | image-content-cur | **PASS** | pushed 172.17.0.1:5056/culvert@sha256:7aef494381724759485a2c334beb723390b91d850a3b453e0c23a85ad3921556 has config sha256:75dd735cebbfe312e7f15c2e86f82bf66493853d707c6d2b3d664e03f6e47779 (re-hashed) = source tar config; tar sha256 1db620abbf4fe34424749e64a4e8b9 |
| E0 | image-content-pred | **PASS** | pushed 172.17.0.1:5056/culvert@sha256:7aef494381724759485a2c334beb723390b91d850a3b453e0c23a85ad3921556 has config sha256:75dd735cebbfe312e7f15c2e86f82bf66493853d707c6d2b3d664e03f6e47779 (re-hashed) = source tar config; tar sha256 1db620abbf4fe34424749e64a4e8b9 |
| E0 | image-store-bounded | **PASS** | server=29.8.2 driver=overlayfs root=/var/lib/docker containerd-store=[[driver-type io.containerd.snapshotter.v1]]; content store /var/lib/docker/containerd/daemon/io.containerd.content.v1.content; every state dir on one device (1792 ) |
| E0 | dind-image | **PASS** | docker:29-dind@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 = docker@sha256:7dcdfc4a20246236f558175182ccace1eb15a41bd3eb119dd2284f393498b7c1 |
| E0 | image-pulled | **PASS** | nested daemon runs sha256:7aef494381724759485a2c334beb723390b91d850a3b453e0c23a85ad3921556 = the pushed manifest digest |
| E0 | seeded-predecessor | **PASS** | running v1.0.327-candidate.gb910508629e9 image=sha256:7aef494381724759485a2c334beb723390b91d850a3b453e0c23a85ad3921556 state=5395d1a3277c039d |
| E0 | image-running | **PASS** | container culvert runs sha256:7aef494381724759485a2c334beb723390b91d850a3b453e0c23a85ad3921556 |
| E0 | ca-identity | **PASS** | root CA sha256 26:C9:66:C3:92:79:B2:CF:11:5D:AE:2B:34:B0:4E:65:8C:CB:6E:5A:F7:6C:48:19:51:85:BB:30:12:02:18:2E |
| E0 | enforcement | **PASS** | allowed=200 blocked=403 with the default-deny block page (real traffic through the proxy) |
| E0 | agent-identity | **PASS** | shipped binary sha256 81e4214d98f3cf9b1fffc3e41a2e5576f643c9865e7a49f908d700fd105ce64e, v1.0.327-candidate.gb910508629e9 |
| E0 | agent-start | **PASS** | {"agent_version":"v1.0.327-candidate.gb910508629e9","status":"ok"} |
| W | filled-during-write | **PASS** | FeedSync: parsed 2601320 domain entries, writing to BadgerDB; write still in flight; filled to 6140KiB free |
| W | known-failure-reproduced | **SURVIVED** | no crash: still running, no restart since the fill; status=running exit=0 restarts=0; /health version=v1.0.327-candidate.gb910508629e9; the write then reported: FeedSync: bulk write failed (import NOT complete; it is retried, and redone at the next start): can |
| W | under-fill-enforcement | **PASS** | under fill (free 6140->6140KiB): allowed=200 blocked=403 (deny body: <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Access Denied — Culvert</title><style>*,*::before,*::af |
| W | degraded-state-truthful | **PASS** | disk full, pre-cleanup (free 6140KiB): import NOT certified complete (last_sync=0) AND the failed import is surfaced (sync_failures_total=1); /health version=v1.0.327-candidate.gb910508629e9; feed metrics: culvert_category_feed_last_sync_timestamp_seconds 0 cu |
| W | recovered-serving | **PASS** | /health 200 version=v1.0.327-candidate.gb910508629e9; recovered at step 1: docker compose up -d |
| W | recovery-step-1-sufficient | **PASS** | free space + docker compose up -d |
| W | state-intact | **PASS** | admin login http 200; ui_users.json+ca.bundle digest 5395d1a3277c039d unchanged |
| W | ca-identity-intact | **PASS** | root CA sha256 26:C9:66:C3:92:79:B2:CF:11:5D:AE:2B:34:B0:4E:65:8C:CB:6E:5A:F7:6C:48:19:51:85:BB:30:12:02:18:2E |
| W | enforcement | **PASS** | allowed=200 blocked=403 with the default-deny block page (real traffic through the proxy) |
| W | category-store-opens | **PASS** | culvert_catfeeddb_available 1 culvert_catfeeddb_recovered 0 culvert_catfeeddb_quarantined_copies 0  |
| W | category-coverage-after-recovery | **INFO** | post-recovery feed log: FeedSync: starting UT1 sync from https://raw.githubusercontent.com/NethServer/toulouse-bl-mirror/master/blacklists.tar.gz FeedSync: parsed 2601320 domain entries, writing to BadgerDB… FeedSync: bulk write failed (import NOT complete; it |
| W | category-import-converges | **PASS** | convergence PROVEN: sync complete: 2601320 domains in 12s (948s) — after recovery |
| midwrite | convergence-verdict | **PASS** | convergence PROVEN (FeedSync sync complete observed) — the mandatory convergence verdict is satisfied |

Failures: 0
