# Claim-Evidence Ledger — "High availability"

Article: [`high-availability.md`](high-availability.md). Verified against repo
revision `ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| `-ha-auto-failover` off by default (2-node split-brain risk) | src | `main.go:244` (flag help) |
| Fencing lease enabled via `-ha-etcd-endpoints`; ignores `-ha-auto-failover` | src | `main.go:244-245` |
| etcd mTLS + lease TTL flags | src | `main.go:246-249` |
| Lease key `/culvert/ha/leader`, epoch = create_revision | src | `internal/halease/etcd.go:20,101,150` |
| Lease armed before any role branch; unreachable etcd = fail-closed | src | `cluster_startup.go:43,152` (`armHALease`) |
| Acquire-gated promotion | src | `ha_lease.go:84` (`p.Acquire`) |
| Keepalive self-fences on lease loss/unconfirmed | src | `ha_lease.go:183-202` (`selfFence`) |
| `WriteAllowed()` gates writes; epoch stamped on write sinks | src | `ha_lease.go:242-247,269` |
| Auto-promotion guarded by hysteresis + freshness, then Acquire | src | `ha_failover.go:12-15,74,98` (`leaseAutoPromote`) |
| Demoted node resyncs from ex-leader | src | `ha_failover.go:111-117` (`enterStandbyResync`) |
| Fast restart waits for ghost lease | src | `ha_failover.go:145-153` (`acquireLeaseForResume`) |
| Manual promotion (break-glass) route | src | `ui_cluster.go:594` (`/api/cluster/ha/promote`) |
| HA status route; `/healthz` + `/api/cluster/ha` expose lease_mode/valid/epoch | src | `ui_cluster.go:593`; `ha_lease.go:269` |

## Gap resolution (G-02)

**Resolved.** The `internal/halease/halease.go:7` comment ("S1 ships the
primitive ONLY — nothing in the runtime consumes it yet") is a **package
slice-history** note describing that package's own scope (S1 = the primitive; the
comment itself lists S2 wiring Acquire into promotion, S3 epoch-stamping, S5
flags/GUI). The runtime consumption lives in package `main`
(`ha_lease.go`, `ha_failover.go`, `cluster_startup.go:43`) and is present and
wired. The overview's "Supported (optional etcd fencing lease)" row stands; the
apparent contradiction was reading a scoped comment out of context. Content-
factory finding G-02 is closed.
