# High availability: etcd fencing lease & failover

Culvert supports an active/passive HA Control Plane. Two failover models exist:
the legacy manual model, and — recommended for unattended failover — an **etcd
fencing lease** that arbitrates leadership so two nodes can never both act as
leader (split-brain). This guide covers both, the lease mechanics, and how to
operate failover safely.

Prerequisite reading: [Control Plane / Data Plane](control-plane-data-plane.md).

---

## Purpose

Keep the Control Plane available across a node failure without risking two
leaders writing conflicting configuration.

## Two failover models

| Model | Trigger | Split-brain safety |
|---|---|---|
| Legacy manual (ADR-0004) | Operator promotes a standby, or `-ha-auto-failover` self-promotes on leader loss | **Unsafe unattended** in 2-node (no witness) — off by default |
| Fencing lease (ADR-0005) | A strongly-consistent etcd lease arbitrates every path to leadership | Fail-closed: only the lease holder may write |

`-ha-auto-failover` is **off by default** because a 2-node active/passive pair
has no witness, so unattended self-promotion can split-brain
(`main.go:244`). When you enable the fencing lease, `-ha-auto-failover` is
**ignored** — the lease arbitrates instead (`main.go:244-245`).

## How the fencing lease works

A single cluster-wide lease with a strictly-monotonic **epoch** (the fencing
token) is arbitrated by etcd:

- Lease key `/culvert/ha/leader`, epoch = the etcd `create_revision`
  (`internal/halease/etcd.go`).
- The lease is armed **before any role branch** at startup (`armHALease`,
  `cluster_startup.go:43,152`); malformed lease config is fatal, and unreachable
  etcd lazily **denies** leadership (fail-closed).
- Promotion is **Acquire-gated**: a node becomes leader only by acquiring the
  lease (`HAState.Acquire`, `ha_lease.go:84`).
- A keepalive loop treats etcd as the clock; if the lease is lost or unconfirmed
  beyond its validity window, the node **self-fences** to a read-only standby
  (`selfFence`, `ha_lease.go:183-202`).
- All writes are gated by `WriteAllowed()` — the lease-layer write-authority
  primitive (`ha_lease.go:242-247`); the epoch is stamped on write sinks so a
  stale ex-leader's writes are rejected.

> The `internal/halease` package documents itself as an ADR-0005 **S1 primitive**
> ("nothing in the runtime consumes it yet"). That comment describes the
> package's own slice scope — the runtime consumption (Acquire-gated promotion,
> keepalive, self-fence, epoch stamping) is implemented in package `main`
> (`ha_lease.go`, `ha_failover.go`, `cluster_startup.go`). The feature is wired.

## Failover behavior

Lease-mode auto-promotion (`leaseAutoPromote`, `ha_failover.go:74`) is guarded:

- **Hysteresis:** refuse to re-promote within a cooldown after a recent
  promotion (`ha_failover.go:15`).
- **Freshness:** refuse to auto-promote on state older than a freshness window —
  a stale standby will not take over (`ha_failover.go:12,98`).
- Then **Acquire** the lease before acting.
- A demoted node **resyncs** from its recorded ex-leader before rejoining
  (`enterStandbyResync`, `ha_failover.go:111-117`).
- A fast leader restart waits briefly for its own prior ("ghost") lease to
  expire before re-acquiring (`acquireLeaseForResume`, `ha_failover.go:145-153`).

**Manual promotion** is a break-glass action that bypasses freshness/hysteresis:
`POST /api/cluster/ha/promote` (`ui_cluster.go:594`).

## Configuration

| Flag | Purpose |
|---|---|
| `-ha-etcd-endpoints` | Comma-separated etcd endpoints (enables the lease) |
| `-ha-etcd-cert` / `-ha-etcd-key` / `-ha-etcd-ca` | etcd client mTLS |
| `-ha-lease-ttl` | Lease TTL in seconds (failover latency ≈ TTL; min 3; `0` = config or 10) |

(`main.go:245-249`.) These may also come from `cluster.etcd_*` /
`lease_ttl_seconds` in YAML. All are read once at startup.

```bash
./culvert -cp-grpc-addr :50051 \
  -ha-etcd-endpoints https://etcd1:2379,https://etcd2:2379 \
  -ha-etcd-cert /data/etcd-client.crt \
  -ha-etcd-key  /data/etcd-client.key \
  -ha-etcd-ca   /data/etcd-ca.crt \
  -ha-lease-ttl 10
```

## Observability

- `GET /api/cluster/ha` — HA status (`ui_cluster.go:593`).
- `/healthz` and `/api/cluster/ha` expose `lease_mode`, `lease_valid`, and
  `epoch` (`ha_lease.go:269`).

## Validation steps

```bash
curl -sk https://<cp-host>:9090/api/cluster/ha
# Expect lease_mode true, lease_valid true on the current leader, and an epoch.
```

Then stop the leader and confirm a standby acquires the lease (its epoch
increments) within roughly the lease TTL.

## Failure modes

| Condition | Behavior |
|---|---|
| etcd unreachable at startup | Leadership lazily **denied** (fail-closed) |
| Malformed lease config | Fatal at startup |
| Leader loses the lease / can't confirm it | Self-fences to read-only standby |
| Network partition | Bounded last-writer-wins window ≤ the lease TTL (documented F4 posture) |
| Stale standby tries to auto-promote | Refused by the freshness gate |

## Security implications

- Protect etcd with mTLS (`-ha-etcd-*`); the lease is the write-authority root.
- The lab compose ships a single-node etcd witness for demos only — production
  wants a real etcd quorum on separate machines.

## Known limitations

- Legacy manual mode without a witness can split-brain under unattended
  auto-failover — this is why `-ha-auto-failover` is off by default; use the
  fencing lease for safe automation.
- On partition, the fencing lease bounds inconsistency to ≤ the lease TTL
  (bounded LWW), not zero.
- The compose-provided etcd is lab-only (single node, no TLS as shipped).

## Related documentation

- [Control Plane / Data Plane](control-plane-data-plane.md) ·
  [Architecture → CP/DP](../01-overview/architecture.md#control-plane--data-plane).
- In-repo operator runbook:
  [`../../../docs/operator/ha-lease-failover.md`](../../../docs/operator/ha-lease-failover.md).

## Source evidence

Claim-evidence ledger: [`high-availability.evidence.md`](high-availability.evidence.md).
