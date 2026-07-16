# HA automatic failover with an etcd fencing lease (ADR-0005)

This runbook covers enabling **safe automatic failover** for a 2-Control-Plane
HA pair by arbitrating leadership through a **fencing lease held in etcd**.

Without a lease, Culvert HA is manual-failover only (ADR-0004): on leader loss
the standby stays read-only until an operator promotes it. That is deliberate —
two nodes alone cannot distinguish "leader is dead" from "network between us is
down", and guessing wrong means split-brain. The lease adds the missing third
authority: leadership belongs to whoever holds the lease in etcd, and **only**
that node may promote or accept cluster writes.

## What the lease changes

| Behavior | Legacy (no lease) | Lease mode |
|---|---|---|
| Automatic failover | Opt-in flag, unsafe (15s timeout guess); split-brain possible | Always on, fence-gated: the standby promotes only after **acquiring the lease**, which etcd denies while the leader lives |
| `--ha-auto-failover` flag | Governs the 15s trigger | **Ignored** (logged); the lease arbitrates |
| Partitioned leader | Keeps leading (split-brain) | **Self-fences**: demotes itself to read-only standby the moment it can no longer confirm the lease, then resyncs from the new leader |
| Cluster writes (enroll, cert renewal, revocations, config push) | Role-based only | Additionally **epoch-fenced**: a fenced ex-leader's writes are refused by Data Planes and the bundle verifier |
| HA term on `/healthz` | Incremented counter | Collapsed to the etcd lease **epoch** (strictly monotonic across all leadership changes) |

Two extra gates protect the **automatic** path only (manual promotion bypasses
both, and logs that it did):

- **Freshness** — a standby refuses to auto-promote on state older than
  10 minutes (or never synced). Prefer an availability gap over serving stale
  config as the new source of truth.
- **Hysteresis** — a node that just self-fenced refuses to auto-re-promote for
  30 seconds, so a flapping link cannot churn leadership.

## Prerequisites

- An etcd v3 endpoint reachable from **both** Control Planes. For real fault
  tolerance the witness must not share fate with a CP:
  - **Production**: a 3-node etcd cluster, or at minimum a single etcd on a
    **third machine**. An etcd on the same host as a CP cannot arbitrate that
    host's failure.
  - **Lab / evaluation**: the profile-gated `etcd` service in
    `docker-compose.yml` (`docker compose --profile ha up -d`) — single member,
    plaintext, compose-network only. Do not use it in production.
- TLS strongly recommended in production: give etcd a server cert and point
  Culvert at the CA (`--ha-etcd-ca`); add client certs (`--ha-etcd-cert/key`)
  if etcd requires client auth.

## Enabling

Set the endpoints on **both** Control Planes (leader and standby) and restart.
Configuration is **read once at startup** — the admin UI shows lease *status*
but cannot change the endpoints at runtime.

CLI flags:

```
./culvert ... \
  -ha-etcd-endpoints https://etcd1:2379,https://etcd2:2379,https://etcd3:2379 \
  -ha-etcd-ca /etc/culvert/etcd-ca.pem \
  -ha-etcd-cert /etc/culvert/etcd-client.pem \
  -ha-etcd-key /etc/culvert/etcd-client-key.pem \
  -ha-lease-ttl 10
```

or `config.yaml`:

```yaml
cluster:
  etcd_endpoints: "https://etcd1:2379,https://etcd2:2379,https://etcd3:2379"
  etcd_ca_file: /etc/culvert/etcd-ca.pem
  etcd_cert_file: /etc/culvert/etcd-client.pem
  etcd_key_file: /etc/culvert/etcd-client-key.pem
  lease_ttl_seconds: 10
```

On boot the log shows:

```
HA: etcd fencing lease ARMED (endpoints=..., ttl=10s, candidate=<nodeID>) — leadership is lease-arbitrated (ADR-0005)
```

Malformed lease config (unreadable TLS material, unparsable CA) is **fatal at
boot** — silently falling back to legacy mode would be an invisible safety
downgrade. An *unreachable* etcd is not fatal: the client connects lazily, and
until etcd answers, leadership acquisition is simply **denied** (fail-closed).

Roll out: restart the standby first, verify its panel/healthz shows
`lease_mode: lease`, then restart the leader (see the ghost-lease note below —
a fast leader restart re-acquires its own lease automatically).

## Choosing the TTL (`-ha-lease-ttl`, default 10s)

The TTL is the **failover-latency ↔ tolerance trade**:

- **Unplanned failover latency ≈ TTL**: the standby can acquire the lease only
  after the dead leader's lease expires in etcd.
- A partitioned leader keeps write authority for at most its last
  etcd-confirmed validity window minus a 1s write margin, then self-fences.
  The keepalive renews at TTL/3 (capped at 2s), so transient etcd blips
  shorter than roughly TTL−1s never fence a healthy leader.
- Lower TTL = faster failover but less tolerance for etcd/network hiccups.
  10s is a sane default; go below 5s only on a very reliable LAN. The
  enforced minimum is **3s** — a TTL at or below the 1s write margin would
  grant a lease that never confers write authority, so startup rejects it.

## Observing

- **`GET /healthz`** (both roles) and **`GET /api/cluster/ha`** include:
  - `lease_mode` — `"lease"` (fence armed) or `"none"` (legacy),
  - `lease_valid` — whether this node currently holds write authority,
  - `epoch` — the fencing epoch (0 = not held). Strictly increases on every
    leadership change; two nodes claiming the same epoch is impossible.
- **Admin UI → Cluster → High Availability**: a "Fencing Lease" card shows
  `held (epoch N)` / `not held`. Endpoints are startup config, so the panel is
  status-only.
- **Standby sync health** — `GET /api/cluster/ha` adds, standby-side only:
  - `sync_fail_count` — consecutive `HASync` failures since the last success
    (resets to 0 on every successful sync),
  - `sync_max_fail` — the threshold (3) at which the standby stops waiting and
    either self-promotes (lease/auto-failover) or, with automatic failover
    off, stays read-only until an operator promotes it manually,
  - `last_sync_ok` — RFC3339 timestamp of the last successful sync apply.

  The HA panel mirrors this as a "Sync to Leader" stat card (green at 0,
  amber below the threshold, red at/above it) — the early warning before a
  standby silently hits `haStandbyMaxFail` and fails over.
- **Alerts**: `ha_self_fenced` fires when a leader demotes itself;
  `ha_resume_unfenced` fires when a restarted leader could not re-acquire the
  lease and has no standby to resync from.

## Failure scenarios

- **Leader host dies** — lease expires after ≤TTL; the standby's
  leader-unreachable path acquires it and promotes (if its state passes the
  freshness gate). Total unplanned failover ≈ TTL + a few seconds of retry.
- **Network partition (leader ↔ standby, leader ↔ etcd)** — the leader
  self-fences when its confirmed window ends; the standby acquires and
  promotes. When the partition heals, the ex-leader is already a standby
  resyncing from the new leader. **Bounded last-writer-wins window**: admin
  writes accepted by the old leader inside its final validity window (≤TTL)
  but not yet replicated are lost on resync — this is the documented LWW-A
  posture; the fence bounds the window, it does not make replication
  synchronous.
- **etcd unreachable from BOTH nodes** — the leader self-fences at window end;
  the standby cannot acquire. **Availability stops until etcd returns** — the
  cluster prefers read-only to split-brain. Admin UI stays up read-only;
  proxying continues (the data path never depends on etcd).
- **Leader process restarts quickly** (within the TTL) — the key in etcd is
  still held by the *previous process's* lease. The resume path recognizes its
  own ghost (holder == own node ID), waits it out (bounded at 45s), and
  re-acquires. A denial by any **other** holder is treated as real: the node
  re-enters standby against it.
- **Standby also down during failover** — nothing promotes; the lease sits
  expired until a node returns and acquires it.

## Break-glass

- **Manual promotion** (UI button / `POST /api/cluster/ha/promote`) still
  requires acquiring the lease, but **bypasses the freshness and hysteresis
  gates** — use it when auto-promotion refuses on stale state and you accept
  serving that state.
- **etcd lost long-term / decided to abandon fencing**: remove
  `-ha-etcd-endpoints` (or the yaml keys) and restart — the node runs in
  legacy manual-failover mode (ADR-0004 posture). Do this on **both** nodes;
  never run one fenced and one legacy.
- **Force a specific node to lead**: stop the other node, delete the lease key
  if needed (`etcdctl del /culvert/ha/leader`), then use manual promotion (or
  restart-as-leader).

## Related

- `docs/adr/0005-ha-lease-witness-failover.md` — design, adversarial review,
  slice log (S0–S5).
- `docs/adr/0004-ha-split-brain-safe-defaults.md` — the manual-failover
  baseline this builds on.
- `docs/engineering/TECHNICAL-RISK-REGISTER.md` RISK-001 — the split-brain
  risk this closes.
