# HA fencing-lease recovery

**Audience:** operators running Culvert Control Planes with the ADR-0005
fencing lease armed (`-ha-etcd-endpoints` / `cluster.etcd_endpoints`).

**Companion:** `docs/operator/ha-lease-failover.md` covers normal failover.
This page covers the state where a node holds the **leader role** but not the
**fence** — it serves reads and cannot write.

---

## 1. What "unfenced" means

In lease mode, write authority is not the role — it is the lease. A node may
hold `role=leader` while `WriteAllowed()` is false, and in that state it
**cannot**:

- issue or renew a data-plane certificate (`Enroll`, `RenewCert`),
- accept a revocation sync,
- publish a config snapshot that data planes will accept (it stamps epoch 0,
  and a DP that has seen a positive epoch rejects that),
- serve an HA state bundle a standby will import.

It **can** still serve the admin UI read-only, answer health probes, and let
data planes keep enforcing their last-good policy. Nothing breaks for end
users. Configuration simply stops changing.

Since CHAOS-55 the node recovers from this on its own in the common cases. This
page tells you how to confirm that, and what to do when it does not.

---

## 2. The one alert rule you need

```yaml
- alert: CulvertHAUnfencedLeader
  expr: culvert_ha_unfenced == 1
  for: 5m
  annotations:
    summary: "Culvert CP holds the HA leader role without fencing write authority"

- alert: CulvertHAUnfencedAndStuck
  expr: culvert_ha_unfenced == 1 and culvert_ha_lease_recovering == 0
  for: 1m
  annotations:
    summary: "Culvert CP is read-only and has STOPPED trying to recover — operator action required"
```

The second rule is the urgent one. The distinction it encodes:

| `unfenced` | `recovering` | meaning | action |
|---|---|---|---|
| 0 | 0 | healthy leader, or a standby | none |
| 1 | 1 | read-only, **retrying in the background** | wait; fix etcd |
| 1 | 0 | read-only and **latched** | act now — §5 |

`culvert_ha_unfenced` is emitted **only** on nodes with a fencing backend
armed, so it is safe to alert on `== 1` fleet-wide without excluding standalone
or legacy-mode nodes. It is deliberately not "no write authority": a standby has
none either, and that is healthy.

Supporting series (same gating):

| series | use |
|---|---|
| `culvert_ha_write_authority` | 1 = this node may write right now |
| `culvert_ha_lease_epoch` | current fencing epoch; 0 = not held |
| `culvert_ha_lease_reacquire_attempts_total` | rate of failed recovery rounds — how hard it is trying |
| `culvert_ha_lease_reacquired_total` | recoveries that completed with no operator |

The same posture is on `GET /api/cluster/ha` and `/healthz` as `lease_valid`,
`epoch`, and `lease_recovering`, and on the admin UI's **Fencing Lease** card.

**Alerts.** The existing `ha_resume_unfenced` (entering the state) and
`ha_self_fenced` (standing down) still fire. A completed background recovery
fires the new **`ha_lease_reacquired`**. Webhooks subscribed to `*` receive it
automatically; a webhook with an explicit event list needs it added, or the
recovery half of the episode arrives only in the log and the metrics.

---

## 3. How a node gets here

| cause | what happens | recovers by itself? |
|---|---|---|
| etcd not yet accepting connections at boot (host reboot starts culvert and etcd together) | the resume acquire retries for a few seconds inline | **yes**, usually with no read-only window at all |
| etcd down longer than that during a CP restart | node takes the leader role read-only and arms the background recovery loop — the boot is NOT held up, so the proxy data plane starts normally | **yes**, as soon as etcd returns |
| etcd unreachable from this node only (network/TLS/firewall) | as above; recovery keeps retrying at 1 s → 30 s | yes, once reachability is fixed |
| a peer legitimately promoted while this node was down | node re-enters standby against the peer, or keeps a read-only leader role if it has no recorded peer | **no** — this is correct, not a fault |
| a peer took the fence while this node was unfenced | node stands down and **latches** | **no**, by design — §4 |

---

## 4. Why "latched" is deliberate

Once this node has **seen another node holding the lease**, it stops trying,
permanently, for the life of the process — even if that holder later
disappears.

That is not a bug. Another node has been the source of truth for an unknown
length of time, so this node's configuration may be arbitrarily stale. Silently
taking over when the current leader dies would make stale config authoritative
across the fleet. Promotion decisions of that kind belong to the standby
machinery, which gates them on freshness (`haPromoteFreshnessWindow`, 10 min of
successful state sync) and hysteresis — or to you.

The node logs `CRITICAL — another node holds the fencing lease` and fires
`ha_resume_unfenced` when it latches.

---

## 5. Runbook: `unfenced=1` and `recovering=0`

**1. Confirm what the fence says.**

```sh
curl -s https://<cp>:9090/api/cluster/ha | jq '{role,term,lease_mode,lease_valid,epoch,lease_recovering,standby_addr}'
ETCDCTL_API=3 etcdctl --endpoints=<endpoints> get /culvert/ha/leader -w json | jq
```

**2. Is another node holding it?**

- **Yes, and it is a healthy leader** — this node is not the leader. Nothing to
  do here. If it should become the standby, restart it with the peer's address
  so it can resync (it will re-enter standby on its own if `standby_addr` was
  recorded).
- **Yes, but it is dead / decommissioned** — the lease will expire within one
  TTL and the key will vanish. Then go to step 3.
- **No holder at all** — the cluster has no leader. Go to step 3.

**3. Decide which node should lead, then check its state is current.**

There is no automatic answer to this and that is the point of the latch.
Compare `term`, and compare the config version each node last published
(`culvert_cluster_config_version`). Prefer the node with the highest config
version that you believe served traffic most recently.

**4. Restart the chosen node.** A restart re-runs the resume path with a
reachable etcd and acquires cleanly. This is the safe, boring recovery and it is
the one to reach for first.

**5. If the chosen node is a standby**, promote it from the admin UI (Cluster →
HA → Promote) or `POST /api/cluster/ha/promote`. Manual promotion deliberately
bypasses the freshness and hysteresis gates — it is the break-glass, so confirm
step 3 before using it. `PromoteManually` refuses a node whose role is already
`leader`; restart that node instead.

---

## 6. Runbook: `unfenced=1` and `recovering=1`

The node is retrying on its own. Fix the fence and it will recover with no
further action.

```sh
# From the CP host — the recovery loop's own view
ETCDCTL_API=3 etcdctl --endpoints=<endpoints> endpoint health
journalctl -u culvert | grep -E 'HA: (still UNFENCED|RECOVERED|lease recovery ARMED)'
```

The log is deliberately quiet: the first failure of an episode, then at most one
line per minute, then a single `HA: RECOVERED` line naming how many were
suppressed. Use `culvert_ha_lease_reacquire_attempts_total` for the magnitude.

Recovery raises the term to the new fencing epoch, which is expected — the term
collapses into the epoch on every grant (ADR-0005 Finding 6). Data planes
ratchet forward to it automatically.

---

## 7. Prevention

- **Order etcd before culvert.** In compose, `depends_on` with a healthcheck
  condition; under systemd, `After=`/`Requires=` on the etcd unit. The inline
  resume retry absorbs a normal race and the background loop covers the rest,
  but ordering removes the read-only window entirely.

  Note the inline retry is deliberately short (seconds, not the 45 s the
  ghost-lease wait gets): `ResumeAsLeader` runs ahead of the proxy listener in
  the startup sequence, so blocking there would trade a control-plane write
  outage for a **data-plane** one. An etcd outage never delays the gateway.
- **Run a real witness.** The compose `--profile ha` etcd is a single node and
  is labelled LAB ONLY. A single-node witness makes a witness restart a
  fleet-wide write outage.
- **Do not set the lease TTL near the write margin.** The floor is 3 s and a
  lower value is fatal at startup. If you ever observe
  `culvert_ha_write_authority 0` together with a non-zero
  `culvert_ha_lease_epoch`, the backend is reporting a validity shorter than the
  1 s write margin — that combination is otherwise impossible and is worth its
  own alert.

---

## 8. Known gaps

### 8.1 A long blind period cannot be proven empty (HA-19)

The recovery loop looks at the fence at least once per lease TTL, and etcd keeps
a holder's key for a full TTL after that holder stops renewing — so a peer that
acquires, leads and dies cannot slip past unnoticed between two **successful**
observations.

What it cannot rule out is a period in which this node could not reach etcd
**while a peer could** (a one-sided partition). If a peer led and vanished
entirely inside such a window, this node sees a free lease afterwards and takes
it, with configuration that may be older than the peer's.

Two things keep this in proportion, and both matter when you are deciding
whether to intervene:

- A backend that is *down* cannot have granted the lease to anyone else either,
  so an ordinary etcd outage — the case this loop exists for — is unaffected.
- The same is true of a plain restart: a leader you restart by hand acquires a
  free lease with no proof either. This is not new behaviour, only newly
  reachable without you.

If you have had a one-sided partition longer than a lease TTL and configuration
correctness matters more than availability, compare
`culvert_cluster_config_version` across both CPs before letting the recovered
node stay leader, exactly as in §5 step 3.

### 8.2 A self-fenced ex-leader with no recorded peer

A leader that **self-fences** (loses the lease mid-flight) and has **no
recorded ex-standby address** becomes a passive standby with no loops running,
and will not re-acquire on its own even when the lease is free. Recovery is a
restart. This is tracked as register row **HA-18**: re-acquiring from a standby
role is a promotion, and the freshness gate that governs promotions is keyed on
successful state sync — a measure that is structurally wrong for an ex-leader,
which does not sync. Changing it is a posture decision, not a bug fix.

`standby_addr` is recorded automatically the first time a standby syncs to this
leader, so any cluster that has ever had a working standby is unaffected.
