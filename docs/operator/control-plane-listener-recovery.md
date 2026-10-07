# Control Plane listener recovery (CHAOS-71)

Operator runbook for the cluster **Control Plane gRPC listener** — the socket
every Data Plane node connects to for configuration sync, enrollment and
certificate renewal.

Companion runbooks for the other two supervised listeners:
[`admin-ui-listener-recovery.md`](admin-ui-listener-recovery.md) and
[`socks5-listener-health.md`](socks5-listener-health.md). All three share one
fault vocabulary on purpose — if you can read one, you can read the others.

---

## 1. What changed, and why you might care

Before this change, two things were true on a Control Plane node:

1. **A Control Plane listener that could not bind killed the whole appliance.**
   The bind happened before the HTTP/HTTPS proxy and the admin UI started, so an
   occupied port, a privileged port without the capability, or an address that
   was not up yet terminated the process with exit 1 — no proxy, no admin UI, no
   `/health`, no `/ready`. Under `restart: unless-stopped` that is an
   unattended crash loop recoverable only with shell access.

2. **A Control Plane listener that died was invisible.** If the listener bound
   and later stopped serving, one log line was written and nothing else
   happened: nothing rebound it, and no surface reported it. `/healthz` kept
   answering `{"status":"ok","role":"leader","write_authority":true}`, and in
   lease mode the fencing lease kept being renewed — so a leader whose control
   plane was dark went on holding the fence against its own standby while every
   Data Plane sat frozen on its last snapshot.

Now the listener is **supervised**: it binds, serves, and rebinds, and its state
is reported on five surfaces. The node's own proxy and admin UI are never
affected by a Control Plane listener fault.

> **Unchanged on purpose.** The proxy's own listener failure is still fatal. The
> proxy *is* the product, and a gateway that cannot serve must exit loudly
> rather than linger as a black hole. The asymmetry is deliberate.

---

## 2. First question: is this node's traffic affected?

**No.** A Control Plane listener fault affects *fleet management*, not this
node's proxying:

| Still working | Degraded while the listener is down |
|---|---|
| This node's HTTP/HTTPS proxy | Data Plane config sync (DPs keep serving their last snapshot) |
| This node's SOCKS5 listener | New node enrollment |
| This node's admin UI | Data Plane certificate renewal |
| This node's policy enforcement | Cluster-wide rate-limit aggregation |

Data Plane nodes do **not** stop filtering when the Control Plane is
unreachable. They keep enforcing the last configuration they synced, and their
own `/ready cp_poll` row reports the staleness. The risk is **drift**, not an
outage: a policy change you make now will not reach the fleet until the listener
is back.

---

## 3. Surfaces

Every surface below is **absent or `disabled`** on a node with no Control Plane
configured. That is deliberate: a flat zero on a standalone appliance would be
indistinguishable from a Control Plane whose listener is dead.

### `/health` (proxy port, unauthenticated)

```json
{ "status": "ok", "control_plane": "ready" }
```

| Value | Meaning |
|---|---|
| *(field absent)* | No Control Plane configured on this node. |
| `ready` | Listener bound and serving. |
| `degraded` | Listener unusable, still retrying, under the 30 s threshold. |
| `unavailable` | Listener unusable for longer than 30 s. **Act.** |
| `stopped` | Node is shutting down. |

This field lives on the **proxy** port because that is the surface that survives
the fault.

### `/ready` (proxy port) — report-only

A `control_plane` row appears with status `ok`, or `fail` while the listener is
unusable. **It does not gate the default readiness verdict**: a Control Plane
node whose cluster listener cannot bind is still proxying perfectly, and failing
readiness would eject a healthy gateway from your load balancer over a
fleet-management fault. Use `/ready?strict=1` if you *want* such nodes ejected.

### `/healthz` (admin port)

The leader and standalone responses carry two extra fields:

```json
{ "status": "ok", "role": "leader", "write_authority": true,
  "control_plane": "unavailable", "control_plane_unavailable": true }
```

> **The HTTP status and the `status` string are deliberately unchanged.** A
> leader whose control plane is dark still answers `200` with `"status":"ok"`.
> Flipping that is a posture decision with an availability cost — an
> orchestrator keying on the code could demote or fail over on a condition that
> clears by itself in seconds, and a planned CP handoff hands this very port
> between two processes. Page on the fields and the metrics instead; see §6.

### `/metrics` (proxy port)

```
culvert_cp_grpc_up 0
culvert_cp_grpc_unavailable 1
culvert_cp_grpc_bind_failures_total 7
culvert_cp_grpc_binds_total 0
culvert_cp_grpc_serve_exits_total 0
culvert_cp_grpc_bind_backoff_seconds 30
```

`bind_failures_total` and `serve_exits_total` are deliberately separate: a bind
failure says the socket could not be taken, a serve exit says a **working**
socket went away. The second is the one that used to leave no trace at all.

### `/api/diagnostics` (admin API, viewer role)

The `control_plane_listener` row carries the bounded reason class and a remedy
**specific to that class**. The raw error never appears here — it goes to the
rate-limited log line only.

### Alerts

Event name: **`control_plane_unavailable`**, Source `control_plane`.

> **This is a new event name.** Webhooks you already have configured in the
> field are **not** subscribed to it — a new name is silently unsubscribed. Add
> it to your webhook subscriptions, or you will not be paged for this condition.

It fires **once per episode**, when the listener has been unusable for longer
than 30 s, and re-arms only after an observed successful bind.

---

## 4. Reason classes and what to do

Each class has its own remedy because the actions genuinely differ. Two things
are true in every case: **the listener rebinds by itself** once the fault
clears, and **this node's proxy and admin UI are unaffected** — so do not
restart the node to achieve what is already in progress.

| Class | Cause | Action |
|---|---|---|
| `port_in_use` | Another process holds the port: a predecessor container still draining, a second Culvert, a host service, or an HA planned handoff in progress. | `ss -ltnp \| grep <port>`. If it is a draining predecessor or a handoff, wait — it clears in seconds. |
| `permission_denied` | Privileged port without `CAP_NET_BIND_SERVICE`, or the container stopped running as root. | Grant the capability, run as a user that may bind it, or move `-cp-grpc-addr` to an unprivileged port. |
| `address_unavailable` | `-cp-grpc-addr` names an address that is not on this host yet. **The common case for a CP**: an HA pair fronted by a floating/VIP address, binding before the interface carries it. | `ip addr` to confirm the address is present. Usually a host-boot race that clears on its own. |
| `descriptors_exhausted` | Out of file descriptors, so no socket can be opened. | Raise the `nofile` limit and look for a descriptor leak. This one is rarely isolated — check the other listeners too. |
| `tls_material` | `-cp-grpc-cert` / `-cp-grpc-key` / `-cp-grpc-ca` missing, unreadable, or invalid; or no TLS material and no `-cluster-insecure`. | Verify the paths exist and are readable by the process. Note this self-heals: a certificate rotation that briefly truncates the pair recovers with no restart. |
| `listen_failed` | Unrecognised listen error. | Read the rate-limited `ControlPlane gRPC listener ... could not bind` log line for the underlying error. |

---

## 5. Retry behaviour

- **Rate-bounded, never count-bounded.** 1 s, doubling to a 30 s ceiling, ±20%
  jitter. The listener never gives up, because the terminal state of "give up"
  is a fleet whose Control Plane is gone until someone restarts it.
- **Never silent.** The first failure logs immediately, then at most one line
  per 60 s, then one recovery line naming how many lines were suppressed. The
  magnitude lives in the counters.
- **Recovery is evidence-based.** Only an observed successful bind clears the
  state, the gauge and the alert latch. Elapsed time never clears anything — a
  loop that stopped failing because it stopped attempting looks identical to a
  bound one.
- **The backoff is not reset between binds.** A socket that dies immediately
  after each bind escalates to one attempt per 30 s rather than settling into a
  permanent one-bind-per-second cadence.

---

## 6. Recommended alerting

```yaml
# The Control Plane listener is down and has been for more than 30s.
- alert: CulvertControlPlaneListenerDown
  expr: culvert_cp_grpc_unavailable == 1
  for: 2m
  annotations:
    summary: "Control Plane gRPC listener unavailable — Data Plane nodes cannot sync config"

# A working listener keeps dying. Rebinding works, but something is killing the socket.
- alert: CulvertControlPlaneListenerFlapping
  expr: increase(culvert_cp_grpc_serve_exits_total[1h]) > 3
  annotations:
    summary: "Control Plane gRPC listener stopped serving repeatedly"
```

**The condition worth paging on hardest** is a leader that holds the fencing
lease and cannot be reached, because the HA mechanism will not recover from it
on its own — the standby cannot take the fence while the leader keeps renewing
it. Express it by joining the listener gauge with `/healthz`'s
`write_authority`, or:

```yaml
- alert: CulvertControlPlaneDarkButFenced
  expr: culvert_cp_grpc_unavailable == 1 and culvert_ha_write_authority == 1
  for: 2m
  annotations:
    summary: "This node holds HA write authority but its Control Plane is unreachable"
    runbook: "Fix the listener fault, or fail over deliberately (docs/operator/ha-lease-failover.md)"
```

A node in that state does **not** surrender the fence by itself. That is
deliberate — automatic surrender would flap a healthy pair during an ordinary
planned handoff — so the failover decision is yours. See
[`ha-lease-failover.md`](ha-lease-failover.md) for the manual promotion path.

---

## 7. What is deliberately not done

- **A dark leader still answers `/healthz` 200 with `status: ok`.** Changing
  the status code is a posture decision with an availability cost; the honest
  fields are there so you can act on them. Recorded as register row CP-4.
- **A dark leader does not surrender the fencing lease.** Same reasoning: an
  automatic surrender trades a control outage for a failover that can flap.
- **HA promotion and the admin API still fail all-or-nothing.** If a standby
  cannot bind the Control Plane port during promotion, it stays a standby and
  does *not* retry in the background — a standby must never hold the Control
  Plane port. Only the boot path, on a node already configured as a Control
  Plane, keeps retrying.
- **The HA fencing-lease arming is still fatal.** A lease the operator asked for
  that cannot be built is a deterministic misconfiguration that does not
  self-heal, and booting past it would mean silently running unfenced. That one
  is correct and is left alone.
